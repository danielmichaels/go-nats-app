// Package app starts the NATS connections, stores, services and the auth
// callout in order, and stops them in reverse.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nats.go/micro"

	"{{ cookiecutter.go_module_path }}/internal/account"
	"{{ cookiecutter.go_module_path }}/internal/api"
	"{{ cookiecutter.go_module_path }}/internal/authn"
	"{{ cookiecutter.go_module_path }}/internal/callout"
	"{{ cookiecutter.go_module_path }}/internal/config"
	"{{ cookiecutter.go_module_path }}/internal/natsauth"
	"{{ cookiecutter.go_module_path }}/internal/natsdev"
	"{{ cookiecutter.go_module_path }}/internal/notes"
	"{{ cookiecutter.go_module_path }}/internal/oidcauth"
	"{{ cookiecutter.go_module_path }}/internal/session"
	"{{ cookiecutter.go_module_path }}/internal/users"
)

type App struct {
	Config  config.Config
	Runtime natsauth.Runtime
	// NATSURL is the server-side client URL.
	NATSURL string
	Auth    *authn.Service
	HTTP    *authn.Handler
	Service *nats.Conn

	embedded *natsdev.Server
	callout  *nats.Conn
	micro    micro.Service
}

func Start(ctx context.Context, cfg config.Config) (*App, error) {
	a := &App{Config: cfg}
	if err := a.start(ctx); err != nil {
		a.Close()
		return nil, err
	}
	return a, nil
}

func (a *App) start(ctx context.Context) error {
	cfg := a.Config
	browserURL := cfg.NATSBrowserURL
	if cfg.EmbeddedNATS {
		keys, err := natsauth.LoadOrCreateKeys(filepath.Join(cfg.DataDir, "nats", "keys.json"))
		if err != nil {
			return fmt.Errorf("development NATS keys: %w", err)
		}
		origins := []string{cfg.PublicURL, "http://localhost:5173", "http://127.0.0.1:5173"}
		a.embedded, err = natsdev.Start(keys, natsdev.Options{
			Port: cfg.NATSPort, WebsocketPort: cfg.NATSWSPort, AllowedOrigins: origins,
			StoreDir: filepath.Join(cfg.DataDir, "nats", "jetstream"),
		})
		if err != nil {
			return err
		}
		a.Runtime, a.NATSURL = a.embedded.Runtime, a.embedded.ClientURL()
		if browserURL == "" {
			browserURL = a.embedded.WebsocketURL()
		}
		slog.Info("embedded NATS started", "url", a.NATSURL, "websocket", browserURL)
	} else {
		rt, err := natsauth.LoadRuntime(cfg.NATSRuntimeFile)
		if err != nil {
			return fmt.Errorf("NATS runtime file: %w", err)
		}
		a.Runtime, a.NATSURL = rt, cfg.NATSURL
	}

	svcCreds, err := natsauth.Creds(a.Runtime.ServiceCreds)
	if err != nil {
		return fmt.Errorf("service creds: %w", err)
	}
	a.Service, err = nats.Connect(a.NATSURL, svcCreds, nats.Name("app-service"), nats.MaxReconnects(-1),
		nats.RetryOnFailedConnect(false), nats.ReconnectWait(time.Second))
	if err != nil {
		return fmt.Errorf("connect service account: %w", err)
	}
	js, err := jetstream.New(a.Service)
	if err != nil {
		return err
	}
	us, err := users.Open(ctx, js, cfg.Replicas)
	if err != nil {
		return fmt.Errorf("open users: %w", err)
	}
	ss, err := session.Open(ctx, js, cfg.SessionTTL, cfg.Replicas, a.Runtime.TokenBytes())
	if err != nil {
		return fmt.Errorf("open sessions: %w", err)
	}
	var provider *oidcauth.Provider
	if o := cfg.OIDC; o != nil {
		provider, err = oidcauth.New(ctx, oidcauth.Config{
			Issuer: o.Issuer, ClientID: o.ClientID, ClientSecret: o.ClientSecret,
			RedirectURL: o.RedirectURL, Scopes: o.Scopes, AllowHTTP: o.AllowHTTP,
		})
		if err != nil {
			return err
		}
		slog.Info("OIDC sign-in enabled", "issuer", o.Issuer)
	}
	publish := a.Service.Publish
	a.Auth, err = authn.New(ctx, js, cfg.Replicas, us, ss, provider, publish, authn.Options{
		SessionTTL: cfg.SessionTTL, ConnectTTL: cfg.ConnectTTL, RefreshMargin: cfg.RefreshMargin,
	})
	if err != nil {
		return err
	}

	id := api.Identity{UsersAccount: a.Runtime.UsersAccount, Users: us}
	ns, err := notes.Open(ctx, js, cfg.Replicas, id, publish)
	if err != nil {
		return fmt.Errorf("open notes: %w", err)
	}
	a.micro, err = micro.AddService(a.Service, micro.Config{Name: "app", Version: "0.1.0", Description: "application API"})
	if err != nil {
		return err
	}
	acct := &account.Service{ID: id, Revoked: func(userID string) {
		b, _ := json.Marshal(map[string]string{"type": "revoked"})
		_ = publish(authn.AccountEventSubject(userID), b)
	}}
	if err := acct.Register(a.micro); err != nil {
		return err
	}
	if err := ns.Register(a.micro); err != nil {
		return err
	}

	// The callout starts after the session store, so no admission is offered
	// before the issuer can check sessions.
	issuer, err := callout.New(a.Runtime, ss, us, cfg.UserJWTTTL)
	if err != nil {
		return err
	}
	calloutCreds, err := natsauth.Creds(a.Runtime.CalloutCreds)
	if err != nil {
		return fmt.Errorf("callout creds: %w", err)
	}
	a.callout, err = nats.Connect(a.NATSURL, calloutCreds, nats.Name("app-callout"), nats.MaxReconnects(-1))
	if err != nil {
		return fmt.Errorf("connect callout: %w", err)
	}
	if _, err := issuer.Serve(a.callout); err != nil {
		return err
	}
	if err := a.callout.Flush(); err != nil {
		return err
	}

	a.HTTP = &authn.Handler{Auth: a.Auth, SecureCookie: cfg.CookieSecure, TrustedProxies: cfg.TrustedProxies,
		NATS: authn.NATSConfig{Servers: []string{browserURL}, Sentinel: a.Runtime.Sentinel}}

	if tok, err := us.EnsureSetupToken(ctx); err != nil {
		return err
	} else if tok != "" {
		slog.Warn("no users yet: open /setup and enter this one-time setup token", "token", tok)
	}
	return nil
}

// Ready reports whether admission and services can work.
func (a *App) Ready() error {
	if a.Service == nil || !a.Service.IsConnected() {
		return errors.New("service connection is down")
	}
	if a.callout == nil || !a.callout.IsConnected() {
		return errors.New("callout connection is down")
	}
	return nil
}

func (a *App) Health(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if err := a.Ready(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func (a *App) Close() {
	if a.micro != nil {
		_ = a.micro.Stop()
	}
	for _, nc := range []*nats.Conn{a.callout, a.Service} {
		if nc != nil {
			_ = nc.Drain()
			deadline := time.Now().Add(3 * time.Second)
			for !nc.IsClosed() && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			nc.Close()
		}
	}
	if a.embedded != nil {
		a.embedded.Stop()
	}
}
