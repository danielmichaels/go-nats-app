package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"{{ cookiecutter.go_module_path }}/internal/app"
	"{{ cookiecutter.go_module_path }}/internal/authn"
	"{{ cookiecutter.go_module_path }}/internal/config"
	"{{ cookiecutter.go_module_path }}/internal/oidctest"
	"{{ cookiecutter.go_module_path }}/internal/session"
	"{{ cookiecutter.go_module_path }}/internal/users"
)

func oidcConfig(dir string, p *oidctest.Provider) config.Config {
	cfg := testConfig(dir)
	cfg.OIDC = &config.OIDC{Issuer: p.Issuer(), ClientID: oidctest.ClientID, RedirectURL: "http://localhost/auth/oidc/callback", AllowHTTP: true}
	return cfg
}

// replica starts a second app process on the first app's NATS server, as a
// deployment with two replicas does.
func replica(t *testing.T, a *app.App, p *oidctest.Provider) *app.App {
	t.Helper()
	dir := t.TempDir()
	b, _ := json.Marshal(a.Runtime)
	path := filepath.Join(dir, "runtime.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := oidcConfig(dir, p)
	cfg.EmbeddedNATS, cfg.NATSURL, cfg.NATSRuntimeFile = false, a.NATSURL, path
	cfg.RefreshMargin = a.Config.RefreshMargin
	return start(t, cfg)
}

func linkedUser(t *testing.T, a *app.App, name, issuer, subject string) users.User {
	t.Helper()
	ctx := context.Background()
	u, err := a.Auth.Users.Create(ctx, name, "correct horse battery", users.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if u, err = a.Auth.Users.Link(ctx, u.ID, users.Identity{Issuer: issuer, Subject: subject}); err != nil {
		t.Fatal(err)
	}
	return u
}

type attempt struct{ state, nonce, challenge, redirect string }

func startLogin(t *testing.T, a *app.App) attempt {
	t.Helper()
	raw, state, err := a.Auth.OIDCStart(context.Background(), "/notes", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	if q.Get("state") != state || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorize URL = %s", raw)
	}
	return attempt{state, q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri")}
}

func oidcLogin(t *testing.T, a *app.App, p *oidctest.Provider) signedIn {
	t.Helper()
	at := startLogin(t, a)
	code := p.Code(at.nonce, at.challenge, at.redirect)
	tok, cur, redirect, err := a.Auth.OIDCCallback(context.Background(), at.state, at.state, code)
	if err != nil {
		t.Fatal(err)
	}
	if redirect != "/notes" {
		t.Fatalf("redirect = %q", redirect)
	}
	return signedIn{tok, cur}
}

func TestOIDCCallbackValidation(t *testing.T) {
	p := oidctest.New()
	defer p.Close()
	a := start(t, oidcConfig(t.TempDir(), p))
	ctx := context.Background()
	linkedUser(t, a, "alice", p.Issuer(), "subject-1")

	s := oidcLogin(t, a, p)
	nc := connect(t, a, s)
	if _, err := createNote(ctx, nc, "oidc-note-1", "via oidc"); err != nil {
		t.Fatal(err)
	}
	if got, err := a.Auth.Session(ctx, s.token); err != nil || got.User.Username != "alice" || got.Record.Method != session.MethodOIDC {
		t.Fatalf("session = %+v, %v", got, err)
	}

	// Password login reaches the same user and the same notes.
	pw := login(t, a, "alice")
	if n := listNotes(t, connect(t, a, pw)); len(n) != 1 {
		t.Fatalf("password session notes = %+v", n)
	}

	refused := func(name string, setup func(*oidctest.Provider), want error) {
		t.Run(name, func(t *testing.T) {
			p.Set(setup)
			defer p.Set(func(p *oidctest.Provider) {
				p.Mutate, p.SignWithOtherKey, p.Subject = nil, false, "subject-1"
			})
			at := startLogin(t, a)
			code := p.Code(at.nonce, at.challenge, at.redirect)
			if _, _, _, err := a.Auth.OIDCCallback(ctx, at.state, at.state, code); !errors.Is(err, want) {
				t.Fatalf("err = %v, want %v", err, want)
			}
		})
	}
	refused("wrong issuer", func(p *oidctest.Provider) { p.Mutate = func(c map[string]any) { c["iss"] = "https://evil.example" } }, authn.ErrIdentityRefused)
	refused("wrong audience", func(p *oidctest.Provider) { p.Mutate = func(c map[string]any) { c["aud"] = "other-client" } }, authn.ErrIdentityRefused)
	refused("wrong authorized party", func(p *oidctest.Provider) {
		p.Mutate = func(c map[string]any) { c["aud"] = []string{oidctest.ClientID, "other"}; c["azp"] = "other" }
	}, authn.ErrIdentityRefused)
	refused("bad signature", func(p *oidctest.Provider) { p.SignWithOtherKey = true }, authn.ErrIdentityRefused)
	refused("expired ID token", func(p *oidctest.Provider) {
		p.Mutate = func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }
	}, authn.ErrIdentityRefused)
	refused("nonce mismatch", func(p *oidctest.Provider) { p.Mutate = func(c map[string]any) { c["nonce"] = "other" } }, authn.ErrIdentityRefused)
	refused("unbound subject with matching email", func(p *oidctest.Provider) {
		p.Subject = "subject-2"
		p.Mutate = func(c map[string]any) { c["email"] = "subject-1@example.com"; c["preferred_username"] = "alice" }
	}, authn.ErrUnbound)

	t.Run("replayed callback", func(t *testing.T) {
		at := startLogin(t, a)
		code := p.Code(at.nonce, at.challenge, at.redirect)
		if _, _, _, err := a.Auth.OIDCCallback(ctx, at.state, at.state, code); err != nil {
			t.Fatal(err)
		}
		code = p.Code(at.nonce, at.challenge, at.redirect)
		if _, _, _, err := a.Auth.OIDCCallback(ctx, at.state, at.state, code); !errors.Is(err, authn.ErrLoginExpired) {
			t.Fatalf("replay err = %v", err)
		}
	})
	t.Run("state not bound to this browser", func(t *testing.T) {
		at := startLogin(t, a)
		code := p.Code(at.nonce, at.challenge, at.redirect)
		if _, _, _, err := a.Auth.OIDCCallback(ctx, "other-browser-state", at.state, code); !errors.Is(err, authn.ErrLoginState) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("disabled local user", func(t *testing.T) {
		bob := linkedUser(t, a, "bob", p.Issuer(), "subject-3")
		if _, err := a.Auth.Users.SetDisabled(ctx, bob.ID, true); err != nil {
			t.Fatal(err)
		}
		p.Set(func(p *oidctest.Provider) { p.Subject = "subject-3" })
		defer p.Set(func(p *oidctest.Provider) { p.Subject = "subject-1" })
		at := startLogin(t, a)
		code := p.Code(at.nonce, at.challenge, at.redirect)
		if _, _, _, err := a.Auth.OIDCCallback(ctx, at.state, at.state, code); !errors.Is(err, authn.ErrUnbound) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("callback finishes on another replica", func(t *testing.T) {
		b := replica(t, a, p)
		at := startLogin(t, a)
		code := p.Code(at.nonce, at.challenge, at.redirect)
		tok, _, _, err := b.Auth.OIDCCallback(ctx, at.state, at.state, code)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.Auth.Session(ctx, tok); err != nil {
			t.Fatalf("first replica does not see the session: %v", err)
		}
	})
}

func shortIdentity(t *testing.T) (*oidctest.Provider, *app.App, string) {
	t.Helper()
	p := oidctest.New()
	t.Cleanup(p.Close)
	p.Set(func(p *oidctest.Provider) { p.IDTTL = 4 * time.Second })
	dir := t.TempDir()
	cfg := oidcConfig(dir, p)
	cfg.RefreshMargin = 3 * time.Second
	a := start(t, cfg)
	linkedUser(t, a, "alice", p.Issuer(), "subject-1")
	return p, a, dir
}

func expiry(t *testing.T, a *app.App, ref string) time.Time {
	t.Helper()
	rec, _, err := a.Auth.Sessions.Get(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	return rec.OIDC.IdentityExpiry
}

func TestOIDCRefresh(t *testing.T) {
	ctx := context.Background()

	t.Run("rotation is kept and survives restart", func(t *testing.T) {
		p, a, dir := shortIdentity(t)
		s := oidcLogin(t, a, p)
		first := expiry(t, a, s.cur.Ref)
		time.Sleep(1500 * time.Millisecond)
		if _, _, _, err := a.Auth.ConnectToken(ctx, s.cur.Ref); err != nil {
			t.Fatal(err)
		}
		if !expiry(t, a, s.cur.Ref).After(first) || p.RefreshCount() != 1 {
			t.Fatalf("no refresh: count %d", p.RefreshCount())
		}
		a.Close()
		time.Sleep(1500 * time.Millisecond)
		b := start(t, oidcConfig(dir, p))
		cur, err := b.Auth.Session(ctx, s.token)
		if err != nil {
			t.Fatalf("restored session: %v", err)
		}
		if p.RefreshCount() != 2 {
			t.Fatalf("restore did not refresh with the latest token: count %d", p.RefreshCount())
		}
		connect(t, b, signedIn{s.token, cur})
	})

	t.Run("revoked refresh token ends the session", func(t *testing.T) {
		p, a, _ := shortIdentity(t)
		s := oidcLogin(t, a, p)
		p.Revoke()
		time.Sleep(1500 * time.Millisecond)
		if _, _, _, err := a.Auth.ConnectToken(ctx, s.cur.Ref); !errors.Is(err, authn.ErrUnauthenticated) {
			t.Fatalf("err = %v", err)
		}
		if _, _, err := a.Auth.Sessions.Get(ctx, s.cur.Ref); !errors.Is(err, session.ErrNotFound) {
			t.Fatalf("session kept: %v", err)
		}
		// Password login stays available as its own choice.
		login(t, a, "alice")
	})

	t.Run("changed identity ends the session", func(t *testing.T) {
		p, a, _ := shortIdentity(t)
		s := oidcLogin(t, a, p)
		p.Set(func(p *oidctest.Provider) { p.RefreshSubject = "subject-9" })
		time.Sleep(1500 * time.Millisecond)
		if _, _, _, err := a.Auth.ConnectToken(ctx, s.cur.Ref); !errors.Is(err, authn.ErrUnauthenticated) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("lost rotation result ends the session", func(t *testing.T) {
		p, a, _ := shortIdentity(t)
		s := oidcLogin(t, a, p)
		p.Set(func(p *oidctest.Provider) { p.LoseRefresh = true })
		time.Sleep(1500 * time.Millisecond)
		if _, _, _, err := a.Auth.ConnectToken(ctx, s.cur.Ref); !errors.Is(err, authn.ErrUnauthenticated) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("crash during refresh ends the session", func(t *testing.T) {
		p, a, _ := shortIdentity(t)
		s := oidcLogin(t, a, p)
		rec, rev, _ := a.Auth.Sessions.Get(ctx, s.cur.Ref)
		rec.OIDC.RefreshingUntil = time.Now().Add(-time.Second)
		rec.OIDC.IdentityExpiry = time.Now().Add(time.Second)
		if _, err := a.Auth.Sessions.Update(ctx, s.cur.Ref, rec, rev); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := a.Auth.ConnectToken(ctx, s.cur.Ref); !errors.Is(err, authn.ErrUnauthenticated) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("outage never extends verified identity", func(t *testing.T) {
		p, a, _ := shortIdentity(t)
		s := oidcLogin(t, a, p)
		deadline := expiry(t, a, s.cur.Ref)
		nc := connect(t, a, s)
		expired := make(chan time.Time, 1)
		nc.SetErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			if app.AuthError(err) {
				expired <- time.Now()
			}
		})
		p.Set(func(p *oidctest.Provider) { p.Down = true })
		time.Sleep(1500 * time.Millisecond)
		_, _, exp, err := a.Auth.ConnectToken(ctx, s.cur.Ref)
		if err != nil {
			t.Fatalf("still within verified identity: %v", err)
		}
		if exp.After(deadline) {
			t.Fatalf("connect token %v outlives identity %v", exp, deadline)
		}
		select {
		case at := <-expired:
			if at.After(deadline.Add(1500 * time.Millisecond)) {
				t.Fatalf("NATS user expired at %v, identity at %v", at, deadline)
			}
		case <-time.After(8 * time.Second):
			t.Fatal("NATS user outlived the verified identity")
		}
		if _, _, _, err := a.Auth.ConnectToken(ctx, s.cur.Ref); !errors.Is(err, authn.ErrUnavailable) {
			t.Fatalf("after identity expiry during outage: %v", err)
		}
		if _, _, err := a.Auth.Sessions.Get(ctx, s.cur.Ref); err != nil {
			t.Fatalf("outage ended the session: %v", err)
		}
		p.Set(func(p *oidctest.Provider) { p.Down = false })
		if _, _, _, err := a.Auth.ConnectToken(ctx, s.cur.Ref); err != nil {
			t.Fatalf("no recovery after outage: %v", err)
		}
	})

	t.Run("concurrent tabs and replicas refresh once", func(t *testing.T) {
		p, a, _ := shortIdentity(t)
		b := replica(t, a, p)
		s := oidcLogin(t, a, p)
		// The refreshed identity stays fresh for the whole test, so a second
		// grant can only come from callers that did not wait for the first.
		p.Set(func(p *oidctest.Provider) { p.Delay, p.IDTTL = 500*time.Millisecond, time.Hour })
		time.Sleep(1500 * time.Millisecond)
		var wg sync.WaitGroup
		errs := make(chan error, 20)
		for i := range 20 {
			srv := a
			if i%2 == 1 {
				srv = b
			}
			wg.Go(func() {
				_, _, _, err := srv.Auth.ConnectToken(ctx, s.cur.Ref)
				errs <- err
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("concurrent connect token: %v", err)
			}
		}
		if n := p.RefreshCount(); n != 1 {
			t.Fatalf("refresh grants = %d, want 1", n)
		}
	})

	t.Run("logout during refresh is not undone", func(t *testing.T) {
		p, a, _ := shortIdentity(t)
		s := oidcLogin(t, a, p)
		p.Set(func(p *oidctest.Provider) { p.Delay = time.Second })
		time.Sleep(1500 * time.Millisecond)
		done := make(chan error, 1)
		go func() {
			_, _, _, err := a.Auth.ConnectToken(ctx, s.cur.Ref)
			done <- err
		}()
		time.Sleep(300 * time.Millisecond)
		a.Auth.Logout(ctx, s.token)
		if err := <-done; !errors.Is(err, authn.ErrUnauthenticated) {
			t.Fatalf("refresh after logout: %v", err)
		}
		if _, _, err := a.Auth.Sessions.Get(ctx, s.cur.Ref); !errors.Is(err, session.ErrNotFound) {
			t.Fatalf("logged out session came back: %v", err)
		}
	})
}
