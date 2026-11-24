// Package cliauth signs the command-line client in through the browser and
// connects it to NATS as the signed-in user.
//
// Login listens on a random loopback port, opens the server's
// /auth/cli/start page, and waits for the one-time code that the server
// sends back to that port. It exchanges the code and its PKCE verifier for
// a session token (RFC 8252). The token is a session like a browser's: it
// lasts SESSION_TTL, and logout, disabling the user or losing the OIDC
// identity ends it. The client never holds a provider token.
//
// Connect trades the session for a short connect token on every CONNECT,
// so the auth callout signs a NATS user JWT for the user, and services read
// the caller from Nats-Request-Info as they do for the browser.
package cliauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"golang.org/x/oauth2"

	"{{ cookiecutter.go_module_path }}/internal/natsauth"
	"{{ cookiecutter.go_module_path }}/internal/users"
)

var ErrSignedOut = errors.New("not signed in: run login")

// Credentials are what Login stores on disk.
type Credentials struct {
	Server   string     `json:"server"`
	Token    string     `json:"token"`
	Deadline time.Time  `json:"deadline"`
	User     users.User `json:"user"`
}

var client = &http.Client{Timeout: 30 * time.Second}

// Login signs in against server, the app's public URL. open shows the sign-in
// page to the user, normally in a browser. Login returns when the browser
// comes back or ctx ends.
func Login(ctx context.Context, server string, open func(string) error) (Credentials, error) {
	server = strings.TrimSuffix(server, "/")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return Credentials{}, err
	}
	verifier, state := oauth2.GenerateVerifier(), random()
	type result struct {
		c   Credentials
		err error
	}
	done := make(chan result, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		if q.Get("state") != state {
			page(w, false)
			return
		}
		c, err := exchange(r.Context(), server, q.Get("code"), verifier)
		page(w, err == nil)
		select {
		case done <- result{c, err}:
		default:
		}
	})}
	go func() { _ = srv.Serve(l) }()
	defer func() { _ = srv.Close() }()

	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	u := server + "/auth/cli/start?" + url.Values{
		"port": {port}, "state": {state}, "challenge": {oauth2.S256ChallengeFromVerifier(verifier)},
	}.Encode()
	if err := open(u); err != nil {
		return Credentials{}, err
	}
	select {
	case <-ctx.Done():
		return Credentials{}, ctx.Err()
	case r := <-done:
		return r.c, r.err
	}
}

func random() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func page(w http.ResponseWriter, ok bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	text := "Signed in. You can close this tab and return to the terminal."
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		text = "Sign-in failed. Return to the terminal for details."
	}
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Command-line sign-in</title></head><body><p>%s</p></body></html>`, text)
}

func exchange(ctx context.Context, server, code, verifier string) (Credentials, error) {
	var out struct {
		Token    string     `json:"token"`
		Deadline time.Time  `json:"deadline"`
		User     users.User `json:"user"`
	}
	if err := call(ctx, http.MethodPost, server+"/auth/cli/token", "", map[string]string{"code": code, "verifier": verifier}, &out); err != nil {
		return Credentials{}, fmt.Errorf("exchange sign-in code: %w", err)
	}
	return Credentials{Server: server, Token: out.Token, Deadline: out.Deadline, User: out.User}, nil
}

// call sends JSON and decodes the JSON answer. A 401 is ErrSignedOut.
func call(ctx context.Context, method, u, token string, in, out any) error {
	var body bytes.Buffer
	if in != nil {
		if err := json.NewEncoder(&body).Encode(in); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, u, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized {
		return ErrSignedOut
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("%s %s: %s %s", method, u, resp.Status, e.Error)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// DefaultPath is where the client keeps its credentials.
func DefaultPath(app string) (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, app, "session.json"), nil
}

// Save writes c readable only by the current user.
func Save(path string, c Credentials) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(path, b, 0o600)
}

func Load(path string) (Credentials, error) {
	var c Credentials
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, ErrSignedOut
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if !time.Now().Before(c.Deadline) {
		return c, ErrSignedOut
	}
	return c, nil
}

type connectToken struct {
	Token       string `json:"token"`
	InboxPrefix string `json:"inbox_prefix"`
}

// Connect opens a NATS connection as the signed-in user. natsURL may be
// empty to use the server the app advertises to browsers.
func (c Credentials) Connect(ctx context.Context, natsURL string, opts ...nats.Option) (*nats.Conn, error) {
	var cfg struct {
		NATS struct {
			Servers  []string `json:"servers"`
			Sentinel string   `json:"sentinel"`
		} `json:"nats"`
	}
	if err := call(ctx, http.MethodGet, c.Server+"/auth/config", "", nil, &cfg); err != nil {
		return nil, err
	}
	if natsURL == "" {
		natsURL = strings.Join(cfg.NATS.Servers, ",")
	}
	var first connectToken
	if err := call(ctx, http.MethodPost, c.Server+"/auth/connect-token", c.Token, nil, &first); err != nil {
		return nil, err
	}
	token := func() string {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var t connectToken
		if err := call(ctx, http.MethodPost, c.Server+"/auth/connect-token", c.Token, nil, &t); err != nil {
			return "invalid"
		}
		return t.Token
	}
	used := false
	base := []nats.Option{
		natsauth.Sentinel(cfg.NATS.Sentinel),
		nats.TokenHandler(func() string {
			if !used {
				used = true
				return first.Token
			}
			return token()
		}),
		nats.CustomInboxPrefix(first.InboxPrefix),
		nats.Name("cli:" + c.User.Username),
	}
	return nats.Connect(natsURL, append(base, opts...)...)
}

// Logout ends the session on the server.
func (c Credentials) Logout(ctx context.Context) error {
	err := call(ctx, http.MethodPost, c.Server+"/auth/logout", c.Token, nil, nil)
	if errors.Is(err, ErrSignedOut) {
		return nil
	}
	return err
}
