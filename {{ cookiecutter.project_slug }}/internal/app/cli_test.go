package app_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"{{ cookiecutter.go_module_path }}/internal/account"
	"{{ cookiecutter.go_module_path }}/internal/api"
	"{{ cookiecutter.go_module_path }}/internal/app"
	"{{ cookiecutter.go_module_path }}/internal/authn"
	"{{ cookiecutter.go_module_path }}/internal/cliauth"
	"{{ cookiecutter.go_module_path }}/internal/config"
	"{{ cookiecutter.go_module_path }}/internal/oidctest"
	"{{ cookiecutter.go_module_path }}/internal/session"
	"{{ cookiecutter.go_module_path }}/internal/users"
)

// serveHTTP starts the app's HTTP routes on l, or on a new listener.
func serveHTTP(t *testing.T, a *app.App, l net.Listener) string {
	t.Helper()
	mux := http.NewServeMux()
	a.Health(mux)
	a.HTTP.Routes(mux, http.NewCrossOriginProtection())
	srv := httptest.NewUnstartedServer(mux)
	if l != nil {
		_ = srv.Listener.Close()
		srv.Listener = l
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv.URL
}

// browser plays the person at the browser: it opens the sign-in page and
// submits form, following redirects to the provider and the CLI.
func browser(t *testing.T, form url.Values) (func(string) error, *cookiejar.Jar) {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	return func(start string) error {
		go func() {
			resp, err := c.Get(start)
			if err != nil {
				t.Errorf("open sign-in page: %v", err)
				return
			}
			_ = resp.Body.Close()
			u, _ := url.Parse(start)
			f := u.Query()
			for k, v := range form {
				f[k] = v
			}
			u.RawQuery = ""
			resp, err = c.PostForm(u.String(), f)
			if err != nil {
				t.Errorf("submit sign-in page: %v", err)
				return
			}
			_ = resp.Body.Close()
		}()
		return nil
	}, jar
}

func whoami(t *testing.T, a *app.App, c cliauth.Credentials) users.User {
	t.Helper()
	nc, err := c.Connect(context.Background(), a.NATSURL)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	var u users.User
	if err := api.Request(context.Background(), nc, account.SubjectWhoami, nil, &u); err != nil {
		t.Fatal(err)
	}
	return u
}

func cliLogin(t *testing.T, server string, form url.Values) (cliauth.Credentials, *cookiejar.Jar) {
	t.Helper()
	open, jar := browser(t, form)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := cliauth.Login(ctx, server, open)
	if err != nil {
		t.Fatal(err)
	}
	return c, jar
}

func TestCLIPasswordLogin(t *testing.T) {
	a := start(t, testConfig(t.TempDir()))
	server := serveHTTP(t, a, nil)
	login(t, a, "alice")

	c, jar := cliLogin(t, server, url.Values{"method": {"password"}, "username": {"alice"}, "password": {"correct horse battery"}})
	if u := whoami(t, a, c); u.Username != "alice" || c.User.Username != "alice" {
		t.Fatalf("whoami = %+v, credentials user %+v; want alice", u, c.User)
	}
	if left := time.Until(c.Deadline); left < 55*time.Minute || left > time.Hour {
		t.Fatalf("deadline in %s, want the one-hour SESSION_TTL", left)
	}
	su, _ := url.Parse(server)
	if cs := jar.Cookies(su); len(cs) != 0 {
		t.Fatalf("browser cookies %v; the CLI login must not sign the browser in", cs)
	}

	if err := c.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Connect(context.Background(), a.NATSURL); !errors.Is(err, cliauth.ErrSignedOut) {
		t.Fatalf("connect after logout err = %v, want ErrSignedOut", err)
	}
}

func TestCLILoginEndsWithTheUser(t *testing.T) {
	a := start(t, testConfig(t.TempDir()))
	server := serveHTTP(t, a, nil)
	login(t, a, "alice")
	c, _ := cliLogin(t, server, url.Values{"method": {"password"}, "username": {"alice"}, "password": {"correct horse battery"}})

	ctx := context.Background()
	u, err := a.Auth.Users.ByName(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Auth.Users.SetDisabled(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Connect(ctx, a.NATSURL); !errors.Is(err, cliauth.ErrSignedOut) {
		t.Fatalf("connect as a disabled user err = %v, want ErrSignedOut", err)
	}
}

func TestCLICodeNeedsTheVerifierAndWorksOnce(t *testing.T) {
	a := start(t, testConfig(t.TempDir()))
	login(t, a, "alice")
	ctx := context.Background()
	verifier := oauth2.GenerateVerifier()
	issue := func() string {
		t.Helper()
		req, err := authn.ParseCLIRequest("50000", strings.Repeat("s", 32), oauth2.S256ChallengeFromVerifier(verifier))
		if err != nil {
			t.Fatal(err)
		}
		next, err := a.Auth.CLIPassword(ctx, req, "alice", "correct horse battery", "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(next)
		if u.Host != "127.0.0.1:50000" || u.Query().Get("state") != strings.Repeat("s", 32) {
			t.Fatalf("callback = %s, want the CLI's loopback port and state", next)
		}
		return u.Query().Get("code")
	}

	code := issue()
	if _, _, err := a.Auth.CLIExchange(ctx, code, oauth2.GenerateVerifier()); !errors.Is(err, authn.ErrLoginState) {
		t.Fatalf("wrong verifier err = %v, want ErrLoginState", err)
	}
	if _, _, err := a.Auth.CLIExchange(ctx, code, verifier); !errors.Is(err, authn.ErrLoginExpired) {
		t.Fatalf("code after a wrong verifier err = %v, want ErrLoginExpired: a code is tried once", err)
	}

	code = issue()
	if _, cur, err := a.Auth.CLIExchange(ctx, code, verifier); err != nil || cur.User.Username != "alice" {
		t.Fatalf("exchange = %+v, %v", cur, err)
	}
	if _, _, err := a.Auth.CLIExchange(ctx, code, verifier); !errors.Is(err, authn.ErrLoginExpired) {
		t.Fatalf("second exchange err = %v, want ErrLoginExpired", err)
	}

	for _, bad := range [][3]string{
		{"80", strings.Repeat("s", 32), oauth2.S256ChallengeFromVerifier(verifier)},
		{"50000", "short", oauth2.S256ChallengeFromVerifier(verifier)},
		{"50000", strings.Repeat("s", 32), "plain-verifier"},
	} {
		if _, err := authn.ParseCLIRequest(bad[0], bad[1], bad[2]); !errors.Is(err, authn.ErrCLIRequest) {
			t.Errorf("ParseCLIRequest(%q) err = %v, want ErrCLIRequest", bad, err)
		}
	}
}

func TestCLIWrongPasswordStaysOnThePage(t *testing.T) {
	a := start(t, testConfig(t.TempDir()))
	server := serveHTTP(t, a, nil)
	login(t, a, "alice")
	verifier := oauth2.GenerateVerifier()
	form := url.Values{"port": {"50000"}, "state": {strings.Repeat("s", 32)}, "challenge": {oauth2.S256ChallengeFromVerifier(verifier)},
		"method": {"password"}, "username": {"alice"}, "password": {"wrong"}}
	resp, err := http.PostForm(server+"/auth/cli/start", form)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Host != strings.TrimPrefix(server, "http://") || !strings.Contains(string(body), "role=\"alert\"") {
		t.Fatalf("status %d at %s; want the sign-in page again with an error", resp.StatusCode, resp.Request.URL)
	}
	resp, err = http.Get(server + "/auth/cli/start?port=80")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad request status = %d, want 400", resp.StatusCode)
	}
}

func TestCLIOIDCLogin(t *testing.T) {
	p := oidctest.New()
	defer p.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := oidcConfig(t.TempDir(), p)
	cfg.OIDC = &config.OIDC{Issuer: p.Issuer(), ClientID: oidctest.ClientID, RedirectURL: "http://" + l.Addr().String() + "/auth/oidc/callback", AllowHTTP: true}
	a := start(t, cfg)
	server := serveHTTP(t, a, l)
	linkedUser(t, a, "alice", p.Issuer(), "subject-1")

	c, jar := cliLogin(t, server, url.Values{"method": {"oidc"}})
	if u := whoami(t, a, c); u.Username != "alice" {
		t.Fatalf("whoami = %+v, want alice", u)
	}
	cur, err := a.Auth.Session(context.Background(), c.Token)
	if err != nil || cur.Record.Method != session.MethodOIDC || cur.Record.OIDC == nil || cur.Record.OIDC.RefreshToken == "" {
		t.Fatalf("CLI session = %+v, %v; want an OIDC session with its own refresh token", cur.Record, err)
	}
	su, _ := url.Parse(server)
	for _, ck := range jar.Cookies(su) {
		if ck.Name == "session" {
			t.Fatalf("browser got session cookie %v; the CLI login must not sign the browser in", ck)
		}
	}
}
