package htmlui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"{{ cookiecutter.go_module_path }}/internal/app"
	"{{ cookiecutter.go_module_path }}/internal/config"
	"{{ cookiecutter.go_module_path }}/internal/users"
)

func testApp(t *testing.T, dir string) (*app.App, *UI, http.Handler) {
	t.Helper()
	a, err := app.Start(context.Background(), config.Config{
		Env: "test", PublicURL: "http://localhost", DataDir: dir, EmbeddedNATS: true, NATSPort: -1,
		Replicas: 1, SessionTTL: time.Hour, ConnectTTL: time.Minute, UserJWTTTL: 15 * time.Minute, RefreshMargin: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	ui, _ := New(a)
	mux := http.NewServeMux()
	csrf := http.NewCrossOriginProtection()
	a.HTTP.Routes(mux, csrf)
	ui.Routes(mux, csrf)
	return a, ui, mux
}

func do(h http.Handler, method, path, cookie string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Datastar-Request", "true")
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: "session", Value: cookie})
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func (u *UI) open() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.conns)
}

// TestSessionConnection covers what the Datastar frontend owns: a per-session
// user connection that comes back after a restart, renders only that user's
// notes, and goes away on logout or when the user is disabled.
func TestSessionConnection(t *testing.T) {
	dir := t.TempDir()
	a, ui, h := testApp(t, dir)
	ctx := context.Background()
	for _, n := range []string{"alice", "bob"} {
		if _, err := a.Auth.Users.Create(ctx, n, "correct horse battery", users.RoleMember); err != nil {
			t.Fatal(err)
		}
	}
	login := func(h http.Handler, name string) string {
		w := do(h, "POST", "/ui/login", "", url.Values{"username": {name}, "password": {"correct horse battery"}})
		for _, c := range w.Result().Cookies() {
			if c.Name == "session" && c.Value != "" {
				return c.Value
			}
		}
		t.Fatalf("%s: no session cookie: %s", name, w.Body)
		return ""
	}
	alice := login(h, "alice")
	w := do(h, "POST", "/ui/notes", alice, url.Values{"request_id": {"alice-note-1"}, "title": {"alice private"}})
	if !strings.Contains(w.Body.String(), "alice private") {
		t.Fatalf("create note: %s", w.Body)
	}
	if ui.open() != 1 {
		t.Fatalf("open connections = %d", ui.open())
	}

	ui.Close()
	a.Close()
	a, ui, h = testApp(t, dir)
	t.Cleanup(func() { ui.Close(); a.Close() })
	if w := do(h, "GET", "/", alice, nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "alice private") {
		t.Fatalf("after restart: %d %s", w.Code, w.Body)
	}

	bob := login(h, "bob")
	if body := do(h, "GET", "/", bob, nil).Body.String(); strings.Contains(body, "alice private") {
		t.Fatal("bob sees alice's note")
	}
	if ui.open() != 2 {
		t.Fatalf("open connections = %d", ui.open())
	}

	aliceCur, _ := a.Auth.Session(ctx, alice)
	bobCur, _ := a.Auth.Session(ctx, bob)
	ui.mu.Lock()
	bobNC := ui.conns[bobCur.Ref].nc
	ui.mu.Unlock()
	forged := "app.events." + aliceCur.User.ID + ".session." + aliceCur.Record.SessionID
	if err := bobNC.PublishRequest("app.api.whoami", forged, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if ui.open() != 2 {
		t.Fatal("a reply forged onto alice's session subject dropped her connection")
	}

	if w := do(h, "POST", "/logout", alice, url.Values{}); !strings.Contains(w.Body.String(), "/login") {
		t.Fatalf("logout: %s", w.Body)
	}
	if w := do(h, "GET", "/", alice, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("after logout: %d", w.Code)
	}

	u, _ := a.Auth.Users.ByName(ctx, "bob")
	_, _ = a.Auth.Users.SetDisabled(ctx, u.ID, true)
	_ = a.Service.Publish("app.events."+u.ID+".account", []byte(`{"type":"disabled"}`))
	deadline := time.Now().Add(3 * time.Second)
	for ui.open() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if ui.open() != 0 {
		t.Fatalf("connections left after logout and disable: %d", ui.open())
	}
	if w := do(h, "GET", "/", bob, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("disabled user page: %d", w.Code)
	}
}
