package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"{{ cookiecutter.go_module_path }}/internal/api"
	"{{ cookiecutter.go_module_path }}/internal/app"
	"{{ cookiecutter.go_module_path }}/internal/authn"
	"{{ cookiecutter.go_module_path }}/internal/config"
	"{{ cookiecutter.go_module_path }}/internal/natsauth"
	"{{ cookiecutter.go_module_path }}/internal/notes"
	"{{ cookiecutter.go_module_path }}/internal/users"
)

func testConfig(dir string) config.Config {
	return config.Config{
		Env: "test", PublicURL: "http://localhost", DataDir: dir, EmbeddedNATS: true,
		NATSPort: -1, Replicas: 1, SessionTTL: time.Hour, ConnectTTL: time.Minute,
		UserJWTTTL: 15 * time.Minute, RefreshMargin: time.Minute,
	}
}

func start(t *testing.T, cfg config.Config) *app.App {
	t.Helper()
	a, err := app.Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

type signedIn struct {
	token string
	cur   authn.Current
}

func login(t *testing.T, a *app.App, name string) signedIn {
	t.Helper()
	ctx := context.Background()
	if _, err := a.Auth.Users.ByName(ctx, name); errors.Is(err, users.ErrNotFound) {
		if _, err := a.Auth.Users.Create(ctx, name, "correct horse battery", users.RoleMember); err != nil {
			t.Fatal(err)
		}
	}
	tok, cur, err := a.Auth.Login(ctx, name, "correct horse battery", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return signedIn{tok, cur}
}

// browserConnect does what the React client does: sentinel plus a connect
// token from the HTTP endpoint, and the session's inbox prefix.
func browserConnect(a *app.App, connectToken, inbox string) (*nats.Conn, error) {
	return nats.Connect(a.NATSURL, natsauth.Sentinel(a.Runtime.Sentinel), nats.Token(connectToken),
		nats.CustomInboxPrefix(inbox), nats.MaxReconnects(0))
}

func connect(t *testing.T, a *app.App, s signedIn) *nats.Conn {
	t.Helper()
	ct, cur, _, err := a.Auth.ConnectToken(context.Background(), s.cur.Ref)
	if err != nil {
		t.Fatal(err)
	}
	nc, err := browserConnect(a, ct, cur.Record.InboxPrefix())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func createNote(ctx context.Context, nc *nats.Conn, id, title string) (notes.CreateReply, error) {
	var out notes.CreateReply
	err := api.Request(ctx, nc, notes.SubjectCreate, notes.CreateRequest{RequestID: id, Title: title}, &out)
	return out, err
}

func listNotes(t *testing.T, nc *nats.Conn) []notes.Note {
	t.Helper()
	var out notes.ListReply
	if err := api.Request(context.Background(), nc, notes.SubjectList, nil, &out); err != nil {
		t.Fatal(err)
	}
	return out.Notes
}

func permissionDenied(t *testing.T, nc *nats.Conn) <-chan error {
	errs := make(chan error, 16)
	nc.SetErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { errs <- err })
	return errs
}

func expectDenied(t *testing.T, errs <-chan error, what string) {
	t.Helper()
	select {
	case err := <-errs:
		if !errors.Is(err, nats.ErrPermissionViolation) {
			t.Fatalf("%s: want a permission violation, got %v", what, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("%s: server allowed it", what)
	}
}

func TestAdmissionAndIsolation(t *testing.T) {
	a := start(t, testConfig(t.TempDir()))
	ctx := context.Background()
	alice, bob := login(t, a, "alice"), login(t, a, "bob")
	anc, bnc := connect(t, a, alice), connect(t, a, bob)

	var who users.User
	if err := api.Request(ctx, anc, "app.api.whoami", nil, &who); err != nil || who.Username != "alice" {
		t.Fatalf("whoami = %+v, %v", who, err)
	}

	bobEvents, err := bnc.SubscribeSync(notes.EventSubject(bob.cur.User.ID))
	if err != nil {
		t.Fatal(err)
	}
	_ = bnc.Flush()
	if _, err := createNote(ctx, anc, "alice-note-1", "alice secret"); err != nil {
		t.Fatal(err)
	}
	if n := listNotes(t, anc); len(n) != 1 || n[0].Title != "alice secret" {
		t.Fatalf("alice notes = %+v", n)
	}
	if n := listNotes(t, bnc); len(n) != 0 {
		t.Fatalf("bob sees %+v", n)
	}
	if _, err := bobEvents.NextMsg(300 * time.Millisecond); !errors.Is(err, nats.ErrTimeout) {
		t.Fatalf("bob got alice's event: %v", err)
	}

	t.Run("same request id is idempotent", func(t *testing.T) {
		r, err := createNote(ctx, anc, "alice-note-1", "alice secret")
		if err != nil || !r.Duplicate {
			t.Fatalf("resend = %+v, %v", r, err)
		}
		var e *api.Error
		if _, err := createNote(ctx, anc, "alice-note-1", "other"); !errors.As(err, &e) || e.Code != api.CodeConflict {
			t.Fatalf("reuse with other content = %v", err)
		}
	})

	t.Run("spoofed caller header is replaced", func(t *testing.T) {
		ci, _ := json.Marshal(server.ClientInfo{Account: a.Runtime.UsersAccount, NameTag: alice.cur.User.ID})
		m := nats.NewMsg(notes.SubjectList)
		m.Header.Set(server.ClientInfoHdr, string(ci))
		r, err := bnc.RequestMsg(m, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		var out notes.ListReply
		_ = json.Unmarshal(r.Data, &out)
		if len(out.Notes) != 0 {
			t.Fatalf("spoofed header read alice's notes: %+v", out.Notes)
		}
	})

	t.Run("foreign events, inboxes and protected buckets are denied", func(t *testing.T) {
		errs := permissionDenied(t, bnc)
		if _, err := bnc.SubscribeSync(notes.EventSubject(alice.cur.User.ID)); err != nil {
			t.Fatal(err)
		}
		expectDenied(t, errs, "subscribe to another user's events")
		if _, err := bnc.SubscribeSync(alice.cur.Record.InboxPrefix() + ".>"); err != nil {
			t.Fatal(err)
		}
		expectDenied(t, errs, "subscribe to another session's inbox")
		if _, err := bnc.SubscribeSync("_INBOX.>"); err != nil {
			t.Fatal(err)
		}
		expectDenied(t, errs, "subscribe to the default inbox")
		for _, subj := range []string{
			"$JS.API.STREAM.INFO.KV_app_sessions", "$JS.API.DIRECT.GET.KV_app_users",
			"$KV.app_notes." + alice.cur.User.ID + ".x", "app.events." + alice.cur.User.ID + ".notes",
			"$SYS.REQ.USER.AUTH", "app.api.admin.users.list",
		} {
			_ = bnc.Publish(subj, []byte("{}"))
			expectDenied(t, errs, "publish "+subj)
		}
	})

	t.Run("admission is refused", func(t *testing.T) {
		good, _, _, _ := a.Auth.ConnectToken(ctx, alice.cur.Ref)
		other := a.Auth.Sessions.MintConnectToken(alice.cur.Ref, time.Now().Add(-time.Second))
		cases := map[string]func() (*nats.Conn, error){
			"sentinel alone": func() (*nats.Conn, error) {
				return nats.Connect(a.NATSURL, natsauth.Sentinel(a.Runtime.Sentinel), nats.MaxReconnects(0))
			},
			"wrong token":   func() (*nats.Conn, error) { return browserConnect(a, good[:len(good)-2]+"xx", "_INBOX_x") },
			"expired token": func() (*nats.Conn, error) { return browserConnect(a, other, "_INBOX_x") },
			"no sentinel":   func() (*nats.Conn, error) { return nats.Connect(a.NATSURL, nats.Token(good), nats.MaxReconnects(0)) },
		}
		for name, f := range cases {
			if nc, err := f(); err == nil {
				nc.Close()
				t.Errorf("%s: admitted", name)
			}
		}
	})

	t.Run("deleted session and disabled user are refused", func(t *testing.T) {
		carol := login(t, a, "carol")
		ct, _, _, err := a.Auth.ConnectToken(ctx, carol.cur.Ref)
		if err != nil {
			t.Fatal(err)
		}
		a.Auth.Logout(ctx, carol.token)
		if nc, err := browserConnect(a, ct, "_INBOX_x"); err == nil {
			nc.Close()
			t.Fatal("deleted session admitted")
		}
		dave := login(t, a, "dave")
		ct, _, _, _ = a.Auth.ConnectToken(ctx, dave.cur.Ref)
		if _, err := a.Auth.Users.SetDisabled(ctx, dave.cur.User.ID, true); err != nil {
			t.Fatal(err)
		}
		if nc, err := browserConnect(a, ct, "_INBOX_x"); err == nil {
			nc.Close()
			t.Fatal("disabled user admitted")
		}
		if _, _, _, err := a.Auth.ConnectToken(ctx, dave.cur.Ref); !errors.Is(err, authn.ErrUnauthenticated) {
			t.Fatalf("disabled user got a connect token: %v", err)
		}
		erin := login(t, a, "erin")
		for _, off := range []bool{true, false} {
			if _, err := a.Auth.Users.SetDisabled(ctx, erin.cur.User.ID, off); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, _, err := a.Auth.ConnectToken(ctx, erin.cur.Ref); !errors.Is(err, authn.ErrUnauthenticated) {
			t.Fatalf("re-enabled user's old session got a connect token: %v", err)
		}
	})
}

// TestSessionSurvivesRestart restarts the whole process state: the same
// data directory gives the same keys and the stored session.
func TestSessionSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	a, err := app.Start(context.Background(), testConfig(dir))
	if err != nil {
		t.Fatal(err)
	}
	s := login(t, a, "alice")
	a.Close()

	b := start(t, testConfig(dir))
	cur, err := b.Auth.Session(context.Background(), s.token)
	if err != nil || cur.User.Username != "alice" {
		t.Fatalf("session after restart = %+v, %v", cur, err)
	}
	nc := connect(t, b, signedIn{s.token, cur})
	if _, err := createNote(context.Background(), nc, "after-restart", "kept"); err != nil {
		t.Fatal(err)
	}
}

// TestUserJWTExpiryReconnects proves that a session connection outlives its
// short user JWT by reconnecting with a new connect token, and stops when the
// session ends.
func TestUserJWTExpiryReconnects(t *testing.T) {
	cfg := testConfig(t.TempDir())
	cfg.UserJWTTTL = 2 * time.Second
	a := start(t, cfg)
	s := login(t, a, "alice")
	ended := make(chan struct{}, 1)
	reconnected := make(chan struct{}, 4)
	nc, err := a.DialSession(s.cur.Ref, func() { ended <- struct{}{} },
		nats.ReconnectHandler(func(*nats.Conn) { reconnected <- struct{}{} }))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	select {
	case <-reconnected:
	case <-time.After(10 * time.Second):
		t.Fatal("no reconnect after the user JWT expired")
	}
	if _, err := createNote(context.Background(), nc, "after-expiry", "still here"); err != nil {
		t.Fatalf("request after JWT renewal: %v", err)
	}
	a.Auth.Logout(context.Background(), s.token)
	select {
	case <-ended:
	case <-time.After(10 * time.Second):
		t.Fatal("ended was not reported after logout and JWT expiry")
	}
}

func TestSessionDeadlineBoundsJWT(t *testing.T) {
	cfg := testConfig(t.TempDir())
	cfg.SessionTTL = 3 * time.Second
	a := start(t, cfg)
	s := login(t, a, "alice")
	nc := connect(t, a, s)
	closed := make(chan error, 1)
	nc.SetErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { closed <- err })
	select {
	case err := <-closed:
		if !app.AuthError(err) {
			t.Fatalf("disconnect reason = %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("connection outlived the session deadline")
	}
	if _, _, _, err := a.Auth.ConnectToken(context.Background(), s.cur.Ref); !errors.Is(err, authn.ErrUnauthenticated) {
		t.Fatalf("expired session got a connect token: %v", err)
	}
}
