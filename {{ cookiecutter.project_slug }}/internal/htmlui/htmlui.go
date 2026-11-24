// Package htmlui is the Datastar frontend. The server renders HTML and SSE.
// Each web session owns one NATS connection as its own user, admitted through
// the auth callout with an internally minted connect token. Every
// application operation uses that connection; the privileged service
// connection is never a fallback.
package htmlui

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/a-h/templ"
	"github.com/nats-io/nats.go"
	"github.com/starfederation/datastar-go/datastar"
	"golang.org/x/sync/singleflight"

	"{{ cookiecutter.go_module_path }}/internal/account"
	"{{ cookiecutter.go_module_path }}/internal/api"
	"{{ cookiecutter.go_module_path }}/internal/app"
	"{{ cookiecutter.go_module_path }}/internal/authn"
	"{{ cookiecutter.go_module_path }}/internal/notes"
	"{{ cookiecutter.go_module_path }}/internal/users"
)

//go:embed static
var static embed.FS

const requestTimeout = 5 * time.Second

type UI struct {
	a *app.App

	mu      sync.Mutex
	conns   map[string]*userConn
	opening singleflight.Group
}

// userConn is one web session's NATS connection. done closes when the
// connection ends for good.
type userConn struct {
	nc   *nats.Conn
	done chan struct{}
	once sync.Once
}

func New(a *app.App) (*UI, error) {
	return &UI{a: a, conns: map[string]*userConn{}}, nil
}

func (u *UI) Routes(mux *http.ServeMux, csrf *http.CrossOriginProtection) {
	mux.Handle("GET /static/", http.FileServerFS(static))
	mux.HandleFunc("GET /{$}", u.notesPage)
	mux.HandleFunc("GET /login", u.loginPage)
	mux.HandleFunc("GET /setup", u.setupPage)
	mux.HandleFunc("GET /admin", u.adminPage)
	mux.HandleFunc("GET /ui/notes/live", u.live)
	post := func(pattern string, h http.HandlerFunc) { mux.Handle("POST "+pattern, csrf.Handler(h)) }
	post("/ui/login", u.login)
	post("/ui/setup", u.setup)
	post("/logout", u.logout)
	post("/ui/notes", u.createNote)
	post("/ui/admin/users", u.createUser)
	post("/ui/admin/users/{id}", u.updateUser)
}

// Close ends every session connection. The durable sessions stay, so a new
// process opens them again.
func (u *UI) Close() {
	u.mu.Lock()
	refs := make([]string, 0, len(u.conns))
	for ref := range u.conns {
		refs = append(refs, ref)
	}
	u.mu.Unlock()
	for _, ref := range refs {
		u.drop(ref)
	}
}

func (u *UI) drop(ref string) {
	u.mu.Lock()
	c := u.conns[ref]
	delete(u.conns, ref)
	u.mu.Unlock()
	if c != nil {
		c.once.Do(func() { close(c.done) })
		c.nc.Close()
	}
}

// conn returns the session's connection, and opens it when this process does
// not have it, such as after a restart or on another replica.
func (u *UI) conn(cur authn.Current) (*userConn, error) {
	u.mu.Lock()
	c := u.conns[cur.Ref]
	u.mu.Unlock()
	if c != nil && !c.nc.IsClosed() {
		return c, nil
	}
	v, err, _ := u.opening.Do(cur.Ref, func() (any, error) {
		ref := cur.Ref
		nc, _, err := u.a.DialSession(ref, func() { go u.drop(ref) },
			nats.ClosedHandler(func(*nats.Conn) { go u.drop(ref) }))
		if err != nil {
			return nil, err
		}
		c := &userConn{nc: nc, done: make(chan struct{})}
		end := func(*nats.Msg) { go u.drop(ref) }
		for _, subj := range []string{
			authn.SessionEventSubject(cur.User.ID, cur.Record.SessionID),
			authn.AccountEventSubject(cur.User.ID),
		} {
			if _, err := nc.Subscribe(subj, end); err != nil {
				nc.Close()
				return nil, err
			}
		}
		u.mu.Lock()
		u.conns[ref] = c
		u.mu.Unlock()
		return c, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*userConn), nil
}

func isDatastar(r *http.Request) bool { return r.Header.Get("Datastar-Request") == "true" }

// go sends the browser to path, by redirect or by SSE for a Datastar request.
func goTo(w http.ResponseWriter, r *http.Request, path string) {
	if isDatastar(r) {
		_ = datastar.NewSSE(w, r).Redirect(path)
		return
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

func unavailable(w http.ResponseWriter, r *http.Request) {
	if isDatastar(r) {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	http.Error(w, "Temporarily unavailable. Reload the page to try again.", http.StatusServiceUnavailable)
}

// require checks the session and returns its user connection. It answers
// the request itself when it returns false.
func (u *UI) require(w http.ResponseWriter, r *http.Request) (authn.Current, *userConn, bool) {
	cur, err := u.a.Auth.Session(r.Context(), u.a.HTTP.SessionToken(r))
	if errors.Is(err, authn.ErrUnauthenticated) {
		u.a.HTTP.ClearSession(w)
		goTo(w, r, "/login")
		return cur, nil, false
	}
	if err != nil {
		unavailable(w, r)
		return cur, nil, false
	}
	c, err := u.conn(cur)
	if err != nil {
		slog.Warn("open session connection", "user", cur.User.ID, "error", err)
		if app.AuthError(err) || errors.Is(err, authn.ErrUnauthenticated) {
			goTo(w, r, "/login")
		} else {
			unavailable(w, r)
		}
		return cur, nil, false
	}
	return cur, c, true
}

func viewer(cur authn.Current) Viewer {
	return Viewer{Username: cur.User.Username, Role: cur.User.Role, Method: cur.Record.Method}
}

func render(w http.ResponseWriter, r *http.Request, c templ.Component) {
	w.Header().Set("Cache-Control", "no-store")
	if err := c.Render(r.Context(), w); err != nil {
		slog.Error("render", "error", err)
	}
}

func patch(sse *datastar.ServerSentEventGenerator, c templ.Component, opts ...datastar.PatchElementOption) {
	if err := sse.PatchElementTempl(c, opts...); err != nil {
		slog.Debug("patch", "error", err)
	}
}

func newRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func errorMessage(err error) string {
	var e *api.Error
	switch {
	case errors.As(err, &e):
		return e.Message
	case errors.Is(err, nats.ErrNoResponders):
		return "The service is not running. Try again soon."
	case errors.Is(err, nats.ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		return "No reply in time."
	case errors.Is(err, nats.ErrPermissionViolation):
		return "Permission denied."
	}
	return "Request failed. Try again."
}

var loginErrors = map[string]string{
	"refused":     "The identity provider login failed.",
	"state":       "The login state did not match. Start again.",
	"expired":     "The login took too long or was already used. Start again.",
	"unbound":     "This identity is not linked to an active user. Ask an admin to link it.",
	"unavailable": "Sign-in is temporarily unavailable.",
}

func (u *UI) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, err := u.a.Auth.Session(r.Context(), u.a.HTTP.SessionToken(r)); err == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	setup, _ := u.a.Auth.Users.SetupRequired(r.Context())
	render(w, r, LoginPage(LoginView{OIDC: u.a.Auth.OIDC != nil, Setup: setup, Error: loginErrors[r.URL.Query().Get("error")]}))
}

func (u *UI) setupPage(w http.ResponseWriter, r *http.Request) {
	if setup, err := u.a.Auth.Users.SetupRequired(r.Context()); err == nil && !setup {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	render(w, r, SetupPage())
}

func (u *UI) login(w http.ResponseWriter, r *http.Request) {
	token, cur, err := u.a.Auth.Login(r.Context(), r.FormValue("username"), r.FormValue("password"), authn.Remote(r))
	u.finishLogin(w, r, token, cur, err)
}

func (u *UI) setup(w http.ResponseWriter, r *http.Request) {
	token, cur, err := u.a.Auth.Setup(r.Context(), r.FormValue("token"), r.FormValue("username"), r.FormValue("password"), authn.Remote(r))
	if err != nil && !errors.Is(err, users.ErrSetup) && !errors.Is(err, authn.ErrThrottled) && !errors.Is(err, authn.ErrUnavailable) {
		patch(datastar.NewSSE(w, r), loginError(err.Error()))
		return
	}
	u.finishLogin(w, r, token, cur, err)
}

func (u *UI) finishLogin(w http.ResponseWriter, r *http.Request, token string, cur authn.Current, err error) {
	if err != nil {
		_, msg := authn.ErrorStatus(err)
		patch(datastar.NewSSE(w, r), loginError(msg))
		return
	}
	if old := u.a.HTTP.SessionToken(r); old != "" {
		if prev, err := u.a.Auth.Session(r.Context(), old); err == nil {
			u.drop(prev.Ref)
		}
	}
	u.a.HTTP.StartSession(w, r, token, cur)
	_ = datastar.NewSSE(w, r).Redirect("/")
}

func (u *UI) logout(w http.ResponseWriter, r *http.Request) {
	if tok := u.a.HTTP.SessionToken(r); tok != "" {
		if cur, err := u.a.Auth.Session(r.Context(), tok); err == nil {
			u.drop(cur.Ref)
		}
		u.a.Auth.Logout(r.Context(), tok)
	}
	u.a.HTTP.ClearSession(w)
	w.Header().Set("Cache-Control", "no-store")
	goTo(w, r, "/login")
}

func listNotes(ctx context.Context, nc *nats.Conn) ([]NoteView, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	var out notes.ListReply
	if err := api.Request(ctx, nc, notes.SubjectList, nil, &out); err != nil {
		return nil, err
	}
	vs := make([]NoteView, len(out.Notes))
	for i, n := range out.Notes {
		vs[i] = NoteView(n)
	}
	return vs, nil
}

func (u *UI) notesPage(w http.ResponseWriter, r *http.Request) {
	cur, c, ok := u.require(w, r)
	if !ok {
		return
	}
	ns, err := listNotes(r.Context(), c.nc)
	if err != nil {
		slog.Warn("list notes", "error", err)
	}
	render(w, r, NotesPage(viewer(cur), ns, newRequestID()))
}

// live streams note changes and connection state to one page. It lists
// again after every event and every reconnect, because events can be lost.
func (u *UI) live(w http.ResponseWriter, r *http.Request) {
	cur, c, ok := u.require(w, r)
	if !ok {
		return
	}
	events := make(chan *nats.Msg, 16)
	sub, err := c.nc.ChanSubscribe(notes.EventSubject(cur.User.ID), events)
	if err != nil {
		unavailable(w, r)
		return
	}
	defer func() { _ = sub.Unsubscribe() }()
	status := c.nc.StatusChanged(nats.CONNECTED, nats.RECONNECTING, nats.DISCONNECTED)
	defer c.nc.RemoveStatusListener(status)

	sse := datastar.NewSSE(w, r)
	refresh := func() {
		ns, err := listNotes(sse.Context(), c.nc)
		if err != nil {
			patch(sse, connState("reconnecting"))
			return
		}
		patch(sse, connState("connected"))
		patch(sse, NoteList(ns))
	}
	refresh()
	check := time.NewTicker(30 * time.Second)
	defer check.Stop()
	token := u.a.HTTP.SessionToken(r)
	for {
		select {
		case <-sse.Context().Done():
			return
		case <-c.done:
			patch(sse, connState("ended"))
			_ = sse.Redirect("/")
			return
		case <-events:
			refresh()
		case st := <-status:
			if st == nats.CONNECTED {
				refresh()
			} else {
				patch(sse, connState("reconnecting"))
			}
		case <-check.C:
			if _, err := u.a.Auth.Session(sse.Context(), token); errors.Is(err, authn.ErrUnauthenticated) {
				u.drop(cur.Ref)
				_ = sse.Redirect("/login")
				return
			}
		}
	}
}

// createNote keeps the request ID when the outcome is unknown, so a resend
// cannot store the note twice.
func (u *UI) createNote(w http.ResponseWriter, r *http.Request) {
	_, c, ok := u.require(w, r)
	if !ok {
		return
	}
	in := notes.CreateRequest{RequestID: r.FormValue("request_id"), Title: r.FormValue("title"), Body: r.FormValue("body")}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	err := api.Request(ctx, c.nc, notes.SubjectCreate, in, &notes.CreateReply{})
	sse := datastar.NewSSE(w, r)
	switch {
	case err == nil:
		patch(sse, noteForm(newRequestID(), "", "", ""))
		if ns, err := listNotes(r.Context(), c.nc); err == nil {
			patch(sse, NoteList(ns))
		}
	case errors.Is(err, nats.ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		patch(sse, noteForm(in.RequestID, in.Title, in.Body,
			"No reply in time. The note may be saved; submit again to retry safely."))
	default:
		patch(sse, noteForm(in.RequestID, in.Title, in.Body, errorMessage(err)))
	}
}

func listUsers(ctx context.Context, nc *nats.Conn) ([]UserView, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	var out account.ListReply
	if err := api.Request(ctx, nc, account.SubjectList, nil, &out); err != nil {
		return nil, err
	}
	vs := make([]UserView, len(out.Users))
	for i, us := range out.Users {
		v := UserView{ID: us.ID, Username: us.Username, Role: us.Role, Disabled: us.Disabled}
		for _, id := range us.Identities {
			v.Identities = append(v.Identities, id.Issuer+" · "+id.Subject)
		}
		vs[i] = v
	}
	return vs, nil
}

// requireAdmin answers early for members. NATS also denies their admin
// requests, but a denied publish only shows as a timeout.
func (u *UI) requireAdmin(w http.ResponseWriter, r *http.Request) (authn.Current, *userConn, bool) {
	cur, c, ok := u.require(w, r)
	if ok && cur.User.Role != users.RoleAdmin {
		http.Error(w, "Admin role required", http.StatusForbidden)
		return cur, nil, false
	}
	return cur, c, ok
}

func (u *UI) adminPage(w http.ResponseWriter, r *http.Request) {
	cur, c, ok := u.requireAdmin(w, r)
	if !ok {
		return
	}
	us, err := listUsers(r.Context(), c.nc)
	if err != nil {
		http.Error(w, errorMessage(err), http.StatusForbidden)
		return
	}
	render(w, r, AdminPage(viewer(cur), us))
}

func (u *UI) adminReply(w http.ResponseWriter, r *http.Request, nc *nats.Conn, err error) {
	msg := ""
	if err != nil {
		msg = errorMessage(err)
	}
	us, lerr := listUsers(r.Context(), nc)
	if lerr != nil {
		msg = errorMessage(lerr)
	}
	patch(datastar.NewSSE(w, r), UserTable(us, msg))
}

func (u *UI) createUser(w http.ResponseWriter, r *http.Request) {
	_, c, ok := u.requireAdmin(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	err := api.Request(ctx, c.nc, account.SubjectCreate, account.CreateRequest{
		Username: r.FormValue("username"), Password: r.FormValue("password"), Role: r.FormValue("role"),
	}, nil)
	u.adminReply(w, r, c.nc, err)
}

func (u *UI) updateUser(w http.ResponseWriter, r *http.Request) {
	_, c, ok := u.requireAdmin(w, r)
	if !ok {
		return
	}
	req := account.UpdateRequest{ID: r.PathValue("id")}
	switch r.FormValue("op") {
	case "disable", "enable":
		d := r.FormValue("op") == "disable"
		req.Disabled = &d
	case "link":
		req.Link = &users.Identity{Issuer: r.FormValue("issuer"), Subject: r.FormValue("subject")}
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	err := api.Request(ctx, c.nc, account.SubjectUpdate, req, nil)
	u.adminReply(w, r, c.nc, err)
}
