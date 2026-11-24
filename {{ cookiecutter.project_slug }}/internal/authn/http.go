package authn

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"{{ cookiecutter.go_module_path }}/internal/session"
	"{{ cookiecutter.go_module_path }}/internal/users"
)

// NATSConfig is the public browser connection data. The sentinel is a
// bearer JWT that may do nothing; the auth callout decides the rest.
type NATSConfig struct {
	Servers  []string `json:"servers"`
	Sentinel string   `json:"sentinel"`
}

type Handler struct {
	Auth         *Service
	SecureCookie bool
	NATS         NATSConfig
	// TrustedProxies are the reverse proxies whose X-Forwarded-For is read.
	TrustedProxies []netip.Prefix
}

func (h *Handler) CookieName() string {
	if h.SecureCookie {
		return "__Host-session"
	}
	return "session"
}

func (h *Handler) stateCookie() string {
	if h.SecureCookie {
		return "__Host-oidc_state"
	}
	return "oidc_state"
}

// SessionToken reads the session cookie, or a bearer token, which the
// command-line client sends.
func (h *Handler) SessionToken(r *http.Request) string {
	if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return tok
	}
	c, err := r.Cookie(h.CookieName())
	if err != nil {
		return ""
	}
	return c.Value
}

func (h *Handler) SetSession(w http.ResponseWriter, token string, deadline time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: h.CookieName(), Value: token, Path: "/", Expires: deadline,
		MaxAge: int(time.Until(deadline).Seconds()), HttpOnly: true, Secure: h.SecureCookie, SameSite: http.SameSiteLaxMode,
	})
}

func (h *Handler) ClearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: h.CookieName(), Path: "/", MaxAge: -1, HttpOnly: true, Secure: h.SecureCookie, SameSite: http.SameSiteLaxMode})
}

// StartSession replaces any session the browser had with the new one.
func (h *Handler) StartSession(w http.ResponseWriter, r *http.Request, token string, c Current) {
	if old := h.SessionToken(r); old != "" && old != token {
		h.Auth.Logout(r.Context(), old)
	}
	h.SetSession(w, token, c.Record.Deadline)
}

// Remote is the client address used for login throttling. X-Forwarded-For
// is read only when the peer is a configured trusted proxy, from the right,
// skipping the trusted hops; a client can prepend any value to the header.
func (h *Handler) Remote(r *http.Request) string {
	addr, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	ip := addr.Addr().Unmap()
	if !h.trusted(ip) {
		return ip.String()
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		if ip = hop.Unmap(); !h.trusted(ip) {
			break
		}
	}
	return ip.String()
}

func (h *Handler) trusted(ip netip.Addr) bool {
	for _, p := range h.TrustedProxies {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Routes adds the authentication endpoints. Every state-changing route
// rejects cross-origin browser requests.
func (h *Handler) Routes(mux *http.ServeMux, csrf *http.CrossOriginProtection) {
	mux.HandleFunc("GET /auth/config", h.config)
	mux.Handle("POST /auth/setup", csrf.Handler(http.HandlerFunc(h.setup)))
	mux.Handle("POST /auth/login", csrf.Handler(http.HandlerFunc(h.login)))
	mux.Handle("POST /auth/logout", csrf.Handler(http.HandlerFunc(h.logout)))
	mux.HandleFunc("GET /auth/session", h.session)
	mux.Handle("POST /auth/connect-token", csrf.Handler(http.HandlerFunc(h.connectToken)))
	mux.HandleFunc("GET /auth/oidc/start", h.oidcStart)
	mux.HandleFunc("GET /auth/oidc/callback", h.oidcCallback)
	mux.HandleFunc("GET /auth/cli/start", h.cliPage)
	mux.Handle("POST /auth/cli/start", csrf.Handler(http.HandlerFunc(h.cliApprove)))
	mux.Handle("POST /auth/cli/token", csrf.Handler(http.HandlerFunc(h.cliToken)))
}

type SessionView struct {
	User     users.User `json:"user"`
	Method   string     `json:"method"`
	Deadline time.Time  `json:"deadline"`
	ID       string     `json:"session_id"`
}

func View(c Current) SessionView {
	return SessionView{User: c.User, Method: c.Record.Method, Deadline: c.Record.Deadline, ID: c.Record.SessionID}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	status, msg := ErrorStatus(err)
	writeJSON(w, status, map[string]string{"error": msg})
}

// ErrorStatus maps a service error to a status and a message that is safe
// to show.
func ErrorStatus(err error) (int, string) {
	switch {
	case errors.Is(err, ErrUnauthenticated):
		return http.StatusUnauthorized, ErrUnauthenticated.Error()
	case errors.Is(err, users.ErrBadLogin):
		return http.StatusUnauthorized, users.ErrBadLogin.Error()
	case errors.Is(err, users.ErrSetup):
		return http.StatusForbidden, users.ErrSetup.Error()
	case errors.Is(err, ErrThrottled):
		return http.StatusTooManyRequests, ErrThrottled.Error()
	case errors.Is(err, ErrUnavailable):
		return http.StatusServiceUnavailable, ErrUnavailable.Error()
	case errors.Is(err, ErrOIDCDisabled):
		return http.StatusNotFound, ErrOIDCDisabled.Error()
	}
	var ve validationError
	if errors.As(err, &ve) {
		return http.StatusBadRequest, ve.Error()
	}
	slog.Error("auth request failed", "error", err)
	return http.StatusInternalServerError, "internal error"
}

type validationError struct{ error }

func (h *Handler) config(w http.ResponseWriter, r *http.Request) {
	setup, err := h.Auth.Users.SetupRequired(r.Context())
	if err != nil {
		writeError(w, errors.Join(ErrUnavailable, err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"setup_required": setup, "oidc": h.Auth.OIDC != nil, "nats": h.NATS})
}

type credentials struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func decode(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 16<<10)
	return json.NewDecoder(r.Body).Decode(v)
}

func (h *Handler) setup(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if err := decode(r, &c); err != nil {
		writeError(w, validationError{errors.New("invalid request")})
		return
	}
	token, cur, err := h.Auth.Setup(r.Context(), c.Token, c.Username, c.Password, h.Remote(r))
	if err != nil {
		if !errors.Is(err, users.ErrSetup) && !errors.Is(err, ErrThrottled) && !errors.Is(err, ErrUnavailable) {
			err = validationError{err}
		}
		writeError(w, err)
		return
	}
	h.StartSession(w, r, token, cur)
	writeJSON(w, http.StatusOK, View(cur))
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if err := decode(r, &c); err != nil {
		writeError(w, validationError{errors.New("invalid request")})
		return
	}
	token, cur, err := h.Auth.Login(r.Context(), c.Username, c.Password, h.Remote(r))
	if err != nil {
		writeError(w, err)
		return
	}
	h.StartSession(w, r, token, cur)
	writeJSON(w, http.StatusOK, View(cur))
}

// logout answers JSON clients with 204 and form posts with a redirect.
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	h.Auth.Logout(r.Context(), h.SessionToken(r))
	h.ClearSession(w)
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("Content-Type") == "application/json" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) session(w http.ResponseWriter, r *http.Request) {
	cur, err := h.Auth.Session(r.Context(), h.SessionToken(r))
	if errors.Is(err, ErrUnauthenticated) {
		h.ClearSession(w)
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, View(cur))
}

func (h *Handler) connectToken(w http.ResponseWriter, r *http.Request) {
	tok := h.SessionToken(r)
	if tok == "" {
		writeError(w, ErrUnauthenticated)
		return
	}
	ct, cur, exp, err := h.Auth.ConnectToken(r.Context(), session.Ref(tok))
	if errors.Is(err, ErrUnauthenticated) {
		h.ClearSession(w)
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token": ct, "inbox_prefix": cur.Record.InboxPrefix(), "expires": exp,
		"user": cur.User, "session_id": cur.Record.SessionID,
	})
}

func (h *Handler) oidcStart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	u, state, err := h.Auth.OIDCStart(r.Context(), r.URL.Query().Get("redirect"), h.Remote(r))
	if err != nil {
		status, _ := ErrorStatus(err)
		if status == http.StatusNotFound {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/login?error=unavailable", http.StatusSeeOther)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: h.stateCookie(), Value: state, Path: "/", MaxAge: 300, HttpOnly: true, Secure: h.SecureCookie, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, u, http.StatusSeeOther)
}

func (h *Handler) oidcCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	var browserState string
	if c, err := r.Cookie(h.stateCookie()); err == nil {
		browserState = c.Value
	}
	http.SetCookie(w, &http.Cookie{Name: h.stateCookie(), Path: "/", MaxAge: -1, HttpOnly: true, Secure: h.SecureCookie, SameSite: http.SameSiteLaxMode})
	q := r.URL.Query()
	if q.Get("error") != "" {
		http.Redirect(w, r, "/login?error=refused", http.StatusSeeOther)
		return
	}
	token, cur, redirect, err := h.Auth.OIDCCallback(r.Context(), browserState, q.Get("state"), q.Get("code"))
	if err != nil {
		code := "refused"
		switch {
		case errors.Is(err, ErrLoginState):
			code = "state"
		case errors.Is(err, ErrLoginExpired):
			code = "expired"
		case errors.Is(err, ErrUnbound):
			code = "unbound"
		case errors.Is(err, ErrUnavailable):
			code = "unavailable"
		}
		http.Redirect(w, r, "/login?error="+url.QueryEscape(code), http.StatusSeeOther)
		return
	}
	if token != "" {
		h.StartSession(w, r, token, cur)
	}
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}
