package authn

import (
	"errors"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"time"

	"{{ cookiecutter.go_module_path }}/internal/users"
)

// CLITokenReply is the answer to POST /auth/cli/token.
type CLITokenReply struct {
	Token    string     `json:"token"`
	Deadline time.Time  `json:"deadline"`
	User     users.User `json:"user"`
}

func cliRequest(r *http.Request) (CLIRequest, error) {
	return ParseCLIRequest(r.FormValue("port"), r.FormValue("state"), r.FormValue("challenge"))
}

// cliPage asks the person at the browser to sign the command-line client
// in. It never approves on its own: a page any local process can open must
// not hand out a session without a click.
func (h *Handler) cliPage(w http.ResponseWriter, r *http.Request) {
	req, err := cliRequest(r)
	if err != nil {
		http.Error(w, ErrCLIRequest.Error(), http.StatusBadRequest)
		return
	}
	h.renderCLI(w, http.StatusOK, req, "")
}

func (h *Handler) cliApprove(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	req, err := cliRequest(r)
	if err != nil {
		http.Error(w, ErrCLIRequest.Error(), http.StatusBadRequest)
		return
	}
	if r.FormValue("method") == "oidc" {
		u, state, err := h.Auth.CLIOIDCStart(r.Context(), req, h.Remote(r))
		if err != nil {
			_, msg := ErrorStatus(err)
			h.renderCLI(w, http.StatusOK, req, msg)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: h.stateCookie(), Value: state, Path: "/", MaxAge: 300, HttpOnly: true, Secure: h.SecureCookie, SameSite: http.SameSiteLaxMode})
		http.Redirect(w, r, u, http.StatusSeeOther)
		return
	}
	next, err := h.Auth.CLIPassword(r.Context(), req, r.FormValue("username"), r.FormValue("password"), h.Remote(r))
	if err != nil {
		_, msg := ErrorStatus(err)
		h.renderCLI(w, http.StatusOK, req, msg)
		return
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (h *Handler) cliToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code     string `json:"code"`
		Verifier string `json:"verifier"`
	}
	if err := decode(r, &in); err != nil {
		writeError(w, validationError{errors.New("invalid request")})
		return
	}
	token, cur, err := h.Auth.CLIExchange(r.Context(), in.Code, in.Verifier)
	switch {
	case errors.Is(err, ErrLoginExpired), errors.Is(err, ErrLoginState):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	case err != nil:
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, CLITokenReply{Token: token, Deadline: cur.Record.Deadline, User: cur.User})
}

func (h *Handler) renderCLI(w http.ResponseWriter, status int, req CLIRequest, problem string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	hidden := fmt.Sprintf(`<input type="hidden" name="port" value="%d"><input type="hidden" name="state" value="%s"><input type="hidden" name="challenge" value="%s">`,
		req.Port, html.EscapeString(req.State), html.EscapeString(req.Challenge))
	var msg, sso string
	if problem != "" {
		msg = `<p role="alert">` + html.EscapeString(problem) + `</p>`
	}
	if h.Auth.OIDC != nil {
		sso = `<form method="post" action="/auth/cli/start">` + hidden +
			`<input type="hidden" name="method" value="oidc"><button>Continue with single sign-on</button></form><p>or use a password:</p>`
	}
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Sign in the command-line client</title></head><body>
<h1>Sign in the command-line client</h1>
<p>A command-line client on this computer, listening on port %s, asked to sign in. Continue only if you started it.</p>
%s%s
<form method="post" action="/auth/cli/start">%s<input type="hidden" name="method" value="password">
<label>Username <input name="username" autocomplete="username" required></label>
<label>Password <input name="password" type="password" autocomplete="current-password" required></label>
<button>Sign in</button></form>
</body></html>`, strconv.Itoa(req.Port), msg, sso, hidden)
}
