// Package callout answers NATS auth callout requests. A client connects with
// the public sentinel JWT and a connect token. The issuer checks the token,
// the stored session and the user, and signs a short user JWT in the USERS
// account with that session's permissions.
package callout

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"{{ cookiecutter.go_module_path }}/internal/natsauth"
	"{{ cookiecutter.go_module_path }}/internal/session"
	"{{ cookiecutter.go_module_path }}/internal/users"
)

const (
	TagSession = "sid:"
	queue      = "callout"
)

var errDenied = errors.New("not authorized")

type Issuer struct {
	Sessions *session.Store
	Users    *users.Store
	JWTTTL   time.Duration
	Now      func() time.Time

	usersAccount string
	authAccount  string
	userKey      nkeys.KeyPair
	responseKey  nkeys.KeyPair
	xkey         nkeys.KeyPair
}

func New(rt natsauth.Runtime, s *session.Store, u *users.Store, ttl time.Duration) (*Issuer, error) {
	uk, err := rt.UsersSigningKey()
	if err != nil {
		return nil, err
	}
	rk, err := rt.AuthSigningKey()
	if err != nil {
		return nil, err
	}
	xk, err := rt.XKeyPair()
	if err != nil {
		return nil, err
	}
	return &Issuer{Sessions: s, Users: u, JWTTTL: ttl, Now: time.Now,
		usersAccount: rt.UsersAccount, authAccount: rt.AuthAccount, userKey: uk, responseKey: rk, xkey: xk}, nil
}

// Permissions are the subjects a session user may use. Only admins may use
// the admin API.
func Permissions(role, userID, sessionID string) jwt.Permissions {
	var p jwt.Permissions
	if role == users.RoleAdmin {
		p.Pub.Allow.Add("app.api.>")
	} else {
		p.Pub.Allow.Add("app.api.whoami", "app.api.notes.>")
	}
	p.Sub.Allow.Add("_INBOX_"+sessionID+".>", "app.events."+userID+".>")
	return p
}

func (is *Issuer) Serve(nc *nats.Conn) (*nats.Subscription, error) {
	return nc.QueueSubscribe(natsauth.CalloutSubject, queue, is.handle)
}

func (is *Issuer) handle(m *nats.Msg) {
	serverKey := m.Header.Get("Nats-Server-Xkey")
	data := m.Data
	if serverKey != "" {
		var err error
		if data, err = is.xkey.Open(m.Data, serverKey); err != nil {
			slog.Warn("decrypt authorization request", "error", err)
			return
		}
	}
	req, err := jwt.DecodeAuthorizationRequestClaims(string(data))
	if err != nil {
		slog.Warn("bad authorization request", "error", err)
		return
	}
	resp := jwt.NewAuthorizationResponseClaims(req.UserNkey)
	resp.Audience = req.Server.ID
	resp.IssuerAccount = is.authAccount
	if token, err := is.authorize(req); err != nil {
		resp.Error = err.Error()
	} else {
		resp.Jwt = token
	}
	out, err := resp.Encode(is.responseKey)
	if err != nil {
		slog.Error("sign authorization response", "error", err)
		return
	}
	body := []byte(out)
	if serverKey != "" {
		if body, err = is.xkey.Seal(body, serverKey); err != nil {
			slog.Error("encrypt authorization response", "error", err)
			return
		}
	}
	if err := m.Respond(body); err != nil {
		slog.Warn("respond to authorization request", "error", err)
	}
}

func (is *Issuer) authorize(req *jwt.AuthorizationRequestClaims) (string, error) {
	co := req.ConnectOptions
	if co.Token == "" || co.Username != "" || co.Password != "" || co.Nkey != "" {
		return "", errDenied
	}
	ref, err := is.Sessions.ParseConnectToken(co.Token)
	if err != nil {
		return "", errDenied
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	rec, _, err := is.Sessions.Get(ctx, ref)
	if err != nil {
		if !errors.Is(err, session.ErrNotFound) {
			slog.Warn("callout session lookup", "error", err)
		}
		return "", errDenied
	}
	now := is.Now()
	until := rec.ValidUntil()
	if !now.Before(until) || (rec.Method == session.MethodOIDC && rec.OIDC == nil) {
		return "", errDenied
	}
	u, err := is.Users.Get(ctx, rec.UserID)
	if err != nil || !rec.Admits(u) {
		return "", errDenied
	}
	uc := jwt.NewUserClaims(req.UserNkey)
	uc.Name = u.ID
	uc.IssuerAccount = is.usersAccount
	uc.Expires = min(now.Add(is.JWTTTL).Unix(), until.Unix())
	uc.Tags.Add(TagSession + rec.SessionID)
	uc.Permissions = Permissions(u.Role, u.ID, rec.SessionID)
	uc.AllowedConnectionTypes.Add(jwt.ConnectionTypeStandard, jwt.ConnectionTypeWebsocket)
	token, err := uc.Encode(is.userKey)
	if err != nil {
		slog.Error("sign user JWT", "error", err)
		return "", errDenied
	}
	slog.Debug("session admitted", "user", u.ID, "method", rec.Method, "expires", time.Unix(uc.Expires, 0).UTC())
	return token, nil
}
