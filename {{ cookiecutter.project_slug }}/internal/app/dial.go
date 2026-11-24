package app

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"{{ cookiecutter.go_module_path }}/internal/authn"
	"{{ cookiecutter.go_module_path }}/internal/natsauth"
)

// DialSession opens a NATS connection as the session's user. Every CONNECT
// gets a new connect token, so a reconnect after the user JWT expires works
// while the session is valid and fails once it ends. ended is called once
// when the server refuses the session.
func (a *App) DialSession(ref string, ended func(), opts ...nats.Option) (*nats.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	_, cur, _, err := a.Auth.ConnectToken(ctx, ref)
	cancel()
	if err != nil {
		return nil, err
	}
	token := func() string {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		t, _, _, err := a.Auth.ConnectToken(ctx, ref)
		if err != nil {
			return "invalid"
		}
		return t
	}
	base := []nats.Option{
		natsauth.Sentinel(a.Runtime.Sentinel),
		nats.TokenHandler(token),
		nats.CustomInboxPrefix(cur.Record.InboxPrefix()),
		nats.Name("session:" + cur.Record.SessionID),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(500 * time.Millisecond),
	}
	if ended != nil {
		base = append(base, nats.ErrorHandler(func(nc *nats.Conn, _ *nats.Subscription, err error) {
			if AuthError(err) {
				// The session may only be in a transient state; check it.
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				if _, err := a.Auth.SessionByRef(ctx, ref); errors.Is(err, authn.ErrUnauthenticated) {
					ended()
				}
			}
		}))
	}
	return nats.Connect(a.NATSURL, append(base, opts...)...)
}

func AuthError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return errors.Is(err, nats.ErrAuthorization) || errors.Is(err, nats.ErrAuthExpired) ||
		strings.Contains(s, "authorization violation") || strings.Contains(s, "authentication expired")
}
