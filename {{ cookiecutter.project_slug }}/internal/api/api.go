// Package api holds the NATS request/reply conventions that every
// application service uses, and the caller identity that NATS supplies.
//
// A request names no user. The server adds the Nats-Request-Info header when
// a USERS client calls a service through the shared import; its name tag is
// the user ID that the auth callout signed. Clients cannot set that header.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/micro"

	"{{ cookiecutter.go_module_path }}/internal/users"
)

const (
	CodeBadRequest = 400
	CodeForbidden  = 403
	CodeNotFound   = 404
	CodeConflict   = 409
	CodeInternal   = 500
)

// Error is a service error. Services send it in the Nats-Service-Error-Code
// and Nats-Service-Error headers.
type Error struct {
	Code    int
	Message string
}

func (e *Error) Error() string { return e.Message }

func Errorf(code int, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

type Caller struct {
	User      users.User
	SessionID string
}

type Identity struct {
	UsersAccount string
	Users        *users.Store
}

// Caller returns the active user that sent req.
func (id Identity) Caller(ctx context.Context, req micro.Request) (Caller, error) {
	raw := req.Headers().Get(server.ClientInfoHdr)
	if raw == "" {
		return Caller{}, Errorf(CodeForbidden, "caller identity is missing")
	}
	var ci server.ClientInfo
	if err := json.Unmarshal([]byte(raw), &ci); err != nil || ci.Account != id.UsersAccount || ci.NameTag == "" {
		return Caller{}, Errorf(CodeForbidden, "caller identity is not valid")
	}
	u, err := id.Users.Get(ctx, ci.NameTag)
	if errors.Is(err, users.ErrNotFound) || (err == nil && u.Disabled) {
		return Caller{}, Errorf(CodeForbidden, "user is not active")
	}
	if err != nil {
		return Caller{}, Errorf(CodeInternal, "user lookup failed")
	}
	c := Caller{User: u.Public()}
	for _, t := range ci.Tags {
		if s, ok := strings.CutPrefix(t, "sid:"); ok {
			c.SessionID = s
		}
	}
	return c, nil
}

// Respond sends v, or the error in service error headers.
func Respond(req micro.Request, v any, err error) {
	if err != nil {
		var e *Error
		if !errors.As(err, &e) {
			e = &Error{Code: CodeInternal, Message: "internal error"}
		}
		_ = req.Error(strconv.Itoa(e.Code), e.Message, nil)
		return
	}
	_ = req.RespondJSON(v)
}

// Request sends a JSON request and decodes the reply or the service error.
func Request(ctx context.Context, nc *nats.Conn, subject string, in, out any) error {
	var data []byte
	if in != nil {
		var err error
		if data, err = json.Marshal(in); err != nil {
			return err
		}
	}
	m, err := nc.RequestWithContext(ctx, subject, data)
	if err != nil {
		return err
	}
	if code := m.Header.Get(micro.ErrorCodeHeader); code != "" {
		n, _ := strconv.Atoi(code)
		return &Error{Code: n, Message: m.Header.Get(micro.ErrorHeader)}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(m.Data, out)
}
