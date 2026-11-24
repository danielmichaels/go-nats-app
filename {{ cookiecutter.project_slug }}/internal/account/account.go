// Package account serves the caller's own record and the admin user
// operations over NATS.
//
//	app.api.whoami               {}            -> users.User
//	app.api.admin.users.list     {}            -> ListReply
//	app.api.admin.users.create   CreateRequest -> users.User
//	app.api.admin.users.update   UpdateRequest -> users.User
//
// Only admins may publish on app.api.admin.>; the handlers check the role
// again.
package account

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/nats-io/nats.go/micro"

	"{{ cookiecutter.go_module_path }}/internal/api"
	"{{ cookiecutter.go_module_path }}/internal/users"
)

const (
	SubjectWhoami = "app.api.whoami"
	SubjectList   = "app.api.admin.users.list"
	SubjectCreate = "app.api.admin.users.create"
	SubjectUpdate = "app.api.admin.users.update"
)

type ListReply struct {
	Users []users.User `json:"users"`
}

type CreateRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type UpdateRequest struct {
	ID       string          `json:"id"`
	Disabled *bool           `json:"disabled,omitempty"`
	Role     string          `json:"role,omitempty"`
	Link     *users.Identity `json:"link,omitempty"`
	Unlink   *users.Identity `json:"unlink,omitempty"`
}

type Service struct {
	ID api.Identity
	// Disabled is called after a user is disabled, so their clients close.
	Disabled func(userID string)
}

func (s *Service) Register(svc micro.Service) error {
	for _, ep := range []struct {
		name, subject string
		h             func(context.Context, api.Caller, []byte) (any, error)
		admin         bool
	}{
		{"whoami", SubjectWhoami, s.whoami, false},
		{"users-list", SubjectList, s.list, true},
		{"users-create", SubjectCreate, s.create, true},
		{"users-update", SubjectUpdate, s.update, true},
	} {
		h, admin := ep.h, ep.admin
		err := svc.AddEndpoint(ep.name, micro.HandlerFunc(func(req micro.Request) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := s.ID.Caller(ctx, req)
			if err == nil && admin && c.User.Role != users.RoleAdmin {
				err = api.Errorf(api.CodeForbidden, "admin role required")
			}
			var out any
			if err == nil {
				out, err = h(ctx, c, req.Data())
			}
			api.Respond(req, out, err)
		}), micro.WithEndpointSubject(ep.subject))
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) whoami(_ context.Context, c api.Caller, _ []byte) (any, error) { return c.User, nil }

func (s *Service) list(ctx context.Context, _ api.Caller, _ []byte) (any, error) {
	us, err := s.ID.Users.List(ctx)
	if err != nil {
		return nil, api.Errorf(api.CodeInternal, "could not list users")
	}
	return ListReply{Users: us}, nil
}

func (s *Service) create(ctx context.Context, _ api.Caller, data []byte) (any, error) {
	var in CreateRequest
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, api.Errorf(api.CodeBadRequest, "invalid request")
	}
	u, err := s.ID.Users.Create(ctx, in.Username, in.Password, in.Role)
	if errors.Is(err, users.ErrExists) {
		return nil, api.Errorf(api.CodeConflict, "%s", err.Error())
	}
	if err != nil {
		return nil, api.Errorf(api.CodeBadRequest, "%s", err.Error())
	}
	return u.Public(), nil
}

func (s *Service) update(ctx context.Context, c api.Caller, data []byte) (any, error) {
	var in UpdateRequest
	if err := json.Unmarshal(data, &in); err != nil || in.ID == "" {
		return nil, api.Errorf(api.CodeBadRequest, "invalid request")
	}
	if in.ID == c.User.ID && ((in.Disabled != nil && *in.Disabled) || (in.Role != "" && in.Role != users.RoleAdmin)) {
		return nil, api.Errorf(api.CodeBadRequest, "you cannot disable or demote yourself")
	}
	u, err := s.ID.Users.Get(ctx, in.ID)
	if err != nil {
		return nil, api.Errorf(api.CodeNotFound, "user not found")
	}
	if in.Role != "" {
		if u, err = s.ID.Users.SetRole(ctx, in.ID, in.Role); err != nil {
			return nil, api.Errorf(api.CodeBadRequest, "%s", err.Error())
		}
	}
	if in.Link != nil {
		if u, err = s.ID.Users.Link(ctx, in.ID, *in.Link); err != nil {
			code := api.CodeBadRequest
			if errors.Is(err, users.ErrLinked) {
				code = api.CodeConflict
			}
			return nil, api.Errorf(code, "%s", err.Error())
		}
	}
	if in.Unlink != nil {
		if u, err = s.ID.Users.Unlink(ctx, in.ID, *in.Unlink); err != nil {
			return nil, api.Errorf(api.CodeBadRequest, "%s", err.Error())
		}
	}
	if in.Disabled != nil {
		if u, err = s.ID.Users.SetDisabled(ctx, in.ID, *in.Disabled); err != nil {
			return nil, api.Errorf(api.CodeInternal, "could not update the user")
		}
		if *in.Disabled && s.Disabled != nil {
			s.Disabled(in.ID)
		}
	}
	return u.Public(), nil
}
