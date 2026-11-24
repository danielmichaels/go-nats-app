// Package notes is the example application service: each user creates and
// lists their own notes and receives live changes.
//
// Contract (JSON over NATS request/reply):
//
//	app.api.notes.create  CreateRequest -> CreateReply
//	app.api.notes.list    {}            -> ListReply
//	app.events.<user>.notes             Event
//
// The request ID is the note ID. Sending the same request again returns the
// stored note with Duplicate set; the same ID with other content is a
// conflict. A client whose request timed out does not know whether the note
// was stored, so it lists again or resends the same request ID.
//
// The KV write and the event publish are separate steps. An event can be
// lost; clients list again after they reconnect.
package notes

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nats.go/micro"

	"{{ cookiecutter.go_module_path }}/internal/api"
)

const (
	Bucket        = "app_notes"
	SubjectCreate = "app.api.notes.create"
	SubjectList   = "app.api.notes.list"
	maxTitle      = 200
	maxBody       = 4000
)

var requestIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

type Note struct {
	ID      string    `json:"id"`
	Title   string    `json:"title"`
	Body    string    `json:"body"`
	Created time.Time `json:"created"`
}

type CreateRequest struct {
	RequestID string `json:"request_id"`
	Title     string `json:"title"`
	Body      string `json:"body"`
}

type CreateReply struct {
	Note      Note `json:"note"`
	Duplicate bool `json:"duplicate"`
}

type ListReply struct {
	Notes []Note `json:"notes"`
}

type Event struct {
	Type string `json:"type"`
	Note Note   `json:"note"`
}

func EventSubject(userID string) string { return "app.events." + userID + ".notes" }

type Service struct {
	kv      jetstream.KeyValue
	id      api.Identity
	publish func(subject string, data []byte) error
}

func Open(ctx context.Context, js jetstream.JetStream, replicas int, id api.Identity, publish func(string, []byte) error) (*Service, error) {
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: Bucket, Description: "notes", History: 1, Storage: jetstream.FileStorage, Replicas: replicas,
	})
	if err != nil {
		return nil, err
	}
	return &Service{kv: kv, id: id, publish: publish}, nil
}

func (s *Service) Register(svc micro.Service) error {
	if err := svc.AddEndpoint("notes-create", micro.HandlerFunc(s.create), micro.WithEndpointSubject(SubjectCreate)); err != nil {
		return err
	}
	return svc.AddEndpoint("notes-list", micro.HandlerFunc(s.list), micro.WithEndpointSubject(SubjectList))
}

func (s *Service) create(req micro.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := s.id.Caller(ctx, req)
	if err != nil {
		api.Respond(req, nil, err)
		return
	}
	var in CreateRequest
	if err := json.Unmarshal(req.Data(), &in); err != nil {
		api.Respond(req, nil, api.Errorf(api.CodeBadRequest, "invalid request"))
		return
	}
	in.Title = strings.TrimSpace(in.Title)
	switch {
	case !requestIDRe.MatchString(in.RequestID):
		err = api.Errorf(api.CodeBadRequest, "request_id must be 8-64 characters: A-Z, a-z, 0-9, _ or -")
	case in.Title == "" || utf8.RuneCountInString(in.Title) > maxTitle:
		err = api.Errorf(api.CodeBadRequest, "title must be 1-%d characters", maxTitle)
	case utf8.RuneCountInString(in.Body) > maxBody:
		err = api.Errorf(api.CodeBadRequest, "body must be at most %d characters", maxBody)
	}
	if err != nil {
		api.Respond(req, nil, err)
		return
	}
	n := Note{ID: in.RequestID, Title: in.Title, Body: in.Body, Created: time.Now().UTC()}
	key := c.User.ID + "." + n.ID
	b, _ := json.Marshal(n)
	if _, err := s.kv.Create(ctx, key, b); errors.Is(err, jetstream.ErrKeyExists) {
		old, err := s.get(ctx, key)
		if err != nil {
			api.Respond(req, nil, err)
			return
		}
		if old.Title != n.Title || old.Body != n.Body {
			api.Respond(req, nil, api.Errorf(api.CodeConflict, "request_id was used for another note"))
			return
		}
		api.Respond(req, CreateReply{Note: old, Duplicate: true}, nil)
		return
	} else if err != nil {
		slog.Error("store note", "error", err)
		api.Respond(req, nil, api.Errorf(api.CodeInternal, "could not store the note"))
		return
	}
	ev, _ := json.Marshal(Event{Type: "created", Note: n})
	if err := s.publish(EventSubject(c.User.ID), ev); err != nil {
		slog.Warn("publish note event", "error", err)
	}
	api.Respond(req, CreateReply{Note: n}, nil)
}

func (s *Service) get(ctx context.Context, key string) (Note, error) {
	var n Note
	e, err := s.kv.Get(ctx, key)
	if err != nil {
		return n, api.Errorf(api.CodeInternal, "could not read the note")
	}
	return n, json.Unmarshal(e.Value(), &n)
}

func (s *Service) list(req micro.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := s.id.Caller(ctx, req)
	if err != nil {
		api.Respond(req, nil, err)
		return
	}
	out := ListReply{Notes: []Note{}}
	lister, err := s.kv.ListKeysFiltered(ctx, c.User.ID+".*")
	if err != nil {
		api.Respond(req, nil, api.Errorf(api.CodeInternal, "could not list notes"))
		return
	}
	for k := range lister.Keys() {
		if n, err := s.get(ctx, k); err == nil {
			out.Notes = append(out.Notes, n)
		}
	}
	slices.SortFunc(out.Notes, func(a, b Note) int { return b.Created.Compare(a.Created) })
	api.Respond(req, out, nil)
}
