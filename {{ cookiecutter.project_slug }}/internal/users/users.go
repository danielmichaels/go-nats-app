// Package users stores application users in the protected KV bucket of the
// service account. Only the application process reads it.
package users

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/crypto/bcrypt"
)

const (
	Bucket      = "app_users"
	RoleAdmin   = "admin"
	RoleMember  = "member"
	MinPassword = 12
	setupKey    = "setup"
)

var (
	ErrBadLogin = errors.New("invalid username or password")
	ErrNotFound = errors.New("user not found")
	ErrExists   = errors.New("username is already in use")
	ErrLinked   = errors.New("identity is already linked to a user")
	ErrSetup    = errors.New("setup token is not valid, or setup is done")
	nameRe      = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)
)

var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy password for timing"), bcrypt.DefaultCost)

type Identity struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

type User struct {
	ID         string     `json:"id"`
	Username   string     `json:"username"`
	Role       string     `json:"role"`
	Disabled   bool       `json:"disabled"`
	Created    time.Time  `json:"created"`
	Identities []Identity `json:"identities,omitempty"`
	Hash       string     `json:"hash,omitempty"`
	// SessionsAfter is when the user was last disabled. Sessions that
	// started earlier stay ended after the user is enabled again.
	SessionsAfter time.Time `json:"sessions_after,omitzero"`
}

// Public is the user record without its password hash.
func (u User) Public() User {
	u.Hash = ""
	return u
}

type Store struct{ kv jetstream.KeyValue }

func Open(ctx context.Context, js jetstream.JetStream, replicas int) (*Store, error) {
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: Bucket, Description: "application users", History: 1,
		Storage: jetstream.FileStorage, Replicas: replicas,
	})
	if err != nil {
		return nil, err
	}
	return &Store{kv: kv}, nil
}

func ValidName(name string) bool { return nameRe.MatchString(name) }

func ValidRole(role string) bool { return role == RoleAdmin || role == RoleMember }

func ValidatePassword(pw string) error {
	if len(pw) < MinPassword {
		return fmt.Errorf("password must be at least %d characters", MinPassword)
	}
	if len(pw) > 72 {
		return errors.New("password must be at most 72 bytes")
	}
	return nil
}

func identityKey(i Identity) string {
	sum := sha256.Sum256([]byte(i.Issuer + "\x00" + i.Subject))
	return "oidc." + hex.EncodeToString(sum[:])
}

func newID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (s *Store) Create(ctx context.Context, username, password, role string) (User, error) {
	if !ValidName(username) {
		return User{}, errors.New("username must be 1-32 characters: a-z, 0-9, _ or -")
	}
	if !ValidRole(role) {
		return User{}, errors.New("role must be admin or member")
	}
	if err := ValidatePassword(password); err != nil {
		return User{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}
	u := User{ID: newID(), Username: username, Role: role, Created: time.Now().UTC(), Hash: string(hash)}
	if _, err := s.kv.Create(ctx, "name."+username, []byte(u.ID)); err != nil {
		if errors.Is(err, jetstream.ErrKeyExists) {
			return User{}, ErrExists
		}
		return User{}, err
	}
	b, _ := json.Marshal(u)
	if _, err := s.kv.Create(ctx, "user."+u.ID, b); err != nil {
		_ = s.kv.Delete(ctx, "name."+username)
		return User{}, err
	}
	return u, nil
}

func (s *Store) get(ctx context.Context, id string) (User, uint64, error) {
	var u User
	e, err := s.kv.Get(ctx, "user."+id)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return u, 0, ErrNotFound
	}
	if err != nil {
		return u, 0, err
	}
	if err := json.Unmarshal(e.Value(), &u); err != nil {
		return u, 0, err
	}
	return u, e.Revision(), nil
}

func (s *Store) Get(ctx context.Context, id string) (User, error) {
	if id == "" || strings.ContainsAny(id, ".*> ") {
		return User{}, ErrNotFound
	}
	u, _, err := s.get(ctx, id)
	return u, err
}

func (s *Store) ByName(ctx context.Context, username string) (User, error) {
	if !ValidName(username) {
		return User{}, ErrNotFound
	}
	e, err := s.kv.Get(ctx, "name."+username)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	return s.Get(ctx, string(e.Value()))
}

// CheckPassword spends the same bcrypt work for an unknown name as for a
// wrong password.
func (s *Store) CheckPassword(ctx context.Context, username, password string) (User, error) {
	u, err := s.ByName(ctx, username)
	if errors.Is(err, ErrNotFound) {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return User{}, ErrBadLogin
	}
	if err != nil {
		return User{}, err
	}
	if u.Hash == "" || bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(password)) != nil || u.Disabled {
		return User{}, ErrBadLogin
	}
	return u, nil
}

func (s *Store) ByIdentity(ctx context.Context, i Identity) (User, error) {
	e, err := s.kv.Get(ctx, identityKey(i))
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	u, err := s.Get(ctx, string(e.Value()))
	if err != nil {
		return User{}, err
	}
	if !slices.Contains(u.Identities, i) {
		return User{}, ErrNotFound
	}
	return u, nil
}

func (s *Store) update(ctx context.Context, id string, f func(*User) error) (User, error) {
	for range 5 {
		u, rev, err := s.get(ctx, id)
		if err != nil {
			return User{}, err
		}
		if err := f(&u); err != nil {
			return User{}, err
		}
		b, _ := json.Marshal(u)
		if _, err := s.kv.Update(ctx, "user."+id, b, rev); err == nil {
			return u, nil
		} else if !isConflict(err) {
			return User{}, err
		}
	}
	return User{}, errors.New("user changed during update, try again")
}

func isConflict(err error) bool {
	var apiErr *jetstream.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence
}

func (s *Store) SetDisabled(ctx context.Context, id string, disabled bool) (User, error) {
	return s.update(ctx, id, func(u *User) error {
		u.Disabled = disabled
		if disabled {
			u.SessionsAfter = time.Now()
		}
		return nil
	})
}

func (s *Store) SetRole(ctx context.Context, id, role string) (User, error) {
	if !ValidRole(role) {
		return User{}, errors.New("role must be admin or member")
	}
	return s.update(ctx, id, func(u *User) error { u.Role = role; return nil })
}

// Link binds an exact issuer and subject to a user. It never matches by
// email or any other claim.
func (s *Store) Link(ctx context.Context, id string, i Identity) (User, error) {
	if i.Issuer == "" || i.Subject == "" {
		return User{}, errors.New("issuer and subject are required")
	}
	if _, err := s.Get(ctx, id); err != nil {
		return User{}, err
	}
	if _, err := s.kv.Create(ctx, identityKey(i), []byte(id)); err != nil {
		if errors.Is(err, jetstream.ErrKeyExists) {
			return User{}, ErrLinked
		}
		return User{}, err
	}
	u, err := s.update(ctx, id, func(u *User) error {
		if !slices.Contains(u.Identities, i) {
			u.Identities = append(u.Identities, i)
		}
		return nil
	})
	if err != nil {
		_ = s.kv.Delete(ctx, identityKey(i))
	}
	return u, err
}

func (s *Store) Unlink(ctx context.Context, id string, i Identity) (User, error) {
	u, err := s.update(ctx, id, func(u *User) error {
		u.Identities = slices.DeleteFunc(u.Identities, func(x Identity) bool { return x == i })
		return nil
	})
	if err != nil {
		return User{}, err
	}
	if e, err := s.kv.Get(ctx, identityKey(i)); err == nil && string(e.Value()) == id {
		_ = s.kv.Delete(ctx, identityKey(i), jetstream.LastRevision(e.Revision()))
	}
	return u, nil
}

func (s *Store) List(ctx context.Context) ([]User, error) {
	lister, err := s.kv.ListKeysFiltered(ctx, "user.*")
	if err != nil {
		return nil, err
	}
	var out []User
	for k := range lister.Keys() {
		u, err := s.Get(ctx, strings.TrimPrefix(k, "user."))
		if err == nil {
			out = append(out, u.Public())
		}
	}
	slices.SortFunc(out, func(a, b User) int { return strings.Compare(a.Username, b.Username) })
	return out, nil
}

func (s *Store) hasUsers(ctx context.Context) (bool, error) {
	lister, err := s.kv.ListKeysFiltered(ctx, "user.*")
	if err != nil {
		return false, err
	}
	found := false
	for range lister.Keys() {
		found = true
	}
	return found, nil
}

// SetupRequired reports whether no user exists yet.
func (s *Store) SetupRequired(ctx context.Context) (bool, error) {
	has, err := s.hasUsers(ctx)
	return !has, err
}

// EnsureSetupToken makes a one-time setup token while no user exists. It
// returns "" when users exist. Only the token hash is stored.
func (s *Store) EnsureSetupToken(ctx context.Context) (string, error) {
	if has, err := s.hasUsers(ctx); err != nil || has {
		return "", err
	}
	tok := newID() + newID()
	sum := sha256.Sum256([]byte(tok))
	if _, err := s.kv.Put(ctx, setupKey, []byte(hex.EncodeToString(sum[:]))); err != nil {
		return "", err
	}
	return tok, nil
}

// Setup consumes the setup token and makes the first admin.
func (s *Store) Setup(ctx context.Context, token, username, password string) (User, error) {
	e, err := s.kv.Get(ctx, setupKey)
	if err != nil {
		return User{}, ErrSetup
	}
	sum := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(e.Value(), []byte(hex.EncodeToString(sum[:]))) != 1 {
		return User{}, ErrSetup
	}
	if has, err := s.hasUsers(ctx); err != nil || has {
		return User{}, ErrSetup
	}
	if !ValidName(username) {
		return User{}, errors.New("username must be 1-32 characters: a-z, 0-9, _ or -")
	}
	if err := ValidatePassword(password); err != nil {
		return User{}, err
	}
	if err := s.kv.Delete(ctx, setupKey, jetstream.LastRevision(e.Revision())); err != nil {
		return User{}, ErrSetup
	}
	return s.Create(ctx, username, password, RoleAdmin)
}
