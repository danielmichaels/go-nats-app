// Package session keeps durable web sessions in the protected KV bucket of
// the service account, and mints the short connect tokens that the auth
// callout accepts.
//
// The browser cookie holds a random token. KV keys and connect tokens hold
// only its SHA-256 (the session reference), so the bucket does not hold
// usable cookies.
package session

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

const (
	Bucket         = "app_sessions"
	MethodPassword = "password"
	MethodOIDC     = "oidc"
	connectPurpose = "nats_connect"
)

var (
	ErrNotFound     = errors.New("session not found")
	ErrConflict     = errors.New("session changed")
	ErrInvalidToken = errors.New("connect token is not valid")
)

type OIDC struct {
	Issuer         string    `json:"issuer"`
	Subject        string    `json:"subject"`
	IdentityExpiry time.Time `json:"identity_expiry"`
	RefreshToken   string    `json:"refresh_token"`
	// RefreshingUntil marks a refresh in progress on some replica. When it
	// passes without a result, the refresh token state is uncertain.
	RefreshingUntil time.Time `json:"refreshing_until,omitzero"`
}

type Record struct {
	UserID    string    `json:"user_id"`
	SessionID string    `json:"session_id"`
	Method    string    `json:"method"`
	AuthTime  time.Time `json:"auth_time"`
	Deadline  time.Time `json:"deadline"`
	OIDC      *OIDC     `json:"oidc,omitempty"`
}

// InboxPrefix is the only inbox namespace the session's NATS users may
// subscribe to.
func (r Record) InboxPrefix() string { return "_INBOX_" + r.SessionID }

// ValidUntil is the last instant that this session may grant NATS access.
func (r Record) ValidUntil() time.Time {
	t := r.Deadline
	if r.OIDC != nil && r.OIDC.IdentityExpiry.Before(t) {
		t = r.OIDC.IdentityExpiry
	}
	return t
}

type Store struct {
	kv       jetstream.KeyValue
	tokenKey []byte
	Now      func() time.Time
}

func Open(ctx context.Context, js jetstream.JetStream, maxAge time.Duration, replicas int, tokenKey []byte) (*Store, error) {
	if len(tokenKey) < 32 {
		return nil, errors.New("session token key must be at least 32 bytes")
	}
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: Bucket, Description: "web sessions", History: 1,
		Storage: jetstream.FileStorage, TTL: maxAge + time.Hour, Replicas: replicas,
	})
	if err != nil {
		return nil, err
	}
	return &Store{kv: kv, tokenKey: tokenKey, Now: time.Now}, nil
}

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// Ref is the session reference of a cookie token.
func Ref(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func validRef(ref string) bool {
	if len(ref) != 64 {
		return false
	}
	_, err := hex.DecodeString(ref)
	return err == nil
}

func NewSessionID() string {
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(random(10)))
}

// Create stores a new session and returns its cookie token. A new token on
// every login rotates the session identifier.
func (s *Store) Create(ctx context.Context, rec Record) (string, error) {
	token := base64.RawURLEncoding.EncodeToString(random(32))
	if rec.SessionID == "" {
		rec.SessionID = NewSessionID()
	}
	b, _ := json.Marshal(rec)
	if _, err := s.kv.Create(ctx, "s."+Ref(token), b); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Store) Get(ctx context.Context, ref string) (Record, uint64, error) {
	var rec Record
	if !validRef(ref) {
		return rec, 0, ErrNotFound
	}
	e, err := s.kv.Get(ctx, "s."+ref)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return rec, 0, ErrNotFound
	}
	if err != nil {
		return rec, 0, err
	}
	if err := json.Unmarshal(e.Value(), &rec); err != nil {
		return rec, 0, err
	}
	return rec, e.Revision(), nil
}

// Update writes rec only when the stored revision is still rev. A deleted
// session is never written again.
func (s *Store) Update(ctx context.Context, ref string, rec Record, rev uint64) (uint64, error) {
	b, _ := json.Marshal(rec)
	n, err := s.kv.Update(ctx, "s."+ref, b, rev)
	var apiErr *jetstream.APIError
	if errors.As(err, &apiErr) && apiErr.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence {
		return 0, ErrConflict
	}
	return n, err
}

func (s *Store) Delete(ctx context.Context, ref string) error {
	if !validRef(ref) {
		return nil
	}
	return s.kv.Purge(ctx, "s."+ref)
}

type connectClaims struct {
	Purpose string `json:"p"`
	Ref     string `json:"r"`
	Expires int64  `json:"e"`
}

// MintConnectToken returns a token that the auth callout accepts until
// expires. It names the session reference, never the cookie token.
func (s *Store) MintConnectToken(ref string, expires time.Time) string {
	b, _ := json.Marshal(connectClaims{Purpose: connectPurpose, Ref: ref, Expires: expires.Unix()})
	body := base64.RawURLEncoding.EncodeToString(b)
	return body + "." + base64.RawURLEncoding.EncodeToString(s.sign(body))
}

func (s *Store) sign(body string) []byte {
	m := hmac.New(sha256.New, s.tokenKey)
	m.Write([]byte(connectPurpose + ":" + body))
	return m.Sum(nil)
}

func (s *Store) ParseConnectToken(token string) (string, error) {
	body, sig, ok := strings.Cut(token, ".")
	if !ok || len(token) > 512 {
		return "", ErrInvalidToken
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, s.sign(body)) {
		return "", ErrInvalidToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return "", ErrInvalidToken
	}
	var c connectClaims
	if err := json.Unmarshal(raw, &c); err != nil || c.Purpose != connectPurpose || !validRef(c.Ref) {
		return "", ErrInvalidToken
	}
	if !s.Now().Before(time.Unix(c.Expires, 0)) {
		return "", ErrInvalidToken
	}
	return c.Ref, nil
}
