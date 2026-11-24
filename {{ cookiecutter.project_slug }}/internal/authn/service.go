// Package authn owns login, durable sessions, provider refresh and the
// connect tokens that admit a session to NATS. Both frontends use it.
package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/oauth2"

	"{{ cookiecutter.go_module_path }}/internal/oidcauth"
	"{{ cookiecutter.go_module_path }}/internal/session"
	"{{ cookiecutter.go_module_path }}/internal/users"
)

const AttemptsBucket = "app_oidc_attempts"

var (
	ErrUnauthenticated = errors.New("not signed in")
	ErrUnavailable     = errors.New("sign-in service is temporarily unavailable")
	ErrThrottled       = errors.New("too many attempts, try again later")
	ErrOIDCDisabled    = errors.New("OIDC is not configured")
	ErrLoginState      = errors.New("login state is not valid")
	ErrLoginExpired    = errors.New("login attempt expired or was used")
	ErrIdentityRefused = errors.New("identity provider login was refused")
	ErrUnbound         = errors.New("this identity is not linked to an active user")
)

type Options struct {
	SessionTTL     time.Duration
	ConnectTTL     time.Duration
	RefreshMargin  time.Duration
	RefreshLockTTL time.Duration
}

// Publisher sends events on the service account connection.
type Publisher func(subject string, data []byte) error

type Service struct {
	Users    *users.Store
	Sessions *session.Store
	OIDC     *oidcauth.Provider
	attempts jetstream.KeyValue
	cliCodes jetstream.KeyValue
	publish  Publisher
	opts     Options
	limit    *limiter
	now      func() time.Time
}

func New(ctx context.Context, js jetstream.JetStream, replicas int, u *users.Store, s *session.Store, p *oidcauth.Provider, pub Publisher, o Options) (*Service, error) {
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: AttemptsBucket, Description: "OIDC login attempts", History: 1,
		Storage: jetstream.FileStorage, TTL: 10 * time.Minute, MaxBytes: 16 << 20, Replicas: replicas,
	})
	if err != nil {
		return nil, err
	}
	if o.RefreshLockTTL == 0 {
		o.RefreshLockTTL = 20 * time.Second
	}
	svc := &Service{Users: u, Sessions: s, OIDC: p, attempts: kv, publish: pub, opts: o, limit: newLimiter(), now: time.Now}
	if err := svc.openCLICodes(ctx, js, replicas); err != nil {
		return nil, err
	}
	return svc, nil
}

// Current is a validated session.
type Current struct {
	Ref    string
	Record session.Record
	User   users.User
}

func SessionEventSubject(userID, sessionID string) string {
	return "app.events." + userID + ".session." + sessionID
}

func AccountEventSubject(userID string) string { return "app.events." + userID + ".account" }

func (s *Service) Login(ctx context.Context, username, password, remote string) (string, Current, error) {
	u, err := s.checkPassword(ctx, username, password, remote)
	if err != nil {
		return "", Current{}, err
	}
	now := s.now()
	return s.start(ctx, u, session.Record{UserID: u.ID, Method: session.MethodPassword, AuthTime: now, Deadline: now.Add(s.opts.SessionTTL)})
}

// checkPassword checks a login, throttled per user and per client address.
func (s *Service) checkPassword(ctx context.Context, username, password, remote string) (users.User, error) {
	key := "u:" + username
	if !s.limit.allow(key, userLimit) || !s.limit.allow("ip:"+remote, ipLimit) {
		return users.User{}, ErrThrottled
	}
	u, err := s.Users.CheckPassword(ctx, username, password)
	if err != nil {
		if errors.Is(err, users.ErrBadLogin) {
			s.limit.fail(key)
			s.limit.fail("ip:" + remote)
		}
		return users.User{}, err
	}
	s.limit.clear(key)
	return u, nil
}

func (s *Service) Setup(ctx context.Context, token, username, password, remote string) (string, Current, error) {
	if !s.limit.allow("setup", userLimit) || !s.limit.allow("ip:"+remote, ipLimit) {
		return "", Current{}, ErrThrottled
	}
	u, err := s.Users.Setup(ctx, token, username, password)
	if errors.Is(err, users.ErrSetup) {
		s.limit.fail("setup")
		s.limit.fail("ip:" + remote)
	}
	if err != nil {
		return "", Current{}, err
	}
	slog.Info("first admin created", "username", u.Username)
	now := s.now()
	return s.start(ctx, u, session.Record{UserID: u.ID, Method: session.MethodPassword, AuthTime: now, Deadline: now.Add(s.opts.SessionTTL)})
}

func (s *Service) start(ctx context.Context, u users.User, rec session.Record) (string, Current, error) {
	token, err := s.Sessions.Create(ctx, rec)
	if err != nil {
		return "", Current{}, err
	}
	rec, _, err = s.Sessions.Get(ctx, session.Ref(token))
	if err != nil {
		return "", Current{}, err
	}
	return token, Current{Ref: session.Ref(token), Record: rec, User: u.Public()}, nil
}

// Logout destroys the durable session and tells its NATS clients to close.
func (s *Service) Logout(ctx context.Context, token string) {
	if token != "" {
		s.end(ctx, session.Ref(token), "logout")
	}
}

func (s *Service) end(ctx context.Context, ref, reason string) {
	rec, _, getErr := s.Sessions.Get(ctx, ref)
	if err := s.Sessions.Delete(ctx, ref); err != nil {
		slog.Warn("delete session", "error", err)
	}
	if getErr == nil && s.publish != nil {
		b, _ := json.Marshal(map[string]string{"type": "ended", "reason": reason})
		_ = s.publish(SessionEventSubject(rec.UserID, rec.SessionID), b)
	}
}

func (s *Service) Session(ctx context.Context, token string) (Current, error) {
	if token == "" {
		return Current{}, ErrUnauthenticated
	}
	return s.SessionByRef(ctx, session.Ref(token))
}

// SessionByRef loads and checks a session. An OIDC session near its
// identity expiry is refreshed first, so restoring a session after a
// restart also proves the provider still accepts it.
func (s *Service) SessionByRef(ctx context.Context, ref string) (Current, error) {
	rec, rev, err := s.Sessions.Get(ctx, ref)
	if errors.Is(err, session.ErrNotFound) {
		return Current{}, ErrUnauthenticated
	}
	if err != nil {
		return Current{}, errors.Join(ErrUnavailable, err)
	}
	if !s.now().Before(rec.Deadline) {
		s.end(ctx, ref, "expired")
		return Current{}, ErrUnauthenticated
	}
	u, err := s.Users.Get(ctx, rec.UserID)
	if errors.Is(err, users.ErrNotFound) || (err == nil && !rec.Admits(u)) {
		s.end(ctx, ref, "user")
		return Current{}, ErrUnauthenticated
	}
	if err != nil {
		return Current{}, errors.Join(ErrUnavailable, err)
	}
	if rec.Method == session.MethodOIDC {
		if rec, err = s.fresh(ctx, ref, rec, rev); err != nil {
			return Current{}, err
		}
	}
	return Current{Ref: ref, Record: rec, User: u.Public()}, nil
}

// ConnectToken mints a connect token that expires within ConnectTTL and
// never after the session may grant access.
func (s *Service) ConnectToken(ctx context.Context, ref string) (string, Current, time.Time, error) {
	c, err := s.SessionByRef(ctx, ref)
	if err != nil {
		return "", Current{}, time.Time{}, err
	}
	exp := s.now().Add(s.opts.ConnectTTL)
	if until := c.Record.ValidUntil(); until.Before(exp) {
		exp = until
	}
	if exp.Sub(s.now()) < time.Second {
		return "", Current{}, time.Time{}, ErrUnavailable
	}
	return s.Sessions.MintConnectToken(ref, exp), c, exp, nil
}

func (s *Service) fresh(ctx context.Context, ref string, rec session.Record, rev uint64) (session.Record, error) {
	if s.OIDC == nil || rec.OIDC == nil {
		s.end(ctx, ref, "oidc")
		return rec, ErrUnauthenticated
	}
	ctx, cancel := context.WithTimeout(ctx, s.opts.RefreshLockTTL+5*time.Second)
	defer cancel()
	for {
		now := s.now()
		if rec.OIDC.IdentityExpiry.Sub(now) > s.opts.RefreshMargin {
			return rec, nil
		}
		if !rec.OIDC.RefreshingUntil.IsZero() {
			if now.After(rec.OIDC.RefreshingUntil) {
				slog.Warn("OIDC refresh did not finish: session ended", "user", rec.UserID)
				s.end(ctx, ref, "refresh")
				return rec, ErrUnauthenticated
			}
			select {
			case <-ctx.Done():
				return s.stillValid(rec)
			case <-time.After(150 * time.Millisecond):
			}
			var err error
			if rec, rev, err = s.Sessions.Get(ctx, ref); err != nil {
				if errors.Is(err, session.ErrNotFound) {
					return rec, ErrUnauthenticated
				}
				return rec, errors.Join(ErrUnavailable, err)
			}
			continue
		}
		claimed := rec
		o := *rec.OIDC
		o.RefreshingUntil = now.Add(s.opts.RefreshLockTTL)
		claimed.OIDC = &o
		lockRev, err := s.Sessions.Update(ctx, ref, claimed, rev)
		if errors.Is(err, session.ErrConflict) {
			if rec, rev, err = s.Sessions.Get(ctx, ref); err != nil {
				return rec, ErrUnauthenticated
			}
			continue
		}
		if err != nil {
			return s.stillValid(rec)
		}
		return s.refresh(ctx, ref, rec, lockRev)
	}
}

func (s *Service) stillValid(rec session.Record) (session.Record, error) {
	if s.now().Before(rec.ValidUntil()) {
		return rec, nil
	}
	return rec, ErrUnavailable
}

// refresh holds the refresh lock at lockRev. The refresh token is used at
// most once; a lost result ends the session instead of replaying it.
func (s *Service) refresh(ctx context.Context, ref string, rec session.Record, lockRev uint64) (session.Record, error) {
	callCtx, cancel := context.WithTimeout(ctx, s.opts.RefreshLockTTL-2*time.Second)
	want := oidcauth.Identity{Issuer: rec.OIDC.Issuer, Subject: rec.OIDC.Subject}
	i, next, err := s.OIDC.Refresh(callCtx, rec.OIDC.RefreshToken, want)
	cancel()
	switch {
	case errors.Is(err, oidcauth.ErrTransient):
		slog.Warn("OIDC refresh unavailable", "user", rec.UserID, "error", err)
		if _, uerr := s.Sessions.Update(ctx, ref, rec, lockRev); uerr != nil {
			return rec, ErrUnauthenticated
		}
		return s.stillValid(rec)
	case err != nil:
		slog.Warn("OIDC refresh refused: session ended", "user", rec.UserID, "error", err)
		s.end(ctx, ref, "refresh")
		return rec, ErrUnauthenticated
	}
	u, err := s.Users.ByIdentity(ctx, users.Identity{Issuer: i.Issuer, Subject: i.Subject})
	if err != nil || u.ID != rec.UserID || u.Disabled {
		slog.Warn("OIDC identity no longer linked: session ended", "user", rec.UserID)
		s.end(ctx, ref, "identity")
		return rec, ErrUnauthenticated
	}
	updated := rec
	updated.OIDC = &session.OIDC{Issuer: i.Issuer, Subject: i.Subject, IdentityExpiry: i.Expiry, RefreshToken: next}
	if _, err := s.Sessions.Update(ctx, ref, updated, lockRev); err != nil {
		slog.Warn("store refreshed session failed: session ended", "user", rec.UserID, "error", err)
		s.end(context.WithoutCancel(ctx), ref, "refresh")
		return rec, ErrUnauthenticated
	}
	return updated, nil
}

type attempt struct {
	Nonce    string    `json:"nonce"`
	Verifier string    `json:"verifier"`
	Redirect string    `json:"redirect"`
	Expires  time.Time `json:"expires"`
	// CLI, when set, sends the result to a command-line client instead of the browser.
	CLI *CLIRequest `json:"cli,omitempty"`
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func attemptKey(state string) string {
	sum := sha256.Sum256([]byte(state))
	return "a." + hex.EncodeToString(sum[:])
}

// OIDCStart stores a login attempt and returns the provider URL and the
// state, which the caller binds to the browser in a cookie.
func (s *Service) OIDCStart(ctx context.Context, redirect, remote string) (string, string, error) {
	return s.oidcStart(ctx, attempt{Redirect: LocalRedirect(redirect)}, remote)
}

func (s *Service) oidcStart(ctx context.Context, a attempt, remote string) (string, string, error) {
	if s.OIDC == nil {
		return "", "", ErrOIDCDisabled
	}
	if !s.limit.allow("oidc:"+remote, oidcLimit) {
		return "", "", ErrThrottled
	}
	s.limit.fail("oidc:" + remote)
	state := randomHex(32)
	a.Nonce, a.Verifier, a.Expires = randomHex(32), oauth2.GenerateVerifier(), s.now().Add(5*time.Minute)
	b, _ := json.Marshal(a)
	if _, err := s.attempts.Create(ctx, attemptKey(state), b); err != nil {
		return "", "", errors.Join(ErrUnavailable, err)
	}
	return s.OIDC.AuthURL(state, a.Nonce, a.Verifier), state, nil
}

func (s *Service) takeAttempt(ctx context.Context, state string) (attempt, error) {
	var a attempt
	e, err := s.attempts.Get(ctx, attemptKey(state))
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return a, ErrLoginExpired
	}
	if err != nil {
		return a, errors.Join(ErrUnavailable, err)
	}
	if err := s.attempts.Purge(ctx, e.Key(), jetstream.LastRevision(e.Revision())); err != nil {
		return a, ErrLoginExpired
	}
	if err := json.Unmarshal(e.Value(), &a); err != nil || !s.now().Before(a.Expires) {
		return a, ErrLoginExpired
	}
	return a, nil
}

// OIDCCallback finishes a login. browserState is the state cookie value.
// For a CLI login it returns no token, and the redirect is the CLI's
// loopback URL with a one-time code.
func (s *Service) OIDCCallback(ctx context.Context, browserState, state, code string) (string, Current, string, error) {
	if s.OIDC == nil {
		return "", Current{}, "", ErrOIDCDisabled
	}
	if browserState == "" || state == "" || browserState != state {
		return "", Current{}, "", ErrLoginState
	}
	a, err := s.takeAttempt(ctx, state)
	if err != nil {
		return "", Current{}, "", err
	}
	i, refresh, err := s.OIDC.Exchange(ctx, code, a.Verifier, a.Nonce)
	if err != nil {
		slog.Warn("OIDC login refused", "error", err)
		return "", Current{}, "", ErrIdentityRefused
	}
	u, err := s.Users.ByIdentity(ctx, users.Identity{Issuer: i.Issuer, Subject: i.Subject})
	if err != nil || u.Disabled {
		slog.Warn("OIDC login without an active linked user", "issuer", i.Issuer, "subject", i.Subject)
		return "", Current{}, "", ErrUnbound
	}
	now := s.now()
	rec := session.Record{
		UserID: u.ID, Method: session.MethodOIDC, AuthTime: now, Deadline: now.Add(s.opts.SessionTTL),
		OIDC: &session.OIDC{Issuer: i.Issuer, Subject: i.Subject, IdentityExpiry: i.Expiry, RefreshToken: refresh},
	}
	if a.CLI != nil {
		redirect, err := s.issueCLICode(ctx, *a.CLI, rec)
		return "", Current{}, redirect, err
	}
	token, c, err := s.start(ctx, u, rec)
	return token, c, a.Redirect, err
}

// LocalRedirect keeps a post-login destination on this origin.
func LocalRedirect(raw string) string {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.Contains(raw, "\\") {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	return u.RequestURI()
}
