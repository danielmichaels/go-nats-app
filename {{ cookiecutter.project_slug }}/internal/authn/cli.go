package authn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/oauth2"

	"{{ cookiecutter.go_module_path }}/internal/session"
	"{{ cookiecutter.go_module_path }}/internal/users"
)

// CLI sign-in follows RFC 8252: the command-line client listens on a
// loopback port, opens the browser at /auth/cli/start, and receives a
// one-time code there. It exchanges the code and its PKCE verifier for a
// session token of its own. The CLI session has the same lifetime and
// checks as a browser session, and is ended the same ways.

const (
	CLICodesBucket = "app_cli_codes"
	cliCodeTTL     = 2 * time.Minute
)

var (
	ErrCLIRequest = errors.New("command-line sign-in request is not valid")
	reState       = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	reChallenge   = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// CLIRequest is what the CLI sends in the browser URL: its loopback port,
// a state it checks on return, and its S256 PKCE challenge.
type CLIRequest struct {
	Port      int    `json:"port"`
	State     string `json:"state"`
	Challenge string `json:"challenge"`
}

func ParseCLIRequest(port, state, challenge string) (CLIRequest, error) {
	p, err := strconv.Atoi(port)
	if err != nil || p < 1024 || p > 65535 || !reState.MatchString(state) || !reChallenge.MatchString(challenge) {
		return CLIRequest{}, ErrCLIRequest
	}
	return CLIRequest{Port: p, State: state, Challenge: challenge}, nil
}

// Callback is the loopback URL that receives the code.
func (r CLIRequest) Callback(code string) string {
	return fmt.Sprintf("http://127.0.0.1:%d/callback?%s", r.Port, url.Values{"code": {code}, "state": {r.State}}.Encode())
}

type cliCode struct {
	Challenge string         `json:"challenge"`
	Record    session.Record `json:"record"`
	Expires   time.Time      `json:"expires"`
}

func (s *Service) openCLICodes(ctx context.Context, js jetstream.JetStream, replicas int) error {
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: CLICodesBucket, Description: "one-time CLI sign-in codes", History: 1,
		Storage: jetstream.FileStorage, TTL: 10 * time.Minute, MaxBytes: 16 << 20, Replicas: replicas,
	})
	s.cliCodes = kv
	return err
}

func codeKey(code string) string {
	sum := sha256.Sum256([]byte(code))
	return "c." + hex.EncodeToString(sum[:])
}

// issueCLICode stores the session the CLI will get, without a usable token,
// and returns the loopback URL with the code.
func (s *Service) issueCLICode(ctx context.Context, req CLIRequest, rec session.Record) (string, error) {
	code := randomHex(32)
	b, _ := json.Marshal(cliCode{Challenge: req.Challenge, Record: rec, Expires: s.now().Add(cliCodeTTL)})
	if _, err := s.cliCodes.Create(ctx, codeKey(code), b); err != nil {
		return "", errors.Join(ErrUnavailable, err)
	}
	return req.Callback(code), nil
}

// CLIPassword checks a password typed on the CLI sign-in page and returns
// the loopback URL to send the browser to. The browser gets no session.
func (s *Service) CLIPassword(ctx context.Context, req CLIRequest, username, password, remote string) (string, error) {
	u, err := s.checkPassword(ctx, username, password, remote)
	if err != nil {
		return "", err
	}
	now := s.now()
	return s.issueCLICode(ctx, req, session.Record{UserID: u.ID, Method: session.MethodPassword, AuthTime: now, Deadline: now.Add(s.opts.SessionTTL)})
}

// CLIOIDCStart starts a provider login whose callback goes to the CLI.
func (s *Service) CLIOIDCStart(ctx context.Context, req CLIRequest, remote string) (string, string, error) {
	return s.oidcStart(ctx, attempt{CLI: &req}, remote)
}

// CLIExchange trades a code and the verifier behind its challenge for a new
// session token. A code works once, even when the verifier is wrong.
func (s *Service) CLIExchange(ctx context.Context, code, verifier string) (string, Current, error) {
	e, err := s.cliCodes.Get(ctx, codeKey(code))
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return "", Current{}, ErrLoginExpired
	}
	if err != nil {
		return "", Current{}, errors.Join(ErrUnavailable, err)
	}
	if err := s.cliCodes.Purge(ctx, e.Key(), jetstream.LastRevision(e.Revision())); err != nil {
		return "", Current{}, ErrLoginExpired
	}
	var c cliCode
	if err := json.Unmarshal(e.Value(), &c); err != nil || !s.now().Before(c.Expires) {
		return "", Current{}, ErrLoginExpired
	}
	if verifier == "" || oauth2.S256ChallengeFromVerifier(verifier) != c.Challenge {
		return "", Current{}, ErrLoginState
	}
	u, err := s.Users.Get(ctx, c.Record.UserID)
	if errors.Is(err, users.ErrNotFound) || (err == nil && !c.Record.Admits(u)) {
		return "", Current{}, ErrUnauthenticated
	}
	if err != nil {
		return "", Current{}, errors.Join(ErrUnavailable, err)
	}
	return s.start(ctx, u, c.Record)
}
