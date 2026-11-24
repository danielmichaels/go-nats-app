// Package oidctest is a disposable OpenID provider for tests. It signs ID
// tokens with its own key, enforces PKCE, rotates refresh tokens, and can
// fail in the ways a real provider fails.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const ClientID = "test-client"

type Provider struct {
	*httptest.Server

	mu sync.Mutex
	// Subject is the identity that /authorize signs in.
	Subject string
	// IDTTL is the lifetime of each ID token.
	IDTTL time.Duration
	// Down makes the token endpoint answer 503 to refresh grants.
	Down bool
	// Delay holds each refresh grant before it answers.
	Delay time.Duration
	// LoseRefresh rotates the refresh token, then drops the response.
	LoseRefresh bool
	// RefreshSubject, when set, is the subject of refreshed ID tokens.
	RefreshSubject string
	// Mutate changes the claims of every ID token.
	Mutate func(claims map[string]any)
	// SignWithOtherKey signs ID tokens with a key not in the JWKS.
	SignWithOtherKey bool

	key, other *rsa.PrivateKey
	codes      map[string]grant
	refresh    map[string]string
	Refreshes  int
}

type grant struct{ subject, nonce, challenge, redirect string }

func New() *Provider {
	p := &Provider{Subject: "subject-1", IDTTL: time.Hour, codes: map[string]grant{}, refresh: map[string]string{}}
	p.key, _ = rsa.GenerateKey(rand.Reader, 2048)
	p.other, _ = rsa.GenerateKey(rand.Reader, 2048)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	p.Server = httptest.NewServer(mux)
	return p
}

func (p *Provider) Issuer() string { return p.URL }

func (p *Provider) Set(f func(p *Provider)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f(p)
}

func (p *Provider) RefreshCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Refreshes
}

// Revoke makes every current refresh token invalid.
func (p *Provider) Revoke() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refresh = map[string]string{}
}

func random() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer": p.URL, "authorization_endpoint": p.URL + "/authorize", "token_endpoint": p.URL + "/token",
		"jwks_uri": p.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
		"grant_types_supported": []string{"authorization_code", "refresh_token"},
	})
}

func (p *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
}

// authorize signs in Subject at once and redirects with a code.
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != ClientID || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "bad authorize request", http.StatusBadRequest)
		return
	}
	code := p.Code(q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri"))
	u, _ := url.Parse(q.Get("redirect_uri"))
	v := u.Query()
	v.Set("code", code)
	v.Set("state", q.Get("state"))
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// Code issues an authorization code for Subject, as /authorize does.
func (p *Provider) Code(nonce, challenge, redirect string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	code := random()
	p.codes[code] = grant{subject: p.Subject, nonce: nonce, challenge: challenge, redirect: redirect}
	return code
}

func oauthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		p.mu.Lock()
		g, ok := p.codes[r.Form.Get("code")]
		delete(p.codes, r.Form.Get("code"))
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge || r.Form.Get("redirect_uri") != g.redirect {
			oauthError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		p.issue(w, g.subject, g.nonce)
	case "refresh_token":
		p.mu.Lock()
		delay, down := p.Delay, p.Down
		p.mu.Unlock()
		time.Sleep(delay)
		if down {
			oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
			return
		}
		p.mu.Lock()
		p.Refreshes++
		subject, ok := p.refresh[r.Form.Get("refresh_token")]
		delete(p.refresh, r.Form.Get("refresh_token"))
		if p.RefreshSubject != "" {
			subject = p.RefreshSubject
		}
		lose := p.LoseRefresh
		p.mu.Unlock()
		if !ok {
			oauthError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		if lose {
			p.issueTo(nil, subject, "")
			hj, _ := w.(http.Hijacker)
			c, _, _ := hj.Hijack()
			_ = c.Close()
			return
		}
		p.issue(w, subject, "")
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func (p *Provider) issue(w http.ResponseWriter, subject, nonce string) { p.issueTo(w, subject, nonce) }

func (p *Provider) issueTo(w http.ResponseWriter, subject, nonce string) {
	p.mu.Lock()
	now := time.Now()
	claims := map[string]any{
		"iss": p.URL, "sub": subject, "aud": ClientID, "iat": now.Unix(), "exp": now.Add(p.IDTTL).Unix(),
		"preferred_username": "user-" + subject, "email": subject + "@example.com",
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if p.Mutate != nil {
		p.Mutate(claims)
	}
	key := p.key
	if p.SignWithOtherKey {
		key = p.other
	}
	rt := random()
	p.refresh[rt] = subject
	p.mu.Unlock()
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	idt, _ := jwt.Signed(signer).Claims(claims).Serialize()
	if w == nil {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": random(), "token_type": "Bearer", "expires_in": 300, "id_token": idt, "refresh_token": rt,
	})
}
