// Package oidcauth runs the server side of OpenID Connect: Authorization Code
// with S256 PKCE, state and nonce, and refresh of the verified identity.
// Provider tokens stay on the server.
package oidcauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	// ErrRejected means the provider definitively refused the refresh, or the
	// refreshed identity is not the same identity.
	ErrRejected = errors.New("identity provider rejected the session")
	// ErrTransient means the refresh request did not reach a decision. The
	// refresh token was not consumed.
	ErrTransient = errors.New("identity provider is unavailable")
	// ErrUncertain means the provider may have rotated the refresh token but
	// the result was lost.
	ErrUncertain = errors.New("identity provider result is unknown")
)

type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	// AllowHTTP permits a plain HTTP issuer. Only development and tests set it.
	AllowHTTP  bool
	HTTPClient *http.Client
}

type Identity struct {
	Issuer  string
	Subject string
	Name    string
	Expiry  time.Time
	Nonce   string
}

type Provider struct {
	cfg      Config
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	client   *http.Client
}

func New(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, errors.New("OIDC needs an issuer, a client ID and a redirect URL")
	}
	if !allowedURL(cfg.Issuer, cfg.AllowHTTP) || !allowedURL(cfg.RedirectURL, cfg.AllowHTTP) {
		return nil, errors.New("OIDC issuer and redirect URL must use HTTPS")
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{oidc.ScopeOpenID, "profile", oidc.ScopeOfflineAccess}
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	p, err := oidc.NewProvider(oidc.ClientContext(ctx, client), cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	var meta struct {
		JWKS   string   `json:"jwks_uri"`
		Grants []string `json:"grant_types_supported"`
	}
	if err := p.Claims(&meta); err != nil {
		return nil, err
	}
	ep := p.Endpoint()
	if !allowedURL(ep.AuthURL, cfg.AllowHTTP) || !allowedURL(ep.TokenURL, cfg.AllowHTTP) || !allowedURL(meta.JWKS, cfg.AllowHTTP) {
		return nil, errors.New("OIDC endpoints must use HTTPS")
	}
	if len(meta.Grants) > 0 && !contains(meta.Grants, "refresh_token") {
		return nil, errors.New("OIDC provider does not offer the refresh_token grant, which sessions need")
	}
	return &Provider{
		cfg:    cfg,
		client: client,
		oauth: oauth2.Config{
			ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURL,
			Endpoint: ep, Scopes: cfg.Scopes,
		},
		verifier: p.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
	}, nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func allowedURL(raw string, allowHTTP bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	return u.Scheme == "https" || (allowHTTP && u.Scheme == "http")
}

func (p *Provider) Issuer() string { return p.cfg.Issuer }

func (p *Provider) ctx(ctx context.Context) context.Context { return oidc.ClientContext(ctx, p.client) }

func (p *Provider) AuthURL(state, nonce, verifier string) string {
	return p.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
}

// Exchange redeems the code and verifies the ID token, its nonce and its
// authorized party. It needs a refresh token, because sessions depend on
// provider refresh.
func (p *Provider) Exchange(ctx context.Context, code, verifier, nonce string) (Identity, string, error) {
	t, err := p.oauth.Exchange(p.ctx(ctx), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Identity{}, "", fmt.Errorf("code exchange: %w", err)
	}
	i, err := p.verify(ctx, t)
	if err != nil {
		return Identity{}, "", err
	}
	if nonce == "" || i.Nonce != nonce {
		return Identity{}, "", errors.New("ID token nonce does not match")
	}
	if t.RefreshToken == "" {
		return Identity{}, "", errors.New("identity provider gave no refresh token; request offline_access")
	}
	return i, t.RefreshToken, nil
}

func (p *Provider) verify(ctx context.Context, t *oauth2.Token) (Identity, error) {
	raw, _ := t.Extra("id_token").(string)
	if raw == "" {
		return Identity{}, errors.New("identity provider gave no ID token")
	}
	idt, err := p.verifier.Verify(p.ctx(ctx), raw)
	if err != nil {
		return Identity{}, fmt.Errorf("ID token: %w", err)
	}
	if idt.Issuer != p.cfg.Issuer || idt.Subject == "" {
		return Identity{}, errors.New("ID token issuer or subject is not valid")
	}
	var claims struct {
		Name     string `json:"name"`
		Username string `json:"preferred_username"`
		AZP      string `json:"azp"`
	}
	if err := idt.Claims(&claims); err != nil {
		return Identity{}, err
	}
	if (len(idt.Audience) > 1 || claims.AZP != "") && claims.AZP != p.cfg.ClientID {
		return Identity{}, errors.New("ID token authorized party is not this client")
	}
	name := claims.Username
	if name == "" {
		name = claims.Name
	}
	return Identity{Issuer: idt.Issuer, Subject: idt.Subject, Name: name, Expiry: idt.Expiry, Nonce: idt.Nonce}, nil
}

// Refresh uses the refresh token once. It returns the verified new identity
// and the refresh token to keep, which may be the same token.
func (p *Provider) Refresh(ctx context.Context, refreshToken string, want Identity) (Identity, string, error) {
	t, err := p.oauth.TokenSource(p.ctx(ctx), &oauth2.Token{RefreshToken: refreshToken, Expiry: time.Unix(1, 0)}).Token()
	if err != nil {
		return Identity{}, "", classify(err)
	}
	i, err := p.verify(ctx, t)
	if err != nil {
		return Identity{}, "", fmt.Errorf("%w: %v", ErrRejected, err)
	}
	if i.Issuer != want.Issuer || i.Subject != want.Subject {
		return Identity{}, "", fmt.Errorf("%w: refreshed identity changed", ErrRejected)
	}
	next := t.RefreshToken
	if next == "" {
		next = refreshToken
	}
	return i, next, nil
}

func classify(err error) error {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		if re.Response != nil && (re.Response.StatusCode >= 500 || re.Response.StatusCode == http.StatusTooManyRequests) {
			return fmt.Errorf("%w: status %d", ErrTransient, re.Response.StatusCode)
		}
		return fmt.Errorf("%w: %s", ErrRejected, re.ErrorCode)
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return fmt.Errorf("%w: %v", ErrTransient, err)
	}
	return fmt.Errorf("%w: %v", ErrUncertain, err)
}
