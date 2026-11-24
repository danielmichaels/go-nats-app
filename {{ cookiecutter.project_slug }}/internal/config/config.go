// Package config reads the runtime configuration from the environment.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type OIDC struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	AllowHTTP    bool
}

type Config struct {
	Env       string
	HTTPAddr  string
	PublicURL string
	DataDir   string
	LogLevel  string

	// EmbeddedNATS runs a local operator-mode server. Production refuses it.
	EmbeddedNATS    bool
	NATSPort        int
	NATSWSPort      int
	NATSURL         string
	NATSRuntimeFile string
	// NATSBrowserURL is the WebSocket URL that browsers connect to.
	NATSBrowserURL string
	Replicas       int

	CookieSecure  bool
	SessionTTL    time.Duration
	ConnectTTL    time.Duration
	UserJWTTTL    time.Duration
	RefreshMargin time.Duration

	OIDC *OIDC
}

func (c Config) Production() bool { return c.Env == "production" }

func Load() (Config, error) {
	var errs []error
	env := get("APP_ENV", "development")
	prod := env == "production"
	c := Config{
		Env:             env,
		HTTPAddr:        get("HTTP_ADDR", "127.0.0.1:8080"),
		PublicURL:       strings.TrimSuffix(get("PUBLIC_URL", "http://localhost:8080"), "/"),
		DataDir:         get("DATA_DIR", "./data"),
		LogLevel:        get("LOG_LEVEL", "info"),
		EmbeddedNATS:    boolean("NATS_EMBEDDED", !prod, &errs),
		NATSPort:        integer("NATS_PORT", 4222, &errs),
		NATSWSPort:      integer("NATS_WS_PORT", 4223, &errs),
		NATSURL:         os.Getenv("NATS_URL"),
		NATSRuntimeFile: os.Getenv("NATS_RUNTIME_FILE"),
		NATSBrowserURL:  os.Getenv("NATS_BROWSER_URL"),
		Replicas:        integer("NATS_REPLICAS", 1, &errs),
		CookieSecure:    boolean("COOKIE_SECURE", prod, &errs),
		SessionTTL:      duration("SESSION_TTL", 7*24*time.Hour, &errs),
		ConnectTTL:      duration("CONNECT_TOKEN_TTL", time.Minute, &errs),
		UserJWTTTL:      duration("USER_JWT_TTL", 15*time.Minute, &errs),
		RefreshMargin:   duration("OIDC_REFRESH_MARGIN", 2*time.Minute, &errs),
	}
	if iss := os.Getenv("OIDC_ISSUER"); iss != "" {
		c.OIDC = &OIDC{
			Issuer:       iss,
			ClientID:     os.Getenv("OIDC_CLIENT_ID"),
			ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
			RedirectURL:  get("OIDC_REDIRECT_URL", c.PublicURL+"/auth/oidc/callback"),
			Scopes:       strings.Fields(os.Getenv("OIDC_SCOPES")),
			AllowHTTP:    !prod && boolean("OIDC_ALLOW_HTTP", false, &errs),
		}
	}
	if u, err := url.Parse(c.PublicURL); err != nil || u.Host == "" {
		errs = append(errs, errors.New("PUBLIC_URL must be an absolute URL"))
	}
	if prod {
		if c.EmbeddedNATS {
			errs = append(errs, errors.New("production does not run embedded NATS: set NATS_EMBEDDED=false"))
		}
		if !c.CookieSecure {
			errs = append(errs, errors.New("production needs COOKIE_SECURE=true"))
		}
	}
	if !c.EmbeddedNATS && (c.NATSURL == "" || c.NATSRuntimeFile == "") {
		errs = append(errs, errors.New("external NATS needs NATS_URL and NATS_RUNTIME_FILE"))
	}
	if c.ConnectTTL <= 0 || c.UserJWTTTL <= 0 || c.SessionTTL <= 0 {
		errs = append(errs, errors.New("TTL settings must be positive"))
	}
	return c, errors.Join(errs...)
}

func get(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func boolean(k string, def bool, errs *[]error) bool {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %w", k, err))
	}
	return b
}

func integer(k string, def int, errs *[]error) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %w", k, err))
	}
	return n
}

func duration(k string, def time.Duration, errs *[]error) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %w", k, err))
	}
	return d
}
