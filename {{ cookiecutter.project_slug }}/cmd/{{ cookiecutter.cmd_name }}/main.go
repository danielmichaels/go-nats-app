package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"{{ cookiecutter.go_module_path }}/internal/app"
	"{{ cookiecutter.go_module_path }}/internal/config"
{%- if cookiecutter.frontend == "datastar" %}
	ui "{{ cookiecutter.go_module_path }}/internal/htmlui"
{%- else %}
	ui "{{ cookiecutter.go_module_path }}/internal/spa"
{%- endif %}
	"{{ cookiecutter.go_module_path }}/internal/natsauth"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "nats-setup" {
		if err := natsSetup(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		slog.Error("app failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	var level slog.Level
	_ = level.UnmarshalText([]byte(cfg.LogLevel))
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	startCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	a, err := app.Start(startCtx, cfg)
	cancel()
	if err != nil {
		return err
	}
	defer a.Close()

	frontend, err := ui.New(a)
	if err != nil {
		return err
	}
	defer frontend.Close()

	mux := http.NewServeMux()
	csrf := http.NewCrossOriginProtection()
	a.Health(mux)
	a.HTTP.Routes(mux, csrf)
	frontend.Routes(mux, csrf)

	srv := &http.Server{Addr: cfg.HTTPAddr, Handler: securityHeaders(mux), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() {
		slog.Info("http listening", "addr", cfg.HTTPAddr, "public_url", cfg.PublicURL)
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	slog.Info("shutting down")
	frontend.Close()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// natsSetup writes the account keys, the application runtime file and a
// server configuration fragment for an external NATS server. It changes no
// server.
func natsSetup(args []string) error {
	fs := flag.NewFlagSet("nats-setup", flag.ExitOnError)
	dir := fs.String("dir", "nats-setup", "output directory")
	origins := fs.String("allowed-origins", "https://app.example.com", "comma-separated WebSocket origins")
	_ = fs.Parse(args)
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	keysPath := filepath.Join(*dir, "keys.json")
	keys, err := natsauth.LoadOrCreateKeys(keysPath)
	if err != nil {
		return err
	}
	srv, rt, err := keys.Build()
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(rt, "", "  ")
	if err := os.WriteFile(filepath.Join(*dir, "runtime.json"), b, 0o600); err != nil {
		return err
	}
	var quoted []string
	for _, o := range strings.Split(*origins, ",") {
		quoted = append(quoted, fmt.Sprintf("%q", strings.TrimSpace(o)))
	}
	conf := srv.ResolverConfig() + fmt.Sprintf(`
jetstream: { store_dir: "/data/jetstream" }
websocket: {
  port: 443
  # Terminate TLS here or at a proxy; browsers must use wss:// in production.
  tls: { cert_file: "/etc/nats/tls.crt", key_file: "/etc/nats/tls.key" }
  allowed_origins: [%s]
  same_origin: false
}
`, strings.Join(quoted, ", "))
	if err := os.WriteFile(filepath.Join(*dir, "server.conf"), []byte(conf), 0o600); err != nil {
		return err
	}
	fmt.Printf("Wrote %s (root keys: keep offline), runtime.json (give to the app as NATS_RUNTIME_FILE) and server.conf\n", keysPath)
	return nil
}
