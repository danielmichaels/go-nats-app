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
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"{{ cookiecutter.go_module_path }}/internal/account"
	"{{ cookiecutter.go_module_path }}/internal/api"
	"{{ cookiecutter.go_module_path }}/internal/app"
	"{{ cookiecutter.go_module_path }}/internal/cliauth"
	"{{ cookiecutter.go_module_path }}/internal/config"
{%- if cookiecutter.frontend == "datastar" %}
	ui "{{ cookiecutter.go_module_path }}/internal/htmlui"
{%- endif %}
	"{{ cookiecutter.go_module_path }}/internal/natsauth"
{%- if cookiecutter.frontend == "react" %}
	ui "{{ cookiecutter.go_module_path }}/internal/spa"
{%- endif %}
)

func main() {
	commands := map[string]func([]string) error{"nats-setup": natsSetup, "login": login, "logout": logout, "whoami": whoami}
	if len(os.Args) > 1 {
		if cmd, ok := commands[os.Args[1]]; ok {
			if err := cmd(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		}
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

	// No WriteTimeout: SSE responses stay open.
	srv := &http.Server{Addr: cfg.HTTPAddr, Handler: securityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute}
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

// login signs this command-line client in through the browser and keeps
// the session in the user's config directory.
func login(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	server := fs.String("server", envOr("PUBLIC_URL", "http://localhost:8080"), "the app's public URL")
	_ = fs.Parse(args)
	path, err := cliauth.DefaultPath("{{ cookiecutter.project_slug }}")
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	c, err := cliauth.Login(ctx, *server, func(u string) error {
		fmt.Printf("Opening the browser to sign in. If it does not open, visit:\n\n  %s\n\n", u)
		_ = openBrowser(u)
		return nil
	})
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	if err := cliauth.Save(path, c); err != nil {
		return err
	}
	fmt.Printf("Signed in as %s until %s.\n", c.User.Username, c.Deadline.Local().Format(time.DateTime))
	return nil
}

func logout(_ []string) error {
	path, err := cliauth.DefaultPath("{{ cookiecutter.project_slug }}")
	if err != nil {
		return err
	}
	c, err := cliauth.Load(path)
	if errors.Is(err, cliauth.ErrSignedOut) {
		return os.RemoveAll(path)
	}
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.Logout(ctx); err != nil {
		return err
	}
	return os.Remove(path)
}

// whoami asks the API who the signed-in user is, over NATS.
func whoami(args []string) error {
	fs := flag.NewFlagSet("whoami", flag.ExitOnError)
	natsURL := fs.String("nats", os.Getenv("NATS_CLIENT_URL"), "NATS URL (default: the one the app gives browsers)")
	_ = fs.Parse(args)
	path, err := cliauth.DefaultPath("{{ cookiecutter.project_slug }}")
	if err != nil {
		return err
	}
	c, err := cliauth.Load(path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	nc, err := c.Connect(ctx, *natsURL)
	if err != nil {
		return err
	}
	defer nc.Close()
	var u struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	if err := api.Request(ctx, nc, account.SubjectWhoami, nil, &u); err != nil {
		return err
	}
	fmt.Printf("%s (%s)\n", u.Username, u.Role)
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func openBrowser(u string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", u).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
	}
	return exec.Command("xdg-open", u).Start()
}
