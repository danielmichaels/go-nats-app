// Package spa serves the React build. The browser does all application work
// over its own NATS connection; this server only serves files and the
// authentication routes.
package spa

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"

	"{{ cookiecutter.go_module_path }}/internal/app"
)

// dist holds the output of `task web:build`.
//
//go:embed all:dist
var dist embed.FS

type SPA struct{ files fs.FS }

func New(*app.App) (*SPA, error) {
	files, err := fs.Sub(dist, "dist")
	return &SPA{files: files}, err
}

func (s *SPA) Close() {}

func (s *SPA) Routes(mux *http.ServeMux, _ *http.CrossOriginProtection) {
	assets := http.FileServerFS(s.files)
	mux.HandleFunc("GET /assets/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		assets.ServeHTTP(w, r)
	})
	mux.HandleFunc("GET /", s.index)
}

// index answers every client route with the app shell.
func (s *SPA) index(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/auth/") {
		http.NotFound(w, r)
		return
	}
	b, err := fs.ReadFile(s.files, "index.html")
	if err != nil {
		http.Error(w, "The web app is not built. Run `task web:build`.", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}
