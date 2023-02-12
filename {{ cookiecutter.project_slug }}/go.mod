module {{ cookiecutter.go_module_path.strip('/') }}

go {{ cookiecutter.go_version }}

require (
        github.com/joeshaw/envdecode v0.0.0-20200121155833-099f1fc765bd
        github.com/nats-io/nats.go v1.23.0
        github.com/rs/zerolog v1.28.0
)

require (
        github.com/go-chi/chi/v5 v5.0.7 // indirect
        github.com/go-chi/httplog v0.2.5 // indirect
        github.com/mattn/go-colorable v0.1.12 // indirect
        github.com/mattn/go-isatty v0.0.16 // indirect
        github.com/nats-io/nats-server/v2 v2.9.14 // indirect
        github.com/nats-io/nkeys v0.3.0 // indirect
        github.com/nats-io/nuid v1.0.1 // indirect
        golang.org/x/crypto v0.6.0 // indirect
        golang.org/x/sys v0.5.0 // indirect
)
