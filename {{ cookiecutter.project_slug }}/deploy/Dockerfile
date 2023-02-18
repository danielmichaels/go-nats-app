FROM golang:{{ cookiecutter.go_version}}-bullseye AS builder

# Move to working directory (/build).
WORKDIR /build

# only copy mod file for better caching
COPY go.mod go.mod
RUN go mod download

ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
# copy files
COPY . .
RUN go build  \
    -ldflags="-s -w" \
    -o app {{ cookiecutter.go_module_path.strip() }}/cmd/{{ cookiecutter.cmd_name.strip() }}

FROM alpine

COPY --from=builder ["/build/app", "/usr/bin/app"]

## Command to run when starting the container.
ENTRYPOINT ["app"]
