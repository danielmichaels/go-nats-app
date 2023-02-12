FROM golang:{{ cookiecutter.go_version}}-bullseye AS builder

# Move to working directory (/build).
WORKDIR /build

# Copy the code into the container.
COPY . .

RUN go mod download
#
## Set necessary environment variables needed
## for our image and build the sender.
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
RUN go build  \
    -ldflags="-s -w" \
    -o app {{ cookiecutter.go_module_path.strip() }}/cmd/{{ cookiecutter.cmd_name.strip() }}

FROM busybox as busybox

FROM gcr.io/distroless/base

# Add helpful debug tools
COPY --from=busybox ["/bin/sh","/bin/sh"]
COPY --from=busybox ["/bin/ls","/bin/ls"]
COPY --from=busybox ["/bin/cat","/bin/cat"]

COPY --from=builder ["/build/app", "/usr/bin/app"]

## Command to run when starting the container.
ENTRYPOINT ["app"]
