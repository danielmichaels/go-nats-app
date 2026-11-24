{%- if cookiecutter.frontend == "react" %}
FROM node:24-bookworm-slim AS web
WORKDIR /src/web
RUN corepack enable
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN mkdir -p ../internal/spa/dist && pnpm build
{% endif %}
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
{%- if cookiecutter.frontend == "react" %}
COPY --from=web /src/internal/spa/dist ./internal/spa/dist
{%- endif %}
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/app ./cmd/{{ cookiecutter.cmd_name }}

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
ENV APP_ENV=production HTTP_ADDR=:8080 DATA_DIR=/data NATS_EMBEDDED=false
EXPOSE 8080
ENTRYPOINT ["/app"]
