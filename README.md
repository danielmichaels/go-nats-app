# go-nats-app

A [Cookiecutter](https://cookiecutter.readthedocs.io/) template for a
NATS-first Go app with persistent login, an auth callout, per-user NATS
permissions, KV storage and live updates. Pick one frontend:

- `datastar`: Go, [templ](https://templ.guide) and
  [Datastar](https://data-star.dev). The server renders HTML and SSE, and does
  all application work on a NATS connection that belongs to the session.
- `react`: React, TypeScript and TanStack Router, Query and Form. The browser
  connects to NATS over WebSocket with `@nats-io/nats-core` and does all
  application work there.

Both frontends have password login, one-time first-admin setup and optional
OIDC sign-in with server-side provider refresh. Login survives reloads and
restarts. HTTP is used only for sign-in, NATS admission, static files and
health checks; there is no REST application API. A notes example shows
storage, per-user isolation and live updates.

## Use

```sh
uvx cookiecutter gh:danielmichaels/go-nats-app
```

| Prompt | Default |
| --- | --- |
| `project_name` | `go-nats-app` |
| `project_slug` | from `project_name` |
| `github_username` | `danielmichaels` |
| `go_module_path` | `github.com/<github_username>/<project_slug>` |
| `cmd_name` | `app` |
| `project_description` | |
| `docker_registry` | `ghcr.io/<github_username>` |
| `frontend` | `datastar` or `react` |

The generated project contains only the selected frontend. Its README covers
local development, the NATS account layout, OIDC setup, external NATS,
backups and cookies.

Generated projects need Go 1.26 or later and [task](https://taskfile.dev).
React projects also need Node 24 and pnpm.

## Develop the template

```sh
scripts/smoke.sh datastar
scripts/smoke.sh react
```

`smoke.sh` generates a project named "Acme Notes" with module
`github.com/acme/acme-notes`, then runs gofmt, vet, the race tests and a
build. For React it also installs, type-checks, builds and tests the web app. CI runs
both and builds the container images.

Files with Go composite literals or frontend code are copied without
rendering (`_copy_without_render` in `cookiecutter.json`), because Jinja reads
`{{` as template syntax.

## References

This template replaces the earlier `go-nats-app` scaffold. It adapts the
behaviour of two projects; it copies no code from the first.

- **React:** the browser-over-auth-callout design of the Synadia control-plane
  portal (`synadia/control-plane`, through `32e03d1e8`), from its documented
  handoff. Adapted: session cookie in KV keyed by a hash, 60 s connect token
  with a public deny-all sentinel, per-session inbox, an authenticator that
  reads the latest token, Query invalidation after reconnect. Changed: one
  account layout shared with Datastar, no tenancy or event-store sequencing,
  renewal on tab wake and network return as well as on a timer.
- **Datastar:** `danielmichaels/lookout-lab`, `lab/portal`, `lab/issuer`,
  `lab/users` and `lab/identity` at `be82d75d`. Adapted: one NATS user
  connection per web session, OIDC Authorization Code with PKCE and KV login
  attempts, exact subject binding, provider refresh on restore. Changed:
  password sessions are durable too (the issuer admits a session, not a
  password), refresh is serialized across replicas with KV revisions, and
  bindings are stored per user instead of in a config file.
