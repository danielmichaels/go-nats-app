# {{ cookiecutter.project_name }}

{{ cookiecutter.project_description }}

This is a NATS-first app with the {{ cookiecutter.frontend }} frontend. HTTP
handles sign-in and NATS admission only.
{%- if cookiecutter.frontend == "react" %} The browser does all application
work over its own NATS WebSocket connection.
{%- else %} The server renders HTML and SSE with Datastar, and does all
application work on a NATS connection that belongs to the signed-in session.
{%- endif %}

## Start

```sh
go mod download
{%- if cookiecutter.frontend == "react" %}
task web:install
{%- endif %}
task dev
```

The first start prints a one-time setup token in the log. Open
<http://localhost:8080/setup>, enter the token, and create the first admin.
Admins add other users on the Users page.

| Command | What it does |
| --- | --- |
| `task dev` | Run with an embedded NATS server. Data and keys are in `./data`. |
{%- if cookiecutter.frontend == "react" %}
| `task web:dev` | Run Vite on :5173 with hot reload. Run `task dev` too. |
{%- else %}
| `task generate` | Generate Go code from `.templ` files. |
{%- endif %}
| `task check` | gofmt, vet and race tests{% if cookiecutter.frontend == "react" %}, plus the web type check and connection tests{% endif %}. |
| `task build` | Build `bin/{{ cookiecutter.cmd_name }}`. |
| `task docker-build` | Build the container image. |
| `task nats-setup` | Write the files for an external NATS server. |

Keep `./data` between runs. It holds the development NATS keys and the
JetStream store, so sessions survive a restart. If you delete it, every user
must sign in again.

## How it works

- **Accounts.** NATS runs in operator mode with four accounts. `AUTH` has the
  auth callout. `SVC` has the services and all JetStream data. `USERS` has the
  session users and imports only `app.api.>` and `app.events.>` from `SVC`.
  `SYS` is the system account.
- **Sessions.** A sign-in stores a session in the `app_sessions` KV bucket. The
  key is the SHA-256 of the cookie token, so the bucket holds no usable
  cookies. The cookie restores the session after a reload or a restart.
- **Admission.** A client connects with the public sentinel JWT, which may do
  nothing by itself, plus a 60 s connect token from `POST /auth/connect-token`.
  The callout checks the token, the session and the user, then signs a user JWT
  that expires within 15 minutes and never after the session. The JWT allows
  only the session's own inbox and the user's own events.
- **Caller identity.** Services read the caller's user ID from the
  `Nats-Request-Info` header that the server adds. A request body never names
  the user, and a client cannot set that header.
- **Notes example.** `internal/notes` stores notes in KV behind
  `app.api.notes.create` and `app.api.notes.list`. It publishes changes on
  `app.events.<user>.notes`. The request ID makes a create safe to resend. A
  client that gets no reply does not know if the note was saved; it resends
  the same request ID. Events can be lost, so clients list again after a
  reconnect.

Add your own service next to `internal/notes`: register its endpoints on
`app.api.<name>.>`, get the caller with `api.Identity.Caller`, and add the
subjects to `callout.Permissions`.

## Lifetimes and logout

| Setting | Default | Meaning |
| --- | --- | --- |
| `SESSION_TTL` | `168h` | Absolute session lifetime. Nothing extends it. |
| `CONNECT_TOKEN_TTL` | `60s` | Connect token lifetime. Clients renew every 30 s. |
| `USER_JWT_TTL` | `15m` | NATS user JWT lifetime. Clients reconnect with a new token. |
| `OIDC_REFRESH_MARGIN` | `2m` | Refresh an OIDC identity this long before it expires. |

Logout deletes the session and tells that session's clients to close. A client
that ignores this keeps its connection until its user JWT expires, at most
`USER_JWT_TTL`. Disabling a user works the same way. The app does not
disconnect connections on the server side.

## OIDC sign-in

Password sign-in always works. OIDC is a second, optional method that uses
the same sessions and the same NATS permissions.

1. Register a confidential client with the redirect URI
   `https://<your host>/auth/oidc/callback`. Enable the refresh token grant
   and the `offline_access` scope. The provider must return an ID token on
   refresh.
2. Set `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` and, if it is not
   `PUBLIC_URL` plus `/auth/oidc/callback`, `OIDC_REDIRECT_URL`. Keep the
   secret in your secret store, not in `.env`.
3. On the Users page, link each user to the exact issuer and subject (`sub`).
   The app never links by email or name, and never creates users from OIDC.

The login uses Authorization Code with S256 PKCE, state and nonce. The login
attempt is stored in KV, so the callback can land on another replica. The
provider's tokens stay on the server; the refresh token is kept in the
session record only.

An OIDC session lasts as long as the provider keeps refreshing it, up to
`SESSION_TTL`. The app refreshes before the ID token expires and when it
restores a session after a restart. Refresh is serialized across tabs and
replicas, and a rotated refresh token is saved before it is used.

- If the provider rejects the refresh, or returns another subject, the
  session ends.
- If the provider is down, the session stays only until its last verified ID
  token expires. NATS access never outlives that ID token.
- If the result of a refresh is lost, the session ends, because the old
  refresh token may be spent.

Signing out of the provider does not always revoke its refresh tokens. The
app sees a disabled or signed-out account only when the provider rejects the
next refresh. To end access at once, disable the user in this app.

### Authentik example

1. Create an OAuth2/OpenID provider: client type **Confidential**, redirect URI
   `https://app.example.com/auth/oidc/callback`, and add the
   `offline_access` scope mapping.
2. Create an application that uses it, with slug `notes`.
3. Set:

```sh
OIDC_ISSUER=https://auth.example.com/application/o/notes/
OIDC_CLIENT_ID=<client id>
OIDC_CLIENT_SECRET=<client secret>
```

The issuer must match the `iss` claim exactly, including the trailing slash.
Authentik's `sub` depends on the provider's subject mode; link the value the
provider sends.

## Production

Production (`APP_ENV=production`) refuses to start the embedded NATS server
and requires `COOKIE_SECURE=true`. With secure cookies the session cookie is
`__Host-session`: Secure, HttpOnly, SameSite=Lax, path `/`.

### External NATS

`task nats-setup` writes three files to `nats-setup/` and changes no server:

- `keys.json`: the operator and account root keys. Keep it offline and back
  it up. You need it to change the accounts later.
- `runtime.json`: what the app needs: the service and callout creds, the
  sentinel, the signing seeds for `AUTH` and `USERS`, the callout encryption
  key and the connect-token key. Give it to the app as `NATS_RUNTIME_FILE`
  from your secret store. Every replica uses the same file. A new file signs
  out every user.
- `server.conf`: the operator, a memory resolver with the account JWTs,
  JetStream and a WebSocket listener. Merge it into your server config.

For browsers:

- Serve the WebSocket over TLS and set `NATS_BROWSER_URL=wss://…`.
- Set `allowed_origins` to the app's exact origin
  (`task nats-setup -- -allowed-origins https://app.example.com` or edit the
  file).

Set `NATS_URL` to the server's client URL and `NATS_REPLICAS` to the KV
replica count of your cluster.

### Backups

Back up the JetStream store of the `SVC` account. The `app_users`,
`app_sessions` and `app_notes` buckets are the app's data. `app_sessions` also
holds OIDC refresh tokens, so protect its backups as secrets.
`app_oidc_attempts` holds only short-lived login attempts.

### Container

```sh
task docker-build
docker run -p 8080:8080 \
  -v /secure/runtime.json:/run/secrets/nats-runtime.json:ro \
  -e NATS_URL=tls://nats.example.com:4222 \
  -e NATS_RUNTIME_FILE=/run/secrets/nats-runtime.json \
  -e NATS_BROWSER_URL=wss://nats.example.com \
  -e PUBLIC_URL=https://app.example.com \
  -e COOKIE_SECURE=true \
  {{ cookiecutter.docker_registry.strip() }}/{{ cookiecutter.project_slug }}
```

The image runs as a non-root user (UID 65532). The mounted runtime file must
be readable by that user, or pass `--user` to match its owner.
