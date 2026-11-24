import { useForm } from '@tanstack/react-form'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { keys, useConn, useConnState, useSession } from './lib/app'
import { http, leave, type User } from './lib/http'
import { request, UncertainError } from './lib/nats'

type Note = { id: string; title: string; body: string; created: string }

const loginErrors: Record<string, string> = {
  refused: 'The identity provider login failed.',
  state: 'The login state did not match. Start again.',
  expired: 'The login took too long or was already used. Start again.',
  unbound: 'This identity is not linked to an active user. Ask an admin to link it.',
  unavailable: 'Sign-in is temporarily unavailable.',
  session: 'Your session ended. Sign in again.',
}

function errorText(e: unknown) {
  return e instanceof Error ? e.message : 'Request failed.'
}

export function Layout({ children }: { children: React.ReactNode }) {
  const session = useSession()
  return (
    <>
      <header>
        <Link className="brand" to="/">
          Notes
        </Link>
        {session && (
          <nav>
            {session.user.role === 'admin' && <Link to="/admin">Users</Link>}
            <span className="who" data-testid="whoami">
              {session.user.username} · {session.method}
            </span>
            <button
              className="link"
              type="button"
              onClick={async () => {
                await http.logout().catch(() => {})
                leave('/login')
              }}
            >
              Sign out
            </button>
          </nav>
        )}
      </header>
      <main>{children}</main>
    </>
  )
}

function useAuthConfig() {
  return useQuery({ queryKey: ['auth-config'], queryFn: http.config, staleTime: Infinity })
}

export function LoginPage() {
  const search = useSearch({ strict: false }) as { error?: string; redirect?: string }
  const cfg = useAuthConfig()
  const [error, setError] = useState(loginErrors[search.error ?? ''] ?? '')
  const form = useForm({
    defaultValues: { username: '', password: '' },
    onSubmit: async ({ value }) => {
      try {
        await http.login(value.username, value.password)
        leave('/')
      } catch (e) {
        setError(errorText(e))
      }
    },
  })
  return (
    <section className="card narrow">
      <h1>Sign in</h1>
      <p className="error" role="alert">
        {error}
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault()
          void form.handleSubmit()
        }}
      >
        <form.Field name="username">
          {(f) => (
            <label>
              Username
              <input name="username" autoComplete="username" required value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} />
            </label>
          )}
        </form.Field>
        <form.Field name="password">
          {(f) => (
            <label>
              Password
              <input name="password" type="password" autoComplete="current-password" required value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} />
            </label>
          )}
        </form.Field>
        <form.Subscribe selector={(s) => s.isSubmitting}>
          {(busy) => (
            <button type="submit" disabled={busy}>
              Sign in with password
            </button>
          )}
        </form.Subscribe>
      </form>
      {cfg.data?.oidc && (
        <>
          <div className="or">or</div>
          <a className="button secondary" href="/auth/oidc/start?redirect=/">
            Sign in with your identity provider
          </a>
        </>
      )}
      {cfg.data?.setup_required && (
        <p className="muted">
          No users yet. <Link to="/setup">Create the first admin</Link>.
        </p>
      )}
    </section>
  )
}

export function SetupPage() {
  const navigate = useNavigate()
  const cfg = useAuthConfig()
  const [error, setError] = useState('')
  useEffect(() => {
    if (cfg.data && !cfg.data.setup_required) void navigate({ to: '/login' })
  }, [cfg.data, navigate])
  const form = useForm({
    defaultValues: { token: '', username: '', password: '' },
    onSubmit: async ({ value }) => {
      try {
        await http.setup(value.token, value.username, value.password)
        leave('/')
      } catch (e) {
        setError(errorText(e))
      }
    },
  })
  const field = (name: 'token' | 'username' | 'password', label: string, type = 'text') => (
    <form.Field name={name}>
      {(f) => (
        <label>
          {label}
          <input name={name} type={type} required autoComplete="off" value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} />
        </label>
      )}
    </form.Field>
  )
  return (
    <section className="card narrow">
      <h1>Create the first admin</h1>
      <p className="muted">Enter the one-time setup token from the server log.</p>
      <p className="error" role="alert">
        {error}
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault()
          void form.handleSubmit()
        }}
      >
        {field('token', 'Setup token')}
        {field('username', 'Username')}
        {field('password', 'Password', 'password')}
        <button type="submit">Create admin</button>
      </form>
    </section>
  )
}

function requestId() {
  const b = new Uint8Array(16)
  crypto.getRandomValues(b)
  return btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function NotesPage() {
  const { nc, user } = useConn()
  const qc = useQueryClient()
  const state = useConnState()
  const notes = useQuery({
    queryKey: keys.notes(user.id),
    queryFn: async () => (await request<{ notes: Note[] }>(nc, 'app.api.notes.list')).notes,
  })

  useEffect(() => {
    const sub = nc.subscribe(`app.events.${user.id}.notes`)
    void (async () => {
      for await (const _ of sub) void qc.invalidateQueries({ queryKey: keys.notes(user.id) })
    })()
    return () => sub.unsubscribe()
  }, [nc, qc, user.id])

  // The request ID stays until the server confirms the note, so a retry after
  // an unknown outcome cannot store it twice.
  const [rid, setRid] = useState(requestId)
  const create = useMutation({
    mutationFn: (v: { title: string; body: string }) =>
      request(nc, 'app.api.notes.create', { request_id: rid, title: v.title, body: v.body }),
    onSuccess: () => {
      setRid(requestId())
      form.reset()
      void qc.invalidateQueries({ queryKey: keys.notes(user.id) })
    },
  })
  const form = useForm({
    defaultValues: { title: '', body: '' },
    onSubmit: ({ value }) => create.mutateAsync(value).catch(() => {}),
  })
  const createError =
    create.error instanceof UncertainError
      ? 'No reply in time. The note may be saved; submit again to retry safely.'
      : create.error
        ? errorText(create.error)
        : ''

  return (
    <>
      <section className="card">
        <h1>Your notes</h1>
        <form
          id="note-form"
          onSubmit={(e) => {
            e.preventDefault()
            void form.handleSubmit()
          }}
        >
          <form.Field name="title">
            {(f) => (
              <label>
                Title
                <input name="title" maxLength={200} required value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} />
              </label>
            )}
          </form.Field>
          <form.Field name="body">
            {(f) => (
              <label>
                Body
                <textarea name="body" maxLength={4000} value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} />
              </label>
            )}
          </form.Field>
          <button type="submit" disabled={create.isPending}>
            Add note
          </button>
          <p className="error" role="alert">
            {createError}
          </p>
        </form>
      </section>
      <section className="card">
        <p className={`state ${state}`} data-testid="conn-state">
          {state}
        </p>
        {notes.error && <p className="error">{errorText(notes.error)}</p>}
        <ul className="notes" data-testid="notes">
          {notes.data?.map((n) => (
            <li key={n.id}>
              <strong>{n.title}</strong>
              {n.body && <p>{n.body}</p>}
              <time>{new Date(n.created).toLocaleString()}</time>
            </li>
          ))}
          {notes.data?.length === 0 && <li className="muted">No notes yet.</li>}
        </ul>
      </section>
    </>
  )
}

export function AdminPage() {
  const { nc, user } = useConn()
  const qc = useQueryClient()
  const users = useQuery({
    queryKey: keys.users(user.id),
    queryFn: async () => (await request<{ users: User[] }>(nc, 'app.api.admin.users.list')).users,
  })
  const refresh = () => qc.invalidateQueries({ queryKey: keys.users(user.id) })
  const update = useMutation({
    mutationFn: (body: object) => request(nc, 'app.api.admin.users.update', body),
    onSettled: refresh,
  })
  const create = useMutation({
    mutationFn: (body: object) => request(nc, 'app.api.admin.users.create', body),
    onSuccess: () => {
      form.reset()
      void refresh()
    },
  })
  const form = useForm({
    defaultValues: { username: '', password: '', role: 'member' },
    onSubmit: ({ value }) => create.mutateAsync(value).catch(() => {}),
  })
  const err = update.error ?? create.error ?? users.error
  return (
    <>
      <section className="card">
        <h1>Users</h1>
        <p className="error" role="alert">
          {err ? errorText(err) : ''}
        </p>
        <table id="users">
          <thead>
            <tr>
              <th>User</th>
              <th>Role</th>
              <th>Status</th>
              <th>Linked identities</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {users.data?.map((u) => (
              <tr key={u.id}>
                <td>{u.username}</td>
                <td>{u.role}</td>
                <td>{u.disabled ? 'disabled' : 'active'}</td>
                <td>
                  {u.identities?.map((i) => (
                    <div className="mono" key={i.issuer + i.subject}>
                      {i.issuer} · {i.subject}
                    </div>
                  ))}
                  <form
                    className="inline"
                    onSubmit={(e) => {
                      e.preventDefault()
                      const f = new FormData(e.currentTarget)
                      update.mutate({ id: u.id, link: { issuer: f.get('issuer'), subject: f.get('subject') } })
                    }}
                  >
                    <input name="issuer" placeholder="issuer" required />
                    <input name="subject" placeholder="subject" required />
                    <button type="submit">Link</button>
                  </form>
                </td>
                <td>
                  <button type="button" onClick={() => update.mutate({ id: u.id, disabled: !u.disabled })}>
                    {u.disabled ? 'Enable' : 'Disable'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      <section className="card">
        <h2>Add a user</h2>
        <form
          onSubmit={(e) => {
            e.preventDefault()
            void form.handleSubmit()
          }}
        >
          <form.Field name="username">
            {(f) => (
              <label>
                Username <input name="username" required value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} />
              </label>
            )}
          </form.Field>
          <form.Field name="password">
            {(f) => (
              <label>
                Password{' '}
                <input name="password" type="password" minLength={12} required value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} />
              </label>
            )}
          </form.Field>
          <form.Field name="role">
            {(f) => (
              <label>
                Role
                <select name="role" value={f.state.value} onChange={(e) => f.handleChange(e.target.value)}>
                  <option value="member">member</option>
                  <option value="admin">admin</option>
                </select>
              </label>
            )}
          </form.Field>
          <button type="submit">Add user</button>
        </form>
      </section>
    </>
  )
}
