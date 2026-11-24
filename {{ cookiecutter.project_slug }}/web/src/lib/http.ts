// HTTP is used only for authentication and NATS admission.

export class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message)
  }
}

export type User = {
  id: string
  username: string
  role: 'admin' | 'member'
  disabled: boolean
  identities?: { issuer: string; subject: string }[]
}

export type Session = { user: User; method: 'password' | 'oidc'; deadline: string; session_id: string }

export type AuthConfig = {
  setup_required: boolean
  oidc: boolean
  nats: { servers: string[]; sentinel: string }
}

export type ConnectToken = {
  token: string
  inbox_prefix: string
  expires: string
  user: User
  session_id: string
}

async function call<T>(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
  })
  if (!res.ok) {
    const data = await res.json().catch(() => ({}))
    throw new HttpError(res.status, data.error ?? res.statusText)
  }
  return res.status === 204 ? (undefined as T) : res.json()
}

export const http = {
  config: () => call<AuthConfig>('GET', '/auth/config'),
  session: async (): Promise<Session | null> => {
    try {
      return await call<Session>('GET', '/auth/session')
    } catch (e) {
      if (e instanceof HttpError && e.status === 401) return null
      throw e
    }
  },
  login: (username: string, password: string) => call<Session>('POST', '/auth/login', { username, password }),
  setup: (token: string, username: string, password: string) =>
    call<Session>('POST', '/auth/setup', { token, username, password }),
  logout: () => call<void>('POST', '/auth/logout', {}),
  connectToken: (signal?: AbortSignal) => call<ConnectToken>('POST', '/auth/connect-token', {}, signal),
}

// Tabs share one session cookie. A tab that signs in or out tells the others.
const channel = typeof BroadcastChannel === 'undefined' ? null : new BroadcastChannel('app-session')

let leaving = false

// leave tells other tabs and loads path. The session end that this tab
// caused is then not reported as an expiry.
export function leave(path: string) {
  leaving = true
  channel?.postMessage('changed')
  window.location.assign(path)
}

export function isLeaving() {
  return leaving
}

export function onSessionChange(f: () => void): () => void {
  if (!channel) return () => {}
  const h = () => f()
  channel.addEventListener('message', h)
  return () => channel.removeEventListener('message', h)
}
