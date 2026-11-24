import { type NatsConnection, wsconnect, headers as natsHeaders } from '@nats-io/nats-core'
import { type ConnectToken, HttpError, http } from './http'

// A connect token lives 60 s on the server. Renew at 30 s, and whenever the
// tab wakes or the network returns, because timers stop while a device sleeps.
const RENEW_MS = 30_000
const AUTH_WAIT_MS = 1_500

export type EndReason = 'expired' | 'identity-changed'

export type AppConnection = {
  nc: NatsConnection
  user: ConnectToken['user']
  sessionId: string
  // ended resolves when the session can no longer be admitted.
  ended: Promise<EndReason>
  close: () => Promise<void>
}

export class SessionEnded extends Error {}

export async function connectApp(): Promise<AppConnection> {
  const cfg = await http.config()
  let current: ConnectToken
  try {
    current = await http.connectToken()
  } catch (e) {
    if (e instanceof HttpError && e.status === 401) throw new SessionEnded('not signed in')
    throw e
  }
  const first = current
  let endedResolve!: (r: EndReason) => void
  const ended = new Promise<EndReason>((r) => (endedResolve = r))
  let over = false

  const end = (reason: EndReason) => {
    if (over) return
    over = true
    endedResolve(reason)
  }

  // renew is single-flight: tabs share the session, each tab renews once.
  let renewing: Promise<ConnectToken | null> | null = null
  const renew = (): Promise<ConnectToken | null> => {
    renewing ??= http
      .connectToken()
      .then((t) => {
        if (t.user.id !== first.user.id || t.session_id !== first.session_id) {
          end('identity-changed')
          return null
        }
        current = t
        return t
      })
      .catch((e) => {
        if (e instanceof HttpError && e.status === 401) end('expired')
        return null
      })
      .finally(() => (renewing = null))
    return renewing
  }

  const fresh = () => Date.parse(current.expires) - Date.now() > 5_000

  // The authenticator runs at every CONNECT. A stale token is still sent
  // when renewal is slow: the server refuses it and the client tries again.
  const authenticator = async () => {
    if (over) throw new SessionEnded('session ended')
    if (!fresh()) {
      await Promise.race([renew(), new Promise((r) => setTimeout(r, AUTH_WAIT_MS))])
      if (over) throw new SessionEnded('session ended')
    }
    return { jwt: cfg.nats.sentinel, auth_token: current.token }
  }

  const nc = await wsconnect({
    servers: cfg.nats.servers,
    inboxPrefix: first.inbox_prefix,
    authenticator,
    ignoreAuthErrorAbort: true,
    maxReconnectAttempts: -1,
    reconnectTimeWait: 1_000,
    name: `browser:${first.session_id}`,
  })

  const timer = setInterval(renew, RENEW_MS)
  const wake = () => {
    if (document.visibilityState === 'visible') void renew()
  }
  document.addEventListener('visibilitychange', wake)
  window.addEventListener('online', wake)

  // The server publishes here when the session ends, such as a logout in
  // another browser or a disabled user.
  const prefix = `app.events.${first.user.id}`
  const ends = [nc.subscribe(`${prefix}.session.${first.session_id}`), nc.subscribe(`${prefix}.account`)]
  for (const sub of ends) {
    void (async () => {
      for await (const _ of sub) {
        end('expired')
        break
      }
    })()
  }

  void (async () => {
    for await (const s of nc.status()) {
      if (s.type === 'disconnect' || s.type === 'reconnecting' || s.type === 'error') void renew()
    }
  })()

  const close = async () => {
    over = true
    clearInterval(timer)
    document.removeEventListener('visibilitychange', wake)
    window.removeEventListener('online', wake)
    if (!nc.isClosed()) await nc.close()
  }
  void ended.then(close)
  void nc.closed().then(() => {
    if (!over) void renew()
  })

  return { nc, user: first.user, sessionId: first.session_id, ended, close }
}

export class ApiError extends Error {
  constructor(public code: number, message: string) {
    super(message)
  }
}

// UncertainError means the request may have run: the reply did not arrive.
export class UncertainError extends Error {}

export async function request<T>(nc: NatsConnection, subject: string, body?: unknown, timeout = 5_000): Promise<T> {
  let msg
  try {
    msg = await nc.request(subject, body === undefined ? '' : JSON.stringify(body), { timeout, headers: natsHeaders() })
  } catch (e) {
    const err = e as Error
    if (err.name === 'TimeoutError' || /timeout/i.test(err.message)) throw new UncertainError('No reply in time.')
    if (/no responders/i.test(err.message)) throw new ApiError(503, 'The service is not running.')
    if (/permission/i.test(err.message)) throw new ApiError(403, 'Permission denied.')
    throw err
  }
  const code = msg.headers?.get('Nats-Service-Error-Code')
  if (code) throw new ApiError(Number(code), msg.headers?.get('Nats-Service-Error') ?? 'Request failed')
  return msg.json<T>()
}
