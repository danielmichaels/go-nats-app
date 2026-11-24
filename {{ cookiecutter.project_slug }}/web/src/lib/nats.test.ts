// Runs the browser connection code against the real Go server and NATS, with
// short lifetimes, so token renewal and session end are tested end to end.
import { type ChildProcess, execFileSync, spawn } from 'node:child_process'
import { mkdtempSync, readdirSync, rmSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { afterAll, beforeAll, expect, test } from 'vitest'
import { http } from './http'
import { connectApp, request } from './nats'

const root = resolve(import.meta.dirname, '../../..')
let dir: string
let server: ChildProcess
let base: string
let setupToken: string
let cookie = ''

function freePort(): Promise<number> {
  return new Promise((res) => {
    const s = createServer().listen(0, '127.0.0.1', () => {
      const { port } = s.address() as { port: number }
      s.close(() => res(port))
    })
  })
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

// The browser sends the cookie and resolves relative URLs; Node does not.
const realFetch = globalThis.fetch
globalThis.fetch = async (input, init = {}) => {
  const headers = new Headers(init.headers)
  if (cookie) headers.set('cookie', cookie)
  const res = await realFetch(new URL(String(input), base), { ...init, headers })
  for (const c of res.headers.getSetCookie()) {
    const [pair] = c.split(';')
    cookie = /max-age=(0|-)/i.test(c) ? '' : pair
  }
  return res
}
const listeners = { addEventListener() {}, removeEventListener() {} }
Object.assign(globalThis, {
  document: { visibilityState: 'visible', ...listeners },
  window: { ...listeners, location: { assign() {} } },
})

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), 'web-test-'))
  execFileSync('go', ['build', '-o', join(dir, 'bin') + '/', './cmd/...'], { cwd: root, stdio: 'inherit' })
  const bin = join(dir, 'bin', readdirSync(join(dir, 'bin'))[0])
  const [httpPort, natsPort, wsPort] = [await freePort(), await freePort(), await freePort()]
  base = `http://127.0.0.1:${httpPort}`
  server = spawn(bin, [], {
    env: {
      ...process.env,
      APP_ENV: 'test',
      DATA_DIR: join(dir, 'data'),
      HTTP_ADDR: `127.0.0.1:${httpPort}`,
      PUBLIC_URL: base,
      NATS_PORT: String(natsPort),
      NATS_WS_PORT: String(wsPort),
      CONNECT_TOKEN_TTL: '3s',
      USER_JWT_TTL: '4s',
    },
  })
  let log = ''
  server.stderr!.on('data', (b) => (log += b))
  for (let i = 0; i < 100 && !setupToken; i++) {
    setupToken = /token=([0-9a-f]+)/.exec(log)?.[1] ?? ''
    await sleep(100)
  }
  if (!setupToken) throw new Error(`server did not start:\n${log}`)
  await http.setup(setupToken, 'admin', 'correct horse battery')
}, 120_000)

afterAll(() => {
  server?.kill()
  if (dir) rmSync(dir, { recursive: true, force: true })
})

// The renewal timer (30 s) is slower than the connect token (3 s), as after a
// suspended tab, so each reconnect must get a new token before CONNECT.
test('admission is renewed after the user JWT expires', async () => {
  const conn = await connectApp()
  let reconnects = 0
  void (async () => {
    for await (const s of conn.nc.status()) if (s.type === 'reconnect') reconnects++
  })()
  await request(conn.nc, 'app.api.notes.create', { request_id: 'before-expiry', title: 'before' })
  await sleep(9_000)
  const { notes } = await request<{ notes: { id: string }[] }>(conn.nc, 'app.api.notes.list')
  expect(reconnects).toBeGreaterThan(0)
  expect(notes.map((n) => n.id)).toContain('before-expiry')
  await conn.close()
}, 30_000)

test('logout ends the connection', async () => {
  const conn = await connectApp()
  await http.logout()
  const reason = await Promise.race([conn.ended, sleep(2_500).then(() => 'timeout')])
  expect(reason).toBe('expired')
  await sleep(100)
  expect(conn.nc.isClosed()).toBe(true)
}, 30_000)
