import type { NatsConnection } from '@nats-io/nats-core'
import { QueryClient, useQueryClient } from '@tanstack/react-query'
import { createContext, type ReactNode, use, useEffect, useState } from 'react'
import type { Session, User } from './http'
import { type AppConnection, ApiError } from './nats'

export type ConnState = 'connected' | 'reconnecting' | 'disconnected'

type Ctx = { session: Session | null; conn: AppConnection | null }

const AppContext = createContext<Ctx>({ session: null, conn: null })

export function AppProvider({ value, children }: { value: Ctx; children: ReactNode }) {
  return <AppContext value={value}>{children}</AppContext>
}

export function useSession(): Session | null {
  return use(AppContext).session
}

export function useConn(): { nc: NatsConnection; user: User } {
  const { conn } = use(AppContext)
  if (!conn) throw new Error('not connected')
  return { nc: conn.nc, user: conn.user }
}

// Every query key starts with ['nats', userId], so the cache of one user is
// never read for another. The page reloads on sign-in and sign-out as well.
export const keys = {
  all: (userId: string) => ['nats', userId] as const,
  notes: (userId: string) => ['nats', userId, 'notes'] as const,
  users: (userId: string) => ['nats', userId, 'admin', 'users'] as const,
}

export function newQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 30_000,
        retry: (n, e) => !(e instanceof ApiError && e.code >= 400 && e.code < 500) && n < 3,
      },
      mutations: { retry: false },
    },
  })
}

// useConnState follows the connection and refetches the user's queries after
// a reconnect, because events sent while disconnected are lost.
export function useConnState(): ConnState {
  const { nc, user } = useConn()
  const qc = useQueryClient()
  const [state, setState] = useState<ConnState>(nc.isClosed() ? 'disconnected' : 'connected')
  useEffect(() => {
    let live = true
    void (async () => {
      for await (const s of nc.status()) {
        if (!live) break
        if (s.type === 'reconnect') {
          setState('connected')
          void qc.invalidateQueries({ queryKey: keys.all(user.id) })
        } else if (s.type === 'disconnect' || s.type === 'reconnecting') {
          setState('reconnecting')
        } else if (s.type === 'close') {
          setState('disconnected')
        }
      }
    })()
    return () => {
      live = false
    }
  }, [nc, qc, user.id])
  return state
}
