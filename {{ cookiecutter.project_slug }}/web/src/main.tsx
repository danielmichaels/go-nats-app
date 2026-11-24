import { QueryClientProvider } from '@tanstack/react-query'
import { createRootRouteWithContext, createRoute, createRouter, Outlet, RouterProvider, redirect } from '@tanstack/react-router'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { AppProvider, newQueryClient } from './lib/app'
import { http, isLeaving, onSessionChange, type Session } from './lib/http'
import { type AppConnection, connectApp, SessionEnded } from './lib/nats'
import { AdminPage, Layout, LoginPage, NotesPage, SetupPage } from './pages'
import './app.css'

type RouterContext = { session: Session | null }

const root = createRootRouteWithContext<RouterContext>()({
  component: () => (
    <Layout>
      <Outlet />
    </Layout>
  ),
})

const signedIn = ({ context, location }: { context: RouterContext; location: { href: string } }) => {
  if (!context.session) throw redirect({ to: '/login', search: { redirect: location.href } })
}

const routes = [
  createRoute({ getParentRoute: () => root, path: '/', beforeLoad: signedIn, component: NotesPage }),
  createRoute({
    getParentRoute: () => root,
    path: '/admin',
    beforeLoad: (o) => {
      signedIn(o)
      if (o.context.session?.user.role !== 'admin') throw redirect({ to: '/' })
    },
    component: AdminPage,
  }),
  createRoute({
    getParentRoute: () => root,
    path: '/login',
    beforeLoad: ({ context }) => {
      if (context.session) throw redirect({ to: '/' })
    },
    component: LoginPage,
  }),
  createRoute({ getParentRoute: () => root, path: '/setup', component: SetupPage }),
]

const router = createRouter({ routeTree: root.addChildren(routes), context: { session: null } })

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}

function Unavailable({ error }: { error: unknown }) {
  return (
    <main>
      <section className="card narrow">
        <h1>Cannot connect</h1>
        <p className="error">{error instanceof Error ? error.message : String(error)}</p>
        <button type="button" onClick={() => window.location.reload()}>
          Try again
        </button>
      </section>
    </main>
  )
}

// The cookie restores the session on every load. Admission to NATS happens
// before the app renders, so pages always have a connection.
async function start() {
  const el = createRoot(document.getElementById('root')!)
  let session: Session | null = null
  let conn: AppConnection | null = null
  try {
    session = await http.session()
    if (session) conn = await connectApp()
  } catch (e) {
    if (!(e instanceof SessionEnded)) {
      el.render(<Unavailable error={e} />)
      return
    }
    session = null
  }
  if (conn) {
    void conn.ended.then(() => {
      if (!isLeaving()) window.location.assign('/login?error=session')
    })
  }
  // A sign-in or sign-out in another tab reloads this one.
  onSessionChange(() => {
    if (!isLeaving()) window.location.reload()
  })

  const queryClient = newQueryClient()
  el.render(
    <StrictMode>
      <AppProvider value={{ session, conn }}>
        <QueryClientProvider client={queryClient}>
          <RouterProvider router={router} context={{ session }} />
        </QueryClientProvider>
      </AppProvider>
    </StrictMode>,
  )
}

void start()
