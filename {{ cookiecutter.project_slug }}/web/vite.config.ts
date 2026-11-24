import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// The Go server embeds the build output. In development, Vite proxies the
// authentication routes to it; the browser connects to NATS directly.
export default defineConfig({
  plugins: [react()],
  build: { outDir: '../internal/spa/dist', emptyOutDir: true },
  server: {
    port: 5173,
    proxy: { '/auth': 'http://127.0.0.1:8080', '/readyz': 'http://127.0.0.1:8080' },
  },
})
