import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Dev server proxies /api to wkdmgr-mgmt's own dev-mode TCP listener isn't
// a thing (mgmt only binds Unix sockets) -- for local frontend development
// point this at a socat/nginx bridge, or just build and let nginx serve
// the static bundle alongside the real mgmt socket. See README.md.
export default defineConfig({
  plugins: [vue()],
  build: {
    outDir: 'dist',
  },
})
