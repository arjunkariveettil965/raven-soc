import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const apiProxyTarget = env.VITE_DEV_API_PROXY || 'http://127.0.0.1:8000'

  const proxyConfig = {
    '/api/v1': {
      target: apiProxyTarget,
      changeOrigin: true,
    },
  }

  return {
    plugins: [react()],
    server: {
      proxy: proxyConfig,
    },
    preview: {
      proxy: proxyConfig,
    },
  }
})
