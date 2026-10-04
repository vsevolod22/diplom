import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react-swc';
import { defineConfig } from 'vite';
import svgr from 'vite-plugin-svgr';
import tsconfigPaths from 'vite-tsconfig-paths';

// Local opt-in auth only. Never route the protected scan API through the dev server.
const authTarget = process.env.AUTH_DEV_PROXY_TARGET;
if (authTarget) {
  const url = new URL(authTarget);
  if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) ||
    url.origin !== authTarget || !url.port) {
    throw new Error('AUTH_DEV_PROXY_TARGET must be a loopback HTTP origin with an explicit port');
  }
}

export default defineConfig({
  server: authTarget ? {
    proxy: { '^/api/v1/auth(?:/|$)': { target: authTarget, changeOrigin: false } },
  } : undefined,
  plugins: [tailwindcss(), react(), svgr(), tsconfigPaths()],
  build: {
    rollupOptions: { input: ['index.html', 'admin.html'] },
  },
});
