import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react-swc';
import svgr from 'vite-plugin-svgr';
import tsconfigPaths from 'vite-tsconfig-paths';

// Test-only source transform. Never load .env files, proxies, app server, or checker.
export default {
  envDir: false,
  plugins: [tailwindcss(), react(), svgr(), tsconfigPaths()],
  server: { host: '127.0.0.1', port: 0, proxy: undefined, hmr: false },
};
