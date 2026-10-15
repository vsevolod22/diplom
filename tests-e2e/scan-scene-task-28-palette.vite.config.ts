import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react-swc';
import { defineConfig } from 'vite';
import svgr from 'vite-plugin-svgr';
import tsconfigPaths from 'vite-tsconfig-paths';

export default defineConfig({
  envDir: false,
  plugins: [tailwindcss(), react(), svgr(), tsconfigPaths()],
  server: { proxy: undefined },
});
