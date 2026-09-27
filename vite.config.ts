import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react-swc';
import { defineConfig } from 'vite';
import svgr from 'vite-plugin-svgr';
import tsconfigPaths from 'vite-tsconfig-paths';

export default defineConfig({
  plugins: [tailwindcss(), react(), svgr(), tsconfigPaths()],
  build: {
    rollupOptions: { input: ['index.html', 'admin.html'] },
  },
});
