import { defineConfig } from 'vitest/config';
import tsconfigPaths from 'vite-tsconfig-paths';

export default defineConfig({
  envDir: false,
  plugins: [tsconfigPaths()],
  test: {
    environment: 'jsdom',
    include: ['tests-vite/ui/scans/ScanSceneTask28{,Palette}.test.tsx'],
    cache: false,
  },
});
