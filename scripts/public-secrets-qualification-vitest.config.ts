import { defineConfig } from 'vitest/config';
import tsconfigPaths from 'vite-tsconfig-paths';

export default defineConfig({
  plugins: [tsconfigPaths()],
  cacheDir: process.env.PUBLIC_SECRETS_UI_RESULT ? `${process.env.PUBLIC_SECRETS_UI_RESULT}.cache` : '/tmp/public-secrets-qualification-vite-cache',
  test: {
    environment: 'jsdom',
    include: ['scripts/public-secrets-qualification-ui.test.tsx'],
    fileParallelism: false,
    testTimeout: 8000,
    reporters: ['dot'],
  },
});
