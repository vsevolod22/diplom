import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  testMatch: 'scan-scene-task-28.spec.ts',
    outputDir: '../docs/scan-scene-task-28-screens/playwright-results',
  workers: 1,
  use: { baseURL: 'http://127.0.0.1:4186', browserName: 'chromium' },
  webServer: {
    command: 'env -u AUTH_DEV_PROXY_TARGET pnpm exec vite --host 127.0.0.1 --port 4186 --strictPort',
    url: 'http://127.0.0.1:4186',
    reuseExistingServer: false,
    timeout: 30000,
  },
});
