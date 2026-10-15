import { defineConfig } from '@playwright/test';
import baseConfig from './playwright.config';

// Keep the shared suite's explicit testMatch unchanged; reuse its isolated Vite setup.
export default defineConfig({
  ...baseConfig,
  testMatch: 'scan-create-long-reference.spec.ts',
  outputDir: '/tmp/scan-create-long-reference-results',
  workers: 1,
  use: { ...baseConfig.use, baseURL: 'http://127.0.0.1:4197' },
  webServer: {
    command:
      'pnpm exec vite --config tests-e2e/report-task-39.vite.config.ts --host 127.0.0.1 --port 4197 --strictPort',
    url: 'http://127.0.0.1:4197',
    reuseExistingServer: false,
    timeout: 30000,
  },
});
