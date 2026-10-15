import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  testMatch: 'scan-scene-task-28-palette.spec.ts',
  outputDir: '../test-results/scan-scene-task-28-palette/playwright-results',
  reporter: [['list'], ['json', { outputFile: 'test-results/scan-scene-task-28-palette/results.json' }]],
  workers: 1,
  use: { baseURL: 'http://127.0.0.1:4187', browserName: 'chromium' },
  webServer: {
    command:
      'pnpm exec vite --config tests-e2e/scan-scene-task-28-palette.vite.config.ts --host 127.0.0.1 --port 4187 --strictPort',
    url: 'http://127.0.0.1:4187',
    reuseExistingServer: false,
    timeout: 30000,
  },
});
