import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  testMatch: ['scans.accessibility.spec.ts', 'auth.demo.spec.ts'],
  use: { baseURL: 'http://127.0.0.1:4178', browserName: 'chromium', reducedMotion: 'reduce' },
  webServer: { command: 'pnpm exec vite --host 127.0.0.1 --port 4178 --strictPort', url: 'http://127.0.0.1:4178', reuseExistingServer: false, timeout: 30000 },
});
