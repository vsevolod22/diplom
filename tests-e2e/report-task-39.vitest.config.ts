import { defineConfig } from 'vitest/config';
import tsconfigPaths from 'vite-tsconfig-paths';
export default defineConfig({ envDir: false, plugins: [tsconfigPaths()], test: {
  environment: 'jsdom', cache: false,
  include: ['tests-vite/ui/scans/task39*.test.{ts,tsx}', 'tests-vite/ui/scans/reportPaging.test.tsx', 'tests-vite/ui/scans/scanTransport.test.ts'],
} });
