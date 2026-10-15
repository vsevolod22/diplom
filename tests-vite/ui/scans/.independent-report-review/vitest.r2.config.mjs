import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../../../', import.meta.url));

export default {
  root,
  envDir: false,
  plugins: [],
  resolve: { alias: { '@': fileURLToPath(new URL('src', new URL('../../../../', import.meta.url))) } },
  esbuild: { jsx: 'automatic' },
  test: {
    include: ['tests-vite/ui/scans/reportViewR2.test.tsx', 'tests-vite/ui/scans/.independent-report-review/corrective-r2.test.tsx'],
    environment: 'jsdom',
    setupFiles: [],
    globalSetup: [],
    cache: false,
    maxWorkers: 1,
    minWorkers: 1,
    fileParallelism: false,
    testTimeout: 5000,
    hookTimeout: 5000,
  },
};
