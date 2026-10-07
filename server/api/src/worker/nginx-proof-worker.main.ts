import { runWorker } from './worker-runtime.js';
// Explicit isolated composition, not selected by production env or HTTP.
await runWorker('proof');
