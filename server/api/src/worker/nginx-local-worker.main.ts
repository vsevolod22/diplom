import { runWorker } from './worker-runtime.js';
import { localDbTrustAnchorFromEnv } from './vuln-db-trust.js';
await runWorker('local', localDbTrustAnchorFromEnv());
