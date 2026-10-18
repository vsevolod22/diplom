import { runWorker } from './worker-runtime.js';
import { localDbTrustAnchorFromEnv } from './vuln-db-trust.js';

// Process composition, not a job executionProfile or an environment admission flag.
await runWorker(undefined, localDbTrustAnchorFromEnv(), true);
