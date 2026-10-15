import { HistoryStore } from './history-store.js';
import { historyEnabled } from './history-runtime.js';

// Operator-only, network-none, API UID/auth mount. Never imported by Nest.
// Restoring requires a separate explicit quiesced lineage rotation; never reset quota.
try {
  if (!historyEnabled() || process.argv.length !== 3 || !['--initialize', '--rotate-restored-lineage'].includes(process.argv[2])) throw new Error();
  const store = new HistoryStore('/auth/llm-history.sqlite', process.argv[2] === '--initialize');
  try { if (process.argv[2] === '--rotate-restored-lineage') store.rotateRestoredLineage(); }
  finally { store.close(); }
  process.stdout.write('History operator action complete. No provider call or runtime activation performed.\n');
} catch {
  process.stderr.write('History operator action refused; no quota reset or automatic repair.\n'); process.exitCode = 1;
}
