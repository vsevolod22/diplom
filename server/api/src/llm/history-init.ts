import { HistoryStore } from './history-store.js';
import { historyEnabled } from './history-runtime.js';

// Operator-only, network-none, API UID/auth mount. Never imported by Nest.
// Restoring requires a separate explicit quiesced lineage rotation; never reset quota.
// --migrate-summary-schema requires a stopped API and an operator backup. It is
// additive v3 -> v4 only: preserves history/pending/incarnation, never a restore.
// Old binaries refuse v4; rollback requires a coordinated restore, not a version edit.
// v4 -> v5 is a separate, existing-file action with no provider environment.
// Once v5 commits, HOLD on failure: no old-v4 binary, header downgrade or stale restore.
try {
  const action = process.argv[2];
  if (process.argv.length !== 3 ||
      !['--initialize', '--rotate-restored-lineage', '--migrate-summary-schema', '--migrate-history-v4-to-v5'].includes(action)) throw new Error();
  if (action === '--migrate-history-v4-to-v5') {
    HistoryStore.migrateSummaryReservations({ path: '/auth/llm-history.sqlite' });
  } else {
    if (!historyEnabled()) throw new Error();
    const store = new HistoryStore('/auth/llm-history.sqlite', action === '--initialize');
    try {
      if (action === '--rotate-restored-lineage') store.rotateRestoredLineage();
      if (action === '--migrate-summary-schema') store.migrateSummarySchema();
    } finally { store.close(); }
  }
  process.stdout.write('History operator action complete. No provider call or runtime activation performed.\n');
} catch {
  process.stderr.write('History operator action refused; no quota reset or automatic repair.\n'); process.exitCode = 1;
}
