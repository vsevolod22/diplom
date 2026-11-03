import { HISTORY, bytes, hashValue, historyCapacity, validateHead, type HistoryHead } from './history-contract.js';
import { SUMMARY_STORAGE } from './summary-record.js';

// Admission-only shares, not new storage maxima or a promise of reserved tenant
// space. Existing over-share data remains readable; no migration or eviction.
export const HISTORY_OWNER_CAPACITY = Object.freeze({ version: 'history-owner-capacity-v1',
  heads: HISTORY.heads / 8, historyBytes: HISTORY.dbBytes / 8,
  summaries: SUMMARY_STORAGE.entries / 8, summaryBytes: SUMMARY_STORAGE.bytes / 8 });

export type OwnerOccupancy = { scope: string; scanId?: string; bytes: number };

// Only validated, immutable history occupancies can carry this admission exemption.
// It is not serialized or accepted from a caller-supplied flag (including summaries).
const emptyHistoryOccupancies = new WeakSet<OwnerOccupancy>();

export function historyOccupancy(scope: string, head: HistoryHead, storedBytes = bytes(head)): OwnerOccupancy {
  validateHead(head);
  const records = [...head.turns, ...head.decisions];
  const scanId = records[0]?.report.scanId;
  // Old empty heads have no recoverable owner binding. Mixed historical bindings
  // are also unknown; never infer an owner from just the first record.
  const consistentScan = scanId && records.every(record => record.report.scanId === scanId) ? scanId : undefined;
  // Charge the entire scope ceiling while pending. Association/revision growth
  // and any valid terminal reply can consume this charge without new admission.
  const occupancy = Object.freeze({ scope, scanId: consistentScan, bytes: head.pending ? HISTORY.scopeBytes : storedBytes });
  // These legacy placeholders still consume global head count and physical bytes.
  if (!head.turns.length && !head.decisions.length && head.pending === null) emptyHistoryOccupancies.add(occupancy);
  return occupancy;
}

export function assertOwnerCapacity(owner: string, scope: string, nextBytes: number,
  rows: readonly OwnerOccupancy[], limits: { entries: number; bytes: number }): void {
  let entries = 1, size = nextBytes;
  for (const row of rows) {
    if (row.scope === scope || emptyHistoryOccupancies.has(row)) continue;
    // The existing key is SHA256(JSON([owner, scanId])). No auth-store enumeration
    // or new ownership index is needed. Other unknown occupancy is charged to EVERY
    // owner, not treated as free space or silently reassigned/deleted.
    if (row.scanId && hashValue([owner, row.scanId]) !== row.scope) continue;
    entries++; size += row.bytes;
  }
  if (entries > limits.entries || size > limits.bytes) return historyCapacity();
}
