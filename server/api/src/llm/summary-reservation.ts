import { historyCapacity, historyUnavailable, isId } from './history-contract.js';
import { exact } from './response.js';
import { SUMMARY_STORAGE, decodeSummaryRecord, summaryRecordHash, type SummaryRow } from './summary-record.js';

const RESERVATION_VERSION = 'durable-summary-reservation-v1';
export const SUMMARY_RESERVATION_MAX_MS = 120_000;
type SummaryReservation = { version: typeof RESERVATION_VERSION; id: string; scanId: string; deadline: number; previous: string | null };
type SummarySlot = {
  scanId: string;
  record: ReturnType<typeof decodeSummaryRecord> | undefined;
  reservation?: SummaryReservation;
};

// Equal payload size preserves the admitted SQLite local/overflow allocation;
// even a shorter payload can otherwise require a B-tree split at completion.
export function padSummary(content: string): string {
  const remaining = SUMMARY_STORAGE.entryBytes - Buffer.byteLength(content);
  if (remaining < 0) return historyCapacity();
  return content + ' '.repeat(remaining);
}

export function summaryReservationContent(id: string, scanId: string, deadline: number, previous: string | null): string {
  if (!isId(id) || !isId(scanId) || !Number.isSafeInteger(deadline) || deadline <= 0) return historyUnavailable();
  // Failed compaction can leave allocation-only trailing padding. Do not nest
  // that padding; preserve ordinary unpadded bytes and recompute the recovery hash.
  const retained = previous !== null && Buffer.byteLength(previous) === SUMMARY_STORAGE.entryBytes ? previous.trimEnd() : previous;
  return padSummary(JSON.stringify({ version: RESERVATION_VERSION, id, scanId, deadline, previous: retained }));
}

// Only schema5 callers may decode this envelope. Reads expose the previous
// ordinary result, never the token, and never reclaim even an expired slot.
export function decodeSummarySlot(row: SummaryRow): SummarySlot {
  try {
    if (!/^[a-f0-9]{64}$/.test(row.scope) || typeof row.content !== 'string' ||
        Buffer.byteLength(row.content) > SUMMARY_STORAGE.entryBytes || summaryRecordHash(row.scope, row.content) !== row.content_hash)
      return historyUnavailable();
    const value: unknown = JSON.parse(row.content);
    if (!exact(value, ['version', 'id', 'scanId', 'deadline', 'previous']) || value.version !== RESERVATION_VERSION) {
      const record = decodeSummaryRecord(row);
      return { scanId: record.value.scanId, record };
    }
    if (!isId(value.id) || !isId(value.scanId) || !Number.isSafeInteger(value.deadline) || (value.deadline as number) <= 0 ||
        value.previous !== null && typeof value.previous !== 'string' || Buffer.byteLength(row.content) !== SUMMARY_STORAGE.entryBytes)
      return historyUnavailable();
    const reservation = value as SummaryReservation;
    const record = reservation.previous === null ? undefined : decodeSummaryRecord({ scope: row.scope,
      content: reservation.previous, content_hash: summaryRecordHash(row.scope, reservation.previous) });
    if (record && record.value.scanId !== reservation.scanId) return historyUnavailable();
    return { scanId: reservation.scanId, record, reservation };
  } catch { return historyUnavailable(); }
}
