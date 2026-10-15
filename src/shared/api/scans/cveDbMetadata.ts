import { z } from 'zod';

// Decoder rejection is not a transient HTTP failure; never retain its previous report baseline.
export class CveReportContractError extends Error {
  constructor() {
    super('Invalid CVE report contract');
    this.name = 'CveReportContractError';
  }
}

const DAY_NS = 86_400_000_000_000n;
const clock = z.number().int().positive().max(253402300799999).refine(Number.isSafeInteger);
export const cveMetadataFields = {
  resultContractVersion: z.literal(2),
  dbPolicy: z.strictObject({
    version: z.literal(2), policy: z.literal('cve-db-updated-at-14d-v2'), evaluatedAt: clock,
    status: z.enum(['usable', 'stale-but-usable']),
    warnings: z.array(z.enum(['DB_DATA_OLDER_THAN_24H', 'DB_PUBLICATION_OVERDUE'])).max(2),
  }),
  usableUntil: z.string(), workerCheckedAt: clock,
};
export type CveMetadata = z.infer<z.ZodObject<typeof cveMetadataFields>>;
type DbTimes = { updatedAt: string; downloadedAt: string; nextUpdate: string };

// Metadata consistency only: the browser does not authenticate the DB signature or files.
function timestampNs(value: string): bigint {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d{1,9})Z$/.exec(value);
  if (!match) throw new Error('Invalid DB timestamp');
  const base = `${match[1]}.000Z`;
  const ms = Date.parse(base);
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== base) throw new Error('Invalid DB calendar');
  return BigInt(ms) * 1_000_000n + BigInt(match[2].padEnd(9, '0'));
}
function warningsAt(db: DbTimes, savedClock: number) {
  const now = BigInt(clock.parse(savedClock)) * 1_000_000n;
  const updated = timestampNs(db.updatedAt);
  const downloaded = timestampNs(db.downloadedAt);
  const next = timestampNs(db.nextUpdate);
  if (updated > now + 300_000_000_000n || downloaded > now + 300_000_000_000n ||
      downloaded < updated || next <= updated || next - updated > 7n * DAY_NS || now - updated > 14n * DAY_NS)
    throw new Error('Invalid saved DB policy evidence');
  const warnings: CveMetadata['dbPolicy']['warnings'] = [];
  if (now - updated > DAY_NS) warnings.push('DB_DATA_OLDER_THAN_24H');
  if (now >= next) warnings.push('DB_PUBLICATION_OVERDUE');
  return warnings;
}
export function validateCveMetadata(value: CveMetadata & { db: DbTimes; checkedAt: string }): boolean {
  try {
    const { dbPolicy, workerCheckedAt, db, checkedAt, usableUntil } = value;
    if (workerCheckedAt > dbPolicy.evaluatedAt || checkedAt !== new Date(workerCheckedAt).toISOString()) return false;
    warningsAt(db, workerCheckedAt);
    const warnings = warningsAt(db, dbPolicy.evaluatedAt);
    const expiry = timestampNs(db.updatedAt) + 14n * DAY_NS;
    const seconds = expiry / 1_000_000_000n;
    const fraction = expiry % 1_000_000_000n;
    const expectedUntil = `${new Date(Number(seconds * 1000n)).toISOString().slice(0, 19)}.${String(fraction).padStart(9, '0')}Z`;
    return usableUntil === expectedUntil && JSON.stringify(warnings) === JSON.stringify(dbPolicy.warnings) &&
      dbPolicy.status === (warnings.length ? 'stale-but-usable' : 'usable');
  } catch { return false; }
}
export function hasCveMetadata(value: unknown): boolean {
  return !!value && typeof value === 'object' && Object.keys(cveMetadataFields).some(key => key in value);
}
export function cveMetadataIdentity(value: { db?: unknown; resultContractVersion?: unknown; dbPolicy?: unknown; usableUntil?: unknown; workerCheckedAt?: unknown; checkedAt?: unknown; os?: unknown; node?: unknown }) {
  return JSON.stringify([value.resultContractVersion, value.db, value.dbPolicy, value.usableUntil, value.workerCheckedAt, value.checkedAt, value.os, value.node]);
}
export function savedDbAge(db: DbTimes, evaluatedAt: number): string {
  const age = BigInt(evaluatedAt) * 1_000_000n - timestampNs(db.updatedAt);
  return age < 0n ? 'в пределах допуска будущего времени (до 300 секунд)' : `${Number(age / 3_600_000_000_000n)} полных ч`;
}
