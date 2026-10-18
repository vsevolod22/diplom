import { createHash } from 'node:crypto';
import { ReportViewError, type ReportQuery, type VulnQuery, type SbomQuery, type SecretQuery,
  type ReportLimit, type Severity, type ReportEcosystem } from './report-query.js';

export type ReportPage = {
  version: 1; limit: ReportLimit; offset: number; returnedCount: number;
  totalCount: number | null; matchedCount: number | null;
  sort: ReportQuery['sort']; filters: ReportQuery['filters'];
};
export type ReportContext = { subject: string; scanId: string };
type VulnRow = { findingId: string; severity: Severity };
type SbomRow = { ecosystem: ReportEcosystem; name: string; version: string };
type SecretRow = { findingId: string; ruleId: string; line: number | null };
const ascii = (a: string, b: string): number => a < b ? -1 : a > b ? 1 : 0;
const rank: Record<Severity, number> = { UNKNOWN: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const hash = (value: unknown): string => createHash('sha256').update(JSON.stringify(value,
  (_key, item: unknown) => item !== null && typeof item === 'object' && !Array.isArray(item)
    ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => ascii(a, b))) : item)).digest('hex');
const invalidCursor = (): never => { throw new ReportViewError('INVALID_PAGINATION'); };

function cursorOffset(cursor: unknown, q: string, r: string): number {
  if (cursor === undefined) return 0;
  if (typeof cursor !== 'string' || cursor.length > 512 || !/^[A-Za-z0-9_-]+$/.test(cursor)) return invalidCursor();
  const text = Buffer.from(cursor, 'base64url').toString('utf8');
  let value: unknown;
  try { value = JSON.parse(text); } catch { return invalidCursor(); }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return invalidCursor();
  const token = value as Record<string, unknown>;
  if (Object.keys(token).length !== 4 || token.v !== 1 ||
      typeof token.q !== 'string' || !/^[a-f0-9]{64}$/.test(token.q) ||
      typeof token.r !== 'string' || !/^[a-f0-9]{64}$/.test(token.r) ||
      !Number.isSafeInteger(token.o) || (token.o as number) < 0 || (token.o as number) > 1000 ||
      text !== JSON.stringify({ v: 1, q: token.q, r: token.r, o: token.o }) ||
      Buffer.from(text).toString('base64url') !== cursor) return invalidCursor();
  if (token.q !== q) throw new ReportViewError('REPORT_CURSOR_QUERY_MISMATCH');
  if (token.r !== r) throw new ReportViewError('REPORT_CURSOR_STALE');
  return token.o as number;
}

function paginate<T>(rows: readonly T[], query: ReportQuery, context: ReportContext, snapshot: unknown,
  checked: boolean, matches: (row: T) => boolean, compare: (a: T, b: T) => number) {
  if (rows.length > 1000 || !checked && rows.length !== 0) throw new TypeError('Invalid report dataset');
  const q = hash([1, context.subject, context.scanId, query.kind, query.filters, query.sort, query.limit]);
  const r = hash(snapshot);
  const offset = cursorOffset(query.cursor, q, r);
  const selected = checked ? rows.filter(matches).sort(compare) : [];
  if (offset > selected.length) return invalidCursor();
  const items = selected.slice(offset, offset + query.limit);
  const end = offset + items.length;
  const nextCursor = end < selected.length ? Buffer.from(JSON.stringify({ v: 1, q, r, o: end })).toString('base64url') : null;
  const page: ReportPage = { version: 1, limit: query.limit, offset, returnedCount: items.length,
    totalCount: checked ? rows.length : null, matchedCount: checked ? selected.length : null,
    sort: query.sort, filters: query.filters };
  return { items, nextCursor, page };
}

export function pageVuln<T extends VulnRow>(rows: readonly T[], query: VulnQuery, context: ReportContext, snapshot: unknown, checked = true) {
  return paginate(rows, query, context, snapshot, checked,
    row => query.filters.severity === null || query.filters.severity.includes(row.severity),
    (a, b) => {
      if (a.severity === 'UNKNOWN' && b.severity !== 'UNKNOWN') return 1;
      if (b.severity === 'UNKNOWN' && a.severity !== 'UNKNOWN') return -1;
      return (query.sort === 'severity:asc' ? rank[a.severity] - rank[b.severity] : rank[b.severity] - rank[a.severity]) || ascii(a.findingId, b.findingId);
    });
}
export function pageSbom<T extends SbomRow>(rows: readonly T[], query: SbomQuery, context: ReportContext, snapshot: unknown, checked = true) {
  return paginate(rows, query, context, snapshot, checked,
    row => (query.filters.ecosystem === null || row.ecosystem === query.filters.ecosystem) &&
      (query.filters.name === null || row.name.toLowerCase().includes(query.filters.name)),
    (a, b) => {
      const direction = query.sort.endsWith(':desc') ? -1 : 1;
      return query.sort.startsWith('name:')
        ? direction * ascii(a.name, b.name) || ascii(a.ecosystem, b.ecosystem) || ascii(a.version, b.version)
        : direction * ascii(a.ecosystem, b.ecosystem) || ascii(a.name, b.name) || ascii(a.version, b.version);
    });
}
export function pageSecrets<T extends SecretRow>(rows: readonly T[], query: SecretQuery, context: ReportContext, snapshot: unknown, checked = true) {
  return paginate(rows, query, context, snapshot, checked,
    row => (query.filters.ruleId === null || row.ruleId === query.filters.ruleId) &&
      (query.filters.linePresence === null || (query.filters.linePresence === 'known' ? row.line !== null : row.line === null)),
    (a, b) => {
      const direction = query.sort.endsWith(':desc') ? -1 : 1;
      if (query.sort.startsWith('line:')) {
        if (a.line === null && b.line !== null) return 1;
        if (b.line === null && a.line !== null) return -1;
        return direction * ((a.line ?? 0) - (b.line ?? 0)) || ascii(a.ruleId, b.ruleId) || ascii(a.findingId, b.findingId);
      }
      return direction * ascii(a.ruleId, b.ruleId) || ascii(a.findingId, b.findingId);
    });
}
