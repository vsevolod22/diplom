import { z } from 'zod';
import { advisorySeverity, assertPlainWire } from './vulnAdvisory';

export const REPORT_LIMITS = [5, 10, 25, 50] as const;
export const REPORT_SEVERITIES = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export type ReportKind = 'vuln' | 'sbom' | 'secret';
export type Severity = typeof REPORT_SEVERITIES[number];
export type ReportLimit = typeof REPORT_LIMITS[number];
export type VulnReportQuery = { view: 'report-v1'; limit?: ReportLimit; severity?: Severity[] | null; sort?: 'severity:asc' | 'severity:desc' };
export type SbomReportQuery = { view: 'report-v1'; limit?: ReportLimit; ecosystem?: 'apk' | 'npm' | null; name?: string | null; sort?: 'name:asc' | 'name:desc' | 'ecosystem:asc' | 'ecosystem:desc' };
export type SecretReportQuery = { view: 'report-v1'; limit?: ReportLimit; ruleId?: string | null; linePresence?: 'known' | 'unknown' | null; sort?: 'ruleId:asc' | 'ruleId:desc' | 'line:asc' | 'line:desc' };
export type ReportQueries = { vuln: VulnReportQuery; sbom: SbomReportQuery; secret: SecretReportQuery };
const limit = z.union([z.literal(5), z.literal(10), z.literal(25), z.literal(50)]);
const literalName = z.string().regex(/^[A-Za-z0-9@._+/-]{1,128}$/);
export const REPORT_RULE_ID_PATTERN = /^[A-Za-z0-9._-]{1,80}$/;
const ruleId = z.string().regex(REPORT_RULE_ID_PATTERN);
const filters = {
  vuln: z.strictObject({ severity: z.array(advisorySeverity).min(1).max(5).nullable() }),
  sbom: z.strictObject({ ecosystem: z.enum(['apk', 'npm']).nullable(), name: literalName.nullable() }),
  secret: z.strictObject({ ruleId: ruleId.nullable(), linePresence: z.enum(['known', 'unknown']).nullable() }),
};
const sorts = {
  vuln: z.enum(['severity:asc', 'severity:desc']),
  sbom: z.enum(['name:asc', 'name:desc', 'ecosystem:asc', 'ecosystem:desc']),
  secret: z.enum(['ruleId:asc', 'ruleId:desc', 'line:asc', 'line:desc']),
};
const baseQuery = { view: z.literal('report-v1'), limit: limit.optional() };
const queries = {
  vuln: z.strictObject({ ...baseQuery, severity: filters.vuln.shape.severity.optional(), sort: sorts.vuln.optional() }),
  sbom: z.strictObject({ ...baseQuery, ecosystem: filters.sbom.shape.ecosystem.optional(), name: filters.sbom.shape.name.optional(), sort: sorts.sbom.optional() }),
  secret: z.strictObject({ ...baseQuery, ruleId: filters.secret.shape.ruleId.optional(), linePresence: filters.secret.shape.linePresence.optional(), sort: sorts.secret.optional() }),
};
const count = z.number().int().min(0).max(1000);
const pageBase = { version: z.literal(1), limit, offset: count, returnedCount: count, totalCount: count.nullable(), matchedCount: count.nullable() };
const pages = {
  vuln: z.strictObject({ ...pageBase, sort: sorts.vuln, filters: filters.vuln }),
  sbom: z.strictObject({ ...pageBase, sort: sorts.sbom, filters: filters.sbom }),
  secret: z.strictObject({ ...pageBase, sort: sorts.secret, filters: filters.secret }),
};
export type ReportPages = { [K in ReportKind]: z.infer<typeof pages[K]> };
export type ReportPage = ReportPages[ReportKind];
export class ReportViewContractError extends Error {
  constructor() { super('Недопустимый ответ report-v1'); }
}
export class ReportCursorResetError extends Error {
  constructor() { super('Cursor отчёта устарел или относится к другому запросу'); }
}
export class ReportQueryError extends ReportViewContractError {
  constructor() { super(); this.message = 'Исправьте фильтры отчёта и повторите загрузку с первой страницы.'; }
}

export function normalizeReportQuery<K extends ReportKind>(kind: K, query: ReportQueries[K]): Pick<ReportPages[K], 'limit' | 'sort' | 'filters'>;
export function normalizeReportQuery(kind: ReportKind, query: ReportQueries[ReportKind]) {
  let parsed;
  try {
    assertPlainWire(query);
    parsed = queries[kind].parse(query);
  } catch { throw new ReportQueryError(); }
  if (kind === 'vuln') {
    const selected = 'severity' in parsed ? parsed.severity : null;
    const canonical = selected ? REPORT_SEVERITIES.filter(item => selected.includes(item)) : null;
    return { limit: parsed.limit ?? 25, sort: parsed.sort ?? 'severity:desc', filters: { severity: canonical?.length === REPORT_SEVERITIES.length ? null : canonical } };
  }
  if (kind === 'sbom') return { limit: parsed.limit ?? 25, sort: parsed.sort ?? 'name:asc', filters: { ecosystem: 'ecosystem' in parsed ? parsed.ecosystem ?? null : null, name: 'name' in parsed ? parsed.name?.toLowerCase() ?? null : null } };
  return { limit: parsed.limit ?? 25, sort: parsed.sort ?? 'ruleId:asc', filters: { ruleId: 'ruleId' in parsed ? parsed.ruleId ?? null : null, linePresence: 'linePresence' in parsed ? parsed.linePresence ?? null : null } };
}

export function reportViewSearch<K extends ReportKind>(kind: K, query: ReportQueries[K], cursor?: string): string {
  const normalized = normalizeReportQuery(kind, query);
  if (cursor !== undefined && (typeof cursor !== 'string' || cursor.length === 0 || cursor.length > 512)) throw new ReportViewContractError();
  const params = new URLSearchParams({ view: 'report-v1', limit: String(normalized.limit), sort: normalized.sort });
  for (const [key, value] of Object.entries(normalized.filters)) {
    if (value !== null) params.set(key, Array.isArray(value) ? value.join(',') : value);
  }
  if (cursor !== undefined) params.set('cursor', cursor);
  return params.toString();
}

// Offset is a page coordinate, never part of the report/query identity.
export function reportViewIdentity(page?: ReportPage): string | null {
  return page ? JSON.stringify([page.version, page.limit, page.sort, page.filters, page.totalCount, page.matchedCount]) : null;
}

const opaqueCursor = z.string().min(1).max(512).nullable();
const secretRow = z.strictObject({ findingId: z.string(), ruleId: z.string(), line: z.number().int().nonnegative().nullable(), evidenceRef: z.string() });
const secretEnvelope = z.strictObject({ findings: z.array(secretRow).max(50), nextCursor: opaqueCursor, coverage: z.unknown(), page: pages.secret });
function plainRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ReportViewContractError();
  return value as Record<string, unknown>;
}

/** Reuse the closed legacy row/receipt schemas with a numeric cursor bridge; never strip v2 evidence. */
export function parseReportView<K extends ReportKind, T>(
  value: unknown, kind: K, query: ReportQueries[K], cursor: string | undefined, parseLegacy: (value: unknown) => T,
): T & { page: ReportPages[K]; nextCursor: string | null } {
  try {
    assertPlainWire(value);
    const envelope = plainRecord(value);
    const page = pages[kind].parse(envelope.page) as ReportPages[K];
    const nextCursor = opaqueCursor.parse(envelope.nextCursor);
    if (cursor !== undefined) opaqueCursor.unwrap().parse(cursor);
    const expected = normalizeReportQuery(kind, query);
    if (page.limit !== expected.limit || page.sort !== expected.sort || JSON.stringify(page.filters) !== JSON.stringify(expected.filters)) throw new ReportViewContractError();
    const selectedSeverity = 'severity' in page.filters ? page.filters.severity : null;
    if (selectedSeverity && JSON.stringify(selectedSeverity) !== JSON.stringify(REPORT_SEVERITIES.filter(item => selectedSeverity.includes(item)))) throw new ReportViewContractError();
    const rows = z.array(z.unknown()).max(page.limit).parse(envelope[kind === 'sbom' ? 'components' : 'findings']);
    const coverage = kind === 'secret' && envelope.coverage !== null ? plainRecord(envelope.coverage) : null;
    const checked = kind === 'secret' ? coverage?.outcome === 'checked' : envelope.outcome === 'checked';
    const wholeTotal = kind === 'secret' ? coverage?.findingCount : envelope[kind === 'sbom' ? 'componentCount' : 'findingCount'];
    const end = page.offset + rows.length;
    if (page.returnedCount !== rows.length || page.offset % page.limit !== 0 || (cursor === undefined ? page.offset !== 0 : page.offset === 0) || nextCursor === cursor) throw new ReportViewContractError();
    if (checked) {
      if (Object.values(page.filters).every(item => item === null) && page.matchedCount !== page.totalCount) throw new ReportViewContractError();
      if (kind === 'secret' && coverage?.errorCode !== null) throw new ReportViewContractError();
      if (page.totalCount === null || page.matchedCount === null || page.totalCount !== wholeTotal || page.matchedCount > page.totalCount || end > page.matchedCount ||
          (nextCursor === null ? end !== page.matchedCount : rows.length !== page.limit || end >= page.matchedCount)) throw new ReportViewContractError();
    } else if (page.totalCount !== null || page.matchedCount !== null || page.offset !== 0 || rows.length !== 0 || nextCursor !== null) throw new ReportViewContractError();
    if (kind === 'secret') secretEnvelope.parse(value);
    const payload = { ...envelope };
        delete payload.page;
        delete payload.nextCursor;
    const parsed = parseLegacy({ ...payload, nextCursor: nextCursor === null ? null : end });
    // Validate the returned subset, not an invented global filter over the loaded page.
    for (const row of rows) {
      const item = plainRecord(row);
      if ('severity' in page.filters && page.filters.severity && !page.filters.severity.includes(item.severity as Severity)) throw new ReportViewContractError();
      if ('ecosystem' in page.filters && ((page.filters.ecosystem && page.filters.ecosystem !== item.ecosystem) ||
          (page.filters.name && (typeof item.name !== 'string' || !item.name.replace(/[a-z]/g, char => char.toUpperCase()).includes(page.filters.name.replace(/[a-z]/g, char => char.toUpperCase())))))) throw new ReportViewContractError();
      if ('ruleId' in page.filters && ((page.filters.ruleId && page.filters.ruleId !== item.ruleId) ||
          (page.filters.linePresence && (page.filters.linePresence === 'known') !== (item.line !== null)))) throw new ReportViewContractError();
    }
    return { ...parsed, nextCursor, page };
  } catch { throw new ReportViewContractError(); }
}
