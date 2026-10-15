export const REPORT_SEVERITIES = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export type Severity = typeof REPORT_SEVERITIES[number];
export type ReportKind = 'vuln' | 'sbom' | 'secret';
export type ReportLimit = 5 | 10 | 25 | 50;
export type VulnSort = 'severity:asc' | 'severity:desc';
export type SbomSort = 'name:asc' | 'name:desc' | 'ecosystem:asc' | 'ecosystem:desc';
export type SecretSort = 'ruleId:asc' | 'ruleId:desc' | 'line:asc' | 'line:desc';
export type VulnFilters = { severity: Severity[] | null };
export type SbomFilters = { ecosystem: 'apk' | 'npm' | null; name: string | null };
export type SecretFilters = { ruleId: string | null; linePresence: 'known' | 'unknown' | null };
type CommonQuery = { limit: ReportLimit; cursor: unknown };
export type VulnQuery = CommonQuery & { kind: 'vuln'; sort: VulnSort; filters: VulnFilters };
export type SbomQuery = CommonQuery & { kind: 'sbom'; sort: SbomSort; filters: SbomFilters };
export type SecretQuery = CommonQuery & { kind: 'secret'; sort: SecretSort; filters: SecretFilters };
export type ReportQuery = VulnQuery | SbomQuery | SecretQuery;
export type ReportErrorCode = 'INVALID_REPORT_QUERY' | 'INVALID_PAGINATION' |
  'REPORT_CURSOR_QUERY_MISMATCH' | 'REPORT_CURSOR_STALE';

// Framework-free errors keep the synthetic query/page tests outside the runtime graph.
export class ReportViewError extends Error {
  constructor(readonly errorCode: ReportErrorCode) { super(errorCode); }
}
const invalid = (): never => { throw new ReportViewError('INVALID_REPORT_QUERY'); };
const filterKeys = ['severity', 'ecosystem', 'name', 'ruleId', 'linePresence', 'sort'];

export function hasReportView(value: unknown): boolean {
  return value !== null && typeof value === 'object' && Object.hasOwn(value, 'view');
}

function queryObject(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return invalid();
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !('value' in Object.getOwnPropertyDescriptor(value, key)!)) return invalid();
  }
  return value as Record<string, unknown>;
}
function scalar(query: Record<string, unknown>, key: string): string | undefined {
  if (!Object.hasOwn(query, key)) return undefined;
  const value = query[key];
  if (typeof value !== 'string' || value.length === 0) return invalid();
  return value;
}
function choice<T extends string>(value: string | undefined, values: readonly T[], fallback: T): T {
  if (value === undefined) return fallback;
  if (!values.includes(value as T)) return invalid();
  return value as T;
}

// Cursor decoding belongs after the owner-scoped snapshot read, not in query parsing.
export function parseReportQuery(kind: ReportKind, value: unknown): ReportQuery | undefined {
  const query = queryObject(value);
  if (!Object.hasOwn(query, 'view')) {
    if (filterKeys.some(key => Object.hasOwn(query, key))) return invalid();
    return undefined;
  }
  const keys = ['view', 'limit', 'cursor', 'sort', ...(kind === 'vuln' ? ['severity'] :
    kind === 'sbom' ? ['ecosystem', 'name'] : ['ruleId', 'linePresence'])];
  if (Object.keys(query).some(key => !keys.includes(key)) || scalar(query, 'view') !== 'report-v1') return invalid();
  const limit = choice(scalar(query, 'limit'), ['5', '10', '25', '50'] as const, '25');
  const common = { limit: Number(limit) as ReportLimit, cursor: Object.hasOwn(query, 'cursor') ? query.cursor ?? null : undefined };
  if (kind === 'vuln') {
    const raw = scalar(query, 'severity');
    if (raw !== undefined && raw.length > 32) return invalid();
    const values = raw === undefined ? [] : raw.split(',');
    if (new Set(values).size !== values.length || values.some(item => !(REPORT_SEVERITIES as readonly string[]).includes(item))) return invalid();
    const severity = raw === undefined || values.length === REPORT_SEVERITIES.length ? null :
      REPORT_SEVERITIES.filter(item => values.includes(item));
    return { ...common, kind, sort: choice(scalar(query, 'sort'), ['severity:asc', 'severity:desc'], 'severity:desc'), filters: { severity } };
  }
  if (kind === 'sbom') {
    const ecosystem = scalar(query, 'ecosystem'), name = scalar(query, 'name');
    if (ecosystem !== undefined && ecosystem !== 'apk' && ecosystem !== 'npm' ||
        name !== undefined && !/^[A-Za-z0-9@._+/-]{1,128}$/.test(name)) return invalid();
    return { ...common, kind, sort: choice(scalar(query, 'sort'), ['name:asc', 'name:desc', 'ecosystem:asc', 'ecosystem:desc'], 'name:asc'),
      filters: { ecosystem: ecosystem ?? null, name: name?.toLowerCase() ?? null } };
  }
  const ruleId = scalar(query, 'ruleId'), linePresence = scalar(query, 'linePresence');
  if (ruleId !== undefined && !/^[A-Za-z0-9._-]{1,80}$/.test(ruleId) ||
      linePresence !== undefined && linePresence !== 'known' && linePresence !== 'unknown') return invalid();
  return { ...common, kind, sort: choice(scalar(query, 'sort'), ['ruleId:asc', 'ruleId:desc', 'line:asc', 'line:desc'], 'ruleId:asc'),
    filters: { ruleId: ruleId ?? null, linePresence: linePresence ?? null } };
}
