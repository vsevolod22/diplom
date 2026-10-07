// Advisory-v1 is data only: no scanner URLs, computed scores, or inferred language.
export const ADVISORY_SOURCES = ['unknown', 'alpine', 'nvd', 'ghsa', 'npm', 'nodejs-security-wg', 'osv', 'cve', 'redhat', 'ubuntu', 'photon', 'amazon', 'oracle-oval', 'julia', 'alma', 'azure', 'rocky', 'cbl-mariner', 'bitnami', 'ruby-advisory-db', 'bottlerocket'] as const;
export type SourceId = typeof ADVISORY_SOURCES[number];
export type Severity = 'UNKNOWN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
const severities: Severity[] = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const states = ['available', 'missing', 'invalid', 'redacted', 'truncated', 'unsupported', 'omitted'] as const;
export type FieldState = typeof states[number];
export type PlainField = { value: string | null; state: FieldState; redacted: boolean };
export type SourceCvss = { family: 'v2' | 'v3'; version: '2.0' | '3.0' | '3.1' | null; versionState: FieldState; reportedScore: number | null; scoreState: FieldState; vector: string | null; vectorState: FieldState };
export type AdvisoryAssessment = { source: SourceId; provenanceRef: string; title: PlainField; description: PlainField; language: string | null; severity: Severity | null; fixedVersion: string | null; cvss: SourceCvss | null };
export type AdvisoryReference = { kind: 'canonical' | 'calculator'; authority: 'cve' | 'nvd' | 'first'; url: string };
const conflicts = ['title', 'description', 'severity', 'fixedVersion', 'cvss'] as const;
const limitations = ['invalid_metadata', 'redaction', 'field_limit', 'assessment_limit', 'reference_limit', 'finding_budget', 'scan_budget', 'report_budget'] as const;
export type AdvisoryV1 = { schemaVersion: 1; state: 'available' | 'omitted'; assessments: AdvisoryAssessment[]; references: AdvisoryReference[]; conflicts: (typeof conflicts[number])[]; conflictState: 'none' | 'present' | 'unknown'; limitations: (typeof limitations[number])[] };
export const ADVISORY_FINDING_BYTES = 16_384;
export const ADVISORY_SCAN_BYTES = 1_048_576;
export const jsonBytes = (value: unknown): number => Buffer.byteLength(JSON.stringify(value));
export const plainObject = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value) && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null) && Reflect.ownKeys(value).every(key => typeof key === 'string' && !['__proto__', 'prototype', 'constructor'].includes(key) && 'value' in Object.getOwnPropertyDescriptor(value, key)!);
const exact = (value: unknown, keys: string[]): value is Record<string, unknown> => plainObject(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
export const sourceId = (value: unknown): SourceId => typeof value === 'string' && (ADVISORY_SOURCES as readonly string[]).includes(value) ? value as SourceId : 'unknown';
const missing = (): PlainField => ({ value: null, state: 'missing', redacted: false });
const version = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._+~:-]{0,79}$/.test(value);
const language = (value: unknown): value is string => typeof value === 'string' && value.length <= 35 && /^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$/.test(value);
function utf8Prefix(value: string, max: number): string {
  let result = '', bytes = 0;
  for (const character of value) { bytes += Buffer.byteLength(character); if (bytes > max) break; result += character; }
  return result;
}
export function normalizePlain(value: unknown, max: number): PlainField {
  if (value == null || value === '') return missing();
  if (typeof value !== 'string') return { value: null, state: 'invalid', redacted: false };
  const safe = value
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)/gi, '')
    .replace(/<(script|style|iframe|object|svg)\b[^>]*>[\s\S]*?(?:<\/\1\s*>|$)/gi, '')
    .replace(/<[^>]*>/g, '')
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/(?:https?:\/\/|www\.)[^\s<>]+/gi, '')
    .replace(/\b(?:bearer\s+(?:"(?:\\.|[^"\\])*(?:"|$)|'(?:\\.|[^'\\])*(?:'|$)|[^\r\n,;}]+)|(?:password|passwd|secret|credentials?|api[_-]?key|access[_-]?key|token|signature|x-amz-[\w-]+)["']?\s*[:=]\s*(?:"(?:\\.|[^"\\])*(?:"|$)|'(?:\\.|[^'\\])*(?:'|$)|[^\r\n,;}]+))/gi, '')
    .replace(/\b(?:CANARY[\w-]*|[\w-]*CANARY[\w-]*|AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]{12,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b/gi, '')
    .replace(/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\ufeff\ud800-\udfff]/gu, ' ')
    .trim();
  const redacted = safe !== value.trim();
  if (!safe) return { value: null, state: redacted ? 'redacted' : 'missing', redacted };
  const truncated = Buffer.byteLength(safe) > max;
  return { value: utf8Prefix(safe, max).trimEnd(), state: truncated ? 'truncated' : 'available', redacted };
}
// Only base metrics are implemented. Optional or unknown metrics fail closed.
export function validV3Vector(value: unknown): value is string {
  if (typeof value !== 'string' || Buffer.byteLength(value) > 256 || !/^CVSS:3\.[01]\//.test(value)) return false;
  const metrics: Record<string, string> = { AV: 'NALP', AC: 'LH', PR: 'NLH', UI: 'NR', S: 'UC', C: 'NLH', I: 'NLH', A: 'NLH' };
  const parts = value.split('/').slice(1), seen = new Set<string>();
  return parts.length === 8 && parts.every(part => {
    const [key, level, extra] = part.split(':');
    if (!Object.hasOwn(metrics, key) || !level || level.length !== 1 || extra !== undefined || !metrics[key].includes(level) || seen.has(key)) return false;
    seen.add(key); return true;
  });
}
function cvss(raw: Record<string, unknown>, family: 'v2' | 'v3'): SourceCvss {
  const score = raw[family === 'v3' ? 'V3Score' : 'V2Score'];
  const vector = raw[family === 'v3' ? 'V3Vector' : 'V2Vector'];
  const validScore = typeof score === 'number' && Number.isFinite(score) && score >= 0 && score <= 10;
  const validVector = family === 'v3' && validV3Vector(vector);
  return { family, version: family === 'v2' ? '2.0' : validVector ? (vector as string).slice(5, 8) as '3.0' | '3.1' : null,
    versionState: family === 'v2' || validVector ? 'available' : vector == null ? 'missing' : 'invalid',
    reportedScore: validScore ? score : null, scoreState: validScore ? 'available' : score == null ? 'missing' : 'invalid',
    vector: validVector ? vector as string : null, vectorState: family === 'v2' ? 'unsupported' : validVector ? 'available' : vector == null ? 'missing' : 'invalid' };
}
function references(cveId: string, assessments: AdvisoryAssessment[]): AdvisoryReference[] {
  const refs: AdvisoryReference[] = /^CVE-[0-9]{4}-[0-9]{4,12}$/.test(cveId) ? [
    { kind: 'canonical', authority: 'cve', url: `https://www.cve.org/CVERecord?id=${cveId}` },
    { kind: 'canonical', authority: 'nvd', url: `https://nvd.nist.gov/vuln/detail/${cveId}` },
  ] : [];
  if (refs.length > 0 && assessments.some(a => a.cvss?.version === '3.1' && validV3Vector(a.cvss.vector))) refs.push({ kind: 'calculator', authority: 'first', url: 'https://www.first.org/cvss/calculator/3.1' });
  return refs;
}
function stableKey(value: unknown): string {
  return JSON.stringify(value, (_key, item) => plainObject(item) ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item);
}
const compare = (a: unknown, b: unknown): number => stableKey(a) < stableKey(b) ? -1 : stableKey(a) > stableKey(b) ? 1 : 0;
function finalize(assessments: AdvisoryAssessment[], cveId: string, prior: AdvisoryV1['limitations'] = [], priorConflicts: AdvisoryV1['conflicts'] = [], unknown = false, bound = true): AdvisoryV1 {
  const unique = [...new Map(assessments.map(a => [stableKey(a), a])).values()].sort(compare);
  const found = conflicts.filter(key => priorConflicts.includes(key) || (key === 'cvss'
    ? ['v2', 'v3'].some(family => ['reportedScore', 'vector', 'version'].some(field => new Set(unique.flatMap(a => {
      const value = a.cvss?.family === family ? a.cvss[field as keyof SourceCvss] : null;
      return value == null ? [] : [stableKey(value)];
    })).size > 1))
    : new Set(unique.flatMap(a => {
    const value = key === 'title' || key === 'description' ? a[key].value : a[key];
    return value === null ? [] : [stableKey(value)];
  })).size > 1));
  const limits = new Set(prior);
  for (const a of unique) {
    if (a.title.redacted || a.description.redacted) limits.add('redaction');
    if (a.title.state === 'truncated' || a.description.state === 'truncated') limits.add('field_limit');
    if (a.title.state === 'invalid' || a.description.state === 'invalid' || a.cvss && [a.cvss.scoreState, a.cvss.vectorState].includes('invalid')) limits.add('invalid_metadata');
  }
  if (bound && unique.length > 16) { limits.add('assessment_limit'); unknown = true; }
  const kept = bound ? unique.slice(0, 16) : unique;
  return { schemaVersion: 1, state: 'available', assessments: kept, references: references(cveId, kept), conflicts: found,
    conflictState: unknown ? 'unknown' : found.length ? 'present' : 'none', limitations: limitations.filter(l => limits.has(l)) };
}
export function normalizeAdvisory(raw: Record<string, unknown>, provenanceRef: string, cveId: string): AdvisoryV1 {
  const base = (source: SourceId): AdvisoryAssessment => ({ source, provenanceRef, title: missing(), description: missing(), language: null, severity: null, fixedVersion: null, cvss: null });
  const main = base(plainObject(raw.DataSource) ? sourceId(raw.DataSource.ID) : 'unknown');
  main.title = normalizePlain(raw.Title, 512); main.description = normalizePlain(raw.Description, 4096);
  main.language = language(raw.Language) ? raw.Language : null;
  main.fixedVersion = version(raw.FixedVersion) ? raw.FixedVersion : null;
  const severity = base(sourceId(raw.SeveritySource)); severity.severity = severities.includes(raw.Severity as Severity) ? raw.Severity as Severity : null;
  const rows = [main, severity];
  const invalid: AdvisoryV1['limitations'] = [];
  if (raw.Language != null && !language(raw.Language) || raw.FixedVersion != null && raw.FixedVersion !== '' && !version(raw.FixedVersion) || raw.DataSource != null && (!plainObject(raw.DataSource) || sourceId(raw.DataSource.ID) === 'unknown') || raw.SeveritySource != null && sourceId(raw.SeveritySource) === 'unknown') invalid.push('invalid_metadata');
  if (raw.VendorSeverity != null) {
    if (!plainObject(raw.VendorSeverity)) invalid.push('invalid_metadata');
    else for (const [source, score] of Object.entries(raw.VendorSeverity)) {
      if (sourceId(source) === 'unknown' || !Number.isInteger(score) || (score as number) < 0 || (score as number) > 4) { invalid.push('invalid_metadata'); continue; }
      const row = base(sourceId(source)); row.severity = severities[score as number]; rows.push(row);
    }
  }
  if (raw.CVSS != null) {
    if (!plainObject(raw.CVSS)) invalid.push('invalid_metadata');
    else for (const [source, data] of Object.entries(raw.CVSS)) {
      if (!plainObject(data)) { invalid.push('invalid_metadata'); continue; }
      if (sourceId(source) === 'unknown') invalid.push('invalid_metadata');
      for (const family of ['v2', 'v3'] as const) {
        if (Object.keys(data).some(key => key.startsWith(family === 'v3' ? 'V3' : 'V2'))) {
          const row = base(sourceId(source)); row.cvss = cvss(data, family); rows.push(row);
        }
      }
      if (Object.keys(data).some(key => !['V2Score', 'V2Vector', 'V3Score', 'V3Vector'].includes(key))) invalid.push('invalid_metadata');
    }
  }
  return finalize(rows, cveId, invalid, [], false, false);
}
export function mergeAdvisories(a: AdvisoryV1, b: AdvisoryV1, cveId: string): AdvisoryV1 {
  return finalize([...a.assessments, ...b.assessments], cveId, [...a.limitations, ...b.limitations], [...a.conflicts, ...b.conflicts], a.conflictState === 'unknown' || b.conflictState === 'unknown', false);
}
export function omittedAdvisory(reason: 'finding_budget' | 'scan_budget' | 'report_budget'): AdvisoryV1 {
  return { schemaVersion: 1, state: 'omitted', assessments: [], references: [], conflicts: [], conflictState: 'unknown', limitations: [reason] };
}
type FindingWithAdvisory = { findingId: string; cveId: string; advisory?: AdvisoryV1 | null };
export function allocateAdvisoryBudget<T extends FindingWithAdvisory>(findings: T[]): T[] {
  const copies = findings.map(f => ({ ...f }));
  // Reserve every compact omission first, so the limit is never exceeded by later rows.
  let used = 2 + Math.max(0, copies.length - 1) + copies.reduce((n, f) => n + (f.advisory ? jsonBytes(omittedAdvisory('scan_budget')) : 0), 0);
  for (const f of [...copies].sort((a, b) => a.findingId < b.findingId ? -1 : a.findingId > b.findingId ? 1 : 0)) {
    if (!f.advisory) continue;
    if (f.advisory.state === 'available') f.advisory = finalize(f.advisory.assessments, f.cveId, f.advisory.limitations, f.advisory.conflicts, f.advisory.conflictState === 'unknown');
    if (jsonBytes(f) > ADVISORY_FINDING_BYTES) f.advisory = omittedAdvisory('finding_budget');
    const delta = jsonBytes(f.advisory) - jsonBytes(omittedAdvisory('scan_budget'));
    if (used + delta > ADVISORY_SCAN_BYTES) f.advisory = omittedAdvisory('scan_budget');
    else used += delta;
  }
  return copies;
}
function invalid(): never { throw new TypeError('Invalid vulnerability advisory'); }
function plainArray(value: unknown): value is unknown[] {
  return Array.isArray(value) && Object.getPrototypeOf(value) === Array.prototype && Reflect.ownKeys(value).every(key => typeof key === 'string' && (key === 'length' || /^(0|[1-9][0-9]*)$/.test(key)) && 'value' in Object.getOwnPropertyDescriptor(value, key)!) && Object.keys(value).length === value.length;
}
function orderedUnique(value: unknown, allowed: readonly string[]): value is string[] {
  return plainArray(value) && value.every((item, i) => typeof item === 'string' && allowed.includes(item) && (i === 0 || allowed.indexOf(value[i - 1] as string) < allowed.indexOf(item)));
}
function validatePlain(value: unknown, max: number): void {
  if (!exact(value, ['value', 'state', 'redacted']) || !(states as readonly unknown[]).includes(value.state) || typeof value.redacted !== 'boolean') invalid();
  if (value.state === 'available' || value.state === 'truncated') {
    if (typeof value.value !== 'string' || !value.value || Buffer.byteLength(value.value) > max || normalizePlain(value.value, max).value !== value.value) invalid();
  } else if (value.value !== null) invalid();
  if (value.state === 'redacted' && !value.redacted) invalid();
}
export function validateAdvisory(value: unknown, cveId: string): asserts value is AdvisoryV1 {
  if (!exact(value, ['schemaVersion', 'state', 'assessments', 'references', 'conflicts', 'conflictState', 'limitations']) || value.schemaVersion !== 1 || !['available', 'omitted'].includes(value.state as string) || !plainArray(value.assessments) || value.assessments.length > 16 || !plainArray(value.references) || value.references.length > 8 || !orderedUnique(value.conflicts, conflicts) || !orderedUnique(value.limitations, limitations) || !['none', 'present', 'unknown'].includes(value.conflictState as string)) invalid();
  if (value.conflictState === 'present' && value.conflicts.length === 0 || value.conflictState === 'none' && value.conflicts.length !== 0) invalid();
  if (value.state === 'omitted') {
    if (value.assessments.length || value.references.length || value.conflicts.length || value.conflictState !== 'unknown' || !value.limitations.some(l => ['finding_budget', 'scan_budget', 'report_budget'].includes(l))) invalid();
  }
  const seen = new Set<string>();
  for (const a of value.assessments) {
    if (!exact(a, ['source', 'provenanceRef', 'title', 'description', 'language', 'severity', 'fixedVersion', 'cvss']) || !(ADVISORY_SOURCES as readonly unknown[]).includes(a.source) || typeof a.provenanceRef !== 'string' || !/^target-[a-f0-9]{64}$/.test(a.provenanceRef) || a.language !== null && !language(a.language) || a.severity !== null && !severities.includes(a.severity as Severity) || a.fixedVersion !== null && !version(a.fixedVersion)) invalid();
    validatePlain(a.title, 512); validatePlain(a.description, 4096);
    if (a.cvss !== null) {
      const c = a.cvss;
      if (!exact(c, ['family', 'version', 'versionState', 'reportedScore', 'scoreState', 'vector', 'vectorState']) || !['v2', 'v3'].includes(c.family as string) || !['available', 'missing', 'invalid'].includes(c.scoreState as string) || !(states as readonly unknown[]).includes(c.vectorState) || !(states as readonly unknown[]).includes(c.versionState)) invalid();
      if (c.scoreState === 'available' ? typeof c.reportedScore !== 'number' || !Number.isFinite(c.reportedScore) || c.reportedScore < 0 || c.reportedScore > 10 : c.reportedScore !== null) invalid();
      if (c.family === 'v2') { if (c.version !== '2.0' || c.versionState !== 'available' || c.vector !== null || c.vectorState !== 'unsupported') invalid(); }
      else if (c.vectorState === 'available') { if (!validV3Vector(c.vector) || c.version !== c.vector.slice(5, 8) || c.versionState !== 'available') invalid(); }
      else if (c.vector !== null || c.version !== null || !['missing', 'invalid', 'unsupported', 'omitted'].includes(c.vectorState as string) || !['missing', 'invalid', 'unsupported', 'omitted'].includes(c.versionState as string)) invalid();
    }
    const key = stableKey(a); if (seen.has(key)) invalid(); seen.add(key);
  }
  const allowed = references(cveId, value.assessments as AdvisoryAssessment[]);
  let previous = -1;
  for (const ref of value.references) {
    if (!exact(ref, ['kind', 'authority', 'url'])) invalid();
    const index = allowed.findIndex(r => r.kind === ref.kind && r.authority === ref.authority && r.url === ref.url);
    if (index <= previous) invalid(); previous = index;
  }
  if (jsonBytes(value) > ADVISORY_FINDING_BYTES) invalid();
}
export function validateAdvisoryBudget(findings: FindingWithAdvisory[]): void {
  if (!plainArray(findings)) invalid();
  let bytes = 2 + Math.max(0, findings.length - 1);
  for (const finding of findings) {
    if (!plainObject(finding)) invalid();
    if (finding.advisory == null) continue;
    validateAdvisory(finding.advisory, finding.cveId);
    if (jsonBytes(finding) > ADVISORY_FINDING_BYTES) invalid();
    bytes += jsonBytes(finding.advisory);
  }
  if (bytes > ADVISORY_SCAN_BYTES) invalid();
}
