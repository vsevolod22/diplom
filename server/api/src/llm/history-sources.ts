import { ADVISORY_SOURCES } from '../worker/vuln-advisory.js';
import { exact, object } from './response.js';

const matches = (v: unknown, pattern: RegExp) => typeof v === 'string' && pattern.test(v);
const member = (v: unknown, values: readonly unknown[]) => values.includes(v);
const severity = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const states = ['available', 'missing', 'invalid', 'redacted', 'truncated', 'unsupported', 'omitted'];
const list = (v: unknown, values: readonly unknown[], max: number) => Array.isArray(v) && v.length <= max &&
  new Set(v).size === v.length && v.every(x => member(x, values));

// Reopened historical citations must satisfy the same data-only projection shape.
// A valid SQLite/content hash alone does not authorize extra free text or raw evidence.
export function safeHistoryFinding(value: unknown): boolean {
  if (!object(value) || !member(value.severity, severity)) return false;
  const f = value;
  if (f.check === 'secret') return exact(f, ['check', 'findingId', 'severity', 'ruleId', 'line', 'evidenceRef']) &&
    f.severity === 'UNKNOWN' && matches(f.findingId, /^secret-\d{1,6}-\d{1,6}$/) &&
    matches(f.ruleId, /^rule-[a-f0-9]{16}$/) && matches(f.evidenceRef, /^result-\d{1,6}-secret-\d{1,6}$/) &&
    (f.line === null || Number.isSafeInteger(f.line) && (f.line as number) >= 0 && (f.line as number) <= 10000000);
  if (f.check === 'config') return exact(f, ['check', 'findingId', 'severity', 'ruleId', 'classification', 'configDigest', 'manifestDigest', 'location']) &&
    matches(f.findingId, /^sha256:[a-f0-9]{64}$/) && f.severity === 'MEDIUM' && f.ruleId === 'IMGCFG_USER_ROOT' &&
    member(f.classification, ['DEFAULT_ROOT', 'NUMERIC_ROOT']) && matches(f.configDigest, /^sha256:[a-f0-9]{64}$/) &&
    matches(f.manifestDigest, /^sha256:[a-f0-9]{64}$/) && f.location === '/config/User';
  if (f.check !== 'vuln') return false;
  const base = ['check', 'findingId', 'severity', 'cveId', 'ecosystem', 'severitySources', 'provenanceRef', 'fixedVersionReported', 'advisoryState'];
  const advisory = ['assessments', 'conflictState', 'conflicts', 'limitations'];
  if (!exact(f, f.advisoryState === 'unknown' ? base : [...base, ...advisory]) ||
    !matches(f.findingId, /^vuln-[a-f0-9]{64}$/) || !matches(f.cveId, /^CVE-\d{4}-\d{4,12}$/) ||
    !member(f.ecosystem, ['apk', 'npm']) || !Array.isArray(f.severitySources) || !f.severitySources.length ||
    !list(f.severitySources, ADVISORY_SOURCES, ADVISORY_SOURCES.length) ||
    !matches(f.provenanceRef, /^target-[a-f0-9]{64}$/) || typeof f.fixedVersionReported !== 'boolean') return false;
  if (f.advisoryState === 'unknown') return true;
  if (!member(f.advisoryState, ['available', 'omitted']) || !member(f.conflictState, ['none', 'present', 'unknown']) ||
    !list(f.conflicts, ['title', 'description', 'severity', 'fixedVersion', 'cvss'], 5) ||
    !list(f.limitations, ['invalid_metadata', 'redaction', 'field_limit', 'assessment_limit', 'reference_limit', 'finding_budget', 'scan_budget', 'report_budget'], 8) ||
    !Array.isArray(f.assessments) || f.assessments.length > 16) return false;
  return f.assessments.every(a => {
    if (!exact(a, ['source', 'severity', 'fixedVersionReported', 'cvss']) || !member(a.source, ADVISORY_SOURCES) ||
      !member(a.severity, [...severity, null]) || typeof a.fixedVersionReported !== 'boolean') return false;
    if (a.cvss === null) return true;
    const c = a.cvss;
    return exact(c, ['family', 'version', 'versionState', 'reportedScore', 'scoreState', 'vectorState']) &&
      member(c.family, ['v2', 'v3']) && member(c.version, ['2.0', '3.0', '3.1', null]) &&
      member(c.versionState, states) && member(c.scoreState, ['available', 'missing', 'invalid']) && member(c.vectorState, states) &&
      (c.scoreState === 'available' ? typeof c.reportedScore === 'number' && Number.isFinite(c.reportedScore) &&
        c.reportedScore >= 0 && c.reportedScore <= 10 : c.reportedScore === null);
  });
}
