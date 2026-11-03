import { ConflictException } from '@nestjs/common';
import type { ReportContext, SafeFinding } from './report-context.js';
import type { LlmPolicy } from './policy.js';
import { prepareSummary } from './prepared-request.js';

export const mandatoryFinding = (f: SafeFinding) => ['CRITICAL', 'UNKNOWN'].includes(f.severity) ||
  Array.isArray(f.assessments) && f.assessments.some(a => a && typeof a === 'object' && 'severity' in a && a.severity === 'CRITICAL');
export const SUMMARY_OPTIONAL_FINDINGS = 8;
const priority: Readonly<Record<string, number>> = { HIGH: 3, MEDIUM: 2, LOW: 1 };
export const compareFindings = (a: SafeFinding, b: SafeFinding) =>
  (priority[b.severity] ?? 0) - (priority[a.severity] ?? 0) || a.findingId.localeCompare(b.findingId);

// Only the explicitly composed public report uses bounded selection. Legacy summary
// continues to require all evidence. Whole counts/coverage never describe the subset.
export function selectSummaryReport(report: ReportContext, policy: LlmPolicy, inputCeiling: number): ReportContext {
  if (!report.profile) return report;
  return selectPreparedSummary(report, policy.findings, inputCeiling, candidate => prepareSummary(candidate, policy)).report;
}

export function selectPreparedSummary<T extends { reserve: { input: number } }>(report: ReportContext, maxFindings: number,
  inputCeiling: number, prepare: (report: ReportContext) => T): { report: ReportContext; prepared: T } {
  if (!report.profile) {
    try {
      const prepared = prepare(report);
      if (report.findings.length <= maxFindings && prepared.reserve.input <= inputCeiling) return { report, prepared };
    } catch { /* Legacy reports require all evidence. */ }
    throw new ConflictException({ errorCode: 'LLM_CONTEXT_LIMIT' });
  }
  const required = report.findings.filter(mandatoryFinding);
  const optional = report.findings.filter(f => !mandatoryFinding(f)).sort(compareFindings);
  // A focused remediation report does not need dozens of optional findings.
    // Keep every critical/unknown finding, then a small severity-ranked sample;
    // whole counts and explicit omissions still describe the complete scan.
    for (let n = Math.min(SUMMARY_OPTIONAL_FINDINGS, optional.length, maxFindings - required.length); n >= 0; n--) {
    const findings = [...required, ...optional.slice(0, n)].sort((a, b) => a.findingId.localeCompare(b.findingId));
        if (!findings.length) break;
    const selected: ReportContext = { ...report, findings, contextSelection: {
      totalFindings: report.findingCount, selectedFindings: findings.length, omittedFindings: report.findingCount - findings.length,
      strategy: 'all-critical-and-unknown-then-severity', selectedFindingIds: findings.map(f => f.findingId),
    } };
    try {
          const prepared = prepare(selected);
          if (prepared.reserve.input <= inputCeiling) return { report: selected, prepared };
        } catch { /* Drop optional findings only. */ }
  }
  throw new ConflictException({ errorCode: 'LLM_CONTEXT_LIMIT' });
}
