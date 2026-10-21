import { ConflictException } from '@nestjs/common';
import type { ReportContext, SafeFinding } from './report-context.js';
import type { LlmPolicy } from './policy.js';
import { prepareSummary } from './prepared-request.js';

export const mandatoryFinding = (f: SafeFinding) => ['CRITICAL', 'UNKNOWN'].includes(f.severity) ||
  Array.isArray(f.assessments) && f.assessments.some(a => a && typeof a === 'object' && 'severity' in a && a.severity === 'CRITICAL');
const priority: Readonly<Record<string, number>> = { HIGH: 3, MEDIUM: 2, LOW: 1 };
export const compareFindings = (a: SafeFinding, b: SafeFinding) =>
  (priority[b.severity] ?? 0) - (priority[a.severity] ?? 0) || a.findingId.localeCompare(b.findingId);

// Only the explicitly composed public report uses bounded selection. Legacy summary
// continues to require all evidence. Whole counts/coverage never describe the subset.
export function selectSummaryReport(report: ReportContext, policy: LlmPolicy, inputCeiling: number): ReportContext {
  if (!report.profile) return report;
  const required = report.findings.filter(mandatoryFinding);
  const optional = report.findings.filter(f => !mandatoryFinding(f)).sort(compareFindings);
  for (let n = Math.min(32, optional.length, policy.findings - required.length); n >= 0; n--) {
    const findings = [...required, ...optional.slice(0, n)].sort((a, b) => a.findingId.localeCompare(b.findingId));
        if (!findings.length) break;
    const selected: ReportContext = { ...report, findings, contextSelection: {
      totalFindings: report.findingCount, selectedFindings: findings.length, omittedFindings: report.findingCount - findings.length,
      strategy: 'all-critical-and-unknown-then-severity', selectedFindingIds: findings.map(f => f.findingId),
    } };
    try { if (prepareSummary(selected, policy).reserve.input <= inputCeiling) return selected; } catch { /* Drop optional findings only. */ }
  }
  throw new ConflictException({ errorCode: 'LLM_CONTEXT_LIMIT' });
}
