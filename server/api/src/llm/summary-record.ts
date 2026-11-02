import { isDeepStrictEqual } from 'node:util';
import { PUBLIC_IMAGE_PROFILE } from '../oci/public-image-policy.js';
import { hashValue, historyUnavailable, isId, reportBinding } from './history-contract.js';
import { publicFreePolicy } from './policy.js';
import { checkedOpenAiPolicy } from './openai-policy.js';
import { openAiNarrative } from './openai-response-contract.js';
import type { SummaryValidationPolicy } from './provider-runtime-contract.js';
import type { ReportContext } from './report-context.js';
import { exact, object, validateReply } from './response.js';
import { SUMMARY_OPTIONAL_FINDINGS, compareFindings, mandatoryFinding } from './summary-context.js';
import type { SummaryResponse } from './summary-result-cache.js';

export const SUMMARY_STORAGE = Object.freeze({ version: 'durable-summary-v1', entries: 64,
  bytes: 2 * 1024 * 1024, responseBytes: 65536, entryBytes: 69632, busyMs: 100 });
export type SummaryRow = { scope: string; content: string; content_hash: string };
type SummaryRecord = { version: string; policyVersion: string; value: SummaryResponse };
const hash = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);

// Integrity is scoped: copying a row to another owner+scan cannot make it readable.
export function summaryRecordHash(scope: string, content: string): string { return hashValue([scope, content]); }
export function decodeSummaryRecord(row: SummaryRow): SummaryRecord {
  try {
    if (!hash(row.scope) || typeof row.content !== 'string' || Buffer.byteLength(row.content) > SUMMARY_STORAGE.entryBytes ||
        !hash(row.content_hash) || summaryRecordHash(row.scope, row.content) !== row.content_hash) return historyUnavailable();
    const record: unknown = JSON.parse(row.content);
    if (!exact(record, ['version', 'policyVersion', 'value']) || record.version !== SUMMARY_STORAGE.version ||
        !hash(record.policyVersion) || !object(record.value) || !isId(record.value.scanId) ||
        typeof record.value.digest !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(record.value.digest) ||
        record.value.platform !== 'linux/amd64' || !hash(record.value.reportVersion) ||
        Buffer.byteLength(JSON.stringify(record.value)) > SUMMARY_STORAGE.responseBytes) return historyUnavailable();
    // This only decodes the envelope. Publication also requires validateStoredSummary
    // against a freshly authorized report; stored scannerFacts are never authority.
    return record as SummaryRecord;
  } catch { return historyUnavailable(); }
}

function supportedPolicy(policy: SummaryValidationPolicy): boolean {
  if (!('provider' in policy)) return publicFreePolicy(policy);
  checkedOpenAiPolicy(policy.policy);
  return policy.provider === 'OpenAI' && policy.findings === policy.policy.findings &&
    policy.requestBytes === policy.policy.requestBytes && policy.responseBytes === policy.policy.responseBytes;
}

export function validateStoredSummary(value: unknown, report: ReportContext, policy: SummaryValidationPolicy): SummaryResponse {
  try {
    if (!supportedPolicy(policy)) return historyUnavailable();
    if ('provider' in policy && (!object(value) || !Array.isArray(value.hypotheses) || value.hypotheses.length < 1 ||
        value.hypotheses.length > 6 || value.hypotheses.some(item => !object(item) || typeof item.text !== 'string' ||
          !openAiNarrative(item.text) || [...item.text].length > 320 || !Array.isArray(item.citations) || item.citations.length < 1 || item.citations.length > 2)))
      return historyUnavailable();
    // Only the fresh authorized report selects this branch, never stored fields.
    // Legacy generation uses all evidence, without public selection or identities.
    if (report.profile === undefined) {
      if (report.contextSelection !== undefined || !report.findings.length ||
          report.findings.length > policy.findings || Buffer.byteLength(JSON.stringify(report)) > policy.requestBytes ||
          !exact(value, ['scanId', 'digest', 'platform', 'reportVersion', 'hypotheses', 'scannerFacts']) ||
          Buffer.byteLength(JSON.stringify(value)) > Math.min(policy.responseBytes, SUMMARY_STORAGE.responseBytes) ||
          !Array.isArray(value.hypotheses)) return historyUnavailable();
      const hypotheses = value.hypotheses.map(item => {
        if (!exact(item, ['kind', 'text', 'citations']) || item.kind !== 'hypothesis') return historyUnavailable();
        return { text: item.text, citations: item.citations };
      });
      const validated = validateReply({ scanId: value.scanId, digest: value.digest, platform: value.platform,
        reportVersion: value.reportVersion, hypotheses }, report, true);
      const expected = JSON.parse(JSON.stringify(validated)) as SummaryResponse;
      if (!isDeepStrictEqual(value, expected)) return historyUnavailable();
      return expected;
    }
    const keys = ['scanId', 'digest', 'platform', 'reportVersion', 'hypotheses', 'scannerFacts',
      'findingCount', 'findingCounts', 'coverage', 'contextSelection'];
    if (report.identifierCounts !== undefined) keys.push('identifierCounts');
    if (report.profile !== PUBLIC_IMAGE_PROFILE || !exact(value, keys) ||
        Buffer.byteLength(JSON.stringify(value)) > Math.min(policy.responseBytes, SUMMARY_STORAGE.responseBytes)) return historyUnavailable();
    const selection = value.contextSelection;
    if (!exact(selection, ['totalFindings', 'selectedFindings', 'omittedFindings', 'strategy', 'selectedFindingIds']) ||
        selection.strategy !== 'all-critical-and-unknown-then-severity' || !Array.isArray(selection.selectedFindingIds) ||
        !selection.selectedFindingIds.length || selection.selectedFindingIds.length > policy.findings ||
        selection.selectedFindingIds.some(id => typeof id !== 'string') ||
        new Set(selection.selectedFindingIds).size !== selection.selectedFindingIds.length ||
        !Array.isArray(value.hypotheses)) return historyUnavailable();
    const required = report.findings.filter(mandatoryFinding);
    const optional = report.findings.filter(f => !mandatoryFinding(f)).sort(compareFindings);
    const optionalCount = selection.selectedFindingIds.length - required.length;
    if (optionalCount < 0 || optionalCount > Math.min(SUMMARY_OPTIONAL_FINDINGS, optional.length, policy.findings - required.length))
      return historyUnavailable();
    // Input admission may shorten the producer's optional prefix, never skip a
    // higher-ranked finding. Reconstruct it without quota access or preparation.
    const findings = [...required, ...optional.slice(0, optionalCount)].sort((a, b) => a.findingId.localeCompare(b.findingId));
    if (!isDeepStrictEqual(selection.selectedFindingIds, findings.map(f => f.findingId))) return historyUnavailable();
    const hypotheses = value.hypotheses.map(item => {
      if (!exact(item, ['kind', 'text', 'citations']) || item.kind !== 'hypothesis') return historyUnavailable();
      return { text: item.text, citations: item.citations };
    });
    const validated = validateReply({ scanId: value.scanId, digest: value.digest, platform: value.platform,
      reportVersion: value.reportVersion, hypotheses }, { ...report, findings }, true);
    const expected: SummaryResponse = { ...validated, findingCount: report.findingCount,
      findingCounts: report.findingCounts, coverage: report.coverage,
      ...(report.identifierCounts === undefined ? {} : { identifierCounts: report.identifierCounts }),
      contextSelection: { totalFindings: report.findingCount, selectedFindings: findings.length,
        omittedFindings: report.findingCount - findings.length, strategy: 'all-critical-and-unknown-then-severity',
        selectedFindingIds: findings.map(f => f.findingId) } };
    // Reject altered facts, coverage, counts, selection and extra fields even when
    // a stored checksum was recomputed. Do not silently repair a persisted output.
    if (!isDeepStrictEqual(value, JSON.parse(JSON.stringify(expected)))) return historyUnavailable();
    return JSON.parse(JSON.stringify(expected)) as SummaryResponse;
  } catch { return historyUnavailable(); }
}

export function summaryRecordMatches(record: SummaryRecord, report: ReportContext, policy: SummaryValidationPolicy): boolean {
  return record.policyVersion === policy.version &&
    Object.entries(reportBinding(report)).every(([key, value]) => record.value[key as keyof SummaryResponse] === value);
}
