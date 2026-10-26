import { BadGatewayException } from '@nestjs/common';
import type { ReportContext } from './report-context.js';
import { groundedIdentifiers, russianHumanText } from './russian-text.js';
import { diagnose, type FailurePhase, type FailureReason } from './provider-diagnostic.js';

export const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) &&
  [Object.prototype, null].includes(Object.getPrototypeOf(v));
export const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => object(v) &&
  Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
export const invalidReply = (phase: FailurePhase = 'content', reason: FailureReason = 'invalid_content'): never => {
  throw diagnose(new BadGatewayException({ errorCode: 'LLM_INVALID_RESPONSE' }), phase, reason);
};

function plainText(value: unknown): string {
  if (typeof value !== 'string' || !value.trim() || Buffer.byteLength(value) > 2000 ||
      // eslint-disable-next-line no-control-regex, no-useless-escape -- Preserve the audited security regex rejecting controls and markup.
      /[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\ud800-\udfff<>`*#~\[\]{}\\]|[a-z][a-z0-9+.-]*:\/\/|https?:|javascript:|data:|mailto:|www\.|CANARY|[A-Za-z0-9_+/=-]{40,}|\b(?:Bearer|password|api[_-]?key|token|secret)\s*[:=]|\b(?:sk-|sk-or-|AKIA)[A-Za-z0-9_-]+/i.test(value)) return invalidReply();
  return value;
}

export function validateReply(value: unknown, report: ReportContext, requireRussian = false) {
  if (!exact(value, ['scanId', 'digest', 'platform', 'reportVersion', 'hypotheses']) ||
      value.scanId !== report.scanId || value.digest !== report.digest || value.platform !== report.platform ||
      value.reportVersion !== report.reportVersion || !Array.isArray(value.hypotheses) ||
      value.hypotheses.length < 1 || value.hypotheses.length > 12) return invalidReply();
  const allowed = new Set(report.findings.map(f => f.findingId));
  const hypotheses = value.hypotheses.map(item => {
    if (!exact(item, ['text', 'citations']) || !Array.isArray(item.citations) || !item.citations.length ||
        item.citations.length > 20 || new Set(item.citations).size !== item.citations.length ||
        item.citations.some(id => typeof id !== 'string' || !allowed.has(id))) return invalidReply();
    const text = plainText(item.text);
    const evidence = report.findings.filter(finding => (item.citations as string[]).includes(finding.findingId));
    if (requireRussian && !groundedIdentifiers(text, evidence))
      throw diagnose(new BadGatewayException({ errorCode: 'LLM_INVALID_RESPONSE' }), 'grounding', 'unknown_identifier');
    if (requireRussian && !russianHumanText(text, JSON.stringify(evidence)))
      throw diagnose(new BadGatewayException({ errorCode: 'LLM_INVALID_RESPONSE' }), 'language', 'not_russian');
    return { kind: 'hypothesis' as const, text, citations: item.citations as string[] };
  });
  // Membership proves the source exists, not the model's inference. Facts come only from the server.
  return { scanId: report.scanId, digest: report.digest, platform: report.platform, reportVersion: report.reportVersion,
    hypotheses, scannerFacts: report.findings.filter(f => hypotheses.some(h => h.citations.includes(f.findingId))) };
}
