import { createHash } from 'node:crypto';
import { BadRequestException, ConflictException, ServiceUnavailableException } from '@nestjs/common';
import type { ReportContext, SafeFinding } from './report-context.js';
import { exact, invalidReply, object } from './response.js';
import { safeHistoryFinding } from './history-sources.js';

export const HISTORY = Object.freeze({ version: 'owner-history-v1', questionBytes: 2048, bodyBytes: 8192,
  scopeBytes: 524288, turns: 256, decisions: 128, references: 4096, heads: 128,
  dbBytes: 8388608, sidecarBytes: 16777216, diskHeadroom: 134217728, busyMs: 100,
  replyBytes: 16384, citations: 32, citationBytes: 2048, completionReserve: 102400,
  cacheEntries: 128, cacheBytes: 4194304, cacheMs: 60000 });
export const historyUnavailable = (): never => { throw new ServiceUnavailableException({ errorCode: 'LLM_HISTORY_UNAVAILABLE' }); };
export const historyConflict = (): never => { throw new ConflictException({ errorCode: 'LLM_HISTORY_CONFLICT' }); };
export const historyCapacity = (): never => { throw new ConflictException({ errorCode: 'LLM_HISTORY_CAPACITY' }); };
export const invalidHistoryRequest = (): never => { throw new BadRequestException({ errorCode: 'LLM_INVALID_REQUEST' }); };
export const contextLimit = (): never => { throw new ConflictException({ errorCode: 'LLM_CONTEXT_LIMIT' }); };
export const hashValue = (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
export const bytes = (value: unknown) => Buffer.byteLength(JSON.stringify(value));
export const isId = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value);
export function cleanText(value: unknown, ceiling: number = HISTORY.questionBytes): string {
  if (typeof value !== 'string' || !value.trim() || Buffer.byteLength(value) > ceiling ||
    // eslint-disable-next-line no-control-regex -- Intentionally reject control characters in untrusted chat text.
    /[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\ud800-\udfff<>]|CANARY|[a-z][a-z0-9+.-]*:\/\/|javascript:|data:|file:|www\.|[A-Za-z0-9_+/=-]{40,}|\b(?:Bearer|password|api[_-]?key|token|secret)\s*[:=]|\b(?:sk-|sk-or-|AKIA)[A-Za-z0-9_-]+/iu.test(value)) return invalidHistoryRequest();
  return value;
}
export type ReportBinding = Pick<ReportContext, 'scanId' | 'digest' | 'platform' | 'reportVersion'>;
export function reportBinding(report: ReportContext): ReportBinding {
  return { scanId: report.scanId, digest: report.digest, platform: report.platform, reportVersion: report.reportVersion };
}
export type Source = ReportBinding & { finding: SafeFinding };
export type ChatReply = ReportBinding & { kind: 'hypothesis'; text: string; sources: Source[] };
export type Turn = { id: string; mutationId: string; state: 'pending' | 'completed' | 'failed' | 'cancelled' | 'interrupted';
  question: string; report: ReportBinding; createdAt: number; inputHash: string; consentPolicyVersion: string; requestHash: string; reply?: ChatReply };
export function mutationInputHash(scanId: string, expected: { epoch: string; revision: number; mutationId: string; reportVersion: string },
  question: string, consentPolicyVersion: string): string {
  return hashValue(['history-chat-input-v1', 'chat', scanId, expected.epoch, expected.revision, expected.mutationId,
    expected.reportVersion, question, true, consentPolicyVersion]);
}
export type Decision = { id: string; mutationId: string; kind: 'user-decision'; text: string; report: ReportBinding; sources: Source[] };
export type Pending = { id: string; sessionId: string; generation: number; accessIncarnation: string; policyVersion: string;
  deadline: number; requestHash: string; reservation?: string };
export type HistoryHead = { epoch: string; revision: number; turns: Turn[]; decisions: Decision[]; pending: Pending | null };
export type PublicTurn = Pick<Turn, 'id' | 'mutationId' | 'state' | 'question' | 'report' | 'createdAt' | 'reply'>;
function publicTurn(turn: Turn): PublicTurn {
  return { id: turn.id, mutationId: turn.mutationId, state: turn.state, question: turn.question,
    report: turn.report, createdAt: turn.createdAt,
    ...(turn.state === 'completed' && turn.reply ? { reply: turn.reply } : {}) };
}
export function publicHistory(head: HistoryHead) {
  return { epoch: head.epoch, revision: head.revision, turns: head.turns.map(publicTurn), decisions: head.decisions,
    pending: head.pending ? { turnId: head.pending.id, state: 'pending' as const } : null,
    retention: 'Confirmed history persists until separately authorized operator lifecycle; no automatic expiry or reset.' };
}
// Supported report bindings are fixed-width ASCII (UUID36/digest71/platform11/version64).
// This measures the exact envelope overhead, never substitutes authorization or report content.
const budgetBinding: ReportBinding = Object.freeze({ scanId: '00000000-0000-0000-0000-000000000000',
  digest: `sha256:${'0'.repeat(64)}`, platform: 'linux/amd64', reportVersion: '0'.repeat(64) });
export function historyProjection(head: HistoryHead, binding: ReportBinding = budgetBinding) {
  return { ...binding, ...publicHistory(head) };
}
export function validateChatReply(value: unknown, report: ReportContext): ChatReply {
  if (!exact(value, ['scanId', 'digest', 'platform', 'reportVersion', 'text', 'citations']) ||
    !Object.entries(reportBinding(report)).every(([key, entry]) => value[key] === entry) ||
    !Array.isArray(value.citations) || value.citations.length < 1 || value.citations.length > HISTORY.citations ||
    new Set(value.citations).size !== value.citations.length) return invalidReply();
  let text: string;
  try { text = cleanText(value.text, HISTORY.replyBytes); } catch { return invalidReply(); }
  const sources = value.citations.map(id => {
    const finding = report.findings.find(f => f.findingId === id);
    if (!finding) return invalidReply();
    const source = { ...reportBinding(report), finding };
    if (bytes(source) > HISTORY.citationBytes) return invalidReply();
    return source;
  });
  return { ...reportBinding(report), kind: 'hypothesis', text, sources };
}
export function validateHead(value: unknown): asserts value is HistoryHead {
  if (!exact(value, ['epoch', 'revision', 'turns', 'decisions', 'pending']) || !isId(value.epoch) ||
    !Number.isSafeInteger(value.revision) || (value.revision as number) < 0 || !Array.isArray(value.turns) ||
    !Array.isArray(value.decisions) || value.turns.length > HISTORY.turns || value.decisions.length > HISTORY.decisions ||
    value.pending !== null && !object(value.pending)) return historyUnavailable();
  const mutationIds = new Set<string>(), ids = new Set<string>(); let refs = 0;
  const binding = (b: unknown) => object(b) && exact(b, ['scanId', 'digest', 'platform', 'reportVersion']) && isId(b.scanId) &&
    typeof b.digest === 'string' && /^sha256:[a-f0-9]{64}$/.test(b.digest) && b.platform === 'linux/amd64' &&
    typeof b.reportVersion === 'string' && /^[a-f0-9]{64}$/.test(b.reportVersion);
  const sources = (s: unknown, report: ReportBinding): boolean => Array.isArray(s) && s.length <= HISTORY.citations &&
      new Set(s.map(source => object(source) && object(source.finding) ? source.finding.findingId : null)).size === s.length && s.every(source => {
    refs++; return object(source) && exact(source, ['scanId', 'digest', 'platform', 'reportVersion', 'finding']) &&
      binding({ scanId: source.scanId, digest: source.digest, platform: source.platform, reportVersion: source.reportVersion }) &&
      safeHistoryFinding(source.finding) && Object.entries(report).every(([key, v]) => source[key] === v) && bytes(source) <= HISTORY.citationBytes;
  });
  for (const entry of [...value.turns, ...value.decisions]) {
    if (!object(entry) || !isId(entry.id) || !isId(entry.mutationId) || ids.has(entry.id) || mutationIds.has(entry.mutationId) || !binding(entry.report)) return historyUnavailable();
    ids.add(entry.id); mutationIds.add(entry.mutationId);
    try { cleanText('question' in entry ? entry.question : entry.text); } catch { return historyUnavailable(); }
    if ('question' in entry) {
      if (!exact(entry, entry.state === 'completed' ? ['id', 'mutationId', 'state', 'question', 'report', 'createdAt', 'inputHash', 'consentPolicyVersion', 'requestHash', 'reply'] :
              ['id', 'mutationId', 'state', 'question', 'report', 'createdAt', 'inputHash', 'consentPolicyVersion', 'requestHash']) ||
              ![entry.inputHash, entry.consentPolicyVersion, entry.requestHash].every(v => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v)) ||
              !['pending', 'completed', 'failed', 'cancelled', 'interrupted'].includes(String(entry.state)) ||
              !Number.isSafeInteger(entry.createdAt) || (entry.createdAt as number) < 0) return historyUnavailable();
      if (entry.state === 'completed') {
        if (!exact(entry.reply, ['scanId', 'digest', 'platform', 'reportVersion', 'kind', 'text', 'sources']) ||
                  entry.reply.kind !== 'hypothesis' || !Array.isArray(entry.reply.sources) || !entry.reply.sources.length ||
                  !sources(entry.reply.sources, entry.report as ReportBinding) ||
          !Object.entries(entry.report as ReportBinding).every(([k, v]) => entry.reply && (entry.reply as Record<string, unknown>)[k] === v)) return historyUnavailable();
        try { cleanText(entry.reply.text, HISTORY.replyBytes); } catch { return historyUnavailable(); }
      } else if (entry.reply !== undefined) return historyUnavailable();
    } else if (!exact(entry, ['id', 'mutationId', 'kind', 'text', 'report', 'sources']) ||
          entry.kind !== 'user-decision' || !sources(entry.sources, entry.report as ReportBinding)) return historyUnavailable();
  }
  if (refs > HISTORY.references) return historyCapacity();
  const p = value.pending;
  if (p !== null && (!exact(p, p.reservation === undefined ? ['id', 'sessionId', 'generation', 'accessIncarnation', 'policyVersion', 'deadline', 'requestHash'] :
      ['id', 'sessionId', 'generation', 'accessIncarnation', 'policyVersion', 'deadline', 'requestHash', 'reservation']) || !isId(p.id) || !value.turns.some(t => t.id === p.id && t.state === 'pending') ||
    !/^[a-f0-9]{32}$/.test(String(p.sessionId)) || !Number.isSafeInteger(p.generation) || (p.generation as number) <= 0 || !Number.isSafeInteger(p.deadline) || (p.deadline as number) < 0 ||
    !/^[a-f0-9]{32}$/.test(String(p.accessIncarnation)) || !/^[a-f0-9]{64}$/.test(String(p.policyVersion)) ||
    !/^[a-f0-9]{64}$/.test(String(p.requestHash)) || p.reservation !== undefined && !isId(p.reservation))) return historyUnavailable();
  if (value.turns.filter(t => t.state === 'pending').length !== (p ? 1 : 0)) return historyUnavailable();
  if (p) {
    const turn = value.turns.find(t => t.id === p.id)!;
    if (turn.consentPolicyVersion !== p.policyVersion || turn.requestHash !== p.requestHash) return historyUnavailable();
  }
  if (bytes(value) > HISTORY.scopeBytes || bytes(historyProjection(value as HistoryHead)) > HISTORY.scopeBytes) return historyCapacity();
}
