import { createHash } from 'node:crypto';
import { PUBLIC_IMAGE_PROFILE } from '../oci/public-image-policy.js';
import type { ReportContext } from './report-context.js';
import type { HistoryContext } from './history-context.js';
import { HISTORY, cleanText, isId, validateChatReply } from './history-contract.js';
import { safeHistoryFinding } from './history-sources.js';
import { exact, invalidReply, object, validateReply } from './response.js';
import { checkedOpenAiPolicy, openAiConfigurationError, type OpenAiPolicy } from './openai-policy.js';
import { openAiReserve, type OpenAiReserve } from './openai-usage.js';
import { openAiNarrative, openAiResponseFormat, type OpenAiOperation } from './openai-response-contract.js';

export type { OpenAiOperation } from './openai-response-contract.js';
export type OpenAiPrepared = Readonly<{
  operation: OpenAiOperation; body: string; hash: string; policyVersion: string; reserve: OpenAiReserve;
}>;
const prepared = new WeakMap<OpenAiPrepared, { policy: OpenAiPolicy; report: ReportContext }>();
const fail = (): never => { throw openAiConfigurationError(); };
const digest = (value: unknown) => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value);
const hash = (value: unknown) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const count = (value: unknown, max: number) => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= max;

// Snapshot data, not executable objects. Bound traversal before JSON serialization;
// reject getters, toJSON/functions, cycles and exotic prototypes. Never mutate input.
function snapshot<T>(value: T, limit: number): T {
  let bytes = 0, nodes = 0;
  const active = new Set<object>();
  const clone = (item: unknown, depth: number): unknown => {
    if (++nodes > 32_768 || depth > 24 || (bytes += 8) > limit) return fail();
    if (typeof item === 'string') {
      if ((bytes += Buffer.byteLength(item)) > limit) return fail();
      return item;
    }
    if (item === null || typeof item === 'boolean' || typeof item === 'number' && Number.isFinite(item)) return item;
    if (!Array.isArray(item) && !object(item) || active.has(item as object)) return fail();
    const source = item as object;
    active.add(source);
    const descriptors = Object.getOwnPropertyDescriptors(source);
    if (Object.getOwnPropertySymbols(source).length) return fail();
    const entries: [string, unknown][] = [];
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (Array.isArray(item) && key === 'length') continue;
      if (!descriptor.enumerable || !('value' in descriptor) || (bytes += Buffer.byteLength(key)) > limit) return fail();
      entries.push([key, clone(descriptor.value, depth + 1)]);
    }
    active.delete(source);
    if (Array.isArray(item)) {
      if (entries.length !== item.length || entries.some(([key], index) => key !== String(index))) return fail();
      return Object.freeze(entries.map(([, entry]) => entry));
    }
    return Object.freeze(Object.fromEntries(entries));
  };
  const result = clone(value, 0) as T;
  if (Buffer.byteLength(JSON.stringify(result)) > limit) return fail();
  return result;
}

function binding(value: unknown): boolean {
  return object(value) && isId(value.scanId) && digest(value.digest) && value.platform === 'linux/amd64' && hash(value.reportVersion);
}
function checkReport(report: ReportContext, policy: OpenAiPolicy): void {
  const keys = ['scanId', 'digest', 'platform', 'reportVersion', 'state', 'attempt', 'requestedChecks',
    'coverage', 'findings', 'findingCount', 'checkedIsNotSafe', 'omittedEvidence'];
  for (const key of ['profile', 'findingCounts', 'identifierCounts', 'contextSelection'])
    if (Object.hasOwn(report, key)) keys.push(key);
  if (!exact(report, keys) || !binding(report) || report.profile !== undefined && report.profile !== PUBLIC_IMAGE_PROFILE ||
      !['completed', 'partial', 'failed', 'cancelled'].includes(report.state) || !count(report.attempt, Number.MAX_SAFE_INTEGER) ||
      !Array.isArray(report.requestedChecks) || !report.requestedChecks.length ||
      new Set(report.requestedChecks).size !== report.requestedChecks.length ||
      report.requestedChecks.some(check => !['config', 'secret', 'vuln', 'sbom'].includes(check)) ||
      !exact(report.coverage, ['config', 'secret', 'vuln', 'sbom']) || report.checkedIsNotSafe !== true ||
      !count(report.findingCount, 1000) || !Array.isArray(report.findings) || !report.findings.length ||
      report.findings.length > policy.findings || report.findings.length > report.findingCount ||
      report.findings.some(finding => !safeHistoryFinding(finding)) ||
      new Set(report.findings.map(f => f.findingId)).size !== report.findings.length) return fail();
  if (report.profile === undefined && (report.contextSelection !== undefined || report.findingCounts !== undefined ||
      report.identifierCounts !== undefined || report.findings.some(f => 'identifierKind' in f || 'packageName' in f) ||
      report.omittedEvidence !== 'All free text, URLs, credentials, env, package strings and raw output excluded')) return fail();
  if (report.profile === PUBLIC_IMAGE_PROFILE &&
      report.omittedEvidence !== 'All free text, URLs, credentials, env and raw output excluded; package identities and versions are sanitized scanner facts') return fail();
}

function checkHistory(context: HistoryContext): void {
  const h = context.history, omission = context.omission;
  if (!exact(context, ['version', 'report', 'history', 'question', 'omission']) || context.version !== HISTORY.version ||
      !exact(h, ['epoch', 'revision', 'userTurns', 'decisions', 'optionalExplanations']) || !isId(h.epoch) ||
      !count(h.revision, Number.MAX_SAFE_INTEGER) || !Array.isArray(h.userTurns) || h.userTurns.length > HISTORY.turns ||
      !Array.isArray(h.decisions) || h.decisions.length > HISTORY.decisions ||
      !Array.isArray(h.optionalExplanations) || h.optionalExplanations.length > HISTORY.turns ||
      !exact(omission, ['findings', 'explanations', 'selectedFindingIds']) || !count(omission.findings, 1000) ||
      !count(omission.explanations, HISTORY.turns) || !Array.isArray(omission.selectedFindingIds) ||
      JSON.stringify(omission.selectedFindingIds) !== JSON.stringify(context.report.findings.map(f => f.findingId)) ||
      omission.findings !== context.report.findingCount - context.report.findings.length) return fail();
  cleanText(context.question);
  const sources = (value: unknown) => Array.isArray(value) && value.length <= HISTORY.citations && value.every(source =>
    exact(source, ['scanId', 'digest', 'platform', 'reportVersion', 'finding']) && binding(source) && safeHistoryFinding(source.finding));
  for (const entry of [...h.userTurns, ...h.decisions]) {
    const decision = h.decisions.includes(entry);
    if (!exact(entry, decision ? ['id', 'mutationId', 'kind', 'text', 'report', 'sources', 'sourceState'] :
      ['id', 'text', 'report', 'sources', 'sourceState']) || !isId(entry.id) ||
        !exact(entry.report, ['scanId', 'digest', 'platform', 'reportVersion']) || !binding(entry.report) || !sources(entry.sources) ||
        !['same-report', 'historical-unresolved'].includes(String(entry.sourceState)) ||
        decision && (!isId(entry.mutationId) || entry.kind !== 'user-decision')) return fail();
    cleanText(entry.text);
  }
  for (const entry of h.optionalExplanations) {
    if (!exact(entry, ['id', 'text', 'kind']) || !isId(entry.id) || entry.kind !== 'hypothesis') return fail();
    cleanText(entry.text, HISTORY.replyBytes);
  }
}


// Inputs MUST come from the authorized ReportReader/selected history pipeline.
// These structural checks do not establish ownership or reconstruct scanner provenance.
// No raw messages/schema/model/prompt argument is accepted at preparation time.
export function prepareOpenAiSummary(report: ReportContext, policy: OpenAiPolicy): OpenAiPrepared {
  return prepare('summary', report, policy);
}
export function prepareOpenAiChat(context: HistoryContext, policy: OpenAiPolicy): OpenAiPrepared {
  return prepare('chat', context, policy);
}
function prepare(operation: OpenAiOperation, input: ReportContext | HistoryContext, policy: OpenAiPolicy): OpenAiPrepared {
  const prompts = checkedOpenAiPolicy(policy);
  try {
    const content = snapshot(input, policy.requestBytes);
    const report = operation === 'summary' ? content as ReportContext : (content as HistoryContext).report;
    checkReport(report, policy);
    if (operation === 'chat') checkHistory(content as HistoryContext);
    else if (report.profile === undefined && report.findings.length !== report.findingCount) return fail();
    const body = JSON.stringify({ model: policy.model, max_completion_tokens: policy.outputTokens,
      reasoning_effort: 'none', n: 1, stream: false, store: false, service_tier: 'default',
      response_format: openAiResponseFormat(operation),
      messages: [{ role: 'system', content: prompts[operation] }, { role: 'user', content: JSON.stringify(content) }] });
    const bytes = Buffer.byteLength(body);
    if (bytes > policy.requestBytes) return fail();
    // Same conservative byte bound as the existing adapter, including framing allowance.
    const reserve = openAiReserve(bytes + 1024, policy);
    const request = Object.freeze({ operation, body, hash: createHash('sha256').update(body).digest('hex'),
      policyVersion: policy.version, reserve });
    prepared.set(request, { policy, report });
    return request;
  } catch { return fail(); }
}

export function checkedOpenAiPrepared(request: OpenAiPrepared, policy: OpenAiPolicy): void {
  checkedOpenAiPolicy(policy);
  if (prepared.get(request)?.policy !== policy) return fail();
}
export function validateOpenAiPreparedReply(request: OpenAiPrepared, policy: OpenAiPolicy, value: unknown) {
  checkedOpenAiPrepared(request, policy);
  const report = prepared.get(request)!.report;
  const paragraph = (item: unknown, maxText: number, maxCitations: number) => object(item) &&
    typeof item.text === 'string' && [...item.text].length <= maxText &&
    Array.isArray(item.citations) && item.citations.length >= 1 && item.citations.length <= maxCitations;
  // Do not trust provider-side schema enforcement to honor the narrower wire caps.
  if (!object(value) || (request.operation === 'summary'
    ? !Array.isArray(value.hypotheses) || value.hypotheses.length < 1 || value.hypotheses.length > 6 ||
      value.hypotheses.some(item => !paragraph(item, 320, 2))
    : !paragraph(value, 600, 3))) return invalidReply();
  const result = request.operation === 'summary'
    ? { operation: 'summary' as const, value: validateReply(value, report, true) }
    : { operation: 'chat' as const, value: validateChatReply(value, report, true) };
  // Keep all shared safety/grounding checks; additionally enforce the OpenAI wire
  // alphabet locally. Never strip, transliterate or otherwise repair model text.
  const texts = result.operation === 'summary' ? result.value.hypotheses.map(item => item.text) : [result.value.text];
  if (texts.some(text => !openAiNarrative(text))) return invalidReply();
  return result;
}
