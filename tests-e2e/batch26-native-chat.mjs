// Preparatory runner. Import/default execution performs NO browser/network work.
// A fixed, permanently spent attempt authorizes at most ONE future chat POST.
import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { open, mkdir, realpath, lstat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { BROWSER_ARGS } from './public-product-live.mjs';
import { SCAN, MODEL, ORIGIN, BASE, QUESTION, allowedRead, fingerprint, contracts, collectVulnCorpus,
  policyMatches, readinessMatches } from './native-h7v3-paid-sol.mjs';
import { diagnosticContracts, captureResponseDiagnostics } from './native-h7v3-finite-diagnostics.mjs';
import { usageProjection, costDelta } from './native-h7v3-recovery-7f.mjs';

export { SCAN, MODEL, ORIGIN, BASE, QUESTION };
export const WORK = '697696f3-5722-4c0d-a61c-908f33ceb534';
export const RUN = '548510b1-d52b-43f5-97a8-a0fb72ec3141';
export const ROOT = fileURLToPath(new URL('../', import.meta.url));
export const DIRECTORY = join(ROOT, 'test-results/native-h7v3-batch26-native-chat');
export const ATTEMPT_FILE = join(DIRECTORY, 'final26-chat-once.spent.json');
export const SESSION_FILE = join(ROOT, 'tests-e2e/batch25-browser-final-evidence/private-storage.json');
const OLD_STATE = join(ROOT, 'test-results/native-h7v3-paid-sol/state.json');
const HASH = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const bindingKeys = ['scanId', 'digest', 'platform', 'reportVersion'];
const same = (a, b) => bindingKeys.every(key => a?.[key] === b?.[key]);
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const need = (value, code) => { if (!value) throw Error(code); };
const digest = value => createHash('sha256').update(value).digest('hex');
export const ACKS = Object.freeze(['--run-once', '--ack-coordinator-final-deployment-go',
  '--ack-one-paid-chat-uncapped', '--ack-preserve-summary-two-failed-and-old-slots']);
export function modeOf(args) {
  if (!args.length) return { mode: 'inert' };
  if (JSON.stringify(args) === JSON.stringify(['--fingerprint'])) return { mode: 'fingerprint' };
  need(args.length === ACKS.length + 4 && ACKS.every((flag, index) => args[index] === flag) &&
    args[4] === '--deployment-id' && /^[a-f0-9]{32}$/.test(args[5]) &&
    args[6] === '--review-sha256' && HASH.test(args[7]), 'EXACT_FINAL_GO_REQUIRED');
  return { mode: 'run-once', deployment: args[5], review: args[7] };
}
// Includes direct runner helpers and the contracts used to validate current wire.
// A source change after review must not silently execute under the old GO.
export const REVIEW_FILES = Object.freeze([
  'tests-e2e/batch26-native-chat.mjs', 'tests-e2e/batch26-native-chat.test.mjs',
  'tests-e2e/native-h7v3-paid-sol.mjs', 'tests-e2e/native-h7v3-recovery-7f.mjs',
  'tests-e2e/native-h7v3-finite-diagnostics.mjs', 'tests-e2e/public-product-live.mjs',
  'src/shared/api/scans/llmChatContract.ts', 'src/shared/api/scans/llmUsageClient.ts',
  'src/shared/api/scans/llmSummaryClient.ts', 'src/shared/api/scans/llmPublicContract.ts',
  'src/shared/api/scans/llmFindingContract.ts', 'server/api/src/llm/provider-diagnostic.ts',
  'server/api/src/llm/remediation-identifiers.ts', 'server/api/src/llm/openai-response-contract.ts',
  'server/api/src/llm/openai-policy.ts', 'server/api/src/llm/provider-runtime.ts', 'server/api/src/llm/summary-record.ts',
  'server/api/src/llm/history-contract.ts', 'server/api/src/llm/chat-source-budget.ts',
]);
export async function reviewFingerprint() {
  const pairs = [];
  for (const path of REVIEW_FILES) {
    const file = await open(join(ROOT, path), constants.O_RDONLY | constants.O_NOFOLLOW);
    try { pairs.push([path, digest(await file.readFile())]); } finally { await file.close(); }
  }
  return digest(JSON.stringify(pairs));
}
async function safeDirectory(path) {
  need(await realpath(path) === path, 'PRIVATE_PATH_UNSAFE');
  const stat = await lstat(path);
  need(stat.isDirectory() && !stat.isSymbolicLink() && (stat.mode & 0o077) === 0 &&
    (!process.getuid || stat.uid === process.getuid()), 'PRIVATE_PATH_UNSAFE');
}
export async function privateSnapshot(path) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await file.stat();
    need(stat.isFile() && stat.nlink === 1 && (stat.mode & 0o777) === 0o600 && stat.size <= 1048576 &&
      (!process.getuid || stat.uid === process.getuid()) && await realpath(path) === path, 'PRIVATE_SESSION_UNSAFE');
    let value, raw;
    try { raw = await file.readFile(); value = JSON.parse(raw.toString('utf8')); } catch { throw Error('PRIVATE_SESSION_UNSAFE'); }
    const after = await file.stat();
    need(after.ino === stat.ino && after.size === stat.size && after.mtimeMs === stat.mtimeMs, 'PRIVATE_SESSION_UNSAFE');
    return { value, byteHash: digest(raw) };
  } finally { await file.close(); }
}
export async function privateJson(path) { return (await privateSnapshot(path)).value; }
export function validateStorage(state) {
  need(exact(state, ['cookies', 'origins']) && Array.isArray(state.cookies) && state.cookies.length === 1 &&
    Array.isArray(state.origins) && state.origins.length <= 1, 'PRIVATE_SESSION_UNSAFE');
  const cookie = state.cookies[0];
  need(cookie.name === 'demo_session' && cookie.domain === '127.0.0.1' && cookie.path === '/' &&
    cookie.httpOnly === true && typeof cookie.value === 'string' && cookie.value.length > 0 &&
    (cookie.expires === -1 || cookie.expires > Date.now() / 1000) &&
    state.origins.every(origin => origin.origin === ORIGIN && Array.isArray(origin.localStorage)), 'PRIVATE_SESSION_UNSAFE');
  return state;
}
export async function spendAttempt(path, metadata) {
  // Never delete this file, including on preflight failure or process crash.
  const file = await open(path, 'wx', 0o600);
  try {
    await file.writeFile(JSON.stringify({ ...metadata, spent: true, work: WORK, run: RUN, beforeAnyNetwork: true }));
    await file.sync();
  } finally { await file.close(); }
  const directory = await open(dirname(path), constants.O_RDONLY);
  try { await directory.sync(); } finally { await directory.close(); }
}
export function initialHistory(history, context) {
  return !!history && !history.pending && history.revision === 4 && history.epoch === context?.epoch &&
    history.revision === context?.revision && same(history, context) && Array.isArray(history.turns) && history.turns.length === 2 &&
    history.turns.every(turn => turn.state === 'failed' && same(turn.report, context)) &&
    Array.isArray(history.decisions) && history.decisions.length === 0;
}
export function completionPreserved(before, after, answer) {
  return !!after && !after.pending && after.epoch === before.epoch && after.revision === before.revision + 2 &&
    same(before, after) && after.turns?.length === 3 && fingerprint(after.turns.slice(0, 2)) === fingerprint(before.turns) &&
    fingerprint(after.decisions) === fingerprint(before.decisions) && after.turns[2].state === 'completed' &&
    after.turns[2].id === answer.turnId && fingerprint(after.turns[2].reply) === fingerprint(answer.reply);
}
export class ChatGate {
  constructor(persist) { this.persist = persist; this.spent = false; this.stopped = false; this.permit = null; }
  arm(context, history) {
    need(!this.spent && !this.stopped && !this.permit && policyMatches(context) && initialHistory(history, context), 'FRESH_CHAT_GATE_REFUSED');
    this.permit = { context: structuredClone(context), previousMutations: history.turns.map(turn => turn.mutationId) };
  }
  async consume(path, body) {
    const permit = this.permit, c = permit?.context;
    if (this.stopped || this.spent || !c || path !== BASE + '/llm/chat' ||
      !exact(body, ['epoch', 'revision', 'mutationId', 'reportVersion', 'question', 'consent']) ||
      body.epoch !== c.epoch || body.revision !== c.revision || body.reportVersion !== c.reportVersion || body.question !== QUESTION ||
      !UUID.test(body.mutationId ?? '') || permit.previousMutations.includes(body.mutationId) ||
      !exact(body.consent, ['accepted', 'policyVersion']) || body.consent.accepted !== true || body.consent.policyVersion !== c.policyVersion) return false;
    this.spent = true; this.permit = null; // synchronous before persistence/await and before route.continue
    try { await this.persist({ policyVersion: c.policyVersion, reportVersion: c.reportVersion }); }
    catch { this.stop(); throw Error('DISPATCH_INTENT_UNCERTAIN_NO_RETRY'); }
    return !this.stopped;
  }
  stop() { this.stopped = true; this.permit = null; }
}
export function assertNoCaptureEnvironment(environment) {
  need(['DEBUG', 'PWDEBUG', 'NODE_DEBUG', 'NODE_DEBUG_NATIVE'].every(key =>
    !environment[key] || environment[key] === '0'), 'CAPTURE_DEBUG_ENABLED');
}
export function allowedGet(url) {
  try {
    const u = new URL(url);
    return allowedRead(url) && !/\/translation(?:\/|$)/.test(u.pathname) && !u.pathname.endsWith('/events');
  } catch { return false; }
}
export function outboundPlan(url, method, redirected = false) {
  let parsed;
  try { parsed = new URL(url); } catch { return 'deny'; }
  if (redirected || parsed.origin !== ORIGIN || parsed.username || parsed.password || parsed.hash) return 'deny';
  if (method === 'GET') return allowedGet(url) ? 'read' : 'deny';
  return method === 'POST' && !parsed.search && parsed.pathname === BASE + '/llm/chat' ? 'chat' : 'deny';
}
export function safeFailure(error) {
  const codes = new Set(['EXACT_FINAL_GO_REQUIRED', 'REVIEW_FINGERPRINT_CHANGED', 'PRIVATE_PATH_UNSAFE', 'PRIVATE_SESSION_UNSAFE',
    'PRIOR_LEDGER_INVALID', 'FRESH_CHAT_GATE_REFUSED', 'DISPATCH_INTENT_UNCERTAIN_NO_RETRY', 'REQUEST_GUARD',
    'MANUAL_GET_BOUND', 'GET_FAILED', 'CURRENT_POLICY_OR_READINESS', 'AUTOMATION_NOT_OFF', 'SUMMARY_CHANGED',
    'HISTORY_NOT_TWO_FAILED', 'CORPUS_MISMATCH', 'CURRENT_CONSENT_NOT_VISIBLE', 'BEFORE_SEND_CHANGED',
    'CHAT_RESPONSE_UNKNOWN_NO_RETRY', 'CHAT_FAILED_NO_RETRY', 'CHAT_WIRE_INVALID', 'NATIVE_CITATION_MISMATCH',
    'RUSSIAN_VALIDATION_FAILED', 'DURABLE_REPLY_MISMATCH', 'USAGE_MISMATCH', 'RELOAD_CHANGED_OR_POST', 'UI_REPLY_NOT_VISIBLE',
    'WHOLE_RUN_DEADLINE', 'ATTEMPT_ALREADY_SPENT_NO_RETRY', 'CAPTURE_DEBUG_ENABLED', 'SUMMARY_PRESERVATION_UNPROVEN']);
  return { code: codes.has(error?.message) ? error.message : error?.code === 'EEXIST' ? 'ATTEMPT_ALREADY_SPENT_NO_RETRY' : 'BOUNDED_RUNNER_FAILURE' };
}
export const CONTENT_PREDICATES = Object.freeze([
  'chat_shape', 'chat_binding', 'chat_citation_type', 'chat_citation_count', 'chat_citation_duplicate',
  'chat_citation_unknown', 'chat_source_bytes', 'chat_sources_bytes', 'chat_text', 'chat_text_length', 'chat_narrative',
]);
export async function openEvidenceJournal(path) {
  const file = await open(path, 'wx', 0o600);
  return {
    async publish(finite) { await file.writeFile(JSON.stringify(finite) + '\n'); await file.sync(); },
    async checkpoint(phase, aggregate) {
      need(['before-body', 'before-parser'].includes(phase), 'INVALID_DIAGNOSTIC_CHECKPOINT');
      await writeAggregate(`${path}.${phase}.aggregate.json`, aggregate);
    },
    async close() { await file.close(); },
  };
}
export async function writeAggregate(path, aggregate) {
  const file = await open(path, 'wx', 0o600);
  try { await file.writeFile(JSON.stringify(aggregate, null, 2)); await file.sync(); }
  finally { await file.close(); }
}
export async function captureIntoAggregate(response, c, context, mutationId, aggregate, journal) {
  const observed = await captureChatResponse(response, c, context, mutationId, async finite => {
    aggregate.responseDiagnostics = structuredClone(finite);
    await journal.publish({ event: 'response-diagnostics', ...finite });
    if (finite.bodyInspection === 'not-read') await journal.checkpoint('before-body', aggregate);
  });
  await journal.checkpoint('before-parser', aggregate);
  return observed;
}
// Current summary GET proves a matching DTO or a policy-qualified miss, not the
// continued existence of an old-policy storage row. No verification endpoint or
// trusted all-row preservation receipt is available to this browser-only runner.
export function summaryAcceptance(status, value, expectedHash, schema) {
  if (status === 200) {
    const parsed = schema.safeParse(value);
    const matches = parsed.success && HASH.test(expectedHash) && fingerprint(parsed.data) === expectedHash;
    return { availability: 'available', originalDtoHashMatched: !!matches, canProceed: !!matches,
      authoritativeOldRowPreservation: 'NOT_INDEPENDENTLY_MEASURED' };
  }
  if (status === 404 && exact(value, ['errorCode']) && value.errorCode === 'LLM_SUMMARY_MISSING')
    return { availability: 'unavailable_current_policy', errorCode: 'LLM_SUMMARY_MISSING', canProceed: false,
      originalDtoHashMatched: false, authoritativeOldRowPreservation: 'UNPROVEN_BY_CURRENT_ENDPOINT',
      cause: 'NO_MATCHING_CURRENT_RESULT_OLD_ROW_EXISTENCE_UNKNOWN' };
  return { availability: 'unverified', canProceed: false, originalDtoHashMatched: false,
    authoritativeOldRowPreservation: 'UNPROVEN_BY_CURRENT_ENDPOINT' };
}
export function contentHeaders(headers, predicate, c) {
  if (headers['X-LLM-Failure-Phase'] !== 'content' || headers['X-LLM-Failure-Reason'] !== 'invalid_content' ||
    typeof predicate !== 'string' || !CONTENT_PREDICATES.includes(predicate) || !c.diagnostic.CHAT_CONTENT_PREDICATES.includes(predicate)) return headers;
  const target = {};
  c.diagnostic.diagnoseChatContent(target, predicate);
  return { ...headers, ...c.diagnostic.diagnosticHeaders(target) };
}
// Diagnostics are written BEFORE the authoritative parser runs. Raw body is only
// returned transiently to that parser; never place it in an evidence object.
export async function captureChatResponse(response, c, context, mutationId, publish) {
  let predicate;
  try { predicate = await response.headerValue('x-llm-content-predicate'); } catch { /* absence is not a predicate */ }
  const observed = await captureResponseDiagnostics(response, c, async meta => {
    const safe = { httpStatus: meta.httpStatus, headers: contentHeaders(meta.headers, predicate, c),
      headerReadFailed: meta.headerReadFailed, bodyInspection: meta.bodyInspection,
      ...(meta.applicationFailure ? { applicationFailure: meta.applicationFailure } : {}) };
    await publish(safe);
  });
  const meta = { httpStatus: observed.diagnostics.httpStatus,
    headers: contentHeaders(observed.diagnostics.headers, predicate, c), bodyInspection: observed.diagnostics.bodyInspection,
    ...(observed.diagnostics.applicationFailure ? { applicationFailure: observed.diagnostics.applicationFailure } : {}) };
  const raw = observed.raw;
  let receipt, tuple;
  if (raw.endsWith('\n') && !raw.endsWith('\n\n')) {
    const lines = raw.slice(0, -1).split('\n');
    if (lines.length <= c.chat.CHAT_DELIVERY.frames && lines.every(line => Buffer.byteLength(line) + 1 <= c.chat.CHAT_DELIVERY.lineBytes)) {
      for (let seq = 0; seq < lines.length; seq++) {
        let parsed;
        try { parsed = c.chat.chatFrameSchema.safeParse(JSON.parse(lines[seq])); } catch { break; }
        if (!parsed.success) break;
        const frame = parsed.data;
        if (frame.seq !== seq || !same(frame, context) || frame.epoch !== context.epoch || frame.mutationId !== mutationId ||
          frame.revision !== context.revision + 2 || tuple && frame.turnId !== tuple) break;
        tuple ??= frame.turnId;
        if (frame.type === 'usage' && seq === 0 && c.chat.chatReceiptMatchesProvider(frame.usage, context)) {
          receipt = frame.usage; meta.currentUsageReceipt = { ...receipt }; meta.currentReceiptCaptured = true;
        }
        if (frame.type === 'error' && (frame.receipt === 'accepted') === !!receipt) {
          meta.currentTerminal = { errorCode: frame.errorCode, receipt: frame.receipt,
            ...(frame.providerFailure ? { providerFailure: frame.providerFailure } : {}) };
          break;
        }
      }
    }
  }
  await publish(structuredClone(meta));
  return { raw, diagnostics: meta };
}
export function parseAnswer(raw, c, context, mutationId) {
  need(raw.endsWith('\n') && !raw.endsWith('\n\n') && Buffer.byteLength(raw) <= c.chat.CHAT_DELIVERY.totalBytes, 'CHAT_WIRE_INVALID');
  const lines = raw.slice(0, -1).split('\n');
  need(lines.length <= c.chat.CHAT_DELIVERY.frames && lines.every(line => Buffer.byteLength(line) + 1 <= c.chat.CHAT_DELIVERY.lineBytes), 'CHAT_WIRE_INVALID');
  const parser = c.chat.createChatFrameParser(context, mutationId);
  for (const line of lines) parser.accept(JSON.parse(line));
  const answer = parser.finish();
  need(answer.reply && !answer.duplicate && !answer.errorCode, 'CHAT_FAILED_NO_RETRY');
  return answer;
}
export function nativeFinding(row) {
  if (row.check === 'config' || row.ruleId === 'IMGCFG_USER_ROOT') return Object.fromEntries([
    ['check', 'config'], ['findingId', row.findingId], ['severity', 'MEDIUM'], ['ruleId', row.ruleId],
    ['classification', row.classification], ['configDigest', row.configDigest], ['manifestDigest', row.manifestDigest], ['location', row.location],
  ]);
  const out = { check: 'vuln', findingId: row.findingId, severity: row.severity, cveId: row.cveId, identifierKind: row.identifierKind,
    ecosystem: row.ecosystem, severitySources: row.severitySources, provenanceRef: row.provenanceRef,
    fixedVersionReported: row.fixedVersion !== null, packageName: row.packageName, installedVersion: row.installedVersion, fixedVersion: row.fixedVersion };
  if (!row.advisory) return { ...out, advisoryState: 'unknown' };
  const advisory = row.advisory;
  return { ...out, advisoryState: advisory.state, conflictState: advisory.conflictState, conflicts: advisory.conflicts,
    limitations: advisory.limitations, assessments: advisory.assessments.map(a => ({ source: a.source, severity: a.severity,
      fixedVersionReported: a.fixedVersion !== null, cvss: a.cvss === null ? null : Object.fromEntries(
        ['family', 'version', 'versionState', 'reportedScore', 'scoreState', 'vectorState'].map(key => [key, a.cvss[key]])) })) };
}
export function replyProof(answer, corpus, c, tools) {
  need(answer.reply.sources.length >= 1 && answer.reply.sources.length <= 3 &&
    answer.reply.sources.every(source => corpus.has(source.finding.findingId) &&
      fingerprint(source.finding) === fingerprint(nativeFinding(corpus.get(source.finding.findingId)))), 'NATIVE_CITATION_MISMATCH');
  const facts = answer.reply.sources.map(source => source.finding);
  need(!tools.language.publicReportLanguageFailure(answer.reply.text, facts) &&
    !tools.language.remediationGroundingRejection(answer.reply.text, facts) &&
    c.narrative.openAiNarrative(answer.reply.text), 'RUSSIAN_VALIDATION_FAILED');
  return { exactNativeCitationMatch: true, citationCount: facts.length,
    replyHash: fingerprint(answer.reply), textBytes: Buffer.byteLength(answer.reply.text),
    sourceBytes: answer.reply.sources.map(source => Buffer.byteLength(JSON.stringify(source))),
    russianObservation: { directRussianProse: 'VALIDATED', typedSourceGrounding: 'VALIDATED',
      semanticAccuracy: 'UNVERIFIED_REQUIRES_IN_MEMORY_HUMAN_REVIEW', unsupportedCausalClaims: 'NOT_PROVEN_ABSENT' } };
}
export function usageDifference(before, after, receipt) {
  if (receipt) return costDelta(before, after, receipt);
  if (!before?.available || !after?.available || !same(before, after) || before.window.start !== after.window.start)
    return { valid: false, reason: 'unavailable_binding_or_window_changed', receiptMatched: false };
  const delta = {};
  for (const scope of ['user', 'scan']) {
    delta[scope] = {};
    for (const group of ['used', 'held', 'carried']) {
      delta[scope][group] = {};
      for (const key of ['input', 'output', 'costMicros']) {
        const value = after[scope][group][key] - before[scope][group][key];
        if (!Number.isSafeInteger(value)) return { valid: false, reason: 'unavailable_binding_or_window_changed', receiptMatched: false };
        delta[scope][group][key] = value;
      }
    }
  }
  return { valid: true, reason: 'same_window_aggregate_only_no_receipt', receiptMatched: false, delta };
}
export async function extraContracts() {
  const { createRequire } = await import('node:module');
  const require = createRequire(join(ROOT, 'server/api/package.json')), manifest = require('tsx/package.json');
  const { tsImport } = await import(pathToFileURL(join(dirname(require.resolve('tsx/package.json')), manifest.exports['./esm/api'].import.default)).href);
  const load = path => tsImport(join(ROOT, path), { parentURL: import.meta.url, tsconfig: join(ROOT, 'tsconfig.json') });
  return { usage: (await load('src/shared/api/scans/llmUsageClient.ts')).usageSchema,
    narrative: await load('server/api/src/llm/openai-response-contract.ts') };
}
export async function runOnce(options) {
  need(options?.mode === 'run-once' && HASH.test(options.review) && /^[a-f0-9]{32}$/.test(options.deployment), 'EXACT_FINAL_GO_REQUIRED');
  assertNoCaptureEnvironment({ DEBUG: process.env.DEBUG, PWDEBUG: process.env.PWDEBUG,
    NODE_DEBUG: process.env.NODE_DEBUG, NODE_DEBUG_NATIVE: process.env.NODE_DEBUG_NATIVE });
  need(await reviewFingerprint() === options.review, 'REVIEW_FINGERPRINT_CHANGED');
  process.umask(0o077);
  await mkdir(DIRECTORY, { recursive: true, mode: 0o700 }); await safeDirectory(DIRECTORY);
  const runId = randomUUID();
  await spendAttempt(ATTEMPT_FILE, { runId, review: options.review, deployment: options.deployment, at: Date.now() });
  const log = { runId, work: WORK, status: 'PREPARING', deployment: options.deployment, review: options.review,
    requests: 0, maxRequests: 400, manualGets: 0, maxManualGets: 40, postAttempts: 0, dispatched: 0, denied: 0, pageErrors: 0,
    chatPosts: 0, summaryPosts: 0, translationPosts: 0, scanPosts: 0, captures: 'OFF', phase: 'local-preflight' };
  const events = await openEvidenceJournal(join(DIRECTORY, 'diagnostics.ndjson'));
  const publish = finite => events.publish(finite);
  let browser, context, gate, timer, prior, oldHash, sessionHash;
  try {
    const old = await privateSnapshot(OLD_STATE); prior = old.value; oldHash = old.byteHash;
    need(prior.summary === 1 && prior.chat === 1 && prior.summarySucceeded === true && HASH.test(prior.summaryHash), 'PRIOR_LEDGER_INVALID');
    const retainedSession = await privateSnapshot(SESSION_FILE); sessionHash = retainedSession.byteHash;
    const storage = validateStorage(retainedSession.value);
    const tools = await contracts(), c = { ...await diagnosticContracts(), ...await extraContracts() };
    gate = new ChatGate(async metadata => {
      const file = await open(join(DIRECTORY, 'dispatch-intent.json'), 'wx', 0o600);
      try { await file.writeFile(JSON.stringify({ work: WORK, runId, ...metadata })); await file.sync(); }
      finally { await file.close(); }
    });
    const { chromium } = await import('@playwright/test');
    // Nonpersistent context: never rewrite the retained private storage file/profile.
    const browserEnvironment = Object.fromEntries(['PATH', 'HOME', 'TMPDIR', 'LANG', 'TZ', 'SystemRoot']
      .filter(key => process.env[key] !== undefined).map(key => [key, process.env[key]]));
    browser = await chromium.launch({ headless: true, timeout: 20000, env: browserEnvironment, args: [...BROWSER_ARGS] });
    context = await browser.newContext({ storageState: storage, serviceWorkers: 'block', acceptDownloads: false,
      viewport: { width: 1280, height: 960 }, reducedMotion: 'reduce' });
    timer = setTimeout(() => { log.phase = 'deadline'; gate.stop(); void browser.close(); }, 360000); timer.unref();
    await context.route('**/*', async route => {
      const r = route.request();
      const deny = async () => { log.denied++; gate.stop(); await route.abort().catch(() => {}); };
      const proceed = async () => {
        try { await route.continue(); }
        catch { log.routeContinuationUncertain = true; gate.stop(); await route.abort().catch(() => {}); }
      };
      if (++log.requests > log.maxRequests) return deny();
      const plan = outboundPlan(r.url(), r.method(), !!r.redirectedFrom());
      if (r.method() !== 'GET') log.postAttempts++;
      if (plan === 'read') return proceed();
      if (plan !== 'chat' || await r.headerValue('accept') !== 'application/x-ndjson') return deny();
      let body; try { body = r.postDataJSON(); } catch { return deny(); }
      try { if (!await gate.consume(BASE + '/llm/chat', body)) return deny(); } catch { return deny(); }
      try { await publish({ event: 'dispatch-intent-durable', chatPermit: 1, consentAccepted: true }); }
      catch { return deny(); }
      if (gate.stopped) return deny();
      log.dispatched++; log.chatPosts++;
      return proceed();
    });
    await context.routeWebSocket('**/*', socket => { log.denied++; gate.stop(); socket.close(); });
    const page = await context.newPage(); page.setDefaultTimeout(20000); page.on('pageerror', () => { log.pageErrors++; });
    const read = async suffix => {
      need(++log.manualGets <= log.maxManualGets, 'MANUAL_GET_BOUND');
      const result = await page.evaluate(async path => {
        const response = await fetch(path, { signal: AbortSignal.timeout(15000) });
        let value; try { value = await response.json(); } catch { value = null; }
        return { status: response.status, value };
      }, BASE + suffix);
      const labels = { '': 'status', '/llm/summary': 'summary', '/llm/history': 'history', '/llm/context': 'summary-context',
        '/llm/chat/context': 'chat-context', '/llm/readiness': 'readiness', '/llm/usage': 'usage', '/vuln': 'vuln-page' };
      const label = labels[suffix.split('?')[0]] ?? 'other-own-get';
      log.getStatuses ??= {};
      const key = `${label}:${Number.isInteger(result.status) && result.status >= 100 && result.status <= 599 ? result.status : 'invalid'}`;
      log.getStatuses[key] = (log.getStatuses[key] ?? 0) + 1;
      return result;
    };
    const get = async suffix => { const result = await read(suffix); need(result.status === 200, 'GET_FAILED'); return result.value; };
    const history = async () => c.chat.chatHistorySchema.parse(await get('/llm/history'));
    const summary = async () => {
      const result = await read('/llm/summary');
      const proof = summaryAcceptance(result.status, result.value, prior.summaryHash, tools.summary.summaryReplySchema);
      log.summaryRead = proof;
      await publish({ event: 'summary-read', ...proof });
      need(proof.canProceed, proof.availability === 'unavailable_current_policy' ? 'SUMMARY_PRESERVATION_UNPROVEN' : 'SUMMARY_CHANGED');
      return tools.summary.summaryReplySchema.parse(result.value);
    };
    const current = async () => {
      const s = tools.summary.summaryContextSchema.parse(await get('/llm/context')),
        h = c.chat.chatContextSchema.parse(await get('/llm/chat/context')),
        r = c.chat.chatReadinessSchema.parse(await get('/llm/readiness'));
      need(s.scanId === SCAN && s.digest === 'sha256:abe13b25e07ccaedcc8797120c37781f0462a0f0682105cf2d8b8d6f99070d55' &&
        same(s, h) && policyMatches(s) && policyMatches(h) && readinessMatches(r, h) && !h.pending, 'CURRENT_POLICY_OR_READINESS');
      return { s, h, r };
    };
    const usage = async () => c.usage.parse(await get('/llm/usage'));
    log.phase = 'automation-read-only';
    await page.goto(ORIGIN + '/account');
    const details = page.locator('details.demo-auth__preferences'); await details.waitFor({ state: 'visible' });
    if (await details.getAttribute('open') === null) await details.locator(':scope > summary').click();
    const prefs = details.getByRole('region', { name: 'Настройки отчётов', exact: true });
    need(await prefs.getByLabel('ИИ-разбор', { exact: true }).inputValue() === 'off' &&
      await prefs.getByLabel('Язык исходных описаний уязвимостей', { exact: true }).inputValue() === 'original', 'AUTOMATION_NOT_OFF');
    log.phase = 'initial-read-only';
    await page.goto(`${ORIGIN}/scans/${SCAN}`); await page.locator('.scan-report-overview').waitFor();
    const existingSummary = await summary(), first = await current(), before = await history();
    need(same(existingSummary, first.h) && initialHistory(before, first.h), 'HISTORY_NOT_TWO_FAILED');
    log.priorHistoryHash = fingerprint(before); log.priorFailedCount = 2; log.existingSummaryHash = prior.summaryHash;
    const snapshot = await get('');
    need(snapshot.state === 'completed' && snapshot.perCheck?.secret?.findingCount === 0 && snapshot.perCheck?.vuln?.findingCount === 440, 'CORPUS_MISMATCH');
    const corpus = new Map((snapshot.config?.findings ?? []).map(row => [row.findingId, row]));
    const native = await collectVulnCorpus(get, 440);
    const identifierCounts = { cve: 0, debianTemp: 0, debianDla: 0 };
    for (const [id, row] of native.findings) {
      corpus.set(id, row);
      const key = { cve: 'cve', 'debian-temp': 'debianTemp', 'debian-dla': 'debianDla' }[row.identifierKind];
      need(key, 'CORPUS_MISMATCH'); identifierCounts[key]++;
    }
    need(identifierCounts.cve === 431 && identifierCounts.debianTemp === 6 && identifierCounts.debianDla === 3, 'CORPUS_MISMATCH');
    log.corpus = { vulnerabilityCount: native.findings.size, pages: native.pages, identifierCounts, complete: true };
    log.phase = 'fresh-paid-consent';
    const fresh = await current(), head = await history(); await summary();
    need(initialHistory(head, fresh.h) && fingerprint(head) === fingerprint(before) &&
      fresh.h.policyVersion === first.h.policyVersion && fingerprint(fresh.h.disclosure) === fingerprint(first.h.disclosure), 'BEFORE_SEND_CHANGED');
    const chat = page.getByRole('region', { name: 'Чат по отчёту', exact: true });
    const disclosure = chat.getByLabel('Условия OpenAI', { exact: true }); await disclosure.waitFor({ state: 'visible' });
    const disclosureText = await disclosure.innerText();
    need(disclosureText.includes(MODEL) && disclosureText.includes('без локального денежного лимита') &&
      disclosureText.includes('не бесплатный режим') && disclosureText.includes('ZDR') &&
      (await chat.locator('#scan-chat-send-help').innerText()).includes('платный запрос OpenAI'), 'CURRENT_CONSENT_NOT_VISIBLE');
    const beforeUsage = await usage();
    need(beforeUsage.available && same(beforeUsage, fresh.h), 'USAGE_MISMATCH'); log.usageBefore = usageProjection(beforeUsage);
    log.currentPolicy = { provider: 'OpenAI', model: MODEL, monetaryLimit: 'uncapped', freshConsentUi: true, policyVersion: fresh.h.policyVersion };
    await chat.getByRole('textbox', { name: 'Вопрос чату', exact: true }).fill(QUESTION);
    need(log.postAttempts === 0 && log.denied === 0, 'REQUEST_GUARD');
    gate.arm(fresh.h, head); log.phase = 'one-chat';
    const pending = page.waitForResponse(response => response.request().method() === 'POST' &&
      new URL(response.url()).pathname === BASE + '/llm/chat', { timeout: 150000 }).catch(() => null);
    await chat.getByRole('button', { name: 'Отправить вопрос', exact: true }).click();
    const response = await pending; gate.stop(); need(response, 'CHAT_RESPONSE_UNKNOWN_NO_RETRY');
    const mutationId = response.request().postDataJSON().mutationId;
    const observed = await captureIntoAggregate(response, c, fresh.h, mutationId, log, events);
    // On failure, capture current aggregate usage and retained history BEFORE stop;
    // no retries, resets or assertions that an absent receipt means zero consumption.
    const afterUsage = await usage(); log.usageAfter = usageProjection(afterUsage);
    log.usageDelta = usageDifference(beforeUsage, afterUsage, observed.diagnostics.currentUsageReceipt);
    const after = await history(); await summary(); log.existingSummaryPreserved = true;
    log.failedPrefixUnchanged = fingerprint(after.turns.slice(0, 2)) === fingerprint(before.turns);
    log.historyAfter = { revision: after.revision, turnCount: after.turns.length, pending: !!after.pending,
      failedCount: after.turns.filter(turn => turn.state === 'failed').length,
      completedCount: after.turns.filter(turn => turn.state === 'completed').length };
    need(log.failedPrefixUnchanged, 'DURABLE_REPLY_MISMATCH');
    need(response.status() === 200 && !observed.diagnostics.currentTerminal, 'CHAT_FAILED_NO_RETRY');
    const answer = parseAnswer(observed.raw, c, fresh.h, mutationId);
    need(observed.diagnostics.currentReceiptCaptured && fingerprint(answer.usage) === fingerprint(observed.diagnostics.currentUsageReceipt), 'USAGE_MISMATCH');
    log.reply = replyProof(answer, corpus, c, tools);
    need(completionPreserved(before, after, answer), 'DURABLE_REPLY_MISMATCH');
    need(log.usageDelta.valid === true, 'USAGE_MISMATCH');
    need((await chat.innerText()).includes(answer.reply.text), 'UI_REPLY_NOT_VISIBLE');
    log.historyHash = fingerprint(after); log.phase = 'reload-get-only';
    await page.reload(); await page.locator('.scan-report-overview').waitFor();
    await summary(); const reloaded = await history();
    need(fingerprint(reloaded) === log.historyHash && completionPreserved(before, reloaded, answer) &&
      log.postAttempts === 1 && log.dispatched === 1 && log.denied === 0 && log.pageErrors === 0, 'RELOAD_CHANGED_OR_POST');
    const reloadedChat = page.getByRole('region', { name: 'Чат по отчёту', exact: true });
    await reloadedChat.getByRole('heading', { name: 'Ответ · проверьте по источникам', exact: true }).waitFor({ state: 'visible' });
    need((await reloadedChat.innerText()).includes(answer.reply.text), 'UI_REPLY_NOT_VISIBLE');
    log.reload = { exactHistory: true, exactReply: true, oldTwoFailedPreserved: true, existingSummaryPreserved: true, paidPosts: 0 };
    log.status = 'WIRE_DURABLE_RUSSIAN_VERIFIED_SEMANTICS_PENDING';
  } catch (error) {
    gate?.stop(); log.status = 'BLOCKED_OR_PARTIAL'; log.failure = { phase: log.phase, ...safeFailure(error) };
    await publish({ event: 'stopped', ...log.failure });
  } finally {
    clearTimeout(timer); gate?.stop(); await context?.close().catch(() => {}); await browser?.close().catch(() => {});
    log.browserClosed = true;
    if (oldHash) {
      try { log.oldLedgerUnchanged = (await privateSnapshot(OLD_STATE)).byteHash === oldHash; }
      catch { log.oldLedgerUnchanged = false; }
      if (!log.oldLedgerUnchanged) log.status = 'BLOCKED_OR_PARTIAL';
    }
    if (sessionHash) {
      try { log.retainedSessionFileUnchanged = (await privateSnapshot(SESSION_FILE)).byteHash === sessionHash; }
      catch { log.retainedSessionFileUnchanged = false; }
      if (!log.retainedSessionFileUnchanged) log.status = 'BLOCKED_OR_PARTIAL';
    }
    await writeAggregate(join(DIRECTORY, 'aggregate.json'), log);
    await events.close();
    console.log(JSON.stringify(log));
    if (log.status === 'BLOCKED_OR_PARTIAL') process.exitCode = 1;
  }
  return log;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const options = modeOf(process.argv.slice(2));
    if (options.mode === 'inert') console.log('INERT: no browser/network. Final deployment + new coordinator paid GO and safety review required.');
    else if (options.mode === 'fingerprint') console.log(await reviewFingerprint());
    else await runOnce(options);
  } catch (error) { console.log(JSON.stringify({ status: 'REFUSED_NO_RETRY', ...safeFailure(error) })); process.exitCode = 1; }
}
