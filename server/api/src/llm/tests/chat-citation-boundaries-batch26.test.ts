import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HttpException } from '@nestjs/common';
import { EventEmitter } from 'node:events';
import Database from 'better-sqlite3';
import { AuthStore } from '../../auth/auth.store.js';
import { HistoryRuntime, HISTORY_AUTHORITY } from '../history-runtime.js';
import { HistoryService } from '../history.service.js';
import { registerHistoryIngress } from '../history-ingress.js';
import { openRouterRuntime } from '../provider-runtime.js';
import { OpenRouterProvider } from '../openrouter-provider.js';
import type { GuardedTransport } from '../openrouter-transport.js';
import { FixtureQuotaLedger, quotaPolicy, quotaEnv } from './quota-fixtures.js';
import { quotaPolicyFromEnvironment } from '../quota-policy.js';
import { openAiDisclosure, CHAT_SENT_DATA, CHAT_LOCAL_RETENTION } from '../provider-browser-contract.js';
import type { LlmQuotaRuntime } from '../quota-runtime.js';
import type { ReportReader } from '../report-context.js';
import { ADVISORY_SOURCES } from '../../worker/vuln-advisory.js';
import { PUBLIC_VULN_SOURCES } from '../../worker/vuln-findings.js';
import { PUBLIC_IMAGE_PROFILE } from '../../oci/public-image-policy.js';
import type { ReportContext, SafeFinding } from '../report-context.js';
import { HISTORY, bytes, hashValue, reportBinding, validateChatReply, historyProjection, type HistoryHead, type Turn } from '../history-contract.js';
import { HistoryStore } from '../history-store.js';
import { safeHistoryFinding } from '../history-sources.js';
import { selectPreparedHistory, type HistoryContext } from '../history-context.js';
import { prepareOpenAiChat, validateOpenAiPreparedReply } from '../openai-prepared-request.js';
import { prepareHistory } from '../prepared-request.js';
import { policyFromEnvironment } from '../policy.js';
import { fixtureEnv } from './fixtures.js';
import { encodeDelivery, DELIVERY } from '../history-delivery.js';
import { OPENAI_COST_BASIS } from '../openai-accounting.js';
import { makeOpenAiPolicy, openAiReport } from './openai-core.fixture.js';
import { checkedOpenAiPolicy, OPENAI_ENDPOINT } from '../openai-policy.js';
import { openAiResponseFormat } from '../openai-response-contract.js';
import { CHAT_SOURCE_BUDGET, chatSourcesWithinBudget } from '../chat-source-budget.js';
import { diagnosticHeaders } from '../provider-diagnostic.js';
import { chatSourceSchema, chatReplySchema, chatHistorySchema, chatFrameSchema, CHAT_DELIVERY, chatContextSchema, createChatFrameParser, CHAT_SOURCE_BUDGET as BROWSER_CHAT_SOURCE_BUDGET } from '../../../../../src/shared/api/scans/llmChatContract.js';

const prose = 'Сканер сообщил о находке; требуется проверка.';
const owner = 'a'.repeat(32);
const empty = (): HistoryHead => ({ epoch: randomUUID(), revision: 0, turns: [], decisions: [], pending: null });
function finding(index: number, large = false): SafeFinding {
  const base: SafeFinding = { check: 'vuln', findingId: `vuln-${index.toString(16).padStart(64, '0')}`,
    severity: 'CRITICAL', cveId: `CVE-2026-${1000 + index}`, identifierKind: 'cve', ecosystem: 'deb',
    severitySources: ['debian'], provenanceRef: `target-${'b'.repeat(64)}`, fixedVersionReported: false,
    packageName: 'libc6', installedVersion: '1.0', fixedVersion: null, advisoryState: 'unknown' };
  if (!large) return base;
  return { ...base, packageName: 'libc6.'.repeat(21) + 'ab', installedVersion: '1.'.repeat(39) + '1',
    severitySources: [...PUBLIC_VULN_SOURCES], advisoryState: 'available', conflictState: 'present',
    conflicts: ['title', 'description', 'severity', 'fixedVersion', 'cvss'],
    limitations: ['invalid_metadata', 'redaction', 'field_limit', 'assessment_limit', 'reference_limit', 'finding_budget', 'scan_budget', 'report_budget'],
    assessments: [...ADVISORY_SOURCES].sort((a, b) => b.length - a.length).slice(0, 16).map(source => ({ source,
      severity: 'CRITICAL', fixedVersionReported: false, cvss: { family: 'v3', version: '3.1', versionState: 'unsupported',
        reportedScore: 9.999999999999998, scoreState: 'available', vectorState: 'unsupported' } })) };
}
function report(findings: SafeFinding[]): ReportContext {
  return { ...openAiReport, profile: PUBLIC_IMAGE_PROFILE, requestedChecks: ['vuln'], findings, findingCount: findings.length,
    coverage: { ...openAiReport.coverage, secret: { outcome: 'unknown', reason: 'CHECK_NOT_REQUESTED' },
      vuln: { outcome: 'checked', findingCount: findings.length } },
    omittedEvidence: 'All free text, URLs, credentials, env and raw output excluded; package identities and versions are sanitized scanner facts' };
}
function context(value: ReportContext): HistoryContext {
  return { version: HISTORY.version, report: value, question: 'Что проверить?', history: { epoch: randomUUID(), revision: 0, decisions: [], userTurns: [], optionalExplanations: [] },
    omission: { findings: 0, explanations: 0, selectedFindingIds: value.findings.map(f => f.findingId) } };
}
function begin(store: HistoryStore, value: ReportContext) {
  const head = store.snapshot(owner, value.scanId), id = randomUUID();
  const turn: Turn = { id, mutationId: randomUUID(), state: 'pending', question: 'Что проверить?', report: reportBinding(value),
    createdAt: Date.now(), inputHash: 'a'.repeat(64), consentPolicyVersion: 'b'.repeat(64), requestHash: 'c'.repeat(64) };
  return { id, head: store.begin(owner, value.scanId, head.epoch, head.revision, turn,
    { id, sessionId: 'd'.repeat(32), generation: 1, accessIncarnation: 'e'.repeat(32), policyVersion: turn.consentPolicyVersion,
      deadline: Date.now() + 60000, requestHash: turn.requestHash }) };
}
function temporary(action: (store: HistoryStore, path: string) => void) {
  const directory = mkdtempSync(join(tmpdir(), 'chat-boundary-batch26-')), path = join(directory, 'llm-history.sqlite');
  const store = new HistoryStore(path, true);
  try { action(store, path); } finally { store.close(); rmSync(directory, { recursive: true, force: true }); }
}
const receipt = { input: 20, output: 10, costMicros: 40, source: OPENAI_COST_BASIS } as const;
function delivery(value: ReportContext, reply: ReturnType<typeof validateChatReply>) {
  return { ...reportBinding(value), epoch: randomUUID(), revision: 2, mutationId: randomUUID(), turnId: randomUUID(),
    outcome: 'completed' as const, reply, usage: receipt };
}

function browserRoundTrip(plan: ReturnType<typeof encodeDelivery>, expected: ReturnType<typeof validateChatReply>) {
  const first = JSON.parse(plan.lines[0]);
  const policy = makeOpenAiPolicy();
  const quota = quotaPolicyFromEnvironment({ ...quotaEnv, LLM_QUOTA_USER_COST_USD: '1', LLM_QUOTA_SCAN_COST_USD: '1' })!;
  const context = chatContextSchema.parse({ scanId: expected.scanId, digest: expected.digest, platform: expected.platform,
    reportVersion: expected.reportVersion, epoch: first.epoch, revision: 0, enabled: true,
    policyVersion: policy.version, disclosure: { ...openAiDisclosure(policy, quota, true), sentData: CHAT_SENT_DATA,
      localRetention: CHAT_LOCAL_RETENTION }, limits: { questionBytes: 2048, bodyBytes: 8192 }, deliveryMode: 'completed-response', pending: false });
  const parser = createChatFrameParser(context, first.mutationId);
  for (const line of plan.lines) parser.accept(JSON.parse(line));
  const completed = parser.finish();
  assert.equal('reply' in completed, true);
  if (!('reply' in completed)) assert.fail('completed reply required');
  assert.deepEqual(completed.reply, expected);
  const incomplete = createChatFrameParser(context, first.mutationId);
  for (const line of plan.lines.slice(0, -1)) incomplete.accept(JSON.parse(line));
  assert.throws(() => incomplete.finish(), 'no publication on missing terminal/unclean EOF');
  assert.throws(() => parser.accept(JSON.parse(plan.lines[0])), 'no frames after terminal');
}

test('batch26 full sixteen-assessment findings stay immutable across strict OpenAI, browser, NDJSON and durable old/new history', t => {
  const full = report([finding(0, true), finding(1, true), finding(2, true)]);
  assert.equal(full.findings.every(safeHistoryFinding), true, 'large fixture must remain a legitimate typed full finding');
  const sources = full.findings.map(finding => ({ ...reportBinding(full), finding }));
  assert.equal(sources.every(source => bytes(source) > 2048), true, 'exercise the original defect, not small substitutes');
  t.diagnostic(JSON.stringify({ legitimateFullSources: 3, sourceBytes: sources.map(bytes) }));
  const policy = makeOpenAiPolicy({ requestBytes: 262144 });
  const prepared = prepareOpenAiChat(context(full), policy);
  const raw = { ...reportBinding(full), text: prose, citations: full.findings.map(f => f.findingId) };
  const result = validateOpenAiPreparedReply(prepared, policy, raw);
  assert.equal(result.operation, 'chat');
  if (result.operation !== 'chat') assert.fail('chat operation required');
  assert.deepEqual(result.value.sources, sources, 'never truncate/drop assessments to fit');
  assert.equal(chatReplySchema.safeParse(result.value).success, true);
  const plan = encodeDelivery(delivery(full, result.value));
  browserRoundTrip(plan, result.value);
  assert.equal(plan.lines.every(line => Buffer.byteLength(line) <= DELIVERY.lineBytes), true);
  assert.equal(plan.lines.every(line => chatFrameSchema.safeParse(JSON.parse(line)).success), true);
  temporary((store, path) => {
    const old = report([finding(90)]), oldPending = begin(store, old);
    const oldReply = validateChatReply({ ...reportBinding(old), text: prose, citations: [old.findings[0].findingId] }, old);
    const oldHead = store.finish(owner, old.scanId, oldPending.head.epoch, oldPending.head.revision, oldPending.id, oldReply);
    const pending = begin(store, full);
    store.finish(owner, full.scanId, pending.head.epoch, pending.head.revision, pending.id, result.value);
    const head = store.snapshot(owner, full.scanId);
    store.decision(owner, full.scanId, head.epoch, head.revision, { id: randomUUID(), mutationId: randomUUID(), kind: 'user-decision',
      text: 'Проверить полные исходные данные.', report: reportBinding(full), sources });
    const reopened = new HistoryStore(path);
    try {
      const retained = reopened.snapshot(owner, full.scanId);
      assert.deepEqual(retained.turns[0], oldHead.turns[0], 'old small citation and replay identity unchanged');
      assert.deepEqual(retained.turns[1].reply, result.value);
      assert.deepEqual(retained.decisions[0].sources, sources);
      assert.equal(chatHistorySchema.safeParse(historyProjection(retained, reportBinding(full))).success, true);
    } finally { reopened.close(); }
  });
  t.diagnostic(JSON.stringify({ legitimateFullSources: 3, sourceBytes: sources.map(bytes), frames: plan.lines.length }));
});

test('batch26 maximum32 small citations and maximum UTF8 text persist and fit actual server/browser delivery bounds', () => {
  const full = report(Array.from({ length: 32 }, (_, index) => finding(index)));
  assert.equal(full.findings.every(safeHistoryFinding), true);
  const text = 'я'.repeat(HISTORY.replyBytes / 2);
  assert.equal(Buffer.byteLength(text), HISTORY.replyBytes);
  const reply = validateChatReply({ ...reportBinding(full), text, citations: full.findings.map(f => f.findingId) }, full);
  assert.equal(reply.sources.length, 32);
  assert.equal(chatReplySchema.safeParse(reply).success, true);
  const plan = encodeDelivery(delivery(full, reply));
  browserRoundTrip(plan, reply);
  assert.equal(plan.lines.every(line => Buffer.byteLength(line) <= DELIVERY.lineBytes), true);
  assert.equal(Buffer.byteLength(plan.lines.join('')) <= DELIVERY.totalBytes, true);
  assert.equal(plan.lines.length + 1 <= DELIVERY.frames, true);
  assert.deepEqual(CHAT_DELIVERY, { lineBytes: DELIVERY.lineBytes, totalBytes: DELIVERY.totalBytes,
    frames: DELIVERY.frames, deltaBytes: DELIVERY.deltaBytes });
  assert.equal(plan.lines.every(line => chatFrameSchema.safeParse(JSON.parse(line)).success), true);
  temporary((store, path) => {
    const pending = begin(store, full);
    const done = store.finish(owner, full.scanId, pending.head.epoch, pending.head.revision, pending.id, reply);
    const reopened = new HistoryStore(path);
    try {
      assert.deepEqual(reopened.snapshot(owner, full.scanId), done);
      assert.equal(chatHistorySchema.safeParse(historyProjection(done, reportBinding(full))).success, true);
    } finally { reopened.close(); }
  });
});

test('batch26 OpenAI maximum3 citations is strict; duplicates, unknowns, extra facts and fourth citation stay rejected', () => {
  const full = report(Array.from({ length: 4 }, (_, index) => finding(index)));
  const policy = makeOpenAiPolicy(), prepared = prepareOpenAiChat(context(full), policy);
  const raw = { ...reportBinding(full), text: prose, citations: full.findings.slice(0, 3).map(f => f.findingId) };
  assert.equal(validateOpenAiPreparedReply(prepared, policy, raw).operation, 'chat');
  for (const value of [{ ...raw, citations: full.findings.map(f => f.findingId) },
    { ...raw, citations: [raw.citations[0], raw.citations[0]] }, { ...raw, citations: ['unknown'] },
    { ...raw, sources: [] }, { ...raw, text: 'Проверить <script> вручную.' }]) {
    assert.throws(() => validateOpenAiPreparedReply(prepared, policy, value),
      error => error instanceof HttpException && error.getStatus() === 502);
  }
  const changed = structuredClone(full);
  changed.findings[0] = { ...changed.findings[0], rawEvidence: 'batch26-private-marker' };
  assert.equal(safeHistoryFinding(changed.findings[0]), false);
  assert.throws(() => prepareOpenAiChat(context(changed), policy));
  assert.equal(chatSourceSchema.safeParse({ ...reportBinding(full), finding: changed.findings[0] }).success, false);
});

test('batch26 policy fingerprint binds full source budgets and schemas and invalidates the previous citation contract', () => {
  const policy = makeOpenAiPolicy(), prompts = checkedOpenAiPolicy(policy);
  const { provider: ignoredProvider, version: ignoredVersion, ...settings } = policy;
  assert.equal(ignoredProvider, 'OpenAI');
  assert.equal(ignoredVersion.length, 64);
  const base = { contract: 'openai-offline-core-v2', accounting: 'configured-rates-ceil-micros-v1', provider: 'OpenAI',
    endpoint: OPENAI_ENDPOINT, ...settings };
  const digestText = (text: string) => createHash('sha256').update(text).digest('hex');
  const tail = { prompts: { summary: digestText(prompts.summary), chat: digestText(prompts.chat) },
    responseFormats: { summary: openAiResponseFormat('summary'), chat: openAiResponseFormat('chat') } };
  assert.equal(policy.version, hashValue({ ...base, chatSources: CHAT_SOURCE_BUDGET, ...tail }));
  assert.notEqual(policy.version, hashValue({ ...base, ...tail }), 'old prepared/consent fingerprint cannot authorize new source contract');
  assert.notEqual(policy.version, hashValue({ ...base, chatSources: { ...CHAT_SOURCE_BUDGET, sourcesBytes: HISTORY.sourcesBytes + 1 }, ...tail }));
  assert.notEqual(policy.version, hashValue({ ...base, chatSources: { ...CHAT_SOURCE_BUDGET, citationBytes: HISTORY.citationBytes + 1 }, ...tail }));
});

test('batch26 prepared binding snapshots full selected facts and never rebinds later caller mutations', () => {
  const full = report([finding(1, true)]), policy = makeOpenAiPolicy({ requestBytes: 262144 });
  const input = context(full), before = structuredClone(input);
  const prepared = prepareOpenAiChat(input, policy);
  assert.deepEqual(input, before, 'preparation is passive on caller-owned facts');
  full.findings[0].severity = 'LOW';
  full.reportVersion = 'd'.repeat(64);
  const result = validateOpenAiPreparedReply(prepared, policy, { ...reportBinding(before.report), text: prose,
    citations: [before.report.findings[0].findingId] });
  assert.equal(result.operation, 'chat');
  if (result.operation !== 'chat') assert.fail('chat operation required');
  assert.deepEqual(result.value.sources[0], { ...reportBinding(before.report), finding: before.report.findings[0] });
  assert.throws(() => validateOpenAiPreparedReply(prepared, policy, { ...reportBinding(full), text: prose,
    citations: [full.findings[0].findingId] }), 'later caller report binding must not replace prepared snapshot');
});

test('batch26 mandatory finding selection fails closed rather than omitting required evidence', () => {
  const full = report(Array.from({ length: 4 }, (_, index) => finding(index, true)));
  let prepared = 0;
  assert.throws(() => selectPreparedHistory(full, empty(), 'Что проверить?', 3, 65536,
    () => { prepared++; return { reserve: { input: 1 } }; }),
  error => error instanceof HttpException && error.getStatus() === 409);
  assert.equal(prepared, 0);
  assert.equal(full.findings.length, 4);
});

test('batch26 exact serialized per-source and aggregate budget boundaries count UTF8 and JSON escaping, not JS length', () => {
  assert.deepEqual(BROWSER_CHAT_SOURCE_BUDGET, CHAT_SOURCE_BUDGET, 'server/browser contract constants remain identical');
  assert.equal(HISTORY.citationBytes, CHAT_SOURCE_BUDGET.citationBytes);
  assert.equal(HISTORY.sourcesBytes, 32 * 2048, 'preserve original total source allowance and held reservation');
  // Byte-only padding fixtures exercise the shared budget arithmetic, not the
  // finding schema. End-to-end legitimate full finding tests remain separate.
  const atBytes = (size: number) => ({ padding: 'x'.repeat(size - bytes({ padding: '' })) });
  const at = atBytes(HISTORY.citationBytes), over = atBytes(HISTORY.citationBytes + 1);
  assert.equal(chatSourcesWithinBudget([at]), true);
  assert.equal(chatSourcesWithinBudget([over]), false);
  const multi = { padding: 'я'.repeat(Math.floor((HISTORY.citationBytes - bytes({ padding: '' })) / 2)) };
  assert.equal(chatSourcesWithinBudget([multi]), true);
  assert.equal(chatSourcesWithinBudget([{ ...multi, padding: multi.padding + 'яя' }]), false);
  const escaped = { padding: '\\'.repeat(Math.floor((HISTORY.citationBytes - bytes({ padding: '' })) / 2)) };
  assert.equal(chatSourcesWithinBudget([escaped]), true);
  assert.equal(chatSourcesWithinBudget([{ ...escaped, padding: escaped.padding + '\\\\' }]), false);
  const whole = Math.floor(HISTORY.sourcesBytes / HISTORY.citationBytes);
  const remainder = HISTORY.sourcesBytes - whole * HISTORY.citationBytes;
  const sources = [...Array.from({ length: whole }, () => at), atBytes(remainder)];
  assert.equal(sources.reduce((total, source) => total + bytes(source), 0), HISTORY.sourcesBytes);
  assert.equal(chatSourcesWithinBudget(sources), true);
  assert.equal(chatSourcesWithinBudget([...sources.slice(0, -1), atBytes(remainder + 1)]), false);
  assert.equal(chatSourcesWithinBudget(Array.from({ length: 33 }, () => ({}))), false);
  const replyWrapper = bytes({ ...reportBinding(openAiReport), kind: 'hypothesis', text: '', sources: [] });
  const reservationField = bytes({ reservation: randomUUID() }) - 2 + 1;
  const growth = 2 * HISTORY.replyBytes + HISTORY.sourcesBytes + (HISTORY.citations - 1) + replyWrapper +
    Buffer.byteLength(',"reply":') + ('completed'.length - 'pending'.length) + 16 + reservationField;
  assert.equal(growth <= HISTORY.completionReserve, true, 'aggregate cap preserves existing physical completion reserve proof');
});

test('batch26 source and aggregate overflow return distinct finite private diagnostics', () => {
  const source = { ...reportBinding(openAiReport), finding: { ...openAiReport.findings[0], evidenceRef: '' } };
  const pad = HISTORY.citationBytes - bytes(source);
  const oversized = { ...openAiReport, findings: [{ ...source.finding, evidenceRef: 'x'.repeat(pad + 1) }] };
  let reason: string | undefined;
  try { validateChatReply({ ...reportBinding(oversized), text: prose, citations: [source.finding.findingId] }, oversized); }
  catch (error) {
    assert.equal(error instanceof HttpException, true);
    reason = diagnosticHeaders(error)['X-LLM-Content-Predicate'];
    assert.equal(JSON.stringify(diagnosticHeaders(error)).includes('result-'), false);
  }
  assert.equal(reason, 'chat_source_bytes');
  const full = report(Array.from({ length: 32 }, (_, index) => finding(index, true)));
  assert.equal(full.findings.every(safeHistoryFinding), true);
  assert.equal(full.findings.every(finding => bytes({ ...reportBinding(full), finding }) <= HISTORY.citationBytes), true);
  assert.throws(() => validateChatReply({ ...reportBinding(full), text: prose, citations: full.findings.map(f => f.findingId) }, full),
    error => error instanceof HttpException && diagnosticHeaders(error)['X-LLM-Content-Predicate'] === 'chat_sources_bytes');
  const tooLarge = { ...reportBinding(full), kind: 'hypothesis' as const, text: prose,
    sources: full.findings.map(finding => ({ ...reportBinding(full), finding })) };
  assert.equal(chatReplySchema.safeParse(tooLarge).success, false);
  assert.throws(() => encodeDelivery(delivery(full, tooLarge)));
  temporary((store, path) => {
    const pending = begin(store, full);
    assert.throws(() => store.finish(owner, full.scanId, pending.head.epoch, pending.head.revision, pending.id, tooLarge));
    const reopened = new HistoryStore(path);
    try { assert.deepEqual(reopened.snapshot(owner, full.scanId), pending.head, 'rejected aggregate does not change pending authority'); }
    finally { reopened.close(); }
  });
});

test('batch26 legacy32 large mandatory sources cannot prepare a request whose possible completion cannot persist', t => {
  const full = report(Array.from({ length: 32 }, (_, index) => finding(index, true)));
  assert.equal(full.findings.every(safeHistoryFinding), true);
  const worst = { ...reportBinding(full), kind: 'hypothesis', text: 'я'.repeat(HISTORY.replyBytes / 2),
    sources: full.findings.map(finding => ({ ...reportBinding(full), finding })) };
  assert.equal(bytes(worst) > HISTORY.completionReserve, true, 'independent serialized aggregate must exceed held completion space');
  const policy = policyFromEnvironment({ ...fixtureEnv, LLM_FREE_ONLY: 'true', LLM_MODEL: 'apodex/apodex-1.1-mini:free',
    LLM_PROVIDER_ALLOWLIST: 'novita/bf16', LLM_REQUEST_BUDGET_USD: '0', LLM_INPUT_PRICE_PER_MILLION_USD: '0',
    LLM_OUTPUT_PRICE_PER_MILLION_USD: '0', LLM_REQUEST_PRICE_USD: '0' })!;
  assert.ok(policy);
  let dispatched = 0;
  assert.throws(() => {
    selectPreparedHistory(full, empty(), 'Что проверить?', policy.findings, 262144, value => prepareHistory(value, policy));
    dispatched++;
  }, 'mandatory evidence may not be dropped and unpersistable context must fail before dispatch');
  assert.equal(dispatched, 0);
  assert.equal(full.findings.length, 32);
  t.diagnostic(JSON.stringify({ mandatory: 32, possibleReplyBytes: bytes(worst), heldCompletionBytes: HISTORY.completionReserve, dispatched }));
});

test('batch26 actual service manual decisions retain full sources; failed durable allocation blocks dispatch/quota without HTTP', { timeout: 20000 }, async t => {
  const directory = mkdtempSync(join(tmpdir(), 'chat-service-batch26-'));
  const path = join(directory, 'llm-history.sqlite'), origin = 'http://127.0.0.1:8081';
  const environment = { AUTH_DB_PATH: join(directory, 'auth.sqlite'), AUTH_ORIGIN: origin,
    AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true', SCAN_BROWSER_ALLOWED_USER_IDS: '',
    LLM_HISTORY_ENABLED: 'true', LLM_HISTORY_REVISION: HISTORY.version, LLM_HISTORY_AUTHORITY: HISTORY_AUTHORITY };
  const previous = Object.fromEntries(Object.keys(environment).map(key => [key, process.env[key]]));
  Object.assign(process.env, environment);
  new HistoryStore(path, true).close();
  const auth = new AuthStore(), runtime = new HistoryRuntime(path), db = new Database(path);
  const quota = new FixtureQuotaLedger(join(directory, 'llm-usage.sqlite'), quotaPolicy);
  let service: HistoryService | undefined;
  let adapters = 0, sends = 0, reservations = 0, held = 0;
  try {
    const policy = policyFromEnvironment({ ...fixtureEnv, LLM_FREE_ONLY: 'true', LLM_MODEL: 'apodex/apodex-1.1-mini:free',
      LLM_PROVIDER_ALLOWLIST: 'novita/bf16', LLM_REQUEST_BUDGET_USD: '0', LLM_INPUT_PRICE_PER_MILLION_USD: '0',
      LLM_OUTPUT_PRICE_PER_MILLION_USD: '0', LLM_REQUEST_PRICE_USD: '0' })!;
    assert.ok(policy);
    const full = report([finding(1, true), finding(2, true), finding(3, true)]);
    const transport = Object.assign(async () => assert.fail('unguarded transport forbidden'), {
      sendGuarded: async () => { sends++; return assert.fail('failed storage admission must not dispatch'); },
    }) as unknown as GuardedTransport;
    const snapshot = openRouterRuntime(policy, () => {
      adapters++;
      return new OpenRouterProvider('synthetic_batch26_not_a_real_key', transport);
    });
    const providers = { resolve: () => snapshot, policy: () => null, provider: () => assert.fail('legacy lookup forbidden') };
    let currentReport = full;
    const reports = { read: () => currentReport } as unknown as ReportReader;
    service = new HistoryService(auth, reports, providers, { ledger: () => quota } as unknown as LlmQuotaRuntime,
      () => { held++; return () => { held--; }; }, origin, runtime);
    const user = await auth.register('chat-boundary-batch26@example.invalid', 'synthetic-batch26-password-1234');
    assert.ok(user);
    const cookie = `demo_session=${auth.createSession(user.id)}`;
    const requestFor = (body: unknown) => {
      const request = Object.assign(new EventEmitter(), { method: 'POST', url: `/api/v1/browser/scans/${full.scanId}/llm/chat`,
        headers: { cookie, origin, 'content-type': 'application/json', 'content-length': String(bytes(body)) },
        socket: { remoteAddress: '127.0.0.1' }, body: undefined as unknown });
      let ingress!: (request: unknown, response: unknown, next: () => void) => void;
      registerHistoryIngress({ use: (fn: typeof ingress) => { ingress = fn; } } as unknown as Parameters<typeof registerHistoryIngress>[0]);
      let parsed = false;
      ingress(request, { writeHead: () => assert.fail('synthetic ingress rejected'), once() {}, end() {} }, () => { parsed = true; });
      request.emit('data', Buffer.from(JSON.stringify(body))); request.emit('end'); assert.equal(parsed, true);
      return request;
    };
    const store = runtime.readStore(), initial = store.snapshot(user.id, full.scanId);
    const body = { epoch: initial.epoch, revision: initial.revision, mutationId: randomUUID(), reportVersion: full.reportVersion,
      text: 'Проверить исходные данные вручную.', findingIds: full.findings.map(finding => finding.findingId) };
    const decision = service.decision(requestFor(body), full.scanId, body);
    decision.write(() => {});
    const retained = store.snapshot(user.id, full.scanId);
    assert.deepEqual(retained.decisions[0].sources.map(source => source.finding), full.findings);
    assert.equal(chatHistorySchema.safeParse(decision.value).success, true);
    const before = db.prepare('SELECT * FROM history_head ORDER BY scope').all();
    currentReport = report(Array.from({ length: 32 }, (_, index) => finding(index, true)));
    const oversizedDecision = { ...body, epoch: retained.epoch, revision: retained.revision, mutationId: randomUUID(),
      findingIds: currentReport.findings.map(finding => finding.findingId) };
    assert.throws(() => service!.decision(requestFor(oversizedDecision), full.scanId, oversizedDecision),
      error => error instanceof HttpException && error.getStatus() === 400);
    assert.deepEqual(db.prepare('SELECT * FROM history_head ORDER BY scope').all(), before,
      'aggregate manual decision refusal preserves accepted full facts and revision');
    currentReport = full;
    const reserve = quota.reserve.bind(quota);
    t.mock.method(quota, 'reserve', (...args: Parameters<typeof reserve>) => { reservations++; return reserve(...args); });
    db.exec("CREATE TRIGGER batch26_refuse_padding BEFORE INSERT ON history_completion_space BEGIN SELECT RAISE(ABORT,'synthetic allocation refusal'); END");
    const generate = { epoch: retained.epoch, revision: retained.revision, mutationId: randomUUID(), reportVersion: full.reportVersion,
      question: 'Что проверить?', consent: { accepted: true, policyVersion: snapshot.chatVersion } };
    await assert.rejects(service.generate(requestFor(generate), full.scanId, generate, new AbortController().signal),
      error => error instanceof HttpException && error.getStatus() === 503);
    assert.deepEqual({ sends, reservations, held }, { sends: 0, reservations: 0, held: 0 });
    assert.equal(adapters <= 1, true, 'at most one synthetic adapter may be admitted, never dispatched');
    assert.deepEqual(db.prepare('SELECT * FROM history_head ORDER BY scope').all(), before, 'allocation rollback preserves exact accepted decision/history');
    assert.deepEqual(db.prepare('SELECT * FROM history_completion_space').all(), []);
    const reopened = new HistoryStore(path);
    try { assert.deepEqual(reopened.snapshot(user.id, full.scanId), retained); }
    finally { reopened.close(); }
  } finally {
    service?.close(); runtime.close(); auth.onModuleDestroy(); quota.close(); db.close();
    for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    rmSync(directory, { recursive: true, force: true });
  }
});
