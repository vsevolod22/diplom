import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { Gate, routePlan, installRoutes as installGuard, bounded, journey, browserIo, modeOf, spend, reviewFingerprint, runOnce, REVIEW_SOURCE, SCAN, MODEL, ORIGIN, BASE,
  DIRECTORY, RUN_PHASES, FAILURE_CODES, recordFailure, closeRuntimeFence, validateSummary, corpusContracts } from './batch27-final-native.mjs';
import { contracts, fingerprint, QUESTION } from './native-h7v3-paid-sol.mjs';
import { diagnosticContracts } from './native-h7v3-finite-diagnostics.mjs';
import { extraContracts, parseAnswer, nativeFinding, replyProof } from './batch26-native-chat.mjs';
const c = { ...await diagnosticContracts(), ...await extraContracts() }, tools = await contracts();
// Explicit OFFLINE transport seam for the pre-existing A/C regression matrix.
// Production runOnce always supplies the fixed receipt/runtime authority handle.
const installRoutes = (...args) => installGuard(...args, async (_kind, send) => send());
const uuid = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const binding = { scanId: SCAN, digest: 'sha256:abe13b25e07ccaedcc8797120c37781f0462a0f0682105cf2d8b8d6f99070d55', platform: 'linux/amd64', reportVersion: 'b'.repeat(64) };
function current() {
  return c.chat.chatContextSchema.parse({ ...binding, epoch: uuid(1), revision: 4, enabled: true, policyVersion: 'c'.repeat(64),
    disclosure: { provider: 'OpenAI', model: MODEL, monetaryLimit: 'uncapped', requestBudgetMicros: null, userBudgetMicros: null, scanBudgetMicros: null,
      retention: 'no-training', operatorApprovedRouting: true, providerComplianceNotProvenByDeclaration: true, zeroDataRetentionVerified: false,
      costBasis: c.public.OPENAI_COST_BASIS, estimatedPrice: { unit: 'microUSD-per-million-tokens', input: 1000000, output: 2000000 },
      data: c.public.REMEDIATION_SCANNER_DISCLOSURE, sentData: 'Cleaned question, all user history/accepted decisions and selected findings with complete coverage.', localRetention: 'Durable owner+scan history until separately authorized operator lifecycle; capacity can refuse; context cache only, not output cache.' },
    limits: { questionBytes: 2048, bodyBytes: 8192 }, deliveryMode: 'completed-response', pending: false });
}
const before = () => ({ ...binding, epoch: uuid(1), revision: 4, pending: null, decisions: [], turns: [2, 3].map(n => ({
  id: uuid(n), mutationId: uuid(n + 10), state: 'failed', question: 'Сохранённый вопрос.', report: binding, createdAt: 1 })),
  retention: 'Confirmed history persists until separately authorized operator lifecycle; no automatic expiry or reset.' });
const request = () => ({ epoch: uuid(1), revision: 4, mutationId: uuid(20), reportVersion: binding.reportVersion,
  question: QUESTION, consent: { accepted: true, policyVersion: current().policyVersion } });
const receipt = { input: 20, output: 10, costMicros: 40, source: 'server-estimated-configured-rates-not-invoice' };
const finding = { check: 'vuln', findingId: 'vuln-' + 'd'.repeat(64), severity: 'HIGH', cveId: 'CVE-2026-1000',
  identifierKind: 'cve', ecosystem: 'deb', severitySources: ['debian'], provenanceRef: 'target-' + 'e'.repeat(64),
  fixedVersionReported: false, packageName: 'libc6', installedVersion: '1.0', fixedVersion: null, advisoryState: 'unknown' };
const text = 'Сканер сообщил о находке; требуется проверка.';
const frame = (seq, type, payload = {}) => ({ ...binding, v: 1, seq, type, deliveryMode: 'validated-completed-reply', nativeProviderStream: false,
  epoch: uuid(1), revision: 6, mutationId: uuid(20), turnId: uuid(30), ...payload });
const frames = () => [frame(0, 'usage', { usage: receipt }), frame(1, 'citation', { index: 0, source: { ...binding, finding } }),
  frame(2, 'delta', { index: 0, text }), frame(3, 'done', { outcome: 'completed', kind: 'hypothesis', textBytes: Buffer.byteLength(text), citationCount: 1, deltaCount: 1 })];
const summary = () => ({ ...binding, hypotheses: [{ kind: 'hypothesis', text, citations: [finding.findingId] }], scannerFacts: [finding] });
function response(raw, status = 200, headers = {}) {
  return { status: () => status, text: async () => raw, request: () => ({ postDataJSON: request }),
    headerValue: async key => headers[key] ?? (key === 'content-type' ? 'application/x-ndjson' : null) };
}
function readiness() { return { ...binding, localReady: true, status: 'locally-configured', blockers: [], provider: {
  name: 'OpenAI', model: MODEL, status: 'configured-unprobed', liveVerified: false }, credential: 'environment-valid',
  accounting: 'configured', history: 'available', quota: 'available', requiresConsent: true, acceptsCredentials: false, generationVerified: false }; }
const contexts = () => ({ s: current(), h: current(), r: readiness() });
const usage = n => { const value = { input: 20 * n, output: 10 * n, costMicros: 40 * n }, liabilities = { input: 7, output: 8, costMicros: 9 };
  return { ...binding, available: true, window: { start: 1 }, user: { used: value, held: liabilities, carried: liabilities }, scan: { used: value, held: liabilities, carried: liabilities } }; };
function fixture(path = 'fresh-summary') {
  const log = { requests: 0, postAttempts: 0, dispatched: 0, denied: 0, pageErrors: 0, summaryPosts: 0, chatPosts: 0 };
  const gate = new Gate(async () => {}), calls = [], events = [];
  let histories = 0, usages = 0;
  const answer = parseAnswer(frames().map(x => JSON.stringify(x)).join('\n') + '\n', c, current(), uuid(20)).reply;
  const after = () => ({ ...before(), revision: 6, turns: [...before().turns, { id: uuid(30), state: 'completed', reply: answer }] });
  const io = {
    publish: async v => { events.push(v); }, preflight: async () => ({ ...contexts(), history: before() }), corpus: async () => new Map([[finding.findingId, finding]]),
    usage: async () => usage(usages++ === 2 ? (path === 'fresh-summary' ? 2 : 1) : usages === 2 && path === 'fresh-summary' ? 1 : 0),
    paidSummary: async () => { calls.push('summary-consent'); }, paidChat: async () => { calls.push('chat-consent'); },
    async generate(kind) {
      calls.push(kind); log.postAttempts++;
      const body = kind === 'summary' ? { reportVersion: binding.reportVersion, consent: { accepted: true, policyVersion: current().policyVersion } } : request();
      assert.equal(await gate.consume(kind, body), true); log[kind + 'Posts']++; log.dispatched++;
      return kind === 'summary' ? response(JSON.stringify(summary())) : response(frames().map(x => JSON.stringify(x)).join('\n') + '\n');
    },
    disableAutomation: async () => { calls.push('disable'); }, summaryRead: async () => ({ status: 200, value: summary() }),
    summaryVisible: async () => {}, chatVisible: async () => {}, current: async () => contexts(),
    history: async () => histories++ === 0 ? before() : after(), reload: async () => { calls.push('reload'); },
  };
  return { io, gate, log, calls, events };
}
// Ordinary public API DTOs: NO identifierKind/check/fixedVersionReported/advisoryState.
// Only the validated runner projection adds these LLM-facing fields.
function ordinaryCorpusFixture() {
  const rows = Array.from({ length: 440 }, (_, i) => ({ findingId: 'vuln-' + (i + 1).toString(16).padStart(64, '0'),
    cveId: i < 431 ? `CVE-2026-${1000 + i}` : i < 437 ? `TEMP-${1000000 + i}-ABCDEF` : `DLA-${1000 + i}-1`,
    ecosystem: 'deb', packageName: 'libc6', installedVersion: '1.0', severity: 'HIGH', fixedVersion: null,
    severitySources: ['debian'], provenanceRef: 'target-' + (i + 1000).toString(16).padStart(64, '0') }));
  const dbDigest = 'sha256:' + 'f'.repeat(64), checkedAt = '2026-11-04T12:00:00.000Z';
  const metadata = { outcome: 'checked', coverage: 'image', profile: 'public-hub-amd64-v1',
    image: 'registry-1.docker.io/library/nginx@' + binding.digest, platform: 'linux/amd64', findingCount: 440,
    scannerVersion: '0.69.3', checkedAt, identifierCounts: { cve: 431, debianTemp: 6, debianDla: 3 },
    db: { envelopeVersion: 1, signer: 'local-db-operator-v1', source: 'ghcr.io/aquasecurity/trivy-db@' + dbDigest, schemaVersion: 2,
      manifestDigest: dbDigest, artifactSha256: 'a'.repeat(64), metadataSha256: 'b'.repeat(64), dbSha256: 'c'.repeat(64),
      updatedAt: '2026-11-04T10:00:00.000Z', downloadedAt: '2026-11-04T11:00:00.000Z', nextUpdate: '2026-11-05T10:00:00.000Z' },
    resultContractVersion: 2, workerCheckedAt: Date.parse(checkedAt),
    dbPolicy: { version: 2, policy: 'cve-db-updated-at-14d-v2', evaluatedAt: Date.parse(checkedAt), status: 'usable', warnings: [] },
    usableUntil: '2026-11-18T10:00:00.000000000Z' };
  const pages = Array.from({ length: 9 }, (_, n) => ({ ...structuredClone(metadata), findings: rows.slice(n * 50, (n + 1) * 50), nextCursor: n === 8 ? null : (n + 1) * 50 }));
  const snapshot = { ...binding, state: 'completed', perCheck: { secret: { findingCount: 0 }, vuln: { findingCount: 440 } } };
  const gets = [], log = { requests: 0, postAttempts: 0, dispatched: 0, denied: 0, pageErrors: 0, summaryPosts: 0, chatPosts: 0 };
  const page = { evaluate: async (_, url) => {
    gets.push(url);
    if (url === BASE) return { status: 200, value: structuredClone(snapshot) };
    const match = url.match(/\/vuln\?cursor=(\d+)&limit=50$/);
    assert.ok(match, 'offline adapter allows exact corpus GET only');
    return { status: 200, value: structuredClone(pages[Number(match[1]) / 50]) };
  } };
  return { rows, pages, snapshot, gets, log, io: () => browserIo(page, tools, c, log, async () => {}) };
}
test('actual frontend parser accepts ordinary absent-kind DTOs; production browser corpus derives exact431/6/3 from9 pages', async () => {
  const f = ordinaryCorpusFixture(), raw = fingerprint(f.pages), parsers = await corpusContracts();
  assert.equal(f.rows.every(row => !Object.hasOwn(row, 'identifierKind')), true);
  for (const page of f.pages) assert.equal(parsers.parseCurrentVuln(page).outcome, 'checked');
  const corpus = await (await f.io()).corpus();
  assert.equal(corpus.size, 440); assert.equal(f.gets.length, 10);
  assert.deepEqual(f.log.corpus, { vulnerabilities: 440, identifiers: { cve: 431, 'debian-temp': 6, 'debian-dla': 3 }, pages: 9 });
  for (const [i, row] of f.rows.entries()) {
    const normalized = corpus.get(row.findingId), expected = i < 431 ? 'cve' : i < 437 ? 'debian-temp' : 'debian-dla';
    assert.equal(normalized.identifierKind, expected); assert.equal(normalized.cveId, row.cveId);
    assert.equal(nativeFinding(normalized).identifierKind, expected);
  }
  assert.equal(fingerprint(f.pages), raw, 'normalization never rewrites raw DTO rows');
  assert.equal(f.log.postAttempts, 0); assert.equal(f.log.dispatched, 0);
});
test('summary and unchanged batch26 nativeFinding/replyProof agree with normalized absent-kind CVE/TEMP/DLA DTOs', async () => {
  const f = ordinaryCorpusFixture(), corpus = await (await f.io()).corpus();
  const facts = [0, 431, 437].map(i => nativeFinding(corpus.get(f.rows[i].findingId)));
  const value = { ...binding, hypotheses: [{ kind: 'hypothesis', text, citations: facts.map(row => row.findingId) }], scannerFacts: facts };
  assert.deepEqual(validateSummary(value, current(), corpus, tools), value);
  const answer = { reply: { text, sources: facts.map(row => ({ ...binding, finding: row })) } };
  assert.equal(replyProof(answer, corpus, c, tools).exactNativeCitationMatch, true);
  for (const key of ['severitySources', 'provenanceRef', 'cveId', 'installedVersion']) {
    const changed = structuredClone(value);
    changed.scannerFacts[0][key] = { severitySources: ['nvd'], provenanceRef: 'target-' + '9'.repeat(64), cveId: 'CVE-2026-9999', installedVersion: '2.0' }[key];
    assert.throws(() => validateSummary(changed, current(), corpus, tools), /SUMMARY_FACT_CHANGED/);
  }
  const changed = structuredClone(answer); changed.reply.sources[1].finding.provenanceRef = 'target-' + '9'.repeat(64);
  assert.throws(() => replyProof(changed, corpus, c, tools), /NATIVE_CITATION_MISMATCH/);
});
test('production browser corpus allows readonly journey to reach a non-dispatching generate sentinel', async () => {
  const corpus = ordinaryCorpusFixture(), f = fixture(), io = await corpus.io();
  f.io.corpus = io.corpus; let generates = 0;
  f.io.generate = async () => { generates++; throw Error('OFFLINE_GENERATE_SENTINEL'); };
  await assert.rejects(journey(f.io, f.gate, 'fresh-summary', tools, c, f.log), /OFFLINE_GENERATE_SENTINEL/);
  assert.equal(generates, 1); assert.equal(f.log.dispatched, 0); assert.equal(f.log.postAttempts, 0);
  assert.deepEqual(f.gate.counts, { summary: 0, chat: 0 });
  assert.deepEqual(f.log.firstFailure, { phase: 'summary-response', code: 'UNCLASSIFIED_FAILURE' });
});
for (const [name, mutate] of [
  ['unknown profile', f => { f.pages[0].profile = 'other'; }],
  ['missing public profile', f => { delete f.pages[0].profile; }],
  ['wrong target image', f => { f.pages[0].image = 'registry-1.docker.io/library/nginx@sha256:' + '9'.repeat(64); }],
  ['wrong platform', f => { f.pages[0].platform = 'linux/arm64'; }],
  ['unsupported ecosystem', f => { f.pages[8].findings[31].ecosystem = 'unknown'; }],
  ['TEMP in npm ecosystem', f => { f.pages[8].findings[31].ecosystem = 'npm'; }],
  ['DLA in npm ecosystem', f => { f.pages[8].findings[37].ecosystem = 'npm'; }],
  ['unknown ID must not default to CVE', f => { f.pages[0].findings[0].cveId = 'UNRECOGNIZED-123'; }],
  ['wire identifierKind injection', f => { f.pages[0].findings[0].identifierKind = 'debian-temp'; }],
  ['unknown severity source', f => { f.pages[0].findings[0].severitySources = ['untrusted']; }],
  ['malformed finding provenance', f => { f.pages[0].findings[0].provenanceRef = 'other'; }],
  ['DB source disagrees with manifest', f => { f.pages[0].db.source = 'ghcr.io/aquasecurity/trivy-db@sha256:' + '9'.repeat(64); }],
  ['page provenance epoch drift', f => { f.pages[1].scannerVersion = 'other'; }],
  ['identifier totals drift', f => { f.pages[1].identifierCounts = { cve: 430, debianTemp: 7, debianDla: 3 }; }],
  ['row duplicate', f => { f.pages[1].findings[0] = structuredClone(f.pages[0].findings[0]); }],
  ['cursor skips page', f => { f.pages[0].nextCursor = 100; }],
  ['page total mismatch', f => { f.pages[0].findingCount = 439; }],
]) test(`ordinary DTO corpus rejects ${name} before paid arming or dispatch`, async () => {
  const corpus = ordinaryCorpusFixture(); mutate(corpus);
  const f = fixture(), io = await corpus.io(); f.io.corpus = io.corpus;
  f.io.generate = async () => assert.fail('invalid corpus cannot generate');
  await assert.rejects(journey(f.io, f.gate, 'fresh-summary', tools, c, f.log));
  assert.equal(f.log.dispatched, 0); assert.equal(f.log.postAttempts, 0); assert.deepEqual(f.gate.counts, { summary: 0, chat: 0 });
  assert.equal(f.calls.length, 0); assert.equal(f.log.firstFailure.phase, 'corpus'); assert.ok(FAILURE_CODES.includes(f.log.firstFailure.code));
});
test('fixed future batch31 directory never selects or resets the retained batch27 slot', async () => {
  assert.equal(DIRECTORY, new URL('../test-results/batch31-final-native-20261104', import.meta.url).pathname);
  const source = await readFile(new URL('./batch27-final-native.mjs', import.meta.url), 'utf8');
  assert.equal(source.includes("join(ROOT, 'test-results/batch27-final-native')"), false);
  assert.equal([...source.matchAll(/writeAggregate\(join\(DIRECTORY, 'aggregate\.json'\), log\)/g)].length, 1, 'one append-only final aggregate publication');
  const run = source.slice(source.indexOf('export async function runOnce'));
  assert.ok(run.indexOf("'journey-aggregate.json'") < run.indexOf('await closeRuntimeFence(authority, log)'), 'journey proof stays durable before fence release');
});
test('finite first-failure enums preserve earliest cause, never raw errors/payload/uppercase arbitrary strings', () => {
  const log = { phase: 'corpus' }; recordFailure(log, Error('CORPUS_PAGE_INVALID'));
  log.phase = 'cleanup'; recordFailure(log, Error('GATE_STOPPED'));
  assert.deepEqual(log.firstFailure, { phase: 'corpus', code: 'CORPUS_PAGE_INVALID' });
  const marker = 'PRIVATE_CANARY_RAW_PAYLOAD', untrusted = { phase: marker };
  const error = Error(marker); error.name = marker; error.payload = marker;
  recordFailure(untrusted, error); assert.deepEqual(untrusted.firstFailure, { phase: 'unknown', code: 'UNCLASSIFIED_FAILURE' });
  assert.equal(JSON.stringify(untrusted.firstFailure).includes(marker), false);
  assert.equal(new Set(RUN_PHASES).size, RUN_PHASES.length); assert.equal(new Set(FAILURE_CODES).size, FAILURE_CODES.length);
});
test('runtime fence disposition records privacy-safe failure without replacing original corpus failure or retrying close', async () => {
  const log = { status: 'BLOCKED_OR_PARTIAL', phase: 'corpus' }; recordFailure(log, Error('CORPUS_MISMATCH'));
  let closes = 0;
  await closeRuntimeFence({ close: async success => { closes++; assert.equal(success, false); throw Error('PRIVATE_CANARY'); } }, log);
  assert.equal(closes, 1); assert.equal(log.runtimeFenceReleased, false); assert.equal(log.status, 'BLOCKED_OR_PARTIAL');
  assert.deepEqual(log.firstFailure, { phase: 'corpus', code: 'CORPUS_MISMATCH' }); assert.equal(JSON.stringify(log).includes('PRIVATE_CANARY'), false);
});
for (const success of [false, true]) test(`owned fence disposition closes exactly once with success=${success}`, async () => {
  const log = { status: success ? 'NATIVE_WIRE_HISTORY_RELOAD_VERIFIED_SEMANTICS_PENDING' : 'BLOCKED_OR_PARTIAL' }; let closes = 0;
  await closeRuntimeFence({ close: async value => { closes++; assert.equal(value, success); return { released: true }; } }, log);
  assert.equal(closes, 1); assert.equal(log.runtimeFenceReleased, true); assert.equal(log.firstFailure, undefined);
});
test('future stopped-route denial records only finite first failure and never turns an earlier refusal into PASS', async () => {
  const f = fixture(); f.log.phase = 'cleanup'; f.gate.stop(); let handler;
  await installRoutes({ route: async (_, fn) => { handler = fn; }, routeWebSocket: async () => {} }, f.gate, f.log, async () => {});
  const r = mockRoute(ORIGIN + BASE + '/llm/history', 'GET'); await handler(r);
  assert.deepEqual(f.log.firstFailure, { phase: 'cleanup', code: 'GATE_STOPPED' }); assert.deepEqual(r.trace, ['abort']);
  assert.equal(f.log.dispatched, 0); assert.equal(f.log.denied, 1);
});

test('explicit fresh summary then chat success and GET-only exact history reload with retained liabilities', async () => {
  const f = fixture(); await journey(f.io, f.gate, 'fresh-summary', tools, c, f.log);
  assert.deepEqual(f.calls, ['summary-consent', 'summary', 'disable', 'chat-consent', 'chat', 'reload']);
  assert.equal(f.log.reload.repeatedPosts, 0); assert.equal(f.log.reply.exactNativeCitationMatch, true);
  assert.equal(f.log.chatAccounting.valid, true); assert.equal(f.log.summaryAccounting.receipt, 'NOT_EXPOSED_BY_SUMMARY_DTO');
  assert.match(f.log.summaryStorage, /REPLACEMENT/); assert.match(f.log.status, /SEMANTICS_PENDING/);
});
test('explicit existing-current success sends zero summary and one chat', async () => {
  const f = fixture('existing-current-summary'); await journey(f.io, f.gate, 'existing-current-summary', tools, c, f.log);
  assert.equal(f.log.summaryPosts, 0); assert.equal(f.log.chatPosts, 1); assert.equal(f.calls.includes('summary-consent'), false);
});
for (const kind of ['http404', 'http503', 'invalid-json', 'wrong-binding', 'wrong-facts', 'throw-timeout']) test(`summary ${kind} stops before chat/reload/no second POST`, async () => {
  const f = fixture(); f.io.generate = async operation => {
    f.calls.push(operation); if (kind === 'throw-timeout') throw Error('timeout');
    const s = summary(); if (kind === 'wrong-binding') s.reportVersion = 'f'.repeat(64);
    if (kind === 'wrong-facts') s.scannerFacts[0] = { ...finding, installedVersion: 'wrong' };
    return response(kind === 'invalid-json' ? 'bad' : JSON.stringify(s), kind === 'http404' ? 404 : kind === 'http503' ? 503 : 200);
  };
  await assert.rejects(journey(f.io, f.gate, 'fresh-summary', tools, c, f.log));
  assert.deepEqual(f.calls, ['summary-consent', 'summary']);
});
test('existing current404 never falls back to fresh generation', async () => {
  const f = fixture(); f.io.summaryRead = async () => ({ status: 404, value: { errorCode: 'LLM_SUMMARY_MISSING' } });
  await assert.rejects(journey(f.io, f.gate, 'existing-current-summary', tools, c, f.log), /NO_FALLBACK/); assert.deepEqual(f.calls, []);
});
test('strict CLI inert default and exact new GO/source binding, no old acknowledgements', () => {
  assert.equal(modeOf([]).mode, 'inert'); assert.equal(modeOf(['--fingerprint']).mode, 'fingerprint');
  const flags = ['--run-once', '--ack-new-coordinator-postdeploy-go', '--ack-paid-openai-uncapped', '--ack-separate-b0-b1-preservation', '--path', 'fresh-summary', '--deployment-id', 'a'.repeat(32), '--review-sha256', 'b'.repeat(64)];
  assert.equal(modeOf(flags).path, 'fresh-summary');
  for (let i = 0; i < flags.length; i++) { const bad = [...flags]; bad[i] = 'wrong'; assert.throws(() => modeOf(bad)); }
  assert.throws(() => modeOf([...flags, '--retry']));
});
test('review fingerprint includes the concrete custody, catalog and deployment authority implementation, not only the CLI label', () => {
  for (const path of ['scripts/native-runtime-authority.mjs', 'scripts/test_native_runtime_authority.mjs', 'scripts/deploy-reference-custody.mjs',
    'scripts/deploy-adapter.mjs', 'scripts/deploy-authority.mjs', 'scripts/deploy-adapter-stores.mjs', 'scripts/deploy-core.mjs',
    'scripts/deploy-supervisor.mjs', 'scripts/public-llm-deployment-catalog.mjs',
    ...['scanTransport.ts', 'publicVulnerabilityIdentifiers.ts', 'publicImageProfile.ts', 'reportView.ts', 'vulnAdvisory.ts',
      'cveDbMetadata.ts', 'imageConfigReport.ts', 'imageFailure.ts', 'types.ts'].map(n => 'src/shared/api/scans/' + n)]) assert.equal(REVIEW_SOURCE.includes(path), true, path);
  assert.equal(new Set(REVIEW_SOURCE).size, REVIEW_SOURCE.length);
});
test('strict route classification rejects foreign/query/redirect/auth/events/translation/scan/reset mutations', () => {
  for (const kind of ['summary', 'chat']) assert.equal(routePlan(ORIGIN + BASE + '/llm/' + kind, 'POST'), kind);
  for (const url of [ORIGIN + BASE + '/llm/chat?x=1', ORIGIN + BASE + '/llm/chat#x', ORIGIN + '/api/v1/auth/login', ORIGIN + BASE + '/events',
    ORIGIN + BASE + '/llm/translation', 'http://127.0.0.1:8080' + BASE, 'https://other.test/', ORIGIN + BASE.replace(SCAN, uuid(90)) + '/llm/chat'])
    assert.equal(routePlan(url, 'POST'), 'deny');
  assert.equal(routePlan(ORIGIN + BASE + '/llm/history', 'GET'), 'read');
  assert.equal(routePlan(ORIGIN + BASE + '/events', 'GET'), 'deny');
  assert.equal(routePlan(ORIGIN + BASE + '/llm/chat', 'POST', true), 'deny');
  for (const method of ['PUT', 'PATCH', 'DELETE', 'HEAD']) assert.equal(routePlan(ORIGIN + BASE + '/llm/chat', method), 'deny');
});
function mockRoute(url, method, body, headers = {}, status = 200) {
  const trace = [], fetchOptions = [];
  const result = { status: () => status, url: () => url, dispose: async () => { trace.push('dispose'); } };
  return { trace, fetchOptions, result, request: () => ({ url: () => url, method: () => method, redirectedFrom: () => null,
    headerValue: async key => headers[key] ?? (key === 'content-type' ? 'application/json' : 'application/x-ndjson'), postDataJSON: () => body }),
    fetch: async options => { fetchOptions.push(options); trace.push('fetch'); return result; },
    fulfill: async value => { assert.deepEqual(value, { response: result }); trace.push('fulfill'); },
    continue: async () => { trace.push('continue'); }, abort: async () => { trace.push('abort'); } };
}
for (const kind of ['read', 'summary', 'chat']) {
  const url = ORIGIN + BASE + (kind === 'read' ? '/llm/history' : '/llm/' + kind);
  const method = kind === 'read' ? 'GET' : 'POST';
  const body = kind === 'summary' ? { reportVersion: binding.reportVersion, consent: { accepted: true, policyVersion: current().policyVersion } } : request();
  for (const status of [300, 301, 302, 303, 304, 305, 306, 307, 308, 399]) test(`installed ${kind} transport refuses ${status} without follow/fulfill/continue/retry`, async () => {
    const f = fixture(); let handler;
    await installRoutes({ route: async (_, fn) => { handler = fn; }, routeWebSocket: async () => {} }, f.gate, f.log, async () => {});
    if (kind !== 'read') f.gate.arm(kind, current(), kind === 'chat' ? before() : undefined);
    const r = mockRoute(url, method, body, {}, status); await handler(r);
    assert.deepEqual(r.fetchOptions, [{ maxRedirects: 0, maxRetries: 0, timeout: kind === 'read' ? 15000 : 150000 }]);
    assert.deepEqual(r.trace, ['fetch', 'abort', 'dispose']);
    assert.equal(f.gate.stopped, true); assert.equal(f.log.denied, 1);
    assert.equal(f.log.dispatched, kind === 'read' ? 0 : 1);
    await handler(r); assert.deepEqual(r.trace, ['fetch', 'abort', 'dispose', 'abort']);
    assert.equal(r.fetchOptions.length, 1);
  });
  test(`installed ${kind} preserves original request and fulfills checked response once`, async () => {
    const f = fixture(); let handler;
    await installRoutes({ route: async (_, fn) => { handler = fn; }, routeWebSocket: async () => {} }, f.gate, f.log, async () => {});
    if (kind !== 'read') f.gate.arm(kind, current(), kind === 'chat' ? before() : undefined);
    const r = mockRoute(url, method, body); await handler(r);
    assert.deepEqual(r.fetchOptions, [{ maxRedirects: 0, maxRetries: 0, timeout: kind === 'read' ? 15000 : 150000 }]);
    assert.deepEqual(r.trace, ['fetch', 'fulfill', 'dispose']); assert.equal(f.log.denied, 0);
  });
}
for (const failure of ['timeout', 'connection-reset', 'foreign-response', 'invalid-status', 'stop-in-flight', 'fulfill-failed']) test(`installed transport ${failure} fails closed without retry or browser continuation`, async () => {
  const f = fixture(); let handler;
  await installRoutes({ route: async (_, fn) => { handler = fn; }, routeWebSocket: async () => {} }, f.gate, f.log, async () => {});
  f.gate.arm('chat', current(), before());
  const r = mockRoute(ORIGIN + BASE + '/llm/chat', 'POST', request());
  const fetch = r.fetch;
  r.fetch = async options => {
    const result = await fetch(options);
    if (failure === 'timeout' || failure === 'connection-reset') throw Error(failure);
    if (failure === 'foreign-response') result.url = () => 'https://other.test/';
    if (failure === 'invalid-status') result.status = () => NaN;
    if (failure === 'stop-in-flight') f.gate.stop();
    return result;
  };
  if (failure === 'fulfill-failed') r.fulfill = async () => { r.trace.push('fulfill-failed'); throw Error('closed'); };
  await handler(r); assert.equal(f.gate.stopped, true); assert.equal(f.log.denied, 1);
  assert.equal(f.log.dispatched, 1); assert.equal(f.gate.counts.chat, 1);
  assert.equal(r.trace.includes('continue'), false); assert.equal(r.trace.includes('fulfill'), false);
  assert.equal(r.trace.filter(x => x === 'abort').length, 1); assert.equal(r.fetchOptions.length, 1);
  assert.equal(r.trace.includes('dispose'), !['timeout', 'connection-reset'].includes(failure));
  await handler(r); assert.equal(r.fetchOptions.length, 1);
});
for (const status of [400, 404, 429, 500, 503]) test(`installed read preserves nonredirect HTTP${status} for caller validation`, async () => {
  const f = fixture(); let handler;
  await installRoutes({ route: async (_, fn) => { handler = fn; }, routeWebSocket: async () => {} }, f.gate, f.log, async () => {});
  const r = mockRoute(ORIGIN + BASE + '/llm/summary', 'GET', undefined, {}, status);
  await handler(r); assert.deepEqual(r.trace, ['fetch', 'fulfill', 'dispose']); assert.equal(f.gate.stopped, false);
});
test('failed diagnostic publication prevents transport after durable one-shot spend', async () => {
  const f = fixture(); let handler;
  await installRoutes({ route: async (_, fn) => { handler = fn; }, routeWebSocket: async () => {} }, f.gate, f.log, async () => { throw Error('disk'); });
  f.gate.arm('chat', current(), before()); const r = mockRoute(ORIGIN + BASE + '/llm/chat', 'POST', request());
  await handler(r); assert.deepEqual(r.trace, ['abort']); assert.equal(f.gate.counts.chat, 1); assert.equal(f.log.dispatched, 0);
});
test('live entry rejects caller JSON/factory authority overrides before all I/O', async () => {
  const moduleUrl = new URL('./batch27-final-native.mjs', import.meta.url).href;
  const script = `import assert from 'node:assert/strict';
    import fs from 'node:fs'; import {syncBuiltinESMExports} from 'node:module';
    import {runOnce} from ${JSON.stringify(moduleUrl)};
    let calls = 0;
    for (const name of ['open','mkdir','realpath','lstat']) fs.promises[name] = async () => { calls++; throw Error('IO_BEFORE_AUTHORITY'); };
    globalThis.fetch = async () => { calls++; throw Error('NETWORK_BEFORE_AUTHORITY'); };
    syncBuiltinESMExports();
    for (const claimed of [undefined, {deployment:'wrong'}, {deployment:'a'.repeat(32),stale:true},
      {deployment:'a'.repeat(32),targetReplaced:true}, {deployment:'a'.repeat(32),origin:'${ORIGIN}',review:'b'.repeat(64),validated:true}]) {
      await assert.rejects(runOnce({mode:'run-once',path:'fresh-summary',deployment:'a'.repeat(32),review:'b'.repeat(64),authority:claimed}), /EXACT_NEW_GO_REQUIRED/);
    }
    assert.equal(calls,0); console.log('AUTHORITY_REFUSED_ZERO_IO');`;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], { timeout: 10000, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr); assert.match(result.stdout, /AUTHORITY_REFUSED_ZERO_IO/);
  await assert.rejects(runOnce({ ...modeOf(['--run-once', '--ack-new-coordinator-postdeploy-go', '--ack-paid-openai-uncapped',
    '--ack-separate-b0-b1-preservation', '--path', 'existing-current-summary', '--deployment-id', 'a'.repeat(32), '--review-sha256', 'b'.repeat(64)]), authority: { validated: true } }), /EXACT_NEW_GO_REQUIRED/);
});
test('installed paid route has NO permissive default authority', async () => {
  const f = fixture(); let handler;
  await installGuard({ route: async (_, fn) => { handler = fn; }, routeWebSocket: async () => {} }, f.gate, f.log, async () => {});
  f.gate.arm('chat', current(), before()); const r = mockRoute(ORIGIN + BASE + '/llm/chat', 'POST', request());
  await handler(r); assert.deepEqual(r.trace, ['abort']); assert.equal(f.gate.counts.chat, 1);
  assert.equal(f.log.dispatched, 0); assert.equal(f.log.chatPosts, 0); assert.equal(f.gate.stopped, true);
});
test('fresh paid authority fence follows durable spend/publication and precedes transport', async () => {
  const f = fixture(), order = []; let handler;
  f.gate.persist = async () => { order.push('spent'); };
  await installGuard({ route: async (_, fn) => { handler = fn; }, routeWebSocket: async () => {} }, f.gate, f.log,
    async () => { order.push('published'); }, async (kind, send) => { assert.equal(kind, 'chat'); order.push('fresh-fence'); await send(); order.push('post-fence'); });
  f.gate.arm('chat', current(), before()); const r = mockRoute(ORIGIN + BASE + '/llm/chat', 'POST', request());
  const fetch = r.fetch; r.fetch = async options => { order.push('fetch'); return fetch(options); };
  await handler(r); assert.deepEqual(order, ['spent', 'published', 'fresh-fence', 'fetch', 'post-fence']);
  assert.deepEqual(r.trace, ['fetch', 'fulfill', 'dispose']);
});
for (const at of ['before', 'after']) test(`authority replacement ${at} transport stops without retry/unchecked fulfill`, async () => {
  const f = fixture(); let handler;
  await installGuard({ route: async (_, fn) => { handler = fn; }, routeWebSocket: async () => {} }, f.gate, f.log, async () => {}, async (_kind, send) => {
    if (at === 'after') await send(); throw Error('RUNTIME_TARGET_REPLACED');
  });
  f.gate.arm('chat', current(), before()); const r = mockRoute(ORIGIN + BASE + '/llm/chat', 'POST', request());
  await handler(r); assert.deepEqual(r.trace, at === 'before' ? ['abort'] : ['fetch', 'abort', 'dispose']);
  assert.equal(f.log.dispatched, at === 'before' ? 0 : 1); assert.equal(f.gate.stopped, true);
  await handler(r); assert.equal(r.fetchOptions.length, at === 'before' ? 0 : 1);
});
test('actual installed route handler spends before dispatch, allows only one armed exact body', async () => {
  let routeHandler, socketHandler;
  const f = fixture(), sequence = []; f.gate.persist = async () => { sequence.push('spent'); };
  await installRoutes({ route: async (_, fn) => { routeHandler = fn; }, routeWebSocket: async (_, fn) => { socketHandler = fn; } }, f.gate, f.log, async () => { sequence.push('published'); });
  f.gate.arm('chat', current(), before()); const r = mockRoute(ORIGIN + BASE + '/llm/chat', 'POST', request());
  const fetch = r.fetch; r.fetch = async options => { sequence.push('fetched'); return fetch(options); }; await routeHandler(r);
  assert.deepEqual(sequence, ['spent', 'published', 'fetched']);
  assert.deepEqual(r.trace, ['fetch', 'fulfill', 'dispose']);
  const repeat = mockRoute(ORIGIN + BASE + '/llm/chat', 'POST', request()); await routeHandler(repeat); assert.deepEqual(repeat.trace, ['abort']);
  let closed = false; socketHandler({ close() { closed = true; } }); assert.equal(closed, true);
});
test('gate rejects stale consent/extra keys/prior mutation/wrong question/epoch/revision without consuming; concurrency and stopped flush cannot resend', async () => {
  const mutations = [b => { b.consent.accepted = false; }, b => { b.consent.policyVersion = 'old'; }, b => { b.extra = true; },
    b => { b.question = 'other'; }, b => { b.epoch = uuid(9); }, b => { b.revision++; }, b => { b.mutationId = uuid(12); }];
  for (const mutate of mutations) { const g = new Gate(async () => {}); g.arm('chat', current(), before()); const b = request(); mutate(b);
    assert.equal(await g.consume('chat', b), false); assert.equal(g.counts.chat, 0); }
  let release; const g = new Gate(() => new Promise(r => { release = r; })); g.arm('chat', current(), before());
  const first = g.consume('chat', request()); assert.equal(await g.consume('chat', request()), false); g.stop(); release(); assert.equal(await first, false);
});
test('permanent actual0600 marker survives restart and process contention; no replacement or reset', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'batch27-synthetic-spent-')), path = join(dir, 'attempt.spent.json');
  await spend(path, { test: true }); assert.equal((await stat(path)).mode & 0o777, 0o600);
  const saved = await readFile(path, 'utf8'); await assert.rejects(spend(path, {}), { code: 'EEXIST' });
  const script = `import {spend} from ${JSON.stringify(new URL('./batch27-final-native.mjs', import.meta.url).href)}; await spend(${JSON.stringify(path)}, {});`;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], { timeout: 10000, encoding: 'utf8' });
  assert.notEqual(result.status, 0); assert.match(result.stderr, /EEXIST/); assert.equal(await readFile(path, 'utf8'), saved);
});
test('bounded deadline stops pending operation; late completion does not authorize another send', async () => {
  let resolve, stopped = false; const pending = new Promise(r => { resolve = r; });
  await assert.rejects(bounded(() => pending, 5, () => { stopped = true; }), /DEADLINE_NO_RETRY/);
  assert.equal(stopped, true); resolve('late');
});
test('chat producer predicate persisted before parser failure and no reload on error', async () => {
  for (const predicate of c.diagnostic.CHAT_CONTENT_PREDICATES) {
    const f = fixture(), original = f.io.generate;
    f.io.generate = async kind => kind === 'summary' ? original(kind) : response('invalid\n', 200, {
      'x-llm-failure-phase': 'content', 'x-llm-failure-reason': 'invalid_content', 'x-llm-content-predicate': predicate });
    await assert.rejects(journey(f.io, f.gate, 'fresh-summary', tools, c, f.log));
    assert.equal(f.calls.includes('reload'), false);
    assert.equal(f.events.some(x => x.headers?.['X-LLM-Content-Predicate'] === predicate), true);
    assert.equal(JSON.stringify(f.events).includes('invalid\\n'), false);
  }
});
test('browser adapter uses exact UI button, fresh consent, bounded response matcher and no fetch POST', async () => {
  const actions = [], replies = [];
  const node = (label = '') => ({
    getByLabel: name => node(name), locator: name => node(name), getByRole: (_, options) => node(options.name),
    waitFor: async () => {}, getAttribute: async () => 'open',
    innerText: async () => `${MODEL} без локального денежного лимита не бесплатный режим ZDR Старое бесплатное согласие не применяется платный запрос OpenAI`,
    fill: async value => { actions.push(['fill', value]); },
    click: async () => { actions.push(['click', label]); },
  });
  const page = {
    locator: label => node(label), getByRole: (_, options) => node(options.name),
    evaluate: async (_, url) => { actions.push(['get', url]); return { status: 404, value: { errorCode: 'LLM_SUMMARY_MISSING' } }; },
    waitForResponse: async (predicate, options) => {
      assert.equal(options.timeout, 150000);
      const r = { url: () => ORIGIN + BASE + '/llm/' + (replies.length === 0 ? 'summary' : 'chat'), request: () => ({ method: () => 'POST' }) };
      assert.equal(predicate(r), true); assert.equal(predicate({ ...r, url: () => r.url() + '?x=1' }), false);
      replies.push(r); return r;
    },
  };
  const io = await browserIo(page, tools, c, {}, async () => {});
  await io.paidSummary(); await io.generate('summary'); await io.paidChat(); await io.generate('chat');
  assert.deepEqual(actions.filter(x => x[0] === 'click').map(x => x[1]), ['Включить платный авторазбор OpenAI', 'Отправить вопрос']);
  assert.equal(actions.filter(x => x[0] === 'get').length, 1);
  assert.equal(actions.find(x => x[0] === 'fill')[1], QUESTION);
});
test('summary accounting cannot erase carried/held unknown liabilities; receipt mismatch and reload mutation fail', async () => {
  for (const failure of ['liability', 'receipt', 'reload']) {
    const f = fixture(), base = f.io.usage; let count = 0;
    if (failure !== 'reload') f.io.usage = async () => {
      const u = structuredClone(await base()); count++;
      if (failure === 'liability' && count === 2) u.scan.carried.costMicros = 0;
      if (failure === 'receipt' && count === 3) u.scan.used.costMicros++;
      return u;
    };
    else f.io.reload = async () => { f.log.postAttempts++; };
    await assert.rejects(journey(f.io, f.gate, 'fresh-summary', tools, c, f.log));
    assert.equal(f.calls.includes('reload'), false);
    if (failure === 'liability') assert.equal(f.calls.includes('chat'), false);
  }
});
test('failed dispatch-intent persistence aborts actual installed route with zero continue', async () => {
  let handler;
  const f = fixture(); f.gate.persist = async () => { throw Error('disk'); };
  await installRoutes({ route: async (_, fn) => { handler = fn; }, routeWebSocket: async () => {} }, f.gate, f.log, async () => {});
  f.gate.arm('summary', current()); const r = mockRoute(ORIGIN + BASE + '/llm/summary', 'POST', {
    reportVersion: binding.reportVersion, consent: { accepted: true, policyVersion: current().policyVersion } });
  await handler(r); assert.deepEqual(r.trace, ['abort']); assert.equal(f.gate.counts.summary, 1); assert.equal(f.log.dispatched, 0);
  await handler(r); assert.deepEqual(r.trace, ['abort', 'abort']);
});
test('inert executable and source fingerprint read source only', async () => {
  const result = spawnSync(process.execPath, [new URL('./batch27-final-native.mjs', import.meta.url).pathname], { timeout: 10000, encoding: 'utf8' });
  assert.equal(result.status, 0); assert.match(result.stdout, /NO_PRIVATE_READS_NO_BROWSER_NO_NETWORK/); assert.match(await reviewFingerprint(), /^[a-f0-9]{64}$/);
});
