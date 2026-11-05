// OFFLINE ONLY. Fake Playwright/command seams and synthetic DTOs; no browser,
// HTTP, Docker, retained session/real-state read, build or provider dispatch.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { modeOf, readPlan, installRoutes, createGuard, toolReview, validateCurrent,
  verifyProduct, visibleProduct, geometry, runView, closeBrowser, failureCode, EVIDENCE_SCOPE, VIEWPORTS, BOUNDS, reviewFingerprint } from './batch33-product-readonly.mjs';
import { contracts, fingerprint, SCAN, ORIGIN, BASE, MODEL } from './native-h7v3-paid-sol.mjs';
import { extraContracts, nativeFinding } from './batch26-native-chat.mjs';
import { diagnosticContracts } from './native-h7v3-finite-diagnostics.mjs';
import { browserIo, reviewFingerprint as currentGenerationToolFingerprint } from './batch27-final-native.mjs';

const tools = await contracts(), c = { ...await diagnosticContracts(), ...await extraContracts() };
const id = n => n.toString(16).padStart(64, '0'), uuid = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const options = { mode: 'view', review: id(99) };
const bind = { scanId: SCAN, digest: 'sha256:abe13b25e07ccaedcc8797120c37781f0462a0f0682105cf2d8b8d6f99070d55', platform: 'linux/amd64', reportVersion: id(90) };
const prose = 'Сканер сообщил о находках; требуется проверка.';
function fixture() {
  const h = c.chat.chatContextSchema.parse({ ...bind, epoch: uuid(1), revision: 6, enabled: true, policyVersion: id(91),
    disclosure: { provider: 'OpenAI', model: MODEL, monetaryLimit: 'uncapped', requestBudgetMicros: null, userBudgetMicros: null, scanBudgetMicros: null,
      retention: 'no-training', operatorApprovedRouting: true, providerComplianceNotProvenByDeclaration: true, zeroDataRetentionVerified: false,
      costBasis: c.public.OPENAI_COST_BASIS, estimatedPrice: { unit: 'microUSD-per-million-tokens', input: 1000000, output: 2000000 },
      data: c.public.REMEDIATION_SCANNER_DISCLOSURE, sentData: 'Cleaned question, all user history/accepted decisions and selected findings with complete coverage.',
      localRetention: 'Durable owner+scan history until separately authorized operator lifecycle; capacity can refuse; context cache only, not output cache.' },
    limits: { questionBytes: 2048, bodyBytes: 8192 }, deliveryMode: 'completed-response', pending: false });
  // Distinct same-package identifiers, no synthetic identifierKind in ordinary DTOs.
  const rows = [1, 2, 3].map(n => ({ findingId: 'vuln-' + id(n), cveId: `CVE-2026-${1000 + n}`, ecosystem: 'deb', severity: 'HIGH',
    severitySources: ['debian'], provenanceRef: 'target-' + id(n + 10), packageName: 'libc6', installedVersion: '1.0', fixedVersion: null }));
  const corpus = new Map(rows.map(row => [row.findingId, { ...row, check: 'vuln', identifierKind: 'cve' }]));
  const facts = [...corpus.values()].map(nativeFinding);
  const r = { ...bind, localReady: true, status: 'locally-configured', blockers: [], provider: { name: 'OpenAI', model: MODEL, status: 'configured-unprobed', liveVerified: false },
    credential: 'environment-valid', accounting: 'configured', history: 'available', quota: 'available', requiresConsent: true, acceptsCredentials: false, generationVerified: false,
    setupAction: 'operator-server-environment-configuration' };
  const summary = { ...bind, hypotheses: [0, 1, 2, 3].map(i => ({ kind: 'hypothesis', text: prose, citations: [facts[i % 3].findingId] })), scannerFacts: facts };
  const history = { ...bind, epoch: h.epoch, revision: 6, pending: null, decisions: [],
    retention: 'Confirmed history persists until separately authorized operator lifecycle; no automatic expiry or reset.',
    turns: [1, 2].map(n => ({ id: uuid(n + 10), mutationId: uuid(n + 20), question: 'Прежний вопрос.', report: bind, createdAt: 1, state: 'failed' })) };
  history.turns.push({ id: uuid(13), mutationId: uuid(23), question: 'Текущий вопрос.', report: bind, createdAt: 2, state: 'completed',
    reply: { ...bind, kind: 'hypothesis', text: prose, sources: facts.map(finding => ({ ...bind, finding })) } });
  const zero = { input: 0, output: 0, costMicros: 0 }, carried = { input: 1, output: 2, costMicros: 3 }, used = { input: 30085, output: 1118, costMicros: 27596 };
  const scope = { limits: { input: 1000000, output: 1000000, costMicros: null }, used, held: zero, carried,
    remaining: { input: 1000000 - used.input - carried.input, output: 1000000 - used.output - carried.output, costMicros: null }, warning: false, exhausted: false };
  const usage = { ...bind, integrationEnabled: true, quotaEnabled: true, available: true, monetaryLimit: 'uncapped', reason: 'ready', admission: { status: 'unavailable' },
    window: { start: 1793750400000, end: 1793836800000 }, signals: [], user: structuredClone(scope), scan: structuredClone(scope) };
  const disclosure = { ...h.disclosure }; delete disclosure.sentData; delete disclosure.localRetention;
  const s = tools.summary.summaryContextSchema.parse({ ...bind, enabled: true, policyVersion: h.policyVersion, disclosure });
  return { sample: { context: { s, h, r }, summary, history, usage }, corpus };
}
function ioFixture(f) {
  const calls = [];
  const io = { preflight: async () => { calls.push('preflight'); return { ...structuredClone(f.sample.context), history: structuredClone(f.sample.history) }; },
    corpus: async () => { calls.push('corpus'); return f.corpus; },
    current: async () => { calls.push('context'); return structuredClone(f.sample.context); },
    summaryRead: async () => { calls.push('summary'); return { status: 200, value: structuredClone(f.sample.summary) }; },
    history: async () => { calls.push('history'); return structuredClone(f.sample.history); },
    usage: async () => { calls.push('usage'); return structuredClone(f.sample.usage); },
    visible: async sample => { calls.push('visible'); validateCurrent(sample, f.corpus, tools, c); },
    geometry: async width => { calls.push('geometry' + width); }, viewport: async width => { calls.push('width' + width); },
    reload: async () => { calls.push('reload'); },
    generate: () => assert.fail('no generation'), paidChat: () => assert.fail('no consent'), paidSummary: () => assert.fail('no consent'),
    disableAutomation: () => assert.fail('no preference save') };
  const source = { check: async () => { calls.push('tool-review'); } };
  return { io, source, calls };
}
test('default CLI is inert, import/default never reaches private/live entry; strict new VIEW CLI only', async () => {
  const args = ['--view-readonly', '--ack-coordinator-get-only', '--ack-retain-native-lock-original-wire-failed', '--review-sha256', options.review];
  assert.deepEqual(modeOf(args), options); assert.deepEqual(modeOf([]), { mode: 'inert' });
  assert.deepEqual(modeOf(['--fingerprint']), { mode: 'fingerprint' });
  for (const bad of [args.slice(1), [...args, '--release'], [...args, '--summary-hash', id(1)], ['--run-once'], ['--reconcile-known-commits'], args.map(x => x === options.review ? 'not-hash' : x)]) assert.throws(() => modeOf(bad));
  for (const extra of [{ passed: true }, { anchors: {} }, { runtime: true }, { path: 'fresh-summary' }, { attempt: uuid(50) }, { deployment: 'c63d2e0ce8ecdce681de307fc6e25d6f' }]) await assert.rejects(runView({ ...options, ...extra }), /EXACT_VIEW_GO_REQUIRED/);
  const result = spawnSync(process.execPath, ['tests-e2e/batch33-product-readonly.mjs'], { cwd: fileURLToPath(new URL('../', import.meta.url)), timeout: 10000, encoding: 'utf8' });
  assert.equal(result.status, 0); assert.deepEqual(JSON.parse(result.stdout), { status: 'INERT_NO_BROWSER_NO_NETWORK_NO_PRIVATE_READ' });
});
test('import with private filesystem/network/process traps performs no private or live action', () => {
  const moduleUrl = new URL('./batch33-product-readonly.mjs', import.meta.url).href;
  const code = `import fs from 'node:fs'; import fsp from 'node:fs/promises'; import cp from 'node:child_process'; import {syncBuiltinESMExports} from 'node:module';
    const privatePath = p => /\\.local-public-images|private-storage|batch31-final-native-20261104/.test(String(p));
    for (const [object, names] of [[fs,['openSync','readFileSync','lstatSync','statSync','readdirSync','realpathSync']], [fsp,['open','readFile','lstat','stat','readdir','realpath']]])
      for (const name of names) { const original=object[name]; object[name]=function(p,...args) { if(privatePath(p)) throw Error('PRIVATE_READ_TRAP'); return original.call(this,p,...args); }; }
    for (const name of ['spawn','spawnSync','execFile','execFileSync','exec','execSync']) cp[name]=()=>{throw Error('PROCESS_TRAP');};
    globalThis.fetch=()=>{throw Error('NETWORK_TRAP');}; syncBuiltinESMExports();
    const m=await import(${JSON.stringify(moduleUrl)}); if(m.modeOf([]).mode!=='inert') throw Error('NOT_INERT'); console.log('IMPORT_INERT');`;
  const result = spawnSync(process.execPath, ['--input-type=module', '--eval', code], { timeout: 10000, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr); assert.equal(result.stdout.trim(), 'IMPORT_INERT');
});
test('public source fingerprint uses actual bytes, no private or original-mutation pins', async () => {
  assert.match(await reviewFingerprint(), /^[a-f0-9]{64}$/);
  const source = await readFile(new URL('./batch33-product-readonly.mjs', import.meta.url), 'utf8');
  for (const forbidden of ['writeFile(', 'mkdir(', 'rename(', 'unlink(', '.screenshot(', 'storageState(', 'launchPersistentContext(', 'openNativeRuntimeAuthority(']) assert.equal(source.includes(forbidden), false, forbidden);
  assert.equal(source.includes('qualifyDurableCommit('), false);
});
for (const [name, url, method, redirected] of [
  ['summary POST', ORIGIN + BASE + '/llm/summary', 'POST'], ['chat POST', ORIGIN + BASE + '/llm/chat', 'POST'],
  ['settings POST', ORIGIN + '/account', 'POST'], ['auth POST', ORIGIN + '/api/v1/auth/login', 'POST'],
  ['scan POST', ORIGIN + '/api/v1/browser/scans', 'POST'], ['PUT', ORIGIN + BASE, 'PUT'], ['HEAD', ORIGIN + BASE, 'HEAD'],
  ['provider', 'https://api.openai.com/v1/responses', 'GET'], ['other loopback', 'http://127.0.0.1:8080' + BASE, 'GET'],
  ['other owner scan', ORIGIN + BASE.replace(SCAN, uuid(999)), 'GET'], ['events', ORIGIN + BASE + '/events', 'GET'],
  ['translation', ORIGIN + BASE + '/llm/translation/context?findingId=vuln-' + id(1) + '&assessmentIndex=0', 'GET'],
  ['runtime discovery', ORIGIN + '/api/v1/browser/runtime', 'GET'], ['redirected', ORIGIN + BASE, 'GET', true],
  ['query mutation', ORIGIN + BASE + '/llm/summary?generate=1', 'GET'], ['userinfo', 'http://x@127.0.0.1:8081' + BASE, 'GET'],
  ['encoded path', ORIGIN + '/assets/%2e%2e/main.js', 'GET'], ['fragment', ORIGIN + BASE + '#private', 'GET'],
]) test(`readPlan rejects ${name}`, () => { assert.equal(readPlan(url, method, redirected), false); });
test('readPlan permits only actual report/account/assets and bounded current-report GET contracts', () => {
  for (const path of ['/account', `/scans/${SCAN}`, '/api/v1/auth/me', '/assets/index-a1.js', BASE, BASE + '/llm/summary', BASE + '/llm/history',
    BASE + '/llm/context', BASE + '/llm/chat/context', BASE + '/llm/readiness', BASE + '/llm/usage', BASE + '/vuln?cursor=0&limit=50',
    BASE + '/vuln?view=report-v1&limit=25&sort=severity%3Adesc']) assert.equal(readPlan(ORIGIN + path, 'GET'), true, path);
});
async function routeFixture({ method = 'GET', url = ORIGIN + BASE + '/llm/history', status = 200, responseUrl = url, headers = {}, bytes = Buffer.from('{}'), redirected = false, body = null, during = null, failed = false } = {}) {
  const guard = createGuard(), calls = []; let handler, websocket;
  const context = { route: async (_, fn) => { handler = fn; }, routeWebSocket: async (_, fn) => { websocket = fn; } };
  await installRoutes(context, guard);
  const route = { request: () => ({ method: () => method, url: () => url, redirectedFrom: () => redirected, postData: () => body }),
    abort: async () => { calls.push('abort'); }, continue: () => assert.fail('no continue'),
    fetch: async config => { calls.push(['fetch', config]); during?.(guard); if (failed) throw Error('PRIVATE_BODY_canary');
      return { status: () => status, url: () => responseUrl, headers: () => headers, body: async () => bytes, dispose: async () => { calls.push('dispose'); } }; },
    fulfill: async value => { calls.push(['fulfill', value.body]); } };
  return { guard, calls, run: () => handler(route), websocket };
}
for (const status of [300, 301, 302, 303, 304, 305, 306, 307, 308, 399]) test(`installed handler refuses HTTP${status} without follow, fulfill or retry`, async () => {
  const f = await routeFixture({ status }); await f.run();
  assert.deepEqual(f.calls, [['fetch', { maxRedirects: 0, maxRetries: 0, timeout: 15000 }], 'abort', 'dispose']); assert.equal(f.guard.denied, 1);
});
for (const bad of [{ method: 'POST' }, { method: 'GET', body: 'not-empty' }, { url: 'https://api.openai.com/v1/responses' }, { redirected: true }]) test(`installed handler denies before transport ${JSON.stringify(bad)}`, async () => {
  const f = await routeFixture(bad); await f.run(); assert.deepEqual(f.calls, ['abort']); assert.equal(f.guard.stopped, true);
});
for (const bad of [{ responseUrl: 'https://foreign.invalid/' }, { status: 199 }, { status: 600 }, { status: '200' }, { headers: { Location: '/next' } },
  { headers: { 'Content-Disposition': 'attachment' } }, { headers: { 'content-length': '999999999' } }, { bytes: Buffer.alloc(1048577) },
  { during: guard => { guard.stopped = true; } }, { failed: true }]) test(`installed nofollow fetch fails closed ${Object.keys(bad)[0]}`, async () => {
  const f = await routeFixture(bad); await f.run(); assert.equal(f.calls.some(x => Array.isArray(x) && x[0] === 'fulfill'), false); assert.equal(f.guard.stopped, true);
  assert.equal(JSON.stringify(f.guard).includes('PRIVATE_BODY'), false);
});
test('ordinary HTTP200/404 are checked/fulfilled then disposed; websocket and finite request cap fail closed', async () => {
  for (const status of [200, 404]) { const f = await routeFixture({ status }); await f.run(); assert.equal(f.calls[1][0], 'fulfill'); assert.equal(f.calls[2], 'dispose'); }
  const f = await routeFixture(); f.guard.requests = 400; await f.run(); assert.deepEqual(f.calls, ['abort']);
  let closed = 0; f.websocket({ close: () => closed++ }); assert.equal(closed, 1); assert.equal(f.guard.stopped, true);
});
test('shutdown aborts only already allowed GETs quietly; POST during shutdown still fails the whole view', async () => {
  const f = await routeFixture(); f.guard.closing = true; f.guard.stopped = true; await f.run(); assert.deepEqual(f.calls, ['abort']); assert.equal(f.guard.denied, 0);
  const bad = await routeFixture({ method: 'POST' }); bad.guard.closing = true; bad.guard.stopped = true; await bad.run(); assert.equal(bad.guard.nonGet, 1); assert.equal(bad.guard.denied, 1);
  for (const failed of [false, true]) {
    const pending = await routeFixture({ failed, during: guard => { guard.closing = true; guard.stopped = true; } });
    await pending.run(); assert.equal(pending.guard.denied, 0); assert.equal(pending.guard.firstFailure, null);
    assert.equal(pending.calls.some(v => Array.isArray(v) && v[0] === 'fulfill'), false);
    assert.equal(pending.calls.filter(v => Array.isArray(v) && v[0] === 'fetch').length, 1);
  }
});
test('current tool review changes independently of original generation review; subsequent local drift still refuses', async () => {
  let current = id(13); const source = toolReview(current, async () => current);
  assert.deepEqual(Object.keys(source), ['check']); await source.check(); current = id(14);
  await assert.rejects(source.check(), /SOURCE_CHANGED/);
  assert.throws(() => toolReview('not-a-hash'), /EXACT_VIEW_GO_REQUIRED/);
});
test('completion4 borrowed-candidate deployment stays viewable after local delivery-tool changes, without deployment/lock reads or build claims', async () => {
  // Synthetic historical provenance only; VIEW must not re-authorize it using
  // today's local generation sources, rewrite it, or claim to verify its bytes.
  const originalReview = '94a442d6767be909bb0b714fd86a2db85b85d1a36ea8f519e7d957d08acf0c19';
  const origin = { kind: 'adapter-completion', nonce: 'a'.repeat(32), sha256: id(1) };
  const sealed = { complete: { version: 4, nonce: 'c63d2e0ce8ecdce681de307fc6e25d6f', outcome: 'published', references: [],
    borrowedReferences: ['api', 'web'].map(name => ({ name, tag: `dip-deploy-${name}:candidate-${origin.nonce}`, image: 'sha256:' + id(2), origin })) },
    referenceCustody: { version: 2, candidates: ['api', 'web'].map(name => ({ name, tag: `dip-deploy-${name}:candidate-${origin.nonce}`, image: 'sha256:' + id(2), ownership: 'borrowed', origin })) },
    nativeOwner: { review: originalReview, retained: true } };
  const before = fingerprint(sealed), f = fixture(), a = ioFixture(f);
  // Different actual current public-tool bytes are independently fingerprinted;
  // no replacement original hash, caller passed boolean, or deployment waiver.
  const currentGenerationReview = await currentGenerationToolFingerprint();
  assert.notEqual(currentGenerationReview, originalReview, 'precondition: changed local delivery/tool bytes no longer have the old generation review');
  const currentReview = await reviewFingerprint(); assert.notEqual(currentReview, originalReview);
  const source = toolReview(currentReview);
  const result = await verifyProduct(a.io, source, tools, c);
  assert.equal(fingerprint(sealed), before); assert.equal(result.nativeLock, 'RETAINED_NO_DISPOSITION');
  assert.deepEqual(result.evidenceScope, EVIDENCE_SCOPE);
  assert.equal(result.evidenceScope.deployedBuildIdentity, 'NOT_MEASURED');
  assert.equal(result.evidenceScope.runtimeEpochIdentity, 'NOT_MEASURED');
  assert.equal(result.evidenceScope.generationEligibility, 'NOT_ASSESSED');
  assert.equal(result.paidRetryAuthorized, false); assert.equal(result.historicalWire.chatHttp, 502);
  // Pin removal is structural in the real production entry, not merely a mock:
  const sourceText = await readFile(new URL('./batch33-product-readonly.mjs', import.meta.url), 'utf8');
  for (const forbidden of ['originalFingerprint', 'ORIGINAL_REVIEW', 'captureNativeRuntimeSource', 'captureNativeDeploymentRecords',
    'createNativeRuntimeAuthority', 'createNativeRuntimeObserver', 'captureNativeReconcileEvidence', 'openRuntimeView', 'deploy-adapter.mjs'])
    assert.equal(sourceText.includes(forbidden), false, forbidden);
  assert.equal(sourceText.includes('const source = toolReview(options.review); await source.check();'), true);
});

test('actual current strict frontend contracts/source/language qualify current VIEW without inventing original anchors', () => {
  const f = fixture(), before = fingerprint(f.sample); assert.equal(validateCurrent(f.sample, f.corpus, tools, c).history.revision, 6); assert.equal(fingerprint(f.sample), before);
  // This view does NOT require/claim the missing original mutation or prior-history anchor.
  f.sample.history.turns[2].mutationId = uuid(888); validateCurrent(f.sample, f.corpus, tools, c);
});
for (const [name, change] of [
  ['pending', f => { f.sample.context.h.pending = true; }], ['revision', f => { f.sample.history.revision = 8; }],
  ['turn state', f => { f.sample.history.turns[0].state = 'completed'; }], ['extra turn', f => { f.sample.history.turns.push(f.sample.history.turns[0]); }],
  ['missing citation', f => { f.sample.history.turns[2].reply.sources.pop(); }], ['source binding', f => { f.sample.history.turns[2].reply.sources[0].reportVersion = id(999); }],
  ['source fact', f => { f.sample.history.turns[2].reply.sources[0].finding.installedVersion = '9.9'; }],
  ['summary source', f => { f.sample.summary.scannerFacts[0].provenanceRef = 'target-' + id(999); }], ['summary paragraphs', f => { f.sample.summary.hypotheses.pop(); }],
  ['English', f => { f.sample.summary.hypotheses[0].text = 'Update this vulnerable package immediately.'; }],
  ['wrong model', f => { f.sample.context.h.disclosure.model = 'another-model'; }], ['wrong report', f => { f.sample.history.reportVersion = id(999); }],
  ['unknown schema field', f => { f.sample.history.passed = true; }], ['quota unavailable', f => { f.sample.usage.available = false; }],
]) test(`current VIEW refuses ${name}; cannot self-green with current hashes`, () => { const f = fixture(); change(f); assert.throws(() => validateCurrent(f.sample, f.corpus, tools, c)); });
test('full practical read-only journey covers375/1280 before/after actual IO reload boundary; output aggregate flags only', async () => {
  const f = fixture(), adapter = ioFixture(f), result = await verifyProduct(adapter.io, adapter.source, tools, c);
  assert.deepEqual(result.viewports.map(v => v.width), VIEWPORTS); assert.equal(adapter.calls.filter(x => x === 'reload').length, 2);
  assert.equal(adapter.calls.filter(x => x === 'visible').length, 4); assert.equal(adapter.calls.filter(x => x === 'tool-review').length, 5);
  assert.equal(result.historicalWire.chatHttp, 502); assert.equal(result.historicalWire.originalWireResult, 'FAILED_NOT_REPAIRED');
  assert.equal(result.nativeLock, 'RETAINED_NO_DISPOSITION'); assert.equal(result.paidRetryAuthorized, false);
  const serialized = JSON.stringify(result); for (const privateValue of [prose, 'Прежний вопрос.', 'Текущий вопрос.', f.sample.history.turns[2].mutationId, bind.reportVersion, 'libc6']) assert.equal(serialized.includes(privateValue), false);
  assert.match(result.originalRequestCorrelation, /NOT_ESTABLISHED/); assert.match(result.semanticAccuracy, /UNVERIFIED/);
});
for (const [name, mutate] of [
  ['summary', f => { f.sample.summary.hypotheses[0].text = 'Результат требует дополнительной проверки.'; }],
  ['prior failed question', f => { f.sample.history.turns[0].question = 'Изменённый вопрос.'; }],
  ['completed mutation', f => { f.sample.history.turns[2].mutationId = uuid(888); }],
  ['carried liability', f => { f.sample.usage.user.carried.input++; }],
  ['used estimate', f => { f.sample.usage.scan.used.input++; }],
  ['window', f => { f.sample.usage.window.start++; }],
  ['policy', f => { f.sample.context.h.policyVersion = id(777); }],
]) test(`reload proves current in-memory exact DTO stability: changed ${name} stops`, async () => {
  const f = fixture(), adapter = ioFixture(f); adapter.io.reload = async () => { mutate(f); };
  await assert.rejects(verifyProduct(adapter.io, adapter.source, tools, c));
});
test('summary404 and UI/geometry/tool-review failures never trigger fallback or report verification', async () => {
  for (const fail of ['missing', 'ui', 'geometry', 'tool-review']) {
    const f = fixture(), a = ioFixture(f);
    if (fail === 'missing') a.io.summaryRead = async () => ({ status: 404, value: { errorCode: 'LLM_SUMMARY_MISSING' } });
    if (fail === 'ui') a.io.visible = async () => { throw Error('UI_UNVERIFIED'); };
    if (fail === 'geometry') a.io.geometry = async () => { throw Error('GEOMETRY_UNVERIFIED'); };
    if (fail === 'tool-review') a.source.check = async () => { throw Error('SOURCE_CHANGED'); };
    await assert.rejects(verifyProduct(a.io, a.source, tools, c));
  }
});
test('actual geometry function requires375/1280 and no document/body horizontal overflow, not a success flag', async () => {
  await geometry({ evaluate: async () => ({ width: 375, client: 375, scroll: 375, body: 375 }) }, 375);
  await assert.rejects(geometry({ evaluate: async () => ({ width: 375, client: 375, scroll: 420, body: 375 }) }, 375), /GEOMETRY_UNVERIFIED/);
  await assert.rejects(geometry({ evaluate: async () => ({ width: 1280, client: 1280, scroll: 1280, body: 1280 }) }, 375));
});
test('bounded cleanup attempts browser.close even if context rejects or ignores cancellation; never claims success', async () => {
  assert.ok(BOUNDS.workMs + 2 * BOUNDS.closeMs + BOUNDS.sessionCheckMs <= 120000);
  for (const hangs of [false, true]) {
    const calls = [], context = { close: () => { calls.push('context'); return hangs ? new Promise(() => {}) : Promise.reject(Error('context failed')); } },
      browser = { close: async () => { calls.push('browser'); } };
    await assert.rejects(closeBrowser(context, browser, 10)); assert.deepEqual(calls, ['context', 'browser']);
  }
  await closeBrowser({ close: async () => {} }, { close: async () => {} }, 10);
});
test('failure projection never serializes private body/stack/error values', () => {
  assert.equal(failureCode(Error('private reply TOKEN_VALUE')), 'READONLY_UNVERIFIED'); assert.equal(failureCode({ message: 'UI_UNVERIFIED', stack: 'private' }), 'UI_UNVERIFIED');
});

// Exercise actual browserIo ordinary corpus decoder with440 DTO rows lacking kind.
test('VIEW corpus reuses production frontend parser and exact431CVE/6TEMP/3DLA normalization, GET only', async () => {
  const f = fixture(), rows = Array.from({ length: 440 }, (_, i) => ({ findingId: 'vuln-' + id(i + 1),
    cveId: i < 431 ? `CVE-2026-${1000 + i}` : i < 437 ? `TEMP-${1000000 + i}-ABCDEF` : `DLA-${1000 + i}-1`, ecosystem: 'deb', packageName: 'libc6', installedVersion: '1.0', severity: 'HIGH',
    fixedVersion: null, severitySources: ['debian'], provenanceRef: 'target-' + id(i + 1000) }));
  const dbDigest = 'sha256:' + id(999), checkedAt = '2026-11-04T12:00:00.000Z';
  const metadata = { outcome: 'checked', coverage: 'image', profile: 'public-hub-amd64-v1', image: 'registry-1.docker.io/library/nginx@' + bind.digest,
    platform: 'linux/amd64', findingCount: 440, scannerVersion: '0.69.3', checkedAt, identifierCounts: { cve: 431, debianTemp: 6, debianDla: 3 },
    db: { envelopeVersion: 1, signer: 'local-db-operator-v1', source: 'ghcr.io/aquasecurity/trivy-db@' + dbDigest, schemaVersion: 2, manifestDigest: dbDigest,
      artifactSha256: id(1000), metadataSha256: id(1001), dbSha256: id(1002), updatedAt: '2026-11-04T10:00:00.000Z', downloadedAt: '2026-11-04T11:00:00.000Z', nextUpdate: '2026-11-05T10:00:00.000Z' },
    resultContractVersion: 2, workerCheckedAt: Date.parse(checkedAt), dbPolicy: { version: 2, policy: 'cve-db-updated-at-14d-v2', evaluatedAt: Date.parse(checkedAt), status: 'usable', warnings: [] }, usableUntil: '2026-11-18T10:00:00.000000000Z' };
  const reads = [], page = { evaluate: async (_, url) => {
    reads.push(url); assert.ok(readPlan(ORIGIN + url, 'GET'));
    if (url === BASE) return { status: 200, value: { ...bind, state: 'completed', perCheck: { secret: { findingCount: 0 }, vuln: { findingCount: 440 } } } };
    const match = url.match(/\/vuln\?cursor=(\d+)&limit=50$/); assert.ok(match); const cursor = Number(match[1]);
    return { status: 200, value: { ...metadata, findings: rows.slice(cursor, cursor + 50), nextCursor: cursor === 400 ? null : cursor + 50 } };
  } };
  const io = await browserIo(page, tools, c, {}, () => assert.fail('no writes')), corpus = await io.corpus();
  assert.equal(corpus.size, 440); assert.equal(reads.length, 10);
  assert.equal([...corpus.values()].filter(row => row.identifierKind === 'debian-dla').length, 3);
  assert.equal(rows.some(row => 'identifierKind' in row), false); assert.equal(f.sample.context.h.revision, 6);
});

// A minimal Playwright-shaped DOM adapter tests the real semantic selectors and
// every assertion; it is NOT native layout/browser evidence.
function domFixture(sample) {
  const calls = []; let opened = false;
  const leaf = text => ({ waitFor: async () => {}, innerText: async () => text, count: async () => 1 });
  const cards = sources => ({ evaluateAll: async () => sources.map(s => s.finding.findingId) });
  const completed = sample.history.turns[2];
  const article = index => ({
    innerText: async () => index < 2 ? `Вопрос · ошибка ${sample.history.turns[index].question} Подтверждённого ответа нет` : `${completed.question} ${completed.reply.text}`,
    getByLabel: () => ({ locator: selector => { assert.equal(selector, '.report-remediation'); return cards(completed.reply.sources); } }),
    locator: selector => { assert.match(selector, /^\.report-remediation\[data-finding-id=/); const source = completed.reply.sources.find(s => selector.includes(s.finding.findingId)); assert.ok(source);
      return { locator: tag => { assert.equal(tag, 'code'); return { allTextContents: async () => Object.values(source.finding).filter(v => typeof v === 'string') }; }, innerText: async () => source.finding.cveId }; },
  });
  const chat = { getByRole: () => leaf(''), locator: selector => { assert.equal(selector, ':scope > article'); return { count: async () => 3, nth: article }; } };
  const explanation = { getAttribute: async () => opened ? '' : null, locator: selector => { assert.equal(selector, ':scope > summary'); return { click: async () => { calls.push('open-local-summary'); opened = true; } }; } };
  const output = { ...leaf(''), locator: selector => { assert.equal(selector, 'details.scan-summary-explanation'); return explanation; },
    getByLabel: name => { const index = Number(name.match(/\d+/)[0]) - 1, paragraph = sample.summary.hypotheses[index]; assert.ok(paragraph);
      return { ...leaf(''), locator: selector => selector === '..' ? leaf(paragraph.text) : { evaluateAll: async () => paragraph.citations } }; } };
  const page = { locator: selector => { assert.equal(selector, '.scan-report-overview'); return { ...leaf(''), locator: () => leaf('440 находок') }; },
    getByLabel: name => { assert.equal(name, 'ИИ-разбор отчёта'); return output; },
    getByRole: (role, config) => { assert.equal(role, 'region'); assert.equal(config.name, 'Чат по отчёту'); return chat; } };
  return { page, calls, output, chat };
}
test('actual visibleProduct checks four paragraph-local citation lists, three historical states, exact sources/composer with no action buttons', async () => {
  const f = fixture(), dom = domFixture(f.sample); await visibleProduct(dom.page, f.sample);
  assert.deepEqual(dom.calls, ['open-local-summary']); await visibleProduct(dom.page, f.sample); assert.equal(dom.calls.length, 1);
  dom.output.getByLabel = () => ({ waitFor: async () => {}, locator: () => ({ innerText: async () => 'wrong', evaluateAll: async () => [] }) });
  await assert.rejects(visibleProduct(dom.page, f.sample), /UI_UNVERIFIED/);
});
