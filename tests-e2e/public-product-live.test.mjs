// Offline pure guards only: no browser/server/scanner, credentials, key files or native state.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import test from 'node:test';
import { ORIGIN, SCANS, CHECKS, TARGETS, parseMode, fixedUrl, allowedGet, validIntent, eligibilityReady,
  EligibilityFence, awaitEligibility, consumePermit, partition, cancelVerdict, preservationVerdict, keyBoundaryAllowed, checkPage, readAllPages, loadContracts, safeMeta, ResultBook, GLOBAL_MS, WORKER_MS,
    BROWSER_ARGS, safeMutationRequest, assertDeniedReply, assertChatUsage, renderedRowParts, paginationVerdict, evidenceDocuments, writeEvidence } from './public-product-live.mjs';

const id = '12345678-1234-4234-8234-123456789abc';
const ready = target => ({ imageReference: target.reference, eligible: true, reason: 'READY', eligibility: 'public-hub-profile', allowedCheckSets: [[...CHECKS]] });
const intent = target => ({ imageReference: target.reference, scope: 'image', checks: [...CHECKS], idempotencyKey: 'offline-idempotency' });

test('default is not-run; full explicit GO/no-key-activation acknowledgements required', () => {
  assert.equal(parseMode([]), 'not-run');
  assert.equal(parseMode(['--self-test']), 'offline');
  assert.equal(parseMode(['--run', '--ack-coordinator-go', '--ack-no-key-activation']), 'native');
  for (const args of [['--run'], ['--run', '--ack-coordinator-go'], ['--native-child'], ['--run-native'], ['--url', ORIGIN], ['--self-test', '--run'], ['--run', '--ack-coordinator-go', '--ack-no-key-activation', '--target=other']]) assert.throws(() => parseMode(args));
});

test('exact public origin: no old port, localhost, credentials, fragments, redirect destinations', () => {
  assert.ok(fixedUrl(`${ORIGIN}/scans`));
  assert.ok(fixedUrl(`${ORIGIN}${SCANS}?limit=100`));
  for (const value of ['http://127.0.0.1:8080/scans', 'http://localhost:8081/scans', 'https://127.0.0.1:8081/scans', 'http://[::1]:8081/scans', 'http://127.0.0.1:8081@outside.invalid/scans', `${ORIGIN}/scans#other`, 'http://user:synthetic@127.0.0.1:8081/scans', `${ORIGIN}.outside.invalid/scans`]) assert.equal(fixedUrl(value), false);
});

test('GET allowlist contains actual report/LLM routes and known scan IDs only', () => {
  for (const suffix of ['', '/events', '/results', '/sbom', '/vuln', '/llm/context', '/llm/usage', '/llm/readiness', '/llm/history', '/llm/chat/context', '/llm/chat/usage']) assert.ok(allowedGet(`${SCANS}/${id}${suffix}`, [id]));
  assert.ok(allowedGet('/api/v1/auth/me', [])); assert.ok(allowedGet(SCANS, []));
  for (const path of [`${SCANS}/${id}/llm/chat`, `${SCANS}/${id}/cancel`, `${SCANS}/${id}/runtime`, `${SCANS}/images`, '/api/v1/admin', `${SCANS}/${id}/llm/history/decision`]) assert.equal(allowedGet(path, [id]), false);
  assert.equal(allowedGet(`${SCANS}/${id}`, []), false);
});

test('two fixed image targets; exact image-only canonical four-check intent', () => {
  assert.equal(TARGETS.length, 2);
  for (const target of TARGETS) {
    assert.ok(validIntent(intent(target), target));
    for (const mutation of [{ scope: 'host' }, { platform: 'linux/arm64' }, { checks: ['secret'] }, { checks: [...CHECKS].reverse() }, { imageReference: 'registry-1.docker.io/library/node:latest' }, { idempotencyKey: '' }, { key: 'synthetic' }]) assert.equal(validIntent({ ...intent(target), ...mutation }, target), false);
  }
  assert.equal(validIntent(intent(TARGETS[0]), TARGETS[1]), false);
});

test('fresh real full-check eligibility grant is sequence/target/time fenced', () => {
  const fence = new EligibilityFence(), target = TARGETS[0];
  const body = { imageReference: target.reference, checks: [...CHECKS] };
  const old = fence.start(), current = fence.start();
  fence.accept(old, body, ready(target), target, 1000); assert.equal(fence.fresh(0, 1001), false);
  fence.accept(current, body, ready(target), target, 1000);
  assert.ok(fence.fresh(current - 1, 1001)); assert.equal(fence.fresh(current, 1001), false);
  assert.equal(fence.fresh(0, 999), false); assert.equal(fence.fresh(0, 31001), false);
  fence.start(); assert.equal(fence.fresh(0, 1001), false);
  for (const mutation of [{ eligible: false }, { reason: 'DB_UNAVAILABLE' }, { allowedCheckSets: [['secret']] }, { imageReference: TARGETS[1].reference }]) assert.equal(eligibilityReady({ ...ready(target), ...mutation }, target), false);
  const seq = fence.start(); fence.accept(seq, { ...body, checks: ['secret'] }, ready(target), target, 1000); assert.equal(fence.fresh(0, 1001), false);
});

test('create guard waits for genuine eligibility inspection, not browser response delivery order', async () => {
  const fence = new EligibilityFence(), target = TARGETS[0];
  const sequence = fence.start();
  let finish, settled = false;
  const pending = new Promise(resolve => { finish = () => {
    fence.accept(sequence, { imageReference: target.reference, checks: CHECKS }, ready(target), target);
    resolve();
  }; });
  assert.equal(fence.fresh(sequence - 1), false);
  const allowed = awaitEligibility(fence, sequence - 1, pending, () => true).then(value => { settled = true; return value; });
  await Promise.resolve(); assert.equal(settled, false);
  finish(); assert.equal(await allowed, true);
});

test('eligibility wait rechecks abort/authority and bounds missing or rejected responses', async () => {
  const fence = new EligibilityFence(), target = TARGETS[0], sequence = fence.start();
  fence.accept(sequence, { imageReference: target.reference, checks: CHECKS }, ready(target), target);
  assert.equal(await awaitEligibility(fence, sequence - 1, Promise.resolve(), () => false), false);
  fence.start();
  assert.equal(await awaitEligibility(fence, sequence - 1, Promise.resolve(), () => true), false);
  await assert.rejects(awaitEligibility(fence, 0, new Promise(() => {}), () => true, 1));
  await assert.rejects(awaitEligibility(fence, 0, Promise.reject(new Error('synthetic response failure')), () => true));
});

test('mutation permits are one-shot, exact-path, exact-body and POST-only', () => {
  const value = { question: 'synthetic question', consent: { accepted: false } };
  const permit = { path: `${SCANS}/${id}/llm/chat`, used: false, matches: body => JSON.stringify(body) === JSON.stringify(value) };
  assert.equal(consumePermit(permit, 'GET', permit.path, value), false);
  assert.equal(consumePermit(permit, 'POST', permit.path + '/other', value), false);
  assert.equal(consumePermit(permit, 'POST', permit.path + '?override=true', value), false);
  assert.equal(consumePermit(permit, 'POST', permit.path, { ...value, consent: { accepted: true } }), false);
  assert.equal(permit.used, false);
  assert.equal(consumePermit(permit, 'POST', permit.path, value), true);
  assert.equal(consumePermit(permit, 'POST', permit.path, value), false);
});

test('CVE/TEMP partition is derived from all rows, never hardcoded or conflated', () => {
  const rows = [
    { cveId: 'CVE-2026-1234', ecosystem: 'npm' },
    { cveId: 'CVE-2026-1234', ecosystem: 'deb' },
    { cveId: 'TEMP-1234567-ABCDEF', ecosystem: 'deb' },
  ];
  assert.deepEqual(partition(rows), { cve: 2, debianTemp: 1 }); // Rows, not distinct identifiers.
  assert.deepEqual(partition([]), { cve: 0, debianTemp: 0 });
  for (const row of [{ cveId: 'TEMP-1234567-ABCDEF', ecosystem: 'npm' }, { cveId: 'TEMP-1234567-abcdef', ecosystem: 'deb' }, { cveId: 'GHSA-not-a-cve', ecosystem: 'npm' }, { cveId: 'TEMP-1234567-ABCDEF', ecosystem: 'deb', advisory: { references: ['fabricated'] } }]) assert.throws(() => partition([row]));
});

test('report page counts, offset and row identity must agree across pages', () => {
  const page = (rows, offset, nextCursor = null) => ({ findings: rows.map(findingId => ({ findingId })), nextCursor, page: { totalCount: 3, matchedCount: 3, offset, returnedCount: rows.length } });
  const expected = { whole: 3, matched: 3 }, seen = new Set();
  assert.equal(checkPage('vuln', page(['one', 'two'], 0, 'opaque'), expected, 0, seen).length, 2);
  assert.equal(checkPage('vuln', page(['three'], 2), expected, 2, seen).length, 1);
  assert.throws(() => checkPage('vuln', page(['one'], 2), expected, 2, seen));
  assert.throws(() => checkPage('vuln', page([], 0, 'opaque'), expected, 0, new Set()));
  assert.throws(() => checkPage('vuln', page(['new'], 1), expected, 0, new Set()));
  assert.throws(() => checkPage('vuln', page(['new'], 0), { whole: 4, matched: 3 }, 0, new Set()));
  assert.throws(() => checkPage('vuln', { ...page(['new'], 0), page: { ...page(['new'], 0).page, returnedCount: 2 } }, expected, 0, new Set()));
});

test('whole-page walker requires real EOF, correct total, unique advancing cursors', async () => {
  const page = (offset, ids, nextCursor, total = 3) => ({ findings: ids.map(findingId => ({ findingId })), nextCursor, page: { totalCount: total, matchedCount: total, offset, returnedCount: ids.length } });
  const calls = [];
  const result = await readAllPages('vuln', { whole: 3, matched: 3 }, async cursor => {
    calls.push(cursor); return cursor === undefined ? page(0, ['a', 'b'], 'opaque') : page(2, ['c'], null);
  });
  assert.deepEqual(calls, [undefined, 'opaque']); assert.equal(result.pages, 2); assert.equal(result.rows.length, 3);
  await assert.rejects(readAllPages('vuln', { whole: 3, matched: 3 }, async () => page(0, ['a'], null)));
  await assert.rejects(readAllPages('vuln', { whole: 3, matched: 3 }, async cursor => cursor === undefined ? page(0, ['a'], 'same') : page(1, ['b'], 'same')));
  let index = 0;
  await assert.rejects(readAllPages('vuln', { whole: 201, matched: 201 }, async () => { const offset = index++; return page(offset, [`row-${offset}`], `cursor-${offset}`, 201); }));
  assert.equal(index, 200);
  const empty = await readAllPages('vuln', { whole: 0, matched: 0 }, async () => page(0, [], null, 0));
  assert.equal(empty.rows.length, 0);
});

test('SBOM uniqueness is tuple-based, not only package name', () => {
  const components = [{ ecosystem: 'deb', name: 'same', version: '1' }, { ecosystem: 'npm', name: 'same', version: '1' }];
  const page = { components, nextCursor: null, page: { totalCount: 2, matchedCount: 2, offset: 0, returnedCount: 2 } };
  assert.equal(checkPage('sbom', page, { whole: 2, matched: 2 }, 0, new Set()).length, 2);
  assert.throws(() => checkPage('sbom', { ...page, components: [components[0], components[0]] }, { whole: 2, matched: 2 }, 0, new Set()));
});

test('cancel races are INCONCLUSIVE, not cancel PASS; unexpected replies fail', () => {
  assert.deepEqual(cancelVerdict('cancelled', 200), { status: 'PASS', code: 'VERIFIED' });
  for (const state of ['completed', 'partial', 'failed']) for (const status of [409, null]) assert.equal(cancelVerdict(state, status).status, 'INCONCLUSIVE');
  for (const [state, status] of [['running', 200], ['cancelled', 409], ['completed', 200], ['cancelled', null]]) assert.equal(cancelVerdict(state, status).status, 'BLOCKED');
});

test('consented negative boundary requires fresh missing key, stores and matching report', () => {
  const context = { scanId: id, digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64', reportVersion: 'b'.repeat(64), policyVersion: 'c'.repeat(64), enabled: true, pending: false };
  const readiness = { ...context, credential: 'missing', localReady: false, generationVerified: false, requiresConsent: true, acceptsCredentials: false, blockers: ['public-key-required'], quota: 'available', history: 'available' };
  assert.ok(keyBoundaryAllowed(readiness, context));
  for (const mutation of [{ credential: 'metadata-valid' }, { credential: 'unsafe' }, { localReady: true }, { blockers: [] }, { quota: 'unavailable' }, { history: 'unavailable' }, { reportVersion: 'c'.repeat(64) }, { scanId: 'foreign' }]) assert.equal(keyBoundaryAllowed({ ...readiness, ...mutation }, context), false);
  assert.equal(keyBoundaryAllowed(readiness, { ...context, enabled: false }), false);
  assert.equal(keyBoundaryAllowed(readiness, { ...context, pending: true }), false);
});

test('sanitized metadata is closed and preserves unknown counts rather than zero', () => {
  const projected = safeMeta({ scanId: id, state: 'cancelled', credential: 'missing', blockers: ['public-key-required', 'private-path'], httpStatus: 503,
    counts: { secret: 0, vuln: null, sbom: 17, raw: 100, config: -1 }, checks: { secret: 'checked', vuln: null, sbom: 'not-real', private: 'checked' },
    observedCompletedChecks: ['sbom', 'private'], password: 'SYNTHETIC_PRIVATE_MARKER', token: 'SYNTHETIC_PRIVATE_MARKER', providerPayload: 'SYNTHETIC_PRIVATE_MARKER', error: new Error('SYNTHETIC_PRIVATE_MARKER'), arbitrary: 'SYNTHETIC_PRIVATE_MARKER' });
  assert.equal(JSON.stringify(projected).includes('SYNTHETIC_PRIVATE_MARKER'), false);
  assert.deepEqual(projected.counts, { secret: 0, sbom: 17, vuln: null });
  assert.deepEqual(projected.checks, { secret: 'checked', vuln: null });
  assert.deepEqual(projected.blockers, ['public-key-required']);
  assert.deepEqual(projected.observedCompletedChecks, ['sbom']);
});

test('result book does not accept arbitrary case names/status/error text', () => {
  const book = new ResultBook();
  book.record('llm_generation', 'BLOCKED', 'KEY_ABSENT', { token: 'SYNTHETIC_PRIVATE_MARKER' });
  book.record('cancel', 'INCONCLUSIVE', 'CANCEL_RACE');
  assert.equal(book.evidence().cases.llm_generation.status, 'BLOCKED');
  assert.equal(JSON.stringify(book.evidence()).includes('SYNTHETIC_PRIVATE_MARKER'), false);
  assert.throws(() => book.record('raw-message', 'PASS', 'VERIFIED'));
  assert.throws(() => book.record('cancel', 'PASS', 'raw-message'));
  assert.throws(() => book.record('cancel', 'SUCCESS', 'VERIFIED'));
  book.record('ownership', 'BLOCKED', 'ASSERTION_FAILED');
  book.record('ownership', 'PASS', 'VERIFIED');
  assert.equal(book.evidence().cases.ownership.status, 'BLOCKED');
  assert.equal(book.evidence().cases.ownership.failure, true);
});

test('offline entrypoints do not launch browser, access stand or write evidence', () => {
  const script = fileURLToPath(new URL('./public-product-live.mjs', import.meta.url));
  const env = Object.fromEntries(['PATH', 'HOME', 'TMPDIR', 'LANG', 'TZ', 'SystemRoot'].filter(key => process.env[key] !== undefined).map(key => [key, process.env[key]]));
  for (const [args, expected] of [[['--self-test'], 0], [[], 2], [['--run'], 2]]) {
    const result = spawnSync(process.execPath, [script, ...args], { env, timeout: 10000, encoding: 'utf8' });
    assert.equal(result.status, expected); assert.equal(result.stderr, '');
    const value = JSON.parse(result.stdout); assert.equal(value.browserLaunched, false);
    if (args[0] === '--self-test') { assert.equal(value.networkRequests, 0); assert.equal(value.evidenceWritten, false); }
  }
});

test('native single-process TS imports resolve actual decoder and existing chat contracts offline', async () => {
  const { decoder, view, metadata, chat } = await loadContracts();
  for (const name of ['parseCurrentStatus', 'parseCurrentResults', 'parseCurrentSbom', 'parseCurrentVuln', 'parseCurrentList']) assert.equal(typeof decoder[name], 'function');
  assert.equal(typeof metadata.validateCveMetadata, 'function');
  assert.equal(view.reportViewSearch('sbom', { view: 'report-v1', limit: 5, sort: 'name:asc', ecosystem: 'npm' }), 'view=report-v1&limit=5&sort=name%3Aasc&ecosystem=npm');
  for (const name of ['chatReadinessSchema', 'chatContextSchema', 'chatHistorySchema']) assert.equal(typeof chat[name].parse, 'function');
  assert.throws(() => decoder.parseCurrentStatus({ scanId: id, state: 'completed', profile: 'public-hub-amd64-v1' }));
});

test('mutations reject query overrides, injected authorization and non-browser/non-JSON requests', () => {
  const url = `${ORIGIN}${SCANS}`, headers = { origin: ORIGIN, 'content-type': 'application/json' };
  assert.ok(safeMutationRequest(url, headers));
  for (const value of [url + '?model=other', 'http://127.0.0.1:8080/api/v1/browser/scans']) assert.equal(safeMutationRequest(value, headers), false);
  for (const value of [{}, { ...headers, origin: 'http://localhost:8081' }, { ...headers, 'content-type': 'text/plain' }, { ...headers, authorization: 'SYNTHETIC' }, { ...headers, 'Proxy-Authorization': 'SYNTHETIC' }, { ...headers, 'x-api-key': 'SYNTHETIC' }]) assert.equal(safeMutationRequest(url, value), false);
});

test('browser has a deny-by-default proxy fence for redirect hops and other loopback ports', () => {
  assert.ok(BROWSER_ARGS.includes('--proxy-server=http://public-product-denied.invalid:1'));
  assert.ok(BROWSER_ARGS.includes('--proxy-bypass-list=<-loopback>;127.0.0.1:8081'));
  assert.ok(BROWSER_ARGS.includes('--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1'));
  assert.equal(BROWSER_ARGS.includes('--no-proxy-server'), false);
});

test('denied replies cannot pass with HTML, oversized/null JSON, nested data or extra payloads', () => {
  assert.doesNotThrow(() => assertDeniedReply({ status: 401, value: { errorCode: 'UNAUTHORIZED' } }, 401));
  assert.doesNotThrow(() => assertDeniedReply({ status: 404, value: { statusCode: 404, message: 'Not Found', error: 'Not Found' } }, 404));
  assert.doesNotThrow(() => assertDeniedReply({ status: 404, value: { errorCode: 'LLM_UNAVAILABLE' } }, 404));
  for (const value of [null, '<html>not found</html>', [], { errorCode: 'LLM_UNAVAILABLE', findings: [] }, { error: { turns: [] } }, { errorCode: 'ARBITRARY_PRIVATE_MESSAGE' }]) assert.throws(() => assertDeniedReply({ status: 404, value }, 404));
  assert.throws(() => assertDeniedReply({ status: 200, value: { errorCode: 'LLM_UNAVAILABLE' } }, 404));
});

test('quota unchanged cannot pass by comparing missing vectors or unavailable snapshots', () => {
  const binding = { scanId: id, digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64', reportVersion: 'b'.repeat(64) };
  const vector = n => ({ input: n, output: n, costMicros: 0 });
  const scope = () => ({ limits: vector(100), used: vector(10), held: vector(0), carried: vector(0), remaining: vector(90) });
  const value = { ...binding, available: true, admission: { status: 'unavailable' }, window: { start: 0, end: 86400000 }, user: scope(), scan: scope() };
  assert.doesNotThrow(() => assertChatUsage(value, binding));
  for (const mutation of [{ available: false }, { user: undefined }, { scan: {} }, { window: undefined }, { reportVersion: 'c'.repeat(64) }, { admission: { status: 'fits' } }]) assert.throws(() => assertChatUsage({ ...value, ...mutation }, binding));
  const missing = structuredClone(value); delete missing.user.used; assert.throws(() => assertChatUsage(missing, binding));
  const wrong = structuredClone(value); wrong.scan.remaining.input++; assert.throws(() => assertChatUsage(wrong, binding));
  const invalid = structuredClone(value); invalid.user.held.input = -1; assert.throws(() => assertChatUsage(invalid, binding));
  assert.throws(() => assertChatUsage(null, binding));
});

test('render checks bind every row identity/content, not only the number of rows', () => {
  assert.notDeepEqual(renderedRowParts('sbom', { name: 'one', version: '1', ecosystem: 'npm' }), renderedRowParts('sbom', { name: 'one', version: '2', ecosystem: 'npm' }));
  assert.notDeepEqual(renderedRowParts('secret', { ruleId: 'rule-a', findingId: 'one', line: 1 }), renderedRowParts('secret', { ruleId: 'rule-a', findingId: 'two', line: 1 }));
  const row = { cveId: 'CVE-2026-1234', findingId: 'one', packageName: 'one', installedVersion: '1', severity: 'HIGH' };
  assert.notDeepEqual(renderedRowParts('vuln', row), renderedRowParts('vuln', { ...row, findingId: 'two' }));
});

test('one paginated dataset does not qualify all three; no checked subset is not preservation PASS', () => {
  assert.equal(paginationVerdict(1, 3).status, 'INCONCLUSIVE'); assert.equal(paginationVerdict(3, 3).status, 'PASS');
  const before = { perCheck: { secret: { outcome: 'failed' }, config: { outcome: 'checked' } } };
  assert.equal(preservationVerdict(before, ['secret'], {}, false).status, 'INCONCLUSIVE');
  assert.equal(preservationVerdict(before, ['config'], {}, false).status, 'PASS');
  assert.equal(preservationVerdict(before, ['config'], {}, true).status, 'INCONCLUSIVE');
  assert.equal(preservationVerdict({ perCheck: { secret: { outcome: 'checked' } } }, ['secret'], {}, false).status, 'INCONCLUSIVE');
});

test('evidence files are both acquired first, provisional Markdown precedes final JSON', async () => {
  const book = new ResultBook(), events = []; let index = 0;
  await writeEvidence(book.evidence(), async (_path, mode, permissions) => {
    assert.equal(mode, 'wx'); assert.equal(permissions, 0o600);
    const n = index++; events.push(`open${n}`);
    return { writeFile: async () => { events.push(`write${n}`); }, sync: async () => { events.push(`sync${n}`); }, close: async () => { events.push(`close${n}`); } };
  });
  assert.deepEqual(events.slice(0, 6), ['open0', 'open1', 'write1', 'sync1', 'write0', 'sync0']);
  const [json, md] = evidenceDocuments(book.evidence());
  assert.equal(JSON.parse(json).runId, book.runId); assert.ok(md.includes('Provisional summary only'));
});

test('second evidence-path collision and Markdown failure do not write a passing JSON', async () => {
  let opens = 0, writes = 0, closes = 0;
  await assert.rejects(writeEvidence(new ResultBook().evidence(), async () => {
    if (opens++) throw new Error('synthetic collision');
    return { writeFile: async () => { writes++; }, sync: async () => {}, close: async () => { closes++; } };
  }));
  assert.equal(writes, 0); assert.equal(closes, 1);
  let index = 0; const events = [];
  await assert.rejects(writeEvidence(new ResultBook().evidence(), async () => {
    const n = index++;
    return { writeFile: async () => { events.push(n); throw new Error('synthetic write failure'); }, sync: async () => {}, close: async () => {} };
  }));
  assert.deepEqual(events, [1]);
});

test('evidence close failure is not silently accepted as a successful write', async () => {
  await assert.rejects(writeEvidence(new ResultBook().evidence(), async () => ({
    writeFile: async () => {}, sync: async () => {}, close: async () => { throw new Error('synthetic close failure'); },
  })));
});

test('native mutation guard obtains complete headers, not the security-redacted headers shortcut', () => {
  const source = readFileSync(new URL('./public-product-live.mjs', import.meta.url), 'utf8');
  assert.ok(source.includes('const headers = await request.allHeaders();'));
  assert.equal(source.includes('safeMutationRequest(request.url(), request.headers())'), false);
  assert.ok(source.includes('stopped || fatalCode || !safeMutationRequest(request.url(), headers)'));
});

test('runner source has no response mocking, saved browser state, lifecycle or historical holders', () => {
  const source = readFileSync(new URL('./public-product-live.mjs', import.meta.url), 'utf8');
  for (const pattern of [/route\.fulfill\s*\(/, /\.addCookies\s*\(/, /storageState\s*:/, /\.screenshot\s*\(/, /\.tracing\./, /recordHar\s*:/, /recordVideo\s*:/, /\bspawn\s*\(/, /docker (?:run|exec|start|stop|cp|inspect|compose)/, /\.local-auth/, /privateEnv/, /task16-chat-browser/]) assert.equal(pattern.test(source), false);
  assert.ok(GLOBAL_MS > WORKER_MS * 3 && GLOBAL_MS <= 45 * 60000);
});
