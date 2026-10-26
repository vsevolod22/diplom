// OFFLINE ONLY: synthetic transport/locator fixtures, never browser/runtime/provider initialization.
import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { readFileSync, readdirSync } from 'node:fs';
import {
  CASES, GLOBAL_MS, WORKER_MS, parseMode, evidencePaths, assertFreshAttempt, browserGetAllowed,
  ResultBook, exitCode, evidenceDocuments, writeEvidence, generationMetadata, generationKind,
  GenerationGate, summaryBody, readGeneration, estimateSample, savePreferences,
    automationDisclosureMatches, summaryMissing, passiveSummaryValue, assertSummaryRestored,
        FAILURE_PREDICATES, SUMMARY_DRAIN_MS, automationMeta, failureMetadata, checkPredicate, parseBoundReport, collectAdmittedSummary,
} from './public-automation-live.mjs';
import {
  MODEL, ENDPOINT, diagnosticFromHeaders, llmFailureMeta, projectMeta,
  DIAGNOSTIC_PHASES, DIAGNOSTIC_REASONS, loadTranslationContracts, translationBody,
} from './public-ai-translation-live.mjs';
import { ORIGIN, SCANS, CHECKS, TARGETS, readAllPages } from './public-product-live.mjs';
const scanId = randomUUID(), attemptId = randomUUID();
const binding = { scanId, digest: `sha256:${'b'.repeat(64)}`, platform: 'linux/amd64', reportVersion: 'c'.repeat(64) };
const context = { ...binding, enabled: true, epoch: randomUUID(), revision: 0, policyVersion: 'd'.repeat(64),
  findingId: `vuln-${'a'.repeat(64)}`, assessmentIndex: 0, sourceVersion: 'e'.repeat(64), targetLanguage: 'ru',
  disclosure: { provider: 'OpenRouter', model: MODEL, providers: [ENDPOINT], freeOnly: true, requestBudgetUsd: 0,
    retention: 'no-storage', region: 'global', maxPrice: { prompt: 0, completion: 0, request: 0 },
    operatorApprovedRouting: true, providerComplianceNotProvenByDeclaration: true,
        data: 'Sanitized scanner findings and coverage; no raw evidence or credentials.' } };
    const translationDisclosure = { ...context.disclosure,
      data: 'Only the selected normalized advisory title and description eligible for translation; no other report metadata, package data, history, raw evidence or credentials. Identifiers within the selected text remain unchanged.',
      targetLanguage: 'ru', machineTranslation: true, automaticDispatch: 'account-preference', persistentTranslationCache: false };
    const readiness = { ...binding, status: 'locally-configured', localReady: true, credential: 'metadata-valid', blockers: [],
      quota: 'available', history: 'available', generationVerified: false, requiresConsent: true, acceptsCredentials: false,
      setupAction: 'operator-public-file-configuration', provider: { status: 'catalog-listed-unprobed', checkedOn: '2026-10-21',
        liveVerified: false, model: MODEL, endpoint: ENDPOINT, zdrListed: true } };
    const summaryHeaders = { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-llm-summary-retention': 'process-lifetime' };
    const missingSummary = () => ({ status: 404, value: { errorCode: 'LLM_SUMMARY_MISSING' }, headers: summaryHeaders });
const question = 'Синтетический вопрос о покрытии';
const chatBody = () => ({ epoch: context.epoch, revision: context.revision, mutationId: randomUUID(),
  reportVersion: context.reportVersion, question, consent: { accepted: true, policyVersion: context.policyVersion } });
const pathFor = kind => `${SCANS}/${scanId}/llm/${kind}`;
function admission(kind, patch = {}) {
  const body = kind === 'summary' ? summaryBody(context) : kind === 'chat' ? chatBody() : translationBody(context);
  const permit = { kind, path: pathFor(kind), used: false, question, matches: value => JSON.stringify(value) === JSON.stringify(body) };
  const report = { ...binding, state: 'completed', perCheck: Object.fromEntries(CHECKS.map(check => [check, { outcome: 'checked' }])) };
  return { owner: true, scanId, path: pathFor(kind), body, permit,
      context: kind === 'translation' ? { ...context, disclosure: translationDisclosure } : context,
      readiness, passiveSummary: missingSummary(), completed: true, report,
    preferences: { language: kind === 'translation' ? 'ru' : 'original', autoSummary: true }, ...patch };
}
const source = () => readFileSync(new URL('./public-automation-live.mjs', import.meta.url), 'utf8');
const response = (status, value, headers = {}, requestBody = {}) => ({ status: () => status,
  headers: () => headers, body: async () => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)),
  request: () => ({ postDataJSON: () => requestBody }) });

test('default/import/preflight are inert; exact READYGO + deployed-source + four-post acknowledgements only', () => {
  assert.equal(parseMode([]), 'not-run'); assert.equal(parseMode(['--preflight']), 'offline');
  const flags = ['--run', '--ack-coordinator-readygo', '--ack-four-generation-posts', '--ack-source-deployed', '--attempt-id', attemptId];
  assert.equal(parseMode(flags), 'live');
  for (let index = 0; index < flags.length; index++) assert.throws(() => parseMode(flags.filter((_, i) => i !== index)));
  for (const args of [['--run'], [...flags, '--retry'], [...flags, '--translation-only'], ['--self-test'],
    [...flags.slice(0, 5), '../attempt'], [...flags.slice(0, 5), 'attempt2'], [...flags.slice(0, 5), '29f3a78d-9455-1131-b29a-45aca5c2c657']]) assert.throws(() => parseMode(args));
  const docs = new URL('../docs/', import.meta.url), before = readdirSync(docs).sort();
  for (const args of [[], ['--run'], ['--preflight']]) {
    const run = spawnSync(process.execPath, [new URL('./public-automation-live.mjs', import.meta.url).pathname, ...args], { encoding: 'utf8', timeout: 20_000 });
    assert.equal(run.status, args.includes('--preflight') ? 0 : 2); assert.equal(run.stderr, '');
    const value = JSON.parse(run.stdout); assert.equal(value.actuallyRun, false);
    if (args.includes('--preflight')) assert.deepEqual({ browser: value.browserLaunched, network: value.networkRequests, evidence: value.evidenceWritten }, { browser: false, network: 0, evidence: false });
  }
  const imported = spawnSync(process.execPath, ['--input-type=module', '-e', `await import(${JSON.stringify(new URL('./public-automation-live.mjs', import.meta.url).href)})`], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(imported.status, 0); assert.equal(imported.stdout, ''); assert.equal(imported.stderr, '');
  assert.deepEqual(readdirSync(docs).sort(), before);
});

test('fresh v4 UUID-only destinations refuse historical IDs across evidence namespaces, without reading payloads', () => {
  assert.equal(evidencePaths(attemptId).length, 2);
  assert.ok(evidencePaths(attemptId).every(path => path.includes(`public-automation-${attemptId}`)));
  assert.doesNotThrow(() => assertFreshAttempt(attemptId, ['public-ai-live-20261022.json']));
  for (const prefix of ['public-automation-', 'public-final-', 'public-final-ownership-'])
    assert.throws(() => assertFreshAttempt(attemptId, [`${prefix}${attemptId}-ai-translation.json`]));
  assert.throws(() => evidencePaths('attempt2')); assert.throws(() => evidencePaths('../private'));
  const book = new ResultBook(attemptId); assert.notEqual(book.runId, attemptId);
});

test('exact existing GET allowlist plus finite browser navigation/assets, not a local or API prefix bypass', () => {
  const ids = new Set([scanId]);
  for (const path of ['/account', `/scans/${scanId}`, '/assets/index-AbC123.js', '/api/v1/auth/me', `${pathFor('chat')}/context`,
    `${SCANS}/${scanId}/llm/context`, pathFor('summary'), `${SCANS}/${scanId}/llm/translation/context?findingId=${context.findingId}&assessmentIndex=0`])
    assert.equal(browserGetAllowed(`${ORIGIN}${path}`, ids), true, path);
  for (const url of ['http://127.0.0.1:8080/account', 'https://openrouter.ai/api/v1/chat/completions',
    `${ORIGIN}/anything`, `${ORIGIN}/account?token=private`, `${ORIGIN}/assets/../../private`, `${ORIGIN}/api/v1/admin`,
    `${ORIGIN}/scans/${randomUUID()}`, `${ORIGIN}${pathFor('summary')}?`, `${ORIGIN}${pathFor('summary')}/extra`, `${ORIGIN}${pathFor('translation')}`, `${ORIGIN}${pathFor('chat')}?x=1`,
    `${ORIGIN}/api/v1/browser/runtime/targets?extra=1`, `${ORIGIN}${pathFor('translation')}/context?findingId=${context.findingId}&assessmentIndex=0&extra=1`])
    assert.equal(browserGetAllowed(url, ids), false, url);
});

test('operation identity rejects other scans, suffix lookalikes, query strings and extra segments', () => {
  for (const kind of ['summary', 'chat', 'translation']) {
    assert.equal(generationKind(pathFor(kind), scanId), kind);
        for (const method of ['GET', 'HEAD', 'PUT', 'DELETE']) assert.equal(generationKind(pathFor(kind), scanId, method), undefined);
    for (const path of [pathFor(kind) + '/extra', pathFor(kind) + '?retry=1', '/other' + pathFor(kind), pathFor(kind).replace(scanId, randomUUID())])
      assert.equal(generationKind(path, scanId), undefined);
  }
});

test('one summary, sequential successful chat1/chat2 and one selected translation, total at most four', () => {
  const gate = new GenerationGate();
  assert.equal(gate.admit(admission('summary')), true);
  assert.equal(gate.admit(admission('chat')), false); // Still in flight, even with a valid next permit.
  gate.finish(); assert.equal(gate.admit(admission('summary')), false);
  assert.equal(gate.admit(admission('chat')), true); gate.finish();
  assert.equal(gate.admit(admission('chat')), false); // Delivery/history success has not been established.
  gate.chatSuccesses++; assert.equal(gate.admit(admission('chat')), true); gate.finish(); gate.chatSuccesses++;
  assert.equal(gate.admit(admission('translation')), true); gate.finish();
  for (const kind of ['summary', 'chat', 'translation']) assert.equal(gate.admit(admission(kind)), false);
  assert.deepEqual(generationMetadata(gate), { total: 4, summaryPosts: 1, chatPosts: 2, translationPosts: 1, halted: false });
});

test('automatic permits require completed owner/report, explicit saved preferences, exact bodies and current fixed policy', () => {
  for (const kind of ['summary', 'chat', 'translation']) {
    for (const patch of [{ owner: false }, { completed: false }, { report: null }, { report: { ...binding, state: 'running' } },
          { report: { ...binding, state: 'completed', perCheck: { secret: { outcome: 'checked' } } } },
          { report: { ...admission(kind).report, digest: `sha256:${'f'.repeat(64)}` } },
          { permit: null }, { context: null }, { path: pathFor(kind) + '/hidden' },
      { context: { ...context, scanId: randomUUID() } }, { context: { ...context, disclosure: { ...context.disclosure, freeOnly: false } } }]) {
      const gate = new GenerationGate(), input = admission(kind, patch); assert.equal(gate.admit(input), false); assert.equal(gate.total, 0);
    }
    for (const mutation of [value => ({ ...value, text: 'private' }), value => ({ ...value, apiKey: 'private' }),
      value => ({ ...value, consent: { accepted: false, policyVersion: context.policyVersion } }),
      value => ({ ...value, consent: { accepted: true, policyVersion: 'f'.repeat(64) } }),
      value => ({ ...value, reportVersion: 'f'.repeat(64) })]) {
      const input = admission(kind); input.body = mutation(input.body); input.permit.matches = () => true;
      assert.equal(new GenerationGate().admit(input), false);
    }
    const input = admission(kind); input.permit.used = true; assert.equal(new GenerationGate().admit(input), false);
    input.permit.used = false; input.permit.path += '/other'; assert.equal(new GenerationGate().admit(input), false);
  }
  for (const kind of ['summary', 'translation']) {
    assert.equal(new GenerationGate().admit(admission(kind, { preferences: null })), false);
    assert.equal(new GenerationGate().admit(admission(kind, { preferences: { language: kind === 'summary' ? 'ru' : 'original', autoSummary: true } })), false);
  }
  assert.equal(new GenerationGate().admit(admission('summary', { preferences: { language: 'original', autoSummary: false } })), false);
  const stale = admission('chat'); stale.body.revision++; stale.permit.matches = () => true; assert.equal(new GenerationGate().admit(stale), false);
  const wrongSource = admission('translation'); wrongSource.body.sourceVersion = 'f'.repeat(64); wrongSource.permit.matches = () => true; assert.equal(new GenerationGate().admit(wrongSource), false);
});

test('429/503 permanently close all automatic, queued and manual generation lanes, even malformed provider metadata', () => {
  for (const [status, value] of [[429], [503], [200, { providerFailure: { status: 429, private: 'SYNTHETIC_PRIVATE' } }],
    [502, { providerFailure: { status: 503, kind: 'invalid' } }], [200, { errorCode: 'LLM_PROVIDER_RATE_LIMITED' }]]) {
    const gate = new GenerationGate(); assert.equal(gate.admit(admission('summary')), true);
    gate.observe(status, value); gate.finish(); assert.equal(gate.halted, true);
    for (const kind of ['summary', 'chat', 'translation']) assert.equal(gate.admit(admission(kind)), false);
    gate.observe(200, {}); gate.finish(); assert.equal(gate.halted, true);
  }
});

test('real completed-reply NDJSON parser catches HTTP200 terminal 429/503 before releasing the generation lock', async () => {
  const { chat } = await loadTranslationContracts();
  for (const status of [429, 503]) {
    const gate = new GenerationGate(), input = admission('chat'); assert.equal(gate.admit(input), true);
    const frame = { ...binding, v: 1, deliveryMode: 'validated-completed-reply', nativeProviderStream: false,
      epoch: context.epoch, revision: 2, mutationId: input.body.mutationId, turnId: randomUUID(), type: 'error', seq: 0,
      receipt: 'unavailable', errorCode: 'LLM_PROVIDER_RATE_LIMITED', providerFailure: { kind: 'rate_limited', status } };
    await assert.rejects(readGeneration(response(200, JSON.stringify(frame) + '\n', { 'content-type': 'application/x-ndjson',
      'x-llm-failure-phase': 'headers', 'x-llm-failure-reason': 'http_error' }, input.body), gate, chat, context), error => {
      assert.deepEqual(error.meta, { httpStatus: 200, errorCode: 'LLM_PROVIDER_RATE_LIMITED', providerFailure: { kind: 'rate_limited', status },
        providerDiagnostic: { phase: 'headers', reason: 'http_error' }, deliveryKind: 'ndjson-error' }); return true;
    });
    assert.equal(gate.halted, true); assert.equal(gate.busy, false);
    assert.equal(gate.admit(admission('translation')), false); assert.equal(gate.admit(admission('summary')), false);
  }
});

test('automatic summary/translation errors preserve only finite response-header diagnostics; no retry on invalid output', async () => {
  for (const kind of ['summary', 'translation']) for (const status of [429, 503, 502]) {
    const gate = new GenerationGate(); assert.equal(gate.admit(admission(kind)), true);
    const value = { errorCode: status === 502 ? 'LLM_INVALID_RESPONSE' : 'LLM_PROVIDER_RATE_LIMITED', message: 'SYNTHETIC_PRIVATE',
      providerDiagnostic: { phase: 'tls', reason: 'io_error' }, ...(status === 502 ? {} : { providerFailure: { kind: 'rate_limited', status } }) };
    await assert.rejects(readGeneration(response(status, value, { 'x-llm-failure-phase': 'translation_title', 'x-llm-failure-reason': 'identifier_mismatch' }), gate), error => {
      assert.deepEqual(error.meta.providerDiagnostic, { phase: 'translation_title', reason: 'identifier_mismatch' });
      assert.equal(JSON.stringify(error.meta).includes('SYNTHETIC_PRIVATE'), false); return true;
    });
    assert.equal(gate.halted, true); assert.equal(gate.busy, false); assert.equal(gate.admit(admission('chat')), false);
  }
  for (const value of ['not-json', '{"reply":"private"}\nnot-json']) {
    const gate = new GenerationGate(); gate.busy = true;
    await assert.rejects(readGeneration(response(200, value), gate)); assert.equal(gate.halted, true);
  }
  const gate = new GenerationGate(); await assert.rejects(readGeneration(null, gate)); assert.equal(gate.halted, true);
});

test('new finite phase/reason exports match backend completely and survive only headers, not body-forged diagnostics', async () => {
  const { diagnostics } = await loadTranslationContracts();
  assert.deepEqual(DIAGNOSTIC_PHASES, [...diagnostics.FAILURE_PHASES]); assert.deepEqual(DIAGNOSTIC_REASONS, [...diagnostics.FAILURE_REASONS]);
  for (const phase of ['translation_title', 'translation_description']) for (const reason of ['null_mismatch', 'unsafe_text', 'invalid_markup',
    'identifier_mismatch', 'nonprose_changed', 'not_normalized', 'invalid_link']) {
    const safe = diagnosticFromHeaders({ 'x-llm-failure-phase': phase, 'x-llm-failure-reason': reason, authorization: 'PRIVATE' });
    assert.deepEqual(safe, { phase, reason });
    const book = new ResultBook(attemptId); book.record('translation', 'BLOCKED', 'LLM_HTTP_ERROR', llmFailureMeta(502, { errorCode: 'LLM_INVALID_RESPONSE' }, 'http-error', safe));
    assert.deepEqual(book.evidence().cases.translation.providerDiagnostic, safe);
    assert.equal(llmFailureMeta(502, { providerDiagnostic: safe }).providerDiagnostic, undefined);
    assert.equal(diagnosticFromHeaders({ 'x-llm-failure-phase': phase + ',PRIVATE', 'x-llm-failure-reason': reason }), undefined);
  }
});

test('preferences save is an explicit UI gesture and disclosure precedes save; no storage/session injection', async () => {
  const events = [];
  const panel = {
    count: async () => 1, locator: () => ({ kind: 'disclosure' }),
    getByLabel: label => ({ selectOption: async value => events.push([label, value]) }),
    getByRole: (role, options) => role === 'button' ? { click: async () => events.push(['click', options.name]) } : { kind: 'status' },
  };
  const page = { getByRole: (role, options) => { assert.equal(role, 'region'); assert.equal(options.name, 'Язык и сводка отчётов'); return panel; } };
  const expect = locator => ({ toBeVisible: async () => events.push(['visible']),
    toContainText: async () => { assert.equal(locator.kind, 'disclosure'); events.push(['disclosure']); },
    toHaveText: async () => { assert.equal(locator.kind, 'status'); events.push(['saved']); } });
  assert.deepEqual(await savePreferences(page, expect, 'original', true), { language: 'original', autoSummary: true });
  assert.deepEqual(events, [['visible'], ['disclosure'], ['Язык отчёта', 'original'], ['Краткая ИИ-сводка', 'on'], ['click', 'Сохранить настройки отчётов'], ['saved']]);
});

test('estimated progress is explicitly approximate, running-only, bounded below 100 and has no fabricated ETA', () => {
  const sample = { state: 'running', value: 12, text: 'Оценка прогресса: ≈12%. Точное оставшееся время неизвестно.' };
  assert.equal(estimateSample(sample), true);
  for (const patch of [{ state: 'completed' }, { state: 'queued' }, { value: 100 }, { value: -1 }, { value: NaN }, { text: 'Прогресс: 12%' }])
    assert.equal(estimateSample({ ...sample, ...patch }), false);
});

test('every case is required; cache misses and single-account limits stay explicitly BLOCKED, not accepted', () => {
  const book = new ResultBook(attemptId); assert.equal(exitCode(book), 2);
  for (const name of CASES) book.record(name, 'PASS'); assert.equal(exitCode(book), 0);
  book.record('settings_owner_isolation', 'BLOCKED', 'SECOND_OWNER_NOT_AUTHORIZED'); assert.equal(exitCode(book), 2);
  book.record('summary_reload_restore', 'BLOCKED', 'SUMMARY_NOT_RESTORED'); assert.equal(exitCode(book), 2);
  book.record('safety', 'FAIL', 'REQUEST_GUARD'); book.record('safety', 'PASS'); assert.equal(exitCode(book), 1);
  assert.equal(book.evidence().cases.safety.status, 'FAIL');
  assert.equal(book.evidence().semanticAccuracy, 'unverified-requires-memory-only-human-review');
});

test('sanitized evidence excludes answers, source strings, auth artifacts and arbitrary diagnostics; finite counts include summary', () => {
  const marker = 'SYNTHETIC_PRIVATE'; const book = new ResultBook(attemptId);
  const gate = new GenerationGate(); gate.admit(admission('summary')); book.generation = gate;
  book.record('summary', 'PASS', 'VERIFIED', { text: marker, reply: marker, hypotheses: [marker], password: marker, JWT: marker,
    storageState: marker, diagnostic: marker, httpStatus: 200, costMicros: 0 });
  book.cases.summary.payload = marker; gate.payload = marker;
  assert.equal(evidenceDocuments(book).join('').includes(marker), false);
  assert.deepEqual(book.evidence().generationAdmissions, { total: 1, summaryPosts: 1, chatPosts: 0, translationPosts: 0, halted: false });
  assert.deepEqual(projectMeta({ text: marker, selectedSource: marker, JWT: marker }), {});
});

test('evidence writes only after actual contact, using fresh exclusive 0600 files; fixture writer never touches disk', async () => {
  const book = new ResultBook(attemptId), writes = [], opens = [];
  const writer = async (path, flags, mode) => { opens.push({ path, flags, mode }); return {
    writeFile: async text => writes.push(text), sync: async () => {}, close: async () => {},
  }; };
  await assert.rejects(writeEvidence(book, writer)); assert.equal(opens.length, 0);
  book.actual = true; await writeEvidence(book, writer);
  assert.deepEqual(opens.map(item => [item.flags, item.mode]), [['wx', 0o600], ['wx', 0o600]]);
  assert.deepEqual(opens.map(item => item.path), evidencePaths(attemptId)); assert.equal(writes.length, 2);
  assert.equal(JSON.parse(writes[1]).actuallyRun, true);
});

async function publicWireProof() {
  const { decoder, view } = await loadTranslationContracts();
  const fixture = compileFrontend('../tests-vite/ui/scans/reportViewSynthetic.ts');
  const queries = compileFrontend('../server/api/src/scans/report-query.ts');
  const pages = compileFrontend('../server/api/src/scans/report-page.ts', { './report-query.js': queries });
  const scannerVersion = '0.69.3', checkedAt = fixture.checkedAt, imageReference = `registry-1.docker.io/library/node@${binding.digest}`;
  const coverage = count => ({ check: 'secret', coverage: 'image', outcome: 'checked', findingCount: count,
    errorCode: null, scannerVersion, checkedAt });
  const snapshot = { ...binding, imageReference, profile: 'public-hub-amd64-v1', state: 'completed',
    identifierCounts: { cve: fixture.vulnRows.length, debianTemp: 0 }, perCheck: {
      secret: coverage(fixture.secretRows.length), vuln: { check: 'vuln', coverage: 'image', outcome: 'checked',
        findingCount: fixture.vulnRows.length, scannerVersion, checkedAt } } };
  const wire = (kind, query, cursor, rows = kind === 'secret' ? fixture.secretRows : fixture.vulnRows) => {
    const parsed = queries.parseReportQuery(kind, Object.fromEntries(new URLSearchParams(view.reportViewSearch(kind, query, cursor))));
    const source = kind === 'secret' ? { findings: rows, coverage: coverage(rows.length) }
      : { outcome: 'checked', coverage: 'image', profile: snapshot.profile, image: imageReference, platform: snapshot.platform,
        findingCount: rows.length, identifierCounts: { cve: rows.length, debianTemp: 0 }, scannerVersion, checkedAt,
        ...fixture.v2Evidence(), findings: rows };
    const { items, ...paging } = (kind === 'secret' ? pages.pageSecrets : pages.pageVuln)(rows, parsed, { subject: 'controlled-owner', scanId }, source);
    return { ...source, findings: items, ...paging };
  };
  return { decoder, snapshot, wire };
}

test('root proof: real backend report paging + real decoder retain vuln identity but Secrets has no image/platform', async () => {
  const { decoder, snapshot, wire } = await publicWireProof();
  const vulnQuery = { view: 'report-v1', limit: 50, sort: 'severity:desc' }, secretQuery = { view: 'report-v1', limit: 50, sort: 'ruleId:asc' };
  const vulnWire = wire('vuln', vulnQuery), secretWire = wire('secret', secretQuery);
  const vuln = decoder.parseCurrentVuln(vulnWire, vulnQuery), secret = decoder.parseCurrentResults(secretWire, secretQuery);
  assert.equal(vuln.image, snapshot.imageReference); assert.equal(vuln.platform, snapshot.platform);
  assert.equal(Object.hasOwn(secretWire, 'image'), false); assert.equal(Object.hasOwn(secretWire, 'platform'), false);
  assert.equal(Object.hasOwn(secret, 'image'), false); assert.equal(Object.hasOwn(secret, 'platform'), false);
  // Reproduce the exact old predicates against accepted real-wire shapes, not guessed pinned/tag conversions.
  assert.throws(() => assert.equal(secret.image, snapshot.imageReference), { code: 'ERR_ASSERTION' });
  assert.throws(() => assert.equal(secret.platform, snapshot.platform), { code: 'ERR_ASSERTION' });
  assert.deepEqual(parseBoundReport('secret', secretWire, snapshot, secretQuery, undefined, decoder), secret);
  assert.deepEqual(parseBoundReport('vuln', vulnWire, snapshot, vulnQuery, undefined, decoder), vuln);
  const prior = readFileSync(new URL('./public-product-live.mjs', import.meta.url), 'utf8');
  assert.ok(prior.includes("kind === 'secret' ? response.value.coverage : value"));
  assert.ok(prior.includes("if (kind !== 'secret') { assert.equal(value.image, snapshot.imageReference)"));
});

test('correct report predicates keep complete real cursor walks and checked-zero Secrets without inventing identity fields', async () => {
  const { decoder, snapshot, wire } = await publicWireProof();
  for (const kind of ['secret', 'vuln']) {
    const query = { view: 'report-v1', limit: 5, sort: kind === 'secret' ? 'ruleId:asc' : 'severity:desc' };
    const result = await readAllPages(kind, { whole: 30, matched: 30 }, async cursor => parseBoundReport(kind, wire(kind, query, cursor), snapshot, query, cursor, decoder));
    assert.equal(result.rows.length, 30); assert.equal(result.pages, 6);
  }
  const query = { view: 'report-v1', limit: 50, sort: 'ruleId:asc' }, zero = wire('secret', query, undefined, []);
  const emptySnapshot = { ...snapshot, perCheck: { ...snapshot.perCheck, secret: { ...snapshot.perCheck.secret, findingCount: 0 } } };
  assert.equal(parseBoundReport('secret', zero, emptySnapshot, query, undefined, decoder).coverage[0].findingCount, 0);
});

test('report binding is fail-closed on wrong target/profile/count/stamp/scanner and malformed wire, with finite predicate metadata', async () => {
  const { decoder, snapshot, wire } = await publicWireProof();
  for (const [kind, field, value, predicate] of [
    ['secret', 'scannerVersion', 'other', 'secret-scanner-version'], ['secret', 'checkedAt', '2026-01-03T00:00:00.000Z', 'secret-checked-at'],
    ['secret', 'findingCount', 31, 'secret-count'], ['vuln', 'imageReference', `registry-1.docker.io/library/other@${binding.digest}`, 'vuln-target-image'],
    ['vuln', 'platform', 'linux/arm64', 'vuln-target-platform'], ['vuln', 'profile', 'other', 'vuln-profile'],
  ]) {
    const query = { view: 'report-v1', limit: 50, sort: kind === 'secret' ? 'ruleId:asc' : 'severity:desc' };
    const changed = kind === 'secret' ? { ...snapshot, perCheck: { ...snapshot.perCheck, secret: { ...snapshot.perCheck.secret, [field]: value } } } : { ...snapshot, [field]: value };
    assert.throws(() => parseBoundReport(kind, wire(kind, query), changed, query, undefined, decoder), error => {
      assert.equal(error.message, 'ASSERTION_FAILED'); assert.equal(error.failure, true);
      assert.equal(error.meta.predicate, predicate); assert.ok(failureMetadata(error).runnerLine > 0); return true;
    });
  }
  for (const kind of ['secret', 'vuln']) {
    const query = { view: 'report-v1', limit: 50, sort: kind === 'secret' ? 'ruleId:asc' : 'severity:desc' };
    assert.throws(() => parseBoundReport(kind, { private: 'SYNTHETIC_PRIVATE' }, snapshot, query, undefined, decoder), error => error.meta.predicate === `${kind}-decode`);
  }
});

test('failure metadata stores only bounded source line and finite predicate, never assertion values, stack or payload', () => {
  const error = new Error('SYNTHETIC_PRIVATE'); error.actual = 'SYNTHETIC_PRIVATE'; error.expected = 'SYNTHETIC_PRIVATE';
  error.stack = 'SYNTHETIC_PRIVATE public-automation-live.mjs:321:1\n at report (file:///controlled/tests-e2e/public-automation-live.mjs:588:7)';
  error.meta = { predicate: 'secret-checked-at', raw: 'SYNTHETIC_PRIVATE' };
  const meta = failureMetadata(error); assert.deepEqual(meta, { runnerLine: 588, predicate: 'secret-checked-at' });
  assert.deepEqual(automationMeta({ predicate: 'SYNTHETIC_PRIVATE', runnerLine: 100001, actual: 'SYNTHETIC_PRIVATE' }), {});
  const book = new ResultBook(attemptId); book.record('report', 'FAIL', 'ASSERTION_FAILED', meta);
  book.record('report', 'PASS', 'VERIFIED', { runnerLine: 1, predicate: 'vuln-target-image' });
  assert.deepEqual(book.evidence().cases.report, { status: 'FAIL', code: 'ASSERTION_FAILED', ...meta });
  assert.equal(evidenceDocuments(book).join('').includes('SYNTHETIC_PRIVATE'), false);
  assert.ok(FAILURE_PREDICATES.length < 32); assert.throws(() => checkPredicate(false, 'not-a-predicate'));
});

test('cleanup captures only an already-admitted pending summary before close, preserves first FAIL, and never qualifies/infers consumption', async () => {
  const gate = new GenerationGate(); assert.equal(gate.admit(admission('summary')), true); gate.halted = true;
  const book = new ResultBook(attemptId); book.record('report', 'FAIL', 'ASSERTION_FAILED', { predicate: 'secret-checked-at', runnerLine: 588 });
  const firstCases = structuredClone(book.cases), events = []; let complete;
  const pending = new Promise(resolve => { complete = () => { events.push('received'); resolve({ text: 'SYNTHETIC_PRIVATE', usage: { costMicros: 0 } }); }; });
  const closing = (async () => { await collectAdmittedSummary(book, gate, pending, 1000); events.push('close'); })();
  await new Promise(setImmediate); assert.deepEqual(events, []); complete(); await closing;
  assert.deepEqual(events, ['received', 'close']); assert.deepEqual(book.cases, firstCases);
  book.generation = gate;
  assert.deepEqual(book.evidence().admittedSummaryObservation, { admitted: true, consumption: 'UNKNOWN', capture: 'RESPONSE_RECEIVED', httpStatus: 200 });
  assert.equal(book.cases.summary.code, 'NOT_RUN'); assert.equal(exitCode(book), 1); assert.equal(gate.total, 1);
  for (const kind of ['summary', 'chat', 'translation']) assert.equal(gate.admit(admission(kind)), false);
  assert.equal(evidenceDocuments(book).join('').includes('SYNTHETIC_PRIVATE'), false);
});

test('bounded pending drain leaves unknown on timeout/missing promise; late completion cannot rewrite capture or dispatch', async () => {
  assert.equal(SUMMARY_DRAIN_MS, 45_000);
  const gate = new GenerationGate(); gate.admit(admission('summary')); gate.halted = true;
  const book = new ResultBook(attemptId); let complete;
  const pending = new Promise(resolve => { complete = resolve; });
  await collectAdmittedSummary(book, gate, pending, 5);
  const observation = structuredClone(book.summaryObservation);
  assert.equal(observation.capture, 'DELIVERY_UNKNOWN'); assert.equal(observation.consumption, 'UNKNOWN');
  complete({ text: 'SYNTHETIC_PRIVATE' }); await new Promise(setImmediate); assert.deepEqual(book.summaryObservation, observation);
  await collectAdmittedSummary(book, gate, undefined, 0); assert.equal(book.summaryObservation.capture, 'DELIVERY_UNKNOWN');
  const notAdmitted = new GenerationGate(); let touched = false;
  await collectAdmittedSummary(book, notAdmitted, { then: () => { touched = true; } }, 0);
  assert.equal(touched, false); assert.equal(book.summaryObservation.capture, 'NOT_ADMITTED'); assert.equal(gate.total, 1);
});

test('already-admitted summary 429/503 drain retains finite failure/header predicates with UNKNOWN liability and no new call', async () => {
  for (const status of [429, 503]) {
    const gate = new GenerationGate(); gate.admit(admission('summary')); gate.halted = true;
    const book = new ResultBook(attemptId); book.record('report', 'FAIL', 'ASSERTION_FAILED', { predicate: 'secret-count' });
    const pending = readGeneration(response(502, { errorCode: 'LLM_PROVIDER_RATE_LIMITED', providerFailure: { kind: 'rate_limited', status },
      message: 'SYNTHETIC_PRIVATE' }, { 'x-llm-failure-phase': 'headers', 'x-llm-failure-reason': 'http_error' }), gate);
    await collectAdmittedSummary(book, gate, pending, 1000);
    const evidence = book.evidence(); assert.equal(evidence.admittedSummaryObservation.capture, 'ERROR_CAPTURED');
    assert.equal(evidence.admittedSummaryObservation.consumption, 'UNKNOWN');
    assert.deepEqual(evidence.admittedSummaryObservation.providerFailure, { kind: 'rate_limited', status });
    assert.deepEqual(evidence.admittedSummaryObservation.providerDiagnostic, { phase: 'headers', reason: 'http_error' });
    assert.equal(evidence.cases.report.status, 'FAIL'); assert.equal(evidence.cases.summary.status, 'BLOCKED');
    assert.equal(gate.total, 1); assert.equal(evidenceDocuments(book).join('').includes('SYNTHETIC_PRIVATE'), false);
  }
});

function compileFrontend(relative, imports = {}) {
  const require = createRequire(new URL('../server/api/package.json', import.meta.url));
  const ts = require('typescript'), text = readFileSync(new URL(relative, import.meta.url), 'utf8');
  const js = ts.transpileModule(text, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  const module = { exports: {} }, sourceRequire = createRequire(new URL(relative, import.meta.url));
  new Function('require', 'module', 'exports', js)(name => {
    if (Object.hasOwn(imports, name)) return imports[name];
    if (name.startsWith('.')) return compileFrontend(new URL(`${name}.ts`, new URL(relative, import.meta.url)).href, imports);
    return sourceRequire(name);
  }, module, module.exports);
  return module.exports;
}

test('passive summary is not a provider call/permit and only exact owner404 missing permits first automatic summary', () => {
  const gate = new GenerationGate();
  assert.equal(summaryMissing(missingSummary()), true); assert.equal(passiveSummaryValue(missingSummary(), context), null);
  assert.equal(passiveSummaryValue({ ...missingSummary(), headers: { ...summaryHeaders, 'cache-control': 'no-store, no-store' } }, context), null);
  for (const policy of ['', 'public', 'no-store, public', 'no-store, max-age=60', 'no-store,'])
    assert.throws(() => passiveSummaryValue({ ...missingSummary(), headers: { ...summaryHeaders, 'cache-control': policy } }, context));
  assert.deepEqual(generationMetadata(gate), { total: 0, summaryPosts: 0, chatPosts: 0, translationPosts: 0, halted: false });
  for (const status of [429, 503]) {
    const readFailureGate = new GenerationGate(); readFailureGate.observe(status, { errorCode: 'AUTH_UNAVAILABLE' });
    assert.deepEqual(generationMetadata(readFailureGate), { total: 0, summaryPosts: 0, chatPosts: 0, translationPosts: 0, halted: true });
    for (const kind of ['summary', 'chat', 'translation']) assert.equal(readFailureGate.admit(admission(kind)), false);
  }
  for (const result of [{ status: 404, value: { errorCode: 'SCAN_NOT_FOUND' }, headers: summaryHeaders },
    { ...missingSummary(), status: 503 }, { ...missingSummary(), value: { errorCode: 'LLM_SUMMARY_MISSING', extra: 'private' } },
    { ...missingSummary(), headers: { ...summaryHeaders, 'cache-control': 'public' } }, undefined,
    { status: 200, value: { ...binding }, headers: summaryHeaders }]) {
    assert.equal(new GenerationGate().admit(admission('summary', { passiveSummary: result })), false);
  }
  assert.throws(() => passiveSummaryValue({ status: 404, value: { errorCode: 'SCAN_NOT_FOUND' }, headers: summaryHeaders }, context), error =>
    error.message === 'SUMMARY_READ_FAILED' && error.meta.errorCode === 'SCAN_NOT_FOUND');
  assert.equal(gate.admit(admission('summary')), true); gate.finish();
  // Missing after reload/eviction/restart never authorizes a replay with a fresh permit.
  assert.equal(gate.admit(admission('summary', { passiveSummary: missingSummary() })), false);
});

test('retained summary restores the exact enriched POST DTO after reload/login; miss stays blocked without another POST', () => {
  const value = { ...binding, hypotheses: [{ kind: 'hypothesis', text: 'Синтетическая интерпретация', citations: [context.findingId] }],
    scannerFacts: [{ findingId: context.findingId, check: 'vuln', severity: 'HIGH' }], findingCount: 1,
    identifierCounts: { cve: 1, debianTemp: 0 }, coverage: [], contextSelection: { totalFindings: 1, selectedFindings: 1, omittedFindings: 0,
      strategy: 'all-critical-and-unknown-then-severity', selectedFindingIds: [context.findingId] } };
  const retained = { status: 200, value: structuredClone(value), headers: summaryHeaders };
  for (const scope of ['reload', 'fresh-login']) assert.deepEqual(assertSummaryRestored(retained, context, value), value, scope);
  for (const invalid of [{ ...retained, value: { cached: true, summary: value } },
    { ...retained, value: { ...value, cached: true } }, { ...retained, value: { ...value, reportVersion: 'f'.repeat(64) } },
    { ...retained, headers: { ...summaryHeaders, 'x-llm-summary-retention': 'durable' } }]) assert.throws(() => assertSummaryRestored(invalid, context, value));
  assert.throws(() => assertSummaryRestored(missingSummary(), context, value), error => error.message === 'SUMMARY_NOT_RESTORED');
});

test('automatic disclosure exactly matches actual current helper; mismatched profile/data/privacy/extra metadata cannot dispatch', () => {
  const auth = { scanSession: () => ({ subject: 'fixture', generation: 1 }), subscribeScanSession: () => () => {} };
  const { allowAutomationDisclosure } = compileFrontend('../src/shared/api/scans/reportAutomation.ts', {
    '@/shared/api/auth/scanSession': auth, '@/shared/api/preferences/reportPreferences': { REPORT_AUTOMATION_REVISION: 'report-automation-v1', readReportPreferences: () => ({}) },
  });
  for (const kind of ['summary', 'translation']) {
    const correct = kind === 'summary' ? context.disclosure : translationDisclosure;
    const mutations = [correct, { ...correct, data: 'private payload' }, { ...correct, model: 'paid-model' },
      { ...correct, providers: [ENDPOINT, 'fallback'] }, { ...correct, region: 'elsewhere' }, { ...correct, retention: 'no-training' },
      { ...correct, maxPrice: { prompt: 0, completion: 1, request: 0 } }, { ...correct, maxPrice: { ...correct.maxPrice, unknown: 0 } },
      { ...correct, freeOnly: false }, { ...correct, requestBudgetUsd: 1 }, { ...correct, extra: true },
      { ...correct, operatorApprovedRouting: false }, { ...correct, providerComplianceNotProvenByDeclaration: false }, null];
    if (kind === 'translation') mutations.push({ ...correct, targetLanguage: 'en' }, { ...correct, persistentTranslationCache: true },
          ...[false, true, null, 'automatic', 'account-preferences', 'account-preference '].map(automaticDispatch => ({ ...correct, automaticDispatch })));
    for (const disclosure of mutations) {
      assert.equal(automationDisclosureMatches(disclosure, kind), allowAutomationDisclosure(disclosure, kind));
      const input = admission(kind, { context: { ...context, disclosure } });
      assert.equal(new GenerationGate().admit(input), disclosure === correct);
    }
  }
  for (const kind of ['summary', 'chat', 'translation']) for (const ready of [null, { ...readiness, localReady: false },
    { ...readiness, reportVersion: 'f'.repeat(64) }, { ...readiness, provider: { ...readiness.provider, endpoint: 'other' } },
    { ...readiness, provider: { ...readiness.provider, status: 'unverified-profile' } }, { ...readiness, credential: 'unsafe' }])
    assert.equal(new GenerationGate().admit(admission(kind, { readiness: ready })), false);
});

test('translation metadata requires literal account-preference, rejects legacy booleans, and does not grant GET generation', () => {
  assert.equal(automationDisclosureMatches(translationDisclosure, 'translation'), true);
  const gate = new GenerationGate();
  for (const automaticDispatch of [false, true, undefined, null, 'automatic', 'account-preference ']) {
    const disclosure = { ...translationDisclosure, automaticDispatch };
    assert.equal(automationDisclosureMatches(disclosure, 'translation'), false);
    assert.equal(gate.admit(admission('translation', { context: { ...context, disclosure } })), false);
  }
  const missing = { ...translationDisclosure }; delete missing.automaticDispatch;
  assert.equal(automationDisclosureMatches(missing, 'translation'), false);
  for (const kind of ['summary', 'translation']) assert.equal(generationKind(pathFor(kind), scanId, 'GET'), undefined);
  assert.deepEqual(generationMetadata(gate), { total: 0, summaryPosts: 0, chatPosts: 0, translationPosts: 0, halted: false });
});

test('actual updated summary client existing() uses passive GET only, decodes same DTO and never falls through on denial', async () => {

  const session = { subject: 'fixture', generation: 1 }, calls = [];
  const { createSummaryClient } = compileFrontend('../src/shared/api/scans/llmSummaryClient.ts', {
    '@/shared/api/auth/scanSession': { scanSession: () => session, subscribeScanSession: () => () => {} },
    './scanTransport': { BROWSER_SCANS_PATH: SCANS },
    './publicVulnerabilityIdentifiers': compileFrontend('../src/shared/api/scans/publicVulnerabilityIdentifiers.ts'),
  });
  const reply = { ...binding, hypotheses: [{ kind: 'hypothesis', text: 'Синтетическая сводка', citations: [context.findingId] }],
    scannerFacts: [{ findingId: context.findingId, check: 'vuln', severity: 'HIGH' }] };
  let result = { status: 200, value: reply };
  const client = createSummaryClient(session, async (path, init) => {
    calls.push(init.method); assert.equal(path, `${SCANS}/${scanId}/llm/summary`); assert.equal(init.method, 'GET');
    assert.equal(init.body, undefined); assert.equal(init.cache, 'no-store'); assert.equal(init.credentials, 'same-origin'); assert.equal(init.redirect, 'error');
    return new Response(JSON.stringify(result.value), { status: result.status, headers: summaryHeaders });
  });
  assert.deepEqual(await client.existing(context, new AbortController().signal), reply);
  result = missingSummary(); assert.equal(await client.existing(context, new AbortController().signal), null);
  result = { status: 404, value: { errorCode: 'SCAN_NOT_FOUND' } }; await assert.rejects(client.existing(context, new AbortController().signal));
  result = { status: 200, value: { ...reply, reportVersion: 'f'.repeat(64) } }; await assert.rejects(client.existing(context, new AbortController().signal));
  assert.deepEqual(calls, ['GET', 'GET', 'GET', 'GET']);
  const ui = readFileSync(new URL('../src/features/scans/ScanSummaryPanel.tsx', import.meta.url), 'utf8');
  const require = createRequire(new URL('../server/api/package.json', import.meta.url)), ts = require('typescript');
  const file = ts.createSourceFile('ScanSummaryPanel.tsx', ui, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const find = (node, predicate) => {
    if (predicate(node)) return node;
    return ts.forEachChild(node, child => find(child, predicate));
  };
  const refresh = find(file, node => ts.isFunctionDeclaration(node) && node.name?.text === 'refresh');
  assert.ok(refresh, 'actual refresh function must exist');
  const existing = find(refresh, node => ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'existing');
  const generate = find(refresh, node => ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'generate');
  assert.ok(existing && generate && existing.pos < generate.pos, 'passive existing retrieval must precede generation');
  const enclosingIf = node => {
    for (let parent = node.parent; parent && parent !== refresh; parent = parent.parent)
      if (ts.isIfStatement(parent)) return parent;
  };
  const recoveryGate = enclosingIf(existing), generationGate = enclosingIf(generate);
  assert.ok(recoveryGate && generationGate, 'recovery and generation must have separate guards');
  const optInNames = new Set(['authorized', 'autoSummary', 'automationCurrent']);
  assert.equal(!!find(recoveryGate, node => ts.isIdentifier(node) && optInNames.has(node.text)), false,
    'passive recovery must not depend on automation opt-in');
  for (const statement of refresh.body.statements) {
    if (statement.pos >= recoveryGate.pos) break;
    assert.equal(!!find(statement, node => ts.isIfStatement(node) &&
      !!find(node.expression, part => ts.isIdentifier(part) && optInNames.has(part.text))), false,
    'an earlier opt-in guard must not prevent reaching passive recovery');
  }
  const canRecover = new Function('existing', 'status', 'PUBLIC_IMAGE_PROFILE', 'authorized', 'preferences',
    `return !!(${recoveryGate.expression.getText(file)});`);
  for (const optIn of [false, true]) {
    const preferences = { authorized: optIn, autoSummary: optIn };
    assert.equal(canRecover(() => {}, { state: 'completed', profile: 'public-hub-amd64-v1' }, 'public-hub-amd64-v1', optIn, preferences), true);
    for (const status of [{ state: 'running', profile: 'public-hub-amd64-v1' }, { state: 'completed' }, { state: 'completed', profile: 'legacy' }])
      assert.equal(canRecover(() => {}, status, 'public-hub-amd64-v1', optIn, preferences), false);
    assert.equal(canRecover(undefined, { state: 'completed', profile: 'public-hub-amd64-v1' }, 'public-hub-amd64-v1', optIn, preferences), false);
  }
  const canGenerate = new Function('automate', 'recovered', 'accepted', 'generation', 'version', 'authorized', 'status',
    `return !!(${generationGate.expression.getText(file)});`);
  assert.equal(canGenerate(true, false, {}, { current: 1 }, 1, true, { state: 'completed' }), true);
  assert.equal(canGenerate(true, true, {}, { current: 1 }, 1, true, { state: 'completed' }), false, 'a recovered result must suppress generation');
  assert.equal(canGenerate(true, false, {}, { current: 1 }, 1, false, { state: 'completed' }), false, 'generation still requires opt-in');
});

test('native workflow source binds automatic effects before actions, one account/scan, actual four checks and no runtime lifecycle', () => {
  const code = source(); assert.equal(WORKER_MS, 660_000); assert.equal(GLOBAL_MS, 20 * 60_000);
  const cleanup = code.slice(code.indexOf('    stopped = true; gate.halted = true; clearTimeout(timer);'));
  assert.ok(cleanup.indexOf('collectAdmittedSummary(book, gate, pendingSummary,') > 0);
  assert.ok(cleanup.indexOf('collectAdmittedSummary(book, gate, pendingSummary,') < cleanup.indexOf('handle.context.close()'));
  assert.ok(cleanup.includes('Math.min(SUMMARY_DRAIN_MS, deadlineAt - Date.now())'));
  assert.ok(code.includes("return parseBoundReport('vuln', response.value, snapshot, query, cursor, tools.decoder)"));
  assert.ok(code.includes("return parseBoundReport('secret', response.value, snapshot, query, cursor, tools.decoder)"));
  assert.equal(TARGETS[0].name, 'node'); assert.deepEqual(CHECKS, ['secret', 'sbom', 'vuln', 'config']);
  for (const text of ["savePreferences(own.page, expect, 'original', true)", "savePreferences(own.page, expect, 'ru', true)",
    "arm(state, `${SCANS}/${scanId}/llm/summary`", "const target = TARGETS[0]", "for (const check of CHECKS)",
    "stats.accountsCreated !== 0", 'stats.scanLaunches !== 0', "gate.chatSuccesses++", 'completeFreshOwnerLogin',
    "assert.deepEqual((await readChat(own.page)).history, savedHistory)", "'SUMMARY_NOT_RESTORED'", "'SECOND_OWNER_NOT_AUTHORIZED'",
    'row.advisory?.assessments?.length === 1', 'state.observations', 'readGeneration(response, gate', 'gate.admit(',
        'tools.chat.chatReadinessSchema.safeParse', 'readiness: readiness.data', 'passiveSummary: state.summaryReads.at(-1)',
        'summary_initial_missing', 'assertSummaryRestored(reloadRead', 'assertSummaryRestored(freshSummaryRead', 'response.request().method()',
    "not.toHaveAttribute('open', '')", "help.click()", 'samples.at(-1) > samples[0]']) assert.ok(code.includes(text), text);
  assert.ok(code.indexOf('arm(own, post,') < code.indexOf("row.locator('details.scan-vuln-row__details > summary').click()"));
  for (const forbidden of ['storageState(', 'screenshot(', 'recordHar', 'addCookies(', 'addInitScript(', 'localStorage.', 'sessionStorage.',
    'route.fulfill(', 'route.fetch(', 'spawn(', 'exec(', 'docker ', 'up --build', 'waitForTimeout(', "name: 'Повторить перевод'"])
    assert.equal(code.includes(forbidden), false, forbidden);
});
