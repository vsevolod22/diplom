import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, open, readFile, rm, stat, chmod, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { diagnosticContracts, captureResponseDiagnostics } from './native-h7v3-finite-diagnostics.mjs';
import { contracts, fingerprint } from './native-h7v3-paid-sol.mjs';
import { ACKS, WORK, SCAN, MODEL, ORIGIN, BASE, QUESTION, ATTEMPT_FILE, SESSION_FILE,
  modeOf, spendAttempt, privateJson, privateSnapshot, validateStorage, initialHistory, completionPreserved, ChatGate,
  allowedGet, outboundPlan, assertNoCaptureEnvironment, safeFailure, contentHeaders, captureChatResponse, parseAnswer, nativeFinding,
  replyProof, usageDifference, extraContracts, reviewFingerprint, REVIEW_FILES, CONTENT_PREDICATES,
  openEvidenceJournal, writeAggregate, captureIntoAggregate, summaryAcceptance } from './batch26-native-chat.mjs';
const c = { ...await diagnosticContracts(), ...await extraContracts() }, tools = await contracts();
const marker = 'PRIVATE_MARKER_DO_NOT_PRINT';
const noLeak = value => assert.equal(JSON.stringify(value).includes(marker), false);
const uuid = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const binding = { scanId: SCAN, digest: 'sha256:' + 'a'.repeat(64), platform: 'linux/amd64', reportVersion: 'b'.repeat(64) };
function current() {
  return c.chat.chatContextSchema.parse({ ...binding, epoch: uuid(1), revision: 4, enabled: true, policyVersion: 'c'.repeat(64),
    disclosure: { provider: 'OpenAI', model: MODEL, monetaryLimit: 'uncapped', requestBudgetMicros: null, userBudgetMicros: null, scanBudgetMicros: null,
      retention: 'no-training', operatorApprovedRouting: true, providerComplianceNotProvenByDeclaration: true, zeroDataRetentionVerified: false,
      costBasis: c.public.OPENAI_COST_BASIS, estimatedPrice: { unit: 'microUSD-per-million-tokens', input: 1000000, output: 2000000 },
      data: c.public.REMEDIATION_SCANNER_DISCLOSURE,
      sentData: 'Cleaned question, all user history/accepted decisions and selected findings with complete coverage.',
      localRetention: 'Durable owner+scan history until separately authorized operator lifecycle; capacity can refuse; context cache only, not output cache.' },
    limits: { questionBytes: 2048, bodyBytes: 8192 }, deliveryMode: 'completed-response', pending: false });
}
const before = () => ({ ...binding, epoch: uuid(1), revision: 4, pending: null, decisions: [], turns: [2, 3].map(n => ({
  id: uuid(n), mutationId: uuid(n + 10), state: 'failed', question: 'Сохранённый вопрос.', report: binding, createdAt: 1 })),
  retention: 'Confirmed history persists until separately authorized operator lifecycle; no automatic expiry or reset.' });
const request = () => ({ epoch: uuid(1), revision: 4, mutationId: uuid(20), reportVersion: binding.reportVersion,
  question: QUESTION, consent: { accepted: true, policyVersion: current().policyVersion } });
const receipt = { input: 20, output: 10, costMicros: 40, source: 'server-estimated-configured-rates-not-invoice' };
const sourceFinding = { check: 'vuln', findingId: 'vuln-' + 'd'.repeat(64), severity: 'HIGH', cveId: 'CVE-2026-1000',
  identifierKind: 'cve', ecosystem: 'deb', severitySources: ['debian'], provenanceRef: 'target-' + 'e'.repeat(64),
  fixedVersionReported: false, packageName: 'libc6', installedVersion: '1.0', fixedVersion: null, advisoryState: 'unknown' };
const frame = (seq, type, payload = {}) => ({ ...binding, v: 1, seq, type, deliveryMode: 'validated-completed-reply', nativeProviderStream: false,
  epoch: uuid(1), revision: 6, mutationId: uuid(20), turnId: uuid(30), ...payload });
const errorFrames = (patch = {}) => [frame(0, 'usage', { usage: receipt }), frame(1, 'error', { errorCode: 'LLM_UNAVAILABLE', receipt: 'accepted', ...patch })];
const text = 'Сканер сообщил о находке; требуется проверка.';
const successFrames = () => [frame(0, 'usage', { usage: receipt }), frame(1, 'citation', { index: 0, source: { ...binding, finding: sourceFinding } }),
  frame(2, 'delta', { index: 0, text }), frame(3, 'done', { outcome: 'completed', kind: 'hypothesis', textBytes: Buffer.byteLength(text), citationCount: 1, deltaCount: 1 })];
const wire = frames => frames.map(x => JSON.stringify(x)).join('\n') + '\n';
function response(raw, headers = {}, status = 200) {
  return { requested: [], status: () => status, async headerValue(key) {
    this.requested.push(key); return key === 'content-type' ? 'application/x-ndjson' : headers[key] ?? null;
  }, text: async () => raw };
}

test('default/import is inert; exact postdeployment paid GO plus reviewed fingerprint required, never old flags', () => {
  assert.deepEqual(modeOf([]), { mode: 'inert' });
  assert.deepEqual(modeOf(['--fingerprint']), { mode: 'fingerprint' });
  const args = [...ACKS, '--deployment-id', 'a'.repeat(32), '--review-sha256', 'b'.repeat(64)];
  assert.equal(modeOf(args).mode, 'run-once');
  for (const input of [ACKS, args.slice(1), [...args, '--retry'], ['--generate'], ['--diagnostic-chat-once'],
    [...ACKS, '--deployment-id', 'not-deployed', '--review-sha256', 'b'.repeat(64)]]) assert.throws(() => modeOf(input));
  assert.equal(ATTEMPT_FILE.includes('batch26-native-chat'), true);
  assert.equal(SESSION_FILE.endsWith('batch25-browser-final-evidence/private-storage.json'), true);
});

test('exclusive0600 spent file survives partial use, refuses repeats and concurrent spend before mocked network', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'batch26-spent-')), path = join(dir, 'attempt.json');
  try {
    let network = 0;
    await spendAttempt(path, { deployment: 'a'.repeat(32), spent: false, beforeAnyNetwork: false });
    const value = JSON.parse(await readFile(path, 'utf8'));
    assert.equal(value.spent, true); assert.equal(value.beforeAnyNetwork, true); assert.equal(value.work, WORK);
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    await assert.rejects(async () => { await spendAttempt(path, {}); network++; }, { code: 'EEXIST' });
    assert.equal(network, 0);
    const concurrent = await Promise.allSettled([spendAttempt(join(dir, 'race.json'), {}), spendAttempt(join(dir, 'race.json'), {})]);
    assert.equal(concurrent.filter(x => x.status === 'fulfilled').length, 1);
    assert.equal(concurrent.filter(x => x.status === 'rejected').length, 1);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('private session accepts only owned0600 regular JSON, no symlink or public file; unsafe values never appear in errors', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'batch26-session-')), path = join(dir, 'session.json');
  try {
    const file = await open(path, 'wx', 0o600); await file.writeFile(JSON.stringify({ private: marker })); await file.close();
    assert.equal((await privateJson(path)).private, marker);
    const original = await privateSnapshot(path);
    const changed = await open(path, 'w'); await changed.writeFile(JSON.stringify(original.value) + ' '); await changed.close();
    const next = await privateSnapshot(path);
    assert.deepEqual(next.value, original.value);
    assert.notEqual(next.byteHash, original.byteHash, 'old-slot preservation detects even whitespace-only rewrites');
    await chmod(path, 0o644); await assert.rejects(privateJson(path), /PRIVATE_SESSION_UNSAFE/);
    await chmod(path, 0o600); await symlink(path, join(dir, 'link.json')); await assert.rejects(privateJson(join(dir, 'link.json')));
    const state = { cookies: [{ name: 'demo_session', domain: '127.0.0.1', path: '/', httpOnly: true, expires: -1, value: marker }],
      origins: [{ origin: ORIGIN, localStorage: [] }] };
    assert.equal(validateStorage(state), state);
    for (const invalid of [{ ...state, cookies: [] }, { ...state, origins: [{ origin: 'https://foreign.invalid', localStorage: [] }] },
      { ...state, cookies: [{ ...state.cookies[0], domain: 'other.invalid' }] }, { ...state, cookies: [...state.cookies, state.cookies[0]] }]) {
      let error; try { validateStorage(invalid); } catch (e) { error = e; }
      assert.ok(error); noLeak(safeFailure(error));
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('history admission requires exact two failed rev4/current binding/no decisions and no pending', () => {
  assert.equal(initialHistory(before(), current()), true);
  for (const patch of [{ revision: 2 }, { pending: {} }, { turns: before().turns.slice(0, 1) }, { decisions: [{}] },
    { turns: [...before().turns, before().turns[0]] }, { epoch: uuid(99) }, { reportVersion: 'a'.repeat(64) },
    { turns: [{ ...before().turns[0], state: 'completed' }, before().turns[1]] }]) assert.equal(initialHistory({ ...before(), ...patch }, current()), false);
});

test('gate allows exactly one current consent chat; old failed mutation and all other operations refused', async () => {
  let persisted = 0;
  const gate = new ChatGate(async () => { persisted++; }); gate.arm(current(), before());
  const original = before();
  for (const suffix of ['/llm/summary', '/llm/translation', '', '/cancel', '/history/decision']) assert.equal(await gate.consume(BASE + suffix, request()), false);
  for (const patch of [{ revision: 3 }, { epoch: uuid(99) }, { mutationId: before().turns[0].mutationId },
    { question: 'Другое.' }, { reportVersion: 'd'.repeat(64) }, { extra: marker },
    { consent: { accepted: true, policyVersion: 'd'.repeat(64) } }, { consent: { accepted: false, policyVersion: current().policyVersion } }])
    assert.equal(await gate.consume(BASE + '/llm/chat', { ...request(), ...patch }), false);
  assert.equal(await gate.consume(BASE + '/llm/chat', request()), true);
  assert.equal(await gate.consume(BASE + '/llm/chat', request()), false);
  assert.equal(persisted, 1); assert.deepEqual(before(), original); assert.throws(() => gate.arm(current(), before()));
});

test('gate spends synchronously before persistence, blocks concurrent call and cannot retry failed flush', async () => {
  let release; const barrier = new Promise(resolve => { release = resolve; });
  const gate = new ChatGate(async () => barrier); gate.arm(current(), before());
  const first = gate.consume(BASE + '/llm/chat', request());
  assert.equal(await gate.consume(BASE + '/llm/chat', request()), false); release(); assert.equal(await first, true);
  const failed = new ChatGate(async () => { throw Error(marker); }); failed.arm(current(), before());
  await assert.rejects(failed.consume(BASE + '/llm/chat', request()), /DISPATCH_INTENT_UNCERTAIN_NO_RETRY/);
  assert.equal(await failed.consume(BASE + '/llm/chat', request()), false);
});

test('stop during intent persistence prevents a previously armed route from continuing', async () => {
  let resume; const barrier = new Promise(resolve => { resume = resolve; });
  const gate = new ChatGate(async () => barrier); gate.arm(current(), before());
  const pending = gate.consume(BASE + '/llm/chat', request());
  gate.stop(); resume();
  assert.equal(await pending, false);
  assert.equal(await gate.consume(BASE + '/llm/chat', request()), false);
});

test('network reads are own sameorigin only, reject8080/foreign/redirect-shaped credentials/events/translation', () => {
  for (const suffix of ['', '/llm/history', '/llm/summary', '/llm/chat/context', '/llm/readiness', '/llm/usage', '/vuln?cursor=0&limit=50'])
    assert.equal(allowedGet(ORIGIN + BASE + suffix), true, suffix);
  for (const url of ['http://127.0.0.1:8080' + BASE, 'https://example.invalid', ORIGIN + '/api/v1/browser/scans/' + uuid(99),
    ORIGIN + BASE + '/events', ORIGIN + BASE + '/llm/translation/context', 'http://user:password@127.0.0.1:8081' + BASE,
    ORIGIN + BASE + '#private']) assert.equal(allowedGet(url), false);
});

test('outbound plan denies every mutation except one guarded exact chat URL and forbids redirect/query variants', () => {
  assert.equal(outboundPlan(ORIGIN + BASE + '/llm/chat', 'POST'), 'chat');
  assert.equal(outboundPlan(ORIGIN + BASE + '/llm/history', 'GET'), 'read');
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']) {
    for (const suffix of ['', '/llm/summary', '/llm/translation', '/llm/history/decision', '/cancel'])
      assert.equal(outboundPlan(ORIGIN + BASE + suffix, method), 'deny');
  }
  for (const url of [ORIGIN + BASE + '/llm/chat?retry=1', ORIGIN + BASE + '/llm/chat#fragment',
    'http://127.0.0.1:8080' + BASE + '/llm/chat', 'https://foreign.invalid' + BASE + '/llm/chat'])
    assert.equal(outboundPlan(url, 'POST'), 'deny');
  assert.equal(outboundPlan(ORIGIN + BASE + '/llm/chat', 'POST', true), 'deny');
});

test('all11 Content-Predicate values captured as finite factory metadata, no arbitrary headers or values', () => {
  for (const predicate of c.diagnostic.CHAT_CONTENT_PREDICATES) {
    const out = contentHeaders({ 'X-LLM-Failure-Phase': 'content', 'X-LLM-Failure-Reason': 'invalid_content' }, predicate, c);
    assert.equal(out['X-LLM-Content-Predicate'], predicate); noLeak(out);
  }
  assert.deepEqual(contentHeaders({}, 'chat_shape', c), {});
  for (const predicate of [marker, 'x'.repeat(65), null]) {
    const out = contentHeaders({ 'X-LLM-Failure-Phase': 'content', 'X-LLM-Failure-Reason': 'invalid_content' }, predicate, c);
    assert.equal(out['X-LLM-Content-Predicate'], undefined); noLeak(out);
  }
});

test('609 regression: exact11 actual producer predicates survive capture and disk aggregate; first failure is durable before parser throws', async () => {
  const expected = ['chat_shape', 'chat_binding', 'chat_citation_type', 'chat_citation_count', 'chat_citation_duplicate',
    'chat_citation_unknown', 'chat_source_bytes', 'chat_sources_bytes', 'chat_text', 'chat_text_length', 'chat_narrative'];
  assert.deepEqual(CONTENT_PREDICATES, expected, 'independent exact list, not a self-expanding enum assertion');
  assert.deepEqual([...c.diagnostic.CHAT_CONTENT_PREDICATES], expected);
  const dir = await mkdtemp(join(tmpdir(), 'batch26-producer-persist-'));
  try {
    for (const predicate of expected) {
      const first = c.diagnostic.diagnoseChatContent(new Error(marker), predicate);
      c.diagnostic.diagnoseChatContent(first, expected.find(value => value !== predicate));
      c.diagnostic.diagnose(first, 'deadline', 'timeout');
      const carried = c.diagnostic.carryDiagnostic(first, new Error(marker));
      const produced = c.diagnostic.diagnosticHeaders(carried);
      assert.equal(produced['X-LLM-Content-Predicate'], predicate);
      const browserHeaders = Object.fromEntries(Object.entries(produced).map(([key, value]) => [key.toLowerCase(), value]));
      const legacy = [];
      await captureResponseDiagnostics(response(wire(errorFrames()), browserHeaders), c, async meta => legacy.push(meta));
      assert.equal(legacy.at(-1).headers['X-LLM-Content-Predicate'], undefined,
        'unchanged spent helper still reproduces609; replacement must close the final path itself');
      const journalPath = join(dir, predicate + '.ndjson'), aggregatePath = join(dir, predicate + '.json');
      const journal = await openEvidenceJournal(journalPath), aggregate = { status: 'PENDING' };
      try {
        // A private fragment AFTER the valid error forces the full browser parser
        // to throw. Capture must already have persisted the producer's first cause.
        const raw = wire([...errorFrames(), frame(2, 'delta', { index: 0, text: marker })]);
        const r = response(raw, browserHeaders);
        r.text = async () => {
          const durableBeforeBody = JSON.parse((await readFile(journalPath, 'utf8')).trim().split('\n')[0]);
          assert.equal(durableBeforeBody.bodyInspection, 'not-read');
          assert.equal(durableBeforeBody.headers['X-LLM-Content-Predicate'], predicate);
          const checkpoint = JSON.parse(await readFile(journalPath + '.before-body.aggregate.json', 'utf8'));
          assert.equal(checkpoint.responseDiagnostics.headers['X-LLM-Content-Predicate'], predicate); noLeak(checkpoint);
          return raw;
        };
        const observed = await captureIntoAggregate(r, c, current(), uuid(20), aggregate, journal);
        const beforeParser = JSON.parse(await readFile(journalPath + '.before-parser.aggregate.json', 'utf8'));
        assert.equal(beforeParser.responseDiagnostics.headers['X-LLM-Content-Predicate'], predicate);
        assert.deepEqual(beforeParser.responseDiagnostics.currentUsageReceipt, receipt);
        assert.equal((await stat(journalPath + '.before-parser.aggregate.json')).mode & 0o777, 0o600);
        noLeak(beforeParser);
        let parserThrew = false;
        try { parseAnswer(observed.raw, c, current(), uuid(20)); }
        catch (error) { parserThrew = true; aggregate.failure = safeFailure(error); }
        assert.equal(parserThrew, true);
        aggregate.status = 'BLOCKED_OR_PARTIAL';
        await writeAggregate(aggregatePath, aggregate);
        const disk = JSON.parse(await readFile(aggregatePath, 'utf8'));
        assert.equal(disk.responseDiagnostics.headers['X-LLM-Failure-Phase'], 'content');
        assert.equal(disk.responseDiagnostics.headers['X-LLM-Failure-Reason'], 'invalid_content');
        assert.equal(disk.responseDiagnostics.headers['X-LLM-Content-Predicate'], predicate);
        assert.deepEqual(disk.responseDiagnostics.currentUsageReceipt, receipt);
        assert.equal(disk.responseDiagnostics.currentTerminal.receipt, 'accepted');
        assert.equal((await stat(aggregatePath)).mode & 0o777, 0o600);
        noLeak(disk); noLeak(await readFile(journalPath, 'utf8'));
        assert.equal(r.requested.includes('set-cookie'), false);
      } finally { await journal.close(); }
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('producer first deadline cannot be enriched by a later chat predicate through capture/persist', async () => {
  const first = c.diagnostic.diagnose(new Error(marker), 'deadline', 'timeout');
  c.diagnostic.diagnoseChatContent(first, 'chat_shape');
  const headers = c.diagnostic.diagnosticHeaders(c.diagnostic.carryDiagnostic(first, new Error(marker)));
  const r = response(wire(errorFrames()), { ...Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value])),
    'x-llm-content-predicate': 'chat_shape' });
  const dir = await mkdtemp(join(tmpdir(), 'batch26-first-cause-'));
  const journal = await openEvidenceJournal(join(dir, 'events.ndjson')), aggregate = {};
  try {
    await captureIntoAggregate(r, c, current(), uuid(20), aggregate, journal);
    await writeAggregate(join(dir, 'aggregate.json'), aggregate);
    const stored = JSON.parse(await readFile(join(dir, 'aggregate.json'), 'utf8'));
    assert.equal(stored.responseDiagnostics.headers['X-LLM-Failure-Phase'], 'deadline');
    assert.equal(stored.responseDiagnostics.headers['X-LLM-Content-Predicate'], undefined); noLeak(stored);
  } finally { await journal.close(); await rm(dir, { recursive: true, force: true }); }
});

test('summary gate proves available original DTO hash but never treats a policy404/local hash or operator assertion as row-preservation proof', () => {
  const saved = tools.summary.summaryReplySchema.parse({ ...binding,
    hypotheses: [{ kind: 'hypothesis', text, citations: [sourceFinding.findingId] }], scannerFacts: [sourceFinding] });
  const hash = fingerprint(saved), schema = tools.summary.summaryReplySchema;
  assert.equal(summaryAcceptance(200, saved, hash, schema).canProceed, true);
  assert.equal(summaryAcceptance(200, { ...saved, reportVersion: 'f'.repeat(64) }, hash, schema).canProceed, false);
  assert.equal(summaryAcceptance(200, { ...saved, raw: marker }, hash, schema).canProceed, false);
  const miss = summaryAcceptance(404, { errorCode: 'LLM_SUMMARY_MISSING' }, hash, schema,
    { verified: true, predeploymentHash: hash, postdeploymentHash: hash });
  assert.equal(miss.availability, 'unavailable_current_policy');
  assert.equal(miss.canProceed, false, 'there is no authoritative old-row verification endpoint in this runner');
  assert.equal(miss.authoritativeOldRowPreservation, 'UNPROVEN_BY_CURRENT_ENDPOINT');
  noLeak(miss);
  for (const value of [{ errorCode: 'SCAN_NOT_FOUND' }, { errorCode: 'LLM_SUMMARY_MISSING', raw: marker }, null]) {
    const gate = summaryAcceptance(404, value, hash, schema);
    assert.equal(gate.canProceed, false); assert.equal(gate.availability, 'unverified'); noLeak(gate);
  }
});

test('current accepted receipt and finite content failure persisted BEFORE authoritative parser throws', async () => {
  const records = [], r = response(wire(errorFrames()), { 'x-llm-failure-phase': 'content', 'x-llm-failure-reason': 'invalid_content',
    'x-llm-content-predicate': 'chat_sources_bytes', 'set-cookie': marker });
  const observed = await captureChatResponse(r, c, current(), uuid(20), async record => records.push(record));
  assert.equal(records[0].bodyInspection, 'not-read');
  assert.equal(records[0].headers['X-LLM-Content-Predicate'], 'chat_sources_bytes');
  assert.equal(records.at(-1).currentReceiptCaptured, true);
  assert.deepEqual(records.at(-1).currentUsageReceipt, receipt);
  assert.deepEqual(records.at(-1).currentTerminal, { errorCode: 'LLM_UNAVAILABLE', receipt: 'accepted' });
  assert.throws(() => parseAnswer(observed.raw, c, current(), uuid(99)));
  assert.equal(r.requested.includes('set-cookie'), false); noLeak(records);
});

test('non200 content predicate is durable before body inspection, without promoting unbound error metadata', async () => {
  const records = [];
  const r = response(JSON.stringify({ errorCode: 'LLM_INVALID_RESPONSE', message: marker }), {
    'x-llm-failure-phase': 'content', 'x-llm-failure-reason': 'invalid_content', 'x-llm-content-predicate': 'chat_narrative',
  }, 502);
  await captureChatResponse(r, c, current(), uuid(20), async record => records.push(record));
  assert.equal(records[0].httpStatus, 502);
  assert.equal(records[0].headers['X-LLM-Content-Predicate'], 'chat_narrative');
  assert.equal(records.at(-1).currentReceiptCaptured, undefined);
  noLeak(records);
});

test('foreign mutation/binding and malformed receipts cannot be labelled current accepted receipt', async () => {
  for (const patch of [{ mutationId: uuid(99) }, { reportVersion: 'f'.repeat(64) }, { revision: 4 }, { usage: { ...receipt, input: -1 } }]) {
    const frames = errorFrames(); frames[0] = { ...frames[0], ...patch };
    const records = [];
    await captureChatResponse(response(wire(frames)), c, current(), uuid(20), async record => records.push(record));
    assert.equal(records.at(-1).currentReceiptCaptured, undefined); noLeak(records);
  }
});

test('raw body/private text never enters diagnostics even on non200, invalid EOF, oversized body or read failure', async () => {
  for (const raw of [marker, JSON.stringify({ type: 'delta', text: marker }) + '\n', JSON.stringify({ errorCode: 'LLM_INVALID_RESPONSE', message: marker })]) {
    const records = []; await captureChatResponse(response(raw, {}, 502), c, current(), uuid(20), async record => records.push(record)); noLeak(records);
  }
  const huge = [], r = response(marker + 'x'.repeat(196609));
  await assert.rejects(captureChatResponse(r, c, current(), uuid(20), async record => huge.push(record)), /CHAT_WIRE_BOUND/); noLeak(huge);
  const failed = [], unreadable = response(''); unreadable.text = async () => { throw Error(marker); };
  await assert.rejects(captureChatResponse(unreadable, c, current(), uuid(20), async record => failed.push(record)), /RESPONSE_BODY_UNAVAILABLE/); noLeak(failed);
});

test('success uses actual strict browser parser and full native fact match, emits hashes/counts only and honest semantic scope', () => {
  const answer = parseAnswer(wire(successFrames()), c, current(), uuid(20));
  const native = { ...sourceFinding }; delete native.check; delete native.fixedVersionReported; delete native.advisoryState;
  const corpus = new Map([[sourceFinding.findingId, native]]);
  const proof = replyProof(answer, corpus, c, tools);
  assert.equal(proof.exactNativeCitationMatch, true); assert.equal(proof.citationCount, 1);
  assert.equal(proof.russianObservation.directRussianProse, 'VALIDATED');
  assert.equal(proof.russianObservation.semanticAccuracy, 'UNVERIFIED_REQUIRES_IN_MEMORY_HUMAN_REVIEW');
  assert.equal(JSON.stringify(proof).includes(text), false);
  assert.equal(JSON.stringify(proof).includes(sourceFinding.packageName), false);
  const changed = { ...native, installedVersion: '2.0' };
  assert.throws(() => replyProof(answer, new Map([[sourceFinding.findingId, changed]]), c, tools), /NATIVE_CITATION_MISMATCH/);
  const complete = { ...before(), revision: 6, turns: [...before().turns, { id: answer.turnId, state: 'completed', reply: answer.reply }] };
  assert.equal(completionPreserved(before(), complete, answer), true);
  const bad = structuredClone(complete); bad.turns[0].question = 'Переписано.';
  assert.equal(completionPreserved(before(), bad, answer), false);
});

test('native advisory projection preserves all typed facts and full assessments, excludes original free text', () => {
  const row = { ...sourceFinding, advisory: { state: 'available', conflictState: 'none', conflicts: [], limitations: [],
    assessments: [{ source: 'nvd', severity: 'HIGH', fixedVersion: null, title: marker, description: marker, language: 'en',
      cvss: { family: 'v3', version: '3.1', versionState: 'available', reportedScore: 8.1, scoreState: 'available', vectorState: 'available', vector: marker } }] } };
  const safe = nativeFinding(row); noLeak(safe);
  assert.equal(safe.assessments.length, 1); assert.equal(safe.assessments[0].cvss.reportedScore, 8.1);
});

test('usage delta matches current numeric receipt, never calls unknown consumption zero; liabilities/window mismatches fail', () => {
  const vector = () => ({ input: 0, output: 0, costMicros: 0 });
  const scope = () => ({ used: vector(), held: vector(), carried: vector() });
  const a = { ...binding, available: true, window: { start: '2026-11-03' }, user: scope(), scan: scope() };
  const b = structuredClone(a); b.user.used = { input: 20, output: 10, costMicros: 40 }; b.scan.used = { ...b.user.used };
  assert.equal(usageDifference(a, b, receipt).valid, true);
  assert.equal(usageDifference(a, { ...b, window: { start: 'changed' } }, receipt).valid, false);
  assert.equal(usageDifference(a, b).receiptMatched, false);
  assert.equal(usageDifference(a, b).reason, 'same_window_aggregate_only_no_receipt');
  b.scan.carried.costMicros = 40; assert.equal(usageDifference(a, b, receipt).valid, false);
});

test('debug capture environment refuses before any future browser or attempt, no raw flag reflection', () => {
  assert.doesNotThrow(() => assertNoCaptureEnvironment({}));
  assert.doesNotThrow(() => assertNoCaptureEnvironment({ PWDEBUG: '0' }));
  for (const key of ['DEBUG', 'PWDEBUG', 'NODE_DEBUG', 'NODE_DEBUG_NATIVE']) {
    let error; try { assertNoCaptureEnvironment({ [key]: marker }); } catch (e) { error = e; }
    assert.ok(error); assert.equal(safeFailure(error).code, 'CAPTURE_DEBUG_ENABLED'); noLeak(safeFailure(error));
  }
});

test('safe errors never echo arbitrary raw text, identity or stack', () => {
  noLeak(safeFailure({ name: marker, message: marker, stack: marker }));
  assert.deepEqual(safeFailure({ message: 'CHAT_FAILED_NO_RETRY' }), { code: 'CHAT_FAILED_NO_RETRY' });
});

test('source safety: new fixed slot, no capture APIs, no credential/login/reset/deploy/old runner writes; review closure includes both new files', async () => {
  const source = await readFile(new URL('./batch26-native-chat.mjs', import.meta.url), 'utf8');
  assert.equal(/\.screenshot\(|\.tracing\.|recordHar|recordVideo|launchPersistentContext|\.storageState\(/.test(source), false);
  // URL.password is deliberately checked to reject userinfo, not read as a credential.
  assert.equal(/\b(?:unlink|rename|rm)\s*\(|(?:owner|credentials|state)\.password\b|\/auth\/(?:login|register)|\/reset|docker|8080/.test(source), false);
  assert.equal(source.includes("await spendAttempt(ATTEMPT_FILE"), true);
  assert.equal(source.indexOf('await spendAttempt(ATTEMPT_FILE') < source.indexOf('await chromium.launch('), true);
  assert.equal(source.includes('await captureIntoAggregate(response, c, fresh.h, mutationId, log, events)'), true);
  assert.equal(source.includes('await captureChatResponse(response, c, context, mutationId, async finite =>'), true);
  assert.equal(source.includes("await writeAggregate(join(DIRECTORY, 'aggregate.json'), log)"), true);
  assert.equal(REVIEW_FILES.includes('tests-e2e/batch26-native-chat.test.mjs'), true);
  assert.equal(REVIEW_FILES.includes('server/api/src/llm/provider-diagnostic.ts'), true);
  assert.match(await reviewFingerprint(), /^[a-f0-9]{64}$/);
});
