// OFFLINE ONLY: synthetic transport/locator fixtures, never browser/runtime/provider initialization.
import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { readFileSync, readdirSync } from 'node:fs';
import {
  CASES, TRANSLATION_CASES, diagnosticFromHeaders as automationDiagnosticFromHeaders, GROUNDING_PREDICATES, GROUNDING_SOURCE_RELATIONS, GROUNDING_LEXICAL_CLASSES, GROUNDING_BOUNDARY_CLASSES, LANGUAGE_REASONS, LANGUAGE_TOKEN_CLASSES, CHAT_TRANSLATION_CASES, loadCoverageLabels, coverageTile, COVERAGE_WARNING, assertCoverageWarning, GLOBAL_MS, WORKER_MS, AUTOMATION_REVISION, parseMode, evidencePaths, assertFreshAttempt, browserGetAllowed,
  ResultBook, exitCode, evidenceDocuments, writeEvidence, generationMetadata, generationKind,
  GenerationGate, selectTranslationCandidate, locateTranslationRow, summaryBody, readGeneration, receiveGeneration, estimateSample, savePreferences,
    SUMMARY_CASES, GENERATION_MS, METADATA_MS, assertOneSummary, assertSummaryQualification, assertZeroSummaryUsage,
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
    retention: 'no-training', region: 'global', maxPrice: { prompt: 0, completion: 0, request: 0 },
    operatorApprovedRouting: true, providerComplianceNotProvenByDeclaration: true,
        data: 'Sanitized scanner findings, package names, installed and reported fixed versions, and coverage; no raw evidence or credentials.' } };
    const translationDisclosure = { ...context.disclosure,
      data: 'Only the selected normalized advisory title and description eligible for translation; no other report metadata, package data, history, raw evidence or credentials. Identifiers within the selected text remain unchanged.',
      targetLanguage: 'ru', machineTranslation: true, automaticDispatch: 'account-preference', persistentTranslationCache: false };
    const readiness = { ...binding, status: 'locally-configured', localReady: true, credential: 'metadata-valid', blockers: [],
      quota: 'available', history: 'available', generationVerified: false, requiresConsent: true, acceptsCredentials: false,
      setupAction: 'operator-public-file-configuration', provider: { status: 'catalog-listed-unprobed', checkedOn: '2026-10-29',
        liveVerified: false, model: MODEL, endpoint: ENDPOINT, zdrListed: false, retention: 'no-training' } };
    const summaryHeaders = { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-llm-summary-retention': 'durable-owner-scan' };
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

test('language rejection exact enums match production and complete triplets survive receipts without raw/body overrides', async () => {
  const production = readFileSync(new URL('../server/api/src/llm/language-rejection.ts', import.meta.url), 'utf8');
  for (const [name, values] of Object.entries({ LANGUAGE_REASONS, LANGUAGE_TOKEN_CLASSES })) {
    const match = production.match(new RegExp(name + " = Object.freeze\\(\\[([^\\]]+)\\]"));
    assert.ok(match); assert.deepEqual([...match[1].matchAll(/'([^']+)'/g)].map(value => value[1]), [...values]);
  }
  const base = { 'x-llm-failure-phase': 'language', 'x-llm-failure-reason': 'not_russian' };
  const headers = { ...base, 'x-llm-language-reason': 'residual_latin', 'x-llm-language-index': '0', 'x-llm-language-token-class': 'unknown' };
  for (const reason of LANGUAGE_REASONS) for (const tokenClass of LANGUAGE_TOKEN_CLASSES) for (const index of ['0', '11']) {
    const detail = automationDiagnosticFromHeaders({ ...headers, 'x-llm-language-reason': reason, 'x-llm-language-token-class': tokenClass, 'x-llm-language-index': index });
    assert.deepEqual(detail, { phase: 'language', reason: 'not_russian', languageRejection: { reason, tokenClass, index: Number(index) } });
    assert.deepEqual(automationMeta({ providerDiagnostic: detail }).providerDiagnostic, detail);
  }
  for (const key of ['x-llm-language-reason', 'x-llm-language-index', 'x-llm-language-token-class']) for (const bad of [undefined, null, 'CANARY_PRIVATE', 'unknown,unknown', ' unknown', 'unknown\n'])
    assert.deepEqual(automationDiagnosticFromHeaders({ ...headers, [key]: bad }), { phase: 'language', reason: 'not_russian' });
  for (const index of ['-1', '12', '01', '1.0', ' 1', 1]) assert.equal(automationDiagnosticFromHeaders({ ...headers, 'x-llm-language-index': index }).languageRejection, undefined);
  const inherited = Object.assign(Object.create(headers), base);
  assert.equal(automationDiagnosticFromHeaders(inherited).languageRejection, undefined);
  for (const patch of [{ 'x-llm-failure-phase': 'translation_title' }, { 'x-llm-failure-phase': 'grounding', 'x-llm-failure-reason': 'unknown_identifier' }])
    assert.equal(automationDiagnosticFromHeaders({ ...headers, ...patch }).languageRejection, undefined);
  const detail = automationDiagnosticFromHeaders(headers);
  const accessor = { ...detail.languageRejection }; Object.defineProperty(accessor, 'reason', { get() { assert.fail('no getter'); } });
  for (const invalid of [{ ...detail.languageRejection, raw: 'PRIVATE' }, { reason: 'mixed' }, Object.create(detail.languageRejection), accessor])
    assert.equal(automationMeta({ providerDiagnostic: { ...detail, languageRejection: invalid } }).providerDiagnostic.languageRejection, undefined);
  const gate = new GenerationGate(); let failure;
  try { await readGeneration(response(502, { errorCode: 'LLM_INVALID_RESPONSE', languageRejection: { reason: 'CANARY_PRIVATE' } }, headers), gate); }
  catch (error) { failure = error; }
  assert.ok(failure); assert.equal(gate.halted, true);
  const book = new ResultBook(attemptId); book.record('summary', 'FAIL', 'LLM_HTTP_ERROR', failure.meta);
  assert.deepEqual(book.evidence().cases.summary.providerDiagnostic, detail);
  assert.ok(!JSON.stringify(book.evidence()).includes('CANARY_PRIVATE'));
});

test('grounding headers preserve old diagnostics and allow only exact predicate/index pairs', () => {
  const headers = { 'x-llm-failure-phase': 'grounding', 'x-llm-failure-reason': 'unknown_identifier' };
  for (const predicate of GROUNDING_PREDICATES) for (const index of ['0', '11']) {
    const value = automationDiagnosticFromHeaders({ ...headers, 'x-llm-grounding-predicate': predicate, 'x-llm-grounding-index': index });
    assert.deepEqual(value, { phase: 'grounding', reason: 'unknown_identifier', groundingPredicate: predicate, groundingIndex: Number(index) });
    assert.deepEqual(automationMeta({ providerDiagnostic: value }).providerDiagnostic, value);
  }
  for (const [predicate, index] of [['unknown', '0'], ['score_value\nCANARY', '0'], ['score_value', '-1'], ['score_value', '12'], ['score_value', '01'], ['score_value', '1.0'], ['score_value', ' 1'], ['score_value', 1], ['score_value', '1,2'], [undefined, '0'], ['score_value', undefined]]) {
    assert.deepEqual(automationDiagnosticFromHeaders({ ...headers, 'x-llm-grounding-predicate': predicate, 'x-llm-grounding-index': index }), { phase: 'grounding', reason: 'unknown_identifier' });
  }
  const spoof = Object.create({ 'x-llm-grounding-predicate': 'score_value', 'x-llm-grounding-index': '0' });
  Object.assign(spoof, headers);
  assert.deepEqual(automationDiagnosticFromHeaders(spoof), { phase: 'grounding', reason: 'unknown_identifier' });
  const unrelated = automationDiagnosticFromHeaders({ 'x-llm-failure-phase': 'language', 'x-llm-failure-reason': 'not_russian', 'x-llm-grounding-predicate': 'score_value', 'x-llm-grounding-index': '0' });
  assert.deepEqual(unrelated, { phase: 'language', reason: 'not_russian' });
  assert.ok(!JSON.stringify(automationMeta({ providerDiagnostic: { phase: 'grounding', reason: 'unknown_identifier', groundingPredicate: 'CANARY', groundingIndex: 0, raw: 'PRIVATE' } })).includes('CANARY'));
});

test('grounding witness enums exactly track production source', () => {
  const production = readFileSync(new URL('../server/api/src/llm/grounding-witness.ts', import.meta.url), 'utf8');
  for (const [name, values] of Object.entries({ GROUNDING_SOURCE_RELATIONS, GROUNDING_LEXICAL_CLASSES, GROUNDING_BOUNDARY_CLASSES })) {
    const match = production.match(new RegExp(name + " = Object.freeze\\(\\[([^\\]]+)\\]"));
    assert.ok(match, name);
    assert.deepEqual([...match[1].matchAll(/'([^']+)'/g)].map(value => value[1]), [...values]);
  }
});

test('witness is all-or-nothing after valid grounding predicate/index and projects only finite scalars', () => {
  const base = { 'x-llm-failure-phase': 'grounding', 'x-llm-failure-reason': 'unknown_identifier', 'x-llm-grounding-predicate': 'score_value', 'x-llm-grounding-index': '0' };
  const fields = ['x-llm-grounding-source-relation', 'x-llm-grounding-lexical-class', 'x-llm-grounding-boundary-class'];
  const witness = { sourceRelation: 'cited_value_match', lexicalClass: 'unsigned_decimal', boundaryClass: 'typography' };
  const headers = { ...base, [fields[0]]: witness.sourceRelation, [fields[1]]: witness.lexicalClass, [fields[2]]: witness.boundaryClass };
  for (const sourceRelation of GROUNDING_SOURCE_RELATIONS) for (const lexicalClass of GROUNDING_LEXICAL_CLASSES) for (const boundaryClass of GROUNDING_BOUNDARY_CLASSES) {
    const value = automationDiagnosticFromHeaders({ ...headers, [fields[0]]: sourceRelation, [fields[1]]: lexicalClass, [fields[2]]: boundaryClass });
    assert.deepEqual(value.groundingWitness, { sourceRelation, lexicalClass, boundaryClass });
    assert.deepEqual(automationMeta({ providerDiagnostic: value }).providerDiagnostic, value);
  }
  for (const field of fields) for (const bad of [undefined, null, 0, 'CANARY_PRIVATE', 'indeterminate,other', ' indeterminate', 'indeterminate\n']) {
    const value = automationDiagnosticFromHeaders({ ...headers, [field]: bad });
    assert.equal(value.groundingWitness, undefined);
    assert.equal(value.groundingPredicate, 'score_value'); assert.equal(value.groundingIndex, 0);
  }
  for (const patch of [{ 'x-llm-grounding-index': '12' }, { 'x-llm-grounding-predicate': 'unknown' }, { 'x-llm-failure-phase': 'language', 'x-llm-failure-reason': 'not_russian' }])
    assert.equal(automationDiagnosticFromHeaders({ ...headers, ...patch }).groundingWitness, undefined);
  const inherited = Object.assign(Object.create(Object.fromEntries(fields.map(field => [field, headers[field]]))), base);
  assert.equal(automationDiagnosticFromHeaders(inherited).groundingWitness, undefined);
  const diagnostic = automationDiagnosticFromHeaders(headers);
  for (const invalid of [{ ...witness, raw: 'PRIVATE' }, { sourceRelation: 'cited_value_match' }, Object.create(witness), { ...witness, lexicalClass: 'PRIVATE' }])
    assert.equal(automationMeta({ providerDiagnostic: { ...diagnostic, groundingWitness: invalid } }).providerDiagnostic.groundingWitness, undefined);
  const accessor = { ...witness }; Object.defineProperty(accessor, 'sourceRelation', { get() { assert.fail('must not invoke getter'); } });
  assert.equal(automationMeta({ providerDiagnostic: { ...diagnostic, groundingWitness: accessor } }).providerDiagnostic.groundingWitness, undefined);
});

test('grounding header detail survives generation Fault and sanitized evidence, body spoof never wins', async () => {
  const headers = { 'x-llm-failure-phase': 'grounding', 'x-llm-failure-reason': 'unknown_identifier',
    'x-llm-grounding-predicate': 'version_label', 'x-llm-grounding-index': '11',
        'x-llm-grounding-source-relation': 'no_cited_value_match', 'x-llm-grounding-lexical-class': 'ascii_identity', 'x-llm-grounding-boundary-class': 'end' };
  const gate = new GenerationGate();
  let failure;
  try { await readGeneration(response(502, { errorCode: 'LLM_INVALID_RESPONSE', groundingPredicate: 'CANARY', groundingIndex: 99, groundingWitness: { sourceRelation: 'CANARY', raw: 'PRIVATE' } }, headers), gate); }
  catch (error) { failure = error; }
  assert.ok(failure); assert.equal(gate.halted, true);
  const book = new ResultBook(attemptId); book.record('summary', 'FAIL', 'LLM_HTTP_ERROR', failure.meta);
  assert.deepEqual(book.evidence().cases.summary.providerDiagnostic, { phase: 'grounding', reason: 'unknown_identifier', groundingPredicate: 'version_label', groundingIndex: 11,
      groundingWitness: { sourceRelation: 'no_cited_value_match', lexicalClass: 'ascii_identity', boundaryClass: 'end' } });
  assert.ok(!JSON.stringify(book.evidence()).includes('CANARY'));
});

test('translation-only source fences summary/chat before body parsing and skips history prerequisites without weakening translation checks', () => {
  const code = source();
  const fence = code.indexOf("if (translationOnly && /\\/llm\\/chat(?:\\/|$)/.test(path)) return deny('ai-permit-or-limit');");
  assert.ok(fence > 0 && fence < code.indexOf('let body; try { body = request.postDataJSON()'));
  assert.ok(code.includes("const chatTranslationOnly = mode === 'chat-translation-only' || translationOnly"));
  assert.ok(code.includes('(translationOnly ? [] : QUESTIONS).entries()'));
  assert.ok(code.includes("if (!translationOnly) await step('history_reload'"));
  assert.ok(code.includes('tools.translation.sameTranslationBinding(translated, context)'));
  assert.ok(code.includes('tools.translation.matchesTranslationFields(translated, selected.item)'));
  assert.ok(code.includes('assert.deepEqual(ids(result), ids(original))'));
  assert.ok(code.includes('assert.equal(gate.counts.summary, 0); assert.equal(gate.counts.chat, 0)'));
});

test('translation-only exact ack, isolated cases and one-post fail-closed gate', () => {
  const flags = ['--run', '--translation-only', '--ack-coordinator-readygo', '--ack-one-generation-post', '--ack-source-deployed', '--attempt-id', attemptId];
  assert.equal(parseMode(flags), 'translation-only');
  for (let i = 0; i < flags.length; i++) assert.throws(() => parseMode(flags.filter((_, index) => index !== i)));
  assert.throws(() => parseMode([...flags, '--retry']));
  const book = new ResultBook(attemptId, 'translation-only');
  assert.deepEqual(book.requiredCases, TRANSLATION_CASES); assert.equal(book.evidence().maxGenerationPosts, 1);
  for (const name of ['summary', 'chat_1', 'chat_2', 'history_reload', 'fresh_login']) assert.equal(book.cases[name].status, 'NOT_RUN');
  for (const patch of [{ owner: false }, { completed: false }, { readiness: { ...readiness, localReady: false } },
    { context: { ...context, disclosure: translationDisclosure, reportVersion: '0'.repeat(64) } }, { permit: undefined },
    { body: {} }, { preferences: { language: 'original', autoSummary: false } }]) {
    const gate = new GenerationGate('translation-only');
    assert.equal(gate.admit(admission('translation', { preferences: { language: 'ru', autoSummary: false }, ...patch })), false);
    assert.equal(gate.total, 0);
  }
  for (const failure of [false, true]) {
    const gate = new GenerationGate('translation-only');
    for (const kind of ['summary', 'chat']) assert.equal(gate.admit(admission(kind)), false);
    assert.equal(gate.admit(admission('translation')), false, 'auto-summary must be off');
    const candidate = () => admission('translation', { preferences: { language: 'ru', autoSummary: false } });
    assert.equal(gate.admit(candidate()), true, 'no summary/chat prerequisite');
    assert.equal(gate.admit(candidate()), false);
    gate.observe(failure ? 502 : 200, failure ? { errorCode: 'LLM_INVALID_RESPONSE' } : {}); gate.finish();
    assert.equal(gate.admit(candidate()), false); assert.equal(gate.total, 1);
    assert.deepEqual(gate.counts, { summary: 0, chat: 0, translation: 1 });
  }
});

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

test('summary-only exact seven arguments require GO, deployed-source, one-post ack and fresh UUID; no mixed/broadened mode', () => {
  const flags = ['--run', '--summary-only', '--ack-coordinator-readygo', '--ack-one-generation-post', '--ack-source-deployed', '--attempt-id', attemptId];
  assert.equal(parseMode(flags), 'summary-only');
  for (let index = 0; index < flags.length; index++) assert.throws(() => parseMode(flags.filter((_, i) => i !== index)));
  for (const args of [[...flags, '--ack-four-generation-posts'], [...flags, '--fresh-login'],
    flags.map(flag => flag === '--ack-one-generation-post' ? '--ack-four-generation-posts' : flag),
    flags.map(flag => flag === '--summary-only' ? '--unknown-mode' : flag),
    [...flags.slice(0, -1), 'NOT-A-UUID'], [...flags.slice(0, -1), attemptId.toUpperCase()],
    [flags[1], flags[0], ...flags.slice(2)]]) assert.throws(() => parseMode(args));
  assert.throws(() => assertFreshAttempt(attemptId, [`public-automation-${attemptId}.json`]));
  const before = readdirSync(new URL('../docs/', import.meta.url)).sort();
  const run = spawnSync(process.execPath, [new URL('./public-automation-live.mjs', import.meta.url).pathname, ...flags.slice(0, -1)], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(run.status, 2); assert.equal(run.stderr, ''); assert.equal(JSON.parse(run.stdout).actuallyRun, false);
  assert.deepEqual(readdirSync(new URL('../docs/', import.meta.url)).sort(), before);
});

test('summary-only admits exactly one automatic summary and rejects every chat/translation before, during and after success', () => {
  const gate = new GenerationGate('summary-only'); assert.equal(gate.maxPosts, 1);
  assert.throws(() => { gate.mode = 'full'; }); assert.throws(() => { gate.maxPosts = 4; });
  assert.throws(() => new GenerationGate('unknown-mode'));
  for (const kind of ['chat', 'translation']) assert.equal(gate.admit(admission(kind)), false);
  assert.equal(gate.admit(admission('summary')), true);
  for (const kind of ['summary', 'chat', 'translation']) assert.equal(gate.admit(admission(kind)), false);
  gate.observe(200, {}); gate.finish(); gate.chatSuccesses = 2;
  for (const kind of ['summary', 'chat', 'translation']) assert.equal(gate.admit(admission(kind)), false);
  assertOneSummary(gate);
  assert.deepEqual(generationMetadata(gate), { total: 1, summaryPosts: 1, chatPosts: 0, translationPosts: 0, halted: false });
  for (const patch of [{ preferences: { language: 'original', autoSummary: false } }, { preferences: { language: 'ru', autoSummary: true } },
    { preferences: null }, { completed: false }, { owner: false }, { passiveSummary: { status: 200 } }])
    assert.equal(new GenerationGate('summary-only').admit(admission('summary', patch)), false);
});

test('summary-only evidence has its own required scope; chat/translation remain NOT_RUN and never become a claimed root cause', () => {
  const book = new ResultBook(attemptId, 'summary-only'), gate = new GenerationGate('summary-only');
  book.generation = gate; assert.equal(exitCode(book), 2);
  for (const name of SUMMARY_CASES) book.record(name, 'PASS');
  assert.equal(exitCode(book), 0);
  const evidence = book.evidence(); assert.deepEqual(evidence.requiredCases, SUMMARY_CASES);
  assert.equal(evidence.maxGenerationPosts, 1); assert.equal(evidence.maxAccounts, 1); assert.equal(evidence.maxScans, 1);
  assert.deepEqual(evidence.requiredChecks, CHECKS);
  for (const name of ['chat_1', 'chat_2', 'translation', 'preferences_ru', 'fresh_login'])
    assert.deepEqual(evidence.cases[name], { status: 'NOT_RUN', code: 'NOT_RUN' });
  assert.equal(evidence.admittedSummaryObservation.consumption, 'UNKNOWN');
  assert.ok(evidenceDocuments(book)[1].includes('not diagnosed as current root causes'));
  book.record('summary', 'FAIL', 'ASSERTION_FAILED'); assert.equal(exitCode(book), 1);
  assert.equal(new ResultBook(attemptId).evidence().maxGenerationPosts, 4);
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

test('generation observer distinguishes bounded body-read and JSON failures without raw error text', async () => {
  for (const [predicate, mocked] of [
    ['generation-body-read', { ...response(200, {}), body: async () => { throw new Error('SYNTHETIC_PRIVATE'); } }],
    ['generation-json', response(200, 'SYNTHETIC_PRIVATE not JSON')],
  ]) {
    const gate = new GenerationGate('summary-only');
    assert.equal(gate.admit(admission('summary')), true);
    await assert.rejects(readGeneration(mocked, gate), error => {
      assert.equal(error.meta.predicate, predicate);
      assert.equal(JSON.stringify(error.meta).includes('SYNTHETIC_PRIVATE'), false);
      return true;
    });
    assertOneSummary(gate); assert.equal(gate.halted, true);
  }
});

test('summary-only failure evidence stops at one POST for 429/503/invalid content, keeps only finite headers and UNKNOWN consumption', async () => {
  for (const [status, value] of [[429, { errorCode: 'LLM_PROVIDER_RATE_LIMITED', providerFailure: { kind: 'rate_limited', status: 429 }, message: 'SYNTHETIC_PRIVATE' }],
    [503, { errorCode: 'LLM_PROVIDER_UNAVAILABLE', message: 'SYNTHETIC_PRIVATE' }], [502, { errorCode: 'LLM_INVALID_RESPONSE', message: 'SYNTHETIC_PRIVATE' }],
    [200, 'SYNTHETIC_PRIVATE not JSON']]) {
    const gate = new GenerationGate('summary-only'), book = new ResultBook(attemptId, 'summary-only');
    assert.equal(gate.admit(admission('summary')), true); book.generation = gate;
    const pending = readGeneration(response(status, value, { 'x-llm-failure-phase': 'content', 'x-llm-failure-reason': 'invalid_content',
      authorization: 'SYNTHETIC_PRIVATE', 'x-private': 'SYNTHETIC_PRIVATE' }), gate);
    await collectAdmittedSummary(book, gate, pending, 1000);
    const evidence = book.evidence(); assert.equal(evidence.generationAdmissions.total, 1);
    assert.equal(evidence.admittedSummaryObservation.consumption, 'UNKNOWN');
    assert.equal(evidence.admittedSummaryObservation.httpStatus, status);
    assert.deepEqual(evidence.admittedSummaryObservation.providerDiagnostic, { phase: 'content', reason: 'invalid_content' });
    assert.equal(gate.halted, true);
    for (const kind of ['summary', 'chat', 'translation']) assert.equal(gate.admit(admission(kind)), false);
    assert.equal(evidence.cases.chat_1.status, 'NOT_RUN'); assert.equal(evidence.cases.translation.status, 'NOT_RUN');
    assert.equal(evidenceDocuments(book).join('').includes('SYNTHETIC_PRIVATE'), false);
  }
  const gate = new GenerationGate('summary-only'); gate.admit(admission('summary'));
  const { reply, fullContext, snapshot, checks } = summaryFixture(); reply.hypotheses[0].text = 'English only';
  const value = await readGeneration(response(200, reply, { 'x-llm-failure-phase': 'content', 'x-llm-failure-reason': 'not_russian' }), gate);
  assert.throws(() => assertSummaryQualification(value, fullContext, snapshot, checks, () => true));
  assert.deepEqual(gate.responseMeta, { httpStatus: 200, providerDiagnostic: { phase: 'content', reason: 'not_russian' } });
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

function delayedPreferencesFixture(visibleAt) {
  let now = 0;
  const actions = [];
  const panel = {
    count: async () => Number(now >= visibleAt),
    locator: () => ({ kind: 'disclosure' }),
    getByLabel: label => ({ selectOption: async value => actions.push([label, value]) }),
    getByRole: role => role === 'button' ? { click: async () => actions.push(['save']) } : { kind: 'status' },
  };
  const page = { getByRole: () => panel };
  const expect = locator => ({
    toBeVisible: async options => {
      assert.equal(locator, panel); assert.equal(options?.timeout, 15_000);
      // Deterministic virtual Playwright polling: no real browser, timers or network.
      const end = now + options.timeout;
      while (now < visibleAt && now < end) now += Math.min(25, end - now);
      if (now < visibleAt) throw new Error('PRIVATE_ASSERTION_CANARY_TIMEOUT');
    },
    toHaveAttribute: async () => actions.push(['revision']),
    toContainText: async () => actions.push(['disclosure']),
    toHaveText: async () => actions.push(['saved']),
  });
  return { panel, page, expect, actions, elapsed: () => now };
}

test('candidate selection reaches later report pages without inventing advisory text', async () => {
  const { translation } = await loadTranslationContracts();
  const missing = { value: null, state: 'missing', redacted: false };
  const assessment = { source: 'nvd', provenanceRef: `target-${'a'.repeat(64)}`, language: null, severity: null, fixedVersion: null, cvss: null,
    title: { value: 'Memory flaw', state: 'available', redacted: false }, description: missing };
  const rows = Array.from({ length: 161 }, (_, index) => ({ findingId: `vuln-${index.toString(16).padStart(64, '0')}`, advisory: {
    state: 'available', assessments: [{ ...assessment, title: missing }] } }));
  rows[125].advisory.assessments = [assessment];
  const candidate = selectTranslationCandidate(rows, translation);
  assert.equal(candidate?.row, rows[125]); assert.equal(candidate?.index, 0);
  assert.equal(selectTranslationCandidate(rows.slice(0, 125), translation), undefined);
});

test('normalized multi-source card with exactly one UI-translatable assessment is safe to select', async () => {
  const { translation } = await loadTranslationContracts();
  const { normalizeAdvisory } = compileFrontend('../server/api/src/worker/vuln-advisory.ts');
  const advisory = normalizeAdvisory({ DataSource: { ID: 'alpine' }, Title: 'Memory flaw', SeveritySource: 'nvd', Severity: 'HIGH', CVSS: { nvd: { V3Score: 7.5 } } }, `target-${'a'.repeat(64)}`, 'CVE-2026-1234');
  assert.ok(advisory.assessments.length > 1);
  assert.equal(advisory.assessments.filter(translation.hasTranslationText).length, 1);
  const row = { advisory };
  const candidate = selectTranslationCandidate([row], translation);
  assert.equal(candidate?.row, row);
  assert.equal(candidate?.item.title.value, 'Memory flaw');
  const eligible = candidate.item, metadataOnly = advisory.assessments.find(item => !translation.hasTranslationText(item));
  const reordered = { advisory: { ...advisory, assessments: [metadataOnly, eligible] } };
  assert.equal(selectTranslationCandidate([reordered], translation)?.index, 1);
  assert.equal(selectTranslationCandidate([{ advisory: { ...advisory, assessments: [eligible, { ...eligible, source: 'nvd' }] } }], translation), undefined, 'never mount two automatic translations');
  for (const state of ['omitted', 'missing']) assert.equal(selectTranslationCandidate([{ advisory: { ...advisory, state } }], translation), undefined);
  const nullText = { ...eligible, title: { value: null, state: 'missing', redacted: false }, description: { value: null, state: 'missing', redacted: false } };
  assert.equal(selectTranslationCandidate([{ advisory: { ...advisory, assessments: [nullText, metadataOnly] } }], translation), undefined, 'source provenance cannot manufacture text');
  for (const title of [{ value: 'Memory flaw', state: 'available', redacted: true }, { value: 'https://evil.invalid', state: 'available', redacted: false }, { value: 'x'.repeat(513), state: 'available', redacted: false }])
    assert.equal(selectTranslationCandidate([{ advisory: { ...advisory, assessments: [{ ...eligible, title }] } }], translation), undefined);
});

test('later candidate UI paging is sequential read-only and completes before any details are opened', async () => {
  const rows = Array.from({ length: 161 }, (_, index) => ({ findingId: `vuln-${index.toString(16).padStart(64, '0')}` }));
  let offset = 0, clicks = 0;
  const first = { kind: 'first' }, selectedRow = { kind: 'selected', locator: () => ({ kind: 'details' }) };
  const list = { first: () => first, filter: options => { assert.deepEqual(options, { hasText: `ID находки: ${rows[125].findingId}` }); return selectedRow; } };
  const next = { click: async () => { offset += 25; clicks++; } };
  const report = { locator: selector => { assert.equal(selector, 'li.scan-vuln-row'); return list; },
    getByRole: (role, options) => { assert.equal(role, 'button'); assert.deepEqual(options, { name: 'Далее · Уязвимости', exact: true }); return next; } };
  const page = { getByRole: (role, options) => { assert.equal(role, 'region'); assert.deepEqual(options, { name: 'Результаты Уязвимости', exact: true }); return report; } };
  const expect = locator => ({
    toContainText: async text => { assert.equal(locator, first); assert.equal(text, `ID находки: ${rows[offset].findingId}`); },
    toBeEnabled: async () => { assert.equal(locator, next); },
    toBeVisible: async () => { assert.equal(locator, selectedRow); assert.equal(offset, 125); },
    not: { toHaveAttribute: async (name, value) => { assert.equal(locator.kind, 'details'); assert.equal(name, 'open'); assert.equal(value, ''); } },
  });
  assert.equal(await locateTranslationRow(page, expect, { row: rows[125] }, rows), selectedRow);
  assert.equal(clicks, 5);
  assert.ok(source().indexOf('const row = await locateTranslationRow') < source().indexOf("arm(own, post, body => isDeepStrictEqual(body, translationBody(context))"));
});

test('account navigation with delayed region rendering eventually saves preferences once', async () => {
  const fixture = delayedPreferencesFixture(250);
  assert.equal(await fixture.panel.count(), 0, 'old eager count sees absent region');
  assert.deepEqual(await savePreferences(fixture.page, fixture.expect, 'ru', false), { language: 'ru', autoSummary: false });
  assert.equal(fixture.elapsed(), 250);
  assert.equal(fixture.actions.filter(([action]) => action === 'save').length, 1);
  assert.equal(fixture.actions.at(-1)[0], 'saved');
  assert.ok(fixture.actions.find(([action, value]) => action === 'ИИ-разбор' && value === 'off'));
  assert.ok(fixture.actions.findIndex(([action]) => action === 'disclosure') < fixture.actions.findIndex(([action]) => action === 'Язык исходных описаний уязвимостей'));
});

test('absent account region fails at bounded visible deadline before any mutation without raw timeout details', async () => {
  const fixture = delayedPreferencesFixture(Infinity);
  await assert.rejects(savePreferences(fixture.page, fixture.expect, 'ru', false), error => {
    assert.equal(error.message, 'UI_NOT_DEPLOYED');
    assert.ok(!JSON.stringify(failureMetadata(error)).includes('CANARY'));
    return true;
  });
  assert.equal(fixture.elapsed(), 15_000); assert.deepEqual(fixture.actions, []);
  const gate = new GenerationGate('translation-only');
  assert.equal(gate.total, 0); assert.deepEqual(gate.counts, { summary: 0, chat: 0, translation: 0 });
});

test('preferences save is an explicit UI gesture and disclosure precedes save; no storage/session injection', async () => {
  const events = [];
  const panel = {
    count: async () => 1, locator: () => ({ kind: 'disclosure' }),
    getByLabel: label => ({ selectOption: async value => events.push([label, value]) }),
    getByRole: (role, options) => role === 'button' ? { click: async () => events.push(['click', options.name]) } : { kind: 'status' },
  };
  const page = { getByRole: (role, options) => { assert.equal(role, 'region'); assert.equal(options.name, 'Настройки отчётов'); return panel; } };
  const expect = locator => ({ toBeVisible: async () => events.push(['visible']),
    toContainText: async text => { assert.equal(locator.kind, 'disclosure'); events.push(['disclosure', text]); },
        toHaveAttribute: async (name, value) => { assert.equal(locator.kind, 'disclosure'); events.push([name, value]); },
    toHaveText: async () => { assert.equal(locator.kind, 'status'); events.push(['saved']); } });
  assert.deepEqual(await savePreferences(page, expect, 'original', true), { language: 'original', autoSummary: true });
  assert.deepEqual(events, [['visible'], ['data-automation-revision', 'report-automation-v4-remediation'], ...['До сохранения выбора внешняя отправка не разрешена.', MODEL, 'провайдеру Atlas Cloud', ENDPOINT,
    'отсутствие обучения (no-training)', 'но не отсутствие хранения', 'могут сохраняться', 'не Zero Data Retention (ZDR)'].map(text => ['disclosure', text]),
    ['Язык исходных описаний уязвимостей', 'original'], ['ИИ-разбор', 'on'], ['click', 'Сохранить настройки отчётов'], ['saved']]);
});

test('stale model or missing no-training/non-ZDR disclosure stops before any preference selection or save', async () => {
  for (const missing of ['data-automation-revision', MODEL, 'провайдеру Atlas Cloud', ENDPOINT, 'отсутствие обучения (no-training)', 'но не отсутствие хранения', 'могут сохраняться', 'не Zero Data Retention (ZDR)']) {
    const actions = [];
    const panel = { count: async () => 1, locator: () => ({ kind: 'disclosure' }),
      getByLabel: () => ({ selectOption: async () => actions.push('select') }),
      getByRole: () => ({ click: async () => actions.push('save') }) };
    const page = { getByRole: () => panel };
    const expect = () => ({ toBeVisible: async () => {},
      toHaveAttribute: async (name, value) => {
        assert.equal(value, AUTOMATION_REVISION);
        if (name === missing) throw new Error('STALE_DISCLOSURE');
      },
      toContainText: async text => { if (text === missing) throw new Error('STALE_DISCLOSURE'); } });
    await assert.rejects(savePreferences(page, expect, 'original', true), /STALE_DISCLOSURE/);
    assert.deepEqual(actions, []);
  }
});

function summaryFixture() {
  const counts = { secret: 0, sbom: 0, vuln: 1, config: 0 };
  const snapshot = { ...binding, identifierCounts: { cve: 1, debianTemp: 0 }, perCheck: Object.fromEntries(CHECKS.map(check =>
    [check, { outcome: 'checked', ...(check === 'sbom' ? { componentCount: 5 } : { findingCount: counts[check] }),
      scannerVersion: '0.69.3', checkedAt: '2026-10-27T00:00:00.000Z' }])) };
  const fullContext = { ...context, findingCount: 1, findingCounts: { byCheck: counts, bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, UNKNOWN: 0 } },
    identifierCounts: snapshot.identifierCounts, coverage: structuredClone(snapshot.perCheck) };
  const reply = { ...binding, findingCount: 1, findingCounts: structuredClone(fullContext.findingCounts), identifierCounts: snapshot.identifierCounts,
    coverage: structuredClone(fullContext.coverage), hypotheses: [{ kind: 'hypothesis', text: 'Синтетическая интерпретация', citations: [context.findingId] }],
    scannerFacts: [{ findingId: context.findingId, check: 'vuln', severity: 'HIGH' }],
    contextSelection: { totalFindings: 1, selectedFindings: 1, omittedFindings: 0, strategy: 'all-critical-and-unknown-then-severity', selectedFindingIds: [context.findingId] } };
  return { snapshot, fullContext, reply, checks: new Map([[context.findingId, 'vuln']]) };
}

test('one-summary qualification binds Russian text/citations, selected and whole counts, source snapshot and unchanged zero policy', async () => {
  const { chat } = await loadTranslationContracts();
  const qualify = ({ reply, fullContext, snapshot, checks }) => assertSummaryQualification(reply, fullContext, snapshot, checks, chat.validChatText);
  qualify(summaryFixture());
  const subset = summaryFixture(), otherId = `vuln-${'f'.repeat(64)}`;
  subset.checks.set(otherId, 'vuln');
  subset.snapshot.perCheck.vuln.findingCount = 2; subset.snapshot.identifierCounts.cve = 2;
  subset.fullContext.findingCount = 2; subset.fullContext.findingCounts.byCheck.vuln = 2;
  subset.fullContext.findingCounts.bySeverity.HIGH = 2; subset.fullContext.coverage.vuln.findingCount = 2;
  subset.reply.findingCount = 2; subset.reply.findingCounts.byCheck.vuln = 2;
  subset.reply.findingCounts.bySeverity.HIGH = 2; subset.reply.coverage.vuln.findingCount = 2;
  subset.reply.contextSelection.totalFindings = 2; subset.reply.contextSelection.selectedFindings = 2;
  subset.reply.contextSelection.selectedFindingIds.push(otherId);
  qualify(subset); // Actual server scannerFacts are the cited subset, not the entire selection.
  subset.reply.scannerFacts.push({ findingId: otherId, check: 'vuln', severity: 'HIGH' });
  assert.throws(() => qualify(subset)); // An uncited fact cannot masquerade as a cited source.
  for (const mutate of [f => { f.reply.digest = 'sha256:' + 'f'.repeat(64); }, f => { f.reply.reportVersion = 'f'.repeat(64); },
    f => { f.reply.hypotheses[0].text = 'Only English'; }, f => { f.reply.hypotheses[0].text = 'Русский\u202eтекст'; },
    f => { f.reply.hypotheses[0].citations = ['unknown']; }, f => { f.reply.hypotheses[0].citations.push(context.findingId); },
    f => { f.reply.findingCount++; }, f => { f.reply.findingCounts.byCheck.vuln++; }, f => { f.reply.identifierCounts = { cve: 0, debianTemp: 1 }; },
    f => { f.reply.coverage.secret.outcome = 'failed'; }, f => { f.fullContext.coverage.secret.checkedAt = 'wrong'; },
    f => { f.reply.contextSelection.selectedFindings = 2; }, f => { f.reply.contextSelection.omittedFindings = 1; },
    f => { f.reply.contextSelection.selectedFindingIds = ['unknown']; }, f => { f.reply.scannerFacts[0].check = 'secret'; },
    f => { f.reply.scannerFacts.push(f.reply.scannerFacts[0]); }, f => { f.checks.clear(); },
    f => { f.fullContext.disclosure = { ...f.fullContext.disclosure, requestBudgetUsd: 1 }; },
    f => { f.fullContext.disclosure = { ...f.fullContext.disclosure, model: 'fallback' }; },
    f => { f.fullContext.disclosure = { ...f.fullContext.disclosure, retention: 'no-storage' }; }]) {
    const fixture = summaryFixture(); mutate(fixture); assert.throws(() => qualify(fixture));
  }
});

test('summary usage read verifies bound zero costs without inferring consumed/refunded tokens or permitting a provider probe', () => {
  const usage = { ...binding, available: true, integrationEnabled: true, quotaEnabled: true,
    ...Object.fromEntries(['user', 'scan'].map(scope => [scope, Object.fromEntries(['used', 'held', 'carried'].map(vector =>
      [vector, { input: 10, output: 2, costMicros: 0 }]))])) };
  assert.doesNotThrow(() => assertZeroSummaryUsage(usage, context));
  for (const mutate of [v => { v.scan.used.costMicros = 1; }, v => { v.user.carried.costMicros = 1; },
    v => { v.scan.held.costMicros = -1; }, v => { v.available = false; }, v => { v.reportVersion = 'f'.repeat(64); }]) {
    const value = structuredClone(usage); mutate(value); assert.throws(() => assertZeroSummaryUsage(value, context));
  }
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
  assert.equal(SUMMARY_DRAIN_MS, GENERATION_MS); assert.equal(GENERATION_MS, 135_000);
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
  for (const retention of ['process-lifetime', 'durable', '', undefined]) {
    assert.throws(() => assertSummaryRestored({ ...retained,
      headers: { ...summaryHeaders, 'x-llm-summary-retention': retention } }, context, value),
      error => error.message === 'SUMMARY_READ_FAILED');
  }
  assert.throws(() => assertSummaryRestored(missingSummary(), context, value), error => error.message === 'SUMMARY_NOT_RESTORED');
  const controller = readFileSync(new URL('../server/api/src/llm/llm.controller.ts', import.meta.url), 'utf8');
  assert.match(controller, /'x-llm-summary-retention': 'durable-owner-scan'/);
  const book = new ResultBook(attemptId);
  assert.equal(book.evidence().summaryRetention, 'durable-owner-scan');
  assert.match(evidenceDocuments(book)[1], /API restart\/backup\/restore durability is not exercised/);
});

test('automatic disclosure exactly matches actual current helper; mismatched profile/data/privacy/extra metadata cannot dispatch', () => {
  const auth = { scanSession: () => ({ subject: 'fixture', generation: 1 }), subscribeScanSession: () => () => {} };
  const { REPORT_AUTOMATION_REVISION } = compileFrontend('../src/shared/api/preferences/reportPreferences.ts', {
      '@/shared/api/auth/scanSession': auth, react: {},
    });
    assert.equal(AUTOMATION_REVISION, REPORT_AUTOMATION_REVISION);
    const { allowAutomationDisclosure } = compileFrontend('../src/shared/api/scans/reportAutomation.ts', {
    '@/shared/api/auth/scanSession': auth, '@/shared/api/preferences/reportPreferences': { REPORT_AUTOMATION_REVISION: 'report-automation-v4-remediation', readReportPreferences: () => ({}) },
  });
  for (const kind of ['summary', 'translation']) {
    const correct = kind === 'summary' ? context.disclosure : translationDisclosure;
    const mutations = [correct, { ...correct, data: 'private payload' }, { ...correct, model: 'paid-model' },
      { ...correct, providers: [ENDPOINT, 'fallback'] }, { ...correct, region: 'elsewhere' }, { ...correct, retention: 'no-storage' },
            { ...correct, model: 'xingchen-agi/xing4.0-29b-a4b:free', providers: ['phala'], retention: 'no-storage' },
                  { ...correct, model: 'nvidia/nemotron-3.5-super-vl:free', providers: ['nvidia'], retention: 'no-training' },
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

test('every generation lane rejects stale or forged Dots/Atlas readiness before consuming its single-use permit', () => {
  for (const kind of ['summary', 'chat', 'translation'])
    for (const patch of [{ status: 'unverified-profile' }, { status: 'operator-approved-unprobed' }, { checkedOn: null },
      { checkedOn: '2026-10-21' }, { zdrListed: true }, { retention: 'no-storage' }, { retention: undefined },
      { model: 'unknown/model:free' }, { endpoint: 'phala' }, { liveVerified: true }, { extra: true }]) {
      const gate = new GenerationGate();
      const input = admission(kind, { readiness: { ...readiness, provider: { ...readiness.provider, ...patch } } });
      assert.equal(gate.admit(input), false); assert.equal(input.permit.used, false); assert.equal(gate.total, 0);
    }
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

test('generation budgets outlive API90 + metadata5/browser120; all old 45s generation paths are explicitly replaced', () => {
  assert.equal(METADATA_MS, 45_000); assert.equal(GENERATION_MS, 135_000);
  assert.ok(GENERATION_MS > 90_000 + 5_000); assert.ok(GENERATION_MS > 120_000);
  assert.equal(SUMMARY_DRAIN_MS, GENERATION_MS); assert.ok(WORKER_MS + GENERATION_MS + 120_000 < GLOBAL_MS);
  const code = source(); assert.equal((code.match(/45_000/g) ?? []).length, 1); // Only named metadata default.
  const delivered = code.slice(code.indexOf('  const delivered ='), code.indexOf('  const waitSummaryRead ='));
  assert.ok(delivered.includes('GENERATION_MS')); assert.ok(delivered.includes('generationDeadlines.get(key) - Date.now()'));
  assert.equal(delivered.includes('METADATA_MS'), false);
  const responseWait = code.slice(code.indexOf('  const responseFor ='), code.indexOf('  const readResponse ='));
  assert.ok(responseWait.includes('generationKind(path, scanId) ? GENERATION_MS : METADATA_MS'));
  for (const name of ['receiveGeneration', 'readGeneration']) {
    const body = name === 'receiveGeneration' ? code.slice(code.indexOf('export async function receiveGeneration'), code.indexOf('export async function readGeneration')) :
      code.slice(code.indexOf('export async function readGeneration'), code.indexOf('export function assertOneSummary'));
    assert.ok(body.includes('deadlineAt = Date.now() + GENERATION_MS'));
    assert.ok(body.includes('Math.max(0, deadlineAt - Date.now())')); assert.equal(body.includes('METADATA_MS'), false);
  }
  const step = code.slice(code.indexOf('  const step ='), code.indexOf('  const http ='));
  assert.equal(/bounded\(|45_000|METADATA_MS/.test(step), false);
  assert.ok(step.includes('gate.responseMeta')); // Shape/Russian/source failures retain finite HTTP/header evidence.
  assert.ok(code.includes('deadlineAt - Date.now() < GENERATION_MS'));
});

test('virtual long generation survives 45s headers/body cutoffs and uses one absolute 135s admission budget', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: 1000 });
  const flush = async () => { for (let index = 0; index < 12; index++) await Promise.resolve(); };
  const gate = new GenerationGate('summary-only'); gate.admit(admission('summary'));
  let requests = 0, settled = false;
  const pending = receiveGeneration({ response: () => {
    requests++; return new Promise(resolve => setTimeout(() => resolve({ ...response(200, {}),
      body: () => new Promise(resolve => setTimeout(() => resolve(Buffer.from('{}')), 35_000)) }), 95_000));
  } }, gate);
  pending.then(() => { settled = true; });
  t.mock.timers.tick(45_001); await flush(); assert.equal(settled, false);
  t.mock.timers.tick(49_999); await flush(); assert.equal(settled, false); // Headers at API90 + metadata5.
  t.mock.timers.tick(25_000); await flush(); assert.equal(settled, false); // Still observing at browser120.
  t.mock.timers.tick(10_000); await flush(); assert.deepEqual(await pending, {});
  assert.equal(requests, 1); assert.equal(gate.halted, false); assertOneSummary(gate);
});

test('45s-compatible replies still complete and an absolute timeout stops with header-only diagnostics, no retry', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: 1000 });
  const flush = async () => { for (let index = 0; index < 12; index++) await Promise.resolve(); };
  for (const ms of [1_000, 44_999, 90_001]) {
    const gate = new GenerationGate('summary-only'); gate.admit(admission('summary'));
    const pending = readGeneration({ ...response(200, {}), body: () => new Promise(resolve => setTimeout(() => resolve(Buffer.from('{}')), ms)) }, gate);
    t.mock.timers.tick(ms); await flush(); assert.deepEqual(await pending, {}); assertOneSummary(gate);
  }
  const gate = new GenerationGate('summary-only'); gate.admit(admission('summary'));
  const pending = receiveGeneration({ response: () => new Promise(resolve => setTimeout(() => resolve({ ...response(200, {}, {
    'x-llm-failure-phase': 'headers', 'x-llm-failure-reason': 'timeout', authorization: 'SYNTHETIC_PRIVATE' }),
    body: () => new Promise(() => {}) }), 95_000)) }, gate);
  const failure = assert.rejects(pending, error => {
    assert.equal(error.message, 'DELIVERY_UNCONFIRMED_NO_RETRY'); assert.equal(error.meta.httpStatus, 200);
        assert.deepEqual(error.meta.providerDiagnostic, { phase: 'headers', reason: 'timeout' });
    assert.equal(JSON.stringify(error.meta).includes('SYNTHETIC_PRIVATE'), false); return true;
  });
  t.mock.timers.tick(95_000); await flush();
    t.mock.timers.tick(39_999); await flush(); assert.equal(gate.halted, false);
    t.mock.timers.tick(1); await flush(); await failure;
  assert.equal(gate.halted, true); assert.equal(gate.busy, false);
  for (const kind of ['summary', 'chat', 'translation']) assert.equal(gate.admit(admission(kind)), false);
});

test('summary-only returns before the legacy four-call workflow on every outcome and route rejects chat/translation before dispatch', () => {
  const code = source();
  const guard = code.indexOf("if (summaryOnly && /\\/llm\\/(?:chat|translation)(?:\\/|$)/.test(path)) return deny('ai-permit-or-limit')");
  assert.ok(guard > 0); assert.ok(guard < code.indexOf('let body; try { body = request.postDataJSON()'));
  const branch = code.slice(code.indexOf('      if (summaryOnly) {'), code.indexOf('      for (const [index, question] of (translationOnly ? [] : QUESTIONS).entries())'));
  assert.ok(branch.includes('if (!summaryOk) return;')); assert.ok(branch.includes('gate.halted = true'));
  assert.ok(branch.includes("step('summary_reload_no_post'")); assert.ok(branch.includes("step('summary_reload_restore'"));
  assert.ok(branch.includes('assertZeroSummaryUsage')); assert.match(branch.trimEnd(), /return;\n\s+}$/);
  for (const forbidden of ['QUESTIONS', "savePreferences(", 'arm(', 'submit.click()', 'completeFreshOwnerLogin', "'/llm/chat'", "'/llm/translation'"])
    assert.equal(branch.includes(forbidden), false, forbidden);
  assert.ok(code.includes("new GenerationGate(mode)")); assert.ok(code.includes("mode === 'live' ? 'full' : mode"));
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
  for (const text of ["savePreferences(own.page, expect, 'original', !chatTranslationOnly)", "savePreferences(own.page, expect, 'ru', !chatTranslationOnly)",
    "arm(state, `${SCANS}/${scanId}/llm/summary`", "const target = TARGETS[0]", "for (const check of CHECKS)",
    "stats.accountsCreated !== 0", 'stats.scanLaunches !== 0', "gate.chatSuccesses++", 'completeFreshOwnerLogin',
    "assert.deepEqual((await readChat(own.page)).history, savedHistory)", "'SUMMARY_NOT_RESTORED'", "'SECOND_OWNER_NOT_AUTHORIZED'",
    'if (eligible.length !== 1) continue;', 'state.observations', 'readGeneration(response, gate', 'gate.admit(',
        'tools.chat.chatReadinessSchema.safeParse', 'readiness: readiness.data', 'passiveSummary: state.summaryReads.at(-1)',
        'summary_initial_missing', 'assertSummaryRestored(reloadRead', 'assertSummaryRestored(freshSummaryRead', 'response.request().method()',
    "not.toHaveAttribute('open', '')", 'assertCoverageWarning(region, expect)', 'samples.at(-1) > samples[0]']) assert.ok(code.includes(text), text);
  assert.ok(code.indexOf('arm(own, post,') < code.indexOf("row.locator('details.scan-vuln-row__details > summary').click()"));
  for (const forbidden of ['storageState(', 'screenshot(', 'recordHar', 'addCookies(', 'addInitScript(', 'localStorage.', 'sessionStorage.',
    'route.fulfill(', 'route.fetch(', 'spawn(', 'exec(', 'docker ', 'up --build', 'waitForTimeout(', "name: 'Повторить перевод'"])
    assert.equal(code.includes(forbidden), false, forbidden);
});

test('coverage tiles use all four actual canonical UI labels with exact selectors and retain checked/technical assertions', async () => {
  const labels = await loadCoverageLabels();
  assert.deepEqual(labels, { secret: 'Поиск секретов', sbom: 'Состав пакетов (SBOM)', vuln: 'Уязвимости', config: 'Конфигурация образа' });
  assert.equal(Object.isFrozen(labels), true);
  for (const check of CHECKS) {
    const calls = [], tile = {};
    const page = { getByText: (label, options) => { calls.push([label, options]); return { label }; } };
    const outcomes = { locator: selector => {
      assert.equal(selector, ':scope > li');
      return { filter: options => { assert.deepEqual(options, { has: { label: labels[check] } }); return tile; } };
    } };
    assert.equal(coverageTile(outcomes, page, labels, check), tile);
    assert.deepEqual(calls, [[labels[check], { exact: true }]]);
  }
  assert.throws(() => coverageTile({}, {}, labels, 'other'));
  assert.throws(() => coverageTile({}, {}, { ...labels, extra: 'bypass' }, 'secret'));
  const ui = readFileSync(new URL('../src/pages/scans/ScanDetailPage.tsx', import.meta.url), 'utf8');
  assert.ok(ui.includes('check: scanCheckLabels[check]'));
  assert.ok(ui.includes('<strong>{item.check}</strong>'));
  const branch = source().slice(source().indexOf("step('coverage_click'"), source().indexOf("step('report'"));
  assert.ok(branch.includes('coverageTile(outcomes, own.page, tools.coverageLabels, check)'));
  assert.ok(branch.includes("toHaveAttribute('data-outcome', 'checked')"));
  assert.ok(branch.includes("details.locator('summary').click()"));
  assert.ok(branch.includes("expect(details.locator('p').first()).toBeVisible()"));
});

test('coverage warning is the actual visible safety contract, not an invented disclosure button', async () => {
  const ui = readFileSync(new URL('../src/pages/scans/ScanDetailPage.tsx', import.meta.url), 'utf8');
  assert.ok(ui.includes(`className="scan-a1__coverage-note">${COVERAGE_WARNING}</p>`));
  const events = [], locator = {};
  await assertCoverageWarning({ getByText: (text, options) => { events.push([text, options]); return locator; } },
    value => { assert.equal(value, locator); return { toBeVisible: async () => { events.push('visible'); } }; });
  assert.deepEqual(events, [[COVERAGE_WARNING, { exact: true }], 'visible']);
  const branch = source().slice(source().indexOf("step('coverage_click'"), source().indexOf("step('report'"));
  assert.ok(branch.includes('assertCoverageWarning(region, expect)'));
  assert.equal(branch.includes('Что означает неполный отчёт?'), false);
  assert.equal(branch.includes('aria-expanded'), false);
  assert.ok(branch.includes('assert.equal(gate.total, before)'));
});

test('chat-translation-only needs its exact independent GO/three-post/deployed-source interface, never resumes an old attempt', () => {
  const flags = ['--run', '--chat-translation-only', '--ack-coordinator-readygo', '--ack-three-generation-posts', '--ack-source-deployed', '--attempt-id', attemptId];
  assert.equal(parseMode(flags), 'chat-translation-only');
  for (let index = 0; index < flags.length; index++) assert.throws(() => parseMode(flags.filter((_, i) => i !== index)));
  for (const ack of ['--ack-four-generation-posts', '--ack-one-generation-post', '--ack-three-provider-requests'])
    assert.throws(() => parseMode(flags.map(flag => flag === '--ack-three-generation-posts' ? ack : flag)));
  for (const extra of ['--summary-only', '--resume', '--scan-id', '--retry']) assert.throws(() => parseMode([...flags, extra]));
  assert.throws(() => parseMode([...flags.slice(0, -1), 'not-a-uuid']));
  assert.throws(() => assertFreshAttempt(attemptId, [`public-automation-${attemptId}.json`]));
});

test('isolated generation gate forbids summary on every outcome; only two successful sequential chats then one translation', () => {
  const gate = new GenerationGate('chat-translation-only');
  const allow = kind => admission(kind, { preferences: { language: kind === 'translation' ? 'ru' : 'original', autoSummary: false }, passiveSummary: undefined });
  assert.equal(gate.maxPosts, 3);
  assert.throws(() => { gate.mode = 'full'; }); assert.throws(() => { gate.maxPosts = 4; });
  assert.equal(gate.admit(allow('summary')), false);
  assert.equal(gate.admit(allow('translation')), false);
  for (let index = 0; index < 2; index++) {
    assert.equal(gate.admit(allow('chat')), true);
    for (const kind of ['summary', 'chat', 'translation']) assert.equal(gate.admit(allow(kind)), false);
    gate.finish();
    assert.equal(gate.admit(allow('chat')), false, 'completion must be validated before next chat');
    gate.chatSuccesses++;
    assert.equal(gate.admit(allow('summary')), false);
  }
  assert.equal(gate.admit(allow('chat')), false);
  assert.equal(gate.admit(allow('translation')), true); gate.finish();
  for (const kind of ['summary', 'chat', 'translation']) assert.equal(gate.admit(allow(kind)), false);
  assert.deepEqual(generationMetadata(gate), { total: 3, summaryPosts: 0, chatPosts: 2, translationPosts: 1, halted: false });
});

test('isolated mode preserves owner, snapshot, current readiness, consent/body and preferences guards without requiring summary', () => {
  const base = () => admission('chat', { preferences: { language: 'original', autoSummary: false }, passiveSummary: undefined });
  assert.equal(new GenerationGate('chat-translation-only').admit(base()), true);
  for (const patch of [{ owner: false }, { completed: false }, { permit: null }, { context: null },
    { report: { ...base().report, state: 'running' } }, { report: { ...base().report, perCheck: {} } },
    { readiness: { ...readiness, localReady: false } }, { readiness: { ...readiness, blockers: ['history-store-unavailable'] } },
    { readiness: { ...readiness, provider: { ...readiness.provider, model: 'fallback' } } },
    { preferences: null }, { preferences: { language: 'original', autoSummary: true } }]) {
    const request = { ...base(), ...patch }, gate = new GenerationGate('chat-translation-only');
    assert.equal(gate.admit(request), false); assert.equal(gate.total, 0); assert.equal(request.permit?.used ?? false, false);
  }
  for (const change of [request => { request.context = { ...request.context, reportVersion: 'bad' }; },
    request => { request.body.consent.accepted = false; }, request => { request.body.question = 'another'; },
    request => { request.body.extra = true; }]) {
    const request = base(); change(request); assert.equal(new GenerationGate('chat-translation-only').admit(request), false);
  }
});

test('isolated mode first HTTP/provider/parse failure permanently closes both chat and translation with no retry', async () => {
  for (const [status, value] of [[502, { errorCode: 'LLM_INVALID_RESPONSE' }], [429, { errorCode: 'LLM_PROVIDER_RATE_LIMITED' }],
    [503, { errorCode: 'LLM_PROVIDER_UNAVAILABLE' }], [200, '{invalid-json']]) {
    const gate = new GenerationGate('chat-translation-only');
    const request = () => admission('chat', { preferences: { language: 'original', autoSummary: false } });
    assert.equal(gate.admit(request()), true);
    await assert.rejects(readGeneration(response(status, value), gate, {}));
    assert.equal(gate.halted, true); assert.equal(gate.busy, false);
    for (const kind of ['summary', 'chat', 'translation']) assert.equal(gate.admit(admission(kind)), false);
    assert.deepEqual(generationMetadata(gate), { total: 1, summaryPosts: 0, chatPosts: 1, translationPosts: 0, halted: true });
  }
});

test('isolated evidence retains every non-summary criterion and marks summary NOT_RUN without rewriting the full-run verdict', () => {
  const book = new ResultBook(attemptId, 'chat-translation-only');
  assert.deepEqual(CHAT_TRANSLATION_CASES, CASES.filter(name => !name.startsWith('summary')));
  assert.deepEqual(book.requiredCases, CHAT_TRANSLATION_CASES);
  assert.equal(book.evidence().maxGenerationPosts, 3);
  for (const name of CASES.filter(name => name.startsWith('summary'))) assert.deepEqual(book.cases[name], { status: 'NOT_RUN', code: 'NOT_RUN' });
  for (const name of CHAT_TRANSLATION_CASES) book.record(name, name === 'settings_owner_isolation' ? 'BLOCKED' : 'PASS', name === 'settings_owner_isolation' ? 'SECOND_OWNER_NOT_AUTHORIZED' : 'VERIFIED');
  assert.equal(exitCode(book), 2, 'one-account isolation remains a real blocked criterion');
  assert.equal(book.evidence().maxAccounts, 1); assert.equal(book.evidence().maxScans, 1);
  assert.ok(evidenceDocuments(book)[1].includes('summary POSTs are forbidden'));
  const full = new ResultBook(attemptId); assert.deepEqual(full.requiredCases, CASES); assert.equal(full.evidence().maxGenerationPosts, 4);
  assert.equal(full.cases.summary.status, 'BLOCKED');
});

test('isolated source fences summary before any dispatch, disables automation in both settings saves and keeps all read/privacy/budget guards', () => {
  const code = source();
  const guard = code.indexOf("if (chatTranslationOnly && /\\/llm\\/summary(?:\\/|$)/.test(path)) return deny('ai-permit-or-limit')");
  assert.ok(guard > 0 && guard < code.indexOf('let body; try { body = request.postDataJSON()'));
  assert.ok(code.includes('if (!chatTranslationOnly) arm(state,'));
  assert.ok(code.includes("savePreferences(own.page, expect, 'original', !chatTranslationOnly)"));
  assert.ok(code.includes("savePreferences(own.page, expect, 'ru', !chatTranslationOnly)"));
  const summaryBranch = code.slice(code.indexOf('      if (!chatTranslationOnly) {'), code.indexOf('      if (summaryOnly) {'));
  assert.ok(summaryBranch.includes("step('summary_initial_missing'")); assert.ok(summaryBranch.includes("step('summary'"));
  assert.ok(code.includes('if (!chatTranslationOnly && !summaryOk || gate.halted || index === 1'));
  assert.ok(code.includes('if (chatTranslationOnly) { await own.page.reload();'));
  for (const guard of ['safeReadRequest(input, await request.allHeaders())', 'browserGetAllowed(input, knownIds)',
    'tools.chat.chatReadinessSchema.safeParse', 'readiness: readiness.data', 'gate.admit(',
    'chatTranslationOnly && gate.counts.summary !== 0', 'deadlineAt - Date.now() < GENERATION_MS']) assert.ok(code.includes(guard));
  assert.equal(GLOBAL_MS, 20 * 60_000); assert.equal(WORKER_MS, 660_000); assert.equal(GENERATION_MS, 135_000); assert.equal(METADATA_MS, 45_000);
});
