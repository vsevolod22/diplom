import { openAiSettings as baseSettings, openAiPrompts as moduleApiPrompts, openAiReport as moduleApiReport, openAiHistory as moduleApiHistory, openAiReply as moduleApiReply, openAiText as moduleApiText } from './openai-core.fixture.js';
import assert from 'node:assert/strict';
import test from 'node:test';
import { HttpException } from '@nestjs/common';
import { createModuleApiPolicy, checkedModuleApiPolicy, MODULEAPI_ENDPOINT, MODULEAPI_MODEL, type ModuleApiPolicy, type ModuleApiSettings } from '../moduleapi-policy.js';
import { prepareModuleApiSummary, prepareModuleApiChat, checkedModuleApiPrepared, validateModuleApiPreparedReply, type ModuleApiPrepared } from '../moduleapi-prepared-request.js';
import { diagnostic } from '../provider-diagnostic.js';
import { PUBLIC_IMAGE_PROFILE } from '../../oci/public-image-policy.js';
import { validateReply } from '../response.js';
import { validateChatReply } from '../history-contract.js';
import type { ReportContext, SafeFinding } from '../report-context.js';

const configuration = (error: unknown) => error instanceof HttpException && error.getStatus() === 503 &&
  (error.getResponse() as { errorCode: string }).errorCode === 'LLM_CONFIGURATION_UNAVAILABLE';


const moduleApiSettings: ModuleApiSettings = { ...baseSettings, model: MODULEAPI_MODEL, retention: 'unknown', monetaryLimit: 'capped', requestBudgetMicros: 100_000 };
const makeModuleApiPolicy = (overrides: Partial<ModuleApiSettings> = {}) => {
  const policy = createModuleApiPolicy({ ...moduleApiSettings, ...overrides }, moduleApiPrompts);
  if (!policy) throw new Error('Invalid synthetic ModuleAPI policy fixture');
  return policy;
};

test('ModuleAPI policy is explicit snapshot/approval/prices/budget only, disabled/incomplete/alternate models never default', () => {
  assert.equal(MODULEAPI_MODEL, 'gpt-5.4-mini'); assert.equal(MODULEAPI_ENDPOINT, 'https://moduleapi.pro/v1/chat/completions');
  const policy = makeModuleApiPolicy(); assert.ok(Object.isFrozen(policy)); assert.equal(policy.provider, 'ModuleAPI');
  for (const patch of [{ enabled: false }, { enabled: undefined }, { routingApproved: false }, { retention: 'no-storage' }, { retention: 'no-training' },
    { model: 'gpt-5.4-mini-2026-03-17' }, { model: 'gpt-4o-mini' }, { model: 'moduleapi/gpt-5.4-mini-2026-03-17' },
    { model: 'dots-studio/dots-3-note-preview:free' }, { revision: '' }, { revision: 'bad revision' },
    { inputPriceMicrosPerMillion: 0 }, { outputPriceMicrosPerMillion: 0 }, { requestBudgetMicros: 0 },
    { inputPriceMicrosPerMillion: '1000000' }, { requestBudgetMicros: NaN }, { outputTokens: 4097 },
    { timeoutMs: 90001 }, { requestBytes: 262145 }, { responseBytes: 65537 }, { inputTokens: 65537 }, { findings: 1001 },
    { endpoint: 'https://invalid.example' }, { temperature: 0 }, { apiKey: 'synthetic' }])
    assert.equal(createModuleApiPolicy({ ...moduleApiSettings, ...patch }, moduleApiPrompts), null, JSON.stringify(patch));
  for (const field of Object.keys(moduleApiSettings)) {
    const missing: Record<string, unknown> = { ...moduleApiSettings }; delete missing[field];
    assert.equal(createModuleApiPolicy(missing, moduleApiPrompts), null, field);
  }
  for (const prompts of [{ ...moduleApiPrompts, summary: '' }, { ...moduleApiPrompts, chat: 'x'.repeat(16385) },
    { ...moduleApiPrompts, summary: 'bad\u0000prompt' }, { ...moduleApiPrompts, template: 'extra' }])
    assert.equal(createModuleApiPolicy(moduleApiSettings, prompts), null);
});

test('policy version binds exact settings and immutable server prompts; policy copies/forged and cross-instance prepared objects have no authority', () => {
  const mutable = { ...moduleApiPrompts }, settings = { ...moduleApiSettings };
  const policy = createModuleApiPolicy(settings, mutable)!;
  mutable.summary = 'Changed prompt'; settings.outputTokens = 1;
  assert.equal(checkedModuleApiPolicy(policy).summary, moduleApiPrompts.summary); assert.ok(Object.isFrozen(checkedModuleApiPolicy(policy)));
  const equal = makeModuleApiPolicy(); assert.equal(equal.version, policy.version);
  for (const candidate of [createModuleApiPolicy(moduleApiSettings, { ...moduleApiPrompts, chat: 'Another prompt' })!,
    makeModuleApiPolicy({ inputPriceMicrosPerMillion: 1 }), makeModuleApiPolicy({ requestBudgetMicros: 99999 }), makeModuleApiPolicy({ revision: 'offline-v2' })])
    assert.notEqual(candidate.version, policy.version);
  assert.throws(() => checkedModuleApiPolicy({ ...policy }), configuration);
  const request = prepareModuleApiSummary(moduleApiReport, policy);
  assert.throws(() => checkedModuleApiPrepared(request, equal), configuration);
  for (const forged of [{ ...request }, { ...request, policyVersion: equal.version }, JSON.parse(JSON.stringify(request))])
    assert.throws(() => checkedModuleApiPrepared(forged as ModuleApiPrepared, policy), configuration);
  assert.throws(() => prepareModuleApiSummary(moduleApiReport, { ...policy } as ModuleApiPolicy), configuration);
});

test('summary/chat wire has direct-Russian selected server prompt, strict closed schema, none reasoning, storefalse and no temperature/router fallback', () => {
  const policy = makeModuleApiPolicy();
  for (const [request, input] of [[prepareModuleApiSummary(moduleApiReport, policy), moduleApiReport], [prepareModuleApiChat(moduleApiHistory, policy), moduleApiHistory]] as const) {
    assert.ok(Object.isFrozen(request) && Object.isFrozen(request.reserve)); checkedModuleApiPrepared(request, policy);
    const wire = JSON.parse(request.body);
    assert.deepEqual(Object.keys(wire).sort(), ['model', 'max_completion_tokens', 'reasoning_effort', 'n', 'stream', 'store', 'service_tier', 'response_format', 'messages'].sort());
    assert.equal(wire.model, MODULEAPI_MODEL); assert.equal(wire.max_completion_tokens, policy.outputTokens); assert.equal(wire.reasoning_effort, 'none');
    assert.equal(wire.n, 1); assert.equal(wire.stream, false); assert.equal(wire.store, false); assert.equal(wire.service_tier, 'default');
    assert.equal(wire.messages[0].content, moduleApiPrompts[request.operation]); assert.deepEqual(JSON.parse(wire.messages[1].content), input);
    assert.equal(wire.response_format.type, 'json_schema'); assert.equal(wire.response_format.json_schema.strict, true);
    const schema = wire.response_format.json_schema.schema;
    assert.equal(schema.additionalProperties, false); assert.deepEqual(schema.required.sort(), Object.keys(schema.properties).sort());
    if (request.operation === 'summary') { assert.equal(schema.properties.hypotheses.maxItems, 6); assert.equal(schema.properties.hypotheses.items.additionalProperties, false); }
    else { assert.equal(schema.properties.text.maxLength, 600); assert.equal(schema.properties.citations.maxItems, 3); }
    assert.equal(request.reserve.input, Buffer.byteLength(request.body) + 1024); assert.equal(request.reserve.output, policy.outputTokens);
    assert.ok(request.reserve.costMicros > 0);
  }
});

test('preparation snapshots authorized evidence without getters/toJSON/cycles/exotic objects, rejects invalid report/history shapes and budget', () => {
  const policy = makeModuleApiPolicy(); let reads = 0;
  const getter = Object.defineProperty({ ...moduleApiReport }, 'findings', { enumerable: true, get() { reads++; return []; } });
  const cycle: Record<string, unknown> = { ...moduleApiReport }; cycle.coverage = cycle;
  for (const value of [getter, cycle, { ...moduleApiReport, toJSON() { reads++; return moduleApiReport; } },
    { ...moduleApiReport, [Symbol('extra')]: 'bad' }, { ...moduleApiReport, findings: [] }, { ...moduleApiReport, profile: 'unknown' },
    { ...moduleApiReport, profile: PUBLIC_IMAGE_PROFILE }, { ...moduleApiReport, findingCount: 2 },
    { ...moduleApiReport, findings: [moduleApiReport.findings[0], moduleApiReport.findings[0]], findingCount: 2 },
    { ...moduleApiReport, scanId: 'bad' }, { ...moduleApiReport, findings: [{ ...moduleApiReport.findings[0], raw: 'extra' }] },
    { ...moduleApiReport, coverage: new Date() }]) assert.throws(() => prepareModuleApiSummary(value as ReportContext, policy), configuration);
  assert.equal(reads, 0);
  const mutable = structuredClone(moduleApiReport), request = prepareModuleApiSummary(mutable, policy), body = request.body;
  mutable.findings[0].findingId = 'secret-0-999'; mutable.reportVersion = 'd'.repeat(64);
  assert.equal(request.body, body); assert.doesNotThrow(() => validateModuleApiPreparedReply(request, policy, moduleApiReply()));
  for (const patch of [{ question: 'password=synthetic' }, { history: { ...moduleApiHistory.history, epoch: 'bad' } },
    { omission: { ...moduleApiHistory.omission, selectedFindingIds: [] } }, { history: { ...moduleApiHistory.history, userTurns: [{ id: 'bad' }] } }])
    assert.throws(() => prepareModuleApiChat({ ...moduleApiHistory, ...patch }, policy), configuration);
  assert.throws(() => prepareModuleApiSummary(moduleApiReport, makeModuleApiPolicy({ requestBudgetMicros: 1 })), configuration);
  assert.throws(() => prepareModuleApiSummary(moduleApiReport, makeModuleApiPolicy({ requestBytes: 100 })), configuration);
});

test('public prepared evidence retains exact cited package/CVE authority and Russian guards without granting uncited findings', () => {
  const first: SafeFinding = { check: 'vuln', findingId: `vuln-${'a'.repeat(64)}`, severity: 'HIGH', cveId: 'CVE-2026-1234',
    identifierKind: 'cve', ecosystem: 'deb', packageName: 'libc6', installedVersion: '1.0', fixedVersion: null,
    severitySources: ['nvd'], provenanceRef: `target-${'b'.repeat(64)}`, fixedVersionReported: false, advisoryState: 'unknown' };
  const second: SafeFinding = { ...first, findingId: `vuln-${'c'.repeat(64)}`, cveId: 'CVE-2026-5678', packageName: 'other-library' };
  const context: ReportContext = { ...moduleApiReport, profile: PUBLIC_IMAGE_PROFILE, requestedChecks: ['vuln'], findings: [first, second], findingCount: 2,
    coverage: { ...moduleApiReport.coverage, secret: { outcome: 'unknown', reason: 'CHECK_NOT_REQUESTED' }, vuln: { outcome: 'checked', findingCount: 2 } },
    omittedEvidence: 'All free text, URLs, credentials, env and raw output excluded; package identities and versions are sanitized scanner facts' };
  const policy = makeModuleApiPolicy(), request = prepareModuleApiSummary(context, policy);
  const answer = (text: string) => ({ scanId: context.scanId, digest: context.digest, platform: context.platform, reportVersion: context.reportVersion,
    hypotheses: [{ text, citations: [first.findingId] }] });
  const text = 'В указанной находке сообщено об уязвимости. Применимость требует проверки.';
  assert.deepEqual(validateModuleApiPreparedReply(request, policy, answer(text)), { operation: 'summary', value: validateReply(answer(text), context, true) });
  for (const bad of ['Пакет other-library.', 'Проверить CVE-2026-5678.', 'Проверить libc6. This finding is safe.'])
    assert.throws(() => validateModuleApiPreparedReply(request, policy, answer(bad)), error => {
      assert.ok(error instanceof HttpException); assert.equal(error.getStatus(), 502); assert.equal(diagnostic(error)?.phase, bad.includes('This') ? 'language' : 'grounding'); return true;
    });
});

test('prepared replies reuse existing exact source/Russian validators; no translation/repair and narrower schema caps are independently checked', () => {
  const policy = makeModuleApiPolicy();
  for (const operation of ['summary', 'chat'] as const) {
    const request = operation === 'summary' ? prepareModuleApiSummary(moduleApiReport, policy) : prepareModuleApiChat(moduleApiHistory, policy);
    const input = moduleApiReply(operation);
    const result = validateModuleApiPreparedReply(request, policy, input);
    assert.equal(result.operation, operation);
    assert.deepEqual(result.value, operation === 'summary' ? validateReply(input, moduleApiReport, true) : validateChatReply(input, moduleApiReport, true));
    assert.ok(JSON.stringify(result.value).includes(moduleApiText), 'double space is preserved, not auto-repaired');
    for (const text of ['This finding needs review.', 'Проверить CVE-2099-9999.']) {
      assert.throws(() => validateModuleApiPreparedReply(request, policy, moduleApiReply(operation, text)), error => {
        assert.ok(error instanceof HttpException); assert.equal(error.getStatus(), 502);
        assert.equal(diagnostic(error)?.phase, text.startsWith('This') ? 'language' : 'grounding'); return true;
      });
    }
    assert.throws(() => validateModuleApiPreparedReply(request, policy, { ...input, digest: `sha256:${'d'.repeat(64)}` }));
    const bad = operation === 'summary' ? { ...input, hypotheses: [{ text: moduleApiText, citations: ['foreign-finding'] }] }
      : { ...input, citations: ['foreign-finding'] };
    assert.throws(() => validateModuleApiPreparedReply(request, policy, bad));
    assert.throws(() => validateModuleApiPreparedReply(request, policy, moduleApiReply(operation, 'я'.repeat(operation === 'summary' ? 321 : 601))));
  }
  const request = prepareModuleApiSummary(moduleApiReport, policy);
  assert.throws(() => validateModuleApiPreparedReply(request, policy, { ...moduleApiReply(), hypotheses: Array.from({ length: 7 }, () => ({ text: moduleApiText, citations: ['secret-0-1'] })) }));
});
