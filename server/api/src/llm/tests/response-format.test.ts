import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { HttpException } from '@nestjs/common';
import { validateChatReply } from '../history-contract.js';
import { OpenRouterProvider } from '../openrouter-provider.js';
import { FREE_MODEL, FREE_PROVIDER, policyFromEnvironment } from '../policy.js';
import { checkedPrepared, prepareHistory, prepareSummary, prepareTranslation } from '../prepared-request.js';
import { diagnostic } from '../provider-diagnostic.js';
import { validateReply } from '../response.js';
import { validateTranslationReply } from '../translation-contract.js';
import { envelope, fakeKey, fixtureEnv, fixturePolicy, fixtureReport, reply } from './fixtures.js';
import { quotaPolicy } from './quota-fixtures.js';

const policy = policyFromEnvironment({ ...fixtureEnv, LLM_FREE_ONLY: 'true', LLM_MODEL: 'xingchen-agi/xing4.0-29b-a4b:free',
  LLM_PROVIDER_ALLOWLIST: 'phala', LLM_REQUEST_BUDGET_USD: '0', LLM_INPUT_PRICE_PER_MILLION_USD: '0',
  LLM_OUTPUT_PRICE_PER_MILLION_USD: '0', LLM_REQUEST_PRICE_USD: '0' })!;
const source = { title: 'Memory flaw in Node.js', description: null };
const translated = { title: 'Ошибка памяти в Node.js', description: null };
const chat = { scanId: fixtureReport.scanId, digest: fixtureReport.digest, platform: fixtureReport.platform,
  reportVersion: fixtureReport.reportVersion, text: 'Сканер сообщил о находке; эксплуатация не установлена.',
  citations: [fixtureReport.findings[0].findingId] };

// These are controlled JSON-object-mode examples, NOT captured provider responses
// or explanations of sanitized324's unknown rejection. They expose the source gap:
// valid JSON alone does not express the publication validators' exact shapes.
const cases = [
  { name: 'summary', request: prepareSummary(fixtureReport, policy), valid: reply(fixtureReport),
    invalid: { summary: 'Сканер сообщил о находке.' }, validate: (value: unknown) => validateReply(value, fixtureReport, true) },
  { name: 'chat', request: prepareHistory({ report: fixtureReport, question: 'Что известно?' }, policy), valid: chat,
    invalid: { ...chat, kind: 'hypothesis' }, validate: (value: unknown) => validateChatReply(value, fixtureReport, true) },
  { name: 'translation', request: prepareTranslation(source, policy), valid: translated,
    invalid: { translation: translated }, validate: (value: unknown) => validateTranslationReply(value, source) },
];

for (const item of cases) test(`${item.name}: prepared provider schema matches parser keys, not the server-enriched DTO`, async () => {
  const body = JSON.parse(checkedPrepared(item.request, policy));
  const format = body.response_format;
  assert.equal(format.type, 'json_schema'); assert.equal(format.json_schema.strict, true);
  assert.equal(format.json_schema.name, `scanner_${item.name}`);
  const schema = format.json_schema.schema;
  assert.equal(schema.type, 'object'); assert.equal(schema.additionalProperties, false);
  assert.deepEqual(schema.required, Object.keys(item.valid));
  assert.deepEqual(Object.keys(schema.properties), Object.keys(item.valid));
  if (item.name === 'summary') {
    const hypothesis = schema.properties.hypotheses.items;
    assert.equal(schema.properties.hypotheses.type, 'array');
    assert.equal(hypothesis.additionalProperties, false);
    assert.deepEqual(hypothesis.required, ['text', 'citations']);
    assert.deepEqual(hypothesis.properties, { text: { type: 'string' }, citations: { type: 'array', items: { type: 'string' } } });
  } else if (item.name === 'chat') {
    assert.deepEqual(schema.properties.text, { type: 'string' });
    assert.deepEqual(schema.properties.citations, { type: 'array', items: { type: 'string' } });
  } else {
    assert.deepEqual(schema.properties, { title: { type: 'string' }, description: { type: 'null' } });
    assert.deepEqual(JSON.parse(body.messages[1].content), source);
    assert.doesNotMatch(item.request.body, /scanId|reportVersion|sourceVersion|provenanceRef|findingId/);
  }
  for (const value of [item.valid, item.invalid]) {
    let calls = 0, observations = 0;
    const provider = new OpenRouterProvider(fakeKey, (async (_url, init) => {
      calls++; assert.equal(init?.body, item.request.body);
      return new Response(JSON.stringify({ ...envelope(value), model: policy.model,
        usage: { prompt_tokens: 500, completion_tokens: 32, cost: 0 } }), { headers: { 'content-type': 'application/json' } });
    }) as typeof fetch);
    const parsed = await provider.summarizePrepared(item.request, policy, new AbortController().signal,
      { policy: quotaPolicy, observe() { observations++; } });
    if (value === item.valid) assert.doesNotThrow(() => item.validate(parsed));
    else assert.throws(() => item.validate(parsed), error => {
      assert.ok(error instanceof HttpException); assert.deepEqual(error.getResponse(), { errorCode: 'LLM_INVALID_RESPONSE' }); return true;
    });
    assert.equal(calls, 1); assert.equal(observations, 1, 'accounting precedes local shape rejection; never repair or retry');
  }
});

test('translation schema mirrors each selected field null independently, without adding local source metadata', () => {
  for (const text of [source, { title: null, description: 'Memory flaw' }, { title: 'Memory flaw', description: 'Details' }]) {
    const wire = JSON.parse(prepareTranslation(text, policy).body);
    assert.deepEqual(JSON.parse(wire.messages[1].content), text);
    for (const field of ['title', 'description'] as const)
      assert.deepEqual(wire.response_format.json_schema.schema.properties[field], { type: text[field] === null ? 'null' : 'string' });
    assert.equal(wire.plugins, undefined); assert.equal(wire.tools, undefined); assert.equal(wire.models, undefined);
  }
});

test('schema-conforming but ungrounded, English, unsafe or changed-identifier replies still fail locally', () => {
  const summary = reply(fixtureReport);
  assert.throws(() => validateReply({ ...summary, reportVersion: 'f'.repeat(64) }, fixtureReport, true));
  assert.throws(() => validateReply({ ...summary, hypotheses: [{ text: 'Придуманная находка.', citations: ['foreign-id'] }] }, fixtureReport, true));
  assert.throws(() => validateChatReply({ ...chat, text: 'This finding is safe.' }, fixtureReport, true));
  assert.throws(() => validateChatReply({ ...chat, text: 'Неизвестная находка CVE-2099-9999.' }, fixtureReport, true));
  for (const title of ['Ошибка https://evil.test', 'Ошибка в OpenSSL', 'Memory flaw in Node.js'])
    assert.throws(() => validateTranslationReply({ title, description: null }, source));
  // Preserve the existing fail-closed limit on unknown technical names; do not
  // exempt arbitrary source words to force a Russian-script check to succeed.
  assert.throws(() => validateTranslationReply({ title: 'Ошибка в zlib', description: null }, { title: 'Flaw in zlib', description: null }), error => {
    assert.deepEqual(diagnostic(error), { phase: 'translation_title', reason: 'not_russian' }); return true;
  });
});

test('new response contract invalidates pre-schema consent/cache identity; separate legacy profiles stay JSON-object mode', () => {
  const { version, ...settings } = policy;
  const previous = createHash('sha256').update(JSON.stringify({ revision: fixtureEnv.LLM_POLICY_REVISION,
    responseLanguageRevision: 'russian-prose-v3-grounded', ...settings })).digest('hex');
  assert.notEqual(version, previous);
  const legacy = { ...policy, model: FREE_MODEL, providers: [FREE_PROVIDER] };
  for (const request of [prepareSummary(fixtureReport, fixturePolicy), prepareSummary(fixtureReport, legacy), prepareHistory({}, legacy)])
    assert.deepEqual(JSON.parse(request.body).response_format, { type: 'json_object' });
});
