import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { HttpException } from '@nestjs/common';
import { PUBLIC_IMAGE_PROFILE } from '../../oci/public-image-policy.js';
import { validateChatReply } from '../history-contract.js';
import { OpenRouterProvider } from '../openrouter-provider.js';
import { CEILINGS, FREE_MODEL, FREE_PROVIDER, policyFromEnvironment } from '../policy.js';
import { checkedPrepared, prepareHistory, prepareSummary, prepareTranslation } from '../prepared-request.js';
import { diagnostic } from '../provider-diagnostic.js';
import { validateReply } from '../response.js';
import type { ReportContext } from '../report-context.js';
import { translationPolicy, validateTranslationReply } from '../translation-contract.js';
import { envelope, fakeKey, fixtureEnv, fixturePolicy, fixtureReport, reply } from './fixtures.js';
import { quotaPolicy } from './quota-fixtures.js';

const policy = policyFromEnvironment({ ...fixtureEnv, LLM_FREE_ONLY: 'true', LLM_MODEL: 'dots-studio/dots-3-note-preview:free',
  LLM_PROVIDER_ALLOWLIST: 'atlas-cloud/fp8', LLM_RETENTION: 'no-training', LLM_REQUEST_BUDGET_USD: '0', LLM_INPUT_PRICE_PER_MILLION_USD: '0',
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
    assert.equal(schema.properties.hypotheses.maxItems, 6);
        assert.equal(schema.properties.hypotheses.minItems, 1);
        assert.deepEqual(hypothesis.properties, { text: { type: 'string', maxLength: 320 },
          citations: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 2 } });
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

test('public summary provider round trip keeps cited scores and labels exact, rejects invented scores after one usage observation', async () => {
  const finding = { ...fixtureReport.findings[0], cveId: 'CVE-2026-1234', identifierKind: 'cve', ecosystem: 'deb',
    packageName: 'libc6', installedVersion: '1.0', fixedVersion: null,
    assessments: [{ cvss: { scoreState: 'available', reportedScore: 7.5 } }] };
  const report: ReportContext = { ...fixtureReport, profile: PUBLIC_IMAGE_PROFILE, findings: [finding] };
  const request = prepareSummary(report, policy);
  for (const [text, accepted] of [
    ['Пакет:libc6; версия:1.0. Сканер сообщил CVSS 7.5.', true],
    ['Пакет:libc6; версия:1.0. Оценка CVSS:7,5.', true],
    ['Пакет:libc6; версия:1.0. Оценка CVSS 9,9.', false],
    ['Пакет:libc6; версия:1.0. Сканер сообщил 99 баллов.', false],
  ] as const) {
    const value = { ...reply(report), hypotheses: [{ text, citations: [finding.findingId] }] };
    let calls = 0, observations = 0;
    const provider = new OpenRouterProvider(fakeKey, (async (_url, init) => {
      calls++; assert.equal(init?.body, request.body);
      return new Response(JSON.stringify({ ...envelope(value), model: policy.model,
        usage: { prompt_tokens: 500, completion_tokens: 32, cost: 0 } }), { headers: { 'content-type': 'application/json' } });
    }) as typeof fetch);
    const parsed = await provider.summarizePrepared(request, policy, new AbortController().signal,
      { policy: quotaPolicy, observe(observation) { observations++; assert.equal(observation.normal, true); } });
    assert.deepEqual(parsed, value);
    if (accepted) {
      const result = validateReply(parsed, report, true);
      assert.equal(result.hypotheses[0].text, text); assert.deepEqual(result.scannerFacts, [finding]);
    } else assert.throws(() => validateReply(parsed, report, true), error => {
      assert.ok(error instanceof HttpException); assert.deepEqual(error.getResponse(), { errorCode: 'LLM_INVALID_RESPONSE' });
      assert.deepEqual(diagnostic(error), { phase: 'grounding', reason: 'unknown_identifier' }); return true;
    });
    assert.equal(calls, 1); assert.equal(observations, 1, 'local rejection never retries or erases accounted usage');
  }
});

test('public summary/chat concision is prompt-only; bindings, privacy, schemas and configured token caps stay exact', () => {
  const context = { report: fixtureReport, question: 'Что известно?' };
  const summary = JSON.parse(prepareSummary(fixtureReport, policy).body);
  const history = JSON.parse(prepareHistory(context, policy).body);
  assert.match(summary.messages[0].content, /4-6 коротких абзацев, суммарно не более 1600 символов текста/);
  assert.match(summary.messages[0].content, /В citations перечисли findingId КАЖДОЙ находки/);
  assert.match(summary.messages[0].content, /что проверить или исправить первым; объясни почему/);
  assert.match(summary.messages[0].content, /сообщённую исправленную версию, только если они переданы/);
  assert.match(summary.messages[0].content, /Если исправленная версия неизвестна, скажи об этом/);
  assert.match(summary.messages[0].content, /не доказывает возможность эксплуатации, доступность из сети или последствия/);
  assert.match(summary.messages[0].content, /не угадывай механизм CVE, последствия или команды/);
  assert.match(summary.messages[0].content, /пропуски выборки и неизвестное\/неуспешное покрытие/);
  assert.match(summary.messages[0].content, /Не обсуждай модель, провайдера, JSON, цитирование или внутреннюю архитектуру/);
  assert.match(summary.messages[0].content, /hypotheses array is a compatibility envelope/);
  assert.match(history.messages[0].content, /text at most 600 characters of Russian prose/);
  assert.match(history.messages[0].content, /only 1-3 findingId values in citations/);
  assert.match(history.messages[0].content, /Use less text and fewer citations when the question requires less/);
  for (const wire of [summary, history]) {
    const prompt = wire.messages[0].content;
    assert.match(prompt, /Весь человекочитаемый текст пиши по-русски кириллицей/);
    assert.match(prompt, /НИКОГДА не копируй в прозу исходные названия проверок, статусы, уровни серьёзности или имена полей: sbom\/config\/secret\/vuln\/checked\/CRITICAL\/LOW/);
    assert.match(prompt, /Передавай их смысл русскими словами, не меняя фактов и неизвестного покрытия/);
    assert.match(prompt, /Конкретные CVE\/TEMP, packageName, installedVersion, fixedVersion бери только из находок, указанных в citations именно этого абзаца/);
    assert.match(prompt, /Only packageName, installedVersion and fixedVersion in cited findings/);
    assert.match(prompt, /A null fixedVersion is unknown; fixedVersionReported alone supplies no version/);
    assert.match(prompt, /A reported fix is scanner data, not proof that upgrading is sufficient or compatible/);
    assert.doesNotMatch(prompt, /Package\/version strings are intentionally excluded/);
    assert.match(prompt, /идентификаторы сохраняй без изменений в JSON-привязках и массивах citations, а не повторяй в прозе/);
    assert.match(prompt, /Собственные технические имена можно опустить; не переводи и не транслитерируй идентификаторы/);
    assert.match(prompt, /Ключи JSON, привязки отчёта и идентификаторы цитат оставляй точными/);
  }
  assert.deepEqual(JSON.parse(summary.messages[1].content), fixtureReport);
  assert.deepEqual(JSON.parse(history.messages[1].content), context);
  assert.equal(CEILINGS.outputTokens, 2048);
  for (const outputTokens of [policy.outputTokens, 2048, 2049, 4096]) {
    const bounded = { ...policy, outputTokens };
    for (const request of [prepareSummary(fixtureReport, bounded), prepareHistory(context, bounded), prepareTranslation(source, bounded)]) {
      const wire = JSON.parse(request.body);
      assert.equal(wire.max_tokens, outputTokens); assert.equal(request.reserve.output, outputTokens);
      assert.equal(request.reserve.costMicros, 0); assert.equal(wire.stream, false);
      assert.deepEqual(wire.reasoning, { enabled: false, exclude: true });
      assert.deepEqual(wire.provider, { only: ['atlas-cloud/fp8'], allow_fallbacks: false, require_parameters: true,
        data_collection: 'deny', max_price: { prompt: 0, completion: 0, request: 0 } });
      assert.equal(wire.response_format.json_schema.strict, true);
      if (wire.response_format.json_schema.name === 'scanner_summary') {
              const paragraphs = wire.response_format.json_schema.schema.properties.hypotheses;
              assert.equal(paragraphs.maxItems, 6);
              assert.equal(paragraphs.items.properties.text.maxLength, 320);
              assert.equal(paragraphs.items.properties.citations.maxItems, 2);
            } else assert.doesNotMatch(JSON.stringify(wire.response_format), /"(?:maxLength|maxItems)"/);
      assert.equal(wire.models, undefined); assert.equal(wire.tools, undefined); assert.equal(wire.plugins, undefined);
    }
  }
  assert.equal(policyFromEnvironment({ ...fixtureEnv, LLM_OUTPUT_TOKENS: '2049' }), null);
  assert.throws(() => prepareSummary(fixtureReport, { ...policy, outputTokens: 4097 }));
  assert.throws(() => prepareHistory(context, { ...policy, outputTokens: 4097 }));
  const legacy = { ...policy, model: FREE_MODEL, providers: [FREE_PROVIDER], retention: 'no-storage' as const };
  for (const request of [prepareSummary(fixtureReport, fixturePolicy), prepareSummary(fixtureReport, legacy),
    prepareHistory(context, legacy), prepareTranslation(source, policy)])
    assert.doesNotMatch(JSON.parse(request.body).messages[0].content, /4-6 коротких абзацев|1600 символов|at most 600 characters|Весь человекочитаемый текст|НИКОГДА не копируй/);
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
  for (const label of ['sbom', 'config', 'secret', 'vuln', 'checked', 'CRITICAL', 'LOW']) {
    const text = `Сканер сообщил о находке: ${label}.`;
    assert.throws(() => validateReply({ ...summary, hypotheses: [{ text, citations: chat.citations }] }, fixtureReport, true));
    assert.throws(() => validateChatReply({ ...chat, text }, fixtureReport, true));
  }
  for (const title of ['Ошибка https://evil.test', 'Ошибка в OpenSSL', 'Memory flaw in Node.js'])
    assert.throws(() => validateTranslationReply({ title, description: null }, source));
  // Preserve the existing fail-closed limit on unknown technical names; do not
  // exempt arbitrary source words to force a Russian-script check to succeed.
  assert.throws(() => validateTranslationReply({ title: 'Ошибка в zlib', description: null }, { title: 'Flaw in zlib', description: null }), error => {
    assert.deepEqual(diagnostic(error), { phase: 'translation_title', reason: 'not_russian' }); return true;
  });
});

test('remediation v10 revision invalidates v7 consent/cache identity; separate legacy profiles stay JSON-object mode', () => {
  const { version, ...settings } = policy;
  const previous = createHash('sha256').update(JSON.stringify({ revision: fixtureEnv.LLM_POLICY_REVISION,
    responseLanguageRevision: 'russian-remediation-v7', ...settings })).digest('hex');
  assert.equal(version, createHash('sha256').update(JSON.stringify({ revision: fixtureEnv.LLM_POLICY_REVISION,
    responseLanguageRevision: 'russian-remediation-v10-bounded', ...settings })).digest('hex'));
  assert.notEqual(version, previous);
  assert.notEqual(translationPolicy(policy), translationPolicy({ ...policy, version: previous }));
  const legacy = { ...policy, model: FREE_MODEL, providers: [FREE_PROVIDER], retention: 'no-storage' as const };
  for (const request of [prepareSummary(fixtureReport, fixturePolicy), prepareSummary(fixtureReport, legacy), prepareHistory({}, legacy)])
    assert.deepEqual(JSON.parse(request.body).response_format, { type: 'json_object' });
});
