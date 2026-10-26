import assert from 'node:assert/strict';
import test from 'node:test';
import { HttpException } from '@nestjs/common';
import { checkedTranslationText, validateTranslationReply } from '../translation-contract.js';
import { russianHumanText } from '../russian-text.js';
import { validateReply } from '../response.js';
import { validateChatReply } from '../history-contract.js';
import { prepareHistory, prepareSummary } from '../prepared-request.js';
import { policyFromEnvironment } from '../policy.js';
import { diagnostic } from '../provider-diagnostic.js';
import { fixtureEnv, fixturePolicy, fixtureReport, reply } from './fixtures.js';

for (const [original, translated] of [
  ['Compiler flaw in C#', 'Ошибка компилятора C#'],
  ['Flaw in OpenSSL and libxml2', 'Ошибка OpenSSL и libxml2'],
  ['Memory flaw in Node.js', 'Ошибка памяти в Node.js'],
  ['Memory flaw in Node.js.', 'Ошибка памяти в Node.js.'],
  ['Node.js.', 'Node.js.'],
  ['OpenSSL', 'OpenSSL'], ['C#', 'C#'], ['Node.js', 'Node.js'], ['libxml2', 'libxml2'],
]) test(`preserves technical identifier without manufactured Russian filler: ${original}`, () => {
  const source = { title: original, description: null }, value = { title: translated, description: null };
  assert.deepEqual(checkedTranslationText(source), source);
  assert.deepEqual(validateTranslationReply(value, source), value);
});

test('technical exceptions cannot admit URLs, credentials, markup, changed names or untranslated prose', () => {
  for (const value of ['https://Node.js', 'Node.js/path', 'Node.js?private', 'Node.js#private', 'Node.js.evil.test', 'www.Node.js', 'node.js',
    'Node.js:443', 'Node.js@evil.test', 'Node.js./path', 'Node.js.?private', 'Node.js.#private', 'Node.js..',
    'Node.js.evil', 'Node.js. evil.test', 'evil.test', '192.168.1.2', 'api_key="private"', '<b>Node.js</b>'])
    assert.throws(() => checkedTranslationText({ title: value, description: null }), value);
  const source = { title: 'Compiler issue in C# and Node.js', description: null };
  for (const title of ['# Ошибка C# и Node.js', 'Ошибка C++ и Node.js', 'Ошибка C# и OtherRuntime', 'Ошибка C# и Node.js https://evil.test',
    'Compiler issue in C# and Node.js', 'и Compiler issue in C# and Node.js', 'Ошибка ** C# и Node.js'])
    assert.throws(() => validateTranslationReply({ title, description: null }, source), title);
  for (const title of ['Memory flaw', 'Authentication bypass', 'Some English sentence'])
    assert.throws(() => validateTranslationReply({ title, description: null }, { title, description: null }));
});

test('P2: arbitrary source-bound spelling cannot exempt untranslated CamelCase, snake_case or digit words', () => {
  for (const title of ['IgnorePreviousInstructions', 'AuthenticationBypass RemoteCodeExecution', 'HyperLongTechnicalComponentName',
    'IgnorePreviousInstructions2', 'ignore_previous_instructions', 'CVE-IgnorePreviousInstructions', 'TEMP-RemoteCodeExecution']) {
    assert.equal(russianHumanText(title, title), false, title);
    assert.equal(russianHumanText(`Ошибка ${title}`, title), false, title);
    assert.throws(() => validateTranslationReply({ title, description: null }, { title, description: null }), title);
    assert.throws(() => validateTranslationReply({ title: `Ошибка ${title}`, description: null }, { title, description: null }), title);
  }
  for (const name of ['C#', 'Node.js', 'OpenSSL', 'libxml2']) {
    assert.equal(russianHumanText(name, name), true, name);
    assert.equal(russianHumanText(name, 'Memory flaw'), false, name);
    assert.throws(() => validateTranslationReply({ title: `Ошибка ${name}`, description: null }, { title: 'Memory flaw', description: null }), name);
  }
});

test('P2: long Russian introductions cannot hide an untranslated English sentence in any publication validator', () => {
  const mixed = 'Подтверждено сканером: сохранённая находка требует подробной дополнительной проверки оператором. This finding is harmless and requires no action.';
  assert.equal(russianHumanText(mixed, mixed), false);
  assert.throws(() => validateTranslationReply({ title: mixed, description: null }, { title: mixed, description: null }));
  const value = reply(fixtureReport), citations = [fixtureReport.findings[0].findingId];
  assert.throws(() => validateReply({ ...value, hypotheses: [{ text: mixed, citations }] }, fixtureReport, true));
  assert.throws(() => validateChatReply({ scanId: fixtureReport.scanId, digest: fixtureReport.digest, platform: fixtureReport.platform,
    reportVersion: fixtureReport.reportVersion, text: mixed, citations }, fixtureReport, true));
});

test('summary/chat new-publication Russian guard rejects English but does not rewrite durable history or original sources', () => {
  const source = structuredClone(fixtureReport), original = structuredClone(source);
  const summary = reply(source);
  const result = validateReply(summary, source, true);
  assert.deepEqual(result.scannerFacts, source.findings);
  assert.deepEqual(source, original);
  const chat = { scanId: source.scanId, digest: source.digest, platform: source.platform, reportVersion: source.reportVersion,
    text: 'Подтверждено сканером: сохранена находка. Эксплуатация не установлена; требуется проверка.', citations: [source.findings[0].findingId] };
  assert.equal(validateChatReply(chat, source, true).text, chat.text);
  for (const text of ['This finding may need an investigation.', 'Проверка This finding may need a long operator investigation.', 'これは検証されていない回答です']) {
    assert.throws(() => validateReply({ ...summary, hypotheses: [{ text, citations: chat.citations }] }, source, true), error => {
      assert.ok(error instanceof HttpException); assert.deepEqual(diagnostic(error), { phase: 'language', reason: 'not_russian' }); return true;
    });
    assert.throws(() => validateChatReply({ ...chat, text }, source, true));
  }
  assert.equal(russianHumanText('OpenSSL', 'OpenSSL'), true);
  assert.equal(russianHumanText('UnknownRuntime', 'OpenSSL'), false);
});

test('grounding requires current cited findings and forbids newly invented CVE/TEMP identifiers', () => {
  const report = { ...fixtureReport, findings: [{ ...fixtureReport.findings[0], cveId: 'CVE-2025-1000' },
    { ...fixtureReport.findings[0], findingId: 'vuln-' + 'd'.repeat(64), cveId: 'CVE-2025-2000' }] };
  const summary = reply(report);
  const text = 'Подтверждено сканером: CVE-2025-1000. Эксплуатация остаётся неизвестной.';
  assert.equal(validateReply({ ...summary, hypotheses: [{ text, citations: [report.findings[0].findingId] }] }, report, true).scannerFacts.length, 1);
  for (const id of ['CVE-2025-2000', 'CVE-2099-9999', 'TEMP-1234567-ABCDEF']) {
    assert.throws(() => validateReply({ ...summary, hypotheses: [{ text: `Неизвестная уязвимость ${id}`, citations: [report.findings[0].findingId] }] }, report, true), error => {
      assert.deepEqual(diagnostic(error), { phase: 'grounding', reason: 'unknown_identifier' }); return true;
    });
  }
  assert.throws(() => validateReply({ ...summary, hypotheses: [{ text, citations: ['foreign-finding'] }] }, report, true));
  assert.equal(report.coverage.secret, fixtureReport.coverage.secret, 'unknown coverage remains authoritative source data');
});

test('new prompt revision invalidates previous consent; prompts separate scanner facts from uncertain interpretations', () => {
  const current = policyFromEnvironment(fixtureEnv)!;
  assert.equal(current.version, fixturePolicy.version);
  const free = policyFromEnvironment({ ...fixtureEnv, LLM_FREE_ONLY: 'true', LLM_MODEL: 'xingchen-agi/xing4.0-29b-a4b:free', LLM_PROVIDER_ALLOWLIST: 'phala',
    LLM_REQUEST_BUDGET_USD: '0', LLM_INPUT_PRICE_PER_MILLION_USD: '0', LLM_OUTPUT_PRICE_PER_MILLION_USD: '0', LLM_REQUEST_PRICE_USD: '0' })!;
  for (const prepared of [prepareSummary(fixtureReport, current), prepareHistory({}, free)]) {
    const wire = JSON.parse(prepared.body), prompt = wire.messages[0].content;
    assert.match(prompt, /Human prose must be Russian, not English with a Russian heading/);
    assert.match(prompt, /Do not label scanner findings themselves as hypotheses/);
    assert.match(prompt, /Never invent findings, CVE\/TEMP IDs/);
    assert.match(prompt, /Clearly separate confirmed scanner facts/);
  }
});
