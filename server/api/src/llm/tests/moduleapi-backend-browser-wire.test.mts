import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { chatContextSchema, chatReadinessSchema, chatReceiptSchema, chatReceiptMatchesProvider } from '../../../../../src/shared/api/scans/llmChatContract.js';
import { moduleApiDisclosureSchema, moduleApiReadinessShape, validModuleApiReadiness, openAiDisclosureSchema } from '../../../../../src/shared/api/scans/llmPublicContract.js';
import { z } from 'zod';
import { ModuleApiRuntimeResolver } from '../provider-runtime.js';
import { moduleApiReadiness } from '../public-readiness.js';
import { moduleApiDisclosure, MODULEAPI_ESTIMATE_SOURCE, OPENAI_ESTIMATE_SOURCE, OPENROUTER_RECEIPT_SOURCE, CHAT_SENT_DATA, CHAT_LOCAL_RETENTION } from '../provider-browser-contract.js';
import { reportBinding, HISTORY } from '../history-contract.js';
import { moduleApiBackendConfiguration, moduleApiBackendQuota, moduleApiBackendReport } from './moduleapi-backend.fixture.js';

// Native NodeNext API files and browser Bundler files deliberately have separate
// TS projects; this explicit .mts cross-boundary test runs with tsx, no UI writes.
const strictReadiness = z.strictObject(moduleApiReadinessShape).refine(validModuleApiReadiness);
const bound = reportBinding(moduleApiBackendReport);
function readiness(configuration: 'missing' | 'accounting-missing' | 'valid', keyReady = true, quotaAvailable = true, historyAvailable = true) {
  const config = moduleApiBackendConfiguration();
  const resolver = new ModuleApiRuntimeResolver({ environment: () => ({ LLM_PROVIDER: 'moduleapi' }),
    moduleApiConfiguration: () => configuration === 'missing' ? null : configuration === 'accounting-missing'
      ? { ...config, accountingRevision: '' } : config,
    quotaPolicy: () => moduleApiBackendQuota, moduleApiCredentialReady: () => keyReady,
    moduleApiCredential: () => assert.fail('wire test must not open a credential'),
    moduleApiTransport: () => assert.fail('wire test must not construct a transport') });
  return moduleApiReadiness(resolver, quotaAvailable, historyAvailable);
}

for (const configuration of ['missing', 'accounting-missing', 'valid'] as const) {
  for (const key of [false, true]) for (const quota of [false, true]) for (const history of [false, true]) {
    test(`actual ModuleAPI readiness -> strict browser schema: ${configuration}/key=${key}/quota=${quota}/history=${history}`, () => {
      const value = readiness(configuration, key, quota, history);
      assert.deepEqual(strictReadiness.parse(value), value);
      const wire = { ...bound, ...value };
      assert.deepEqual(chatReadinessSchema.parse(wire), wire);
      assert.equal(value.localReady, configuration === 'valid' && key && quota && history);
      assert.equal(value.costBasis, 'moduleapi-server-estimated-configured-rates-not-invoice');
      assert.equal(value.provider.retention, 'unknown'); assert.equal(value.provider.operatorApprovedRouting, true);
      assert.equal(value.provider.tariffVerified, false); assert.equal(value.provider.zeroDataRetentionVerified, false);
    });
  }
}

test('actual readiness truthful literals are required, exact and cannot become direct OpenAI or verified privacy/tariff', () => {
  const value = readiness('valid');
  for (const field of ['costBasis', 'provider'] as const) {
    const changed = { ...value }; Reflect.deleteProperty(changed, field);
    assert.equal(strictReadiness.safeParse(changed).success, false);
  }
  for (const field of ['retention', 'operatorApprovedRouting', 'zeroDataRetentionVerified', 'tariffVerified'] as const) {
    const changed = { ...value, provider: { ...value.provider } }; Reflect.deleteProperty(changed.provider, field);
    assert.equal(strictReadiness.safeParse(changed).success, false);
  }
  for (const provider of [{ ...value.provider, name: 'OpenAI' }, { ...value.provider, retention: 'no-training' },
    { ...value.provider, operatorApprovedRouting: false }, { ...value.provider, zeroDataRetentionVerified: true },
    { ...value.provider, tariffVerified: true }, { ...value.provider, extra: true }])
    assert.equal(chatReadinessSchema.safeParse({ ...bound, ...value, provider }).success, false);
  for (const change of [{ costBasis: 'server-estimated-configured-rates-not-invoice' }, { extra: true }, { generationVerified: true },
    { localReady: false }, { blockers: ['configuration-required'] }])
    assert.equal(chatReadinessSchema.safeParse({ ...bound, ...value, ...change }).success, false);
});

test('actual ModuleAPI disclosure and receipt parse unchanged in browser and retain separate provider binding', () => {
  const config = moduleApiBackendConfiguration();
  for (const publicReport of [false, true]) {
    const value = moduleApiDisclosure(config.policy, moduleApiBackendQuota, publicReport);
    assert.deepEqual(moduleApiDisclosureSchema.parse(value), value);
    assert.equal(openAiDisclosureSchema.safeParse(value).success, false);
    assert.equal(value.lifetimeUserCostMicros, 5000000);
  }
  const receipt = { input: 20, output: 10, costMicros: 40, source: MODULEAPI_ESTIMATE_SOURCE } as const;
  assert.deepEqual(chatReceiptSchema.parse(receipt), receipt);
  const context = chatContextSchema.parse({ ...bound, epoch: '00000000-0000-4000-8000-000000000001', revision: 0,
    enabled: true, policyVersion: config.policy.version,
    disclosure: { ...moduleApiDisclosure(config.policy, moduleApiBackendQuota, false),
      sentData: CHAT_SENT_DATA, localRetention: CHAT_LOCAL_RETENTION },
    limits: { questionBytes: HISTORY.questionBytes, bodyBytes: HISTORY.bodyBytes }, deliveryMode: 'completed-response', pending: false });
  assert.equal(chatReceiptMatchesProvider(receipt, context), true);
  assert.equal(chatReceiptMatchesProvider({ ...receipt, source: OPENAI_ESTIMATE_SOURCE }, context), false);
  assert.equal(chatReceiptMatchesProvider({ ...receipt, costMicros: 0, source: OPENROUTER_RECEIPT_SOURCE }, context), false);
});
