import assert from 'node:assert/strict';
import test from 'node:test';
import { createImageConfigModule } from './index.js';
import { compatibleCases, formats, hash, linkedInput, minimalConfig } from './optional-null-fixtures.js';

async function analyze(input: ReturnType<typeof linkedInput>) {
  const target = Object.freeze({});
  const module = createImageConfigModule({ resolveAuthorizedTarget: handle => handle === target ? input : undefined });
  return module.analyze({ enabled: true, target });
}

for (const format of Object.keys(formats) as (keyof typeof formats)[]) {
  for (const [name, fields] of compatibleCases) {
    test(`${format}: optional ${name} preserves original byte proof and default-user coverage`, async () => {
      const input = linkedInput({ ...minimalConfig(), ...fields }, format);
      const before = Buffer.from(input.configBytes);
      const result = await analyze(input);
      assert.equal(result.config.outcome, 'checked');
      assert.deepEqual(result.completedRuleIds, ['IMGCFG_USER_ROOT']);
      assert.equal(result.findings[0]?.classification, 'DEFAULT_ROOT');
      assert.equal(result.findings[0]?.configDigest, hash(before));
      assert.equal(result.findings[0]?.manifestDigest, input.identity.manifestDigest);
      assert.deepEqual(input.configBytes, before);
      assert.equal(result.checksVersion, 'image-config-user-v1');
      assert.equal(result.resourcePolicyVersion, 'image-config-policy-v1');
      assert.equal(result.history.reason, 'RULE_NOT_IMPLEMENTED');
      assert.equal(result.dockerfile.reason, 'SOURCE_NOT_PROVIDED');
      assert.equal(result.iac.reason, 'SOURCE_NOT_PROVIDED');
      assert.equal(JSON.stringify(result).includes('CANARY'), false);
      assert.deepEqual(await analyze(input), result);
    });
  }
  for (const [name, fields] of [
    ['runtime false', { config: false }], ['User number', { config: { User: 0 } }],
    ['Env object', { config: { Env: {} } }], ['Env null element', { config: { Env: [null] } }],
    ['Labels array', { config: { Labels: [] } }], ['Labels null value', { config: { Labels: { CANARY: null } } }],
    ['history null element', { history: [null] }], ['history empty_layer wrong type', { history: [{ empty_layer: '' }] }],
    ['history created wrong type', { history: [{ created: 1 }] }],
  ] as const) {
    test(`${format}: ${name} is not optional-null absence`, async () => {
      const result = await analyze(linkedInput({ ...minimalConfig(), ...fields }, format));
      assert.equal(result.config.reason, 'INVALID_CONFIG');
      assert.deepEqual(result.completedRuleIds, []); assert.deepEqual(result.findings, []);
    });
  }
  test(`${format}: null interpretation never repairs tampered bytes or required identity`, async () => {
    const input = linkedInput({ ...minimalConfig(), config: { Labels: null } }, format);
    input.configBytes[0] = 32;
    assert.equal((await analyze(input)).config.reason, 'OCI_IDENTITY_REJECTED');
    for (const fields of [{ os: null }, { architecture: null }, { variant: '' }, { variant: 'v3' }]) {
      assert.equal((await analyze(linkedInput({ ...minimalConfig(), ...fields }, format))).config.reason, 'OCI_IDENTITY_REJECTED');
    }
    const variant = linkedInput({ ...minimalConfig(), variant: null }, format);
    assert.equal((await analyze({ ...variant, identity: { ...variant.identity,
      platform: { ...variant.identity.platform, variant: 'v3' } } })).config.reason, 'OCI_IDENTITY_REJECTED');
    const matched = linkedInput({ ...minimalConfig(), variant: 'v3' }, format);
    assert.equal((await analyze({ ...matched, identity: { ...matched.identity,
      platform: { ...matched.identity.platform, variant: 'v3' } } })).config.outcome, 'checked');
  });
}
