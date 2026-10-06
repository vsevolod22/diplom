import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { createImageConfigModule } from './index.js';

const digest = (bytes: Uint8Array) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const encode = (value: unknown) => Buffer.from(JSON.stringify(value));

// Fixture-only authority: not a production authorization adapter.
function fixture(config: unknown = { os: 'linux', architecture: 'amd64', config: { User: '0' } }) {
  const configBytes = typeof config === 'string' ? Buffer.from(config) : encode(config);
  const manifestBytes = encode({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: { mediaType: 'application/vnd.oci.image.config.v1+json', digest: digest(configBytes), size: configBytes.length }, layers: [] });
  const target = Object.freeze({});
  const value = { identity: { registry: 'registry.example', repository: 'demo/image', manifestDigest: digest(manifestBytes),
    platform: { os: 'linux', architecture: 'amd64' } }, manifestBytes, configBytes };
  let calls = 0;
  const module = createImageConfigModule({ resolveAuthorizedTarget(handle: unknown) {
    calls++;
    return handle === target ? value : undefined;
  } });
  return { module, target, value, calls: () => calls, analyze: () => module.analyze({ enabled: true, target }) };
}

test('public entry verifies the pinned chain and returns a redacted deterministic root finding', async () => {
  const f = fixture();
  const result = await f.analyze();
  assert.equal(result.config.outcome, 'checked');
  assert.equal(result.findings[0]?.classification, 'NUMERIC_ROOT');
  assert.deepEqual(result.completedRuleIds, ['IMGCFG_USER_ROOT']);
  assert.equal(result.checksVersion, 'image-config-user-v1');
  assert.equal(result.resourcePolicyVersion, 'image-config-policy-v1');
  assert.deepEqual(await f.analyze(), result);
  assert.equal(result.history.outcome, 'unsupported');
  assert.equal(result.dockerfile.reason, 'SOURCE_NOT_PROVIDED');
  assert.equal(result.iac.reason, 'SOURCE_NOT_PROVIDED');
});

test('off and malformed flags never read target or call the authority', async () => {
  const f = fixture();
  for (const enabled of [false, null, 'true', 1, {}, undefined]) {
    const request = { enabled, get target(): never { throw new Error('SECRET_CANARY'); } };
    const result = await f.module.analyze(request);
    assert.equal(result.config.outcome, enabled === false ? 'skipped' : 'failed');
    assert.equal(JSON.stringify(result).includes('SECRET_CANARY'), false);
  }
  assert.equal((await f.module.analyze({ get target(): never { throw new Error('canary'); } })).config.outcome, 'skipped');
  assert.equal(f.calls(), 0);
});

test('structural trust flags, clones, casts, foreign handles and foreign descriptors cannot authorize', async () => {
  const f = fixture();
  for (const target of [{ verified: true, ...f.value }, { ...f.target }, JSON.parse(JSON.stringify(f.target)), fixture().target]) {
    const result = await f.module.analyze({ enabled: true, target });
    assert.equal(result.config.reason, 'OCI_IDENTITY_REJECTED');
    assert.deepEqual(result.findings, []);
  }
  f.value.configBytes = encode({ os: 'linux', architecture: 'amd64', config: { User: '1000' } });
  assert.equal((await f.analyze()).config.reason, 'OCI_IDENTITY_REJECTED');
});

test('platform mismatch, invalid UTF-8, decoded duplicate keys and malformed types fail closed', async () => {
  const wrongPlatform = fixture({ os: 'linux', architecture: 'arm64' });
  assert.equal((await wrongPlatform.analyze()).config.reason, 'OCI_IDENTITY_REJECTED');
  for (const config of ['{"os":"linux","architecture":"amd64","config":{"User":"0","\\u0055ser":"1"}}', '{',
    { os: 'linux', architecture: 'amd64', config: { User: null } },
    { os: 'linux', architecture: 'amd64', config: { Env: [1] } },
    { os: 'linux', architecture: 'amd64', history: [{ created_by: false }] }]) {
    assert.equal((await fixture(config).analyze()).config.reason, 'INVALID_CONFIG');
  }
});

test('User has exact default/numeric semantics and never resolves names', async () => {
  for (const [user, expected, classification] of [
    [undefined, 'checked', 'DEFAULT_ROOT'], ['', 'checked', 'DEFAULT_ROOT'], ['000', 'checked', 'NUMERIC_ROOT'],
    ['0:1000', 'checked', 'NUMERIC_ROOT'], ['1000:0', 'checked', undefined], ['4294967295', 'checked', undefined],
    ['4294967296', 'unsupported', undefined], ['root', 'unsupported', undefined], ['app', 'unsupported', undefined],
    ['0:app', 'unsupported', undefined], [' 0', 'unsupported', undefined], ['+0', 'unsupported', undefined],
    ['0:1:2', 'unsupported', undefined], ['00000000000', 'unsupported', undefined],
    ['0000000000', 'checked', 'NUMERIC_ROOT'], ['4294967295:4294967295', 'checked', undefined],
    ['0:4294967296', 'unsupported', undefined], ['0:', 'unsupported', undefined], [':0', 'unsupported', undefined],
    ['0:-1', 'unsupported', undefined], ['\t0', 'unsupported', undefined], ['0\n', 'unsupported', undefined],
  ] as const) {
    const result = await fixture({ os: 'linux', architecture: 'amd64', config: { User: user } }).analyze();
    assert.equal(result.config.outcome, expected, String(user));
    assert.equal(result.findings[0]?.classification, classification, String(user));
  }
});

test('unknown fields count toward budgets and source bytes are never read', async () => {
  const f = fixture({ os: 'linux', architecture: 'amd64', unknown: 'x'.repeat(8193) });
  assert.equal((await f.analyze()).config.reason, 'CONFIG_LIMIT_EXCEEDED');
  const result = await f.module.analyze({ enabled: false, dockerfileProvided: true, iacProvided: true,
    get sourceBytes(): never { throw new Error('SECRET_CANARY'); } });
  assert.equal(result.dockerfile.reason, 'SOURCE_ANALYZER_UNSUPPORTED');
  assert.equal(result.iac.reason, 'SOURCE_ANALYZER_UNSUPPORTED');
});

test('all metadata canaries stay out of outputs and caller errors', async () => {
  const canary = 'SECRET_CANARY_<script>curl http://169.254.169.254</script>';
  for (const user of ['0', canary, null]) {
    const result = await fixture({ os: 'linux', architecture: 'amd64', config: { User: user, Env: [canary], Labels: { [canary]: canary } },
      history: [{ created_by: canary, author: canary, comment: canary }], unknown: canary }).analyze();
    assert.equal(JSON.stringify(result).includes(canary), false);
  }
  const module = createImageConfigModule({ resolveAuthorizedTarget() { throw new Error(canary); } });
  assert.equal(JSON.stringify(await module.analyze({ enabled: true, target: {} })).includes(canary), false);
});
