import assert from 'node:assert/strict';
import test from 'node:test';
import { POLICY } from './index.js';
import { enforceOutputBounds } from './result.js';
import { ConfigFailure } from './policy.js';
import { baseConfig, encode, pad, setup } from './test-fixtures.js';

function objectOf(count: number) { return Object.fromEntries(Array.from({ length: count }, (_, i) => [`k${i}`, 'x'])); }
const offsets = [-1, 0, 1];
function expected(actual: string | undefined, over: boolean, name: string) {
  assert.equal(actual, over ? 'CONFIG_LIMIT_EXCEEDED' : undefined, name);
}

for (const kind of ['manifest', 'config', 'total'] as const) {
  test(`public entry inclusive ${kind} byte limits`, async () => {
    for (const offset of offsets) {
      const configBytes = pad(encode(baseConfig()), kind === 'manifest' ? 100 : POLICY.configBytes + (kind === 'total' ? 0 : offset));
      const f = setup(configBytes);
      const manifestSize = kind === 'config' ? f.input.manifestBytes.length : POLICY.manifestBytes + offset;
      f.repinManifest(pad(f.input.manifestBytes, manifestSize));
      expected((await f.analyze()).config.reason, offset > 0, `${kind} ${offset}`);
    }
  });
}

for (const [kind, limit, configFor] of [
  ['stringBytes', POLICY.stringBytes, (n: number) => ({ os: 'linux', architecture: 'amd64', unknown: 'x'.repeat(n) })],
  ['keyBytes', POLICY.keyBytes, (n: number) => ({ os: 'linux', architecture: 'amd64', unknown: { ['x'.repeat(n)]: true } })],
  ['userBytes', POLICY.userBytes, (n: number) => ({ os: 'linux', architecture: 'amd64', config: { User: 'x'.repeat(n) } })],
  ['env', POLICY.env, (n: number) => ({ os: 'linux', architecture: 'amd64', config: { Env: Array(n).fill('a=b') } })],
  ['labels', POLICY.labels, (n: number) => ({ os: 'linux', architecture: 'amd64', config: { Labels: objectOf(n) } })],
  ['history', POLICY.history, (n: number) => ({ os: 'linux', architecture: 'amd64', history: Array.from({ length: n }, () => ({})) })],
  ['array collection', POLICY.collection, (n: number) => ({ os: 'linux', architecture: 'amd64', unknown: Array(n).fill(null) })],
  ['object collection', POLICY.collection, (n: number) => ({ os: 'linux', architecture: 'amd64', unknown: objectOf(n) })],
  ['depth', POLICY.depth, (n: number) => {
    let unknown: unknown = null;
    for (let i = 0; i < n - 2; i++) unknown = [unknown];
    return { os: 'linux', architecture: 'amd64', unknown };
  }],
  ['nodes', POLICY.nodes, (n: number) => {
    // root + os + arch + unknown array + four child arrays = eight nodes.
    const numbers = n - 8;
    return { os: 'linux', architecture: 'amd64', unknown: [Array(4096).fill(0), Array(4096).fill(0), Array(4096).fill(0), Array(numbers - 12288).fill(0)] };
  }],
] as const) {
  test(`public entry inclusive ${kind} limit`, async () => {
    for (const offset of offsets) {
      const result = await setup(configFor(limit + offset)).analyze();
      // The User limit examples deliberately have unsupported names, not checked input.
      const reason = kind === 'userBytes' && offset <= 0 ? 'USER_NOT_RESOLVABLE' : undefined;
      assert.equal(result.config.reason, offset > 0 ? 'CONFIG_LIMIT_EXCEEDED' : reason, `${kind} ${offset}`);
      if (offset > 0) assert.deepEqual(result.findings, []);
    }
  });
}

test('UTF-8 byte budgets are not UTF-16 code-unit budgets; escaped keys also count', async () => {
  for (const n of [8190, 8192, 8194]) {
    const result = await setup({ os: 'linux', architecture: 'amd64', unknown: 'é'.repeat(n / 2) }).analyze();
    expected(result.config.reason, n > 8192, `string UTF-8 ${n}`);
  }
  for (const n of [254, 256, 258]) {
    const result = await setup({ os: 'linux', architecture: 'amd64', unknown: { ['é'.repeat(n / 2)]: 0 } }).analyze();
    expected(result.config.reason, n > 256, `key UTF-8 ${n}`);
  }
  for (const n of [255, 256, 257]) {
    const bytes = Buffer.from(`{"os":"linux","architecture":"amd64","unknown":{"${'\\u0061'.repeat(n)}":0}}`);
    expected((await setup(bytes).analyze()).config.reason, n > 256, `escaped key ${n}`);
  }
});

test('unknown manifest fields obey the same traversal budgets', async () => {
  for (const count of [8191, 8192, 8193]) {
    const f = setup();
    f.repinManifest(encode({ ...f.manifest, unknown: 'x'.repeat(count) }));
    expected((await f.analyze()).config.reason, count > 8192, `manifest string ${count}`);
  }
});

test('internal result encoder applies inclusive bytes and finding caps without invented rules', () => {
  for (const offset of offsets) {
    const result = 'x'.repeat(POLICY.resultBytes - 2 + offset); // JSON quotes add two bytes.
    if (offset <= 0) assert.doesNotThrow(() => enforceOutputBounds(result, 1));
    else assert.throws(() => enforceOutputBounds(result, 1), (error: unknown) => error instanceof ConfigFailure && error.reason === 'CONFIG_LIMIT_EXCEEDED');
  }
  for (const count of [0, 1]) assert.doesNotThrow(() => enforceOutputBounds({}, count));
  assert.throws(() => enforceOutputBounds({}, 2), ConfigFailure);
});

test('callers cannot override fixed policy, and override getters are not read', async () => {
  const f = setup();
  for (const value of [null, {}, { stringBytes: Infinity }, 'unknown', 'image-config-policy-v1']) {
    assert.equal((await f.analyze({ policy: value })).config.reason, 'INVALID_RESOURCE_POLICY');
  }
  const result = await f.module.analyze({ enabled: true, target: f.target, get resourcePolicyVersion(): never { throw new Error('secret'); } });
  assert.equal(result.config.reason, 'INVALID_RESOURCE_POLICY');
  assert.equal(f.calls(), 0);
});
