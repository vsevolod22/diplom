import assert from 'node:assert/strict';
import test from 'node:test';
import { baseConfig, encode, setup } from './test-fixtures.js';
import { parseBoundedJson } from './bounded-json.js';
import { ConfigFailure } from './policy.js';

for (const [label, config] of [
  ['null root', null], ['array root', []],
  ['array runtime config', { ...baseConfig(), config: [] }],
  ...[0, false, [], {}].map(User => ['invalid User', { ...baseConfig(), config: { User } }] as const),
  ...['A=B', {}, [null], [1]].map(Env => ['invalid Env', { ...baseConfig(), config: { Env } }] as const),
  ...[[], 'a', { a: null }, { a: 1 }].map(Labels => ['invalid Labels', { ...baseConfig(), config: { Labels } }] as const),
  ...[{}, 'a', [null], [[]], ['a'], [{ created: 1 }], [{ created_by: false }], [{ author: false }],
    [{ comment: [] }], [{ empty_layer: 1 }]].map(history => ['invalid history', { ...baseConfig(), history }] as const),
] as const) {
  test(`public entry rejects ${label} ${JSON.stringify(config)}`, async () => {
    const result = await setup(config).analyze();
    assert.equal(result.config.reason, 'INVALID_CONFIG');
    assert.deepEqual(result.findings, []);
  });
}

for (const json of ['{', '{} trailing', '{"a":1,}', '[1,]', '{"a":01}', '{"a":NaN}', '{"a":1e999}',
  '{"a":"\\uD800"}', '{"a":"\\q"}', '{"a":"\n"}', '{"a":true,"a":false}',
  '{"a":1,"\\u0061":2}', '{"é":1,"\\u00e9":2}', '\ufeff{}']) {
  test(`bounded decoder rejects malformed or ambiguous JSON ${JSON.stringify(json)}`, () => {
    assert.throws(() => parseBoundedJson(Buffer.from(json)), (error: unknown) => error instanceof ConfigFailure && error.reason === 'INVALID_CONFIG');
  });
}

test('public entry rejects fatal UTF-8 in both verified documents, without parser text', async () => {
  const bad = Buffer.from([123, 34, 120, 34, 58, 34, 0xc3, 0x28, 34, 125]);
  const config = setup(bad);
  assert.equal((await config.analyze()).config.reason, 'INVALID_CONFIG');
  const manifest = setup();
  manifest.repinManifest(bad);
  assert.equal((await manifest.analyze()).config.reason, 'INVALID_CONFIG');
});

test('optional metadata may be absent; config.User absent defaults root', async () => {
  for (const config of [{ os: 'linux', architecture: 'amd64' }, { os: 'linux', architecture: 'amd64', config: {} }]) {
    assert.equal((await setup(config).analyze()).findings[0]?.classification, 'DEFAULT_ROOT');
  }
});

test('missing/invalid required platform fields and non-null wrong variants are identity failures', async () => {
  for (const config of [{ architecture: 'amd64' }, { os: 'linux' }, { os: 1, architecture: 'amd64' },
    { os: 'linux', architecture: null }, { ...baseConfig(), variant: false }]) {
    assert.equal((await setup(config).analyze()).config.reason, 'OCI_IDENTITY_REJECTED');
  }
});

test('bounded parser handles escaped/supplementary text and special object keys safely', () => {
  const text = '{"__proto__":{"polluted":true},"constructor":"x","a":"\\uD83D\\uDE00","b":-1.25e+2,"c":[true,false,null]}';
  const result = parseBoundedJson(Buffer.from(text));
  assert.equal(Object.getPrototypeOf(result), null);
  assert.equal((result as Record<string, unknown>).a, '😀');
  assert.equal((result as Record<string, unknown>).b, -125);
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
});

test('public entry rejects decoded duplicate manifest keys even if manifest is pinned', async () => {
  const f = setup();
  const text = encode(f.manifest).toString().replace('"schemaVersion":2', '"schemaVersion":2,"\\u0073chemaVersion":2');
  f.repinManifest(Buffer.from(text));
  assert.equal((await f.analyze()).config.reason, 'INVALID_CONFIG');
});

test('deterministic generated bounded documents roundtrip through the decoder', () => {
  let state = 0x12345678;
  const next = () => { state = (Math.imul(state, 1664525) + 1013904223) >>> 0; return state; };
  const texts = ['é', '😀', '\\"\\\\\n\t', '__proto__', '\\u0061', '', '0:1000'];
  function generate(depth: number): unknown {
    const choice = next() % (depth < 4 ? 7 : 5);
    if (choice === 0) return null;
    if (choice === 1) return next() % 2 === 0;
    if (choice === 2) return (next() - 0x80000000) / 128;
    if (choice === 3 || choice === 4) return texts[next() % texts.length];
    if (choice === 5) return Array.from({ length: next() % 6 }, () => generate(depth + 1));
    return Object.fromEntries(Array.from({ length: next() % 6 }, (_, i) => [`${texts[next() % texts.length]}${i}`, generate(depth + 1)]));
  }
  for (let i = 0; i < 300; i++) {
    const json = JSON.stringify(generate(0));
    assert.equal(JSON.stringify(parseBoundedJson(Buffer.from(json))), json);
  }
});

test('field collection bounds precede per-entry processing even for invalid entries', async () => {
  for (const config of [
    { ...baseConfig(), config: { Env: Array(1025).fill(null) } },
    { ...baseConfig(), config: { Labels: Object.fromEntries(Array.from({ length: 257 }, (_, i) => [`k${i}`, null])) } },
    { ...baseConfig(), history: Array(1025).fill(null) },
  ]) assert.equal((await setup(config).analyze()).config.reason, 'CONFIG_LIMIT_EXCEEDED');
});
