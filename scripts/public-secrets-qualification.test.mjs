import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { makeFixture, sha, tarMember, hasPrivate } from './public-secrets-qualification-fixture.mjs';
import { PIN, COMMAND, createArgs, validateWorker, qualificationDestination } from './public-secrets-qualification.mjs';

test('dedup proof selects a separate fixed evidence path without rewriting historical packets', () => {
  assert.equal(qualificationDestination(['--dedup']).endsWith('public-secrets-qualification-20261020.dedup.json'), true);
  assert.equal(qualificationDestination([]) !== qualificationDestination(['--dedup']), true);
  for (const args of [['--force'], ['--output', '/tmp/other'], ['--dedup', '--dedup']]) assert.throws(() => qualificationDestination(args));
});

const observed = { image: PIN, command: COMMAND, user: '65532:65532', project: 'dip-public-images', service: 'worker',
  stand: 'v1', publicProject: 'dip-public-images', memory: 4294967296, swap: 4294967296, cpus: 1000000000, pids: 128 };
test('worker guard requires exact existing public identity, labels, command and resource envelope', () => {
  assert.equal(validateWorker(observed), true);
  for (const patch of [{ image: 'sha256:wrong' }, { command: ['sh'] }, { project: 'dip-local-full' }, { service: 'api' },
    { stand: '' }, { publicProject: 'foreign' }, { user: '0' }, { memory: 2147483648 }, { swap: 8589934592 }, { cpus: 2000000000 }, { pids: 256 }]) {
    assert.throws(() => validateWorker({ ...observed, ...patch }));
  }
});
test('fresh container uses pinned image, no pull/socket/ports/env-file/fixture entrypoint and bounded isolation', () => {
  const args = createArgs(`public-secrets-qualification-${randomUUID()}`, join(tmpdir(), 'public-secrets-qualification-test'));
  const option = key => args[args.indexOf(key) + 1];
  assert.equal(option('--network'), 'none'); assert.equal(option('--entrypoint'), 'node');
  assert.equal(option('--memory'), '4g'); assert.equal(option('--memory-swap'), '4g');
  assert.equal(option('--cpus'), '1'); assert.equal(option('--pids-limit'), '128');
  assert.equal(option('--pull'), 'never'); assert.equal(option('--log-driver'), 'none');
  assert.equal(args.includes('--read-only') && args.includes(PIN), true);
  assert.equal(args.some(item => /docker\.sock|--env-file|--privileged|--publish|--volumes-from|\.local-|8080/.test(item)), false);
  assert.throws(() => createArgs('existing-worker', '/tmp/unrelated'));
});
test('fresh synthetic bytes have honest manifest/config/compressed/diffID bindings without a runnable fixture entrypoint', () => {
  const a = makeFixture(), b = makeFixture();
  const manifest = JSON.parse(a.manifest), config = JSON.parse(a.config);
  assert.equal(a.target.digest === sha(a.manifest) && a.target.configDigest === sha(a.config), true);
  assert.equal(manifest.layers[0].digest === sha(a.compressed) && config.rootfs.diff_ids[0] === sha(a.layer), true);
  assert.equal(a.values.length === 2 && a.values.every(value => /^ghp_[A-Za-z0-9]{36}$/.test(value)), true);
  assert.equal(a.target.digest !== b.target.digest && a.values[0] !== b.values[0], true);
  assert.equal(!config.config.Entrypoint && !config.config.Cmd && a.layer.length < 8192, true);
});
test('tar helper refuses absolute/traversal/ambiguous members before producing archive bytes', () => {
  for (const name of ['/absolute', '../escape', 'a/../b', './dot', 'a//b', 'a/./b', 'a'.repeat(101)]) assert.throws(() => tarMember(name, Buffer.from('inert')));
});
test('synthetic transport never falls through to a network and enforces byte/request bounds', async () => {
  const source = makeFixture();
  await assert.rejects(source.fetch('foreign.example', '/v2/test'));
  await assert.rejects(source.request(null, new URL(`https://${source.target.registry}/v2/${source.target.repository}/manifests/${source.target.digest}`), {}, 1));
  for (let i = 0; i < 11; i++) await source.request(null, new URL(`https://${source.target.registry}/v2/${source.target.repository}/manifests/${source.target.digest}`), {}, 10000);
  await assert.rejects(source.request(null, new URL(`https://${source.target.registry}/v2/${source.target.repository}/manifests/${source.target.digest}`), {}, 10000));
});
test('redaction guard handles object/string/binary without disclosing a canary as assertion operands', () => {
  const source = makeFixture();
  assert.equal(hasPrivate(source.layer, source.values), true);
  assert.equal(hasPrivate(JSON.stringify({ Match: source.values[0] }), source.values), true);
  assert.equal(hasPrivate({ findings: [{ ruleId: 'rule-abcdef0123456789', line: 1 }] }, source.values), false);
});
