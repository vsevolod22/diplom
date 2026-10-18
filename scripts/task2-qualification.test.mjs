import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { createArgs, fixture, tar, sha256, IMAGE } from './task2-qualification-native.mjs';

function files(bytes) {
  const result = new Map();
  for (let offset = 0; offset + 512 <= bytes.length && bytes[offset] !== 0;) {
    const header = bytes.subarray(offset, offset + 512);
    const name = header.subarray(0, 100).toString().split('\0')[0];
    const size = parseInt(header.subarray(124, 136).toString().split('\0')[0], 8);
    const stored = parseInt(header.subarray(148, 156).toString().split('\0')[0], 8);
    const checksum = Buffer.from(header); checksum.fill(32, 148, 156);
    assert.equal(checksum.reduce((n, b) => n + b, 0), stored);
    assert.equal(header[156], 48, 'regular file only');
    result.set(name, bytes.subarray(offset + 512, offset + 512 + size));
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return result;
}

test('new inventory archive binds config/diffID and contains only inert files', () => {
  const f = fixture();
  const outer = files(f.archive);
  const manifest = JSON.parse(outer.get('manifest.json'));
  const configBytes = outer.get(manifest[0].Config);
  const config = JSON.parse(configBytes);
  const layerBytes = outer.get(manifest[0].Layers[0]);
  const layer = files(layerBytes);
  assert.equal('sha256:' + sha256(configBytes), f.configDigest);
  assert.equal('sha256:' + sha256(layerBytes), f.diffId);
  assert.deepEqual(config.rootfs.diff_ids, [f.diffId]);
  assert.deepEqual(config.config, {});
  assert.equal(config.architecture, 'amd64');
  assert.deepEqual(JSON.parse(layer.get('app/node_modules/lodash/package.json')), { name: 'lodash', version: '4.17.20', license: 'MIT' });
  assert.equal(layer.size, 5);
  const canary = [...layer.entries()].find(([path]) => path.includes(f.marker))[1];
  assert.ok(f.secrets.every(s => canary.includes(Buffer.from(s))));
  assert.ok(f.archive.length < 20_000);
});

test('fixture tar refuses traversal, shell-ish paths and oversized payloads', () => {
  for (const name of ['../escape', '/absolute', 'space name', 'x;echo']) {

    assert.throws(() => tar({ [name]: 'x' }), /fixture-path/);
  }
  assert.throws(() => tar({ large: Buffer.alloc(1_000_000) }), /fixture-size/);
});

test('container arguments stay pinned, offline, unprivileged and own-fixture-only', () => {
  const args = createArgs('task2-qualification-1234-abcd', '/tmp/own-fixture', '/public/local-db', ['--version']);
  for (const flag of ['--read-only', '--cap-drop', '--security-opt', '--network', '--user', '--pids-limit', '--memory', '--memory-swap', '--cpus', '--log-driver']) assert.ok(args.includes(flag));
  const value = flag => args[args.indexOf(flag) + 1];
  assert.equal(value('--pull'), 'never');
  assert.equal(value('--cap-drop'), 'ALL');
  assert.equal(value('--security-opt'), 'no-new-privileges:true');
  assert.equal(value('--network'), 'none');
  assert.equal(value('--log-driver'), 'none');
  assert.equal(value('--user'), '65532:65532');
  assert.equal(value('--memory'), '1g');
  assert.equal(value('--memory-swap'), '1g');
  assert.equal(value('--pids-limit'), '64');
  assert.deepEqual(args.slice(-2), [IMAGE, '--version']);
  assert.ok(args.includes('type=bind,src=/tmp/own-fixture,dst=/fixture,readonly'));
  assert.ok(args.includes('type=bind,src=/public/local-db,dst=/tmp/cache/db,readonly'));
  assert.ok(!args.some(arg => /docker\.sock|privileged|env-file|\.local-auth|HOLD/.test(arg)));
  assert.throws(() => createArgs('dip-local-full-worker-1', '/tmp/fixture', null, []), /container-name/);
});

test('retained executed evidence is sanitized, bounded and explicit about qualification', () => {
  const text = readFileSync(new URL('../server/deploy/proof/task2-qualification-results.json', import.meta.url), 'utf8');
  const e = JSON.parse(text);
  assert.equal(e.success, true);
  assert.equal(e.checks.length, 16);
  assert.equal(e.sourceDriftDuringRun, false);
  assert.equal(e.tempStoreRemoved, true);
  assert.equal(e.containers.length, 5);
  assert.ok(e.containers.every(c => c.cleanup && c.fixtureRemoved));
  assert.ok(e.scope.includes('NOT remote admission'));
  assert.ok(!/ghp_[a-zA-Z0-9]{36}|TASK2_TRANSIENT_PATH_|BEGIN .*PRIVATE KEY/.test(text));
  assert.ok(e.nativeNpm.some(f => f.cveId === 'CVE-2021-23337' && ['ghsa', 'nvd'].every(source => f.assessments.some(a => a.source === source))));
  assert.ok(e.checks.some(c => c.name === 'native-missing-db-nonzero-no-checked-report'));
  assert.ok(e.checks.some(c => c.name.includes('after-reopen')));
});
