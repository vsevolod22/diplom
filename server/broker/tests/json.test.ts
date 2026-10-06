import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { strictJson } from '../src/strict-json.js';
import { project, canonical } from '../src/projection.js';
import { limits } from '../src/contracts.js';
import { PolicyStore } from '../src/policy.js';
import { inspect, fixtureState, request } from './support.js';
const store = new PolicyStore();
store.replace(fixtureState('/private/engine.sock'));
const pin = store.authorize(request(), 100_000)!;
const encode = (v: unknown) => Buffer.from(JSON.stringify(v));

test('duplicate-aware strict JSON, Unicode, depth/fields/nodes/string boundaries', () => {
  for (const input of [
    '{"Id":1,"Id":2}',
    '{"Id":1,"\\u0049d":2}',
    '{"nested":{"x":1,"x":2}}',
    '{}{}',
    '1e999',
    'NaN',
    '[1,]',
    '{"a":}',
    '"\\ud800"',
    '\ufeff{}',
    '"control\n"',
  ]) {
    assert.throws(() => strictJson(Buffer.from(input)), input);
  }
  assert.throws(() => strictJson(Buffer.from([0xff])));
  assert.deepEqual(strictJson(Buffer.from('{"a":"\\ud83d\\ude00"}')), { a: '😀' });
  assert.throws(() => strictJson(Buffer.from('['.repeat(33) + '0' + ']'.repeat(33))));
  assert.deepEqual(strictJson(Buffer.from('[0]'), limits({ depth: 2 })), [0]);
  assert.throws(() => strictJson(Buffer.from('[[0]]'), limits({ depth: 2 })));
  assert.deepEqual(strictJson(Buffer.from('{"a":0}'), limits({ fields: 1 })), { a: 0 });
  assert.throws(() => strictJson(Buffer.from('{"a":0,"b":1}'), limits({ fields: 1 })));
  assert.deepEqual(strictJson(Buffer.from('[0]'), limits({ nodes: 2 })), [0]);
  assert.throws(() => strictJson(Buffer.from('[0,1]'), limits({ nodes: 2 })));
  assert.equal(strictJson(Buffer.from('"é"'), limits({ stringBytes: 2 })), 'é');
  assert.throws(() => strictJson(Buffer.from('"éa"'), limits({ stringBytes: 2 })));
});

test('allowlist projection keeps dangerous facts; all-field canaries never emitted/hash raw', () => {
  const canary = 'SECRET_CANARY_RAW_ENV_LABEL_PATH_LOG';
  const raw: any = inspect();
  Object.assign(raw, {
    Env: [canary],
    LogPath: canary,
    Name: canary,
    Mounts: [{ Type: canary, RW: true, Source: '/var/run/docker.sock', Destination: canary, Name: canary }],
    unknown: { secret: canary },
  });
  Object.assign(raw.Config, {
    Env: [canary],
    Labels: { [canary]: canary },
    User: canary,
    Cmd: [canary],
    Entrypoint: [canary],
  });
  Object.assign(raw.HostConfig, {
    CapAdd: ['SYS_ADMIN', 'ALL', canary],
    CapDrop: ['NET_RAW'],
    SecurityOpt: ['seccomp=unconfined', 'apparmor=' + canary],
    NetworkMode: canary,
    PidMode: 'host',
    IpcMode: 'container:' + canary,
    UsernsMode: canary,
    PortBindings: { '80/tcp': [{ HostIp: canary, HostPort: '8080' }] },
    Memory: 0,
    NanoCpus: 1,
  });
  const snapshot = project(strictJson(encode(raw)), pin, 100_000);
  assert.ok(!canonical(snapshot).includes(canary));
  assert.equal(snapshot.facts.configuredUser, 'unknown');
  assert.deepEqual(snapshot.facts.capAdd, ['ALL', 'SYS_ADMIN', 'unknown']);
  assert.equal(snapshot.facts.privileged, true);
  assert.equal(snapshot.facts.readonlyRootfs, false);
  assert.deepEqual(snapshot.facts.security, { seccomp: 'unconfined', apparmor: 'custom' });
  assert.equal(snapshot.facts.namespaces.pid, 'host');
  assert.equal(snapshot.facts.namespaces.ipc, 'shared-container');
  assert.equal(snapshot.facts.mounts.socketPresent, true);
  assert.equal(snapshot.facts.resources.memory, 0);
  const { hash, ...envelope } = snapshot;
  assert.equal(hash, createHash('sha256').update(canonical(envelope)).digest('hex'));
  raw.Config.Env = ['different'];
  raw.LogPath = 'different';
  assert.equal(project(strictJson(encode(raw)), pin, 100_000).hash, hash);
});

test('optional unknown is not false/safe; missing/mismatched required facts fail', () => {
  const snapshot = project(inspect(), pin, 100_000);
  assert.equal(snapshot.facts.security.seccomp, 'unknown');
  assert.equal(snapshot.facts.mounts.socketPresent, 'unknown');
  assert.equal(snapshot.facts.resources.memory, 'unknown');
  assert.equal(snapshot.facts.capAdd, 'unknown');
  for (const change of [
    (v: any) => (v.Id = 'b'.repeat(64)),
    (v: any) => delete v.Config,
    (v: any) => delete v.HostConfig.Privileged,
    (v: any) => (v.HostConfig.ReadonlyRootfs = 'false'),
    (v: any) => (v.Config.User = 0),
    (v: any) => (v.Mounts = [{ Type: 'bind', RW: 'false' }]),
    (v: any) => (v.HostConfig.CapAdd = [1]),
    (v: any) => (v.HostConfig.SecurityOpt = {}),
    (v: any) => (v.HostConfig.Memory = -1),
    (v: any) => (v.HostConfig.PortBindings = { 'bad/tcp': [] }),
    (v: any) => (v.Mounts = Array.from({ length: 257 }, () => ({ Type: 'bind', RW: true }))),
  ]) {
    const raw = inspect();
    change(raw);
    assert.throws(() => project(raw, pin, 100_000));
  }
  assert.throws(() => project(inspect(), pin, 100_000, limits({ outputBytes: 1 })));
  for (const [user, expected] of [
    ['', 'root'],
    ['0', 'root'],
    ['root:users', 'root'],
    ['000:0', 'root'],
    ['1000:users', 'non-root'],
    ['daemon', 'unknown'],
  ]) {
    const raw = inspect();
    raw.Config.User = user;
    assert.equal(project(raw, pin, 100_000).facts.configuredUser, expected);
  }
});
