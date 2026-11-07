// Real readers/adapter; synthetic disposable state and fake engine/HTTP only.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import fsDefault from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { performance } from 'node:perf_hooks';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { adapterFixture } from './test_deploy_history_v5_batch26_fixture.mjs';
import { deployAdapterDiagnostic } from './deploy-adapter.mjs';
import * as custody from './deploy-reference-custody.mjs';
import { captureDeploymentCatalog, archiveHash, DEPLOYMENT_CAPACITY_POLICY } from './public-llm-deployment-catalog.mjs';
import { capturePublicLlmRetentions, publicLlmRetentionTag } from './public-llm-stand.mjs';

const PROJECT = 'dip-public-images';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const nonceAt = i => i.toString(16).padStart(32, '0');
const write = (path, value) => fs.writeFileSync(path, typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value), { mode: 0o600 });
const mkdir = path => fs.mkdirSync(path, { recursive: true, mode: 0o700 });
const read = path => JSON.parse(fs.readFileSync(path));
const web = { mode: 'web', services: ['web'] };

function tree(path) {
  const result = [];
  const walk = (path, relative = '') => {
    const s = fs.lstatSync(path);
    const identity = { path: relative, dev: s.dev, ino: s.ino, mode: s.mode, uid: s.uid, nlink: s.nlink };
    if (s.isDirectory()) {
      const names = fs.readdirSync(path).sort(); result.push({ ...identity, names });
      for (const name of names) walk(join(path, name), relative ? relative + '/' + name : name);
    } else result.push({ ...identity, size: s.size, mtime: s.mtimeMs, ctime: s.ctimeMs, sha256: hash(fs.readFileSync(path)) });
  };
  walk(path); return result;
}
function evidence(path) {
  return tree(path).filter(e => e.path && !['complete.json', 'operation.lock'].includes(e.path) && !e.path.startsWith('operation.lock/'))
    .map(e => e.names ? { path: e.path, directory: true } : { path: e.path, bytes: e.size, sha256: e.sha256 });
}
function seedLegacyCatalog(f, { active = 26, archived = 9 } = {}) {
  const activePath = join(f.stand, 'llm-deployments'), archivePath = join(f.stand, 'llm-deployments-archive');
  const operations = join(f.stand, 'llm-deployment-archive-operations');
  for (const path of [activePath, archivePath, operations]) mkdir(path);
  const entries = [];
  for (let i = 0; i < active + archived; i++) {
    const name = 'deploy-' + nonceAt(i + 1), path = join(i < active ? activePath : archivePath, name);
    mkdir(path);
    for (const phase of ['fenced', 'before-api', 'after-api']) for (const group of ['core', 'llm']) {
      mkdir(join(path, phase, group));
      for (const role of ['auth', 'ledger']) write(join(path, phase, group, role + '.sqlite'), Buffer.from(`synthetic preserved ${name}/${phase}/${group}/${role}`));
    }
    const build = { version: 1, phase: 'validated-before-build', sourceBasis: 'validated-before-build', retirementPolicy: null,
      baseline: { historyVersion: 4, llm: {} }, imageMetadata: {}, jwtIdentity: {}, peers: [], pins: {}, publicProfile: {}, source: 'a'.repeat(64) };
    // Retain references in both locations, without exhausting the independent image budget.
    const retained = i === 0 || i === active;
    if (retained) for (const role of ['api', 'worker', 'web', 'llm-egress']) {
      const image = f.images.get(f.pins().services[role].image);
      build.imageMetadata[role] = { Id: image.Id, Os: image.Os, Config: structuredClone(image.Config) };
      build.pins.services ??= {}; build.pins.services[role] = { image: image.Id };
      image.RepoTags.push(publicLlmRetentionTag(name, role));
    }
    write(join(path, 'build-checkpoint.json'), build);
    write(join(path, 'complete.json'), { version: 1, project: PROJECT, preserved: true });
    if (retained) {
      const receipt = { version: 1, project: PROJECT, audit: name, checkpointSha256: hash(fs.readFileSync(join(path, 'build-checkpoint.json'))),
        images: Object.fromEntries(Object.entries(build.imageMetadata).map(([role, image]) => [role, { image, tag: publicLlmRetentionTag(name, role) }])) };
      for (const file of ['image-retention-intent.json', 'image-retention.json']) write(join(path, file), receipt);
    }
    entries.push({ name, path, archived: i >= active });
  }
  const archivedEntries = entries.filter(e => e.archived);
  for (let i = 0; i < archivedEntries.length; i += 8) {
    const selected = archivedEntries.slice(i, i + 8);
    const trees = selected.map(e => ({ name: e.name,
      directories: tree(e.path).filter(v => v.names).map(v => ({ path: v.path, dev: v.dev, ino: v.ino, names: v.names })),
      files: tree(e.path).filter(v => !v.names).map(v => ({ path: v.path, digest: v.sha256 })) }));
    const plan = { version: 1, root: f.root, catalog: [], cve: null, selected: selected.map(e => e.name), source: 'a'.repeat(64), trees };
    const review = archiveHash(plan), path = join(operations, review); mkdir(path);
    write(join(path, 'intent.json'), { version: 1, project: PROJECT, command: 'archive-completed-deployments', review, plan });
    write(join(path, 'complete.json'), { version: 1, project: PROJECT, review, archived: plan.selected, preserved: true });
  }
  return { entries, operations };
}
function seedAdapterHistory(f, count = 13) {
  const parent = join(f.stand, 'deploy-adapter-v1'); mkdir(parent);
  const rows = [], image = f.pins().services.web.image;
  for (let i = 0; i < count; i++) {
    const nonce = nonceAt(1000 + i), dir = join(parent, nonce); mkdir(join(dir, 'operation.lock'));
    write(join(dir, 'operation.lock/deploy-adapter-owner.json'), { version: 2, nonce, kind: 'preserving-deployment' });
    mkdir(join(dir, 'snapshots/fenced'));
    write(join(dir, 'snapshots/fenced/auth.sqlite'), Buffer.from('synthetic adapter snapshot ' + nonce));
    const references = [], borrowedReferences = [];
    let referenceCustody = null;
    if (i === 0) {
      const tag = `dip-deploy-web:old-${nonce}`; references.push({ name: 'web', tag, image }); f.images.get(image).RepoTags.push(tag);
    } else if (i === 1) {
      const original = rows[0], old = original.record.references[0], origin = { kind: 'adapter-completion', nonce: original.nonce, sha256: hash(fs.readFileSync(join(original.dir, 'complete.json'))) };
      const tag = `dip-deploy-web:candidate-${nonce}`;
      references.push({ name: 'web', tag, image }); f.images.get(image).RepoTags.push(tag);
      borrowedReferences.push({ ...old, origin });
      referenceCustody = { version: 1, old: [{ ...old, ownership: 'borrowed', origin }], candidates: [{ name: 'web', tag }] };
      write(join(dir, 'reference-custody.json'), referenceCustody);
    }
    const record = { version: i === 0 ? 2 : 3, project: PROJECT, nonce, outcome: i > 1 ? 'pre-mutation-aborted' : 'published', references,
      ...(i === 0 ? {} : { borrowedReferences, referenceCustody }), evidence: evidence(dir) };
    write(join(dir, 'complete.json'), record); rows.push({ nonce, dir, record });
  }
  return { parent, rows };
}
function preserve(paths) {
  const before = paths.map(path => [path, tree(path)]);
  return () => { for (const [path, value] of before) assert.deepEqual(tree(path), value, 'historical tree changed: ' + path); };
}
function noDispatch(f) {
  assert.equal(f.locked(), false);
  assert.ok(!f.calls.some(c => c[0] === 'build' || c[0] === 'create' || c[0] === 'image' && ['tag', 'rm', 'prune'].includes(c[1]) || c[0] === 'container' && ['start', 'stop', 'rm'].includes(c[1])));
  assert.deepEqual(f.events, []); f.verifyStores();
}

test('history domains: 35 legacy + 13 complete adapter attempts admit without dropping any evidence or references', async t => {
  const f = await adapterFixture(t, { historyVersion: 5 }), legacy = seedLegacyCatalog(f), history = seedAdapterHistory(f);
  const catalog = captureDeploymentCatalog(f.root), retentions = capturePublicLlmRetentions(f.root);
  assert.equal(catalog.active.length, 26); assert.equal(catalog.archived.length, 9); assert.equal(catalog.entries.length, 35);
  assert.equal(retentions.tags.length, 8); assert.equal(history.rows.length, 13);
  const unchanged = preserve([...legacy.entries.map(e => e.path), legacy.operations, history.parent]);
  const plan = await f.rawAdapter.prepare(web);
  assert.equal(plan.mode, 'web'); assert.equal(plan.referenceCustody.old[0].ownership, 'borrowed');
  unchanged(); noDispatch(f);
});

test('history domains retain independent legacy and adapter limits', () => {
  assert.deepEqual(DEPLOYMENT_CAPACITY_POLICY, { version: 2, active: 32, archived: 16, total: 48, archiveBatch: 8, retainedReferences: 128 });
  assert.equal(custody.ADAPTER_HISTORY_LIMIT, 48);
  for (const count of [0, 13, 47, 48]) assert.doesNotThrow(() => custody.assertAdapterHistoryCapacity(count));
  for (const count of [0, 13, 47]) assert.doesNotThrow(() => custody.assertAdapterHistoryCapacity(count, { reserve: 1 }));
  for (const [count, options] of [[48, { reserve: 1 }], [49, {}], [-1, {}], [0.5, {}], [NaN, {}], [Infinity, {}], [Number.MAX_SAFE_INTEGER, {}], [0, { reserve: -1 }], [0, { reserve: 2 }], [0, { reserve: true }]]) {
    assert.throws(() => custody.assertAdapterHistoryCapacity(count, options), error => custody.referenceCustodyDiagnostic(error) === 'ADAPTER_HISTORY_CAPACITY');
  }
});

test('a full valid legacy catalog does not consume current adapter slots', async t => {
  const f = await adapterFixture(t, { historyVersion: 5 });
  const legacy = seedLegacyCatalog(f, { active: 32, archived: 16 });
  const history = seedAdapterHistory(f, 1);
  const unchanged = preserve([...legacy.entries.map(e => e.path), legacy.operations, history.parent]);
  assert.equal(captureDeploymentCatalog(f.root).entries.length, 48);
  await f.rawAdapter.prepare(web);
  unchanged(); noDispatch(f);
});

test('attempt 48 is admitted with 47 completed records; its own directory counts and completion stays readable', async t => {
  const f = await adapterFixture(t, { historyVersion: 5 });
  seedLegacyCatalog(f, { active: 1, archived: 0 });
  const history = seedAdapterHistory(f, 47), unchanged = preserve(history.rows.map(row => row.dir));
  const lease = await f.rawAdapter.acquireLock(web), ctx = { ...web, lease, options: {} };
  assert.equal(fs.readdirSync(history.parent).length, 48);
  ctx.plan = await f.rawAdapter.preflight(ctx);
  await f.rawAdapter.releaseLock(ctx);
  unchanged(); noDispatch(f);
  const added = fs.readdirSync(history.parent).find(name => !history.rows.some(row => row.nonce === name));
  assert.equal(read(join(history.parent, added, 'complete.json')).outcome, 'pre-mutation-aborted');
  await assert.rejects(f.rawAdapter.prepare(web), error => deployAdapterDiagnostic(error).code === 'ADAPTER_HISTORY_CAPACITY');
  // The capacity check must not substitute for validating the 48th completed record.
  write(join(history.parent, added, 'lease.json'), { version: 2, project: PROJECT, nonce: 'f'.repeat(32) });
  await assert.rejects(f.rawAdapter.prepare(web), error => deployAdapterDiagnostic(error).code === 'ADAPTER_HISTORY_EVIDENCE_CHANGED');
  noDispatch(f);
});

test('49 total directories refuse before evidence or engine work, including an excluded owned attempt', async t => {
  const f = await adapterFixture(t, { historyVersion: 5 });
  const history = seedAdapterHistory(f, 47);
  const lease = await f.rawAdapter.acquireLock(web), ctx = { ...web, lease, options: {} };
  const extra = join(history.parent, nonceAt(9999)); mkdir(extra);
  const before = f.calls.length;
  await assert.rejects(f.rawAdapter.preflight(ctx), error => deployAdapterDiagnostic(error).code === 'ADAPTER_HISTORY_CAPACITY');
  assert.equal(f.calls.length, before);
  assert.equal(fs.readdirSync(history.parent).length, 49);
  assert.equal(f.locked(), true, 'the test must not silently release an already owned fence');
});

for (const fault of ['snapshot', 'completion', 'owner', 'custody-origin', 'symlink']) {
  test(`full mixed history still rejects ${fault} corruption before dispatch`, async t => {
    const f = await adapterFixture(t, { historyVersion: 5 });
    seedLegacyCatalog(f);
    const history = seedAdapterHistory(f), last = history.rows.at(-1);
    if (fault === 'snapshot') write(join(last.dir, 'snapshots/fenced/auth.sqlite'), Buffer.from('changed synthetic evidence'));
    if (fault === 'completion') fs.unlinkSync(join(last.dir, 'complete.json'));
    if (fault === 'owner') write(join(last.dir, 'operation.lock/deploy-adapter-owner.json'), { version: 2, nonce: nonceAt(9999), kind: 'preserving-deployment' });
    if (fault === 'symlink') {
      const file = join(last.dir, 'snapshots/fenced/auth.sqlite'); fs.unlinkSync(file);
      fs.symlinkSync(join(history.rows[0].dir, 'snapshots/fenced/auth.sqlite'), file);
    }
    if (fault === 'custody-origin') {
      const row = history.rows[1], record = read(join(row.dir, 'complete.json'));
      record.referenceCustody.old[0].origin.sha256 = 'd'.repeat(64);
      record.borrowedReferences[0].origin.sha256 = 'd'.repeat(64);
      write(join(row.dir, 'reference-custody.json'), record.referenceCustody);
      record.evidence = evidence(row.dir); write(join(row.dir, 'complete.json'), record);
    }
    const unchanged = fault === 'symlink' ? null : preserve(history.rows.map(row => row.dir));
    await assert.rejects(f.rawAdapter.prepare(web));
    unchanged?.(); noDispatch(f);
    if (fault === 'custody-origin') assert.equal(f.calls.length, 0, 'forged owning receipt must fail before engine access');
  });
}

for (const occurrence of [1, 2]) {
  test(`history hashing observes the existing deadline on scan ${occurrence} before acquiring a lock`, async t => {
    const f = await adapterFixture(t, { historyVersion: 5 }), history = seedAdapterHistory(f, 1);
    const row = history.rows[0], payload = join(row.dir, 'snapshots/fenced/auth.sqlite');
    write(payload, Buffer.alloc(131073, 1)); row.record.evidence = evidence(row.dir); write(join(row.dir, 'complete.json'), row.record);
    const unchanged = preserve([history.parent]);
    let tick = 0, reads = 0;
    const originalRead = fsDefault.readSync;
    const clock = t.mock.method(performance, 'now', () => tick);
    const readMock = t.mock.method(fsDefault, 'readSync', (fd, ...args) => {
      const value = originalRead(fd, ...args);
      if (fsDefault.fstatSync(fd).size === 131073 && args[1] === 0 && ++reads === occurrence * 4 - 3) tick = 300001;
      return value;
    });
    syncBuiltinESMExports();
    try {
      await assert.rejects(occurrence === 1 ? f.rawAdapter.prepare(web) : f.rawAdapter.acquireLock(web), error => deployAdapterDiagnostic(error).code === 'ADAPTER_DEADLINE');
      noDispatch(f);
    } finally { readMock.mock.restore(); clock.mock.restore(); syncBuiltinESMExports(); }
    unchanged();
  });
}
