// Synthetic injected tests ONLY. Never call the production Docker/operator opener.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { captureNativeDeploymentRecords, captureNativeReferenceOrigins, createNativeRuntimeAuthority, createNativeRuntimeObserver, acquireNativeRuntimeLease, NATIVE_PROJECT, NATIVE_ORIGIN, NATIVE_EPOCH_FORMAT, NATIVE_REFERENCE_FORMAT } from './native-runtime-authority.mjs';
import { installRoutes } from '../tests-e2e/batch27-final-native.mjs';
import { BASE } from '../tests-e2e/native-h7v3-paid-sol.mjs';
import { custodyCompletionReferences } from './deploy-reference-custody.mjs';

const hash = b => createHash('sha256').update(b).digest('hex');
const roles = ['api', 'auth-volume-init', 'egress', 'llm-egress', 'openai-egress', 'scan-volume-init', 'web', 'worker'];
const targets = ['api', 'egress', 'llm-egress', 'openai-egress', 'web', 'worker'];
const deployment = 'a'.repeat(32), review = 'b'.repeat(64), selected = { deployment, review, origin: NATIVE_ORIGIN };
const id = n => n.toString(16).padStart(64, '0'), image = n => `sha256:${id(n)}`;
const startedAt = '2026-11-04T01:00:00.000Z', created = '2026-11-04T00:59:00.000Z';
function fixture(targeted = false, borrowed = false) {
  const rebuilt = targeted ? ['api', 'web'] : targets;
  const old = roles.map((role, i) => ({ role, id: id(i + 1), image: image(i + 1), startedAt }));
  const source = { build: id(101), adapter: id(102), entries: [103, 104, 105, 106, 107, 108].map(id), verify() { if (f.sourceChanged) throw Error('SOURCE_CHANGED'); } };
  const candidates = Object.fromEntries(rebuilt.map((name, i) => { const o = old.find(v => v.role === name); return [name, { image: image(i + 21), tag: `dip-deploy-${name}:candidate-${deployment}`, oldImage: o.image, oldTag: `dip-deploy-${name}:old-${deployment}` }]; }));
  const starts = Object.fromEntries(rebuilt.map((role, i) => [role, { role, id: id(i + 21), image: candidates[role].image, startedAt }]));
  if (targeted) starts.worker = { ...old.find(v => v.role === 'worker'), startedAt: '2026-11-04T01:00:30.000Z' };
  const peers = Object.fromEntries(roles.map(name => [name, starts[name] ?? old.find(v => v.role === name)]));
  const pins = { services: Object.fromEntries(roles.map(n => [n, { image: peers[n].image }])) };
  const records = {
    complete: { version: 2, project: NATIVE_PROJECT, nonce: deployment, outcome: 'published', references: rebuilt.flatMap(name => [{ name, tag: candidates[name].tag, image: candidates[name].image }, { name, tag: candidates[name].oldTag, image: candidates[name].oldImage }]), evidence: [] },
    owner: { version: 2, nonce: deployment, kind: 'preserving-deployment' },
    intent: { version: 2, kind: 'preserving-deployment', project: NATIVE_PROJECT, nonce: deployment, mode: 'app', services: rebuilt, daemon: 'daemon:synthetic', source: source.build, adapter: source.adapter, entrySources: source.entries, old: rebuilt.map(role => { const v = old.find(v => v.role === role); return { role, id: v.id, image: v.image }; }), lifecycle: false },
    built: { version: 1, nonce: deployment, outcome: 'candidate-built-old-site-unchanged', candidates, lifecycle: false },
    published: { version: 2, project: NATIVE_PROJECT, nonce: deployment, mode: 'app', services: rebuilt, healthy: true, completedAt: '2026-11-04T01:01:00.000Z', pins },
    recovery: { version: 2, project: NATIVE_PROJECT, nonce: deployment, daemon: 'daemon:synthetic', services: rebuilt, old }, starts,
    verify() { if (f.recordsChanged) throw Error('RECEIPT_CHANGED'); },
  };
  if (targeted) {
    const migration = 'history-reservations-v4-to-v5';
    const proof = { version: 1, migration, from: 4, to: 5, before: id(201), after: id(202), allRowsPreserved: true };
    const before = { historyVersion: 4, llm: { history: proof.before } }, after = { historyVersion: 5, llm: { history: proof.after } };
    Object.assign(records.recovery, { migration: false, historyMigration: migration, historyVersion: 4, interruptedServices: ['api', 'web', 'worker'] });
    Object.assign(records.published, { migration: false, historyMigration: migration, historyProof: proof, verified: true, stores: after, interruptedServices: ['api', 'web', 'worker'] });
    records.authority = { version: 3, project: NATIVE_PROJECT, nonce: deployment, authority: { containers: old.map(c => ({
      role: c.role, Id: c.id, Image: c.image, Created: created, process: [startedAt, '', !c.role.endsWith('volume-init'), c.role.endsWith('volume-init') ? 'exited' : 'running', c.role.endsWith('volume-init') ? 0 : 100, 0, 0],
    })) } };
    records.migrationIntent = { version: 1, migration, from: 4, to: 5, source: source.build, candidateImage: candidates.api.image, expected: proof, baseline: before };
    records.migrationComplete = { version: 1, proof, candidateImage: candidates.api.image, before, after };
  }
  if (borrowed) {
    const originalNonce = 'c'.repeat(32);
    const original = { version: 2, nonce: originalNonce, project: NATIVE_PROJECT, outcome: 'published',
      references: rebuilt.map(name => ({ name, tag: `dip-deploy-${name}:candidate-${originalNonce}`, image: old.find(v => v.role === name).image })) };
    const origin = { kind: 'adapter-completion', nonce: originalNonce, sha256: hash(JSON.stringify(original)) };
    const custody = { version: 1, old: original.references.map(v => borrowed === 'mixed' && v.name === 'web' ?
          { name: v.name, image: v.image, tag: `dip-deploy-${v.name}:old-${deployment}`, ownership: 'owned' } : { ...v, ownership: 'borrowed', origin }),
      candidates: rebuilt.map(name => ({ name, tag: candidates[name].tag })) };
    for (const row of custody.old) candidates[row.name].oldTag = row.tag;
    records.custody = custody; records.origins = custody.old.filter(v => v.ownership === 'borrowed').map(v => ({ name: v.name, tag: v.tag, image: v.image, origin }));
    for (const r of [records.intent, records.built, records.published, records.recovery]) r.referenceCustody = custody;
    Object.assign(records.complete, { version: 3, referenceCustody: custody, ...custodyCompletionReferences(custody, deployment, candidates) });
    source.entries.push(id(109)); records.original = original;
  }
  const references = [...records.complete.references, ...(records.complete.borrowedReferences ?? [])];
  const observed = { referenceImages: references.map(r => ({ image: r.image, tags: [r.tag] })), status: { version: 1, project: NATIVE_PROJECT, origin: NATIVE_ORIGIN, hold: true, reason: 'SHARED_OPERATION_HOLD', daemon: 'daemon:synthetic',
    services: roles.map(name => ({ name, id: peers[name].id, image: peers[name].image, running: !name.endsWith('volume-init'), healthy: !name.endsWith('volume-init'), restartCount: 0 })) },
    epochs: roles.map(name => ({ name, id: peers[name].id, image: peers[name].image, created, startedAt: peers[name].startedAt, pid: name.endsWith('volume-init') ? 0 : 100, restartCount: 0 })) };
  const f = { records, source, observed, references, ticks: 0, checks: 0, acquired: 0, released: 0, reads: 0, events: [], currentReview: review, locked: true, order: [],
    open: null, observeHook: null, recordsChanged: false, sourceChanged: false };
  f.open = createNativeRuntimeAuthority({ records: () => { f.reads++; return records; }, captureSource: () => source,
    readReview: async () => f.currentReview,
    acquire: () => { f.acquired++; return { verify() { assert.equal(f.locked, true, 'LOCK_CHANGED'); }, record(phase, operation) { f.recordHook?.(phase); f.events.push({ phase, operation }); }, release() { f.released++; f.locked = false; } }; },
    observe: async () => { f.checks++; f.order.push('observe'); await f.observeHook?.(); return structuredClone(observed); }, now: () => f.ticks, wall: () => Date.parse('2026-11-04T02:00:00.000Z'),
  });
  return f;
}

test('qualified existing receipt + independent runtime: fresh check for each paid send, successful owned lock release', async () => {
  const f = fixture(), a = await f.open(selected); assert.equal(f.checks, 1);
  for (const kind of ['summary', 'chat']) await a.dispatch(kind, async () => { f.order.push(kind); return 'ok'; });
  assert.deepEqual(f.order, ['observe', 'observe', 'summary', 'observe', 'observe', 'chat', 'observe']);
  assert.equal(f.released, 0); assert.deepEqual(await a.close(true), { released: true }); assert.equal(f.released, 1);
  await assert.rejects(a.dispatch('chat', () => assert.fail('after close')));
});
for (const [name, mutate] of [
  ['wrong nonce', f => { f.records.complete.nonce = 'c'.repeat(32); }],
  ['unpublished', f => { f.records.complete.outcome = 'old-restored'; }],
  ['wrong project', f => { f.records.intent.project = 'other'; }],
  ['web-only', f => { f.records.intent.mode = 'web'; }],
  ['missing worker build', f => { f.records.intent.services = ['api', 'web']; }],
  ['wrong owner nonce', f => { f.records.owner.nonce = 'c'.repeat(32); }],
  ['build source mismatch', f => { f.source.build = id(900); }],
  ['adapter mismatch', f => { f.source.adapter = id(900); }],
  ['entry source mismatch', f => { f.source.entries = [id(900)]; }],
  ['unhealthy publication', f => { f.records.published.healthy = false; }],
  ['future receipt', f => { f.records.published.completedAt = '2027-01-01'; }],
  ['nonce-shaped tag only', f => { f.records.built.candidates.api.image = 'candidate-' + deployment; }],
  ['mutable tag mismatch', f => { f.records.built.candidates.api.tag = 'arbitrary:latest'; }],
  ['inconsistent old identities', f => { f.records.intent.old[0].id = id(900); }],
  ['publication pins mismatch', f => { f.records.published.pins.services.api.image = image(900); }],
  ['missing container receipt', f => { delete f.records.starts.api; }],
  ['unchanged old container claimed new', f => { f.records.starts.api.id = f.records.recovery.old.find(v => v.role === 'api').id; }],
  ['extra role', f => { f.records.recovery.old.push({ role: 'foreign' }); }],
  ['references mismatch', f => { f.records.complete.references.pop(); }],
  ['wrong reviewed runner', f => { f.currentReview = id(900); }],
  ['changed immutable receipt', f => { f.recordsChanged = true; }],
  ['changed source', f => { f.sourceChanged = true; }],
]) test(`reject ${name} before acquiring dispatch fence`, async () => {
  const f = fixture(); mutate(f); await assert.rejects(f.open(selected)); assert.equal(f.acquired, 0); assert.equal(f.checks, 0);
});
for (const input of [{ ...selected, origin: 'http://127.0.0.1:8080' }, { ...selected, origin: NATIVE_ORIGIN + '/' }, { ...selected, review: 'label' }, { ...selected, deployment: '../x' }]) test(`selection fails without reading sources: ${JSON.stringify(input)}`, async () => {
  const f = fixture(); await assert.rejects(f.open(input), /RUNTIME_SELECTION_INVALID/); assert.equal(f.reads, 0);
});
for (const [name, change] of [
  ['foreign origin', f => { f.observed.status.origin = 'http://127.0.0.1:8080'; }],
  ['wrong daemon', f => { f.observed.status.daemon = 'another:daemon'; }],
  ['unheld operation lock', f => { f.observed.status.hold = false; }],
  ['container replacement', f => { f.observed.status.services[0].id = id(900); }],
  ['image replacement', f => { f.observed.status.services[0].image = image(900); }],
  ['unhealthy api', f => { f.observed.status.services[0].healthy = false; }],
  ['extra namespace peer', f => { f.observed.status.services.push({ name: 'foreign' }); }],
  ['missing epoch', f => { f.observed.epochs.pop(); }],
  ['restarted same ID', f => { f.observed.epochs[0].startedAt = '2026-11-04T01:30:00.000Z'; }],
  ['restart count', f => { f.observed.epochs[0].restartCount++; }],
  ['same epoch changed pid', f => { f.observed.epochs[0].pid++; }],
  ['changed created identity', f => { f.observed.epochs[0].created = '2026-11-04T00:58:00.000Z'; }],
  ['changed review', f => { f.currentReview = id(901); }],
  ['changed receipt', f => { f.recordsChanged = true; }],
  ['changed source', f => { f.sourceChanged = true; }],
  ['lost owned lock', f => { f.locked = false; }],
  ['old retained tag removed', f => { f.observed.referenceImages[1].tags = []; }],
  ['candidate tag rebound', f => { f.observed.referenceImages[0].image = image(999); }],
]) test(`replacement/freshness attack before NEXT paid dispatch: ${name}`, async () => {
  const f = fixture(), a = await f.open(selected); let sends = 0;
  await a.dispatch('summary', async () => { sends++; }); change(f);
  await assert.rejects(a.dispatch('chat', async () => { sends++; })); assert.equal(sends, 1); assert.equal(f.released, 0);
  await assert.rejects(a.dispatch('chat', async () => { sends++; })); assert.equal(sends, 1);
  assert.deepEqual(await a.close(false), { released: false }); assert.equal(f.released, 0);
});
test('replacement DURING paid dispatch refuses publication and retains lock; never resends', async () => {
  const f = fixture(), a = await f.open(selected); let sends = 0;
  await assert.rejects(a.dispatch('chat', async () => { sends++; f.observed.status.services[0].id = id(900); return 'untrusted'; }), /RUNTIME_TARGET_REPLACED/);
  await assert.rejects(a.dispatch('chat', async () => { sends++; })); assert.equal(sends, 1); assert.equal(f.released, 0);
});
for (const ticks of [15000, 600000, -1]) test(`stale/expired/backwards clock ${ticks} refuses before send`, async () => {
  const f = fixture(), a = await f.open(selected); let sends = 0;
  if (ticks === 15000) f.observeHook = () => { f.ticks += ticks; }; else f.ticks = ticks;
  await assert.rejects(a.dispatch('chat', async () => { sends++; })); assert.equal(sends, 0); assert.equal(f.released, 0);
});
test('slow review after fresh observation does not reuse an expired observation', async () => {
  const f = fixture(); let reads = 0;
  const open = createNativeRuntimeAuthority({ records: () => f.records, captureSource: () => f.source,
    readReview: async () => { if (++reads >= 3) f.ticks += 16000; return review; }, acquire: () => ({ verify() {}, record() {}, release() {} }),
    observe: async () => f.observed, now: () => f.ticks, wall: () => Date.parse('2026-11-04T02:00:00Z') });
  const a = await open(selected); await assert.rejects(a.dispatch('chat', () => assert.fail('stale review dispatched')));
});
test('concurrent dispatch cannot share one check; failed transport is never retried', async () => {
  const f = fixture(), a = await f.open(selected); let finish, sends = 0;
  const pending = a.dispatch('summary', async () => { sends++; await new Promise(r => { finish = r; }); throw Error('UNCERTAIN_TRANSPORT'); });
  while (!finish) await Promise.resolve();
  await assert.rejects(a.dispatch('chat', () => assert.fail('concurrent send'))); finish();
  await assert.rejects(pending, /UNCERTAIN_TRANSPORT/); await assert.rejects(a.dispatch('summary', () => assert.fail('retry')));
  assert.equal(sends, 1); assert.equal(f.released, 0);
});
test('even a successful operation cannot be dispatched twice by one authority handle', async () => {
  const f = fixture(), a = await f.open(selected); let sends = 0;
  await a.dispatch('summary', async () => { sends++; });
  await assert.rejects(a.dispatch('summary', async () => { sends++; })); assert.equal(sends, 1);
});
test('failed side-effect-free journey releases only its own admission fence', async () => {
  const f = fixture(), a = await f.open(selected); assert.deepEqual(await a.close(false), { released: true }); assert.equal(f.released, 1);
});
test('initial read-only observation refusal releases its known admission fence', async () => {
  const f = fixture(); f.observed.status.origin = 'http://127.0.0.1:8080';
  await assert.rejects(f.open(selected)); assert.equal(f.released, 1);
});
test('extra inspect has only epoch identity fields; never Env, args, Health logs, private payload', () => {
  for (const word of ['Env', 'Health', 'Args', 'Mount', 'Secret', 'Log']) assert.equal(NATIVE_EPOCH_FORMAT.includes(word), false);
});

test('production observer uses exact scoped existing metadata commands, pins local daemon and excludes secrets', async () => {
  const f = fixture(), calls = [];
  const observe = createNativeRuntimeObserver(async () => { calls.push(['status']); return f.observed.status; }, async (args, options) => {
    calls.push(args); assert.equal(options.timeout, 10000);
    assert.deepEqual(Object.keys(options.env).sort(), args[0] === 'context' ? ['COMPOSE_DISABLE_ENV_FILE', 'HOME', 'PATH'] : ['COMPOSE_DISABLE_ENV_FILE', 'DOCKER_HOST', 'HOME', 'PATH']);
    if (args[0] === 'context') return JSON.stringify('unix:///synthetic.sock');
    assert.equal(options.env.DOCKER_HOST, 'unix:///synthetic.sock');
    if (args[0] === 'info') return JSON.stringify(f.observed.status.daemon);
    if (args[0] === 'image') {
      assert.deepEqual(args, ['image', 'inspect', ...f.references.map(r => r.tag), '--format', NATIVE_REFERENCE_FORMAT]);
      return f.observed.referenceImages.map(e => JSON.stringify(e)).join('\n');
    }
    assert.deepEqual(args, ['container', 'inspect', ...roles.map(n => `${NATIVE_PROJECT}-${n}-1`), '--format', NATIVE_EPOCH_FORMAT]);
    return f.observed.epochs.map(e => JSON.stringify(e)).join('\n');
  }, '/synthetic-root', '/synthetic-home');
  assert.deepEqual(await observe({ references: f.references }), f.observed);
  assert.deepEqual(calls.map(a => a[0]), ['status', 'context', 'info', 'container', 'image', 'info']);
  assert.equal(JSON.stringify(calls).includes('8080'), false);
});
for (const attack of ['remote-context', 'daemon-before', 'daemon-after', 'invalid-epoch-json', 'status-failed']) test(`production observer refuses ${attack}`, async () => {
  const f = fixture(); let info = 0, inspected = 0;
  const observe = createNativeRuntimeObserver(async () => { if (attack === 'status-failed') throw Error('STATUS_REFUSED'); return f.observed.status; }, async args => {
    if (args[0] === 'context') return JSON.stringify(attack === 'remote-context' ? 'tcp://other:2375' : 'unix:///synthetic.sock');
    if (args[0] === 'info') { info++; return JSON.stringify(attack === 'daemon-before' || attack === 'daemon-after' && info === 2 ? 'changed:daemon' : f.observed.status.daemon); }
    inspected++; return attack === 'invalid-epoch-json' ? 'not-json' : (args[0] === 'image' ? f.observed.referenceImages : f.observed.epochs).map(e => JSON.stringify(e)).join('\n');
  }, '/synthetic-root', '/synthetic-home');
  await assert.rejects(observe({ references: f.references })); if (['remote-context', 'daemon-before', 'status-failed'].includes(attack)) assert.equal(inspected, 0);
});
test('actual installed handler uses receipt authority for summary, then rejects changed runtime before chat transport', async () => {
  const f = fixture(), authority = await f.open(selected), order = [];
  let handler; const log = { requests: 0, denied: 0, postAttempts: 0, dispatched: 0, summaryPosts: 0, chatPosts: 0 };
  const gate = { stopped: false, async consume(kind) { order.push('spent-' + kind); return true; }, stop() { this.stopped = true; } };
  await installRoutes({ route: async (_, fn) => { handler = fn; }, routeWebSocket: async () => {} }, gate, log, async () => { order.push('published'); }, authority.dispatch);
  const route = kind => {
    const url = NATIVE_ORIGIN + BASE + '/llm/' + kind;
    const response = { status: () => 200, url: () => url, dispose: async () => { order.push('dispose'); } };
    return { request: () => ({ url: () => url, method: () => 'POST', redirectedFrom: () => null, postDataJSON: () => ({}), headerValue: async key => key === 'content-type' ? 'application/json' : 'application/x-ndjson' }),
      fetch: async options => { assert.deepEqual(options, { maxRedirects: 0, maxRetries: 0, timeout: 150000 }); order.push('fetch-' + kind); return response; },
      fulfill: async () => { order.push('fulfill'); }, abort: async () => { order.push('abort'); } };
  };
  await handler(route('summary')); assert.equal(log.summaryPosts, 1); assert.equal(f.checks, 3);
  f.observed.epochs[0].startedAt = '2026-11-04T01:30:00.000Z';
  await handler(route('chat')); assert.equal(log.chatPosts, 0); assert.equal(log.dispatched, 1); assert.equal(gate.stopped, true);
  assert.deepEqual(order, ['spent-summary', 'published', 'fetch-summary', 'fulfill', 'dispose', 'spent-chat', 'published', 'abort']);
  await handler(route('chat')); assert.equal(log.dispatched, 1); assert.equal(f.released, 0);
});
function metadataFixture(targeted = false, borrowed = false) {
  const f = fixture(targeted, borrowed), root = fs.mkdtempSync(join(tmpdir(), 'native-authority-synthetic-'));
  const parent = join(root, '.local-public-images/deploy-adapter-v1'), dir = join(parent, deployment);
  fs.mkdirSync(join(dir, 'operation.lock'), { recursive: true, mode: 0o700 });
  const files = { 'intent.json': f.records.intent, 'built.json': f.records.built, 'published.json': f.records.published, 'recovery.json': f.records.recovery,
    ...Object.fromEntries(Object.entries(f.records.starts).map(([n, v]) => [`start-${n}-complete.json`, v])),
    ...(targeted ? { 'authority-v3.json': f.records.authority, 'history-migration-intent.json': f.records.migrationIntent, 'history-migration-complete.json': f.records.migrationComplete } : {}),
        ...(borrowed ? { 'reference-custody.json': f.records.custody } : {}) };
  const write = (name, value) => fs.writeFileSync(join(dir, name), JSON.stringify(value), { mode: 0o600 });
  for (const [name, value] of Object.entries(files)) write(name, value);
  const evidence = Object.entries(files).map(([path, value]) => { const bytes = Buffer.from(JSON.stringify(value)); return { path, bytes: bytes.length, sha256: hash(bytes) }; });
  write('complete.json', { ...f.records.complete, evidence }); write('operation.lock/deploy-adapter-owner.json', f.records.owner);
  let originDir;
  if (borrowed) {
    const original = f.records.original;
    originDir = join(parent, original.nonce); fs.mkdirSync(join(originDir, 'operation.lock'), { recursive: true, mode: 0o700 });
    fs.writeFileSync(join(originDir, 'complete.json'), JSON.stringify(original), { mode: 0o600 });
    fs.writeFileSync(join(originDir, 'operation.lock/deploy-adapter-owner.json'), JSON.stringify({ version: 2, nonce: original.nonce, kind: 'preserving-deployment' }), { mode: 0o600 });
  }
  return { root, dir, write, originDir, f };
}
test('real fixed-path receipt reader verifies sealed metadata without opening private snapshots', () => {
  const { root, dir } = metadataFixture();
  fs.mkdirSync(join(dir, 'snapshots'), { mode: 0o700 });
  fs.writeFileSync(join(dir, 'snapshots/private.sqlite'), 'SYNTHETIC_NEVER_READ', { mode: 0o000 });
  const original = fs.openSync, opened = [];
  fs.openSync = function (path, ...args) { opened.push(path); assert.equal(String(path).includes('snapshots'), false); return original.call(this, path, ...args); };
  syncBuiltinESMExports();
  try { const r = captureNativeDeploymentRecords(root, deployment); r.verify(); assert.equal(r.intent.nonce, deployment); }
  finally { fs.openSync = original; syncBuiltinESMExports(); }
  assert.equal(opened.every(p => p.endsWith('.json')), true);
});
for (const kind of ['byte-change', 'same-bytes-replacement', 'symlink', 'hardlink', 'public-mode', 'evidence-mismatch', 'recovery-branch', 'extra-owner-entry', 'parent-symlink']) test(`fixed receipt filesystem attack ${kind} fails closed`, () => {
  const { root, dir, write } = metadataFixture(), file = join(dir, 'intent.json');
  if (kind === 'byte-change' || kind === 'same-bytes-replacement') {
    const r = captureNativeDeploymentRecords(root, deployment), bytes = fs.readFileSync(file);
    if (kind === 'byte-change') fs.appendFileSync(file, ' ');
    else { fs.renameSync(file, join(dir, 'preserved-intent.json')); fs.writeFileSync(file, bytes, { mode: 0o600 }); }
    assert.throws(() => r.verify()); return;
  }
  if (kind === 'symlink') { fs.renameSync(file, join(dir, 'preserved-intent.json')); fs.symlinkSync('preserved-intent.json', file); }
  if (kind === 'hardlink') fs.linkSync(file, join(dir, 'linked-intent.json'));
  if (kind === 'public-mode') fs.chmodSync(file, 0o644);
  if (kind === 'evidence-mismatch') { const value = JSON.parse(fs.readFileSync(file)); value.source = id(999); write('intent.json', value); }
  if (kind === 'recovery-branch') fs.mkdirSync(join(dir, 'recovery-v5'), { mode: 0o700 });
  if (kind === 'extra-owner-entry') write('operation.lock/other.json', {});
  if (kind === 'parent-symlink') { const parent = join(root, '.local-public-images'); fs.renameSync(parent, join(root, 'preserved-state')); fs.symlinkSync('preserved-state', parent); }
  assert.throws(() => captureNativeDeploymentRecords(root, deployment));
});

for (const borrowed of [false, true, 'mixed']) test(`targeted actual web/api history4→5 qualified path; borrowed=${borrowed}`, async () => {
  const f = fixture(true, borrowed), a = await f.open(selected), sends = [];
  assert.deepEqual(a.qualification, { rebuiltRoles: ['api', 'web'], retainedRoles: roles.filter(n => !['api', 'web'].includes(n)),
    retainedRolesCurrentSourceClaim: false, historyMigration: 'history-reservations-v4-to-v5' });
  await a.dispatch('summary', async () => { sends.push('summary'); });
  await a.dispatch('chat', async () => { sends.push('chat'); });
  assert.deepEqual(sends, ['summary', 'chat']); assert.deepEqual(await a.close(true), { released: true });
  assert.deepEqual(f.events.map(e => e.phase), ['admitted', 'dispatch-submitted', 'dispatch-observed', 'dispatch-submitted', 'dispatch-observed', 'release']);
});
for (const [name, mutate] of [
  ['missing preflight', f => { delete f.records.authority; }],
  ['preflight wrong nonce', f => { f.records.authority.nonce = 'd'.repeat(32); }],
  ['preflight old image', f => { f.records.authority.authority.containers[2].Image = image(999); }],
  ['preflight created after start', f => { f.records.authority.authority.containers[2].Created = '2027-01-01'; }],
  ['preflight epoch differs', f => { f.records.authority.authority.containers[2].process[0] = '2026-11-04T00:00:00Z'; }],
  ['preflight restarted', f => { f.records.authority.authority.containers[2].process[5] = 1; }],
  ['worker rebuilt under retained claim', f => { f.records.starts.worker.id = id(999); }],
  ['missing retained worker restart', f => { delete f.records.starts.worker; }],
  ['worker old epoch reused', f => { f.records.starts.worker.startedAt = startedAt; }],
  ['retained gateway has start receipt', f => { f.records.starts.egress = { role: 'egress' }; }],
  ['initializer unexpectedly restarted', f => { f.records.starts['auth-volume-init'] = {}; }],
  ['auth migration not allowed', f => { f.records.recovery.migration = true; }],
  ['history3 not admitted', f => { f.records.recovery.historyVersion = 3; }],
  ['history migration unverified', f => { f.records.published.verified = false; }],
  ['missing explicit history intent', f => { delete f.records.migrationIntent; }],
  ['wrong migration source', f => { f.records.migrationIntent.source = id(999); }],
  ['wrong migration candidate', f => { f.records.migrationComplete.candidateImage = image(999); }],
  ['unpreserved migration', f => { f.records.migrationComplete.proof = { ...f.records.migrationComplete.proof, allRowsPreserved: false }; }],
  ['history final wrong schema', f => { f.records.published.stores = { historyVersion: 4 }; }],
]) test(`targeted refusal before acquisition: ${name}`, async () => {
  const f = fixture(true); mutate(f); await assert.rejects(f.open(selected)); assert.equal(f.acquired, 0);
});
for (const role of ['worker', 'egress', 'llm-egress', 'openai-egress', 'auth-volume-init', 'scan-volume-init']) test(`targeted retained ${role} identity and epoch are fenced on first and later observation`, async () => {
  const f = fixture(true), a = await f.open(selected);
  f.observed.epochs.find(v => v.name === role).created = '2026-11-04T00:58:00Z';
  await assert.rejects(a.dispatch('chat', () => assert.fail('retained peer drift sent')));
  assert.deepEqual(await a.close(false), { released: true });
  const first = fixture(true); first.observed.epochs.find(v => v.name === role).created = '2026-11-04T00:58:00Z';
  await assert.rejects(first.open(selected)); assert.equal(first.released, 1);
});
for (const [name, mutate] of [
  ['custody mismatch', f => { f.records.published.referenceCustody = { ...f.records.custody, version: 2 }; }],
  ['missing custody', f => { delete f.records.custody; }],
  ['unproven origin', f => { f.records.origins = []; }],
    ['missing authenticated origins', f => { delete f.records.origins; }],
  ['wrong owning hash', f => { f.records.origins = f.records.origins.map(r => ({ ...r, origin: { ...r.origin, sha256: id(999) } })); }],
  ['extra borrowed', f => { f.records.complete.borrowedReferences.push(f.records.complete.borrowedReferences[0]); }],
  ['legacy v2 cannot borrow', f => { f.records.complete.version = 2; }],
  ['changed borrowed image', f => { f.records.built.candidates.api.oldImage = image(999); }],
]) test(`versioned custody refuses ${name}`, async () => {
  const f = fixture(true, true); mutate(f); await assert.rejects(f.open(selected)); assert.equal(f.acquired, 0);
});
test('real sealed targeted and borrowed receipt joins original metadata owner, not an injected authority assertion', async () => {
  const { root, f } = metadataFixture(true, true), r = captureNativeDeploymentRecords(root, deployment);
  r.verify(); f.open = createNativeRuntimeAuthority({ records: () => r, captureSource: () => f.source, readReview: async () => review,
    acquire: () => ({ verify() {}, record() {}, release() {} }), observe: async () => f.observed, wall: () => Date.parse('2026-11-04T02:00:00Z') });
  const a = await f.open(selected); await a.dispatch('chat', async () => {}); await a.close(true);
});
for (const attack of ['original-byte-change', 'original-owner', 'non-owning-borrow', 'origin-replacement', 'origin-link', 'own-custody-byte-change']) test(`borrowed origin fixed metadata attack: ${attack}`, () => {
  const { root, originDir, dir } = metadataFixture(true, true);
  const path = join(originDir, 'complete.json');
  if (attack === 'origin-replacement' || attack === 'original-byte-change') {
    const r = captureNativeDeploymentRecords(root, deployment), bytes = fs.readFileSync(path);
    if (attack === 'original-byte-change') fs.appendFileSync(path, ' ');
    else { fs.renameSync(path, join(originDir, 'preserved.json')); fs.writeFileSync(path, bytes, { mode: 0o600 }); }
    assert.throws(() => r.verify()); return;
  }
  if (attack === 'original-owner') fs.writeFileSync(join(originDir, 'operation.lock/deploy-adapter-owner.json'), '{}');
  if (attack === 'non-owning-borrow') { const c = JSON.parse(fs.readFileSync(path)); c.references = []; fs.writeFileSync(path, JSON.stringify(c)); }
  if (attack === 'origin-link') fs.linkSync(path, join(originDir, 'linked.json'));
  if (attack === 'own-custody-byte-change') fs.appendFileSync(join(dir, 'reference-custody.json'), ' ');
  assert.throws(() => captureNativeDeploymentRecords(root, deployment));
});

function leaseFixture(ioFactory = io => io) {
  const root = fs.mkdtempSync(join(tmpdir(), 'native-lease-synthetic-')), state = join(root, '.local-public-images'), path = join(state, '.operation.lock');
  fs.mkdirSync(state, { mode: 0o700 }); let acquisitions = 0;
  const acquire = () => {
    acquisitions++; fs.mkdirSync(path, { mode: 0o700 }); const old = fs.lstatSync(path);
    return { path, verify() { const s = fs.lstatSync(path); assert.equal(s.dev, old.dev); assert.equal(s.ino, old.ino); }, release() { this.verify(); fs.rmdirSync(path); } };
  };
  return { root, state, path, open: () => acquireNativeRuntimeLease(root, acquire, selected, ioFactory(fs)), acquisitions: () => acquisitions,
    audit: () => join(state, 'native-runtime-v1', fs.readdirSync(join(state, 'native-runtime-v1'))[0]) };
}
test('real native lease has durable recoverable intent before acquisition, releases empty admission without deleting audit', () => {
  const f = leaseFixture(), lease = f.open(); lease.record('admitted');
  assert.deepEqual(fs.readdirSync(f.path), []); assert.equal(JSON.parse(fs.readFileSync(join(f.audit(), 'intent.json'))).deployment, deployment);
  lease.verify(); lease.release(); assert.equal(fs.existsSync(f.path), false); assert.equal(fs.existsSync(f.audit()), true);
});
test('real postdispatch unknown keeps an explicit immutable pointer and prior intent, not anonymous empty HOLD', () => {
  const f = leaseFixture(), lease = f.open(); lease.record('admitted'); lease.record('dispatch-submitted', 'summary'); lease.record('retained-unknown');
  lease.verify(); assert.deepEqual(fs.readdirSync(f.path), ['native-runtime-owner.json']);
  const pointer = JSON.parse(fs.readFileSync(join(f.path, 'native-runtime-owner.json')));
  assert.equal(pointer.deployment, deployment); assert.equal(pointer.review, review); assert.match(pointer.audit, /^native-runtime-v1\//);
  assert.equal(fs.readdirSync(f.audit()).some(n => n.endsWith('dispatch-submitted.json')), true);
  assert.throws(() => f.open()); assert.equal(fs.existsSync(f.path), true);
});
test('successful real lease archives the whole own fence, preserving all metadata', () => {
  const f = leaseFixture(), lease = f.open(); lease.record('admitted'); lease.record('dispatch-submitted', 'chat'); lease.record('dispatch-observed', 'chat'); lease.record('release');
  lease.release(); assert.equal(fs.existsSync(f.path), false);
  assert.deepEqual(fs.readdirSync(join(f.audit(), 'operation.lock')), ['native-runtime-owner.json']);
  assert.throws(() => lease.verify());
});
for (const phase of ['intent.json', 'acquired.json', 'dispatch-submitted.json', 'native-runtime-owner.json']) test(`metadata write fault ${phase} cannot send or strand a known anonymous admission`, () => {
  let armed = true;
  const f = leaseFixture(io => ({ ...io, openSync(path, flags, ...args) {
    if (armed && typeof path === 'string' && path.endsWith(phase) && flags & io.constants.O_CREAT) { armed = false; throw Error('SYNTHETIC_METADATA_IO'); }
    return io.openSync(path, flags, ...args);
  } }));
  if (['intent.json', 'acquired.json'].includes(phase)) {
    assert.throws(() => f.open(), /SYNTHETIC_METADATA_IO/); assert.equal(fs.existsSync(f.path), false);
    if (phase === 'intent.json') assert.equal(f.acquisitions(), 0);
  } else {
    const lease = f.open(); assert.throws(() => lease.record('dispatch-submitted', 'chat'), /SYNTHETIC_METADATA_IO/);
    lease.release(); assert.equal(fs.existsSync(f.path), false);
  }
});
test('changed/foreign lock is never removed even after side-effect-free failure', () => {
  const f = leaseFixture(), lease = f.open(); fs.writeFileSync(join(f.path, 'foreign.json'), '{}', { mode: 0o600 });
  assert.throws(() => lease.release()); assert.equal(fs.existsSync(join(f.path, 'foreign.json')), true);
});
for (const phase of ['admitted', 'dispatch-submitted', 'dispatch-observed']) test(`authority metadata fault ${phase} fails closed with truthful dispatch disposition`, async () => {
  const f = fixture(true, true); let sends = 0;
  f.recordHook = at => { if (at === phase) throw Error('METADATA_FAILURE'); };
  if (phase === 'admitted') { await assert.rejects(f.open(selected), /METADATA_FAILURE/); assert.equal(f.released, 1); return; }
  const a = await f.open(selected); await assert.rejects(a.dispatch('chat', async () => { sends++; }), /METADATA_FAILURE/);
  assert.equal(sends, phase === 'dispatch-observed' ? 1 : 0);
  assert.deepEqual(await a.close(false), { released: sends === 0 });
  await assert.rejects(a.dispatch('chat', () => assert.fail('metadata failure retry')));
});
for (const phase of ['intent.json', 'acquired.json', 'native-runtime-owner.json', 'dispatch-observed.json']) test(`partial fsync failure ${phase} retains diagnostic metadata and releases only unsent own fence`, () => {
  let faultFd, armed = true;
  const f = leaseFixture(io => ({ ...io, openSync(path, flags, ...args) {
    const fd = io.openSync(path, flags, ...args);
    if (armed && typeof path === 'string' && path.endsWith(phase) && flags & io.constants.O_CREAT) faultFd = fd;
    return fd;
  }, fsyncSync(fd) { if (armed && fd === faultFd) { armed = false; throw Error('SYNTHETIC_FSYNC'); } return io.fsyncSync(fd); } }));
  if (['intent.json', 'acquired.json'].includes(phase)) {
    assert.throws(() => f.open(), /SYNTHETIC_FSYNC/); assert.equal(fs.existsSync(f.path), false); return;
  }
  const lease = f.open();
  if (phase === 'native-runtime-owner.json') { assert.throws(() => lease.record('dispatch-submitted', 'chat'), /SYNTHETIC_FSYNC/); lease.release(); assert.equal(fs.existsSync(f.path), false); }
  else {
    lease.record('dispatch-submitted', 'chat'); assert.throws(() => lease.record('dispatch-observed', 'chat'), /SYNTHETIC_FSYNC/);
    assert.equal(fs.existsSync(join(f.path, 'native-runtime-owner.json')), true);
    assert.equal(fs.existsSync(join(f.audit(), 'intent.json')), true);
  }
});
test('acquisition failure after an unreturned lock creation has prior durable intent but never unproven auto-unlock', () => {
  const f = leaseFixture();
  assert.throws(() => acquireNativeRuntimeLease(f.root, () => { fs.mkdirSync(f.path, { mode: 0o700 }); throw Error('ACQUIRE_SYNC_UNCERTAIN'); }, selected), /ACQUIRE_SYNC_UNCERTAIN/);
  assert.equal(fs.existsSync(f.path), true);
  const intent = JSON.parse(fs.readFileSync(join(f.audit(), 'intent.json')));
  assert.equal(intent.kind, 'native-runtime-authority'); assert.equal(intent.pid, process.pid); assert.equal(intent.lock, '.operation.lock');
});
test('unchanged gateway PID is pinned to original fresh preflight even at initial admission', async () => {
  const f = fixture(true); f.observed.epochs.find(v => v.name === 'openai-egress').pid++;
  await assert.rejects(f.open(selected)); assert.equal(f.released, 1);
});
test('slow pre-send durable fsync cannot age an observation into dispatch authority', async () => {
  const f = fixture(true, true), a = await f.open(selected); let sends = 0;
  f.recordHook = phase => { if (phase === 'dispatch-submitted') f.ticks += 16000; };
  await assert.rejects(a.dispatch('chat', async () => { sends++; }), /RUNTIME_OBSERVATION_STALE/);
  assert.equal(sends, 0); assert.deepEqual(await a.close(false), { released: true });
});
for (const drift of [false, true]) test(`composed qualified production components + actual installed transport: targeted v3 borrowed custody, drift=${drift}`, async () => {
  const { root, f } = metadataFixture(true, true), records = captureNativeDeploymentRecords(root, deployment);
  const path = join(root, '.local-public-images/.operation.lock');
  const acquire = () => {
    fs.mkdirSync(path, { mode: 0o700 }); const old = fs.lstatSync(path);
    return { path, verify() { const s = fs.lstatSync(path); assert.equal(s.ino, old.ino); assert.equal(s.dev, old.dev); }, release() { this.verify(); fs.rmdirSync(path); } };
  };
  const observe = createNativeRuntimeObserver(async () => structuredClone(f.observed.status), async args => {
    if (args[0] === 'context') return JSON.stringify('unix:///synthetic.sock');
    if (args[0] === 'info') return JSON.stringify(f.observed.status.daemon);
    return (args[0] === 'image' ? f.observed.referenceImages : f.observed.epochs).map(v => JSON.stringify(v)).join('\n');
  }, root, '/synthetic-home');
  const authority = await createNativeRuntimeAuthority({ records: () => records, captureSource: () => f.source, readReview: async () => review,
    acquire: () => acquireNativeRuntimeLease(root, acquire, selected), observe, wall: () => Date.parse('2026-11-04T02:00:00Z') })(selected);
  let handler; const sent = [], log = { requests: 0, denied: 0, postAttempts: 0, dispatched: 0, summaryPosts: 0, chatPosts: 0 };
  const gate = { stopped: false, async consume() { return true; }, stop() { this.stopped = true; } };
  await installRoutes({ async route(_, fn) { handler = fn; }, async routeWebSocket() {} }, gate, log, async () => {}, authority.dispatch);
  const request = kind => {
    const url = NATIVE_ORIGIN + BASE + '/llm/' + kind;
    return { request: () => ({ url: () => url, method: () => 'POST', redirectedFrom: () => null, postDataJSON: () => ({}), headerValue: async key => key === 'content-type' ? 'application/json' : 'application/x-ndjson' }),
      fetch: async () => {
        assert.equal(JSON.parse(fs.readFileSync(join(path, 'native-runtime-owner.json'))).deployment, deployment);
        const pointer = JSON.parse(fs.readFileSync(join(path, 'native-runtime-owner.json')));
        const events = fs.readdirSync(join(root, '.local-public-images', pointer.audit));
        assert.equal(events.some(n => n.endsWith('dispatch-submitted.json')), true); sent.push(kind);
        return { status: () => 200, url: () => url, dispose: async () => {} };
      }, fulfill: async () => {}, abort: async () => {} };
  };
  await handler(request('summary'));
  if (drift) f.observed.referenceImages[0].image = image(999);
  await handler(request('chat'));
  assert.deepEqual(sent, drift ? ['summary'] : ['summary', 'chat']);
  assert.deepEqual(await authority.close(!drift), { released: !drift });
  assert.equal(fs.existsSync(path), drift);
  if (drift) assert.equal(fs.existsSync(join(path, 'native-runtime-owner.json')), true);
});
function legacyOriginFixture() {
  const f = leaseFixture(), audit = 'deploy-' + 'd'.repeat(32), directory = join(f.state, 'llm-deployments', audit);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const metadata = Object.fromEntries(['api', 'worker', 'web', 'llm-egress'].map((name, index) => {
    const node = ['api', 'worker'].includes(name), web = name === 'web';
    const Config = { Labels: { 'org.diplom.public-image-stand': 'v1', 'org.diplom.public-image-project': NATIVE_PROJECT },
      Env: ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', ...(node ? ['NODE_VERSION=24.11.1', 'YARN_VERSION=1.22.22'] : web ? ['NGINX_VERSION=1.27.5'] : ['PYTHON_VERSION=3.13.7', 'GPG_KEY=' + 'a'.repeat(40), 'PYTHON_SHA256=' + 'a'.repeat(64)])],
      Entrypoint: node ? ['docker-entrypoint.sh'] : web ? ['/docker-entrypoint.sh'] : null,
      Cmd: node ? ['node', '--import', 'tsx', name === 'api' ? 'src/main.ts' : 'src/worker/worker.main.ts'] : web ? ['nginx', '-g', 'daemon off;'] : ['python', '-I', 'openrouter.py'],
      User: web ? '101:101' : '65532:65532', WorkingDir: node ? '/app/server/api' : web ? '/' : '/opt/gateway',
      ExposedPorts: web ? { '80/tcp': {}, '8080/tcp': {} } : {}, StopSignal: web ? 'SIGQUIT' : '' };
    return [name, { Id: image(index + 300), Os: 'linux', Config }];
  }));
  const build = { version: 1, phase: 'validated-before-build', sourceBasis: 'validated-before-build', imageMetadata: metadata,
    pins: { services: Object.fromEntries(Object.entries(metadata).map(([name, v]) => [name, { image: v.Id }])) } };
  const write = (name, value) => fs.writeFileSync(join(directory, name), JSON.stringify(value), { mode: 0o600 });
  write('build-checkpoint.json', build);
  const receipt = { version: 1, audit, project: NATIVE_PROJECT, checkpointSha256: hash(JSON.stringify(build)), images: Object.fromEntries(Object.entries(metadata).map(([name, v]) => [name, { image: v, tag: `${NATIVE_PROJECT}-${name}:retained-${audit.slice(7)}` }])) };
  write('image-retention.json', receipt); write('image-retention-intent.json', receipt); write('complete.json', { version: 1, project: NATIVE_PROJECT, preserved: true });
  const borrowed = ['api', 'web'].map(name => ({ name, image: metadata[name].Id, tag: receipt.images[name].tag, origin: { kind: 'llm-retention', audit, sha256: hash(JSON.stringify(receipt)) } }));
  return { ...f, directory, borrowed, write, receipt };
}
test('production original LLM-retention origin uses real receipt/checkpoint/catalog validators, no store payload reads', () => {
  const f = legacyOriginFixture(), original = fs.openSync, opened = [];
  fs.openSync = function(path, ...args) { opened.push(path); assert.equal(String(path).endsWith('.sqlite'), false); return original.call(this, path, ...args); }; syncBuiltinESMExports();
  try {
    const proof = captureNativeReferenceOrigins(f.root, f.borrowed); proof.verify(); assert.deepEqual(proof.references, f.borrowed);
    fs.appendFileSync(join(f.directory, 'build-checkpoint.json'), ' '); assert.throws(() => proof.verify());
  } finally { fs.openSync = original; syncBuiltinESMExports(); }
  assert.equal(opened.some(p => p.endsWith('image-retention.json')), true);
});
for (const attack of ['checkpoint', 'missing-complete', 'intent', 'origin-hash', 'tag', 'image', 'receipt-link']) test(`original LLM retention origin refuses ${attack}`, () => {
  const f = legacyOriginFixture();
  if (attack === 'checkpoint') fs.appendFileSync(join(f.directory, 'build-checkpoint.json'), ' ');
  if (attack === 'missing-complete') fs.unlinkSync(join(f.directory, 'complete.json'));
  if (attack === 'intent') fs.appendFileSync(join(f.directory, 'image-retention-intent.json'), ' ');
  if (attack === 'origin-hash') f.borrowed[0].origin.sha256 = id(999);
  if (attack === 'tag') f.borrowed[0].tag = 'other:tag';
  if (attack === 'image') f.borrowed[0].image = image(999);
  if (attack === 'receipt-link') fs.linkSync(join(f.directory, 'image-retention.json'), join(f.directory, 'linked.json'));
  assert.throws(() => captureNativeReferenceOrigins(f.root, f.borrowed));
});
test('postdispatch metadata damage refuses release while retaining explicit owner and original intent', () => {
  const f = leaseFixture(), lease = f.open(); lease.record('dispatch-submitted', 'chat');
  fs.appendFileSync(join(f.audit(), 'intent.json'), ' '); assert.throws(() => lease.verify()); assert.throws(() => lease.release());
  assert.equal(fs.existsSync(join(f.path, 'native-runtime-owner.json')), true);
});
