// Import-safe operator seam. No CLI JSON attestation, endpoint or live probe at import.
// Supports normal completed full app and targeted web/api publications. Retained
// peers keep their sealed preflight identities; they are NOT a current-source build.
// Recovery/web-only evidence needs separate qualification. Metadata here does not
// replace the coordinator's B0/B1 database equality qualification.
import * as fs from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual as equal } from 'node:util';
import { completionReferences, validateReferenceCustody, custodyCompletionReferences } from './deploy-reference-custody.mjs';
import { capturePublicLlmRetentions } from './public-llm-stand.mjs';
import { captureDeploymentCatalog, archiveDirectory, archiveFile } from './public-llm-deployment-catalog.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
export const NATIVE_PROJECT = 'dip-public-images';
export const NATIVE_ORIGIN = 'http://127.0.0.1:8081';
const ROLES = Object.freeze(['api', 'auth-volume-init', 'egress', 'llm-egress', 'openai-egress', 'scan-volume-init', 'web', 'worker']);
const TARGETS = ROLES.filter(n => !n.endsWith('volume-init'));
const ENTRIES = ['deploy.mjs', 'deploy-core.mjs', 'deploy-adapter-stores.mjs', 'public-llm-stand.mjs', 'deploy-supervisor.mjs', 'deploy-authority.mjs'];
const hex = v => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const nonce = v => typeof v === 'string' && /^[a-f0-9]{32}$/.test(v);
const image = v => typeof v === 'string' && /^sha256:[a-f0-9]{64}$/.test(v);
const hash = b => createHash('sha256').update(b).digest('hex');
const need = (ok, code = 'RUNTIME_AUTHORITY_REFUSED') => { if (!ok) throw Error(code); };
const exact = (v, names) => v && Object.getPrototypeOf(v) === Object.prototype && equal(Object.keys(v).sort(), [...names].sort());
const stamp = s => [s.dev, s.ino, s.uid, s.mode, s.nlink, s.size, s.mtimeMs, s.ctimeMs];

// Fixed metadata files only: never walk/read evidence snapshots, Env, JWT or keys.
// complete.evidence seals the files we use, NOT the private files we do not read.
export function captureNativeDeploymentRecords(root, deployment, captureOrigins = captureNativeReferenceOrigins) {
  need(nonce(deployment) && resolve(root) === root && fs.realpathSync(root) === root);
  const directory = join(root, '.local-public-images/deploy-adapter-v1', deployment), guards = [];
  for (const path of [root, join(root, '.local-public-images'), dirname(directory), directory, join(directory, 'operation.lock')]) {
    const s = fs.lstatSync(path);
    need(s.isDirectory() && !s.isSymbolicLink() && s.uid === process.getuid() && !(s.mode & 0o022));
    if (path !== root) need((s.mode & 0o7777) === 0o700);
    guards.push(() => { const t = fs.lstatSync(path); need(t.isDirectory() && !t.isSymbolicLink() && equal([t.dev, t.ino, t.uid, t.mode], [s.dev, s.ino, s.uid, s.mode])); });
  }
  need(equal(fs.readdirSync(join(directory, 'operation.lock')), ['deploy-adapter-owner.json']));
  const names = fs.readdirSync(directory).sort();
  // No adoption of recovered/reconciled or unclassified publications.
  need(!names.some(n => /^(recovery-v5|compensation|restore-|failure)/.test(n)), 'RUNTIME_RECEIPT_BRANCH_UNSUPPORTED');
  const cache = new Map();
  const read = name => {
    need(['complete.json', 'intent.json', 'built.json', 'published.json', 'recovery.json', 'operation.lock/deploy-adapter-owner.json',
      'authority-v3.json', 'history-migration-intent.json', 'history-migration-complete.json', 'reference-custody.json',
      ...TARGETS.map(n => `start-${n}-complete.json`)].includes(name));
    if (cache.has(name)) return cache.get(name).value;
    const path = join(directory, name), s = fs.lstatSync(path);
    need(s.isFile() && !s.isSymbolicLink() && s.nlink === 1 && s.uid === process.getuid() && (s.mode & 0o7777) === 0o600 && s.size <= 262144);
    const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    let bytes;
    try { need(equal(stamp(s), stamp(fs.fstatSync(fd)))); bytes = fs.readFileSync(fd); need(equal(stamp(s), stamp(fs.fstatSync(fd)))); }
    finally { fs.closeSync(fd); }
    need(equal(stamp(s), stamp(fs.lstatSync(path))));
    const text = bytes.toString('utf8'); need(Buffer.from(text).equals(bytes));
    const value = JSON.parse(text);
    cache.set(name, { value, bytes, digest: hash(bytes) });
    guards.push(() => {
      need(equal(stamp(s), stamp(fs.lstatSync(path))));
      const f = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
      try { need(equal(stamp(s), stamp(fs.fstatSync(f))) && fs.readFileSync(f).equals(bytes) && equal(stamp(s), stamp(fs.fstatSync(f)))); }
      finally { fs.closeSync(f); }
    });
    return value;
  };
  const complete = read('complete.json'), intent = read('intent.json'), built = read('built.json'), published = read('published.json'), recovery = read('recovery.json');
  const owner = read('operation.lock/deploy-adapter-owner.json');
  const custody = complete.version === 3 ? read('reference-custody.json') : null;
  const origins = complete.version === 3 ? captureOrigins(root, complete.borrowedReferences) : { references: [], verify() {} };
  const authority = names.includes('authority-v3.json') ? read('authority-v3.json') : null;
  const migrationIntent = names.includes('history-migration-intent.json') ? read('history-migration-intent.json') : null;
  const migrationComplete = names.includes('history-migration-complete.json') ? read('history-migration-complete.json') : null;
  const starts = Object.fromEntries(TARGETS.filter(n => names.includes(`start-${n}-complete.json`)).map(n => [n, read(`start-${n}-complete.json`)]));
  const verify = () => {
    guards.forEach(g => g()); origins.verify(); need(equal(fs.readdirSync(directory).sort(), names));
    need(equal(fs.readdirSync(join(directory, 'operation.lock')), ['deploy-adapter-owner.json']));
    need(Array.isArray(complete.evidence) && complete.evidence.length <= 256);
    for (const [name, proof] of cache) {
      if (['complete.json', 'operation.lock/deploy-adapter-owner.json'].includes(name)) continue;
      const rows = complete.evidence.filter(e => e.path === name);
      need(rows.length === 1 && exact(rows[0], ['path', 'bytes', 'sha256']) && rows[0].bytes === proof.bytes.length && rows[0].sha256 === proof.digest);
    }
  };
  verify(); return { complete, intent, built, published, recovery, owner, starts, authority, migrationIntent, migrationComplete, custody, origins: origins.references, verify };
}

// Borrowing authenticates the ORIGINAL owning receipt, not another borrower's
// assertion. Existing retention/catalog validators read metadata only, no stores.
export function captureNativeReferenceOrigins(root, borrowed) {
  need(Array.isArray(borrowed) && borrowed.length <= TARGETS.length, 'RUNTIME_BORROWED_ORIGIN_INVALID');
  const proofs = [], references = [];
  let retentions, catalog;
  for (const row of borrowed) {
    const origin = row.origin; need(origin && hex(origin.sha256), 'RUNTIME_BORROWED_ORIGIN_INVALID');
    if (origin.kind === 'llm-retention') {
      need(/^deploy-[a-f0-9]{32}$/.test(origin.audit), 'RUNTIME_BORROWED_ORIGIN_INVALID');
      retentions ??= capturePublicLlmRetentions(root); catalog ??= captureDeploymentCatalog(root);
      const receipt = retentions.receipts.find(v => v.audit === origin.audit), entry = catalog.entries.find(v => v.name === origin.audit);
      need(receipt && entry, 'RUNTIME_BORROWED_ORIGIN_INVALID');
      const file = archiveFile(join(entry.path, 'image-retention.json'), 262144), ref = receipt.images[row.name];
      need(file.digest === origin.sha256 && ref?.tag === row.tag && ref.image.Id === row.image, 'RUNTIME_BORROWED_ORIGIN_INVALID');
      proofs.push(file);
    } else {
      need(origin.kind === 'adapter-completion' && nonce(origin.nonce), 'RUNTIME_BORROWED_ORIGIN_INVALID');
      const parent = archiveDirectory(join(root, '.local-public-images/deploy-adapter-v1'));
      const directory = archiveDirectory(join(parent.path, origin.nonce)), lock = archiveDirectory(join(directory.path, 'operation.lock'));
      const file = archiveFile(join(directory.path, 'complete.json'), 262144), owner = archiveFile(join(lock.path, 'deploy-adapter-owner.json'), 4096);
      const c = JSON.parse(file.bytes);
      need(file.digest === origin.sha256 && c.project === NATIVE_PROJECT && ['published', 'old-restored', 'pre-mutation-aborted'].includes(c.outcome) &&
        equal(JSON.parse(owner.bytes), { version: 2, nonce: origin.nonce, kind: 'preserving-deployment' }) && equal(lock.names, ['deploy-adapter-owner.json']), 'RUNTIME_BORROWED_ORIGIN_INVALID');
      const original = completionReferences(c, origin.nonce).owned;
      need(original.some(v => v.name === row.name && v.tag === row.tag && v.image === row.image), 'RUNTIME_BORROWED_ORIGIN_INVALID');
      proofs.push(parent, directory, lock, file, owner);
    }
    references.push(structuredClone(row));
  }
  return { references, verify() { retentions?.verify(); catalog?.verify(); proofs.forEach(p => p.verify()); } };
}

function targetedPreflight(r, deployment) {
  const { authority: a, recovery: q, published: p, intent: i, built: b, migrationIntent: m, migrationComplete: done } = r;
  const migration = 'history-reservations-v4-to-v5';
  need(a?.version === 3 && a.project === NATIVE_PROJECT && a.nonce === deployment &&
    Array.isArray(a.authority?.containers) && equal(a.authority.containers.map(c => c.role).sort(), ROLES), 'RUNTIME_PREFLIGHT_REQUIRED');
  need(q.migration === false && q.historyVersion === 4 && q.historyMigration === migration && p.migration === false &&
    p.historyMigration === migration && p.verified === true && equal(p.interruptedServices, ['api', 'web', 'worker']) &&
    equal(q.interruptedServices, p.interruptedServices), 'RUNTIME_MIGRATION_UNQUALIFIED');
  need(m?.version === 1 && m.migration === migration && m.from === 4 && m.to === 5 && m.source === i.source &&
    m.candidateImage === b.candidates.api.image && done?.version === 1 && done.candidateImage === m.candidateImage &&
    equal(done.proof, m.expected) && equal(done.proof, p.historyProof) && equal(done.before, m.baseline) &&
    done.before?.historyVersion === 4 && done.after?.historyVersion === 5 && p.stores?.historyVersion === 5,
  'RUNTIME_MIGRATION_UNQUALIFIED');
  const proof = done.proof;
  need(exact(proof, ['version', 'migration', 'from', 'to', 'before', 'after', 'allRowsPreserved']) && proof.version === 1 &&
    proof.migration === migration && proof.from === 4 && proof.to === 5 && proof.allRowsPreserved === true &&
    hex(proof.before) && hex(proof.after) && done.before.llm?.history === proof.before && done.after.llm?.history === proof.after,
  'RUNTIME_MIGRATION_UNQUALIFIED');
  const preflight = Object.fromEntries(a.authority.containers.map(c => {
    const old = q.old.find(v => v.role === c.role), running = !c.role.endsWith('volume-init');
    need(old && c.Id === old.id && c.Image === old.image && Number.isFinite(Date.parse(c.Created)) &&
      c.process?.length === 7 && c.process[0] === old.startedAt && Date.parse(c.process[0]) >= Date.parse(c.Created) &&
      c.process[2] === running && c.process[3] === (running ? 'running' : 'exited') &&
      Number.isSafeInteger(c.process[4]) && (running ? c.process[4] > 0 : c.process[4] === 0) && c.process[5] === 0 && c.process[6] === 0,
    'RUNTIME_PREFLIGHT_IDENTITY_MISMATCH');
    return [c.role, c];
  }));
  return preflight;
}

function receiptIdentities(r, deployment, source, wall) {
  const { complete: c, intent: i, built: b, published: p, recovery: q, owner, starts } = r;
  need([2, 3].includes(c?.version) && c.project === NATIVE_PROJECT && c.nonce === deployment && c.outcome === 'published');
  need(equal(owner, { version: 2, nonce: deployment, kind: 'preserving-deployment' }));
  need(i?.version === 2 && i.kind === 'preserving-deployment' && i.project === NATIVE_PROJECT && i.nonce === deployment && i.mode === 'app' && i.lifecycle === false);
  const targeted = equal(i.services, ['api', 'web']);
  need(Array.isArray(i.services) && equal(i.services, [...new Set(i.services)].sort()) && (equal(i.services, TARGETS) || targeted), 'RUNTIME_RECEIPT_BRANCH_UNSUPPORTED');
  need(hex(i.source) && i.source === source.build && i.adapter === source.adapter && equal(i.entrySources, source.entries), 'RUNTIME_BUILD_SOURCE_MISMATCH');
  need(p?.version === 2 && p.project === NATIVE_PROJECT && p.nonce === deployment && p.mode === 'app' && p.healthy === true && equal(p.services, i.services) && Number.isFinite(Date.parse(p.completedAt)) && Date.parse(p.completedAt) <= wall, 'RUNTIME_PUBLICATION_INVALID');
  need(b?.version === 1 && b.nonce === deployment && b.outcome === 'candidate-built-old-site-unchanged' && b.lifecycle === false && exact(b.candidates, i.services));
  need(q?.version === 2 && q.project === NATIVE_PROJECT && q.nonce === deployment && q.daemon === i.daemon && equal(q.services, i.services));
  need(Array.isArray(q.old) && q.old.length === ROLES.length && equal(q.old.map(v => v.role).sort(), ROLES) && new Set(q.old.map(v => v.id)).size === ROLES.length);
  need(equal(i.old, i.services.map(role => { const v = q.old.find(v => v.role === role); return { role, id: v.id, image: v.image }; })), 'RUNTIME_OLD_IDENTITIES_MISMATCH');
  need(exact(p.pins, ['services']) && exact(p.pins.services, ROLES));
  const preflight = targeted ? targetedPreflight(r, deployment) : null;
  let custody = null;
  if (c.version === 3) {
    need(Array.isArray(r.origins) && equal(r.origins, c.borrowedReferences), 'RUNTIME_BORROWED_ORIGIN_INVALID');
    custody = validateReferenceCustody(r.custody, deployment, r.origins);
    need(equal(custody, c.referenceCustody) && equal(custody, i.referenceCustody) && equal(custody, b.referenceCustody) &&
      equal(custody, p.referenceCustody) && equal(custody, q.referenceCustody) && equal(custody.old.map(v => v.name), i.services), 'RUNTIME_CUSTODY_MISMATCH');
    const refs = custodyCompletionReferences(custody, deployment, b.candidates);
    completionReferences(c, deployment);
    need(equal(c.references, refs.references) && equal(c.borrowedReferences, refs.borrowedReferences), 'RUNTIME_REFERENCES_MISMATCH');
  }
  const references = [], ids = [];
  const expected = Object.fromEntries(ROLES.map(name => {
    const old = q.old.find(v => v.role === name); need(hex(old.id) && image(old.image) && Number.isFinite(Date.parse(old.startedAt)));
    let row = old;
    if (i.services.includes(name)) {
      const candidate = b.candidates[name], start = starts[name];
      need(exact(candidate, ['image', 'tag', 'oldImage', 'oldTag']) && image(candidate.image) && candidate.oldImage === old.image && candidate.tag === `dip-deploy-${name}:candidate-${deployment}` && candidate.oldTag === (custody ? custody.old.find(v => v.name === name).tag : `dip-deploy-${name}:old-${deployment}`));
      references.push({ name, tag: candidate.tag, image: candidate.image });
      if (!custody || custody.old.find(v => v.name === name).ownership === 'owned') references.push({ name, tag: candidate.oldTag, image: candidate.oldImage });
      need(exact(start, ['role', 'id', 'image', 'startedAt']) && start.role === name && hex(start.id) && start.id !== old.id && start.image === candidate.image && Number.isFinite(Date.parse(start.startedAt)));
      row = start;
    } else if (targeted && name === 'worker') {
      // The preserving app flow stops/restarts the worker, but does not rebuild it.
      const start = starts[name];
      need(exact(start, ['role', 'id', 'image', 'startedAt']) && start.role === name && start.id === old.id && start.image === old.image &&
        Number.isFinite(Date.parse(start.startedAt)) && Date.parse(start.startedAt) > Date.parse(old.startedAt), 'RUNTIME_RETAINED_RESTART_INVALID');
      row = start;
    } else need(!Object.hasOwn(starts, name));
    need(Date.parse(row.startedAt) <= Date.parse(p.completedAt), 'RUNTIME_PUBLICATION_INVALID');
    need(exact(p.pins.services[name], ['image']) && p.pins.services[name].image === row.image, 'RUNTIME_PINS_MISMATCH');
    ids.push(row.id); return [name, { id: row.id, image: row.image, startedAt: row.startedAt,
      ...(preflight && !i.services.includes(name) ? { created: preflight[name].Created,
              ...(name !== 'worker' ? { pid: preflight[name].process[4] } : {}) } : {}) }];
  }));
  need(new Set(ids).size === ROLES.length && equal(c.references, references), 'RUNTIME_REFERENCES_MISMATCH');
  return { expected, daemon: i.daemon, references: [...c.references, ...(c.version === 3 ? c.borrowedReferences : [])], qualification: Object.freeze({
    rebuiltRoles: Object.freeze([...i.services]), retainedRoles: Object.freeze(ROLES.filter(n => !i.services.includes(n))),
    retainedRolesCurrentSourceClaim: false, historyMigration: q.historyMigration ?? 'none',
  }) };
}

function runtimeIdentity(observed, receipt) {
  const { status: s, epochs, referenceImages } = observed;
  need(Array.isArray(referenceImages) && referenceImages.length === receipt.references.length, 'RUNTIME_REFERENCE_CHANGED');
  for (const [index, ref] of receipt.references.entries()) {
    const row = referenceImages[index];
    need(exact(row, ['image', 'tags']) && row.image === ref.image && Array.isArray(row.tags) && row.tags.length <= 256 &&
      row.tags.every(t => typeof t === 'string' && t.length <= 384) && row.tags.includes(ref.tag), 'RUNTIME_REFERENCE_CHANGED');
  }
  need(s?.version === 1 && s.project === NATIVE_PROJECT && s.origin === NATIVE_ORIGIN && s.hold === true && s.reason === 'SHARED_OPERATION_HOLD' && s.daemon === receipt.daemon, 'RUNTIME_NAMESPACE_MISMATCH');
  need(Array.isArray(s.services) && s.services.length === ROLES.length && equal(s.services.map(v => v.name).sort(), ROLES));
  need(Array.isArray(epochs) && epochs.length === ROLES.length && equal(epochs.map(v => v.name).sort(), ROLES));
  const result = [];
  for (const name of ROLES) {
    const v = s.services.find(v => v.name === name), e = epochs.find(v => v.name === name), expected = receipt.expected[name], running = !name.endsWith('volume-init');
    need(v.id === expected.id && v.image === expected.image && v.running === running && v.restartCount === 0 && (!running || v.healthy === true), 'RUNTIME_TARGET_REPLACED');
    need(exact(e, ['name', 'id', 'image', 'created', 'startedAt', 'pid', 'restartCount']) && e.id === expected.id && e.image === expected.image && e.startedAt === expected.startedAt && Number.isFinite(Date.parse(e.created)) && Date.parse(e.startedAt) >= Date.parse(e.created) && e.restartCount === 0 && (!expected.created || e.created === expected.created) && (expected.pid === undefined || e.pid === expected.pid) && Number.isSafeInteger(e.pid) && (running ? e.pid > 0 : e.pid === 0), 'RUNTIME_EPOCH_CHANGED');
    result.push([name, e.id, e.image, e.created, e.startedAt, e.pid, e.restartCount]);
  }
  return result;
}

// Durable metadata precedes acquisition, so even an acquire/fsync failure has an
// identifiable recovery intent. The lock itself stays empty during admission.
// A submitted paid operation adds an immutable owner pointer; UNKNOWN never loses
// that pointer or its append-only metadata. No old lock/marker is adopted here.
export function acquireNativeRuntimeLease(root, acquire, selection, io = fs) {
  const state = join(root, '.local-public-images'), parent = join(state, 'native-runtime-v1');
  const identity = path => {
    const s = io.lstatSync(path);
    need(s.isDirectory() && !s.isSymbolicLink() && s.uid === process.getuid() && (s.mode & 0o7777) === 0o700, 'RUNTIME_METADATA_UNSAFE');
    return [s.dev, s.ino, s.uid, s.mode];
  };
  const sync = path => { const fd = io.openSync(path, io.constants.O_RDONLY | io.constants.O_NOFOLLOW); try { io.fsyncSync(fd); } finally { io.closeSync(fd); } };
  need(resolve(root) === root && io.realpathSync(root) === root);
  const stateId = identity(state);
  try { io.mkdirSync(parent, { mode: 0o700 }); sync(state); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  const parentId = identity(parent), attempt = randomUUID(), audit = join(parent, attempt);
  io.mkdirSync(audit, { mode: 0o700 }); sync(parent); const auditId = identity(audit);
  const files = new Map(); let seq = 0, lock, lockId, owner, ownerComplete = false, submitted = false, closed = false;
  const directories = () => {
    need(equal(identity(state), stateId) && equal(identity(parent), parentId) && equal(identity(audit), auditId), 'RUNTIME_METADATA_CHANGED');
  };
  const write = (path, value) => {
    const bytes = Buffer.from(JSON.stringify(value)), fd = io.openSync(path, io.constants.O_WRONLY | io.constants.O_CREAT | io.constants.O_EXCL | io.constants.O_NOFOLLOW, 0o600);
    const s = io.fstatSync(fd), proof = { id: [s.dev, s.ino], bytes };
    if (path.endsWith('/native-runtime-owner.json')) owner = proof;
    else files.set(path, proof);
    try { io.writeFileSync(fd, bytes); io.fsyncSync(fd); } finally { io.closeSync(fd); }
    sync(dirname(path)); return proof;
  };
  const verifyFile = (path, proof) => {
    const s = io.lstatSync(path);
    need(s.isFile() && !s.isSymbolicLink() && s.nlink === 1 && s.uid === process.getuid() && (s.mode & 0o7777) === 0o600 &&
      equal([s.dev, s.ino], proof.id) && s.size === proof.bytes.length, 'RUNTIME_METADATA_CHANGED');
    const fd = io.openSync(path, io.constants.O_RDONLY | io.constants.O_NOFOLLOW | io.constants.O_NONBLOCK);
    try { need(equal(stamp(s), stamp(io.fstatSync(fd))) && io.readFileSync(fd).equals(proof.bytes) && equal(stamp(s), stamp(io.fstatSync(fd)))); }
    finally { io.closeSync(fd); }
    need(equal(stamp(s), stamp(io.lstatSync(path))));
  };
  const event = (phase, operation = null) => {
    directories();
    write(join(audit, `${String(++seq).padStart(4, '0')}-${phase}.json`), { version: 1, attempt, phase, operation, lockIdentity: lockId ?? null });
  };
  const pointer = () => join(lock.path, 'native-runtime-owner.json');
  const verifyLock = () => {
    lock.verify(); need(equal(identity(lock.path), lockId), 'RUNTIME_LOCK_CHANGED');
    need(equal(io.readdirSync(lock.path), owner ? ['native-runtime-owner.json'] : []), 'RUNTIME_LOCK_CHANGED');
    if (owner) verifyFile(pointer(), owner);
  };
  // Fixed selection metadata only. Never include session, question or key material.
  write(join(audit, 'intent.json'), { version: 1, kind: 'native-runtime-authority', project: NATIVE_PROJECT, attempt,
    deployment: selection.deployment, review: selection.review, origin: NATIVE_ORIGIN,
    pid: process.pid, uid: process.getuid(), createdAt: new Date().toISOString(), lock: '.operation.lock' });
  const releaseEmptyAdmission = () => {
    lock.verify(); need(equal(identity(lock.path), lockId), 'RUNTIME_LOCK_CHANGED');
    need(equal(io.readdirSync(lock.path), owner ? ['native-runtime-owner.json'] : []), 'RUNTIME_LOCK_CHANGED');
    if (owner) {
      // This is ONLY a pre-send failure. Even a partially fsynced pointer may be
      // removed if its exclusive-created inode is still exactly ours; never adopt.
      const s = io.lstatSync(pointer());
      need(s.isFile() && !s.isSymbolicLink() && s.nlink === 1 && equal([s.dev, s.ino], owner.id), 'RUNTIME_LOCK_CHANGED');
      io.unlinkSync(pointer()); sync(lock.path);
    }
    lock.release(); closed = true;
  };
  try {
    lock = acquire(); need(lock.path === join(state, '.operation.lock'), 'RUNTIME_LOCK_CHANGED');
    lockId = identity(lock.path); verifyLock(); event('acquired');
  } catch (error) {
    if (lock && lockId) { try { releaseEmptyAdmission(); } catch { /* Known intent retained for explicit disposition. */ } }
    // Acquisition may have failed after mkdir/fsync but before returning an owned
    // handle. The prior durable intent is the recovery record, NOT permission to
    // remove an unproven lock or to retry. No provider dispatch can have happened.
    throw error;
  }
  return {
    verify() {
      need(!closed); directories(); verifyLock();
      need(equal(io.readdirSync(audit).sort(), [...files.keys()].map(p => p.slice(audit.length + 1)).sort()), 'RUNTIME_METADATA_CHANGED');
      for (const [path, proof] of files) verifyFile(path, proof);
    },
    record(phase, operation = null) {
      need(!closed && ['admitted', 'dispatch-submitted', 'dispatch-observed', 'retained-unknown', 'release'].includes(phase));
      this.verify(); event(phase, operation);
      if (phase === 'dispatch-submitted' && !owner) {
        write(pointer(), { version: 1, kind: 'native-runtime-authority', project: NATIVE_PROJECT, attempt,
          deployment: selection.deployment, review: selection.review, audit: `native-runtime-v1/${attempt}`, lockIdentity: lockId });
        ownerComplete = true;
      }
      if (phase === 'dispatch-submitted') submitted = true;
    },
    release() {
      need(!closed);
      if (!submitted) return releaseEmptyAdmission();
      this.verify(); need(ownerComplete, 'RUNTIME_METADATA_CHANGED');
      // Preserve the whole owned fence and its intent, rather than unlinking
      // liability metadata. Any uncertain rename/fsync is still diagnosable.
      io.renameSync(lock.path, join(audit, 'operation.lock')); sync(audit); sync(state); closed = true;
    },
  };
}

// Injection is a CODE boundary for offline tests, never serialized caller proof.
// The runner uses ONLY openNativeRuntimeAuthority's fixed production sources.
export function createNativeRuntimeAuthority({ records, captureSource, readReview, acquire, observe, now = () => performance.now(), wall = () => Date.now() }) {
  return async ({ deployment, review, origin }) => {
    need(nonce(deployment) && hex(review) && origin === NATIVE_ORIGIN, 'RUNTIME_SELECTION_INVALID');
    const r = records(deployment), source = captureSource(r); r.verify(); source.verify();
    need(await readReview() === review, 'RUNTIME_REVIEW_CHANGED');
    const receipt = receiptIdentities(r, deployment, source, wall());
    const lock = acquire(); // Existing exclusive shared operation lock; no lifecycle.
    const start = now(), used = new Set(); let baseline, observedAt, failed = false, closed = false, busy = false, dispatched = false;
    const fence = () => {
      need(!failed && !closed && Number.isFinite(now()) && now() >= start && now() - start < 600000, 'RUNTIME_AUTHORITY_EXPIRED');
      lock.verify(); r.verify(); source.verify();
    };
    const check = async () => {
      fence(); const began = now();
      const current = runtimeIdentity(await observe(receipt), receipt);
      need(now() >= began && now() - began < 15000, 'RUNTIME_OBSERVATION_STALE');
      need(await readReview() === review, 'RUNTIME_REVIEW_CHANGED');
      fence(); need(now() >= began && now() - began < 15000, 'RUNTIME_OBSERVATION_STALE');
      if (baseline) need(equal(current, baseline), 'RUNTIME_EPOCH_CHANGED'); else baseline = current;
      observedAt = began;
    };
    try { await check(); lock.record('admitted'); }
    catch (error) {
      failed = true;
      // Read-only admission cannot incur a provider liability. Release only our
      // known exclusive empty fence; changed/foreign locks still fail closed.
      try { lock.release(); closed = true; } catch { /* Recoverable acquisition intent remains. */ }
      throw error;
    }
    return Object.freeze({
      qualification: receipt.qualification,
      async dispatch(kind, send) {
        need(!busy && !failed && !closed && ['summary', 'chat'].includes(kind) && !used.has(kind) && typeof send === 'function'); busy = true; used.add(kind);
        try {
          await check(); fence(); need(now() >= observedAt && now() - observedAt < 15000, 'RUNTIME_OBSERVATION_STALE');
          // No awaited caller work between this fence and the original route.fetch.
          lock.record('dispatch-submitted', kind);
          // Durable fsync is synchronous but can still stall. It must not let an
          // expired observation or changed source authorize the actual transport.
          need(await readReview() === review, 'RUNTIME_REVIEW_CHANGED');
          fence(); need(now() >= observedAt && now() - observedAt < 15000, 'RUNTIME_OBSERVATION_STALE');
          dispatched = true;
          const result = await send();
          await check(); lock.record('dispatch-observed', kind); return result;
        } catch (error) { failed = true; throw error; }
        finally { busy = false; }
      },
      async close(success) {
        need(!closed && !busy);
        if (dispatched && (!success || failed)) {
          try { lock.record('retained-unknown'); } catch { /* Pre-send owner pointer and metadata survive. */ }
          closed = true; return { released: false };
        }
        try {
          if (dispatched) { await check(); fence(); lock.record('release'); }
          else { try { lock.record('release'); } catch { /* No paid send; known own admission may still be released. */ } }
          lock.release(); closed = true; return { released: true };
        }
        catch (error) { failed = true; throw error; }
      },
    });
  };
}

// Only identity fields leave the extra Docker inspect; NEVER Config/Env/Health logs.
export const NATIVE_REFERENCE_FORMAT = '{"image":{{json .Id}},"tags":{{json .RepoTags}}}';
export const NATIVE_EPOCH_FORMAT = '{"name":{{json (index .Config.Labels "com.docker.compose.service")}},"id":{{json .Id}},"image":{{json .Image}},"created":{{json .Created}},"startedAt":{{json .State.StartedAt}},"pid":{{json .State.Pid}},"restartCount":{{json .RestartCount}}}';
// Code-only injected observer tests the exact production commands without Docker.
export function createNativeRuntimeObserver(status, run, root, home) {
  const env = { PATH: '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin', HOME: home, COMPOSE_DISABLE_ENV_FILE: '1' };
  return async receipt => {
    const current = await status();
    const options = { root, env, timeout: 10000 };
    const host = JSON.parse(await run(['context', 'inspect', 'desktop-linux', '--format', '{{json .Endpoints.docker.Host}}'], options));
    need(typeof host === 'string' && /^unix:\/\/\/[^\s\0]+$/.test(host));
    const pinned = { ...options, env: { ...env, DOCKER_HOST: host } };
    const daemon = async () => JSON.parse(await run(['info', '--format', '{{json .ID}}'], pinned));
    need(await daemon() === current.daemon, 'RUNTIME_DAEMON_CHANGED');
    const text = await run(['container', 'inspect', ...ROLES.map(n => `${NATIVE_PROJECT}-${n}-1`), '--format', NATIVE_EPOCH_FORMAT], pinned);
    need(Array.isArray(receipt?.references) && receipt.references.length > 0 && receipt.references.length <= TARGETS.length * 2, 'RUNTIME_REFERENCES_MISMATCH');
    const images = await run(['image', 'inspect', ...receipt.references.map(r => r.tag), '--format', NATIVE_REFERENCE_FORMAT], pinned);
    need(await daemon() === current.daemon, 'RUNTIME_DAEMON_CHANGED');
    const epochs = text.trim().split('\n').map(line => JSON.parse(line)), referenceImages = images.trim().split('\n').map(line => JSON.parse(line));
    return { status: current, epochs, referenceImages };
  };
}
export async function openNativeRuntimeAuthority(selection, readReview) {
  const [{ createDeployAdapter }, { capturePublicLlmSource }, { acquireLock, runIsolatedDocker }] = await Promise.all([
    import('./deploy-adapter.mjs'), import('./public-llm-stand.mjs'), import('./public-image-stand.mjs'),
  ]);
  const { homedir } = await import('node:os');
  const adapter = createDeployAdapter({ root: ROOT });
  const acquire = () => acquireNativeRuntimeLease(ROOT, () => acquireLock(ROOT), selection);
  const captureSource = records => {
    const source = capturePublicLlmSource(ROOT, { openai: true }), proofs = [];
    const read = path => {
      const s = fs.lstatSync(path); need(s.isFile() && !s.isSymbolicLink() && s.nlink === 1 && s.uid === process.getuid() && !(s.mode & 0o022) && s.size <= 1024 ** 2);
      const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
      let bytes; try { need(equal(stamp(s), stamp(fs.fstatSync(fd)))); bytes = fs.readFileSync(fd); need(equal(stamp(s), stamp(fs.fstatSync(fd)))); } finally { fs.closeSync(fd); }
      need(equal(stamp(s), stamp(fs.lstatSync(path))));
      proofs.push(() => {
        need(equal(stamp(s), stamp(fs.lstatSync(path))));
        const f = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
        try { need(equal(stamp(s), stamp(fs.fstatSync(f))) && fs.readFileSync(f).equals(bytes) && equal(stamp(s), stamp(fs.fstatSync(f)))); }
        finally { fs.closeSync(f); }
        need(equal(stamp(s), stamp(fs.lstatSync(path))));
      }); return hash(bytes);
    };
    return { build: hash(JSON.stringify(source.manifest.files.map(f => ({ path: f.path, digest: f.digest })))),
      adapter: read(join(ROOT, 'scripts/deploy-adapter.mjs')), entries: [...ENTRIES, ...(records.complete.version === 3 ? ['deploy-reference-custody.mjs'] : [])].map(n => read(join(ROOT, 'scripts', n))), verify() { source.verify(); proofs.forEach(p => p()); } };
  };
  const observe = createNativeRuntimeObserver(() => adapter.status(), runIsolatedDocker, ROOT, homedir());
  return createNativeRuntimeAuthority({ records: n => captureNativeDeploymentRecords(ROOT, n), captureSource, readReview, acquire, observe })(selection);
}
