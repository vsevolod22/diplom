#!/usr/bin/env node
// Public-only trust/lifecycle. A v1 binding is migrated only by the explicit
// coordinated provision command; ordinary refresh never adopts LOCAL state.
import * as fs from 'node:fs';
import {
  createHash,
  randomBytes,
  createPrivateKey,
  createPublicKey,
  timingSafeEqual,
  verify as verifySignature,
} from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  childEnvironment,
  runChild,
  cveTimeout,
  directory,
  readBounded,
  writeExclusive,
  syncDirectory,
} from './setup-local-cve.mjs';
import {
  prepareFrozenCandidate,
  verifierArguments,
  verifiedOutput,
  cveCheckpoint,
  cveRefreshDiagnostic,
  READY_PROBE,
} from './refresh-local-cve.mjs';
import { createPublicCveBridge } from './public-cve-bridge.mjs';
import { loadCveRuntime } from './public-cve-bridge-runtime.mjs';
import { publicImageCveConfig, validatePublicImageCveRelease } from './public-image-stand-profile.mjs';
import {
  PROJECT,
  STATE,
  CONFIG_SECRET,
  cveOverlay,
  checkIgnores,
  runIsolatedDocker,
} from './public-image-stand.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const HEX = /^[a-f0-9]{64}(?![\s\S])/;
const DIGEST = /^sha256:[a-f0-9]{64}(?![\s\S])/;
const ID = /^[a-z0-9][a-z0-9_-]{0,127}(?![\s\S])/;
const json = JSON.stringify;
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const equal = (a, b) => json(a) === json(b);
const role = (c) => c.Config.Labels['com.docker.compose.service'];
const active = (c) =>
  c.State.Running === true &&
  c.State.Status === 'running' &&
  !c.State.Paused &&
  !c.State.Restarting &&
  !c.State.Dead &&
  !c.State.OOMKilled;
const stopped = (c) =>
  c.State.Running === false &&
  c.State.Status === 'exited' &&
  c.State.ExitCode === 0 &&
  !c.State.Paused &&
  !c.State.Restarting &&
  !c.State.Dead &&
  !c.State.OOMKilled;
const known = [
  'preflight',
  'discovery',
  'verify-current',
  'staging',
  'download',
  'prepare',
  'sign',
  'verify',
  'namespace',
  'fence',
  'drain',
  'preservation',
  'activate',
  'readiness',
  'cleanup',
];
const failures = new WeakMap();
function failure(phase = 'preflight', hold = false, checkpoint = 'validation', diagnostic = null) {
  if (!known.includes(phase)) phase = 'preflight';
  checkpoint = cveCheckpoint(phase, checkpoint);
  const detail = diagnostic ? ` cause=${diagnostic.cause}${diagnostic.transport ? ` transport=${diagnostic.transport.boundary}/${diagnostic.transport.cause}${diagnostic.transport.status ? ` status=${diagnostic.transport.status}` : ''}` : ''};` : '';
  const details = Object.freeze({
    phase, hold, checkpoint, ...(diagnostic ? { diagnostic } : {}),
    message: `PUBLIC CVE refresh refused${hold ? '/HOLD' : ''}; phase=${phase}; checkpoint=${checkpoint}.${detail} No automatic recovery.`,
  });
  const error = new Error(details.message);
  failures.set(error, details);
  return error;
}
export function publicCveFailure(error) {
  return failures.get(error) ?? failures.get(failure());
}
function safe(ok) {
  if (!ok) throw failure();
}
export const present = (path) => fs.lstatSync(path, { throwIfNoEntry: false }) !== undefined;

export function publicPaths(root) {
  safe(resolve(root) === root && fs.realpathSync(root) === root);
  checkIgnores(root);
  const stand = join(root, STATE);
  directory(stand, 0o700);
  return {
    stand,
    releases: join(stand, 'db-releases'),
    trust: join(stand, 'trust'),
    profile: join(stand, 'profile.json'),
    overlay: join(stand, 'compose.cve.json'),
    pins: join(stand, 'compose.images.json'),
  };
}
export function publicCveConfig(root, value) {
  safe(
    value &&
      equal(Object.keys(value).sort(), [
        'artifactSha256',
        'manifestDigest',
        'publicKeySha256',
        'release',
        'version',
      ]) &&
      value.version === 1 &&
      typeof value.release === 'string' &&
      value.release.startsWith('db-releases/') &&
      ID.test(value.release.slice(12)) &&
      DIGEST.test(value.manifestDigest) &&
      HEX.test(value.artifactSha256) &&
      HEX.test(value.publicKeySha256),
  );
  return publicImageCveConfig(root, value, 2);
}
function publicKey(paths, expected) {
  safe(HEX.test(expected));
  directory(paths.trust, 0o700);
  const bytes = readBounded(join(paths.trust, `${expected}.pub.pem`), 8192, 0o444);
  const key = createPublicKey(bytes);
  safe(key.asymmetricKeyType === 'ed25519' && sha(key.export({ type: 'spki', format: 'der' })) === expected);
  return key;
}
function readSignature(path) {
  const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const s = fs.fstatSync(fd),
      bytes = Buffer.alloc(65);
    safe(
      s.isFile() &&
        s.size === 64 &&
        s.nlink === 1 &&
        s.uid === process.getuid() &&
        (s.mode & 0o777) === 0o444,
    );
    safe(fs.readSync(fd, bytes, 0, bytes.length, 0) === 64);
    const after = fs.fstatSync(fd);
    safe(s.mtimeMs === after.mtimeMs && s.ctimeMs === after.ctimeMs && after.size === 64);
    return bytes.subarray(0, 64);
  } finally {
    fs.closeSync(fd);
  }
}
export function validatePublicRelease(root, value) {
  publicPaths(root);
  return validatePublicImageCveRelease(root, value);
}
export function loadPublicBinding(root) {
  const paths = publicPaths(root),
    bytes = readBounded(paths.profile, 4096, 0o600),
    value = JSON.parse(bytes);
  // v1 means a legacy external pinned release. Never open its paths or migrate it.
  safe(
    value?.version === 2 &&
      value.project === PROJECT &&
      equal(Object.keys(value), ['version', 'project', 'cve']),
  );
  const cve = validatePublicRelease(root, value.cve);
  safe(
    bytes === json({ version: 2, project: PROJECT, cve: value.cve }) &&
      readBounded(paths.overlay, 16384, 0o600) === json(cveOverlay(cve)),
  );
  return { paths, current: value.cve, cve };
}
export function existingPublicKeys(paths, expected) {
  const pub = publicKey(paths, expected);
  const privatePath = join(paths.trust, 'refresh-signing-key.pem');
  const key = createPrivateKey(readBounded(privatePath, 8192, 0o600));
  safe(
    key.asymmetricKeyType === 'ed25519' &&
      timingSafeEqual(
        createPublicKey(key).export({ type: 'spki', format: 'der' }),
        pub.export({ type: 'spki', format: 'der' }),
      ),
  );
  return { privatePath, publicPath: join(paths.trust, `${expected}.pub.pem`), publicKeySha256: expected };
}

// Identity+bytes fences are private in-memory objects, never serialized. In
// particular JWT bytes AND its digest must never enter a receipt or diagnostics.
export function fileFence(path, cap, mode = 0o600) {
  const stamp = () => {
    const s = fs.lstatSync(path);
    return [s.dev, s.ino, s.mode, s.uid, s.nlink, s.size, s.mtimeMs, s.ctimeMs];
  };
  const before = stamp(),
    bytes = readBounded(path, cap, mode);
  safe(equal(before, stamp()));
  return {
    bytes,
    verify() {
      safe(equal(before, stamp()) && readBounded(path, cap, mode) === bytes);
    },
  };
}
function directoryFence(path, mode) {
  directory(path, mode);
  const original = fs.lstatSync(path);
  return {
    verify() {
      directory(path, mode);
      const current = fs.lstatSync(path);
      safe(current.dev === original.dev && current.ino === original.ino);
    },
  };
}
function releaseFences(cve) {
  return [
    ['descriptor.json', 4096],
    ['descriptor.sig', 64],
    ['db/metadata.json', 4096],
  ].map(([name, cap]) => fileFence(join(cve.releaseHostDir, name), cap, 0o444));
}
function one(resources, name) {
  const rows = resources.containers.filter((c) => role(c) === name);
  safe(rows.length === 1);
  return rows[0];
}
function ordered(value) {
  return Array.isArray(value)
    ? value.map(ordered)
    : value && typeof value === 'object'
      ? Object.fromEntries(
          Object.keys(value)
            .sort()
            .map((key) => [key, ordered(value[key])]),
        )
      : value;
}
function sameContainer(a, b) {
  // Engine materialized mounts are unordered; declarations/argv/env arrays are
  // not. Keep every observed field while avoiding order-only false HOLD.
  const mounts = (c) => [...c.Mounts].sort((x, y) => x.Destination.localeCompare(y.Destination));
  safe(
    a.Id === b.Id &&
      a.Image === b.Image &&
      equal(ordered(a.Config), ordered(b.Config)) &&
      equal(ordered(a.HostConfig), ordered(b.HostConfig)) &&
      equal(ordered(mounts(a)), ordered(mounts(b))),
  );
}
function sameEpoch(a, b) {
  sameContainer(a, b);
  safe(
    a.State.StartedAt === b.State.StartedAt &&
      a.State.Pid === b.State.Pid &&
      a.RestartCount === b.RestartCount,
  );
}

// Public ledger schema 15, not the LOCAL v14 predicate. Pending outbox, delayed
// retries, cancelled-but-leased attempts all block. No ScanLedger constructor,
// RW open, schema migration, cancellation or lease expiry manipulation.
export const PUBLIC_DRAIN_PROBE = `const DB=require('better-sqlite3');
const db=new DB('/data/ledger.sqlite',{readonly:true,fileMustExist:true,timeout:2000});
try {db.pragma('query_only = ON');db.exec('BEGIN');
if(db.pragma('user_version',{simple:true})!==15)throw Error('schema');
const r=db.prepare("SELECT (SELECT count(*) FROM scans WHERE state IN ('queued','running')) AS jobs,(SELECT count(*) FROM outbox WHERE delivered_at IS NULL) AS outbox,(SELECT count(*) FROM outbox WHERE lease_until IS NOT NULL OR lease_token IS NOT NULL) AS leases").get();
if(!Object.values(r).every(n=>Number.isSafeInteger(n)&&n>=0))throw Error('count');
db.exec('ROLLBACK');console.log(JSON.stringify(r));}finally{db.close();}`;
// Public worker intentionally does not emit nginx-local.ready. chainReady checks
// its real durable heartbeat/gateway/no-bypass predicates. Runtime envelope and
// candidate mount declaration/materialization are checked BEFORE this exec.
export const PUBLIC_READY_PROBE = READY_PROBE.replace(
  "import {localWorkerReady} from './src/oci/nginx-local-profile.ts';\n",
  '',
).replace('||!await localWorkerReady()', '');
export const PUBLIC_WEB_PROBE = `const r=await fetch('http://127.0.0.1:8081/api/v1/auth/me',{redirect:'error',signal:AbortSignal.timeout(5000)});await r.body?.cancel();if(r.status!==401)throw Error('routing');console.log('{"webReady":true}');`;

// Manual CLI and launchd share the concrete public launcher bridge by default.
// The injectable interface is a test seam, not an external approval/capability
// gate or permission to substitute a weaker history/snapshot implementation.
export function requirePublicIntegration(integration) {
  safe(
    integration?.version === 1 &&
      typeof integration.assertCompatible === 'function' &&
      typeof integration.acquireLock === 'function' &&
      typeof integration.capturePreservation === 'function' &&
      typeof integration.preflightPreservation === 'function',
  );
}
const dispositionSources = ['scripts/refresh-public-cve.mjs', 'scripts/refresh-local-cve.mjs', 'scripts/setup-local-cve.mjs', 'server/deploy/trust/fetch-db-layer.mjs'];
const dispositionIdentity = s => ({ dev: String(s.dev), ino: String(s.ino), uid: s.uid, mode: s.mode, nlink: s.nlink, size: s.size, mtime: s.mtimeMs, ctime: s.ctimeMs });
function emptyStagingProof(root, paths, lock) {
  const work = join(paths.stand, '.cve-refresh-work'), parent = directoryFence(paths.stand, 0o700);
  directory(work, 0o700); const identity = dispositionIdentity(fs.lstatSync(work));
  const sources = dispositionSources.map(name => {
    const path = join(root, name);
    safe(fs.realpathSync(dirname(path)) === dirname(path));
    const before = fs.lstatSync(path); safe(!(before.mode & 0o022));
    const bytes = readBounded(path, 256 * 1024), after = fs.lstatSync(path);
    safe(equal(dispositionIdentity(before), dispositionIdentity(after)));
    return { name, path, identity: dispositionIdentity(after), sha256: sha(bytes) };
  });
  const verify = () => {
    parent.verify(); lock.verify(); directory(work, 0o700);
    safe(equal(dispositionIdentity(fs.lstatSync(work)), identity) && (fs.lstatSync(work).mode & 0o7777) === 0o700 && fs.readdirSync(work).length === 0);
    safe(!fs.readdirSync(paths.stand).some(n => n.startsWith('.llm-pending-') || n.endsWith('.lock') && n !== '.operation.lock'));
    for (const p of ['.profile.pending', '.compose.cve.pending', '.compose.images.pending']) safe(!present(join(paths.stand, p)));
    for (const s of sources) {
      safe(fs.realpathSync(dirname(s.path)) === dirname(s.path) && equal(dispositionIdentity(fs.lstatSync(s.path)), s.identity) && sha(readBounded(s.path, 256 * 1024)) === s.sha256);
    }
  };
  verify();
  const evidence = { version: 1, kind: 'empty-public-cve-staging-only', workspace: identity,
    sources: sources.map(({ name, identity, sha256 }) => ({ name, identity, sha256 })),
    priorFailureCause: 'UNKNOWN', priorAttemptCertified: false, refreshAuthorized: false };
  return { work, identity, verify, evidence, review: sha(json(evidence)) };
}

// Separate explicit operation: no activation, key/JWT/DB access, network or retry.
// A private exclusive archive parent makes rename's target unoccupied; uncertainty
// leaves this operation's intent/lock sticky, never steals or deletes another lock.
export async function disposeEmptyPublicCveStaging(argv, { root = ROOT, integration = createPublicCveBridge(), onLocked = () => {}, onBeforeMove = () => {} } = {}) {
  let lock, hold = false;
  try {
    const checking = equal(argv, ['--check-empty-staging']);
    safe(checking || argv.length === 3 && argv[0] === '--archive-empty-staging' && argv[1] === '--review' && HEX.test(argv[2]));
    const paths = publicPaths(root), state = directoryFence(paths.stand, 0o700);
    requirePublicIntegration(integration); lock = await integration.acquireLock(root);
    safe(lock?.path === join(paths.stand, '.operation.lock') && typeof lock.verify === 'function' && typeof lock.release === 'function');
    state.verify(); lock.verify(); await onLocked(); safe(fs.readdirSync(lock.path).length === 0);
    const proof = emptyStagingProof(root, paths, lock);
    if (checking) return { version: 1, outcome: 'empty-staging-review-only', review: proof.review, empty: true, archived: false, refreshAuthorized: false };
    safe(argv[2] === proof.review); proof.verify();
    const catalog = join(paths.stand, '.cve-refresh-archives');
    if (present(catalog)) {
      directory(catalog, 0o700); const entries = fs.readdirSync(catalog);
      safe(entries.length < 16 && entries.every(n => /^empty-[a-f0-9]{32}$/.test(n)));
      for (const n of entries) directory(join(catalog, n), 0o700);
    }
    hold = true;
    const intent = join(lock.path, 'empty-staging-intent.json');
    writeExclusive(intent, json({ ...proof.evidence, review: proof.review }), 0o600); syncDirectory(lock.path);
    const intentFence = fileFence(intent, 16384);
    if (!present(catalog)) { fs.mkdirSync(catalog, { mode: 0o700 }); syncDirectory(paths.stand); }
    const catalogFence = directoryFence(catalog, 0o700), archive = join(catalog, 'empty-' + randomBytes(16).toString('hex'));
    fs.mkdirSync(archive, { mode: 0o700 }); syncDirectory(catalog);
    const archiveFence = directoryFence(archive, 0o700), target = join(archive, 'work');
    await onBeforeMove(); proof.verify(); intentFence.verify(); state.verify(); catalogFence.verify(); archiveFence.verify(); safe(!present(target));
    fs.renameSync(proof.work, target); syncDirectory(paths.stand); syncDirectory(archive);
    directory(target, 0o700); const moved = dispositionIdentity(fs.lstatSync(target));
    safe(moved.dev === proof.identity.dev && moved.ino === proof.identity.ino && fs.readdirSync(target).length === 0 && !present(proof.work));
    state.verify(); lock.verify(); catalogFence.verify(); archiveFence.verify();
    writeExclusive(join(archive, 'complete.json'), json({ version: 1, outcome: 'empty-staging-archived-only', review: proof.review,
      originalIdentity: proof.identity, archivedIdentity: moved, priorFailureCause: 'UNKNOWN', priorAttemptCertified: false, refreshSubmitted: false }), 0o600);
    syncDirectory(archive);
    // Preserve the intent too; do not unlink failure evidence merely to release.
    safe(equal(fs.readdirSync(lock.path), ['empty-staging-intent.json'])); intentFence.verify();
    safe(!present(join(archive, 'intent.json')));
    fs.renameSync(intent, join(archive, 'intent.json')); syncDirectory(archive); syncDirectory(lock.path);
    hold = false;
    return { version: 1, outcome: 'empty-staging-archived-only', review: proof.review, archived: true, priorFailureCause: 'UNKNOWN', refreshSubmitted: false };
  } catch (error) { throw failure('staging', hold, 'workspace', cveRefreshDiagnostic(error)); }
  finally {
    if (lock && !hold) {
      try { lock.verify(); lock.release(); } catch { throw failure('cleanup', true); }
    }
  }
}

export async function refreshPublicCve(
  argv = [],
  {
    root = ROOT,
    integration = createPublicCveBridge(),
    run = runChild,
    docker = runIsolatedDocker,
    log = console.log,
    onLocked = () => {},
    now = () => performance.now(),
    sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
    drainMs = 120_000,
    diskCheck,
    platform = process.platform,
  } = {},
) {
  if (argv[0] === '--check-empty-staging' || argv[0] === '--archive-empty-staging') {
    const result = await disposeEmptyPublicCveStaging(argv, { root, integration, onLocked });
    log(JSON.stringify(result)); return result;
  }
  let phase = 'preflight', checkpoint = 'validation',
    hold = false,
    lock,
    temporaryOverlay;
  const records = new Map();
  const mark = (p, nextCheckpoint = 'validation') => {
    safe(known.includes(p)); phase = p; checkpoint = cveCheckpoint(p, nextCheckpoint);
  };
  const deadline = now() + 900_000;
  const remaining = (cap) => cveTimeout(cap, deadline, now());
  try {
    const migrating = argv.length === 2 && argv[0] === '--migrate-v1' && /^[a-f0-9]{32}$/.test(argv[1]);
    safe(equal(argv, []) || equal(argv, ['--stage-only']) || migrating);
    requirePublicIntegration(integration);
    await integration.assertCompatible(root); // source compatibility/history, no LOCAL access
    const paths = publicPaths(root);
    lock = await integration.acquireLock(root);
    safe(
      lock?.path === join(paths.stand, '.operation.lock') &&
        typeof lock.verify === 'function' &&
        typeof lock.release === 'function',
    );
    const stateDirectory = directoryFence(paths.stand, 0o700);
    const acquired = lock;
    lock = {
      path: acquired.path,
      verify() {
        stateDirectory.verify();
        acquired.verify();
      },
      release() {
        stateDirectory.verify();
        acquired.release();
      },
    };
    lock.verify();
    await onLocked();
    safe(fs.readdirSync(lock.path).length === 0);
    for (const name of [
      '.cve-refresh-work',
      '.profile.pending',
      '.compose.cve.pending',
      '.compose.images.pending',
    ])
      safe(!present(join(paths.stand, name)));
    const migration = migrating
      ? (await import('./public-cve-provision.mjs')).loadMigrationPlan(root, argv[1])
      : null;
    const { current, cve } = migration ?? loadPublicBinding(root);
    const runtime = await loadCveRuntime(root);
    const profile = fileFence(paths.profile, 4096),
      overlay = fileFence(paths.overlay, 16384);
    const pinsFile = fileFence(paths.pins, 16384),
      jwt = fileFence(join(paths.stand, 'scan-jwt'), 96);
    safe(/^[a-f0-9]{96}(?![\s\S])/.test(jwt.bytes));
    const trust = fileFence(cve.publicKeyPath, 8192, 0o444),
      oldFiles = [
        directoryFence(paths.trust, 0o700),
        directoryFence(paths.releases, 0o700),
        directoryFence(cve.releaseHostDir, 0o555),
        directoryFence(join(cve.releaseHostDir, 'db'), 0o555),
        ...releaseFences(cve),
      ];
    const cas = () => {
      lock.verify();
      runtime.verify();
      migration?.verify();
      [profile, overlay, pinsFile, jwt, trust, ...oldFiles, ...records.values()].forEach((f) => f.verify());
    };
    const oldDescriptor = JSON.parse(readBounded(join(cve.releaseHostDir, 'descriptor.json'), 4096, 0o444));
    safe(
      HEX.test(oldDescriptor.dbSha256) &&
        oldDescriptor.manifestDigest === current.manifestDigest &&
        oldDescriptor.artifactSha256 === current.artifactSha256 &&
        oldDescriptor.signer === 'local-db-operator-v1' &&
        oldDescriptor.source === `ghcr.io/aquasecurity/trivy-db@${current.manifestDigest}` &&
        oldDescriptor.schemaVersion === 2 &&
        verifySignature(
          null,
          Buffer.from(readBounded(join(cve.releaseHostDir, 'descriptor.json'), 4096, 0o444)),
          publicKey(paths, current.publicKeySha256),
          readSignature(join(cve.releaseHostDir, 'descriptor.sig')),
        ),
    );
    const child = (exe, args, cap) => {
      cas();
      return run(exe, args, { cwd: root, env: childEnvironment(), timeout: remaining(cap) });
    };
    const keys = { publicPath: cve.publicKeyPath, publicKeySha256: current.publicKeySha256 };
    const verify = async (release, pins, anchor = keys) =>
      verifiedOutput(
        await child(process.execPath, verifierArguments(root, release, anchor, pins), 120_000),
        pins,
      );
    let candidate, next, pins, release, manifest, candidateAnchor;
    if (migration) {
      ({ candidate, next, pins, release } = migration);
      manifest = candidate.manifestDigest;
      candidateAnchor = { publicPath: next.publicKeyPath, publicKeySha256: candidate.publicKeySha256 };
      mark('verify');
      await verify(release, pins, candidateAnchor);
    } else {
      mark('discovery', 'fetch');
      const discovered = await child(process.execPath, [join(root, 'server/deploy/trust/fetch-db-layer.mjs'), 'discover'], 60_000);
      mark('discovery', 'receipt');
      const found = /^Review upstream tag :2, then download by digest: (sha256:[a-f0-9]{64})\r?\n$/.exec(discovered);
      safe(found);
      manifest = found[1];
      if (manifest === current.manifestDigest) {
        mark('verify-current');
        await verify(cve.releaseHostDir, { ...current, dbSha256: oldDescriptor.dbSha256 });
        cas();
        log('PUBLIC CVE unchanged; signature/hashes/freshness verified; no Docker or signing.');
        return { outcome: 'unchanged', manifest };
      }
      const signerFile = fileFence(join(paths.trust, 'refresh-signer.json'), 4096);
      const signer = JSON.parse(signerFile.bytes);
      safe(
        equal(Object.keys(signer), ['version', 'publicKeySha256']) &&
          signer.version === 1 &&
          HEX.test(signer.publicKeySha256),
      );
      publicKey(paths, signer.publicKeySha256);
      oldFiles.push(
        signerFile,
        fileFence(join(paths.trust, `${signer.publicKeySha256}.pub.pem`), 8192, 0o444),
      );
      candidateAnchor = {
        publicPath: join(paths.trust, `${signer.publicKeySha256}.pub.pem`),
        publicKeySha256: signer.publicKeySha256,
      };
      ({ candidate, next, pins, release } = await prepareFrozenCandidate({
        root,
        paths,
        current: { ...current, publicKeySha256: signer.publicKeySha256 },
        oldDescriptor,
        manifest,
        child,
        verify: (r, p) => verify(r, p, candidateAnchor),
        mark,
        diskCheck,
        getKeys: () => existingPublicKeys(paths, signer.publicKeySha256),
        validateCandidate: (value) => validatePublicRelease(root, value),
      }));
    }
    cas();
    if (argv[0] === '--stage-only') return { outcome: 'staged', manifest };

    mark('namespace');
    // Never inherit Docker selectors, proxy/provider/scanner/hook env. Resolve
    // the default client context ONCE, then pin the literal local Unix socket.
    const base = { ...childEnvironment(), COMPOSE_DISABLE_ENV_FILE: '1' };
    const endpoint = JSON.parse(
      await docker(['context', 'inspect', '--format', '{{json .Endpoints.docker.Host}}'], {
        root,
        env: base,
        timeout: remaining(15_000),
      }),
    );
    safe(typeof endpoint === 'string' && /^unix:\/\/\/[^\s\0]+(?![\s\S])/.test(endpoint));
    const env = Object.freeze({ ...base, DOCKER_HOST: endpoint });
    const d = async (args, extra = {}) => {
      lock.verify();
      runtime.verify();
      const result = await docker(args, { root, env, ...extra, timeout: remaining(extra.timeout ?? 30_000) });
      runtime.verify();
      return result;
    };
    const config = runtime.model(cve),
      nextConfig = runtime.model(next);
    const inventory = (model) =>
      runtime.inspect(d, { root, env }, model === nextConfig ? next : cve, { platform, secret: jwt.bytes });
    const before = await inventory(config);
    const apps = runtime.roles.filter((name) => !name.endsWith('volume-init'));
    if (apps.some((name) => !before.containers.some((c) => role(c) === name && active(c)))) {
      cas();
      return { outcome: 'deferred-stopped', manifest };
    }
    runtime.counts(before);
    runtime.membership(before);
    const images = {};
    const pinRecord = JSON.parse(pinsFile.bytes);
    safe(
      equal(Object.keys(pinRecord), ['services']) &&
        equal(Object.keys(pinRecord.services).sort(), Object.keys(config.services).sort()),
    );
    for (const c of before.containers) {
      const name = role(c),
        id = pinRecord.services[name]?.image;
      safe(
        equal(pinRecord.services[name], { image: id }) &&
          DIGEST.test(id) &&
          c.Image === id &&
          c.Config.Image === id,
      );
      const rows = JSON.parse(await d(['image', 'inspect', id]));
      safe(rows.length === 1 && rows[0].Id === id);
      runtime.validateImage(rows[0], name);
      images[name] = rows[0];
      runtime.validateContainer(c, name, config.services[name], images[name], config, {
        platform,
        secret: jwt.bytes,
        images,
      });
      if (!apps.includes(name)) safe(stopped(c));
    }
    const api = one(before, 'api'),
      worker = one(before, 'worker'),
      web = one(before, 'web');
    safe(api.State.Health?.Status === 'healthy');
    let apiStopped = false,
      workerStopped = false;
    const writers = async () => {
      for (const volume of ['auth_accounts', 'scan_ledger']) {
        const expected = [
          ...(!apiStopped ? [api.Id] : []),
          ...(volume === 'scan_ledger' && !workerStopped ? [worker.Id] : []),
        ].sort();
        const ids = (
          await d([
            'container',
            'ls',
            '--filter',
            `volume=${PROJECT}_${volume}`,
            '--format',
            '{{.ID}}',
            '--no-trunc',
          ])
        )
          .trim()
          .split('\n')
          .filter(Boolean)
          .sort();
        safe(equal(ids, expected));
      }
    };
    const inspectOne = async (target, name, model) => {
      const rows = JSON.parse(await d(['container', 'inspect', target]));
      safe(rows.length === 1);
      const c = rows[0];
      runtime.validateContainer(c, name, model.services[name], images[name], model, {
        platform,
        secret: jwt.bytes,
        images,
      });
      return c;
    };
    // Exact public-only prospective overlay. Never change the launcher's pins,
    // web/egress/initializer settings, source profile or image tags.
    const nextOverlay = join(lock.path, 'candidate.cve.json');
    writeExclusive(nextOverlay, json(cveOverlay(next)), 0o600);
    temporaryOverlay = fileFence(nextOverlay, 16384);
    records.set('candidate.cve.json', temporaryOverlay);
    const compose = (args, prospective = false) => runtime.compose(args, { prospective });
    for (const [prospective, model, binding] of [
      [false, config, cve],
      [true, nextConfig, next],
    ]) {
      const rendered = JSON.parse(
        await d(compose(['config', '--format', 'json'], prospective), {
          env: { ...env, SCAN_JWT_SECRET: CONFIG_SECRET },
        }),
      );
      runtime.validateConfig(rendered, binding, images);
      safe(Object.keys(model.services).length === runtime.roles.length);
    }
    const record = (name, value) => {
      lock.verify();
      writeExclusive(join(lock.path, name), json(value), 0o600);
      syncDirectory(lock.path);
      records.set(name, fileFence(join(lock.path, name), 16384));
    };
    const resumeWeb = async (model, verify) => {
      verify();
      record('resume-web.json', { version: 1, project: PROJECT, phase: 'resume-original-web', endpoint });
      await d(['container', 'start', web.Id]);
      const limit = now() + 60000;
      let resumed;
      do {
        verify();
        const c = await inspectOne(web.Id, 'web', model);
        sameContainer(web, c);
        safe(active(c));
        resumed = c;
        if (!c.State.Health || c.State.Health.Status === 'healthy') break;
        safe(now() < limit);
        await sleep(1000);
      } while (true);
      const probe = runtime.selection ? runtime.webProbe : PUBLIC_WEB_PROBE;
      const report = JSON.parse(
        await run(process.execPath, ['--input-type=module', '-e', probe], {
          cwd: root,
          env: childEnvironment(),
          timeout: remaining(15000),
        }),
      );
      safe(report.webReady === true);
      verify();
      return resumed;
    };
    await writers();
    cas();
    const fencedBaseline = await inventory(config);
    runtime.storage(before, fencedBaseline);
    runtime.membership(fencedBaseline);
    for (const prior of before.containers) sameEpoch(prior, one(fencedBaseline, role(prior)));
    cas();
    const reservation = await integration.preflightPreservation({ root, lock, runtime });
    reservation.verify();
    cas();
    mark('fence');
    hold = true; // Set before the first durable intent can fail.
    record('mutation.json', {
      version: 1,
      project: PROJECT,
      command: 'refresh-cve',
      phase: 'fence-web-outcome-unconfirmed',
      endpoint,
    });
    record('refresh.json', {
      version: 1,
      project: PROJECT,
      prior: current,
      candidate,
      containers: before.containers.map((c) => ({ id: c.Id, role: role(c), image: c.Image })),
    });
    const submit = async (name, args, extra) => {
      cas();
      record(`${name}.json`, { version: 1, project: PROJECT, phase: name, endpoint });
      return d(args, extra);
    };
    await submit('stop-web', ['container', 'stop', '--signal', 'SIGTERM', '--time', '30', web.Id], {
      timeout: 45000,
    });
    const stoppedWeb = await inspectOne(web.Id, 'web', config);
    sameContainer(web, stoppedWeb);
    safe(stopped(stoppedWeb));
    await submit('stop-api', ['container', 'stop', '--time', '60', api.Id], { timeout: 75_000 });
    let a = await inspectOne(api.Id, 'api', config);
    sameContainer(api, a);
    safe(stopped(a));
    apiStopped = true;
    mark('drain');
    const until = now() + Math.min(drainMs, 120_000);
    let drained = false;
    safe(Number.isFinite(drainMs) && drainMs >= 0);
    do {
      cas();
      await writers();
      a = await inspectOne(api.Id, 'api', config);
      const w = await inspectOne(worker.Id, 'worker', config);
      sameContainer(api, a);
      sameEpoch(worker, w);
      safe(stopped(a) && active(w));
      const counts = JSON.parse(await d(['container', 'exec', worker.Id, 'node', '-e', PUBLIC_DRAIN_PROBE]));
      safe(
        equal(Object.keys(counts).sort(), ['jobs', 'leases', 'outbox']) &&
          Object.values(counts).every((n) => Number.isSafeInteger(n) && n >= 0),
      );
      if (Object.values(counts).every((n) => n === 0)) {
        drained = true;
        break;
      }
      if (now() >= until) break;
      await sleep(Math.min(1000, Math.max(1, until - now())));
    } while (now() <= until);
    const cleanup = () => {
      lock.verify();
      safe(equal(fs.readdirSync(lock.path).sort(), [...records.keys()].sort()));
      for (const fence of records.values()) fence.verify();
      for (const name of records.keys()) fs.unlinkSync(join(lock.path, name));
      records.clear();
      temporaryOverlay = undefined;
      syncDirectory(lock.path);
      hold = false;
    };
    if (!drained) {
      cas();
      await writers();
      await submit('resume-api', ['container', 'start', api.Id]);
      const limit = now() + 60_000;
      do {
        a = await inspectOne(api.Id, 'api', config);
        sameContainer(api, a);
        safe(active(a));
        if (a.State.Health?.Status === 'healthy') break;
        safe(now() < limit);
        await sleep(1000);
      } while (true);
      await resumeWeb(config, cas);
      const after = await inventory(config);
      runtime.storage(before, after);
      runtime.membership(after);
      for (const prior of before.containers) {
        const observed = one(after, role(prior));
        if (['api', 'web'].includes(role(prior))) sameContainer(prior, observed);
        else sameEpoch(prior, observed);
      }
      cas();
      cleanup();
      return { outcome: 'deferred-busy', manifest };
    }
    mark('fence');
    await submit('stop-worker', ['container', 'stop', '--time', '30', worker.Id], { timeout: 45_000 });
    const w = await inspectOne(worker.Id, 'worker', config);
    sameContainer(worker, w);
    safe(stopped(w));
    workerStopped = true;
    a = await inspectOne(api.Id, 'api', config);
    sameContainer(api, a);
    safe(stopped(a));
    await writers();
    cas();
    mark('preservation');
    // Bridge runs a separately reviewed public-only RO snapshot helper while
    // both writers are stopped. Its opaque comparison closure retains data in
    // private memory/storage, never in our journal or status. No backup/migration
    // privileges are inferred from a container being stopped.
    let liveFence = cas;
    const preservation = await integration.capturePreservation({
      root,
      lock,
      endpoint,
      before,
      images,
      d,
      verifyState: () => liveFence(),
      runtime,
      reservation,
      verifyAdmission: async () => {
        const c = await inspectOne(web.Id, 'web', config);
        sameContainer(web, c);
        safe(stopped(c));
      },
    });
    safe(typeof preservation?.verify === 'function');
    cas();
    await writers();
    mark('verify');
    await verify(release, pins, candidateAnchor);
    const candidateFiles = [
      directoryFence(next.releaseHostDir, 0o555),
      directoryFence(join(next.releaseHostDir, 'db'), 0o555),
      ...releaseFences(next),
    ];
    candidateFiles.forEach((f) => f.verify());
    mark('activate');
    const pendingProfile = join(paths.stand, '.profile.pending'),
      pendingOverlay = join(paths.stand, '.compose.cve.pending');
    writeExclusive(pendingProfile, json({ version: 2, project: PROJECT, cve: candidate }), 0o600);
    writeExclusive(pendingOverlay, json(cveOverlay(next)), 0o600);
    cas();
    record('publish.json', { version: 1, project: PROJECT, phase: 'publish-public-binding', endpoint });
    // Two-file transaction is guarded by sticky .operation.lock. A crash between
    // renames is HOLD, not a state that an ordinary launcher may repair/adopt.
    fs.renameSync(pendingOverlay, paths.overlay);
    fs.renameSync(pendingProfile, paths.profile);
    syncDirectory(paths.stand);
    const newProfile = fileFence(paths.profile, 4096),
      newOverlay = fileFence(paths.overlay, 16384);
    const committedFence = () => {
      lock.verify();
      runtime.verify();
      [
        newProfile,
        newOverlay,
        pinsFile,
        jwt,
        trust,
        ...oldFiles,
        ...candidateFiles,
        ...records.values(),
      ].forEach((f) => f.verify());
    };
    liveFence = committedFence;
    const ready = async (name) => {
      const limit = now() + 60_000;
      do {
        committedFence();
        const c = await inspectOne(`${PROJECT}-${name}-1`, name, nextConfig);
        safe(active(c) && c.Id !== (name === 'api' ? api.Id : worker.Id));
        if (name !== 'api' || c.State.Health?.Status === 'healthy') {
          const result = JSON.parse(
            await d(
              [
                'container',
                'exec',
                c.Id,
                'node',
                '--import',
                'tsx',
                '--input-type=module',
                '-e',
                name === 'api' && runtime.selection
                  ? runtime.llm.PUBLIC_LLM_GATEWAY_PROBE + PUBLIC_READY_PROBE
                  : PUBLIC_READY_PROBE,
              ],
              { timeout: 120_000 },
            ),
          );
          safe(
            result.ready === true &&
              result.manifest === manifest &&
              result.bundle === pins.artifactSha256 &&
              result.db === pins.dbSha256,
          );
          return c;
        }
        safe(now() < limit);
        await sleep(1000);
      } while (true);
    };
    const up = async (name) => {
      committedFence();
      record(`up-${name}.json`, { version: 1, project: PROJECT, phase: `up-${name}`, endpoint });
      await d(compose(['up', '-d', '--no-deps', '--no-build', '--pull', 'never', '--force-recreate', name]), {
        env: { ...env, SCAN_JWT_SECRET: jwt.bytes },
        timeout: 120_000,
      });
    };
    await up('worker');
    await sleep(3000);
    const readyWorker = await ready('worker');
    mark('preservation');
    await preservation.verify({ d, lock, endpoint, phase: 'before-api' });
    committedFence();
    // New worker must remain the same execution epoch and idle; admissions
    // remain closed even while the preservation bridge runs its helper.
    const stillWorker = await inspectOne(readyWorker.Id, 'worker', nextConfig);
    sameEpoch(readyWorker, stillWorker);
    safe(active(stillWorker));
    const stillApi = await inspectOne(api.Id, 'api', config);
    sameContainer(api, stillApi);
    safe(stopped(stillApi));
    for (const volume of ['auth_accounts', 'scan_ledger']) {
      const ids = (
        await d([
          'container',
          'ls',
          '--filter',
          `volume=${PROJECT}_${volume}`,
          '--format',
          '{{.ID}}',
          '--no-trunc',
        ])
      )
        .trim()
        .split('\n')
        .filter(Boolean)
        .sort();
      safe(equal(ids, volume === 'scan_ledger' ? [readyWorker.Id] : []));
    }
    const counts = JSON.parse(
      await d(['container', 'exec', readyWorker.Id, 'node', '-e', PUBLIC_DRAIN_PROBE]),
    );
    safe(
      equal(Object.keys(counts).sort(), ['jobs', 'leases', 'outbox']) &&
        Object.values(counts).every((n) => n === 0),
    );
    mark('activate');
    await up('api');
    await sleep(3000);
    const readyApi = await ready('api');
    mark('preservation');
    await preservation.verify({ d, lock, endpoint, phase: 'after-api' });
    mark('readiness');
    const after = await inventory(nextConfig);
    runtime.storage(before, after);
    runtime.membership(after);
    const finalWorker = one(after, 'worker'),
      finalApi = one(after, 'api');
    sameEpoch(readyWorker, finalWorker);
    sameEpoch(readyApi, finalApi);
    safe(active(finalWorker) && active(finalApi) && finalApi.State.Health?.Status === 'healthy');
    const stillWeb = one(after, 'web');
    sameContainer(web, stillWeb);
    safe(stopped(stillWeb));
    for (const prior of before.containers.filter((c) => !['api', 'worker', 'web'].includes(role(c))))
      sameEpoch(prior, one(after, role(prior)));
    const resumedWeb = await resumeWeb(nextConfig, committedFence);
    const accepted = await inventory(nextConfig);
    runtime.storage(before, accepted);
    runtime.membership(accepted);
    sameEpoch(readyWorker, one(accepted, 'worker'));
    sameEpoch(readyApi, one(accepted, 'api'));
    sameEpoch(resumedWeb, one(accepted, 'web'));
    safe(
      active(one(accepted, 'api')) &&
        one(accepted, 'api').State.Health?.Status === 'healthy' &&
        active(one(accepted, 'worker')) &&
        active(one(accepted, 'web')) &&
        (!one(accepted, 'web').State.Health || one(accepted, 'web').State.Health.Status === 'healthy'),
    );
    for (const prior of before.containers.filter((c) => !['api', 'worker', 'web'].includes(role(c))))
      sameEpoch(prior, one(accepted, role(prior)));
    committedFence();
    safe(equal(loadPublicBinding(root).current, candidate));
    record('complete.json', { version: 1, project: PROJECT, outcome: 'activated', manifest });
    mark('cleanup');
    cleanup();
    log(
      'PUBLIC CVE activated; API/worker replaced, original web resumed after preservation; prior releases retained. Not scanner finding qualification.',
    );
    return { outcome: 'activated', manifest };
  } catch (error) {
    throw failure(phase, hold, checkpoint, cveRefreshDiagnostic(error));
  } finally {
    if (lock && !hold) {
      try {
        lock.verify();
        if (temporaryOverlay) {
          temporaryOverlay.verify();
          fs.unlinkSync(join(lock.path, 'candidate.cve.json'));
          syncDirectory(lock.path);
        }
        lock.release();
      } catch {
        throw failure('cleanup', true);
      }
    }
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  refreshPublicCve(process.argv.slice(2)).catch((error) => {
    console.error(publicCveFailure(error).message);
    process.exitCode = 1;
  });
}
