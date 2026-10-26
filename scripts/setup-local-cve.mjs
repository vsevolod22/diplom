import { execFile } from 'node:child_process';
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, timingSafeEqual } from 'node:crypto';
import * as fs from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cveTimeout, parseTransportFailureReceipt } from '../server/deploy/trust/fetch-db-layer.mjs';
export { cveTimeout };

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
// Absolute end assertions also reject a trailing newline (unlike JavaScript's $).
const HEX = /^[a-f0-9]{64}(?![\s\S])/;
const MANIFEST = /^sha256:[a-f0-9]{64}(?![\s\S])/;
const SAFE_ID = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}(?![\s\S])/;
const PUBLIC_PEM = /^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END PUBLIC KEY-----\s*$/;
const PRIVATE_PEM = /^-----BEGIN PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END PRIVATE KEY-----\s*$/;
const failure = () => new Error('LOCAL CVE setup refused; inspect public configuration, file permissions and incomplete setup state.');
function requireSafe(ok) { if (!ok) throw failure(); }
const uid = () => process.getuid();
const fingerprint = key => createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex');

export function parseSetupArguments(argv) {
  const names = ['--release', '--manifest', '--bundle', '--db'];
  const args = {};
  requireSafe(argv.length === 8 && argv.every(value => typeof value === 'string'));
  for (let i = 0; i < argv.length; i += 2) {
    requireSafe(names.includes(argv[i]) && !Object.hasOwn(args, argv[i]));
    args[argv[i]] = argv[i + 1];
  }
  requireSafe(SAFE_ID.test(args['--release']) && MANIFEST.test(args['--manifest']) &&
    HEX.test(args['--bundle']) && HEX.test(args['--db']));
  return { id: args['--release'], manifest: args['--manifest'], bundle: args['--bundle'], db: args['--db'] };
}

function exists(path) {
  try { fs.lstatSync(path); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; }
}
function directory(path, mode, create = false) {
  if (create) {
    try { fs.mkdirSync(path, { mode }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  }
  const stat = fs.lstatSync(path);
  requireSafe(stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === uid() &&
    (mode === undefined || (stat.mode & 0o777) === mode));
}
function syncDirectory(path) {
  const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function regular(path, cap, mode) {
  const stat = fs.lstatSync(path);
  requireSafe(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 && stat.uid === uid() &&
    stat.size > 0 && stat.size <= cap && (mode === undefined || (stat.mode & 0o777) === mode));
  return stat;
}
function readBounded(path, cap, mode) {
  const before = regular(path, cap, mode);
  const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const opened = fs.fstatSync(fd);
    requireSafe(opened.dev === before.dev && opened.ino === before.ino && opened.isFile() &&
      opened.nlink === 1 && opened.uid === uid() && opened.size === before.size &&
      (mode === undefined || (opened.mode & 0o777) === mode));
    const buffer = Buffer.alloc(cap + 1);
    let size = 0;
    while (size < buffer.length) {
      const n = fs.readSync(fd, buffer, size, buffer.length - size, null);
      if (!n) break;
      size += n;
    }
    const after = fs.fstatSync(fd);
    requireSafe(size === before.size && size <= cap && after.size === opened.size && after.nlink === 1 &&
      after.mtimeMs === opened.mtimeMs && after.ctimeMs === opened.ctimeMs);
    return buffer.subarray(0, size).toString('utf8');
  } finally { fs.closeSync(fd); }
}
function writeExclusive(path, bytes, mode) {
  const fd = fs.openSync(path, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, mode);
  try { fs.writeFileSync(fd, bytes); fs.fchmodSync(fd, mode); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function publicKey(path, expected) {
  const pem = readBounded(path, 8192, 0o444);
  requireSafe(PUBLIC_PEM.test(pem));
  const key = createPublicKey(pem);
  requireSafe(key.asymmetricKeyType === 'ed25519' && (!expected || fingerprint(key) === expected));
  return key;
}
function keyPair(trust, generatePair) {
  const privatePath = join(trust, 'db-signing-key.pem'), publicPath = join(trust, 'db-signing-key.pub.pem');
  const privateExists = exists(privatePath), publicExists = exists(publicPath);
  requireSafe(privateExists === publicExists);
  if (!privateExists) {
    const { privateKey, publicKey: pub } = generatePair();
    requireSafe(privateKey.asymmetricKeyType === 'ed25519' && pub.asymmetricKeyType === 'ed25519' &&
      fingerprint(createPublicKey(privateKey)) === fingerprint(pub));
    writeExclusive(privatePath, privateKey.export({ type: 'pkcs8', format: 'pem' }), 0o600);
    writeExclusive(publicPath, pub.export({ type: 'spki', format: 'pem' }), 0o444);
    syncDirectory(trust);
  }
  const pem = readBounded(privatePath, 8192, 0o600);
  requireSafe(PRIVATE_PEM.test(pem));
  const privateKey = createPrivateKey(pem), pub = publicKey(publicPath);
  requireSafe(privateKey.asymmetricKeyType === 'ed25519' && timingSafeEqual(
    createPublicKey(privateKey).export({ type: 'spki', format: 'der' }), pub.export({ type: 'spki', format: 'der' })));
  return { privatePath, publicPath, publicKeySha256: fingerprint(pub) };
}
function layout(release, signed, frozen = false) {
  directory(release, frozen ? 0o555 : 0o700);
  directory(join(release, 'db'), frozen ? 0o555 : 0o700);
  const expected = signed ? ['bundle.bin', 'db', 'descriptor.json', 'descriptor.sig'] : ['bundle.bin', 'db'];
  requireSafe(JSON.stringify(fs.readdirSync(release).sort()) === JSON.stringify(expected.sort()) &&
    JSON.stringify(fs.readdirSync(join(release, 'db')).sort()) === JSON.stringify(['metadata.json', 'trivy.db']));
  const files = [['bundle.bin', 512 * 1024 ** 2], ['db/trivy.db', 2 * 1024 ** 3], ['db/metadata.json', 4096],
    ...(signed ? [['descriptor.json', 4096], ['descriptor.sig', 64]] : [])];
  for (const [file, cap] of files) {
    const stat = regular(join(release, file), cap, frozen ? 0o444 : undefined);
    requireSafe(!(stat.mode & 0o022));
    if (file === 'descriptor.sig') requireSafe(stat.size === 64);
  }
  return files.map(([name]) => join(release, name));
}
function localPaths(root) {
  requireSafe(resolve(root) === root && fs.realpathSync(root) === root);
  const stand = join(root, '.local-stand');
  directory(stand, 0o700);
  return { stand, config: join(stand, 'cve.json'), trust: join(stand, 'trust'), releases: join(stand, 'db-releases') };
}

// Public structure/anchor validation only; use verify-local-cve for authenticated DB usability.
// This loader never reads the private key or JWT and never creates files.
export function loadCveActivation(root = ROOT) {
  try {
    const paths = localPaths(root);
    const raw = readBounded(paths.config, 4096, 0o600), value = JSON.parse(raw);
    requireSafe(value && typeof value === 'object' && !Array.isArray(value) && value.version === 1 &&
      typeof value.release === 'string' && value.release.startsWith('db-releases/') &&
      SAFE_ID.test(value.release.slice('db-releases/'.length)) && MANIFEST.test(value.manifestDigest) &&
      HEX.test(value.artifactSha256) && HEX.test(value.publicKeySha256));
    const canonical = { version: 1, release: value.release, manifestDigest: value.manifestDigest,
      artifactSha256: value.artifactSha256, publicKeySha256: value.publicKeySha256 };
    requireSafe(raw === JSON.stringify(canonical));
    directory(paths.trust, 0o700);
    directory(paths.releases, 0o700);
    publicKey(join(paths.trust, 'db-signing-key.pub.pem'), value.publicKeySha256);
    layout(join(paths.stand, value.release), true, true);
    return Object.freeze(canonical);
  } catch { throw failure(); }
}

export function childEnvironment() {
  return { PATH: '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', TZ: 'UTC' };
}
const childFailures = new WeakMap();
const ownChildValue = (v, k) => v && typeof v === 'object' ? Object.getOwnPropertyDescriptor(v, k)?.value : undefined;
export function cveChildFailure(error) { return childFailures.get(error) ?? null; }
export function runChild(executable, args, { cwd, env, timeout }, execute = execFile) {
  return new Promise((resolveOutput, reject) => {
    const refused = (error, stderr) => {
      const code = ownChildValue(error, 'code');
      const cause = code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' ? 'CHILD_OUTPUT_LIMIT' : ownChildValue(error, 'killed') ? 'CHILD_TIMEOUT' :
        code === 'ENOENT' ? 'CHILD_SPAWN' : 'CHILD_EXIT_NONZERO';
      const transport = executable === process.execPath && args[0] === join(cwd, 'server/deploy/trust/fetch-db-layer.mjs') && code === 1 ? parseTransportFailureReceipt(stderr) : null;
      const safeError = failure();
      childFailures.set(safeError, Object.freeze({ cause, ...(transport ? { transport } : {}) })); reject(safeError);
    };
    if (!Number.isInteger(timeout) || timeout < 1 || timeout > 2147483647) {
      const error = failure(); childFailures.set(error, Object.freeze({ cause: 'CHILD_TIMEOUT_INVALID' })); reject(error); return;
    }
    try {
      execute(executable, args, { cwd, env, timeout, killSignal: 'SIGKILL', maxBuffer: 65536,
        encoding: 'utf8', shell: false }, (error, stdout, stderr) => {
        if (error) refused(error, stderr); else resolveOutput(stdout);
      });
    } catch (error) { refused(error); }
  });
}
// Shared by setup, refresh and launcher lifecycle operations. Never steal a stale
// lock: a killed controller may have left a partially switched stand.
export function acquireStandLock(root = ROOT) {
  requireSafe(resolve(root) === root && fs.realpathSync(root) === root);
  const stand = join(root, '.local-stand');
  directory(stand, 0o700, true);
  const path = join(stand, '.stand-operation.lock');
  fs.mkdirSync(path, { mode: 0o700 });
  const identity = fs.lstatSync(path);
  syncDirectory(stand);
  return () => {
    const current = fs.lstatSync(path);
    requireSafe(current.dev === identity.dev && current.ino === identity.ino && !current.isSymbolicLink());
    fs.rmdirSync(path); // A refresh journal deliberately keeps an uncertain operation locked.
    syncDirectory(stand);
  };
}

export function existingLocalCveKeyPair(root, expected) {
  const paths = localPaths(root);
  directory(paths.trust, 0o700);
  const keys = keyPair(paths.trust, () => { throw failure(); });
  requireSafe(keys.publicKeySha256 === expected);
  return keys;
}

// These bounded filesystem primitives are shared only with the host updater.
export { directory, layout, readBounded, writeExclusive, syncDirectory, localPaths };

function publish(paths, value) {
  const temporary = join(paths.stand, '.cve.json.pending');
  writeExclusive(temporary, JSON.stringify(value), 0o600);
  // link is an atomic no-replace publication; rename would overwrite an existing activation.
  fs.linkSync(temporary, paths.config);
  syncDirectory(paths.stand);
  fs.unlinkSync(temporary);
  syncDirectory(paths.stand);
}

function releaseSetupLock(path) {
  try { fs.rmdirSync(path); } catch { throw failure(); }
}

export async function setupLocalCve(argv, { root = ROOT, run = runChild,
  generatePair = () => generateKeyPairSync('ed25519'), log = console.log } = {}) {
  let lock, unlock;
  try {
    const args = parseSetupArguments(argv);
    unlock = acquireStandLock(root);
    const paths = localPaths(root);
    requireSafe(!exists(paths.config) && !exists(join(paths.stand, '.cve.json.pending')));
    directory(paths.releases, 0o700);
    const release = join(paths.releases, args.id);
    layout(release, false);
    const lockPath = join(paths.stand, '.cve-setup.lock');
    fs.mkdirSync(lockPath, { mode: 0o700 });
    lock = lockPath;
    requireSafe(!exists(paths.config));
    directory(paths.trust, 0o700, true);
    const keys = keyPair(paths.trust, generatePair);
    const deadline = performance.now() + 120_000;
    const child = async argv => {
      const timeout = cveTimeout(120_000, deadline, performance.now());
      return run(process.execPath, argv, { cwd: root, env: childEnvironment(), timeout });
    };
    await child([join(root, 'server/deploy/trust/sign-offline-db.mjs'), release, keys.privatePath, keys.publicPath,
      args.manifest, args.bundle, args.db]);
    layout(release, true);
    const output = await child(['--import', join(root, 'server/api/node_modules/tsx/dist/loader.mjs'),
      join(root, 'scripts/verify-local-cve.mjs'), '--release-dir', release, '--public-key', keys.publicPath,
      '--public-key-sha256', keys.publicKeySha256, '--manifest', args.manifest, '--bundle', args.bundle, '--db', args.db]);
    const verified = JSON.parse(output);
    requireSafe(verified.kind === 'authenticated-release-usability-only' && verified.scannerChecked === false &&
      verified.admissionChecked === false && verified.db?.dbSha256 === args.db &&
      verified.db.manifestDigest === args.manifest && verified.db.artifactSha256 === args.bundle);
    for (const path of layout(release, true)) fs.chmodSync(path, 0o444);
    fs.chmodSync(join(release, 'db'), 0o555);
    fs.chmodSync(release, 0o555);
    syncDirectory(join(release, 'db'));
    syncDirectory(release);
    const activation = { version: 1, release: `db-releases/${args.id}`, manifestDigest: args.manifest,
      artifactSha256: args.bundle, publicKeySha256: keys.publicKeySha256 };
    publish(paths, activation);
    log('Published LOCAL CVE activation. Operator-attested DB only; scanner/admission acceptance not established.');
    return activation;
  } catch { throw failure(); }
  finally {
    if (lock) releaseSetupLock(lock);
    if (unlock) unlock();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  setupLocalCve(process.argv.slice(2)).catch(() => {
    console.error(failure().message);
    process.exitCode = 1;
  });
}
