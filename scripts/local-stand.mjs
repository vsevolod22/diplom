import { execFile } from 'node:child_process';
import { createHash, createPublicKey, randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const PROJECT = 'dip-local-full';
export const LABEL = 'org.diplom.local-stand';
export const ORIGIN = 'http://127.0.0.1:8080';
const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const CONFIG_SECRET = '0'.repeat(96); // Config validation only; never used to start a service.
const SERVICES = ['auth-volume-init', 'scan-volume-init', 'egress', 'worker', 'api', 'web'];
const VOLUMES = ['auth_accounts', 'scan_ledger'];
const NETWORKS = ['auth_internal', 'scan_internal', 'registry_uplink', 'web_edge'];
const DOCKERFILES = { egress: 'gateway/Dockerfile', api: 'api.Dockerfile', worker: 'worker.Dockerfile', web: 'stand.Dockerfile' };
const MOUNTS = {
  'auth-volume-init': { '/data': 'auth_accounts' }, 'scan-volume-init': { '/data': 'scan_ledger' },
  api: { '/auth': 'auth_accounts', '/data': 'scan_ledger' }, worker: { '/data': 'scan_ledger' }, egress: {}, web: {},
};
const CONNECTIONS = {
  'auth-volume-init': [], 'scan-volume-init': [], egress: ['scan_internal', 'registry_uplink'],
  worker: ['scan_internal'], api: ['auth_internal', 'scan_internal'], web: ['auth_internal', 'web_edge'],
};
const COMMANDS = {
  'auth-volume-init': ['chown', '65532:65532', '/data'], 'scan-volume-init': ['chown', '65532:65532', '/data'],
  api: ['node', '--import', 'tsx', 'src/oci/nginx-local.main.ts'],
  worker: ['node', '--import', 'tsx', 'src/worker/nginx-local-worker.main.ts'],
};

class StandError extends Error {}
function requireSafe(ok, message) {
  if (!ok) throw new StandError(message);
}
function sameKeys(actual, expected) {
  return JSON.stringify(Object.keys(actual ?? {}).sort()) === JSON.stringify([...expected].sort());
}
function sameList(actual, expected) {
  return JSON.stringify([...(actual ?? [])].sort()) === JSON.stringify([...expected].sort());
}
function owned(labels) {
  return labels?.[LABEL] === 'v1' && labels?.['com.docker.compose.project'] === PROJECT;
}
function namespaced(name) {
  return name === PROJECT || name.startsWith(`${PROJECT}-`) || name.startsWith(`${PROJECT}_`);
}

// Only Docker client settings cross the process boundary. No dotenv, COMPOSE_*,
// scanner, provider key, NODE_OPTIONS, proxy or frontend environment is inherited.
export function dockerEnvironment(ambient = process.env) {
  const env = { PATH: '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin', COMPOSE_DISABLE_ENV_FILE: 'true' };
  for (const key of ['PATH', 'HOME', 'TMPDIR', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']) {
    if (ambient[key] !== undefined) env[key] = ambient[key];
  }
  return env;
}
export function composeArguments(root, args, cve = null) {
  return ['compose', '--env-file', '/dev/null', '-p', PROJECT,
    '-f', join(root, 'server/deploy/compose.stand.yaml'),
    '-f', join(root, 'server/deploy/compose.local.full.yaml'),
    ...(cve ? ['-f', join(root, 'server/deploy/compose.local.cve.yaml')] : []), ...args];
}
function composeEnvironment(env, secret = CONFIG_SECRET, cve = null) {
  return { ...env, SCAN_JWT_SECRET: secret, AUTH_ORIGIN: ORIGIN,
    AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOWED_USER_IDS: '', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true',
    ...(cve ? { SCAN_VULN_RELEASE_HOST_DIR: cve.releaseHostDir,
      SCAN_VULN_MANIFEST_DIGEST: cve.manifestDigest, SCAN_VULN_ARTIFACT_SHA256: cve.artifactSha256,
      LOCAL_CVE_TRUST_SHA256: cve.publicKeySha256 } : {}) };
}
export function runDocker(args, { root, env, timeout = 30_000 }) {
  return new Promise((resolveOutput, reject) => {
    execFile('docker', args, { cwd: root, env, timeout, killSignal: 'SIGKILL', maxBuffer: 16 * 1024 * 1024,
      encoding: 'utf8' }, (error, stdout) => {
      // execFile errors can contain complete argv/stdout/stderr. Never forward them.
      if (error) reject(new StandError(error.killed ? 'Docker command timed out; partial resources are preserved. Check status before retrying.' :
        'Docker command failed; output withheld to protect secrets. Check Docker availability and the reviewed Compose files.'));
      else resolveOutput(stdout);
    });
  });
}

const CVE_KEYS = ['version', 'release', 'manifestDigest', 'artifactSha256', 'publicKeySha256'];
const RELEASE_PATH = /^db-releases\/[a-z0-9][a-z0-9_-]{0,127}$/;
const CVE_TMPFS = ['/tmp:rw,noexec,nosuid,size=16m', '/tmp/trivy:rw,noexec,nosuid,uid=65532,gid=65532,size=512m'];
function cveEnvironment(cve) {
  return cve ? { SCAN_VULN_ENABLED: 'true', SCAN_VULN_RELEASE_DIR: '/opt/release',
    SCAN_VULN_MANIFEST_DIGEST: cve.manifestDigest, SCAN_VULN_ARTIFACT_SHA256: cve.artifactSha256,
    LOCAL_CVE_TRUST_SHA256: cve.publicKeySha256 } : { SCAN_VULN_ENABLED: 'false' };
}
function cveShape(value) {
  requireSafe(value && sameKeys(value, CVE_KEYS) && value.version === 1 &&
    typeof value.release === 'string' && RELEASE_PATH.test(value.release) &&
    /^sha256:[a-f0-9]{64}$/.test(value.manifestDigest) && /^[a-f0-9]{64}$/.test(value.artifactSha256) &&
    /^[a-f0-9]{64}$/.test(value.publicKeySha256), 'Invalid LOCAL CVE activation schema or pins.');
}
function safeDirectory(path, mode, io, uid) {
  const stat = io.lstatSync(path);
  requireSafe(stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === uid &&
    (mode === undefined ? (stat.mode & 0o022) === 0 : (stat.mode & 0o7777) === mode),
  'Unsafe LOCAL CVE directory ownership, mode or symlink.');
}
function safePublicFile(path, mode, io, uid) {
  const stat = io.lstatSync(path);
  requireSafe(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 && stat.uid === uid &&
    (stat.mode & 0o7777) === mode, 'Unsafe LOCAL CVE file ownership, mode, link or type.');
  return stat;
}
function readPublicBounded(path, mode, limit, io, uid) {
  const before = safePublicFile(path, mode, io, uid);
  const fd = io.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const opened = io.fstatSync(fd);
    requireSafe(opened.dev === before.dev && opened.ino === before.ino && opened.size > 0 && opened.size <= limit,
      'Invalid LOCAL CVE public file size or identity.');
    const buffer = Buffer.alloc(limit + 1);
    let total = 0, count;
    while (total < buffer.length && (count = io.readSync(fd, buffer, total, buffer.length - total, null)) > 0) total += count;
    const after = io.fstatSync(fd);
    requireSafe(total === before.size && total <= limit && after.size === before.size &&
      after.mtimeMs === before.mtimeMs && after.ctimeMs === before.ctimeMs && after.mode === before.mode,
    'LOCAL CVE public file changed while reading.');
    return buffer.subarray(0, total);
  } finally { io.closeSync(fd); }
}
function validateCveRelease(root, value, { io = fs, uid = process.getuid() } = {}) {
  cveShape(value);
  const directory = join(root, '.local-stand'), releaseHostDir = join(directory, value.release);
  safeDirectory(directory, 0o700, io, uid);
  safeDirectory(join(directory, 'db-releases'), undefined, io, uid);
  safeDirectory(releaseHostDir, 0o555, io, uid);
  safeDirectory(join(releaseHostDir, 'db'), 0o555, io, uid);
  requireSafe(sameList(io.readdirSync(releaseHostDir), ['descriptor.json', 'descriptor.sig', 'bundle.bin', 'db']) &&
    sameList(io.readdirSync(join(releaseHostDir, 'db')), ['metadata.json', 'trivy.db']), 'Unexpected LOCAL CVE release contents.');
  for (const file of ['descriptor.json', 'descriptor.sig', 'bundle.bin', 'db/metadata.json', 'db/trivy.db']) {
    safePublicFile(join(releaseHostDir, file), 0o444, io, uid);
  }
  safeDirectory(join(directory, 'trust'), undefined, io, uid);
  const publicKeyPath = join(directory, 'trust/db-signing-key.pub.pem');
  const pem = readPublicBounded(publicKeyPath, 0o444, 4096, io, uid);
  requireSafe(/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\r?\n?$/.test(pem.toString('utf8')),
    'Invalid LOCAL CVE public PEM.');
  const key = createPublicKey(pem);
  requireSafe(key.asymmetricKeyType === 'ed25519' &&
    createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex') === value.publicKeySha256,
  'LOCAL CVE public key does not match activation SPKI SHA256.');
  return Object.freeze({ ...value, releaseHostDir, publicKeyPath });
}

// No provisioning here: absence alone disables CVE; a present invalid file always refuses.
// Canonical bytes are JSON.stringify in CVE_KEYS order, without whitespace or a newline.
export function loadCveActivation(root, { io = fs, uid = process.getuid() } = {}) {
  const directory = join(root, '.local-stand');
  try { io.lstatSync(directory); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  safeDirectory(directory, 0o700, io, uid);
  const path = join(directory, 'cve.json');
  try { io.lstatSync(path); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  const bytes = readPublicBounded(path, 0o600, 4096, io, uid);
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  cveShape(value);
  requireSafe(JSON.stringify(Object.fromEntries(CVE_KEYS.map(key => [key, value[key]]))) === bytes.toString('utf8'),
    'LOCAL CVE activation must be canonical public JSON.');
  return validateCveRelease(root, value, { io, uid });
}
function cveMounts(service, cve) {
  if (!cve || !['api', 'worker'].includes(service)) return [];
  return [{ type: 'bind', source: cve.releaseHostDir, target: '/opt/release', read_only: true },
    { type: 'bind', source: cve.publicKeyPath, target: '/opt/local-db-trust/public.pem', read_only: true },
    ...(service === 'worker' ? [{ type: 'bind', source: join(cve.releaseHostDir, 'db'), target: '/tmp/trivy/db', read_only: true }] : [])];
}

export function expectedEnvironment(service, cve = null) {
  if (service === 'worker') return { SCAN_LEDGER_PATH: '/data/ledger.sqlite', SCAN_WORKER_READY_PATH: '/data/worker.ready',
    TRIVY_CACHE_DIR: '/tmp/trivy', ...cveEnvironment(cve) };
  if (service !== 'api') return {};
  return { SCAN_BIND_ADDRESS: '0.0.0.0', PORT: '3001', SCAN_JWT_SECRET: CONFIG_SECRET,
    SCAN_JWT_ISSUER: PROJECT, SCAN_JWT_AUDIENCE: PROJECT, AUTH_DB_PATH: '/auth/auth.sqlite',
    AUTH_ORIGIN: ORIGIN, AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOWED_USER_IDS: '',
    SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true', SCAN_LEDGER_PATH: '/data/ledger.sqlite',
    SCAN_WORKER_READY_PATH: '/data/worker.ready', ...cveEnvironment(cve), LLM_ENABLED: 'false',
    LLM_ROUTING_APPROVED: 'false', LLM_QUOTA_ENABLED: 'false', LLM_HISTORY_ENABLED: 'false' };
}

export function validateConfig(config, root, cve = null) {
  requireSafe(config.name === PROJECT && sameKeys(config.services, SERVICES) && sameKeys(config.volumes, VOLUMES) &&
    sameKeys(config.networks, NETWORKS), 'Unexpected Compose project or resource set.');
  requireSafe(!config.secrets && !config.configs, 'External Compose secrets/configs are not allowed.');
  for (const [kind, keys] of [['volumes', VOLUMES], ['networks', NETWORKS]]) {
    for (const key of keys) {
      const item = config[kind][key];
      requireSafe(item.name === `${PROJECT}_${key}` && item.labels?.[LABEL] === 'v1' &&
        !item.external && !item.driver_opts && (!item.driver || item.driver === (kind === 'volumes' ? 'local' : 'bridge')),
      'Shared, external or unowned storage/network in Compose configuration.');
      if (kind === 'networks') requireSafe(Boolean(item.internal) === key.endsWith('_internal'), 'Unexpected network isolation.');
    }
  }
  for (const [service, spec] of Object.entries(config.services)) {
    requireSafe(spec.labels?.[LABEL] === 'v1' && !spec.container_name && !spec.profiles && !spec.env_file && !spec.secrets &&
      !spec.configs && !spec.privileged && !spec.devices && !spec.volumes_from && !spec.external_links &&
      !spec.pid && !spec.ipc && !spec.develop && !spec.post_start && !spec.pre_stop,
    'Unexpected service authority or configuration.');
    const env = spec.environment ?? {}, expected = expectedEnvironment(service, cve);
    requireSafe(sameKeys(env, Object.keys(expected)) && Object.entries(expected).every(([key, value]) => env[key] === value),
      'Unexpected service environment or LOCAL CVE pins.');
    if (DOCKERFILES[service]) {
      requireSafe(spec.image === `${PROJECT}-${service}:local` && spec.build?.context === root &&
        spec.build.dockerfile === `server/deploy/${DOCKERFILES[service]}` && spec.build.labels?.[LABEL] === 'v1' &&
        !spec.build.args && !spec.build.additional_contexts && !spec.build.secrets && !spec.build.ssh && !spec.build.target &&
                !spec.build.network && !spec.build.dockerfile_inline,
      'Unexpected image or build source.');
    } else requireSafe(spec.image === 'busybox:1.37.0' && !spec.build, 'Unexpected volume initializer.');
    if (COMMANDS[service]) requireSafe(JSON.stringify(spec.command) === JSON.stringify(COMMANDS[service]), 'Unexpected service entrypoint.');
    requireSafe(!spec.entrypoint, 'Unexpected service entrypoint override.');
    const mounts = spec.volumes ?? [], binds = cveMounts(service, cve);
    // Compose JSON omits create_host_path:false as the bind option's zero value.
    requireSafe(mounts.length === Object.keys(MOUNTS[service]).length + binds.length &&
      sameList(mounts.map(mount => mount.target), [...Object.keys(MOUNTS[service]), ...binds.map(mount => mount.target)]) &&
      mounts.every(mount => (mount.type === 'volume' && MOUNTS[service][mount.target] === mount.source &&
        !mount.read_only && !mount.volume?.subpath) || binds.some(bind => mount.type === 'bind' &&
        mount.target === bind.target && mount.source === bind.source && mount.read_only === true &&
        mount.bind && (mount.bind.create_host_path === undefined || mount.bind.create_host_path === false) &&
        Object.keys(mount.bind).every(key => key === 'create_host_path'))),
    'Bind, shared or unexpected service mount.');
    if (service === 'worker' && cve) requireSafe(sameList(spec.tmpfs, CVE_TMPFS), 'Unexpected LOCAL CVE worker tmpfs.');
    requireSafe(sameKeys(spec.networks, CONNECTIONS[service]) &&
      (!spec.network_mode || (CONNECTIONS[service].length === 0 && spec.network_mode === 'none')),
    'Unexpected service networking.');
    const ports = spec.ports ?? [];
    requireSafe(service === 'web' ? ports.length === 1 && ports[0].host_ip === '127.0.0.1' &&
      String(ports[0].published) === '8080' && ports[0].target === 8080 && ports[0].protocol === 'tcp' : ports.length === 0,
    'Only web may publish 127.0.0.1:8080.');
  }
  requireSafe(config.services.worker.mem_limit === '1073741824' || config.services.worker.mem_limit === 1073741824,
    'LOCAL worker memory envelope changed.');
  requireSafe(String(config.services.worker.memswap_limit) === '1073741824' && config.services.worker.cpus === 1 &&
    config.services.worker.pids_limit === 128, 'LOCAL worker resource envelope changed.');
}

function inspectedCve(item, service, root, platform) {
  const pairs = (item.Config.Env ?? []).map(entry => entry.split(/=(.*)/s));
  const cvePairs = pairs.filter(([key]) => key.startsWith('SCAN_VULN_') || key.startsWith('LOCAL_CVE_'));
  const env = Object.fromEntries(cvePairs.map(([key, value]) => [key, value]));
  requireSafe(Object.keys(env).length === cvePairs.length, 'Duplicate preexisting LOCAL CVE environment.');
  if (!['api', 'worker'].includes(service)) {
    requireSafe(cvePairs.length === 0, 'Unexpected preexisting LOCAL CVE environment.');
    return null;
  }
  let cve = null;
  if (env.SCAN_VULN_ENABLED === 'true') {
    const declarations = (item.HostConfig?.Mounts ?? []).filter(mount => mount.Target === '/opt/release');
    const declaration = declarations[0], source = declaration?.Source;
    requireSafe(declarations.length === 1 && declaration.Type === 'bind' && declaration.ReadOnly === true &&
      typeof root === 'string' && typeof source === 'string', 'Missing or unsafe preexisting LOCAL CVE release declaration.');
    const prefix = `${join(root, '.local-stand')}/`;
    // Desktop can store its literal VM prefix in the declaration too. Match only
    // this project's known prefix; never normalize an arbitrary observed path.
    const matchedPrefix = [prefix, ...(platform === 'darwin' ? [`/host_mnt${prefix}`] : [])]
      .find(candidate => source.startsWith(candidate) && RELEASE_PATH.test(source.slice(candidate.length)));
    requireSafe(matchedPrefix, 'Foreign preexisting LOCAL CVE release path.');
    cve = validateCveRelease(root, { version: 1, release: source.slice(matchedPrefix.length),
      manifestDigest: env.SCAN_VULN_MANIFEST_DIGEST, artifactSha256: env.SCAN_VULN_ARTIFACT_SHA256,
      publicKeySha256: env.LOCAL_CVE_TRUST_SHA256 });
  }
  const expected = cveEnvironment(cve);
  requireSafe(sameKeys(env, Object.keys(expected)) && Object.entries(expected).every(([key, value]) => env[key] === value),
    'Unexpected preexisting LOCAL CVE environment or pins.');
  return cve;
}

function declaredBindMatches(declaration, mount, bind, platform) {
  if (!declaration || declaration.Type !== 'bind' || declaration.Target !== bind.target || declaration.ReadOnly !== true ||
      (declaration.BindOptions && !sameKeys(declaration.BindOptions, []))) return false;
  if (declaration.Source === bind.source && mount.Source === bind.source) return true;
  if (platform !== 'darwin' || !bind.source.startsWith('/')) return false;
  const desktopSource = `/host_mnt${bind.source}`;
  // Require a matching declaration even for Desktop's exact, bounded VM alias.
  return mount.Source === desktopSource && (declaration.Source === bind.source || declaration.Source === desktopSource);
}

// Inventory by name AND project label: an unexpected resource cannot hide behind
// a renamed container. Inspect only candidates, never old stand/dev resources.
export async function inspectNamespace(run, options, { platform = process.platform } = {}) {
  const containers = [], volumes = [], networks = [];
  for (const [kind, destination] of [['container', containers], ['volume', volumes], ['network', networks]]) {
    const format = `{{.${kind === 'container' ? 'Names' : 'Name'}}}\t{{.Label "com.docker.compose.project"}}`;
    const output = await run([kind, 'ls', ...(kind === 'container' ? ['--all'] : []), '--format', format], options);
    const candidates = output.trim().split('\n').filter(Boolean).map(line => line.split('\t'))
      .filter(([name, project]) => namespaced(name) || project === PROJECT);
    for (const [name] of candidates) {
      const [item] = JSON.parse(await run([kind, 'inspect', name], options));
      const labels = kind === 'container' ? item.Config?.Labels : item.Labels;
      requireSafe(owned(labels), 'Refusing unexpected preexisting namespace resource (ownership labels missing).');
      if (kind === 'container') {
        const service = labels['com.docker.compose.service'];
        requireSafe(SERVICES.includes(service) && name === `${PROJECT}-${service}-1` &&
          item.Config.Image === (DOCKERFILES[service] ? `${PROJECT}-${service}:local` : 'busybox:1.37.0'),
        'Refusing unexpected preexisting container.');
        // Existing owned services may still be in either exact mode while Compose transitions.
        const cve = inspectedCve(item, service, options.root, platform), binds = cveMounts(service, cve), mounts = item.Mounts ?? [];
        const declarations = (item.HostConfig?.Mounts ?? []).filter(mount =>
          mount.Type === 'bind' || binds.some(bind => bind.target === mount.Target));
        requireSafe(sameList(declarations.map(mount => mount.Target), binds.map(bind => bind.target)),
          'Preexisting container uses missing or foreign bind declarations.');
        const persistent = mounts.filter(mount => mount.Type !== 'tmpfs');
        requireSafe(sameList(persistent.map(mount => mount.Destination),
          [...Object.keys(MOUNTS[service]), ...binds.map(bind => bind.target)]) && mounts.every(mount =>
          (mount.Type === 'volume' && MOUNTS[service][mount.Destination] && mount.RW === true &&
            mount.Name === `${PROJECT}_${MOUNTS[service][mount.Destination]}` && !mount.SubPath) ||
          binds.some(bind => mount.Type === 'bind' && mount.Destination === bind.target && mount.RW === false &&
            (!mount.Propagation || mount.Propagation === 'rprivate') &&
            declaredBindMatches(declarations.find(declaration => declaration.Target === bind.target), mount, bind, platform)) ||
          (mount.Type === 'tmpfs' && ((mount.Destination === '/tmp' && ['api', 'worker', 'web'].includes(service)) ||
            (mount.Destination === '/tmp/trivy' && service === 'worker' && cve)))),
        'Preexisting container uses foreign mounts.');
        const networks = CONNECTIONS[service].length ? CONNECTIONS[service].map(key => `${PROJECT}_${key}`) : ['none'];
        requireSafe(sameKeys(item.NetworkSettings?.Networks, networks),
          'Preexisting container uses foreign networks.');
      } else {
        const keys = kind === 'volume' ? VOLUMES : NETWORKS;
        requireSafe(keys.some(key => name === `${PROJECT}_${key}`) && item.Name === name,
          'Refusing unexpected preexisting storage/network.');
        requireSafe(item.Driver === (kind === 'volume' ? 'local' : 'bridge') &&
          (kind !== 'volume' || !item.Options || Object.keys(item.Options).length === 0), 'Foreign storage/network driver.');
        if (kind === 'network') requireSafe(Boolean(item.Internal) === name.endsWith('_internal'), 'Foreign network isolation.');
      }
      destination.push(item);
    }
  }
  const images = await run(['image', 'ls', '--format', '{{.Repository}}:{{.Tag}}'], options);
  for (const image of new Set(images.trim().split('\n').filter(name => namespaced(name.split(':')[0])))) {
    requireSafe(Object.keys(DOCKERFILES).some(service => image === `${PROJECT}-${service}:local`), 'Unexpected preexisting image tag.');
    const [item] = JSON.parse(await run(['image', 'inspect', image], options));
    requireSafe(item.Config?.Labels?.[LABEL] === 'v1', 'Refusing unowned preexisting image tag.');
  }
  return { containers, volumes, networks };
}

export function checkIgnores(root, io = fs) {
  for (const file of ['.gitignore', '.dockerignore']) {
    const lines = io.readFileSync(join(root, file), 'utf8').split(/\r?\n/).map(line => line.trim());
    const last = lines.findLast(line => /^!?\/?\.local-stand\/?$/.test(line));
    requireSafe(last && !last.startsWith('!'), 'Add .local-stand/ to .gitignore and .dockerignore before starting.');
  }
}

export function loadSecret(root, { mustExist = false, io = fs, random = randomBytes, uid = process.getuid() } = {}) {
  const directory = join(root, '.local-stand'), path = join(directory, 'scan-jwt');
  try { io.mkdirSync(directory, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  const dir = io.lstatSync(directory);
  requireSafe(dir.isDirectory() && !dir.isSymbolicLink() && dir.uid === uid && (dir.mode & 0o777) === 0o700,
    'Unsafe .local-stand directory; expected owned non-symlink mode 0700.');
  let fd;
  try {
    try {
      fd = io.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    } catch (error) {
      if (error.code !== 'ENOENT' || mustExist) throw new StandError('Existing stand signing secret is unavailable; refusing replacement.');
      fd = io.openSync(path, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
      try { io.writeFileSync(fd, random(48).toString('hex')); io.fsyncSync(fd); } finally { io.closeSync(fd); fd = undefined; }
      fd = io.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    }
    const stat = io.fstatSync(fd);
    requireSafe(stat.isFile() && stat.nlink === 1 && stat.uid === uid && (stat.mode & 0o777) === 0o600 && stat.size === 96,
      'Unsafe signing secret; expected owned single-link regular mode 0600 file.');
    const secret = io.readFileSync(fd, 'utf8');
    requireSafe(/^[a-f0-9]{96}$/.test(secret), 'Invalid signing secret; refusing rotation.');
    return secret;
  } finally { if (fd !== undefined) io.closeSync(fd); }
}

export async function localStand(argv, { root = ROOT, run = runDocker, ambient = process.env, log = console.log,
  getSecret = loadSecret, platform = process.platform } = {}) {
  const [command, ...flags] = argv;
  requireSafe(['up', 'stop', 'status'].includes(command) &&
    (flags.length === 0 || (command === 'up' && flags.length === 1 && flags[0] === '--build')),
  'Usage: node scripts/local-stand.mjs up [--build] | stop | status');
  const cve = loadCveActivation(root);
  const options = { root, env: dockerEnvironment(ambient) };
  const config = JSON.parse(await run(composeArguments(root, ['config', '--format', 'json'], cve),
    { ...options, env: composeEnvironment(options.env, CONFIG_SECRET, cve) }));
  validateConfig(config, root, cve);
  const resources = await inspectNamespace(run, options, { platform });
  if (command === 'status') {
    log(resources.containers.length ? 'dip-local-full services:' : 'No dip-local-full containers; stored volumes, if any, are preserved.');
    for (const item of resources.containers) log(`${item.Config.Labels['com.docker.compose.service']}: ${item.State.Status}`);
    return;
  }
  if (command === 'stop') {
    const ids = resources.containers.filter(item => item.State.Running).map(item => item.Id);
    if (ids.length) await run(['container', 'stop', '--time', '30', ...ids], { ...options, timeout: 90_000 });
    log('dip-local-full stopped; containers, databases, volumes, networks and images preserved.');
    return;
  }
  checkIgnores(root);
  const secret = getSecret(root, { mustExist: resources.containers.length > 0 || resources.volumes.length > 0 });
  log('Starting detached dip-local-full (up/build timeout: 600 seconds).');
  await run(composeArguments(root, ['up', ...(flags.includes('--build') ? ['--build'] : []), '-d'], cve),
    { ...options, env: composeEnvironment(options.env, secret, cve), timeout: 600_000 });
  log('Detached stand started at http://127.0.0.1:8080. Register a new local account; use status to inspect service state.');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  localStand(process.argv.slice(2)).catch(error => {
    // Only our fixed diagnostics are public; raw exceptions may contain private data.
    console.error(error instanceof StandError ? error.message :
      'Local stand refused. Check configuration, secret permissions and Docker availability. No cleanup was attempted.');
    process.exitCode = 1;
  });
}
