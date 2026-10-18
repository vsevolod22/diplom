import * as fs from 'node:fs';
import { execFile } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dockerEnvironment, loadCveActivation, validateCveRelease, declaredBindMatches } from './local-stand.mjs';
import { writeExclusive, syncDirectory } from './setup-local-cve.mjs';
import { PUBLIC_IMAGE_COMMANDS, PUBLIC_IMAGE_TMPFS, publicImageCveConfig } from './public-image-stand-profile.mjs';

export const PROJECT = 'dip-public-images';
export const LABEL = 'org.diplom.public-image-stand';
export const IMAGE_LABEL = 'org.diplom.public-image-project';
export const ORIGIN = 'http://127.0.0.1:8081';
export const STATE = '.local-public-images';
export const CONFIG_SECRET = '0'.repeat(96);
const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const SERVICES = ['auth-volume-init', 'scan-volume-init', 'egress', 'worker', 'api', 'web'];
const VOLUMES = ['auth_accounts', 'scan_ledger'];
const NETWORKS = ['auth_internal', 'scan_internal', 'registry_uplink', 'web_edge'];
const FILES = { egress: 'gateway/Dockerfile', worker: 'worker.Dockerfile', api: 'api.Dockerfile', web: 'stand.Dockerfile' };
const CONNECTIONS = { 'auth-volume-init': [], 'scan-volume-init': [], egress: ['scan_internal', 'registry_uplink'],
  worker: ['scan_internal'], api: ['auth_internal', 'scan_internal'], web: ['auth_internal', 'web_edge'] };
const STORAGE = { 'auth-volume-init': { '/data': 'auth_accounts' }, 'scan-volume-init': { '/data': 'scan_ledger' },
  egress: {}, worker: { '/data': 'scan_ledger' }, api: { '/auth': 'auth_accounts', '/data': 'scan_ledger' }, web: {} };
const COMMANDS = { ...PUBLIC_IMAGE_COMMANDS, 'auth-volume-init': ['chown', '65532:65532', '/data'],
  'scan-volume-init': ['chown', '65532:65532', '/data'], egress: ['python', '-I', 'proxy.py'], web: ['nginx', '-g', 'daemon off;'] };
const ENTRYPOINTS = { api: ['docker-entrypoint.sh'], worker: ['docker-entrypoint.sh'], web: ['/docker-entrypoint.sh'] };
const CVE_KEYS = ['version', 'release', 'manifestDigest', 'artifactSha256', 'publicKeySha256'];
const USAGE = 'Usage: node scripts/public-image-stand.mjs up [--build] [--isolated] | status | stop | reconcile-build-only --ack-no-services | reconcile-network-only --ack-no-services | reconcile-running-build-only --ack-build-failed-before-start | recover-build-and-redeploy --ack-unavailable-prior-images | resume-recover-build-and-redeploy --ack-pre-lifecycle-only --audit redeploy-<32hex> | check-recover-created-drain --audit redeploy-<32hex> --helper-id <64hex> | continue-recover-created-drain --ack-created-drain-only --audit redeploy-<32hex> --helper-id <64hex> | check-recover-started-drain --audit redeploy-<32hex> --helper-id <64hex> | continue-recover-started-drain --ack-started-drain-only --audit redeploy-<32hex> --helper-id <64hex> | check-recover-backup-copy --audit redeploy-<32hex> --helper-id <64hex> | continue-recover-backup-copy --ack-quiescent-backup-transfer --audit redeploy-<32hex> --helper-id <64hex>';
const RECONCILE_GUARD = '.reconcile-build-only.lock';
const NETWORK_GUARD = '.reconcile-network-only.lock';
const NETWORK_PAIR = ['auth_internal', 'registry_uplink'];
const NETWORK_OUTCOME = 'PARTIAL_NETWORKS_ONLY_NO_SERVICES';
const RUNNING_GUARD = '.reconcile-running-build-only.lock';
const REDEPLOY_GUARD = '.recover-build-and-redeploy.lock';
const REDEPLOY_ACK = '--ack-unavailable-prior-images';
const REDEPLOYS = 'redeployments';
const RECOVERY_GUARDS = [RECONCILE_GUARD, NETWORK_GUARD, RUNNING_GUARD, REDEPLOY_GUARD];
const RUNNING_ACK = '--ack-build-failed-before-start';
const RUNNING_OUTCOME = 'RUNNING_BUILD_ONLY_NO_LIFECYCLE_SUBMITTED';
const HISTORY = 'reconciliations';
const BUILD_PHASE = 'build-pull-start-outcome-unconfirmed';
const IMAGE_ID = /^sha256:[a-f0-9]{64}(?![\s\S])/;
const HEX_SHA = /^[a-f0-9]{64}(?![\s\S])/;
const sha = value => createHash('sha256').update(value).digest('hex');
class IsolatedError extends Error {}
class RecoveryRefusal extends IsolatedError {
  constructor(reason){super('Recovery guard refused; details withheld.');this.reason=/^[A-Z][A-Z0-9_]{1,95}$/.test(reason)?reason:'INVALID_INTERNAL_DIAGNOSTIC';}
}
function recoverySafe(ok,reason){if(!ok)throw new RecoveryRefusal(reason);}
function recoverySync(reason,work){try{return work();}catch(e){if(e instanceof RecoveryRefusal||e instanceof IsolatedDockerFailure)throw e;throw new RecoveryRefusal(reason);}}
async function recoveryStep(reason,work){try{return await work();}catch(e){if(e instanceof RecoveryRefusal||e instanceof IsolatedDockerFailure)throw e;throw new RecoveryRefusal(reason);}}
class IsolatedDockerFailure extends IsolatedError {
  constructor(category) { super(`Isolated Docker command failed; failure=${category}; output withheld.`); this.category = category; }
}
const IMAGE_EVIDENCE = {
  runtime: { prefix: 'runtime-image-', reason: 'RUNTIME_IMAGE_METADATA_UNAVAILABLE' },
  pinned: { prefix: 'proof-pinned-image-', reason: 'PINNED_IMAGE_METADATA_UNAVAILABLE' },
  selected: { prefix: 'selected-image-', reason: 'SELECTED_IMAGE_METADATA_UNAVAILABLE' },
};
class IsolatedImageEvidenceFailure extends IsolatedError {
  constructor(role, scope) {
    safe(SERVICES.includes(role) && Object.hasOwn(IMAGE_EVIDENCE, scope));
    const { prefix, reason } = IMAGE_EVIDENCE[scope], checkpoint = prefix + role;
    super(`Isolated image evidence unavailable; checkpoint=${checkpoint}; reason=${reason}. No tag/container-config fallback; no automatic recovery.`);
    this.checkpoint = checkpoint; this.reason = reason;
  }
}
async function imageEvidence(run, options, reference, role, scope) {
  try { return await run(['image', 'inspect', reference], options); }
  catch (error) {
    if (error instanceof IsolatedDockerFailure && error.category === 'image') throw new IsolatedImageEvidenceFailure(role, scope);
    throw error;
  }
}
function dockerCategory(error, stdout = '', stderr = '') {
  const bounded = value => typeof value === 'string' ? `${value.slice(0, 32768)}\n${value.slice(-32768)}` : '';
  const text = `${bounded(stderr)}\n${bounded(stdout)}`.toLowerCase();
  if (error?.killed) return 'timeout';
  if (error?.code === 'ENOENT' || /cannot connect to the docker daemon|is the docker daemon running/.test(text)) return 'docker_unavailable';
  if (/address pools.*fully subnetted|non-overlapping.*address pool|pool overlaps|address pool.*exhaust/.test(text)) return 'network_pool';
  if (error?.code === 'EAGAIN' || /no space left on device|cannot allocate memory|out of memory|insufficient resources|resource temporarily unavailable|not enough memory/.test(text)) return 'resources';
  if (/is unhealthy|dependency failed to start|healthcheck.*failed|container.*exited/.test(text)) return 'runtime_health';
  if (/no such image|pull access denied|manifest unknown|failed to resolve.*(metadata|reference)|image.*not found/.test(text)) return 'image';
  return 'unclassified';
}
// Stand-owned adapter: classification is a diagnostic hint, NEVER recovery
// authority. Raw errors/stdout/stderr/cmd/cause are not retained on rejection.
export function runIsolatedDocker(args, { root, env, timeout = 30_000 }, execute = execFile) {
  return new Promise((resolveOutput, reject) => {
    try {
      execute('docker', args, { cwd: root, env, timeout, killSignal: 'SIGKILL', maxBuffer: 16 * 1024 * 1024, encoding: 'utf8' },
        (error, stdout, stderr) => error ? reject(new IsolatedDockerFailure(dockerCategory(error, stdout, stderr))) : resolveOutput(stdout));
    } catch (error) { reject(new IsolatedDockerFailure(dockerCategory(error))); }
  });
}
function safe(ok, message = 'Isolated qualification stand refused unsafe configuration or namespace collision.') {
  if (!ok) throw new IsolatedError(message);
}
const equal = (a, b) => JSON.stringify(stable(a)) === JSON.stringify(stable(b));
function stable(value) {
  return Array.isArray(value) ? value.map(stable) : value && typeof value === 'object' ?
    Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
}
const sorted = values => [...(values ?? [])].sort();
const keys = (value, names) => equal(sorted(Object.keys(value ?? {})), sorted(names));
const neutral = value => value === undefined || value === null || value === false || value === 0 || value === '' ||
  (Array.isArray(value) ? value.length === 0 : typeof value === 'object' && Object.keys(value).length === 0);
const owned = labels => labels?.[LABEL] === 'v1' && labels?.['com.docker.compose.project'] === PROJECT;
const imageOwned = image => image.Config?.Labels?.[LABEL] === 'v1' && image.Config.Labels[IMAGE_LABEL] === PROJECT;
const namespaced = name => name === PROJECT || name.startsWith(`${PROJECT}-`) || name.startsWith(`${PROJECT}_`);
const serviceOf = item => item.Config?.Labels?.['com.docker.compose.service'];
const metadata = cve => cve === null ? null : Object.fromEntries(CVE_KEYS.map(key => [key, cve[key]]));

export function expectedEnvironment(service, cve = null, secret = CONFIG_SECRET) {
  const vuln = cve ? { SCAN_VULN_ENABLED: 'true', SCAN_VULN_RELEASE_DIR: '/opt/release',
    SCAN_VULN_MANIFEST_DIGEST: cve.manifestDigest, SCAN_VULN_ARTIFACT_SHA256: cve.artifactSha256,
    LOCAL_CVE_TRUST_SHA256: cve.publicKeySha256 } : { SCAN_VULN_ENABLED: 'false' };
  if (service === 'worker') return { SCAN_LEDGER_PATH: '/data/ledger.sqlite', SCAN_WORKER_READY_PATH: '/data/worker.ready',
    TRIVY_CACHE_DIR: '/tmp/trivy', ...vuln };
  if (service !== 'api') return {};
  return { SCAN_BIND_ADDRESS: '0.0.0.0', PORT: '3001', SCAN_JWT_SECRET: secret, SCAN_JWT_ISSUER: PROJECT,
    SCAN_JWT_AUDIENCE: PROJECT, AUTH_DB_PATH: '/auth/auth.sqlite', AUTH_ORIGIN: ORIGIN,
    AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOWED_USER_IDS: '', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true',
    SCAN_LEDGER_PATH: '/data/ledger.sqlite', SCAN_WORKER_READY_PATH: '/data/worker.ready', ...vuln,
    LLM_ENABLED: 'false', LLM_ROUTING_APPROVED: 'false', LLM_QUOTA_ENABLED: 'false', LLM_HISTORY_ENABLED: 'false' };
}
function cveBinds(service, cve) {
  if (!cve || !['api', 'worker'].includes(service)) return [];
  return [{ type: 'bind', source: cve.releaseHostDir, target: '/opt/release', read_only: true, bind: { create_host_path: false } },
    { type: 'bind', source: cve.publicKeyPath, target: '/opt/local-db-trust/public.pem', read_only: true, bind: { create_host_path: false } },
    ...(service === 'worker' ? [{ type: 'bind', source: join(cve.releaseHostDir, 'db'), target: '/tmp/trivy/db', read_only: true,
      bind: { create_host_path: false } }] : [])];
}
export function cveOverlay(cve) {
  safe(cve !== null);
  return { services: Object.fromEntries(['api', 'worker'].map(name => [name, {
    environment: Object.fromEntries(Object.entries(expectedEnvironment(name, cve)).filter(([key]) =>
      key.startsWith('SCAN_VULN_') || key === 'LOCAL_CVE_TRUST_SHA256')), volumes: cveBinds(name, cve),
  }])) };
}

// Independent normative model; never infer policy from a potentially modified Compose file.
export function expectedConfig(root, cve = null) {
  const config = { name: PROJECT, services: {}, volumes: {}, networks: {} };
  for (const name of SERVICES) {
    const init = name.endsWith('volume-init');
    const memory = init ? 67108864 : name === 'worker' ? 4294967296 : name === 'api' ? 536870912 : 268435456;
    const item = { image: init ? 'busybox:1.37.0' : `${PROJECT}-${name}:local`, labels: { [LABEL]: 'v1' },
      read_only: true, user: init ? '0:0' : name === 'web' ? '101:101' : '65532:65532',
      cap_drop: ['ALL'], security_opt: ['no-new-privileges:true'], mem_limit: String(memory), memswap_limit: String(memory),
      cpus: init ? 0.25 : 1, pids_limit: init ? 16 : 128, restart: init ? 'no' : 'unless-stopped' };
    if (init) { item.cap_add = ['CHOWN']; item.network_mode = 'none'; }
    else {
      item.build = { context: root, dockerfile: `server/deploy/${FILES[name]}`, labels: { [LABEL]: 'v1', [IMAGE_LABEL]: PROJECT } };
      item.networks = Object.fromEntries(CONNECTIONS[name].map(key => [key, null]));
    }
    if (COMMANDS[name]) item.command = [...COMMANDS[name]];
    if (name === 'worker') item.tmpfs = [...PUBLIC_IMAGE_TMPFS];
    if (name === 'api') item.tmpfs = [PUBLIC_IMAGE_TMPFS[0]];
    if (name === 'web') item.tmpfs = ['/tmp:rw,noexec,nosuid,uid=101,gid=101,size=16m'];
    const env = expectedEnvironment(name, cve);
    if (Object.keys(env).length) item.environment = env;
    const mounts = [...Object.entries(STORAGE[name]).map(([target, source]) => ({ type: 'volume', source, target })), ...cveBinds(name, cve)];
    if (mounts.length) item.volumes = mounts;
    if (name === 'worker') item.depends_on = { egress: { condition: 'service_started' }, 'scan-volume-init': { condition: 'service_completed_successfully' } };
    if (name === 'api') {
      item.depends_on = { 'auth-volume-init': { condition: 'service_completed_successfully' }, 'scan-volume-init': { condition: 'service_completed_successfully' },
        egress: { condition: 'service_started' }, worker: { condition: 'service_started' } };
      item.healthcheck = { test: ['CMD', 'node', '-e', "fetch('http://127.0.0.1:3001/api/v1/auth/me').then(r=>process.exit(r.status===401?0:1)).catch(()=>process.exit(1))"],
        interval: '5s', timeout: '3s', retries: 12 };
    }
    if (name === 'web') { item.depends_on = { api: { condition: 'service_healthy' } };
      item.ports = [{ host_ip: '127.0.0.1', published: '8081', target: 8080, protocol: 'tcp' }]; }
    config.services[name] = item;
  }
  for (const name of VOLUMES) config.volumes[name] = { name: `${PROJECT}_${name}`, labels: { [LABEL]: 'v1' } };
  for (const name of NETWORKS) config.networks[name] = { name: `${PROJECT}_${name}`, labels: { [LABEL]: 'v1' },
    ...(name.endsWith('_internal') ? { internal: true } : {}) };
  return config;
}
function normalizedConfig(config) {
  const copy = structuredClone(config);
  for (const section of ['volumes', 'networks']) for (const value of Object.values(copy[section] ?? {})) {
    if (value.internal === false) delete value.internal;
    if (value.driver === (section === 'volumes' ? 'local' : 'bridge')) delete value.driver;
    if (section === 'networks' && value.ipam !== null && typeof value.ipam === 'object' &&
      !Array.isArray(value.ipam) && keys(value.ipam, [])) delete value.ipam;
  }
  for (const spec of Object.values(copy.services ?? {})) {
    if (spec.entrypoint === null) delete spec.entrypoint;
    for (const key of ['mem_limit', 'memswap_limit']) if (spec[key] !== undefined) spec[key] = String(spec[key]);
    for (const [key, value] of Object.entries(spec.networks ?? {})) {
      safe(value === null || (typeof value === 'object' && Object.entries(value).every(([k, v]) => k === 'priority' && v === 0)));
      spec.networks[key] = null;
    }
    for (const dependency of Object.values(spec.depends_on ?? {})) {
      if (dependency.required === true) delete dependency.required;
      if (dependency.restart === false) delete dependency.restart;
    }
    for (const port of spec.ports ?? []) if (port.mode === 'ingress') delete port.mode;
    for (const mount of spec.volumes ?? []) {
      if (mount.type === 'bind' && mount.bind && keys(mount.bind, [])) mount.bind.create_host_path = false;
      if (mount.type === 'volume' && equal(mount.volume, {})) delete mount.volume;
      if (mount.type === 'volume' && mount.read_only === false) delete mount.read_only;
    }
  }
  return copy;
}
export function validateConfig(config, root, cve = null, images = null) {
  const expected = expectedConfig(root, cve);
  if (images) {
    safe(keys(images, SERVICES));
    for (const name of SERVICES) { validateImage(images[name], name); expected.services[name].image = images[name].Id; }
  }
  safe(equal(normalizedConfig(config), expected), 'Isolated Compose configuration differs from the fixed qualification policy.');
}
export function composeArguments(root, args, cve = null, pinned = false) {
  return ['compose', '--env-file', '/dev/null', '-p', PROJECT, '-f', join(root, 'server/deploy/compose.public-images.yaml'),
    ...(cve ? ['-f', join(root, STATE, 'compose.cve.json')] : []),
    ...(pinned ? ['-f', join(root, STATE, 'compose.images.json')] : []), ...args];
}
function composeEnv(env, secret = CONFIG_SECRET) { return Object.freeze({ ...env, SCAN_JWT_SECRET: secret }); }
async function requireLocalEngine(run, options) {
  const env = options.env;
  const endpoint = env.DOCKER_HOST && !env.DOCKER_CONTEXT ? env.DOCKER_HOST : JSON.parse(await run([
    'context', 'inspect', ...(env.DOCKER_CONTEXT ? [env.DOCKER_CONTEXT] : []), '--format', '{{json .Endpoints.docker.Host}}',
  ], options));
  safe(typeof endpoint === 'string' && /^unix:\/\/\/[^\s\0]+(?![\s\S])/.test(endpoint),
    'Isolated LOCAL qualification requires a local unix:// Docker endpoint; remote/TCP/SSH contexts are refused.');
  // Context resolution is client metadata only. Every subsequent engine call,
  // including Compose subprocesses, uses this literal endpoint, not a selector.
  const bound = { ...env, DOCKER_HOST: endpoint };
  for (const key of ['DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']) delete bound[key];
  return Object.freeze({ ...options, env: Object.freeze(bound) });
}

function privateDirectory(path) {
  const s = fs.lstatSync(path);
  safe(s.isDirectory() && !s.isSymbolicLink() && s.uid === process.getuid() && (s.mode & 0o7777) === 0o700,
    'Unsafe isolated state directory; expected owned non-symlink mode 0700.');
  return s;
}
function exists(path) { try { fs.lstatSync(path); return true; } catch (e) { if (e.code === 'ENOENT') return false; throw e; } }
function privateRead(path, max = 16384, publicSource = false) {
  const before = fs.lstatSync(path);
  safe(before.isFile() && !before.isSymbolicLink() && before.nlink === 1 && before.uid === process.getuid() &&
    (publicSource ? (before.mode & 0o022) === 0 : (before.mode & 0o7777) === 0o600) &&
    before.size > 0 && before.size <= max, 'Unsafe isolated state file.');
  const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const opened = fs.fstatSync(fd);
    safe(opened.dev === before.dev && opened.ino === before.ino && opened.size === before.size);
    const buffer = Buffer.alloc(max + 1); let total = 0, count;
    while (total < buffer.length && (count = fs.readSync(fd, buffer, total, buffer.length - total, null)) > 0) total += count;
    const after = fs.fstatSync(fd);
    safe(total === before.size && after.size === before.size && after.mtimeMs === before.mtimeMs && after.ctimeMs === before.ctimeMs);
    return buffer.subarray(0, total).toString('utf8');
  } finally { fs.closeSync(fd); }
}
export function checkIgnores(root) {
  for (const file of Object.values(FILES)) safe(!exists(join(root, 'server/deploy', `${file}.dockerignore`)),
    'Dockerfile-specific ignore overrides are not supported; preserve the root private-state ignore policy.');
  for (const file of ['.gitignore', '.dockerignore']) {
    const lines = privateRead(join(root, file), 131072, true).split(/\r?\n/).map(s => s.trim());
    const at = lines.findLastIndex(line => line === `${STATE}/` || line === `/${STATE}/`);
    // Conservative: a later negation could expose files to Git or the web COPY . . build.
    safe(at >= 0 && !lines.slice(at + 1).some(line => line.startsWith('!')),
      'Before launch, coordinator must append .local-public-images/ to BOTH .gitignore and .dockerignore (after any negations).');
  }
}
function readProfile(root) {
  const dir = join(root, STATE);
  if (!exists(dir)) return undefined;
  privateDirectory(dir);
  const path = join(dir, 'profile.json');
  if (!exists(path)) return undefined;
  const bytes = privateRead(path), value = JSON.parse(bytes);
  safe(keys(value, ['version', 'project', 'cve']) && value.version === 1 && value.project === PROJECT && equal(value, { version: 1, project: PROJECT, cve: value.cve }));
  const cve = publicImageCveConfig(root, value.cve);
  safe(bytes === JSON.stringify({ version: 1, project: PROJECT, cve: metadata(cve) }), 'Noncanonical isolated profile state.');
  return { cve };
}
export function loadSecret(root, mustExist, random = randomBytes) {
  const dir = join(root, STATE); privateDirectory(dir);
  const path = join(dir, 'scan-jwt');
  if (!exists(path)) {
    safe(!mustExist, 'Existing isolated JWT missing; refusing replacement or rotation.');
    writeExclusive(path, random(48).toString('hex'), 0o600); syncDirectory(dir);
  }
  const secret = privateRead(path, 96);
  safe(/^[a-f0-9]{96}$/.test(secret), 'Invalid isolated JWT; refusing rotation.');
  return secret;
}
function acquireLock(root) {
  const dir = join(root, STATE), path = join(dir, '.operation.lock');
  privateDirectory(dir);
  safe(!exists(path) && RECOVERY_GUARDS.every(name => !exists(join(dir, name))), 'Isolated operation locked/HOLD. Never remove a stale lock or uncertainty marker automatically; reviewed reconciliation required.');
  try { assertReconciliationHistory(root); }
  catch { throw new IsolatedError('Incomplete or unsafe isolated reconciliation history/HOLD; ordinary lifecycle cannot finish it.'); }
  fs.mkdirSync(path, { mode: 0o700 }); const identity = privateDirectory(path); syncDirectory(dir);
  const verify = () => { const current = privateDirectory(path); safe(current.dev === identity.dev && current.ino === identity.ino, 'Isolated operation lock identity changed/HOLD.'); };
  return { path, verify, release() { verify(); fs.rmdirSync(path); syncDirectory(dir); } };
}
function environment(entries) {
  safe(Array.isArray(entries));
  const pairs = entries.map(s => { safe(typeof s === 'string' && s.includes('=')); const i = s.indexOf('='); return [s.slice(0, i), s.slice(i + 1)]; });
  safe(new Set(pairs.map(([key]) => key)).size === pairs.length);
  return Object.fromEntries(pairs);
}
const SYSTEM_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
function imagePolicy(name) {
  const init = name.endsWith('volume-init');
  return { entrypoint: ENTRYPOINTS[name] ?? null,
    directory: ['api', 'worker'].includes(name) ? '/app/server/api' : name === 'egress' ? '/opt/gateway' : name === 'web' ? '/' : '',
    user: init ? '' : name === 'web' ? '101:101' : '65532:65532',
    command: init ? ['sh'] : name === 'api' ? ['node', '--import', 'tsx', 'src/main.ts'] :
      name === 'worker' ? ['node', '--import', 'tsx', 'src/worker/worker.main.ts'] : COMMANDS[name],
    ports: name === 'web' ? { '80/tcp': {}, '8080/tcp': {} } : {}, stop: name === 'web' ? 'SIGQUIT' : '' };
}
export function validateImage(image, name) {
  safe(SERVICES.includes(name) && /^sha256:[a-f0-9]{64}(?![\s\S])/.test(image?.Id) && image.Os === 'linux' &&
    (FILES[name] ? imageOwned(image) : image.RepoTags?.includes('busybox:1.37.0')), 'Untrusted isolated image identity.');
  const policy = imagePolicy(name), c = image.Config, env = environment(c.Env ?? []);
  validateBaseEnvironment(env, name);
  // Version/hash strings are inert metadata, not image authenticity evidence.
  safe(equal(c.Entrypoint ?? null, policy.entrypoint) && equal(c.Cmd, policy.command) && c.User === policy.user &&
    c.WorkingDir === policy.directory && equal(c.ExposedPorts ?? {}, policy.ports) && (c.StopSignal ?? '') === policy.stop &&
    allowedArgsEscaped(name, c.ArgsEscaped) &&
    ['Healthcheck', 'OnBuild', 'Volumes', 'Shell', 'Tty', 'OpenStdin', 'StdinOnce', 'NetworkDisabled', 'StopTimeout']
      .every(key => neutral(c[key])), 'Isolated image execution defaults violate the independent policy.');
  return env;
}
function validateBaseEnvironment(env, name) {
  const metadataRules = { PATH: value => value === SYSTEM_PATH ||
    (name === 'egress' && value === `/usr/local/bin:${SYSTEM_PATH}`) };
  if (['api', 'worker'].includes(name)) Object.assign(metadataRules, {
    NODE_VERSION: v => v === '24.11.1', YARN_VERSION: v => v === '1.22.22',
  });
  if (name === 'egress') Object.assign(metadataRules, { LANG: v => v === 'C.UTF-8', PYTHON_VERSION: v => v === '3.13.7',
    GPG_KEY: v => /^[a-fA-F0-9]{40}$/.test(v), PYTHON_SHA256: v => /^[a-f0-9]{64}$/.test(v) });
  if (name === 'web') Object.assign(metadataRules, { NGINX_VERSION: v => v === '1.27.5',
    NJS_VERSION: v => /^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v),
    NJS_RELEASE: v => /^\d{1,4}$/.test(v), PKG_RELEASE: v => /^\d{1,4}$/.test(v), DYNPKG_RELEASE: v => /^\d{1,4}$/.test(v) });
  const required = ['PATH', ...(['api', 'worker'].includes(name) ? ['NODE_VERSION', 'YARN_VERSION'] :
    name === 'egress' ? ['PYTHON_VERSION', 'GPG_KEY', 'PYTHON_SHA256'] : name === 'web' ? ['NGINX_VERSION'] : [])];
  safe(required.every(key => Object.hasOwn(env, key)) && Object.entries(env).every(([key, value]) =>
    Object.hasOwn(metadataRules, key) && metadataRules[key](value)), 'Isolated image environment violates the reviewed base-metadata policy.');
}
// On reviewed Linux Node/Python images this boolean is inert metadata. It does not
// authorize string/shell commands, entrypoint overrides, or non-Linux images.
function allowedArgsEscaped(name, value) {
  return value === undefined || value === false || (['api', 'worker', 'egress'].includes(name) && value === true);
}
function tmpfs(values) {
  return Object.fromEntries(values.map(value => { const i = value.indexOf(':'); return [value.slice(0, i), sorted(value.slice(i + 1).split(','))]; }));
}
const MASKED = ['/proc/asound', '/proc/acpi', '/proc/interrupts', '/proc/kcore', '/proc/keys', '/proc/latency_stats',
  '/proc/timer_list', '/proc/timer_stats', '/proc/sched_debug', '/proc/scsi', '/sys/firmware', '/sys/devices/virtual/powercap'];
const READONLY = ['/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger'];
export function validateContainer(item, name, spec, image, config, { platform = process.platform, secret, images } = {}) {
  safe(item.Name === `/${PROJECT}-${name}-1` && owned(item.Config?.Labels) && serviceOf(item) === name);
  safe(image.Id === item.Image && image.Os === 'linux' && (FILES[name] ? imageOwned(image) : image.RepoTags?.includes('busybox:1.37.0')));
  safe(item.Config.Image === spec.image || item.Config.Image === item.Image);
  if (images) safe(item.Image === images[name].Id && item.Config.Image === images[name].Id,
    'Isolated start did not consume the validated immutable image identity.');
  validateRuntimeContainer(item, name, spec, config, { platform, secret }, validateImage(image, name));
}
// Independent container policy, also used ONLY by the acknowledged replacement
// transaction when prior image metadata is unavailable. This does not certify it.
function validateRuntimeContainer(item, name, spec, config, { platform = process.platform, secret } = {}, baseEnv) {
  safe(SERVICES.includes(name) && item.Name === `/${PROJECT}-${name}-1` && owned(item.Config?.Labels) && serviceOf(item) === name);
  const c = item.Config, h = item.HostConfig, policy = imagePolicy(name);
  const expectedEnv = { ...baseEnv, ...(spec.environment ?? {}) };
  if (name === 'api') {
    const actual = environment(c.Env).SCAN_JWT_SECRET;
    safe(typeof actual === 'string' && /^[a-f0-9]{96}$/.test(actual));
    expectedEnv.SCAN_JWT_SECRET = secret ?? actual; // status/stop never open the JWT file.
  }
  safe(equal(environment(c.Env), expectedEnv) && equal(c.Cmd, spec.command) &&
    equal(c.Entrypoint ?? null, ENTRYPOINTS[name] ?? null) &&
    c.User === spec.user && c.WorkingDir === policy.directory && !c.Tty && !c.OpenStdin && !c.StdinOnce &&
    !c.NetworkDisabled && !c.AttachStdin && allowedArgsEscaped(name, c.ArgsEscaped) && !c.Domainname &&
    (c.StopSignal ?? '') === policy.stop && ['', 'docker-default'].includes(item.AppArmorProfile ?? '') && !item.ProcessLabel && !item.MountLabel,
  'Isolated container command, credentials, entrypoint or image identity drift.');
  const expectedNetworks = CONNECTIONS[name].map(n => `${PROJECT}_${n}`);
  safe(keys(item.NetworkSettings?.Networks, expectedNetworks.length ? expectedNetworks : ['none']));
  const cap = value => value.replace(/^CAP_/, '');
  safe(h && h.Privileged === false && h.AutoRemove === false && h.ReadonlyRootfs === true &&
    equal(sorted((h.CapDrop ?? []).map(cap)), ['ALL']) && equal(sorted((h.CapAdd ?? []).map(cap)), sorted(spec.cap_add)) &&
    equal((h.SecurityOpt ?? []).map(v => v === 'no-new-privileges' ? 'no-new-privileges:true' : v), spec.security_opt) &&
    (expectedNetworks.length ? expectedNetworks.includes(h.NetworkMode) : h.NetworkMode === 'none'));
  const bindings = name === 'web' ? { '8080/tcp': [{ HostIp: '127.0.0.1', HostPort: '8081' }] } : {};
  const exposed = policy.ports;
  safe(equal(h.PortBindings ?? {}, bindings) && h.PublishAllPorts === false && equal(c.ExposedPorts ?? {}, exposed));
  if (item.State.Running) safe(equal(item.NetworkSettings.Ports ?? {}, Object.fromEntries(Object.keys(exposed).map(key => [key, bindings[key] ?? null]))));
  safe(equal(tmpfs(Object.entries(h.Tmpfs ?? {}).map(([key, val]) => `${key}:${val}`)), tmpfs(spec.tmpfs ?? [])) &&
    equal(sorted(h.MaskedPaths), sorted(MASKED)) && equal(sorted(h.ReadonlyPaths), sorted(READONLY)), 'Isolated tmpfs or kernel path isolation drift.');
  const fixed = { Memory: Number(spec.mem_limit), MemorySwap: Number(spec.memswap_limit), NanoCpus: spec.cpus * 1e9, PidsLimit: spec.pids_limit,
    MemoryReservation: 0, CpuShares: 0, CpuPeriod: 0, CpuQuota: 0, CpuRealtimePeriod: 0, CpuRealtimeRuntime: 0,
    CpusetCpus: '', CpusetMems: '', OomScoreAdj: 0, ShmSize: 67108864, IpcMode: 'private', PidMode: '', UTSMode: '', UsernsMode: '',
    CgroupParent: '', CgroupnsMode: 'private', Runtime: 'runc' };
  safe(Object.entries(fixed).every(([key, value]) => h[key] === value), 'Isolated container resource/namespace drift.');
  safe([null, -1].includes(h.MemorySwappiness) && [null, false].includes(h.OomKillDisable) &&
    equal(h.RestartPolicy, { Name: spec.restart, MaximumRetryCount: 0 }) && equal(h.ConsoleSize, [0, 0]) &&
    ['json-file', 'local'].includes(h.LogConfig?.Type) && equal(h.LogConfig.Config ?? {}, {}));
  const handled = new Set([...Object.keys(fixed), 'Privileged', 'AutoRemove', 'ReadonlyRootfs', 'CapDrop', 'CapAdd', 'SecurityOpt', 'NetworkMode',
    'PortBindings', 'PublishAllPorts', 'Tmpfs', 'MaskedPaths', 'ReadonlyPaths', 'MemorySwappiness', 'OomKillDisable', 'RestartPolicy',
    'ConsoleSize', 'LogConfig', 'Mounts']);
  safe(Object.entries(h).every(([key, value]) => handled.has(key) || neutral(value)), 'Unexpected isolated container authority.');
  const desired = spec.volumes ?? [], observed = item.Mounts ?? [], declarations = h.Mounts ?? [];
  safe(declarations.length === desired.length && equal(sorted(observed.filter(m => m.Type !== 'tmpfs').map(m => m.Destination)), sorted(desired.map(m => m.target))));
  safe(observed.filter(m => m.Type === 'tmpfs').every(m => (spec.tmpfs ?? []).some(s => s.startsWith(`${m.Destination}:`))));
  for (const mount of desired) {
    const declared = declarations.filter(m => m.Target === mount.target), actual = observed.filter(m => m.Destination === mount.target);
    safe(declared.length === 1 && actual.length === 1);
    const d = declared[0], a = actual[0];
    safe(!a.SubPath && (!a.Propagation || a.Propagation === 'rprivate'));
    if (mount.type === 'volume') safe(d.Type === 'volume' && d.Source === `${PROJECT}_${mount.source}` && !d.ReadOnly &&
      Object.values(d.VolumeOptions ?? {}).every(neutral) && a.Type === 'volume' && a.Name === d.Source && a.RW === true);
    else safe(a.Type === 'bind' && a.RW === false && neutral(d.VolumeOptions) && declaredBindMatches(d, a, mount, platform));
    if (mount.type === 'volume') safe(neutral(d.BindOptions));
    safe(Object.entries(d).every(([key, value]) => ['Type', 'Source', 'Target', 'ReadOnly', 'VolumeOptions', 'BindOptions'].includes(key) || neutral(value)));
  }
  const health = spec.healthcheck;
  safe(health ? equal(c.Healthcheck, { Test: health.test, Interval: 5e9, Timeout: 3e9, Retries: 12 }) : c.Healthcheck === undefined);
}

export async function inspectNamespace(run, options, config, extra = {}) {
  const out = { containers: [], volumes: [], networks: [], images: [] }, imageCache = new Map();
  const inspectImage = async (id, role, scope) => {
    if (!imageCache.has(id)) { const values = JSON.parse(await imageEvidence(run, options, id, role, scope)); safe(values.length === 1); imageCache.set(id, values[0]); }
    return imageCache.get(id);
  };
  for (const [kind, destination] of [['container', out.containers], ['volume', out.volumes], ['network', out.networks]]) {
    const format = `{{.${kind === 'container' ? 'Names' : 'Name'}}}\t{{.Label "com.docker.compose.project"}}`;
    const lines = (await run([kind, 'ls', ...(kind === 'container' ? ['--all'] : []), '--format', format], options)).trim().split('\n').filter(Boolean);
    const candidates = lines.map(line => line.split('\t')).filter(([name, project]) => namespaced(name) || project === PROJECT);
    const allowed = kind === 'container' ? SERVICES.map(n => `${PROJECT}-${n}-1`) :
      (kind === 'volume' ? VOLUMES : NETWORKS).map(n => `${PROJECT}_${n}`);
    safe(candidates.every(([name]) => allowed.includes(name)), 'Off-allowlist isolated project/name collision; offending resources not inspected.');
    for (const [name] of candidates) {
      const values = JSON.parse(await run([kind, 'inspect', name], options)); safe(values.length === 1);
      const item = values[0]; safe(owned(kind === 'container' ? item.Config?.Labels : item.Labels), 'Unowned isolated namespace collision.');
      if (kind === 'container') {
        const service = serviceOf(item); safe(SERVICES.includes(service) && name === `${PROJECT}-${service}-1` && /^[a-f0-9]{64}(?![\s\S])/.test(item.Id) &&
          /^sha256:[a-f0-9]{64}(?![\s\S])/.test(item.Image));
        validateContainer(item, service, config.services[service], await inspectImage(item.Image, service, 'runtime'), config, extra);
      } else {
        const names = kind === 'volume' ? VOLUMES : NETWORKS;
        safe(names.some(n => name === `${PROJECT}_${n}`) && item.Name === name && item.Driver === (kind === 'volume' ? 'local' : 'bridge'));
        safe(kind === 'volume' ? neutral(item.Options) : Boolean(item.Internal) === name.endsWith('_internal') &&
          neutral(item.Options) && !item.Attachable && !item.Ingress && !item.EnableIPv6 &&
          (!item.IPAM || (item.IPAM.Driver === 'default' && neutral(item.IPAM.Options))));
      }
      safe(!destination.some(previous => (kind === 'container' ? previous.Id === item.Id : previous.Name === item.Name)));
      destination.push(item);
    }
  }
  for (const network of out.networks) safe(Object.keys(network.Containers ?? {}).every(id =>
    out.containers.some(c => c.Id === id && Object.hasOwn(c.NetworkSettings.Networks, network.Name))), 'Foreign endpoint on isolated network.');
  for (const volume of out.volumes) {
    const ids = (await run(['container', 'ls', '--all', '--filter', `volume=${volume.Name}`, '--format', '{{.ID}}', '--no-trunc'], options)).trim().split('\n').filter(Boolean);
    safe(equal(sorted(ids), sorted(out.containers.filter(c => c.Mounts.some(m => m.Type === 'volume' && m.Name === volume.Name)).map(c => c.Id))),
      'Foreign writer/collision or changed membership on isolated volume.');
  }
  const tags = (await run(['image', 'ls', '--format', '{{.Repository}}:{{.Tag}}'], options)).trim().split('\n').filter(Boolean);
  for (const tag of new Set(tags.filter(name => namespaced(name.split(':')[0])))) {
    const service = Object.keys(FILES).find(n => tag === `${PROJECT}-${n}:local`);
    safe(service);
    validateImage(await inspectImage(tag, service, 'selected'), service); out.images.push(tag);
  }
  return out;
}

async function selectedImages(run, options, config, observe = () => {}) {
  const images = {}, cache = new Map();
  for (const name of SERVICES) {
    observe(name);
    const tag = config.services[name].image;
    if (!cache.has(tag)) {
      const values = JSON.parse(await run(['image', 'inspect', tag], options));
      safe(values.length === 1 && values[0].RepoTags?.includes(tag), 'Missing or substituted isolated image tag.');
      cache.set(tag, values[0]);
    }
    validateImage(cache.get(tag), name);
    images[name] = structuredClone(cache.get(tag));
  }
  return images;
}
function pinImages(root, images) {
  const dir = join(root, STATE), path = join(dir, 'compose.images.json');
  const value = { services: Object.fromEntries(SERVICES.map(name => [name, { image: images[name].Id }])) };
  if (exists(path)) {
    const previous = JSON.parse(privateRead(path));
    safe(keys(previous, ['services']) && keys(previous.services, SERVICES) && Object.values(previous.services).every(spec =>
      keys(spec, ['image']) && /^sha256:[a-f0-9]{64}$/.test(spec.image)), 'Unsafe isolated image-pin overlay.');
  }
  const pending = join(dir, '.compose.images.pending');
  writeExclusive(pending, JSON.stringify(value), 0o600);
  fs.renameSync(pending, path); syncDirectory(dir);
  const bytes = JSON.stringify(value);
  safe(privateRead(path) === bytes);
  return bytes;
}

function directoryIdentity(path) {
  const s = privateDirectory(path);
  return { dev: s.dev, ino: s.ino, uid: s.uid, mode: s.mode };
}
function verifyDirectory(path, identity) { safe(equal(directoryIdentity(path), identity), 'Isolated directory identity changed/HOLD.'); }
function fileStamp(path) {
  const s = fs.lstatSync(path);
  return { dev: s.dev, ino: s.ino, uid: s.uid, mode: s.mode, size: s.size, nlink: s.nlink, mtimeMs: s.mtimeMs, ctimeMs: s.ctimeMs };
}
function captureFile(path, max = 16384, publicSource = false) {
  const stamp = fileStamp(path), bytes = privateRead(path, max, publicSource);
  safe(equal(stamp, fileStamp(path)));
  return { bytes, identity: { dev: stamp.dev, ino: stamp.ino }, verify(at = path) {
    safe(equal(stamp, fileStamp(at)) && privateRead(at, max, publicSource) === bytes, 'Isolated file identity/content changed/HOLD.');
  } };
}
function validateReconciliationSource(bytes, root) {
  // This shipped file is JSON-compatible YAML. Reject env_file/extends or other
  // indirection before asking Compose to parse it or open any referenced file.
  const source = JSON.parse(bytes);
  safe(source.services?.api?.environment?.SCAN_JWT_SECRET === '${SCAN_JWT_SECRET:?Use scripts/public-image-stand.mjs}');
  source.services.api.environment.SCAN_JWT_SECRET = CONFIG_SECRET;
  for (const name of Object.keys(FILES)) {
    safe(source.services?.[name]?.build?.context === '../..'); source.services[name].build.context = root;
  }
  validateConfig(source, root);
}
function canonicalJson(path) {
  const bytes = privateRead(path), value = JSON.parse(bytes);
  safe(bytes === JSON.stringify(value), 'Noncanonical isolated audit record/HOLD.');
  return { bytes, value };
}
function buildMarker(bytes, endpoint) {
  const m = JSON.parse(bytes), recorded = Object.hasOwn(m, 'endpoint');
  const expected = { version: 1, project: PROJECT, command: 'up', phase: BUILD_PHASE, ...(recorded ? { endpoint: m.endpoint } : {}) };
  safe(bytes === JSON.stringify(expected) && (!recorded || (typeof m.endpoint === 'string' &&
    /^unix:\/\/\/[^\s\0]+(?![\s\S])/.test(m.endpoint) && (endpoint === undefined || m.endpoint === endpoint))),
  'Only the exact original build/pull HOLD marker is eligible; recorded endpoints must match.');
  return m;
}
function networkStartMarker(bytes, endpoint) {
  const m = JSON.parse(bytes);
  safe(typeof m.endpoint === 'string' && /^unix:\/\/\/[^\s\0]+(?![\s\S])/.test(m.endpoint) &&
    (endpoint === undefined || m.endpoint === endpoint) && bytes === JSON.stringify({ version: 1, project: PROJECT,
      command: 'up', phase: 'start-outcome-unconfirmed', endpoint: m.endpoint }), 'Only the exact endpoint-bound start HOLD is eligible for network-only reconciliation.');
  return m;
}
function startSubmission(bytes, endpoint) {
  safe(bytes === JSON.stringify({ version: 1, project: PROJECT, phase: 'service-start-submission', endpoint }),
    'Start-submission record is missing, changed or does not match the endpoint.');
}
function ipv4(value) {
  safe(typeof value === 'string' && /^\d{1,3}(?:\.\d{1,3}){3}(?![\s\S])/.test(value));
  const parts = value.split('.'); safe(parts.every(p => Number(p) <= 255 && String(Number(p)) === p));
  return parts.reduce((a, p) => a * 256 + Number(p), 0);
}
function defaultSubnet(config) {
  safe(config && keys(config, Object.keys(config).filter(k => ['Subnet', 'Gateway', 'IPRange', 'AuxiliaryAddresses'].includes(k))) &&
    typeof config.Subnet === 'string' && (config.IPRange === undefined || config.IPRange === '') &&
    equal(config.AuxiliaryAddresses ?? {}, {}));
  const fields = config.Subnet.split('/'); safe(fields.length === 2 && /^(?:[89]|[12]\d|30)$/.test(fields[1]));
  const first = ipv4(fields[0]), size = 2 ** (32 - Number(fields[1])), last = first + size - 1;
  safe(first % size === 0 && ipv4(config.Gateway) === first + 1 &&
    [['10.0.0.0', '10.255.255.255'], ['172.16.0.0', '172.31.255.255'], ['192.168.0.0', '192.168.255.255']]
      .some(([low, high]) => first >= ipv4(low) && last <= ipv4(high)), 'Only dynamically allocated default private IPv4 subnet/gateway pairs are accepted.');
  return { first, last };
}
function emptyOwnNetwork(item, key) { return defaultOwnNetwork(item, key, NETWORK_PAIR); }
function defaultOwnNetwork(item, key, allowedKeys) {
  const labels = item?.Labels;
  safe(allowedKeys.includes(key) && item.Name === `${PROJECT}_${key}` && /^[a-f0-9]{64}(?![\s\S])/.test(item.Id) &&
    item.Driver === 'bridge' && item.Scope === 'local' && item.Internal === key.endsWith('_internal') &&
    (item.EnableIPv4 === undefined || item.EnableIPv4 === true) && item.EnableIPv6 === false &&
    item.Attachable === false && item.Ingress === false && item.ConfigOnly === false &&
    (item.ConfigFrom === undefined || item.ConfigFrom === null || equal(item.ConfigFrom, { Network: '' })) &&
    equal(item.Options ?? {}, {}) && equal(item.Containers, {}) && neutral(item.Peers) && neutral(item.Services),
    'Network-only reconciliation requires an empty default own bridge network.');
  safe(owned(labels) && labels['com.docker.compose.network'] === key &&
    Object.entries(labels).every(([k, v]) => [LABEL, 'com.docker.compose.project', 'com.docker.compose.network'].includes(k) ||
      (k === 'com.docker.compose.version' && typeof v === 'string' && /^\d{1,3}\.\d{1,3}\.\d{1,3}(?:[-+][0-9A-Za-z.-]{1,32})?(?![\s\S])/.test(v)) ||
      (k === 'com.docker.compose.config-hash' && typeof v === 'string' && HEX_SHA.test(v))), 'Unexpected own network labels.');
  safe(item.IPAM?.Driver === 'default' && equal(item.IPAM.Options ?? {}, {}) && keys(item.IPAM, Object.keys(item.IPAM).filter(k => ['Driver', 'Options', 'Config'].includes(k))) &&
    Array.isArray(item.IPAM.Config) && item.IPAM.Config.length === 1);
  defaultSubnet(item.IPAM.Config[0]);
  const fields = new Set(['Name', 'Id', 'Created', 'Driver', 'Scope', 'Internal', 'EnableIPv4', 'EnableIPv6', 'Attachable', 'Ingress',
    'ConfigOnly', 'ConfigFrom', 'Containers', 'Options', 'Labels', 'IPAM', 'Peers', 'Services']);
  safe(Object.entries(item).every(([k, v]) => fields.has(k) || neutral(v)), 'Unexpected own network authority.');
  return { Name: item.Name, Id: item.Id, Driver: 'bridge', Scope: 'local', Internal: item.Internal, EnableIPv4: true, EnableIPv6: false,
    Attachable: false, Ingress: false, ConfigOnly: false, ConfigFrom: { Network: '' }, Containers: {}, Options: {}, Labels: structuredClone(labels),
    IPAM: { Driver: 'default', Options: {}, Config: [{ Subnet: item.IPAM.Config[0].Subnet, Gateway: item.IPAM.Config[0].Gateway }] } };
}
function networkPairSnapshot(networks) {
  safe(keys(networks, NETWORK_PAIR));
  const result = Object.fromEntries(NETWORK_PAIR.map(key => [key, emptyOwnNetwork(networks[key], key)]));
  const [a, b] = NETWORK_PAIR.map(key => defaultSubnet(result[key].IPAM.Config[0]));
  safe(result.auth_internal.Id !== result.registry_uplink.Id && (a.last < b.first || b.last < a.first), 'Own network identities/subnets overlap.');
  return result;
}
async function networkOnlyNamespace(run, options) {
  for (const kind of ['container', 'volume']) {
    const format = `{{.${kind === 'container' ? 'Names' : 'Name'}}}\t{{.Label "com.docker.compose.project"}}`;
    const rows = (await run([kind, 'ls', ...(kind === 'container' ? ['--all'] : []), '--format', format], options)).trim().split('\n').filter(Boolean);
    safe(rows.every(row => { const [name, project] = row.split('\t'); return !namespaced(name) && project !== PROJECT; }),
      'Network-only reconciliation requires ZERO own containers (stopped included) and volumes.');
  }
  const rows = (await run(['network', 'ls', '--format', '{{.Name}}\t{{.Label "com.docker.compose.project"}}'], options)).trim().split('\n').filter(Boolean);
  const candidates = rows.map(row => row.split('\t')).filter(([name, project]) => namespaced(name) || project === PROJECT);
  safe(equal(sorted(candidates.map(([name]) => name)), sorted(NETWORK_PAIR.map(key => `${PROJECT}_${key}`))),
    'Only the exact auth_internal/registry_uplink own pair is eligible; other network details are not inspected.');
  const networks = {};
  for (const key of NETWORK_PAIR) {
    const values = JSON.parse(await run(['network', 'inspect', `${PROJECT}_${key}`], options)); safe(values.length === 1);
    networks[key] = emptyOwnNetwork(values[0], key);
  }
  return networkPairSnapshot(networks);
}
function readImagePins(bytes) {
  const value = JSON.parse(bytes);
  safe(bytes === JSON.stringify(value) && keys(value, ['services']) && keys(value.services, SERVICES) &&
    Object.values(value.services).every(spec => keys(spec, ['image']) && IMAGE_ID.test(spec.image)), 'Invalid own image-pin record.');
  const pins = Object.fromEntries(SERVICES.map(name => [name, value.services[name].image]));
  safe(bytes === JSON.stringify({ services: Object.fromEntries(SERVICES.map(name => [name, { image: pins[name] }])) }), 'Noncanonical start image-pin order.');
  return pins;
}
function runningBuildMarker(bytes, endpoint) {
  const marker = buildMarker(bytes, endpoint);
  safe(Object.hasOwn(marker, 'endpoint'), 'Running-build reconciliation requires the original recorded endpoint.');
  return marker;
}
const controlHash = value => sha(JSON.stringify(stable(value)));
const timestamp = value => typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)(?![\s\S])/.test(value) && Number.isFinite(Date.parse(value));
function runningState(item, role, config) {
  const s = item.State, init = role.endsWith('volume-init');
  safe(s && !s.Restarting && !s.Dead && !s.OOMKilled && neutral(s.Error) && s.ExitCode === 0 &&
    s.Running === !init && s.Status === (init ? 'exited' : 'running') && Number.isSafeInteger(s.Pid) && (init ? s.Pid === 0 : s.Pid > 0) &&
    Number.isSafeInteger(item.RestartCount) && item.RestartCount >= 0 && timestamp(s.StartedAt) && timestamp(s.FinishedAt) &&
    (config.services[role].healthcheck ? s.Health?.Status === 'healthy' && s.Health.FailingStreak === 0 : neutral(s.Health)),
    'Running-build recovery requires healthy running services and successfully exited initializers.');
  return { status: s.Status, pid: s.Pid, startedAt: s.StartedAt, finishedAt: s.FinishedAt,
    restartCount: item.RestartCount, health: s.Health?.Status ?? null };
}
function ownImageReferences(image, role, untagged = false) {
  const tag = `${PROJECT}-${role}:local`;
  safe((untagged && neutral(image.RepoTags) || equal(image.RepoTags, [tag])) &&
    (neutral(image.RepoDigests) || equal(image.RepoDigests, [`${PROJECT}-${role}@${image.Id}`])) &&
    (image.Config.Labels['com.docker.compose.project'] === undefined || image.Config.Labels['com.docker.compose.project'] === PROJECT) &&
    (image.Config.Labels['com.docker.compose.service'] === undefined || image.Config.Labels['com.docker.compose.service'] === role),
    'Running-build image has foreign/mixed references.');
}
async function exactRunningCensus(run, options) {
  // Check the complete name set and project labels BEFORE opening any resource.
  for (const [kind, names] of [['container', SERVICES.map(role => `${PROJECT}-${role}-1`)],
    ['volume', VOLUMES.map(key => `${PROJECT}_${key}`)], ['network', NETWORKS.map(key => `${PROJECT}_${key}`)]]) {
    const format = `{{.${kind === 'container' ? 'Names' : 'Name'}}}\t{{.Label "com.docker.compose.project"}}`;
    const rows = (await run([kind, 'ls', ...(kind === 'container' ? ['--all'] : []), '--format', format], options)).trim().split('\n').filter(Boolean)
      .map(row => row.split('\t')).filter(([name, project]) => namespaced(name) || project === PROJECT);
    safe(equal(sorted(rows.map(([name]) => name)), sorted(names)) && rows.every(row => row.length === 2 && row[1] === PROJECT),
      'Running-build recovery requires the exact complete owned namespace; no unknown resources inspected.');
  }
}
async function runningBuildProof(run, options, root, profile, pins, secret, platform) {
  await exactRunningCensus(run, options);
  const config = expectedConfig(root, profile.cve), images = {}, cache = new Map();
  for (const role of SERVICES) {
    const id = pins[role];
    if (!cache.has(id)) { const values = JSON.parse(await imageEvidence(run, options, id, role, 'pinned')); safe(values.length === 1 && values[0].Id === id); cache.set(id, values[0]); }
    const image = cache.get(id); validateImage(image, role);
    if (FILES[role]) ownImageReferences(image, role, true);
    images[role] = image;
  }
  safe(new Set(Object.keys(FILES).map(role => images[role].Id)).size === 4 && pins['auth-volume-init'] === pins['scan-volume-init']);
  const rendered = JSON.parse(await run(composeArguments(root, ['config', '--format', 'json'], profile.cve, true), { ...options, env: composeEnv(options.env) }));
  validateConfig(rendered, root, profile.cve, images);
  // Never follow a substituted container's arbitrary image ID during inspection.
  const constrained = (args, opts) => {
    if (args[0] === 'image' && args[1] === 'inspect') safe(Object.values(pins).includes(args[2]) || Object.keys(FILES).some(role => args[2] === `${PROJECT}-${role}:local`));
    return run(args, opts);
  };
  const inventory = await inspectNamespace(constrained, options, config, { secret, images, platform });
  safe(inventory.containers.length === 6 && inventory.volumes.length === 2 && inventory.networks.length === 4);
  const containers = {}, volumes = {}, networks = {}, tagImages = {};
  for (const c of inventory.containers) {
    const role = serviceOf(c), sanitized = structuredClone(c.Config);
    sanitized.Env = sanitized.Env.filter(value => !value.startsWith('SCAN_JWT_SECRET='));
    containers[role] = { id: c.Id, image: c.Image, state: runningState(c, role, config),
      controlSha256: controlHash({ Config: sanitized, HostConfig: c.HostConfig, Mounts: c.Mounts, NetworkSettings: c.NetworkSettings }) };
  }
  for (const v of inventory.volumes) {
    const key = v.Name.slice(PROJECT.length + 1);
    safe(v.Scope === 'local' && timestamp(v.CreatedAt) && typeof v.Mountpoint === 'string' && v.Mountpoint.startsWith('/') &&
      v.Labels['com.docker.compose.volume'] === key, 'Running-build volume identity/configuration mismatch.');
    volumes[key] = { createdAt: v.CreatedAt, controlSha256: controlHash(v) };
  }
  const subnets = [];
  for (const n of inventory.networks) {
    const key = n.Name.slice(PROJECT.length + 1), base = defaultOwnNetwork({ ...n, Containers: {} }, key, NETWORKS);
    const members = inventory.containers.filter(c => CONNECTIONS[serviceOf(c)].includes(key));
    safe(equal(sorted(Object.keys(n.Containers ?? {})), sorted(members.map(c => c.Id))), 'Running-build network membership changed.');
    for (const c of members) {
      const attachment = c.NetworkSettings.Networks[n.Name], endpoint = n.Containers[c.Id];
      safe(attachment.NetworkID === n.Id && endpoint.Name === c.Name.slice(1) && HEX_SHA.test(attachment.EndpointID) &&
        endpoint.EndpointID === attachment.EndpointID, 'Running-build network endpoint identity changed.');
    }
    subnets.push(defaultSubnet(base.IPAM.Config[0]));
    networks[key] = { id: n.Id, containers: sorted(members.map(c => c.Id)), controlSha256: controlHash(n) };
  }
  safe(new Set(Object.values(networks).map(n => n.id)).size === 4 && subnets.every((a, i) => subnets.every((b, j) => i === j || a.last < b.first || b.last < a.first)));
  const tags = (await run(['image', 'ls', '--format', '{{.Repository}}:{{.Tag}}'], options)).trim().split('\n').filter(Boolean);
  safe(equal(sorted([...new Set(tags.filter(tag => namespaced(tag.split(':')[0])))]), sorted(Object.keys(FILES).map(role => `${PROJECT}-${role}:local`))));
  const usersChecked = new Set();
  for (const role of Object.keys(FILES)) {
    const tag = `${PROJECT}-${role}:local`, values = JSON.parse(await run(['image', 'inspect', tag], options)); safe(values.length === 1);
    const image = values[0]; validateImage(image, role); ownImageReferences(image, role); tagImages[role] = image.Id;
    // Old running IDs may now be untagged; new tag IDs must not be in use.
    for (const id of [pins[role], image.Id]) if (!usersChecked.has(id)) {
      const users = (await run(['container', 'ls', '--all', '--filter', `ancestor=${id}`, '--format', '{{.ID}}', '--no-trunc'], options)).trim().split('\n').filter(Boolean);
      safe(equal(sorted(users), sorted(inventory.containers.filter(c => c.Image === id).map(c => c.Id))), 'Running-build image has unexpected container references.');
      usersChecked.add(id);
    }
  }
  await exactRunningCensus(run, options);
  return { containers, volumes, networks, tagImages };
}
function validateRunningReceipt(ack, name, root, futureBuild = false) {
  const identity = value => keys(value, ['dev', 'ino']) && Object.values(value).every(n => Number.isSafeInteger(n) && n >= 0);
  safe(keys(ack, ['version', 'project', 'operation', 'acknowledgement', 'originalOutcome', 'originalMutationSha256', 'profileSha256', 'sourceSha256',
    'originalLockIdentity', 'originalMarkerIdentity', 'cve', 'images', 'imageContainerReferences', 'endpoint', 'endpointProvenance', 'namespace', 'jwtPreserved', 'at',
    'imagePinsSha256', 'imagePinsIdentity', 'imagePins', 'transactionNonce', 'operatorAttestation', 'profileIdentity', 'jwtIdentity', 'cveOverlaySha256', 'cveOverlayIdentity',
    'startSubmission', 'prebuildBaseline', 'runtime', ...(futureBuild ? ['buildRecords'] : [])]) && ack.version === 1 && ack.project === PROJECT && ack.operation === RUNNING_OUTCOME &&
    ack.acknowledgement === RUNNING_ACK && ack.originalOutcome === 'HOLD_PRESERVED' && ack.jwtPreserved === true && ack.startSubmission === 'ABSENT' &&
    ack.prebuildBaseline === 'OPERATOR_ATTESTED' && ack.operatorAttestation === 'BUILD_FAILED_BEFORE_START_LAUNCHER_RETURNED_AND_QUIESCENT' &&
    ack.transactionNonce === name.slice('running-build-only-'.length) && equal(ack.namespace, { containers: 6, volumes: 2, networks: 4 }) &&
    ack.endpointProvenance === 'recorded-match' && typeof ack.endpoint === 'string' && /^unix:\/\/\/[^\s\0]+(?![\s\S])/.test(ack.endpoint) && timestamp(ack.at) &&
    HEX_SHA.test(ack.profileSha256) && HEX_SHA.test(ack.sourceSha256) && identity(ack.profileIdentity) && identity(ack.jwtIdentity) && identity(ack.imagePinsIdentity) &&
    keys(ack.imagePins, SERVICES) && Object.values(ack.imagePins).every(id => IMAGE_ID.test(id)) &&
    ack.imagePins['auth-volume-init'] === ack.imagePins['scan-volume-init'] && keys(ack.images, Object.keys(FILES)) &&
    Object.keys(FILES).every(role => ack.images[role] === ack.imagePins[role]) && new Set(Object.values(ack.images)).size === 4 && ack.imageContainerReferences === 4 &&
    ack.imagePinsSha256 === sha(JSON.stringify({ services: Object.fromEntries(SERVICES.map(role => [role, { image: ack.imagePins[role] }])) })) &&
    (ack.cve === null ? ack.cveOverlaySha256 === null && ack.cveOverlayIdentity === null : identity(ack.cveOverlayIdentity) &&
          ack.cveOverlaySha256 === sha(JSON.stringify(cveOverlay(publicImageCveConfig(root, ack.cve))))));
  const r = ack.runtime;
  safe(keys(r, ['containers', 'volumes', 'networks', 'tagImages']) && keys(r.containers, SERVICES) && keys(r.volumes, VOLUMES) && keys(r.networks, NETWORKS) &&
    keys(r.tagImages, Object.keys(FILES)) && Object.values(r.tagImages).every(id => IMAGE_ID.test(id)));
  for (const role of SERVICES) {
    const c = r.containers[role], s = c.state, init = role.endsWith('volume-init'), health = role === 'api' ? 'healthy' : null;
    safe(keys(c, ['id', 'image', 'state', 'controlSha256']) && HEX_SHA.test(c.id) && c.image === ack.imagePins[role] && HEX_SHA.test(c.controlSha256) &&
      keys(s, ['status', 'pid', 'startedAt', 'finishedAt', 'restartCount', 'health']) && s.status === (init ? 'exited' : 'running') &&
      Number.isSafeInteger(s.pid) && (init ? s.pid === 0 : s.pid > 0) && Number.isSafeInteger(s.restartCount) && s.restartCount >= 0 && s.health === health &&
      timestamp(s.startedAt) && timestamp(s.finishedAt));
  }
  safe(new Set(Object.values(r.containers).map(c => c.id)).size === 6 && new Set(Object.values(r.networks).map(n => n.id)).size === 4);
  for (const key of VOLUMES) safe(keys(r.volumes[key], ['createdAt', 'controlSha256']) && timestamp(r.volumes[key].createdAt) && HEX_SHA.test(r.volumes[key].controlSha256));
  for (const key of NETWORKS) {
    const n = r.networks[key]; safe(keys(n, ['id', 'containers', 'controlSha256']) && HEX_SHA.test(n.id) && HEX_SHA.test(n.controlSha256) &&
      equal(n.containers, sorted(SERVICES.filter(role => CONNECTIONS[role].includes(key)).map(role => r.containers[role].id))));
  }
}
function assertReconciliationHistory(root, pendingRedeploy = null) {
  redeployHistory(root, pendingRedeploy);
  const dir = join(root, STATE, HISTORY);
  if (!exists(dir)) return;
  privateDirectory(dir);
  const names = fs.readdirSync(dir);
  safe(names.length <= 32, 'Isolated reconciliation history requires reviewed maintenance/HOLD.');
  for (const name of names) {
    safe(/^(?:build-only|network-only|running-build-only)-[a-f0-9]{32}(?![\s\S])/.test(name));
    const network = name.startsWith('network-only-'), running = name.startsWith('running-build-only-');
    const outcome = running ? RUNNING_OUTCOME : network ? NETWORK_OUTCOME : 'NOT_EXECUTED_SERVICES';
    const archive = join(dir, name); privateDirectory(archive);
    safe(equal(sorted(fs.readdirSync(archive)), sorted(['acknowledgement.json', 'completion.json', 'original-operation.lock', 'reconciliation-operation.lock'])),
      'Incomplete isolated reconciliation history/HOLD; ordinary lifecycle cannot finish it.');
    const original = join(archive, 'original-operation.lock'), guard = join(archive, 'reconciliation-operation.lock');
    privateDirectory(original); privateDirectory(guard);
    const futureBuild = running && exists(join(original,'build-evidence.json'));
        safe(equal(sorted(fs.readdirSync(original)), futureBuild ? ['build-evidence.json','build-failure.json','mutation.json'] : network ? ['mutation.json', 'start-submission.json'] : ['mutation.json']) && equal(fs.readdirSync(guard), ['intent.json']));
    const marker = privateRead(join(original, 'mutation.json'));
    const { bytes: ackBytes, value: ack } = canonicalJson(join(archive, 'acknowledgement.json'));
    const { value: completion } = canonicalJson(join(archive, 'completion.json'));
    const { value: intent } = canonicalJson(join(guard, 'intent.json'));
    if (running) {
          validateRunningReceipt(ack, name, root, futureBuild);
          if (futureBuild) {
            const evidence=privateRead(join(original,'build-evidence.json')), failure=privateRead(join(original,'build-failure.json'));
            safe(equal(ack.buildRecords,{evidenceSha256:sha(evidence),failureSha256:sha(failure)}));
            validateBuildEvidence(evidence,failure,snapshotBuildBaseline(ack.runtime),ack.endpoint);
          }
        }
    else safe(keys(ack, ['version', 'project', 'operation', 'acknowledgement', 'originalOutcome', 'originalMutationSha256',
      'profileSha256', 'sourceSha256', 'originalLockIdentity', 'originalMarkerIdentity', 'cve', 'images', 'imageContainerReferences', 'endpoint', 'endpointProvenance', 'namespace', 'jwtPreserved', 'at',
      ...(network ? ['originalStartSubmissionSha256', 'originalStartSubmissionIdentity', 'imagePinsSha256', 'imagePinsIdentity', 'imagePins', 'networks',
        'transactionNonce', 'operatorAttestation', 'profileIdentity', 'jwtIdentity', 'cveOverlaySha256', 'cveOverlayIdentity'] : [])]) &&
      ack.version === 1 && ack.project === PROJECT && ack.operation === outcome &&
      ack.acknowledgement === '--ack-no-services' && ack.originalOutcome === 'HOLD_PRESERVED' && ack.jwtPreserved === true &&
      equal(ack.namespace, { containers: 0, volumes: 0, networks: network ? 2 : 0 }) && HEX_SHA.test(ack.profileSha256) && HEX_SHA.test(ack.sourceSha256) &&
      keys(ack.images, Object.keys(FILES)) && Object.values(ack.images).every(id => IMAGE_ID.test(id)) && ack.imageContainerReferences === 0 &&
      typeof ack.endpoint === 'string' && /^unix:\/\/\/[^\s\0]+(?![\s\S])/.test(ack.endpoint) && typeof ack.at === 'string');
    publicImageCveConfig(root, ack.cve); // Schema only; never reopen historical private/public assets here.
    const m = (running ? runningBuildMarker : network ? networkStartMarker : buildMarker)(marker, ack.endpoint), archivedStamp = fileStamp(join(original, 'mutation.json'));
    safe(equal(ack.originalLockIdentity, directoryIdentity(original)) &&
      equal(ack.originalMarkerIdentity, { dev: archivedStamp.dev, ino: archivedStamp.ino }), 'Original reconciliation evidence identity changed/HOLD.');
    safe(ack.originalMutationSha256 === sha(marker) && ack.endpointProvenance ===
      (Object.hasOwn(m, 'endpoint') ? 'recorded-match' : 'operator-acknowledged-legacy-marker'));
    if (network) {
          const start = privateRead(join(original, 'start-submission.json')), stamp = fileStamp(join(original, 'start-submission.json'));
          startSubmission(start, ack.endpoint);
          const identity = value => keys(value, ['dev', 'ino']) && Object.values(value).every(n => Number.isSafeInteger(n) && n >= 0);
          safe(ack.originalStartSubmissionSha256 === sha(start) && equal(ack.originalStartSubmissionIdentity, { dev: stamp.dev, ino: stamp.ino }) &&
            ack.transactionNonce === name.slice('network-only-'.length) && ack.operatorAttestation === 'LAUNCHER_RETURNED_AND_LONG_QUIESCENCE' &&
            identity(ack.imagePinsIdentity) && identity(ack.profileIdentity) && identity(ack.jwtIdentity) &&
            keys(ack.imagePins, SERVICES) && Object.values(ack.imagePins).every(id => IMAGE_ID.test(id)) &&
            Object.keys(FILES).every(role => ack.images[role] === ack.imagePins[role]) &&
            ack.imagePins['auth-volume-init'] === ack.imagePins['scan-volume-init'] &&
            ack.imagePinsSha256 === sha(JSON.stringify({ services: Object.fromEntries(SERVICES.map(role => [role, { image: ack.imagePins[role] }])) })) &&
            equal(ack.networks, networkPairSnapshot(ack.networks)) &&
            (ack.cve === null ? ack.cveOverlaySha256 === null && ack.cveOverlayIdentity === null :
              identity(ack.cveOverlayIdentity) && ack.cveOverlaySha256 === sha(JSON.stringify(cveOverlay(publicImageCveConfig(root, ack.cve))))));
        }
        safe(equal(intent, { version: 1, project: PROJECT, command: running ? 'reconcile-running-build-only' : network ? 'reconcile-network-only' : 'reconcile-build-only', archive: name, originalMutationSha256: sha(marker) }));
    safe(keys(completion, ['version', 'project', 'operation', 'archive', 'originalMutationSha256', 'acknowledgementSha256']) &&
      equal(completion, { version: 1, project: PROJECT, operation: outcome, archive: name,
        originalMutationSha256: sha(marker), acknowledgementSha256: sha(ackBytes) }));
  }
}
async function emptyNamespace(run, options) {
  // Projection-only census: even a mislabeled legacy name is refused without
  // ever requesting a container environment, mounts or old JWT.
  for (const kind of ['container', 'volume', 'network']) {
    const format = `{{.${kind === 'container' ? 'Names' : 'Name'}}}\t{{.Label "com.docker.compose.project"}}`;
    const rows = (await run([kind, 'ls', ...(kind === 'container' ? ['--all'] : []), '--format', format], options)).trim().split('\n').filter(Boolean);
    safe(rows.every(row => { const [name, project] = row.split('\t'); return !namespaced(name) && project !== PROJECT; }),
      'Build-only reconciliation requires ZERO isolated containers (including stopped), volumes and networks.');
  }
}
async function builtImageIds(run, options) {
  const tags = (await run(['image', 'ls', '--format', '{{.Repository}}:{{.Tag}}'], options)).trim().split('\n').filter(Boolean);
  const own = [...new Set(tags.filter(tag => namespaced(tag.split(':')[0])))];
  safe(equal(sorted(own), sorted(Object.keys(FILES).map(name => `${PROJECT}-${name}:local`))), 'Build-only reconciliation requires exactly the four own image tags.');
  const ids = {};
  for (const name of Object.keys(FILES)) {
    const tag = `${PROJECT}-${name}:local`, values = JSON.parse(await run(['image', 'inspect', tag], options));
    safe(values.length === 1);
    const image = values[0]; validateImage(image, name);
    // Docker Desktop's containerd store records a local self-digest after build.
        // Accept only this exact own repository/immutable ID, never foreign aliases.
        const selfDigest = `${PROJECT}-${name}@${image.Id}`;
        safe(equal(image.RepoTags, [tag]) && (neutral(image.RepoDigests) || equal(image.RepoDigests, [selfDigest])) &&
      (image.Config.Labels['com.docker.compose.project'] === undefined || image.Config.Labels['com.docker.compose.project'] === PROJECT) &&
      (image.Config.Labels['com.docker.compose.service'] === undefined || image.Config.Labels['com.docker.compose.service'] === name),
    'Isolated image has foreign/mixed references.');
    const users = await run(['container', 'ls', '--all', '--filter', `ancestor=${image.Id}`, '--format', '{{.ID}}', '--no-trunc'], options);
    safe(users.trim() === '', 'Isolated build image is referenced by a container; no foreign resource details were inspected.');
    ids[name] = image.Id;
  }
  safe(new Set(Object.values(ids)).size === 4);
  return ids;
}
// Share only the durable archival transaction, never the two eligibility policies.
async function reconcileHeldOperation(kind, root, run, ambient, verifyRelease, log, checkpoint, platform) {
  safe(['build-only', 'network-only', 'running-build-only'].includes(kind));
  const network = kind === 'network-only', running = kind === 'running-build-only', command = `reconcile-${kind}`;
  const outcome = running ? RUNNING_OUTCOME : network ? NETWORK_OUTCOME : 'NOT_EXECUTED_SERVICES';
  const guardName = running ? RUNNING_GUARD : network ? NETWORK_GUARD : RECONCILE_GUARD;
  const futureBuild = running && exists(join(root,STATE,'.operation.lock/build-evidence.json'));
    const originalNames = futureBuild ? ['build-evidence.json','build-failure.json','mutation.json'] : network ? ['mutation.json', 'start-submission.json'] : ['mutation.json'];
  const parseMarker = running ? runningBuildMarker : network ? networkStartMarker : buildMarker;
  const dir = join(root, STATE), operation = join(dir, '.operation.lock'), guardPath = join(dir, guardName);
  let stage = 'state', retain = false, guardIdentity, stateIdentity, archivedGuard, guardMoved = false, committed = false;
  try {
    stateIdentity = directoryIdentity(dir);
    safe(RECOVERY_GUARDS.every(name => !exists(join(dir, name))), 'Isolated reconciliation already locked/HOLD.');
    assertReconciliationHistory(root);
    const originalIdentity = directoryIdentity(operation);
    safe(originalIdentity.dev === stateIdentity.dev, 'Build-only reconciliation requires same-filesystem atomic archival.');
    safe(equal(sorted(fs.readdirSync(operation)), originalNames), 'Only the exact original operation records are eligible.');
    const marker = captureFile(join(operation, 'mutation.json')), initialMarker = parseMarker(marker.bytes);
    const start = network ? captureFile(join(operation, 'start-submission.json')) : null;
        const buildFiles = futureBuild ? ['build-evidence.json','build-failure.json'].map(n => [n,captureFile(join(operation,n))]) : [];
    if (start) startSubmission(start.bytes, initialMarker.endpoint);
    fs.mkdirSync(guardPath, { mode: 0o700 }); guardIdentity = directoryIdentity(guardPath); syncDirectory(dir);
    const guardCheck = () => {
          verifyDirectory(dir, stateIdentity); verifyDirectory(guardPath, guardIdentity);
          safe(RECOVERY_GUARDS.filter(name => name !== guardName).every(name => !exists(join(dir, name))), 'Competing isolated reconciliation/HOLD.');
        };
    const originalCheck = (at = operation) => {
      verifyDirectory(at, originalIdentity); safe(equal(sorted(fs.readdirSync(at)), originalNames)); marker.verify(join(at, 'mutation.json'));
      start?.verify(join(at, 'start-submission.json')); buildFiles.forEach(([n,f])=>f.verify(join(at,n)));
    };
    const profileFile = captureFile(join(dir, 'profile.json')), profile = readProfile(root); safe(profile !== undefined); profileFile.verify();
    const jwt = captureFile(join(dir, 'scan-jwt'), 96); safe(/^[a-f0-9]{96}(?![\s\S])/.test(jwt.bytes));
    const pinsFile = network || running ? captureFile(join(dir, 'compose.images.json')) : null;
    const pins = pinsFile ? readImagePins(pinsFile.bytes) : null;
    const source = captureFile(join(root, 'server/deploy/compose.public-images.yaml'), 131072, true);
    validateReconciliationSource(source.bytes, root);
    const cveFile = profile.cve ? captureFile(join(dir, 'compose.cve.json')) : null;
    safe(cveFile ? cveFile.bytes === JSON.stringify(cveOverlay(profile.cve)) : !exists(join(dir, 'compose.cve.json')));
    const publicStamps = [];
    if (profile.cve) {
      verifyRelease(root, metadata(profile.cve));
      for (const path of [profile.cve.releaseHostDir, join(profile.cve.releaseHostDir, 'db'), profile.cve.publicKeyPath,
        ...['descriptor.json', 'descriptor.sig', 'bundle.bin', 'db/metadata.json', 'db/trivy.db'].map(p => join(profile.cve.releaseHostDir, p))]) {
        publicStamps.push([path, fileStamp(path)]); // Metadata only for DB/bundle; no large/unbounded reads.
      }
    }
    const historyPath = join(dir, HISTORY); let historyIdentity = exists(historyPath) ? directoryIdentity(historyPath) : null;
    safe(!historyIdentity || historyIdentity.dev === stateIdentity.dev, 'Build-only reconciliation history must be on the same filesystem.');
    let archived = false, archivePath;
    const stateCheck = () => {
      verifyDirectory(dir, stateIdentity); safe(fs.realpathSync(root) === root);
      profileFile.verify(); jwt.verify(); source.verify(); cveFile?.verify(); pinsFile?.verify();
      safe(equal(sorted(fs.readdirSync(dir)), sorted(['profile.json', 'scan-jwt', guardName, ...(network || running ? ['compose.images.json'] : []),
        ...(!archived ? ['.operation.lock'] : []), ...(profile.cve ? ['compose.cve.json'] : []), ...(historyIdentity ? [HISTORY] : [])])),
      'Unexpected isolated state, image pins or pending files are not eligible for build-only reconciliation.');
      if (historyIdentity) verifyDirectory(historyPath, historyIdentity); else safe(!exists(historyPath));
      if (profile.cve) verifyRelease(root, metadata(profile.cve));
      safe(publicStamps.every(([path, stamp]) => equal(stamp, fileStamp(path))), 'Pinned public CVE assets changed during reconciliation.');
      guardCheck(); originalCheck(archived ? join(archivePath, 'original-operation.lock') : operation);
    };
    // Bounded Docker budget; no retries, no build/pull/start/stop/delete calls.
    const deadline = performance.now() + 60_000;
    const d = (args, options) => { const remaining = Math.floor(deadline - performance.now()); safe(remaining > 0, 'Build-only reconciliation Docker budget exhausted.');
      return run(args, { ...options, timeout: Math.min(30_000, remaining) }); };
    stage = 'endpoint'; stateCheck();
    const options = await requireLocalEngine(d, { root, env: dockerEnvironment(ambient) });
    safe(options.env.DOCKER_HOST.length <= 4096); const original = parseMarker(marker.bytes, options.env.DOCKER_HOST);
    if (start) startSubmission(start.bytes, options.env.DOCKER_HOST);
    stage = 'proof'; stateCheck();
    const proof = async () => {
      if (running) {
        const runtime = await runningBuildProof(d, options, root, profile, pins, jwt.bytes, platform);
        stateCheck(); return runtime;
      }
      const networks = network ? await networkOnlyNamespace(d, options) : await emptyNamespace(d, options);
      const ids = await builtImageIds(d, options);
      let selected;
      if (network) {
        safe(Object.keys(FILES).every(name => ids[name] === pins[name]), 'Own image tags no longer match start pins.');
        // Inspect only fixed reviewed tags, never an ID supplied by a pin file.
        selected = await selectedImages(d, options, expectedConfig(root, profile.cve));
        safe(SERVICES.every(name => selected[name].Id === pins[name]) && Object.keys(FILES).every(name => selected[name].Id === ids[name]),
          'Pinned initializer/own image selection changed.');
      }
      const rendered = JSON.parse(await d(composeArguments(root, ['config', '--format', 'json'], profile.cve, network),
        { ...options, env: composeEnv(options.env) }));
      validateConfig(rendered, root, profile.cve, selected);
      if (network) safe(equal(networks, await networkOnlyNamespace(d, options)), 'Own networks changed during proof.');
      stateCheck(); return network ? { ids, networks } : ids;
    };
    const images = await proof();
        if (futureBuild) validateBuildEvidence(buildFiles[0][1].bytes,buildFiles[1][1].bytes,snapshotBuildBaseline(images),options.env.DOCKER_HOST);
        checkpoint('proof-complete'); stateCheck();
    safe(!historyIdentity || fs.readdirSync(historyPath).length < 32, 'Reconciliation history limit/HOLD; reviewed maintenance required.');
    const archiveName = `${kind}-${randomBytes(16).toString('hex')}`;
    archivePath = join(historyPath, archiveName);
    const intent = JSON.stringify({ version: 1, project: PROJECT, command, archive: archiveName, originalMutationSha256: sha(marker.bytes) });
    stage = 'archive-intent'; retain = true;
    writeExclusive(join(guardPath, 'intent.json'), intent, 0o600); syncDirectory(guardPath); syncDirectory(dir);
    const intentFile = captureFile(join(guardPath, 'intent.json'));
    checkpoint('intent-durable'); guardCheck(); stateCheck(); intentFile.verify();
    if (!historyIdentity) { fs.mkdirSync(historyPath, { mode: 0o700 }); historyIdentity = directoryIdentity(historyPath); syncDirectory(dir); }
    fs.mkdirSync(archivePath, { mode: 0o700 }); const archiveIdentity = directoryIdentity(archivePath);
    const archiveCheck = () => { guardCheck(); verifyDirectory(historyPath, historyIdentity); verifyDirectory(archivePath, archiveIdentity); };
    const ack = running ? {
          version: 1, project: PROJECT, operation: outcome, acknowledgement: RUNNING_ACK, originalOutcome: 'HOLD_PRESERVED',
          originalMutationSha256: sha(marker.bytes), profileSha256: sha(profileFile.bytes), sourceSha256: sha(source.bytes),
          originalLockIdentity: originalIdentity, originalMarkerIdentity: marker.identity, cve: metadata(profile.cve),
          images: Object.fromEntries(Object.keys(FILES).map(role => [role, pins[role]])), imageContainerReferences: 4,
          endpoint: options.env.DOCKER_HOST, endpointProvenance: 'recorded-match', namespace: { containers: 6, volumes: 2, networks: 4 },
          jwtPreserved: true, at: new Date().toISOString(), imagePinsSha256: sha(pinsFile.bytes), imagePinsIdentity: pinsFile.identity,
          imagePins: pins, transactionNonce: archiveName.slice('running-build-only-'.length),
          operatorAttestation: 'BUILD_FAILED_BEFORE_START_LAUNCHER_RETURNED_AND_QUIESCENT', startSubmission: 'ABSENT', prebuildBaseline: 'OPERATOR_ATTESTED',
          profileIdentity: profileFile.identity, jwtIdentity: jwt.identity, cveOverlaySha256: cveFile ? sha(cveFile.bytes) : null,
          cveOverlayIdentity: cveFile?.identity ?? null, runtime: images,
                ...(futureBuild ? {buildRecords:{evidenceSha256:sha(buildFiles[0][1].bytes),failureSha256:sha(buildFiles[1][1].bytes)}} : {}),
        } : { version: 1, project: PROJECT, operation: outcome, acknowledgement: '--ack-no-services',
      originalOutcome: 'HOLD_PRESERVED', originalMutationSha256: sha(marker.bytes), profileSha256: sha(profileFile.bytes), sourceSha256: sha(source.bytes),
      originalLockIdentity: originalIdentity, originalMarkerIdentity: marker.identity,
      cve: metadata(profile.cve), images: network ? images.ids : images, imageContainerReferences: 0, endpoint: options.env.DOCKER_HOST,
      endpointProvenance: Object.hasOwn(original, 'endpoint') ? 'recorded-match' : 'operator-acknowledged-legacy-marker',
      namespace: { containers: 0, volumes: 0, networks: network ? 2 : 0 }, jwtPreserved: true, at: new Date().toISOString(),
      ...(network ? { originalStartSubmissionSha256: sha(start.bytes), originalStartSubmissionIdentity: start.identity,
        imagePinsSha256: sha(pinsFile.bytes), imagePinsIdentity: pinsFile.identity, imagePins: pins, networks: images.networks,
        transactionNonce: archiveName.slice('network-only-'.length), operatorAttestation: 'LAUNCHER_RETURNED_AND_LONG_QUIESCENCE',
        profileIdentity: profileFile.identity, jwtIdentity: jwt.identity,
        cveOverlaySha256: cveFile ? sha(cveFile.bytes) : null, cveOverlayIdentity: cveFile?.identity ?? null } : {}) };
    const ackBytes = JSON.stringify(ack);
    writeExclusive(join(archivePath, 'acknowledgement.json'), ackBytes, 0o600); syncDirectory(archivePath); syncDirectory(historyPath);
    const ackFile = captureFile(join(archivePath, 'acknowledgement.json'));
    stage = 'archive-prepared'; checkpoint('archive-prepared');
    safe(equal(images, await proof()), 'Isolated image identities changed during reconciliation.');
    archiveCheck(); ackFile.verify(); safe(equal(fs.readdirSync(archivePath), ['acknowledgement.json']));
    intentFile.verify();
    safe(privateRead(join(guardPath, 'intent.json')) === intent);
    fs.renameSync(operation, join(archivePath, 'original-operation.lock')); archived = true;
    syncDirectory(archivePath); syncDirectory(dir);
    stage = 'lock-archived'; checkpoint('lock-archived'); stateCheck(); archiveCheck(); ackFile.verify();
    safe(equal(images, await proof()), 'Namespace/image proof changed before reconciliation commit.');
    const completion = JSON.stringify({ version: 1, project: PROJECT, operation: outcome, archive: archiveName,
      originalMutationSha256: sha(marker.bytes), acknowledgementSha256: sha(ackBytes) });
    writeExclusive(join(archivePath, 'completion.json'), completion, 0o600); syncDirectory(archivePath); syncDirectory(historyPath); syncDirectory(dir);
    const completionFile = captureFile(join(archivePath, 'completion.json'));
    stage = 'completion-recorded'; checkpoint('completion-recorded'); stateCheck(); archiveCheck(); ackFile.verify();
    safe(privateRead(join(archivePath, 'completion.json')) === completion && privateRead(join(guardPath, 'intent.json')) === intent &&
      equal(fs.readdirSync(guardPath), ['intent.json']));
    completionFile.verify(); intentFile.verify();
    stage = 'guard-release'; checkpoint('guard-release');
    safe(equal(images, await proof()), 'Namespace/image proof changed at guard release.');
    stateCheck(); archiveCheck(); completionFile.verify(); intentFile.verify();
    archivedGuard = join(archivePath, 'reconciliation-operation.lock'); safe(!exists(archivedGuard));
    fs.renameSync(guardPath, archivedGuard); guardMoved = true;
    checkpoint('guard-archived');
    verifyDirectory(archivedGuard, guardIdentity); verifyDirectory(dir, stateIdentity);
    verifyDirectory(historyPath, historyIdentity); verifyDirectory(archivePath, archiveIdentity);
    originalCheck(join(archivePath, 'original-operation.lock')); ackFile.verify(); completionFile.verify(); intentFile.verify(join(archivedGuard, 'intent.json'));
    safe(privateRead(join(archivePath, 'completion.json')) === completion && privateRead(join(archivedGuard, 'intent.json')) === intent);
    profileFile.verify(); jwt.verify(); source.verify(); cveFile?.verify(); pinsFile?.verify();
    safe(publicStamps.every(([path, stamp]) => equal(stamp, fileStamp(path))));
    assertReconciliationHistory(root); syncDirectory(archivePath); syncDirectory(dir);
    // Commit point: original failure + acknowledgement + both lock histories are
    // durable. No Docker service operation was submitted by this command.
    retain = false; guardIdentity = undefined; committed = true;
    log(`${kind} reconciliation recorded: ${outcome}; receipt=${HISTORY}/${archiveName}. Original HOLD history archived unchanged; own JWT/profile preserved. No service or network mutation was submitted by reconciliation; native qualification is not approved.`);
    return { operation: outcome, archive: `${HISTORY}/${archiveName}` };
  } catch (error) {
    if (committed) throw new IsolatedError(`${kind} reconciliation committed ${outcome}; output acknowledgement unavailable. Review own archived receipts before any next operation.`);
    if (guardMoved && guardIdentity) {
      // A failure before acknowledged commit restores the exclusion barrier;
      // never delete or rewrite the original failure/acknowledgement history.
      try { verifyDirectory(dir, stateIdentity); verifyDirectory(archivedGuard, guardIdentity);
        safe(!exists(guardPath)); fs.renameSync(archivedGuard, guardPath); syncDirectory(dir); syncDirectory(dirname(archivedGuard)); } catch { /* retain all evidence; no force cleanup */ }
    }
    const checkpoint = error instanceof IsolatedImageEvidenceFailure ? error.checkpoint : stage;
        const reason = error instanceof IsolatedImageEvidenceFailure ? error.reason : error instanceof IsolatedDockerFailure ? 'DOCKER_PROOF_READ_FAILED' : 'POLICY_OR_PROOF_REFUSED';
        throw new IsolatedError(`${kind} reconciliation refused/incomplete HOLD; checkpoint=${checkpoint}; reason=${reason}. Original failure/history retained. No service operation or automatic recovery; reviewed reconciliation required.`);
  } finally {
    if (!retain && guardIdentity) {
      verifyDirectory(dir, stateIdentity); verifyDirectory(guardPath, guardIdentity);
      safe(fs.readdirSync(guardPath).length === 0, 'Reconciliation guard changed/HOLD; no cleanup.');
      fs.rmdirSync(guardPath); syncDirectory(dir);
    }
  }
}

// Only byte reads touch source DBs. SQLite opens the fenced, private main+WAL
// copy, never an immutable/stale main-only view and never the RO source volume.
export function copyStableSqlite(io, crypto, source, scratch) {
  const refuse = (changed = false) => { const e = Error(changed ? 'SQLITE_SOURCE_CHANGED' : 'SQLITE_SNAPSHOT_REFUSED'); e.code = e.message; throw e; };
  const check = value => { if (!value) refuse(); };
  const stamp = s => [s.dev,s.ino,s.uid,s.mode,s.nlink,s.size,s.mtimeMs,s.ctimeMs];
  const optional = p => { try { return io.lstatSync(p); } catch(e) { if(e.code==='ENOENT')return null; throw e; } };
  const stat = p => { const s=optional(p); if(s)check(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1&&s.size<=256*1024**2);return s; };
  const family = () => { check(!optional(source+'-journal')); const main=stat(source),wal=stat(source+'-wal');check(main&&main.size>0);stat(source+'-shm');
    return [{path:source,name:'db.sqlite',s:main},...(wal?[{path:source+'-wal',name:'db.sqlite-wal',s:wal}]:[])]; };
  const stream = (f, destination) => {
    const h=crypto.createHash('sha256'),b=Buffer.alloc(65536);let fd,to,total=0;
    try {fd=io.openSync(f.path,io.constants.O_RDONLY|io.constants.O_NOFOLLOW|io.constants.O_NONBLOCK);const opened=io.fstatSync(fd);check(opened.isFile());if(JSON.stringify(stamp(opened))!==JSON.stringify(stamp(f.s)))refuse(true);
      if(destination)to=io.openSync(destination,io.constants.O_WRONLY|io.constants.O_CREAT|io.constants.O_EXCL|io.constants.O_NOFOLLOW,0o600);
      let n;while((n=io.readSync(fd,b,0,b.length,null))){total+=n;if(total>f.s.size)refuse(true);h.update(b.subarray(0,n));
        if(to!==undefined){let written=0;while(written<n){const size=io.writeSync(to,b,written,n-written,null);check(size>0);written+=size;}}}
      if(total!==f.s.size||JSON.stringify(stamp(io.fstatSync(fd)))!==JSON.stringify(stamp(f.s))||JSON.stringify(stamp(io.lstatSync(f.path)))!==JSON.stringify(stamp(f.s)))refuse(true);
      if(to!==undefined)io.fsyncSync(to);return h.digest('hex');
    }catch(e){if(['ENOENT','ESTALE'].includes(e.code))refuse(true);throw e;}
    finally{if(fd!==undefined)io.closeSync(fd);if(to!==undefined)io.closeSync(to);}
  };
  const files=family();check(files.reduce((n,f)=>n+f.s.size,0)<=256*1024**2);
  for(const f of files)f.hash=stream(f);
  const capacity=io.statfsSync(scratch.slice(0,scratch.lastIndexOf('/')));check(capacity.bavail*capacity.bsize>=2*files.reduce((n,f)=>n+f.s.size,0)+16*1024**2);
  io.mkdirSync(scratch,{mode:0o700});const directory=io.lstatSync(scratch);
  const cleanup=()=>{const s=io.lstatSync(scratch);check(s.isDirectory()&&!s.isSymbolicLink()&&s.dev===directory.dev&&s.ino===directory.ino);
    const names=io.readdirSync(scratch);check(names.every(n=>['db.sqlite','db.sqlite-wal','db.sqlite-shm','db.sqlite-journal'].includes(n)));
    for(const n of names){check(!io.lstatSync(scratch+'/'+n).isSymbolicLink());io.unlinkSync(scratch+'/'+n);}io.rmdirSync(scratch);};
  const verify=()=>{const now=family();if(JSON.stringify(now.map(f=>[f.name,stamp(f.s)]))!==JSON.stringify(files.map(f=>[f.name,stamp(f.s)])))refuse(true);
    for(const f of files)if(stream(f)!==f.hash)refuse(true);};
  try {for(const f of files)if(stream(f,scratch+'/'+f.name)!==f.hash)refuse(true);verify();return {path:scratch+'/db.sqlite',verify,cleanup};}
  catch(e){cleanup();throw e;}
}
export function sqliteTypedRow(row) {
  return JSON.stringify(row.map(value=>{
    if(value===null)return ['null'];
    if(typeof value==='bigint')return ['integer',value.toString()];
    if(typeof value==='number'){const b=Buffer.alloc(8);b.writeDoubleBE(value);return ['real',b.toString('hex')];}
    if(typeof value==='string'){if(Buffer.byteLength(value)>4*1024**2)throw Error('SQLITE_VALUE_BOUND');return ['text',value];}
    if(Buffer.isBuffer(value)){if(value.length>4*1024**2)throw Error('SQLITE_VALUE_BOUND');return ['blob',value.toString('hex')];}
    throw Error('SQLITE_VALUE_TYPE');
  }));
}
// SQLite online-backup API is applied to the private, consistent copy only.
// Dependencies/paths are explicit so the identical core can be tested offline.
export async function recoverySqlite(DB, io, crypto, paths, output, options = {}) {
  const check = value => { if (!value) throw Error('SQLITE_RECOVERY_REFUSED'); };
  check(!output || options.quiescent === true);
  const result = {}, sourceFences = [];
  for (const role of ['auth', 'ledger']) {
    const source = paths[role], stat = io.lstatSync(source);
    check(stat.isFile() && !stat.isSymbolicLink() && stat.size > 0 && stat.size <= 256 * 1024 ** 2);
    const snapshot=output?copyStableSqlite(io,crypto,source,output+'/source-'+role):null;
    if(snapshot)sourceFences.push(snapshot.verify);
    let db;
    const fingerprint = d => {
      d.defaultSafeIntegers(true);d.exec('BEGIN');try {
      check(d.pragma('integrity_check', { simple: true }) === 'ok' && d.pragma('foreign_key_check').length === 0);
      const version=d.pragma('user_version',{simple:true}),expected=role==='ledger'?15:0;
            check(version===expected||version===BigInt(expected));
      const tables = d.prepare("SELECT name,sql FROM sqlite_master WHERE type='table' AND (name NOT LIKE 'sqlite_%' OR name='sqlite_sequence') ORDER BY name").all();
      check(tables.length > 0 && tables.length <= 128 && (role === 'auth' ? ['users','sessions','trusted_sessions','browser_access','auth_attempts'] : ['scans','outbox']).every(n => tables.some(t => t.name === n)));
      if (role === 'ledger') check(d.prepare("SELECT (SELECT count(*) FROM scans WHERE state IN ('queued','running'))+(SELECT count(*) FROM outbox WHERE delivered_at IS NULL) n").safeIntegers(true).get().n === 0n);
      const h = crypto.createHash('sha256'); let bytes = 0;
      const schema=d.prepare("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").all();check(schema.length<=512);h.update(JSON.stringify(schema));
      for (const table of tables) {
        check(/^[a-z_][a-z0-9_]*$/.test(table.name)); h.update(JSON.stringify(table));
        for (const row of d.prepare('SELECT rowid, * FROM "' + table.name + '" ORDER BY rowid').safeIntegers(true).raw(true).iterate()) {
          const text = sqliteTypedRow(row); bytes += Buffer.byteLength(text); check(bytes <= 256 * 1024 ** 2); h.update(text); h.update('\n');
        }
      }
      return h.digest('hex');
      }finally{d.exec('ROLLBACK');}
    };
    try {
      db = new DB(snapshot?.path ?? source, { readonly: !snapshot, fileMustExist: true, timeout: 2000 });
      db.pragma('query_only = ON'); const logicalSha256 = fingerprint(db);
      if (!output) { result[role] = { logicalSha256 }; continue; }
      const destination = output + '/' + role + '.sqlite'; check(!io.existsSync(destination));
      await db.backup(destination); io.chmodSync(destination, 0o600);
      const copy = new DB(destination, { readonly: true, fileMustExist: true, timeout: 2000 });
      try { check(fingerprint(copy) === logicalSha256); } finally { copy.close(); }
      // The sources have been fenced. Recheck both source stability and copied bytes.
      check(fingerprint(db) === logicalSha256);
      const size = io.lstatSync(destination).size; check(size > 0 && size <= 256 * 1024 ** 2);
      const h = crypto.createHash('sha256'), fd = io.openSync(destination, io.constants.O_RDONLY | io.constants.O_NOFOLLOW), buffer = Buffer.alloc(65536);
      try { let n; while ((n = io.readSync(fd, buffer, 0, buffer.length, null))) h.update(buffer.subarray(0, n)); io.fsyncSync(fd); }
      finally { io.closeSync(fd); }
      result[role] = { logicalSha256, sha256: h.digest('hex'), bytes: size, integrity: 'ok' };
    } finally { db?.close(); if(snapshot){try{snapshot.verify();}finally{snapshot.cleanup();}} }
  }
  sourceFences.forEach(verify=>verify());return result;
}
export function recoveryDrain(DB,io,crypto,source,scratch) {
  const snapshot=copyStableSqlite(io,crypto,source,scratch);let db;
  try {db=new DB(snapshot.path,{fileMustExist:true,timeout:2000});db.defaultSafeIntegers(true);db.pragma('query_only=ON');db.exec('BEGIN');
    const version=db.pragma('user_version',{simple:true});if(version!==15&&version!==15n)throw Error('SQLITE_DRAIN_SCHEMA');
    const n=db.prepare("SELECT (SELECT count(*) FROM scans WHERE state IN ('queued','running'))+(SELECT count(*) FROM outbox WHERE delivered_at IS NULL) n").safeIntegers(true).get().n;
    if(typeof n!=='bigint'||n<0n||n>BigInt(Number.MAX_SAFE_INTEGER))throw Error('SQLITE_DRAIN_COUNT');
    db.exec('ROLLBACK');snapshot.verify();return {pending:Number(n)};
  }finally{db?.close();snapshot.cleanup();}
}
const SQLITE_IMPORTS = "import DB from 'better-sqlite3';import * as io from 'node:fs';import * as crypto from 'node:crypto';";
const SQLITE_CORE = SQLITE_IMPORTS+'const copyStableSqlite='+copyStableSqlite.toString()+';const sqliteTypedRow='+sqliteTypedRow.toString()+';const core='+recoverySqlite.toString()+';';
export const LEGACY_RECOVERY_BACKUP = SQLITE_CORE + "process.umask(0o077);const watchdog=setTimeout(()=>process.exit(71),120000);try{const result=await core(DB,io,crypto,{auth:'/auth/auth.sqlite',ledger:'/data/ledger.sqlite'},'/backup',{quiescent:true});io.writeFileSync('/backup/ready.json',JSON.stringify(result),{flag:'wx',mode:0o600});clearTimeout(watchdog);setTimeout(()=>process.exit(0),300000);}catch{process.exit(70);}";
export const RECOVERY_BACKUP = SQLITE_CORE + "process.umask(0o077);const watchdog=setTimeout(()=>process.exit(71),120000);try{const result=await core(DB,io,crypto,{auth:'/auth/auth.sqlite',ledger:'/data/ledger.sqlite'},'/backup',{quiescent:true});io.writeFileSync('/backup/ready.json',JSON.stringify(result),{flag:'wx',mode:0o600});const fd=io.openSync('/backup/ready.json','r');io.fsyncSync(fd);io.closeSync(fd);const dir=io.openSync('/backup','r');io.fsyncSync(dir);io.closeSync(dir);clearTimeout(watchdog);process.on('SIGTERM',()=>process.exit(0));setInterval(()=>{},60000);}catch{process.exit(70);}";
const RECOVERY_COMPARE = SQLITE_CORE + ";try{process.stdout.write(JSON.stringify(await core(DB,io,crypto,{auth:'/auth/auth.sqlite',ledger:'/data/ledger.sqlite'},null)));}catch{process.exit(70);}";
export const RECOVERY_PROBE_SERVICE = "process.on('SIGTERM',()=>process.exit(0));setTimeout(()=>process.exit(0),360000);";
export const RECOVERY_DRAIN = SQLITE_IMPORTS+'const copyStableSqlite='+copyStableSqlite.toString()+';const drain='+recoveryDrain.toString()+";process.umask(0o077);try{process.stdout.write(JSON.stringify(drain(DB,io,crypto,'/data/ledger.sqlite','/backup/drain-source')));}catch(e){if(e.code==='SQLITE_SOURCE_CHANGED')process.stdout.write('{\"retry\":true}');else process.exit(70);}";
const EXPORT_CHUNK_BYTES=1024*1024;
// Runs only in a freshly validated, RO/nocopy backup helper. Paths are fixed in
// the CLI; dependency-injected paths below exist solely for offline native tests.
export function backupExportOperation(io,crypto,request,paths={backup:'/backup',auth:'/auth/auth.sqlite',ledger:'/data/ledger.sqlite'}){
  const check=v=>{if(!v)throw Error('BACKUP_EXPORT_REFUSED');};const limit=256*1024**2,chunk=1024**2;
  const stamp=s=>Object.fromEntries(['dev','ino','uid','mode','nlink','size','mtimeNs','ctimeNs'].map(k=>[k,String(s[k])]));
  const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
  const read=(path,work,privateFile=false,allowEmpty=false)=>{const s=io.lstatSync(path,{bigint:true});check(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1n&&s.uid===BigInt(process.getuid())&&(s.size>0n||allowEmpty&&s.size===0n)&&s.size<=BigInt(limit));
    if(privateFile)check((s.mode&0o7777n)===0o600n);let fd;
    try{fd=io.openSync(path,io.constants.O_RDONLY|io.constants.O_NOFOLLOW|io.constants.O_NONBLOCK);check(eq(stamp(s),stamp(io.fstatSync(fd,{bigint:true}))));
      const result=work(fd,stamp(s));check(eq(stamp(s),stamp(io.fstatSync(fd,{bigint:true})))&&eq(stamp(s),stamp(io.lstatSync(path,{bigint:true}))));return result;
    }finally{if(fd!==undefined)io.closeSync(fd);}};
  const digest=(path,allowEmpty=false)=>read(path,(fd,s)=>{const h=crypto.createHash('sha256'),b=Buffer.alloc(65536);let n,total=0;while((n=io.readSync(fd,b,0,b.length,null))){total+=n;check(total<=Number(s.size));h.update(b.subarray(0,n));}check(total===Number(s.size));return {stamp:s,sha256:h.digest('hex')};},false,allowEmpty);
  const optional=path=>{try{return io.lstatSync(path,{bigint:true});}catch(e){if(e.code==='ENOENT')return null;throw e;}};
  const sources=()=>Object.fromEntries(['auth','ledger'].map(role=>{const p=paths[role];check(!optional(p+'-journal'));if(optional(p+'-shm')){const s=optional(p+'-shm');check(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1n&&s.size<=BigInt(limit));}
    return [role,[{part:'main',...digest(p)},...(optional(p+'-wal')?[{part:'wal',...digest(p+'-wal',true)}]:[])]];}));
  check(request&&typeof request==='object'&&!Array.isArray(request));
  if(request.action==='manifest'){
    check(Object.keys(request).length===1);const before=sources();
    const receipt=read(paths.backup+'/ready.json',(fd,s)=>{check(Number(s.size)<=131072);const b=Buffer.alloc(Number(s.size));let total=0;while(total<b.length){const n=io.readSync(fd,b,total,b.length-total,null);check(n>0);total+=n;}return JSON.parse(b.toString('utf8'));},true);
    const files={};for(const role of ['auth','ledger']){const v=read(paths.backup+'/'+role+'.sqlite',(fd,s)=>{check((BigInt(s.mode)&0o7777n)===0o600n);return s;},true),hash=digest(paths.backup+'/'+role+'.sqlite');
      check(eq(v,hash.stamp)&&receipt[role]?.bytes===Number(v.size)&&receipt[role]?.sha256===hash.sha256);files[role]=v;}
    check(eq(before,sources()));return {version:1,receipt,files,sources:before};
  }
  check(request.action==='chunk'&&Object.keys(request).sort().join(',')==='action,bytes,offset,role,stamp'&&['auth','ledger'].includes(request.role)&&Number.isSafeInteger(request.offset)&&request.offset>=0&&Number.isSafeInteger(request.bytes)&&request.bytes>0&&request.bytes<=chunk);
  return read(paths.backup+'/'+request.role+'.sqlite',(fd,s)=>{check(eq(s,request.stamp)&&request.offset+request.bytes<=Number(s.size));const b=Buffer.alloc(request.bytes);let n=0;while(n<b.length){const count=io.readSync(fd,b,n,b.length-n,request.offset+n);check(count>0);n+=count;}
    return {version:1,role:request.role,offset:request.offset,data:b.toString('base64')};},true);
}
export const BACKUP_EXPORT_PROGRAM="const fs=require('node:fs'),crypto=require('node:crypto');const exportBackup="+backupExportOperation.toString()+";try{process.stdout.write(JSON.stringify(exportBackup(fs,crypto,JSON.parse(process.argv[1]))));}catch{process.exit(72);}";
function validateExportManifest(m){
  recoverySafe(keys(m,['version','receipt','files','sources'])&&m.version===1&&keys(m.receipt,['auth','ledger'])&&keys(m.files,['auth','ledger'])&&keys(m.sources,['auth','ledger']),'BACKUP_EXPORT_MANIFEST_SCHEMA');
  const validateStamp=(s,allowEmpty=false)=>{recoverySafe(keys(s,['dev','ino','uid','mode','nlink','size','mtimeNs','ctimeNs'])&&Object.values(s).every(v=>typeof v==='string'&&/^\d{1,32}$/.test(v))&&s.nlink==='1'&&s.uid==='65532'&&(BigInt(s.size)>0n||allowEmpty&&BigInt(s.size)===0n)&&BigInt(s.size)<=256n*1024n**2n,'BACKUP_EXPORT_FILE_IDENTITY');};
  for(const r of ['auth','ledger']){const b=m.receipt[r];recoverySafe(keys(b,['logicalSha256','sha256','bytes','integrity'])&&HEX_SHA.test(b.logicalSha256)&&HEX_SHA.test(b.sha256)&&Number.isSafeInteger(b.bytes)&&b.bytes>0&&b.bytes<=256*1024**2&&b.integrity==='ok','BACKUP_RECEIPT_INTEGRITY_BOUNDS');validateStamp(m.files[r]);
    recoverySafe((BigInt(m.files[r].mode)&0o7777n)===0o600n&&BigInt(m.files[r].size)===BigInt(b.bytes),'BACKUP_EXPORT_PRIVATE_FILE');
    recoverySafe(Array.isArray(m.sources[r])&&m.sources[r].length>=1&&m.sources[r].length<=2&&equal(m.sources[r].map(f=>f.part),m.sources[r].length===1?['main']:['main','wal']),'BACKUP_EXPORT_SOURCE_FAMILY');
    for(const f of m.sources[r]){recoverySafe(keys(f,['part','stamp','sha256'])&&HEX_SHA.test(f.sha256),'BACKUP_EXPORT_SOURCE_HASH');validateStamp(f.stamp,f.part==='wal');}}
}
export async function transferBackupSnapshot({io=fs,crypto={createHash},dir,role,manifest,readChunk,verify}){
  validateExportManifest(manifest);recoverySafe(['auth','ledger'].includes(role),'BACKUP_EXPORT_ROLE');const b=manifest.receipt[role],path=join(dir,role+'.sqlite'),partial=join(dir,'.'+role+'.sqlite.exporting');
  recoverySafe(!io.existsSync(path)&&!io.existsSync(partial),'BACKUP_DESTINATION_EXISTS');const identity=io.lstatSync(dir);recoverySafe(identity.isDirectory()&&!identity.isSymbolicLink()&&(identity.mode&0o7777)===0o700&&identity.uid===process.getuid(),'BACKUP_EXPORT_DIRECTORY');
  let fd;try{fd=io.openSync(partial,io.constants.O_CREAT|io.constants.O_EXCL|io.constants.O_WRONLY|io.constants.O_NOFOLLOW,0o600);const h=crypto.createHash('sha256');
    for(let offset=0;offset<b.bytes;){await verify();const count=Math.min(EXPORT_CHUNK_BYTES,b.bytes-offset),v=await readChunk({action:'chunk',role,offset,bytes:count,stamp:manifest.files[role]});
      recoverySafe(keys(v,['version','role','offset','data'])&&v.version===1&&v.role===role&&v.offset===offset&&typeof v.data==='string'&&v.data.length===4*Math.ceil(count/3)&&/^[A-Za-z0-9+/]*={0,2}$/.test(v.data),'BACKUP_EXPORT_CHUNK_PROTOCOL');
      const bytes=Buffer.from(v.data,'base64');recoverySafe(bytes.length===count&&bytes.toString('base64')===v.data,'BACKUP_EXPORT_CHUNK_ENCODING');let written=0;while(written<bytes.length){const n=io.writeSync(fd,bytes,written,bytes.length-written,null);recoverySafe(n>0,'BACKUP_EXPORT_HOST_WRITE');written+=n;}h.update(bytes);offset+=bytes.length;}
    await verify();recoverySafe(h.digest('hex')===b.sha256,'BACKUP_PRIVATE_COPY_HASH');io.fsyncSync(fd);const s=io.fstatSync(fd),p=io.lstatSync(partial),d=io.lstatSync(dir);
    recoverySafe(s.isFile()&&s.nlink===1&&(s.mode&0o7777)===0o600&&s.uid===process.getuid()&&s.size===b.bytes&&s.ino===p.ino&&s.dev===p.dev&&identity.ino===d.ino&&identity.dev===d.dev,'BACKUP_PRIVATE_COPY_BYTES_MODE');
    // Atomic no-overwrite publication. No Docker operation during the brief link.
    io.linkSync(partial,path);io.unlinkSync(partial);const directory=io.openSync(dir,'r');try{io.fsyncSync(directory);}finally{io.closeSync(directory);}
  }finally{if(fd!==undefined)io.closeSync(fd);} // Partial evidence is NEVER erased on failure.
}
const BACKUP_READY = "const fs=require('node:fs');try{process.stdout.write(fs.readFileSync('/backup/ready.json','utf8'));}catch{process.stdout.write('{}');}";
const RECOVERY_READY = "const fs=require('node:fs');const n=Number(fs.readFileSync('/data/worker.ready','utf8')),start=Number(process.argv[1]);if(!Number.isFinite(n)||!Number.isFinite(start)||n<start||Date.now()-n<0||Date.now()-n>5000)process.exit(70);process.stdout.write('{\"ready\":true}');";
function secretlessControl(c, includeNetworks = false, legacyMounts = null) {
  const Config = structuredClone(c.Config); Config.Env = Config.Env.filter(v => !v.startsWith('SCAN_JWT_SECRET='));
  // Engine Mounts is an unordered observation. Do not sort command/env arrays or
  // HostConfig.Mounts (the caller's declarations), or discard any mount field.
  const Mounts = legacyMounts ?? [...c.Mounts].sort((a,b)=>a.Destination.localeCompare(b.Destination));
  safe(new Set(Mounts.map(m=>m.Destination)).size===Mounts.length);
  return controlHash({ Config, HostConfig: c.HostConfig, Mounts, ...(includeNetworks ? {NetworkSettings:c.NetworkSettings} : {}) });
}
function legacyMountContinuity(saved, current) {
  const projected=structuredClone(current.snapshot);
  for(const c of current.inventory.containers){const role=serviceOf(c),expected=saved.containers?.[role]?.controlSha256;
    if(projected.containers[role].controlSha256===expected)continue;
    // Only this explicit pre-lifecycle resume can read a V1 order-sensitive hash.
    // At most six independently validated profile mounts; every field is retained.
    safe(c.Mounts.length<=6);let matched=false;
    const visit=(prefix,remaining)=>{if(matched)return;if(!remaining.length){matched=secretlessControl(c,false,prefix)===expected;return;}
      for(let i=0;i<remaining.length;i++)visit([...prefix,remaining[i]],remaining.filter((_,j)=>i!==j));};
    visit([],c.Mounts);safe(matched);projected.containers[role].controlSha256=expected;
  }
  safe(equal(saved,projected));
}
function binaryBackup(path) {
  const s = fs.lstatSync(path);
  safe(s.isFile() && !s.isSymbolicLink() && s.nlink === 1 && s.uid === process.getuid() && (s.mode & 0o7777) === 0o600 && s.size > 0 && s.size <= 256 * 1024 ** 2);
  const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK), h = createHash('sha256'), b = Buffer.alloc(65536);
  try { const f = fs.fstatSync(fd); safe(f.isFile() && equal(fileStampFromStat(f),fileStampFromStat(s))); let n,total=0;
    while ((n = fs.readSync(fd, b, 0, b.length, null))) {total+=n;safe(total<=s.size);h.update(b.subarray(0, n));}
    safe(total===s.size);fs.fsyncSync(fd); safe(equal(fileStamp(path), fileStampFromStat(s))&&equal(fileStampFromStat(fs.fstatSync(fd)),fileStampFromStat(s))); }
  finally { fs.closeSync(fd); }
  return { bytes: s.size, sha256: h.digest('hex') };
}
function fileStampFromStat(s) { return { dev: s.dev, ino: s.ino, uid: s.uid, mode: s.mode, size: s.size, nlink: s.nlink, mtimeMs: s.mtimeMs, ctimeMs: s.ctimeMs }; }
async function priorRuntime(run, options, config, pins, secret, platform, stopped = []) {
  await recoveryStep('PRIOR_NAMESPACE_CENSUS',()=>exactRunningCensus(run,options));
  const out = { containers: [], volumes: [], networks: [] }, snapshot = { containers: {}, volumes: {}, networks: {} };
  for (const role of SERVICES) {
    const rows = JSON.parse(await run(['container', 'inspect', `${PROJECT}-${role}-1`], options)); safe(rows.length === 1);
    const c = rows[0]; recoverySafe(HEX_SHA.test(c.Id)&&c.Image===pins[role]&&c.Config?.Image===pins[role],'PRIOR_CONTAINER_IMAGE_PIN');
    const env = environment(c.Config.Env);
    // Spec environment, not image/container supplied configuration, defines reserved authority.
    const base = Object.fromEntries(Object.entries(env).filter(([key]) => !Object.hasOwn(config.services[role].environment ?? {}, key)));
    recoverySafe(['OnBuild','Shell','Volumes','StopTimeout'].every(k=>neutral(c.Config[k])),'PRIOR_STARTUP_AUTHORITY');
    recoverySync('PRIOR_BASE_ENVIRONMENT',()=>validateBaseEnvironment(base,role));
    recoverySync('PRIOR_CONTAINER_SECURITY_CONTROLS',()=>validateRuntimeContainer(c,role,config.services[role],config,{secret,platform},base));
    if(stopped.includes(role))recoverySafe(c.State.Running===false&&c.State.Status==='exited'&&([0,...(role==='web'?[143]:[])].includes(c.State.ExitCode))&&c.State.Pid===0&&!c.State.OOMKilled&&!c.State.Restarting&&!c.State.Dead,'PRIOR_WRITER_CLEAN_STOP');
    else recoverySync('PRIOR_RUNNING_PROCESS_STATE',()=>runningState(c,role,config));
    snapshot.containers[role] = { id: c.Id, image: c.Image, controlSha256: secretlessControl(c),
      process: { startedAt: c.State.StartedAt, finishedAt: c.State.FinishedAt, pid: c.State.Pid, restartCount: c.RestartCount },
      networksSha256: controlHash(c.NetworkSettings), running: c.State.Running };
    out.containers.push(c);
  }
  for (const key of VOLUMES) {
    const rows = JSON.parse(await run(['volume', 'inspect', `${PROJECT}_${key}`], options)); safe(rows.length === 1);
    const v=rows[0];recoverySafe(v.Name===`${PROJECT}_${key}`&&owned(v.Labels)&&v.Labels['com.docker.compose.volume']===key&&v.Driver==='local'&&v.Scope==='local'&&neutral(v.Options)&&timestamp(v.CreatedAt),'PRIOR_VOLUME_IDENTITY_DRIVER');
    const consumers = (await run(['container', 'ls', '--all', '--filter', `volume=${v.Name}`, '--format', '{{.ID}}', '--no-trunc'], options)).trim().split('\n').filter(Boolean);
    recoverySafe(equal(sorted(consumers),sorted(out.containers.filter(c=>c.Mounts.some(m=>m.Type==='volume'&&m.Name===v.Name)).map(c=>c.Id))),'PRIOR_VOLUME_EXACT_CONSUMERS');
    snapshot.volumes[key] = controlHash(v); out.volumes.push(v);
  }
  const ranges = [];
  for (const key of NETWORKS) {
    const rows = JSON.parse(await run(['network', 'inspect', `${PROJECT}_${key}`], options)); safe(rows.length === 1);
    const n=rows[0],base=recoverySync('PRIOR_NETWORK_DRIVER_IPAM',()=>defaultOwnNetwork({...n,Containers:{}},key,NETWORKS));ranges.push(recoverySync('PRIOR_NETWORK_SUBNET',()=>defaultSubnet(base.IPAM.Config[0])));
    const members = out.containers.filter(c => c.State.Running && CONNECTIONS[serviceOf(c)].includes(key));
    recoverySafe(equal(sorted(Object.keys(n.Containers??{})),sorted(members.map(c=>c.Id))),'PRIOR_NETWORK_MEMBERSHIP');
    for(const c of members)recoverySafe(c.NetworkSettings.Networks[n.Name].NetworkID===n.Id&&n.Containers[c.Id].Name===c.Name.slice(1)&&HEX_SHA.test(n.Containers[c.Id].EndpointID)&&n.Containers[c.Id].EndpointID===c.NetworkSettings.Networks[n.Name].EndpointID,'PRIOR_NETWORK_ENDPOINT_IDENTITY');
    snapshot.networks[key] = { id: n.Id, controlSha256: controlHash({ ...n, Containers: {} }), endpointsSha256: controlHash(n.Containers) }; out.networks.push(n);
  }
  recoverySafe(new Set(out.networks.map(n=>n.Id)).size===4&&ranges.every((a,i)=>ranges.every((b,j)=>i===j||a.last<b.first||b.last<a.first)),'PRIOR_NETWORK_DISJOINT_RANGES');
  await recoveryStep('PRIOR_FINAL_NAMESPACE_CENSUS',()=>exactRunningCensus(run,options));return {inventory:out,snapshot};
}
function priorContinuity(before,after,stopped){
  recoverySafe(equal(before.volumes,after.volumes),'CONTINUITY_VOLUME_IDENTITY');
  for(const key of NETWORKS)recoverySafe(before.networks[key].id===after.networks[key].id&&before.networks[key].controlSha256===after.networks[key].controlSha256,'CONTINUITY_NETWORK_IDENTITY');
  for(const role of SERVICES){const a=before.containers[role],b=after.containers[role];
    recoverySafe(a.id===b.id&&a.image===b.image&&a.controlSha256===b.controlSha256,'CONTINUITY_CONTAINER_CONTROLS');
    recoverySafe(a.process.startedAt===b.process.startedAt&&a.process.restartCount===b.process.restartCount,'CONTINUITY_PROCESS_IDENTITY');
    if(!stopped.includes(role)||a.running===false)recoverySafe(equal(a,b),'CONTINUITY_PROCESS_NETWORK_STATE');}
}
function backupArguments(name, image, purpose = 'backup') {
  safe(['backup','drain'].includes(purpose));
  return ['create', '--pull', 'never', '--name', name, '--label', `${LABEL}=v1`, '--label', `com.docker.compose.project=${PROJECT}`,
    '--label', 'org.diplom.recovery-helper=v1', '--label', 'org.diplom.recovery-purpose='+purpose, '--network', 'none', '--read-only', '--user', '65532:65532', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges', '--memory', '1073741824', '--memory-swap', '1073741824', '--cpus', '1', '--pids-limit', '32', '--restart', 'no',
    '--tmpfs', '/backup:rw,noexec,nosuid,uid=65532,gid=65532,size=512m',
    ...(purpose==='backup'?['--mount',`type=volume,src=${PROJECT}_auth_accounts,dst=/auth,readonly,volume-nocopy`]:[]), '--mount', `type=volume,src=${PROJECT}_scan_ledger,dst=/data,readonly,volume-nocopy`,
    '--workdir', '/app/server/api', '--entrypoint', 'node', image, '--input-type=module', '-e', purpose==='backup'?RECOVERY_BACKUP:RECOVERY_PROBE_SERVICE];
}
const HELPER_FIXED={MemoryReservation:0,CpuShares:0,CpuPeriod:0,CpuQuota:0,CpuRealtimePeriod:0,CpuRealtimeRuntime:0,CpusetCpus:'',CpusetMems:'',OomScoreAdj:0,
  ShmSize:67108864,IpcMode:'private',PidMode:'',UTSMode:'',UsernsMode:'',CgroupParent:'',CgroupnsMode:'private',Runtime:'runc'};
const HELPER_HOST_FIELDS=[...Object.keys(HELPER_FIXED),'Memory','MemorySwap','NanoCpus','PidsLimit','ReadonlyRootfs','Privileged','AutoRemove','NetworkMode','PortBindings','PublishAllPorts',
  'CapDrop','CapAdd','SecurityOpt','Tmpfs','RestartPolicy','Mounts','MaskedPaths','ReadonlyPaths','MemorySwappiness','OomKillDisable','ConsoleSize','LogConfig'];
export function validateBackupHelper(c, name, image, purpose = 'backup', state = 'running', legacyBackup = false) {
  recoverySafe(['backup','drain'].includes(purpose)&&['created','running','exited'].includes(state),'HELPER_POLICY_ARGUMENTS');
  const h=c.HostConfig,conf=c.Config,s=c.State,program=purpose==='backup'?(legacyBackup?LEGACY_RECOVERY_BACKUP:RECOVERY_BACKUP):RECOVERY_PROBE_SERVICE;
  recoverySafe(s?.Status===state&&s.Running===(state==='running')&&Number.isSafeInteger(s.Pid)&&(state==='running'?s.Pid>0:s.Pid===0)&&!s.Restarting&&!s.OOMKilled&&!s.Dead,'HELPER_STATE');
  recoverySafe(HEX_SHA.test(c.Id)&&c.Name==='/'+name&&owned(conf?.Labels)&&conf.Labels['org.diplom.recovery-helper']==='v1'&&conf.Labels['org.diplom.recovery-purpose']===purpose,'HELPER_IDENTITY_LABELS');
  recoverySafe(c.Image===image.Id&&conf.Image===image.Id,'HELPER_IMMUTABLE_IMAGE');
  recoverySafe(equal(conf.Entrypoint,['node'])&&equal(conf.Cmd,['--input-type=module','-e',program]),'HELPER_ENTRYPOINT_PROGRAM');
    recoverySafe(c.Path==='node'&&equal(c.Args,conf.Cmd),'HELPER_EXECUTABLE_ARGS');
  recoverySafe(conf.User==='65532:65532'&&conf.WorkingDir==='/app/server/api','HELPER_USER_DIRECTORY');
  recoverySafe(equal(conf.Env,image.Config.Env)&&neutral(conf.Healthcheck)&&['OnBuild','Shell','Volumes','StopTimeout','StopSignal'].every(k=>neutral(conf[k])),'HELPER_ENV_STARTUP_AUTHORITY');
  recoverySafe(h?.ReadonlyRootfs===true&&h.Privileged===false&&h.AutoRemove===false&&h.NetworkMode==='none'&&neutral(h.PortBindings)&&h.PublishAllPorts===false,'HELPER_READONLY_NETWORK');
  recoverySafe(h.Memory===1073741824&&h.MemorySwap===1073741824&&h.NanoCpus===1e9&&h.PidsLimit===32,'HELPER_RESOURCES');
  recoverySafe(equal(sorted(h.CapDrop),['ALL'])&&neutral(h.CapAdd)&&equal((h.SecurityOpt??[]).map(v=>v==='no-new-privileges'?'no-new-privileges:true':v),['no-new-privileges:true']),'HELPER_CAPABILITIES');
  recoverySafe(equal(tmpfs(Object.entries(h.Tmpfs??{}).map(([k,v])=>k+':'+v)),tmpfs(['/backup:rw,noexec,nosuid,uid=65532,gid=65532,size=512m'])),'HELPER_TMPFS');
  recoverySafe((keys(c.NetworkSettings?.Networks,['none'])||state==='created'&&equal(c.NetworkSettings?.Networks,{}))&&equal(h.RestartPolicy,{Name:'no',MaximumRetryCount:0}),'HELPER_NETWORK_RESTART');
  const fixed=HELPER_FIXED;
  recoverySafe(Object.entries(fixed).every(([k,v])=>h[k]===v),'HELPER_RESOURCE_NAMESPACE_DEFAULTS');
  recoverySafe(equal(h.MaskedPaths,MASKED)&&equal(h.ReadonlyPaths,READONLY),'HELPER_KERNEL_PATHS');
  recoverySafe([null,-1].includes(h.MemorySwappiness)&&[null,false].includes(h.OomKillDisable)&&equal(h.ConsoleSize,[0,0])&&['local','json-file'].includes(h.LogConfig?.Type)&&equal(h.LogConfig.Config??{},{}),'HELPER_ENGINE_DEFAULTS');
  const handled=HELPER_HOST_FIELDS;
  recoverySafe(Object.entries(h).every(([k,v])=>handled.includes(k)||neutral(v)),'HELPER_UNKNOWN_HOST_AUTHORITY');
  recoverySafe(!conf.Tty&&!conf.OpenStdin&&!conf.StdinOnce&&!conf.AttachStdin&&!conf.NetworkDisabled&&!conf.Domainname&&neutral(conf.ExposedPorts)&&neutral(c.NetworkSettings.Ports)&&!c.ProcessLabel&&!c.MountLabel&&['','docker-default'].includes(c.AppArmorProfile??'')&&allowedArgsEscaped('api',conf.ArgsEscaped),'HELPER_EXTRA_EXECUTION_AUTHORITY');
  const mounts=purpose==='backup'?[['auth_accounts','/auth'],['scan_ledger','/data']]:[['scan_ledger','/data']];
  recoverySafe(h.Mounts?.length===mounts.length&&c.Mounts?.filter(m=>m.Type!=='tmpfs').length===mounts.length&&c.Mounts.filter(m=>m.Type==='tmpfs').every(m=>m.Destination==='/backup'),'HELPER_MOUNT_SET');
  for(const[key,target]of mounts){
    const declarations=h.Mounts.filter(m=>m.Target===target),observed=c.Mounts.filter(m=>m.Destination===target);
    recoverySafe(declarations.length===1&&observed.length===1,'HELPER_MOUNT_UNIQUENESS');const m=declarations[0],o=observed[0],v=m.VolumeOptions;
    recoverySafe(m.Type==='volume'&&m.Source===`${PROJECT}_${key}`&&m.ReadOnly===true&&neutral(m.BindOptions)&&Object.entries(m).every(([k,x])=>['Type','Source','Target','ReadOnly','BindOptions','VolumeOptions'].includes(k)||neutral(x)),'HELPER_MOUNT_DECLARATION');
    // Engine create adds DriverConfig: {}. Only that exact empty object is inert;
    // null/custom driver/name/options, NoCopy:false and unknown options still refuse.
    recoverySafe(v?.NoCopy===true&&(keys(v,['NoCopy'])||keys(v,['NoCopy','DriverConfig'])&&equal(v.DriverConfig,{})),'HELPER_VOLUME_NOCOPY_DRIVER');
    recoverySafe(o.Type==='volume'&&o.Name===`${PROJECT}_${key}`&&o.RW===false&&!o.SubPath&&(!o.Propagation||o.Propagation==='rprivate'),'HELPER_MOUNT_OBSERVATION');
  }
}
function redeployHistory(root, pending = null) {
  const path = join(root, STATE, REDEPLOYS); if (!exists(path)) return;
  privateDirectory(path); safe(fs.readdirSync(path).length <= 4, 'Recovery backup history limit/HOLD; no automatic pruning.');
  for (const name of fs.readdirSync(path)) {
    safe(/^redeploy-[a-f0-9]{32}$/.test(name)); const dir = join(path,name); privateDirectory(dir);
    if(name===pending)continue;
    const { value: result, bytes } = canonicalJson(join(dir,'result.json')), { value: complete } = canonicalJson(join(dir,'completion.json'));
    safe(keys(result,['version','project','operation','originalImageMetadataVerified','rollbackToPriorImages','originalLockIdentity','originalMarkerIdentity','originalMutationSha256',
      'backups','images','containers','jwtPreserved','cve','at']) && result.version===1 && result.operation === 'RECOVERED_REDEPLOY_PRIOR_IMAGES_UNVERIFIED' && result.project === PROJECT && result.rollbackToPriorImages === false &&
      result.originalImageMetadataVerified === false && result.jwtPreserved===true && timestamp(result.at) && HEX_SHA.test(result.originalMutationSha256) &&
      keys(complete,['version','project','operation','resultSha256','files']) && complete.version===1 && complete.project===PROJECT && complete.operation === result.operation && complete.resultSha256 === sha(bytes));
    safe(keys(result.images,SERVICES) && Object.values(result.images).every(i=>keys(i,['image'])&&IMAGE_ID.test(i.image)) && keys(result.backups,['auth','ledger']));
    safe(Array.isArray(result.containers)&&result.containers.length===6&&equal(sorted(result.containers.map(c=>c.role)),sorted(SERVICES))&&new Set(result.containers.map(c=>c.id)).size===6&&
      result.containers.every(c=>keys(c,['id','role','image'])&&HEX_SHA.test(c.id)&&c.image===result.images[c.role].image));
    publicImageCveConfig(root,result.cve);
    const required=['intent.json','baseline.json','prior-pins.json','candidate.images.json','helper-drain.json','helper-backup.json','backup-receipt.json','saved-main-pins.json','result.json'];
    safe(required.every(n=>Object.hasOwn(complete.files,n)) && Object.keys(complete.files).every(n=>required.includes(n)||/^phase-\d{3}\.json$/.test(n)||['failure.json','resume.json','resume-baseline.json','continue-drain.json','continue-drain-baseline.json','continue-failure.json','started-drain.json','started-drain-baseline.json','helper-drain-next.json','backup-export-manifest.json','backup-export-verified.json','backup-transfer.json','backup-transfer-baseline.json','started-failure.json','helper-backup-export.json','backup-generation.json','backup-original-manifest.json'].includes(n)));
    safe(equal(sorted(fs.readdirSync(dir)),sorted([...Object.keys(complete.files),'completion.json','backups','original-operation.lock','recovery-operation.lock'])));
    for(const [n,f] of Object.entries(complete.files))safe(keys(f,['sha256','identity'])&&HEX_SHA.test(f.sha256)&&sha(privateRead(join(dir,n),131072))===f.sha256&&equal(fileIdentity(join(dir,n)),f.identity));
    const intent=canonicalJson(join(dir,'intent.json')).value;
    safe(intent.operation==='recover-build-and-redeploy'&&intent.project===PROJECT&&intent.acknowledgement===REDEPLOY_ACK&&intent.helperPolicy==='CREATE_INSPECT_START_V2'&&intent.originalImageMetadataVerified===false&&
      intent.rollbackToPriorImages===false&&intent.originalMutationSha256===result.originalMutationSha256&&equal(intent.originalLockIdentity,result.originalLockIdentity)&&equal(intent.originalMarkerIdentity,result.originalMarkerIdentity));
    safe(equal(canonicalJson(join(dir,'candidate.images.json')).value.services,result.images)&&equal(canonicalJson(join(dir,'backup-receipt.json')).value,result.backups));
    safe(equal(canonicalJson(join(dir,'saved-main-pins.json')).value,canonicalJson(join(dir,'prior-pins.json')).value));
    const original = join(dir,'original-operation.lock'); verifyDirectory(original,result.originalLockIdentity);
    safe(sha(privateRead(join(original,'mutation.json'))) === result.originalMutationSha256 && equal(fileIdentity(join(original,'mutation.json')),result.originalMarkerIdentity));
    const originalNames=sorted(fs.readdirSync(original));safe(equal(originalNames,['mutation.json'])||equal(originalNames,['build-evidence.json','build-failure.json','mutation.json']));
    runningBuildMarker(privateRead(join(original,'mutation.json')),intent.endpoint);
    const recoveryLock=join(dir,'recovery-operation.lock');privateDirectory(recoveryLock);
    const resumed=Object.hasOwn(complete.files,'resume.json');
    const continued=Object.hasOwn(complete.files,'continue-drain.json');
    const started=Object.hasOwn(complete.files,'started-drain.json'),transferred=Object.hasOwn(complete.files,'backup-transfer.json');
    safe(equal(sorted(fs.readdirSync(recoveryLock)),transferred?['backup-transfer.lock','continue-drain.lock','intent.json','resume.lock','started-drain.lock']:started?['continue-drain.lock','intent.json','resume.lock','started-drain.lock']:continued?['continue-drain.lock','intent.json','resume.lock']:resumed?['intent.json','resume.lock']:['intent.json'])&&equal(canonicalJson(join(recoveryLock,'intent.json')).value,intent));
    if(resumed){const receipt=canonicalJson(join(dir,'resume.json')).value;
      safe(Object.hasOwn(complete.files,'failure.json')&&Object.hasOwn(complete.files,'resume-baseline.json'));
      validateResumeReceipt(receipt,dir,intent);privateDirectory(join(recoveryLock,'resume.lock'));
      safe(equal(fs.readdirSync(join(recoveryLock,'resume.lock')),['receipt.json'])&&equal(canonicalJson(join(recoveryLock,'resume.lock/receipt.json')).value,receipt));
    }else safe(!Object.hasOwn(complete.files,'failure.json')&&!Object.hasOwn(complete.files,'resume-baseline.json'));
    if(continued){recoverySafe(resumed&&Object.hasOwn(complete.files,'continue-drain-baseline.json'),'CONTINUE_HISTORY_BASELINE');const r=canonicalJson(join(dir,'continue-drain.json')).value;
      validateCreatedDrainReceipt(r,dir);privateDirectory(join(recoveryLock,'continue-drain.lock'));recoverySafe(equal(fs.readdirSync(join(recoveryLock,'continue-drain.lock')),['receipt.json'])&&equal(canonicalJson(join(recoveryLock,'continue-drain.lock/receipt.json')).value,r),'CONTINUE_HISTORY_RECEIPT');
    }else safe(!Object.hasOwn(complete.files,'continue-drain-baseline.json'));
    if(started){recoverySafe(continued&&Object.hasOwn(complete.files,'continue-failure.json')&&Object.hasOwn(complete.files,'started-drain-baseline.json'),'STARTED_HISTORY_EVIDENCE');const r=canonicalJson(join(dir,'started-drain.json')).value;validateStartedDrainReceipt(r,dir);
      privateDirectory(join(recoveryLock,'started-drain.lock'));recoverySafe(equal(fs.readdirSync(join(recoveryLock,'started-drain.lock')),['receipt.json'])&&equal(canonicalJson(join(recoveryLock,'started-drain.lock/receipt.json')).value,r),'STARTED_HISTORY_RECEIPT');
      if(Object.hasOwn(complete.files,'helper-drain-next.json')){const next=canonicalJson(join(dir,'helper-drain-next.json')).value;recoverySafe(next.name===r.helper.name+'-next'&&next.id!==r.helper.id&&next.image===r.helper.image&&next.controlPolicy==='HELPER_AUTHORITY_V3','STARTED_HISTORY_REPLACEMENT_PROBE');}
    }else recoverySafe(!Object.hasOwn(complete.files,'continue-failure.json')&&!Object.hasOwn(complete.files,'started-drain-baseline.json')&&!Object.hasOwn(complete.files,'helper-drain-next.json'),'STARTED_HISTORY_NO_UNACKNOWLEDGED_EXTRAS');
    if(transferred){recoverySafe(started&&['started-failure.json','backup-transfer-baseline.json','helper-backup-export.json','backup-generation.json','backup-export-manifest.json','backup-export-verified.json'].every(n=>Object.hasOwn(complete.files,n)),'BACKUP_TRANSFER_HISTORY_FILES');
      const r=canonicalJson(join(dir,'backup-transfer.json')).value;validateBackupTransferReceipt(r,dir);privateDirectory(join(recoveryLock,'backup-transfer.lock'));
      recoverySafe(equal(fs.readdirSync(join(recoveryLock,'backup-transfer.lock')),['receipt.json'])&&equal(canonicalJson(join(recoveryLock,'backup-transfer.lock/receipt.json')).value,r),'BACKUP_TRANSFER_HISTORY_RECEIPT');
      const h=canonicalJson(join(dir,'helper-backup-export.json')).value;recoverySafe(h.id!==r.helper.id&&h.name===r.helper.name+'-export'&&h.image===r.helper.image&&h.purpose==='backup'&&h.controlPolicy==='HELPER_AUTHORITY_V3','BACKUP_TRANSFER_HISTORY_HELPER');
      const generation=canonicalJson(join(dir,'backup-generation.json')).value;recoverySafe(keys(generation,['version','originalSnapshots','policy'])&&generation.version===1&&generation.policy==='REGENERATE_FROM_VERIFIED_QUIESCENT_SOURCES_NO_OLD_RESTART'&&['RECEIPT_AND_SOURCE_FENCES_CAPTURED','LEGACY_TMPFS_EXPIRED_NO_DURABLE_SNAPSHOT_RECEIPT'].includes(generation.originalSnapshots),'BACKUP_TRANSFER_GENERATION_RECORD');
      if(generation.originalSnapshots==='RECEIPT_AND_SOURCE_FENCES_CAPTURED'){const original=canonicalJson(join(dir,'backup-original-manifest.json')).value,current=canonicalJson(join(dir,'backup-export-manifest.json')).value;validateExportManifest(original);recoverySafe(equal(original.receipt,current.receipt)&&equal(original.sources,current.sources),'BACKUP_TRANSFER_GENERATION_SOURCE_HASHES');}
    }else recoverySafe(!['started-failure.json','backup-transfer-baseline.json','helper-backup-export.json','backup-generation.json','backup-original-manifest.json'].some(n=>Object.hasOwn(complete.files,n)),'BACKUP_TRANSFER_NO_UNACKNOWLEDGED_FILES');
    if(Object.hasOwn(complete.files,'backup-export-manifest.json')){const m=canonicalJson(join(dir,'backup-export-manifest.json')).value,v=canonicalJson(join(dir,'backup-export-verified.json')).value;validateExportManifest(m);
      recoverySafe(equal(m.receipt,result.backups)&&equal(v,{version:1,manifestSha256:sha(JSON.stringify(m)),transport:'VALIDATED_EXEC_BOUNDED_BASE64_V1'}),'BACKUP_EXPORT_HISTORY');}
    privateDirectory(join(dir,'backups'));safe(equal(sorted(fs.readdirSync(join(dir,'backups'))),['auth.sqlite','ledger.sqlite']));
    for (const role of ['auth','ledger']) {const b=result.backups[role];safe(keys(b,['logicalSha256','sha256','bytes','integrity'])&&HEX_SHA.test(b.logicalSha256)&&b.integrity==='ok'&&
      equal(binaryBackup(join(dir,'backups',role+'.sqlite')), {bytes:b.bytes,sha256:b.sha256}));}
  }
}
function fileIdentity(path) { const s = fs.lstatSync(path); return {dev:s.dev,ino:s.ino}; }
const RESUME_PHASES=['build-submission','build-egress','build-worker','build-api','build-web','new-image-validation'];
function preLifecycleResume(root,name) {
  safe(/^redeploy-[a-f0-9]{32}$/.test(name));const dir=join(root,STATE),audit=join(dir,REDEPLOYS,name),guard=join(dir,REDEPLOY_GUARD);
  const auditId=directoryIdentity(audit),guardId=directoryIdentity(guard),backupsId=directoryIdentity(join(audit,'backups'));
  const names=sorted(['intent.json','baseline.json','prior-pins.json','candidate.images.json','failure.json','backups',...RESUME_PHASES.map((_,i)=>`phase-${String(i+1).padStart(3,'0')}.json`)]);
  safe(equal(sorted(fs.readdirSync(audit)),names)&&equal(fs.readdirSync(guard),['intent.json'])&&fs.readdirSync(join(audit,'backups')).length===0);
  const files=new Map(names.filter(n=>n!=='backups').map(n=>[n,captureFile(join(audit,n),131072)]));
  const parse=n=>{const f=files.get(n),v=JSON.parse(f.bytes);safe(f.bytes===JSON.stringify(v));return v;};
  const intent=parse('intent.json'),guardIntent=captureFile(join(guard,'intent.json'),131072),failure=parse('failure.json');
  safe(guardIntent.bytes===files.get('intent.json').bytes&&keys(failure,['version','project','checkpoint','failure','at'])&&failure.version===1&&failure.project===PROJECT&&failure.checkpoint==='new-image-validation'&&failure.failure==='guard'&&timestamp(failure.at));
  let last=0;for(const [i,phase]of RESUME_PHASES.entries()){const p=parse(`phase-${String(i+1).padStart(3,'0')}.json`);safe(keys(p,['version','phase','at'])&&p.version===1&&p.phase===phase&&timestamp(p.at)&&Date.parse(p.at)>=last);last=Date.parse(p.at);}
  safe(Date.parse(failure.at)>=last);const candidate=parse('candidate.images.json');readImagePins(JSON.stringify(candidate));
  return {names,files,intent,baseline:parse('baseline.json'),priorPins:parse('prior-pins.json'),candidate,verify(at=guard){
    verifyDirectory(audit,auditId);verifyDirectory(at,guardId);verifyDirectory(join(audit,'backups'),backupsId);
    files.forEach((f,n)=>f.verify(join(audit,n)));guardIntent.verify(join(at,'intent.json'));
    safe(equal(sorted(fs.readdirSync(at)),exists(join(at,'resume.lock'))?['intent.json','resume.lock']:['intent.json']));
  }};
}
function validateResumeReceipt(receipt,dir,intent) {
  safe(keys(receipt,['version','project','operation','acknowledgement','audit','endpoint','originalFailureSha256','originalFiles','canonicalMountPolicy','stateIdentity','stateFiles','dataPolicy','at'])&&
    receipt.version===1&&receipt.project===PROJECT&&receipt.operation==='RESUME_PRE_LIFECYCLE_ONLY'&&receipt.acknowledgement==='--ack-pre-lifecycle-only'&&
    receipt.audit===dir.slice(dir.lastIndexOf('/')+1)&&receipt.endpoint===intent.endpoint&&receipt.canonicalMountPolicy==='RUNTIME_MOUNTS_BY_DESTINATION_V1'&&
    receipt.dataPolicy==='SAME_LIVE_VOLUMES_NO_LAUNCHER_DB_ACCESS_BEFORE_QUIESCENCE'&&timestamp(receipt.at)&&keys(receipt.stateFiles,['profile','jwt','pins']));
  const names=['intent.json','baseline.json','prior-pins.json','candidate.images.json','failure.json',...RESUME_PHASES.map((_,i)=>`phase-${String(i+1).padStart(3,'0')}.json`)];
  safe(keys(receipt.originalFiles,names));for(const n of names){const f=receipt.originalFiles[n];safe(keys(f,['sha256','identity'])&&HEX_SHA.test(f.sha256)&&f.sha256===sha(privateRead(join(dir,n),131072))&&equal(f.identity,fileIdentity(join(dir,n))));}
  safe(receipt.originalFailureSha256===receipt.originalFiles['failure.json'].sha256&&keys(receipt.stateIdentity,['dev','ino','uid','mode'])&&
    Object.values(receipt.stateIdentity).every(Number.isSafeInteger)&&receipt.stateIdentity.uid===process.getuid()&&(receipt.stateIdentity.mode&0o7777)===0o700);
  for(const f of Object.values(receipt.stateFiles))safe(keys(f,['dev','ino'])&&Number.isSafeInteger(f.dev)&&Number.isSafeInteger(f.ino));
  const failure=canonicalJson(join(dir,'failure.json')).value;safe(keys(failure,['version','project','checkpoint','failure','at'])&&failure.version===1&&failure.project===PROJECT&&failure.checkpoint==='new-image-validation'&&failure.failure==='guard'&&timestamp(failure.at));
  let last=0;for(const [i,phase]of RESUME_PHASES.entries()){const p=canonicalJson(join(dir,`phase-${String(i+1).padStart(3,'0')}.json`)).value;
    safe(keys(p,['version','phase','at'])&&p.version===1&&p.phase===phase&&timestamp(p.at)&&Date.parse(p.at)>=last);last=Date.parse(p.at);}
  safe(Date.parse(failure.at)>=last&&Date.parse(receipt.at)>=Date.parse(failure.at));
}
const CREATED_DRAIN_PHASES=[...RESUME_PHASES,'resume-authorized','stop-web','stop-api','drain-helper-submission'];
// Call only AFTER independent helper-policy validation on every observation.
// Unknown nonneutral HostConfig authority still refuses in validateBackupHelper;
// unknown neutral fields have no authority and are not identity evidence.
export function helperAuthorityProjection(c){
  const Config=structuredClone(c.Config),h=c.HostConfig,HostConfig=Object.fromEntries(HELPER_HOST_FIELDS.map(k=>[k,structuredClone(h[k])]));
  recoverySafe([null,false].includes(h.OomKillDisable)&&[null,-1].includes(h.MemorySwappiness),'HELPER_DEFAULT_EQUIVALENCE');
  HostConfig.OomKillDisable=false;HostConfig.MemorySwappiness=null;HostConfig.CapAdd=[];HostConfig.PortBindings={};
  HostConfig.SecurityOpt=h.SecurityOpt.map(v=>v==='no-new-privileges'?'no-new-privileges:true':v);
  HostConfig.Tmpfs=tmpfs(Object.entries(h.Tmpfs).map(([k,v])=>k+':'+v));
  HostConfig.LogConfig={Type:h.LogConfig.Type,Config:{}};
  HostConfig.Mounts=h.Mounts.map(m=>{const v=m.VolumeOptions;recoverySafe(v?.NoCopy===true&&(keys(v,['NoCopy'])||keys(v,['NoCopy','DriverConfig'])&&equal(v.DriverConfig,{})),'HELPER_VOLUME_NOCOPY_DRIVER');
    return {Type:m.Type,Source:m.Source,Target:m.Target,ReadOnly:m.ReadOnly,VolumeOptions:{NoCopy:true}};}).sort((a,b)=>a.Target.localeCompare(b.Target));
  for(const k of ['Healthcheck','OnBuild','Volumes','Shell','StopTimeout','ExposedPorts'])if(neutral(Config[k]))delete Config[k];
  // Already validated as inert Linux Node metadata, not execution authority.
  delete Config.ArgsEscaped;
  return {Config,HostConfig};
}
const helperControl=c=>controlHash(helperAuthorityProjection(c));
function legacyCreatedHelperProof(c,record){
  if(record.controlPolicy==='HELPER_AUTHORITY_V3')return recoverySafe(helperControl(c)===record.createdControlSha256,'STARTED_HELPER_CREATED_AUTHORITY');
  recoverySafe(!Object.hasOwn(record,'controlPolicy'),'STARTED_HELPER_CONTROL_POLICY');
  // V2 recorded raw Config/HostConfig. Only the OBSERVED OOM false/null change
  // is permitted when reconstructing this historical digest; no broad fallback.
  recoverySafe([null,false].includes(c.HostConfig.OomKillDisable),'STARTED_HELPER_OOM_POLICY');
  recoverySafe([null,false].some(value=>controlHash({Config:c.Config,HostConfig:{...c.HostConfig,OomKillDisable:value}})===record.createdControlSha256),'STARTED_HELPER_LEGACY_CREATED_DIGEST');
}
const STARTED_DRAIN_PHASES=[...CREATED_DRAIN_PHASES,'continue-created-drain-authorized','drain-helper-start'];
const BACKUP_COPY_PHASES=[...STARTED_DRAIN_PHASES,'continue-started-drain-authorized','retire-started-drain-remove','drain-helper-submission','drain-helper-start','drain','drain-helper-stop','drain-helper-remove','stop-worker','writers-quiescent','backup-helper-submission','backup-helper-start','backup-copy'];
function createdDrainResume(root,name,started=false,backup=false){
  const dir=join(root,STATE),audit=join(dir,REDEPLOYS,name),guard=join(dir,REDEPLOY_GUARD);
  const auditId=directoryIdentity(audit),guardId=directoryIdentity(guard),backupId=directoryIdentity(join(audit,'backups')),resumeId=directoryIdentity(join(guard,'resume.lock'));
  const phaseList=backup?BACKUP_COPY_PHASES:started?STARTED_DRAIN_PHASES:CREATED_DRAIN_PHASES;
  const names=sorted(['intent.json','baseline.json','prior-pins.json','candidate.images.json','failure.json','resume.json','resume-baseline.json','backups',...(started?['continue-drain.json','continue-drain-baseline.json','continue-failure.json','helper-drain.json']:[]),...(backup?['started-drain.json','started-drain-baseline.json','started-failure.json','helper-drain-next.json','helper-backup.json']:[]),...phaseList.map((_,i)=>`phase-${String(i+1).padStart(3,'0')}.json`)]);
  recoverySafe(equal(sorted(fs.readdirSync(audit)),names)&&equal(sorted(fs.readdirSync(guard)),backup?['continue-drain.lock','intent.json','resume.lock','started-drain.lock']:started?['continue-drain.lock','intent.json','resume.lock']:['intent.json','resume.lock'])&&equal(fs.readdirSync(join(guard,'resume.lock')),['receipt.json'])&&fs.readdirSync(join(audit,'backups')).length===0,'CONTINUE_EXACT_EVIDENCE_SET');
  const files=new Map(names.filter(n=>n!=='backups').map(n=>[n,captureFile(join(audit,n),131072)]));
  const parse=n=>{const f=files.get(n),v=JSON.parse(f.bytes);recoverySafe(f.bytes===JSON.stringify(v),'CONTINUE_CANONICAL_RECORDS');return v;};
  const intent=parse('intent.json'),guardIntent=captureFile(join(guard,'intent.json')),receipt=parse('resume.json'),resumeReceipt=captureFile(join(guard,'resume.lock/receipt.json'),131072);
  recoverySafe(guardIntent.bytes===files.get('intent.json').bytes&&resumeReceipt.bytes===files.get('resume.json').bytes,'CONTINUE_PRIOR_RECEIPT_BYTES');
  validateResumeReceipt(receipt,audit,intent);recoverySafe(equal(receipt.stateIdentity,directoryIdentity(dir)),'CONTINUE_STATE_DIRECTORY_IDENTITY');
  for(const[key,n]of [['profile','profile.json'],['jwt','scan-jwt'],['pins','compose.images.json']])recoverySafe(equal(receipt.stateFiles[key],fileIdentity(join(dir,n))),'CONTINUE_STATE_FILE_IDENTITY');
  let last=0;const phases=phaseList.map((phase,i)=>{const p=parse(`phase-${String(i+1).padStart(3,'0')}.json`);recoverySafe(keys(p,['version','phase','at'])&&p.version===1&&p.phase===phase&&timestamp(p.at)&&Date.parse(p.at)>=last,'CONTINUE_EXACT_PHASE_CHAIN');last=Date.parse(p.at);return p;});
  const candidate=parse('candidate.images.json');readImagePins(JSON.stringify(candidate));
  let previousLock,previousReceipt,previousId,helperRecord,previousFailure,startedId,startedFile;
  if(started){const path=join(guard,'continue-drain.lock');previousId=directoryIdentity(path);recoverySafe(equal(fs.readdirSync(path),['receipt.json']),'STARTED_PRIOR_LOCK_FILES');previousReceipt=captureFile(join(path,'receipt.json'),131072);
    recoverySafe(previousReceipt.bytes===files.get('continue-drain.json').bytes,'STARTED_PRIOR_RECEIPT_BYTES');validateCreatedDrainReceipt(parse('continue-drain.json'),audit);
    helperRecord=parse('helper-drain.json');previousFailure=parse('continue-failure.json');
    recoverySafe((keys(helperRecord,['id','name','purpose','image','createdControlSha256'])||keys(helperRecord,['id','name','purpose','image','createdControlSha256','controlPolicy']))&&helperRecord.purpose==='drain'&&HEX_SHA.test(helperRecord.createdControlSha256),'STARTED_PRIOR_HELPER_RECORD');
    recoverySafe(keys(previousFailure,['version','project','checkpoint','reason','at'])&&previousFailure.version===1&&previousFailure.project===PROJECT&&previousFailure.checkpoint==='drain-helper-start'&&previousFailure.reason==='HELPER_CONTROL_IDENTITY'&&timestamp(previousFailure.at)&&Date.parse(previousFailure.at)>=Date.parse(phases[11].at),'STARTED_EXACT_PREVIOUS_FAILURE');
    previousLock=path;
  }
  if(backup){const path=join(guard,'started-drain.lock');startedId=directoryIdentity(path);recoverySafe(equal(fs.readdirSync(path),['receipt.json']),'BACKUP_PRIOR_LOCK_FILES');startedFile=captureFile(join(path,'receipt.json'),131072);
    recoverySafe(startedFile.bytes===files.get('started-drain.json').bytes,'BACKUP_PRIOR_RECEIPT_BYTES');validateStartedDrainReceipt(parse('started-drain.json'),audit);
    helperRecord=parse('helper-backup.json');previousFailure=parse('started-failure.json');
    recoverySafe(keys(helperRecord,['id','name','purpose','image','createdControlSha256','controlPolicy'])&&helperRecord.purpose==='backup'&&helperRecord.controlPolicy==='HELPER_AUTHORITY_V3'&&HEX_SHA.test(helperRecord.createdControlSha256),'BACKUP_PRIOR_HELPER_RECORD');
    recoverySafe(keys(previousFailure,['version','project','checkpoint','reason','at'])&&previousFailure.version===1&&previousFailure.project===PROJECT&&previousFailure.checkpoint==='backup-copy'&&previousFailure.reason==='DOCKER_UNCLASSIFIED'&&timestamp(previousFailure.at)&&Date.parse(previousFailure.at)>=Date.parse(phases[23].at),'BACKUP_EXACT_PREVIOUS_FAILURE');
  }
  return {names,files,intent,candidate,baseline:parse('baseline.json'),canonicalBaseline:parse('resume-baseline.json'),priorPins:parse('prior-pins.json'),phases,helperRecord,previousFailure,verify(at=guard){
    verifyDirectory(audit,auditId);verifyDirectory(at,guardId);verifyDirectory(join(audit,'backups'),backupId);verifyDirectory(join(at,'resume.lock'),resumeId);
    files.forEach((f,n)=>f.verify(join(audit,n)));guardIntent.verify(join(at,'intent.json'));resumeReceipt.verify(join(at,'resume.lock/receipt.json'));
    if(previousLock){verifyDirectory(join(at,'continue-drain.lock'),previousId);previousReceipt.verify(join(at,'continue-drain.lock/receipt.json'));}
    if(startedFile){verifyDirectory(join(at,'started-drain.lock'),startedId);startedFile.verify(join(at,'started-drain.lock/receipt.json'));}
    const expected=['intent.json','resume.lock',...(started||exists(join(at,'continue-drain.lock'))?['continue-drain.lock']:[]),...(started&&exists(join(at,'started-drain.lock'))?['started-drain.lock']:[]),...(backup&&exists(join(at,'backup-transfer.lock'))?['backup-transfer.lock']:[])];
    recoverySafe(equal(sorted(fs.readdirSync(at)),sorted(expected)),'CONTINUE_GUARD_RECORDS');
  }};
}
function scopedHelperRun(run,id,name,purpose){return async(args,options)=>{
  const text=await run(args,options);if(args[0]!=='container'||args[1]!=='ls'||!args.includes('--all'))return text;
  const rows=text.trim().split('\n').filter(Boolean);
  if(args.includes('--filter')){const filter=args[args.indexOf('--filter')+1];if(!filter.startsWith('volume='))return text;
    const mounted=filter===`volume=${PROJECT}_scan_ledger`||purpose==='backup'&&filter===`volume=${PROJECT}_auth_accounts`;
    recoverySafe(rows.filter(v=>v===id).length===(mounted?1:0),'HELPER_VOLUME_MEMBERSHIP');return rows.filter(v=>v!==id).join('\n');}
  const helperRows=rows.filter(v=>v.split('\t')[0]===name);recoverySafe(helperRows.length===1&&equal(helperRows[0].split('\t'),[name,PROJECT]),'HELPER_CENSUS_IDENTITY');
  return rows.filter(v=>v.split('\t')[0]!==name).join('\n');
};}
function neverStartedDrain(c){
  recoverySafe(c.RestartCount===0&&c.State.Status==='created'&&c.State.Running===false&&c.State.Pid===0&&c.State.ExitCode===0&&c.State.StartedAt==='0001-01-01T00:00:00Z'&&c.State.FinishedAt==='0001-01-01T00:00:00Z'&&neutral(c.State.Error)&&timestamp(c.Created),'CONTINUE_HELPER_NEVER_STARTED');
  recoverySafe(c.Path==='node'&&equal(c.Args,c.Config.Cmd),'CONTINUE_HELPER_EXECUTABLE');
}
function validateBackupTransferReceipt(r,dir){
  recoverySafe(keys(r,['version','project','operation','acknowledgement','audit','endpoint','helper','originalFiles','stateIdentity','stateFiles','at'])&&r.version===1&&r.project===PROJECT&&r.operation==='CONTINUE_QUIESCENT_BACKUP_TRANSFER'&&r.acknowledgement==='--ack-quiescent-backup-transfer'&&r.audit===dir.slice(dir.lastIndexOf('/')+1)&&timestamp(r.at),'BACKUP_TRANSFER_RECEIPT_SCHEMA');
  const expected=['intent.json','baseline.json','prior-pins.json','candidate.images.json','failure.json','resume.json','resume-baseline.json','continue-drain.json','continue-drain-baseline.json','continue-failure.json','helper-drain.json','started-drain.json','started-drain-baseline.json','started-failure.json','helper-drain-next.json','helper-backup.json',...BACKUP_COPY_PHASES.map((_,i)=>`phase-${String(i+1).padStart(3,'0')}.json`)];
  recoverySafe(keys(r.originalFiles,expected),'BACKUP_TRANSFER_RECEIPT_FILES');for(const[n,f]of Object.entries(r.originalFiles))recoverySafe(keys(f,['sha256','identity'])&&f.sha256===sha(privateRead(join(dir,n),131072))&&equal(f.identity,fileIdentity(join(dir,n))),'BACKUP_TRANSFER_RECEIPT_ORIGINAL_IDENTITY');
  const h=r.helper,previous=canonicalJson(join(dir,'started-drain.json')).value,record=canonicalJson(join(dir,'helper-backup.json')).value;
  recoverySafe(keys(h,['id','name','image','created','authoritySha256','epoch','state'])&&h.id===record.id&&h.name===record.name&&h.name===`${PROJECT}-recovery-${r.audit.slice(9)}-backup`&&h.image===record.image&&HEX_SHA.test(h.authoritySha256)&&timestamp(h.created)&&keys(h.epoch,['startedAt','pid','restartCount'])&&timestamp(h.epoch.startedAt)&&h.epoch.restartCount===0&&Number.isSafeInteger(h.epoch.pid)&&['running','exited'].includes(h.state)&&r.endpoint===previous.endpoint&&equal(r.stateIdentity,previous.stateIdentity)&&equal(r.stateFiles,previous.stateFiles),'BACKUP_TRANSFER_RECEIPT_BINDING');
}
function backupCopyState(c,evidence){const s=c.State;
  recoverySafe(c.Id===evidence.helperRecord.id&&c.Image===evidence.helperRecord.image&&c.RestartCount===0&&neutral(s.Error)&&timestamp(c.Created)&&Date.parse(c.Created)>=Date.parse(evidence.phases[21].at)&&timestamp(s.StartedAt)&&Date.parse(s.StartedAt)>=Date.parse(evidence.phases[22].at)&&Date.parse(s.StartedAt)<=Date.parse(evidence.phases[23].at),'BACKUP_HELPER_HISTORICAL_EPOCH');
  if(s.Status==='running'){recoverySafe(s.Running&&s.Pid>0&&s.FinishedAt==='0001-01-01T00:00:00Z','BACKUP_HELPER_RUNNING');return;}
  const elapsed=Date.parse(s.FinishedAt)-Date.parse(evidence.phases[23].at);
  recoverySafe(s.Status==='exited'&&!s.Running&&s.Pid===0&&s.ExitCode===0&&!s.OOMKilled&&timestamp(s.FinishedAt)&&Date.parse(s.FinishedAt)<=Date.now()+1000&&elapsed>=295000&&elapsed<=330000,'BACKUP_HELPER_CLEAN_LEGACY_EXPIRY');
}
function startedDrainState(c,evidence){
  const s=c.State;
  recoverySafe(c.RestartCount===0&&neutral(s.Error)&&timestamp(s.StartedAt)&&Date.parse(s.StartedAt)>=Date.parse(evidence.phases[11].at)&&Date.parse(s.StartedAt)<=Date.parse(evidence.previousFailure.at),'STARTED_HELPER_PROCESS_EPOCH');
  recoverySafe(c.Path==='node'&&equal(c.Args,c.Config.Cmd),'STARTED_HELPER_EXECUTABLE');
  if(s.Status==='running'){recoverySafe(s.Running&&s.Pid>0&&s.FinishedAt==='0001-01-01T00:00:00Z','STARTED_HELPER_RUNNING_STATE');return;}
  const elapsed=Date.parse(s.FinishedAt)-Date.parse(s.StartedAt);
  recoverySafe(s.Status==='exited'&&!s.Running&&s.Pid===0&&s.ExitCode===0&&!s.OOMKilled&&timestamp(s.FinishedAt)&&Date.parse(s.FinishedAt)<=Date.now()+1000&&elapsed>=355000&&elapsed<=390000,'STARTED_HELPER_CLEAN_TIMER_EXPIRY');
}
const helperEpoch=c=>({startedAt:c.State.StartedAt,pid:c.State.Pid,restartCount:c.RestartCount});
// Pure models derived from THIS engine's inspected shapes plus the normative
// policy and validated candidate images. No Docker create/exec or DB access.
// These detect configuration/default mismatches, not future native execution.
export function validateRemainingEngineShapes(helper,images,inventory,config,options){
  for(const role of Object.keys(FILES)){
    const c=structuredClone(inventory.containers.find(c=>serviceOf(c)===role)),image=images[role],spec=config.services[role];
    const base=validateImage(image,role);c.Image=image.Id;c.Config.Image=image.Id;c.Config.Cmd=structuredClone(spec.command);c.Config.Entrypoint=structuredClone(image.Config.Entrypoint??null);
    c.Config.User=spec.user;c.Config.WorkingDir=image.Config.WorkingDir;c.Config.ArgsEscaped=image.Config.ArgsEscaped;
    c.Config.Env=Object.entries({...base,...(spec.environment??{}),...(role==='api'?{SCAN_JWT_SECRET:options.secret}:{})}).map(([k,v])=>k+'='+v);
    c.Config.ExposedPorts=structuredClone(image.Config.ExposedPorts??{});c.Config.StopSignal=image.Config.StopSignal??'';
    c.State.Running=true;c.NetworkSettings.Ports=Object.fromEntries(Object.keys(c.Config.ExposedPorts).map(k=>[k,c.HostConfig.PortBindings?.[k]??null]));
    validateContainer(c,role,spec,image,config,{...options,images});
  }
  const image=images.api,model=structuredClone(helper),name=helper.Name.slice(1)+'-backup-model';
  model.Name='/'+name;model.Image=image.Id;model.Config={...model.Config,Image:image.Id,Env:structuredClone(image.Config.Env),Entrypoint:['node'],Cmd:['--input-type=module','-e',RECOVERY_BACKUP],Labels:{...model.Config.Labels,'org.diplom.recovery-purpose':'backup'}};
  model.Path='node';model.Args=structuredClone(model.Config.Cmd);
  model.HostConfig.Mounts=VOLUMES.map((key,i)=>({Type:'volume',Source:PROJECT+'_'+key,Target:i?'/data':'/auth',ReadOnly:true,VolumeOptions:{NoCopy:true,DriverConfig:{}}}));
  model.Mounts=VOLUMES.map((key,i)=>({Type:'volume',Name:PROJECT+'_'+key,Source:inventory.volumes.find(v=>v.Name===PROJECT+'_'+key).Mountpoint,Driver:'local',Destination:i?'/data':'/auth',Mode:'z',RW:false,Propagation:''}));
  let authority;
  for(const state of ['created','running']){model.State={Status:state,Running:state==='running',Pid:state==='running'?1:0,Restarting:false,OOMKilled:false,Dead:false};
    model.HostConfig.OomKillDisable=state==='created'?false:null;model.HostConfig.MemorySwappiness=state==='created'?null:-1;
    validateBackupHelper(model,name,image,'backup',state);const value=helperControl(model);if(authority)recoverySafe(authority===value,'REMAINING_HELPER_DEFAULT_MODEL');else authority=value;
  }
  return {candidateApplications:'validated-models',backupHelper:'validated-model',nativeExecution:'not-executed'};
}
function validateStartedDrainReceipt(r,dir){
  recoverySafe(keys(r,['version','project','operation','acknowledgement','audit','endpoint','helper','originalFiles','stateIdentity','stateFiles','at'])&&r.version===1&&r.project===PROJECT&&r.operation==='CONTINUE_STARTED_DRAIN_ONLY'&&r.acknowledgement==='--ack-started-drain-only'&&r.audit===dir.slice(dir.lastIndexOf('/')+1)&&timestamp(r.at),'STARTED_RECEIPT_SCHEMA');
  const h=r.helper;recoverySafe(keys(h,['id','name','image','created','authoritySha256','epoch','state'])&&HEX_SHA.test(h.id)&&h.name===`${PROJECT}-recovery-${r.audit.slice(9)}-drain`&&IMAGE_ID.test(h.image)&&HEX_SHA.test(h.authoritySha256)&&timestamp(h.created)&&['running','exited'].includes(h.state)&&keys(h.epoch,['startedAt','pid','restartCount'])&&timestamp(h.epoch.startedAt)&&h.epoch.restartCount===0&&Number.isSafeInteger(h.epoch.pid),'STARTED_RECEIPT_HELPER');
  const expected=['intent.json','baseline.json','prior-pins.json','candidate.images.json','failure.json','resume.json','resume-baseline.json','continue-drain.json','continue-drain-baseline.json','continue-failure.json','helper-drain.json',...STARTED_DRAIN_PHASES.map((_,i)=>`phase-${String(i+1).padStart(3,'0')}.json`)];
  recoverySafe(keys(r.originalFiles,expected),'STARTED_RECEIPT_FILES');for(const[n,f]of Object.entries(r.originalFiles))recoverySafe(keys(f,['sha256','identity'])&&f.sha256===sha(privateRead(join(dir,n),131072))&&equal(f.identity,fileIdentity(join(dir,n))),'STARTED_RECEIPT_ORIGINAL_IDENTITY');
  const previous=canonicalJson(join(dir,'continue-drain.json')).value;
  recoverySafe(equal(r.stateIdentity,previous.stateIdentity)&&equal(r.stateFiles,previous.stateFiles)&&r.endpoint===previous.endpoint&&h.id===previous.helper.id&&h.image===previous.helper.image&&h.created===previous.helper.created,'STARTED_RECEIPT_PRIOR_BINDING');
}
function validateCreatedDrainReceipt(r,dir){
  recoverySafe(keys(r,['version','project','operation','acknowledgement','audit','endpoint','helper','originalFiles','stateIdentity','stateFiles','at'])&&r.version===1&&r.project===PROJECT&&r.operation==='CONTINUE_CREATED_DRAIN_ONLY'&&r.acknowledgement==='--ack-created-drain-only'&&r.audit===dir.slice(dir.lastIndexOf('/')+1)&&timestamp(r.at),'CONTINUE_RECEIPT_SCHEMA');
  const h=r.helper;recoverySafe(keys(h,['id','name','image','created','controlSha256'])&&HEX_SHA.test(h.id)&&h.name===`${PROJECT}-recovery-${r.audit.slice(9)}-drain`&&IMAGE_ID.test(h.image)&&timestamp(h.created)&&HEX_SHA.test(h.controlSha256),'CONTINUE_RECEIPT_HELPER');
  const expected=['intent.json','baseline.json','prior-pins.json','candidate.images.json','failure.json','resume.json','resume-baseline.json',...CREATED_DRAIN_PHASES.map((_,i)=>`phase-${String(i+1).padStart(3,'0')}.json`)];
  recoverySafe(keys(r.originalFiles,expected),'CONTINUE_RECEIPT_FILES');for(const[n,f]of Object.entries(r.originalFiles))recoverySafe(keys(f,['sha256','identity'])&&f.sha256===sha(privateRead(join(dir,n),131072))&&equal(f.identity,fileIdentity(join(dir,n))),'CONTINUE_RECEIPT_ORIGINAL_IDENTITY');
  const intent=canonicalJson(join(dir,'intent.json')).value,resume=canonicalJson(join(dir,'resume.json')).value;
  recoverySafe(r.endpoint===intent.endpoint&&equal(r.stateIdentity,resume.stateIdentity)&&equal(r.stateFiles,resume.stateFiles),'CONTINUE_RECEIPT_STATE_ENDPOINT');
  const helper=canonicalJson(join(dir,'helper-drain.json')).value;recoverySafe(helper.id===h.id&&helper.name===h.name&&helper.image===h.image&&helper.createdControlSha256===h.controlSha256,'CONTINUE_RECEIPT_ADOPTED_HELPER');
}
async function recoverBuildAndRedeploy(root, run, ambient, verifyRelease, log, platform, sleep, request, checkpoint, resumeName = null, continuation = null) {
  const dir = join(root,STATE), original = join(dir,'.operation.lock'), guard = join(dir,REDEPLOY_GUARD);
  let stage = 'preflight', retained = false, guardId, audit, archiveGuard, guardMoved = false, committed = false;
    const auditFiles=new Map(); let guardIntent, auditIdentity, historyDirectory, historyIdentity, backupDirectory, backupIdentity, stateIdentity;
  let guardReason='RECOVERY_PREFLIGHT',resumeLockId,resumeReceipt,continueLockId,continueReceipt,continuationAccepted=false,startedLockId,startedReceipt,startedAccepted=false,transferLockId,transferReceipt,transferAccepted=false;
  const continuing=continuation!==null,checkOnly=continuation?.checkOnly===true,startedMode=continuation?.started===true,backupMode=continuation?.backup===true;
  const initialStopped=backupMode?['web','api','worker']:continuing?['web','api']:[];
  try {
    const stateId = directoryIdentity(dir);stateIdentity=stateId;
    safe(RECOVERY_GUARDS.filter(n=>!resumeName||n!==REDEPLOY_GUARD).every(n => !exists(join(dir,n))));
    let resuming=null;
    if(resumeName){guardReason=continuing?'CONTINUE_EVIDENCE_REFUSED':'RESUME_EVIDENCE_REFUSED';resuming=recoverySync(guardReason,()=>continuing?createdDrainResume(root,resumeName,startedMode||backupMode,backupMode):preLifecycleResume(root,resumeName));guardId=directoryIdentity(guard);retained=true;}
    assertReconciliationHistory(root,resumeName);
    const originalId = directoryIdentity(original), records = sorted(fs.readdirSync(original));
    safe(equal(records,['mutation.json']) || equal(records,['build-evidence.json','build-failure.json','mutation.json']));
    if(continuing)recoverySafe(equal(records,['mutation.json']),'CONTINUE_ORIGINAL_MARKER_SET');
    const originalFiles = records.map(name => [name,captureFile(join(original,name))]), marker = originalFiles.find(([n]) => n === 'mutation.json')[1]; runningBuildMarker(marker.bytes);
    const profileFile = captureFile(join(dir,'profile.json')), profile = readProfile(root); safe(profile !== undefined);
    const jwt = captureFile(join(dir,'scan-jwt'),96); safe(/^[a-f0-9]{96}$/.test(jwt.bytes));
    const pinsFile = captureFile(join(dir,'compose.images.json')), oldPins = readImagePins(pinsFile.bytes);
    const source = captureFile(join(root,'server/deploy/compose.public-images.yaml'),131072,true); validateReconciliationSource(source.bytes,root);
        const buildInputs=Object.fromEntries(['.gitignore','.dockerignore',...Object.values(FILES).map(n=>'server/deploy/'+n)].map(n=>{
          const path=join(root,n);safe(fs.realpathSync(path)===path);return [n,captureFile(path,131072,true)];}));
    const cveFile = profile.cve ? captureFile(join(dir,'compose.cve.json')) : null;
    safe(cveFile ? cveFile.bytes === JSON.stringify(cveOverlay(profile.cve)) : !exists(join(dir,'compose.cve.json')));
    if (profile.cve) verifyRelease(root,metadata(profile.cve));
    const publicStamps=profile.cve ? [profile.cve.releaseHostDir,join(profile.cve.releaseHostDir,'db'),profile.cve.publicKeyPath,
      ...['descriptor.json','descriptor.sig','bundle.bin','db/metadata.json','db/trivy.db'].map(n=>join(profile.cve.releaseHostDir,n))].map(p=>[p,fileStamp(p)]) : [];
    const allowedState=['.operation.lock','profile.json','scan-jwt','compose.images.json',...(profile.cve?['compose.cve.json']:[]),...(exists(join(dir,HISTORY))?[HISTORY]:[]),
      ...(exists(join(dir,REDEPLOYS))?[REDEPLOYS]:[])];
    let activePins = pinsFile, originalAt = original;
    const fence = () => {
      verifyDirectory(dir,stateId); verifyDirectory(originalAt,originalId); originalFiles.forEach(([n,f]) => f.verify(join(originalAt,n)));
      recoverySafe(equal(sorted(fs.readdirSync(originalAt)),records),'FENCE_ORIGINAL_RECORD_SET');
      recoverySync('FENCE_PROFILE_IDENTITY',()=>profileFile.verify());recoverySync('FENCE_JWT_IDENTITY',()=>jwt.verify());
      recoverySync('FENCE_COMPOSE_SOURCE_IDENTITY',()=>source.verify());recoverySync('FENCE_CVE_OVERLAY_IDENTITY',()=>cveFile?.verify());
      recoverySync('FENCE_ACTIVE_PINS_IDENTITY',()=>activePins.verify());recoverySync('FENCE_BUILD_IGNORES',()=>checkIgnores(root));
      if(profile.cve)recoverySync('FENCE_PUBLIC_CVE_VALIDATION',()=>verifyRelease(root,metadata(profile.cve)));
      recoverySafe(publicStamps.every(([p,s])=>equal(fileStamp(p),s)),'FENCE_PUBLIC_CVE_FILE_IDENTITY');
      safe(equal(sorted(fs.readdirSync(dir)),sorted([...allowedState.filter(n=>n!=='.operation.lock'||originalAt===original),
        ...(exists(join(dir,REDEPLOYS))&&!allowedState.includes(REDEPLOYS)?[REDEPLOYS]:[]),...(guardId&&!guardMoved?[REDEPLOY_GUARD]:[])])));
      if(auditIdentity){verifyDirectory(audit,auditIdentity);
        safe(equal(sorted(fs.readdirSync(audit)),sorted([...auditFiles.keys(),'backups',...(originalAt!==original?['original-operation.lock']:[]),...(guardMoved?['recovery-operation.lock']:[])])));}
      if(historyIdentity)verifyDirectory(historyDirectory,historyIdentity);if(backupIdentity)verifyDirectory(backupDirectory,backupIdentity);
      recoverySync('FENCE_DOCKERFILE_IGNORE_IDENTITY',()=>Object.values(buildInputs).forEach(f=>f.verify()));
      recoverySync('FENCE_AUDIT_FILE_IDENTITY',()=>auditFiles.forEach(f=>f.verify()));
      recoverySync('FENCE_RECOVERY_INTENT_IDENTITY',()=>guardIntent?.verify(guardMoved?join(archiveGuard,'intent.json'):join(guard,'intent.json')));
      if(resuming)resuming.verify(guardMoved?archiveGuard:guard);
      if(resumeLockId){const p=join(guardMoved?archiveGuard:guard,'resume.lock');verifyDirectory(p,resumeLockId);safe(equal(fs.readdirSync(p),['receipt.json']));resumeReceipt.verify(join(p,'receipt.json'));}
      if(continueLockId){const p=join(guardMoved?archiveGuard:guard,'continue-drain.lock');verifyDirectory(p,continueLockId);recoverySafe(equal(fs.readdirSync(p),['receipt.json']),'CONTINUE_LOCK_FILES');continueReceipt.verify(join(p,'receipt.json'));}
      if(startedLockId){const p=join(guardMoved?archiveGuard:guard,'started-drain.lock');verifyDirectory(p,startedLockId);recoverySafe(equal(fs.readdirSync(p),['receipt.json']),'STARTED_LOCK_FILES');startedReceipt.verify(join(p,'receipt.json'));}
      if(transferLockId){const p=join(guardMoved?archiveGuard:guard,'backup-transfer.lock');verifyDirectory(p,transferLockId);recoverySafe(equal(fs.readdirSync(p),['receipt.json']),'BACKUP_TRANSFER_LOCK_FILES');transferReceipt.verify(join(p,'receipt.json'));}
      if (guardId && !guardMoved) verifyDirectory(guard,guardId);
      safe(RECOVERY_GUARDS.filter(n => n !== REDEPLOY_GUARD).every(n => !exists(join(dir,n))));
    };
    fence(); let options = await requireLocalEngine(run,{root,env:dockerEnvironment(ambient)}); runningBuildMarker(marker.bytes,options.env.DOCKER_HOST);
    const deadline = performance.now()+1200_000;
    const d = (args, extra = {}) => { recoverySync('STATE_AUDIT_SOURCE_IDENTITY_FENCE',fence);const remaining=Math.floor(deadline-performance.now());recoverySafe(remaining>0,'RECOVERY_TOTAL_DEADLINE');
      if(checkOnly)recoverySafe(['container','volume','network','image'].includes(args[0])&&['ls','inspect'].includes(args[1])||args[0]==='compose'&&args.includes('config')&&!args.includes('build')&&!args.includes('up'),'CHECK_READ_ONLY_COMMAND');
      return recoveryStep('DOCKER_RESPONSE_UNCLASSIFIED',()=>run(args,{...options,...extra,env:extra.env??options.env,timeout:Math.min(extra.timeout??30000,remaining)})); };
    const config = expectedConfig(root,profile.cve);
    const adoptedName=continuing?`${PROJECT}-recovery-${resumeName.slice(9)}-${backupMode?'backup':'drain'}`:null;
    const scoped=continuing?scopedHelperRun(d,continuation.helperId,adoptedName,backupMode?'backup':'drain'):d;
    let adopted=null,adoptedImage=null,refreshDrain=false;
    const inspectAdopted=async()=>{await recoveryStep('CONTINUE_NAMESPACE_CENSUS',()=>exactRunningCensus(scoped,options));
      const rows=JSON.parse(await d(['container','inspect',adoptedName]));recoverySafe(rows.length===1&&rows[0].Id===continuation.helperId,'CONTINUE_HELPER_EXACT_ID');
      const c=rows[0];validateBackupHelper(c,adoptedName,adoptedImage,backupMode?'backup':'drain',backupMode||startedMode?c.State.Status:'created',backupMode);
      if(backupMode){backupCopyState(c,resuming);recoverySafe(helperControl(c)===resuming.helperRecord.createdControlSha256,'BACKUP_HELPER_CREATED_AUTHORITY');}
      else if(startedMode){recoverySafe(c.Id===resuming.helperRecord.id&&c.Created===JSON.parse(resuming.files.get('continue-drain.json').bytes).helper.created,'STARTED_HELPER_HISTORICAL_ID');startedDrainState(c,resuming);legacyCreatedHelperProof(c,resuming.helperRecord);}
      else neverStartedDrain(c);
      if(adopted){recoverySafe(helperControl(c)===helperControl(adopted)&&c.Created===adopted.Created,'CONTINUE_HELPER_CONTROL_IDENTITY');
        if(startedMode||backupMode)recoverySafe(c.State.StartedAt===adopted.State.StartedAt&&c.RestartCount===adopted.RestartCount&&(!c.State.Running||c.State.Pid===adopted.State.Pid),'STARTED_HELPER_EPOCH_IDENTITY');}
      return c;};
    if(continuing){await recoveryStep('CONTINUE_NAMESPACE_CENSUS',()=>exactRunningCensus(scoped,options));
      const imageRows=JSON.parse(await d(['image','inspect',resuming.candidate.services.api.image]));recoverySafe(imageRows.length===1,'CONTINUE_API_IMAGE_COUNT');adoptedImage=imageRows[0];
      recoverySync('CONTINUE_API_IMAGE_POLICY',()=>{validateImage(adoptedImage,'api');ownImageReferences(adoptedImage,'api');});adopted=await inspectAdopted();}
    let initial = await recoveryStep('PRIOR_RUNTIME_PREFLIGHT',()=>priorRuntime(scoped,options,config,oldPins,jwt.bytes,platform,initialStopped));
    if (records.length === 3&&!continuing) {
      validateBuildEvidence(originalFiles[0][1].bytes,originalFiles[1][1].bytes,buildBaseline(initial.inventory),options.env.DOCKER_HOST);
    }
    if(!resumeName){fs.mkdirSync(guard,{mode:0o700}); guardId = directoryIdentity(guard); syncDirectory(dir);}
    retained=true;stage=resumeName?'resume-proof':'audit-intent';
    const history = join(dir,REDEPLOYS); if (!exists(history)) {fs.mkdirSync(history,{mode:0o700});syncDirectory(dir);} privateDirectory(history); safe(fs.readdirSync(history).length<(resumeName?5:4));
    historyDirectory=history;historyIdentity=directoryIdentity(history);
    const name = resumeName ?? 'redeploy-'+randomBytes(16).toString('hex'); audit = join(history,name);
    if(!resumeName){fs.mkdirSync(audit,{mode:0o700});syncDirectory(history);}
    const auditId = directoryIdentity(audit); auditIdentity=auditId; safe(auditId.dev===stateId.dev&&originalId.dev===stateId.dev);
    const backupDir = join(audit,'backups'); if(!resumeName)fs.mkdirSync(backupDir,{mode:0o700});backupDirectory=backupDir;backupIdentity=directoryIdentity(backupDir);if(!checkOnly)syncDirectory(audit);
    recoverySafe(fs.statfsSync(backupDir).bavail*fs.statfsSync(backupDir).bsize>=1024**3,'HOST_BACKUP_FREE_SPACE');
    const record=(name,value)=>recoverySync('AUDIT_RECORD_EXCLUSIVE_DURABILITY',()=>{verifyDirectory(audit,auditId);writeExclusive(join(audit,name),JSON.stringify(value),0o600);syncDirectory(audit);auditFiles.set(name,captureFile(join(audit,name),131072));});
    const intent = {version:1,project:PROJECT,operation:'recover-build-and-redeploy',acknowledgement:REDEPLOY_ACK,
      operatorAttestation:'FAILED_BUILD_BEFORE_START_AND_QUIESCENT',prebuildHistoricalIdentity:'OPERATOR_ATTESTED',originalImageMetadataVerified:false,
      rollbackToPriorImages:false,endpoint:options.env.DOCKER_HOST,originalMutationSha256:sha(marker.bytes),originalLockIdentity:originalId,originalMarkerIdentity:marker.identity,
      profileSha256:sha(profileFile.bytes),sourceSha256:sha(source.bytes),cve:metadata(profile.cve),priorPins:oldPins,
            statelessGatewayPolicy:'RECREATE_AFTER_BACKUPS_NO_OLD_EXIT_CERTIFICATION',
                  helperPolicy:'CREATE_INSPECT_START_V2',reviewedSource:'OPERATOR_ATTESTED_NO_CONCURRENT_CHANGES',reviewedBuildInputs:Object.fromEntries(Object.entries(buildInputs).map(([n,f])=>[n,sha(f.bytes)]))};
    if(resumeName){
      safe(equal(intent,resuming.intent));guardIntent=captureFile(join(guard,'intent.json'));
      if(continuing){recoverySync('CONTINUE_ORIGINAL_BASELINE',()=>legacyMountContinuity(resuming.baseline,{snapshot:resuming.canonicalBaseline,inventory:initial.inventory}));
        recoverySync('CONTINUE_STOPPED_RUNTIME_CONTINUITY',()=>priorContinuity(resuming.canonicalBaseline,initial.snapshot,initialStopped));
        for(const[role,i]of [['web',7],['api',8]]){const c=initial.inventory.containers.find(c=>serviceOf(c)===role);recoverySafe(timestamp(c.State.FinishedAt)&&Date.parse(c.State.FinishedAt)>=Date.parse(resuming.phases[i].at)&&Date.parse(c.State.FinishedAt)<=Date.parse(adopted.Created),'CONTINUE_CLEAN_STOP_TIMELINE');}
        recoverySafe(Date.parse(adopted.Created)>=Date.parse(resuming.phases[backupMode?21:9].at),'CONTINUE_HELPER_CREATE_TIMELINE');
        if(backupMode){const worker=initial.inventory.containers.find(c=>serviceOf(c)==='worker');recoverySafe(timestamp(worker.State.FinishedAt)&&Date.parse(worker.State.FinishedAt)>=Date.parse(resuming.phases[19].at)&&Date.parse(worker.State.FinishedAt)<=Date.parse(resuming.phases[20].at),'BACKUP_WORKER_SHUTDOWN_TIMELINE');}
        for(const m of adopted.Mounts.filter(m=>m.Type==='volume'))recoverySafe(m.Driver==='local'&&m.Source===initial.inventory.volumes.find(v=>v.Name===m.Name)?.Mountpoint,'CONTINUE_HELPER_VOLUME_SOURCE');
      }else legacyMountContinuity(resuming.baseline,initial);
      safe(equal(JSON.parse(pinsFile.bytes),resuming.priorPins));
      for(const [n,f]of resuming.files)auditFiles.set(n,f);
    }else{
      writeExclusive(join(guard,'intent.json'),JSON.stringify(intent),0o600);syncDirectory(guard);guardIntent=captureFile(join(guard,'intent.json'));record('intent.json',intent);
      record('baseline.json',initial.snapshot);record('prior-pins.json',JSON.parse(pinsFile.bytes));
    }
    let sequence = backupMode?24:startedMode?12:continuing?10:resumeName?6:0;
    const mark = value => {stage=value;guardReason='PHASE_'+value.replaceAll('-','_').toUpperCase();retained=true;recoverySync('PHASE_IDENTITY_FENCE',fence);record('phase-'+String(++sequence).padStart(3,'0')+'.json',{version:1,phase:value,at:new Date().toISOString()});checkpoint(value);};
    if(!resumeName){mark('build-submission');
      // Bound simultaneous compiler pressure while the prior 4 GiB worker is live.
      for(const role of Object.keys(FILES)){mark('build-'+role);await d(composeArguments(root,['build',role],profile.cve),{env:composeEnv(options.env),timeout:600000});}
      mark('new-image-validation');
    }
    guardReason='NEW_IMAGE_METADATA_REFUSED';const images = await selectedImages(d,options,config);
    safe(SERVICES.filter(n => n.endsWith('volume-init')).every(n => images[n].Id === oldPins[n]));
    safe(new Set(Object.keys(FILES).map(role=>images[role].Id)).size===4);
    for (const role of Object.keys(FILES)) {
      ownImageReferences(images[role],role);
      const users=(await d(['container','ls','--all','--filter','ancestor='+images[role].Id,'--format','{{.ID}}','--no-trunc'])).trim().split('\n').filter(Boolean);
      recoverySafe(equal(sorted(users),sorted([...initial.inventory.containers.filter(c=>c.Image===images[role].Id).map(c=>c.Id),...(continuing&&role==='api'?[continuation.helperId]:[])])),'NEW_IMAGE_EXACT_CONSUMERS');
    }
    const candidate = {services:Object.fromEntries(SERVICES.map(n => [n,{image:images[n].Id}]))};
    if(resumeName)safe(equal(candidate,resuming.candidate));else record('candidate.images.json',candidate);
    guardReason='CANDIDATE_PROFILE_REFUSED';
    const candidateArgs = args => [...composeArguments(root,[],profile.cve),'-f',join(audit,'candidate.images.json'),...args];
    validateConfig(JSON.parse(await d(candidateArgs(['config','--format','json']),{env:composeEnv(options.env)})),root,profile.cve,images);
    if(continuing)recoverySync('REMAINING_ENGINE_SHAPE_MODELS',()=>validateRemainingEngineShapes(adopted,images,initial.inventory,config,{platform,secret:jwt.bytes}));
    const stablePrior = async (stopped,helper) => {if(helper)await helper.inspect('running');
      const runner=helper?helper.scopedRun:continuing&&adopted?scoped:d;
      const value=await recoveryStep('RETAINED_RUNTIME_POLICY',()=>priorRuntime(runner,options,config,oldPins,jwt.bytes,platform,stopped));
      recoverySync('RETAINED_RUNTIME_CONTINUITY',()=>priorContinuity(initial.snapshot,value.snapshot,stopped));return value;};
        const makeHelper=async purpose=>{
          const helperName=PROJECT+'-recovery-'+name.slice('redeploy-'.length)+'-'+purpose+(purpose==='backup'&&backupMode?'-export':purpose==='drain'&&refreshDrain?'-next':'');
          const adopt=continuing&&!backupMode&&purpose==='drain'&&!refreshDrain,alreadyStarted=adopt&&startedMode;let id;
          if(adopt){await inspectAdopted();id=continuation.helperId;}
          else{mark(purpose+'-helper-submission');id=(await d(backupArguments(helperName,images.api.Id,purpose),{timeout:30000})).trim();recoverySafe(HEX_SHA.test(id),'HELPER_CREATE_RESPONSE_ID');}
          let control=adopt?helperControl(adopted):null,epoch=alreadyStarted?helperEpoch(adopted):null;
          const inspect=async state=>{const text=await d(['container','inspect',helperName]),rows=recoverySync('HELPER_INSPECT_JSON',()=>JSON.parse(text));recoverySafe(rows.length===1&&rows[0].Id===id,'HELPER_INSPECT_EXACT_ID');
            recoverySync('HELPER_INSPECT_CONTROL_SHAPE',()=>validateBackupHelper(rows[0],helperName,images.api,purpose,state));
            for(const m of rows[0].Mounts.filter(m=>m.Type==='volume'))recoverySafe(m.Driver==='local'&&m.Source===initial.inventory.volumes.find(v=>v.Name===m.Name)?.Mountpoint,'HELPER_VOLUME_SOURCE');
            const observed=helperControl(rows[0]);if(control)recoverySafe(control===observed,'HELPER_CONTROL_IDENTITY');else control=observed;
            const current=rows[0];recoverySafe(current.RestartCount===0,'HELPER_RESTART_COUNT');
            if(state==='running'){recoverySafe(timestamp(current.State.StartedAt),'HELPER_START_TIMESTAMP');const next=helperEpoch(current);if(epoch)recoverySafe(equal(epoch,next),'HELPER_PROCESS_EPOCH');else epoch=next;}
            else if(epoch)recoverySafe(current.State.StartedAt===epoch.startedAt&&current.RestartCount===epoch.restartCount,'HELPER_STOPPED_PROCESS_EPOCH');
            const projected=(await d(['container','ls','--all','--format','{{.Names}}\t{{.Label "com.docker.compose.project"}}'])).trim().split('\n').filter(Boolean).map(row=>row.split('\t')).filter(([n,p])=>namespaced(n)||p===PROJECT);
            recoverySafe(equal(sorted(projected.map(([n])=>n)),sorted([...SERVICES.map(r=>`${PROJECT}-${r}-1`),helperName]))&&projected.every(row=>row.length===2&&row[1]===PROJECT),'HELPER_EXACT_NAMESPACE');
          };
          if(alreadyStarted)await inspect('running');
          else{await inspect('created');record('helper-'+purpose+(purpose==='backup'&&backupMode?'-export':purpose==='drain'&&refreshDrain?'-next':'')+'.json',{id,name:helperName,purpose,image:images.api.Id,createdControlSha256:control,controlPolicy:'HELPER_AUTHORITY_V3'});
            mark(purpose+'-helper-start');await inspect('created');await d(['container','start',id]);await inspect('running');}
          const scopedRun=scopedHelperRun(d,id,helperName,purpose);
          const remove=async()=>{await inspect('running');mark(purpose+'-helper-stop');await d(['container','stop','--time','10',id],{timeout:20000});await inspect('exited');
            mark(purpose+'-helper-remove');await d(['container','rm',id]);};
          return {id,name:helperName,inspect,scopedRun,remove};
        };
    guardReason='PRIOR_RUNTIME_CONTINUITY_REFUSED';safe(equal(initial.snapshot,(await stablePrior(initialStopped)).snapshot));
    if(continuing){adopted=await inspectAdopted();recoverySync('CONTINUE_FINAL_EVIDENCE_FENCE',fence);
      if(checkOnly){const outcome=backupMode?'READ_ONLY_BACKUP_COPY_PROOF_PASS':startedMode?'READ_ONLY_STARTED_DRAIN_PROOF_PASS':'READ_ONLY_CREATED_DRAIN_PROOF_PASS';log(outcome+'; helper-state='+adopted.State.Status+'; plan='+(backupMode?'RENEW_LEGACY_WITH_HELD_SNAPSHOTS':startedMode&&(!adopted.State.Running||Date.now()-Date.parse(adopted.State.StartedAt)>30000)?'RETIRE_OLD_CREATE_FRESH_RO_PROBE':startedMode?'USE_RUNNING_WITHOUT_START':'START_CREATED_ONCE')+'; no lifecycle/exec/build/state write; helper authority/candidate profile/remaining engine-shape models validated; future native execution NOT proven; independent review required.');return {operation:outcome,audit:resumeName,helperId:continuation.helperId};}
      if(backupMode){
        recoverySafe(equal(sorted(fs.readdirSync(guard)),['continue-drain.lock','intent.json','resume.lock','started-drain.lock']),'BACKUP_TRANSFER_ONE_SHOT_GUARD');
        adopted=await inspectAdopted();fs.mkdirSync(join(guard,'backup-transfer.lock'),{mode:0o700});transferLockId=directoryIdentity(join(guard,'backup-transfer.lock'));syncDirectory(guard);transferAccepted=true;
        const previous=JSON.parse(resuming.files.get('started-drain.json').bytes),receipt={version:1,project:PROJECT,operation:'CONTINUE_QUIESCENT_BACKUP_TRANSFER',acknowledgement:'--ack-quiescent-backup-transfer',audit:resumeName,endpoint:options.env.DOCKER_HOST,
          helper:{id:adopted.Id,name:adoptedName,image:adopted.Image,created:adopted.Created,authoritySha256:helperControl(adopted),epoch:helperEpoch(adopted),state:adopted.State.Status},
          originalFiles:Object.fromEntries([...resuming.files].map(([n,f])=>[n,{sha256:sha(f.bytes),identity:f.identity}])),stateIdentity:stateId,stateFiles:previous.stateFiles,at:new Date().toISOString()};
        writeExclusive(join(guard,'backup-transfer.lock/receipt.json'),JSON.stringify(receipt),0o600);syncDirectory(join(guard,'backup-transfer.lock'));transferReceipt=captureFile(join(guard,'backup-transfer.lock/receipt.json'),131072);
        record('backup-transfer.json',receipt);record('backup-transfer-baseline.json',initial.snapshot);mark('continue-backup-transfer-authorized');
      }else if(startedMode){
        recoverySafe(equal(sorted(fs.readdirSync(guard)),['continue-drain.lock','intent.json','resume.lock']),'STARTED_ONE_SHOT_GUARD');
        adopted=await inspectAdopted();
        fs.mkdirSync(join(guard,'started-drain.lock'),{mode:0o700});startedLockId=directoryIdentity(join(guard,'started-drain.lock'));syncDirectory(guard);startedAccepted=true;
        const prior=JSON.parse(resuming.files.get('continue-drain.json').bytes);
        const receipt={version:1,project:PROJECT,operation:'CONTINUE_STARTED_DRAIN_ONLY',acknowledgement:'--ack-started-drain-only',audit:resumeName,endpoint:options.env.DOCKER_HOST,
          helper:{id:adopted.Id,name:adoptedName,image:adopted.Image,created:adopted.Created,authoritySha256:helperControl(adopted),epoch:helperEpoch(adopted),state:adopted.State.Status},
          originalFiles:Object.fromEntries([...resuming.files].map(([n,f])=>[n,{sha256:sha(f.bytes),identity:f.identity}])),stateIdentity:stateId,stateFiles:prior.stateFiles,at:new Date().toISOString()};
        writeExclusive(join(guard,'started-drain.lock/receipt.json'),JSON.stringify(receipt),0o600);syncDirectory(join(guard,'started-drain.lock'));startedReceipt=captureFile(join(guard,'started-drain.lock/receipt.json'),131072);
        record('started-drain.json',receipt);record('started-drain-baseline.json',initial.snapshot);mark('continue-started-drain-authorized');
      }else{
      recoverySafe(equal(sorted(fs.readdirSync(guard)),['intent.json','resume.lock']),'CONTINUE_ONE_SHOT_GUARD');
      fs.mkdirSync(join(guard,'continue-drain.lock'),{mode:0o700});continueLockId=directoryIdentity(join(guard,'continue-drain.lock'));syncDirectory(guard);continuationAccepted=true;
      const priorReceipt=JSON.parse(resuming.files.get('resume.json').bytes);
      const receipt={version:1,project:PROJECT,operation:'CONTINUE_CREATED_DRAIN_ONLY',acknowledgement:'--ack-created-drain-only',audit:resumeName,endpoint:options.env.DOCKER_HOST,
        helper:{id:adopted.Id,name:adoptedName,image:adopted.Image,created:adopted.Created,controlSha256:helperControl(adopted)},
        originalFiles:Object.fromEntries([...resuming.files].map(([n,f])=>[n,{sha256:sha(f.bytes),identity:f.identity}])),stateIdentity:stateId,stateFiles:priorReceipt.stateFiles,at:new Date().toISOString()};
      writeExclusive(join(guard,'continue-drain.lock/receipt.json'),JSON.stringify(receipt),0o600);syncDirectory(join(guard,'continue-drain.lock'));continueReceipt=captureFile(join(guard,'continue-drain.lock/receipt.json'),131072);
      record('continue-drain.json',receipt);record('continue-drain-baseline.json',initial.snapshot);mark('continue-created-drain-authorized');
      }
    }else if(resumeName){
      fence();resuming.verify(guard);safe(equal(sorted(fs.readdirSync(audit)),resuming.names)&&equal(fs.readdirSync(guard),['intent.json']));
      fs.mkdirSync(join(guard,'resume.lock'),{mode:0o700});resumeLockId=directoryIdentity(join(guard,'resume.lock'));syncDirectory(guard);
      const receipt={version:1,project:PROJECT,operation:'RESUME_PRE_LIFECYCLE_ONLY',acknowledgement:'--ack-pre-lifecycle-only',audit:name,
        endpoint:options.env.DOCKER_HOST,originalFailureSha256:sha(resuming.files.get('failure.json').bytes),
        originalFiles:Object.fromEntries([...resuming.files].map(([n,f])=>[n,{sha256:sha(f.bytes),identity:f.identity}])),
        canonicalMountPolicy:'RUNTIME_MOUNTS_BY_DESTINATION_V1',stateIdentity:stateId,
        stateFiles:Object.fromEntries([['profile',profileFile],['jwt',jwt],['pins',pinsFile]].map(([n,f])=>[n,f.identity])),
        dataPolicy:'SAME_LIVE_VOLUMES_NO_LAUNCHER_DB_ACCESS_BEFORE_QUIESCENCE',at:new Date().toISOString()};
      writeExclusive(join(guard,'resume.lock/receipt.json'),JSON.stringify(receipt),0o600);syncDirectory(join(guard,'resume.lock'));resumeReceipt=captureFile(join(guard,'resume.lock/receipt.json'),131072);
      record('resume.json',receipt);record('resume-baseline.json',initial.snapshot);mark('resume-authorized');
    }
    guardReason='LIFECYCLE_GUARD_REFUSED';const stopped = [...initialStopped];
    const stop = async role => {await stablePrior(stopped);mark('stop-'+role);await d(['container','stop',...(role==='web'?['--signal','SIGTERM']:[]),'--time','30',initial.snapshot.containers[role].id],{timeout:45000});stopped.push(role);await stablePrior(stopped);};
    if(startedMode){
      let current=await inspectAdopted();
      if(!current.State.Running||Date.now()-Date.parse(current.State.StartedAt)>30000){
        // A six-minute RO probe cannot cover a fresh five-minute drain after a
        // long review. Retire only this validated epoch; NEVER restart its ID.
        if(current.State.Running){mark('retire-started-drain-stop');await d(['container','stop','--time','10',current.Id],{timeout:20000});
          const rows=JSON.parse(await d(['container','inspect',adoptedName]));recoverySafe(rows.length===1&&rows[0].Id===current.Id,'RETIRE_HELPER_ID');current=rows[0];validateBackupHelper(current,adoptedName,images.api,'drain','exited');
          recoverySafe(current.State.StartedAt===adopted.State.StartedAt&&current.RestartCount===0&&current.State.ExitCode===0&&helperControl(current)===helperControl(adopted),'RETIRE_HELPER_EPOCH_CONTROLS');}
        mark('retire-started-drain-remove');await d(['container','rm',current.Id]);adopted=null;refreshDrain=true;await stablePrior(stopped);
      }
    }
    if(!backupMode){
    if(!continuing){await stop('web');await stop('api');}const probe=await makeHelper('drain');mark('drain');let drained=false;
    const drainDeadline=performance.now()+300000;
    do {await stablePrior(stopped,probe);const text=await d(['container','exec',probe.id,'node','--input-type=module','-e',RECOVERY_DRAIN]),value=recoverySync('DRAIN_RESULT_JSON',()=>JSON.parse(text));
      recoverySafe(keys(value,['retry'])&&value.retry===true||keys(value,['pending'])&&Number.isSafeInteger(value.pending)&&value.pending>=0,'DRAIN_RESULT_PROTOCOL');
      if(value.pending===0){drained=true;break;}recoverySafe(performance.now()<drainDeadline,'DRAIN_DEADLINE');await sleep(1000);
    }while(performance.now()<drainDeadline);recoverySafe(drained,'DRAIN_NOT_COMPLETE');await probe.remove();adopted=null;await stablePrior(stopped);
    await stop('worker');mark('writers-quiescent');await stablePrior(stopped);
    }
    let legacyManifest=null;
    if(backupMode){let current=await inspectAdopted();
      if(current.State.Running){try{legacyManifest=JSON.parse(await d(['container','exec',current.Id,'node','-e',BACKUP_EXPORT_PROGRAM,JSON.stringify({action:'manifest'})]));validateExportManifest(legacyManifest);record('backup-original-manifest.json',legacyManifest);}
        catch(error){current=await inspectAdopted();if(current.State.Running)throw error;}}
      record('backup-generation.json',{version:1,originalSnapshots:legacyManifest?'RECEIPT_AND_SOURCE_FENCES_CAPTURED':'LEGACY_TMPFS_EXPIRED_NO_DURABLE_SNAPSHOT_RECEIPT',policy:'REGENERATE_FROM_VERIFIED_QUIESCENT_SOURCES_NO_OLD_RESTART'});
      if(current.State.Running){mark('retire-legacy-backup-stop');await d(['container','stop','--time','10',current.Id],{timeout:20000});const rows=JSON.parse(await d(['container','inspect',adoptedName]));recoverySafe(rows.length===1&&rows[0].Id===current.Id,'BACKUP_RETIRE_EXACT_ID');const c=rows[0];validateBackupHelper(c,adoptedName,images.api,'backup','exited',true);recoverySafe([0,143].includes(c.State.ExitCode)&&c.RestartCount===0&&c.State.StartedAt===adopted.State.StartedAt&&helperControl(c)===helperControl(adopted),'BACKUP_RETIRE_EPOCH_AUTHORITY');}
      mark('retire-legacy-backup-remove');await d(['container','rm',current.Id]);adopted=null;await stablePrior(stopped);
    }
        // The stateless gateway has no DB mount or SIGTERM handler. Keep it live
        // through backup, then let the controlled fresh-ID recreation replace it.
        // Never certify an old gateway exit or relax either database writer's stop.
    const noWriters = async () => {for(const key of VOLUMES)recoverySafe((await d(['container','ls','--filter',`volume=${PROJECT}_${key}`,'--format','{{.ID}}','--no-trunc'])).trim()==='','BACKUP_NO_LIVE_WRITERS');};
    await noWriters();
    const backup=await makeHelper('backup'),helperName=backup.name,helperId=backup.id;
    const helper=async()=>{await backup.inspect('running');for(const key of VOLUMES)recoverySafe((await d(['container','ls','--filter',`volume=${PROJECT}_${key}`,'--format','{{.ID}}','--no-trunc'])).trim()===helperId,'BACKUP_EXCLUSIVE_HELPER_CONSUMER');};
    let backups;const backupDeadline=performance.now()+120000;
    do {await helper();backups=await recoveryStep('BACKUP_RESULT_JSON',async()=>JSON.parse(await d(['container','exec',helperId,'node','-e',BACKUP_READY])));if(keys(backups,['auth','ledger']))break;recoverySafe(equal(backups,{})&&performance.now()<backupDeadline,'BACKUP_READY_PROTOCOL_DEADLINE');await sleep(1000);}while(performance.now()<backupDeadline);
    recoverySafe(keys(backups,['auth','ledger']),'BACKUP_MISSING_RESULT');
    const exportRead=async request=>{await helper();return recoveryStep('BACKUP_EXPORT_RESPONSE_JSON',async()=>JSON.parse(await d(['container','exec',helperId,'node','-e',BACKUP_EXPORT_PROGRAM,JSON.stringify(request)])));};
    const manifest=await exportRead({action:'manifest'});validateExportManifest(manifest);recoverySafe(equal(manifest.receipt,backups),'BACKUP_EXPORT_READY_RECEIPT');
    if(legacyManifest)recoverySafe(equal(legacyManifest.receipt,manifest.receipt)&&equal(legacyManifest.sources,manifest.sources),'BACKUP_REGENERATED_RECEIPT_SOURCE_MATCH');
    record('backup-export-manifest.json',manifest);mark('backup-copy');
    for(const role of ['auth','ledger']){await transferBackupSnapshot({dir:backupDir,role,manifest,readChunk:exportRead,verify:helper});
      const b=backups[role];recoverySync('BACKUP_PRIVATE_COPY_BYTES_MODE',()=>recoverySafe(equal(binaryBackup(join(backupDir,role+'.sqlite')),{bytes:b.bytes,sha256:b.sha256}),'BACKUP_PRIVATE_COPY_HASH'));}
    const finalManifest=await exportRead({action:'manifest'});validateExportManifest(finalManifest);recoverySafe(equal(finalManifest,manifest),'BACKUP_EXPORT_FINAL_SOURCE_FILE_FENCE');
    record('backup-export-verified.json',{version:1,manifestSha256:sha(JSON.stringify(manifest)),transport:'VALIDATED_EXEC_BOUNDED_BASE64_V1'});
    syncDirectory(backupDir);record('backup-receipt.json',backups);await helper();await backup.remove();await noWriters();await stablePrior(stopped);
    mark('commit-new-pins');pinsFile.verify();fs.renameSync(join(dir,'compose.images.json'),join(audit,'saved-main-pins.json'));
    writeExclusive(join(dir,'compose.images.json'),JSON.stringify(candidate),0o600);syncDirectory(dir);syncDirectory(audit);activePins=captureFile(join(dir,'compose.images.json'));
        recoverySafe(equal(fileIdentity(join(audit,'saved-main-pins.json')),pinsFile.identity)&&privateRead(join(audit,'saved-main-pins.json'))===pinsFile.bytes,'COMMIT_PRIOR_PINS_IDENTITY');
        auditFiles.set('saved-main-pins.json',captureFile(join(audit,'saved-main-pins.json')));
    const inspectOne=async role=>{recoverySafe(Object.hasOwn(FILES,role),'NEW_RUNTIME_ROLE');const rows=JSON.parse(await d(['container','inspect',`${PROJECT}-${role}-1`]));recoverySafe(rows.length===1,'NEW_RUNTIME_INSPECT_COUNT');
      const c=rows[0];recoverySafe(HEX_SHA.test(c.Id)&&c.Id!==initial.snapshot.containers[role].id&&c.Name===`/${PROJECT}-${role}-1`&&owned(c.Config?.Labels)&&serviceOf(c)===role&&c.Image===images[role].Id&&c.Config.Image===images[role].Id&&timestamp(c.State.StartedAt),'NEW_RUNTIME_IDENTITY_PIN');return c;};
    const ready=async role=>{const until=performance.now()+90000;let c;do{c=await inspectOne(role);recoverySafe(c.State.Running&&c.Image===images[role].Id&&c.Config.Image===images[role].Id,'NEW_RUNTIME_RUNNING_PIN');
      recoverySync('NEW_RUNTIME_SECURITY_CONTROLS',()=>validateContainer(c,role,config.services[role],images[role],config,{platform,secret:jwt.bytes,images}));
      if(role!=='api'||c.State.Health?.Status==='healthy')return c;recoverySafe(performance.now()<until,'NEW_API_HEALTH_DEADLINE');await sleep(1000);}while(performance.now()<until);throw new RecoveryRefusal('NEW_RUNTIME_READINESS_DEADLINE');};
    for(const role of ['egress','worker','api']) {mark('recreate-'+role);await d(candidateArgs(['up','-d','--no-deps','--no-build','--pull','never','--force-recreate',role]),{env:composeEnv(options.env,jwt.bytes),timeout:120000});await ready(role);}
    mark('verify-retained-data');const content=await recoveryStep('RESTORED_DATA_COMPARE_JSON',async()=>JSON.parse(await d(['container','exec',(await inspectOne('api')).Id,'node','--input-type=module','-e',RECOVERY_COMPARE])));
    recoverySafe(keys(content,['auth','ledger'])&&['auth','ledger'].every(r=>keys(content[r],['logicalSha256'])&&content[r].logicalSha256===backups[r].logicalSha256),'RESTORED_DATA_LOGICAL_FINGERPRINT');
    const workerDeadline=performance.now()+30000;let workerReady=false;
    do {try{const worker=await inspectOne('worker');workerReady=JSON.parse(await d(['container','exec',worker.Id,'node','-e',RECOVERY_READY,String(Date.parse(worker.State.StartedAt))])).ready===true;}catch(error){if(error instanceof IsolatedError && !(error instanceof IsolatedDockerFailure))throw error;}
      if(workerReady)break;recoverySafe(performance.now()<workerDeadline,'NEW_WORKER_READY_DEADLINE');await sleep(1000);}while(performance.now()<workerDeadline);recoverySafe(workerReady,'NEW_WORKER_NOT_READY');
    mark('recreate-web');await d(candidateArgs(['up','-d','--no-deps','--no-build','--pull','never','--force-recreate','web']),{env:composeEnv(options.env,jwt.bytes),timeout:120000});await ready('web');
    mark('postflight');const after=await recoveryStep('POSTFLIGHT_NAMESPACE_POLICY',()=>inspectNamespace(d,options,config,{platform,secret:jwt.bytes,images}));recoverySafe(after.containers.length===6&&after.volumes.length===2&&after.networks.length===4,'POSTFLIGHT_RESOURCE_COUNTS');
        recoverySafe(after.containers.every(c=>serviceOf(c).endsWith('volume-init')?!c.State.Running&&c.State.ExitCode===0:c.State.Running&&!c.State.Restarting&&!c.State.OOMKilled&&(serviceOf(c)!=='api'||c.State.Health?.Status==='healthy')),'POSTFLIGHT_SERVICE_STATES');
        const finalWorker=after.containers.find(c=>serviceOf(c)==='worker');recoverySafe(JSON.parse(await d(['container','exec',finalWorker.Id,'node','-e',RECOVERY_READY,String(Date.parse(finalWorker.State.StartedAt))])).ready===true,'POSTFLIGHT_WORKER_READY');
    for(const key of VOLUMES)recoverySafe(controlHash(after.volumes.find(v=>v.Name===`${PROJECT}_${key}`))===initial.snapshot.volumes[key],'POSTFLIGHT_VOLUME_IDENTITY');
    for(const key of NETWORKS){const n=after.networks.find(n=>n.Name===`${PROJECT}_${key}`);recoverySafe(n.Id===initial.snapshot.networks[key].id&&controlHash({...n,Containers:{}})===initial.snapshot.networks[key].controlSha256,'POSTFLIGHT_NETWORK_IDENTITY');
      const members=after.containers.filter(c=>c.State.Running&&CONNECTIONS[serviceOf(c)].includes(key));recoverySafe(equal(sorted(Object.keys(n.Containers)),sorted(members.map(c=>c.Id))),'POSTFLIGHT_NETWORK_MEMBERSHIP');
      for(const c of members)recoverySafe(c.NetworkSettings.Networks[n.Name].NetworkID===n.Id&&n.Containers[c.Id].EndpointID===c.NetworkSettings.Networks[n.Name].EndpointID&&n.Containers[c.Id].Name===c.Name.slice(1),'POSTFLIGHT_ENDPOINT_IDENTITY');}
    for(const c of after.containers){const role=serviceOf(c),prior=initial.snapshot.containers[role];if(FILES[role])recoverySafe(c.Id!==prior.id,'POSTFLIGHT_OLD_CONTAINER_REUSED');else recoverySafe(c.Id===prior.id&&secretlessControl(c)===prior.controlSha256&&c.State.StartedAt===prior.process.startedAt&&c.RestartCount===prior.process.restartCount&&c.State.ExitCode===0&&!c.State.Running,'POSTFLIGHT_INITIALIZER_IDENTITY');}
    const response=await request(ORIGIN+'/api/v1/auth/me',{redirect:'error',signal:AbortSignal.timeout(5000)});recoverySafe(response.status===401,'POSTFLIGHT_PUBLIC_HTTP_STATUS');await response.body?.cancel();
    for(const role of ['auth','ledger'])recoverySync('POSTFLIGHT_BACKUP_BYTES_MODE',()=>recoverySafe(equal(binaryBackup(join(backupDir,role+'.sqlite')),{bytes:backups[role].bytes,sha256:backups[role].sha256}),'POSTFLIGHT_BACKUP_HASH'));
    mark('archive-original');fence();fs.renameSync(original,join(audit,'original-operation.lock'));originalAt=join(audit,'original-operation.lock');syncDirectory(audit);syncDirectory(dir);fence();
    const result={version:1,project:PROJECT,operation:'RECOVERED_REDEPLOY_PRIOR_IMAGES_UNVERIFIED',originalImageMetadataVerified:false,rollbackToPriorImages:false,
      originalLockIdentity:originalId,originalMarkerIdentity:marker.identity,originalMutationSha256:sha(marker.bytes),backups,images:candidate.services,
      containers:after.containers.map(c=>({id:c.Id,role:serviceOf(c),image:c.Image})),jwtPreserved:true,cve:metadata(profile.cve),at:new Date().toISOString()};
    record('result.json',result);
        const files=Object.fromEntries([...auditFiles].map(([n,f])=>[n,{sha256:sha(f.bytes),identity:f.identity}]));
        record('completion.json',{version:1,project:PROJECT,operation:result.operation,resultSha256:sha(JSON.stringify(result)),files});
    archiveGuard=join(audit,'recovery-operation.lock');verifyDirectory(guard,guardId);fs.renameSync(guard,archiveGuard);guardMoved=true;checkpoint('guard-archived');
    verifyDirectory(archiveGuard,guardId);fence();recoverySync('ARCHIVE_COMPLETION_HISTORY',()=>redeployHistory(root));syncDirectory(audit);syncDirectory(dir);committed=true;
    log('Isolated recovery redeployed at '+ORIGIN+'; accounts/history/JWT/volumes retained; verified private SQLite backups saved. Prior image metadata NOT certified; rollback to unavailable images NOT guaranteed. Native/browser qualification still required.');
    return {operation:result.operation,archive:REDEPLOYS+'/'+name};
  }catch(error){
    if(transferAccepted&&!checkOnly&&!committed)try{verifyDirectory(audit,auditIdentity);const path=join(audit,'backup-transfer-failure.json');if(!exists(path)){writeExclusive(path,JSON.stringify({version:1,project:PROJECT,checkpoint:stage,reason:error instanceof RecoveryRefusal?error.reason:error instanceof IsolatedDockerFailure?'DOCKER_'+error.category.toUpperCase():guardReason,at:new Date().toISOString()}),0o600);syncDirectory(audit);}}catch{}
    if(startedAccepted&&!checkOnly&&!committed)try{verifyDirectory(audit,auditIdentity);const path=join(audit,'started-failure.json');if(!exists(path)){writeExclusive(path,JSON.stringify({version:1,project:PROJECT,checkpoint:stage,reason:error instanceof RecoveryRefusal?error.reason:error instanceof IsolatedDockerFailure?'DOCKER_'+error.category.toUpperCase():guardReason,at:new Date().toISOString()}),0o600);syncDirectory(audit);}}catch{}
    if(continuationAccepted&&!checkOnly&&!committed)try{verifyDirectory(audit,auditIdentity);const path=join(audit,'continue-failure.json');if(!exists(path)){writeExclusive(path,JSON.stringify({version:1,project:PROJECT,checkpoint:stage,reason:error instanceof RecoveryRefusal?error.reason:error instanceof IsolatedDockerFailure?'DOCKER_'+error.category.toUpperCase():guardReason,at:new Date().toISOString()}),0o600);syncDirectory(audit);}}catch{}
    if(!checkOnly&&audit&&!committed)try{verifyDirectory(audit,auditIdentity);if(!exists(join(audit,'failure.json'))){writeExclusive(join(audit,'failure.json'),JSON.stringify({version:1,project:PROJECT,checkpoint:stage,failure:error instanceof IsolatedDockerFailure?error.category:'guard',at:new Date().toISOString()}),0o600);syncDirectory(audit);}}catch{}
    if(committed)throw new IsolatedError('Recovery committed; output unavailable. Review durable receipt; do not replay.');
    if(guardMoved)try{verifyDirectory(dir,stateIdentity);verifyDirectory(archiveGuard,guardId);safe(!exists(guard));fs.renameSync(archiveGuard,guard);syncDirectory(audit);syncDirectory(dir);}catch{}
    throw new IsolatedError(`Recovery refused/uncertain HOLD; checkpoint=${stage}; reason=${error instanceof RecoveryRefusal?error.reason:error instanceof IsolatedDockerFailure?'DOCKER_'+error.category.toUpperCase():guardReason}. Original marker/audit retained; no automatic rollback/retry.`);
  }finally{if(!retained&&guardId){verifyDirectory(guard,guardId);safe(fs.readdirSync(guard).length===0);fs.rmdirSync(guard);syncDirectory(dir);}}
}
function validateBuildEvidence(evidenceBytes,failureBytes,baseline,endpoint) {
  const e=JSON.parse(evidenceBytes),f=JSON.parse(failureBytes);
  safe(evidenceBytes===JSON.stringify(e)&&failureBytes===JSON.stringify(f));
  safe(equal(e,{version:1,project:PROJECT,endpoint,baseline,baselineSha256:controlHash(baseline)}) &&
    keys(f,['version','project','checkpoint','failure','prebuildSha256']) && f.version===1 && f.project===PROJECT && f.checkpoint==='build' &&
    ['timeout','docker_unavailable','network_pool','resources','runtime_health','image','unclassified'].includes(f.failure) && f.prebuildSha256===sha(evidenceBytes));
}
function snapshotBuildBaseline(r) {
  return {containers:SERVICES.map(role=>{const c=r.containers[role];return {role,id:c.id,image:c.image,controlSha256:c.controlSha256,startedAt:c.state.startedAt,pid:c.state.pid,restartCount:c.state.restartCount};}).sort((a,b)=>a.role.localeCompare(b.role)),
    volumes:VOLUMES.map(key=>({name:PROJECT+'_'+key,sha256:r.volumes[key].controlSha256})).sort((a,b)=>a.name.localeCompare(b.name)),
    networks:NETWORKS.map(key=>({name:PROJECT+'_'+key,id:r.networks[key].id,sha256:r.networks[key].controlSha256})).sort((a,b)=>a.name.localeCompare(b.name))};
}
function buildBaseline(inventory) {return {containers:inventory.containers.map(c=>({role:serviceOf(c),id:c.Id,image:c.Image,controlSha256:secretlessControl(c,true),startedAt:c.State.StartedAt,pid:c.State.Pid,restartCount:c.RestartCount})).sort((a,b)=>a.role.localeCompare(b.role)),
  volumes:inventory.volumes.map(v=>({name:v.Name,sha256:controlHash(v)})).sort((a,b)=>a.name.localeCompare(b.name)),networks:inventory.networks.map(n=>({name:n.Name,id:n.Id,sha256:controlHash(n)})).sort((a,b)=>a.name.localeCompare(b.name))};}

export async function publicImageStand(argv, { root = ROOT, run = runIsolatedDocker, ambient = process.env, log = console.log,
  random = randomBytes, loadActivation = loadCveActivation, verifyRelease = validateCveRelease, platform = process.platform,
  onReconcileCheckpoint = () => {}, sleep = ms => new Promise(resolve => setTimeout(resolve, ms)), request = fetch } = {}) {
  const [command, ...flags] = argv;
  const backupCommand=['check-recover-backup-copy','continue-recover-backup-copy'].includes(command),startedCommand=['check-recover-started-drain','continue-recover-started-drain'].includes(command);
  const createdCommand=backupCommand||startedCommand||['check-recover-created-drain','continue-recover-created-drain'].includes(command),checkOnly=['check-recover-created-drain','check-recover-started-drain','check-recover-backup-copy'].includes(command),ack=backupCommand?'--ack-quiescent-backup-transfer':startedCommand?'--ack-started-drain-only':'--ack-created-drain-only';
  const createdFlags=createdCommand&&!checkOnly&&flags[0]===ack?flags.slice(1):flags;
  const continuation=createdCommand&&(checkOnly||flags[0]===ack)&&createdFlags.length===4&&createdFlags[0]==='--audit'&&/^redeploy-[a-f0-9]{32}(?![\s\S])/.test(createdFlags[1])&&createdFlags[2]==='--helper-id'&&HEX_SHA.test(createdFlags[3])?{checkOnly,helperId:createdFlags[3],started:startedCommand,backup:backupCommand}:null;
  const resumeName=continuation?createdFlags[1]:command==='resume-recover-build-and-redeploy'&&flags.length===3&&flags[0]==='--ack-pre-lifecycle-only'&&flags[1]==='--audit'&&/^redeploy-[a-f0-9]{32}(?![\s\S])/.test(flags[2])?flags[2]:null;
  safe(['up', 'status', 'stop', 'reconcile-build-only', 'reconcile-network-only', 'reconcile-running-build-only', 'recover-build-and-redeploy', 'resume-recover-build-and-redeploy','check-recover-created-drain','continue-recover-created-drain','check-recover-started-drain','continue-recover-started-drain','check-recover-backup-copy','continue-recover-backup-copy'].includes(command) && (command === 'up' ?
    flags.every(f => ['--build', '--isolated'].includes(f)) && new Set(flags).size === flags.length :
    createdCommand ? continuation!==null : command === 'resume-recover-build-and-redeploy' ? resumeName!==null : command === 'recover-build-and-redeploy' ? equal(flags,[REDEPLOY_ACK]) : command.startsWith('reconcile-') ? equal(flags, [command === 'reconcile-running-build-only' ? RUNNING_ACK : '--ack-no-services']) : flags.length === 0), USAGE);
  safe(resolve(root) === root && fs.realpathSync(root) === root, 'Use the canonical absolute repository root.');
  if (command === 'up' || command.startsWith('reconcile-') || command === 'recover-build-and-redeploy' || resumeName) checkIgnores(root);
    if (command === 'recover-build-and-redeploy' || resumeName) return recoverBuildAndRedeploy(root,run,ambient,verifyRelease,log,platform,sleep,request,onReconcileCheckpoint,resumeName,continuation);
  if (command.startsWith('reconcile-')) return reconcileHeldOperation(command.slice('reconcile-'.length), root, run, ambient, verifyRelease, log, onReconcileCheckpoint, platform);
  let profile = readProfile(root);
  safe(command !== 'up' || profile !== undefined || flags.includes('--isolated'), 'First up requires --isolated: NEW accounts and databases on port 8081; no copy or migration of existing data.');
  const dir = join(root, STATE), lockPath = join(dir, '.operation.lock');
  let options = { root, env: dockerEnvironment(ambient) };
  if (!profile && command !== 'up') {
    if (exists(lockPath) || RECOVERY_GUARDS.some(name => exists(join(dir, name)))) log('HOLD: isolated operation/reconciliation lock exists; no automatic recovery.');
    options = await requireLocalEngine(run, options);
    const inventory = await inspectNamespace(run, options, expectedConfig(root), { platform });
    safe(Object.values(inventory).every(values => values.length === 0), 'Isolated resources exist without profile state; reviewed reconciliation required.');
    log('No dip-public-images stand; no state created and no legacy resources touched.'); return;
  }
  if (command === 'status') {
    if (exists(lockPath) || RECOVERY_GUARDS.some(name => exists(join(dir, name)))) log('HOLD: isolated operation/reconciliation lock exists; mutation outcome unconfirmed; no automatic recovery.');
    try { assertReconciliationHistory(root); } catch { log('HOLD: incomplete or unsafe reconciliation history; ordinary lifecycle cannot finish it.'); }
    options = await requireLocalEngine(run, options);
    const inventory = await inspectNamespace(run, options, expectedConfig(root, profile.cve), { platform });
    log(`dip-public-images isolated qualification only; CVE ${profile.cve ? 'pinned' : 'disabled'}; no updater integration.`);
    for (const c of inventory.containers) log(`${serviceOf(c)}: ${c.State.Status}`);
    return inventory;
  }
  if (!exists(dir)) { fs.mkdirSync(dir, { mode: 0o700 }); syncDirectory(root); }
  const lock = acquireLock(root); let uncertain = false, stage = 'preflight';
  const intent = phase => {
    lock.verify();
    if (uncertain) return;
    uncertain = true;
    writeExclusive(join(lock.path, 'mutation.json'), JSON.stringify({ version: 1, project: PROJECT, command, phase, endpoint: options.env.DOCKER_HOST }), 0o600);
    syncDirectory(lock.path);
  };
  try {
    // Re-read under our own lock; never acquire or alter the LOCAL operation lock.
    profile = readProfile(root);
    if (!profile) safe(command === 'up' && flags.includes('--isolated'), 'Isolated profile changed; refusing operation.');
    const cve = profile?.cve ?? (profile ? null : loadActivation(root));
    options = await requireLocalEngine(run, options);
    const config = expectedConfig(root, cve);
    const before = await inspectNamespace(run, options, config, { platform });
    if (!profile) safe(Object.values(before).every(values => values.length === 0), 'Refusing to adopt existing isolated resources without pinned profile state.');
    if (command === 'stop') {
      const ids = before.containers.filter(c => c.State.Running).map(c => c.Id);
      if (!ids.length) { log('Isolated stand already stopped; all storage retained.'); return; }
      stage = 'stop'; intent('stop-outcome-unconfirmed');
      await run(['container', 'stop', '--time', '30', ...ids], { ...options, timeout: 90_000 });
      stage = 'stop-postflight';
      const after = await inspectNamespace(run, options, config, { platform });
      safe(after.containers.every(c => !c.State.Running) && equal(sorted(after.containers.map(c => c.Id)), sorted(before.containers.map(c => c.Id))));
    } else {
      if (cve) verifyRelease(root, metadata(cve));
      const secret = loadSecret(root, Boolean(profile) || before.containers.length > 0 || before.volumes.length > 0, random);
      for (const c of before.containers.filter(c => serviceOf(c) === 'api')) safe(environment(c.Config.Env).SCAN_JWT_SECRET === secret, 'Isolated API JWT does not match its own state; refusing rotation/recreation.');
      if (!profile) { writeExclusive(join(dir, 'profile.json'), JSON.stringify({ version: 1, project: PROJECT, cve: metadata(cve) }), 0o600); syncDirectory(dir); }
      if (cve) {
        const bytes = JSON.stringify(cveOverlay(cve)), path = join(dir, 'compose.cve.json');
        if (!exists(path)) writeExclusive(path, bytes, 0o600);
        safe(privateRead(path) === bytes, 'Pinned isolated CVE overlay changed; manual refresh is not supported.'); syncDirectory(dir);
      } else safe(!exists(join(dir, 'compose.cve.json')), 'Unexpected CVE overlay in disabled isolated profile.');
      const rendered = JSON.parse(await run(composeArguments(root, ['config', '--format', 'json'], cve), { ...options, env: composeEnv(options.env) }));
      validateConfig(rendered, root, cve);
      checkIgnores(root);
      if (flags.includes('--build')) {
        stage = 'build'; intent(BUILD_PHASE);
        if (before.containers.length === SERVICES.length) {
          const baseline = buildBaseline(before);
          writeExclusive(join(lock.path,'build-evidence.json'),JSON.stringify({version:1,project:PROJECT,endpoint:options.env.DOCKER_HOST,
            baseline,baselineSha256:controlHash(baseline)}),0o600);syncDirectory(lock.path);
        }
        await run(composeArguments(root, ['build'], cve), { ...options, env: composeEnv(options.env), timeout: 600_000 });
        stage = 'initializer-pull';
        await run(['image', 'pull', 'busybox:1.37.0'], { ...options, timeout: 120_000 });
      }
      const images = await selectedImages(run, options, config, name => { stage = `image-policy-${name}`; });
      stage = 'image-pins';
      const imagePins = pinImages(root, images);
      stage = 'pinned-config';
      const pinned = JSON.parse(await run(composeArguments(root, ['config', '--format', 'json'], cve, true),
        { ...options, env: composeEnv(options.env) }));
      validateConfig(pinned, root, cve, images);
      safe(privateRead(join(dir, 'compose.images.json')) === imagePins, 'Isolated image pins changed before start.');
      checkIgnores(root); lock.verify();
      stage = 'start'; intent('start-outcome-unconfirmed');
      // A durable boundary distinguishes future build-only failures from any
      // operation that could have submitted service execution, even if deleted.
      writeExclusive(join(lock.path, 'start-submission.json'), JSON.stringify({ version: 1, project: PROJECT,
        phase: 'service-start-submission', endpoint: options.env.DOCKER_HOST }), 0o600);
      syncDirectory(lock.path);
      // Immutable engine IDs plus no-build/no-pull close tag replacement and
      // build-then-execute gaps; neither tags nor Docker context are authority.
      await run(composeArguments(root, ['up', '-d', '--no-build', '--pull', 'never'], cve, true),
        { ...options, env: composeEnv(options.env, secret), timeout: 600_000 });
      stage = 'postflight';
      const after = await inspectNamespace(run, options, config, { platform, secret, images });
      safe(after.containers.length === SERVICES.length && after.volumes.length === VOLUMES.length && after.networks.length === NETWORKS.length &&
        after.containers.every(c => c.State.Running || (serviceOf(c).endsWith('volume-init') && c.State.ExitCode === 0)),
      'Isolated startup incomplete; qualification not established.');
    }
    lock.verify();
    if (exists(join(lock.path, 'start-submission.json'))) fs.unlinkSync(join(lock.path, 'start-submission.json'));
    for (const name of ['build-evidence.json','build-failure.json']) if (exists(join(lock.path,name))) fs.unlinkSync(join(lock.path,name));
        fs.unlinkSync(join(lock.path, 'mutation.json')); syncDirectory(lock.path); uncertain = false;
    log(command === 'stop' ? 'dip-public-images stopped; own accounts, reports, JWT and volumes retained.' :
      'Isolated stand started at http://127.0.0.1:8081. Register NEW accounts. Native/browser/Trivy qualification is still required; not production acceptance.');
  } catch (error) {
    if (uncertain && stage === 'build' && exists(join(lock.path,'build-evidence.json')) && !exists(join(lock.path,'build-failure.json'))) {
      lock.verify(); const evidence = privateRead(join(lock.path,'build-evidence.json'));
      writeExclusive(join(lock.path,'build-failure.json'),JSON.stringify({version:1,project:PROJECT,checkpoint:'build',failure:error instanceof IsolatedDockerFailure?error.category:'unclassified',prebuildSha256:sha(evidence)}),0o600);syncDirectory(lock.path);
    }
    if (uncertain) throw new IsolatedError(`Isolated mutation outcome uncertain/HOLD; checkpoint=${stage}; failure=${error instanceof IsolatedDockerFailure ? error.category : error instanceof IsolatedError ? 'guard' : 'unclassified'}: .local-public-images/.operation.lock/mutation.json retained. Do not retry, remove locks, reset state or use legacy lifecycle tools. Reviewed reconciliation required.`);
    throw error;
  } finally { if (!uncertain) lock.release(); }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  publicImageStand(process.argv.slice(2)).catch(error => {
    console.error(error instanceof IsolatedError ? error.message : 'Isolated stand refused; details withheld. No automatic recovery, cleanup or secret rotation attempted.');
    process.exitCode = 1;
  });
}
