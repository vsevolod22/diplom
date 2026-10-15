import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
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
export function composeArguments(root, args) {
  return ['compose', '--env-file', '/dev/null', '-p', PROJECT,
    '-f', join(root, 'server/deploy/compose.stand.yaml'),
    '-f', join(root, 'server/deploy/compose.local.full.yaml'), ...args];
}
function composeEnvironment(env, secret = CONFIG_SECRET) {
  return { ...env, SCAN_JWT_SECRET: secret, AUTH_ORIGIN: ORIGIN,
    AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOWED_USER_IDS: '', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true' };
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

export function expectedEnvironment(service) {
  if (service === 'worker') return { SCAN_LEDGER_PATH: '/data/ledger.sqlite', SCAN_WORKER_READY_PATH: '/data/worker.ready',
    TRIVY_CACHE_DIR: '/tmp/trivy', SCAN_VULN_ENABLED: 'false' };
  if (service !== 'api') return {};
  return { SCAN_BIND_ADDRESS: '0.0.0.0', PORT: '3001', SCAN_JWT_SECRET: CONFIG_SECRET,
    SCAN_JWT_ISSUER: PROJECT, SCAN_JWT_AUDIENCE: PROJECT, AUTH_DB_PATH: '/auth/auth.sqlite',
    AUTH_ORIGIN: ORIGIN, AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOWED_USER_IDS: '',
    SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true', SCAN_LEDGER_PATH: '/data/ledger.sqlite',
    SCAN_WORKER_READY_PATH: '/data/worker.ready', SCAN_VULN_ENABLED: 'false', LLM_ENABLED: 'false',
    LLM_ROUTING_APPROVED: 'false', LLM_QUOTA_ENABLED: 'false', LLM_HISTORY_ENABLED: 'false' };
}

export function validateConfig(config, root) {
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
    const env = spec.environment ?? {}, expected = expectedEnvironment(service);
    requireSafe(sameKeys(env, Object.keys(expected)) && Object.entries(expected).every(([key, value]) => env[key] === value),
      'Unexpected service environment; optional operator features must remain off.');
    if (DOCKERFILES[service]) {
      requireSafe(spec.image === `${PROJECT}-${service}:local` && spec.build?.context === root &&
        spec.build.dockerfile === `server/deploy/${DOCKERFILES[service]}` && spec.build.labels?.[LABEL] === 'v1' &&
        !spec.build.args && !spec.build.additional_contexts && !spec.build.secrets && !spec.build.ssh && !spec.build.target &&
                !spec.build.network && !spec.build.dockerfile_inline,
      'Unexpected image or build source.');
    } else requireSafe(spec.image === 'busybox:1.37.0' && !spec.build, 'Unexpected volume initializer.');
    if (COMMANDS[service]) requireSafe(JSON.stringify(spec.command) === JSON.stringify(COMMANDS[service]), 'Unexpected service entrypoint.');
    requireSafe(!spec.entrypoint, 'Unexpected service entrypoint override.');
    const mounts = spec.volumes ?? [];
    requireSafe(mounts.length === Object.keys(MOUNTS[service]).length &&
          sameKeys(Object.fromEntries(mounts.map(mount => [mount.target, true])), Object.keys(MOUNTS[service])) && mounts.every(mount =>
      mount.type === 'volume' && MOUNTS[service][mount.target] === mount.source && !mount.read_only && !mount.volume?.subpath),
    'Bind, shared or unexpected service mount.');
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

// Inventory by name AND project label: an unexpected resource cannot hide behind
// a renamed container. Inspect only candidates, never old stand/dev resources.
export async function inspectNamespace(run, options) {
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
        requireSafe((item.Mounts ?? []).every(mount =>
          (mount.Type === 'volume' && MOUNTS[service][mount.Destination] &&
                      mount.Name === `${PROJECT}_${MOUNTS[service][mount.Destination]}`) ||
          (mount.Type === 'tmpfs' && mount.Destination === '/tmp' && Boolean(DOCKERFILES[service]) && service !== 'egress')),
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
  getSecret = loadSecret } = {}) {
  const [command, ...flags] = argv;
  requireSafe(['up', 'stop', 'status'].includes(command) &&
    (flags.length === 0 || (command === 'up' && flags.length === 1 && flags[0] === '--build')),
  'Usage: node scripts/local-stand.mjs up [--build] | stop | status');
  const options = { root, env: dockerEnvironment(ambient) };
  const config = JSON.parse(await run(composeArguments(root, ['config', '--format', 'json']),
    { ...options, env: composeEnvironment(options.env) }));
  validateConfig(config, root);
  const resources = await inspectNamespace(run, options);
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
  await run(composeArguments(root, ['up', ...(flags.includes('--build') ? ['--build'] : []), '-d']),
    { ...options, env: composeEnvironment(options.env, secret), timeout: 600_000 });
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
