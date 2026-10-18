import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { refreshLocalCve } from './refresh-local-cve.mjs';
import { PROJECT, LABEL, ORIGIN, composeArguments, dockerEnvironment, expectedEnvironment,
  validateConfig, inspectNamespace, checkIgnores, loadSecret, loadCveActivation, localStand,
    validateDefaultInspectedProfile } from './local-stand.mjs';
  import { PUBLIC_IMAGE_COMMANDS, PUBLIC_IMAGE_TMPFS, PUBLIC_IMAGE_MEMORY,
    publicImageCveConfig } from './public-image-stand-profile.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const FIXTURE_SECRET = 'ab'.repeat(48);
const SERVICES = ['auth-volume-init', 'scan-volume-init', 'egress', 'worker', 'api', 'web'];
const VOLUMES = ['auth_accounts', 'scan_ledger'];
const NETWORKS = ['auth_internal', 'scan_internal', 'registry_uplink', 'web_edge'];
const ownership = { [LABEL]: 'v1', 'com.docker.compose.project': PROJECT };
const links = { 'auth-volume-init': [], 'scan-volume-init': [], egress: ['scan_internal', 'registry_uplink'],
  worker: ['scan_internal'], api: ['auth_internal', 'scan_internal'], web: ['auth_internal', 'web_edge'] };

function fixtureConfig(root = ROOT, cve = null) {
  const config = { name: PROJECT, services: {}, volumes: {}, networks: {} };
  const mounts = { 'auth-volume-init': [['auth_accounts', '/data']], 'scan-volume-init': [['scan_ledger', '/data']],
    worker: [['scan_ledger', '/data']], api: [['auth_accounts', '/auth'], ['scan_ledger', '/data']], egress: [], web: [] };
  const files = { egress: 'gateway/Dockerfile', api: 'api.Dockerfile', worker: 'worker.Dockerfile', web: 'stand.Dockerfile' };
  for (const name of SERVICES) {
    const service = { labels: { [LABEL]: 'v1' }, image: files[name] ? `${PROJECT}-${name}:local` : 'busybox:1.37.0',
      environment: expectedEnvironment(name, cve), volumes: mounts[name].map(([source, target]) => ({ type: 'volume', source, target })),
      networks: Object.fromEntries(links[name].map(key => [key, null])) };
    if (files[name]) service.build = { context: root, dockerfile: `server/deploy/${files[name]}`, labels: { [LABEL]: 'v1' } };
    else { delete service.networks; service.network_mode = 'none'; service.command = ['chown', '65532:65532', '/data']; }
    config.services[name] = service;
  }
  config.services.api.command = ['node', '--import', 'tsx', 'src/oci/nginx-local.main.ts'];
  Object.assign(config.services.worker, { command: ['node', '--import', 'tsx', 'src/worker/nginx-local-worker.main.ts'],
    mem_limit: '1073741824', memswap_limit: '1073741824', cpus: 1, pids_limit: 128 });
  if (cve) {
    for (const name of ['api', 'worker']) config.services[name].volumes.push(...fixtureBinds(name, cve));
    config.services.worker.tmpfs = ['/tmp:rw,noexec,nosuid,size=16m', '/tmp/trivy:rw,noexec,nosuid,uid=65532,gid=65532,size=512m'];
  }
  config.services.web.ports = [{ host_ip: '127.0.0.1', target: 8080, published: '8080', protocol: 'tcp' }];
  for (const key of VOLUMES) config.volumes[key] = { name: `${PROJECT}_${key}`, labels: { [LABEL]: 'v1' } };
  for (const key of NETWORKS) config.networks[key] = { name: `${PROJECT}_${key}`, internal: key.endsWith('_internal'), labels: { [LABEL]: 'v1' } };
  return config;
}
function tempRoot(t) {
  const root = fs.mkdtempSync(join(tmpdir(), 'dip-local-launcher-test-'));
  t.after(() => {
    function writable(path) {
      if (!fs.lstatSync(path).isDirectory()) return;
      fs.chmodSync(path, 0o700);
      for (const child of fs.readdirSync(path)) writable(join(path, child));
    }
    writable(root);
    fs.rmSync(root, { recursive: true, force: true }); // Test-owned temporary files only.
  });
  for (const file of ['.gitignore', '.dockerignore']) fs.writeFileSync(join(root, file), '.local-stand/\n');
  return root;
}
function container(service = 'api', extra = {}) {
  return { Id: `fixture-${service}`, Name: `/${PROJECT}-${service}-1`,
    Config: { Labels: { ...ownership, 'com.docker.compose.service': service },
      Image: service.endsWith('volume-init') ? 'busybox:1.37.0' : `${PROJECT}-${service}:local`,
      Cmd: fixtureConfig().services[service].command,
      Env: Object.entries(expectedEnvironment(service)).map(([key, value]) => `${key}=${value}`) },
    HostConfig: { ...(service === 'worker' ? { Memory: 1073741824, MemorySwap: 1073741824,
      NanoCpus: 1000000000, PidsLimit: 128 } : {}), Mounts: fixtureConfig().services[service].volumes.map(mount => ({ Type: 'volume',
      Source: `${PROJECT}_${mount.source}`, Target: mount.target })) },
    Mounts: fixtureConfig().services[service].volumes.map(mount => ({ Type: 'volume',
      Name: `${PROJECT}_${mount.source}`, Destination: mount.target, RW: true })),  NetworkSettings: { Networks: Object.fromEntries((links[service].length ? links[service].map(n => `${PROJECT}_${n}`) : ['none']).map(n => [n, {}])) },
    State: { Running: true, Status: 'running' }, ...extra };
}
function fakeDocker({ config = fixtureConfig(), containers = [], volumes = [], networks = [], images = [], failUp = false } = {}) {
  const calls = [];
  const inventory = { container: containers, volume: volumes, network: networks };
  const run = async (args, options) => {
    calls.push({ args, options });
    if (args[0] === 'compose') {
      if (args.includes('config')) return JSON.stringify(config);
      assert(args.includes('up'));
      if (failUp) throw new Error('fixture build failure');
      return '';
    }
    if (args[0] === 'image') {
      if (args[1] === 'ls') return images.map(item => item.tag).join('\n');
      return JSON.stringify([images.find(item => item.tag === args[2]).inspect]);
    }
    if (args[1] === 'stop') return '';
    const items = inventory[args[0]];
    if (args[1] === 'ls') {
      return items.map(item => `${item.Name.replace(/^\//, '')}\t${(item.Config?.Labels ?? item.Labels)?.['com.docker.compose.project'] ?? ''}`).join('\n');
    }
    assert.equal(args[1], 'inspect');
    const item = items.find(item => item.Name.replace(/^\//, '') === args[2]);
    assert(item, 'Inspect must address only provided fixtures');
    return JSON.stringify([item]);
  };
  return { run, calls };
}
const volume = key => ({ Name: `${PROJECT}_${key}`, Labels: { ...ownership }, Driver: 'local', Options: null });
const network = key => ({ Name: `${PROJECT}_${key}`, Labels: { ...ownership }, Driver: 'bridge', Internal: key.endsWith('_internal') });

test('fixed Docker environment and explicit Compose project/files exclude ambient activation and dotenv', () => {
  assert.deepEqual(dockerEnvironment({ HOME: '/fixture', PATH: '/fixture/bin', DOCKER_CONTEXT: 'desktop-linux',
    SCAN_JWT_SECRET: 'ambient', SCAN_VULN_ENABLED: 'true', OPENROUTER_API_KEY: 'ambient', LLM_ENABLED: 'true',
    RUNTIME_DB_PATH: '/foreign', COMPOSE_FILE: '/foreign', COMPOSE_PROJECT_NAME: 'dip-auth-stand',
    NODE_OPTIONS: '--require=foreign', HTTP_PROXY: 'foreign' }),
  { PATH: '/fixture/bin', HOME: '/fixture', DOCKER_CONTEXT: 'desktop-linux', COMPOSE_DISABLE_ENV_FILE: 'true' });
  assert.deepEqual(composeArguments(ROOT, ['up', '--build', '-d']), ['compose', '--env-file', '/dev/null', '-p', PROJECT,
    '-f', join(ROOT, 'server/deploy/compose.stand.yaml'), '-f', join(ROOT, 'server/deploy/compose.local.full.yaml'), 'up', '--build', '-d']);
});

test('Docker default clean PATH includes Apple Silicon Homebrew without inherited PATH', () => {
  assert.deepEqual(dockerEnvironment({ HOME: '/fixture' }), {
    PATH: '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
    HOME: '/fixture', COMPOSE_DISABLE_ENV_FILE: 'true',
  });
  assert.equal(dockerEnvironment({}).PATH, '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin');
});

test('merged full stack config accepts only exact LOCAL topology and environment', () => {
  validateConfig(fixtureConfig(), ROOT);
  const changes = [
    c => { c.name = 'dip-auth-stand'; },
    c => { c.volumes.auth_accounts.name = 'old_auth_accounts'; },
    c => { c.volumes.auth_accounts.external = true; },
    c => { c.volumes.scan_ledger.driver_opts = { device: '/old' }; },
    c => { c.networks.scan_internal.internal = false; },
    c => { c.networks.scan_internal.name = 'old_scan_internal'; },
    c => { c.networks.registry_uplink.external = true; },
    c => { c.services.api.volumes[0] = { type: 'bind', source: '/old/auth', target: '/auth' }; },
    c => { c.services.api.volumes[0].source = 'old_auth'; },
    c => { c.services.api.ports = [{ target: 3001, published: '3001' }]; },
    c => { c.services.web.ports[0].host_ip = '0.0.0.0'; },
    c => { c.services.web.ports[0].published = '5173'; },
    c => { c.services.api.environment.AUTH_ORIGIN = 'http://localhost:8080'; },
    c => { c.services.api.environment.LLM_ENABLED = 'true'; },
    c => { c.services.worker.environment.SCAN_VULN_ENABLED = 'true'; },
    c => { c.services.api.environment.RUNTIME_DB_PATH = '/data/runtime.sqlite'; },
    c => { c.services.api.env_file = ['/old/private.env']; },
    c => { c.services.api.network_mode = 'host'; },
    c => { c.services.worker.privileged = true; },
    c => { c.services.worker.memswap_limit = '2147483648'; },
    c => { c.services.worker.build.context = '/foreign'; },
    c => { c.services.worker.build.args = { SECRET: 'not-allowed' }; },
    c => { c.services.web.image = 'old-web:latest'; },
    c => { c.services.api.command = ['node', 'src/main.ts']; },
    c => { c.services.api.entrypoint = ['sh']; },
    c => { c.services.web.labels = {}; },
    c => { c.services.extra = {}; },
    c => { c.secrets = { external: {} }; },
  ];
  for (const change of changes) {
    const config = fixtureConfig(); change(config);
    assert.throws(() => validateConfig(config, ROOT), undefined, change.toString());
  }
});

test('namespace inventory skips old/HOLD/dev resources and accepts owned resources only', async () => {
  const own = container();
  const docker = fakeDocker({ containers: [own, { Name: '/dip-auth-stand-api-1', Config: { Labels: {} } }],
    volumes: [volume('auth_accounts'), { Name: 'HOLD_auth', Labels: {} }], networks: [network('scan_internal')],
    images: [{ tag: `${PROJECT}-api:local`, inspect: { Config: { Labels: { [LABEL]: 'v1' } } } },
      { tag: 'dip-auth-stand-api:HOLD', inspect: {} }] });
  const resources = await inspectNamespace(docker.run, {});
  assert.equal(resources.containers.length, 1);
  assert.equal(resources.volumes.length, 1);
  assert.equal(resources.networks.length, 1);
  assert(!docker.calls.some(call => call.args.includes('dip-auth-stand-api-1') || call.args.includes('HOLD_auth') || call.args.includes('dip-auth-stand-api:HOLD')));
  const init = fakeDocker({ containers: [container('auth-volume-init')] });
  await inspectNamespace(init.run, {}); // Docker's built-in none network is not shared application networking.
});

test('foreign or malformed existing namespace resources block reuse without mutation', async () => {
  const cases = [
    { containers: [container('api', { Config: { Labels: {}, Image: `${PROJECT}-api:local` } })] },
    { containers: [container('api', { Name: '/renamed-with-project-label' })] },
    { containers: [container('api', { Mounts: [{ Type: 'bind', Source: '/old', Destination: '/auth' }] })] },
    { containers: [container('api', { Mounts: [{ Type: 'volume', Name: 'HOLD_auth', Destination: '/auth' }] })] },
    { containers: [container('api', { NetworkSettings: { Networks: { old_shared: {} } } })] },
    { volumes: [{ ...volume('auth_accounts'), Labels: {} }] },
    { volumes: [{ ...volume('scan_ledger'), Options: { device: '/old' } }] },
    { networks: [{ ...network('scan_internal'), Labels: {} }] },
    { networks: [{ ...network('scan_internal'), Internal: false }] },
    { images: [{ tag: `${PROJECT}-api:local`, inspect: { Config: { Labels: {} } } }] },
    { images: [{ tag: `${PROJECT}-api:HOLD`, inspect: {} }] },
  ];
  for (const spec of cases) {
    const docker = fakeDocker(spec);
    await assert.rejects(inspectNamespace(docker.run, {}));
    assert(docker.calls.every(({ args }) => ['ls', 'inspect'].includes(args[1])));
  }
});

test('secret is exclusively created mode 0600 and stable across restarts', t => {
  const root = tempRoot(t);
  let generations = 0;
  const opts = { random: size => { generations++; return Buffer.alloc(size, 0xab); } };
  assert.equal(loadSecret(root, opts), FIXTURE_SECRET);
  const file = join(root, '.local-stand/scan-jwt'), before = fs.statSync(file);
  assert.equal(before.mode & 0o777, 0o600);
  assert.equal(fs.statSync(join(root, '.local-stand')).mode & 0o777, 0o700);
  assert.equal(loadSecret(root, { ...opts, mustExist: true }), FIXTURE_SECRET);
  assert.equal(fs.statSync(file).ino, before.ino);
  assert.equal(generations, 1);
});

test('secret refuses missing recovery file, symlinks, hardlinks, invalid content and unsafe permissions without rotation', t => {
  for (const kind of ['missing', 'symlink', 'directory-link', 'hardlink', 'permissions', 'directory-permissions', 'content', 'directory-file']) {
    const root = tempRoot(t), directory = join(root, '.local-stand'), file = join(directory, 'scan-jwt');
    fs.mkdirSync(directory, { mode: 0o700 });
    const outside = join(root, 'fixture-only-secret'); fs.writeFileSync(outside, FIXTURE_SECRET, { mode: 0o600 });
    if (kind === 'symlink') fs.symlinkSync(outside, file);
    else if (kind === 'directory-link') { fs.rmdirSync(directory); fs.symlinkSync(root, directory); }
    else if (kind === 'hardlink') fs.linkSync(outside, file);
    else if (kind === 'directory-file') fs.mkdirSync(file);
    else if (kind !== 'missing') fs.writeFileSync(file, kind === 'content' ? 'invalid' : FIXTURE_SECRET, { mode: 0o600 });
    if (kind === 'permissions') fs.chmodSync(file, 0o644);
    if (kind === 'directory-permissions') fs.chmodSync(directory, 0o755);
    assert.throws(() => loadSecret(root, { mustExist: true, random: () => assert.fail('must never rotate') }), undefined, kind);
    assert.equal(fs.readFileSync(outside, 'utf8'), FIXTURE_SECRET);
  }
});

test('filesystem injection verifies O_EXCL/O_NOFOLLOW at creation and no-follow reads', t => {
  const root = tempRoot(t), opens = [];
  const io = { ...fs, openSync: (path, flags, mode) => { opens.push({ flags, mode }); return fs.openSync(path, flags, mode); } };
  loadSecret(root, { io, random: size => Buffer.alloc(size, 0xab) });
  assert(opens.every(({ flags }) => (flags & fs.constants.O_NOFOLLOW) !== 0));
  const creation = opens.find(({ flags }) => (flags & fs.constants.O_CREAT) !== 0);
  assert(creation.flags & fs.constants.O_EXCL);
  assert.equal(creation.mode, 0o600);
});

test('up --build preflights absent project, starts detached with 600s timeout, never logs or passes secret as argv', async t => {
  const root = tempRoot(t), docker = fakeDocker({ config: fixtureConfig(root) }), output = [];
  await localStand(['up', '--build'], { root, run: docker.run, ambient: { SCAN_JWT_SECRET: 'foreign', LLM_ENABLED: 'true', OPENROUTER_API_KEY: 'foreign' },
    log: line => output.push(line), getSecret: (root, opts) => loadSecret(root, { ...opts, random: size => Buffer.alloc(size, 0xab) }) });
  const up = docker.calls.at(-1);
  assert.deepEqual(up.args.slice(-3), ['up', '--build', '-d']);
  assert.equal(up.options.timeout, 600_000);
  assert.equal(up.options.env.SCAN_JWT_SECRET, FIXTURE_SECRET);
  assert.equal(up.options.env.AUTH_ORIGIN, ORIGIN);
  assert(!('LLM_ENABLED' in up.options.env)); assert(!('OPENROUTER_API_KEY' in up.options.env));
  assert(!JSON.stringify(docker.calls.map(call => call.args)).includes(FIXTURE_SECRET));
  assert(!output.join('\n').includes(FIXTURE_SECRET));
  assert(docker.calls.slice(0, -1).every(call => !JSON.stringify(call.options.env).includes(FIXTURE_SECRET)));
  assert.equal(docker.calls[0].args.at(-3), 'config');
  assert(docker.calls.slice(1, -1).every(call => call.args[1] === 'ls'));
  const second = fakeDocker({ config: fixtureConfig(root), volumes: [volume('auth_accounts')] });
  await localStand(['up'], { root, run: second.run, log: () => {} });
  assert.deepEqual(second.calls.at(-1).args.slice(-2), ['up', '-d']);
  assert.equal(second.calls.at(-1).options.env.SCAN_JWT_SECRET, FIXTURE_SECRET);
});

test('status and stop do not read/create signing secret and stop only inspected running IDs', async t => {
  for (const command of ['status', 'stop']) {
    const root = tempRoot(t);
    const docker = fakeDocker({ config: fixtureConfig(root), containers: [container(), container('auth-volume-init', { State: { Running: false, Status: 'exited' } })] });
    const output = [];
    await localStand([command], { root, run: docker.run, log: line => output.push(line), getSecret: () => assert.fail('secret must not be touched') });
    const stops = docker.calls.filter(call => call.args[1] === 'stop');
    assert.equal(stops.length, command === 'stop' ? 1 : 0);
    if (command === 'stop') assert.deepEqual(stops[0].args, ['container', 'stop', '--time', '30', 'fixture-api']);
    assert(!docker.calls.some(call => call.args.includes('down') || call.args.includes('rm') || call.args.includes('prune') || call.args.includes('up')));
    assert(output.length > 0);
    assert(!fs.existsSync(join(root, '.local-stand/.stand-operation.lock')));
  }
});

test('ignore guard and namespace/recovery refusals happen before up', async t => {
  const root = tempRoot(t);
  fs.writeFileSync(join(root, '.dockerignore'), '.local-auth/\n');
  assert.throws(() => checkIgnores(root), /gitignore and .dockerignore/);
  let docker = fakeDocker({ config: fixtureConfig(root) });
  await assert.rejects(localStand(['up'], { root, run: docker.run, log: () => {}, getSecret: () => assert.fail('secret before ignore check') }));
  assert(!docker.calls.some(call => call.args.includes('up')));
  fs.writeFileSync(join(root, '.dockerignore'), '.local-stand/\n');
  docker = fakeDocker({ config: fixtureConfig(root), volumes: [volume('auth_accounts')] });
  await assert.rejects(localStand(['up'], { root, run: docker.run, log: () => {} }), /refusing replacement/);
  assert(!fs.existsSync(join(root, '.local-stand/scan-jwt')));
  assert(!docker.calls.some(call => call.args.includes('up')));
  docker = fakeDocker({ config: fixtureConfig(root), volumes: [{ ...volume('auth_accounts'), Labels: {} }] });
  await assert.rejects(localStand(['up'], { root, run: docker.run, log: () => {}, getSecret: () => assert.fail('secret before ownership') }));
});

test('failed up preserves signing secret and never attempts destructive cleanup', async t => {
  const root = tempRoot(t), docker = fakeDocker({ config: fixtureConfig(root), failUp: true });
  await assert.rejects(localStand(['up', '--build'], { root, run: docker.run, log: () => {},
    getSecret: (root, opts) => loadSecret(root, { ...opts, random: size => Buffer.alloc(size, 0xab) }) }));
  assert.equal(fs.readFileSync(join(root, '.local-stand/scan-jwt'), 'utf8'), FIXTURE_SECRET);
  assert(docker.calls.at(-1).args.includes('up'));
  assert(!docker.calls.some(call => call.args.some(arg => ['down', 'rm', 'prune', '--force-recreate', '--remove-orphans'].includes(arg))));
});

test('up/stop client errors and timeouts retain durable uncertainty marker and exclude retries/refresh', async t => {
  for (const command of ['up', 'stop']) for (const failure of ['error', 'timeout']) {
    await t.test(`${command}-${failure}`, async t => {
      const root = tempRoot(t), docker = fakeDocker({ config: fixtureConfig(root), containers: [container()] });
      const lock = join(root, '.local-stand/.stand-operation.lock'), marker = join(lock, 'launcher.json');
      const run = async (args, options) => {
        if (args.includes('up') || args[1] === 'stop') {
          assert.deepEqual(JSON.parse(fs.readFileSync(marker, 'utf8')), { version: 1, command,
            phase: 'mutation-intent-outcome-unconfirmed', uncertain: true });
          assert.equal(fs.statSync(marker).mode & 0o777, 0o600);
          const error = new Error('SYNTHETIC-PRIVATE-CLIENT-OUTPUT');
          if (failure === 'timeout') { error.killed = true; error.code = 'ETIMEDOUT'; }
          throw error;
        }
        return docker.run(args, options);
      };
      await assert.rejects(localStand([command], { root, run, log: () => {}, getSecret: () => FIXTURE_SECRET }), error =>
        /uncertain\/HOLD/.test(error.message) && !error.message.includes('SYNTHETIC-PRIVATE'));
      assert(fs.existsSync(marker));
      for (const retry of ['up', 'stop']) await assert.rejects(localStand([retry], { root,
        run: () => assert.fail('locked retry must not contact Docker'), log: () => {} }));
      await assert.rejects(refreshLocalCve([], { root,
        run: () => assert.fail('locked refresh must not start child'), docker: () => assert.fail('locked refresh must not contact Docker') }));
      assert(fs.existsSync(marker));
      assert(!fs.readFileSync(marker, 'utf8').includes(FIXTURE_SECRET));
    });
  }
});

test('read-only preflight errors/timeouts release launcher lock without an uncertainty marker', async t => {
  for (const command of ['up', 'stop']) {
    const root = tempRoot(t), lock = join(root, '.local-stand/.stand-operation.lock');
    await assert.rejects(localStand([command], { root, run: async args => {
      assert(args.includes('config')); throw Object.assign(new Error('preflight timeout'), { killed: true });
    }, log: () => {} }));
    assert(!fs.existsSync(lock));
    const docker = fakeDocker({ config: fixtureConfig(root) });
    await localStand(['stop'], { root, run: docker.run, log: () => {} });
    assert(!fs.existsSync(lock));
  }
});

test('acknowledged up clears mutation marker and releases shared lock', async t => {
  const root = tempRoot(t), docker = fakeDocker({ config: fixtureConfig(root) });
  await localStand(['up'], { root, run: docker.run, log: () => {}, getSecret: () => FIXTURE_SECRET });
  assert(!fs.existsSync(join(root, '.local-stand/.stand-operation.lock')));
});

test('invalid CLI flags reject before any Docker or filesystem activity', async () => {
  for (const args of [[], ['down'], ['up', '--env-file', 'foreign'], ['stop', '--build'], ['up', '--build', '--build']]) {
    await assert.rejects(localStand(args, { run: () => assert.fail('must not call Docker'), getSecret: () => assert.fail('must not read secret') }), /Usage:/);
  }
});

test('override pins real LOCAL entrypoints/builds, fixed flags, labels and project-specific storage', () => {
  const text = fs.readFileSync(join(ROOT, 'server/deploy/compose.local.full.yaml'), 'utf8');
  for (const service of ['egress', 'api', 'worker', 'web']) assert(text.includes(`image: dip-local-full-${service}:local`));
  for (const key of [...VOLUMES, ...NETWORKS]) assert(text.includes(`name: dip-local-full_${key}`));
  assert.equal((text.match(/org\.diplom\.local-stand: v1/g) ?? []).length, 16);
  assert(text.includes('src/oci/nginx-local.main.ts')); assert(text.includes('src/worker/nginx-local-worker.main.ts'));
  assert(text.includes('AUTH_ORIGIN: http://127.0.0.1:8080'));
  assert(text.includes('SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: "true"'));
  assert(text.includes('LLM_ENABLED: "false"')); assert(text.includes('SCAN_VULN_ENABLED: "false"'));
  assert(text.includes('memswap_limit: 1g'));
  assert(!/\.local-auth|env_file:|type: bind|external:|OPENROUTER_API_KEY|RUNTIME_DB_PATH|HOST_DB_PATH/.test(text));
  assert.deepEqual([...text.matchAll(/\$\{([^}]+)\}/g)].map(match => match[1].split(':')[0]), ['SCAN_JWT_SECRET']);
});

function fixtureBinds(service, cve) {
  const mounts = [
    { type: 'bind', source: cve.releaseHostDir, target: '/opt/release', read_only: true, bind: { create_host_path: false } },
    { type: 'bind', source: cve.publicKeyPath, target: '/opt/local-db-trust/public.pem', read_only: true, bind: { create_host_path: false } },
  ];
  if (service === 'worker') mounts.push({ type: 'bind', source: join(cve.releaseHostDir, 'db'), target: '/tmp/trivy/db',
    read_only: true, bind: { create_host_path: false } });
  return mounts;
}
function cveFixture(t) {
  const root = tempRoot(t), directory = join(root, '.local-stand');
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.mkdirSync(join(directory, 'db-releases'), { mode: 0o700 });
  fs.mkdirSync(join(directory, 'trust'), { mode: 0o700 });
  const release = `db-releases/${'a'.repeat(64)}`, releaseHostDir = join(directory, release);
  fs.mkdirSync(releaseHostDir);
  fs.mkdirSync(join(releaseHostDir, 'db'));
  for (const file of ['descriptor.json', 'descriptor.sig', 'bundle.bin', 'db/metadata.json', 'db/trivy.db']) {
    fs.writeFileSync(join(releaseHostDir, file), 'fixture-public-bytes', { mode: 0o444 });
  }
  fs.chmodSync(join(releaseHostDir, 'db'), 0o555);
  fs.chmodSync(releaseHostDir, 0o555);
  const { publicKey } = generateKeyPairSync('ed25519');
  const publicKeyPath = join(directory, 'trust/db-signing-key.pub.pem');
  fs.writeFileSync(publicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o444 });
  const value = { version: 1, release, manifestDigest: `sha256:${'b'.repeat(64)}`, artifactSha256: 'c'.repeat(64),
    publicKeySha256: createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex') };
  const activationPath = join(directory, 'cve.json');
  fs.writeFileSync(activationPath, JSON.stringify(value), { mode: 0o600 });
  return { root, directory, value, activationPath, releaseHostDir, publicKeyPath,
    cve: loadCveActivation(root) };
}
function enabledContainer(service, cve) {
  const item = container(service);
  item.Config.Env = Object.entries(expectedEnvironment(service, cve)).map(([key, value]) => `${key}=${value}`);
  item.HostConfig.Mounts.push(...fixtureBinds(service, cve).map(bind => ({ Type: 'bind', Source: bind.source,
    Target: bind.target, ReadOnly: true, BindOptions: {} })));
  item.Mounts.push(...fixtureBinds(service, cve).map(bind => ({ Type: 'bind', Source: bind.source,
    Destination: bind.target, RW: false, Propagation: 'rprivate' })));
  if (service === 'worker') item.Mounts.push({ Type: 'tmpfs', Destination: '/tmp/trivy' });
  return item;
}

test('activation absence alone disables CVE, without creating directories or accepting ambient enablement', async t => {
  const root = tempRoot(t);
  assert.equal(loadCveActivation(root), null);
  const docker = fakeDocker({ config: fixtureConfig(root) });
  await localStand(['status'], { root, run: docker.run, log: () => {}, ambient: {
    LOCAL_CVE_TRUST_SHA256: 'a'.repeat(64), SCAN_VULN_RELEASE_HOST_DIR: '/foreign', SCAN_VULN_ENABLED: 'true' } });
  assert(!fs.existsSync(join(root, '.local-stand')));
  assert(!docker.calls[0].args.some(arg => arg.endsWith('compose.local.cve.yaml')));
  assert(!('LOCAL_CVE_TRUST_SHA256' in docker.calls[0].options.env));
  fs.mkdirSync(join(root, '.local-stand'), { mode: 0o700 });
  assert.equal(loadCveActivation(root), null);
});

test('canonical public activation validates fixed immutable release and SPKI pin; only public JSON/PEM are opened no-follow', t => {
  const { root, value, activationPath, publicKeyPath, releaseHostDir, directory } = cveFixture(t);
  // A private-key path exists, but even looking through it would be a bug.
  fs.symlinkSync('/private-key-must-never-be-read', join(directory, 'trust/db-signing-key.pem'));
  const opened = [];
  const io = { ...fs, openSync(path, flags) {
    assert([activationPath, publicKeyPath].includes(path));
    assert(flags & fs.constants.O_NOFOLLOW);
    assert(!(flags & (fs.constants.O_CREAT | fs.constants.O_WRONLY | fs.constants.O_RDWR)));
    opened.push(path); return fs.openSync(path, flags);
  } };
  const cve = loadCveActivation(root, { io });
  assert.deepEqual(cve, { ...value, releaseHostDir, publicKeyPath });
  assert(Object.isFrozen(cve));
  assert.deepEqual(opened, [activationPath, publicKeyPath]);
  assert.throws(() => loadCveActivation(root, { uid: process.getuid() + 1 }));
  const args = composeArguments(root, ['config', '--format', 'json'], cve);
  assert.deepEqual(args.slice(-5), ['-f', join(root, 'server/deploy/compose.local.cve.yaml'), 'config', '--format', 'json']);
});

test('activation rejects malformed, noncanonical, oversized, duplicate/extra/missing schema fields and unsafe paths', t => {
  const { root, value, activationPath } = cveFixture(t);
  const bad = [null, [], {}, { ...value, version: 2 }, { ...value, extra: 'private' },
    { ...value, publicKeySha256: undefined }, { ...value, manifestDigest: 'b'.repeat(64) },
    { ...value, artifactSha256: 'C'.repeat(64) }, { ...value, publicKeySha256: 'bad' },
    ...['../db-releases/id', 'db-releases/../id', 'db-releases/id/sub', '/db-releases/id',
      'db-releases/id/', 'db-releases/.', 'db-releases/..', 'db-releases/id.pem', 'db-releases/id\\sub',
      'db-releases/', `db-releases/${'a'.repeat(129)}`].map(release => ({ ...value, release }))];
  const bytes = [...bad.map(item => JSON.stringify(item)), '', '{', JSON.stringify(value) + '\n', JSON.stringify(value, null, 2),
    JSON.stringify({ release: value.release, ...value }), JSON.stringify(value).replace('"version":1', '"version":1,"version":1'),
    JSON.stringify(value).replace('"version":1', '"version":1.0'), ' '.repeat(4097), Buffer.from([0xff])];
  for (const raw of bytes) {
    fs.writeFileSync(activationPath, raw);
    assert.throws(() => loadCveActivation(root), undefined, String(raw));
  }
});

test('activation rejects insecure file/directory permissions, symlinks, hardlinks and release extras', t => {
  const mutations = [
    f => fs.chmodSync(f.directory, 0o755),
    f => fs.chmodSync(f.activationPath, 0o644),
    f => { fs.unlinkSync(f.activationPath); fs.symlinkSync('missing-public-json', f.activationPath); },
    f => { fs.unlinkSync(f.activationPath); fs.mkdirSync(f.activationPath); },
    f => fs.linkSync(f.activationPath, join(f.directory, 'hardlinked-activation')),
    f => { fs.renameSync(f.directory, `${f.directory}-real`); fs.symlinkSync(`${f.directory}-real`, f.directory); },
    f => { fs.renameSync(join(f.directory, 'db-releases'), join(f.directory, 'releases-real'));
      fs.symlinkSync('releases-real', join(f.directory, 'db-releases')); },
    f => { fs.renameSync(f.releaseHostDir, `${f.releaseHostDir}-real`); fs.symlinkSync(`${f.releaseHostDir}-real`, f.releaseHostDir); },
    f => { fs.chmodSync(f.releaseHostDir, 0o755); },
    f => { fs.chmodSync(join(f.releaseHostDir, 'db'), 0o755); },
    f => { fs.chmodSync(f.releaseHostDir, 0o755); fs.renameSync(join(f.releaseHostDir, 'db'), join(f.releaseHostDir, 'db-real'));
      fs.symlinkSync('db-real', join(f.releaseHostDir, 'db')); },
    f => fs.chmodSync(join(f.releaseHostDir, 'db/trivy.db'), 0o644),
    f => fs.linkSync(join(f.releaseHostDir, 'bundle.bin'), join(f.directory, 'hardlinked-bundle')),
    f => { fs.chmodSync(f.releaseHostDir, 0o755); fs.writeFileSync(join(f.releaseHostDir, 'private.pem'), 'not allowed');
      fs.chmodSync(f.releaseHostDir, 0o555); },
    f => { fs.chmodSync(f.releaseHostDir, 0o755); fs.unlinkSync(join(f.releaseHostDir, 'descriptor.sig'));
      fs.symlinkSync('../outside.sig', join(f.releaseHostDir, 'descriptor.sig')); fs.chmodSync(f.releaseHostDir, 0o555); },
    f => { fs.renameSync(join(f.directory, 'trust'), join(f.directory, 'trust-real')); fs.symlinkSync('trust-real', join(f.directory, 'trust')); },
    f => fs.chmodSync(f.publicKeyPath, 0o644),
    f => { fs.unlinkSync(f.publicKeyPath); fs.symlinkSync('missing-public.pem', f.publicKeyPath); },
    f => fs.linkSync(f.publicKeyPath, join(f.directory, 'hardlinked-public-key')),
  ];
  for (const mutate of mutations) {
    const fixture = cveFixture(t); mutate(fixture);
    assert.throws(() => loadCveActivation(fixture.root), undefined, mutate.toString());
  }
});

test('public key pin tampering, malformed PEM and non-public PEM refuse activation', t => {
  const { root, value, activationPath, publicKeyPath } = cveFixture(t);
  fs.writeFileSync(activationPath, JSON.stringify({ ...value, publicKeySha256: 'd'.repeat(64) }));
  assert.throws(() => loadCveActivation(root), /SPKI SHA256/);
  fs.writeFileSync(activationPath, JSON.stringify(value));
  for (const pem of ['bad pem', '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n', 'x'.repeat(4097)]) {
    fs.chmodSync(publicKeyPath, 0o600); fs.writeFileSync(publicKeyPath, pem); fs.chmodSync(publicKeyPath, 0o444);
    assert.throws(() => loadCveActivation(root));
  }
});

test('merged CVE config accepts exact public read-only binds/environment only and unchanged worker envelope', t => {
  const { root, cve, directory } = cveFixture(t);
  validateConfig(fixtureConfig(root, cve), root, cve);
  const normalized = fixtureConfig(root, cve);
  for (const service of ['api', 'worker']) for (const mount of normalized.services[service].volumes) {
    if (mount.type === 'bind') mount.bind = {}; // Actual Compose JSON omits explicit false.
  }
  validateConfig(normalized, root, cve);
  const changes = [
    c => { c.services.api.environment.LOCAL_CVE_TRUST_SHA256 = 'd'.repeat(64); },
    c => { c.services.worker.environment.SCAN_VULN_MANIFEST_DIGEST = `sha256:${'e'.repeat(64)}`; },
    c => { c.services.worker.environment.SCAN_VULN_ARTIFACT_SHA256 = 'e'.repeat(64); },
    c => { c.services.api.environment.SCAN_VULN_RELEASE_DIR = '/other'; },
    c => { c.services.api.environment.SCAN_VULN_ENABLED = 'false'; },
    c => { c.services.api.environment.LOCAL_CVE_TRUST_PATH = '/opt/key.pem'; },
    c => { c.services.api.volumes[2].read_only = false; },
    c => { c.services.api.volumes[2].source = directory; },
    c => { c.services.api.volumes[2].source += '/db'; },
    c => { c.services.api.volumes[3].source = join(directory, 'trust/db-signing-key.pem'); },
    c => { c.services.api.volumes[3].source = join(directory, 'trust'); },
    c => { c.services.api.volumes[3].target = '/opt/local-db-trust'; },
    c => { c.services.api.volumes[3].bind.create_host_path = true; },
    c => { c.services.api.volumes[3].bind.propagation = 'shared'; },
    c => { delete c.services.api.volumes[3].bind; },
    c => { c.services.worker.volumes.at(-1).source = join(directory, 'db'); },
    c => { c.services.worker.volumes.at(-1).target = '/tmp/db'; },
    c => { c.services.worker.volumes.push({ ...c.services.worker.volumes.at(-1) }); },
    c => { c.services.worker.tmpfs = ['/tmp:size=512m']; },
    c => { c.services.worker.mem_limit = '2147483648'; },
    c => { c.services.worker.memswap_limit = '2147483648'; },
    c => { c.services.worker.cpus = 2; },
    c => { c.services.worker.pids_limit = 256; },
  ];
  for (const mutate of changes) {
    const config = fixtureConfig(root, cve); mutate(config);
    assert.throws(() => validateConfig(config, root, cve), undefined, mutate.toString());
  }
  assert.throws(() => validateConfig(fixtureConfig(root, cve), root));
  assert.throws(() => validateConfig(fixtureConfig(root), root, cve));
});

test('owned enabled inventory accepts exact RO binds, rejects private/parent/wrong-path/RW/environment and symlink attacks', async t => {
  const { root, cve, directory } = cveFixture(t);
  for (const service of ['api', 'worker']) {
    const docker = fakeDocker({ containers: [enabledContainer(service, cve)] });
    await inspectNamespace(docker.run, { root });
  }
  const mutations = [
    c => { c.Mounts.find(m => m.Destination === '/opt/release').RW = true; },
    c => { c.Mounts.find(m => m.Destination === '/opt/release').Source = directory; },
    c => { c.Mounts.find(m => m.Destination === '/opt/release').Source += '/../other'; },
    c => { c.Mounts.find(m => m.Destination === '/opt/local-db-trust/public.pem').Source = join(directory, 'trust/db-signing-key.pem'); },
    c => { c.Mounts.find(m => m.Destination === '/opt/local-db-trust/public.pem').Source = join(directory, 'trust'); },
    c => { c.Mounts.find(m => m.Destination === '/opt/local-db-trust/public.pem').Destination = '/opt/key.pem'; },
    c => { c.Mounts.find(m => m.Destination === '/tmp/trivy/db').Source = join(directory, 'db'); },
    c => { c.Mounts.push({ Type: 'bind', Source: directory, Destination: '/leak', RW: false }); },
    c => { c.Config.Env.push('LOCAL_CVE_TRUST_PATH=/opt/other.pem'); },
    c => { c.Config.Env.push('SCAN_VULN_ENABLED=true'); },
    c => { c.Config.Env = c.Config.Env.map(e => e.startsWith('LOCAL_CVE_TRUST_SHA256=') ? `LOCAL_CVE_TRUST_SHA256=${'e'.repeat(64)}` : e); },
    c => { c.Config.Env = c.Config.Env.filter(e => !e.startsWith('SCAN_VULN_ARTIFACT_SHA256=')); },
    c => { c.Config.Env = c.Config.Env.map(e => e === 'SCAN_VULN_ENABLED=true' ? 'SCAN_VULN_ENABLED=false' : e); },
  ];
  for (const mutate of mutations) {
    const item = enabledContainer('worker', cve); mutate(item);
    const docker = fakeDocker({ containers: [item] });
    await assert.rejects(inspectNamespace(docker.run, { root }), undefined, mutate.toString());
    assert(docker.calls.every(({ args }) => ['ls', 'inspect'].includes(args[1])));
  }
  fs.renameSync(cve.releaseHostDir, `${cve.releaseHostDir}-real`);
  fs.symlinkSync(`${cve.releaseHostDir}-real`, cve.releaseHostDir);
  const docker = fakeDocker({ containers: [enabledContainer('api', cve)] });
  await assert.rejects(inspectNamespace(docker.run, { root }));
});

test('present invalid activation refuses every command before Docker/JWT; no fallback off', async t => {
  const { root, activationPath } = cveFixture(t);
  fs.writeFileSync(activationPath, '{}');
  for (const command of ['up', 'status', 'stop']) await assert.rejects(localStand([command], {
    root, run: () => assert.fail('Docker must not be called'), getSecret: () => assert.fail('JWT must not be touched'), log: () => {} }));
});

test('off-to-on reuses owned resources and JWT unchanged, exports only four public CVE substitutions', async t => {
  const { root, cve } = cveFixture(t);
  const jwt = loadSecret(root, { random: size => Buffer.alloc(size, 0xab) });
  const before = fs.statSync(join(root, '.local-stand/scan-jwt'));
  const docker = fakeDocker({ config: fixtureConfig(root, cve), containers: [container('api'), container('worker')],
    volumes: VOLUMES.map(volume), networks: NETWORKS.map(network) });
  await localStand(['up'], { root, run: docker.run, log: () => {}, ambient: { SCAN_VULN_RELEASE_HOST_DIR: '/private',
    LOCAL_CVE_TRUST_SHA256: 'foreign', SCAN_VULN_MANIFEST_DIGEST: 'foreign', SCAN_VULN_ARTIFACT_SHA256: 'foreign' } });
  const up = docker.calls.at(-1);
  assert.equal(up.options.env.SCAN_JWT_SECRET, jwt);
  assert.equal(fs.statSync(join(root, '.local-stand/scan-jwt')).ino, before.ino);
  for (const call of [docker.calls[0], up]) {
    assert(call.args.includes(join(root, 'server/deploy/compose.local.cve.yaml')));
    assert.deepEqual(Object.fromEntries(Object.entries(call.options.env).filter(([key]) => /CVE|VULN/.test(key))), {
      SCAN_VULN_RELEASE_HOST_DIR: cve.releaseHostDir, SCAN_VULN_MANIFEST_DIGEST: cve.manifestDigest,
      SCAN_VULN_ARTIFACT_SHA256: cve.artifactSha256, LOCAL_CVE_TRUST_SHA256: cve.publicKeySha256 });
    assert(!JSON.stringify(call.args).includes(cve.publicKeySha256));
  }
  assert(!docker.calls.some(call => call.args.some(arg => ['down', 'rm', 'prune', '--force-recreate', '--remove-orphans'].includes(arg))));
});

test('enabled status/stop and on-to-off inventory accept legitimate RO binds without touching JWT', async t => {
  const { root, cve, activationPath } = cveFixture(t);
  for (const enabled of [true, false]) {
    if (!enabled) fs.unlinkSync(activationPath);
    for (const command of ['status', 'stop']) {
      const docker = fakeDocker({ config: fixtureConfig(root, enabled ? cve : null),
        containers: [enabledContainer('api', cve), enabledContainer('worker', cve)], volumes: VOLUMES.map(volume) });
      await localStand([command], { root, run: docker.run, log: () => {}, getSecret: () => assert.fail('JWT must not be read') });
      assert.equal(docker.calls.some(call => call.args[1] === 'stop'), command === 'stop');
      assert.equal(docker.calls[0].args.includes(join(root, 'server/deploy/compose.local.cve.yaml')), enabled);
    }
  }
});

function desktopContainer(service, cve, mappedDeclaration = false) {
  const item = enabledContainer(service, cve);
  for (const mount of item.Mounts) if (mount.Type === 'bind') mount.Source = `/host_mnt${mount.Source}`;
  if (mappedDeclaration) for (const mount of item.HostConfig.Mounts) {
    if (mount.Type === 'bind') mount.Source = `/host_mnt${mount.Source}`;
  }
  return item;
}

test('Desktop bind alias is macOS-only and requires exact RO host declarations for API/worker', async t => {
  const { root, cve } = cveFixture(t);
  for (const service of ['api', 'worker']) {
    for (const mappedDeclaration of [false, true]) {
      const docker = fakeDocker({ containers: [desktopContainer(service, cve, mappedDeclaration)] });
      const resources = await inspectNamespace(docker.run, { root }, { platform: 'darwin' });
      assert.equal(resources.containers.length, 1);
      for (const platform of ['linux', 'win32']) await assert.rejects(inspectNamespace(docker.run, { root }, { platform }));
    }
    for (const platform of ['darwin', 'linux']) {
      const docker = fakeDocker({ containers: [enabledContainer(service, cve)] });
      await inspectNamespace(docker.run, { root }, { platform });
    }
  }
});

test('Desktop rejects missing/mismatched declarations, naked aliases, other prefixes, private/parent binds and pin tampering', async t => {
  const { root, cve, directory } = cveFixture(t);
  // Test every release/public-key/worker-DB target rather than permitting an alias
  // globally once the release mount has passed.
  for (const bind of fixtureBinds('worker', cve)) {
    const target = bind.target;
    const declared = item => item.HostConfig.Mounts.find(mount => mount.Target === target);
    const observed = item => item.Mounts.find(mount => mount.Destination === target);
    const mutations = [
      item => { delete item.HostConfig; },
      item => { item.HostConfig.Mounts = item.HostConfig.Mounts.filter(mount => mount.Target !== target); },
      item => { delete declared(item).Source; },
      item => { declared(item).Source = `/host_mnt${bind.source}-other`; },
      item => { declared(item).Source = directory; },
      item => { declared(item).Source = join(directory, 'trust/db-signing-key.pem'); },
      item => { declared(item).ReadOnly = false; },
      item => { delete declared(item).ReadOnly; },
      item => { declared(item).Type = 'volume'; },
      item => { declared(item).Target = '/wrong-target'; },
      item => { declared(item).BindOptions = { Propagation: 'shared' }; },
      item => { item.HostConfig.Mounts.push({ ...declared(item) }); },
      item => { observed(item).RW = true; },
      item => { observed(item).Type = 'volume'; },
      item => { observed(item).Destination = '/wrong-target'; },
      item => { observed(item).Source = `/other_mnt${bind.source}`; },
      item => { observed(item).Source = `/host_mnt/host_mnt${bind.source}`; },
      item => { observed(item).Source = `/host_mnt${bind.source}/../other`; },
      item => { observed(item).Source = `/host_mnt${bind.source}/`; },
      item => { observed(item).Source = `/host_mnt${bind.source.replace('/.local-stand/', '//.local-stand/')}`; },
      item => { observed(item).Source = `/host_mnt${directory}`; },
      item => { observed(item).Source = `/host_mnt${join(directory, 'trust/db-signing-key.pem')}`; },
      item => { declared(item).Source = observed(item).Source = `/host_mnt${directory}`; },
      item => { declared(item).Source = observed(item).Source = `/host_mnt${join(directory, 'trust/db-signing-key.pem')}`; },
      item => { declared(item).Source = `/host_mnt${bind.source}`; observed(item).Source = bind.source; },
      item => { item.Config.Env.push('SCAN_VULN_RELEASE_HOST_DIR=' + cve.releaseHostDir); },
      item => { item.Config.Env = item.Config.Env.map(entry => entry.startsWith('LOCAL_CVE_TRUST_SHA256=') ?
        `LOCAL_CVE_TRUST_SHA256=${'d'.repeat(64)}` : entry); },
    ];
    for (const mutate of mutations) {
      const item = desktopContainer('worker', cve); mutate(item);
      const docker = fakeDocker({ containers: [item] });
      await assert.rejects(inspectNamespace(docker.run, { root }, { platform: 'darwin' }), undefined, `${target}: ${mutate}`);
      assert(docker.calls.every(({ args }) => ['ls', 'inspect'].includes(args[1])));
    }
  }
});

test('Desktop enabled status and simulated up restart retain exact pins/JWT for both declaration forms', async t => {
  const { root, cve } = cveFixture(t);
  const secret = loadSecret(root, { random: size => Buffer.alloc(size, 0xab) });
  for (const mappedDeclaration of [false, true]) {
    for (const command of ['status', 'up']) {
      const docker = fakeDocker({ config: fixtureConfig(root, cve),
        containers: ['api', 'worker'].map(service => desktopContainer(service, cve, mappedDeclaration)), volumes: VOLUMES.map(volume) });
      await localStand([command], { root, run: docker.run, platform: 'darwin', log: () => {},
        getSecret: command === 'status' ? () => assert.fail('status must not touch JWT') : loadSecret });
      if (command === 'up') {
        assert.deepEqual(docker.calls.at(-1).args.slice(-2), ['up', '-d']);
        assert.equal(docker.calls.at(-1).options.env.SCAN_JWT_SECRET, secret);
        assert.equal(docker.calls.at(-1).options.env.LOCAL_CVE_TRUST_SHA256, cve.publicKeySha256);
      } else assert(!docker.calls.some(call => call.args.includes('up')));
      assert(!docker.calls.some(call => call.args.some(arg => ['stop', 'down', 'rm', 'prune', '--force-recreate'].includes(arg))));
    }
  }
});

function publicImageFixture(cve = null) {
  const config = fixtureConfig(ROOT, cve);
  for (const name of ['auth-volume-init', 'scan-volume-init']) Object.assign(config.services[name], {
    cap_drop: ['ALL'], cap_add: ['CHOWN'], security_opt: ['no-new-privileges:true'],
  });
  for (const name of ['api', 'worker', 'web', 'egress']) {
    Object.assign(config.services[name], { read_only: true, user: name === 'web' ? '101:101' : '65532:65532',
      cap_drop: ['ALL'], security_opt: ['no-new-privileges:true'], pids_limit: 128,
      mem_limit: { api: 536870912, worker: PUBLIC_IMAGE_MEMORY, web: 268435456, egress: 268435456 }[name] });
    if (['api', 'web'].includes(name)) config.services[name].tmpfs = ['/tmp'];
  }
  config.services.egress.cpus = 1;
  config.services.api.command = [...PUBLIC_IMAGE_COMMANDS.api];
  Object.assign(config.services.worker, { command: [...PUBLIC_IMAGE_COMMANDS.worker],
    memswap_limit: PUBLIC_IMAGE_MEMORY, tmpfs: [...PUBLIC_IMAGE_TMPFS] });
  return config;
}
const publicCveMetadata = { version: 1, release: 'db-releases/fixture', manifestDigest: `sha256:${'a'.repeat(64)}`,
  artifactSha256: 'b'.repeat(64), publicKeySha256: 'c'.repeat(64) };
const publicCve = () => publicImageCveConfig(ROOT, publicCveMetadata);

test('public profile is explicit and accepts only its exact commands/resources with CVE on or off', () => {
  for (const cve of [null, publicCve()]) {
    const config = publicImageFixture(cve);
    validateConfig(config, ROOT, cve, 'public-images');
    assert.throws(() => validateConfig(config, ROOT, cve), /entrypoint/);
    assert.throws(() => validateConfig(fixtureConfig(ROOT, cve), ROOT, cve, 'public-images'));
    for (const name of ['api', 'worker']) {
      const mixed = structuredClone(config);
      mixed.services[name].command = fixtureConfig().services[name].command;
      assert.throws(() => validateConfig(mixed, ROOT, cve, 'public-images'), /entrypoint/);
    }
  }
  assert.throws(() => validateConfig(publicImageFixture(), ROOT, null, true), /profile/);
  assert.throws(() => composeArguments(ROOT, [], null, 'PUBLIC_IMAGES'), /profile/);
  for (const args of [['up', '-d'], ['stop'], ['config', '--env-file', 'private']]) {
    assert.throws(() => composeArguments(ROOT, args, null, 'public-images'), /activation BLOCKED/);
  }
});

test('public override is LAST after CVE; default file order and resource contract remain closed', () => {
  for (const cve of [null, publicCve()]) {
    const args = composeArguments(ROOT, ['config', '--format', 'json'], cve, 'public-images');
    const files = args.filter((_, i) => args[i - 1] === '-f');
    assert.deepEqual(files, ['compose.stand.yaml', 'compose.local.full.yaml',
      ...(cve ? ['compose.local.cve.yaml'] : []), 'compose.local.public-images.yaml'].map(file => join(ROOT, 'server/deploy', file)));
    assert(!composeArguments(ROOT, [], cve).some(arg => arg.includes('public-images.yaml')));
  }
  validateConfig(fixtureConfig(), ROOT);
  const wrongDefault = fixtureConfig();
  wrongDefault.services.worker.mem_limit = PUBLIC_IMAGE_MEMORY;
  assert.throws(() => validateConfig(wrongDefault, ROOT), /memory/);
  const text = fs.readFileSync(join(ROOT, 'server/deploy/compose.local.public-images.yaml'), 'utf8');
  for (const command of Object.values(PUBLIC_IMAGE_COMMANDS)) assert(text.includes(command.at(-1)));
  for (const tmpfs of PUBLIC_IMAGE_TMPFS) assert(text.includes(`- ${tmpfs}`));
  assert(text.includes('tmpfs: !override'));
  assert(text.includes('mem_limit: 4g')); assert(text.includes('memswap_limit: 4g'));
  assert(text.includes('cpus: 1')); assert(text.includes('pids_limit: 128'));
  assert(!/environment:|volumes:|build:|ports:|networks:|\$\{/.test(text));
});

test('public validation rejects malicious envelopes, authority, mounts, admission and reversed CVE merge', () => {
  const mutations = [
    c => { c.services.worker.mem_limit = 1073741824; },
    c => { c.services.worker.memswap_limit = 8589934592; },
    c => { c.services.worker.memswap_limit = 0; },
    c => { c.services.worker.cpus = 2; },
    c => { c.services.worker.pids_limit = -1; },
    c => { c.services.worker.tmpfs = ['/tmp:size=512m']; },
    c => { c.services.worker.tmpfs[1] = '/tmp/trivy:rw,noexec,nosuid,uid=65532,gid=65532,size=512m'; },
    c => { c.services.worker.tmpfs[0] = '/tmp:rw,noexec,nosuid,size=16m'; },
    c => { c.services.worker.tmpfs[1] = c.services.worker.tmpfs[1].replace('noexec,', ''); },
    c => { c.services.worker.tmpfs.push('/host:rw,size=1g'); },
    c => { c.services.worker.tmpfs.push(c.services.worker.tmpfs[1]); },
    c => { c.services.api.command = 'node --import tsx src/oci/public-image.main.ts'; },
    c => { c.services.worker.command.push('--unsafe'); },
    c => { c.services.web.command = ['sh', '-c', 'foreign']; },
    c => { c.services.egress.command = ['sh', '-c', 'foreign']; },
    c => { c.services.worker.entrypoint = ['sh', '-c']; },
    c => { c.services.worker.environment.PUBLIC_IMAGES = 'true'; },
    c => { c.services.api.environment.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS = 'false'; },
    c => { c.services.api.environment.SCAN_JWT_SECRET = FIXTURE_SECRET; },
    c => { c.services.api.ports = [{ host_ip: '0.0.0.0', published: '3001', target: 3001, protocol: 'tcp' }]; },
    c => { c.services['auth-volume-init'].cap_add = ['SYS_ADMIN']; },
    c => { c.services['scan-volume-init'].mem_limit = PUBLIC_IMAGE_MEMORY; },
    c => { c.services.worker.user = '0:0'; },
    c => { c.services.worker.read_only = false; },
    c => { c.services.worker.cap_add = ['SYS_ADMIN']; },
    c => { c.services.worker.security_opt = ['seccomp:unconfined']; },
    c => { c.services.worker.deploy = { resources: { limits: { memory: 1073741824 } } }; },
    c => { c.services.worker.cpu_quota = -1; },
    c => { c.services.worker.mem_reservation = PUBLIC_IMAGE_MEMORY; },
    c => { c.services.worker.oom_kill_disable = true; },
    c => { c.services.worker.volumes[0].source = 'old_reports'; },
    c => { c.services.api.volumes[0].source = 'old_accounts'; },
    c => { c.services.worker.volumes.push({ type: 'bind', source: '/private', target: '/tmp/trivy' }); },
  ];
  for (const cve of [null, publicCve()]) for (const change of mutations) {
    const config = publicImageFixture(cve); change(config);
    assert.throws(() => validateConfig(config, ROOT, cve, 'public-images'));
  }
  for (const change of [
    c => { c.services.worker.volumes.find(m => m.target === '/tmp/trivy/db').read_only = false; },
    c => { c.services.api.volumes.find(m => m.target === '/opt/local-db-trust/public.pem').source = '/private/key'; },
    c => { c.services.worker.environment.SCAN_VULN_ARTIFACT_SHA256 = 'f'.repeat(64); },
  ]) {
    const cve = publicCve(), config = publicImageFixture(cve); change(config);
    assert.throws(() => validateConfig(config, ROOT, cve, 'public-images'));
  }
  const cve = publicCve();
  assert.throws(() => validateConfig(publicImageFixture(cve), ROOT, null, 'public-images'));
  assert.throws(() => validateConfig(publicImageFixture(), ROOT, cve, 'public-images'));
  assert.throws(() => validateConfig(publicImageFixture(cve), ROOT, { ...cve, releaseHostDir: '/foreign' }, 'public-images'));
});

test('offline public CVE metadata cannot select private, parent, malformed or extra paths/pins', () => {
  assert.equal(publicImageCveConfig(ROOT, null), null);
  for (const value of [undefined, false, {}, { ...publicCveMetadata, release: '../private' },
    { ...publicCveMetadata, release: 'db-releases/a/../../private' },
    { ...publicCveMetadata, release: '/absolute' }, { ...publicCveMetadata, extra: 'private' },
    { ...publicCveMetadata, publicKeySha256: 'bad' }, { ...publicCveMetadata, version: 2 },
    { ...publicCveMetadata, manifestDigest: 'a'.repeat(64) }]) {
    assert.throws(() => publicImageCveConfig(ROOT, value));
  }
});

test('public plan and static validation never access live state, Docker or JWT; output is not activation', async () => {
  const root = '/nonexistent/public-profile-planning-root', log = [];
  const options = { root, log: text => log.push(text),
    run: () => assert.fail('no Docker'), getSecret: () => assert.fail('no JWT') };
  for (const argv of [['plan', '--public-images'], ['plan', '--public-images', '--cve']]) {
    const plan = await localStand(argv, options);
    assert.equal(plan.activation, 'blocked'); assert.equal(plan.cve, argv.includes('--cve'));
    assert(plan.composeFiles.at(-1).endsWith('compose.local.public-images.yaml'));
    assert(plan.requiredBeforeActivation.some(s => s.includes('backup')));
  }
  for (const cve of [null, publicCve()]) {
    const result = await localStand(['validate', '--public-images'], { ...options, root: ROOT,
      readPublicConfig: () => JSON.stringify({ config: publicImageFixture(cve), cve: cve ? publicCveMetadata : null }) });
    assert.deepEqual(result, { profile: 'public-images', validation: 'static-only', activation: 'blocked' });
  }
  assert(!fs.existsSync(root));
  assert(!log.join('\n').includes(FIXTURE_SECRET));
});

test('public activation and unsupported lifecycle refuse before filesystem/Docker even with acknowledgement', async () => {
  const root = '/nonexistent/public-profile-blocked-root';
  for (const argv of [['up', '--public-images'], ['up', '--build', '--public-images'],
    ['up', '--public-images', '--ack-reviewed-rollout'], ['status', '--public-images'], ['stop', '--public-images']]) {
    await assert.rejects(localStand(argv, { root, run: () => assert.fail('no Docker'),
      getSecret: () => assert.fail('no JWT') }), /activation BLOCKED.*drained writers.*backup/);
  }
  for (const argv of [['plan'], ['plan', '--public-images', '--build'], ['plan', '--public-images', '--cve', '--cve'],
    ['validate', '--public-images', '--cve'], ['validate', '--public-images', '--ack-reviewed-rollout']]) {
    await assert.rejects(localStand(argv, { root, readPublicConfig: () => assert.fail('no input read'),
      run: () => assert.fail('no Docker') }), /Usage:/);
  }
  assert(!fs.existsSync(root));
});

test('static validation rejects missing/malicious input without echoing public fixture contents', async () => {
  for (const value of ['CANARY-not-json', '{}', JSON.stringify({ config: publicImageFixture(), cve: null, ack: true }),
    JSON.stringify({ config: publicImageFixture() }), JSON.stringify({ config: fixtureConfig(), cve: null })]) {
    const output = [];
    await assert.rejects(localStand(['validate', '--public-images'], { root: ROOT,
      readPublicConfig: () => value, log: text => output.push(text), run: () => assert.fail('no Docker') }));
    assert.equal(output.length, 0);
  }
});

test('shared inventory is default-closed for public/mixed commands and broad resources, including refresh callers', async () => {
  for (const name of ['api', 'worker']) for (const command of [PUBLIC_IMAGE_COMMANDS[name], ['node', 'foreign.ts'], undefined]) {
    const item = container(name); item.Config.Cmd = command;
    assert.throws(() => validateDefaultInspectedProfile(item, name), /profile\/command/);
    const docker = fakeDocker({ containers: [item] });
    await assert.rejects(inspectNamespace(docker.run, { root: ROOT, env: {} }), /profile\/command/);
    assert(docker.calls.every(call => !call.args.includes('up') && !call.args.includes('stop')));
  }
  for (const change of [
    h => { h.Memory = PUBLIC_IMAGE_MEMORY; h.MemorySwap = PUBLIC_IMAGE_MEMORY; },
    h => { h.Memory = PUBLIC_IMAGE_MEMORY; }, h => { h.MemorySwap = PUBLIC_IMAGE_MEMORY; },
    h => { h.Memory = 2 * PUBLIC_IMAGE_MEMORY; },
  ]) {
    const item = container('worker'); change(item.HostConfig);
    assert.throws(() => validateDefaultInspectedProfile(item, 'worker'), /resource profile/);
  }
});

test('legacy up/status/stop cannot silently adopt an externally deployed public namespace', async t => {
  const root = tempRoot(t);
  for (const name of ['api', 'worker']) for (const command of ['up', 'status', 'stop']) {
    const item = container(name); item.Config.Cmd = PUBLIC_IMAGE_COMMANDS[name];
    const docker = fakeDocker({ config: fixtureConfig(root), containers: [item] });
    await assert.rejects(localStand([command], { root, run: docker.run,
      getSecret: () => assert.fail('no JWT'), log: () => {} }), /profile\/command/);
    assert(!docker.calls.some(call => call.args.includes('up') || call.args.includes('stop')));
    assert(!fs.existsSync(join(root, '.local-stand/scan-jwt')));
    assert(!fs.existsSync(join(root, '.local-stand/.stand-operation.lock')));
  }
});

test('new overlay mounts only fixed public PEM/release and pins CVE without changing CPU/PIDs/auth', () => {
  const text = fs.readFileSync(join(ROOT, 'server/deploy/compose.local.cve.yaml'), 'utf8');
  const substitutions = [...new Set([...text.matchAll(/\$\{([^}:]+)[^}]*\}/g)].map(match => match[1]))].sort();
  assert.deepEqual(substitutions, ['LOCAL_CVE_TRUST_SHA256', 'SCAN_VULN_ARTIFACT_SHA256', 'SCAN_VULN_MANIFEST_DIGEST', 'SCAN_VULN_RELEASE_HOST_DIR']);
  assert.equal((text.match(/source: ..\/..\/.local-stand\/trust\/db-signing-key.pub.pem/g) ?? []).length, 2);
  assert.equal((text.match(/target: \/opt\/local-db-trust\/public.pem/g) ?? []).length, 2);
  assert.equal((text.match(/read_only: true/g) ?? []).length, 5);
  assert.equal((text.match(/create_host_path: false/g) ?? []).length, 5);
  assert(text.includes('tmpfs: !override'));
  assert(text.includes('mem_limit: 1g')); assert(text.includes('memswap_limit: 1g'));
  assert(!/\.local-auth|db-signing-key\.pem|AUTH_|JWT|env_file:|cpus:|pids_limit:/.test(text));
});
