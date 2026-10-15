import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { PROJECT, LABEL, ORIGIN, composeArguments, dockerEnvironment, expectedEnvironment,
  validateConfig, inspectNamespace, checkIgnores, loadSecret, localStand } from './local-stand.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const FIXTURE_SECRET = 'ab'.repeat(48);
const SERVICES = ['auth-volume-init', 'scan-volume-init', 'egress', 'worker', 'api', 'web'];
const VOLUMES = ['auth_accounts', 'scan_ledger'];
const NETWORKS = ['auth_internal', 'scan_internal', 'registry_uplink', 'web_edge'];
const ownership = { [LABEL]: 'v1', 'com.docker.compose.project': PROJECT };
const links = { 'auth-volume-init': [], 'scan-volume-init': [], egress: ['scan_internal', 'registry_uplink'],
  worker: ['scan_internal'], api: ['auth_internal', 'scan_internal'], web: ['auth_internal', 'web_edge'] };

function fixtureConfig(root = ROOT) {
  const config = { name: PROJECT, services: {}, volumes: {}, networks: {} };
  const mounts = { 'auth-volume-init': [['auth_accounts', '/data']], 'scan-volume-init': [['scan_ledger', '/data']],
    worker: [['scan_ledger', '/data']], api: [['auth_accounts', '/auth'], ['scan_ledger', '/data']], egress: [], web: [] };
  const files = { egress: 'gateway/Dockerfile', api: 'api.Dockerfile', worker: 'worker.Dockerfile', web: 'stand.Dockerfile' };
  for (const name of SERVICES) {
    const service = { labels: { [LABEL]: 'v1' }, image: files[name] ? `${PROJECT}-${name}:local` : 'busybox:1.37.0',
      environment: expectedEnvironment(name), volumes: mounts[name].map(([source, target]) => ({ type: 'volume', source, target })),
      networks: Object.fromEntries(links[name].map(key => [key, null])) };
    if (files[name]) service.build = { context: root, dockerfile: `server/deploy/${files[name]}`, labels: { [LABEL]: 'v1' } };
    else { delete service.networks; service.network_mode = 'none'; service.command = ['chown', '65532:65532', '/data']; }
    config.services[name] = service;
  }
  config.services.api.command = ['node', '--import', 'tsx', 'src/oci/nginx-local.main.ts'];
  Object.assign(config.services.worker, { command: ['node', '--import', 'tsx', 'src/worker/nginx-local-worker.main.ts'],
    mem_limit: '1073741824', memswap_limit: '1073741824', cpus: 1, pids_limit: 128 });
  config.services.web.ports = [{ host_ip: '127.0.0.1', target: 8080, published: '8080', protocol: 'tcp' }];
  for (const key of VOLUMES) config.volumes[key] = { name: `${PROJECT}_${key}`, labels: { [LABEL]: 'v1' } };
  for (const key of NETWORKS) config.networks[key] = { name: `${PROJECT}_${key}`, internal: key.endsWith('_internal'), labels: { [LABEL]: 'v1' } };
  return config;
}
function tempRoot(t) {
  const root = fs.mkdtempSync(join(tmpdir(), 'dip-local-launcher-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true })); // Test-owned temporary files only.
  for (const file of ['.gitignore', '.dockerignore']) fs.writeFileSync(join(root, file), '.local-stand/\n');
  return root;
}
function container(service = 'api', extra = {}) {
  return { Id: `fixture-${service}`, Name: `/${PROJECT}-${service}-1`,
    Config: { Labels: { ...ownership, 'com.docker.compose.service': service },
      Image: service.endsWith('volume-init') ? 'busybox:1.37.0' : `${PROJECT}-${service}:local` },
    Mounts: [], NetworkSettings: { Networks: Object.fromEntries((links[service].length ? links[service].map(n => `${PROJECT}_${n}`) : ['none']).map(n => [n, {}])) },
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

test('status and stop do not read/create signing secret and stop only inspected running IDs', async () => {
  for (const command of ['status', 'stop']) {
    const docker = fakeDocker({ containers: [container(), container('auth-volume-init', { State: { Running: false, Status: 'exited' } })] });
    const output = [];
    await localStand([command], { run: docker.run, log: line => output.push(line), getSecret: () => assert.fail('secret must not be touched') });
    const stops = docker.calls.filter(call => call.args[1] === 'stop');
    assert.equal(stops.length, command === 'stop' ? 1 : 0);
    if (command === 'stop') assert.deepEqual(stops[0].args, ['container', 'stop', '--time', '30', 'fixture-api']);
    assert(!docker.calls.some(call => call.args.includes('down') || call.args.includes('rm') || call.args.includes('prune') || call.args.includes('up')));
    assert(output.length > 0);
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
