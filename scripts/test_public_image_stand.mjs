import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { loadCveActivation, validateCveRelease } from './local-stand.mjs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { PROJECT, LABEL, IMAGE_LABEL, STATE, CONFIG_SECRET, ORIGIN, expectedConfig, validateConfig, expectedEnvironment,
  cveOverlay, composeArguments, checkIgnores, loadSecret, inspectNamespace, validateImage, publicImageStand } from './public-image-stand.mjs';
import { publicImageCveConfig } from './public-image-stand-profile.mjs';
import * as isolated from './public-image-stand.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const SECRET = 'ab'.repeat(48);
const META = { version: 1, release: 'db-releases/fixture', manifestDigest: `sha256:${'a'.repeat(64)}`,
  artifactSha256: 'b'.repeat(64), publicKeySha256: 'c'.repeat(64) };
const ownership = { [LABEL]: 'v1', 'com.docker.compose.project': PROJECT };
const MASKED = ['/proc/asound', '/proc/acpi', '/proc/interrupts', '/proc/kcore', '/proc/keys', '/proc/latency_stats',
  '/proc/timer_list', '/proc/timer_stats', '/proc/sched_debug', '/proc/scsi', '/sys/firmware', '/sys/devices/virtual/powercap'];
const READONLY = ['/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger'];
function fixture(t, enabled = false, publicMeta = META) {
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'public-image-isolated-test-')));
  t.after(() => {
    const writable = path => {
      if (!fs.lstatSync(path).isDirectory()) return;
      fs.chmodSync(path, 0o700);
      for (const name of fs.readdirSync(path)) writable(join(path, name));
    };
    writable(root); fs.rmSync(root, { recursive: true, force: true });
  });
  for (const file of ['.gitignore', '.dockerignore']) fs.writeFileSync(join(root, file), `${STATE}/\n`);
  const cve = enabled ? publicImageCveConfig(root, publicMeta) : null;
  const f = { root, cve, calls: [], logs: [], containers: [], volumes: [], networks: [], tags: [], images: new Map(),
    activationReads: 0, verifications: 0, failUp: false, failStop: false, postDrift: false };
  f.config = expectedConfig(root, cve);
  f.imageFor = (name, index) => {
    const spec = f.config.services[name], init = name.endsWith('volume-init');
    const path = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
    const baseEnv = init ? [`PATH=${path}`] : ['api', 'worker'].includes(name) ?
      [`PATH=${path}`, 'NODE_VERSION=24.11.1', 'YARN_VERSION=1.22.22'] : name === 'egress' ?
        [`PATH=/usr/local/bin:${path}`, 'PYTHON_VERSION=3.13.7', `GPG_KEY=${'A'.repeat(40)}`, `PYTHON_SHA256=${'a'.repeat(64)}`] :
        [`PATH=${path}`, 'NGINX_VERSION=1.27.5', 'NJS_VERSION=0.8.10', 'NJS_RELEASE=1', 'PKG_RELEASE=1', 'DYNPKG_RELEASE=1'];
    const image = { Id: `sha256:${(init ? 'e' : (index + 7).toString(16)).repeat(64)}`, Os: 'linux', RepoTags: [spec.image],
      Config: { Env: baseEnv, Labels: init ? {} : { [LABEL]: 'v1', [IMAGE_LABEL]: PROJECT },
        Entrypoint: ['api', 'worker'].includes(name) ? ['docker-entrypoint.sh'] : name === 'web' ? ['/docker-entrypoint.sh'] : null,
        User: init ? '' : spec.user, WorkingDir: ['api', 'worker'].includes(name) ? '/app/server/api' : name === 'egress' ? '/opt/gateway' : name === 'web' ? '/' : '',
                ...(['api', 'worker', 'egress'].includes(name) ? { ArgsEscaped: true } : {}),
        Cmd: init ? ['sh'] : name === 'api' ? ['node', '--import', 'tsx', 'src/main.ts'] :
          name === 'worker' ? ['node', '--import', 'tsx', 'src/worker/worker.main.ts'] : spec.command,
        ...(name === 'web' ? { ExposedPorts: { '80/tcp': {}, '8080/tcp': {} }, StopSignal: 'SIGQUIT' } : {}) } };
    f.images.set(image.Id, image); f.images.set(spec.image, image); return image;
  };
  f.populate = (secret = SECRET, pins = null) => {
    f.containers = Object.entries(f.config.services).map(([name, spec], index) => {
      const image = pins ? f.images.get(pins[name].image) : f.imageFor(name, index), init = name.endsWith('volume-init');
      const connections = Object.keys(spec.networks ?? {}).map(n => `${PROJECT}_${n}`);
      const ports = name === 'web' ? { '8080/tcp': [{ HostIp: '127.0.0.1', HostPort: '8081' }] } : {};
      return { Id: (index + 1).toString(16).repeat(64), Name: `/${PROJECT}-${name}-1`, Image: image.Id,
        Config: { Labels: { ...ownership, 'com.docker.compose.service': name }, Image: pins ? pins[name].image : spec.image, Cmd: spec.command ?? image.Config.Cmd,
          Entrypoint: image.Config.Entrypoint, User: spec.user, WorkingDir: image.Config.WorkingDir, ArgsEscaped: image.Config.ArgsEscaped,
          Env: Object.entries({ ...Object.fromEntries(image.Config.Env.map(v => { const i = v.indexOf('='); return [v.slice(0, i), v.slice(i + 1)]; })), ...expectedEnvironment(name, cve, secret) }).map(([k, v]) => `${k}=${v}`),
          ExposedPorts: image.Config.ExposedPorts ?? {}, StopSignal: image.Config.StopSignal ?? '',
          ...(spec.healthcheck ? { Healthcheck: { Test: spec.healthcheck.test, Interval: 5e9, Timeout: 3e9, Retries: 12 } } : {}) },
        HostConfig: { Privileged: false, AutoRemove: false, ReadonlyRootfs: true, CapDrop: ['ALL'], CapAdd: spec.cap_add ?? [],
          SecurityOpt: spec.security_opt, NetworkMode: connections[0] ?? 'none', PortBindings: ports, PublishAllPorts: false,
          Tmpfs: Object.fromEntries((spec.tmpfs ?? []).map(v => { const i = v.indexOf(':'); return [v.slice(0, i), v.slice(i + 1)]; })),
          MaskedPaths: [...MASKED], ReadonlyPaths: [...READONLY], Memory: Number(spec.mem_limit), MemorySwap: Number(spec.memswap_limit),
          NanoCpus: spec.cpus * 1e9, PidsLimit: spec.pids_limit, MemoryReservation: 0, CpuShares: 0, CpuPeriod: 0, CpuQuota: 0,
          CpuRealtimePeriod: 0, CpuRealtimeRuntime: 0, CpusetCpus: '', CpusetMems: '', OomScoreAdj: 0, ShmSize: 67108864,
          IpcMode: 'private', PidMode: '', UTSMode: '', UsernsMode: '', CgroupParent: '', CgroupnsMode: 'private', Runtime: 'runc',
          MemorySwappiness: null, OomKillDisable: null, RestartPolicy: { Name: spec.restart, MaximumRetryCount: 0 },
          ConsoleSize: [0, 0], LogConfig: { Type: 'json-file', Config: {} },
          Mounts: (spec.volumes ?? []).map(m => ({ Type: m.type, Source: m.type === 'volume' ? `${PROJECT}_${m.source}` : m.source,
            Target: m.target, ReadOnly: Boolean(m.read_only), ...(m.type === 'bind' ? { BindOptions: {} } : { VolumeOptions: {} }) })) },
        Mounts: (spec.volumes ?? []).map(m => ({ Type: m.type, Destination: m.target, RW: !m.read_only,
          ...(m.type === 'volume' ? { Name: `${PROJECT}_${m.source}` } : { Source: m.source, Propagation: 'rprivate' }) })),
        NetworkSettings: { Networks: Object.fromEntries((connections.length ? connections : ['none']).map(n => [n, {}])),
                  Ports: name === 'web' ? { '80/tcp': null, ...ports } : ports },
        State: { Running: !init, Status: init ? 'exited' : 'running', ExitCode: 0 } };
    });
    f.volumes = Object.values(f.config.volumes).map(v => ({ Name: v.name, Driver: 'local', Labels: ownership, Options: null }));
    f.networks = Object.values(f.config.networks).map(n => ({ Name: n.name, Driver: 'bridge', Labels: ownership, Internal: Boolean(n.internal),
      Containers: Object.fromEntries(f.containers.filter(c => c.NetworkSettings.Networks[n.name]).map(c => [c.Id, {}])) }));
    f.tags = ['egress', 'worker', 'api', 'web'].map(n => `${PROJECT}-${n}:local`);
  };
  f.run = async (args, options) => {
    f.calls.push({ args, options });
    assert.equal(options.root, root);
    assert(!args.some(a => /dip-local-full|dip-auth-stand|\.local-auth|scan-jwt/.test(a)), 'never address legacy resources or a JWT in argv');
    if (args[0] === 'context') { assert.equal(args[1], 'inspect'); return JSON.stringify(f.endpoint ?? 'unix:///fixture/docker.sock'); }
    if (args[0] === 'compose') {
      assert.equal(args[args.indexOf('-p') + 1], PROJECT);
      assert.equal(args[args.indexOf('--env-file') + 1], '/dev/null');
      if (args.includes('config')) {
        const rendered = structuredClone(f.rendered ?? f.config);
        if (args.includes(join(f.state, 'compose.images.json'))) {
          const pins = JSON.parse(fs.readFileSync(join(f.state, 'compose.images.json'), 'utf8'));
          for (const [name, spec] of Object.entries(pins.services)) rendered.services[name].image = spec.image;
        }
        return JSON.stringify(rendered);
      }
      if (args.includes('build')) {
        assert.equal(options.env.SCAN_JWT_SECRET, CONFIG_SECRET);
        assert.equal(options.timeout, 600000);
        for (const [index, name] of Object.keys(f.config.services).entries()) if (!name.endsWith('volume-init')) f.imageFor(name, index);
        f.tags = ['egress', 'worker', 'api', 'web'].map(name => `${PROJECT}-${name}:local`);
        f.afterBuild?.(); return '';
      }
      assert(args.includes('up')); assert.equal(options.timeout, 600000);
      assert(args.includes('--no-build')); assert(!args.includes('--build'));
      assert.equal(args[args.indexOf('--pull') + 1], 'never');
      if (f.failUp) throw Error('PRIVATE-SYNTHETIC-ERROR');
      const pins = JSON.parse(fs.readFileSync(join(f.state, 'compose.images.json'), 'utf8')).services;
      f.populate(options.env.SCAN_JWT_SECRET, pins);
      if (f.postDrift) f.containers.find(c => c.Config.Labels['com.docker.compose.service'] === 'worker').HostConfig.Memory = 1073741824;
      return '';
    }
    if (args[0] === 'image') {
      if (args[1] === 'pull') { assert.equal(args[2], 'busybox:1.37.0'); assert(!options.env.SCAN_JWT_SECRET); f.imageFor('auth-volume-init', 0); return ''; }
      if (args[1] === 'ls') return ['dip-local-full-api:local', 'dip-auth-stand-worker:local', ...f.tags].join('\n');
      assert(f.images.has(args[2]), 'only fixture-owned images inspected'); return JSON.stringify([f.images.get(args[2])]);
    }
    if (args[0] === 'container' && args[1] === 'stop') {
      assert.equal(options.timeout, 90000);
      if (f.failStop) throw Error('PRIVATE-SYNTHETIC-ERROR');
      for (const c of f.containers.filter(c => args.includes(c.Id))) { c.State.Running = false; c.State.Status = 'exited'; }
      return '';
    }
    const items = f[`${args[0]}s`]; assert(items);
    if (args[1] === 'ls') {
      if (args.includes('--filter')) {
        assert(args.includes('--no-trunc'));
        const filter = args[args.indexOf('--filter') + 1];
        if (filter.startsWith('ancestor=')) return f.imageUsers ?? f.containers.filter(c => c.Image === filter.slice('ancestor='.length)).map(c => c.Id).join('\n');
        const volume = filter.slice('volume='.length);
        return f.foreignWriter ?? f.containers.filter(c => c.Mounts.some(m => m.Name === volume)).map(c => c.Id).join('\n');
      }
      return [`dip-local-full-${args[0]}-1\tdip-local-full`, ...items.map(c =>
        `${c.Name.replace(/^\//, '')}\t${(c.Config?.Labels ?? c.Labels)['com.docker.compose.project']}`)].join('\n');
    }
    assert.equal(args[1], 'inspect');
    const item = items.find(c => c.Name.replace(/^\//, '') === args[2]); assert(item, 'only fixture namespace inspected');
    return JSON.stringify([item]);
  };
  f.options = { root, run: f.run, random: () => Buffer.from(SECRET, 'hex'), log: s => f.logs.push(s),
    loadActivation: () => { f.activationReads++; return cve; }, verifyRelease: (_root, value) => { f.verifications++; assert.deepEqual(value, publicMeta); return cve; },
    ambient: { PATH: '/fixture/bin', HOME: '/fixture/home', SCAN_JWT_SECRET: 'ambient-secret', SCAN_VULN_ENABLED: 'true',
      COMPOSE_FILE: 'foreign', COMPOSE_PROJECT_NAME: 'dip-local-full', NODE_OPTIONS: 'foreign', HTTP_PROXY: 'foreign', OPENROUTER_API_KEY: 'private' } };
  f.launch = (argv = ['up', '--build', '--isolated'], extra = {}) => publicImageStand(argv, { ...f.options, ...extra });
  f.state = join(root, STATE); f.lock = join(f.state, '.operation.lock'); return f;
}
function seedState(f, cve = f.cve) {
  fs.mkdirSync(f.state, { mode: 0o700 });
  fs.writeFileSync(join(f.state, 'profile.json'), JSON.stringify({ version: 1, project: PROJECT, cve: cve ? META : null }), { mode: 0o600 });
  fs.writeFileSync(join(f.state, 'scan-jwt'), SECRET, { mode: 0o600 });
}

for (const enabled of [false, true]) test(`isolated up build, restart, status and stop retain own state (CVE ${enabled})`, async t => {
  const f = fixture(t, enabled);
  await f.launch();
  const jwt = fs.readFileSync(join(f.state, 'scan-jwt'), 'utf8'), profile = fs.readFileSync(join(f.state, 'profile.json'), 'utf8');
  assert.equal(jwt, SECRET); assert.equal(fs.statSync(f.state).mode & 0o777, 0o700);
  assert.equal(fs.statSync(join(f.state, 'scan-jwt')).mode & 0o777, 0o600);
  assert(!fs.existsSync(f.lock)); assert.equal(f.activationReads, 1);
  await f.launch(['up'], { loadActivation: () => assert.fail('never re-read changed current activation') });
  assert.equal(fs.readFileSync(join(f.state, 'scan-jwt'), 'utf8'), jwt);
  assert.equal(fs.readFileSync(join(f.state, 'profile.json'), 'utf8'), profile);
  fs.chmodSync(join(f.state, 'scan-jwt'), 0o000);
  const beforeStatus = f.calls.length;
  await f.launch(['status']); await f.launch(['stop']);
  assert(f.calls.slice(beforeStatus).every(c => !c.args.includes('up') && !c.args.includes('config')));
  assert(f.containers.every(c => !c.State.Running)); assert(!fs.existsSync(f.lock));
  fs.chmodSync(join(f.state, 'scan-jwt'), 0o600);
  await f.launch(['up', '--build']);
  assert.equal(fs.readFileSync(join(f.state, 'scan-jwt'), 'utf8'), jwt);
  for (const call of f.calls) {
    assert(!call.args.includes(jwt));
    assert(!['OPENROUTER_API_KEY', 'NODE_OPTIONS', 'COMPOSE_FILE', 'COMPOSE_PROJECT_NAME', 'HTTP_PROXY', 'SCAN_VULN_ENABLED'].some(k => k in call.options.env));
    if (call.args.includes('up')) assert.equal(call.options.env.SCAN_JWT_SECRET, SECRET);
    else if (call.args.includes('config') || call.args.includes('build')) assert.equal(call.options.env.SCAN_JWT_SECRET, CONFIG_SECRET);
    else assert(!('SCAN_JWT_SECRET' in call.options.env));
  }
  assert(!f.logs.join('\n').includes(jwt)); assert(f.logs.join('\n').includes(ORIGIN));
  assert.equal(f.activationReads, 1);
  if (enabled) {
    assert.equal(f.verifications, 3);
    const overlay = JSON.parse(fs.readFileSync(join(f.state, 'compose.cve.json'), 'utf8'));
    assert.deepEqual(overlay, cveOverlay(f.cve));
    assert(!JSON.stringify(overlay).includes('PRIVATE KEY'));
    assert(overlay.services.worker.volumes.every(m => m.read_only && m.bind.create_host_path === false));
    assert(!('tmpfs' in overlay.services.worker)); assert(!('mem_limit' in overlay.services.worker));
  } else assert(!fs.existsSync(join(f.state, 'compose.cve.json')));
});

test('Compose defaults normalize only null entrypoints and empty network IPAM', () => {
  const config = expectedConfig(ROOT);
  for (const service of Object.values(config.services)) service.entrypoint = null;
  for (const network of Object.values(config.networks)) network.ipam = {};
  assert.doesNotThrow(() => validateConfig(config, ROOT));
  const entrypoint = structuredClone(config);
  entrypoint.services.api.entrypoint = [];
  assert.throws(() => validateConfig(entrypoint, ROOT));
  const network = structuredClone(config);
  network.networks.scan_internal.ipam = { config: [{ subnet: '10.9.0.0/16' }] };
  assert.throws(() => validateConfig(network, ROOT));
});

test('standalone JSON-compatible YAML independently matches the fixed normative model', () => {
  const source = JSON.parse(fs.readFileSync(join(ROOT, 'server/deploy/compose.public-images.yaml'), 'utf8'));
  source.services.api.environment.SCAN_JWT_SECRET = CONFIG_SECRET;
  for (const spec of Object.values(source.services)) if (spec.build) spec.build.context = ROOT;
  validateConfig(source, ROOT);
  assert.deepEqual(composeArguments(ROOT, ['up', '--build', '-d']), ['compose', '--env-file', '/dev/null', '-p', PROJECT,
    '-f', join(ROOT, 'server/deploy/compose.public-images.yaml'), 'up', '--build', '-d']);
  assert(!JSON.stringify(source).includes('dip-local-full'));
  assert(!JSON.stringify(source).includes('.local-auth'));
  assert.equal(source.services.worker.mem_limit, '4294967296');
  assert.equal(source.services.worker.memswap_limit, source.services.worker.mem_limit);
});

test('strict config rejects wrong profile, resources, admission, mounts, ports and unexpected authorities', () => {
  for (const enabled of [false, true]) {
    const cve = enabled ? publicImageCveConfig(ROOT, META) : null;
    const changes = [
      c => { c.name = 'dip-local-full'; }, c => { c.services.api.command[3] = 'src/oci/nginx-local.main.ts'; },
      c => { c.services.worker.command[3] = 'src/worker/nginx-local-worker.main.ts'; },
      c => { c.services.worker.mem_limit = '1073741824'; }, c => { c.services.worker.memswap_limit = '8589934592'; },
      c => { c.services.worker.cpus = 2; }, c => { c.services.worker.pids_limit = -1; },
      c => { c.services.worker.tmpfs[1] = '/tmp/trivy:size=512m'; }, c => { c.services.worker.tmpfs.push('/host:rw'); },
      c => { c.services.api.environment.PUBLIC_IMAGES = 'true'; }, c => { c.services.api.environment.AUTH_ORIGIN = 'http://127.0.0.1:8080'; },
      c => { c.services.api.environment.SCAN_JWT_SECRET = SECRET; }, c => { c.services.api.env_file = '/private/env'; },
      c => { c.services.worker.volumes[0].source = 'dip-local-full_scan_ledger'; },
      c => { c.services.worker.volumes.push({ type: 'bind', source: '/var/run/docker.sock', target: '/var/run/docker.sock' }); },
      c => { c.services.worker.deploy = { resources: { limits: { memory: '1g' } } }; },
      c => { c.services.worker.entrypoint = ['sh']; }, c => { c.services.worker.privileged = true; },
      c => { c.services.web.ports[0].host_ip = '0.0.0.0'; }, c => { c.services.web.ports[0].published = '8080'; },
      c => { c.volumes.scan_ledger.external = true; }, c => { c.networks.scan_internal.name = 'old_shared'; },
      c => { c.services['auth-volume-init'].cap_add.push('SYS_ADMIN'); }, c => { c.services.api.build.args = { SECRET: 'unsafe' }; },
    ];
    for (const change of changes) { const config = expectedConfig(ROOT, cve); change(config); assert.throws(() => validateConfig(config, ROOT, cve)); }
    const config = expectedConfig(ROOT, cve);
    for (const spec of Object.values(config.services)) {
      for (const link of Object.values(spec.depends_on ?? {})) { link.required = true; link.restart = false; }
      for (const key of Object.keys(spec.networks ?? {})) spec.networks[key] = { priority: 0 };
      for (const port of spec.ports ?? []) port.mode = 'ingress';
      for (const m of spec.volumes ?? []) {
        if (m.bind) delete m.bind.create_host_path;
        if (m.type === 'volume') { m.volume = {}; m.read_only = false; }
      }
    }
    validateConfig(config, ROOT, cve);
  }
});

test('ignore guards and first-up opt-in precede Docker, secret/state creation or public activation reads', async t => {
  const f = fixture(t);
  for (const file of ['.gitignore', '.dockerignore']) {
    fs.writeFileSync(join(f.root, file), '# coordinator has not protected state\n');
    await assert.rejects(f.launch(), /append .local-public-images\/ to BOTH/);
    assert.equal(f.calls.length, 0); assert(!fs.existsSync(f.state));
    fs.writeFileSync(join(f.root, file), `${STATE}/\n!.local-public-images/scan-jwt\n`);
    assert.throws(() => checkIgnores(f.root));
    fs.writeFileSync(join(f.root, file), `${STATE}/\n`);
  }
  await assert.rejects(f.launch(['up', '--build']), /First up requires --isolated/);
  assert(!fs.existsSync(f.state)); assert.equal(f.activationReads, 0);
  for (const args of [[], ['down'], ['up', '--env-file', 'private'], ['up', '--isolated', '--isolated'], ['stop', '--isolated'], ['status', '--build']]) {
    await assert.rejects(f.launch(args), /Usage:/);
  }
  assert.equal(f.calls.length, 0); assert(!fs.existsSync(f.state));
});

test('remote TCP/SSH endpoints refuse before credentials or lifecycle commands', async t => {
  for (const endpoint of ['tcp://remote:2375', 'ssh://remote', 'unix:///socket\nforged', 'unix:///socket\n']) {
    const f = fixture(t); f.endpoint = endpoint;
    await assert.rejects(f.launch(), /local unix:\/\/ Docker endpoint/);
    assert(!f.calls.some(c => c.args.includes('up'))); assert(!fs.existsSync(join(f.state, 'scan-jwt')));
    assert(!fs.existsSync(f.lock));
  }
  const f = fixture(t);
  await assert.rejects(f.launch(undefined, { ambient: { DOCKER_HOST: 'tcp://remote:2375' } }), /local unix:\/\/ Docker endpoint/);
  assert.equal(f.calls.length, 0);
});

test('absent status and stop observe only namespace; no state, JWT, public activation or lock is provisioned', async t => {
  const f = fixture(t);
  await f.launch(['status']); await f.launch(['stop']);
  assert(!fs.existsSync(f.state)); assert.equal(f.activationReads, 0);
  assert(f.calls.every(c => !c.args.includes('up') && !c.args.includes('stop') && !c.args.includes('config')));
});

test('unowned/mixed resource collisions refuse adoption and never touch legacy resources', async t => {
  for (const kind of ['container', 'volume', 'network', 'image']) await t.test(kind, async t => {
    const f = fixture(t); f.populate();
    if (kind === 'container') f.containers[0].Config.Labels = {};
    if (kind === 'volume') f.volumes[0].Labels = {};
    if (kind === 'network') f.networks[0].Labels = {};
    if (kind === 'image') f.images.get(f.tags[0]).Config.Labels = {};
    await assert.rejects(f.launch());
    assert(!fs.existsSync(join(f.state, 'scan-jwt')));
    assert(!f.calls.some(c => c.args.includes('up') || c.args.includes('stop')));
    assert(!fs.existsSync(f.lock));
  });
  const f = fixture(t); f.populate();
  await assert.rejects(f.launch(), /Refusing to adopt/); // Even plausible owned resources need their own profile/JWT.
  assert(!fs.existsSync(join(f.state, 'profile.json')));
});

test('runtime inspection refuses drift before lifecycle mutation, including socket, private and foreign mounts', async t => {
  const changes = [
    f => { f.containers[3].Config.Cmd = ['node', '--import', 'tsx', 'src/worker/nginx-local-worker.main.ts']; },
    f => { f.containers[3].Config.Entrypoint = ['sh']; }, f => { f.containers[3].HostConfig.Memory = 1073741824; },
    f => { f.containers[3].HostConfig.MemorySwap = 8589934592; }, f => { f.containers[3].HostConfig.NanoCpus = 2e9; },
    f => { f.containers[3].HostConfig.PidsLimit = 0; }, f => { f.containers[3].HostConfig.Tmpfs['/tmp/trivy'] = 'exec,size=512m'; },
    f => { f.containers[3].HostConfig.Privileged = true; }, f => { f.containers[3].HostConfig.ReadonlyRootfs = false; },
    f => { f.containers[3].HostConfig.Binds = ['/var/run/docker.sock:/var/run/docker.sock']; },
    f => { f.containers[3].HostConfig.UnknownAuthority = 'host'; }, f => { f.containers[3].HostConfig.CapAdd = ['SYS_ADMIN']; },
    f => { f.containers[4].Config.Env.push('PUBLIC_IMAGES=true'); },
    f => { f.containers[5].HostConfig.PortBindings['8080/tcp'][0].HostIp = '0.0.0.0'; },
    f => { f.containers[3].Mounts[0].Name = 'dip-local-full_scan_ledger'; },
    f => { f.containers[3].NetworkSettings.Networks.old_shared = {}; },
    f => { f.networks[0].Containers['f'.repeat(64)] = {}; }, f => { f.foreignWriter = 'f'.repeat(64); },
    f => { f.networks[0].Options = { 'com.docker.network.bridge.name': 'foreign' }; },
    f => { f.containers[5].Config.Cmd = ['sh', '-c', 'foreign']; },
    f => { f.containers[3].Name = '/renamed-owned-collision'; },
    f => { f.containers[3].Mounts.find(m => m.Destination === '/tmp/trivy/db').RW = true; },
    f => { f.containers[3].HostConfig.Mounts.find(m => m.Target === '/opt/local-db-trust/public.pem').Source = '/private/key'; },
  ];
  for (const change of changes) {
    const f = fixture(t, true); seedState(f); f.populate(); change(f);
    await assert.rejects(f.launch(['up', '--build']));
    assert(!f.calls.some(c => c.args.includes('up') || c.args.includes('stop')));
    assert(!fs.existsSync(f.lock)); assert.equal(f.activationReads, 0);
  }
});

for (const command of ['up', 'stop']) test(`${command} failure retains sticky uncertainty marker; no retry/cleanup/secret rotation`, async t => {
  const f = fixture(t); seedState(f); f.populate();
  if (command === 'up') f.failUp = true; else f.failStop = true;
  await assert.rejects(f.launch(command === 'up' ? ['up', '--build'] : ['stop']), /uncertain\/HOLD/);
  const marker = join(f.lock, 'mutation.json'), bytes = fs.readFileSync(marker, 'utf8');
  assert.equal(JSON.parse(bytes).command, command); assert(!bytes.includes(SECRET));
  const calls = f.calls.length;
  await assert.rejects(f.launch(['up', '--build']), /locked\/HOLD/);
  await assert.rejects(f.launch(['stop']), /locked\/HOLD/);
  assert.equal(f.calls.length, calls); assert.equal(fs.readFileSync(marker, 'utf8'), bytes);
  await f.launch(['status']); assert(f.logs.some(s => s.includes('HOLD')));
  assert.equal(fs.readFileSync(join(f.state, 'scan-jwt'), 'utf8'), SECRET);
  assert(!f.logs.join('\n').includes('PRIVATE-SYNTHETIC-ERROR'));
});

test('acknowledged up followed by unsafe/incomplete postflight stays HOLD, never claims qualification', async t => {
  const f = fixture(t); f.postDrift = true;
  await assert.rejects(f.launch(), /uncertain\/HOLD/);
  assert(fs.existsSync(join(f.lock, 'mutation.json')));
  assert(!f.logs.some(s => s.includes('stand started')));
});

test('read-only preflight/config failure releases only own lock; no mutation or uncertainty marker', async t => {
  const f = fixture(t); f.rendered = expectedConfig(f.root); f.rendered.services.worker.mem_limit = '1073741824';
  await assert.rejects(f.launch(), /fixed qualification policy/);
  assert(!fs.existsSync(f.lock)); assert(!f.calls.some(c => c.args.includes('up')));
  assert.equal(fs.readFileSync(join(f.state, 'scan-jwt'), 'utf8'), SECRET);
  f.rendered = undefined;
  await f.launch(['up', '--build']); // The explicit first-launch acknowledgement and pin survived preflight failure.
  assert.equal(f.activationReads, 1);
});

test('profile state, pinned overlay and missing/unsafe JWT refuse replacement, refresh or key access', async t => {
  for (const change of ['missing-jwt', 'symlink-jwt', 'hardlink-jwt', 'wide-jwt', 'invalid-jwt', 'profile-extra', 'overlay-tamper']) await t.test(change, async t => {
    const f = fixture(t, true); seedState(f); f.populate();
    const jwt = join(f.state, 'scan-jwt');
    if (change === 'missing-jwt') fs.unlinkSync(jwt);
    if (change === 'symlink-jwt') { fs.unlinkSync(jwt); fs.symlinkSync('/must-not-open-private', jwt); }
    if (change === 'hardlink-jwt') fs.linkSync(jwt, join(f.state, 'alias'));
    if (change === 'wide-jwt') fs.chmodSync(jwt, 0o644);
    if (change === 'invalid-jwt') fs.writeFileSync(jwt, 'bad');
    if (change === 'profile-extra') fs.writeFileSync(join(f.state, 'profile.json'), JSON.stringify({ version: 1, project: PROJECT, cve: META, unsafe: true }));
    if (change === 'overlay-tamper') fs.writeFileSync(join(f.state, 'compose.cve.json'), '{"private":"not accepted"}', { mode: 0o600 });
    await assert.rejects(f.launch(['up', '--build']));
    assert(!f.calls.some(c => c.args.includes('up'))); assert.equal(f.activationReads, 0);
    assert(!fs.existsSync(f.lock));
    if (change === 'missing-jwt') assert(!fs.existsSync(jwt));
  });
});

test('secret creation is exclusive and stable, and stale locks are never stolen', async t => {
  const f = fixture(t); fs.mkdirSync(f.state, { mode: 0o700 });
  assert.equal(loadSecret(f.root, false, () => Buffer.from(SECRET, 'hex')), SECRET);
  assert.equal(loadSecret(f.root, true, () => assert.fail('no regeneration')), SECRET);
  fs.mkdirSync(f.lock, { mode: 0o700 });
  await assert.rejects(f.launch(), /locked\/HOLD/);
  assert(fs.existsSync(f.lock)); assert.equal(f.calls.length, 0);
});

test('real existing CVE loader reads only public activation/PEM, pins its release and ignores later activation changes', async t => {
  const { publicKey } = generateKeyPairSync('ed25519'); // Private fixture key is never exported or written.
  const publicMeta = { ...META, publicKeySha256: createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex') };
  const f = fixture(t, true, publicMeta), legacy = join(f.root, '.local-stand'), release = f.cve.releaseHostDir;
  fs.mkdirSync(legacy, { mode: 0o700 }); fs.mkdirSync(join(legacy, 'db-releases'), { mode: 0o700 });
  fs.mkdirSync(join(legacy, 'trust'), { mode: 0o700 }); fs.mkdirSync(release); fs.mkdirSync(join(release, 'db'));
  for (const file of ['descriptor.json', 'descriptor.sig', 'bundle.bin', 'db/metadata.json', 'db/trivy.db']) {
    fs.writeFileSync(join(release, file), 'synthetic-public-release', { mode: 0o444 });
  }
  fs.chmodSync(join(release, 'db'), 0o555); fs.chmodSync(release, 0o555);
  fs.writeFileSync(f.cve.publicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o444 });
  fs.writeFileSync(join(legacy, 'cve.json'), JSON.stringify(publicMeta), { mode: 0o600 });
  fs.writeFileSync(join(legacy, 'scan-jwt'), 'OLD-SYNTHETIC-JWT-DO-NOT-USE', { mode: 0o600 });
  fs.writeFileSync(join(legacy, 'trust/db-signing-key.pem'), 'PRIVATE-FIXTURE-CANARY', { mode: 0o600 });
  const opened = [], io = { ...fs, openSync(path, flags, ...rest) {
    opened.push(path); assert([join(legacy, 'cve.json'), f.cve.publicKeyPath].includes(path), 'only public CVE inputs opened');
    return fs.openSync(path, flags, ...rest);
  } };
  await f.launch(undefined, { loadActivation: root => loadCveActivation(root, { io }), verifyRelease: (root, value) => validateCveRelease(root, value, { io }) });
  assert(opened.includes(join(legacy, 'cve.json'))); assert(opened.includes(f.cve.publicKeyPath));
  fs.writeFileSync(join(legacy, 'cve.json'), 'invalid later activation; must not be loaded by isolated restart');
  await f.launch(['up', '--build'], { loadActivation: () => assert.fail('pinned, not current'),
    verifyRelease: (root, value) => validateCveRelease(root, value, { io }) });
  assert.equal(opened.filter(p => p === join(legacy, 'cve.json')).length, 1);
  assert.equal(fs.readFileSync(join(f.state, 'scan-jwt'), 'utf8'), SECRET);
  assert(!f.logs.join('\n').includes('PRIVATE-FIXTURE-CANARY'));
});

test('invalid current activation refuses before secret/profile creation and releases preflight lock', async t => {
  const f = fixture(t);
  await assert.rejects(f.launch(undefined, { loadActivation: () => { throw Error('synthetic invalid activation'); } }));
  assert(!fs.existsSync(join(f.state, 'scan-jwt'))); assert(!fs.existsSync(join(f.state, 'profile.json')));
  assert(!fs.existsSync(f.lock)); assert.equal(f.calls.length, 0);
});

test('client timeout retains uncertainty even if daemon may have completed the up', async t => {
  const f = fixture(t);
  await assert.rejects(f.launch(undefined, { run: async (args, options) => {
    const result = await f.run(args, options);
    if (args.includes('up')) throw Object.assign(Error('timeout-private-canary'), { killed: true });
    return result;
  } }), /uncertain\/HOLD/);
  assert(f.containers.some(c => c.State.Running)); assert(fs.existsSync(join(f.lock, 'mutation.json')));
  await assert.rejects(f.launch(), /locked\/HOLD/);
});

test('substituted lock is never cleared after mutation', async t => {
  const f = fixture(t);
  await assert.rejects(f.launch(undefined, { run: async (args, options) => {
    const result = await f.run(args, options);
    if (args.includes('up')) { fs.renameSync(f.lock, `${f.lock}-original`); fs.mkdirSync(f.lock, { mode: 0o700 }); }
    return result;
  } }), /uncertain\/HOLD/);
  assert(fs.existsSync(join(`${f.lock}-original`, 'mutation.json'))); assert(fs.existsSync(f.lock));
});

test('review R1: matching image/container startup hooks and scanner/provider env are not self-authorizing', async t => {
  for (const entry of ['NODE_OPTIONS=--require=/tmp/unreviewed.cjs', 'LD_PRELOAD=/tmp/unreviewed.so',
    'SCAN_VULN_RELEASE_DIR=/private/db', 'OPENROUTER_API_KEY=synthetic-private']) {
    const f = fixture(t); f.populate();
    const api = f.containers.find(c => c.Config.Labels['com.docker.compose.service'] === 'api');
    f.images.get(api.Image).Config.Env.push(entry); api.Config.Env.push(entry);
    await assert.rejects(inspectNamespace(f.run, { root: f.root, env: {} }, f.config), /image|environment|policy/i);
  }
});

test('review R1: cached correctly labeled image entrypoint refuses before any start with no existing container', async t => {
  const f = fixture(t); seedState(f);
  const image = f.imageFor('api', 4); image.Config.Entrypoint = ['/bin/sh', '-c'];
  f.tags = [`${PROJECT}-api:local`];
  let starts = 0;
  await assert.rejects(f.launch(['up'], { run: async (args, options) => {
    if (args.includes('up')) { starts++; throw Error('intercepted unsafe start'); }
    return f.run(args, options);
  } }));
  assert.equal(starts, 0, 'owned labels alone must not authorize image execution');
});

test('review R1: newly built image is inspected before a separate no-build no-pull start', async t => {
  const f = fixture(t); let starts = 0, builds = 0;
  await assert.rejects(f.launch(undefined, { run: async (args, options) => {
    if (args[0] === 'compose' && args.includes('build')) {
      builds++;
      for (const [index, name] of ['egress', 'worker', 'api', 'web'].entries()) f.imageFor(name, index + 2);
      f.tags = ['egress', 'worker', 'api', 'web'].map(name => `${PROJECT}-${name}:local`);
      f.images.get(`${PROJECT}-api:local`).Config.Entrypoint = ['/bin/sh', '-c'];
      return '';
    }
    if (args.includes('up')) { starts++; throw Error('intercepted unsafe start'); }
    return f.run(args, options);
  } }));
  assert.equal(starts, 0, 'newly built images must be checked before start');
  assert.equal(builds, 1, 'build and execution must be distinct submissions');
});

test('review R1: cached and freshly built hooks refuse for every service, including initializer images', async t => {
  for (const stage of ['cached', 'built']) for (const name of ['api', 'worker', 'egress', 'web', 'auth-volume-init', 'scan-volume-init']) {
    const f = fixture(t); let starts = 0;
    const corrupt = () => f.images.get(f.config.services[name].image).Config.Env.push('LD_PRELOAD=/tmp/unreviewed.so');
    if (stage === 'cached') {
      seedState(f);
      for (const [index, service] of Object.keys(f.config.services).entries()) f.imageFor(service, index);
      f.tags = ['egress', 'worker', 'api', 'web'].map(service => `${PROJECT}-${service}:local`);
      corrupt();
    } else if (!name.endsWith('volume-init')) f.afterBuild = corrupt;
    await assert.rejects(f.launch(stage === 'cached' ? ['up'] : undefined, { run: async (args, options) => {
      if (args.includes('up')) starts++;
      const result = await f.run(args, options);
      if (stage === 'built' && name.endsWith('volume-init') && args[0] === 'image' && args[1] === 'pull') corrupt();
      return result;
    } }));
    assert.equal(starts, 0, `${stage} ${name}: no container may start with an image hook`);
    assert(!f.logs.join('\n').includes(SECRET));
    assert.equal(fs.existsSync(join(f.lock, 'mutation.json')), stage === 'built');
  }
});

test('review R1: independent image defaults reject working-dir/user/command/healthcheck/volume drift before start', async t => {
  const changes = [
    image => { image.Config.WorkingDir = '/tmp'; }, image => { image.Config.User = '0:0'; },
    image => { image.Config.Cmd = ['sh', '-c', 'unreviewed']; },
    image => { image.Config.Healthcheck = { Test: ['CMD-SHELL', 'unreviewed'] }; },
    image => { image.Config.Volumes = { '/unreviewed': {} }; }, image => { image.Config.OnBuild = ['RUN unreviewed']; },
    image => { image.Config.Shell = ['sh', '-c']; }, image => { image.Config.Env.push('NODE_VERSION=24.11.1'); },
    image => { image.Config.ExposedPorts = { '9999/tcp': {} }; },
  ];
  for (const change of changes) {
    const f = fixture(t); seedState(f); const image = f.imageFor('api', 4); f.tags = [`${PROJECT}-api:local`]; change(image);
    await assert.rejects(f.launch(['up']));
    assert(!f.calls.some(c => c.args.includes('up') || c.args.includes('build')));
  }
});

test('review R1: validated image IDs, not substituted tags, drive no-build/no-pull startup and postflight', async t => {
  const f = fixture(t); let selected, started = false;
  await f.launch(undefined, { run: async (args, options) => {
    if (args.includes('up')) {
      selected = JSON.parse(fs.readFileSync(join(f.state, 'compose.images.json'), 'utf8')).services;
      for (const spec of Object.values(selected)) assert.match(spec.image, /^sha256:[a-f0-9]{64}$/);
      const tag = `${PROJECT}-api:local`, previous = f.images.get(tag), replacement = structuredClone(previous);
      replacement.Id = `sha256:${'f'.repeat(64)}`;
      f.images.set(tag, replacement); f.images.set(replacement.Id, replacement);
      assert(args.includes('--no-build')); assert(!args.includes('--build')); assert.equal(args[args.indexOf('--pull') + 1], 'never');
      started = true;
    }
    return f.run(args, options);
  } });
  assert(started);
  const api = f.containers.find(c => c.Config.Labels['com.docker.compose.service'] === 'api');
  assert.equal(api.Image, selected.api.image); assert.equal(api.Config.Image, selected.api.image);
  assert.notEqual(api.Image, f.images.get(`${PROJECT}-api:local`).Id);
  const build = f.calls.findIndex(c => c.args.includes('build'));
  const start = f.calls.findIndex(c => c.args.includes('up'));
  assert(build >= 0 && start > build);
  assert(f.calls.slice(build + 1, start).some(c => c.args[0] === 'image' && c.args[1] === 'inspect'));
  const changed = fixture(t); let unsafeStarts = 0;
  await assert.rejects(changed.launch(undefined, { run: async (args, options) => {
    if (args.includes('up')) unsafeStarts++;
    const result = await changed.run(args, options);
    if (args.includes('config') && args.includes(join(changed.state, 'compose.images.json'))) {
      const path = join(changed.state, 'compose.images.json'), pins = JSON.parse(fs.readFileSync(path, 'utf8'));
      pins.services.api.image = `sha256:${'f'.repeat(64)}`; fs.writeFileSync(path, JSON.stringify(pins));
    }
    return result;
  } }), /uncertain\/HOLD/);
  assert.equal(unsafeStarts, 0, 'image-pin changes after config rendering must not reach start');
  assert(fs.existsSync(join(changed.lock, 'mutation.json')));
});

test('review R2: exact projected names are checked before inspect, even with misleading project labels', async t => {
  for (const kind of ['container', 'volume', 'network']) for (const name of [
    'dip-local-full-api-1', 'dip-auth-stand-api-1', 'unrelated-HOLD-resource', `${PROJECT}-unexpected-1`, `${PROJECT}_foreign`, PROJECT,
  ]) {
    const f = fixture(t); let foreignInspect = false, mutation = false;
    await assert.rejects(f.launch(undefined, { run: async (args, options) => {
      if (args[0] === kind && args[1] === 'ls') return `${name}\t${PROJECT}`;
      if (args[0] === kind && args[1] === 'inspect' && args[2] === name) {
        foreignInspect = true; throw Error('intercepted before reading foreign Env/JWT');
      }
      if (args.includes('up') || args.includes('stop') || args.includes('build')) mutation = true;
      return f.run(args, options);
    } }));
    assert.equal(foreignInspect, false, 'must refuse the projection without reading foreign resource details');
    assert.equal(mutation, false); assert(!fs.existsSync(join(f.state, 'scan-jwt')));
  }
});

test('review R3: any Dockerfile-specific ignore override refuses before Docker, public reads or private state', async t => {
  for (const file of ['stand.Dockerfile', 'api.Dockerfile', 'worker.Dockerfile', 'gateway/Dockerfile']) {
    const f = fixture(t), path = join(f.root, 'server/deploy', `${file}.dockerignore`);
    fs.mkdirSync(dirname(path), { recursive: true });
    fs.writeFileSync(path, '# empty override defeats the root ignore policy\n');
    await assert.rejects(f.launch(), /Dockerfile.*ignore|ignore.*override/i);
    assert.equal(f.calls.length, 0); assert.equal(f.activationReads, 0); assert(!fs.existsSync(f.state));
  }
});

test('review R3: dangling/safe-looking overrides and overrides introduced before build all refuse', async t => {
  for (const form of ['symlink', 'directory', 'safe-looking']) {
    const f = fixture(t), path = join(f.root, 'server/deploy/stand.Dockerfile.dockerignore');
    fs.mkdirSync(dirname(path), { recursive: true });
    if (form === 'symlink') fs.symlinkSync('/must-not-follow-private-input', path);
    else if (form === 'directory') fs.mkdirSync(path);
    else fs.writeFileSync(path, `${STATE}/\n`);
    await assert.rejects(f.launch(), /Dockerfile-specific ignore/);
    assert.equal(f.calls.length, 0); assert.equal(f.activationReads, 0); assert(!fs.existsSync(f.state));
  }
  const f = fixture(t);
  await assert.rejects(f.launch(undefined, { run: async (args, options) => {
    const result = await f.run(args, options);
    if (args.includes('config')) {
      const path = join(f.root, 'server/deploy/stand.Dockerfile.dockerignore');
      fs.mkdirSync(dirname(path), { recursive: true }); fs.writeFileSync(path, '# injected before context submission');
    }
    return result;
  } }), /Dockerfile-specific ignore/);
  assert(!f.calls.some(c => c.args.includes('build') || c.args.includes('up')));
});

test('review R4: every engine command binds the resolved Unix endpoint despite mutable default/named contexts', async t => {
  for (const ambient of [{}, { DOCKER_CONTEXT: 'review-local', DOCKER_HOST: 'tcp://ignored-remote:2375',
    DOCKER_TLS_VERIFY: '1', DOCKER_CERT_PATH: '/unreviewed/certs' }]) for (const command of ['up', 'status', 'stop']) {
    const f = fixture(t); let resolutions = 0;
    if (command !== 'up') { seedState(f); f.populate(); }
    await f.launch(command === 'up' ? undefined : [command], { ambient, run: async (args, options) => {
      if (args[0] === 'context') { resolutions++; f.endpoint = 'ssh://changed-after-resolution'; return JSON.stringify('unix:///review/validated.sock'); }
      assert.equal(options.env.DOCKER_HOST, 'unix:///review/validated.sock', 'must not resolve a new daemon implicitly');
      for (const key of ['DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']) assert(!Object.hasOwn(options.env, key));
      return f.run(args, options);
    } });
    assert.equal(resolutions, 1);
  }
});

test('review R4: explicit Unix host avoids context resolution and a post-submit endpoint failure retains HOLD', async t => {
  const f = fixture(t); let submitted = false;
  await assert.rejects(f.launch(undefined, { ambient: { DOCKER_HOST: 'unix:///review/explicit.sock', DOCKER_TLS_VERIFY: '1' },
    run: async (args, options) => {
      assert.notEqual(args[0], 'context'); assert.equal(options.env.DOCKER_HOST, 'unix:///review/explicit.sock');
      assert(!Object.hasOwn(options.env, 'DOCKER_TLS_VERIFY'));
      if (submitted) throw Error('synthetic socket/daemon uncertainty');
      const result = await f.run(args, options);
      if (args.includes('up')) submitted = true;
      return result;
    } }), /uncertain\/HOLD/);
  assert(submitted); assert(fs.existsSync(join(f.lock, 'mutation.json')));
  assert(!f.logs.some(s => s.includes('stand started')));
});

function seedBuildHold(f, extra = {}) {
  seedState(f);
  fs.mkdirSync(f.lock, { mode: 0o700 });
  const marker = { version: 1, project: PROJECT, command: 'up', phase: 'build-pull-start-outcome-unconfirmed', ...extra };
  fs.writeFileSync(join(f.lock, 'mutation.json'), JSON.stringify(marker), { mode: 0o600 });
  for (const [index, name] of Object.keys(f.config.services).entries()) if (!name.endsWith('volume-init')) f.imageFor(name, index);
  f.tags = ['egress', 'worker', 'api', 'web'].map(name => `${PROJECT}-${name}:local`);
  fs.mkdirSync(join(f.root, 'server/deploy'), { recursive: true });
  const source = expectedConfig(f.root);
  source.services.api.environment.SCAN_JWT_SECRET = '${SCAN_JWT_SECRET:?Use scripts/public-image-stand.mjs}';
  for (const service of Object.values(source.services)) if (service.build) service.build.context = '../..';
  fs.writeFileSync(join(f.root, 'server/deploy/compose.public-images.yaml'), JSON.stringify(source));
  if (f.cve) {
    fs.writeFileSync(join(f.state, 'compose.cve.json'), JSON.stringify(cveOverlay(f.cve)), { mode: 0o600 });
    fs.mkdirSync(join(f.root, '.local-stand'), { mode: 0o700 });
    fs.mkdirSync(join(f.root, '.local-stand/db-releases'), { mode: 0o700 });
    fs.mkdirSync(f.cve.releaseHostDir); fs.mkdirSync(join(f.cve.releaseHostDir, 'db'));
    fs.mkdirSync(join(f.root, '.local-stand/trust'), { mode: 0o700 });
    for (const file of ['descriptor.json', 'descriptor.sig', 'bundle.bin', 'db/metadata.json', 'db/trivy.db']) {
      fs.writeFileSync(join(f.cve.releaseHostDir, file), 'synthetic-public-data', { mode: 0o444 });
    }
    fs.writeFileSync(f.cve.publicKeyPath, 'synthetic-public-PEM-verified-by-fixture-spy', { mode: 0o444 });
    fs.chmodSync(join(f.cve.releaseHostDir, 'db'), 0o555); fs.chmodSync(f.cve.releaseHostDir, 0o555);
  }
  return fs.readFileSync(join(f.lock, 'mutation.json'), 'utf8');
}
const RECONCILE = ['reconcile-build-only', '--ack-no-services'];

test('reviewed Docker 28 Linux metadata: absent gateway LANG, Node/Python boolean ArgsEscaped and web root directory', async t => {
  const f = fixture(t); f.populate();
  for (const c of f.containers) {
    const name = c.Config.Labels['com.docker.compose.service'], image = f.images.get(c.Image);
    if (name === 'egress') { image.Config.Env = image.Config.Env.filter(v => !v.startsWith('LANG=')); c.Config.Env = c.Config.Env.filter(v => !v.startsWith('LANG=')); }
    if (['api', 'worker', 'egress'].includes(name)) { image.Config.ArgsEscaped = true; c.Config.ArgsEscaped = true; }
    if (name === 'web') { image.Config.WorkingDir = '/'; c.Config.WorkingDir = '/'; }
  }
  await inspectNamespace(f.run, { root: f.root, env: {} }, f.config);
});

test('strict coordinator normalization never erases IPAM arrays or scalar authorities', () => {
  for (const ipam of [[], 0, false, '']) {
    const config = expectedConfig(ROOT); config.networks.scan_internal.ipam = ipam;
    assert.throws(() => validateConfig(config, ROOT));
  }
});

test('build-only reconciliation accepts only exact local containerd self-digests', async t => {
  const f = fixture(t); seedBuildHold(f);
  for (const name of ['egress', 'api', 'worker', 'web']) {
    const image = f.images.get(`${PROJECT}-${name}:local`);
    image.RepoDigests = [`${PROJECT}-${name}@${image.Id}`];
  }
  await f.launch(RECONCILE);
  assert(!fs.existsSync(f.lock));
  for (const kind of ['foreign-repository', 'wrong-digest', 'extra-digest']) {
    const bad = fixture(t); seedBuildHold(bad);
    const image = bad.images.get(`${PROJECT}-api:local`);
    image.RepoDigests = kind === 'foreign-repository' ? [`foreign/api@${image.Id}`] :
      kind === 'wrong-digest' ? [`${PROJECT}-api@sha256:${'f'.repeat(64)}`] :
        [`${PROJECT}-api@${image.Id}`, `foreign/api@${image.Id}`];
    await assert.rejects(bad.launch(RECONCILE), /HOLD/);
    assert(fs.existsSync(bad.lock));
  }
});

test('build-only reconciliation archives original failure, preserves own credentials and never executes services', async t => {
  for (const enabled of [false, true]) {
    const f = fixture(t, enabled), original = seedBuildHold(f), jwt = fs.lstatSync(join(f.state, 'scan-jwt'));
    await f.launch(RECONCILE);
    assert(!fs.existsSync(f.lock)); assert(!fs.existsSync(join(f.state, '.reconcile-build-only.lock')));
    const history = join(f.state, 'reconciliations'), names = fs.readdirSync(history); assert.equal(names.length, 1);
    const archive = join(history, names[0]);
    assert.equal(fs.readFileSync(join(archive, 'original-operation.lock/mutation.json'), 'utf8'), original);
    const ack = JSON.parse(fs.readFileSync(join(archive, 'acknowledgement.json'), 'utf8'));
    assert.equal(ack.operation, 'NOT_EXECUTED_SERVICES'); assert.equal(ack.originalOutcome, 'HOLD_PRESERVED');
    assert.equal(ack.jwtPreserved, true); assert.equal(ack.endpointProvenance, 'operator-acknowledged-legacy-marker');
    assert.deepEqual(ack.namespace, { containers: 0, volumes: 0, networks: 0 });
    assert(fs.existsSync(join(archive, 'completion.json')));
    assert.equal(fs.readFileSync(join(f.state, 'scan-jwt'), 'utf8'), SECRET);
    assert.equal(fs.lstatSync(join(f.state, 'scan-jwt')).ino, jwt.ino);
    assert(!JSON.stringify(ack).includes(SECRET)); assert(!f.logs.join('\n').includes(SECRET));
    assert.equal(f.activationReads, 0);
    assert(f.calls.every(c => !c.args.some(a => ['build', 'pull', 'up', 'stop', 'down', 'prune'].includes(a))));
    assert(f.calls.filter(c => c.args[1] === 'inspect' && c.args[0] !== 'context').every(c => c.args[0] === 'image'));
    assert(f.calls.every(c => c.options.env.SCAN_JWT_SECRET === undefined || c.options.env.SCAN_JWT_SECRET === CONFIG_SECRET));
    await f.launch(['up', '--build']); // Only an explicitly completed reconciliation admits a later normal launch.
  }
});

test('build-only reconciliation crash after archive cannot be recovered by ordinary up', async t => {
  const f = fixture(t), original = seedBuildHold(f);
  await assert.rejects(f.launch(RECONCILE, { onReconcileCheckpoint: stage => { if (stage === 'lock-archived') throw Error('simulated process death'); } }), /reconciliation.*HOLD/i);
  assert(fs.existsSync(join(f.state, '.reconcile-build-only.lock')));
  const history = join(f.state, 'reconciliations'), archive = join(history, fs.readdirSync(history)[0]);
  assert.equal(fs.readFileSync(join(archive, 'original-operation.lock/mutation.json'), 'utf8'), original);
  const calls = f.calls.length;
  await assert.rejects(f.launch(['up', '--build']), /HOLD/); assert.equal(f.calls.length, calls);
});

test('reviewed metadata allowances stay role-specific and reject hooks, malformed flags and other working directories', async t => {
  const f = fixture(t);
  for (const [index, name] of Object.keys(f.config.services).entries()) {
    const image = f.imageFor(name, index); validateImage(image, name);
    for (const value of [null, 0, 1, 'true', 'false', [], {}]) {
      const copy = structuredClone(image); copy.Config.ArgsEscaped = value; assert.throws(() => validateImage(copy, name));
    }
    const bool = structuredClone(image); bool.Config.ArgsEscaped = true;
    if (['api', 'worker', 'egress'].includes(name)) {
      validateImage(bool, name); bool.Config.ArgsEscaped = false; validateImage(bool, name);
      bool.Os = 'windows'; assert.throws(() => validateImage(bool, name));
    } else assert.throws(() => validateImage(bool, name));
    for (const key of ['Tty', 'OpenStdin', 'StdinOnce', 'NetworkDisabled']) {
      const copy = structuredClone(image); copy.Config[key] = true; assert.throws(() => validateImage(copy, name));
    }
    for (const entry of ['NODE_OPTIONS=--require=/tmp/hook', 'LD_PRELOAD=/tmp/hook', 'SCAN_VULN_ENABLED=true', 'OPENROUTER_API_KEY=canary']) {
      const copy = structuredClone(image); copy.Config.Env.push(entry); assert.throws(() => validateImage(copy, name));
    }
  }
  const gateway = f.images.get(`${PROJECT}-egress:local`);
  assert(!gateway.Config.Env.some(v => v.startsWith('LANG=')));
  gateway.Config.Env.push('LANG=C.UTF-8'); validateImage(gateway, 'egress');
  gateway.Config.Env[gateway.Config.Env.length - 1] = 'LANG=arbitrary'; assert.throws(() => validateImage(gateway, 'egress'));
  const web = f.images.get(`${PROJECT}-web:local`);
  for (const directory of ['', '/tmp', '/app', '//']) { const copy = structuredClone(web); copy.Config.WorkingDir = directory; assert.throws(() => validateImage(copy, 'web')); }
});

test('build-only reconciliation CLI is explicit; missing state/marker and ignore failures never provision or contact Docker', async t => {
  for (const argv of [['reconcile-build-only'], ['reconcile-build-only', '--force'], [...RECONCILE, '--build'],
    [...RECONCILE, '--ack-no-services'], ['up', '--ack-no-services']]) {
    const f = fixture(t); await assert.rejects(f.launch(argv), /Usage:/); assert.equal(f.calls.length, 0); assert(!fs.existsSync(f.state));
  }
  const missing = fixture(t); await assert.rejects(missing.launch(RECONCILE), /reconciliation.*HOLD/i);
  assert(!fs.existsSync(missing.state)); assert.equal(missing.calls.length, 0);
  const noMarker = fixture(t); seedState(noMarker); await assert.rejects(noMarker.launch(RECONCILE), /HOLD/);
  assert(!fs.existsSync(join(noMarker.state, '.reconcile-build-only.lock'))); assert.equal(noMarker.calls.length, 0);
  const ignored = fixture(t); seedBuildHold(ignored); fs.writeFileSync(join(ignored.root, '.dockerignore'), '# missing rule');
  await assert.rejects(ignored.launch(RECONCILE), /append/); assert.equal(ignored.calls.length, 0);
});

test('build-only reconciliation accepts only canonical original build-phase up markers and no start/pin evidence', async t => {
  const bad = [
    { version: 2 }, { project: 'dip-local-full' }, { command: 'stop' }, { phase: 'start-outcome-unconfirmed' },
    { phase: 'stop-outcome-unconfirmed' }, { phase: 'other' }, { extra: true }, { endpoint: 'tcp://remote:2375' },
  ];
  for (const fields of bad) {
    const f = fixture(t), original = seedBuildHold(f, fields);
    await assert.rejects(f.launch(RECONCILE), /reconciliation.*HOLD/i);
    assert.equal(fs.readFileSync(join(f.lock, 'mutation.json'), 'utf8'), original);
    assert.equal(f.calls.length, 0); assert(!fs.existsSync(join(f.state, 'reconciliations')));
  }
  for (const form of ['newline', 'duplicate', 'malformed', 'symlink', 'hardlink', 'wide-mode', 'directory', 'lock-symlink',
    'start-evidence', 'extra-lock-file', 'image-pins', 'pending-pins']) {
    const f = fixture(t); const original = seedBuildHold(f), path = join(f.lock, 'mutation.json');
    if (form === 'newline') fs.appendFileSync(path, '\n');
    if (form === 'duplicate') fs.writeFileSync(path, original.replace('"version":1', '"version":1,"version":1'));
    if (form === 'malformed') fs.writeFileSync(path, 'private-canary-not-json');
    if (form === 'symlink') { fs.unlinkSync(path); fs.symlinkSync('/must-not-read-private-env', path); }
    if (form === 'hardlink') fs.linkSync(path, join(f.root, 'marker-hardlink'));
    if (form === 'wide-mode') fs.chmodSync(path, 0o644);
    if (form === 'directory') { fs.unlinkSync(path); fs.mkdirSync(path); }
    if (form === 'lock-symlink') { fs.renameSync(f.lock, join(f.root, 'unrelated-HOLD')); fs.symlinkSync(join(f.root, 'unrelated-HOLD'), f.lock); }
    if (form === 'start-evidence') fs.writeFileSync(join(f.lock, 'start-submission.json'), '{}', { mode: 0o600 });
    if (form === 'extra-lock-file') fs.writeFileSync(join(f.lock, 'unknown.json'), '{}', { mode: 0o600 });
    if (form === 'image-pins' || form === 'pending-pins') fs.writeFileSync(join(f.state, form === 'image-pins' ? 'compose.images.json' : '.compose.images.pending'), '{}', { mode: 0o600 });
    await assert.rejects(f.launch(RECONCILE), /HOLD/);
    assert(!f.calls.some(c => c.args.some(a => ['build', 'pull', 'up', 'stop'].includes(a))));
    assert(!fs.existsSync(join(f.state, 'reconciliations')));
  }
});

test('build-only reconciliation refuses every own resource, stopped resources and misleading project labels before inspecting them', async t => {
  for (const kind of ['container', 'volume', 'network']) for (const label of [PROJECT, 'foreign-project']) {
    const f = fixture(t); seedBuildHold(f);
    const name = kind === 'container' ? `${PROJECT}-api-1` : `${PROJECT}_${kind === 'volume' ? 'scan_ledger' : 'scan_internal'}`;
    await assert.rejects(f.launch(RECONCILE, { run: async (args, options) => {
      if (args[0] === kind && args[1] === 'ls') { f.calls.push({ args, options }); return `${name}\t${label}`; }
      assert(!(args[0] === kind && args[1] === 'inspect'), 'no full resource inspect or Env/JWT access');
      return f.run(args, options);
    } }), /HOLD/);
    assert(fs.existsSync(join(f.lock, 'mutation.json'))); assert(!fs.existsSync(join(f.state, 'reconciliations')));
  }
  for (const name of ['dip-local-full-api-1', 'dip-auth-stand-api-1', 'unknown-HOLD', `${PROJECT}-renamed-1`]) {
    const f = fixture(t); seedBuildHold(f);
    await assert.rejects(f.launch(RECONCILE, { run: async (args, options) => {
      if (args[0] === 'container' && args[1] === 'ls') return `${name}\t${PROJECT}`;
      assert(!(args[0] === 'container' && args[1] === 'inspect')); return f.run(args, options);
    } }), /HOLD/);
  }
});

test('build-only reconciliation refuses missing, extra, unsafe or foreign-referenced images without service operations', async t => {
  const changes = [
    f => { f.tags.pop(); }, f => { f.tags.push(`${PROJECT}-unexpected:local`); },
    f => { f.images.get(`${PROJECT}-api:local`).Config.Labels = {}; },
    f => { f.images.get(`${PROJECT}-api:local`).RepoTags.push('dip-local-full-api:local'); },
    f => { f.images.get(`${PROJECT}-api:local`).RepoDigests = ['foreign/repo@sha256:bad']; },
    f => { f.imageUsers = 'f'.repeat(64); },
    f => { f.images.get(`${PROJECT}-api:local`).Config.Labels['com.docker.compose.project'] = 'dip-local-full'; },
    f => { f.images.get(`${PROJECT}-api:local`).Config.Labels['com.docker.compose.service'] = 'worker'; },
    f => { f.images.get(`${PROJECT}-worker:local`).Config.Env.push('NODE_OPTIONS=--require=/tmp/hook'); },
    f => { f.images.get(`${PROJECT}-web:local`).Config.WorkingDir = '/tmp'; },
    f => { f.images.get(`${PROJECT}-egress:local`).Config.Entrypoint = ['sh']; },
    f => { f.rendered = expectedConfig(f.root); f.rendered.services.worker.mem_limit = '1073741824'; },
  ];
  for (const change of changes) {
    const f = fixture(t), original = seedBuildHold(f); change(f);
    await assert.rejects(f.launch(RECONCILE), /HOLD/);
    assert.equal(fs.readFileSync(join(f.lock, 'mutation.json'), 'utf8'), original);
    assert(!fs.existsSync(join(f.state, 'reconciliations'))); assert(!f.logs.join('\n').includes(SECRET));
    assert(!f.calls.some(c => c.args.some(a => ['build', 'pull', 'up', 'stop', 'down', 'prune'].includes(a))));
  }
});

test('root ignore guards cannot follow symlinks into synthetic private environment files', async t => {
  for (const file of ['.gitignore', '.dockerignore']) {
    const f = fixture(t); seedBuildHold(f);
    const privateCanary = join(f.root, 'synthetic-private-env');
    fs.writeFileSync(privateCanary, `${STATE}/\n# PRIVATE-ENV-CANARY\n`, { mode: 0o600 });
    fs.unlinkSync(join(f.root, file)); fs.symlinkSync(privateCanary, join(f.root, file));
    await assert.rejects(f.launch(RECONCILE));
    assert.equal(f.calls.length, 0); assert(fs.existsSync(join(f.lock, 'mutation.json')));
    assert(!f.logs.join('\n').includes('PRIVATE-ENV-CANARY'));
  }
});

test('build-only reconciliation validates source indirection and the JWT placeholder before Compose can open referenced files', async t => {
  for (const form of ['env-file', 'extends', 'jwt-literal', 'foreign-context']) {
    const f = fixture(t); seedBuildHold(f);
    const path = join(f.root, 'server/deploy/compose.public-images.yaml'), source = JSON.parse(fs.readFileSync(path, 'utf8'));
    if (form === 'env-file') source.services.api.env_file = '/must-not-open-old-env';
    if (form === 'extends') source.services.api.extends = { file: '/must-not-open-old-env', service: 'api' };
    if (form === 'jwt-literal') source.services.api.environment.SCAN_JWT_SECRET = CONFIG_SECRET;
    if (form === 'foreign-context') source.services.api.build.context = '/must-not-open-old-build';
    fs.writeFileSync(path, JSON.stringify(source));
    await assert.rejects(f.launch(RECONCILE), /HOLD/);
    assert.equal(f.calls.length, 0); assert(fs.existsSync(join(f.lock, 'mutation.json')));
  }
});

test('build-only reconciliation refuses unsafe state, credential or profile paths without rotating/copying data', async t => {
  for (const form of ['missing-jwt', 'bad-jwt', 'wide-jwt', 'linked-jwt', 'symlink-jwt', 'profile-extra', 'symlink-profile', 'state-mode', 'state-symlink', 'source-symlink', 'unexpected-state']) {
    const f = fixture(t); seedBuildHold(f); const jwt = join(f.state, 'scan-jwt'), profile = join(f.state, 'profile.json');
    if (form === 'missing-jwt') fs.unlinkSync(jwt);
    if (form === 'bad-jwt') fs.writeFileSync(jwt, 'bad');
    if (form === 'wide-jwt') fs.chmodSync(jwt, 0o644);
    if (form === 'linked-jwt') fs.linkSync(jwt, join(f.root, 'jwt-alias'));
    if (form === 'symlink-jwt') { fs.unlinkSync(jwt); fs.symlinkSync('/must-not-open-old-JWT', jwt); }
    if (form === 'profile-extra') fs.writeFileSync(profile, JSON.stringify({ version: 1, project: PROJECT, cve: null, force: true }));
    if (form === 'symlink-profile') { fs.unlinkSync(profile); fs.symlinkSync('/must-not-open-old-env', profile); }
    if (form === 'state-mode') fs.chmodSync(f.state, 0o755);
    if (form === 'state-symlink') { fs.renameSync(f.state, join(f.root, 'unrelated-state')); fs.symlinkSync(join(f.root, 'unrelated-state'), f.state); }
    if (form === 'source-symlink') { const p = join(f.root, 'server/deploy/compose.public-images.yaml'); fs.unlinkSync(p); fs.symlinkSync('/must-not-open-old-env', p); }
    if (form === 'unexpected-state') fs.writeFileSync(join(f.state, 'unsafe.tmp'), 'must preserve');
    await assert.rejects(f.launch(RECONCILE, { random: () => assert.fail('must never generate or rotate a JWT') }), /HOLD/);
    assert(!f.logs.join('\n').includes(SECRET));
    if (form === 'missing-jwt') assert(!fs.existsSync(jwt));
  }
});

test('build-only reconciliation detects credential/profile/marker/source and directory replacement during proof', async t => {
  for (const form of ['jwt-content', 'jwt-inode', 'profile-inode', 'marker-inode', 'source-content', 'state-directory', 'operation-directory', 'guard-directory']) {
    const f = fixture(t); seedBuildHold(f); let changed = false;
    await assert.rejects(f.launch(RECONCILE, { onReconcileCheckpoint: stage => {
      if (stage !== 'proof-complete') return; changed = true;
      const replaceFile = path => { const bytes = fs.readFileSync(path); fs.renameSync(path, `${path}.old`); fs.writeFileSync(path, bytes, { mode: 0o600 }); };
      if (form === 'jwt-content') fs.writeFileSync(join(f.state, 'scan-jwt'), 'cd'.repeat(48));
      if (form === 'jwt-inode') replaceFile(join(f.state, 'scan-jwt'));
      if (form === 'profile-inode') replaceFile(join(f.state, 'profile.json'));
      if (form === 'marker-inode') replaceFile(join(f.lock, 'mutation.json'));
      if (form === 'source-content') fs.appendFileSync(join(f.root, 'server/deploy/compose.public-images.yaml'), '\n');
      if (form === 'state-directory') { fs.renameSync(f.state, `${f.state}-original`); fs.mkdirSync(f.state, { mode: 0o700 }); fs.writeFileSync(join(f.state, 'sentinel'), 'do-not-clear'); }
      if (form === 'operation-directory') { fs.renameSync(f.lock, `${f.lock}-original`); fs.mkdirSync(f.lock, { mode: 0o700 }); }
      if (form === 'guard-directory') { const g = join(f.state, '.reconcile-build-only.lock'); fs.renameSync(g, `${g}-original`); fs.mkdirSync(g, { mode: 0o700 }); }
    } }), /HOLD/);
    assert(changed);
    if (form === 'state-directory') { assert.equal(fs.readFileSync(join(f.state, 'sentinel'), 'utf8'), 'do-not-clear'); assert(fs.existsSync(join(`${f.state}-original`, '.operation.lock/mutation.json'))); }
    if (form === 'guard-directory') assert(fs.existsSync(join(f.state, '.reconcile-build-only.lock')));
    assert(!f.calls.some(c => c.args.includes('up')));
  }
});

test('build-only reconciliation uses pinned public assets only and rejects changed/invalid CVE state', async t => {
  for (const form of ['missing-overlay', 'changed-overlay', 'verification-error', 'public-inode']) {
    const f = fixture(t, true); seedBuildHold(f);
    if (form === 'missing-overlay') fs.unlinkSync(join(f.state, 'compose.cve.json'));
    if (form === 'changed-overlay') fs.writeFileSync(join(f.state, 'compose.cve.json'), '{}');
    await assert.rejects(f.launch(RECONCILE, {
      loadActivation: () => assert.fail('must never load a later LOCAL activation'),
      verifyRelease: form === 'verification-error' ? () => { throw Error('PRIVATE-ERROR-CANARY'); } : f.options.verifyRelease,
      onReconcileCheckpoint: stage => {
        if (form === 'public-inode' && stage === 'proof-complete') {
          const p = f.cve.publicKeyPath; fs.renameSync(p, `${p}.old`); fs.writeFileSync(p, 'same-public-key-bytes', { mode: 0o444 });
        }
      },
    }), /HOLD/);
    assert(!f.logs.join('\n').includes('PRIVATE-ERROR-CANARY')); assert(fs.existsSync(join(f.lock, 'mutation.json')));
    assert(!f.calls.some(c => c.args.includes('up')));
  }
});

test('build-only reconciliation retains complete original evidence at every interrupted commit boundary', async t => {
  for (const point of ['proof-complete', 'intent-durable', 'archive-prepared', 'lock-archived', 'completion-recorded', 'guard-release', 'guard-archived']) {
    const f = fixture(t), original = seedBuildHold(f);
    await assert.rejects(f.launch(RECONCILE, { onReconcileCheckpoint: stage => { if (stage === point) throw Error('crash-private-canary'); } }), /reconciliation.*HOLD/i);
    const history = join(f.state, 'reconciliations');
    const saved = fs.existsSync(join(f.lock, 'mutation.json')) ? join(f.lock, 'mutation.json') :
      join(history, fs.readdirSync(history)[0], 'original-operation.lock/mutation.json');
    assert.equal(fs.readFileSync(saved, 'utf8'), original);
    assert.equal(fs.readFileSync(join(f.state, 'scan-jwt'), 'utf8'), SECRET);
    const calls = f.calls.length;
    await assert.rejects(f.launch(['up', '--build']), /HOLD/); assert.equal(f.calls.length, calls);
    assert(!f.logs.join('\n').includes('crash-private-canary'));
    if (point !== 'proof-complete') {
      await assert.rejects(f.launch(RECONCILE), /HOLD/); assert.equal(f.calls.length, calls);
    }
  }
});

test('build-only reconciliation will not overwrite archive paths or accept tampered acknowledgement/completion records', async t => {
  for (const form of ['archive-destination', 'ack-content', 'completion-content']) {
    const f = fixture(t); seedBuildHold(f);
    await assert.rejects(f.launch(RECONCILE, { onReconcileCheckpoint: stage => {
      const history = join(f.state, 'reconciliations');
      if (stage !== (form === 'completion-content' ? 'completion-recorded' : 'archive-prepared')) return;
      const archive = join(history, fs.readdirSync(history)[0]);
      if (form === 'archive-destination') fs.mkdirSync(join(archive, 'original-operation.lock'), { mode: 0o700 });
      if (form === 'ack-content') fs.writeFileSync(join(archive, 'acknowledgement.json'), '{"originalOutcome":"PASS"}');
      if (form === 'completion-content') fs.writeFileSync(join(archive, 'completion.json'), '{}');
    } }), /HOLD/);
    assert(fs.existsSync(join(f.state, '.reconcile-build-only.lock')));
    assert(!f.logs.some(s => s.includes('reconciliation recorded')));
  }
});

test('build-only reconciliation must retain the original lock inode even if identical bytes are copied after archival', async t => {
  const f = fixture(t), original = seedBuildHold(f);
  await assert.rejects(f.launch(RECONCILE, { onReconcileCheckpoint: stage => {
    if (stage !== 'guard-archived') return;
    const history = join(f.state, 'reconciliations'), archive = join(history, fs.readdirSync(history)[0]);
    fs.renameSync(join(archive, 'original-operation.lock'), join(f.root, 'preserved-original-lock'));
    fs.mkdirSync(join(archive, 'original-operation.lock'), { mode: 0o700 });
    fs.writeFileSync(join(archive, 'original-operation.lock/mutation.json'), original, { mode: 0o600 });
  } }), /HOLD/);
  assert.equal(fs.readFileSync(join(f.root, 'preserved-original-lock/mutation.json'), 'utf8'), original);
  assert(fs.existsSync(join(f.state, '.reconcile-build-only.lock')));
});

test('completed build-only reconciliation is not replayed and incomplete/tampered history blocks ordinary lifecycle', async t => {
  const f = fixture(t); seedBuildHold(f); await f.launch(RECONCILE);
  const history = join(f.state, 'reconciliations'), archive = join(history, fs.readdirSync(history)[0]);
  await assert.rejects(f.launch(RECONCILE), /HOLD/); assert.equal(fs.readdirSync(history).length, 1);
  fs.renameSync(join(archive, 'reconciliation-operation.lock'), join(archive, 'incomplete-guard'));
  const calls = f.calls.length; await assert.rejects(f.launch(['up']), /HOLD/); assert.equal(f.calls.length, calls);
  assert(!fs.existsSync(f.lock));
});

test('build-only reconciliation pins its endpoint and refuses mismatched recorded endpoints or image changes', async t => {
  const good = fixture(t); seedBuildHold(good, { endpoint: 'unix:///fixture/docker.sock' }); let resolutions = 0;
  await good.launch(RECONCILE, { ambient: { DOCKER_CONTEXT: 'review-local', DOCKER_HOST: 'tcp://ignored:2375' },
    run: async (args, options) => {
      if (args[0] === 'context') { resolutions++; good.endpoint = 'ssh://changed'; return JSON.stringify('unix:///fixture/docker.sock'); }
      assert.equal(options.env.DOCKER_HOST, 'unix:///fixture/docker.sock'); assert(!Object.hasOwn(options.env, 'DOCKER_CONTEXT'));
      return good.run(args, options);
    } });
  assert.equal(resolutions, 1);
  const archive = join(good.state, 'reconciliations', fs.readdirSync(join(good.state, 'reconciliations'))[0]);
  assert.equal(JSON.parse(fs.readFileSync(join(archive, 'acknowledgement.json'))).endpointProvenance, 'recorded-match');
  for (const form of ['recorded-mismatch', 'remote', 'image-change', 'namespace-change']) {
    const f = fixture(t); seedBuildHold(f, form === 'recorded-mismatch' ? { endpoint: 'unix:///different/engine.sock' } : {});
    await assert.rejects(f.launch(RECONCILE, {
      ambient: form === 'remote' ? { DOCKER_HOST: 'tcp://remote:2375' } : f.options.ambient,
      onReconcileCheckpoint: stage => {
        if (stage !== 'archive-prepared') return;
        if (form === 'image-change') f.images.get(`${PROJECT}-api:local`).Id = `sha256:${'f'.repeat(64)}`;
        if (form === 'namespace-change') f.volumes.push({ Name: `${PROJECT}_scan_ledger`, Labels: ownership });
      },
    }), /HOLD/);
    assert(fs.existsSync(join(f.lock, 'mutation.json'))); assert(!f.calls.some(c => c.args.includes('up')));
  }
});

test('build-only reconciliation never steals an existing guard or follows unsafe/incomplete audit paths', async t => {
  for (const form of ['guard', 'guard-symlink', 'history-symlink', 'incomplete-history', 'history-limit']) {
    const f = fixture(t), original = seedBuildHold(f), guard = join(f.state, '.reconcile-build-only.lock'), history = join(f.state, 'reconciliations');
    if (form === 'guard') fs.mkdirSync(guard, { mode: 0o700 });
    if (form === 'guard-symlink') fs.symlinkSync('/must-not-follow-old-lock', guard);
    if (form === 'history-symlink') fs.symlinkSync('/must-not-follow-old-history', history);
    if (form === 'incomplete-history' || form === 'history-limit') {
      fs.mkdirSync(history, { mode: 0o700 });
      for (let i = 0; i < (form === 'history-limit' ? 33 : 1); i++) fs.mkdirSync(join(history, `build-only-${i.toString(16).padStart(32, '0')}`), { mode: 0o700 });
    }
    await assert.rejects(f.launch(RECONCILE), /HOLD/);
    assert.equal(fs.readFileSync(join(f.lock, 'mutation.json'), 'utf8'), original); assert.equal(f.calls.length, 0);
    if (form.startsWith('guard')) assert(fs.lstatSync(guard));
  }
});

test('lost output after an explicitly completed reconciliation does not rewrite or roll back durable evidence', async t => {
  const f = fixture(t), original = seedBuildHold(f);
  await assert.rejects(f.launch(RECONCILE, { log: () => { throw Error('output-unavailable'); } }), /committed NOT_EXECUTED_SERVICES/);
  assert(!fs.existsSync(f.lock)); assert(!fs.existsSync(join(f.state, '.reconcile-build-only.lock')));
  const history = join(f.state, 'reconciliations'), archive = join(history, fs.readdirSync(history)[0]);
  assert.equal(fs.readFileSync(join(archive, 'original-operation.lock/mutation.json'), 'utf8'), original);
  assert.equal(JSON.parse(fs.readFileSync(join(archive, 'completion.json'))).operation, 'NOT_EXECUTED_SERVICES');
  assert.equal(fs.readFileSync(join(f.state, 'scan-jwt'), 'utf8'), SECRET);
});

test('future start submissions are durably distinguished from build-only failures and diagnostics are stage-only', async t => {
  const f = fixture(t); f.failUp = true;
  await assert.rejects(f.launch(), error => /checkpoint=start/.test(error.message) && !error.message.includes('PRIVATE-SYNTHETIC-ERROR'));
  assert(fs.existsSync(join(f.lock, 'start-submission.json')));
  const bytes = fs.readFileSync(join(f.lock, 'mutation.json'), 'utf8');
  assert.equal(JSON.parse(bytes).endpoint, 'unix:///fixture/docker.sock');
  f.containers = []; f.volumes = []; f.networks = [];
  await assert.rejects(f.launch(RECONCILE), /HOLD/);
  assert.equal(fs.readFileSync(join(f.lock, 'mutation.json'), 'utf8'), bytes);
  const post = fixture(t); post.postDrift = true;
  await assert.rejects(post.launch(), /checkpoint=postflight/);
  const image = fixture(t); image.afterBuild = () => { image.images.get(`${PROJECT}-api:local`).Config.Env.push('LD_PRELOAD=private-canary'); };
  await assert.rejects(image.launch(), error => /checkpoint=image-policy-api/.test(error.message) && !error.message.includes('private-canary'));
});

const NETWORK_RECONCILE = ['reconcile-network-only', '--ack-no-services'];
function seedNetworkHold(f) {
  seedBuildHold(f);
  const endpoint = 'unix:///fixture/docker.sock';
  const marker = JSON.stringify({ version: 1, project: PROJECT, command: 'up', phase: 'start-outcome-unconfirmed', endpoint });
  const start = JSON.stringify({ version: 1, project: PROJECT, phase: 'service-start-submission', endpoint });
  fs.writeFileSync(join(f.lock, 'mutation.json'), marker);
  fs.writeFileSync(join(f.lock, 'start-submission.json'), start, { mode: 0o600 });
  f.imageFor('auth-volume-init', 0);
  const pins = { services: Object.fromEntries(Object.entries(f.config.services).map(([name, spec]) => [name, { image: f.images.get(spec.image).Id }])) };
  fs.writeFileSync(join(f.state, 'compose.images.json'), JSON.stringify(pins), { mode: 0o600 });
  f.networks = ['auth_internal', 'registry_uplink'].map((key, i) => ({
    Name: `${PROJECT}_${key}`, Id: (i + 1).toString(16).repeat(64), Created: '2026-10-18T00:00:00Z',
    Driver: 'bridge', Scope: 'local', Internal: key.endsWith('_internal'), EnableIPv4: true, EnableIPv6: false,
    Attachable: false, Ingress: false, ConfigOnly: false, ConfigFrom: { Network: '' }, Options: {}, Containers: {},
    Labels: { ...ownership, 'com.docker.compose.network': key, 'com.docker.compose.version': '2.39.4' },
    IPAM: { Driver: 'default', Options: {}, Config: [{ Subnet: `172.${30 + i}.0.0/16`, Gateway: `172.${30 + i}.0.1` }] },
  }));
  return { marker, start, pins };
}

test('network-only reconciliation preserves the exact empty own pair and archives start evidence without service/network mutations', async t => {
  const f = fixture(t), original = seedNetworkHold(f), networks = structuredClone(f.networks), jwt = fs.lstatSync(join(f.state, 'scan-jwt'));
  await f.launch(NETWORK_RECONCILE);
  assert.deepEqual(f.networks, networks); assert(!fs.existsSync(f.lock));
  const history = join(f.state, 'reconciliations'), name = fs.readdirSync(history)[0], archive = join(history, name);
  assert.match(name, /^network-only-/);
  assert.equal(fs.readFileSync(join(archive, 'original-operation.lock/mutation.json'), 'utf8'), original.marker);
  assert.equal(fs.readFileSync(join(archive, 'original-operation.lock/start-submission.json'), 'utf8'), original.start);
  const ack = JSON.parse(fs.readFileSync(join(archive, 'acknowledgement.json'), 'utf8'));
  assert.equal(ack.operation, 'PARTIAL_NETWORKS_ONLY_NO_SERVICES'); assert.equal(ack.originalOutcome, 'HOLD_PRESERVED');
  assert.deepEqual(ack.namespace, { containers: 0, volumes: 0, networks: 2 });
  assert.equal(ack.imagePinsSha256, createHash('sha256').update(JSON.stringify(original.pins)).digest('hex'));
  assert.equal(fs.lstatSync(join(f.state, 'scan-jwt')).ino, jwt.ino); assert(!JSON.stringify(ack).includes(SECRET));
  assert(f.calls.every(c => !c.args.some(a => ['up', 'stop', 'build', 'pull', 'rm', 'prune', 'create', 'connect', 'disconnect'].includes(a))));
  assert(f.calls.filter(c => c.args[0] === 'network' && c.args[1] === 'inspect').every(c => networks.some(n => n.Name === c.args[2])));
  await f.launch(['up']); // A completed new history type is accepted by regular guarded up.
});

test('network-only reconciliation interrupted after archive remains HOLD and never broadens build-only eligibility', async t => {
  const f = fixture(t), original = seedNetworkHold(f);
  await assert.rejects(f.launch(RECONCILE), /HOLD/);
  await assert.rejects(f.launch(NETWORK_RECONCILE, { onReconcileCheckpoint: stage => { if (stage === 'lock-archived') throw Error('crash-canary'); } }), /HOLD/);
  assert(fs.existsSync(join(f.state, '.reconcile-network-only.lock')));
  const history = join(f.state, 'reconciliations'), archive = join(history, fs.readdirSync(history)[0]);
  assert.equal(fs.readFileSync(join(archive, 'original-operation.lock/start-submission.json'), 'utf8'), original.start);
  const calls = f.calls.length; await assert.rejects(f.launch(['up']), /HOLD/); assert.equal(f.calls.length, calls);
});

test('isolated Docker adapter emits only fixed failure categories, never raw stderr, Env or causes', async () => {
  assert.equal(typeof isolated.runIsolatedDocker, 'function');
  for (const [stderr, category] of [
    ['all predefined address pools have been fully subnetted', 'network_pool'],
    ['could not find an available, non-overlapping IPv4 address pool', 'network_pool'],
    ['no space left on device', 'resources'], ['cannot allocate memory', 'resources'],
    ['No such image: private-canary', 'image'], ['dependency failed to start: container is unhealthy', 'runtime_health'],
    ['unrecognized private-canary', 'unclassified'],
  ]) {
    await assert.rejects(isolated.runIsolatedDocker(['compose', 'up'], { root: ROOT, env: { SCAN_JWT_SECRET: SECRET } },
      (_file, _args, _options, callback) => callback(Error(`private-error-${SECRET}`), `private-output-${SECRET}`, `${stderr}\nPRIVATE-ENV=${SECRET}`)), error => {
        assert.equal(error.category, category); assert(!error.message.includes(SECRET)); assert(!JSON.stringify(error).includes(SECRET));
        assert(!error.cause && !error.stderr && !error.stdout && !error.cmd); return true;
      });
  }
});

test('network-only CLI requires the exact acknowledgement and never auto-recovers on up or stop', async t => {
  for (const argv of [['reconcile-network-only'], [...NETWORK_RECONCILE, '--force'], [...NETWORK_RECONCILE, '--build'], [...NETWORK_RECONCILE, '--ack-no-services']]) {
    const f = fixture(t); await assert.rejects(f.launch(argv), /Usage/); assert.equal(f.calls.length, 0); assert(!fs.existsSync(f.state));
  }
  const f = fixture(t); seedNetworkHold(f);
  for (const argv of [['up'], ['up', '--build'], ['stop']]) await assert.rejects(f.launch(argv), /HOLD/);
  assert.equal(f.calls.length, 0); assert(fs.existsSync(join(f.lock, 'start-submission.json')));
});

test('network-only requires exact endpoint-bound start marker/submission and exact own state entries', async t => {
  for (const change of [
    f => fs.unlinkSync(join(f.lock, 'start-submission.json')),
    f => fs.writeFileSync(join(f.lock, 'extra.json'), '{}'),
    f => { const p = join(f.lock, 'mutation.json'), m = JSON.parse(fs.readFileSync(p)); delete m.endpoint; fs.writeFileSync(p, JSON.stringify(m)); },
    f => { const p = join(f.lock, 'mutation.json'), m = JSON.parse(fs.readFileSync(p)); m.phase = 'build-pull-start-outcome-unconfirmed'; fs.writeFileSync(p, JSON.stringify(m)); },
    ...['stop-outcome-unconfirmed', 'postflight', ''].map(phase => f => { const p = join(f.lock, 'mutation.json'), m = JSON.parse(fs.readFileSync(p)); m.phase = phase; fs.writeFileSync(p, JSON.stringify(m)); }),
    f => fs.appendFileSync(join(f.lock, 'mutation.json'), '\n'),
    f => fs.writeFileSync(join(f.lock, 'start-submission.json'), JSON.stringify({ version: 1, project: PROJECT, phase: 'service-start-submission', endpoint: 'unix:///other.sock' })),
    f => { const p = join(f.lock, 'start-submission.json'), m = JSON.parse(fs.readFileSync(p)); m.extra = true; fs.writeFileSync(p, JSON.stringify(m)); },
    f => fs.appendFileSync(join(f.lock, 'start-submission.json'), '\n'),
    f => fs.writeFileSync(join(f.state, '.compose.images.pending'), '{}', { mode: 0o600 }),
    f => fs.mkdirSync(join(f.state, '.reconcile-build-only.lock'), { mode: 0o700 }),
    f => fs.mkdirSync(join(f.state, '.reconcile-network-only.lock'), { mode: 0o700 }),
  ]) {
    const f = fixture(t); seedNetworkHold(f); change(f);
    await assert.rejects(f.launch(NETWORK_RECONCILE), /HOLD/);
    assert.equal(f.calls.length, 0); assert(fs.existsSync(join(f.lock, 'mutation.json')));
  }
  for (const endpoint of ['unix:///other.sock', 'tcp://localhost:2375', 'ssh://host']) {
    const f = fixture(t); seedNetworkHold(f);
    await assert.rejects(f.launch(NETWORK_RECONCILE, { ambient: { DOCKER_HOST: endpoint } }), /HOLD/);
    assert.equal(f.calls.length, 0);
  }
});

test('network-only refuses stopped containers, volumes and foreign-project mislabels before any resource inspect', async t => {
  for (const kind of ['container', 'volume']) for (const [name, project] of [[`${PROJECT}-unexpected`, PROJECT], ['dip-local-full-secret', PROJECT], [`${PROJECT}_wrong`, 'foreign']]) {
    const f = fixture(t); seedNetworkHold(f);
    await assert.rejects(f.launch(NETWORK_RECONCILE, { run: async (args, options) => {
      if (args[0] === kind && args[1] === 'ls') { f.calls.push({ args, options }); if (kind === 'container') assert(args.includes('--all')); return `${name}\t${project}`; }
      return f.run(args, options);
    } }), /HOLD/);
    assert(!f.calls.some(c => c.args[1] === 'inspect' && c.args[0] !== 'context'));
  }
});

test('network-only prefilters exact pair before inspect, never follows legacy or extra network labels', async t => {
  for (const rows of [[], [`${PROJECT}_auth_internal\t${PROJECT}`],
    [`${PROJECT}_auth_internal\t${PROJECT}`, `dip-local-full-private\t${PROJECT}`],
    [`${PROJECT}_auth_internal\t${PROJECT}`, `${PROJECT}_registry_uplink\t${PROJECT}`, `${PROJECT}_scan_internal\t${PROJECT}`],
    [`${PROJECT}_auth_internal\t${PROJECT}`, `${PROJECT}_registry_uplink\t${PROJECT}`, `dip-local-full-private\t${PROJECT}`]]) {
    const f = fixture(t); seedNetworkHold(f);
    await assert.rejects(f.launch(NETWORK_RECONCILE, { run: async (args, options) => {
      if (args[0] === 'network' && args[1] === 'ls') { f.calls.push({ args, options }); return rows.join('\n'); }
      return f.run(args, options);
    } }), /HOLD/);
    assert(!f.calls.some(c => c.args[0] === 'network' && c.args[1] === 'inspect'));
  }
});

test('network-only rejects network endpoints, custom authorities, labels and nondefault/overlapping IPAM', async t => {
  const changes = [
    n => { n.Containers.foreign = {}; }, n => { n.Driver = 'overlay'; }, n => { n.Scope = 'swarm'; },
    n => { n.Internal = false; }, n => { n.EnableIPv4 = false; }, n => { n.EnableIPv6 = true; }, n => { n.Attachable = true; },
    n => { n.Ingress = true; }, n => { n.ConfigOnly = true; }, n => { n.ConfigFrom.Network = 'foreign'; },
    n => { n.Options['com.docker.network.bridge.name'] = 'foreign'; }, n => { n.Peers = [{ IP: '1.2.3.4' }]; },
    n => { n.Services = { foreign: {} }; }, n => { n.CustomAuthority = true; },
    n => { n.Labels['com.docker.compose.project'] = 'dip-local-full'; }, n => { delete n.Labels[LABEL]; },
    n => { n.Labels.foreign = 'authority'; }, n => { n.Labels['com.docker.compose.network'] = 'web_edge'; },
    n => { n.Labels['com.docker.compose.version'] = 'unreviewed'; }, n => { n.IPAM.Driver = 'foreign'; },
    n => { n.IPAM.Options.custom = 'unsafe'; }, n => { n.IPAM.Config[0].IPRange = '172.30.1.0/24'; },
    n => { n.IPAM.Config[0].AuxiliaryAddresses = { foreign: '172.30.1.5' }; }, n => { n.IPAM.Config[0].Unknown = true; },
    n => { n.IPAM.Config[0].Gateway = '172.30.0.2'; }, n => { n.IPAM.Config.push({ Subnet: '10.0.0.0/8' }); },
    n => { n.IPAM.Config[0] = { Subnet: '8.0.0.0/8', Gateway: '8.0.0.1' }; },
    n => { n.IPAM.Config[0] = { Subnet: '172.30.1.0/16', Gateway: '172.30.1.1' }; },
    (n, f) => { n.Id = f.networks[1].Id; }, (n, f) => { n.IPAM = structuredClone(f.networks[1].IPAM); },
  ];
  for (const change of changes) {
    const f = fixture(t); seedNetworkHold(f); change(f.networks[0], f);
    await assert.rejects(f.launch(NETWORK_RECONCILE), /HOLD/);
    assert(fs.existsSync(join(f.lock, 'start-submission.json'))); assert(!fs.existsSync(join(f.state, 'reconciliations')));
  }
});

test('network-only validates six exact image pins against known tags without inspecting arbitrary pin IDs', async t => {
  for (const change of [
    f => fs.unlinkSync(join(f.state, 'compose.images.json')),
    f => fs.appendFileSync(join(f.state, 'compose.images.json'), '\n'),
    ...['api', 'auth-volume-init', 'scan-volume-init'].map(name => f => {
      const p = join(f.state, 'compose.images.json'), pins = JSON.parse(fs.readFileSync(p)); pins.services[name].image = `sha256:${'f'.repeat(64)}`; fs.writeFileSync(p, JSON.stringify(pins));
    }),
    f => { const p = join(f.state, 'compose.images.json'), pins = JSON.parse(fs.readFileSync(p)); pins.services.api.command = ['unsafe']; fs.writeFileSync(p, JSON.stringify(pins)); },
    f => { f.images.get(`${PROJECT}-api:local`).RepoTags.push('foreign:local'); },
    f => { f.images.get(`${PROJECT}-api:local`).Config.Env.push('NODE_OPTIONS=--import=unsafe'); },
    f => { f.images.get('busybox:1.37.0').Config.Entrypoint = ['unsafe']; },
    f => { f.imageUsers = 'foreign-container'; }, f => { f.tags.push(`${PROJECT}-extra:local`); },
    f => { f.rendered = structuredClone(f.config); f.rendered.services.worker.mem_limit = '1073741824'; },
  ]) {
    const f = fixture(t); seedNetworkHold(f); change(f); await assert.rejects(f.launch(NETWORK_RECONCILE), /HOLD/);
    assert(!f.calls.some(c => c.args[0] === 'image' && c.args[1] === 'inspect' && c.args[2].startsWith('sha256:')));
    assert(fs.existsSync(join(f.lock, 'mutation.json')));
  }
});

test('network-only pins one endpoint, uses placeholder env and public pinned CVE only; no updater/secret inheritance', async t => {
  const f = fixture(t, true); seedNetworkHold(f);
  let resolutions = 0;
  await f.launch(NETWORK_RECONCILE, { loadActivation: () => { throw Error('must not load current activation'); },
    run: async (args, options) => {
      if (args[0] === 'context') { resolutions++; return f.run(args, options); }
      assert.equal(options.env.DOCKER_HOST, 'unix:///fixture/docker.sock'); assert(!options.env.DOCKER_CONTEXT);
      assert(!options.env.OPENROUTER_API_KEY && !options.env.NODE_OPTIONS && !options.env.HTTP_PROXY);
      assert.equal(options.env.SCAN_JWT_SECRET, args[0] === 'compose' ? CONFIG_SECRET : undefined);
      return f.run(args, options);
    } });
  assert.equal(resolutions, 1); assert.equal(f.activationReads, 0); assert(f.verifications >= 4);
  const second = fixture(t); seedNetworkHold(second); await assert.rejects(second.launch(RECONCILE), /HOLD/);
});

test('network-only detects replaced state, records, pins, source, networks and image identity in repeated proof', async t => {
  for (const target of ['profile.json', 'scan-jwt', 'compose.images.json', '.operation.lock/mutation.json', '.operation.lock/start-submission.json', 'source', 'network', 'image', 'state-directory', 'cve']) {
    const f = fixture(t, target === 'cve'); seedNetworkHold(f); let changed = false;
    await assert.rejects(f.launch(NETWORK_RECONCILE, { onReconcileCheckpoint: stage => {
      if (stage !== 'proof-complete' || changed) return; changed = true;
      if (target === 'network') f.networks[0].Id = 'a'.repeat(64);
      else if (target === 'image') { const im = f.images.get(`${PROJECT}-api:local`); im.Id = `sha256:${'f'.repeat(64)}`; }
      else if (target === 'state-directory') { fs.renameSync(f.state, `${f.state}-replaced`); fs.mkdirSync(f.state, { mode: 0o700 }); }
      else {
        const path = target === 'source' ? join(f.root, 'server/deploy/compose.public-images.yaml') :
          target === 'cve' ? f.cve.publicKeyPath : join(f.state, target);
        const bytes = fs.readFileSync(path), mode = fs.lstatSync(path).mode & 0o777;
        fs.unlinkSync(path); fs.writeFileSync(path, bytes, { mode });
      }
    } }), /HOLD/);
    assert(changed); assert(!f.logs.some(s => s.includes('reconciliation recorded')));
  }
});

test('network-only every interrupted archive boundary remains HOLD with original bytes and inode evidence', async t => {
  for (const point of ['proof-complete', 'intent-durable', 'archive-prepared', 'lock-archived', 'completion-recorded', 'guard-release', 'guard-archived']) {
    const f = fixture(t), original = seedNetworkHold(f), lock = fs.lstatSync(f.lock), start = fs.lstatSync(join(f.lock, 'start-submission.json'));
    await assert.rejects(f.launch(NETWORK_RECONCILE, { onReconcileCheckpoint: stage => { if (stage === point) throw Error('private-crash'); } }), /HOLD/);
    const history = join(f.state, 'reconciliations');
    const saved = fs.existsSync(f.lock) ? f.lock : join(history, fs.readdirSync(history)[0], 'original-operation.lock');
    assert.equal(fs.lstatSync(saved).ino, lock.ino); assert.equal(fs.lstatSync(join(saved, 'start-submission.json')).ino, start.ino);
    assert.equal(fs.readFileSync(join(saved, 'mutation.json'), 'utf8'), original.marker);
    assert.equal(fs.readFileSync(join(saved, 'start-submission.json'), 'utf8'), original.start);
    const calls = f.calls.length;
    for (const argv of [['up'], ['stop'], RECONCILE]) await assert.rejects(f.launch(argv), /HOLD/);
    assert.equal(f.calls.length, calls);
    assert(!f.logs.some(s => /reconciliation recorded|private-crash/.test(s)));
  }
});

test('completed network-only history rejects tampered receipts, nonce, start identity and network snapshots', async t => {
  for (const target of ['nonce', 'image-pins', 'networks', 'start-inode', 'lock-inode', 'ack-extra', 'completion', 'intent', 'missing-completion']) {
    const f = fixture(t); seedNetworkHold(f); await f.launch(NETWORK_RECONCILE);
    const history = join(f.state, 'reconciliations'), archive = join(history, fs.readdirSync(history)[0]);
    const ackPath = join(archive, 'acknowledgement.json'), completionPath = join(archive, 'completion.json');
    if (target === 'missing-completion') fs.unlinkSync(completionPath);
    else if (target === 'start-inode') { const p = join(archive, 'original-operation.lock/start-submission.json'), bytes = fs.readFileSync(p); fs.renameSync(p, `${p}.replaced`); fs.writeFileSync(p, bytes, { mode: 0o600 }); fs.unlinkSync(`${p}.replaced`); }
    else if (target === 'lock-inode') { const p = join(archive, 'original-operation.lock'); fs.renameSync(p, `${p}.replaced`); fs.mkdirSync(p, { mode: 0o700 }); for (const name of fs.readdirSync(`${p}.replaced`)) fs.renameSync(join(`${p}.replaced`, name), join(p, name)); fs.rmdirSync(`${p}.replaced`); }
    else if (target === 'completion') fs.appendFileSync(completionPath, '\n');
    else if (target === 'intent') fs.appendFileSync(join(archive, 'reconciliation-operation.lock/intent.json'), '\n');
    else {
      const ack = JSON.parse(fs.readFileSync(ackPath));
      if (target === 'nonce') ack.transactionNonce = 'a'.repeat(32);
      if (target === 'image-pins') ack.imagePins.api = `sha256:${'f'.repeat(64)}`;
      if (target === 'networks') ack.networks.auth_internal.Containers.foreign = {};
      if (target === 'ack-extra') ack.pass = true;
      const bytes = JSON.stringify(ack), completion = JSON.parse(fs.readFileSync(completionPath));
      completion.acknowledgementSha256 = createHash('sha256').update(bytes).digest('hex');
      fs.writeFileSync(ackPath, bytes); fs.writeFileSync(completionPath, JSON.stringify(completion));
    }
    const calls = f.calls.length;
    for (const argv of [['up'], ['stop']]) await assert.rejects(f.launch(argv), /HOLD/);
    assert.equal(f.calls.length, calls);
  }
});

test('network-only refuses absent/unsafe private state and ignore failures without provisioning or secret rotation', async t => {
  const missing = fixture(t); await assert.rejects(missing.launch(NETWORK_RECONCILE), /HOLD/);
  assert.equal(missing.calls.length, 0); assert(!fs.existsSync(missing.state));
  for (const target of ['profile.json', 'scan-jwt', 'compose.images.json', '.operation.lock/start-submission.json']) for (const shape of ['symlink', 'hardlink', 'permissions', 'missing']) {
    const f = fixture(t); seedNetworkHold(f); const path = join(f.state, target), bytes = fs.readFileSync(path);
    if (shape === 'permissions') fs.chmodSync(path, 0o644);
    else if (shape === 'hardlink') fs.linkSync(path, `${path}.link`);
    else { fs.unlinkSync(path); if (shape === 'symlink') { fs.writeFileSync(join(f.root, 'synthetic-private-canary'), bytes, { mode: 0o600 }); fs.symlinkSync(join(f.root, 'synthetic-private-canary'), path); } }
    await assert.rejects(f.launch(NETWORK_RECONCILE, { random: () => { throw Error('must not rotate'); } }), /HOLD/);
    assert.equal(f.calls.length, 0); assert(!f.logs.some(s => s.includes(SECRET)));
  }
  const ignored = fixture(t); seedNetworkHold(ignored); fs.writeFileSync(join(ignored.root, '.dockerignore'), 'other/\n');
  await assert.rejects(ignored.launch(NETWORK_RECONCILE)); assert.equal(ignored.calls.length, 0);
});

test('network-only never steals another recovery guard or accepts directory/record substitutions before commit', async t => {
  for (const target of ['other-guard', 'start-inode', 'ack', 'completion', 'intent', 'extra-archive-file']) {
    const f = fixture(t); seedNetworkHold(f); let changed = false;
    await assert.rejects(f.launch(NETWORK_RECONCILE, { onReconcileCheckpoint: stage => {
      const point = target === 'completion' ? 'completion-recorded' : 'archive-prepared';
      if (stage !== point || changed) return; changed = true;
      const history = join(f.state, 'reconciliations'), archive = join(history, fs.readdirSync(history)[0]);
      if (target === 'other-guard') fs.mkdirSync(join(f.state, '.reconcile-build-only.lock'), { mode: 0o700 });
      else if (target === 'start-inode') {
        const p = join(f.lock, 'start-submission.json'), bytes = fs.readFileSync(p);
        fs.renameSync(p, `${p}.old`); fs.writeFileSync(p, bytes, { mode: 0o600 }); fs.unlinkSync(`${p}.old`);
      } else {
        const path = target === 'intent' ? join(f.state, '.reconcile-network-only.lock/intent.json') :
          join(archive, target === 'ack' ? 'acknowledgement.json' : target === 'completion' ? 'completion.json' : 'extra.json');
        fs.writeFileSync(path, '{}', { mode: 0o600 });
      }
    } }), /HOLD/);
    assert(changed); assert(fs.existsSync(join(f.state, '.reconcile-network-only.lock')));
    const calls = f.calls.length; await assert.rejects(f.launch(['up']), /HOLD/); assert.equal(f.calls.length, calls);
  }
});

test('network-only records no retrospective PASS and preserves completed evidence when output delivery fails', async t => {
  const f = fixture(t), original = seedNetworkHold(f), networks = structuredClone(f.networks);
  await assert.rejects(f.launch(NETWORK_RECONCILE, { log: () => { throw Error('private-output-failure'); } }), /committed PARTIAL_NETWORKS_ONLY_NO_SERVICES/);
  assert(!fs.existsSync(f.lock)); assert(!fs.existsSync(join(f.state, '.reconcile-network-only.lock')));
  const history = join(f.state, 'reconciliations'), archive = join(history, fs.readdirSync(history)[0]);
  assert.equal(fs.readFileSync(join(archive, 'original-operation.lock/mutation.json'), 'utf8'), original.marker);
  const ack = JSON.parse(fs.readFileSync(join(archive, 'acknowledgement.json')));
  assert.equal(ack.operatorAttestation, 'LAUNCHER_RETURNED_AND_LONG_QUIESCENCE'); assert.equal(ack.originalOutcome, 'HOLD_PRESERVED');
  assert.deepEqual(f.networks, networks); await f.launch(['up']);
});

test('isolated Docker adapter bounds subprocesses and classifies synchronous errors/timeouts without raw data', async () => {
  for (const [error, category] of [[Object.assign(Error('PRIVATE'), { killed: true }), 'timeout'],
    [Object.assign(Error('PRIVATE'), { code: 'ENOENT' }), 'docker_unavailable'], [Object.assign(Error('PRIVATE'), { code: 'EAGAIN' }), 'resources']]) {
    await assert.rejects(isolated.runIsolatedDocker(['image', 'ls'], { root: ROOT, env: {}, timeout: 42 }, (file, args, options) => {
      assert.equal(file, 'docker'); assert.deepEqual(args, ['image', 'ls']); assert.equal(options.timeout, 42);
      assert.equal(options.killSignal, 'SIGKILL'); assert.equal(options.maxBuffer, 16 * 1024 * 1024); throw error;
    }), e => e.category === category && !e.message.includes('PRIVATE'));
  }
  const fexec = (_file, _args, _options, callback) => callback(null, 'safe fixture output', 'not echoed');
  assert.equal(await isolated.runIsolatedDocker(['info'], { root: ROOT, env: {} }, fexec), 'safe fixture output');
});

test('next up HOLD emits fixed failure category/stage and keeps start evidence, never raw Docker output', async t => {
  for (const [stderr, category] of [['all predefined address pools have been fully subnetted', 'network_pool'], ['no space left on device', 'resources'], ['No such image', 'image'], ['container is unhealthy', 'runtime_health']]) {
    const f = fixture(t); seedNetworkHold(f); await f.launch(NETWORK_RECONCILE);
    await assert.rejects(f.launch(['up'], { run: (args, options) => args[0] === 'compose' && args.includes('up') ?
      isolated.runIsolatedDocker(args, options, (_file, _args, _options, callback) => callback(Error(SECRET), SECRET, `${stderr} PRIVATE=${SECRET}`)) : f.run(args, options) }), e => {
      assert.match(e.message, new RegExp(`checkpoint=start; failure=${category}`)); assert(!e.message.includes(SECRET)); return true;
    });
    assert(fs.existsSync(join(f.lock, 'start-submission.json')));
  }
});

const RUNNING_RECONCILE = ['reconcile-running-build-only', '--ack-build-failed-before-start'];
function seedRunningBuildHold(f) {
  seedBuildHold(f, { endpoint: 'unix:///fixture/docker.sock' }); f.imageFor('auth-volume-init', 0);
  const pins = { services: Object.fromEntries(Object.entries(f.config.services).map(([name, spec]) => [name, { image: f.images.get(spec.image).Id }])) };
  fs.writeFileSync(join(f.state, 'compose.images.json'), JSON.stringify(pins), { mode: 0o600 }); f.populate(SECRET, pins.services);
  for (const [i, n] of f.networks.entries()) {
    const key = n.Name.slice(PROJECT.length + 1);
    Object.assign(n, { Id: (i + 1).toString(16).repeat(64), Scope: 'local', EnableIPv4: true, EnableIPv6: false,
      Attachable: false, Ingress: false, ConfigOnly: false, ConfigFrom: { Network: '' }, Options: {},
      Labels: { ...ownership, 'com.docker.compose.network': key, 'com.docker.compose.version': '2.39.4' },
      IPAM: { Driver: 'default', Options: {}, Config: [{ Subnet: `172.${20 + i}.0.0/16`, Gateway: `172.${20 + i}.0.1` }] } });
    for (const [id, endpoint] of Object.entries(n.Containers)) {
      const c = f.containers.find(c => c.Id === id), address = `172.${20 + i}.0.${Number.parseInt(id[0], 16) + 2}`;
      Object.assign(endpoint, { Name: c.Name.slice(1), EndpointID: id, IPv4Address: `${address}/16`, IPv6Address: '', MacAddress: '02:42:ac:00:00:02' });
      Object.assign(c.NetworkSettings.Networks[n.Name], { NetworkID: n.Id, EndpointID: id, IPAddress: address, IPPrefixLen: 16 });
    }
  }
  for (const v of f.volumes) Object.assign(v, { Scope: 'local', Mountpoint: `/fixture/docker/volumes/${v.Name}/_data`, CreatedAt: '2026-10-18T00:00:00Z',
    Labels: { ...ownership, 'com.docker.compose.volume': v.Name.slice(PROJECT.length + 1), 'com.docker.compose.version': '2.39.4' } });
  for (const [i, c] of f.containers.entries()) {
    c.RestartCount = 0;
    Object.assign(c.State, { Pid: c.State.Running ? 100 + i : 0, StartedAt: '2026-10-18T00:00:00Z',
      FinishedAt: c.State.Running ? '0001-01-01T00:00:00Z' : '2026-10-18T00:00:01Z', Restarting: false, Dead: false, OOMKilled: false, Error: '' });
    if (f.config.services[c.Config.Labels['com.docker.compose.service']].healthcheck) c.State.Health = { Status: 'healthy', FailingStreak: 0, Log: [] };
  }
  // A failed rebuild can legitimately retarget API/worker tags, not runtime pins.
  for (const [role, digit] of [['api', 'f'], ['worker', '0']]) {
    const tag = `${PROJECT}-${role}:local`, previous = f.images.get(tag), next = structuredClone(previous);
    previous.RepoTags = []; next.Id = `sha256:${digit.repeat(64)}`; f.images.set(tag, next); f.images.set(next.Id, next);
  }
  return { marker: fs.readFileSync(join(f.lock, 'mutation.json'), 'utf8'), pins, containers: structuredClone(f.containers),
    volumes: structuredClone(f.volumes), networks: structuredClone(f.networks) };
}

test('running-build-only preserves pinned running namespace while recording retargeted build tags, never submits lifecycle', async t => {
  const f = fixture(t), before = seedRunningBuildHold(f), jwt = fs.lstatSync(join(f.state, 'scan-jwt'));
  await assert.rejects(f.launch(RECONCILE), /HOLD/); await assert.rejects(f.launch(NETWORK_RECONCILE), /HOLD/);
  const result = await f.launch(RUNNING_RECONCILE);
  assert.equal(result.operation, 'RUNNING_BUILD_ONLY_NO_LIFECYCLE_SUBMITTED');
  assert.deepEqual(f.containers, before.containers); assert.deepEqual(f.volumes, before.volumes); assert.deepEqual(f.networks, before.networks);
  assert.equal(fs.readFileSync(join(f.state, 'compose.images.json'), 'utf8'), JSON.stringify(before.pins));
  assert.equal(fs.lstatSync(join(f.state, 'scan-jwt')).ino, jwt.ino); assert(!fs.existsSync(f.lock));
  const archive = join(f.state, result.archive), ack = JSON.parse(fs.readFileSync(join(archive, 'acknowledgement.json')));
  assert.equal(ack.originalOutcome, 'HOLD_PRESERVED'); assert.equal(ack.startSubmission, 'ABSENT');
  assert.deepEqual(ack.namespace, { containers: 6, volumes: 2, networks: 4 });
  assert.equal(ack.runtime.containers.api.image, before.pins.services.api.image);
  assert.notEqual(ack.runtime.tagImages.api, before.pins.services.api.image);
  assert(!JSON.stringify(ack).includes(SECRET)); assert.equal(fs.readFileSync(join(archive, 'original-operation.lock/mutation.json'), 'utf8'), before.marker);
  assert(f.calls.every(c => !c.args.some(a => ['up', 'stop', 'build', 'pull', 'rm', 'prune', 'create', 'connect', 'disconnect', 'tag'].includes(a))));
  await f.launch(['stop']); // Completed history is understood by regular lifecycle; fixture only.
});

test('running-build-only explicit acknowledgement, build marker, no start receipt and original pins are mandatory', async t => {
  for (const argv of [['reconcile-running-build-only'], ['reconcile-running-build-only', '--ack-no-services'], [...RUNNING_RECONCILE, '--force']]) {
    const f = fixture(t); await assert.rejects(f.launch(argv), /Usage/); assert.equal(f.calls.length, 0);
  }
  for (const change of [
    f => fs.writeFileSync(join(f.lock, 'start-submission.json'), '{}', { mode: 0o600 }),
    f => { const p = join(f.lock, 'mutation.json'), m = JSON.parse(fs.readFileSync(p)); m.phase = 'start-outcome-unconfirmed'; fs.writeFileSync(p, JSON.stringify(m)); },
    f => { const p = join(f.lock, 'mutation.json'), m = JSON.parse(fs.readFileSync(p)); delete m.endpoint; fs.writeFileSync(p, JSON.stringify(m)); },
    f => fs.unlinkSync(join(f.state, 'compose.images.json')),
    f => fs.appendFileSync(join(f.state, 'compose.images.json'), '\n'),
    f => fs.writeFileSync(join(f.state, '.compose.images.pending'), '{}', { mode: 0o600 }),
  ]) {
    const f = fixture(t); seedRunningBuildHold(f); change(f);
    await assert.rejects(f.launch(RUNNING_RECONCILE), /HOLD/); assert.equal(f.calls.length, 0); assert(fs.existsSync(f.lock));
  }
});

test('running-build-only refuses wrong runtime image, credentials, controls, membership and stopped/unhealthy services', async t => {
  for (const change of [
    f => { f.containers[4].Image = f.images.get(`${PROJECT}-api:local`).Id; },
    f => { f.containers[4].Config.Env.push('NODE_OPTIONS=unsafe'); },
    f => { f.containers[4].Config.Env = f.containers[4].Config.Env.map(v => v.startsWith('SCAN_JWT_SECRET=') ? `SCAN_JWT_SECRET=${'cd'.repeat(48)}` : v); },
    f => { f.containers[3].HostConfig.Memory = 1073741824; },
    f => { f.containers[4].State.Running = false; f.containers[4].State.Status = 'exited'; },
    f => { f.containers[4].State.Health.Status = 'unhealthy'; },
    f => { f.containers[0].State.ExitCode = 1; }, f => { f.containers.pop(); },
    f => { f.networks[0].Containers.foreign = {}; }, f => { f.volumes[0].Driver = 'foreign'; },
    f => { f.foreignWriter = 'foreign-container'; }, f => { f.images.get(`${PROJECT}-api:local`).RepoTags.push('foreign:local'); },
    f => { f.images.get(`${PROJECT}-api:local`).Config.Env.push('NODE_OPTIONS=unsafe'); },
  ]) {
    const f = fixture(t); seedRunningBuildHold(f); change(f); await assert.rejects(f.launch(RUNNING_RECONCILE), /HOLD/);
    assert(fs.existsSync(f.lock)); assert(!f.logs.some(s => /reconciliation recorded/.test(s)));
  }
});

test('running-build-only rechecks exact container/config/volume/network/tag identities at archive fences', async t => {
  for (const target of ['container', 'config', 'volume', 'network', 'tag', 'pins', 'jwt', 'start']) {
    const f = fixture(t); seedRunningBuildHold(f); let changed = false;
    await assert.rejects(f.launch(RUNNING_RECONCILE, { onReconcileCheckpoint: stage => {
      if (stage !== 'archive-prepared' || changed) return; changed = true;
      if (target === 'container') f.containers[4].Id = 'a'.repeat(64);
      else if (target === 'config') f.containers[4].Config.Labels['com.docker.compose.version'] = '2.39.5';
      else if (target === 'volume') f.volumes[0].CreatedAt = '2026-10-18T00:01:00Z';
      else if (target === 'network') f.networks[0].Id = 'a'.repeat(64);
      else if (target === 'tag') f.images.get(`${PROJECT}-api:local`).Id = `sha256:${'1'.repeat(64)}`;
      else if (target === 'start') fs.writeFileSync(join(f.lock, 'start-submission.json'), '{}', { mode: 0o600 });
      else { const p = join(f.state, target === 'pins' ? 'compose.images.json' : 'scan-jwt'), bytes = fs.readFileSync(p); fs.renameSync(p, `${p}.old`); fs.writeFileSync(p, bytes, { mode: 0o600 }); fs.unlinkSync(`${p}.old`); }
    } }), /HOLD/);
    assert(changed); assert(fs.existsSync(join(f.state, '.reconcile-running-build-only.lock')));
    const calls = f.calls.length; await assert.rejects(f.launch(['up']), /HOLD/); assert.equal(f.calls.length, calls);
  }
});

test('running-build-only censuses all exact names/project labels before any image or resource inspect', async t => {
  for (const kind of ['container', 'volume', 'network']) for (const shape of ['foreign-name', 'foreign-label', 'missing', 'extra']) {
    const f = fixture(t); seedRunningBuildHold(f);
    await assert.rejects(f.launch(RUNNING_RECONCILE, { run: async (args, options) => {
      const result = await f.run(args, options);
      if (args[0] !== kind || args[1] !== 'ls' || args.includes('--filter')) return result;
      const rows = result.split('\n');
      if (shape === 'foreign-name') rows[1] = `dip-local-full-private\t${PROJECT}`;
      if (shape === 'foreign-label') rows[1] = `${rows[1].split('\t')[0]}\tdip-local-full`;
      if (shape === 'missing') rows.splice(1, 1);
      if (shape === 'extra') rows.push(`${PROJECT}_unknown\t${PROJECT}`);
      return rows.join('\n');
    } }), /HOLD/);
    assert(!f.calls.some(c => c.args[1] === 'inspect' && c.args[0] !== 'context'));
  }
});

test('running-build-only keeps pinned Unix endpoint, placeholder config env and stable public-only CVE identity', async t => {
  const f = fixture(t, true); seedRunningBuildHold(f); let contexts = 0;
  await f.launch(RUNNING_RECONCILE, { loadActivation: () => { throw Error('current activation must not be reopened'); }, run: (args, options) => {
    if (args[0] === 'context') contexts++;
    else {
      assert.equal(options.env.DOCKER_HOST, 'unix:///fixture/docker.sock'); assert(!options.env.DOCKER_CONTEXT && !options.env.DOCKER_TLS_VERIFY);
      assert(!options.env.NODE_OPTIONS && !options.env.OPENROUTER_API_KEY && !options.env.HTTP_PROXY);
      assert.equal(options.env.SCAN_JWT_SECRET, args[0] === 'compose' ? CONFIG_SECRET : undefined);
    }
    return f.run(args, options);
  } });
  assert.equal(contexts, 1); assert.equal(f.activationReads, 0); assert(f.verifications > 4);
  for (const endpoint of ['unix:///other.sock', 'tcp://localhost:2375', 'ssh://host']) {
    const bad = fixture(t); seedRunningBuildHold(bad);
    await assert.rejects(bad.launch(RUNNING_RECONCILE, { ambient: { DOCKER_HOST: endpoint } }), /HOLD/); assert.equal(bad.calls.length, 0);
  }
});

test('running-build-only refuses unsafe/dangling/hardlinked state paths without creating state or rotating JWT', async t => {
  const absent = fixture(t); await assert.rejects(absent.launch(RUNNING_RECONCILE), /HOLD/); assert(!fs.existsSync(absent.state)); assert.equal(absent.calls.length, 0);
  for (const file of ['profile.json', 'scan-jwt', 'compose.images.json', '.operation.lock/mutation.json']) for (const shape of ['missing', 'symlink', 'hardlink', 'mode']) {
    const f = fixture(t); seedRunningBuildHold(f); const path = join(f.state, file);
    if (shape === 'mode') fs.chmodSync(path, 0o644);
    else if (shape === 'hardlink') fs.linkSync(path, `${path}.linked`);
    else { fs.unlinkSync(path); if (shape === 'symlink') fs.symlinkSync(join(f.root, 'synthetic-missing-target'), path); }
    await assert.rejects(f.launch(RUNNING_RECONCILE, { random: () => { throw Error('must not rotate'); } }), /HOLD/);
    assert.equal(f.calls.length, 0); assert(fs.existsSync(f.lock));
  }
});

test('running-build-only refuses unsafe pinned images, retarget references and volume/network authority drift', async t => {
  for (const change of [
    f => { f.images.get(f.containers[4].Image).RepoTags = ['foreign:private']; },
    f => { f.images.get(f.containers[4].Image).Config.Entrypoint = ['unsafe']; },
    f => { f.imageUsers = 'foreign-container'; }, f => { f.tags.push(`${PROJECT}-unknown:local`); },
    f => { f.volumes[0].Labels['com.docker.compose.volume'] = 'foreign'; }, f => { f.volumes[0].Scope = 'global'; },
    f => { f.networks[0].IPAM.Config[0].IPRange = '172.20.1.0/24'; }, f => { f.networks[0].Options.custom = 'unsafe'; },
    f => { f.networks[0].Containers[f.containers[4].Id].EndpointID = 'f'.repeat(64); },
    f => { f.networks[0].IPAM = structuredClone(f.networks[1].IPAM); },
    f => { f.containers[4].Config.Image = `${PROJECT}-api:local`; },
    f => { f.containers[4].State.Restarting = true; }, f => { f.containers[0].State.Running = true; },
    f => { f.containers[4].State.OOMKilled = true; },
  ]) {
    const f = fixture(t); seedRunningBuildHold(f); change(f); await assert.rejects(f.launch(RUNNING_RECONCILE), /HOLD/);
    assert(fs.existsSync(f.lock)); assert(!fs.existsSync(join(f.state, 'reconciliations')));
  }
});

test('running-build-only detects immutable state/source/CVE replacements and runtime restart evidence', async t => {
  for (const target of ['profile', 'source', 'cve-overlay', 'cve-public', 'pid', 'startedAt', 'restartCount', 'network-endpoint']) {
    const f = fixture(t, target.startsWith('cve')); seedRunningBuildHold(f); let changed = false;
    await assert.rejects(f.launch(RUNNING_RECONCILE, { onReconcileCheckpoint: stage => {
      if (stage !== 'proof-complete' || changed) return; changed = true;
      if (target === 'pid') f.containers[4].State.Pid++;
      else if (target === 'startedAt') f.containers[4].State.StartedAt = '2026-10-18T00:01:00Z';
      else if (target === 'restartCount') f.containers[4].RestartCount++;
      else if (target === 'network-endpoint') f.networks[0].Containers[f.containers[4].Id].IPv4Address = '172.20.0.99/16';
      else {
        const p = target === 'profile' ? join(f.state, 'profile.json') : target === 'source' ? join(f.root, 'server/deploy/compose.public-images.yaml') :
          target === 'cve-overlay' ? join(f.state, 'compose.cve.json') : f.cve.publicKeyPath;
        const bytes = fs.readFileSync(p), mode = fs.lstatSync(p).mode & 0o777; fs.renameSync(p, `${p}.old`); fs.writeFileSync(p, bytes, { mode }); fs.unlinkSync(`${p}.old`);
      }
    } }), /HOLD/);
    assert(changed); assert(fs.existsSync(f.lock));
  }
});

test('running-build-only every interrupted archive boundary preserves original HOLD identity and blocks all ordinary recovery', async t => {
  for (const point of ['proof-complete', 'intent-durable', 'archive-prepared', 'lock-archived', 'completion-recorded', 'guard-release', 'guard-archived']) {
    const f = fixture(t), before = seedRunningBuildHold(f), lock = fs.lstatSync(f.lock), marker = fs.lstatSync(join(f.lock, 'mutation.json'));
    await assert.rejects(f.launch(RUNNING_RECONCILE, { onReconcileCheckpoint: stage => { if (stage === point) throw Error('private-crash'); } }), /HOLD/);
    const history = join(f.state, 'reconciliations'), saved = fs.existsSync(f.lock) ? f.lock : join(history, fs.readdirSync(history)[0], 'original-operation.lock');
    assert.equal(fs.lstatSync(saved).ino, lock.ino); assert.equal(fs.lstatSync(join(saved, 'mutation.json')).ino, marker.ino);
    assert.equal(fs.readFileSync(join(saved, 'mutation.json'), 'utf8'), before.marker);
    assert.deepEqual(f.containers, before.containers); assert.deepEqual(f.volumes, before.volumes); assert.deepEqual(f.networks, before.networks);
    const calls = f.calls.length;
    for (const argv of [['up'], ['up', '--build'], ['stop'], RECONCILE, NETWORK_RECONCILE]) await assert.rejects(f.launch(argv), /HOLD/);
    if (point !== 'proof-complete') await assert.rejects(f.launch(RUNNING_RECONCILE), /HOLD/);
    assert.equal(f.calls.length, calls);
  }
});

test('running-build-only completed receipt is strict, tampering/incomplete history cannot unblock lifecycle', async t => {
  for (const change of ['ack-kind', 'nonce', 'runtime-image', 'runtime-hash', 'namespace', 'start-evidence', 'missing-completion', 'marker-inode', 'pins', 'extra']) {
    const f = fixture(t); seedRunningBuildHold(f); const result = await f.launch(RUNNING_RECONCILE), archive = join(f.state, result.archive);
    const ackPath = join(archive, 'acknowledgement.json'), completionPath = join(archive, 'completion.json');
    if (change === 'missing-completion') fs.unlinkSync(completionPath);
    else if (change === 'start-evidence') fs.writeFileSync(join(archive, 'original-operation.lock/start-submission.json'), '{}', { mode: 0o600 });
    else if (change === 'marker-inode') { const p = join(archive, 'original-operation.lock/mutation.json'), bytes = fs.readFileSync(p); fs.renameSync(p, `${p}.old`); fs.writeFileSync(p, bytes, { mode: 0o600 }); fs.unlinkSync(`${p}.old`); }
    else {
      const ack = JSON.parse(fs.readFileSync(ackPath)), completion = JSON.parse(fs.readFileSync(completionPath));
      if (change === 'ack-kind') ack.acknowledgement = '--ack-no-services';
      if (change === 'nonce') ack.transactionNonce = '0'.repeat(32);
      if (change === 'runtime-image') ack.runtime.containers.api.image = ack.runtime.tagImages.api;
      if (change === 'runtime-hash') ack.runtime.containers.api.controlSha256 = 'not-a-hash';
      if (change === 'namespace') ack.namespace.containers = 0;
      if (change === 'pins') ack.imagePins.api = ack.runtime.tagImages.api;
      if (change === 'extra') ack.pass = true;
      const bytes = JSON.stringify(ack); completion.acknowledgementSha256 = createHash('sha256').update(bytes).digest('hex');
      fs.writeFileSync(ackPath, bytes); fs.writeFileSync(completionPath, JSON.stringify(completion));
    }
    const calls = f.calls.length; for (const argv of [['up'], ['stop']]) await assert.rejects(f.launch(argv), /HOLD/); assert.equal(f.calls.length, calls);
  }
});

test('running-build-only accepts the actual launcher build-failure boundary and never rewrites pins to partially rebuilt tags', async t => {
  const f = fixture(t), before = seedRunningBuildHold(f);
  fs.unlinkSync(join(f.lock, 'mutation.json')); fs.rmdirSync(f.lock); // Synthetic successful previous-operation state only.
  await assert.rejects(f.launch(['up', '--build'], { run: async (args, options) => {
    if (args[0] === 'compose' && args.includes('build')) { f.calls.push({ args, options }); throw Error('synthetic web build failed'); }
    return f.run(args, options);
  } }), /checkpoint=build/);
  assert(!fs.existsSync(join(f.lock, 'start-submission.json')));
  assert.equal(fs.readFileSync(join(f.state, 'compose.images.json'), 'utf8'), JSON.stringify(before.pins));
  await f.launch(RUNNING_RECONCILE); assert.deepEqual(f.containers, before.containers);
});

test('running-build-only does not roll back durable evidence when acknowledgement output is lost', async t => {
  const f = fixture(t); seedRunningBuildHold(f);
  await assert.rejects(f.launch(RUNNING_RECONCILE, { log: () => { throw Error('private-output'); } }), /committed RUNNING_BUILD_ONLY_NO_LIFECYCLE_SUBMITTED/);
  assert(!fs.existsSync(f.lock)); assert(!fs.existsSync(join(f.state, '.reconcile-running-build-only.lock')));
  const history = join(f.state, 'reconciliations'), archive = join(history, fs.readdirSync(history)[0]);
  assert(fs.existsSync(join(archive, 'completion.json'))); await f.launch(['stop']);
});

test('missing saved image metadata yields fixed proof role/reason, never substitutes valid retargeted tags or running Config', async t => {
  for (const role of ['egress', 'worker', 'api']) {
    const f = fixture(t), before = seedRunningBuildHold(f), missing = before.pins.services[role].image;
    const originalMarker = fs.readFileSync(join(f.lock, 'mutation.json'), 'utf8');
    await assert.rejects(f.launch(RUNNING_RECONCILE, { run: (args, options) => {
      if (args[0] === 'image' && args[1] === 'inspect' && args[2] === missing) {
        f.calls.push({ args, options });
        return isolated.runIsolatedDocker(args, options, (_file, _args, _options, callback) => callback(Error(SECRET), '', 'No such image: PRIVATE=' + SECRET));
      }
      return f.run(args, options);
    } }), e => {
      assert.match(e.message, new RegExp('checkpoint=proof-pinned-image-' + role + '; reason=PINNED_IMAGE_METADATA_UNAVAILABLE'));
      assert(!e.message.includes(SECRET) && !e.message.includes(missing)); return true;
    });
    assert.equal(fs.readFileSync(join(f.lock, 'mutation.json'), 'utf8'), originalMarker);
    assert.equal(fs.readFileSync(join(f.state, 'compose.images.json'), 'utf8'), JSON.stringify(before.pins));
    assert.deepEqual(f.containers, before.containers); assert(!fs.existsSync(join(f.state, 'reconciliations')));
    assert(!f.calls.some(c => c.args[0] === 'image' && c.args[1] === 'inspect' && c.args[2].endsWith(':local')));
    assert(f.calls.every(c => !c.args.some(a => ['up', 'stop', 'build', 'pull', 'rm', 'prune', 'tag'].includes(a))));
  }
});

test('status missing runtime image metadata has fixed sanitized checkpoint without opening JWT or mutating HOLD', async t => {
  const f = fixture(t), before = seedRunningBuildHold(f), missing = before.pins.services.egress.image;
  const jwt = fs.readFileSync(join(f.state, 'scan-jwt')); fs.unlinkSync(join(f.state, 'scan-jwt')); // Status must not require/open JWT.
  await assert.rejects(f.launch(['status'], { run: (args, options) => args[0] === 'image' && args[1] === 'inspect' && args[2] === missing ?
    isolated.runIsolatedDocker(args, options, (_file, _args, _options, callback) => callback(Error(SECRET), '', 'No such image: ' + SECRET)) : f.run(args, options) }), e => {
    assert.equal(e.checkpoint, 'runtime-image-egress'); assert.equal(e.reason, 'RUNTIME_IMAGE_METADATA_UNAVAILABLE');
    assert(!e.message.includes(SECRET) && !JSON.stringify(e).includes(SECRET)); assert(!e.cause && !e.stderr && !e.stdout); return true;
  });
  assert(f.logs.some(s => s.startsWith('HOLD:'))); assert(!fs.existsSync(join(f.state, 'scan-jwt')));
  assert.equal(fs.readFileSync(join(f.lock, 'mutation.json'), 'utf8'), before.marker); assert.equal(jwt.toString(), SECRET);
});

const REDEPLOY = ['recover-build-and-redeploy','--ack-unavailable-prior-images'];
function recoveryFixture(t, cve = false, unavailable = true) {
  const f=fixture(t,cve), before=seedRunningBuildHold(f), roles=['egress','worker','api','web'];
  for(const relative of ['server/deploy/api.Dockerfile','server/deploy/worker.Dockerfile','server/deploy/stand.Dockerfile','server/deploy/gateway/Dockerfile']){
    const path=join(f.root,relative);fs.mkdirSync(dirname(path),{recursive:true});fs.writeFileSync(path,fs.readFileSync(join(ROOT,relative)));}
  if(unavailable)for(const role of roles) f.images.delete(before.pins.services[role].image); // Old image evidence really is unavailable.
  const rawRun=f.run; let helper=null; f.fresh=null; f.drains=[0]; f.helperLifecycle=[];f.getHelper=()=>helper;
  const dbBytes={auth:Buffer.from('verified-fixture-auth-database'),ledger:Buffer.from('verified-fixture-ledger-database')};
  f.backups=Object.fromEntries(Object.entries(dbBytes).map(([r,b])=>[r,{bytes:b.length,sha256:createHash('sha256').update(b).digest('hex'),logicalSha256:(r==='auth'?'a':'b').repeat(64),integrity:'ok'}]));
  f.exportBytes=dbBytes;
  f.exportManifest=()=>{const stamp=(role)=>({dev:'1',ino:role==='auth'?'10':'20',uid:'65532',mode:'33152',nlink:'1',size:String(dbBytes[role].length),mtimeNs:'1000000000',ctimeNs:'1000000000'});
    return {version:1,receipt:structuredClone(f.backups),files:Object.fromEntries(['auth','ledger'].map(r=>[r,stamp(r)])),sources:Object.fromEntries(['auth','ledger'].map(r=>[r,[{part:'main',stamp:stamp(r),sha256:createHash('sha256').update(dbBytes[r]).digest('hex')}]]))};};
  const reconnect=()=>{
    for(const n of f.networks){const previous=n.Containers;n.Containers={};for(const c of f.containers.filter(c=>c.State.Running&&c.NetworkSettings.Networks[n.Name])){
      const a=c.NetworkSettings.Networks[n.Name];if(a.NetworkID!==n.Id||a.EndpointID!==c.Id)Object.assign(a,{NetworkID:n.Id,EndpointID:c.Id,IPAddress:'172.20.0.2',IPPrefixLen:16});
      n.Containers[c.Id]=previous[c.Id]??{Name:c.Name.slice(1),EndpointID:c.Id,IPv4Address:'172.20.0.2/16',IPv6Address:'',MacAddress:'02:42:ac:00:00:02'};
    }}
  };
  f.recoveryRun=async(args,options)=>{
    if(args[0]==='image'&&args[1]==='inspect')assert(!Object.values(before.pins.services).filter(x=>x.image!==before.pins.services['auth-volume-init'].image).some(x=>x.image===args[2]),'never inspect old own-image metadata');
    if(args[0]==='compose'&&args.includes('build')){
      f.calls.push({args,options});assert.equal(options.env.SCAN_JWT_SECRET,CONFIG_SECRET);f.fresh={};
      for(const [i,role]of roles.entries()){const image=f.imageFor(role,Object.keys(f.config.services).indexOf(role));image.Id='sha256:'+String(i+1).repeat(64);image.RepoTags=[PROJECT+'-'+role+':local'];f.images.set(image.Id,image);f.images.set(image.RepoTags[0],image);f.fresh[role]=image;}
      return '';
    }
    if(args[0]==='compose'&&args.includes('config')){
      f.calls.push({args,options});const config=structuredClone(f.config);
      for(let i=0;i<args.length;i++)if(args[i]==='-f'&&args[i+1].endsWith('candidate.images.json')){const pins=JSON.parse(fs.readFileSync(args[i+1])).services;for(const[r,s]of Object.entries(pins))config.services[r].image=s.image;}
      return JSON.stringify(config);
    }
    if(args[0]==='compose'&&args.includes('up')){
      f.calls.push({args,options});assert(args.includes('--force-recreate')&&args.includes('--no-deps')&&args.includes('--no-build')&&args.includes('never'));assert(!args.includes('--build'));
      assert.equal(options.env.SCAN_JWT_SECRET,SECRET);const role=args.at(-1), saved={containers:f.containers,volumes:f.volumes,networks:f.networks};
      const pins=JSON.parse(fs.readFileSync(join(f.state,'compose.images.json'))).services;f.populate(SECRET,pins);const replacement=f.containers.find(c=>c.Config.Labels['com.docker.compose.service']===role);
      f.containers=saved.containers;f.volumes=saved.volumes;f.networks=saved.networks;
      replacement.Id=(roles.indexOf(role)+7).toString(16).repeat(64);replacement.RestartCount=0;Object.assign(replacement.State,{Pid:700+roles.indexOf(role),StartedAt:'2026-10-18T01:00:00Z',FinishedAt:'0001-01-01T00:00:00Z',Restarting:false,Dead:false,OOMKilled:false,Error:''});
      if(role==='api')replacement.State.Health={Status:'healthy',FailingStreak:0,Log:[]};f.containers[f.containers.findIndex(c=>c.Config.Labels['com.docker.compose.service']===role)]=replacement;reconnect();return '';
    }
    if(args[0]==='create'){
      f.calls.push({args,options});assert.equal(args[args.indexOf('--network')+1],'none');assert(args.includes('--read-only'));assert(args.includes('1073741824'));assert(args.includes('--pull')&&args.includes('never'));assert(args.filter(a=>a.startsWith('type=volume,')).every(a=>a.includes('readonly,volume-nocopy')));assert(!options.env.SCAN_JWT_SECRET);
      const name=args[args.indexOf('--name')+1],image=f.fresh.api,purpose=args.includes('org.diplom.recovery-purpose=drain')?'drain':'backup';const base=structuredClone(before.containers[4]);
      helper={...base,Id:(purpose==='drain'?(name.endsWith('-next')?'d':'e'):(name.endsWith('-export')?'c':'f')).repeat(64),Name:'/'+name,Image:image.Id,Created:new Date().toISOString(),RestartCount:0,Path:'node',Args:['--input-type=module','-e',purpose==='backup'?isolated.RECOVERY_BACKUP:isolated.RECOVERY_PROBE_SERVICE],Config:{...image.Config,Image:image.Id,Entrypoint:['node'],Cmd:['--input-type=module','-e',purpose==='backup'?isolated.RECOVERY_BACKUP:isolated.RECOVERY_PROBE_SERVICE],User:'65532:65532',WorkingDir:'/app/server/api',
        Labels:{...image.Config.Labels,...ownership,'org.diplom.recovery-helper':'v1','org.diplom.recovery-purpose':purpose}},State:{Running:false,Status:'created',Pid:0,StartedAt:'0001-01-01T00:00:00Z',FinishedAt:'0001-01-01T00:00:00Z',ExitCode:0,Error:'',Restarting:false,OOMKilled:false,Dead:false},NetworkSettings:{Networks:{none:{}},Ports:{}},
        HostConfig:{...base.HostConfig,Memory:1073741824,MemorySwap:1073741824,PidsLimit:32,NetworkMode:'none',PortBindings:{},RestartPolicy:{Name:'no',MaximumRetryCount:0},
          Tmpfs:{'/backup':'rw,noexec,nosuid,uid=65532,gid=65532,size=512m'},Mounts:[{Type:'volume',Source:PROJECT+'_auth_accounts',Target:'/auth',ReadOnly:true,VolumeOptions:{NoCopy:true}},{Type:'volume',Source:PROJECT+'_scan_ledger',Target:'/data',ReadOnly:true,VolumeOptions:{NoCopy:true}}]},
        Mounts:[{Type:'volume',Name:PROJECT+'_auth_accounts',Destination:'/auth',RW:false},{Type:'volume',Name:PROJECT+'_scan_ledger',Destination:'/data',RW:false}]};
              if(purpose==='drain'){helper.HostConfig.Mounts=helper.HostConfig.Mounts.filter(m=>m.Target==='/data');helper.Mounts=helper.Mounts.filter(m=>m.Destination==='/data');}
              for(const m of helper.Mounts){m.Driver='local';m.Source=f.volumes.find(v=>v.Name===m.Name).Mountpoint;}
              f.helperLifecycle.push({event:'create',purpose,id:helper.Id});return helper.Id+'\n';
    }
    if(args[0]==='run')throw Error('helpers must never use docker run');
    if(args[0]==='container'&&args[1]==='start') {f.calls.push({args,options});assert(helper&&args[2]===helper.Id&&helper.State.Status==='created');f.helperLifecycle.push({event:'start',purpose:helper.Config.Labels['org.diplom.recovery-purpose'],id:helper.Id});Object.assign(helper.State,{Running:true,Status:'running',Pid:900,StartedAt:new Date().toISOString()});return helper.Id;}
    if(args[0]==='container'&&args[1]==='ls'&&args.includes('--all')){
      const text=await rawRun(args,options);if(!helper)return text;
      if(args.includes('--filter')){const filter=args[args.indexOf('--filter')+1],matches=filter.startsWith('ancestor=')?helper.Image===filter.slice('ancestor='.length):helper.Mounts.some(m=>m.Name===filter.slice('volume='.length));return text+(matches?'\n'+helper.Id:'');}
      return text+'\n'+helper.Name.slice(1)+'\t'+PROJECT;
    }
    if(args[0]==='container'&&args[1]==='inspect'&&helper&&(args[2]===helper.Id||args[2]===helper.Name.slice(1))){f.calls.push({args,options});f.helperLifecycle.push({event:'inspect-'+helper.State.Status,purpose:helper.Config.Labels['org.diplom.recovery-purpose'],id:helper.Id});return JSON.stringify([helper]);}
    if(args[0]==='container'&&args[1]==='ls'&&args.includes('--filter')&&!args.includes('--all')){
      f.calls.push({args,options});const volume=args[args.indexOf('--filter')+1].slice('volume='.length);
      return [...f.containers.filter(c=>c.State.Running&&c.Mounts.some(m=>m.Name===volume)).map(c=>c.Id),...(helper?.State.Running&&helper.Mounts.some(m=>m.Name===volume)?[helper.Id]:[])].join('\n');
    }
    if(args[0]==='container'&&args[1]==='exec'){
      f.calls.push({args,options});assert(!options.env.SCAN_JWT_SECRET);assert(!before.containers.some(c=>c.Id===args[2]),'no exec in unverifiable prior containers');
      if(args.at(-1)===isolated.RECOVERY_DRAIN){assert(helper?.State.Running&&args[2]===helper.Id&&helper.Config.Labels['org.diplom.recovery-purpose']==='drain');f.helperLifecycle.push({event:'exec',purpose:'drain',id:helper.Id});const n=f.drains.length>1?f.drains.shift():f.drains[0];return JSON.stringify(n==='retry'?{retry:true}:{pending:n});}
      if(helper&&args[2]===helper.Id){assert(helper.State.Running);f.helperLifecycle.push({event:'exec',purpose:helper.Config.Labels['org.diplom.recovery-purpose'],id:helper.Id});
        if(args.includes(isolated.BACKUP_EXPORT_PROGRAM)){const request=JSON.parse(args.at(-1));if(request.action==='manifest')return JSON.stringify(f.exportManifest());
          return JSON.stringify({version:1,role:request.role,offset:request.offset,data:dbBytes[request.role].subarray(request.offset,request.offset+request.bytes).toString('base64')});}
        return JSON.stringify(f.backups);}
      if(args.some(a=>a.includes('worker.ready'))){assert(Number.isFinite(Number(args.at(-1))));return '{"ready":true}';}
      return JSON.stringify(Object.fromEntries(Object.entries(f.backups).map(([r,b])=>[r,{logicalSha256:b.logicalSha256}])));
    }
    if(args[0]==='cp'){f.calls.push({args,options});assert(helper?.State.Running);const role=args[1].includes('/auth.sqlite')?'auth':'ledger';fs.writeFileSync(args[2],dbBytes[role],{mode:0o600});return '';}
    if(args[0]==='container'&&args[1]==='stop'){
      if(helper&&args.includes(helper.Id)){f.calls.push({args,options});Object.assign(helper.State,{Running:false,Status:'exited',Pid:0,FinishedAt:new Date().toISOString()});return '';}
      f.calls.push({args,options});assert([45000,90000].includes(options.timeout));for(const c of f.containers.filter(c=>args.includes(c.Id)))Object.assign(c.State,{Running:false,Status:'exited',Pid:0,FinishedAt:new Date().toISOString()});reconnect();return '';
    }
    if(args[0]==='container'&&args[1]==='rm'){f.calls.push({args,options});assert(helper&&!helper.State.Running&&args[2]===helper.Id);helper=null;return '';}
    return rawRun(args,options);
  };
  f.recover=extra=>f.launch(REDEPLOY,{run:f.recoveryRun,sleep:async()=>{},request:async(url,options)=>{assert.equal(url,ORIGIN+'/api/v1/auth/me');assert.equal(options.redirect,'error');return {status:401,body:{cancel:async()=>{}}};},...extra});
  f.before=before;return f;
}

const BACKUP_CONTINUE=(f,check=false)=>[check?'check-recover-backup-copy':'continue-recover-backup-copy',...(!check?['--ack-quiescent-backup-transfer']:[]),'--audit',f.resumeName,'--helper-id',f.getHelper()?.Id??'f'.repeat(64)];
async function backupCopyFixture(t,expired=false){
  const OriginalDate=globalThis.Date;
  class PastDate extends OriginalDate{constructor(...a){super(...(a.length?a:[OriginalDate.now()-600000]));}static now(){return OriginalDate.now()-600000;}}
  let f;try{if(expired)globalThis.Date=PastDate;f=await datedStartedDrainFixture(t,400000,true);
    await assert.rejects(f.continueStarted({onReconcileCheckpoint:p=>{if(p==='backup-copy')throw Error('prior-archive-failure');}}),/HOLD/);
  }finally{globalThis.Date=OriginalDate;}
  fs.unlinkSync(join(f.audit,'backup-export-manifest.json'));
  const c=f.getHelper();c.Config.Cmd=['--input-type=module','-e',isolated.LEGACY_RECOVERY_BACKUP];c.Args=[...c.Config.Cmd];
  const stable=v=>Array.isArray(v)?v.map(stable):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])])):v;
  const p=join(f.audit,'helper-backup.json'),record=JSON.parse(fs.readFileSync(p));record.createdControlSha256=createHash('sha256').update(JSON.stringify(stable(isolated.helperAuthorityProjection(c)))).digest('hex');fs.writeFileSync(p,JSON.stringify(record));
  const failurePath=join(f.audit,'started-failure.json'),failure=JSON.parse(fs.readFileSync(failurePath));failure.reason='DOCKER_UNCLASSIFIED';fs.writeFileSync(failurePath,JSON.stringify(failure));
  if(expired){const phase=JSON.parse(fs.readFileSync(join(f.audit,'phase-024.json')));Object.assign(c.State,{Status:'exited',Running:false,Pid:0,ExitCode:0,FinishedAt:new Date(Date.parse(phase.at)+300000).toISOString()});}
  f.continueBackup=(extra={},check=false)=>f.launch(BACKUP_CONTINUE(f,check),{run:f.recoveryRun,sleep:async()=>{},request:async()=>({status:401,body:{cancel:async()=>{}}}),...extra});return f;
}

test('exact phase-24 backup continuation is read-only before admission, renews only the legacy helper, exports privately and retains all evidence',async t=>{
  for(const expired of [false,true])await t.test(expired?'clean-expired-legacy':'running-legacy',async t=>{
    const f=await backupCopyFixture(t,expired),id=f.getHelper().Id,files=Object.fromEntries(fs.readdirSync(f.audit).filter(n=>n!=='backups').map(n=>[n,{bytes:fs.readFileSync(join(f.audit,n)),ino:fs.statSync(join(f.audit,n)).ino}]));
    let at=f.calls.length;await f.continueBackup({},true);assert(!f.calls.slice(at).some(c=>recoveryMutation(c.args)));assert.deepEqual(fs.readdirSync(f.audit).sort(),[...Object.keys(files),'backups'].sort());
    at=f.calls.length;const result=await f.continueBackup();assert.equal(result.archive,'redeployments/'+f.resumeName);const calls=f.calls.slice(at);
    assert(!calls.some(c=>c.args[0]==='cp'||c.args.includes('build')||c.args.includes('pull')));assert(!calls.some(c=>c.args[0]==='container'&&c.args[1]==='start'&&c.args[2]===id));
    assert(!calls.some(c=>c.args[0]==='container'&&c.args[1]==='stop'&&f.before.containers.some(old=>c.args.includes(old.Id))));
    for(const[n,v]of Object.entries(files)){assert.deepEqual(fs.readFileSync(join(f.audit,n)),v.bytes);assert.equal(fs.statSync(join(f.audit,n)).ino,v.ino);}
    for(const role of ['auth','ledger'])assert.deepEqual(fs.readFileSync(join(f.audit,'backups',role+'.sqlite')),f.exportBytes[role]);
    assert(fs.existsSync(join(f.audit,'backup-export-manifest.json')));assert(fs.existsSync(join(f.audit,'backup-transfer.json')));await f.launch(['stop'],{run:f.recoveryRun});
  });
});

test('backup-copy continuation refuses source/runtime/evidence drift before any mutation and never loops after partial transport',async t=>{
  const changes={
    'helper-id':f=>{f.getHelper().Id='a'.repeat(64);},
    'restarted':f=>{f.getHelper().RestartCount=1;},
    'env':f=>{f.getHelper().Config.Env.push('NODE_OPTIONS=UNTRUSTED_PAYLOAD');},
    'writable-source':f=>{f.getHelper().Mounts[0].RW=true;},
    'worker-running':f=>{f.containers[3].State.Running=true;},
    'worker-killed':f=>{f.containers[3].State.ExitCode=137;},
    'gateway-restarted':f=>{f.containers[2].RestartCount++;},
    'volume':f=>{f.volumes[0].CreatedAt='2026-10-19T00:00:00Z';},
    'network':f=>{f.networks[0].Id='d'.repeat(64);},
    'retag':f=>{f.images.set(PROJECT+'-api:local',f.fresh.worker);},
    'foreign-consumer':f=>{f.foreignWriter='foreign';},
    'wrong-failure':f=>{const p=join(f.audit,'started-failure.json'),v=JSON.parse(fs.readFileSync(p));v.reason='DOCKER_TIMEOUT';fs.writeFileSync(p,JSON.stringify(v));},
    'later-phase':f=>fs.writeFileSync(join(f.audit,'phase-025.json'),'{}',{mode:0o600}),
    'host-partial':f=>fs.writeFileSync(join(f.audit,'backups','.auth.sqlite.exporting'),'PRIVATE',{mode:0o600}),
    'partial-lock':f=>fs.mkdirSync(join(f.state,'.recover-build-and-redeploy.lock','backup-transfer.lock'),{mode:0o700}),
  };
  for(const[name,change]of Object.entries(changes))await t.test(name,async t=>{const f=await backupCopyFixture(t),check=BACKUP_CONTINUE(f,true),command=BACKUP_CONTINUE(f);change(f);const at=f.calls.length,names=fs.readdirSync(f.audit);
    for(const argv of [check,command])await assert.rejects(f.launch(argv,{run:f.recoveryRun}),/HOLD/);assert(!f.calls.slice(at).some(c=>recoveryMutation(c.args)),name);assert.deepEqual(fs.readdirSync(f.audit),names);
  });
  for(const phase of ['continue-backup-transfer-authorized','retire-legacy-backup-remove','backup-helper-start','backup-copy','commit-new-pins','recreate-api','archive-original','guard-archived']){
    const f=await backupCopyFixture(t,true),id=f.getHelper().Id,from=f.calls.length;await assert.rejects(f.continueBackup({onReconcileCheckpoint:p=>{if(p===phase)throw Error('UNTRUSTED_PAYLOAD');}}),/HOLD/);
    assert(fs.existsSync(join(f.state,'.recover-build-and-redeploy.lock','backup-transfer.lock')));assert(fs.existsSync(join(f.audit,'backup-transfer-failure.json')));assert(fs.existsSync(join(f.audit,'started-failure.json')));
    const at=f.calls.length;await assert.rejects(f.continueBackup(),/HOLD/);await assert.rejects(f.continueStarted(),/HOLD/);assert(!f.calls.slice(at).some(c=>recoveryMutation(c.args)));assert(!f.calls.slice(from).some(c=>c.args[0]==='container'&&c.args[1]==='start'&&c.args[2]===id));assert.equal(fs.readdirSync(join(f.state,'redeployments')).length,1);
  }
});

test('backup export rejects malformed frames and changed source fences without publishing unverified bytes or starting new services',async t=>{
  for(const mode of ['offset','extra-key','base64','source-drift']){const f=await backupCopyFixture(t,true),run=f.recoveryRun;let manifests=0;
    await assert.rejects(f.continueBackup({run:async(args,options)=>{const text=await run(args,options);if(!args.includes(isolated.BACKUP_EXPORT_PROGRAM))return text;const request=JSON.parse(args.at(-1)),v=JSON.parse(text);
      if(request.action==='manifest'){manifests++;if(mode==='source-drift'&&manifests>1)v.sources.auth[0].sha256='0'.repeat(64);}
      else if(mode==='offset')v.offset++;else if(mode==='extra-key')v.extra='UNTRUSTED_PAYLOAD';else if(mode==='base64')v.data='UNTRUSTED_PAYLOAD';return JSON.stringify(v);}}),/HOLD/);
    assert(!f.calls.some(c=>c.args[0]==='compose'&&c.args.includes('up')));assert(fs.existsSync(join(f.audit,'backup-transfer-failure.json')));
    if(mode!=='source-drift'){assert(!fs.existsSync(join(f.audit,'backups','auth.sqlite')));assert(fs.existsSync(join(f.audit,'backups','.auth.sqlite.exporting')));}
  }
});

test('backup-copy CLI is explicit and completed transfer receipts/source fences are required for ordinary lifecycle',async t=>{
  for(const flags of [[],['--force'],['--ack-started-drain-only'],['--ack-quiescent-backup-transfer','--audit','../escape','--helper-id','f'.repeat(64)]]){const f=fixture(t);await assert.rejects(f.launch(['continue-recover-backup-copy',...flags]),/Usage/);assert.equal(f.calls.length,0);}
  for(const name of ['backup-transfer.json','backup-export-manifest.json','started-failure.json']){const f=await backupCopyFixture(t,true);await f.continueBackup();fs.appendFileSync(join(f.audit,name),' ');const at=f.calls.length;await assert.rejects(f.launch(['stop'],{run:f.recoveryRun}),/HOLD/);assert.equal(f.calls.length,at);}
});

test('native export reader fences private snapshot/source bytes, supports empty WAL and rejects traversal/changed files',async t=>{
  const f=fixture(t),crypto=await import('node:crypto'),backup=join(f.root,'exports');fs.mkdirSync(backup,{mode:0o700});
  const paths={backup,auth:join(f.root,'auth.sqlite'),ledger:join(f.root,'ledger.sqlite')},receipt={};
  for(const role of ['auth','ledger']){const bytes=Buffer.alloc(role==='auth'?1024*1024+17:127,role==='auth'?37:89);fs.writeFileSync(paths[role],bytes,{mode:0o600});fs.writeFileSync(join(backup,role+'.sqlite'),bytes,{mode:0o600});receipt[role]={bytes:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex'),logicalSha256:'a'.repeat(64),integrity:'ok'};}
  fs.writeFileSync(paths.ledger+'-wal','',{mode:0o600});fs.writeFileSync(join(backup,'ready.json'),JSON.stringify(receipt),{mode:0o600});
  const m=isolated.backupExportOperation(fs,crypto,{action:'manifest'},paths);assert.equal(m.sources.ledger[1].stamp.size,'0');
  const v=isolated.backupExportOperation(fs,crypto,{action:'chunk',role:'auth',offset:0,bytes:1024*1024,stamp:m.files.auth},paths);assert.equal(Buffer.from(v.data,'base64').length,1024*1024);
  for(const request of [{action:'chunk',role:'../scan-jwt',offset:0,bytes:1,stamp:m.files.auth},{action:'chunk',role:'auth',offset:-1,bytes:1,stamp:m.files.auth},{action:'chunk',role:'auth',offset:0,bytes:1024*1024+1,stamp:m.files.auth}])assert.throws(()=>isolated.backupExportOperation(fs,crypto,request,paths),/BACKUP_EXPORT_REFUSED/);
  fs.appendFileSync(join(backup,'auth.sqlite'),'drift');assert.throws(()=>isolated.backupExportOperation(fs,crypto,{action:'chunk',role:'auth',offset:0,bytes:1,stamp:m.files.auth},paths),/BACKUP_EXPORT_REFUSED/);
});

test('bounded exec transfer verifies chunks/hash/mode and no-overwrite publication without logging or deleting partial evidence',async t=>{
  const f=recoveryFixture(t),dir=join(f.root,'exported');fs.mkdirSync(dir,{mode:0o700});const bytes=Buffer.alloc(2*1024*1024+19,91);f.exportBytes.auth=bytes;Object.assign(f.backups.auth,{bytes:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex')});const m=f.exportManifest();let reads=0;
  await isolated.transferBackupSnapshot({dir,role:'auth',manifest:m,verify:async()=>{},readChunk:async r=>{reads++;return {version:1,role:r.role,offset:r.offset,data:bytes.subarray(r.offset,r.offset+r.bytes).toString('base64')};}});
  assert.equal(reads,3);assert.deepEqual(fs.readFileSync(join(dir,'auth.sqlite')),bytes);assert.equal(fs.statSync(join(dir,'auth.sqlite')).mode&0o777,0o600);
  await assert.rejects(isolated.transferBackupSnapshot({dir,role:'auth',manifest:m,verify:async()=>{},readChunk:async()=>assert.fail('existing target must refuse')}));
  const bad=join(f.root,'bad-export');fs.mkdirSync(bad,{mode:0o700});await assert.rejects(isolated.transferBackupSnapshot({dir:bad,role:'auth',manifest:m,verify:async()=>{},readChunk:async r=>({version:1,role:r.role,offset:r.offset,data:'UNTRUSTED_PAYLOAD'})}));assert(fs.existsSync(join(bad,'.auth.sqlite.exporting')));assert(!fs.existsSync(join(bad,'auth.sqlite')));
});

test('quiescent backup API generations retain exact standalone bytes and new helper holds ready snapshots until explicit cleanup',async t=>{
  const f=sqliteReviewFixture(t),crypto=await import('node:crypto');f.a.close();f.l.close();const second=join(f.root,'second');fs.mkdirSync(second,{mode:0o700});
  const first=await isolated.recoverySqlite(f.DB,fs,crypto,{auth:f.auth,ledger:f.ledger},f.output,{quiescent:true}),again=await isolated.recoverySqlite(f.DB,fs,crypto,{auth:f.auth,ledger:f.ledger},second,{quiescent:true});assert.deepEqual(first,again);
  assert(!isolated.RECOVERY_BACKUP.includes('setTimeout(()=>process.exit(0),300000)'));assert(isolated.LEGACY_RECOVERY_BACKUP.includes('setTimeout(()=>process.exit(0),300000)'));assert(isolated.RECOVERY_BACKUP.includes('setInterval(()=>{},60000)'));
});

test('backup transport never uses Docker archive cp for private tmpfs snapshots',async t=>{
  const f=recoveryFixture(t),run=f.recoveryRun;
  await f.recover({run:async(args,options)=>{assert.notEqual(args[0],'cp','Docker archive cannot see the live backup tmpfs');return run(args,options);}});
});

test('engine create false to running null OomKillDisable is not helper authority drift; true is still refused',async t=>{
  const f=recoveryFixture(t),run=f.recoveryRun;
  await f.recover({run:async(args,options)=>{if(args[0]==='create'){const text=await run(args,options);f.getHelper().HostConfig.OomKillDisable=false;return text;}
    const text=await run(args,options);if(args[0]==='container'&&args[1]==='start')f.getHelper().HostConfig.OomKillDisable=null;return text;}});
});

const STARTED_CONTINUE=(f,check=false)=>[check?'check-recover-started-drain':'continue-recover-started-drain',...(!check?['--ack-started-drain-only']:[]),'--audit',f.resumeName,'--helper-id',f.getHelper()?.Id??'e'.repeat(64)];
async function startedDrainFixture(t){
  const f=await createdDrainFixture(t),run=f.recoveryRun;
  await assert.rejects(f.continueDrain({run:async(args,options)=>{const text=await run(args,options);if(args[0]==='container'&&args[1]==='start')throw Error('previous-helper-control-identity');return text;}}),/HOLD/);
  const p=join(f.audit,'continue-failure.json'),failure=JSON.parse(fs.readFileSync(p));failure.reason='HELPER_CONTROL_IDENTITY';fs.writeFileSync(p,JSON.stringify(failure));
  f.continueStarted=(extra={},check=false)=>f.launch(STARTED_CONTINUE(f,check),{run:f.recoveryRun,sleep:async()=>{},request:async()=>({status:401,body:{cancel:async()=>{}}}),...extra});return f;
}
test('started-drain check is read-only and same-audit continuation does not create or start the retained running helper again',async t=>{
  const f=await startedDrainFixture(t),oldId=f.getHelper().Id,names=fs.readdirSync(f.audit),bytes=Object.fromEntries(names.filter(n=>n!=='backups').map(n=>[n,{bytes:fs.readFileSync(join(f.audit,n)),ino:fs.statSync(join(f.audit,n)).ino}]));
  let at=f.calls.length;await f.continueStarted({},true);assert(!f.calls.slice(at).some(c=>recoveryMutation(c.args)));assert.deepEqual(fs.readdirSync(f.audit),names);
  at=f.calls.length;const r=await f.continueStarted();assert.equal(r.archive,'redeployments/'+f.resumeName);
  assert(!f.calls.slice(at).some(c=>c.args[0]==='container'&&c.args[1]==='start'&&c.args[2]===oldId));
  for(const[n,v]of Object.entries(bytes)){assert.deepEqual(fs.readFileSync(join(f.audit,n)),v.bytes);assert.equal(fs.statSync(join(f.audit,n)).ino,v.ino);}
  assert(fs.existsSync(join(f.audit,'started-drain.json')));await f.launch(['stop'],{run:f.recoveryRun});
});

async function datedStartedDrainFixture(t,age,expired=false){
  const OriginalDate=globalThis.Date;
  class PastDate extends OriginalDate{constructor(...args){super(...(args.length?args:[OriginalDate.now()-age]));}static now(){return OriginalDate.now()-age;}}
  let f;try{globalThis.Date=PastDate;f=await startedDrainFixture(t);}finally{globalThis.Date=OriginalDate;}
  if(expired)Object.assign(f.getHelper().State,{Running:false,Status:'exited',Pid:0,ExitCode:0,FinishedAt:new Date(Date.parse(f.getHelper().State.StartedAt)+360000).toISOString()});
  return f;
}
function seedLegacyCreatedControl(f){
  const c=f.getHelper(),stable=v=>Array.isArray(v)?v.map(stable):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])])):v;
  const hash=createHash('sha256').update(JSON.stringify(stable({Config:c.Config,HostConfig:{...c.HostConfig,OomKillDisable:false}}))).digest('hex');
  const path=join(f.audit,'helper-drain.json'),record=JSON.parse(fs.readFileSync(path));record.createdControlSha256=hash;delete record.controlPolicy;fs.writeFileSync(path,JSON.stringify(record));
  const r=JSON.parse(fs.readFileSync(join(f.audit,'continue-drain.json')));r.helper.controlSha256=hash;
  for(const p of [join(f.audit,'continue-drain.json'),join(f.state,'.recover-build-and-redeploy.lock','continue-drain.lock','receipt.json')])fs.writeFileSync(p,JSON.stringify(r));
  c.HostConfig.OomKillDisable=null;
}
test('started legacy helper proves only the observed OOM false/null delta and clean expiry retires without start reissue',async t=>{
  for(const expired of [false,true])await t.test(expired?'expired-timer':'running-near-expiry',async t=>{
    const f=await datedStartedDrainFixture(t,expired?400000:35000,expired);seedLegacyCreatedControl(f);const oldId=f.getHelper().Id,at=f.calls.length;
    await f.continueStarted({},true);const result=await f.continueStarted();assert.equal(result.archive,'redeployments/'+f.resumeName);
    const calls=f.calls.slice(at);assert(!calls.some(c=>c.args[0]==='container'&&c.args[1]==='start'&&c.args[2]===oldId));
    assert.equal(calls.filter(c=>c.args[0]==='container'&&c.args[1]==='rm'&&c.args[2]===oldId).length,1);
    assert.equal(calls.filter(c=>c.args[0]==='create'&&c.args.includes(PROJECT+'-recovery-'+f.resumeName.slice(9)+'-drain-next')).length,1);
    assert(fs.existsSync(join(f.audit,'helper-drain-next.json')));await f.launch(['stop'],{run:f.recoveryRun});
  });
});

test('helper authority projections consolidate validated Engine 28 defaults, not sandbox authority or process state',async t=>{
  const f=await startedDrainFixture(t),original=f.getHelper(),image=f.fresh.api;
  const engineNeutral={Binds:null,ContainerIDFile:'',VolumeDriver:'',VolumesFrom:null,Dns:[],DnsOptions:[],DnsSearch:[],ExtraHosts:null,GroupAdd:null,Cgroup:'',Links:null,Isolation:'',BlkioWeight:0,BlkioWeightDevice:[],BlkioDeviceReadBps:[],BlkioDeviceWriteBps:[],BlkioDeviceReadIOps:[],BlkioDeviceWriteIOps:[],Devices:[],DeviceCgroupRules:null,DeviceRequests:null,Ulimits:[],CpuCount:0,CpuPercent:0,IOMaximumIOps:0,IOMaximumBandwidth:0};
  let expected;
  for(const state of ['created','running','exited']){const c=structuredClone(original);Object.assign(c.HostConfig,engineNeutral,{OomKillDisable:state==='created'?false:null,MemorySwappiness:state==='created'?null:-1});
    Object.assign(c.State,{Status:state,Running:state==='running',Pid:state==='running'?900:0});c.State.Health={ignored:'not authority'};
    c.HostConfig.SecurityOpt=[state==='created'?'no-new-privileges':'no-new-privileges:true'];
    c.Mounts.reverse();if(state==='created')for(const m of c.HostConfig.Mounts)delete m.VolumeOptions.DriverConfig;
    if(state!=='created')c.Mounts.push({Type:'tmpfs',Destination:'/backup',RW:true});
    isolated.validateBackupHelper(c,c.Name.slice(1),image,'drain',state);const p=isolated.helperAuthorityProjection(c);if(expected)assert.deepEqual(p,expected);else expected=p;
  }
  for(const change of [c=>{c.HostConfig.OomKillDisable=true;},c=>{c.HostConfig.Devices=[{PathOnHost:'/dev/unsafe'}];},c=>{c.HostConfig.Memory=1;},c=>{c.HostConfig.Tmpfs['/backup']='rw,size=1g';},c=>{c.Config.Env.push('NODE_OPTIONS=unsafe');},c=>{c.HostConfig.Mounts[0].VolumeOptions.DriverConfig={Name:'local'};}]){
    const c=structuredClone(original);change(c);assert.throws(()=>isolated.validateBackupHelper(c,c.Name.slice(1),image,'drain','running'));}
});

test('started-drain admission refuses authority/epoch/history changes without lifecycle or audit writes',async t=>{
  const changes={
    'wrong-id':f=>{f.getHelper().Id='a'.repeat(64);},
    'oom-disabled':f=>{f.getHelper().HostConfig.OomKillDisable=true;},
    'gpu-request':f=>{f.getHelper().HostConfig.DeviceRequests=[{Driver:'unsafe'}];},
    'env-hook':f=>{f.getHelper().Config.Env.push('NODE_OPTIONS=UNTRUSTED_PAYLOAD');},
    'stop-signal':f=>{f.getHelper().Config.StopSignal='SIGKILL';},
    'restart':f=>{f.getHelper().RestartCount=1;},
    'new-epoch':f=>{f.getHelper().State.StartedAt=new Date(Date.now()+5000).toISOString();},
    'oom-state':f=>{f.getHelper().State.OOMKilled=true;},
    'created-again':f=>{Object.assign(f.getHelper().State,{Status:'created',Running:false,Pid:0});},
    'bad-exit':f=>{Object.assign(f.getHelper().State,{Status:'exited',Running:false,Pid:0,ExitCode:137,FinishedAt:new Date().toISOString()});},
    'early-clean-exit':f=>{Object.assign(f.getHelper().State,{Status:'exited',Running:false,Pid:0,ExitCode:0,FinishedAt:new Date().toISOString()});},
    'legacy-extra-difference':f=>{f.getHelper().HostConfig.MemorySwappiness=-1;},
    'legacy-config-difference':f=>{f.getHelper().Config.Hostname='changed-after-create';},
    'wrong-previous-reason':f=>{const p=join(f.audit,'continue-failure.json'),v=JSON.parse(fs.readFileSync(p));v.reason='DOCKER_TIMEOUT';fs.writeFileSync(p,JSON.stringify(v));},
    'extra-phase':f=>fs.writeFileSync(join(f.audit,'phase-013.json'),'{}',{mode:0o600}),
    'partial-started-lock':f=>fs.mkdirSync(join(f.state,'.recover-build-and-redeploy.lock','started-drain.lock'),{mode:0o700}),
    'backup-bytes':f=>fs.writeFileSync(join(f.audit,'backups','auth.sqlite'),'UNTRUSTED_PAYLOAD',{mode:0o600}),
    'new-jwt-inode':f=>{const p=join(f.state,'scan-jwt'),b=fs.readFileSync(p);fs.renameSync(p,p+'.old');fs.writeFileSync(p,b,{mode:0o600});fs.unlinkSync(p+'.old');},
    'retagged':f=>{f.images.set(PROJECT+'-api:local',f.fresh.worker);},
    'foreign-writer':f=>{f.foreignWriter='foreign';},
  };
  for(const[name,change]of Object.entries(changes))await t.test(name,async t=>{const f=await startedDrainFixture(t);seedLegacyCreatedControl(f);const argv=STARTED_CONTINUE(f),check=STARTED_CONTINUE(f,true);change(f);const names=fs.readdirSync(f.audit),at=f.calls.length;
    for(const command of [check,argv])await assert.rejects(f.launch(command,{run:f.recoveryRun}),e=>{assert(e.message.includes('HOLD'));assert(!e.message.includes('UNTRUSTED_PAYLOAD'));assert(!e.message.includes(SECRET));return true;});
    assert(!f.calls.slice(at).some(c=>recoveryMutation(c.args)),name);assert.deepEqual(fs.readdirSync(f.audit),names);
  });
});

test('started-drain continuation fences epoch drift, foreign name collisions and all later uncertain boundaries',async t=>{
  const foreign=await startedDrainFixture(t),base=foreign.recoveryRun;foreign.containers.push({Name:'/dip-local-full-forged-api-1',Config:{Labels:ownership}});let foreignInspect=false;
  await assert.rejects(foreign.continueStarted({run:async(args,options)=>{if(args[1]==='inspect'&&args[2]?.includes('forged'))foreignInspect=true;return base(args,options);}},true),/HOLD/);assert.equal(foreignInspect,false);
  for(const phase of ['continue-started-drain-authorized','drain','drain-helper-remove','stop-worker','backup-helper-start','backup-copy','commit-new-pins','recreate-worker','verify-retained-data','recreate-web','archive-original','guard-archived']){
    const f=await startedDrainFixture(t),id=f.getHelper().Id,from=f.calls.length;await assert.rejects(f.continueStarted({onReconcileCheckpoint:p=>{if(p===phase)throw Error('UNTRUSTED_PAYLOAD');}}),/HOLD/);
    assert(fs.existsSync(join(f.state,'.recover-build-and-redeploy.lock','started-drain.lock')));assert(fs.existsSync(join(f.audit,'continue-failure.json')));assert(fs.existsSync(join(f.audit,'started-failure.json')));
    const at=f.calls.length;await assert.rejects(f.continueStarted(),/HOLD/);await assert.rejects(f.continueDrain(),/HOLD/);await assert.rejects(f.resume(),/HOLD/);assert(!f.calls.slice(at).some(c=>recoveryMutation(c.args)));
    assert(!f.calls.slice(from).some(c=>c.args[0]==='container'&&c.args[1]==='start'&&c.args[2]===id));assert.equal(fs.readdirSync(join(f.state,'redeployments')).length,1);
  }
  const f=await startedDrainFixture(t),run=f.recoveryRun;let changed=false;
  await assert.rejects(f.continueStarted({run:async(args,options)=>{const text=await run(args,options);if(!changed&&args[0]==='image'&&args[1]==='inspect'&&args[2]===PROJECT+'-api:local'){changed=true;f.getHelper().State.Pid++;}return text;}},true),/HOLD/);
});

test('started-drain CLI is explicit and completed started history cannot lose its preserved failure or receipt',async t=>{
  for(const flags of [[],['--force'],['--ack-created-drain-only'],['--ack-started-drain-only','--audit','../escape','--helper-id','e'.repeat(64)]]){const f=fixture(t);await assert.rejects(f.launch(['continue-recover-started-drain',...flags]),/Usage/);assert.equal(f.calls.length,0);}
  for(const name of ['started-drain.json','continue-failure.json']){const f=await startedDrainFixture(t);await f.continueStarted();fs.appendFileSync(join(f.audit,name),' ');const at=f.calls.length;await assert.rejects(f.launch(['stop'],{run:f.recoveryRun}),/HOLD/);assert.equal(f.calls.length,at);}
});

test('expired-probe retirement and fresh-probe start uncertainty never restart the old ID or clear either failure',async t=>{
  for(const phase of ['retire-started-drain-remove','drain-helper-start']){const f=await datedStartedDrainFixture(t,400000,true),id=f.getHelper().Id,at=f.calls.length;
    await assert.rejects(f.continueStarted({onReconcileCheckpoint:p=>{if(p===phase)throw Error('UNTRUSTED_PAYLOAD');}}),/HOLD/);
    assert(!f.calls.slice(at).some(c=>c.args[0]==='container'&&c.args[1]==='start'&&c.args[2]===id));
    assert(fs.existsSync(join(f.audit,'continue-failure.json')));assert(fs.existsSync(join(f.audit,'started-failure.json')));assert(fs.existsSync(join(f.state,'.recover-build-and-redeploy.lock','started-drain.lock')));
  }
});

test('Docker empty DriverConfig metadata in readonly nocopy helper mounts is accepted, not custom driver authority',async t=>{
  const f=recoveryFixture(t),run=f.recoveryRun;
  await f.recover({run:async(args,options)=>{const text=await run(args,options);if(args[0]==='container'&&args[1]==='inspect'&&args[2].includes('-recovery-')){const rows=JSON.parse(text);for(const m of rows[0].HostConfig.Mounts)m.VolumeOptions.DriverConfig={};return JSON.stringify(rows);}return text;}});
});

const DRAIN_CONTINUE=(f,check=false)=>[check?'check-recover-created-drain':'continue-recover-created-drain',...(!check?['--ack-created-drain-only']:[]),'--audit',f.resumeName,'--helper-id',f.getHelper()?.Id??'e'.repeat(64)];
async function createdDrainFixture(t){
  const f=await failedCandidateFixture(t),run=f.recoveryRun;let interrupted=false;
  await assert.rejects(f.resume({run:async(args,options)=>{const text=await run(args,options);if(!interrupted&&args[0]==='container'&&args[1]==='inspect'&&args[2].endsWith('-drain')){interrupted=true;for(const m of f.getHelper().HostConfig.Mounts)m.VolumeOptions.DriverConfig={};throw Error('preceding-helper-validation-refusal');}return text;}}),/HOLD/);
  f.continueDrain=(extra={},check=false)=>f.launch(DRAIN_CONTINUE(f,check),{run:f.recoveryRun,sleep:async()=>{},request:async()=>({status:401,body:{cancel:async()=>{}}}),...extra});
  return f;
}
test('created-drain same-audit check is read-only then continuation adopts exact stopped helper once without replaying admissions',async t=>{
  const f=await createdDrainFixture(t),names=fs.readdirSync(f.audit),files=Object.fromEntries(names.filter(n=>n!=='backups').map(n=>[n,{bytes:fs.readFileSync(join(f.audit,n)),ino:fs.statSync(join(f.audit,n)).ino}]));
  const calls=f.calls.length;await f.continueDrain({},true);assert(!f.calls.slice(calls).some(c=>recoveryMutation(c.args)));assert.deepEqual(fs.readdirSync(f.audit),names);assert(f.getHelper().State.Status==='created');
  const at=f.calls.length,id=f.getHelper().Id,result=await f.continueDrain();assert.equal(result.archive,'redeployments/'+f.resumeName);
  const after=f.calls.slice(at);assert(!after.some(c=>c.args.includes('build')||c.args.includes('pull')));assert(!after.some(c=>c.args[0]==='create'&&c.args.includes(PROJECT+'-recovery-'+f.resumeName.slice(9)+'-drain')));
  assert.equal(after.filter(c=>c.args[0]==='container'&&c.args[1]==='start'&&c.args[2]===id).length,1);
  assert(!after.some(c=>c.args[0]==='container'&&c.args[1]==='stop'&&[f.before.containers[4].Id,f.before.containers[5].Id].some(id=>c.args.includes(id))));
  for(const[n,v]of Object.entries(files)){assert.deepEqual(fs.readFileSync(join(f.audit,n)),v.bytes);assert.equal(fs.statSync(join(f.audit,n)).ino,v.ino);}
  assert(fs.existsSync(join(f.audit,'continue-drain.json')));await f.launch(['stop'],{run:f.recoveryRun});
});

test('created-drain admission refuses driver authority, started helpers, drift and incomplete evidence with no lifecycle or state writes',async t=>{
  const changes={
    'custom-driver':f=>{f.getHelper().HostConfig.Mounts[0].VolumeOptions.DriverConfig={Name:'unsafe'};},
    'driver-null':f=>{f.getHelper().HostConfig.Mounts[0].VolumeOptions.DriverConfig=null;},
    'driver-array':f=>{f.getHelper().HostConfig.Mounts[0].VolumeOptions.DriverConfig=[];},
    'driver-unknown':f=>{f.getHelper().HostConfig.Mounts[0].VolumeOptions.Extra={};},
    'copy-up':f=>{f.getHelper().HostConfig.Mounts[0].VolumeOptions.NoCopy=false;},
    'writable':f=>{f.getHelper().Mounts[0].RW=true;},
    'observed-source':f=>{f.getHelper().Mounts[0].Source='/foreign';},
    'helper-id':f=>{f.getHelper().Id='a'.repeat(64);},
    'started-at':f=>{f.getHelper().State.StartedAt=new Date().toISOString();},
    'restarts':f=>{f.getHelper().RestartCount=1;},
    'pid':f=>{f.getHelper().State.Pid=100;},
    'status':f=>{Object.assign(f.getHelper().State,{Status:'running',Running:true});},
    'env':f=>{f.getHelper().Config.Env.push('NODE_OPTIONS=PRIVATE');},
    'program':f=>{f.getHelper().Config.Cmd=['--eval','PRIVATE'];},
    'resources':f=>{f.getHelper().HostConfig.Memory=536870912;},
    'namespace':f=>{f.getHelper().HostConfig.PidMode='host';},
    'api-started':f=>{f.containers[4].State.Running=true;},
    'api-nonzero':f=>{f.containers[4].State.ExitCode=137;},
    'worker-restarted':f=>{f.containers[3].RestartCount++;},
    'volume-identity':f=>{f.volumes[0].CreatedAt='2026-10-19T00:00:00Z';},
    'network':f=>{f.networks[0].Id='d'.repeat(64);},
    'jwt-identity':f=>{const p=join(f.state,'scan-jwt'),b=fs.readFileSync(p);fs.renameSync(p,p+'.old');fs.writeFileSync(p,b,{mode:0o600});fs.unlinkSync(p+'.old');},
    'changed-pins':f=>{const p=join(f.state,'compose.images.json'),v=JSON.parse(fs.readFileSync(p));v.services.api.image=f.fresh.api.Id;fs.writeFileSync(p,JSON.stringify(v));},
    'retag':f=>{f.images.set(PROJECT+'-api:local',f.fresh.worker);},
    'foreign-consumer':f=>{f.foreignWriter='foreign';},
    'missing-phase':f=>fs.unlinkSync(join(f.audit,'phase-009.json')),
    'extra-phase':f=>fs.writeFileSync(join(f.audit,'phase-011.json'),'{}',{mode:0o600}),
    'helper-record':f=>fs.writeFileSync(join(f.audit,'helper-drain.json'),'{}',{mode:0o600}),
    'backup-file':f=>fs.writeFileSync(join(f.audit,'backups','partial.sqlite'),'PRIVATE',{mode:0o600}),
    'partial-lock':f=>fs.mkdirSync(join(f.state,'.recover-build-and-redeploy.lock','continue-drain.lock'),{mode:0o700}),
    'resume-receipt':f=>fs.appendFileSync(join(f.audit,'resume.json'),' '),
  };
  for(const[name,change]of Object.entries(changes))await t.test(name,async t=>{const f=await createdDrainFixture(t),argv=DRAIN_CONTINUE(f,true),mutationArgv=DRAIN_CONTINUE(f);change(f);
    const before=f.calls.length,names=fs.readdirSync(f.audit);await assert.rejects(f.launch(argv,{run:f.recoveryRun}),/HOLD/);assert(!f.calls.slice(before).some(c=>recoveryMutation(c.args)),name);assert.deepEqual(fs.readdirSync(f.audit),names);
    const at=f.calls.length;await assert.rejects(f.launch(mutationArgv,{run:f.recoveryRun}),/HOLD/);assert(!f.calls.slice(at).some(c=>recoveryMutation(c.args)),name);});
});

test('created-drain continuation is explicit one-shot; every subsequent mutation/archive interruption retains both prior locks and original audit',async t=>{
  for(const flags of [[],['--force'],['--ack-created-drain-only'],['--ack-created-drain-only','--audit','../escape','--helper-id','e'.repeat(64)]]){const f=fixture(t);await assert.rejects(f.launch(['continue-recover-created-drain',...flags]),/Usage/);assert.equal(f.calls.length,0);}
  for(const phase of ['continue-created-drain-authorized','drain-helper-start','drain','drain-helper-remove','stop-worker','backup-helper-start','backup-copy','commit-new-pins','recreate-api','verify-retained-data','recreate-web','archive-original','guard-archived']){
    const f=await createdDrainFixture(t);await assert.rejects(f.continueDrain({onReconcileCheckpoint:p=>{if(p===phase)throw Error('PRIVATE');}}),/HOLD/);
    assert(fs.existsSync(join(f.state,'.recover-build-and-redeploy.lock','continue-drain.lock')));assert(fs.existsSync(join(f.state,'.recover-build-and-redeploy.lock','resume.lock')));assert(fs.existsSync(join(f.audit,'failure.json')));assert(fs.existsSync(join(f.audit,'continue-failure.json')));
    const at=f.calls.length;await assert.rejects(f.continueDrain(),/HOLD/);await assert.rejects(f.resume(),/HOLD/);await assert.rejects(f.recover(),/HOLD/);assert(!f.calls.slice(at).some(c=>recoveryMutation(c.args)));assert.equal(fs.readdirSync(join(f.state,'redeployments')).length,1);
  }
});

test('helper diagnostics are fixed and specific; custom DriverConfig is not normalized away',async t=>{
  const f=await createdDrainFixture(t);f.getHelper().HostConfig.Mounts[0].VolumeOptions.DriverConfig={Options:{password:'PRIVATE'}};
  await assert.rejects(f.continueDrain({},true),e=>{assert(e.message.includes('reason=HELPER_VOLUME_NOCOPY_DRIVER'));assert(!e.message.includes('PRIVATE'));assert(!e.message.includes(SECRET));return true;});
});

test('remaining drain backup restore and readiness guards have fixed detailed diagnostics without raw output',async t=>{
  for(const[mode,reason]of [['drain-json','DRAIN_RESULT_JSON'],['drain-shape','DRAIN_RESULT_PROTOCOL'],['backup-json','BACKUP_RESULT_JSON'],['backup-copy','BACKUP_PRIVATE_COPY_HASH'],['new-runtime','NEW_RUNTIME_SECURITY_CONTROLS'],['restored-content','RESTORED_DATA_LOGICAL_FINGERPRINT'],['http','POSTFLIGHT_PUBLIC_HTTP_STATUS']])await t.test(mode,async t=>{
    const f=await createdDrainFixture(t),run=f.recoveryRun;
    if(mode==='backup-copy')f.backups.auth.sha256='0'.repeat(64);
    await assert.rejects(f.continueDrain({request:async()=>({status:mode==='http'?200:401,body:{cancel:async()=>{}}}),run:async(args,options)=>{const text=await run(args,options);
      if(args[0]==='container'&&args[1]==='exec'&&args.at(-1)===isolated.RECOVERY_DRAIN){if(mode==='drain-json')return 'FORBIDDEN_PAYLOAD_9981';if(mode==='drain-shape')return '{"pending":-1,"FORBIDDEN_PAYLOAD_9981":true}';}
      if(mode==='backup-json'&&args[0]==='container'&&args[1]==='exec'&&f.getHelper()?.Config.Labels['org.diplom.recovery-purpose']==='backup')return 'FORBIDDEN_PAYLOAD_9981';
      if(mode==='new-runtime'&&args[0]==='compose'&&args.includes('up')&&args.at(-1)==='worker')f.containers[3].HostConfig.Memory=536870912;
      if(mode==='restored-content'&&args[0]==='container'&&args[1]==='exec'&&args[2]===f.containers[4].Id&&!args.some(a=>a.includes('worker.ready')))return '{"auth":{"logicalSha256":"wrong"},"ledger":{"logicalSha256":"wrong"}}';
      return text;}}),e=>{assert(e.message.includes('reason='+reason),e.message);assert(!e.message.includes('FORBIDDEN_PAYLOAD_9981'));assert(!e.message.includes(SECRET));return true;});
    const failure=JSON.parse(fs.readFileSync(join(f.audit,'continue-failure.json')));assert.equal(failure.reason,reason);
  });
});

test('replacement recovery builds before lifecycle, fences/drains, verifies private backups and redeploys without old-image evidence',async t=>{
  const f=recoveryFixture(t,true),marker=fs.lstatSync(join(f.lock,'mutation.json')),jwt=fs.lstatSync(join(f.state,'scan-jwt'));f.drains=[2,0];
  const result=await f.recover();assert.equal(result.operation,'RECOVERED_REDEPLOY_PRIOR_IMAGES_UNVERIFIED');
  const archive=join(f.state,result.archive),receipt=JSON.parse(fs.readFileSync(join(archive,'result.json')));
  assert.equal(receipt.originalImageMetadataVerified,false);assert.equal(receipt.rollbackToPriorImages,false);assert(receipt.jwtPreserved);
  assert.equal(fs.readFileSync(join(archive,'original-operation.lock/mutation.json'),'utf8'),f.before.marker);
  assert.equal(fs.lstatSync(join(archive,'original-operation.lock/mutation.json')).ino,marker.ino);assert.equal(fs.lstatSync(join(f.state,'scan-jwt')).ino,jwt.ino);
  for(const role of ['auth','ledger']){const path=join(archive,'backups',role+'.sqlite');assert.equal(fs.statSync(path).mode&0o777,0o600);assert.equal(createHash('sha256').update(fs.readFileSync(path)).digest('hex'),receipt.backups[role].sha256);}
  assert(!fs.existsSync(f.lock));assert(!fs.existsSync(join(f.state,'.recover-build-and-redeploy.lock')));assert.deepEqual(f.volumes,f.before.volumes);
  const build=f.calls.findIndex(c=>c.args[0]==='compose'&&c.args.includes('build')),stop=f.calls.findIndex(c=>c.args[1]==='stop'),copy=f.calls.findIndex(c=>c.args.includes(isolated.BACKUP_EXPORT_PROGRAM)&&JSON.parse(c.args.at(-1)).action==='chunk'),up=f.calls.findIndex(c=>c.args[0]==='compose'&&c.args.includes('up'));
  assert(build>=0&&stop>build&&copy>stop&&up>copy);assert.deepEqual(f.calls.filter(c=>c.args[0]==='compose'&&c.args.includes('build')).map(c=>c.args.at(-1)),['egress','worker','api','web']);assert(!f.logs.join('').includes(SECRET));
  await f.launch(['stop'],{run:f.recoveryRun}); // Completed replacement history accepted, fixture-only.
});

test('runtime Mounts ordering is not continuity drift; mount contents and declared order remain guarded',async t=>{
  const f=recoveryFixture(t,true),run=f.recoveryRun;let reads=0;
  await f.recover({run:async(args,options)=>{const value=await run(args,options);
    if(args[0]==='container'&&args[1]==='inspect'&&!args[2].includes('-recovery-')){const rows=JSON.parse(value);if(++reads%2)rows[0].Mounts.reverse();return JSON.stringify(rows);}return value;}});
});

const RESUME = name => ['resume-recover-build-and-redeploy','--ack-pre-lifecycle-only','--audit',name];
async function failedCandidateFixture(t) {
  const f=recoveryFixture(t,true),run=f.recoveryRun;
  await assert.rejects(f.recover({run:async(args,options)=>{const value=await run(args,options);
    if(args[0]==='compose'&&args.includes('config')){const config=JSON.parse(value);config.services.worker.mem_limit='1073741824';return JSON.stringify(config);}return value;}}),/HOLD/);
  const name=fs.readdirSync(join(f.state,'redeployments'))[0],audit=join(f.state,'redeployments',name);
  // Reproduce the preceding launcher's order-sensitive hash, not a relaxed expected profile.
  const stable=v=>Array.isArray(v)?v.map(stable):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])])):v;
  const baseline=JSON.parse(fs.readFileSync(join(audit,'baseline.json')));
  for(const c of f.containers){const role=c.Config.Labels['com.docker.compose.service'],Config=structuredClone(c.Config);Config.Env=Config.Env.filter(v=>!v.startsWith('SCAN_JWT_SECRET='));
    baseline.containers[role].controlSha256=createHash('sha256').update(JSON.stringify(stable({Config,HostConfig:c.HostConfig,Mounts:[...c.Mounts].reverse()}))).digest('hex');}
  fs.writeFileSync(join(audit,'baseline.json'),JSON.stringify(baseline));
  f.resumeName=name;f.audit=audit;
  f.resume=extra=>f.launch(RESUME(name),{run:f.recoveryRun,sleep:async()=>{},request:async()=>({status:401,body:{cancel:async()=>{}}}),...extra});
  return f;
}

test('explicit pre-lifecycle resume reuses the single failed audit and completed pins without build/pull or rewriting failure',async t=>{
  const f=await failedCandidateFixture(t),names=fs.readdirSync(f.audit),old=Object.fromEntries(names.filter(n=>n!=='backups').map(n=>[n,{bytes:fs.readFileSync(join(f.audit,n)),ino:fs.statSync(join(f.audit,n)).ino}])),before=f.calls.length;
  const result=await f.resume();assert.equal(result.archive,'redeployments/'+f.resumeName);
  assert.equal(fs.readdirSync(join(f.state,'redeployments')).length,1);
  for(const [n,v]of Object.entries(old)){assert.deepEqual(fs.readFileSync(join(f.audit,n)),v.bytes);assert.equal(fs.statSync(join(f.audit,n)).ino,v.ino);}
  assert(!f.calls.slice(before).some(c=>c.args.includes('build')||c.args.includes('pull')));
  assert(fs.existsSync(join(f.audit,'resume.json')));assert(fs.existsSync(join(f.audit,'completion.json')));
  await f.launch(['stop'],{run:f.recoveryRun});
});

const recoveryMutation = args => args[0]==='create'||args[0]==='run'||args[0]==='cp'||args[0]==='container'&&['stop','start','rm','exec'].includes(args[1])||args[0]==='compose'&&(args.includes('up')||args.includes('build'))||args[0]==='image'&&args[1]==='pull';

test('pre-lifecycle resume refuses altered evidence, controls, namespace, pins, endpoint and image authority without mutation',async t=>{
  const changes={
    'later-phase':f=>fs.writeFileSync(join(f.audit,'phase-007.json'),JSON.stringify({version:1,phase:'stop-web',at:new Date().toISOString()}),{mode:0o600}),
    'start-record':f=>fs.writeFileSync(join(f.audit,'start-submission.json'),'{}',{mode:0o600}),
    'missing-phase':f=>fs.unlinkSync(join(f.audit,'phase-005.json')),
    'wrong-checkpoint':f=>{const p=join(f.audit,'failure.json'),v=JSON.parse(fs.readFileSync(p));v.checkpoint='stop-web';fs.writeFileSync(p,JSON.stringify(v));},
    'partial-backups':f=>fs.writeFileSync(join(f.audit,'backups','auth.sqlite'),'not-a-backup',{mode:0o600}),
    'guard-extra':f=>fs.writeFileSync(join(f.state,'.recover-build-and-redeploy.lock','unknown.json'),'{}',{mode:0o600}),
    'partial-resume':f=>fs.mkdirSync(join(f.state,'.recover-build-and-redeploy.lock','resume.lock'),{mode:0o700}),
    'intent':f=>{const p=join(f.audit,'intent.json'),v=JSON.parse(fs.readFileSync(p));v.endpoint='unix:///elsewhere.sock';fs.writeFileSync(p,JSON.stringify(v));},
    'container-id':f=>{f.containers[4].Id='1'.repeat(64);},
    'process':f=>{f.containers[4].RestartCount++;},
    'volume':f=>{f.volumes[0].CreatedAt='2026-10-19T00:00:00Z';},
    'network':f=>{f.networks[0].Id='d'.repeat(64);},
    'mount-content':f=>{f.containers[4].Mounts.find(m=>m.Destination==='/auth').Name=PROJECT+'_scan_ledger';},
    'mount-field':f=>{f.containers[4].Mounts.find(m=>m.Destination==='/auth').Source='/changed/engine/path';},
    'declared-mount-order':f=>{f.containers[4].HostConfig.Mounts.reverse();},
    'runtime-env':f=>{f.containers[4].Config.Env.push('NODE_OPTIONS=--require=unsafe');},
    'jwt':f=>fs.writeFileSync(join(f.state,'scan-jwt'),'cd'.repeat(48)),
    'profile':f=>{const p=join(f.state,'profile.json');fs.writeFileSync(p,JSON.stringify({version:1,project:PROJECT,cve:null}));},
    'saved-pins':f=>{const p=join(f.state,'compose.images.json'),v=JSON.parse(fs.readFileSync(p));v.services.api.image=f.fresh.api.Id;fs.writeFileSync(p,JSON.stringify(v));},
    'candidate-pins':f=>{const p=join(f.audit,'candidate.images.json'),v=JSON.parse(fs.readFileSync(p));v.services.api.image=v.services.worker.image;fs.writeFileSync(p,JSON.stringify(v));},
    'tag-retarget':f=>{f.images.set(PROJECT+'-api:local',f.fresh.worker);},
    'image-hook':f=>{f.fresh.api.Config.OnBuild=['RUN unsafe'];},
    'foreign-reference':f=>{f.fresh.api.RepoTags.push('foreign:latest');},
    'foreign-consumer':f=>{f.foreignWriter='foreign-id';},
    'dockerfile':f=>fs.appendFileSync(join(f.root,'server/deploy/api.Dockerfile'),'\n# changed after build\n'),
  };
  for(const [name,change]of Object.entries(changes))await t.test(name,async t=>{
    const f=await failedCandidateFixture(t),marker=fs.readFileSync(join(f.lock,'mutation.json')),failure=fs.readFileSync(join(f.audit,'failure.json'));change(f);const at=f.calls.length;
    await assert.rejects(f.resume(),/HOLD/);assert(!f.calls.slice(at).some(c=>recoveryMutation(c.args)),name);
    assert.deepEqual(fs.readFileSync(join(f.lock,'mutation.json')),marker);if(name!=='wrong-checkpoint')assert.deepEqual(fs.readFileSync(join(f.audit,'failure.json')),failure);
    assert.equal(fs.readdirSync(join(f.state,'redeployments')).length,1);
  });
  const f=await failedCandidateFixture(t),at=f.calls.length;await assert.rejects(f.resume({ambient:{DOCKER_HOST:'unix:///other.sock'}}),/HOLD/);assert(!f.calls.slice(at).some(c=>recoveryMutation(c.args)));
});

test('resume is explicit, identity-fenced, crash-sticky and cannot loop or create a fresh audit',async t=>{
  for(const flags of [[],['--force'],['--ack-pre-lifecycle-only'],['--ack-pre-lifecycle-only','--audit','../escape']]){
    const f=fixture(t);await assert.rejects(f.launch(['resume-recover-build-and-redeploy',...flags]),/Usage/);assert.equal(f.calls.length,0);assert(!fs.existsSync(f.state));}
  for(const phase of ['resume-authorized','stop-web','drain-helper-submission','backup-copy','guard-archived']){
    const f=await failedCandidateFixture(t);await assert.rejects(f.resume({onReconcileCheckpoint:value=>{if(value===phase)throw Error('private-synthetic');}}),/HOLD/);
    const at=f.calls.length;await assert.rejects(f.resume(),/HOLD/);await assert.rejects(f.recover(),/HOLD/);await assert.rejects(f.launch(['up']),/HOLD/);
    assert(!f.calls.slice(at).some(c=>recoveryMutation(c.args)));assert.equal(fs.readdirSync(join(f.state,'redeployments')).length,1);
    assert(fs.existsSync(join(f.audit,'failure.json')));assert(fs.existsSync(join(f.state,'.recover-build-and-redeploy.lock')));
  }
  const f=await failedCandidateFixture(t),run=f.recoveryRun;let replaced=false;
  await assert.rejects(f.resume({run:async(args,options)=>{const value=await run(args,options);
    if(!replaced&&args[0]==='image'&&args[1]==='inspect'){replaced=true;const p=join(f.audit,'baseline.json'),b=fs.readFileSync(p);fs.renameSync(p,p+'.old');fs.writeFileSync(p,b,{mode:0o600});fs.unlinkSync(p+'.old');}return value;}}),/HOLD/);
  assert(!f.calls.some(c=>c.args[0]==='container'&&['stop','start','exec'].includes(c.args[1])));
});

test('resume receipt/history corruption and in-flight own JWT identity replacement stay HOLD',async t=>{
  for(const mode of ['receipt','original-failure','missing-completion']){
    const f=await failedCandidateFixture(t);await f.resume();const p=join(f.audit,mode==='receipt'?'resume.json':mode==='original-failure'?'failure.json':'completion.json');
    if(mode==='missing-completion')fs.unlinkSync(p);else fs.appendFileSync(p,' ');
    const at=f.calls.length;await assert.rejects(f.launch(['stop'],{run:f.recoveryRun}),/HOLD/);assert.equal(f.calls.length,at);
  }
  const f=await failedCandidateFixture(t);
  await assert.rejects(f.resume({onReconcileCheckpoint:phase=>{if(phase!=='resume-authorized')return;const p=join(f.state,'scan-jwt'),b=fs.readFileSync(p);fs.renameSync(p,p+'.old');fs.writeFileSync(p,b,{mode:0o600});fs.unlinkSync(p+'.old');}}),/HOLD/);
  assert(!f.calls.some(c=>c.args[0]==='container'&&['stop','start','exec'].includes(c.args[1])));
  assert(fs.existsSync(join(f.audit,'failure.json')));assert(fs.existsSync(join(f.state,'.recover-build-and-redeploy.lock','resume.lock')));
});

test('recovery reports fixed sanitized subreasons, never raw Docker/errors/env',async t=>{
  const f=recoveryFixture(t),run=f.recoveryRun;
  await assert.rejects(f.recover({run:async(args,options)=>{const text=await run(args,options);if(args[0]==='compose'&&args.includes('config')){const c=JSON.parse(text);c.services.worker.mem_limit='1';return JSON.stringify(c);}return text;}}),e=>{assert(e.message.includes('reason=CANDIDATE_PROFILE_REFUSED'));assert(!e.message.includes(SECRET));return true;});
});

test('replacement recovery is explicit and refuses other phases/start evidence/unsafe runtime before any build or lifecycle',async t=>{
  for(const argv of [['recover-build-and-redeploy'],['recover-build-and-redeploy','--force'],[...REDEPLOY,'--build']]){
    const f=fixture(t);await assert.rejects(f.launch(argv),/Usage/);assert.equal(f.calls.length,0);assert(!fs.existsSync(f.state));}
  for(const change of [
    f=>fs.writeFileSync(join(f.lock,'start-submission.json'),'{}',{mode:0o600}),
    f=>{const p=join(f.lock,'mutation.json'),m=JSON.parse(fs.readFileSync(p));m.phase='start-outcome-unconfirmed';fs.writeFileSync(p,JSON.stringify(m));},
    f=>{const p=join(f.lock,'mutation.json'),m=JSON.parse(fs.readFileSync(p));delete m.endpoint;fs.writeFileSync(p,JSON.stringify(m));},
    f=>{f.containers[4].Config.Env.push('NODE_OPTIONS=--require=unsafe');},f=>{f.containers[4].Config.Entrypoint=['unsafe'];},
    f=>{f.containers[4].Config.Env=f.containers[4].Config.Env.map(v=>v.startsWith('SCAN_JWT_SECRET=')?'SCAN_JWT_SECRET='+('cd'.repeat(48)):v);},
    f=>{f.containers[3].HostConfig.Memory=1073741824;},f=>{f.containers[3].HostConfig.Tmpfs['/tmp/trivy']='rw,size=512m';},
    f=>{f.containers[4].Config.Image=PROJECT+'-api:local';},f=>{f.containers[4].Config.Shell=['unsafe'];},f=>{f.foreignWriter='foreign-container';},
    f=>{f.networks[0].Containers.foreign={};},f=>{f.containers[4].State.Health.Status='unhealthy';},
  ]){const f=recoveryFixture(t);change(f);await assert.rejects(f.recover(),/HOLD/);assert(fs.existsSync(join(f.lock,'mutation.json')));
    assert(!f.calls.some(c=>c.args[0]==='run'||c.args.includes('build')||c.args.includes('stop')||c.args.includes('up')));}
});

test('replacement build failure and rejected fresh image keep old stand running with durable baseline and failure stage',async t=>{
  for(const mode of ['build-error','image-hook','config-resource']){
    const f=recoveryFixture(t),run=f.recoveryRun;
    await assert.rejects(f.recover({run:async(args,options)=>{
      if(mode==='build-error'&&args[0]==='compose'&&args.includes('build')){f.calls.push({args,options});throw Error('PRIVATE-FAILURE');}
      const result=await run(args,options);
      if(mode==='image-hook'&&args[0]==='compose'&&args.includes('build'))f.fresh.api.Config.Env.push('NODE_OPTIONS=unsafe');
      if(mode==='config-resource'&&args[0]==='compose'&&args.includes('config')){const c=JSON.parse(result);c.services.worker.mem_limit='1073741824';return JSON.stringify(c);}return result;
    }}),/HOLD/);
    assert.deepEqual(f.containers,f.before.containers);assert.equal(fs.readFileSync(join(f.lock,'mutation.json'),'utf8'),f.before.marker);
    assert(fs.existsSync(join(f.state,'.recover-build-and-redeploy.lock')));const path=join(f.state,'redeployments'),audit=join(path,fs.readdirSync(path)[0]);
    assert(fs.existsSync(join(audit,'baseline.json')));assert(fs.existsSync(join(audit,'failure.json')));assert(!fs.readFileSync(join(audit,'baseline.json'),'utf8').includes(SECRET));
    assert(!f.calls.some(c=>c.args.includes('stop')||c.args.includes('up')));const calls=f.calls.length;await assert.rejects(f.launch(['up']),/HOLD/);assert.equal(f.calls.length,calls);
  }
});

test('replacement guards pin endpoint and detect own state, CVE, source and Dockerfile identity drift before lifecycle',async t=>{
  for(const target of ['jwt','profile','pins','cve','source','dockerfile','container','network']){
    const f=recoveryFixture(t,target==='cve');await assert.rejects(f.recover({onReconcileCheckpoint:phase=>{
      if(phase!=='new-image-validation')return;
      if(target==='container'){f.containers[4].RestartCount++;return;}if(target==='network'){f.networks[0].Id='c'.repeat(64);return;}
      const path=target==='jwt'?join(f.state,'scan-jwt'):target==='profile'?join(f.state,'profile.json'):target==='pins'?join(f.state,'compose.images.json'):
        target==='cve'?f.cve.publicKeyPath:target==='source'?join(f.root,'server/deploy/compose.public-images.yaml'):join(f.root,'server/deploy/stand.Dockerfile');
      const bytes=fs.readFileSync(path),mode=fs.lstatSync(path).mode&0o777;fs.renameSync(path,path+'.old');fs.writeFileSync(path,bytes,{mode});fs.unlinkSync(path+'.old');
    }}),/HOLD/);assert(!f.calls.some(c=>c.args.includes('stop')||c.args.includes('up')));}
  const f=recoveryFixture(t);await assert.rejects(f.recover({ambient:{DOCKER_HOST:'unix:///different.sock'}}),/HOLD/);assert.equal(f.calls.length,0);
});

test('replacement fast-terminates stateless web/SSE but requires writer exit 0 and keeps gateway live through backups',async t=>{
  const f=recoveryFixture(t),run=f.recoveryRun;await f.recover({run:async(args,options)=>{const result=await run(args,options);
    if(args[0]==='container'&&args[1]==='stop')for(const c of f.containers.filter(c=>args.includes(c.Id))){const role=c.Config.Labels['com.docker.compose.service'];if(role==='web')c.State.ExitCode=143;if(role==='web')assert.deepEqual(args.slice(2,4),['--signal','SIGTERM']);assert.notEqual(role,'egress');}
    return result;}});
  const bad=recoveryFixture(t),base=bad.recoveryRun;await assert.rejects(bad.recover({run:async(args,options)=>{const result=await base(args,options);
    if(args[1]==='stop'&&args.includes(bad.before.containers[4].Id))bad.containers[4].State.ExitCode=143;return result;}}),/HOLD/);
  assert(!bad.calls.some(c=>c.args[0]==='run'||c.args.includes('up')));
});

test('replacement drain/shutdown refusal stays HOLD without backup, recreate or automatic resume',async t=>{
  for(const mode of ['drain-invalid','stop-137','foreign-writer']){
    const f=recoveryFixture(t),run=f.recoveryRun;
    await assert.rejects(f.recover({run:async(args,options)=>{
      const result=await run(args,options);
      if(mode==='drain-invalid'&&args[0]==='container'&&args[1]==='exec'&&args.at(-1)===isolated.RECOVERY_DRAIN)return '{"pending":-1}';
      if(mode==='stop-137'&&args[1]==='stop')f.containers.find(c=>args.includes(c.Id)).State.ExitCode=137;
      if(mode==='foreign-writer'&&args[0]==='container'&&args[1]==='ls'&&args.includes('--filter')&&!args.includes('--all'))return 'foreign-writer';
      return result;
    }}),/HOLD/);assert(!f.calls.some(c=>c.args[0]==='run'||c.args.includes('up')||c.args[1]==='start'&&f.before.containers.some(old=>c.args.includes(old.Id))));assert(fs.existsSync(f.lock));
    assert.equal(fs.readFileSync(join(f.state,'compose.images.json'),'utf8'),JSON.stringify(f.before.pins));
  }
});

test('replacement backup helper/copy/integrity failures never execute new services',async t=>{
  for(const mode of ['helper-privileged','helper-copy-up','backup-hash','backup-mode','backup-corrupt']){
    const f=recoveryFixture(t),run=f.recoveryRun;
    await assert.rejects(f.recover({run:async(args,options)=>{
      const result=await run(args,options);
      if((mode==='helper-privileged'||mode==='helper-copy-up')&&args[1]==='inspect'&&args[2].includes('-recovery-')){const rows=JSON.parse(result);if(mode==='helper-privileged')rows[0].HostConfig.PidMode='host';else rows[0].HostConfig.Mounts[0].VolumeOptions.NoCopy=false;return JSON.stringify(rows);}
      if(mode==='backup-hash'&&args[0]==='create'&&args.includes('org.diplom.recovery-purpose=backup'))f.backups.auth.sha256='0'.repeat(64);
      if(args.includes(isolated.BACKUP_EXPORT_PROGRAM)&&JSON.parse(args.at(-1)).action==='chunk'){
        if(mode==='backup-mode')fs.chmodSync(join(f.state,'redeployments',fs.readdirSync(join(f.state,'redeployments'))[0],'backups','.auth.sqlite.exporting'),0o644);
        if(mode==='backup-corrupt'){const v=JSON.parse(result);v.data=Buffer.alloc(Buffer.from(v.data,'base64').length,0).toString('base64');return JSON.stringify(v);}}
      return result;
    }}),/HOLD/);assert(!f.calls.some(c=>c.args[0]==='compose'&&c.args.includes('up')));assert(fs.existsSync(f.lock));
    assert.equal(fs.readFileSync(join(f.state,'compose.images.json'),'utf8'),JSON.stringify(f.before.pins));}
});

test('replacement changed database contents before reopening web stay HOLD with verified backups retained',async t=>{
  const f=recoveryFixture(t),run=f.recoveryRun;
  await assert.rejects(f.recover({run:async(args,options)=>{const result=await run(args,options);
    if(args[0]==='container'&&args[1]==='exec'&&args.at(-1).includes('const core=')&&!args[2].includes('f'.repeat(64))){const b=JSON.parse(result);b.auth.logicalSha256='0'.repeat(64);return JSON.stringify(b);}return result;}}),/checkpoint=verify-retained-data/);
  assert(!f.calls.some(c=>c.args[0]==='compose'&&c.args.includes('up')&&c.args.at(-1)==='web'));assert(fs.existsSync(f.lock));
  const path=join(f.state,'redeployments'),audit=join(path,fs.readdirSync(path)[0]);assert(fs.existsSync(join(audit,'backups/auth.sqlite')));
});

test('replacement interruption fences preserve original failure and block ordinary up at every mutation boundary',async t=>{
  for(const point of ['build-submission','stop-web','stop-api','drain-helper-submission','drain-helper-start','drain','drain-helper-stop','drain-helper-remove','stop-worker','writers-quiescent','backup-helper-submission','backup-helper-start','backup-copy','commit-new-pins','recreate-egress','recreate-worker','recreate-api','verify-retained-data','recreate-web','archive-original','guard-archived']){
    const f=recoveryFixture(t);await assert.rejects(f.recover({onReconcileCheckpoint:phase=>{if(phase===point)throw Error('synthetic-interruption');}}),/HOLD/);
    const path=join(f.state,'redeployments'),audit=join(path,fs.readdirSync(path)[0]),original=fs.existsSync(f.lock)?f.lock:join(audit,'original-operation.lock');
    assert.equal(fs.readFileSync(join(original,'mutation.json'),'utf8'),f.before.marker);assert(fs.existsSync(join(f.state,'.recover-build-and-redeploy.lock')));
    const calls=f.calls.length;await assert.rejects(f.launch(['up']),/HOLD/);await assert.rejects(f.launch(['stop']),/HOLD/);assert.equal(f.calls.length,calls);
  }
});

test('replacement completed audit, backup bytes and original marker identity cannot be tampered to admit ordinary lifecycle',async t=>{
  for(const mode of ['backup','phase','result','marker-inode','completion-missing']){
    const f=recoveryFixture(t),r=await f.recover(),audit=join(f.state,r.archive);
    if(mode==='backup')fs.appendFileSync(join(audit,'backups/auth.sqlite'),'x');
    if(mode==='phase')fs.unlinkSync(join(audit,fs.readdirSync(audit).find(n=>n.startsWith('phase-'))));
    if(mode==='result')fs.appendFileSync(join(audit,'result.json'),'\n');
    if(mode==='completion-missing')fs.unlinkSync(join(audit,'completion.json'));
    if(mode==='marker-inode'){const p=join(audit,'original-operation.lock/mutation.json'),bytes=fs.readFileSync(p);fs.renameSync(p,p+'.old');fs.writeFileSync(p,bytes,{mode:0o600});fs.unlinkSync(p+'.old');}
    const calls=f.calls.length;await assert.rejects(f.launch(['up']),/HOLD/);assert.equal(f.calls.length,calls);
  }
});

test('future build failure records durable exact prebuild baseline and recovery uses it without ordinary up inspecting missing images',async t=>{
  const f=recoveryFixture(t,false,false);fs.unlinkSync(join(f.lock,'mutation.json'));fs.rmdirSync(f.lock);
  await assert.rejects(f.launch(['up','--build'],{run:async(args,options)=>{if(args[0]==='compose'&&args.includes('build'))throw Error('failed web');return f.run(args,options);}}),/checkpoint=build/);
  const evidence=JSON.parse(fs.readFileSync(join(f.lock,'build-evidence.json'))),failure=JSON.parse(fs.readFileSync(join(f.lock,'build-failure.json')));
  assert.equal(failure.checkpoint,'build');assert.equal(evidence.baseline.containers.length,6);assert(!JSON.stringify(evidence).includes(SECRET));
  for(const role of ['egress','worker','api','web'])f.images.delete(f.before.pins.services[role].image);
  const r=await f.recover();assert(fs.existsSync(join(f.state,r.archive,'original-operation.lock/build-failure.json')));
});

test('completed replacement receipt is not rolled back if console delivery fails',async t=>{
  const f=recoveryFixture(t);await assert.rejects(f.recover({log:()=>{throw Error('synthetic-output-failure');}}),/committed; output unavailable/);
  assert(!fs.existsSync(f.lock));assert(!fs.existsSync(join(f.state,'.recover-build-and-redeploy.lock')));
  const path=join(f.state,'redeployments'),audit=join(path,fs.readdirSync(path)[0]);assert(fs.existsSync(join(audit,'completion.json')));assert(!fs.existsSync(join(audit,'failure.json')));
  await f.launch(['stop'],{run:f.recoveryRun});
});

test('SQLite recovery core includes committed WAL, checks integrity and preserves accounts, sessions, reports and sequences',async t=>{
  const DB=createRequire(new URL('../server/api/package.json',import.meta.url))('better-sqlite3'),f=fixture(t),out=join(f.root,'backup');fs.mkdirSync(out,{mode:0o700});
  const auth=join(f.root,'auth.sqlite'),ledger=join(f.root,'ledger.sqlite'),a=new DB(auth),l=new DB(ledger);t.after(()=>{a.close();l.close();});
  a.pragma('journal_mode=WAL');l.pragma('journal_mode=WAL');
  a.exec("CREATE TABLE users(id TEXT PRIMARY KEY,password_hash BLOB);CREATE TABLE sessions(id TEXT,user_id TEXT REFERENCES users(id));CREATE TABLE trusted_sessions(id TEXT);CREATE TABLE browser_access(id TEXT);CREATE TABLE auth_attempts(id TEXT);INSERT INTO users VALUES('owner',x'abcdef');INSERT INTO sessions VALUES('session','owner');");
  l.exec("CREATE TABLE scans(id TEXT PRIMARY KEY,state TEXT);CREATE TABLE outbox(scan_id TEXT,delivered_at TEXT);CREATE TABLE scan_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,body TEXT);INSERT INTO scans VALUES('report','completed');INSERT INTO outbox VALUES('report','done');INSERT INTO scan_events(body) VALUES('retained report');PRAGMA user_version=15;");
  const crypto=await import('node:crypto');const report=await isolated.recoverySqlite(DB,fs,crypto,{auth,ledger},out,{quiescent:true});
  for(const[r,path]of [['auth',auth],['ledger',ledger]]){assert.equal(report[r].integrity,'ok');assert.equal(fs.statSync(join(out,r+'.sqlite')).mode&0o777,0o600);const copy=new DB(join(out,r+'.sqlite'));try{assert.equal(copy.pragma('integrity_check',{simple:true}),'ok');if(r==='auth')assert.deepEqual(copy.prepare('select * from users').get().password_hash,Buffer.from('abcdef','hex'));else assert.equal(copy.prepare('select body from scan_events').get().body,'retained report');}finally{copy.close();}}
  assert.deepEqual(await isolated.recoverySqlite(DB,fs,crypto,{auth,ledger},null),Object.fromEntries(Object.entries(report).map(([r,b])=>[r,{logicalSha256:b.logicalSha256}])));
  l.prepare("UPDATE outbox SET delivered_at=NULL").run();await assert.rejects(isolated.recoverySqlite(DB,fs,crypto,{auth,ledger},null),/SQLITE_RECOVERY_REFUSED/);
    l.prepare("UPDATE outbox SET delivered_at='done'").run();l.pragma('user_version=14');await assert.rejects(isolated.recoverySqlite(DB,fs,crypto,{auth,ledger},null),/SQLITE_RECOVERY_REFUSED/);
    l.pragma('user_version=15');a.pragma('foreign_keys=OFF');a.exec("INSERT INTO sessions VALUES('orphan','missing-owner')");await assert.rejects(isolated.recoverySqlite(DB,fs,crypto,{auth,ledger},null),/SQLITE_RECOVERY_REFUSED/);
});

function sqliteReviewFixture(t) {
  const DB=createRequire(new URL('../server/api/package.json',import.meta.url))('better-sqlite3'),f=fixture(t);
  const source=join(f.root,'sources'),output=join(f.root,'snapshots');fs.mkdirSync(source,{mode:0o700});fs.mkdirSync(output,{mode:0o700});
  const auth=join(source,'auth.sqlite'),ledger=join(source,'ledger.sqlite'),a=new DB(auth),l=new DB(ledger);
  a.pragma('journal_mode=WAL');l.pragma('journal_mode=WAL');
  a.exec("CREATE TABLE users(id TEXT PRIMARY KEY,password_hash BLOB);CREATE TABLE sessions(id TEXT,user_id TEXT REFERENCES users(id));CREATE TABLE trusted_sessions(id TEXT);CREATE TABLE browser_access(id TEXT);CREATE TABLE auth_attempts(id TEXT);INSERT INTO users VALUES('owner',x'abcdef');INSERT INTO sessions VALUES('session','owner');");
  l.exec("CREATE TABLE scans(id TEXT PRIMARY KEY,state TEXT);CREATE TABLE outbox(scan_id TEXT,delivered_at TEXT);CREATE TABLE scan_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,body TEXT);INSERT INTO scans VALUES('report','completed');INSERT INTO outbox VALUES('report','done');INSERT INTO scan_events(body) VALUES('retained report');PRAGMA user_version=15;");
  return {...f,DB,source,output,auth,ledger,a,l};
}

test('RR1 cleanly closed WAL sources without sidecars back up from nonwritable directories without source changes',async t=>{
  const f=sqliteReviewFixture(t);f.a.close();f.l.close();assert.deepEqual(fs.readdirSync(f.source).sort(),['auth.sqlite','ledger.sqlite']);
  for(const p of [f.auth,f.ledger])fs.chmodSync(p,0o400);fs.chmodSync(f.source,0o500);
  const before=Object.fromEntries([f.auth,f.ledger].map(p=>[p,{stat:fs.statSync(p),bytes:fs.readFileSync(p)}]));
  const crypto=await import('node:crypto'),r=await isolated.recoverySqlite(f.DB,fs,crypto,{auth:f.auth,ledger:f.ledger},f.output,{quiescent:true});
  assert.equal(r.auth.integrity,'ok');assert.equal(r.ledger.integrity,'ok');assert.deepEqual(fs.readdirSync(f.source).sort(),['auth.sqlite','ledger.sqlite']);
  for(const p of [f.auth,f.ledger]){assert.deepEqual(fs.readFileSync(p),before[p].bytes);assert.equal(fs.statSync(p).mtimeMs,before[p].stat.mtimeMs);assert.equal(fs.statSync(p).mode&0o777,0o400);}
  for(const role of ['auth','ledger']){const db=new f.DB(join(f.output,role+'.sqlite'));try{assert.equal(db.pragma('integrity_check',{simple:true}),'ok');if(role==='auth')assert.equal(db.prepare('SELECT id FROM users').get().id,'owner');else assert.equal(db.prepare('SELECT body FROM scan_events').get().body,'retained report');}finally{db.close();}}
});

test('RDEP3 fingerprints distinguish adjacent 64-bit INTEGER values and sqlite_sequence beyond 2^53',async t=>{
  const f=sqliteReviewFixture(t),crypto=await import('node:crypto');try{
    f.l.exec('CREATE TABLE precise_values(v)');f.l.prepare('INSERT INTO precise_values VALUES(?)').run(9007199254740992n);
    const one=await isolated.recoverySqlite(f.DB,fs,crypto,{auth:f.auth,ledger:f.ledger},null);
    f.l.prepare('UPDATE precise_values SET v=?').run(9007199254740993n);
    const two=await isolated.recoverySqlite(f.DB,fs,crypto,{auth:f.auth,ledger:f.ledger},null);assert.notEqual(one.ledger.logicalSha256,two.ledger.logicalSha256);
    f.l.prepare('UPDATE sqlite_sequence SET seq=? WHERE name=?').run(9007199254740992n,'scan_events');
    const seq1=await isolated.recoverySqlite(f.DB,fs,crypto,{auth:f.auth,ledger:f.ledger},null);
    f.l.prepare('UPDATE sqlite_sequence SET seq=? WHERE name=?').run(9007199254740993n,'scan_events');
    const seq2=await isolated.recoverySqlite(f.DB,fs,crypto,{auth:f.auth,ledger:f.ledger},null);assert.notEqual(seq1.ledger.logicalSha256,seq2.ledger.logicalSha256);
  }finally{f.a.close();f.l.close();}
});

test('RDEP1 drain never executes or accepts forged output from an unavailable prior application image',async t=>{
  const f=recoveryFixture(t),run=f.recoveryRun,oldIds=f.before.containers.map(c=>c.Id);let oldExec=0;
  await f.recover({run:async(args,options)=>{if(args[0]==='container'&&args[1]==='exec'&&oldIds.includes(args[2])){oldExec++;return '{"pending":0}';}return run(args,options);}});
  assert.equal(oldExec,0);
});

test('RDEP2 rejected helper controls result in zero helper start or run submissions',async t=>{
  const f=recoveryFixture(t),run=f.recoveryRun;let starts=0;
  await assert.rejects(f.recover({run:async(args,options)=>{if(args[0]==='run'||args[0]==='container'&&args[1]==='start')starts++;
    const value=await run(args,options);if(args[1]==='inspect'&&args[2].includes('-recovery-')){const rows=JSON.parse(value);rows[0].HostConfig.PidMode='host';return JSON.stringify(rows);}return value;}}),/HOLD/);
  assert.equal(starts,0);
});

test('RR1 committed WAL frames survive an abruptly terminated writer and restore as standalone snapshots with exact 64-bit sequences',async t=>{
  const f=sqliteReviewFixture(t);f.a.close();f.l.close();
  const program="const {createRequire}=require('node:module');const DB=createRequire(process.argv[1])('better-sqlite3');const a=new DB(process.argv[2]),l=new DB(process.argv[3]);a.pragma('wal_autocheckpoint=0');l.pragma('wal_autocheckpoint=0');a.exec(\"INSERT INTO users VALUES('wal-owner',x'1234');INSERT INTO sessions VALUES('wal-session','wal-owner');\");l.exec(\"INSERT INTO scans VALUES('wal-report','completed');INSERT INTO outbox VALUES('wal-report','done');INSERT INTO scan_events(body) VALUES('committed WAL report');\");l.prepare(\"UPDATE sqlite_sequence SET seq=? WHERE name='scan_events'\").run(9007199254740993n);process.kill(process.pid,'SIGKILL');";
  const child=spawnSync(process.execPath,['-e',program,join(ROOT,'server/api/package.json'),f.auth,f.ledger],{env:{PATH:'/usr/bin:/bin'},timeout:10000,encoding:'utf8'});assert.equal(child.signal,'SIGKILL');
  assert(fs.statSync(f.auth+'-wal').size>0&&fs.statSync(f.ledger+'-wal').size>0);
  const names=fs.readdirSync(f.source).sort(),original=Object.fromEntries(names.map(n=>[n,fs.readFileSync(join(f.source,n))]));
  for(const n of names)fs.chmodSync(join(f.source,n),0o400);fs.chmodSync(f.source,0o500);
  const crypto=await import('node:crypto'),r=await isolated.recoverySqlite(f.DB,fs,crypto,{auth:f.auth,ledger:f.ledger},f.output,{quiescent:true});
  const restore=join(f.root,'restore');fs.mkdirSync(restore,{mode:0o700});for(const role of ['auth','ledger'])fs.copyFileSync(join(f.output,role+'.sqlite'),join(restore,role+'.sqlite'));
  const a=new f.DB(join(restore,'auth.sqlite')),l=new f.DB(join(restore,'ledger.sqlite'));try{
    assert.equal(a.prepare("SELECT user_id FROM sessions WHERE id='wal-session'").get().user_id,'wal-owner');assert.deepEqual(a.prepare("SELECT password_hash FROM users WHERE id='wal-owner'").get().password_hash,Buffer.from('1234','hex'));
    assert.equal(l.prepare("SELECT body FROM scan_events ORDER BY seq DESC LIMIT 1").get().body,'committed WAL report');assert.equal(l.prepare("SELECT seq FROM sqlite_sequence WHERE name='scan_events'").safeIntegers(true).get().seq,9007199254740993n);
  }finally{a.close();l.close();}
  const restored=await isolated.recoverySqlite(f.DB,fs,crypto,{auth:join(restore,'auth.sqlite'),ledger:join(restore,'ledger.sqlite')},null);
  assert.equal(restored.auth.logicalSha256,r.auth.logicalSha256);assert.equal(restored.ledger.logicalSha256,r.ledger.logicalSha256);
  assert.deepEqual(fs.readdirSync(f.source).sort(),names);for(const n of names){assert.deepEqual(fs.readFileSync(join(f.source,n)),original[n]);assert.equal(fs.statSync(join(f.source,n)).mode&0o777,0o400);}
});

test('RR1 source byte/identity drift fails closed, pending probes retry, and partial backup failure does not write sources',async t=>{
  const f=fixture(t),source=join(f.root,'source.bytes'),scratch=join(f.root,'private-copy');fs.writeFileSync(source,'abc');let changed=false;
  const io={...fs,writeSync:(...args)=>{const n=fs.writeSync(...args);if(!changed){changed=true;fs.writeFileSync(source,'xyz');}return n;}};
  assert.throws(()=>isolated.copyStableSqlite(io,createRequire(import.meta.url)('node:crypto'),source,scratch),e=>e.code==='SQLITE_SOURCE_CHANGED');assert(!fs.existsSync(scratch));
  const g=sqliteReviewFixture(t);g.l.pragma('user_version=14');g.a.close();g.l.close();const before=[fs.readFileSync(g.auth),fs.readFileSync(g.ledger)];
  for(const p of [g.auth,g.ledger])fs.chmodSync(p,0o400);fs.chmodSync(g.source,0o500);
  await assert.rejects(isolated.recoverySqlite(g.DB,fs,await import('node:crypto'),{auth:g.auth,ledger:g.ledger},g.output,{quiescent:true}),/SQLITE_RECOVERY_REFUSED/);
  assert(fs.existsSync(join(g.output,'auth.sqlite')));assert.deepEqual(fs.readFileSync(g.auth),before[0]);assert.deepEqual(fs.readFileSync(g.ledger),before[1]);assert.deepEqual(fs.readdirSync(g.source).sort(),['auth.sqlite','ledger.sqlite']);
  const r=recoveryFixture(t);r.drains=['retry',1,0];await r.recover();assert.equal(r.calls.filter(c=>c.args.at(-1)===isolated.RECOVERY_DRAIN).length,3);
});

test('RDEP2 both helper purposes are created stopped and inspected before exact-ID start or SQLite execution',async t=>{
  const f=recoveryFixture(t);await f.recover();assert(!f.calls.some(c=>c.args[0]==='run'));
  for(const purpose of ['drain','backup']){const events=f.helperLifecycle.filter(e=>e.purpose===purpose),start=events.findIndex(e=>e.event==='start'),exec=events.findIndex(e=>e.event==='exec');
    assert.equal(events[0].event,'create');assert(start>0&&exec>start);assert(events.slice(1,start).filter(e=>e.event==='inspect-created').length>=2);
    assert(events.slice(start+1,exec).some(e=>e.event==='inspect-running'));assert(new Set(events.map(e=>e.id)).size===1);}
});

test('RDEP2 unsafe created backup helper and uncertain helper starts keep HOLD without backup execution or recreation',async t=>{
  for(const target of ['backup-controls','start-uncertain']){const f=recoveryFixture(t),run=f.recoveryRun;let badId;
    await assert.rejects(f.recover({run:async(args,options)=>{
      if(target==='start-uncertain'&&args[0]==='container'&&args[1]==='start'){badId=args[2];throw Error('synthetic-start-outcome-unknown');}
      const value=await run(args,options);
      if(target==='backup-controls'&&args[1]==='inspect'&&args[2].endsWith('-backup')){const rows=JSON.parse(value);if(rows[0].State.Status==='created'){badId=rows[0].Id;rows[0].HostConfig.Mounts[0].ReadOnly=false;return JSON.stringify(rows);}}
      return value;
    }}),/HOLD/);assert(badId);assert(!f.calls.some(c=>c.args[1]==='exec'&&c.args[2]===badId));
    if(target==='backup-controls')assert(!f.calls.some(c=>c.args[1]==='start'&&c.args[2]===badId));assert(!f.calls.some(c=>c.args[0]==='compose'&&c.args.includes('up')));assert(fs.existsSync(f.lock));}
});

test('RDEP1 readonly probe membership is accounted exactly and never hides a foreign ledger consumer',async t=>{
  const f=recoveryFixture(t),run=f.recoveryRun;
  await assert.rejects(f.recover({run:async(args,options)=>{const value=await run(args,options);
    if(args[0]==='container'&&args[1]==='ls'&&args.includes('--all')&&args.includes('volume='+PROJECT+'_scan_ledger')&&f.helperLifecycle.some(e=>e.purpose==='drain'&&e.event==='start'))return value+'\n'+'0'.repeat(64);
    return value;}}),/HOLD/);
  assert(!f.calls.some(c=>c.args.at(-1)===isolated.RECOVERY_DRAIN));assert(!f.calls.some(c=>c.args[0]==='create'&&c.args.includes('org.diplom.recovery-purpose=backup')));
  assert(fs.existsSync(f.lock));assert(fs.existsSync(join(f.state,'.recover-build-and-redeploy.lock')));
});

test('RDEP3 typed serialization distinguishes INTEGER, REAL, BLOB, TEXT, NULL and refuses unsupported or oversized values',()=>{
  const encoded=[isolated.sqliteTypedRow([1n]),isolated.sqliteTypedRow([1]),isolated.sqliteTypedRow([Buffer.from('1')]),isolated.sqliteTypedRow(['1']),isolated.sqliteTypedRow([null])];assert.equal(new Set(encoded).size,5);
  assert.notEqual(isolated.sqliteTypedRow([9007199254740992n]),isolated.sqliteTypedRow([9007199254740993n]));assert.notEqual(isolated.sqliteTypedRow([-0]),isolated.sqliteTypedRow([0]));
  assert.throws(()=>isolated.sqliteTypedRow([{}]),/SQLITE_VALUE_TYPE/);assert.throws(()=>isolated.sqliteTypedRow([Buffer.alloc(4*1024**2+1)]),/SQLITE_VALUE_BOUND/);
});

test('Desktop RO aliases require exact declarations; Linux and naked/foreign aliases refuse', async t => {
  const f = fixture(t, true); seedState(f); f.populate();
  for (const c of f.containers) for (const m of c.Mounts.filter(m => m.Type === 'bind')) m.Source = `/host_mnt${m.Source}`;
  await inspectNamespace(f.run, { root: f.root, env: {} }, f.config, { platform: 'darwin' });
  await assert.rejects(inspectNamespace(f.run, { root: f.root, env: {} }, f.config, { platform: 'linux' }));
  f.containers[3].HostConfig.Mounts.find(m => m.Type === 'bind').Source = '/foreign';
  await assert.rejects(inspectNamespace(f.run, { root: f.root, env: {} }, f.config, { platform: 'darwin' }));
});
