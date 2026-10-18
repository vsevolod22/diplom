import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { createHash, createPrivateKey, generateKeyPairSync, sign } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import test from 'node:test';
import { refreshLocalCve, DISK_POLICY, checkDisk, DRAIN_PROBE, READY_PROBE, WEB_PROBE, publicRefreshFailure, validateStorageContinuity, validateRuntimeProfile } from './refresh-local-cve.mjs';
import { acquireStandLock, setupLocalCve, childEnvironment, runChild } from './setup-local-cve.mjs';
import { localStand, PROJECT, LABEL, expectedEnvironment } from './local-stand.mjs';
import { verifyLocalCve } from './verify-local-cve.mjs';
import { scheduledRun } from './schedule-local-cve.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const requireApi = createRequire(join(ROOT, 'server/api/package.json'));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const oldManifest = `sha256:${'a'.repeat(64)}`;
const ownership = { [LABEL]: 'v1', 'com.docker.compose.project': PROJECT };
const secret = 'ab'.repeat(48); // Synthetic fixture only.
const links = { 'auth-volume-init': [], 'scan-volume-init': [], egress: ['scan_internal', 'registry_uplink'],
  worker: ['scan_internal'], api: ['auth_internal', 'scan_internal'], web: ['auth_internal', 'web_edge'] };
const persistent = { 'auth-volume-init': [['auth_accounts', '/data']], 'scan-volume-init': [['scan_ledger', '/data']],
  worker: [['scan_ledger', '/data']], api: [['auth_accounts', '/auth'], ['scan_ledger', '/data']], egress: [], web: [] };
const commands = { api: ['node', '--import', 'tsx', 'src/oci/nginx-local.main.ts'],
  worker: ['node', '--import', 'tsx', 'src/worker/nginx-local-worker.main.ts'],
  'auth-volume-init': ['chown', '65532:65532', '/data'], 'scan-volume-init': ['chown', '65532:65532', '/data'] };
const dockerfiles = { egress: 'gateway/Dockerfile', api: 'api.Dockerfile', worker: 'worker.Dockerfile', web: 'stand.Dockerfile' };
const imageId = name => `sha256:${sha(name)}`;
const refused = /LOCAL CVE refresh refused\/HOLD/;
function failureAt(phase, checkpoint) {
  return error => {
    const details = publicRefreshFailure(error);
    assert.deepEqual(details, { phase, checkpoint,
      message: `LOCAL CVE refresh refused/HOLD; phase=${phase}; checkpoint=${checkpoint}. No automatic recovery or cleanup.` });
    assert.equal(error.message, details.message);
    for (const key of ['cause', 'args', 'stdout', 'stderr', 'env']) assert.equal(Object.hasOwn(error, key), false);
    assert(Object.isFrozen(details));
    return true;
  };
}
function bindings(name, cve) {
  if (!['api', 'worker'].includes(name)) return [];
  return [{ type: 'bind', source: cve.releaseHostDir, target: '/opt/release', read_only: true, bind: {} },
    { type: 'bind', source: cve.publicKeyPath, target: '/opt/local-db-trust/public.pem', read_only: true, bind: {} },
    ...(name === 'worker' ? [{ type: 'bind', source: join(cve.releaseHostDir, 'db'), target: '/tmp/trivy/db', read_only: true, bind: {} }] : [])];
}
function config(root, cve) {
  const result = { name: PROJECT, services: {}, volumes: {}, networks: {} };
  for (const name of Object.keys(links)) {
    const item = { image: dockerfiles[name] ? `${PROJECT}-${name}:local` : 'busybox:1.37.0', labels: { [LABEL]: 'v1' },
      environment: expectedEnvironment(name, cve), volumes: [...persistent[name].map(([source, target]) => ({ type: 'volume', source, target })), ...bindings(name, cve)],
      networks: Object.fromEntries(links[name].map(n => [n, {}])) };
    if (dockerfiles[name]) item.build = { context: root, dockerfile: `server/deploy/${dockerfiles[name]}`, labels: { [LABEL]: 'v1' } };
    else { delete item.networks; item.network_mode = 'none'; }
    if (commands[name]) item.command = commands[name];
    Object.assign(item, { cap_drop: ['ALL'], security_opt: ['no-new-privileges:true'] });
    if (dockerfiles[name]) Object.assign(item, { read_only: true, user: name === 'web' ? '101:101' : '65532:65532',
      restart: 'unless-stopped', pids_limit: 128,
      mem_limit: name === 'worker' ? 1073741824 : name === 'api' ? 536870912 : 268435456 });
    else item.cap_add = ['CHOWN'];
    if (['api', 'web'].includes(name)) item.tmpfs = ['/tmp'];
    if (name === 'egress') item.cpus = 1;
    if (item.volumes.length === 0) delete item.volumes;
    result.services[name] = item;
  }
  Object.assign(result.services.worker, { mem_limit: 1073741824, memswap_limit: 1073741824, cpus: 1, pids_limit: 128,
    tmpfs: ['/tmp:rw,noexec,nosuid,size=16m', '/tmp/trivy:rw,noexec,nosuid,uid=65532,gid=65532,size=512m'] });
  result.services.web.ports = [{ host_ip: '127.0.0.1', target: 8080, published: '8080', protocol: 'tcp' }];
  result.services.api.healthcheck = { test: ['CMD', 'node', '-e', "fetch('http://127.0.0.1:3001/api/v1/auth/me').then(r=>process.exit(r.status===401?0:1)).catch(()=>process.exit(1))"],
    interval: '5s', timeout: '3s', retries: 12 };
  for (const name of ['auth_accounts', 'scan_ledger']) result.volumes[name] = { name: `${PROJECT}_${name}`, labels: { [LABEL]: 'v1' } };
  for (const name of ['auth_internal', 'scan_internal', 'registry_uplink', 'web_edge']) result.networks[name] = {
    name: `${PROJECT}_${name}`, internal: name.endsWith('_internal'), labels: { [LABEL]: 'v1' } };
  return result;
}
function writableTree(path) {
  if (fs.lstatSync(path).isDirectory()) {
    fs.chmodSync(path, 0o700);
    for (const name of fs.readdirSync(path)) writableTree(join(path, name));
  }
}
function desktopBindings(item, mappedDeclaration) {
  for (const mount of item.Mounts) if (mount.Type === 'bind') mount.Source = `/host_mnt${mount.Source}`;
  if (mappedDeclaration) for (const declaration of item.HostConfig.Mounts) {
    if (declaration.Type === 'bind') declaration.Source = `/host_mnt${declaration.Source}`;
  }
}
function imageConfig(name) {
  return { Labels: name.endsWith('volume-init') ? {} : { [LABEL]: 'v1' }, Env: [],
    WorkingDir: ['api', 'worker'].includes(name) ? '/app/server/api' : name === 'egress' ? '/opt/gateway' : '',
    User: name === 'web' ? '101:101' : name.endsWith('volume-init') ? '' : '65532:65532',
    Entrypoint: ['web', 'api', 'worker'].includes(name) ? ['docker-entrypoint.sh'] : null,
    Cmd: name === 'web' ? ['nginx', '-g', 'daemon off;'] : name === 'egress' ? ['python', '-I', 'proxy.py'] : ['sh'],
    ...(name === 'web' ? { ExposedPorts: { '80/tcp': {}, '8080/tcp': {} }, StopSignal: 'SIGQUIT' } : {}) };
}
function fixture(t) {
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'local-cve-refresh-test-'))), stand = join(root, '.local-stand');
  const releases = join(stand, 'db-releases'), trust = join(stand, 'trust');
  for (const dir of [stand, releases, trust]) fs.mkdirSync(dir, { mode: 0o700 });
  const pair = generateKeyPairSync('ed25519');
  fs.writeFileSync(join(trust, 'db-signing-key.pem'), pair.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.writeFileSync(join(trust, 'db-signing-key.pub.pem'), pair.publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o444 });
  fs.writeFileSync(join(stand, 'scan-jwt'), secret, { mode: 0o600 });
  const publicKeySha256 = sha(pair.publicKey.export({ type: 'spki', format: 'der' }));
  const at = Date.now();
  const writeRelease = (release, manifest, signed, age = 3600_000) => {
    fs.mkdirSync(release, { mode: 0o700 }); fs.mkdirSync(join(release, 'db'), { mode: 0o700 });
    const db = Buffer.from('SYNTHETIC DB workflow only ' + manifest), bundle = Buffer.from('SYNTHETIC bundle ' + manifest);
    // Use real gzip so the backend verifier authenticates/decompresses it.
    const gzip = requireApi('node:zlib').gzipSync(db);
    assert(bundle.length > 0);
    const metadata = { Version: 2, UpdatedAt: new Date(at - age).toISOString(), DownloadedAt: new Date(at - 1000).toISOString(),
      NextUpdate: new Date(at + 3600_000).toISOString() };
    for (const [name, bytes] of [['db/trivy.db', db], ['bundle.bin', gzip], ['db/metadata.json', JSON.stringify(metadata)]])
      fs.writeFileSync(join(release, name), bytes, { mode: 0o600 });
    if (signed) signRelease(release, manifest, sha(gzip), sha(db));
    return { bundle: sha(gzip), db: sha(db) };
  };
  function signRelease(release, manifestDigest, artifactSha256, dbSha256) {
    const bytes = fs.readFileSync(join(release, 'db/metadata.json')), m = JSON.parse(bytes);
    const descriptor = Buffer.from(JSON.stringify({ envelopeVersion: 1, signer: 'local-db-operator-v1', source: `ghcr.io/aquasecurity/trivy-db@${manifestDigest}`,
      schemaVersion: 2, artifactSha256, metadataSha256: sha(bytes), dbSha256, manifestDigest,
      updatedAt: m.UpdatedAt, downloadedAt: m.DownloadedAt, nextUpdate: m.NextUpdate }));
    fs.writeFileSync(join(release, 'descriptor.json'), descriptor, { mode: 0o600, flag: 'wx' });
    fs.writeFileSync(join(release, 'descriptor.sig'), sign(null, descriptor, createPrivateKey(fs.readFileSync(join(trust, 'db-signing-key.pem')))), { mode: 0o600, flag: 'wx' });
  }
  const prior = join(releases, 'prior'), old = writeRelease(prior, oldManifest, true, 7200_000);
  for (const name of ['bundle.bin', 'descriptor.json', 'descriptor.sig', 'db/metadata.json', 'db/trivy.db']) fs.chmodSync(join(prior, name), 0o444);
  fs.chmodSync(join(prior, 'db'), 0o555); fs.chmodSync(prior, 0o555);
  const activation = { version: 1, release: 'db-releases/prior', manifestDigest: oldManifest, artifactSha256: old.bundle, publicKeySha256 };
  fs.writeFileSync(join(stand, 'cve.json'), JSON.stringify(activation), { mode: 0o600 });
  const cve = value => ({ ...value, releaseHostDir: join(stand, value.release), publicKeyPath: join(trust, 'db-signing-key.pub.pem') });
  const layer = `sha256:${'c'.repeat(64)}`;
  const manifestBytes = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json',
    artifactType: 'application/vnd.aquasec.trivy.config.v1+json', config: { mediaType: 'application/vnd.oci.empty.v1+json' },
    layers: [{ mediaType: 'application/vnd.aquasec.trivy.db.layer.v1.tar+gzip', digest: layer, size: 10 }] }));
  const manifest = `sha256:${sha(manifestBytes)}`;
  const calls = [], logs = [], containers = {};
  const state = { discover: manifest, pending: [0], fail: null, clock: 0, beforeStop: null, beforeVerify: null, host: 'unix:///synthetic/docker.sock', desktop: null, resourceMutation: null };
  function makeContainer(name, value = cve(activation), pinned = false) {
    const spec = config(root, value).services[name], volumes = spec.volumes ?? [], image = imageConfig(name);
    const bindings = name === 'web' ? { '8080/tcp': [{ HostIp: '127.0.0.1', HostPort: '8080' }] } : {};
    const environment = { ...spec.environment }; if (name === 'api') environment.SCAN_JWT_SECRET = secret;
    const item = { Id: sha(name + (pinned ? '-next' : '-prior')), Name: `/${PROJECT}-${name}-1`, Image: imageId(name),
      Config: { Labels: { ...ownership, 'com.docker.compose.service': name }, Image: pinned ? imageId(name) : spec.image,
        Cmd: spec.command ?? image.Cmd, WorkingDir: image.WorkingDir, Entrypoint: image.Entrypoint, User: spec.user ?? image.User,
        ExposedPorts: image.ExposedPorts ?? {}, StopSignal: image.StopSignal ?? '',
        ...(spec.healthcheck ? { Healthcheck: { Test: spec.healthcheck.test, Interval: 5e9, Timeout: 3e9, Retries: 12 } } : {}),
        Env: Object.entries(environment).map(([k, v]) => `${k}=${v}`) },
      HostConfig: { Mounts: volumes.map(m => ({ Type: m.type, Source: m.type === 'volume' ? `${PROJECT}_${m.source}` : m.source,
        Target: m.target, ReadOnly: !!m.read_only })), ReadonlyRootfs: Boolean(spec.read_only), Privileged: false, AutoRemove: false,
        RestartPolicy: { Name: spec.restart ?? 'no', MaximumRetryCount: 0 },
        PublishAllPorts: false, PortBindings: bindings, CapDrop: spec.cap_drop, CapAdd: spec.cap_add ?? null, SecurityOpt: spec.security_opt,
        NetworkMode: name.endsWith('volume-init') ? 'none' : `${PROJECT}_${links[name][0]}`,
        Tmpfs: Object.fromEntries((spec.tmpfs ?? []).map(v => { const i = v.indexOf(':'); return i < 0 ? [v, ''] : [v.slice(0, i), v.slice(i + 1)]; })),
        Memory: spec.mem_limit ?? 0, MemorySwap: spec.memswap_limit ?? (spec.mem_limit ?? 0) * 2, MemoryReservation: 0,
        NanoCpus: (spec.cpus ?? 0) * 1e9, CpuShares: 0, CpuPeriod: 0, CpuQuota: 0, CpuRealtimePeriod: 0, CpuRealtimeRuntime: 0,
        CpusetCpus: '', CpusetMems: '', OomScoreAdj: 0, ShmSize: 67108864,
        IpcMode: 'private', PidMode: '', UTSMode: '', UsernsMode: '', CgroupParent: '', CgroupnsMode: 'private', Runtime: 'runc',
        PidsLimit: spec.pids_limit ?? null, MemorySwappiness: null, OomKillDisable: null, ConsoleSize: [0, 0], LogConfig: { Type: 'json-file', Config: {} },
        MaskedPaths: ['/proc/asound', '/proc/acpi', '/proc/interrupts', '/proc/kcore', '/proc/keys', '/proc/latency_stats', '/proc/timer_list', '/proc/timer_stats', '/proc/sched_debug', '/proc/scsi', '/sys/firmware', '/sys/devices/virtual/powercap'],
        ReadonlyPaths: ['/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger'] },
      Mounts: volumes.map(m => ({ Type: m.type, Name: m.type === 'volume' ? `${PROJECT}_${m.source}` : undefined,
        Source: m.source, Destination: m.target, RW: !m.read_only })),
      NetworkSettings: { Ports: name === 'web' ? { '80/tcp': null, ...bindings } : {}, Networks: Object.fromEntries((links[name].length ? links[name].map(n => `${PROJECT}_${n}`) : ['none']).map(n => [n, {}])) },
      State: { Running: !!dockerfiles[name], Status: dockerfiles[name] ? 'running' : 'exited', ExitCode: 0, Health: { Status: 'healthy' } } };
    for (const [network, attachment] of Object.entries(item.NetworkSettings.Networks)) {
      Object.assign(attachment, { NetworkID: sha(network), EndpointID: sha(item.Id + network),
        IPAddress: `172.24.0.${Object.keys(links).indexOf(name) + 2}`, IPPrefixLen: 24,
        MacAddress: `02:42:ac:18:00:0${Object.keys(links).indexOf(name) + 2}`, GlobalIPv6Address: '', GlobalIPv6PrefixLen: 0 });
    }
    if (state.desktop) desktopBindings(item, state.desktop === 'both');
    return item;
  }
  for (const name of Object.keys(links)) containers[name] = makeContainer(name);
  const find = target => Object.values(containers).find(c => c.Id === target || c.Name.slice(1) === target);
  const run = async (exe, args, options) => {
    calls.push({ kind: 'child', exe, args, options });
    assert.deepEqual(options.env, childEnvironment()); assert(options.timeout > 0 && options.timeout <= 240_000);
    if (args.at(-1) === WEB_PROBE) {
      if (state.fail === 'web') throw Error('stale web upstream');
      return JSON.stringify({ webReady: true });
    }
    if (args[0]?.endsWith('/fetch-db-layer.mjs')) {
      if (args[1] === 'discover') {
        if (state.fail === 'discover') throw Error('sensitive child stderr');
        return `Review upstream tag :2, then download by digest: ${state.discover}\n`;
      }
      if (state.fail === 'download') throw Error('bounded download failure');
      assert.equal(args[1], manifest); fs.mkdirSync(args[2], { mode: 0o700 });
      fs.writeFileSync(join(args[2], 'manifest.json'), manifestBytes, { mode: 0o600 });
      fs.writeFileSync(join(args[2], 'layer.tar.gz'), 'fake layer', { mode: 0o600 }); return '';
    }
    if (exe === 'python3') {
      if (state.fail === 'prepare') throw Error('invalid archive');
      assert.equal(args[3], manifest); assert.equal(args[4], layer);
      const pins = writeRelease(args[2], manifest, false);
      return JSON.stringify({ manifest, layer, ...pins }) + '\nUnsigned release: independently review pins, then use operator-only signer.\n';
    }
    if (args[0]?.endsWith('/sign-offline-db.mjs')) {
      if (state.fail === 'sign') throw Error('private child failure');
      assert.equal(args[2], join(trust, 'db-signing-key.pem'));
      signRelease(args[1], args[4], args[5], args[6]); return '';
    }
    assert.equal(args[0], '--import');
    if (state.beforeVerify) await state.beforeVerify(args);
    if (state.fail === 'verify') throw Error('private verifier failure');
    return JSON.stringify(await verifyLocalCve(args.slice(3)));
  };
  const docker = async (args, options) => {
    calls.push({ kind: 'docker', args, options });
    assert(options.timeout > 0 && options.timeout <= 120_000);
    assert(!Object.hasOwn(options.env, 'NODE_OPTIONS')); assert(!Object.hasOwn(options.env, 'OPENROUTER_API_KEY'));
    if (args[0] === 'context') return JSON.stringify(state.host);
    if (args[0] === 'compose') {
      if (args.includes('config')) return JSON.stringify(config(root, { ...cve(activation), releaseHostDir: options.env.SCAN_VULN_RELEASE_HOST_DIR,
        manifestDigest: options.env.SCAN_VULN_MANIFEST_DIGEST, artifactSha256: options.env.SCAN_VULN_ARTIFACT_SHA256 }));
      const name = args.at(-1);
      assert(['api', 'worker'].includes(name)); assert(args.includes('--no-deps') && args.includes('--no-build') && args.includes('--force-recreate'));
      assert(args.includes('never') && !args.includes('--build'));
      assert.equal(containers.api.State.Running, false, 'admission API must stay fenced throughout worker activation');
      if (state.fail === `up-${name}`) throw Error('uncertain recreate');
      const current = JSON.parse(fs.readFileSync(join(stand, 'cve.json')));
      containers[name] = makeContainer(name, cve(current), true); return '';
    }
    if (args[0] === 'image') {
      if (args[1] === 'ls') return Object.keys(dockerfiles).map(n => `${PROJECT}-${n}:local`).join('\n');
      const name = Object.keys(links).find(n => args[2] === `${PROJECT}-${n}:local` || args[2] === imageId(n)); assert(name);
      return JSON.stringify([{ Id: imageId(name), Os: 'linux', Config: imageConfig(name), RepoTags: [name.endsWith('volume-init') ? 'busybox:1.37.0' : `${PROJECT}-${name}:local`] }]);
    }
    const kind = args[0];
    if (args[1] === 'ls') {
      if (args.some(a => a.startsWith('volume='))) {
        const volume = args.find(a => a.startsWith('volume=')).slice(7);
        return Object.values(containers).filter(c => c.State.Running && c.Mounts.some(m => m.Name === volume)).map(c => c.Id).join('\n');
      }
      assert(args.includes(`label=${LABEL}=v1`));
      if (kind === 'container') return Object.values(containers).map(c => `${c.Name.slice(1)}\t${PROJECT}`).join('\n');
      const names = kind === 'volume' ? ['auth_accounts', 'scan_ledger'] : ['auth_internal', 'scan_internal', 'registry_uplink', 'web_edge'];
      return names.map(n => `${PROJECT}_${n}\t${PROJECT}`).join('\n');
    }
    if (args[1] === 'inspect') {
      if (kind === 'container') { assert(find(args[2])); return JSON.stringify([find(args[2])]); }
      const record = { Name: args[2], Labels: ownership, Driver: kind === 'volume' ? 'local' : 'bridge',
        [kind === 'volume' ? 'CreatedAt' : 'Created']: new Date(at - 86400_000).toISOString(), Scope: 'local',
        ...(kind === 'volume' ? { Options: null, Mountpoint: `/synthetic/volumes/${args[2]}` } : {
          Id: sha(args[2]), Internal: args[2].endsWith('_internal'), EnableIPv6: false, Attachable: false,
          Options: {}, IPAM: { Driver: 'default', Options: null, Config: [{ Subnet: '172.24.0.0/24', Gateway: '172.24.0.1' }] },
          Containers: Object.fromEntries(Object.values(containers).filter(c => c.State.Running && c.NetworkSettings.Networks[args[2]])
            .map(c => { const a = c.NetworkSettings.Networks[args[2]]; return [c.Id, { Name: c.Name.slice(1), EndpointID: a.EndpointID,
              MacAddress: a.MacAddress, IPv4Address: `${a.IPAddress}/${a.IPPrefixLen}`, IPv6Address: '' }]; })) }) };
      if (containers.api?.Config.Image === containers.api?.Image) {
        if (state.resourceMutation) state.resourceMutation(kind, record);
        // Docker object ordering is not guaranteed between observations.
        return JSON.stringify([Object.fromEntries(Object.entries(record).reverse())]);
      }
      return JSON.stringify([record]);
    }
    const item = find(args[args[1] === 'stop' ? 4 : 2]); assert(item);
    if (args[1] === 'stop') {
      if (state.beforeStop) state.beforeStop(item);
      if (state.fail === 'stop') throw Error('uncertain stop');
      item.State.Running = false; item.State.Status = 'exited'; return '';
    }
    if (args[1] === 'start') { item.State.Running = true; item.State.Status = 'running'; return ''; }
    assert.equal(args[1], 'exec');
    if (args.at(-1) === DRAIN_PROBE) {
      assert.equal(containers.api.State.Running, false, 'no SELECT race: exact API stopped before durable-work probe');
      const pending = state.pending.length > 1 ? state.pending.shift() : state.pending[0];
      return JSON.stringify({ pending });
    }
    assert.equal(args.at(-1), READY_PROBE);
    if (state.fail === 'ready') throw Error('unusable runtime DB');
    const current = JSON.parse(fs.readFileSync(join(stand, 'cve.json')));
    const descriptor = JSON.parse(fs.readFileSync(join(stand, current.release, 'descriptor.json')));
    return JSON.stringify({ ready: true, manifest: current.manifestDigest, bundle: current.artifactSha256, db: descriptor.dbSha256 });
  };
  t.after(() => { writableTree(root); fs.rmSync(root, { recursive: true, force: true }); });
  const refresh = (argv = [], options = {}) => refreshLocalCve(argv, { root, run, docker, now: () => state.clock,
    sleep: async ms => { state.clock += ms; }, ambient: { NODE_OPTIONS: 'do-not-inherit', OPENROUTER_API_KEY: 'do-not-inherit' },
    log: s => logs.push(s), ...options });
  return { root, stand, releases, prior, trust, activation, manifest, calls, state, containers, run, docker, refresh, logs,
    current: () => JSON.parse(fs.readFileSync(join(stand, 'cve.json'))), lock: join(stand, '.stand-operation.lock') };
}
const mutations = f => f.calls.filter(c => c.kind === 'docker' && (c.args.includes('up') || ['stop', 'start'].includes(c.args[1])));

test('unchanged authenticates real signature/usability without private-key access, resigning or Docker', async t => {
  const f = fixture(t); f.state.discover = oldManifest;
  fs.unlinkSync(join(f.trust, 'db-signing-key.pem')); fs.unlinkSync(join(f.stand, 'scan-jwt'));
  const descriptor = fs.readFileSync(join(f.prior, 'descriptor.json'));
  assert.equal((await f.refresh()).outcome, 'unchanged');
  assert.equal(f.calls.length, 2); assert(f.calls.every(c => c.kind === 'child'));
  assert.deepEqual(fs.readFileSync(join(f.prior, 'descriptor.json')), descriptor); assert(!fs.existsSync(f.lock));
});

test('unchanged tampered signature refuses instead of re-signing or fabricating freshness', async t => {
  const f = fixture(t); f.state.discover = oldManifest;
  fs.chmodSync(join(f.prior, 'descriptor.sig'), 0o600); fs.writeFileSync(join(f.prior, 'descriptor.sig'), Buffer.alloc(64)); fs.chmodSync(join(f.prior, 'descriptor.sig'), 0o444);
  await assert.rejects(f.refresh(), failureAt('verify-current', 'usability')); assert.equal(mutations(f).length, 0);
});

test('changed exact download, prepare, existing LOCAL signer, real verify, freeze, fenced CAS and API/worker-only switch', async t => {
  const f = fixture(t), key = fs.readFileSync(join(f.trust, 'db-signing-key.pem'));
  f.state.pending = [3, 1, 0];
  assert.equal((await f.refresh()).outcome, 'activated');
  assert.equal(f.current().manifestDigest, f.manifest); assert(fs.existsSync(f.prior));
  assert.deepEqual(fs.readFileSync(join(f.trust, 'db-signing-key.pem')), key); assert.equal(fs.readFileSync(join(f.stand, 'scan-jwt'), 'utf8'), secret);
  assert.equal(fs.statSync(join(f.stand, f.current().release)).mode & 0o777, 0o555);
  assert.equal(fs.statSync(join(f.stand, f.current().release, 'descriptor.json')).mode & 0o777, 0o444);
  assert.deepEqual(mutations(f).map(c => c.args.includes('up') ? `up-${c.args.at(-1)}` : c.args[1]), ['stop', 'stop', 'up-worker', 'up-api']);
  assert(!fs.existsSync(f.lock)); assert(!fs.existsSync(join(f.stand, '.cve-refresh-work')));
  assert(!f.calls.some(c => c.args.some(a => a.includes('.local-auth') || a.includes('dip-auth-stand'))));
  assert(!f.logs.join('\n').includes(secret)); assert(!JSON.stringify(f.calls.map(c => c.args)).includes(secret));
});

test('full refresh accepts exact Desktop observed-only and declaration+observed aliases on Darwin', async t => {
  for (const desktop of ['observed', 'both']) await t.test(desktop, async t => {
    const f = fixture(t); f.state.desktop = desktop;
    for (const item of Object.values(f.containers)) desktopBindings(item, desktop === 'both');
    assert.equal((await f.refresh([], { platform: 'darwin' })).outcome, 'activated');
    assert.equal(f.current().manifestDigest, f.manifest); assert(!fs.existsSync(f.lock));
    const expected = join(f.stand, f.current().release);
    for (const name of ['api', 'worker']) {
      const item = f.containers[name];
      assert.equal(item.Mounts.find(m => m.Destination === '/opt/release').Source, `/host_mnt${expected}`);
      assert.equal(item.HostConfig.Mounts.find(m => m.Target === '/opt/release').Source,
        desktop === 'both' ? `/host_mnt${expected}` : expected);
    }
  });
});

test('refresh rejects Desktop aliases off Darwin without submitting lifecycle mutation', async t => {
  const f = fixture(t); f.state.desktop = 'both';
  for (const item of Object.values(f.containers)) desktopBindings(item, true);
  await assert.rejects(f.refresh([], { platform: 'linux' }), refused);
  assert.equal(mutations(f).length, 0); assert.deepEqual(f.current(), f.activation);
});

test('refresh uses fixed Homebrew-capable PATH for children and Docker without trusting inherited PATH', async t => {
  const expected = '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin';
  assert.equal(childEnvironment().PATH, expected);
  for (const ambient of [{}, { PATH: '/synthetic/untrusted-bin', NODE_OPTIONS: '--synthetic-untrusted' }]) {
    const f = fixture(t);
    assert.equal((await f.refresh([], { ambient })).outcome, 'activated');
    for (const call of f.calls) {
      assert.equal(call.options.env.PATH, expected);
      assert(!Object.hasOwn(call.options.env, 'NODE_OPTIONS'));
    }
  }
});

test('stable resource comparison ignores only network Containers and object key order, preserving all other fields', () => {
  const before = { volumes: ['auth_accounts', 'scan_ledger'].map(Name => ({ Name, Driver: 'local', CreatedAt: '2026-10-15T00:00:00Z',
    Labels: { b: '2', a: '1' }, Options: null, Mountpoint: '/synthetic/' + Name })),
  networks: ['a', 'b', 'c', 'd'].map(Name => ({ Name, Id: sha(Name), Created: '2026-10-15', CreatedAt: '2026-10-15', Driver: 'bridge',
    IPAM: { Driver: 'default', Config: [{ Subnet: 'first', Gateway: 'one' }, { Subnet: 'second', Gateway: 'two' }] },
    Options: { internal: 'true' }, UnknownStableField: { preserve: true }, Containers: { old: { EndpointID: 'old' } } })) };
  const reordered = JSON.parse(JSON.stringify(before));
  reordered.volumes.reverse(); reordered.networks.reverse();
  for (const network of reordered.networks) {
    network.Containers = { replacement: { EndpointID: 'new' } };
    network.IPAM.Config[0] = Object.fromEntries(Object.entries(network.IPAM.Config[0]).reverse());
  }
  validateStorageContinuity(before, reordered);
  for (const mutate of [a => { a.networks[0].Id = sha('replacement'); }, a => { a.networks[0].Driver = 'overlay'; },
    a => { a.networks[0].CreatedAt = 'replacement'; }, a => { a.networks[0].Options.internal = 'false'; },
    a => { a.networks[0].IPAM.Config.reverse(); }, a => { delete a.networks[0].UnknownStableField; },
    a => { a.volumes[0].Mountpoint = '/other'; }, a => { a.volumes[0].Labels.a = 'changed'; }]) {
    const changed = JSON.parse(JSON.stringify(reordered)); mutate(changed);
    assert.throws(() => validateStorageContinuity(before, changed));
  }
});

test('realistic replaced endpoints and reordered metadata pass full refresh; changed identities/config or foreign endpoints retain HOLD', async t => {
  const mutations = {
    'network-id': (kind, record) => { if (kind === 'network') record.Id = sha('foreign-network'); },
    'network-config': (kind, record) => { if (kind === 'network') record.IPAM.Config[0].Gateway = '172.24.0.254'; },
    'volume-config': (kind, record) => { if (kind === 'volume') record.Mountpoint = '/foreign'; },
    'foreign-endpoint': (kind, record) => { if (kind === 'network') record.Containers[sha('foreign')] = { Name: 'foreign' }; },
    'stale-api-id': (kind, record) => { if (kind === 'network' && record.Name.endsWith('_auth_internal')) {
      record.Containers[sha('api-prior')] = record.Containers[sha('api-next')]; delete record.Containers[sha('api-next')];
    } },
    'wrong-endpoint': (kind, record) => { if (kind === 'network') Object.values(record.Containers)[0].EndpointID = sha('wrong-endpoint'); },
  };
  const good = fixture(t), observations = [];
  const docker = async (args, options) => {
    const output = await good.docker(args, options);
    if (args[0] === 'network' && args[1] === 'inspect') observations.push(JSON.parse(output)[0]);
    return output;
  };
  assert.equal((await good.refresh([], { docker })).outcome, 'activated');
  const auth = observations.filter(n => n.Name.endsWith('_auth_internal'));
  assert(Object.hasOwn(auth[0].Containers, sha('api-prior')));
  assert(Object.hasOwn(auth.at(-1).Containers, sha('api-next')));
  assert(!Object.hasOwn(auth.at(-1).Containers, sha('api-prior')));
  assert(Object.hasOwn(auth.at(-1).Containers, sha('web-prior')));
  for (const [scenario, mutation] of Object.entries(mutations)) await t.test(scenario, async t => {
    const f = fixture(t); f.state.resourceMutation = mutation;
    await assert.rejects(f.refresh(), failureAt('readiness', 'storage'));
    assert(fs.existsSync(join(f.lock, 'refresh.json')));
    assert.equal(f.current().manifestDigest, f.manifest);
  });
});

async function heldFixture(t, desktop = null) {
  const f = fixture(t), startedAt = new Date().toISOString();
  if (desktop) {
    f.state.desktop = desktop;
    for (const item of Object.values(f.containers)) desktopBindings(item, desktop === 'both');
  }
  f.state.resourceMutation = (kind, record) => { if (kind === 'network') record.Id = sha('synthetic-storage-refusal'); };
  await assert.rejects(f.refresh([], desktop ? { platform: 'darwin' } : {}), failureAt('readiness', 'storage'));
  f.state.resourceMutation = null;
  fs.writeFileSync(join(f.stand, 'cve-refresh-status.json'), JSON.stringify({ version: 1, startedAt, finishedAt: new Date().toISOString(),
    state: 'failed', phase: 'readiness', checkpoint: 'storage' }) + '\n', { mode: 0o600 });
  f.calls.length = 0; f.logs.length = 0;
  return f;
}
function assertObservationalCalls(f) {
  assert.equal(mutations(f).length, 0);
  for (const call of f.calls) {
    if (call.kind === 'child') assert(call.args[0] === '--import' || call.args.at(-1) === WEB_PROBE);
    else assert((call.args[0] === 'compose' && call.args.includes('config')) || ['ls', 'inspect'].includes(call.args[1]) ||
      (call.args[1] === 'exec' && call.args.at(-1) === READY_PROBE));
  }
}

test('verify-hold checks current signed active candidate but retains legacy lock with explicit historical evidence gaps', async t => {
  const f = await heldFixture(t);
  const preserved = ['refresh.json', 'images.json'].map(name => [name, fs.readFileSync(join(f.lock, name)), fs.statSync(join(f.lock, name)).ino]);
  const activation = fs.readFileSync(join(f.stand, 'cve.json')), lockInode = fs.statSync(f.lock).ino;
  fs.unlinkSync(join(f.trust, 'db-signing-key.pem')); // The observational verifier must never need/generate it.
  const report = await f.refresh(['--verify-hold']);
  assert.equal(report.outcome, 'hold-retained'); assert.equal(report.currentChecksPassed, true);
  assert.equal(report.lockRemoved, false); assert.equal(report.finalizationAuthorized, false); assert.equal(report.historicalPreservationProven, false);
  assert.deepEqual(report.evidenceGaps, ['historical-storage-network-baseline', 'historical-container-configuration', 'historical-jwt-binding', 'journal-status-run-binding']);
  assert.equal(fs.statSync(f.lock).ino, lockInode);
  for (const [name, bytes, inode] of preserved) { assert.deepEqual(fs.readFileSync(join(f.lock, name)), bytes); assert.equal(fs.statSync(join(f.lock, name)).ino, inode); }
  assert.deepEqual(fs.readFileSync(join(f.stand, 'cve.json')), activation);
  assert(!fs.existsSync(join(f.trust, 'db-signing-key.pem'))); assertObservationalCalls(f);
  assert(!f.logs.join('\n').includes(secret));
  await assert.rejects(f.refresh(['--finalize-hold']), failureAt('preflight', 'arguments'));
  assert(fs.existsSync(f.lock));
});

test('verify-hold rejects wrong journal phase/status, replaced services, JWT/mount mismatch, new resources and failed readiness', async t => {
  const cases = {
    journal: { checkpoint: 'journal', change: f => { const path = join(f.lock, 'refresh.json'), j = JSON.parse(fs.readFileSync(path)); j.phase = 'fence-api'; fs.writeFileSync(path, JSON.stringify(j)); } },
    status: { checkpoint: 'status', change: f => { const path = join(f.stand, 'cve-refresh-status.json'), s = JSON.parse(fs.readFileSync(path)); s.checkpoint = 'web'; fs.writeFileSync(path, JSON.stringify(s)); } },
    'web-id': { checkpoint: 'namespace', change: f => { f.containers.web.Id = sha('replacement-web'); } },
    jwt: { checkpoint: 'bindings', change: f => { fs.writeFileSync(join(f.stand, 'scan-jwt'), 'cd'.repeat(48)); } },
    mount: { checkpoint: 'bindings', change: f => {
      f.containers.api.HostConfig.Mounts.find(m => m.Target === '/opt/release').Source = f.prior;
      f.containers.api.Mounts.find(m => m.Destination === '/opt/release').Source = f.prior;
    } },
    'created-after-start': { checkpoint: 'created-before-start', change: f => {
      f.state.resourceMutation = (kind, record) => { record[kind === 'network' ? 'Created' : 'CreatedAt'] = new Date(Date.now() + 3600_000).toISOString(); };
    } },
    readiness: { checkpoint: 'readiness', change: f => { f.state.fail = 'ready'; } },
    signature: { checkpoint: 'usability', change: f => { f.state.fail = 'verify'; } },
  };
  for (const [name, scenario] of Object.entries(cases)) await t.test(name, async t => {
    const f = await heldFixture(t); scenario.change(f);
    await assert.rejects(f.refresh(['--verify-hold']), failureAt('hold-verification', scenario.checkpoint));
    assert(fs.existsSync(join(f.lock, 'refresh.json'))); assertObservationalCalls(f);
  });
});

test('verify-hold accepts both exact Desktop forms but never finalizes either', async t => {
  for (const desktop of ['observed', 'both']) await t.test(desktop, async t => {
    const f = await heldFixture(t, desktop);
    const report = await f.refresh(['--verify-hold'], { platform: 'darwin' });
    assert.equal(report.currentChecksPassed, true); assert.equal(report.lockRemoved, false);
    assert(fs.existsSync(f.lock)); assertObservationalCalls(f);
  });
});

test('accept-current-hold durably archives exact failure evidence and prospective baseline, then releases only its known lock', async t => {
  const f = await heldFixture(t), journal = fs.readFileSync(join(f.lock, 'refresh.json')), images = fs.readFileSync(join(f.lock, 'images.json'));
  const statusPath = join(f.stand, 'cve-refresh-status.json'), status = fs.readFileSync(statusPath), statusInode = fs.statSync(statusPath).ino;
  const activation = fs.readFileSync(join(f.stand, 'cve.json'));
  fs.unlinkSync(join(f.trust, 'db-signing-key.pem'));
  const removed = [], acceptanceIo = { unlink: path => { removed.push(path); fs.unlinkSync(path); }, rmdir: path => { removed.push(path); fs.rmdirSync(path); } };
  const result = await f.refresh(['--accept-current-hold'], { acceptanceIo });
  assert.equal(result.outcome, 'current-baseline-accepted'); assert.equal(result.lockRemoved, true);
  assert.equal(result.failedAttemptCertified, false); assert.equal(result.failedAttemptReplayed, false);
  assert.equal(result.historicalPreservationProven, false); assert.equal(result.currentBaselineAcceptanceAuthorized, true);
  assert.equal(result.finalizationAuthorized, false); assert(result.evidenceGaps.includes('historical-jwt-binding'));
  assert.deepEqual(removed, [join(f.lock, 'images.json'), join(f.lock, 'refresh.json'), f.lock]);
  assert(!fs.existsSync(f.lock)); assert(!fs.existsSync(join(f.trust, 'db-signing-key.pem')));
  const archive = join(f.stand, result.auditDirectory);
  assert.deepEqual(fs.readdirSync(archive).sort(), ['acceptance.json', 'baseline.json', 'failure-status.json', 'images.json', 'lock-release.json', 'refresh.json']);
  assert.deepEqual(fs.readFileSync(join(archive, 'refresh.json')), journal); assert.deepEqual(fs.readFileSync(join(archive, 'images.json')), images);
  assert.deepEqual(fs.readFileSync(join(archive, 'failure-status.json')), status); assert.deepEqual(fs.readFileSync(statusPath), status);
  assert.equal(fs.statSync(statusPath).ino, statusInode); assert.deepEqual(fs.readFileSync(join(f.stand, 'cve.json')), activation);
  const baselineBytes = fs.readFileSync(join(archive, 'baseline.json'), 'utf8'), baseline = JSON.parse(baselineBytes);
  assert.equal(baseline.desired.services.api.environment.SCAN_JWT_SECRET, '[redacted]');
  assert.equal(baseline.containers.length, 6); assert.equal(baseline.networks.length, 4); assert.equal(baseline.volumes.length, 2);
  assert.equal(baseline.jwtBinding.length, 64); assert(!baselineBytes.includes(secret)); assert(!f.logs.join('\n').includes(secret));
  const acceptance = JSON.parse(fs.readFileSync(join(archive, 'acceptance.json')));
  for (const [name, digest] of Object.entries(acceptance.hashes)) assert.equal(sha(fs.readFileSync(join(archive, name))), digest);
  assert.equal(acceptance.lockRelease, 'pending'); assert.equal(JSON.parse(fs.readFileSync(join(archive, 'lock-release.json'))).lockRemoved, true);
  assertObservationalCalls(f);
  f.calls.length = 0;
  await assert.rejects(f.refresh(['--accept-current-hold']), failureAt('hold-acceptance', 'journal'));
  assert.equal(f.calls.length, 0); assert.equal(fs.readdirSync(join(f.stand, 'cve-current-acceptances')).length, 1);
  f.state.discover = f.manifest;
  assert.equal((await f.refresh()).outcome, 'unchanged'); // Future maintenance is a separate new operation.
});

test('acceptance handles neutral omitted Mounts for mount-free services without relaxing declared profiles', async t => {
  const f = await heldFixture(t);
  for (const name of ['web', 'egress']) delete f.containers[name].HostConfig.Mounts;
  f.containers.egress.HostConfig.PortBindings = null;
  f.containers.api.Config.Healthcheck.StartPeriod = 0; f.containers.api.Config.Healthcheck.StartInterval = 0;
  const result = await f.refresh(['--accept-current-hold']);
  assert.equal(result.outcome, 'current-baseline-accepted'); assert.equal(result.historicalPreservationProven, false);
  assertObservationalCalls(f);
});

test('omitted desired volume lists accept only absent/empty mounts and reject unexpected declared or observed mounts', t => {
  const f = fixture(t), rendered = config(f.root, { ...f.activation, releaseHostDir: f.prior,
    publicKeyPath: join(f.trust, 'db-signing-key.pub.pem') });
  for (const name of ['web', 'egress']) {
    const spec = rendered.services[name], image = { Id: imageId(name), Os: 'linux', Config: imageConfig(name) };
    assert.equal(spec.volumes, undefined);
    for (const mounts of [undefined, null, []]) {
      const item = structuredClone(f.containers[name]); item.HostConfig.Mounts = mounts;
      validateRuntimeProfile(item, spec, image, rendered, secret);
    }
    const declared = structuredClone(f.containers[name]);
    declared.HostConfig.Mounts = [{ Type: 'bind', Source: '/synthetic/unexpected', Target: '/unexpected', ReadOnly: true }];
    const failures = [];
    assert.throws(() => validateRuntimeProfile(declared, spec, image, rendered, secret, (field, match) => { if (!match) failures.push(field); }));
    assert.deepEqual(failures, ['HostConfig.mount-count']);
    const observed = structuredClone(f.containers[name]);
    observed.Mounts.push({ Type: 'bind', Source: '/synthetic/unexpected', Destination: '/unexpected', RW: false });
    const observedFailures = [];
    assert.throws(() => validateRuntimeProfile(observed, spec, image, rendered, secret, (field, match) => { if (!match) observedFailures.push(field); }));
    assert.deepEqual(observedFailures, ['Mounts.persistent-targets']);
  }
});

test('complete runtime qualification refuses exposed ports, capabilities, security, namespace, device, tmpfs and resource drift', async t => {
  const scenarios = {
    'web-port-binding': f => { f.containers.web.HostConfig.PortBindings['8080/tcp'][0].HostIp = '0.0.0.0'; },
    'web-observed-port': f => { f.containers.web.NetworkSettings.Ports['8080/tcp'] = [{ HostIp: '::', HostPort: '8080' }]; },
    'egress-port': f => { f.containers.egress.HostConfig.PortBindings = { '8080/tcp': [{ HostIp: '127.0.0.1', HostPort: '9999' }] }; },
    'publish-all': f => { f.containers.web.HostConfig.PublishAllPorts = true; },
    capability: f => { f.containers.web.HostConfig.CapAdd = ['SYS_ADMIN']; },
    'initializer-capability': f => { f.containers['auth-volume-init'].HostConfig.CapAdd = ['SYS_ADMIN']; },
    security: f => { f.containers.egress.HostConfig.SecurityOpt = ['seccomp:unconfined']; },
    writable: f => { f.containers.egress.HostConfig.ReadonlyRootfs = false; },
    namespace: f => { f.containers.web.HostConfig.PidMode = 'host'; },
    'host-network': f => { f.containers.web.HostConfig.NetworkMode = 'host'; },
    device: f => { f.containers.egress.HostConfig.Devices = [{ PathOnHost: '/dev/kvm', PathInContainer: '/dev/kvm', CgroupPermissions: 'rwm' }]; },
    'device-request': f => { f.containers.worker.HostConfig.DeviceRequests = [{ Count: -1, Capabilities: [['gpu']] }]; },
    tmpfs: f => { f.containers.web.HostConfig.Tmpfs['/tmp'] = 'exec,size=1g'; },
    memory: f => { f.containers.egress.HostConfig.Memory = 0; },
    swap: f => { f.containers.worker.HostConfig.MemorySwap = 2147483648; },
    cpu: f => { f.containers.egress.HostConfig.NanoCpus = 0; },
    pids: f => { f.containers.web.HostConfig.PidsLimit = 0; },
    command: f => { f.containers.egress.Config.Cmd = ['sh']; },
    environment: f => { f.containers.web.Config.Env.push('OPENROUTER_API_KEY=SYNTHETIC-PRIVATE'); },
    masked: f => { f.containers.api.HostConfig.MaskedPaths = []; },
    health: f => { f.containers.api.Config.Healthcheck.Test = ['NONE']; },
    'unknown-authority': f => { f.containers.web.HostConfig.UnknownPrivilegedSetting = 'enabled'; },
  };
  for (const [name, mutate] of Object.entries(scenarios)) await t.test(name, async t => {
    const f = await heldFixture(t); mutate(f);
    await assert.rejects(f.refresh(['--accept-current-hold']), failureAt('hold-acceptance', 'runtime-profile'));
    assert(fs.existsSync(join(f.lock, 'refresh.json'))); assert(!fs.existsSync(join(f.stand, 'cve-current-acceptances')));
    assertObservationalCalls(f); assert(!f.logs.join('\n').includes('SYNTHETIC-PRIVATE'));
  });
});

test('accept-current-hold refuses audit mismatch, replaced source inode and replaced lock inode before unlink', async t => {
  for (const scenario of ['audit-bytes', 'audit-inode', 'source-inode', 'lock-inode']) await t.test(scenario, async t => {
    const f = await heldFixture(t); let injected = false;
    const docker = async (args, options) => {
      const root = join(f.stand, 'cve-current-acceptances');
      if (!injected && fs.existsSync(root) && fs.readdirSync(root).length) {
        injected = true;
        const archive = join(root, fs.readdirSync(root)[0]);
        if (scenario === 'audit-bytes') fs.writeFileSync(join(archive, 'failure-status.json'), 'mismatched audit');
        if (scenario === 'audit-inode') {
          const path = join(archive, 'failure-status.json'), temporary = join(f.stand, '.synthetic-audit');
          fs.writeFileSync(temporary, fs.readFileSync(path), { mode: 0o600 }); fs.renameSync(temporary, path);
        }
        if (scenario === 'source-inode') {
          const path = join(f.lock, 'refresh.json'), temporary = join(f.stand, '.synthetic-journal');
          fs.writeFileSync(temporary, fs.readFileSync(path), { mode: 0o600 }); fs.renameSync(temporary, path);
        }
        if (scenario === 'lock-inode') {
          const prior = join(f.stand, '.synthetic-retained-lock'); fs.renameSync(f.lock, prior); fs.mkdirSync(f.lock, { mode: 0o700 });
          for (const leaf of ['images.json', 'refresh.json']) fs.writeFileSync(join(f.lock, leaf), fs.readFileSync(join(prior, leaf)), { mode: 0o600 });
        }
      }
      return f.docker(args, options);
    };
    await assert.rejects(f.refresh(['--accept-current-hold'], { docker }), failureAt('hold-acceptance', 'release'));
    assert(injected); assert(fs.existsSync(join(f.lock, 'images.json'))); assert(fs.existsSync(join(f.lock, 'refresh.json')));
    const root = join(f.stand, 'cve-current-acceptances'), archive = join(root, fs.readdirSync(root)[0]);
    assert(fs.existsSync(join(archive, 'acceptance.json'))); assert(!fs.existsSync(join(archive, 'lock-release.json')));
    assertObservationalCalls(f);
  });
});

test('partial bounded unlink failure preserves complete archive and refuses replay without repairing lock', async t => {
  const f = await heldFixture(t), originalJournal = fs.readFileSync(join(f.lock, 'refresh.json')), removed = [];
  const acceptanceIo = { unlink: path => {
    if (path.endsWith('/refresh.json')) throw Error('SYNTHETIC-PRIVATE-UNLINK-FAILURE');
    removed.push(path); fs.unlinkSync(path);
  }, rmdir: () => assert.fail('rmdir must not follow a failed unlink') };
  await assert.rejects(f.refresh(['--accept-current-hold'], { acceptanceIo }), failureAt('hold-acceptance', 'release'));
  assert.deepEqual(removed, [join(f.lock, 'images.json')]); assert(fs.existsSync(f.lock));
  assert.deepEqual(fs.readFileSync(join(f.lock, 'refresh.json')), originalJournal);
  const root = join(f.stand, 'cve-current-acceptances'), archive = join(root, fs.readdirSync(root)[0]);
  assert.deepEqual(fs.readFileSync(join(archive, 'refresh.json')), originalJournal);
  assert(fs.existsSync(join(archive, 'images.json'))); assert(fs.existsSync(join(archive, 'acceptance.json')));
  assert(!fs.existsSync(join(archive, 'lock-release.json'))); assertObservationalCalls(f);
  const count = f.calls.length;
  await assert.rejects(f.refresh(['--accept-current-hold']), failureAt('hold-acceptance', 'journal'));
  assert.equal(f.calls.length, count); assert(fs.existsSync(join(f.lock, 'refresh.json')));
});

test('failed bounded rmdir leaves empty original lock and complete audit without replay or compensating cleanup', async t => {
  const f = await heldFixture(t), identity = fs.statSync(f.lock).ino;
  await assert.rejects(f.refresh(['--accept-current-hold'], { acceptanceIo: {
    unlink: fs.unlinkSync, rmdir: path => { assert.equal(path, f.lock); throw Error('synthetic rmdir failure'); },
  } }), failureAt('hold-acceptance', 'release'));
  assert.equal(fs.statSync(f.lock).ino, identity); assert.deepEqual(fs.readdirSync(f.lock), []);
  const root = join(f.stand, 'cve-current-acceptances'), archive = join(root, fs.readdirSync(root)[0]);
  for (const name of ['refresh.json', 'images.json', 'failure-status.json', 'baseline.json', 'acceptance.json']) assert(fs.existsSync(join(archive, name)));
  assert(!fs.existsSync(join(archive, 'lock-release.json'))); assertObservationalCalls(f);
  const count = f.calls.length;
  await assert.rejects(f.refresh(['--accept-current-hold']), failureAt('hold-acceptance', 'journal'));
  assert.equal(f.calls.length, count); assert(fs.existsSync(f.lock));
});

test('accept-current-hold refuses wrong phase and preexisting partial audit without replay', async t => {
  const f = await heldFixture(t), path = join(f.lock, 'refresh.json'), original = fs.readFileSync(path, 'utf8');
  const journal = JSON.parse(original); journal.phase = 'stop-idle-worker'; fs.writeFileSync(path, JSON.stringify(journal));
  await assert.rejects(f.refresh(['--accept-current-hold']), failureAt('hold-acceptance', 'journal'));
  assert.equal(f.calls.length, 0); fs.writeFileSync(path, original);
  const status = fs.readFileSync(join(f.stand, 'cve-refresh-status.json'), 'utf8'), images = fs.readFileSync(join(f.lock, 'images.json'), 'utf8');
  const activation = fs.readFileSync(join(f.stand, 'cve.json'), 'utf8');
  const acceptanceId = sha(JSON.stringify({ activation: sha(activation), images: sha(images), journal: sha(original), status: sha(status) }));
  const root = join(f.stand, 'cve-current-acceptances'); fs.mkdirSync(root, { mode: 0o700 });
  const archive = join(root, `accept-current-${acceptanceId}`); fs.mkdirSync(archive, { mode: 0o700 });
  fs.writeFileSync(join(archive, 'images.json'), 'existing-partial-audit', { mode: 0o600 });
  await assert.rejects(f.refresh(['--accept-current-hold']), failureAt('hold-acceptance', 'archive'));
  assert.equal(fs.readFileSync(join(archive, 'images.json'), 'utf8'), 'existing-partial-audit');
  assert(fs.existsSync(join(f.lock, 'images.json'))); assertObservationalCalls(f);
});

test('verify-hold never claims JWT historical continuity even when file and container have both rotated', async t => {
  const f = await heldFixture(t), replacement = 'cd'.repeat(48);
  fs.writeFileSync(join(f.stand, 'scan-jwt'), replacement);
  f.containers.api.Config.Env = f.containers.api.Config.Env.map(p => p.startsWith('SCAN_JWT_SECRET=') ? `SCAN_JWT_SECRET=${replacement}` : p);
  const report = await f.refresh(['--verify-hold']);
  assert.equal(report.historicalPreservationProven, false); assert(report.evidenceGaps.includes('historical-jwt-binding'));
  assert(fs.existsSync(f.lock)); assertObservationalCalls(f); assert(!f.logs.join('\n').includes(replacement));
});

test('verify-hold fails on journal changes during observation without repairing or removing anything', async t => {
  const f = await heldFixture(t), path = join(f.lock, 'refresh.json');
  const docker = async (args, options) => {
    if (args.at(-1) === READY_PROBE) { const j = JSON.parse(fs.readFileSync(path)); j.phase = 'external-change'; fs.writeFileSync(path, JSON.stringify(j)); }
    return f.docker(args, options);
  };
  await assert.rejects(f.refresh(['--verify-hold'], { docker }), failureAt('hold-verification', 'recheck'));
  assert.equal(JSON.parse(fs.readFileSync(path)).phase, 'external-change'); assert(fs.existsSync(f.lock)); assertObservationalCalls(f);
});

test('stage-only touches no Docker and later refresh reuses frozen release without signing again', async t => {
  const f = fixture(t);
  assert.equal((await f.refresh(['--stage-only'])).outcome, 'staged'); assert.deepEqual(f.current(), f.activation);
  assert(f.calls.every(c => c.kind === 'child')); f.calls.length = 0;
  assert.equal((await f.refresh()).outcome, 'activated');
  assert(!f.calls.some(c => c.args[0]?.endsWith('/sign-offline-db.mjs') || c.exe === 'python3'));
});

test('stopped/paused/absent stand never awakened and activation stays current', async t => {
  for (const mode of ['stopped', 'paused', 'absent']) await t.test(mode, async t => {
    const f = fixture(t);
    if (mode === 'absent') delete f.containers.api;
    else if (mode === 'paused') f.containers.api.State.Paused = true;
    else { f.containers.api.State.Running = false; f.containers.api.State.Status = 'exited'; }
    assert.equal((await f.refresh()).outcome, 'deferred-stopped'); assert.deepEqual(f.current(), f.activation); assert.equal(mutations(f).length, 0);
  });
});

test('busy durable work boundedly defers; only same original API resumes, no worker stop or CAS', async t => {
  const f = fixture(t); f.state.pending = [1];
  assert.equal((await f.refresh([], { drainMs: 2000 })).outcome, 'deferred-busy');
  assert.deepEqual(mutations(f).map(c => c.args[1]), ['stop', 'start']);
  assert.deepEqual(f.current(), f.activation); assert(!fs.existsSync(f.lock));
});

test('shared lock excludes updater, setup and launcher up/stop; stale lock is never stolen', async t => {
  const f = fixture(t), release = acquireStandLock(f.root);
  await assert.rejects(f.refresh());
  await assert.rejects(localStand(['up'], { root: f.root, run: () => { throw Error('must not call Docker'); } }));
  await assert.rejects(localStand(['stop'], { root: f.root, run: () => { throw Error('must not call Docker'); } }));
  await assert.rejects(setupLocalCve(['--release', 'prior', '--manifest', oldManifest, '--bundle', 'b'.repeat(64), '--db', 'd'.repeat(64)], { root: f.root }));
  assert(fs.existsSync(f.lock)); assert.equal(f.calls.length, 0); release();
});

test('concurrent refresh cannot sign or activate while first controller owns lock', async t => {
  const f = fixture(t); let checked = false;
  f.state.beforeVerify = async () => {
    if (checked) return; checked = true;
    await assert.rejects(f.refresh());
  };
  assert.equal((await f.refresh(['--stage-only'])).outcome, 'staged'); assert(checked);
});

test('discovery/sign/verify failures expose only fixed public checkpoints and preserve activation', async t => {
  const expected = { discover: ['discovery', 'fetch'], download: ['download', 'fetch'], prepare: ['prepare', 'convert'],
    sign: ['sign', 'attestation'], verify: ['verify', 'candidate-usability'] };
  for (const failure of Object.keys(expected)) await t.test(failure, async t => {
    const f = fixture(t); f.state.fail = failure;
    await assert.rejects(f.refresh(), failureAt(...expected[failure])); assert.deepEqual(f.current(), f.activation); assert.equal(mutations(f).length, 0);
    assert(!fs.existsSync(f.lock));
    if (failure !== 'discover') { f.state.fail = null; await assert.rejects(f.refresh(), refused); }
  });
});

test('missing existing private key refuses changed release without creating replacement', async t => {
  const f = fixture(t); fs.unlinkSync(join(f.trust, 'db-signing-key.pem'));
  await assert.rejects(f.refresh(), failureAt('sign', 'key-pair')); assert(!fs.existsSync(join(f.trust, 'db-signing-key.pem'))); assert.deepEqual(f.current(), f.activation);
});

test('uncertain stop/recreate/readiness exposes fixed checkpoint, retains journal and excludes retries', async t => {
  const expected = { stop: ['fence', 'api-stop'], 'up-worker': ['activate', 'worker'], 'up-api': ['activate', 'api'],
    ready: ['readiness', 'worker'], web: ['readiness', 'web'] };
  for (const failure of Object.keys(expected)) await t.test(failure, async t => {
    const f = fixture(t); f.state.fail = failure;
    await assert.rejects(f.refresh(), failureAt(...expected[failure]));
    assert(fs.existsSync(join(f.lock, 'refresh.json'))); const calls = f.calls.length;
    await assert.rejects(f.refresh()); assert.equal(f.calls.length, calls);
    assert(!mutations(f).some(c => c.args[1] === 'start'));
    if (failure === 'stop') assert.deepEqual(f.current(), f.activation);
    else assert.equal(f.current().manifestDigest, f.manifest);
  });
});

test('CAS conflict after fencing retains HOLD instead of overwriting concurrent activation', async t => {
  const f = fixture(t);
  f.state.beforeStop = item => {
    if (item.Config.Labels['com.docker.compose.service'] === 'worker') fs.writeFileSync(join(f.stand, 'cve.json'), 'conflicting-public-state');
  };
  await assert.rejects(f.refresh(), refused);
  assert.equal(fs.readFileSync(join(f.stand, 'cve.json'), 'utf8'), 'conflicting-public-state');
  assert(fs.existsSync(join(f.lock, 'refresh.json'))); assert(!mutations(f).some(c => c.args.includes('up')));
});

test('disk policy refuses retained-release count and unknown symlinks, never prunes', async t => {
  const f = fixture(t);
  for (let i = 1; i < DISK_POLICY.maxReleases; i++) fs.mkdirSync(join(f.releases, `retained-${i}`));
  await assert.rejects(f.refresh(['--stage-only']), failureAt('staging', 'disk-budget')); assert.equal(fs.readdirSync(f.releases).length, 8);
  const g = fixture(t); fs.symlinkSync(g.prior, join(g.releases, 'linked'));
  assert.throws(() => checkDisk({ stand: g.stand, releases: g.releases })); assert(fs.existsSync(join(g.releases, 'linked')));
});

test('actual readonly drain predicate counts queued, running and undelivered outbox, even terminal undelivered', t => {
  const f = fixture(t), file = join(f.stand, 'synthetic.sqlite');
  const DB = requireApi('better-sqlite3'), db = new DB(file);
  db.exec('PRAGMA user_version = 14; CREATE TABLE scans(state TEXT); CREATE TABLE outbox(delivered_at TEXT);');
  const probe = () => {
    let answer;
    const source = DRAIN_PROBE.replace('/data/ledger.sqlite', file);
    new Function('require', 'console', source)(requireApi, { log: line => { answer = JSON.parse(line); } });
    return answer.pending;
  };
  try {
    assert.equal(probe(), 0); db.exec("INSERT INTO scans VALUES ('queued'),('running'),('completed'); INSERT INTO outbox VALUES (NULL),('delivered');");
    assert.equal(probe(), 3); db.exec("UPDATE scans SET state='completed';"); assert.equal(probe(), 1);
    db.exec('UPDATE outbox SET delivered_at=\'done\';'); assert.equal(probe(), 0);
  } finally { db.close(); }
});

test('current expired authenticated DB refuses unchanged upstream instead of redating or resigning', async t => {
  const f = fixture(t); f.state.discover = oldManifest;
  const metadataPath = join(f.prior, 'db/metadata.json'), descriptorPath = join(f.prior, 'descriptor.json');
  const m = JSON.parse(fs.readFileSync(metadataPath)), d = JSON.parse(fs.readFileSync(descriptorPath));
  m.UpdatedAt = new Date(Date.now() - 16 * 86400_000).toISOString();
  m.NextUpdate = new Date(Date.now() - 15 * 86400_000).toISOString();
  const metadata = Buffer.from(JSON.stringify(m)); d.updatedAt = m.UpdatedAt; d.nextUpdate = m.NextUpdate; d.metadataSha256 = sha(metadata);
  const descriptor = Buffer.from(JSON.stringify(d));
  for (const [name, bytes] of [['db/metadata.json', metadata], ['descriptor.json', descriptor],
    ['descriptor.sig', sign(null, descriptor, createPrivateKey(fs.readFileSync(join(f.trust, 'db-signing-key.pem'))))]]) {
    fs.chmodSync(join(f.prior, name), 0o600); fs.writeFileSync(join(f.prior, name), bytes); fs.chmodSync(join(f.prior, name), 0o444);
  }
  await assert.rejects(f.refresh(), refused); assert.equal(mutations(f).length, 0);
  assert.deepEqual(fs.readFileSync(descriptorPath), descriptor);
});

test('scheduled updater records first uncertain failure and preserves it across later ticks', async t => {
  const f = fixture(t); f.state.fail = 'stop';
  const refresh = (args, options) => f.refresh(args, options);
  await assert.rejects(scheduledRun({ root: f.root, refresh }));
  const path = join(f.stand, 'cve-refresh-status.json');
  const original = fs.readFileSync(path, 'utf8'), status = JSON.parse(original);
  assert.equal(status.state, 'failed'); assert.equal(status.phase, 'fence'); assert.equal(status.checkpoint, 'api-stop');
  const calls = f.calls.length, identity = fs.lstatSync(path);
  await assert.rejects(scheduledRun({ root: f.root, refresh }));
  assert.equal(fs.readFileSync(path, 'utf8'), original);
  assert.equal(fs.lstatSync(path).ino, identity.ino);
  assert.equal(f.calls.length, calls);
  assert(fs.existsSync(join(f.lock, 'refresh.json')));
});

test('scheduled unchanged updater records running status after acquiring shared lock', async t => {
  const f = fixture(t); f.state.discover = oldManifest;
  f.state.beforeVerify = () => {
    assert(fs.existsSync(f.lock));
    assert.equal(JSON.parse(fs.readFileSync(join(f.stand, 'cve-refresh-status.json'))).state, 'running');
  };
  const result = await scheduledRun({ root: f.root, refresh: (args, options) => f.refresh(args, options) });
  assert.equal(result.outcome, 'unchanged');
  assert.equal(JSON.parse(fs.readFileSync(join(f.stand, 'cve-refresh-status.json'))).state, 'completed');
  assert(!fs.existsSync(f.lock)); assert.equal(mutations(f).length, 0);
});

test('unsafe scheduler status aborts updater before child work and releases its own shared lock', async t => {
  const f = fixture(t), path = join(f.stand, 'cve-refresh-status.json');
  fs.symlinkSync(join(f.root, 'missing-status-target'), path);
  await assert.rejects(scheduledRun({ root: f.root, refresh: (args, options) => f.refresh(args, options) }));
  assert.equal(f.calls.length, 0);
  assert.equal(fs.lstatSync(path).isSymbolicLink(), true);
  assert(!fs.existsSync(f.lock));
  assert(!fs.existsSync(join(f.stand, '.cve-schedule.lock')));
});

test('refresh refuses live runtime security/resource drift before any lifecycle mutation', async t => {
  for (const change of [
    f => { f.containers.web.HostConfig.PortBindings['8080/tcp'][0].HostIp = '0.0.0.0'; },
    f => { f.containers.worker.HostConfig.CapAdd = ['SYS_ADMIN']; },
    f => { f.containers.worker.HostConfig.Memory = 0; },
  ]) {
    const f = fixture(t); change(f);
    await assert.rejects(f.refresh(), failureAt('namespace', 'runtime-profile'));
    assert.equal(mutations(f).length, 0); assert.deepEqual(f.current(), f.activation);
    assert(!fs.existsSync(f.lock));
  }
});

test('refresh retains HOLD when recreated runtime loses security/resource constraints', async t => {
  const f = fixture(t);
  const docker = async (args, options) => {
    const result = await f.docker(args, options);
    if (args[0] === 'compose' && args.includes('up') && args.at(-1) === 'worker')
      f.containers.worker.HostConfig.CapAdd = ['SYS_ADMIN'];
    return result;
  };
  await assert.rejects(f.refresh([], { docker }), failureAt('readiness', 'runtime-profile'));
  assert(fs.existsSync(join(f.lock, 'refresh.json')));
  assert(!mutations(f).some(c => c.args[1] === 'start'));
  assert(!mutations(f).some(c => c.args.includes('up') && c.args.at(-1) === 'api'));
});

test('recreated worker mount drift retains HOLD before any worker readiness exec or API up', async t => {
  const variants = {
    'writable-release-declaration-and-observation': (f, declared, mounted) => { declared.ReadOnly = false; mounted.RW = true; },
    'writable-release-observation': (f, declared, mounted) => { mounted.RW = true; },
    'substituted-release-declaration': (f, declared) => { declared.Source = join(f.root, 'foreign-release'); },
    'substituted-release-observation': (f, declared, mounted) => { mounted.Source = join(f.root, 'foreign-release'); },
    'substituted-existing-release': (f, declared, mounted) => { declared.Source = f.prior; mounted.Source = f.prior; },
    'wrong-observed-data-volume': f => { f.containers.worker.Mounts.find(m => m.Destination === '/data').Name = 'foreign-ledger'; },
    'substituted-observed-cache-bind': f => { f.containers.worker.Mounts.find(m => m.Destination === '/tmp/trivy/db').Source = join(f.prior, 'db'); },
  };
  for (const [name, change] of Object.entries(variants)) await t.test(name, async t => {
    const f = fixture(t); let mutated = false;
    const docker = async (args, options) => {
      const result = await f.docker(args, options);
      if (args[0] === 'compose' && args.includes('up') && args.at(-1) === 'worker') {
        const item = f.containers.worker;
        change(f, item.HostConfig.Mounts.find(m => m.Target === '/opt/release'), item.Mounts.find(m => m.Destination === '/opt/release'));
        mutated = true;
      }
      return result;
    };
    await assert.rejects(f.refresh([], { docker }), failureAt('readiness', 'bindings'));
    assert(mutated);
    assert(fs.existsSync(join(f.lock, 'refresh.json')));
    assert(!f.calls.some(c => c.kind === 'docker' && c.args[1] === 'exec' && c.args[2] === f.containers.worker.Id && c.args.at(-1) === READY_PROBE),
      'unsafe worker must not execute READY_PROBE');
    assert(!mutations(f).some(c => c.args.includes('up') && c.args.at(-1) === 'api'), 'API must remain fenced');
    assert.equal(f.containers.api.State.Running, false);
    assert(!mutations(f).some(c => c.args[1] === 'start'));
    const calls = f.calls.length;
    await assert.rejects(f.refresh([], { docker }), failureAt('preflight', 'lock'));
    assert.equal(f.calls.length, calls, 'retained lock must exclude retries');
  });
});

test('refresh rechecks runtime profiles in final namespace census before reporting activation', async t => {
  const f = fixture(t);
  const docker = async (args, options) => {
    const result = await f.docker(args, options);
    if (args.at(-1) === READY_PROBE && args[2] === f.containers.api.Id)
      f.containers.worker.HostConfig.Memory = 0;
    return result;
  };
  await assert.rejects(f.refresh([], { docker }), failureAt('readiness', 'runtime-profile'));
  assert(fs.existsSync(join(f.lock, 'refresh.json')));
  assert(!f.logs.some(line => line.startsWith('LOCAL CVE activated:')));
});

test('foreign writer, private env drift, image mismatch and remote daemon fail before lifecycle mutation', async t => {
  for (const scenario of ['writer', 'env', 'image', 'remote']) await t.test(scenario, async t => {
    const f = fixture(t);
    if (scenario === 'env') f.containers.api.Config.Env.push('OPENROUTER_API_KEY=synthetic-canary');
    if (scenario === 'image') f.containers.worker.Image = `sha256:${'f'.repeat(64)}`;
    if (scenario === 'remote') f.state.host = 'tcp://remote.invalid:2375';
    const docker = async (args, options) => {
      const answer = await f.docker(args, options);
      if (scenario === 'writer' && args.some(a => a === `volume=${PROJECT}_scan_ledger`)) return answer + '\nforeign-writer';
      return answer;
    };
    await assert.rejects(f.refresh([], { docker }), refused); assert.equal(mutations(f).length, 0);
    assert.deepEqual(f.current(), f.activation); assert(!f.logs.join('\n').includes('synthetic-canary'));
  });
});

test('real child adapter bounds timeout/output and strips raw stderr/secrets from errors', async () => {
  const options = { cwd: ROOT, env: childEnvironment(), timeout: 5000 };
  const output = await runChild(process.execPath, ['-e', 'console.log(JSON.stringify(Object.keys(process.env).sort()))'], options);
  // macOS may add this CoreFoundation locale key at process startup.
  const keys = JSON.parse(output).filter(key => !(process.platform === 'darwin' && key === '__CF_USER_TEXT_ENCODING'));
  assert.deepEqual(keys, Object.keys(childEnvironment()).sort());
  await assert.rejects(runChild(process.execPath, ['-e', "console.error('PRIVATE-CANARY');process.exit(1)"], options), error => !error.message.includes('PRIVATE-CANARY'));
  await assert.rejects(runChild(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { ...options, timeout: 50 }));
  await assert.rejects(runChild(process.execPath, ['-e', "console.log('x'.repeat(70000))"], options));
});

test('runtime readiness imports resolve against actual backend in clean child without constructing ledger or reading host keys', async () => {
  const prelude = READY_PROBE.split('const e=process.env;')[0];
  const output = await runChild(process.execPath, ['--import', join(ROOT, 'server/api/node_modules/tsx/dist/loader.mjs'),
    '--input-type=module', '-e', prelude + "console.log([localDbTrustAnchorFromEnv,readDbTrustPublicKey,preflightVulnDbBundle,chainReady,localWorkerReady].every(f=>typeof f==='function') && typeof CURRENT_DB_POLICY==='string')"],
  { cwd: join(ROOT, 'server/api'), env: childEnvironment(), timeout: 10_000 });
  assert.equal(output.trim(), 'true');
});

test('refresh absent workspace never provisions stand/trust or starts a child', async t => {
  const f = fixture(t); writableTree(f.stand); fs.rmSync(f.stand, { recursive: true });
  await assert.rejects(f.refresh(), refused); assert(!fs.existsSync(f.stand)); assert.equal(f.calls.length, 0);
});

test('CLI rejects unknown flags with fixed checkpoint before any dependency calls', async t => {
  const f = fixture(t); await assert.rejects(f.refresh(['--build']), failureAt('preflight', 'arguments')); assert.equal(f.calls.length, 0);
});

test('public diagnostics discard raw child errors, payloads and forged labels without touching getters', async t => {
  const f = fixture(t), canary = 'SYNTHETIC-PRIVATE-ERROR-ARGV-STDOUT-STDERR';
  const raw = Object.assign(new Error(canary), { phase: canary, checkpoint: canary, args: [canary], stdout: canary,
    stderr: canary, env: { SCAN_JWT_SECRET: canary }, cause: Error(canary) });
  let caught;
  try { await f.refresh([], { run: async () => { throw raw; } }); } catch (error) { caught = error; }
  assert(caught); failureAt('discovery', 'fetch')(caught);
  assert(!JSON.stringify(publicRefreshFailure(caught)).includes(canary));
  assert(!fs.existsSync(f.lock)); assert(!fs.existsSync(join(f.stand, '.cve-refresh-work')));
  assert.deepEqual(f.current(), f.activation); assert.equal(mutations(f).length, 0);
  const hostile = new Proxy({}, { get() { assert.fail('unrecognized error properties must never be read'); } });
  for (const value of [raw, hostile, null, undefined, canary]) assert.deepEqual(publicRefreshFailure(value), {
    phase: 'preflight', checkpoint: 'validation',
    message: 'LOCAL CVE refresh refused/HOLD; phase=preflight; checkpoint=validation. No automatic recovery or cleanup.',
  });
});

test('malformed discovery stdout exposes receipt checkpoint, never untrusted stdout', async t => {
  const f = fixture(t), canary = 'SYNTHETIC-PRIVATE-DISCOVERY-OUTPUT';
  await assert.rejects(f.refresh([], { run: async () => canary }), failureAt('discovery', 'receipt'));
  assert(!f.logs.join('\n').includes(canary)); assert(!fs.existsSync(f.lock));
});

test('namespace and drain failures have distinct fixed diagnostics without changing HOLD behavior', async t => {
  for (const target of ['namespace', 'drain']) await t.test(target, async t => {
    const f = fixture(t);
    const docker = async (args, options) => {
      if ((target === 'namespace' && args[0] === 'context') || (target === 'drain' && args.at(-1) === DRAIN_PROBE))
        throw Object.assign(new Error('SYNTHETIC-PRIVATE-DOCKER'), { stdout: secret, stderr: secret });
      return f.docker(args, options);
    };
    await assert.rejects(f.refresh([], { docker }), failureAt(target, target === 'namespace' ? 'docker-endpoint' : 'query'));
    assert.equal(fs.existsSync(join(f.lock, 'refresh.json')), target === 'drain');
    assert.deepEqual(f.current(), f.activation);
  });
});
