#!/usr/bin/env node
// LOCAL operator attestation only. No production trust changes, Docker startup,
// image builds/pulls, volume cleanup, key generation or automatic HOLD recovery.
import * as fs from 'node:fs';
import { createHash, createHmac } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { manifestDescriptor } from '../server/deploy/trust/fetch-db-layer.mjs';
import { acquireStandLock, childEnvironment, runChild, existingLocalCveKeyPair,
  loadCveActivation, directory, layout, readBounded, writeExclusive, syncDirectory, localPaths } from './setup-local-cve.mjs';
import { PROJECT, LABEL, composeArguments, composeEnvironment, dockerEnvironment,
  runDocker, validateConfig, validateCveRelease, inspectNamespace, validateNamespaceMounts, declaredBindMatches, loadSecret } from './local-stand.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const HEX = /^[a-f0-9]{64}(?![\s\S])/;
const DIGEST = /^sha256:[a-f0-9]{64}(?![\s\S])/;
const GiB = 1024 ** 3;
export const DISK_POLICY = Object.freeze({ maxReleases: 8, maxBytes: 16 * GiB, reserveBytes: 6 * GiB });
// Only source-defined labels may cross the error boundary. In particular, never
// attach a cause, child error, argv, output, URL, path, JWT or key material.
const FAILURE_CHECKPOINTS = Object.freeze({
  preflight: ['validation', 'arguments', 'workspace', 'lock', 'status', 'retained-state', 'activation'],
  discovery: ['fetch', 'receipt'],
  'verify-current': ['usability'],
  staging: ['candidate-layout', 'disk-budget', 'workspace', 'freeze', 'cleanup-download', 'frozen-layout', 'activation-cas', 'image-override', 'journal'],
  download: ['fetch', 'receipt'],
  prepare: ['convert', 'receipt', 'layout'],
  sign: ['key-pair', 'attestation', 'envelope'],
  verify: ['candidate-usability', 'frozen-usability', 'monotonic-freshness', 'pre-activation-usability'],
  namespace: ['docker-endpoint', 'compose-config', 'inventory', 'topology', 'credential-binding', 'api-image', 'worker-image', 'runtime-profile', 'writers'],
  fence: ['api-stop', 'api-stopped', 'worker-stop', 'worker-stopped', 'no-writers'],
  drain: ['journal', 'writers', 'identity', 'query', 'wait', 'defer-cas', 'resume-api', 'resume-readiness'],
  activate: ['prepare-cas', 'cas', 'worker', 'api'],
  readiness: ['worker', 'api', 'namespace', 'unchanged-services', 'bindings', 'runtime-profile', 'storage', 'activation', 'web'],
  cleanup: ['journal', 'unlock'],
  'hold-verification': ['journal', 'status', 'activation', 'usability', 'namespace', 'bindings', 'runtime-profile', 'writers', 'created-before-start', 'readiness', 'recheck'],
  'hold-acceptance': ['journal', 'status', 'activation', 'usability', 'namespace', 'bindings', 'runtime-profile', 'writers', 'created-before-start', 'readiness', 'recheck', 'archive', 'audit-recheck', 'release', 'receipt'],
});
const publicFailures = new WeakMap();
const fail = (phase = 'preflight', checkpoint = 'validation') => {
  if (!Object.hasOwn(FAILURE_CHECKPOINTS, phase) || !FAILURE_CHECKPOINTS[phase].includes(checkpoint)) {
    phase = 'preflight'; checkpoint = 'validation';
  }
  const message = `LOCAL CVE refresh refused/HOLD; phase=${phase}; checkpoint=${checkpoint}. No automatic recovery or cleanup.`;
  const error = new Error(message);
  const details = Object.freeze({ phase, checkpoint, message });
  publicFailures.set(error, details);
  return error;
};
// Safe for scheduler integration: arbitrary/unrecognized errors get a fixed
// fallback, without reading their message, getters or other attacker data.
export function publicRefreshFailure(error) {
  return publicFailures.get(error) ?? publicFailures.get(fail());
}
function requireSafe(ok) { if (!ok) throw fail(); }
function exists(path) {
  try { fs.lstatSync(path); return true; } catch (e) { if (e.code === 'ENOENT') return false; throw e; }
}
const json = (path, cap = 4096, mode = 0o444) => JSON.parse(readBounded(path, cap, mode));
const canonical = value => JSON.stringify(value);
const service = item => item.Config.Labels['com.docker.compose.service'];
const active = item => item.State.Running === true && item.State.Status === 'running' &&
  !item.State.Paused && !item.State.Restarting && !item.State.Dead;
const stopped = item => item.State.Running === false && item.State.Status === 'exited' &&
  !item.State.Paused && !item.State.Restarting && !item.State.Dead;
const sort = values => [...values].sort();
const equal = (a, b) => canonical(a) === canonical(b);
// Object key order is not identity. Arrays retain order, except for the outer
// resource/mount collections that are explicitly compared as sets below.
function ordered(value) {
  if (Array.isArray(value)) return value.map(ordered);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(k => [k, ordered(value[k])]));
  return value;
}
const stable = value => canonical(ordered(value));
const dataEqual = (a, b) => stable(a) === stable(b);
const NETWORK_MEMBERS = Object.freeze({ auth_internal: ['api', 'web'], scan_internal: ['api', 'worker', 'egress'],
  registry_uplink: ['egress'], web_edge: ['web'] });
const withoutEndpoints = network => Object.fromEntries(Object.entries(network).filter(([key]) => key !== 'Containers'));

export function validateStorageContinuity(before, after) {
  const records = (items, transform = value => value) => sort(items.map(item => stable(transform(item))));
  requireSafe(before.volumes.length === 2 && after.volumes.length === 2 && before.networks.length === 4 && after.networks.length === 4 &&
    dataEqual(records(before.volumes), records(after.volumes)) &&
    dataEqual(records(before.networks, withoutEndpoints), records(after.networks, withoutEndpoints)));
}

export function validateNetworkMembership(resources, project = PROJECT) {
  requireSafe(resources.networks.length === Object.keys(NETWORK_MEMBERS).length &&
    dataEqual(sort(resources.volumes.map(v => v.Name)), [`${project}_auth_accounts`, `${project}_scan_ledger`]));
  for (const [suffix, members] of Object.entries(NETWORK_MEMBERS)) {
    const found = resources.networks.filter(n => n.Name === `${project}_${suffix}`);
    requireSafe(found.length === 1);
    const network = found[0], endpoints = network.Containers;
    requireSafe(HEX.test(network.Id) && endpoints && typeof endpoints === 'object' && !Array.isArray(endpoints));
    const expected = members.map(name => byService(resources, name));
    requireSafe(dataEqual(sort(Object.keys(endpoints)), sort(expected.map(c => c.Id))));
    for (const item of expected) {
      const endpoint = endpoints[item.Id], attachment = item.NetworkSettings.Networks[network.Name];
      requireSafe(active(item) && endpoint?.Name === `${project}-${service(item)}-1` && attachment?.NetworkID === network.Id &&
        HEX.test(endpoint.EndpointID) && endpoint.EndpointID === attachment.EndpointID &&
        endpoint.MacAddress === attachment.MacAddress &&
        endpoint.IPv4Address === (attachment.IPAddress ? `${attachment.IPAddress}/${attachment.IPPrefixLen}` : '') &&
        endpoint.IPv6Address === (attachment.GlobalIPv6Address ? `${attachment.GlobalIPv6Address}/${attachment.GlobalIPv6PrefixLen}` : ''));
    }
  }
}

// Count bytes without following links or reading any key/JWT. Never delete an old
// release: it may be a retained/mounted version. Budget exhaustion is an operator HOLD.
export function checkDisk(paths) {
  const names = fs.readdirSync(paths.releases);
  requireSafe(names.length < DISK_POLICY.maxReleases);
  let bytes = 0, entries = 0;
  function count(path, depth) {
    requireSafe(++entries <= 128 && depth <= 3);
    const stat = fs.lstatSync(path);
    requireSafe(stat.uid === process.getuid() && !stat.isSymbolicLink());
    if (stat.isDirectory()) {
      for (const name of fs.readdirSync(path)) count(join(path, name), depth + 1);
    } else {
      requireSafe(stat.isFile() && stat.nlink === 1);
      bytes += stat.size;
      requireSafe(bytes <= DISK_POLICY.maxBytes - DISK_POLICY.reserveBytes);
    }
  }
  for (const name of names) count(join(paths.releases, name), 0);
  const disk = fs.statfsSync(paths.stand);
  requireSafe(disk.bavail * disk.bsize >= DISK_POLICY.reserveBytes);
}

export function verifierArguments(root, release, keys, pins) {
  return ['--import', join(root, 'server/api/node_modules/tsx/dist/loader.mjs'), join(root, 'scripts/verify-local-cve.mjs'),
    '--release-dir', release, '--public-key', keys.publicPath, '--public-key-sha256', keys.publicKeySha256,
    '--manifest', pins.manifestDigest, '--bundle', pins.artifactSha256, '--db', pins.dbSha256];
}
export function verifiedOutput(output, pins) {
  const result = JSON.parse(output);
  requireSafe(result.kind === 'authenticated-release-usability-only' && result.scannerChecked === false &&
    result.admissionChecked === false && result.db?.manifestDigest === pins.manifestDigest &&
    result.db.artifactSha256 === pins.artifactSha256 && result.db.dbSha256 === pins.dbSha256);
  return result;
}

// Deliberately no ScanLedger constructor: that constructor opens RW/WAL and may
// migrate. Only a readonly snapshot of both backend durable-work predicates.
export const DRAIN_PROBE = `const DB=require('better-sqlite3');
const db=new DB('/data/ledger.sqlite',{readonly:true,fileMustExist:true,timeout:2000});
try { db.pragma('query_only = ON'); db.exec('BEGIN');
if(db.pragma('user_version',{simple:true})!==14) throw Error('schema');
const n=db.prepare("SELECT (SELECT count(*) FROM scans WHERE state IN ('queued','running')) + (SELECT count(*) FROM outbox WHERE delivered_at IS NULL) AS n").get().n;
db.exec('ROLLBACK'); if(!Number.isSafeInteger(n)||n<0)throw Error('count'); console.log(JSON.stringify({pending:n}));
} finally {db.close();}`;

// These are real backend predicates and authenticated bundle verification, not
// just Docker health (the API healthcheck only tests an unauthenticated 401).
export const WEB_PROBE = `const r=await fetch('http://127.0.0.1:8080/api/v1/auth/me',{redirect:'error',signal:AbortSignal.timeout(5000)}); await r.body?.cancel(); if(r.status!==401)throw Error('web routing'); console.log('{"webReady":true}');`;

export const READY_PROBE = `import {localDbTrustAnchorFromEnv,readDbTrustPublicKey} from './src/worker/vuln-db-trust.ts';
import {preflightVulnDbBundle} from './src/worker/vuln-db-bundle.ts';
import {CURRENT_DB_POLICY} from './src/worker/cve-db-policy.mjs';
import {chainReady} from './src/scans/scan-readiness.ts';
import {localWorkerReady} from './src/oci/nginx-local-profile.ts';
import {lstat} from 'node:fs/promises';
const e=process.env;
if(e.SCAN_VULN_ENABLED!=='true'||!await chainReady()||!await localWorkerReady())throw Error('not ready');
const {identity}=await preflightVulnDbBundle({directory:'/opt/release',trustedPublicKeyPem:readDbTrustPublicKey(localDbTrustAnchorFromEnv()),expectedSigner:'local-db-operator-v1',expectedSource:'ghcr.io/aquasecurity/trivy-db@'+e.SCAN_VULN_MANIFEST_DIGEST,expectedSchemaVersion:2,expectedManifestDigest:e.SCAN_VULN_MANIFEST_DIGEST,expectedArtifactSha256:e.SCAN_VULN_ARTIFACT_SHA256,policy:CURRENT_DB_POLICY});
if(e.TRIVY_CACHE_DIR){for(const n of ['','/trivy.db','/metadata.json']){const a=await lstat('/opt/release/db'+n),b=await lstat('/tmp/trivy/db'+n);if(a.isSymbolicLink()||b.isSymbolicLink()||a.dev!==b.dev||a.ino!==b.ino)throw Error('cache');}}
console.log(JSON.stringify({ready:true,manifest:identity.manifestDigest,bundle:identity.artifactSha256,db:identity.dbSha256}));`;

// Filter enumeration before any inspection. The historical project and its
// containers/images/volumes are never inspected, read or used by the updater.
function scopedDocker(run) {
  return (args, options) => {
    if (args[1] === 'ls') args = [...args.slice(0, 2), '--filter', `label=${LABEL}=v1`, ...args.slice(2)];
    return run(args, options);
  };
}
function envMap(pairs) {
  const out = {};
  for (const pair of pairs ?? []) {
    const i = pair.indexOf('=');
    requireSafe(i > 0 && !Object.hasOwn(out, pair.slice(0, i)));
    out[pair.slice(0, i)] = pair.slice(i + 1);
  }
  return out;
}
function publicSnapshot(resources) {
  return resources.containers.map(c => ({ id: c.Id, service: service(c), image: c.Image }));
}
function byService(resources, name) {
  const found = resources.containers.filter(c => service(c) === name);
  requireSafe(found.length === 1);
  return found[0];
}
function sameIdentity(before, after) {
  requireSafe(before.Id === after.Id && before.Image === after.Image && dataEqual(before.Config, after.Config) &&
    dataEqual(before.HostConfig, after.HostConfig) &&
    dataEqual(sort(before.Mounts.map(stable)), sort(after.Mounts.map(stable))));
}

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const MASKED_PATHS = ['/proc/asound', '/proc/acpi', '/proc/interrupts', '/proc/kcore', '/proc/keys', '/proc/latency_stats',
  '/proc/timer_list', '/proc/timer_stats', '/proc/sched_debug', '/proc/scsi', '/sys/firmware', '/sys/devices/virtual/powercap'];
const READONLY_PATHS = ['/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger'];
const empty = value => value === undefined || value === null || value === false || value === 0 || value === '' ||
  (Array.isArray(value) ? value.length === 0 : typeof value === 'object' && Object.keys(value).length === 0);
const list = value => value ?? [];
function capability(value) {
  requireSafe(typeof value === 'string' && /^(CAP_)?[A-Z_]+(?![\s\S])/.test(value));
  return value.startsWith('CAP_') ? value.slice(4) : value;
}
function securityOption(value) { return value === 'no-new-privileges' ? 'no-new-privileges:true' : value; }
function tmpfsProfile(values) {
  return Object.fromEntries(list(values).map(value => {
    const i = value.indexOf(':');
    const target = i < 0 ? value : value.slice(0, i), options = i < 0 ? '' : value.slice(i + 1);
    return [target, sort(options.split(',').filter(Boolean))];
  }));
}

// Qualify the actual engine profile, not merely the rendered Compose model.
// Unspecified engine fields must be neutral, except explicitly pinned defaults.
// No exposed/published port, capability, device, namespace or resource override
// is inferred safe merely because the container has an ownership label.
export function validateRuntimeProfile(item, spec, image, config, secret, observe = () => {}) {
  const check = (field, ok) => { observe(field, Boolean(ok)); requireSafe(ok); };
  const name = service(item), h = item.HostConfig, c = item.Config, initializer = name.endsWith('volume-init');
  check('Image.identity', image.Id === item.Image && image.Os === 'linux' && (initializer ? image.RepoTags?.includes('busybox:1.37.0') : image.Config?.Labels?.[LABEL] === 'v1'));
  const expectedEnv = { ...envMap(image.Config.Env), ...spec.environment };
  if (name === 'api') expectedEnv.SCAN_JWT_SECRET = secret;
  check('Config.image-and-service', dataEqual(envMap(c.Env), expectedEnv) && dataEqual(c.Cmd, spec.command ?? image.Config.Cmd) &&
    dataEqual(c.Entrypoint ?? null, image.Config.Entrypoint ?? null) && c.User === (spec.user ?? image.Config.User ?? '') &&
    c.WorkingDir === (spec.working_dir ?? image.Config.WorkingDir ?? '') && !c.Tty && !c.OpenStdin && !c.StdinOnce && !c.NetworkDisabled &&
    !c.AttachStdin && !c.ArgsEscaped && !c.Domainname &&
    (c.StopSignal ?? '') === (spec.stop_signal ?? image.Config.StopSignal ?? '') &&
    ['', 'docker-default'].includes(item.AppArmorProfile ?? '') && !item.ProcessLabel && !item.MountLabel);
  const bindings = {}, exposed = { ...image.Config.ExposedPorts };
  for (const port of spec.ports ?? []) {
    check('Ports.desired', name === 'web' && port.host_ip === '127.0.0.1' && String(port.published) === '8080' && port.target === 8080 && port.protocol === 'tcp');
    const key = `${port.target}/${port.protocol}`;
    bindings[key] = [{ HostIp: port.host_ip, HostPort: String(port.published) }]; exposed[key] = {};
  }
  const materialized = Object.fromEntries(Object.keys(exposed).map(key => [key, bindings[key] ?? null]));
  check('Ports.declared-and-observed', dataEqual(c.ExposedPorts ?? {}, exposed) && dataEqual(h.PortBindings ?? {}, bindings) &&
    dataEqual(item.NetworkSettings.Ports ?? {}, materialized) && h.PublishAllPorts === false);
  check('HostConfig.security', h.Privileged === false && h.AutoRemove === false && h.ReadonlyRootfs === Boolean(spec.read_only) &&
    dataEqual(sort(list(h.CapAdd).map(capability)), sort(list(spec.cap_add).map(capability))) &&
    dataEqual(sort(list(h.CapDrop).map(capability)), sort(list(spec.cap_drop).map(capability))) &&
    dataEqual(sort(list(h.SecurityOpt).map(securityOption)), sort(list(spec.security_opt).map(securityOption))) &&
    dataEqual(sort(list(spec.cap_drop).map(capability)), ['ALL']) &&
    dataEqual(sort(list(spec.security_opt).map(securityOption)), ['no-new-privileges:true']));
  const networks = Object.keys(spec.networks ?? {}).map(n => config.networks[n].name);
  check('HostConfig.NetworkMode', initializer ? h.NetworkMode === 'none' : networks.includes(h.NetworkMode));
  const tmpfs = Object.entries(h.Tmpfs ?? {}).map(([target, options]) => `${target}:${options}`);
  check('HostConfig.tmpfs-and-paths', dataEqual(tmpfsProfile(tmpfs), tmpfsProfile(spec.tmpfs)) &&
    dataEqual(sort(h.MaskedPaths ?? []), sort(MASKED_PATHS)) && dataEqual(sort(h.ReadonlyPaths ?? []), sort(READONLY_PATHS)));
  const memory = Number(spec.mem_limit ?? 0);
  const expected = {
    Memory: memory, MemorySwap: Number(spec.memswap_limit ?? (memory * 2)), MemoryReservation: Number(spec.mem_reservation ?? 0),
    NanoCpus: Number(spec.cpus ?? 0) * 1e9, CpuShares: 0, CpuPeriod: 0, CpuQuota: 0, CpuRealtimePeriod: 0, CpuRealtimeRuntime: 0,
    CpusetCpus: '', CpusetMems: '', OomScoreAdj: 0, ShmSize: 67108864,
    IpcMode: 'private', PidMode: '', UTSMode: '', UsernsMode: '', CgroupParent: '', CgroupnsMode: 'private', Runtime: 'runc',
  };
  for (const [key, value] of Object.entries(expected)) check(`HostConfig.${key}`, h[key] === value);
  check('HostConfig.defaults-and-limits', (spec.pids_limit === undefined ? h.PidsLimit === null || h.PidsLimit === 0 : h.PidsLimit === spec.pids_limit) &&
    [null, -1].includes(h.MemorySwappiness) && [null, false].includes(h.OomKillDisable) &&
    dataEqual(h.RestartPolicy, { Name: spec.restart ?? 'no', MaximumRetryCount: 0 }) &&
    dataEqual(h.ConsoleSize, [0, 0]) && ['json-file', 'local'].includes(h.LogConfig?.Type) && dataEqual(h.LogConfig.Config ?? {}, {}));
  const handled = new Set([...Object.keys(expected), 'PortBindings', 'PublishAllPorts', 'Privileged', 'AutoRemove', 'ReadonlyRootfs',
    'CapAdd', 'CapDrop', 'SecurityOpt', 'NetworkMode', 'Tmpfs', 'MaskedPaths', 'ReadonlyPaths', 'PidsLimit', 'MemorySwappiness',
    'OomKillDisable', 'RestartPolicy', 'ConsoleSize', 'LogConfig', 'Mounts']);
  check('HostConfig.unspecified-fields', Object.entries(h).every(([key, value]) => handled.has(key) || empty(value)));
  const declaredMounts = h.Mounts ?? [], desiredMounts = spec.volumes ?? [];
  check('HostConfig.mount-count', Array.isArray(desiredMounts) && Array.isArray(declaredMounts) && declaredMounts.length === desiredMounts.length);
  const actualMounts = item.Mounts ?? [];
  check('Mounts.persistent-targets', Array.isArray(actualMounts) &&
    dataEqual(sort(actualMounts.filter(m => m.Type !== 'tmpfs').map(m => m.Destination)), sort(desiredMounts.map(m => m.target))));
  for (const mount of desiredMounts) {
    const declarations = declaredMounts.filter(m => m.Target === mount.target);
    check('HostConfig.mount-target', declarations.length === 1);
    const declaration = declarations[0];
    if (mount.type === 'volume') check('HostConfig.volume-mount', declaration.Type === 'volume' && declaration.Source === config.volumes[mount.source].name &&
      !declaration.ReadOnly && empty(declaration.VolumeOptions) && empty(declaration.BindOptions));
    // Exact public bind source, declaration and actual RO materialization are
    // checked by namespace validation plus the fixed release/key/cache checks.
    check('HostConfig.mount-options', Object.entries(declaration).every(([key, value]) =>
      ['Type', 'Source', 'Target', 'ReadOnly', 'BindOptions', 'VolumeOptions'].includes(key) || empty(value)));
  }
  const effectiveHealth = spec.healthcheck ? { Test: spec.healthcheck.test, Interval: durationNs(spec.healthcheck.interval),
    Timeout: durationNs(spec.healthcheck.timeout), Retries: spec.healthcheck.retries } : image.Config.Healthcheck;
  const health = value => value ? { Test: value.Test, Interval: value.Interval ?? 0, Timeout: value.Timeout ?? 0,
    Retries: value.Retries ?? 0, StartPeriod: value.StartPeriod ?? 0, StartInterval: value.StartInterval ?? 0 } : null;
  check('Config.Healthcheck', dataEqual(health(c.Healthcheck), health(effectiveHealth)));
  if (c.Healthcheck) check('Config.Healthcheck-fields', Object.keys(c.Healthcheck).every(k => ['Test', 'Interval', 'Timeout', 'Retries', 'StartPeriod', 'StartInterval'].includes(k)));
}
function durationNs(value) {
  if (typeof value === 'number') return value;
  const match = /^(\d+)(ns|us|ms|s|m|h)(?![\s\S])/.exec(value ?? '');
  requireSafe(match);
  return Number(match[1]) * ({ ns: 1, us: 1000, ms: 1e6, s: 1e9, m: 60e9, h: 3600e9 })[match[2]];
}

// Shared checks for ONLY the late-stage refresh HOLD. The default verify mode is
// observational. The separately selected accept-current mode archives evidence
// and retires only this exact lock; it never certifies/replays the failed attempt,
// changes activation, resumes services, downloads, signs or retries mutations.
export async function verifyLocalCveHold({ root = ROOT, run = runChild, docker = runDocker,
  ambient = process.env, log = console.log, now = () => performance.now(), platform = process.platform,
  acceptanceIo = { unlink: fs.unlinkSync, rmdir: fs.rmdirSync } } = {}, acceptCurrent = false) {
  let checkpoint = 'journal';
  const deadline = now() + 600_000;
  const remaining = cap => { const t = Math.ceil(Math.min(cap, deadline - now())); requireSafe(t > 0); return t; };
  try {
    const paths = localPaths(root), lock = join(paths.stand, '.stand-operation.lock');
    directory(lock, 0o700);
    const lockIdentity = fs.lstatSync(lock);
    requireSafe(dataEqual(sort(fs.readdirSync(lock)), ['images.json', 'refresh.json']) &&
      !exists(join(paths.stand, '.cve-refresh-work')) && !exists(join(paths.stand, '.cve-setup.lock')) &&
      !exists(join(paths.stand, '.cve.json.pending')));
    const journalPath = join(lock, 'refresh.json'), imagePath = join(lock, 'images.json');
    const journalBytes = readBounded(journalPath, 16384, 0o600), imageBytes = readBounded(imagePath, 4096, 0o600);
    const sourceIdentities = new Map([[journalPath, fs.lstatSync(journalPath)], [imagePath, fs.lstatSync(imagePath)]]);
    if (acceptCurrent) requireSafe(!exists(join(paths.stand, '.cve-schedule.lock')));
    const journal = JSON.parse(journalBytes);
    requireSafe(dataEqual(sort(Object.keys(journal)), ['candidate', 'containers', 'images', 'phase', 'prior', 'version']) &&
      journal.version === 1 && journal.phase === 'activate-api' && Array.isArray(journal.containers) &&
      journal.containers.length >= 4 && journal.containers.length <= 6 &&
      dataEqual(sort(Object.keys(journal.images)), ['api', 'worker']) &&
      DIGEST.test(journal.images.api) && DIGEST.test(journal.images.worker) &&
      dataEqual(JSON.parse(imageBytes), { services: { api: { image: journal.images.api }, worker: { image: journal.images.worker } } }));
    const priorRecords = new Map();
    for (const item of journal.containers) {
      requireSafe(dataEqual(sort(Object.keys(item)), ['id', 'image', 'service']) && HEX.test(item.id) && DIGEST.test(item.image) &&
        ['api', 'worker', 'web', 'egress', 'auth-volume-init', 'scan-volume-init'].includes(item.service) && !priorRecords.has(item.service));
      priorRecords.set(item.service, item);
    }
    for (const name of ['api', 'worker', 'web', 'egress']) requireSafe(priorRecords.has(name));
    for (const name of ['api', 'worker']) requireSafe(priorRecords.get(name).image === journal.images[name]);

    checkpoint = 'status';
    const statusPath = join(paths.stand, 'cve-refresh-status.json'), statusBytes = readBounded(statusPath, 4096, 0o600);
    sourceIdentities.set(statusPath, fs.lstatSync(statusPath));
    const status = JSON.parse(statusBytes);
    requireSafe(status.version === 1 && status.state === 'failed' && status.phase === 'readiness' && status.checkpoint === 'storage' &&
      typeof status.startedAt === 'string' && new Date(status.startedAt).toISOString() === status.startedAt &&
      typeof status.finishedAt === 'string' && new Date(status.finishedAt).toISOString() === status.finishedAt &&
      Date.parse(status.finishedAt) >= Date.parse(status.startedAt));

    checkpoint = 'activation';
    const current = loadCveActivation(root), activationBytes = readBounded(paths.config, 4096, 0o600);
    requireSafe(dataEqual(current, journal.candidate) && current.publicKeySha256 === journal.prior.publicKeySha256);
    const cve = validateCveRelease(root, current);
    validateCveRelease(root, journal.prior);
    const descriptor = json(join(cve.releaseHostDir, 'descriptor.json'));
    requireSafe(HEX.test(descriptor.dbSha256));
    const pins = { ...current, dbSha256: descriptor.dbSha256 };
    const child = (args, cap = 120_000) => run(process.execPath, args, { cwd: root, env: childEnvironment(), timeout: remaining(cap) });
    checkpoint = 'usability';
    verifiedOutput(await child(verifierArguments(root, cve.releaseHostDir,
      { publicPath: cve.publicKeyPath, publicKeySha256: current.publicKeySha256 }, pins)), pins);

    checkpoint = 'namespace';
    const options = { root, env: dockerEnvironment({ ...ambient, PATH: childEnvironment().PATH }) };
    const d = (args, extra = {}) => docker(args, { ...options, ...extra, timeout: remaining(extra.timeout ?? 30_000) });
    const host = options.env.DOCKER_HOST && !options.env.DOCKER_CONTEXT ? options.env.DOCKER_HOST :
      JSON.parse(await d(['context', 'inspect', ...(options.env.DOCKER_CONTEXT ? [options.env.DOCKER_CONTEXT] : []),
        '--format', '{{json .Endpoints.docker.Host}}']));
    requireSafe(typeof host === 'string' && host.startsWith('unix:///') && !host.includes('\n'));
    const config = JSON.parse(await d(composeArguments(root, ['config', '--format', 'json'], cve),
      { env: composeEnvironment(options.env, undefined, cve) }));
    validateConfig(config, root, cve);
    const inventory = () => inspectNamespace(scopedDocker(d), options, { platform });
    const observed = await inventory();
    requireSafe(observed.containers.length === journal.containers.length && observed.volumes.length === 2 && observed.networks.length === 4);
    validateNetworkMembership(observed);
    for (const item of observed.containers) {
      const name = service(item), prior = priorRecords.get(name);
      requireSafe(prior && item.Image === prior.image);
      if (['api', 'worker'].includes(name)) requireSafe(active(item) && item.Config.Image === journal.images[name] && item.Id !== prior.id);
      else requireSafe(item.Id === prior.id && (['web', 'egress'].includes(name) ? active(item) : !item.State.Running));
    }

    checkpoint = 'bindings';
    // Current file/container equality only, NOT evidence that this JWT is the
    // pre-switch value: v1 deliberately never journaled that secret or a binding.
    const secret = readBounded(join(paths.stand, 'scan-jwt'), 96, 0o600);
    requireSafe(/^[a-f0-9]{96}(?![\s\S])/.test(secret));
    for (const name of ['api', 'worker']) {
      const item = byService(observed, name);
      const [image] = JSON.parse(await d(['image', 'inspect', journal.images[name]]));
      requireSafe(image.Id === item.Image && image.Config?.Labels?.[LABEL] === 'v1');
      const expected = { ...envMap(image.Config.Env), ...config.services[name].environment };
      if (name === 'api') expected.SCAN_JWT_SECRET = secret;
      requireSafe(dataEqual(envMap(item.Config.Env), expected) && dataEqual(item.Config.Cmd, config.services[name].command) &&
        dataEqual(item.Config.Entrypoint, image.Config.Entrypoint) && item.Config.WorkingDir === '/app/server/api' &&
        item.Config.User === '65532:65532' && item.HostConfig.ReadonlyRootfs === true && !item.HostConfig.Privileged &&
        !item.HostConfig.AutoRemove && item.HostConfig.RestartPolicy?.Name === 'unless-stopped');
      const binds = [{ source: cve.releaseHostDir, target: '/opt/release' },
        { source: cve.publicKeyPath, target: '/opt/local-db-trust/public.pem' },
        ...(name === 'worker' ? [{ source: join(cve.releaseHostDir, 'db'), target: '/tmp/trivy/db' }] : [])];
      for (const bind of binds) {
        const declaration = item.HostConfig.Mounts.find(m => m.Target === bind.target);
        const mount = item.Mounts.find(m => m.Destination === bind.target);
        requireSafe(mount && declaredBindMatches(declaration, mount, bind, platform));
      }
      if (name === 'api') requireSafe(item.State.Health?.Status === 'healthy');
    }
    checkpoint = 'runtime-profile';
    const runtimeImages = new Map();
    requireSafe(dataEqual(sort(observed.containers.map(service)), sort(Object.keys(config.services))));
    for (const item of observed.containers) {
      const [image] = JSON.parse(await d(['image', 'inspect', item.Image]));
      validateRuntimeProfile(item, config.services[service(item)], image, config, secret);
      runtimeImages.set(item.Image, image);
      if (service(item).endsWith('volume-init')) requireSafe(stopped(item) && item.State.ExitCode === 0);
    }
    checkpoint = 'writers';
    for (const [suffix, names] of [['scan_ledger', ['api', 'worker']], ['auth_accounts', ['api']]]) {
      const ids = (await d(['container', 'ls', '--filter', `volume=${PROJECT}_${suffix}`, '--format', '{{.ID}}', '--no-trunc']))
        .trim().split('\n').filter(Boolean);
      requireSafe(dataEqual(sort(ids), sort(names.map(name => byService(observed, name).Id))));
    }
    checkpoint = 'created-before-start';
    // Docker's native names differ: volume CreatedAt versus network Created.
    for (const [items, field] of [[observed.volumes, 'CreatedAt'], [observed.networks, 'Created']]) {
      for (const item of items) requireSafe(typeof item[field] === 'string' &&
        Number.isFinite(Date.parse(item[field])) && Date.parse(item[field]) < Date.parse(status.startedAt));
    }

    checkpoint = 'readiness';
    for (const name of ['worker', 'api']) {
      const item = byService(observed, name);
      const result = JSON.parse(await d(['container', 'exec', item.Id, 'node', '--import', 'tsx', '--input-type=module', '-e', READY_PROBE], { timeout: 120_000 }));
      requireSafe(result.ready === true && result.manifest === current.manifestDigest && result.bundle === current.artifactSha256 && result.db === descriptor.dbSha256);
    }
    requireSafe(JSON.parse(await child(['--input-type=module', '-e', WEB_PROBE], 10_000)).webReady === true);
    checkpoint = 'recheck';
    const final = await inventory();
    validateStorageContinuity(observed, final); validateNetworkMembership(final);
    requireSafe(final.containers.length === observed.containers.length);
    for (const prior of observed.containers) {
      const item = byService(final, service(prior)); sameIdentity(prior, item);
      validateRuntimeProfile(item, config.services[service(item)], runtimeImages.get(item.Image), config, secret);
      requireSafe(dataEqual(prior.NetworkSettings, item.NetworkSettings) && prior.State.Running === item.State.Running &&
        prior.State.Status === item.State.Status && !item.State.Paused && !item.State.Restarting && !item.State.Dead);
      if (service(item) === 'api') requireSafe(item.State.Health?.Status === 'healthy');
    }
    const sourceBytes = new Map([[journalPath, journalBytes], [imagePath, imageBytes], [statusPath, statusBytes]]);
    const recheckSources = (removed = []) => {
      directory(lock, 0o700);
      const identity = fs.lstatSync(lock);
      requireSafe(identity.dev === lockIdentity.dev && identity.ino === lockIdentity.ino &&
        dataEqual(sort(fs.readdirSync(lock)), ['images.json', 'refresh.json'].filter(name => !removed.includes(join(lock, name)))) &&
        readBounded(paths.config, 4096, 0o600) === activationBytes && readBounded(join(paths.stand, 'scan-jwt'), 96, 0o600) === secret &&
        (!acceptCurrent || !exists(join(paths.stand, '.cve-schedule.lock'))));
      for (const [path, bytes] of sourceBytes) if (!removed.includes(path)) {
        const original = sourceIdentities.get(path), current = fs.lstatSync(path);
        requireSafe(current.dev === original.dev && current.ino === original.ino && readBounded(path, 16384, 0o600) === bytes);
      }
    };
    recheckSources();
    const report = { mode: 'verify-hold', outcome: 'hold-retained', currentChecksPassed: true, lockRemoved: false,
      finalizationAuthorized: false, historicalPreservationProven: false,
      checks: ['signed-usability', 'current-namespace-and-exact-endpoints', 'journal-images-and-unchanged-service-ids',
        'current-mounts-and-jwt-equality', 'complete-runtime-profile', 'created-before-recorded-start', 'backend-and-web-readiness', 'stable-recheck'],
      evidenceGaps: ['historical-storage-network-baseline', 'historical-container-configuration', 'historical-jwt-binding', 'journal-status-run-binding'] };
    if (!acceptCurrent) { log(canonical(report)); return report; }

    checkpoint = 'archive';
    for (const bytes of sourceBytes.values()) requireSafe(!bytes.includes('\uFFFD')); // Refuse lossy UTF-8 archival.
    const acceptanceId = sha256(stable({ journal: sha256(journalBytes), images: sha256(imageBytes), status: sha256(statusBytes), activation: sha256(activationBytes) }));
    const auditRoot = join(paths.stand, 'cve-current-acceptances');
    if (!exists(auditRoot)) { fs.mkdirSync(auditRoot, { mode: 0o700 }); syncDirectory(paths.stand); }
    directory(auditRoot, 0o700);
    const auditRootIdentity = fs.lstatSync(auditRoot);
    // At most 16 small, independently retained receipts. No pruning/adoption.
    const archives = fs.readdirSync(auditRoot); requireSafe(archives.length < 16);
    let retainedBytes = 0;
    for (const name of archives) {
      requireSafe(/^accept-current-[a-f0-9]{64}(?![\s\S])/.test(name));
      const path = join(auditRoot, name); directory(path, 0o700);
      const names = fs.readdirSync(path); requireSafe(names.length <= 6);
      for (const leaf of names) {
        requireSafe(['refresh.json', 'images.json', 'failure-status.json', 'baseline.json', 'acceptance.json', 'lock-release.json'].includes(leaf));
        const stat = fs.lstatSync(join(path, leaf));
        requireSafe(stat.isFile() && !stat.isSymbolicLink() && stat.uid === process.getuid() && stat.nlink === 1 &&
                  (stat.mode & 0o7777) === 0o600 && stat.size > 0 && stat.size <= 262144);
        retainedBytes += stat.size;
      }
    }
    requireSafe(retainedBytes <= 8 * 1024 ** 2);
    const archive = join(auditRoot, `accept-current-${acceptanceId}`);
    fs.mkdirSync(archive, { mode: 0o700 }); syncDirectory(auditRoot); // EEXIST means no replay, including partial failure.
    const archiveIdentity = fs.lstatSync(archive);
    const audit = new Map([['refresh.json', journalBytes], ['images.json', imageBytes], ['failure-status.json', statusBytes]]);
    const desired = JSON.parse(stable(config));
    desired.services.api.environment.SCAN_JWT_SECRET = '[redacted]';
    const baseline = { version: 1, establishedAt: new Date().toISOString(), basis: 'new-current-baseline-not-failed-attempt-certification', activation: current,
      desired, jwtBinding: createHmac('sha256', secret).update(`LOCAL-current-baseline-v1:${acceptanceId}:${activationBytes}`).digest('hex'),
      containers: final.containers.map(item => ({ id: item.Id, service: service(item), image: item.Image,
        configSha256: sha256(stable({ ...item.Config, Env: item.Config.Env.filter(p => !p.startsWith('SCAN_JWT_SECRET=')) })),
        user: item.Config.User, workingDir: item.Config.WorkingDir, hostConfig: item.HostConfig, mounts: item.Mounts,
        ports: item.NetworkSettings.Ports, networks: item.NetworkSettings.Networks })),
      volumes: final.volumes.map(v => ({ name: v.Name, createdAt: v.CreatedAt, metadataSha256: sha256(stable(v)) })),
      networks: final.networks.map(n => ({ name: n.Name, id: n.Id, createdAt: n.Created, metadataSha256: sha256(stable(withoutEndpoints(n))), endpoints: n.Containers })) };
    audit.set('baseline.json', canonical(baseline));
    const accepted = { ...report, mode: 'accept-current-hold', outcome: 'current-baseline-qualified-pending-lock-release', acceptanceId,
      acceptedCurrentOnly: true, failedAttemptCertified: false, failedAttemptReplayed: false,
      finalizationAuthorized: false, currentBaselineAcceptanceAuthorized: true, maintenanceResumeAuthorized: true,
      lockRemoved: false, lockRelease: 'pending',
      auditDirectory: `cve-current-acceptances/accept-current-${acceptanceId}`,
      hashes: Object.fromEntries([...audit].map(([name, bytes]) => [name, sha256(bytes)])) };
    audit.set('acceptance.json', canonical(accepted));
    for (const [name, bytes] of audit) { requireSafe(Buffer.byteLength(bytes) <= 262144); writeExclusive(join(archive, name), bytes, 0o600); }
    syncDirectory(archive); syncDirectory(auditRoot);
    const auditIdentities = new Map([...audit.keys()].map(name => [name, fs.lstatSync(join(archive, name))]));
    checkpoint = 'audit-recheck';
    const assertArchive = () => {
      directory(auditRoot, 0o700); directory(archive, 0o700);
      const rootStat = fs.lstatSync(auditRoot), archiveStat = fs.lstatSync(archive);
      requireSafe(rootStat.dev === auditRootIdentity.dev && rootStat.ino === auditRootIdentity.ino &&
        archiveStat.dev === archiveIdentity.dev && archiveStat.ino === archiveIdentity.ino &&
        dataEqual(sort(fs.readdirSync(archive)), sort([...audit.keys()])));
      for (const [name, bytes] of audit) {
        const stat = fs.lstatSync(join(archive, name)), original = auditIdentities.get(name);
        requireSafe(stat.dev === original.dev && stat.ino === original.ino && readBounded(join(archive, name), 262144, 0o600) === bytes);
      }
    };
    assertArchive(); recheckSources();
    const latest = await inventory();
    validateStorageContinuity(final, latest); validateNetworkMembership(latest);
    requireSafe(latest.containers.length === final.containers.length);
    for (const prior of final.containers) {
      const item = byService(latest, service(prior)); sameIdentity(prior, item);
      validateRuntimeProfile(item, config.services[service(item)], runtimeImages.get(item.Image), config, secret);
      requireSafe(dataEqual(prior.NetworkSettings, item.NetworkSettings) &&
        prior.State.Running === item.State.Running && prior.State.Status === item.State.Status && !item.State.Paused && !item.State.Restarting && !item.State.Dead);
      if (service(item) === 'api') requireSafe(item.State.Health?.Status === 'healthy');
    }
    // No awaits or daemon calls after this boundary. Only these two known files
    // may be unlinked, and only the original exact directory may be removed.
    // Failure at any point preserves the durable archive; nothing is replayed.
    checkpoint = 'release';
    assertArchive(); recheckSources();
    const removed = [];
    for (const path of [imagePath, journalPath]) {
      assertArchive(); recheckSources(removed);
      acceptanceIo.unlink(path); removed.push(path); syncDirectory(lock);
    }
    assertArchive(); recheckSources(removed);
    acceptanceIo.rmdir(lock); syncDirectory(paths.stand);
    checkpoint = 'receipt';
    const receipt = { acceptanceId, lockRemoved: true, currentBaselineOnly: true, historicalPreservationProven: false };
    writeExclusive(join(archive, 'lock-release.json'), canonical(receipt), 0o600); syncDirectory(archive);
    const result = { ...accepted, outcome: 'current-baseline-accepted', lockRemoved: true, lockRelease: 'acknowledged' };
    log(canonical(result)); return result;
  } catch { throw fail(acceptCurrent ? 'hold-acceptance' : 'hold-verification', checkpoint); }
}

// Filesystem/transport/signature primitives only: no LOCAL paths, activation,
// Docker, key generation or lifecycle authority. Public refresh supplies its own
// paths, existing-key provider, verifier and candidate binding validator.
export async function prepareFrozenCandidate({ root, paths, current, oldDescriptor, manifest, child, verify,
  getKeys, validateCandidate, diskCheck = checkDisk, mark = () => {} }) {
  mark('staging', 'candidate-layout');
  const releaseName = manifest.slice(7), release = join(paths.releases, releaseName);
  requireSafe(DIGEST.test(manifest));
  let pins;
  if (exists(release)) {
    layout(release, true, true);
    const descriptor = json(join(release, 'descriptor.json'));
    requireSafe(HEX.test(descriptor.artifactSha256) && HEX.test(descriptor.dbSha256));
    pins = { manifestDigest: manifest, artifactSha256: descriptor.artifactSha256, dbSha256: descriptor.dbSha256 };
  } else {
    mark('staging', 'disk-budget'); diskCheck(paths);
    mark('staging', 'workspace');
    const scratch = join(paths.stand, '.cve-refresh-work');
    fs.mkdirSync(scratch, { mode: 0o700 });
    const download = join(scratch, 'download');
    mark('download', 'fetch');
    await child(process.execPath, [join(root, 'server/deploy/trust/fetch-db-layer.mjs'), manifest, download], 240_000);
    mark('download', 'receipt');
    directory(scratch, 0o700); directory(download, 0o700);
    const layer = manifestDescriptor(Buffer.from(readBounded(join(download, 'manifest.json'), 65536, 0o600)), manifest, manifest);
    mark('prepare', 'convert');
    const output = await child('python3', [join(root, 'server/deploy/trust/prepare-db-release.py'), download, release,
      manifest, layer.digest], 240_000);
    mark('prepare', 'receipt');
    const lines = output.trimEnd().split('\n');
    requireSafe(lines.length === 2 && lines[1] === 'Unsigned release: independently review pins, then use operator-only signer.');
    const prepared = JSON.parse(lines[0]);
    requireSafe(prepared.manifest === manifest && prepared.layer === layer.digest && HEX.test(prepared.bundle) && HEX.test(prepared.db));
    pins = { manifestDigest: manifest, artifactSha256: prepared.bundle, dbSha256: prepared.db };
    mark('prepare', 'layout'); layout(release, false);
    mark('sign', 'key-pair'); const keys = getKeys();
    mark('sign', 'attestation');
    await child(process.execPath, [join(root, 'server/deploy/trust/sign-offline-db.mjs'), release,
      keys.privatePath, keys.publicPath, manifest, pins.artifactSha256, pins.dbSha256], 120_000);
    mark('sign', 'envelope'); layout(release, true);
    mark('verify', 'candidate-usability'); await verify(release, pins);
    mark('staging', 'freeze');
    for (const path of layout(release, true)) {
      const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
      try { fs.fchmodSync(fd, 0o444); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    }
    fs.chmodSync(join(release, 'db'), 0o555); fs.chmodSync(release, 0o555);
    syncDirectory(join(release, 'db')); syncDirectory(release); syncDirectory(paths.releases);
    mark('staging', 'cleanup-download');
    directory(scratch, 0o700); directory(download, 0o700);
    requireSafe(equal(sort(fs.readdirSync(download)), ['layer.tar.gz', 'manifest.json']));
    readBounded(join(download, 'manifest.json'), 65536, 0o600);
    const layerStat = fs.lstatSync(join(download, 'layer.tar.gz'));
    requireSafe(layerStat.isFile() && !layerStat.isSymbolicLink() && layerStat.nlink === 1 && layerStat.uid === process.getuid());
    fs.unlinkSync(join(download, 'manifest.json')); fs.unlinkSync(join(download, 'layer.tar.gz'));
    fs.rmdirSync(download); fs.rmdirSync(scratch);
  }
  mark('staging', 'frozen-layout');
  const candidate = { version: 1, release: `db-releases/${releaseName}`, manifestDigest: manifest,
    artifactSha256: pins.artifactSha256, publicKeySha256: current.publicKeySha256 };
  const next = validateCandidate(candidate);
  mark('verify', 'frozen-usability'); const receipt = await verify(release, pins);
  mark('verify', 'monotonic-freshness');
  requireSafe(Number.isFinite(Date.parse(oldDescriptor.updatedAt)) &&
    Date.parse(receipt.db.updatedAt) >= Date.parse(oldDescriptor.updatedAt));
  return { candidate, next, pins, receipt, release };
}

export async function refreshLocalCve(argv = [], { root = ROOT, run = runChild, docker = runDocker,
  ambient = process.env, log = console.log, sleep = ms => new Promise(r => setTimeout(r, ms)),
  now = () => performance.now(), drainMs = 120_000, diskCheck = checkDisk, platform = process.platform, acceptanceIo,
    onLocked = () => {} } = {}) {
  if (equal(argv, ['--verify-hold']) || equal(argv, ['--accept-current-hold']))
    return verifyLocalCveHold({ root, run, docker, ambient, log, now, platform, acceptanceIo }, argv[0] === '--accept-current-hold');
  let phase = 'preflight', checkpoint = 'arguments';
  const mark = (nextPhase, nextCheckpoint) => { phase = nextPhase; checkpoint = nextCheckpoint; };
  let unlock, journalPath, hold = false;
  const releaseLock = () => {
    if (unlock && !hold) {
      try { unlock(); } catch { throw fail('cleanup', 'unlock'); }
    }
  };
  let deadline;
  const remaining = cap => { const t = Math.ceil(Math.min(cap, deadline - now())); requireSafe(t > 0); return t; };
  try {
    requireSafe(argv.length === 0 || equal(argv, ['--stage-only']));
    deadline = now() + 900_000;
    mark('preflight', 'workspace');
    localPaths(root); // Refresh never provisions a stand or trust directory.
    mark('preflight', 'lock');
    unlock = acquireStandLock(root);
    // A refused overlapping run must not replace the current owner's status or HOLD evidence.
    mark('preflight', 'status');
    await onLocked();
    const paths = localPaths(root), lock = join(paths.stand, '.stand-operation.lock');
    // Refuse incomplete prior setup/staging, never adopt or erase it.
    mark('preflight', 'retained-state');
    requireSafe(!exists(join(paths.stand, '.cve-setup.lock')) && !exists(join(paths.stand, '.cve.json.pending')) &&
      !exists(join(paths.stand, '.cve-refresh-work')));
    mark('preflight', 'activation');
    const current = loadCveActivation(root), original = canonical(current);
    const currentDir = join(paths.stand, current.release);
    const oldDescriptor = json(join(currentDir, 'descriptor.json'));
    requireSafe(HEX.test(oldDescriptor.dbSha256));
    const publicKeys = { publicPath: join(paths.trust, 'db-signing-key.pub.pem'), publicKeySha256: current.publicKeySha256 };
    const child = (executable, args, cap) => run(executable, args,
      { cwd: root, env: childEnvironment(), timeout: remaining(cap) });
    const verify = async (release, pins) => verifiedOutput(await child(process.execPath,
      verifierArguments(root, release, publicKeys, pins), 120_000), pins);
    mark('discovery', 'fetch');
    const discovery = await child(process.execPath, [join(root, 'server/deploy/trust/fetch-db-layer.mjs'), 'discover'], 60_000);
    mark('discovery', 'receipt');
    const match = /^Review upstream tag :2, then download by digest: (sha256:[a-f0-9]{64})\r?\n$/.exec(discovery);
    requireSafe(match && DIGEST.test(match[1]));
    const manifest = match[1];
    if (manifest === current.manifestDigest) {
      mark('verify-current', 'usability');
      await verify(currentDir, { ...current, dbSha256: oldDescriptor.dbSha256 });
      log('LOCAL CVE unchanged; current signature, hashes and real-time usability authenticated. No signing or Docker calls.');
      return { outcome: 'unchanged', manifest };
    }
    const { candidate, next, pins, release } = await prepareFrozenCandidate({ root, paths, current, oldDescriptor,
      manifest, child, verify, mark, diskCheck, getKeys: () => existingLocalCveKeyPair(root, current.publicKeySha256),
      validateCandidate: value => validateCveRelease(root, value) });
    mark('staging', 'activation-cas');
    const cas = () => requireSafe(readBounded(paths.config, 4096, 0o600) === original && equal(loadCveActivation(root), current));
    cas();
    if (argv[0] === '--stage-only') {
      log('LOCAL CVE candidate authenticated and frozen; activation unchanged; Docker not contacted.');
      return { outcome: 'staged', manifest };
    }

    mark('namespace', 'docker-endpoint');
    const options = { root, env: dockerEnvironment({ ...ambient, PATH: childEnvironment().PATH }) };
    const d = (args, extra = {}) => docker(args, { ...options, ...extra, timeout: remaining(extra.timeout ?? 30_000) });
    const host = options.env.DOCKER_HOST && !options.env.DOCKER_CONTEXT ? options.env.DOCKER_HOST :
      JSON.parse(await d(['context', 'inspect', ...(options.env.DOCKER_CONTEXT ? [options.env.DOCKER_CONTEXT] : []),
        '--format', '{{json .Endpoints.docker.Host}}']));
    requireSafe(typeof host === 'string' && host.startsWith('unix:///') && !host.includes('\n'));
    const inventory = () => inspectNamespace(scopedDocker(d), options, { platform });
    const composeConfig = async cve => {
      const config = JSON.parse(await d(composeArguments(root, ['config', '--format', 'json'], cve),
        { env: composeEnvironment(options.env, undefined, cve) }));
      validateConfig(config, root, cve); return config;
    };
    mark('namespace', 'compose-config');
    const nextConfig = await composeConfig(next);
    mark('namespace', 'inventory');
    const before = await inventory();
    mark('namespace', 'topology');
    const apps = ['api', 'worker', 'web', 'egress'];
    if (apps.some(name => !before.containers.some(c => service(c) === name && active(c)))) {
      log('LOCAL CVE deferred: stand absent/stopped/paused; candidate retained, no service started or activation changed.');
      return { outcome: 'deferred-stopped', manifest };
    }
    requireSafe(before.volumes.length === 2 && before.networks.length === 4 &&
      before.containers.every(c => apps.includes(service(c)) ? active(c) : !c.State.Running));
    validateNetworkMembership(before);
    const api = byService(before, 'api'), worker = byService(before, 'worker');
    // The only permitted writers to the new ledger/account volumes are these
    // two services. Projection-only volume-filtered census refuses extra actors.
    const writers = async () => {
      for (const [volume, expected] of [['scan_ledger', [api.Id, worker.Id]], ['auth_accounts', [api.Id]]]) {
        const ids = (await d(['container', 'ls', '--filter', `volume=${PROJECT}_${volume}`, '--format', '{{.ID}}', '--no-trunc']))
          .trim().split('\n').filter(Boolean);
        requireSafe(equal(sort(ids), sort(expected.filter(id => id === worker.Id || !apiStopped))));
      }
    };
    let apiStopped = false;
    mark('namespace', 'credential-binding');
    const secret = loadSecret(root, { mustExist: true });
    const config = await composeConfig(validateCveRelease(root, current));
    const images = {};
    for (const item of [api, worker]) {
      const name = service(item);
      mark('namespace', name === 'api' ? 'api-image' : 'worker-image');
      requireSafe(DIGEST.test(item.Image));
      const [image] = JSON.parse(await d(['image', 'inspect', `${PROJECT}-${name}:local`]));
      requireSafe(image.Id === item.Image && image.Config?.Labels?.[LABEL] === 'v1');
      const expected = { ...envMap(image.Config.Env), ...config.services[name].environment };
      if (name === 'api') expected.SCAN_JWT_SECRET = secret;
      requireSafe(equal(sort(Object.entries(envMap(item.Config.Env)).map(canonical)), sort(Object.entries(expected).map(canonical))) &&
        equal(item.Config.Cmd, config.services[name].command) && equal(item.Config.Entrypoint, image.Config.Entrypoint) &&
        item.Config.WorkingDir === '/app/server/api' && image.Config.WorkingDir === '/app/server/api' &&
        item.Config.User === '65532:65532' && item.HostConfig.ReadonlyRootfs === true && !item.HostConfig.Privileged &&
        !item.HostConfig.AutoRemove && item.HostConfig.RestartPolicy?.Name === 'unless-stopped');
      images[name] = item.Image;
      // Current API/worker must both still be on the activation we compared.
      requireSafe(envMap(item.Config.Env).SCAN_VULN_MANIFEST_DIGEST === current.manifestDigest &&
        envMap(item.Config.Env).SCAN_VULN_ARTIFACT_SHA256 === current.artifactSha256 &&
        envMap(item.Config.Env).LOCAL_CVE_TRUST_SHA256 === current.publicKeySha256);
    }
    mark('namespace', 'runtime-profile');
    const runtimeImages = new Map();
    for (const item of before.containers) {
      requireSafe(DIGEST.test(item.Image));
      const inspected = JSON.parse(await d(['image', 'inspect', item.Image]));
      requireSafe(Array.isArray(inspected) && inspected.length === 1);
      validateRuntimeProfile(item, config.services[service(item)], inspected[0], config, secret);
      runtimeImages.set(service(item), inspected[0]);
    }
    mark('namespace', 'writers');
    await writers();
    mark('staging', 'activation-cas'); cas();
    // An immutable image override avoids tag races and --no-deps prevents
    // initializers, web and egress from being started/recreated by Compose.
    mark('staging', 'image-override');
    const override = join(lock, 'images.json');
    writeExclusive(override, canonical({ services: { api: { image: images.api }, worker: { image: images.worker } } }), 0o600);
    journalPath = join(lock, 'refresh.json');
    const journal = phase => {
      const body = canonical({ version: 1, phase, prior: current, candidate, containers: publicSnapshot(before), images });
      if (!exists(journalPath)) writeExclusive(journalPath, body, 0o600);
      else {
        const temporary = join(lock, 'journal.pending');
        writeExclusive(temporary, body, 0o600); fs.renameSync(temporary, journalPath);
      }
      syncDirectory(lock);
    };
    mark('staging', 'journal');
    journal('fence-api'); hold = true;
    mark('fence', 'api-stop');
    await d(['container', 'stop', '--time', '30', api.Id], { timeout: 45_000 });
    const inspectOne = async id => {
      const items = JSON.parse(await d(['container', 'inspect', id]));
      requireSafe(items.length === 1); return items[0];
    };
    mark('fence', 'api-stopped');
    const apiAfter = await inspectOne(api.Id); sameIdentity(api, apiAfter);
    requireSafe(stopped(apiAfter) && apiAfter.State.ExitCode === 0);
    apiStopped = true;
    mark('drain', 'journal');
    journal('drain-worker');
    const until = now() + drainMs;
    let drained = false;
    do {
      mark('drain', 'writers');
      await writers();
      mark('drain', 'identity');
      const a = await inspectOne(api.Id), w = await inspectOne(worker.Id);
      sameIdentity(api, a); sameIdentity(worker, w); requireSafe(stopped(a) && active(w));
      mark('drain', 'query');
      const result = JSON.parse(await d(['container', 'exec', worker.Id, 'node', '-e', DRAIN_PROBE]));
      requireSafe(Number.isSafeInteger(result.pending) && result.pending >= 0);
      if (result.pending === 0) { drained = true; break; }
      if (now() >= until) break;
      mark('drain', 'wait');
      await sleep(Math.min(1000, Math.max(1, until - now())));
    } while (now() <= until);
    if (!drained) {
      mark('drain', 'defer-cas');
      cas(); journal('defer-resume-original-api');
      mark('drain', 'resume-api');
      await d(['container', 'start', api.Id]);
      mark('drain', 'resume-readiness');
      let resumed;
      const resumeDeadline = now() + 60_000;
      do {
        resumed = await inspectOne(api.Id); sameIdentity(api, resumed); requireSafe(active(resumed));
        if (resumed.State.Health?.Status === 'healthy') break;
        requireSafe(now() < resumeDeadline); await sleep(1000);
      } while (resumed.State.Health?.Status !== 'healthy');
      mark('cleanup', 'journal');
      fs.unlinkSync(journalPath); journalPath = undefined; fs.unlinkSync(override); hold = false;
      log('LOCAL CVE deferred: durable work did not drain; only the same original API resumed. Activation unchanged.');
      return { outcome: 'deferred-busy', manifest };
    }
    // No admission process is running; zero durable work cannot race a new job.
    // Cancellation can leave an in-flight scanner; graceful worker stop waits
    // for its AbortController/finally path before the cache mount changes.
    mark('fence', 'worker-stop');
    journal('stop-idle-worker');
    await d(['container', 'stop', '--time', '30', worker.Id], { timeout: 45_000 });
    mark('fence', 'worker-stopped');
    const w = await inspectOne(worker.Id); sameIdentity(worker, w); requireSafe(stopped(w) && w.State.ExitCode === 0);
    const a = await inspectOne(api.Id); sameIdentity(api, a); requireSafe(stopped(a));
    mark('fence', 'no-writers');
    for (const volume of ['scan_ledger', 'auth_accounts']) {
      const noWriters = (await d(['container', 'ls', '--filter', `volume=${PROJECT}_${volume}`, '--format', '{{.ID}}', '--no-trunc'])).trim();
      requireSafe(noWriters === '');
    }
    mark('verify', 'pre-activation-usability');
    await verify(release, pins);
    mark('activate', 'prepare-cas'); cas();
    const pending = join(lock, 'activation.pending');
    writeExclusive(pending, canonical(candidate), 0o600);
    mark('activate', 'cas');
    journal('cas-activation'); cas(); fs.renameSync(pending, paths.config); syncDirectory(paths.stand);
    mark('activate', 'worker');
    journal('activate-worker');
    const up = async name => {
      const args = composeArguments(root, [], next);
      args.push('-f', override, 'up', '-d', '--no-deps', '--no-build', '--pull', 'never', '--force-recreate', name);
      await d(args, { env: composeEnvironment(options.env, secret, next), timeout: 120_000 });
    };
    await up('worker');
    const readiness = async name => {
      const target = `${PROJECT}-${name}-1`;
      let item;
      const readyDeadline = now() + 60_000;
      do {
        item = await inspectOne(target);
        requireSafe(active(item));
        if (name !== 'api' || item.State.Health?.Status === 'healthy') break;
        requireSafe(now() < readyDeadline); await sleep(1000);
      } while (name === 'api' && item.State.Health?.Status !== 'healthy');
      requireSafe(active(item) && item.Image === images[name] && item.Config.Image === images[name] &&
        item.Config.Labels?.[LABEL] === 'v1' && item.Config.Labels?.['com.docker.compose.project'] === PROJECT && service(item) === name);
      mark('readiness', 'runtime-profile');
      validateRuntimeProfile(item, nextConfig.services[name], runtimeImages.get(name), nextConfig, secret);
      mark('readiness', 'bindings');
      validateNamespaceMounts(item, name, root, { platform, expectedCve: next });
      mark('readiness', name);
      const result = JSON.parse(await d(['container', 'exec', item.Id, 'node', '--import', 'tsx', '--input-type=module', '-e', READY_PROBE], { timeout: 120_000 }));
      requireSafe(result.ready === true && result.manifest === manifest && result.bundle === pins.artifactSha256 && result.db === pins.dbSha256);
      return item;
    };
    // Allow heartbeat/gateway establishment but never retry a failed recreate.
    mark('readiness', 'worker');
    await sleep(3000); const readyWorker = await readiness('worker');
    mark('activate', 'api');
    journal('activate-api'); await up('api');
    mark('readiness', 'api');
    await sleep(3000); const readyApi = await readiness('api');
    mark('readiness', 'namespace');
    const after = await inventory();
    mark('readiness', 'unchanged-services');
    for (const name of ['web', 'egress']) {
      const prior = byService(before, name), observed = byService(after, name);
      sameIdentity(prior, observed); requireSafe(active(observed));
    }
    mark('readiness', 'bindings');
    for (const name of ['api', 'worker']) {
      const observed = byService(after, name), env = envMap(observed.Config.Env);
      const declared = observed.HostConfig.Mounts.find(m => m.Target === '/opt/release');
      const mounted = observed.Mounts.find(m => m.Destination === '/opt/release');
      requireSafe(observed.Id === (name === 'api' ? readyApi.Id : readyWorker.Id) &&
        mounted && declaredBindMatches(declared, mounted,
        { source: next.releaseHostDir, target: '/opt/release' }, platform) &&
        active(observed) && observed.Image === images[name] && env.SCAN_VULN_MANIFEST_DIGEST === manifest &&
        env.SCAN_VULN_ARTIFACT_SHA256 === pins.artifactSha256 && env.LOCAL_CVE_TRUST_SHA256 === current.publicKeySha256);
      if (name === 'api') requireSafe(env.SCAN_JWT_SECRET === secret && observed.State.Health?.Status === 'healthy');
    }
    mark('readiness', 'runtime-profile');
    for (const item of after.containers)
      validateRuntimeProfile(item, nextConfig.services[service(item)], runtimeImages.get(service(item)), nextConfig, secret);
    mark('readiness', 'storage');
    validateStorageContinuity(before, after);
    validateNetworkMembership(after);
    for (const prior of before.containers.filter(c => !apps.includes(service(c)))) {
      const observed = byService(after, service(prior)); sameIdentity(prior, observed); requireSafe(!observed.State.Running);
    }
    mark('readiness', 'activation');
    requireSafe(equal(loadCveActivation(root), candidate));
    mark('readiness', 'web');
    requireSafe(JSON.parse(await child(process.execPath, ['--input-type=module', '-e', WEB_PROBE], 10_000)).webReady === true);
    mark('cleanup', 'journal');
    journal('verified-ready');
    fs.unlinkSync(journalPath); journalPath = undefined; fs.unlinkSync(override); hold = false;
    log('LOCAL CVE activated: authenticated DB, backend chain and LOCAL worker/cache ready; API/worker only, prior releases preserved. Not a live scanner finding proof.');
    return { outcome: 'activated', manifest };
  } catch { throw fail(phase, checkpoint); }
  finally {
    // A journal or an ambiguous Docker mutation means HOLD, even after SIGKILL.
    // No automatic rollback: never point running containers at a guessed release.
    releaseLock();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  refreshLocalCve(process.argv.slice(2)).then(result => {
    if (result.outcome === 'hold-retained') process.exitCode = 2;
  }).catch(error => {
    console.error(publicRefreshFailure(error).message);
    process.exitCode = 1;
  });
}
