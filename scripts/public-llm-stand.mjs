#!/usr/bin/env node
// Import-safe public-only integration. No ambient dotenv, key reads or Docker at import.
import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import {
  PROJECT, LABEL, STATE, CONFIG_SECRET, expectedConfig, validateConfig, validateImage, validateContainer,
  inspectNamespace, acquireLock, loadSecret, readProfile, checkIgnores, assertReconciliationHistory,
  runIsolatedDocker, copyStableSqlite, sqliteTypedRow, recoverySqlite, backupArguments,
  validateBackupHelper, helperAuthorityProjection, RECOVERY_BACKUP, backupExportOperation,
  validateExportManifest, transferBackupSnapshot,
} from './public-image-stand.mjs';
import { dockerEnvironment } from './local-stand.mjs';
import { directory, readBounded, writeExclusive, syncDirectory } from './setup-local-cve.mjs';
import { PUBLIC_DRAIN_PROBE, PUBLIC_READY_PROBE } from './refresh-public-cve.mjs';
import { checkPublicLlmSourceBuild } from './public-llm-source-build.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const requireApi = createRequire(new URL('../server/api/package.json', import.meta.url));
const equal = (a, b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
const canonical = v => Array.isArray(v) ? v.map(canonical) : v && typeof v === 'object' ?
  Object.fromEntries(Object.keys(v).sort().map(k => [k, canonical(v[k])])) : v;

const hash = x => crypto.createHash('sha256').update(typeof x === 'string' ? x : JSON.stringify(canonical(x))).digest('hex');
const has = p => fs.lstatSync(p, { throwIfNoEntry: false }) !== undefined;
const safe = ok => { if (!ok) throw new Error('PUBLIC LLM integration refused; details withheld.'); };
// execFile rejects fractional timeouts; zero would disable its timeout entirely.
export function publicLlmDockerTimeout(requested, deadline, now) {
  const remaining = Math.min(requested, deadline - now);
  safe(Number.isFinite(requested) && Number.isFinite(deadline) && Number.isFinite(now) && remaining >= 1 && remaining <= 2147483647);
  return Math.floor(remaining);
}
const ownValue = (error, key) => error && (typeof error === 'object' || typeof error === 'function') ? Object.getOwnPropertyDescriptor(error, key)?.value : undefined;
function finiteFailure(error, origin) {
  const category = ownValue(error, 'category'), stack = ownValue(error, 'stack');
  const frames = typeof stack === 'string' ? [...stack.matchAll(/scripts\/(public-llm-stand|public-image-stand|public-llm-initialize-continuation)\.mjs:([0-9]+):[0-9]+/g)].map(m => ({ module: m[1], line: Number(m[2]) })).filter(f => f.line >= 100).slice(0, 3) : [];
  return { category: ['image', 'timeout', 'docker_unavailable', 'unclassified', 'resources', 'runtime_health'].includes(category) ? category : 'guard', origin, frames };
}
const role = c => c.Config?.Labels?.['com.docker.compose.service'];
const privateJson = text => { try { return JSON.parse(text); } catch { throw new Error('PUBLIC LLM metadata invalid; content withheld.'); } };
const imageId = v => typeof v === 'string' && /^sha256:[a-f0-9]{64}$/.test(v);
const containerId = v => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const owned = v => v?.[LABEL] === 'v1' && v?.['com.docker.compose.project'] === PROJECT;
const netNames = ['llm_internal', 'llm_uplink'];
const llmVariable = k => k.startsWith('LLM_') || k.startsWith('OPENROUTER_');
const envMap = a => { safe(Array.isArray(a)); const entries = a.map(v => { safe(typeof v === 'string' && v.includes('=')); const n = v.indexOf('='); return [v.slice(0, n), v.slice(n + 1)]; }); safe(new Set(entries.map(e => e[0])).size === entries.length); return Object.fromEntries(entries); };
export const PUBLIC_LLM_ENV = Object.freeze({
  LLM_ENABLED: 'true', LLM_FREE_ONLY: 'true', LLM_MODEL: 'xingchen-agi/xing4.0-29b-a4b:free',
  LLM_PROVIDER_ALLOWLIST: 'phala', LLM_POLICY_REVISION: 'public-8081-xing-phala-v1', LLM_ROUTING_APPROVED: 'true',
  LLM_REGION: 'global', LLM_RETENTION: 'no-storage', LLM_TIMEOUT_MS: '30000', LLM_REQUEST_BYTES: '262144',
  LLM_RESPONSE_BYTES: '65536', LLM_MAX_FINDINGS: '1000', LLM_OUTPUT_TOKENS: '2048', LLM_REQUEST_BUDGET_USD: '0',
  LLM_INPUT_PRICE_PER_MILLION_USD: '0', LLM_OUTPUT_PRICE_PER_MILLION_USD: '0', LLM_REQUEST_PRICE_USD: '0',
  OPENROUTER_API_KEY_FILE: '/run/secrets/public_openrouter_key', LLM_HISTORY_ENABLED: 'true',
  LLM_HISTORY_REVISION: 'owner-history-v1', LLM_HISTORY_AUTHORITY: 'single-api-quiesced-terminal-v1',
  LLM_QUOTA_ENABLED: 'true', LLM_QUOTA_REVISION: 'public-8081-quota-v1', LLM_QUOTA_WINDOW: 'utc-day',
  LLM_QUOTA_USER_INPUT: '1048576', LLM_QUOTA_USER_OUTPUT: '32768', LLM_QUOTA_USER_COST_USD: '0',
  LLM_QUOTA_SCAN_INPUT: '262144', LLM_QUOTA_SCAN_OUTPUT: '16384', LLM_QUOTA_SCAN_COST_USD: '0',
  LLM_QUOTA_WARNING_PERCENT: '80', LLM_QUOTA_REQUEST_INPUT: '65536', LLM_QUOTA_OBSERVATION_TOKENS: '1048576',
  LLM_QUOTA_OBSERVATION_COST_USD: '1', LLM_QUOTA_RECEIPT_MS: '300000', LLM_QUOTA_REPLAY_DAYS: '7',
  LLM_QUOTA_MAX_ROWS: '100000', LLM_QUOTA_DB_BYTES: '67108864', LLM_QUOTA_DISK_HEADROOM_BYTES: '134217728',
  LLM_QUOTA_BUSY_MS: '1000', LLM_QUOTA_CLEANUP_BATCH: '256',
});
export function parsePublicLlmConfig(text) {
  safe(typeof text === 'string' && text.length <= 16384 && /^[\x09\x0a\x0d\x20-\x7e]*$/.test(text));
  const values = {};
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith('#')) continue;
    const match = /^([A-Z][A-Z0-9_]*)=([^\s"'`$\\]*)$/.exec(line);
    safe(match && !Object.hasOwn(values, match[1])); values[match[1]] = match[2];
  }
  safe(equal(values, PUBLIC_LLM_ENV)); return PUBLIC_LLM_ENV;
}
export function validateLlmSelection(value) {
  safe(value && equal(Object.keys(value).sort(), ['keyVolume', 'version']) && value.version === 1 &&
    (value.keyVolume === null || typeof value.keyVolume === 'string' && /^diplom-public-8081-llm-key-[a-f0-9]{32}$/.test(value.keyVolume)));
  return Object.freeze({ version: 1, keyVolume: value.keyVolume });
}
export function loadPublicLlmSettings(home = homedir()) {
  const path = join(home, '.local/state/diplom-public-images/llm');
  // No symlinked ancestor may redirect this approved public-only state path.
  const ancestors = []; let current = '/';
  for (const part of resolve(path).split('/').filter(Boolean)) {
    current = join(current, part); const stamp = fs.lstatSync(current);
    safe(stamp.isDirectory() && !stamp.isSymbolicLink()); ancestors.push({ path: current, stamp });
  }
  directory(path, 0o700);
  const config = fileFence(join(path, 'llm.env'), 16384, 0o600);
  parsePublicLlmConfig(config.bytes);
  let keyVolume = null;
  const receiptPath = join(path, 'key-volume.json');
  const receipt = has(receiptPath) ? fileFence(receiptPath, 4096, 0o600) : null;
  if (receipt) {
    const r = privateJson(receipt.bytes);
    safe(equal(Object.keys(r).sort(), ['directoryMode', 'fileMode', 'gid', 'initializerImage', 'target', 'uid', 'version', 'volume']) &&
      r.version === 1 && r.uid === 65532 && r.gid === 65532 && r.fileMode === '0400' && r.directoryMode === '0500' &&
      r.target === PUBLIC_LLM_ENV.OPENROUTER_API_KEY_FILE && imageId(r.initializerImage));
    keyVolume = r.volume;
  }
  // Never stat/open/read openrouter.key. Only the non-secret provisioning receipt selects a mount.
  const selection = validateLlmSelection({ version: 1, keyVolume });
  const fences = [config, ...(receipt ? [receipt] : [])];
  const verify = () => {
    for (const a of ancestors) { const s = fs.lstatSync(a.path); safe(s.isDirectory() && !s.isSymbolicLink() && s.dev === a.stamp.dev && s.ino === a.stamp.ino && s.mode === a.stamp.mode && s.uid === a.stamp.uid); }
    directory(path, 0o700); for (const f of fences) f.verify(); safe(has(receiptPath) === Boolean(receipt));
  };
  verify(); return { selection, verify };
}
export function readPublicLlmBinding(root) {
  const state = join(root, STATE), path = join(state, 'llm-profile.json');
  if (!has(state)) return null;
  directory(state, 0o700);
  safe(!fs.readdirSync(state).some(n => n.startsWith('.llm-pending-')));
  if (!has(path)) { safe(!has(join(root, STATE, 'compose.llm-env.json'))); return null; }
  const text = readBounded(path, 4096, 0o600), value = validateLlmSelection(privateJson(text));
  safe(text === JSON.stringify(value) && equal(privateJson(readBounded(join(state, 'compose.llm-env.json'), 16384, 0o600)), publicLlmEnvironmentOverlay(value)));
  return value;
}
export function publicLlmEnvironmentOverlay(selection) {
  validateLlmSelection(selection);
  return { services: { api: { environment: { ...PUBLIC_LLM_ENV }, ...(selection.keyVolume ? { volumes: [
    { type: 'volume', source: 'public_llm_key', target: '/run/secrets', read_only: true, volume: { nocopy: true } },
  ] } : {}) } }, ...(selection.keyVolume ? { volumes: { public_llm_key: { name: selection.keyVolume, external: true } } } : {}) };
}
export function publicLlmStaticOverlay(root) {
  const gateway = structuredClone(expectedConfig(root).services.egress);
  gateway.image = `${PROJECT}-llm-egress:local`; gateway.build.dockerfile = 'server/deploy/gateway/openrouter.Dockerfile';
  gateway.command = ['python', '-I', 'openrouter.py']; gateway.networks = { llm_internal: null, llm_uplink: null };
  return { services: { web: { build: { dockerfile: 'server/deploy/public-stand.Dockerfile' } }, api: {
    networks: { llm_internal: null }, depends_on: { 'llm-egress': { condition: 'service_started' } },
  }, 'llm-egress': gateway }, networks: Object.fromEntries(netNames.map(name => [name, {
    name: `${PROJECT}_${name}`, labels: { [LABEL]: 'v1' }, ...(name.endsWith('_internal') ? { internal: true } : {}),
  }])) };
}
export function expectedPublicLlmConfig(root, cve = null, selection = null) {
  const model = expectedConfig(root, cve);
  if (!selection) return model;
  const overlay = publicLlmStaticOverlay(root), env = publicLlmEnvironmentOverlay(selection);
  model.services.web.build.dockerfile = overlay.services.web.build.dockerfile;
  model.services.api.environment = { ...model.services.api.environment, ...env.services.api.environment };
  Object.assign(model.services.api.networks, overlay.services.api.networks);
  Object.assign(model.services.api.depends_on, overlay.services.api.depends_on);
  model.services['llm-egress'] = overlay.services['llm-egress']; Object.assign(model.networks, overlay.networks);
  if (selection.keyVolume) { model.services.api.volumes.push(...env.services.api.volumes); Object.assign(model.volumes, env.volumes); }
  return model;
}
// Fixed order is shared by maintenance, future main and BOTH current/prospective CVE models.
export function publicLlmComposeArguments(root, args, { cve = false, llm = true, pinned = true, prospectiveCve = false, directory: dir = join(root, STATE) } = {}) {
  safe(resolve(dir) === dir && [join(root, STATE), join(root, STATE, '.operation.lock/llm-candidate'), join(root, STATE, '.operation.lock/llm-initialize-candidate'), join(root, STATE, '.operation.lock/llm-rebuild-candidate'), join(root, STATE, '.operation.lock/init-exit-current'), join(root, STATE, '.operation.lock/admit-current'), join(root, STATE, '.operation.lock/api-current')].includes(dir));
  safe(!prospectiveCve || cve && dir === join(root, STATE));
  return ['compose', '--env-file', '/dev/null', '-p', PROJECT, '-f', join(root, 'server/deploy/compose.public-images.yaml'),
    ...(cve ? ['-f', prospectiveCve ? join(root, STATE, '.operation.lock/candidate.cve.json') : join(dir, 'compose.cve.json')] : []),
    ...(llm ? ['-f', join(root, 'server/deploy/compose.public-llm.yaml'), '-f', join(dir, 'compose.llm-env.json')] : []),
    ...(pinned ? ['-f', join(dir, 'compose.images.json')] : []), ...args];
}
export function validatePublicLlmImage(image, name) {
  if (name !== 'llm-egress') return validateImage(image, name);
  safe(equal(image?.Config?.Cmd, ['python', '-I', 'openrouter.py']));
  const copy = structuredClone(image); copy.Config.Cmd = ['python', '-I', 'proxy.py']; return validateImage(copy, 'egress');
}
export function validatePublicLlmConfig(value, root, cve = null, selection = null, images = null) {
  if (!selection) return validateConfig(value, root, cve, images);
  const expected = expectedPublicLlmConfig(root, cve, selection), copy = structuredClone(value);
  safe(equal(Object.keys(copy.services ?? {}).sort(), Object.keys(expected.services).sort()));
  safe(equal(Object.keys(copy.networks ?? {}).sort(), Object.keys(expected.networks).sort()));
  safe(equal(Object.keys(copy.volumes ?? {}).sort(), Object.keys(expected.volumes).sort()));
  if (images) { safe(equal(Object.keys(images).sort(), Object.keys(expected.services).sort())); for (const [n, image] of Object.entries(images)) { validatePublicLlmImage(image, n); expected.services[n].image = image.Id; } }
  // Compose's inert defaults are normalized ONLY by the original validator after
  // independently checking/removing the exact extension. Unknown fields survive and refuse.
  const stripDefaults = spec => {
    const x = structuredClone(spec); if (x.entrypoint === null) delete x.entrypoint; for (const dep of Object.values(x.depends_on ?? {})) { if (dep.required === true) delete dep.required; if (dep.restart === false) delete dep.restart; }
    for (const net of Object.keys(x.networks ?? {})) if (equal(x.networks[net], {}) || equal(x.networks[net], { priority: 0 })) x.networks[net] = null;
    for (const k of ['mem_limit', 'memswap_limit']) if (k in x) x[k] = String(x[k]);
    return x;
  };
  safe(equal(stripDefaults(copy.services['llm-egress']), expected.services['llm-egress'])); delete copy.services['llm-egress'];
  for (const n of netNames) { const x = copy.networks[n]; if (x.driver === 'bridge') delete x.driver; if (x.internal === false) delete x.internal; if (equal(x.ipam, {})) delete x.ipam; safe(equal(x, expected.networks[n])); delete copy.networks[n]; }
  safe(copy.services.web.build.dockerfile === 'server/deploy/public-stand.Dockerfile'); copy.services.web.build.dockerfile = 'server/deploy/stand.Dockerfile';
  const api = copy.services.api;
  safe(equal(Object.fromEntries(Object.entries(api.environment ?? {}).filter(([k]) => llmVariable(k))), PUBLIC_LLM_ENV));
  for (const k of Object.keys(api.environment).filter(llmVariable)) delete api.environment[k];
  Object.assign(api.environment, Object.fromEntries(Object.entries(expectedConfig(root).services.api.environment).filter(([k]) => llmVariable(k))));
  safe(equal(api.networks.llm_internal, null) || equal(api.networks.llm_internal, { priority: 0 }) || equal(api.networks.llm_internal, {})); delete api.networks.llm_internal;
  safe(equal(stripDefaults({ depends_on: { x: api.depends_on['llm-egress'] } }).depends_on.x, { condition: 'service_started' })); delete api.depends_on['llm-egress'];
  if (selection.keyVolume) {
    safe(equal(copy.volumes.public_llm_key, expected.volumes.public_llm_key)); delete copy.volumes.public_llm_key;
    const mounts = api.volumes.filter(v => v.target === '/run/secrets'); safe(equal(mounts, publicLlmEnvironmentOverlay(selection).services.api.volumes)); api.volumes = api.volumes.filter(v => v.target !== '/run/secrets');
  }
  const baseImages = images && Object.fromEntries(Object.entries(images).filter(([n]) => n !== 'llm-egress'));
  validateConfig(copy, root, cve, baseImages);
}
export function projectPublicLlmContainer(item, name, spec, image, config, selection) {
  if (!selection) return { item, name, spec, image, config };
  const c = structuredClone(item), im = structuredClone(image), s = structuredClone(spec);
  if (name === 'api') {
    const env = envMap(c.Config.Env);
    safe(equal(Object.fromEntries(Object.entries(env).filter(([k]) => llmVariable(k))), PUBLIC_LLM_ENV));
    for (const k of Object.keys(env).filter(llmVariable)) delete env[k];
    Object.assign(env, { LLM_ENABLED: 'false', LLM_ROUTING_APPROVED: 'false', LLM_QUOTA_ENABLED: 'false', LLM_HISTORY_ENABLED: 'false' });
    c.Config.Env = Object.entries(env).map(([k, v]) => `${k}=${v}`);
    for (const k of Object.keys(s.environment).filter(llmVariable)) delete s.environment[k];
    Object.assign(s.environment, { LLM_ENABLED: 'false', LLM_ROUTING_APPROVED: 'false', LLM_QUOTA_ENABLED: 'false', LLM_HISTORY_ENABLED: 'false' });
    // Unknown non-LLM env stays in c.Config.Env and is rejected by the base validator.
    safe(Object.hasOwn(c.NetworkSettings.Networks, `${PROJECT}_llm_internal`)); delete c.NetworkSettings.Networks[`${PROJECT}_llm_internal`];
    if (c.HostConfig.NetworkMode === `${PROJECT}_llm_internal`) c.HostConfig.NetworkMode = `${PROJECT}_auth_internal`;
    if (selection.keyVolume) {
      const ds = c.HostConfig.Mounts.filter(m => m.Target === '/run/secrets'), ms = c.Mounts.filter(m => m.Destination === '/run/secrets');
      safe(ds.length === 1 && ms.length === 1);
      const d = ds[0], m = ms[0], opts = d.VolumeOptions;
      safe(d.Type === 'volume' && d.Source === selection.keyVolume && d.ReadOnly === true &&
        (equal(opts, { NoCopy: true }) || equal(opts, { NoCopy: true, DriverConfig: {} })) &&
        Object.keys(d).every(k => ['Type', 'Source', 'Target', 'ReadOnly', 'VolumeOptions'].includes(k)) &&
        m.Type === 'volume' && m.Name === selection.keyVolume && m.RW === false && !m.SubPath && (!m.Propagation || m.Propagation === 'rprivate'));
      c.HostConfig.Mounts = c.HostConfig.Mounts.filter(m => m.Target !== '/run/secrets'); c.Mounts = c.Mounts.filter(m => m.Destination !== '/run/secrets');
      s.volumes = s.volumes.filter(m => m.target !== '/run/secrets');
    }
  }
  if (name === 'llm-egress') {
    safe(c.Name === `/${PROJECT}-llm-egress-1` && role(c) === name && owned(c.Config.Labels));
    safe(equal(c.Config.Cmd, ['python', '-I', 'openrouter.py'])); validatePublicLlmImage(im, name);
    safe(equal(Object.keys(c.NetworkSettings.Networks).sort(), netNames.map(n => `${PROJECT}_${n}`).sort()));
    const map = { [`${PROJECT}_llm_internal`]: `${PROJECT}_scan_internal`, [`${PROJECT}_llm_uplink`]: `${PROJECT}_registry_uplink` };
    safe(Object.hasOwn(map, c.HostConfig.NetworkMode)); c.HostConfig.NetworkMode = map[c.HostConfig.NetworkMode];
    c.NetworkSettings.Networks = Object.fromEntries(Object.entries(c.NetworkSettings.Networks).map(([k, v]) => [map[k], v]));
    c.Name = `/${PROJECT}-egress-1`; c.Config.Labels['com.docker.compose.service'] = 'egress';
    c.Config.Cmd = ['python', '-I', 'proxy.py']; im.Config.Cmd = c.Config.Cmd; s.command = c.Config.Cmd; name = 'egress';
  }
  return { item: c, name, spec: s, image: im, config };
}
export function validatePublicLlmContainer(item, name, spec, image, config, extra = {}, selection = null) {
  validatePublicLlmImage(image, name);
  const p = projectPublicLlmContainer(item, name, spec, image, config, selection);
  const images = extra.images && { ...extra.images, ...(name === 'llm-egress' ? { egress: p.image } : {}) };
  validateContainer(p.item, p.name, p.spec, p.image, p.config, { ...extra, images });
}
function validatePublicLlmKeyVolume(v, selection) {
  safe(v.Name === selection.keyVolume && v.Driver === 'local' && v.Scope === 'local' &&
    typeof v.Mountpoint === 'string' && v.Mountpoint.startsWith('/') && !/[\x00-\x1f\x7f]/.test(v.Mountpoint) &&
    equal(v.Options ?? {}, {}) && equal(v.Labels, { 'diplom.public-llm': 'key-v1' }));
}
export async function inspectPublicLlmNamespace(run, options, root, cve = null, selection = null, extra = {}) {
  if (!selection) return inspectNamespace(run, options, expectedConfig(root, cve), extra);
  const model = expectedPublicLlmConfig(root, cve, selection), base = expectedConfig(root, cve), images = new Map();
  const loadImage = async (id, name) => { const a = JSON.parse(await run(['image', 'inspect', id], options)); safe(a.length === 1); validatePublicLlmImage(a[0], name); images.set(id, a[0]); return a[0]; };
  // The extra service is independently validated before projecting the six-service base.
  const rows = JSON.parse(await run(['container', 'inspect', `${PROJECT}-llm-egress-1`], options)); safe(rows.length === 1);
  const gateway = rows[0], gatewayImage = await loadImage(gateway.Image, 'llm-egress');
  validatePublicLlmContainer(gateway, 'llm-egress', model.services['llm-egress'], gatewayImage, model, extra, selection);
  const networks = [];
  for (const n of netNames) {
    const a = JSON.parse(await run(['network', 'inspect', `${PROJECT}_${n}`], options)); safe(a.length === 1);
    const v = a[0]; safe(v.Name === `${PROJECT}_${n}` && owned(v.Labels) && v.Driver === 'bridge' && Boolean(v.Internal) === n.endsWith('_internal') &&
      !v.Attachable && !v.Ingress && !v.EnableIPv6 && equal(v.Options ?? {}, {}) && (!v.IPAM || v.IPAM.Driver === 'default' && equal(v.IPAM.Options ?? {}, {})));
    networks.push(v);
  }
  let keyVolume;
  if (selection.keyVolume) {
    const a = JSON.parse(await run(['volume', 'inspect', selection.keyVolume], options)); safe(a.length === 1);
    keyVolume = a[0]; validatePublicLlmKeyVolume(keyVolume, selection);
    safe(equal(gateway.Mounts.filter(m => m.Type === 'volume'), []));
  }
  const wrapped = async (args, opts) => {
    const text = await run(args, opts);
    if (args[1] === 'ls' && ['container', 'network'].includes(args[0])) {
      const remove = args[0] === 'container' ? [`${PROJECT}-llm-egress-1`] : netNames.map(n => `${PROJECT}_${n}`);
      return text.split('\n').filter(line => !remove.includes(line.split('\t')[0])).join('\n');
    }
    if (args[0] === 'image' && args[1] === 'ls') {
      for (const tag of text.split('\n').filter(t => t === `${PROJECT}-llm-egress:local`)) await loadImage(tag, 'llm-egress');
      return text.split('\n').filter(t => t !== `${PROJECT}-llm-egress:local`).join('\n');
    }
    if (args[0] === 'container' && args[1] === 'inspect') {
      const a = JSON.parse(text); safe(a.length === 1);
      if (role(a[0]) === 'api') {
        const image = images.get(a[0].Image) ?? await loadImage(a[0].Image, 'api');
        validatePublicLlmContainer(a[0], 'api', model.services.api, image, model, extra, selection);
        return JSON.stringify([projectPublicLlmContainer(a[0], 'api', model.services.api, image, model, selection).item]);
      }
    }
    return text;
  };
  const out = await inspectNamespace(wrapped, options, base, extra);
  // Return real, not projected, API observations to preservation/lifecycle callers.
  const a = JSON.parse(await run(['container', 'inspect', `${PROJECT}-api-1`], options)); safe(a.length === 1);
  validatePublicLlmContainer(a[0], 'api', model.services.api, await loadImage(a[0].Image, 'api'), model, extra, selection);
  out.containers = out.containers.map(c => role(c) === 'api' ? a[0] : c); out.containers.push(gateway); out.networks.push(...networks);
  for (const n of networks) {
    const members = out.containers.filter(c => Object.hasOwn(c.NetworkSettings.Networks, n.Name));
    safe(equal(Object.keys(n.Containers ?? {}).sort(), members.filter(c => c.State.Running).map(c => c.Id).sort()));
  }
  if (keyVolume) {
    const ids = (await run(['container', 'ls', '--all', '--filter', `volume=${selection.keyVolume}`, '--format', '{{.ID}}', '--no-trunc'], options)).trim().split('\n').filter(Boolean);
    safe(equal(ids, [a[0].Id]));
    const m = a[0].Mounts.find(m => m.Destination === '/run/secrets'); safe(m.Source === keyVolume.Mountpoint && m.Driver === 'local');
    out.volumes.push(keyVolume);
  }
  return out;
}

function directoryFence(path) {
  directory(path, 0o700); const before = fs.lstatSync(path);
  return () => { directory(path, 0o700); const after = fs.lstatSync(path); safe(after.dev === before.dev && after.ino === before.ino); };
}
function fileFence(path, cap = 16 * 1024 ** 2, mode) {
  const before = fs.lstatSync(path), bytes = readBounded(path, cap, mode), stamp = fs.lstatSync(path);
  safe(before.dev === stamp.dev && before.ino === stamp.ino && before.mode === stamp.mode && before.uid === stamp.uid);
  // Metadata remains nonempty/strict; compare the private JWT directly, never
  // derive a secret fingerprint for diagnostics or output.
  return { path, bytes, verify() { const s = fs.lstatSync(path); safe(s.dev === stamp.dev && s.ino === stamp.ino && s.mode === stamp.mode && s.uid === stamp.uid && readBounded(path, cap, mode) === bytes); } };
}
function sourceFileFence(path) {
  // Source is not private configuration: tracked .gitkeep files may be empty,
  // and public assets must be fenced as bytes, not lossy UTF-8 replacements.
  const read = () => {
    const before = fs.lstatSync(path);
    safe(before.isFile() && !before.isSymbolicLink() && before.nlink === 1 && before.uid === process.getuid() && before.size <= 16 * 1024 ** 2);
    const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    try {
      const opened = fs.fstatSync(fd);
      const same = s => s.isFile() && s.nlink === 1 && s.dev === before.dev && s.ino === before.ino && s.uid === before.uid &&
        s.mode === before.mode && s.size === before.size && s.mtimeMs === before.mtimeMs && s.ctimeMs === before.ctimeMs;
      safe(same(opened));
      const bytes = Buffer.alloc(before.size + 1); let size = 0;
      while (size < bytes.length) { const n = fs.readSync(fd, bytes, size, bytes.length - size, null); if (!n) break; size += n; }
      safe(size === before.size && same(fs.fstatSync(fd)) && same(fs.lstatSync(path)));
      return { dev: before.dev, ino: before.ino, uid: before.uid, mode: before.mode, size,
        digest: crypto.createHash('sha256').update(bytes.subarray(0, size)).digest('hex') };
    } finally { fs.closeSync(fd); }
  };
  const initial = read(); return { path, snapshot: Object.freeze(initial), verify() { safe(equal(initial, read())); } };
}

// Full typed/schema fingerprints: no fixed data-table projection, no INTEGER→Number
// coercion, no omission of decisions, liabilities, duplicate rows or opaque BLOBs.
export function llmFingerprint(DB, io, crypto, path, kind, empty = false) {
  safe(['history', 'quota', 'auth', 'ledger'].includes(kind));
  const db = new DB(path, { readonly: true, fileMustExist: true, timeout: 2000 });
  try {
    db.defaultSafeIntegers(true); db.pragma('query_only=ON'); db.exec('BEGIN');
    safe(db.pragma('integrity_check', { simple: true }) === 'ok' && db.pragma('foreign_key_check').length === 0);
    const versions = [db.pragma('application_id', { simple: true }), db.pragma('user_version', { simple: true })];
    if (kind === 'auth' || kind === 'ledger') safe(String(versions[1]) === (kind === 'auth' ? '0' : '15'));
    else safe(equal(versions.map(String), kind === 'history' ? ['1145655602', '3'] : ['1145655601', '1']));
    const schema = db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name,tbl_name,sql").raw().all();
    safe(schema.length > 0 && schema.length <= 512 && !schema.some(row => /^CREATE\s+VIRTUAL\s+TABLE/i.test(row[3] ?? '')));
    const h = crypto.createHash('sha256'); h.update(sqliteTypedRow(versions)); h.update(sqliteTypedRow(schema.flat()));
    let bytes = 0, rows = 0;
    for (const entry of schema.filter(r => r[0] === 'table')) {
      const table = entry[1]; safe(/^[a-z_][a-z0-9_]*$/.test(table)); h.update(table);
      for (const row of db.prepare(`SELECT rowid,* FROM "${table}" ORDER BY rowid`).safeIntegers(true).raw().iterate()) {
        const text = sqliteTypedRow(row); bytes += Buffer.byteLength(text); safe(bytes <= 256 * 1024 ** 2 && ++rows <= 250000); h.update(text); h.update('\n');
      }
    }
    if (kind === 'history') {
      safe(db.prepare("SELECT count(*) n FROM history_head WHERE json_extract(content,'$.pending') IS NOT NULL").get().n === 0n);
      if (empty) safe(db.prepare('SELECT count(*) n FROM history_head').get().n === 0n && db.prepare('SELECT count(*) n FROM history_completion_space').get().n === 0n);
    } else if (empty) safe(db.prepare('SELECT count(*) n FROM quota_attempt').get().n === 0n && db.prepare('SELECT clock FROM quota_meta WHERE id=1').get().clock === 0n);
    db.exec('ROLLBACK'); return h.digest('hex');
  } finally { db.close(); }
}
// Admission has no earlier LLM snapshot: accept only the native bootstrap tables
// and metadata, never unknown data/schema disguised by empty business tables.
export function assertAdmissionStoreEmpty(DB, path, kind) {
  const db = new DB(path, { readonly: true, fileMustExist: true, timeout: 2000 });
  try {
    db.defaultSafeIntegers(true); db.pragma('query_only=ON'); db.exec('BEGIN');
    const tables = kind === 'history' ? ['history_completion_space', 'history_head', 'history_meta'] : ['quota_attempt', 'quota_meta'];
    safe(equal(db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").pluck().all(), tables));
    safe(db.prepare("SELECT count(*) FROM sqlite_master WHERE type IN ('trigger','view')").pluck().get() === 0n);
    const meta = kind === 'history' ? 'history_meta' : 'quota_meta';
    for (const table of tables.filter(n => n !== meta)) safe(db.prepare(`SELECT count(*) FROM "${table}"`).pluck().get() === 0n);
    if (kind === 'history') { const rows = db.prepare('SELECT id,incarnation FROM history_meta').all(); safe(rows.length === 1 && rows[0].id === 1n && /^[a-f0-9-]{36}$/.test(rows[0].incarnation)); }
    else { const rows = db.prepare('SELECT id,clock FROM quota_meta').all(); safe(rows.length === 1 && rows[0].id === 1n && rows[0].clock === 0n); }
    db.exec('ROLLBACK');
  } finally { db.close(); }
}

// Same stable-copy + native backup + restore check as the existing bridge; the
// role aliases below exist ONLY in the private export protocol, never in live paths.
export async function backupLlmSqlite(DB, io, crypto, paths, output) {
  const exists = p => io.lstatSync(p, { throwIfNoEntry: false }) !== undefined;
  const pair = ['auth', 'ledger'].map(r => exists(paths[r]));
  safe(pair[0] === pair[1]);
  if (!pair[0]) { for (const p of Object.values(paths)) for (const suffix of ['-journal', '-wal', '-shm']) safe(!exists(p + suffix)); return null; }
  const result = {};
  for (const [role, kind] of [['auth', 'history'], ['ledger', 'quota']]) {
    const s = io.lstatSync(paths[role]); safe(s.uid === process.getuid() && (s.mode & 0o7777) === 0o600 && s.size <= (kind === 'history' ? 8 : 64) * 1024 ** 2);
    const copy = copyStableSqlite(io, crypto, paths[role], output + '/source-' + role);
    let db;
    try {
      // Recover the private copy, never the readonly live source/WAL.
      db = new DB(copy.path, { fileMustExist: true }); db.pragma('query_only=ON');
      db.pragma('integrity_check');
      const before = llmFingerprint(DB, io, crypto, copy.path, kind);
      const target = output + '/' + role + '.sqlite'; safe(!exists(target)); await db.backup(target); io.chmodSync(target, 0o600);
      safe(llmFingerprint(DB, io, crypto, target, kind) === before); copy.verify();
      const fd = io.openSync(target, io.constants.O_RDONLY | io.constants.O_NOFOLLOW), h = crypto.createHash('sha256'), b = Buffer.alloc(65536);
      try { let n; while ((n = io.readSync(fd, b, 0, b.length, null))) h.update(b.subarray(0, n)); io.fsyncSync(fd); } finally { io.closeSync(fd); }
      result[role] = { logicalSha256: before, sha256: h.digest('hex'), bytes: io.statSync(target).size, integrity: 'ok' };
    } finally { db?.close(); copy.verify(); copy.cleanup(); }
  }
  return result;
}
const helperImports = "import DB from 'better-sqlite3';import * as io from 'node:fs';import * as crypto from 'node:crypto';";
const safeSource = 'const safe=v=>{if(!v)throw Error("REFUSED");};const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);';
const nativeSource = helperImports + safeSource + 'const copyStableSqlite=' + copyStableSqlite.toString() + ';const sqliteTypedRow=' + sqliteTypedRow.toString() + ';const core=' + recoverySqlite.toString() + ';const llmFingerprint=' + llmFingerprint.toString() + ';const backupLlmSqlite=' + backupLlmSqlite.toString() + ';';
const keeper = "process.on('SIGTERM',()=>process.exit(0));setTimeout(()=>process.exit(73),300000);";
const writeReady = "const save=(p,x)=>{io.writeFileSync(p,JSON.stringify(x),{flag:'wx',mode:0o600});const f=io.openSync(p,'r');io.fsyncSync(f);io.closeSync(f);};";
export const PUBLIC_LLM_BACKUP_PROGRAM = nativeSource + "process.umask(0o077);const timer=setTimeout(()=>process.exit(71),120000);try{" + writeReady +
  "io.mkdirSync('/backup/core',{mode:0o700});const coreReceipt=await core(DB,io,crypto,{auth:'/auth/auth.sqlite',ledger:'/data/ledger.sqlite'},'/backup/core',{quiescent:true});save('/backup/core/ready.json',coreReceipt);io.mkdirSync('/backup/llm',{mode:0o700});const llm=await backupLlmSqlite(DB,io,crypto,{auth:'/auth/llm-history.sqlite',ledger:'/auth/llm-usage.sqlite'},'/backup/llm');if(llm)save('/backup/llm/ready.json',llm);save('/backup/ready.json',{ready:true,llmPresent:llm!==null});clearTimeout(timer);" + keeper + "}catch{process.exit(70);}";
export const PUBLIC_LLM_EXPORT_PROGRAM = "const io=require('node:fs'),crypto=require('node:crypto');const core=" + backupExportOperation.toString() + ";try{const x=JSON.parse(process.argv[1]);if(!['core','llm'].includes(x.group)||Object.keys(x).sort().join(',')!=='group,request')throw Error();const paths=x.group==='core'?{backup:'/backup/core',auth:'/auth/auth.sqlite',ledger:'/data/ledger.sqlite'}:{backup:'/backup/llm',auth:'/auth/llm-history.sqlite',ledger:'/auth/llm-usage.sqlite'};process.stdout.write(JSON.stringify(core(io,crypto,x.request,paths)));}catch{process.exit(72);}";
const initSource = initialize => "import * as io from 'node:fs';import {HistoryStore} from './src/llm/history-store.ts';import {QuotaLedger} from './src/llm/quota-ledger.ts';import {quotaPolicyFromEnvironment} from './src/llm/quota-policy.ts';" +
  "try{process.umask(0o077);const initialize=" + initialize + ";for(const p of ['/auth/llm-history.sqlite','/auth/llm-usage.sqlite'])if(io.existsSync(p)===initialize)throw Error();const p=quotaPolicyFromEnvironment();if(!p)throw Error();const h=new HistoryStore('/auth/llm-history.sqlite',initialize);h.close();const q=new QuotaLedger('/auth/llm-usage.sqlite',p,Date.now,initialize);q.close();io.writeFileSync('/backup/ready.json','{\"ready\":true}',{flag:'wx',mode:0o600});" + keeper + "}catch{process.exit(70);}";
export const PUBLIC_LLM_INITIALIZE_PROGRAM = initSource(true);
export const PUBLIC_LLM_CHECK_PROGRAM = initSource(false);
export const PUBLIC_LLM_GATEWAY_PROBE = "import {connect as connectLlmGateway} from 'node:net';const llmGatewayReady=await new Promise(resolve=>{const s=connectLlmGateway({host:'llm-egress',port:8080,timeout:2000});let done=false;const finish=v=>{if(!done){done=true;s.destroy();resolve(v);}};s.once('connect',()=>finish(true));s.once('error',()=>finish(false));s.once('timeout',()=>finish(false));});if(!llmGatewayReady)throw Error('llm-gateway-not-ready');";
const readyProgram = "const fs=require('node:fs');try{process.stdout.write(fs.readFileSync('/backup/ready.json','utf8'));}catch{process.stdout.write('{}');}";
export function publicLlmHelperArguments(name, image, purpose = 'backup') {
  safe(new RegExp(`^${PROJECT}-llm-[a-f0-9]{32}-(?:(?:continued|initialize-current|rebuild-current|init-exit-current|admit-current|api-current)-)?(?:fenced|before-api|after-api|initialize|check)$`).test(name) && imageId(image) && ['backup', 'initialize', 'check'].includes(purpose));
  const args = backupArguments(name, image);
  args[args.length - 1] = purpose === 'backup' ? PUBLIC_LLM_BACKUP_PROGRAM : purpose === 'initialize' ? PUBLIC_LLM_INITIALIZE_PROGRAM : PUBLIC_LLM_CHECK_PROGRAM;
  args.splice(args.indexOf(image) + 1, 0, '--import', 'tsx');
  args.splice(args.indexOf('--workdir'), 0, '--env', 'TMPDIR=/backup');
  if (purpose !== 'backup') {
    const at = args.indexOf(`type=volume,src=${PROJECT}_auth_accounts,dst=/auth,readonly,volume-nocopy`); safe(at >= 0);
    args[at] = `type=volume,src=${PROJECT}_auth_accounts,dst=/auth,volume-nocopy`;
    const env = Object.entries(PUBLIC_LLM_ENV).flatMap(([k, v]) => ['--env', `${k}=${v}`]); args.splice(args.indexOf('--workdir'), 0, ...env);
  }
  return args;
}
export function validatePublicLlmHelper(c, name, image, purpose, state) {
  safe(c.RestartCount === 0 && c.State?.Paused !== true);
  const program = purpose === 'backup' ? PUBLIC_LLM_BACKUP_PROGRAM : purpose === 'initialize' ? PUBLIC_LLM_INITIALIZE_PROGRAM : PUBLIC_LLM_CHECK_PROGRAM;
  safe(['backup', 'initialize', 'check'].includes(purpose) && equal(c.Config.Cmd, ['--import', 'tsx', '--input-type=module', '-e', program]) && equal(c.Args, c.Config.Cmd));
  const copy = structuredClone(c); copy.Config.Cmd = ['--input-type=module', '-e', RECOVERY_BACKUP]; copy.Args = copy.Config.Cmd;
  safe(equal(envMap(copy.Config.Env), { ...envMap(image.Config.Env), ...(purpose !== 'backup' ? PUBLIC_LLM_ENV : {}), TMPDIR: '/backup' })); copy.Config.Env = image.Config.Env;
  if (purpose !== 'backup') {
    const m = copy.HostConfig.Mounts.filter(m => m.Target === '/auth'), o = copy.Mounts.filter(m => m.Destination === '/auth');
    safe(m.length === 1 && o.length === 1 && (!Object.hasOwn(m[0], 'ReadOnly') || m[0].ReadOnly === false) && o[0].RW === true); m[0].ReadOnly = true; o[0].RW = false;
  }
  validateBackupHelper(copy, name, image, 'backup', state);
}

// The orchestrator has no weak/no-op production defaults. Concrete authority,
// snapshots and probes are assembled below; injected operations are offline test seams.
const admissionContexts = new WeakSet();
export async function executePublicLlmMaintenance(ops, originalBaseline = null, admissionContext = null) {
  const admission = admissionContext !== null;
  safe(!admission || admissionContexts.has(admissionContext));
  for (const key of ['preflight', 'intent', 'stop', 'drain', 'snapshot', 'candidate', 'initialize', 'startRetained', 'up', 'ready', 'publish', 'complete']) safe(typeof ops[key] === 'function');
  await ops.preflight(); await ops.intent();
  if (!originalBaseline) { await ops.stop('web'); await ops.stop('api'); await ops.drain(); await ops.stop('worker'); }
  const baseline = await ops.snapshot('fenced');
  if (originalBaseline) safe(equal(baseline.core, originalBaseline.core) && (admission ? baseline.llm !== null && baseline.empty === true && (originalBaseline.llm === null || equal(baseline.llm, originalBaseline.llm)) : equal(baseline.llm, originalBaseline.llm)));
  await ops.candidate(); // Existing image metadata was proved BEFORE any build.
  if (!admission) {
    await ops.initialize(baseline.llm === null);
    await ops.startRetained(); // Only after the original network-none preservation snapshot.
    await ops.up('llm-egress'); await ops.up('worker');
  }
  await ops.ready('worker');
  const initialized = await ops.snapshot('before-api');
  safe(equal(baseline.core, initialized.core));
  if (baseline.llm === null) safe(initialized.llm !== null && initialized.empty === true);
  else safe(equal(baseline.llm, initialized.llm));
  await ops.up('api'); await ops.ready('api');
  const final = await ops.snapshot('after-api');
  safe(equal(initialized.core, final.core) && equal(initialized.llm, final.llm));
  // Admission is still closed: web is stopped until all four DBs compare.
  await ops.publish(); await ops.up('web'); await ops.ready('web'); await ops.complete();
  return { outcome: 'ready', generationVerified: false };
}

export function capturePublicLlmSource(root) {
  checkIgnores(root);
  for (const file of ['public-stand.Dockerfile', 'gateway/openrouter.Dockerfile']) safe(!has(join(root, 'server/deploy', file + '.dockerignore')));
  const ignore = readBounded(join(root, '.dockerignore'), 131072).split(/\r?\n/).map(s => s.trim());
  safe(['.env', '.env.*', '**/.env', '**/.env.*', '**/*.local', '.local-auth', '.local-stand', '.local-public-images/'].every(s => ignore.includes(s)) && !ignore.some(s => s.startsWith('!')));
  const paths = ['package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml', 'index.html', 'admin.html', 'vite.config.ts', 'tsconfig.json', '.gitignore', '.dockerignore',
    'server/api/package.json', 'server/api/tsconfig.json', 'server/deploy/trust/db-signing-key.pub.pem',
    'server/deploy/compose.public-images.yaml', 'server/deploy/compose.public-llm.yaml',
    'server/deploy/public-stand.Dockerfile', 'server/deploy/public-stand.nginx.conf', 'server/deploy/api.Dockerfile',
    'server/deploy/worker.Dockerfile', 'server/deploy/gateway/Dockerfile', 'server/deploy/gateway/proxy.py',
    'server/deploy/gateway/openrouter.Dockerfile', 'server/deploy/gateway/openrouter.py'];
  const directories = [];
  const walk = p => {
    const s = fs.lstatSync(join(root, p)); safe(!s.isSymbolicLink());
    if (s.isDirectory()) {
      const names = fs.readdirSync(join(root, p)).sort(); directories.push({ p, dev: s.dev, ino: s.ino, names });
      for (const n of names) walk(p + '/' + n);
    } else { safe(s.isFile() && s.size <= 16 * 1024 ** 2); paths.push(p); }
  };
  for (const p of ['src', 'public', 'server/api/src', 'server/runtime/src']) walk(p);
  const files = paths.map(p => sourceFileFence(join(root, p)));
  const overlay = JSON.parse(readBounded(join(root, 'server/deploy/compose.public-llm.yaml'), 16384));
  overlay.services['llm-egress'].build.context = root; safe(equal(overlay, publicLlmStaticOverlay(root)));
  const nginx = readBounded(join(root, 'server/deploy/public-stand.nginx.conf'), 65536);
  safe(nginx.includes('set $history_ingress_enabled 1;') && nginx.includes('set $runtime_ingress_enabled 0;') && nginx.includes('context|usage|readiness'));
  return { manifest: { files: files.map(f => ({ path: f.path.slice(root.length + 1), ...f.snapshot })), directories }, verify() {
    checkIgnores(root); for (const f of files) f.verify();
    for (const d of directories) { const s = fs.lstatSync(join(root, d.p)); safe(s.isDirectory() && !s.isSymbolicLink() && s.dev === d.dev && s.ino === d.ino && equal(fs.readdirSync(join(root, d.p)).sort(), d.names)); }
  } };
}
const sourceFence = root => capturePublicLlmSource(root).verify;
function control(c) {
  const x = structuredClone(c.Config); if (x.Env) x.Env = x.Env.filter(v => !v.startsWith('SCAN_JWT_SECRET='));
  return hash({ Name: c.Name, Image: c.Image, Path: c.Path, Args: c.Args, Config: x, HostConfig: c.HostConfig,
    Mounts: [...c.Mounts].sort((a, b) => a.Destination.localeCompare(b.Destination)) });
}
function epoch(c) { return [c.Id, c.State.StartedAt, c.State.FinishedAt, c.State.Pid, c.RestartCount, c.State.Running, c.State.Status, c.State.ExitCode, c.State.Error]; }
function cleanStopped(c) {
  // Python gateways have no SIGTERM handler; nginx may also exit by SIGTERM.
  // Writers and one-shot initializers must still prove a clean exit0.
  const exits = ['egress', 'llm-egress', 'web'].includes(role(c)) ? [0, 143] : [0];
  safe(!c.State.Running && c.State.Status === 'exited' && exits.includes(c.State.ExitCode) && c.State.Pid === 0 && c.RestartCount === 0 &&
    !c.State.OOMKilled && !c.State.Dead && !c.State.Restarting && !c.State.Paused && !c.State.Error);
}
function ownOne(inventory, name) { const a = inventory.containers.filter(c => role(c) === name); safe(a.length === 1); return a[0]; }
function validateAuditHistory(root) {
  const parent = join(root, STATE, 'llm-deployments');
  if (has(parent)) {
    directory(parent, 0o700); const names = fs.readdirSync(parent);
    safe(names.length < 16 && names.every(n => /^deploy-[a-f0-9]{32}$/.test(n)));
    for (const n of names) { directory(join(parent, n), 0o700); safe(equal(privateJson(readBounded(join(parent, n, 'complete.json'), 4096, 0o600)), { version: 1, project: PROJECT, preserved: true })); }
  }
  const disk = fs.statfsSync(has(parent) ? parent : join(root, STATE)); safe(disk.bavail * disk.bsize >= 4 * 1024 ** 3);
}
function privateAudit(root) {
  validateAuditHistory(root);
  const parent = join(root, STATE, 'llm-deployments');
  if (!has(parent)) { fs.mkdirSync(parent, { mode: 0o700 }); syncDirectory(join(root, STATE)); }
  const nonce = crypto.randomBytes(16).toString('hex'), path = join(parent, 'deploy-' + nonce);
  fs.mkdirSync(path, { mode: 0o700 }); syncDirectory(parent);
  const parentVerify = directoryFence(parent), auditVerify = directoryFence(path);
  return { path, nonce, verify() { parentVerify(); auditVerify(); } };
}

// Reusable four-store bridge for the future CVE owner. Context owns peer/image/
// writer checks; this factory always uses the concrete validated helper/export.
export function createPublicLlmPreservation({ DB, root, lock, audit, helper, verifyState, continued = false, initializedCurrent = false, rebuiltCurrent = false, initExitCurrent = false, admitCurrent = false, apiCurrent = false }) {
  safe(typeof DB === 'function' && typeof helper === 'function' && typeof verifyState === 'function');
  safe(resolve(root) === root && lock.path === join(root, STATE, '.operation.lock') &&
    dirname(audit) === join(root, STATE, 'llm-deployments') && /^deploy-[a-f0-9]{32}$/.test(audit.slice(audit.lastIndexOf('/') + 1)));
  checkIgnores(root); lock.verify();
  const auditVerify = directoryFence(audit), parentVerify = directoryFence(dirname(audit));
  safe([continued, initializedCurrent, rebuiltCurrent, initExitCurrent, admitCurrent, apiCurrent].every(v => typeof v === 'boolean') && [continued, initializedCurrent, rebuiltCurrent, initExitCurrent, admitCurrent, apiCurrent].filter(Boolean).length <= 1);
  const output = apiCurrent ? join(audit, 'api-current') : admitCurrent ? join(audit, 'admit-current') : initExitCurrent ? join(audit, 'init-exit-current') : rebuiltCurrent ? join(audit, 'rebuild-current') : initializedCurrent ? join(audit, 'initialize-current') : continued ? join(audit, 'continued') : audit;
  const outputVerify = directoryFence(output);
  let next = 0;
  return async phase => {
    safe(phase === ['fenced', 'before-api', 'after-api'][next]); parentVerify(); auditVerify(); lock.verify(); await verifyState();
    outputVerify(); const dir = join(output, phase); fs.mkdirSync(dir, { mode: 0o700 }); syncDirectory(output);
    const result = await helper(phase, 'backup', async (id, d, check, receipt) => {
      safe(receipt.ready === true && typeof receipt.llmPresent === 'boolean');
      for (const group of ['core', ...(receipt.llmPresent ? ['llm'] : [])]) {
        const destination = join(dir, group); fs.mkdirSync(destination, { mode: 0o700 }); syncDirectory(dir);
        const read = async request => { await check(); return JSON.parse(await d(['container', 'exec', id, 'node', '-e', PUBLIC_LLM_EXPORT_PROGRAM, JSON.stringify({ group, request })])); };
        const manifest = await read({ action: 'manifest' }); validateExportManifest(manifest);
        writeExclusive(join(destination, 'private-manifest.json'), JSON.stringify(manifest), 0o600);
        for (const r of ['auth', 'ledger']) await transferBackupSnapshot({ dir: destination, role: r, manifest, readChunk: read, verify: check });
        safe(equal(manifest, await read({ action: 'manifest' }))); syncDirectory(destination);
      }
      return receipt.llmPresent;
    });
    await verifyState(); lock.verify(); parentVerify(); auditVerify();
    const paths = { auth: join(dir, 'core/auth.sqlite'), ledger: join(dir, 'core/ledger.sqlite') };
    await recoverySqlite(DB, fs, crypto, paths, null); // Existing restore/schema/drain contract.
    const core = Object.fromEntries(Object.entries(paths).map(([kind, path]) => [kind, {
      logicalSha256: llmFingerprint(DB, fs, crypto, path, kind), // Also includes application_id and all sqlite_master objects.
    }]));
    let llm = null, empty = false;
    if (result) {
      const history = join(dir, 'llm/auth.sqlite'), quota = join(dir, 'llm/ledger.sqlite');
      llm = { history: llmFingerprint(DB, fs, crypto, history, 'history'), quota: llmFingerprint(DB, fs, crypto, quota, 'quota') };
      if (phase === 'before-api' || (admitCurrent || apiCurrent) && phase === 'fenced') {
        try {
                  llmFingerprint(DB, fs, crypto, history, 'history', true); llmFingerprint(DB, fs, crypto, quota, 'quota', true);
                  if ((admitCurrent || apiCurrent) && phase === 'fenced') { assertAdmissionStoreEmpty(DB, history, 'history'); assertAdmissionStoreEmpty(DB, quota, 'quota'); }
                  empty = true;
                }
        catch { /* Existing nonempty durable state is compared, never truncated. */ }
      }
    }
    next++; return { core, llm, empty };
  };
}

const PUBLIC_LLM_PREFLIGHT_DIAGNOSTICS = Object.freeze({
  'preflight-history': 'PUBLIC_HISTORY_REJECTED', 'preflight-profile': 'PUBLIC_PROFILE_REJECTED',
  'preflight-binding': 'PUBLIC_LLM_BINDING_REJECTED', 'preflight-source': 'PUBLIC_SOURCE_REJECTED',
  'preflight-jwt': 'PUBLIC_JWT_UNAVAILABLE', 'preflight-state-files': 'PUBLIC_STATE_FILES_REJECTED',
  'preflight-engine': 'PUBLIC_ENGINE_REJECTED', 'preflight-pins': 'PUBLIC_IMAGE_PINS_REJECTED',
  ...Object.fromEntries(['auth-volume-init', 'scan-volume-init', 'egress', 'worker', 'api', 'web', 'llm-egress']
    .map(name => ['preflight-images-' + name, 'PUBLIC_PRIOR_IMAGE_REJECTED'])),
  'preflight-namespace': 'PUBLIC_NAMESPACE_REJECTED', 'preflight-peer-states': 'PUBLIC_PEER_STATE_REJECTED',
  'preflight-key-volume': 'PUBLIC_KEY_VOLUME_REJECTED', 'preflight-sqlite': 'PUBLIC_SQLITE_UNAVAILABLE',
  'preflight-peers': 'PUBLIC_PEER_AUTHORITY_REJECTED', 'preflight-census': 'PUBLIC_CENSUS_REJECTED',
  'preflight-consumers': 'PUBLIC_VOLUME_CONSUMERS_REJECTED', 'preflight-backup-history': 'PUBLIC_BACKUP_HISTORY_REJECTED',
  'build-source': 'PUBLIC_BUILD_SOURCE_REJECTED', 'build-config': 'PUBLIC_BUILD_CONFIG_REJECTED', 'build-pins': 'PUBLIC_BUILD_PINS_REJECTED',
  ...Object.fromEntries(['api', 'worker', 'web', 'llm-egress'].map(n => ['build-submit-' + n, 'PUBLIC_BUILD_SUBMISSION_REJECTED'])),
  ...Object.fromEntries(['auth-volume-init', 'scan-volume-init', 'api', 'worker', 'web', 'egress', 'llm-egress'].map(n => ['build-image-' + n, 'PUBLIC_BUILD_IMAGE_REJECTED'])),
  'continue-check': 'PUBLIC_CONTINUATION_CHECK_REJECTED',
});

export async function publicLlmStand(argv, { root = ROOT, home = homedir(), run = runIsolatedDocker, ambient = process.env,
  Database, sleep = ms => new Promise(r => setTimeout(r, ms)), now = () => performance.now(), request = fetch, log = console.log, onDiagnostic, checkSource = checkPublicLlmSourceBuild } = {}) {
  const [command, ...flags] = argv;
  let continuation;
  if (['check-current-build', 'continue-current-build', 'check-current-initialize', 'continue-current-initialize', 'check-current-rebuild', 'continue-current-rebuild', 'check-current-init-exit', 'continue-current-init-exit', 'check-current-admit', 'continue-current-admit', 'check-current-api', 'continue-current-api'].includes(command)) {
    safe(flags[0] === '--audit' && /^deploy-[a-f0-9]{32}$/.test(flags[1] ?? '') && resolve(root) === root && fs.realpathSync(root) === root);
    const checking = command.startsWith('check-'), apiOnly = command.endsWith('-api'), admitting = apiOnly || command.endsWith('-admit'), initExit = command.endsWith('-init-exit'), rebuilding = command.endsWith('-rebuild'), initializing = admitting || initExit || rebuilding || command.endsWith('-initialize');
    safe(checking ? flags.length === 2 : flags[2] === '--review' && /^[a-f0-9]{64}$/.test(flags[3] ?? '') && flags[4] === '--ack-reviewed-current-source' &&
      (flags.length === 5 || flags.length === 6 && flags[5] === '--ack-retire-only-unavailable-worker' ||
        initializing && flags.length === 7 && flags[5] === '--ack-retire-only-unavailable-worker' && ['--ack-retire-only-unavailable-api', '--ack-retire-only-unavailable-web'].includes(flags[6]) ||
        initializing && flags.length === 8 && flags[5] === '--ack-retire-only-unavailable-worker' && flags[6] === '--ack-retire-only-unavailable-api' && flags[7] === '--ack-retire-only-unavailable-web'));
    const module = initializing ? await import('./public-llm-initialize-continuation.mjs') : await import('./public-llm-build-continuation.mjs');
    const prepare = apiOnly ? module.preparePublicLlmApiContinuation : admitting ? module.preparePublicLlmAdmitContinuation : initExit ? module.preparePublicLlmInitExitContinuation : rebuilding ? module.preparePublicLlmRebuildContinuation : initializing ? module.preparePublicLlmInitializeContinuation : module.preparePublicLlmBuildContinuation;
    continuation = await prepare({ root, home, audit: flags[1], run, ambient, Database, checkSource });
    if (checking) { log(JSON.stringify(continuation.summary)); return continuation.summary; }
    if (admitting) admissionContexts.add(continuation);
    safe(continuation.review === flags[3] && Boolean(continuation.replacement) === flags.includes('--ack-retire-only-unavailable-worker') &&
      Boolean(continuation.apiReplacement) === flags.includes('--ack-retire-only-unavailable-api') &&
            Boolean(continuation.webReplacement) === flags.includes('--ack-retire-only-unavailable-web'));
  }
  safe(Boolean(continuation) || ['plan', 'status', 'up'].includes(command) && (command === 'up' ? flags.includes('--ack-public-maintenance') &&
    flags.every(f => ['--ack-public-maintenance', '--build'].includes(f)) && new Set(flags).size === flags.length : flags.length === 0));
  safe(resolve(root) === root && fs.realpathSync(root) === root);
  if (command === 'plan') {
    log('Source plan only: 7 fixed services, 6 own networks; API-only optional external readonly key volume. No Docker or key/config read.');
    return { services: 7, ownNetworks: 6, keyMount: 'only-after-provisioning-receipt', generationVerified: false };
  }
  if (command === 'status') { const s = readPublicLlmBinding(root); log(s ? `Public LLM profile recorded; key volume ${s.keyVolume ? 'supplied' : 'unavailable'}; not a runtime/credential verification.` : 'No public LLM profile recorded.'); return; }
  safe(!resolve(home, '.local/state/diplom-public-images/llm').startsWith(root + '/'));
  const settings = loadPublicLlmSettings(home); // Approved non-secret config/receipt only.
  let archivedLock;
  const verifyHeldLock = continuation ? directoryFence(continuation.lockPath) : null;
  const lock = continuation ? { path: continuation.lockPath, verify: verifyHeldLock,
    release() { if (archivedLock) { archivedLock(); return; } verifyHeldLock(); fs.rmdirSync(continuation.lockPath); syncDirectory(join(root, STATE)); } } : acquireLock(root);
  const verifyPublicState = directoryFence(join(root, STATE)); let hold = Boolean(continuation), phase = 'preflight', audit, stage, candidateImages, before, priorImages, profile, priorSelection, jwt, d, options, endpoint, verifySource;
  const records = new Set(), peers = new Map(), peerModels = new Map(), healthy = new Set();
  let failedHelper = continuation?.initialize?.failed ?? null;
    let keyVolumeAuthority, stoppedStand = false, staleHelper = continuation?.initialize?.retired ? null : continuation?.initialize ?? null;
  const outputPrefix = continuation?.apiOnly ? 'api-current' : continuation?.admissionOnly ? 'admit-current' : continuation?.initialize?.failed ? 'init-exit-current' : continuation?.initialize?.retired ? 'rebuild-current' : continuation?.initialize ? 'initialize-current' : 'continued';
  const recordName = name => continuation?.initialize ? outputPrefix + '-' + name : name;
  const fences = [], candidateFences = [];
  let verifyStage, readinessFailure;
  const fence = () => { verifyPublicState(); lock.verify(); continuation?.verifyExecution(); continuation?.initialize?.verify(); settings.verify(); verifySource?.(); audit?.verify(); verifyStage?.(); for (const f of [...fences, ...candidateFences]) f.verify(); };
  const record = (name, value) => { lock.verify(); continuation?.verifyExecution(); const target = recordName(name); writeExclusive(join(lock.path, target), JSON.stringify(value), 0o600); records.add(target); syncDirectory(lock.path); };
  const inspect = async (id, name, model, images, selection) => {
    const a = JSON.parse(await d(['container', 'inspect', id])); safe(a.length === 1 && a[0].Id === id);
    if (continuation?.replacement && !continuation.admissionOnly && name === 'worker' && id === continuation.inventory.containers.find(c => role(c) === 'worker').Id) {
      const module = await import('./public-llm-build-continuation.mjs');
      module.validateRetiredPublicLlmWorker(a[0], continuation.pins.services.worker.image, continuation.replacement, model, images);
    } else if (continuation?.apiReplacement && name === 'api' && id === continuation.inventory.containers.find(c => role(c) === 'api').Id) {
      continuation.initialize.validateRetiredApi(a[0], continuation.pins.services.api.image, model, images, jwt);
    } else if (continuation?.webReplacement && name === 'web' && id === continuation.inventory.containers.find(c => role(c) === 'web').Id) {
      continuation.initialize.validateRetiredWeb(a[0], continuation.pins.services.web.image, model, images);
    } else validatePublicLlmContainer(a[0], name, model.services[name], images[name], model, { secret: jwt, images }, selection);
    const command = [...(a[0].Config.Entrypoint ?? []), ...a[0].Config.Cmd]; safe(a[0].Path === command[0] && equal(a[0].Args, command.slice(1)));
    return a[0];
  };
  const verifyPeers = async () => {
    fence(); if (failedHelper) await failedHelper.check(d);
        if (staleHelper) await staleHelper.checkHelper(d);
        else if (continuation?.initialize?.retired) await continuation.initialize.checkHelper(d);
    for (const [name, previous] of peers) {
      const authority = peerModels.get(name), current = await inspect(previous.Id, name, authority.model, authority.images, authority.selection);
      safe(control(previous) === control(current) && equal(epoch(previous), epoch(current)) && !current.State.Paused && !current.State.Dead && !current.State.Restarting && !current.State.OOMKilled);
      if (!current.State.Running) cleanStopped(current);
      if (healthy.has(name)) safe(current.State.Health?.Status === 'healthy');
    }
    // A replaced volume must be rejected before any helper mounts it, not only
    // in the final namespace comparison after reading a different data source.
    for (const volume of before?.volumes.filter(v => v.Name.startsWith(PROJECT + '_')) ?? []) {
      const rows = JSON.parse(await d(['volume', 'inspect', volume.Name])); safe(rows.length === 1 && equal(rows[0], volume));
    }
    if (keyVolumeAuthority) {
      const rows = JSON.parse(await d(['volume', 'inspect', settings.selection.keyVolume])); safe(rows.length === 1 && equal(rows[0], keyVolumeAuthority));
      const consumers = (await d(['container', 'ls', '--all', '--no-trunc', '--filter', `volume=${settings.selection.keyVolume}`, '--format', '{{.ID}}'])).trim().split('\n').filter(Boolean);
      const allowed = [...peers.values()].filter(c => c.Mounts.some(m => m.Type === 'volume' && m.Name === settings.selection.keyVolume)).map(c => c.Id);
      safe(equal(consumers.sort(), allowed.sort()));
    }
  };
  const users = async (helperId, runningHelper = true) => {
    for (const key of ['auth_accounts', 'scan_ledger']) {
      const allowed = [...peers.values()].filter(c => c.Mounts.some(m => m.Type === 'volume' && m.Name === `${PROJECT}_${key}`));
      for (const all of [true, false]) {
        const ids = (await d(['container', 'ls', ...(all ? ['--all'] : []), '--filter', `volume=${PROJECT}_${key}`, '--format', '{{.ID}}', '--no-trunc'])).trim().split('\n').filter(Boolean);
        safe(equal(ids.sort(), [...allowed.filter(c => all || c.State.Running).map(c => c.Id), ...(helperId && (all || runningHelper) ? [helperId] : []), ...(staleHelper && all ? [staleHelper.helper.id] : []), ...(failedHelper && all ? [failedHelper.id] : [])].sort()));
      }
    }
  };
  const census = async helperRecord => {
    const rows = (await d(['container', 'ls', '--all', '--no-trunc', '--format', '{{.ID}}\t{{.Names}}\t{{.Label "com.docker.compose.project"}}'])).trim().split('\n').filter(Boolean).map(v => v.split('\t'))
      .filter(r => r[1]?.startsWith(PROJECT + '-') || r[2] === PROJECT);
    const expected = [...peers.values()].map(c => [c.Id, c.Name.slice(1), PROJECT]); if (helperRecord) expected.push(helperRecord);
    if (staleHelper) expected.push([staleHelper.helper.id, `${PROJECT}-llm-${continuation.nonce}-continued-initialize`, PROJECT]);
    if (failedHelper) expected.push([failedHelper.id, failedHelper.name, PROJECT]);
    safe(equal(rows.sort((a,b)=>a[1].localeCompare(b[1])), expected.sort((a,b)=>a[1].localeCompare(b[1]))));
  };
  const helper = async (suffix, purpose, work = async () => undefined) => {
    fence(); await verifyPeers(); await users(); await census();
    const image = purpose === 'backup' && (!continuation || suffix === 'fenced') ? (continuation?.backupImage ?? priorImages.api) : candidateImages.api;
    const imageRows = JSON.parse(await d(['image', 'inspect', image.Id]));
    safe(imageRows.length === 1 && imageRows[0].Id === image.Id && imageRows[0].Os === image.Os && equal(imageRows[0].Config, image.Config));
    validateImage(imageRows[0], 'api'); // Retagging may change RepoTags, never immutable execution defaults.
    const recordedSuffix = (continuation ? outputPrefix + '-' : '') + suffix;
    const name = `${PROJECT}-llm-${audit.nonce}-${recordedSuffix}`;
    const id = (await d(publicLlmHelperArguments(name, image.Id, purpose))).trim(); safe(containerId(id));
    let authority, execution;
    const check = async state => {
      fence(); const rows = JSON.parse(await d(['container', 'inspect', id])); safe(rows.length === 1);
      const c = rows[0]; safe(c.Id === id); validatePublicLlmHelper(c, name, image, purpose, state);
      const projection = hash(helperAuthorityProjection(c)); if (authority) safe(authority === projection); else authority = projection;
      if (state === 'running') { safe(Number.isFinite(Date.parse(c.Created)) && Number.isFinite(Date.parse(c.State.StartedAt))); const e = [c.Created, c.State.StartedAt, c.State.Pid, c.RestartCount]; if (execution) safe(equal(e, execution)); else execution = e; }
      if (state === 'exited') safe(c.State.ExitCode === 0 && c.State.StartedAt === execution[1]);
      for (const m of c.Mounts.filter(m => m.Type === 'volume')) { const v = before.volumes.find(v => v.Name === m.Name); safe(v && m.Source === v.Mountpoint && m.Driver === 'local'); }
      await verifyPeers(); await census([id, name, PROJECT]); await users(id, state === 'running');
    };
    record(`helper-${recordedSuffix}.json`, { id, image: image.Id, purpose });
    await check('created');
    // Created containers count in --all but must not appear as running users.
    await d(['container', 'start', id]); await check('running');
    const deadline = now() + 120000; let receipt;
    do { await check('running'); await users(id); receipt = JSON.parse(await d(['container', 'exec', id, 'node', '-e', readyProgram])); if (receipt.ready === true) break; safe(now() < deadline); await sleep(1000); } while (true);
    const result = await work(id, d, () => check('running'), receipt);
    await check('running'); await d(['container', 'stop', '--time', '10', id], { timeout: 20000 }); await check('exited');
    await d(['container', 'rm', id]); await census(); await users(); return result;
  };
  let snapshot, fencedBaseline;
  const stageArgs = args => publicLlmComposeArguments(root, args, { cve: Boolean(profile.cve), directory: stage });
  const nextModel = () => expectedPublicLlmConfig(root, profile.cve, settings.selection);
  const ops = {
    async preflight() {
      if (continuation) {
        phase = 'continue-check'; continuation.verify(); continuation.initialize?.checkPrefix();
        profile = continuation.profile; priorSelection = null; jwt = loadSecret(root, true); before = continuation.inventory; priorImages = continuation.images;
        stage = continuation.initialize ? join(lock.path, continuation.apiOnly ? 'api-current' : continuation.admissionOnly ? 'admit-current' : continuation.initialize.failed ? 'init-exit-current' : continuation.initialize.retired ? 'llm-rebuild-candidate' : 'llm-initialize-candidate') : continuation.stage; options = continuation.options; endpoint = continuation.endpoint;
        verifySource = sourceFence(root); fences.push(...continuation.stateFiles, ...continuation.proofs); candidateFences.push(...continuation.candidateFiles);
        const deadline = now() + 20 * 60 * 1000;
        d = (args, extra = {}) => { fence(); safe((extra.env?.DOCKER_HOST ?? endpoint) === endpoint && now() < deadline); return run(args, { ...options, ...extra, timeout: publicLlmDockerTimeout(extra.timeout ?? 30000, deadline, now()) }); };
        const model = expectedPublicLlmConfig(root, profile.cve, null);
        for (const c of before.containers) {
                  const name = role(c), admittedPeer = continuation.admissionOnly && ['worker', 'llm-egress'].includes(name);
                  peers.set(name, c); peerModels.set(name, admittedPeer ? { model: nextModel(), images: continuation.initialize.candidateImages, selection: settings.selection } : { model, images: priorImages, selection: null });
                }
        await verifyPeers(); await census(); await users(); return;
      }
      phase = 'preflight-history'; assertReconciliationHistory(root);
      phase = 'preflight-profile'; profile = readProfile(root); safe(profile !== undefined && (!profile.cve || profile.version === 2));
      phase = 'preflight-binding'; priorSelection = readPublicLlmBinding(root); safe(priorSelection !== null || flags.includes('--build'));
      if (priorSelection?.keyVolume) safe(equal(priorSelection, settings.selection)); // Activation, not arbitrary secret rotation.
      phase = 'preflight-source'; verifySource = sourceFence(root);
      phase = 'preflight-jwt'; jwt = loadSecret(root, true);
      phase = 'preflight-state-files'; for (const p of ['profile.json', 'scan-jwt', 'compose.images.json', ...(profile.cve ? ['compose.cve.json'] : []),
        ...(priorSelection ? ['llm-profile.json', 'compose.llm-env.json'] : [])]) fences.push(fileFence(join(root, STATE, p)));
      phase = 'preflight-engine'; const baseEnv = dockerEnvironment(ambient), rawEndpoint = baseEnv.DOCKER_HOST && !baseEnv.DOCKER_CONTEXT ? baseEnv.DOCKER_HOST :
        JSON.parse(await run(['context', 'inspect', ...(baseEnv.DOCKER_CONTEXT ? [baseEnv.DOCKER_CONTEXT] : []), '--format', '{{json .Endpoints.docker.Host}}'], { root, env: baseEnv }));
      safe(typeof rawEndpoint === 'string' && /^unix:\/\/\/[^\s\0]+$/.test(rawEndpoint)); endpoint = rawEndpoint;
      const env = { ...baseEnv, DOCKER_HOST: endpoint, COMPOSE_DISABLE_ENV_FILE: '1' }; for (const k of ['DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']) delete env[k];
      options = { root, env }; const end = now() + 20 * 60 * 1000;
      d = (args, extra = {}) => { fence(); safe((extra.env?.DOCKER_HOST ?? endpoint) === endpoint && now() < end); return run(args, { ...options, ...extra, timeout: publicLlmDockerTimeout(extra.timeout ?? 30000, end, now()) }); };
      phase = 'preflight-pins'; const priorModel = expectedPublicLlmConfig(root, profile.cve, priorSelection), pins = JSON.parse(readBounded(join(root, STATE, 'compose.images.json'), 16384, 0o600));
      safe(equal(Object.keys(pins), ['services']) && equal(Object.keys(pins.services).sort(), Object.keys(priorModel.services).sort())); priorImages = {};
      for (const name of Object.keys(priorModel.services)) {
        safe(['auth-volume-init', 'scan-volume-init', 'egress', 'worker', 'api', 'web', 'llm-egress'].includes(name)); phase = 'preflight-images-' + name;
        const id = pins.services[name]?.image; safe(imageId(id) && equal(pins.services[name], { image: id }));
        // No container-config/tag recovery if a historical image ID cannot be inspected.
        const a = JSON.parse(await d(['image', 'inspect', id])); safe(a.length === 1 && a[0].Id === id); validatePublicLlmImage(a[0], name); priorImages[name] = a[0];
      }
      phase = 'preflight-namespace'; before = await inspectPublicLlmNamespace(d, options, root, profile.cve, priorSelection, { secret: jwt, images: priorImages });
      safe(before.containers.length === Object.keys(priorModel.services).length);
      phase = 'preflight-peer-states'; stoppedStand = before.containers.filter(c => !role(c).endsWith('volume-init')).every(c => !c.State.Running);
      for (const c of before.containers) {
        const command = [...(c.Config.Entrypoint ?? []), ...c.Config.Cmd]; safe(c.Path === command[0] && equal(c.Args, command.slice(1)));
        if (stoppedStand || role(c).endsWith('volume-init')) {
          cleanStopped(c);
          if (stoppedStand && !role(c).endsWith('volume-init')) safe(c.State.StartedAt !== '0001-01-01T00:00:00Z' &&
            Number.isFinite(Date.parse(c.State.StartedAt)) && Number.isFinite(Date.parse(c.State.FinishedAt)) && Date.parse(c.State.FinishedAt) >= Date.parse(c.State.StartedAt));
        } else safe(c.State.Running && c.State.Status === 'running' && Number.isSafeInteger(c.State.Pid) && c.State.Pid > 0 &&
          !c.State.OOMKilled && !c.State.Restarting && !c.State.Dead && !c.State.Paused && !c.State.Error && c.RestartCount === 0);
        peers.set(role(c), c); peerModels.set(role(c), { model: priorModel, images: priorImages, selection: priorSelection });
      }
      if (!stoppedStand) { safe(peers.get('api').State.Health?.Status === 'healthy'); healthy.add('api'); }
      phase = 'preflight-key-volume'; if (settings.selection.keyVolume) {
        const rows = JSON.parse(await d(['volume', 'inspect', settings.selection.keyVolume])); safe(rows.length === 1);
        const v = rows[0]; validatePublicLlmKeyVolume(v, settings.selection);
        keyVolumeAuthority = v; // Metadata only; never mount/open/read a key to qualify it.
      }
      phase = 'preflight-sqlite'; const DB = Database ?? requireApi('better-sqlite3'); const probe = new DB(':memory:'); probe.close();
      phase = 'preflight-peers'; await verifyPeers();
      phase = 'preflight-census'; await census();
      phase = 'preflight-consumers'; await users();
      // Budget/partial generations are checked before any live fence or build.
      phase = 'preflight-backup-history'; validateAuditHistory(root);
    },
    async intent() {
      if (continuation) {
        continuation.verify(); continuation.initialize?.checkPrefix(); // Final exclusive-prefix and execution-closure fence.
        phase = 'continue-intent'; record('continue.json', { version: 1, command, audit: continuation.auditName, review: continuation.review,
          sourceReview: 'explicit-current-source-not-historical', retireOnlyWorker: Boolean(continuation.replacement),
          ...(continuation.initialize ? { retireOnlyApi: Boolean(continuation.apiReplacement), retireOnlyWeb: Boolean(continuation.webReplacement), backupHelperBasis: continuation.summary.backupHelperBasis } : {}) });
        record('continuation-checkpoint.json', continuation.reviewEvidence);
        const parentVerify = directoryFence(dirname(continuation.auditPath)), auditVerify = directoryFence(continuation.auditPath);
        audit = { path: continuation.auditPath, nonce: continuation.nonce, verify() { parentVerify(); auditVerify(); } };
        fs.mkdirSync(join(audit.path, outputPrefix), { mode: 0o700 });
        writeExclusive(join(audit.path, outputPrefix, 'review.json'), JSON.stringify(continuation.reviewEvidence), 0o600);
        syncDirectory(join(audit.path, outputPrefix)); syncDirectory(audit.path);
        if (continuation.initialize) {
          fs.mkdirSync(stage, { mode: 0o700 }); syncDirectory(lock.path);
          for (const name of ['compose.cve.json', 'compose.llm-env.json']) {
            writeExclusive(join(stage, name), readBounded(join(continuation.stage, name), 16384, 0o600), 0o600);
            candidateFences.push(fileFence(join(stage, name)));
          }
          syncDirectory(stage);
        }
        verifyStage = directoryFence(stage);
        snapshot = createPublicLlmPreservation({ DB: Database ?? requireApi('better-sqlite3'), root, lock, audit: audit.path, helper, continued: !continuation.initialize, initializedCurrent: Boolean(continuation.initialize && !continuation.initialize.retired), rebuiltCurrent: Boolean(continuation.initialize?.retired && !continuation.initialize.failed && !continuation.admissionOnly), initExitCurrent: Boolean(continuation.initialize?.failed), admitCurrent: Boolean(continuation.admissionOnly && !continuation.apiOnly), apiCurrent: Boolean(continuation.apiOnly),
          verifyState: async () => { await verifyPeers(); await users(); await census(); } });
        return;
      }
      hold = true; record('mutation.json', { version: 1, project: PROJECT, command: 'public-llm-up', phase: 'fence-web', endpoint });
      audit = privateAudit(root); stage = join(lock.path, 'llm-candidate'); fs.mkdirSync(stage, { mode: 0o700 }); syncDirectory(lock.path);
      verifyStage = directoryFence(stage);
      if (profile.cve) writeExclusive(join(stage, 'compose.cve.json'), readBounded(join(root, STATE, 'compose.cve.json'), 16384, 0o600), 0o600);
      writeExclusive(join(stage, 'compose.llm-env.json'), JSON.stringify(publicLlmEnvironmentOverlay(settings.selection)), 0o600);
      for (const name of fs.readdirSync(stage)) candidateFences.push(fileFence(join(stage, name)));
      snapshot = createPublicLlmPreservation({ DB: Database ?? requireApi('better-sqlite3'), root, lock, audit: audit.path, helper, verifyState: async () => { await verifyPeers(); await users(); await census(); } });
    },
    async stop(name) {
      phase = 'stop-' + name; await verifyPeers(); await users();
      healthy.delete(name);
      const c = peers.get(name), a = peerModels.get(name);
      if (stoppedStand) { cleanStopped(c); return; }
      await d(['container', 'stop', '--time', name === 'api' ? '60' : '30', c.Id], { timeout: name === 'api' ? 75000 : 45000 });
      const stopped = await inspect(c.Id, name, a.model, a.images, a.selection); safe(control(c) === control(stopped)); cleanStopped(stopped); peers.set(name, stopped);
    },
    async drain() {
      phase = 'drain';
      if (stoppedStand) {
        // Never restart/exec a stopped writer to inspect it. The mandatory
        // network-none backup's recoverySqlite checks jobs/leases/outbox.
        await verifyPeers(); await users(); await census(); return;
      }
      const end = now() + 120000;
      do { await verifyPeers(); await users(); const counts = JSON.parse(await d(['container', 'exec', peers.get('worker').Id, 'node', '-e', PUBLIC_DRAIN_PROBE]));
        safe(equal(Object.keys(counts).sort(), ['jobs', 'leases', 'outbox']) && Object.values(counts).every(n => Number.isSafeInteger(n) && n >= 0));
        if (Object.values(counts).every(n => n === 0)) return; safe(now() < end); await sleep(1000);
      } while (true);
    },
    async snapshot(part) { phase = 'backup-' + part; const value = await snapshot(part); if (part === 'fenced') { if (priorSelection) safe(value.llm !== null); fencedBaseline = value; } return value; },
    async candidate() {
      if (continuation?.admissionOnly) {
        phase = 'admit-current-pins'; continuation.initialize.verifyImageSource(); candidateImages = continuation.initialize.candidateImages;
        for (const [name, im] of Object.entries(candidateImages)) { const rows = JSON.parse(await d(['image', 'inspect', im.Id])); safe(rows.length === 1 && rows[0].Id === im.Id && equal(rows[0].Config, im.Config)); validatePublicLlmImage(rows[0], name); }
        writeExclusive(join(stage, 'compose.images.json'), JSON.stringify(continuation.initialize.currentPins), 0o600); syncDirectory(stage); candidateFences.push(fileFence(join(stage, 'compose.images.json')));
        validatePublicLlmConfig(JSON.parse(await d(stageArgs(['config', '--format', 'json']), { env: { ...options.env, SCAN_JWT_SECRET: CONFIG_SECRET } })), root, profile.cve, settings.selection, candidateImages); return;
      }
      if (failedHelper) {
        phase = 'retire-exited-initializer'; await verifyPeers(); await users(); await census();
        safe(fencedBaseline.llm === null); await failedHelper.confirmFailure(); await failedHelper.check(d);
        record('retired-failed-initializer.json', failedHelper.evidence);
        await d(['container', 'rm', failedHelper.id]); // Exact exited helper only; never restart/force/stop.
        failedHelper = null; await census(); await users();
        phase = 'reuse-current-pins'; continuation.initialize.verifyImageSource(); candidateImages = continuation.initialize.candidateImages;
        for (const [name, im] of Object.entries(candidateImages)) {
          const rows = JSON.parse(await d(['image', 'inspect', im.Id])); safe(rows.length === 1 && rows[0].Id === im.Id && equal(rows[0].Config, im.Config)); validatePublicLlmImage(rows[0], name);
        }
        writeExclusive(join(stage, 'compose.images.json'), JSON.stringify(continuation.initialize.currentPins), 0o600); syncDirectory(stage); candidateFences.push(fileFence(join(stage, 'compose.images.json')));
        validatePublicLlmConfig(JSON.parse(await d(stageArgs(['config', '--format', 'json']), { env: { ...options.env, SCAN_JWT_SECRET: CONFIG_SECRET } })), root, profile.cve, settings.selection, candidateImages);
        fence(); return;
      }
      if (staleHelper) {
        // Reached only AFTER the new network-none snapshot equals both held backups.
        phase = 'retire-created-initializer'; await verifyPeers(); await users(); await census();
        await staleHelper.checkHelper(d);
        record('retired-initializer.json', staleHelper.evidence);
        await d(['container', 'rm', staleHelper.helper.id]); // No force, stop, start or exec.
        staleHelper = null; await census(); await users();
      }
      phase = 'build-source'; await verifyPeers(); await users();
      const qualified = await checkSource(root); safe(qualified?.typescript === true && qualified?.bundle === true);
      phase = 'build-config'; const rendered = JSON.parse(await d(publicLlmComposeArguments(root, ['config', '--format', 'json'], { cve: Boolean(profile.cve), directory: stage, pinned: false }), { env: { ...options.env, SCAN_JWT_SECRET: CONFIG_SECRET } }));
      validatePublicLlmConfig(rendered, root, profile.cve, settings.selection);
      if (continuation || flags.includes('--build')) {
        const jwtStat = fs.lstatSync(join(root, STATE, 'scan-jwt'));
        record('build-checkpoint.json', { version: 1, phase: 'validated-before-build', source: capturePublicLlmSource(root).manifest,
          sourceBasis: continuation ? 'explicit-reviewed-current' : 'validated-before-build', baseline: fencedBaseline,
          imageMetadata: Object.fromEntries(Object.entries(priorImages).map(([n, im]) => [n, { Id: im.Id, Os: im.Os, Config: im.Config }])),
          retirementPolicy: continuation?.replacement ? { workerId: continuation.pins.services.worker.image, replacementId: continuation.replacement.Id, executeOriginal: false } : null,
          ...(continuation?.initialize ? { backupHelperBasis: 'validated-stale-candidate-api', backupImageId: continuation.backupImage.Id,
            apiRetirementPolicy: continuation.apiReplacement ? { apiId: continuation.pins.services.api.image, validationImageId: continuation.apiReplacement.Id, executeOriginal: false } : null,
            webRetirementPolicy: continuation.webReplacement ? { originalId: continuation.pins.services.web.image, validationImageId: continuation.webReplacement.Id, metadataUnavailable: true, executeOriginal: false } : null } : {}),
          peers: [...peers].map(([name, c]) => ({ name, id: c.Id, image: c.Image, control: control(c), epoch: epoch(c) })),
          publicProfile: profile, pins: JSON.parse(readBounded(join(root, STATE, 'compose.images.json'), 16384, 0o600)),
          jwtIdentity: { dev: String(jwtStat.dev), ino: String(jwtStat.ino), mode: jwtStat.mode, uid: jwtStat.uid, size: jwtStat.size, mtime: jwtStat.mtimeMs, ctime: jwtStat.ctimeMs } });
      }
      if (continuation || flags.includes('--build')) for (const name of ['api', 'worker', 'web', 'llm-egress']) {
        phase = 'build-submit-' + name;
        try { await d(publicLlmComposeArguments(root, ['build', name], { cve: Boolean(profile.cve), directory: stage, pinned: false }), { env: { ...options.env, SCAN_JWT_SECRET: CONFIG_SECRET }, timeout: 600000 }); }
        catch (error) {
          const category = ['timeout', 'docker_unavailable', 'network_pool', 'resources', 'runtime_health', 'image', 'unclassified'].includes(error?.category) ? error.category : 'guard';
          record('build-failure.json', { version: 1, phase, role: name, category }); throw Error('PUBLIC LLM build boundary rejected.');
        }
      }
      candidateImages = {};
      for (const [name, spec] of Object.entries(nextModel().services)) {
        phase = 'build-image-' + name;
        const ref = !continuation && !flags.includes('--build') || name.endsWith('volume-init') || name === 'egress' ? priorImages[name].Id : spec.image;
        const a = JSON.parse(await d(['image', 'inspect', ref])); safe(a.length === 1); validatePublicLlmImage(a[0], name); candidateImages[name] = a[0];
      }
      phase = 'build-pins'; writeExclusive(join(stage, 'compose.images.json'), JSON.stringify({ services: Object.fromEntries(Object.entries(candidateImages).map(([n, im]) => [n, { image: im.Id }])) }), 0o600); syncDirectory(stage);
      candidateFences.push(fileFence(join(stage, 'compose.images.json')));
      const pinned = JSON.parse(await d(stageArgs(['config', '--format', 'json']), { env: { ...options.env, SCAN_JWT_SECRET: CONFIG_SECRET } }));
      validatePublicLlmConfig(pinned, root, profile.cve, settings.selection, candidateImages); fence(); await verifyPeers();
    },
    async initialize(fresh) {
      phase = fresh ? 'initialize' : 'check'; safe(!fresh || priorSelection === null);
      await helper(fresh ? 'initialize' : 'check', fresh ? 'initialize' : 'check');
    },
    async startRetained() {
      if (!stoppedStand) return;
      phase = 'start-retained'; await verifyPeers(); await users(); await census();
      const c = peers.get('egress'), a = peerModels.get('egress'), image = priorImages.egress;
      cleanStopped(c);
      const rows = JSON.parse(await d(['image', 'inspect', image.Id]));
      safe(rows.length === 1 && rows[0].Id === image.Id && rows[0].Os === image.Os && equal(rows[0].Config, image.Config));
      validatePublicLlmImage(rows[0], 'egress');
      await d(['container', 'start', c.Id]);
      const current = await inspect(c.Id, 'egress', a.model, a.images, a.selection);
      safe(control(c) === control(current) && current.State.Running && current.State.Status === 'running' && current.State.ExitCode === 0 &&
        Number.isSafeInteger(current.State.Pid) && current.State.Pid > 0 && current.RestartCount === 0 &&
        !current.State.Paused && !current.State.OOMKilled && !current.State.Dead && !current.State.Restarting && !current.State.Error &&
        current.State.StartedAt !== c.State.StartedAt && Number.isFinite(Date.parse(current.State.StartedAt)));
      peers.set('egress', current); await verifyPeers(); await users(); await census();
    },
    async up(name) {
      phase = 'up-' + name; await verifyPeers(); await users(); healthy.delete(name);
      await d(stageArgs(['up', '-d', '--no-deps', '--no-build', '--pull', 'never', '--force-recreate', name]), { env: { ...options.env, SCAN_JWT_SECRET: jwt }, timeout: 120000 });
      const a = JSON.parse(await d(['container', 'inspect', `${PROJECT}-${name}-1`])); safe(a.length === 1);
      validatePublicLlmContainer(a[0], name, nextModel().services[name], candidateImages[name], nextModel(), { secret: jwt, images: candidateImages }, settings.selection);
      safe(a[0].State.Running && a[0].State.Status === 'running' && !a[0].State.Paused && !a[0].State.Restarting && !a[0].State.Dead && !a[0].State.OOMKilled && a[0].RestartCount === 0);
      if (peers.has(name)) safe(a[0].Id !== peers.get(name).Id);
      peers.set(name, a[0]); peerModels.set(name, { model: nextModel(), images: candidateImages, selection: settings.selection });
    },
    async ready(name) {
      phase = 'ready-' + name; const deadline = now() + 120000;
      do {
        await verifyPeers(); const prior = peers.get(name), a = peerModels.get(name), current = await inspect(prior.Id, name, a.model, a.images, a.selection);
        safe(control(prior) === control(current) && equal(epoch(prior), epoch(current)) && current.State.Running);
        if (name === 'worker' || name === 'api' && current.State.Health?.Status === 'healthy') {
          const reportProbe = profile.cve ? PUBLIC_READY_PROBE : "import {chainReady} from './src/scans/scan-readiness.ts';if(!await chainReady())throw Error('not-ready');console.log('{\"ready\":true}');";
          const code = (name === 'api' ? PUBLIC_LLM_GATEWAY_PROBE : '') + reportProbe;
          let origin = 'docker-dispatch';
          try {
            const text = await d(['container', 'exec', current.Id, 'node', ...['--import', 'tsx', '--input-type=module'], '-e', code], { timeout: publicLlmDockerTimeout(120000, deadline, now()) });
            origin = 'receipt-json'; const r = JSON.parse(text);
            if (r.ready === true && (!profile.cve || r.manifest === profile.cve.manifestDigest && r.bundle === profile.cve.artifactSha256)) { if (name === 'api') healthy.add(name); return; }
            readinessFailure = { category: 'readiness-receipt', origin: 'receipt-compare', frames: [] };
          } catch (error) { readinessFailure = finiteFailure(error, origin); safe(!continuation?.admissionOnly); }
          safe(!continuation?.admissionOnly); // One same-epoch admission attempt; never hide its finite cause.
        }
        if (name === 'web') {
          for (const path of ['/api/v1/auth/me', '/api/v1/browser/scans/00000000-0000-0000-0000-000000000000/llm/readiness',
            '/api/v1/browser/scans/00000000-0000-0000-0000-000000000000/llm/chat/context']) {
            const r = await request('http://127.0.0.1:8081' + path, { redirect: 'error', signal: AbortSignal.timeout(5000) });
            await r.body?.cancel(); safe(r.status === 401);
          }
          return;
        }
        safe(now() < deadline); await sleep(1000);
      } while (true);
    },
    async publish() {
      phase = 'publish'; await verifyPeers(); await users(); await census();
      // Same lock + private pending files: a crash is HOLD, not a mixed-profile retry.
      for (const [target, bytes] of [['compose.images.json', readBounded(join(stage, 'compose.images.json'), 16384, 0o600)],
        ['compose.llm-env.json', readBounded(join(stage, 'compose.llm-env.json'), 16384, 0o600)], ['llm-profile.json', JSON.stringify(settings.selection)]]) {
        const pending = join(root, STATE, '.llm-pending-' + target); safe(!has(pending)); writeExclusive(pending, bytes, 0o600);
        fs.renameSync(pending, join(root, STATE, target)); syncDirectory(join(root, STATE));
      }
      // Rebind only the intentionally published files; JWT/CVE/profile/source remain fenced.
      const replaced = ['compose.images.json', 'llm-profile.json', 'compose.llm-env.json'].map(p => join(root, STATE, p));
      const retained = fences.filter(f => !replaced.includes(f.path)); for (const f of retained) f.verify();
      fences.splice(0, fences.length, ...retained, ...replaced.map(path => fileFence(path)));
    },
    async complete() {
      phase = 'postflight-peers'; await verifyPeers(); await census(); await users();
      phase = 'postflight-namespace';
      const after = await inspectPublicLlmNamespace(d, options, root, profile.cve, settings.selection, { secret: jwt, images: candidateImages });
      phase = 'postflight-storage';
      safe(after.containers.length === 7 && after.networks.length === 6 && after.volumes.length === (settings.selection.keyVolume ? 3 : 2));
      for (const c of after.containers) {
        if (role(c).endsWith('volume-init')) cleanStopped(c);
        else safe(c.State.Running && c.State.Status === 'running' && !c.State.Paused && !c.State.Dead && !c.State.Restarting && !c.State.OOMKilled && c.RestartCount === 0);
      }
      safe(ownOne(after, 'api').State.Health?.Status === 'healthy');
      for (const v of before.volumes.filter(v => v.Name.startsWith(PROJECT + '_'))) safe(after.volumes.some(n => equal(n, v)));
      for (const n of before.networks) { const current = after.networks.find(x => x.Name === n.Name); safe(current && current.Id === n.Id && equal({ ...current, Containers: {} }, { ...n, Containers: {} })); }
      phase = 'postflight-receipt';
      if (records.has(recordName('build-checkpoint.json'))) writeExclusive(join(audit.path, continuation ? outputPrefix + '/build-checkpoint.json' : 'build-checkpoint.json'), readBounded(join(lock.path, recordName('build-checkpoint.json')), 16 * 1024 ** 2, 0o600), 0o600);
      if (continuation?.initialize) {
        // Preserve the ENTIRE original lock, stale stage, receipts and new intent;
        // never overwrite/unlink the failed continuation's evidence on success.
        fence(); const destination = join(audit.path, outputPrefix, 'operation-evidence');
        safe(!has(destination));
        writeExclusive(join(audit.path, 'complete.json'), JSON.stringify({ version: 1, project: PROJECT, preserved: true }), 0o600); syncDirectory(audit.path);
        fs.renameSync(lock.path, destination); archivedLock = directoryFence(destination);
        syncDirectory(dirname(destination)); syncDirectory(join(root, STATE));
        hold = false; return;
      }
      if (continuation) {
        const archive = join(audit.path, 'continued/original-operation'); fs.mkdirSync(archive, { mode: 0o700 });
        for (const f of [...continuation.originalFiles, ...continuation.candidateFiles]) { f.verify(); writeExclusive(join(archive, f.path.split('/').at(-1)), f.bytes, 0o600); }
        syncDirectory(archive);
      }
      fence(); writeExclusive(join(audit.path, 'complete.json'), JSON.stringify({ version: 1, project: PROJECT, preserved: true }), 0o600); syncDirectory(audit.path);
      for (const name of fs.readdirSync(stage)) { safe(['compose.cve.json', 'compose.llm-env.json', 'compose.images.json'].includes(name)); fs.unlinkSync(join(stage, name)); } fs.rmdirSync(stage);
      for (const name of records) fs.unlinkSync(join(lock.path, name));
      if (continuation) for (const f of continuation.originalFiles) { f.verify(); fs.unlinkSync(f.path); }
      syncDirectory(lock.path); hold = false;
    },
  };
  try {
    const result = await executePublicLlmMaintenance(ops, continuation?.baseline ?? null, continuation?.admissionOnly ? continuation : null);
    log(`Public LLM local deployment READY; key ${settings.selection.keyVolume ? 'supplied, generation unverified' : 'unavailable (operator setup required)'}; accounts/reports/JWT/history/quota preserved.`);
    return result;
  } catch (error) {
    if (continuation?.admissionOnly && records.has(recordName('continue.json'))) {
      try {
        record('failure.json', { version: 1, phase, ...finiteFailure(error, 'maintenance'), ...(readinessFailure ? { readiness: readinessFailure } : {}) });
      } catch { /* Preserve HOLD even when a failed source fence prevents diagnostics. */ }
    }
    if (typeof onDiagnostic === 'function') {
      // Only a finite internal reason, never an Error/stack/command/config value.
      const diagnostic = PUBLIC_LLM_PREFLIGHT_DIAGNOSTICS[phase];
      if (diagnostic) try { onDiagnostic(Object.freeze({ phase, reason: diagnostic })); } catch { /* Diagnostics cannot change refusal/lock handling. */ }
    }
    throw new Error(`PUBLIC LLM maintenance ${hold ? 'HOLD' : 'refused'}; phase=${phase}; details withheld. No automatic retry, cleanup, rollback or secret rotation.`);
  } finally { if (!hold) lock.release(); }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  publicLlmStand(process.argv.slice(2)).catch(error => {
    const safeMessage = /^PUBLIC LLM maintenance (?:HOLD|refused); phase=[a-z-]+; details withheld\. No automatic retry, cleanup, rollback or secret rotation\.$/.test(error?.message ?? '');
    if (error?.reason === 'REBUILD_PRIOR_BUILD_FAILURE_REJECTED') { console.error('PUBLIC LLM rebuild refused; phase=prior-build-failure; existing failure receipt preserved; no retry permitted.'); process.exitCode = 1; }
    else console.error(safeMessage ? error.message : 'PUBLIC LLM integration refused/HOLD; details withheld. Review the shared public operation lock; never delete uncertainty evidence automatically.'); process.exitCode = 1;
  });
}
