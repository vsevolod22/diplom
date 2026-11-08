#!/usr/bin/env node
// Import-safe public-only integration. No ambient dotenv, key reads or Docker at import.
import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import {
  PROJECT, LABEL, STATE, CONFIG_SECRET, expectedConfig, validateConfig, validateImage, validateContainer,
  inspectNamespace, acquireLock, loadSecret, readProfile, checkIgnores, assertReconciliationHistory,
  runIsolatedDocker, copyStableSqlite, sqliteTypedRow, recoverySqlite, backupArguments,
  validateBackupHelper, helperAuthorityProjection, RECOVERY_BACKUP, backupExportOperation,
  validateExportManifest, transferBackupSnapshot, isolatedDockerDiagnostic,
} from './public-image-stand.mjs';
import { dockerEnvironment } from './local-stand.mjs';
import { directory, readBounded, writeExclusive, syncDirectory } from './setup-local-cve.mjs';
import { PUBLIC_DRAIN_PROBE, PUBLIC_READY_PROBE } from './refresh-public-cve.mjs';
import { checkPublicLlmSourceBuild, checkOpenAiQuotaSnapshot, discoverOpenAiExecutionClosure } from './public-llm-source-build.mjs';
import { captureDeploymentCatalog, DEPLOYMENT_ACTIVE_LIMIT, DEPLOYMENT_TOTAL_LIMIT, DEPLOYMENT_RETAINED_REFERENCE_LIMIT,
  LEGACY_GATEWAY_STOP_ACK, LEGACY_GATEWAY_STOP_IDS, validateLegacyGatewayStopArchive,
  validatePublicStopDiagnostic, PUBLIC_STOP_DIAGNOSTIC_STEPS } from './public-llm-deployment-catalog.mjs';
export { LEGACY_GATEWAY_STOP_ACK, LEGACY_GATEWAY_STOP_IDS } from './public-llm-deployment-catalog.mjs';
import { readCurrentBackupExport, transferCurrentBackupSnapshot } from './public-current-backup-transfer.mjs';
import { OPENAI_DEPLOYMENT, validateOpenAiDeployment, validateOpenAiVolume,
  openAiEnvironment, assertNoOpenAiDockerSecret, validateOpenAiBuildDeployment, selectOpenAiOperations,
    PUBLIC_IMAGE_OPERATIONS, PUBLIC_IMAGE_OPERATIONS_ACK, PUBLIC_IMAGE_LOGGING,
    PUBLIC_IMAGE_OPERATION_ROLES, PUBLIC_IMAGE_EGRESS_COMMAND,
    MODULEAPI_SLOT_DEPLOYMENT, validateModuleApiDeployment, validateModuleApiBuildDeployment,
    moduleApiEnvironment, validateModuleApiVolume, assertNoModuleApiDockerSecret,
    discoverModuleApiExecutionClosure } from './public-llm-source-build.mjs';

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
// Historical v1 policy also pins the existing maintenance-helper protocol.
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
export const PUBLIC_LLM_TIMING = 'public-8081-90s-v1';
// Historical v2 identity is immutable: archived overlays/recovery still select Xing90.
export const PUBLIC_LLM_CURRENT_ENV = Object.freeze({ ...PUBLIC_LLM_ENV, LLM_TIMEOUT_MS: '90000' });
export const PUBLIC_LLM_NVIDIA_PROFILE = 'public-8081-nvidia-v1';
export const PUBLIC_LLM_NVIDIA_ENV = Object.freeze({ ...PUBLIC_LLM_CURRENT_ENV,
  LLM_MODEL: 'nvidia/nemotron-3.5-super-vl:free', LLM_PROVIDER_ALLOWLIST: 'nvidia',
  LLM_POLICY_REVISION: PUBLIC_LLM_NVIDIA_PROFILE, LLM_RETENTION: 'no-training',
});
// Historical v3 remains NVIDIA90 even though reported training=true conflicts with
// API data_collection=deny. Explicit v4 replacement is non-ZDR: prompts retained.
export const PUBLIC_LLM_DOTS_PROFILE = 'public-8081-dots-v1';
export const PUBLIC_LLM_DOTS_ENV = Object.freeze({ ...PUBLIC_LLM_NVIDIA_ENV,
  LLM_MODEL: 'dots-studio/dots-3-note-preview:free', LLM_PROVIDER_ALLOWLIST: 'atlas-cloud/fp8',
  LLM_POLICY_REVISION: PUBLIC_LLM_DOTS_PROFILE,
});
// Historical v4 stays Dots2048; v5 changes only the full-report output cap/revision.
export const PUBLIC_LLM_REPORT4K_PROFILE = 'public-8081-remediation-4k-v1';
export const PUBLIC_LLM_REPORT4K_ENV = Object.freeze({ ...PUBLIC_LLM_DOTS_ENV,
  LLM_OUTPUT_TOKENS: '4096', LLM_POLICY_REVISION: PUBLIC_LLM_REPORT4K_PROFILE,
});
export function publicLlmSelectedEnvironment(selection) {
  if (selection?.version === 7) return moduleApiEnvironment(selection, publicLlmSelectedEnvironment(selection.openrouter));
  if (selection?.version === 6) return openAiEnvironment(selection, publicLlmSelectedEnvironment(selection.openrouter));
  switch (validateLlmSelection(selection).version) {
    case 1: return PUBLIC_LLM_ENV;
    case 2: return PUBLIC_LLM_CURRENT_ENV;
    case 3: return PUBLIC_LLM_NVIDIA_ENV;
    case 4: return PUBLIC_LLM_DOTS_ENV;
    case 5: return PUBLIC_LLM_REPORT4K_ENV;
  }
}
function publicLlmGatewayCommand(selection) {
  return ['python', '-I', 'openrouter.py', ...(validateLlmSelection(selection).version >= 2 ? ['--public-90s'] : [])];
}
export function validatePublicLlmTransition(prior, next) {
  validateLlmSelection(next);
  if (next.version === 7) { validateModuleApiBuildDeployment({ prior, next }); return; }
  safe(prior?.version !== 7); // No implicit provider rollback, including a v7 -> v6 downgrade.
  if (next.version === 6) {
    safe(prior !== null && prior !== undefined); validateLlmSelection(prior);
    safe(equal(next.openrouter, prior.version === 6 ? prior.openrouter : prior));
    safe(prior.version !== 6 || !prior.credentialVolume || prior.credentialVolume === next.credentialVolume);
    safe(!prior.operations || prior.operations === next.operations);
    safe(!next.operations || prior.version === 6);
    return;
  }
  safe(prior?.version !== 6);
  if (!prior) return;
  validateLlmSelection(prior);
  // Preserve the existing one-time key activation; never rotate/remove a supplied volume.
  safe(!prior.keyVolume || prior.keyVolume === next.keyVolume);
  safe(next.version >= prior.version); // Never downgrade timing or policy.
  safe(prior.version === next.version || prior.keyVolume === next.keyVolume); // No combined policy/key activation.
}
// Separate authority for the current normal-build timeout HOLD; historical
// continuations are not a general policy-upgrade path.
export function validatePublicLlmExistingBuildSelection(audit, prior, next) {
  validatePublicLlmTransition(prior, next);
  safe(prior?.keyVolume && prior.keyVolume === next.keyVolume);
  if (audit === 'deploy-76eb7a61e0da2e108210bc773b964d35') safe(prior.version === 5 && equal(prior, next));
  else if (audit === 'deploy-1cb54172f8cd83708f64067371069fa5') safe(prior.version === 3 && next.version === 4);
  else safe(audit === 'deploy-2c9ed08b8269264b09bf14eb6189a649' && equal(prior, next));
  return true;
}
export function parsePublicLlmConfig(text) {
  safe(typeof text === 'string' && text.length <= 16384 && /^[\x09\x0a\x0d\x20-\x7e]*$/.test(text));
  const values = {};
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith('#')) continue;
    const match = /^([A-Z][A-Z0-9_]*)=([^\s"'`$\\]*)$/.exec(line);
    safe(match && !Object.hasOwn(values, match[1])); values[match[1]] = match[2];
  }
  const environment = [PUBLIC_LLM_ENV, PUBLIC_LLM_CURRENT_ENV, PUBLIC_LLM_NVIDIA_ENV, PUBLIC_LLM_DOTS_ENV, PUBLIC_LLM_REPORT4K_ENV].find(env => equal(values, env));
  safe(environment);
  return environment;
}
export function validateLlmSelection(value) {
  if (Object.getOwnPropertyDescriptor(value ?? {}, 'version')?.value === 7) return validateModuleApiDeployment(value);
  if (Object.getOwnPropertyDescriptor(value ?? {}, 'version')?.value === 6) return validateOpenAiDeployment(value);
  safe(value && (value.version === 1 && equal(Object.keys(value).sort(), ['keyVolume', 'version']) ||
    value.version === 2 && equal(Object.keys(value).sort(), ['keyVolume', 'timing', 'version']) && value.timing === PUBLIC_LLM_TIMING ||
    value.version === 3 && equal(Object.keys(value).sort(), ['keyVolume', 'profile', 'timing', 'version']) &&
      value.timing === PUBLIC_LLM_TIMING && value.profile === PUBLIC_LLM_NVIDIA_PROFILE ||
    value.version === 4 && equal(Object.keys(value).sort(), ['keyVolume', 'profile', 'timing', 'version']) &&
      value.timing === PUBLIC_LLM_TIMING && value.profile === PUBLIC_LLM_DOTS_PROFILE ||
    value.version === 5 && equal(Object.keys(value).sort(), ['keyVolume', 'profile', 'timing', 'version']) &&
      value.timing === PUBLIC_LLM_TIMING && value.profile === PUBLIC_LLM_REPORT4K_PROFILE) &&
    (value.keyVolume === null || typeof value.keyVolume === 'string' && /^diplom-public-8081-llm-key-[a-f0-9]{32}$/.test(value.keyVolume)));
  return Object.freeze({ version: value.version, keyVolume: value.keyVolume, ...(value.version >= 2 ? { timing: PUBLIC_LLM_TIMING } : {}),
    ...(value.version >= 3 ? { profile: value.version === 3 ? PUBLIC_LLM_NVIDIA_PROFILE : value.version === 4 ? PUBLIC_LLM_DOTS_PROFILE : PUBLIC_LLM_REPORT4K_PROFILE } : {}) });
}
export function loadPublicLlmSettings(home = homedir(), { openai = false, moduleapi = false } = {}) {
  safe(typeof openai === 'boolean' && typeof moduleapi === 'boolean' && !(openai && moduleapi));
  const path = join(home, '.local/state/diplom-public-images/llm');
  // No symlinked ancestor may redirect this approved public-only state path.
  const ancestors = []; let current = '/';
  for (const part of resolve(path).split('/').filter(Boolean)) {
    current = join(current, part); const stamp = fs.lstatSync(current);
    safe(stamp.isDirectory() && !stamp.isSymbolicLink()); ancestors.push({ path: current, stamp });
  }
  directory(path, 0o700);
  const config = fileFence(join(path, 'llm.env'), 16384, 0o600);
  const environment = parsePublicLlmConfig(config.bytes);
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
  let selection = validateLlmSelection({ version: environment === PUBLIC_LLM_ENV ? 1 : environment === PUBLIC_LLM_CURRENT_ENV ? 2 : environment === PUBLIC_LLM_NVIDIA_ENV ? 3 : environment === PUBLIC_LLM_DOTS_ENV ? 4 : 5, keyVolume,
    ...(environment !== PUBLIC_LLM_ENV ? { timing: PUBLIC_LLM_TIMING } : {}),
    ...(environment === PUBLIC_LLM_NVIDIA_ENV ? { profile: PUBLIC_LLM_NVIDIA_PROFILE } : environment === PUBLIC_LLM_DOTS_ENV ? { profile: PUBLIC_LLM_DOTS_PROFILE } : environment === PUBLIC_LLM_REPORT4K_ENV ? { profile: PUBLIC_LLM_REPORT4K_PROFILE } : {}) });
  const fences = [config, ...(receipt ? [receipt] : [])];

  if (openai || moduleapi) {
    const descriptor = fileFence(join(path, OPENAI_DEPLOYMENT.configName), 16384, 0o600);
    const next = validateOpenAiDeployment(privateJson(descriptor.bytes)); safe(equal(next.openrouter, selection));
    fences.push(descriptor); selection = next;
  }
  const moduleApiPath = join(path, MODULEAPI_SLOT_DEPLOYMENT.configName);
  const moduleApiPresent = moduleapi && has(moduleApiPath);
  if (moduleApiPresent) {
    const descriptor = fileFence(moduleApiPath, 16384, 0o600);
    const next = validateModuleApiDeployment(privateJson(descriptor.bytes));
    // An approved operations-only publication does not rewrite the protected
    // v6 descriptor. Reconcile ONLY that optional field, then compare everything
    // else exactly. The adapter separately checks the actual published transition.
    const protectedPrior = selectOpenAiOperations(selection, next.openai);
    validateModuleApiBuildDeployment({ prior: protectedPrior, next });
    fences.push(descriptor); selection = next;
  }
  const verify = () => {
    for (const a of ancestors) { const s = fs.lstatSync(a.path); safe(s.isDirectory() && !s.isSymbolicLink() && s.dev === a.stamp.dev && s.ino === a.stamp.ino && s.mode === a.stamp.mode && s.uid === a.stamp.uid); }
    directory(path, 0o700); for (const f of fences) f.verify(); safe(has(receiptPath) === Boolean(receipt));
    if (moduleapi) safe(has(moduleApiPath) === moduleApiPresent);

  };
  verify(); return { selection, verify };
}
export function readPublicLlmBinding(root) {
  const state = join(root, STATE), path = join(state, 'llm-profile.json');
  if (!has(state)) return null;
  directory(state, 0o700);
  safe(!fs.readdirSync(state).some(n => n.startsWith('.llm-pending-')));
  if (!has(path)) { safe(!has(join(root, STATE, 'compose.llm-env.json'))); return null; }
  const text = readBounded(path, 16384, 0o600), value = validateLlmSelection(privateJson(text));
  safe(value.version === 7 || Buffer.byteLength(text) <= 4096);
  safe(text === JSON.stringify(value) && equal(privateJson(readBounded(join(state, 'compose.llm-env.json'), 16384, 0o600)), publicLlmEnvironmentOverlay(value)));
  return value;
}
export function publicLlmEnvironmentOverlay(selection) {
  if (selection?.version === 7) return moduleApiEnvironmentOverlay(selection);
  if (selection?.version === 6) return openAiEnvironmentOverlay(selection);
  const environment = publicLlmSelectedEnvironment(selection);
  return { services: { api: { environment: { ...environment }, ...(selection.keyVolume ? { volumes: [
    { type: 'volume', source: 'public_llm_key', target: '/run/secrets', read_only: true, volume: { nocopy: true } },
  ] } : {}) }, ...(selection.version >= 2 ? { 'llm-egress': { command: publicLlmGatewayCommand(selection) } } : {}) },
    ...(selection.keyVolume ? { volumes: { public_llm_key: { name: selection.keyVolume, external: true } } } : {}) };
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
  if (selection?.version === 7) return expectedModuleApiConfig(root, cve, selection);
  if (selection?.version === 6) return expectedOpenAiConfig(root, cve, selection);
  const model = expectedConfig(root, cve);
  if (!selection) return model;
  const overlay = publicLlmStaticOverlay(root), env = publicLlmEnvironmentOverlay(selection);
  model.services.web.build.dockerfile = overlay.services.web.build.dockerfile;
  model.services.api.environment = { ...model.services.api.environment, ...env.services.api.environment };
  Object.assign(model.services.api.networks, overlay.services.api.networks);
  Object.assign(model.services.api.depends_on, overlay.services.api.depends_on);
  model.services['llm-egress'] = { ...overlay.services['llm-egress'], ...env.services['llm-egress'] }; Object.assign(model.networks, overlay.networks);
  if (selection.keyVolume) { model.services.api.volumes.push(...env.services.api.volumes); Object.assign(model.volumes, env.volumes); }
  return model;
}
// Fixed order is shared by maintenance, future main and BOTH current/prospective CVE models.
export function publicLlmComposeArguments(root, args, { cve = false, llm = true, pinned = true, prospectiveCve = false, directory: dir = join(root, STATE) } = {}) {
  safe(resolve(dir) === dir && [join(root, STATE), join(root, STATE, '.operation.lock/llm-candidate'), join(root, STATE, '.operation.lock/llm-initialize-candidate'), join(root, STATE, '.operation.lock/llm-rebuild-candidate'), join(root, STATE, '.operation.lock/init-exit-current'), join(root, STATE, '.operation.lock/admit-current'), join(root, STATE, '.operation.lock/api-current'), join(root, STATE, '.operation.lock/rollout-current'), join(root, STATE, '.operation.lock/existing-build-current'), join(root, STATE, '.operation.lock/summary-current')].includes(dir));
  safe(!prospectiveCve || cve && dir === join(root, STATE));
  return ['compose', '--env-file', '/dev/null', '-p', PROJECT, '-f', join(root, 'server/deploy/compose.public-images.yaml'),
    ...(cve ? ['-f', prospectiveCve ? join(root, STATE, '.operation.lock/candidate.cve.json') : join(dir, 'compose.cve.json')] : []),
    ...(llm ? ['-f', join(root, 'server/deploy/compose.public-llm.yaml'), '-f', join(dir, 'compose.llm-env.json')] : []),
    ...(pinned ? ['-f', join(dir, 'compose.images.json')] : []), ...args];
}
export function validatePublicLlmImage(image, name, selection = null) {
  if (selection?.version === 7) {
    validateModuleApiDeployment(selection); assertNoModuleApiDockerSecret(image?.Config);
    if (name === 'openai-egress') {
      safe(equal(image?.Config?.Cmd, MODULEAPI_SLOT_DEPLOYMENT.gatewayCommand));
      const copy = structuredClone(image); copy.Config.Cmd = ['python', '-I', 'proxy.py'];
      return validateImage(copy, 'egress');
    }
  }
  if (name === 'openai-egress') {
    assertNoOpenAiDockerSecret(image?.Config); safe(equal(image?.Config?.Cmd, OPENAI_DEPLOYMENT.gatewayCommand));
    const copy = structuredClone(image); copy.Config.Cmd = ['python', '-I', 'proxy.py']; return validateImage(copy, 'egress');
  }
  if (name !== 'llm-egress') return validateImage(image, name);
  safe(equal(image?.Config?.Cmd, ['python', '-I', 'openrouter.py']));
  const copy = structuredClone(image); copy.Config.Cmd = ['python', '-I', 'proxy.py']; return validateImage(copy, 'egress');
}
// Call only AFTER the caller verifies the sealed retained image ID/tag/custody.
// A v7 transition can retain BOTH the replaced OpenAI image and ModuleAPI slot
// images. Keep normal role validation exact; choose only a declared authority.
export function validatePublicLlmRetainedImage(image, name, selection = null) {
  if (selection?.version === 7) {
    const s = validateModuleApiDeployment(selection);
    if (name === 'openai-egress' && equal(image?.Config?.Cmd, OPENAI_DEPLOYMENT.gatewayCommand))
      return validatePublicLlmImage(image, name, s.openai);
    return validatePublicLlmImage(image, name, s);
  }
  return validatePublicLlmImage(image, name, selection);
}
export function validatePublicLlmConfig(value, root, cve = null, selection = null, images = null) {
  if (selection?.version === 7) return validateModuleApiConfig(value, root, cve, selection, images);
  if (selection?.version === 6) return validateOpenAiConfig(value, root, cve, selection, images);
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
  safe(equal(Object.fromEntries(Object.entries(api.environment ?? {}).filter(([k]) => llmVariable(k))), publicLlmSelectedEnvironment(selection)));
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
  if (selection?.version === 7) {
    const p = stripModuleApiContainer(item, name, spec, image, selection);
    return projectPublicLlmContainer(p.item, p.name, p.spec, p.image, config, selection.openrouter);
  }
  if (selection?.version === 6) {
    const p = stripOpenAiContainer(item, name, spec, image, selection);
    return projectPublicLlmContainer(p.item, p.name, p.spec, p.image, config, selection.openrouter);
  }
  if (!selection) return { item, name, spec, image, config };
  const c = structuredClone(item), im = structuredClone(image), s = structuredClone(spec);
  if (name === 'api') {
    const env = envMap(c.Config.Env);
    safe(equal(Object.fromEntries(Object.entries(env).filter(([k]) => llmVariable(k))), publicLlmSelectedEnvironment(selection)));
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
    const command = publicLlmGatewayCommand(selection);
    safe(equal(c.Config.Cmd, command) && equal(s.command, command)); validatePublicLlmImage(im, name);
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
  validatePublicLlmImage(image, name, selection);
  const p = projectPublicLlmContainer(item, name, spec, image, config, selection);
  const images = extra.images && { ...extra.images, ...(['llm-egress', 'openai-egress'].includes(name) ? { egress: p.image } : {}) };
  validateContainer(p.item, p.name, p.spec, p.image, p.config, { ...extra, images });
}
export function validatePublicLlmKeyVolume(v, selection) {
  safe(v.Name === selection.keyVolume && v.Driver === 'local' && v.Scope === 'local' &&
    typeof v.Mountpoint === 'string' && v.Mountpoint.startsWith('/') && !/[\x00-\x1f\x7f]/.test(v.Mountpoint) &&
    equal(v.Options ?? {}, {}) && equal(v.Labels, { 'diplom.public-llm': 'key-v1' }));
}
export async function inspectPublicLlmNamespace(run, options, root, cve = null, selection = null, extra = {}) {
  if (selection?.version === 7) return inspectModuleApiNamespace(run, options, root, cve, selection, extra);
  if (selection?.version === 6) return inspectOpenAiNamespace(run, options, root, cve, selection, extra);
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

// Current normal builds retain named references before overwriting :local.
// Historical namespace/recovery readers above remain strict and unchanged.
export const PUBLIC_LLM_RETENTION_ROLES = Object.freeze(['api', 'worker', 'web', 'llm-egress']);
const retentionRoles = value => {
  if (value.version !== 2) return PUBLIC_LLM_RETENTION_ROLES;
  const deployment = validateOpenAiBuildDeployment(value.deployment);
  return [...PUBLIC_LLM_RETENTION_ROLES, ...(deployment.prior.version === 6 ? ['openai-egress'] : []),
    ...(deployment.next.operations ? ['egress'] : [])];
};
export function publicLlmRetentionTag(audit, name) {
  safe(/^deploy-[a-f0-9]{32}$/.test(audit) && [...PUBLIC_LLM_RETENTION_ROLES, 'openai-egress', 'egress'].includes(name));
  return `${PROJECT}-${name}:retained-${audit.slice(7)}`;
}
export function validatePublicLlmRetentionReceipt(value, audit) {
  safe(equal(Object.keys(value ?? {}).sort(), ['audit', 'checkpointSha256', ...(value?.version === 2 ? ['deployment'] : []), 'images', 'project', 'version']) &&
    [1, 2].includes(value.version) && value.project === PROJECT && value.audit === audit && /^[a-f0-9]{64}$/.test(value.checkpointSha256));
  const roles = retentionRoles(value);
  safe(equal(Object.keys(value.images ?? {}).sort(), [...roles].sort()));
  for (const name of roles) {
    const row = value.images[name];
    safe(equal(Object.keys(row ?? {}).sort(), ['image', 'tag']) && row.tag === publicLlmRetentionTag(audit, name) &&
      equal(Object.keys(row.image ?? {}).sort(), ['Config', 'Id', 'Os']));
    validatePublicLlmImage(row.image, name);
  }
  return value;
}
async function verifyPublicLlmRetentionImages(receipt, run, options, verify) {
  for (const name of retentionRoles(receipt)) {
    const row = receipt.images[name];
    // Both the immutable ID and its retained name must remain available. Neither
    // a tag nor persisted Config can substitute for a missing execution image.
    for (const reference of [row.image.Id, row.tag]) {
      verify(); const values = JSON.parse(await run(['image', 'inspect', reference], options));
      safe(values.length === 1 && equal({ Id: values[0].Id, Os: values[0].Os, Config: values[0].Config }, row.image) &&
        Array.isArray(values[0].RepoTags) && values[0].RepoTags.includes(row.tag));
      validatePublicLlmImage(values[0], name); verify();
    }
  }
}
// A bounded, receipt-backed read policy, not a wildcard allowance for own tags.
// Only the active normal-up caller may admit its unfinished audit; all other
// readers require completed deployments and the original build checkpoint.
export function capturePublicLlmRetentions(root, activeAudit = null) {
  safe(activeAudit === null || /^deploy-[a-f0-9]{32}$/.test(activeAudit));
  const catalog = captureDeploymentCatalog(root), proofs = [], dirs = [], receipts = [];
  safe(activeAudit === null || catalog.active.includes(activeAudit));
  for (const { name: audit, path: dir } of catalog.entries) {
    const intentPath = join(dir, 'image-retention-intent.json'), receiptPath = join(dir, 'image-retention.json');
    dirs.push(directoryFence(dir));
    safe(has(intentPath) === has(receiptPath));
    if (!has(receiptPath)) continue;
    const receipt = fileFence(receiptPath, 262144, 0o600), intent = fileFence(intentPath, 262144, 0o600);
    safe(intent.bytes === receipt.bytes);
    const value = validatePublicLlmRetentionReceipt(privateJson(receipt.bytes), audit);
    const checkpoint = fileFence(audit === activeAudit ? join(root, STATE, '.operation.lock/build-checkpoint.json') : join(dir, 'build-checkpoint.json'), 16 * 1024 ** 2, 0o600);
    safe(hash(checkpoint.bytes) === value.checkpointSha256);
    const build = privateJson(checkpoint.bytes);
    safe(build.version === value.version && build.phase === 'validated-before-build' && build.sourceBasis === 'validated-before-build');
    if (build.version === 2) safe(equal(validateOpenAiBuildDeployment(build.deployment), value.deployment));
    for (const name of retentionRoles(value)) safe(equal(build.imageMetadata?.[name], value.images[name].image) && build.pins?.services?.[name]?.image === value.images[name].image.Id);
    if (audit !== activeAudit) {
      const complete = fileFence(join(dir, 'complete.json'), 4096, 0o600);
      safe(equal(privateJson(complete.bytes), { version: 1, project: PROJECT, preserved: true })); proofs.push(complete);
    }
    proofs.push(receipt, intent, checkpoint); receipts.push(value);
  }
  const tags = receipts.flatMap(r => retentionRoles(r).map(n => r.images[n].tag));
  safe(tags.length <= DEPLOYMENT_RETAINED_REFERENCE_LIMIT && new Set(tags).size === tags.length);
  const verify = () => {
    catalog.verify();
    dirs.forEach(v => v()); proofs.forEach(f => f.verify());
    // Active and archived references share the same exact receipt policy/budget.
    for (const { name: audit, path: dir } of catalog.entries) for (const file of ['image-retention-intent.json', 'image-retention.json'])
      safe(has(join(dir, file)) === receipts.some(r => r.audit === audit));
  };
  verify(); return { receipts, tags, verify };
}
export async function inspectCurrentPublicLlmNamespace(run, options, root, cve = null, selection = null, extra = {}, activeAudit = null) {
  if (!selection) return inspectPublicLlmNamespace(run, options, root, cve, selection, extra);
  const retained = capturePublicLlmRetentions(root, activeAudit); let checked = false;
  const wrapped = async (args, opts) => {
    retained.verify(); const text = await run(args, opts); retained.verify();
    if (args[0] !== 'image' || args[1] !== 'ls') return text;
    safe(Buffer.byteLength(text) <= 1024 ** 2);
    const lines = text.split('\n').filter(Boolean), present = new Set(lines);
    safe(retained.tags.every(tag => present.has(tag)));
    for (const receipt of retained.receipts) await verifyPublicLlmRetentionImages(receipt, run, opts, retained.verify);
    checked = true;
    // Unknown or receipt-less names survive this projection and are rejected by
    // the original namespace validator. Only fully verified references leave it.
    return lines.filter(tag => !retained.tags.includes(tag)).join('\n');
  };
  const inventory = await inspectPublicLlmNamespace(wrapped, options, root, cve, selection, extra);
  safe(checked); retained.verify(); inventory.images.push(...retained.tags); return inventory;
}
export async function retainPublicLlmBuildImages({ root, audit, images, run, options, verify }) {
  safe(resolve(root) === root && /^deploy-[a-f0-9]{32}$/.test(audit) && typeof verify === 'function');
  const path = join(root, STATE, 'llm-deployments', audit), auditVerify = directoryFence(path);
  const checkpoint = fileFence(join(root, STATE, '.operation.lock/build-checkpoint.json'), 16 * 1024 ** 2, 0o600);
  const build = privateJson(checkpoint.bytes);
  safe([1, 2].includes(build.version) && build.phase === 'validated-before-build' && build.sourceBasis === 'validated-before-build');
  const receipt = { version: build.version, project: PROJECT, audit, checkpointSha256: hash(checkpoint.bytes), images: {},
    ...(build.version === 2 ? { deployment: validateOpenAiBuildDeployment(build.deployment) } : {}) };
  const roles = retentionRoles(receipt);
  for (const name of roles) {
    const image = images[name]; validatePublicLlmImage(image, name);
    const metadata = { Id: image.Id, Os: image.Os, Config: structuredClone(image.Config) };
    safe(equal(metadata, build.imageMetadata?.[name]) && build.pins?.services?.[name]?.image === image.Id);
    receipt.images[name] = { tag: publicLlmRetentionTag(audit, name), image: metadata };
  }
  validatePublicLlmRetentionReceipt(receipt, audit);
  const intentPath = join(path, 'image-retention-intent.json'), receiptPath = join(path, 'image-retention.json');
  const fence = () => { verify(); auditVerify(); checkpoint.verify(); };
  const absent = async tag => {
    fence(); const text = await run(['image', 'ls', '--filter', `reference=${tag}`, '--format', '{{.Repository}}:{{.Tag}}'], options);
    safe(text.trim() === ''); fence(); // Errors are not absence, even for the same ID.
  };
  fence(); safe(!has(intentPath) && !has(receiptPath));
  for (const name of roles) await absent(receipt.images[name].tag);
  const bytes = JSON.stringify(receipt); safe(Buffer.byteLength(bytes) <= 262144);
  writeExclusive(intentPath, bytes, 0o600); syncDirectory(path);
  const intent = fileFence(intentPath, 262144, 0o600);
  for (const name of roles) {
    const row = receipt.images[name]; fence(); intent.verify();
    const values = JSON.parse(await run(['image', 'inspect', row.image.Id], options));
    safe(values.length === 1 && equal({ Id: values[0].Id, Os: values[0].Os, Config: values[0].Config }, row.image));
    validatePublicLlmImage(values[0], name);
    await absent(row.tag); intent.verify();
    await run(['image', 'tag', row.image.Id, row.tag], options); // Never remove/overwrite a known reference.
    fence(); intent.verify();
    const tagged = JSON.parse(await run(['image', 'inspect', row.tag], options));
    safe(tagged.length === 1 && equal({ Id: tagged[0].Id, Os: tagged[0].Os, Config: tagged[0].Config }, row.image) && tagged[0].RepoTags?.includes(row.tag));
    validatePublicLlmImage(tagged[0], name);
  }
  await verifyPublicLlmRetentionImages(receipt, run, options, () => { fence(); intent.verify(); });
  writeExclusive(receiptPath, bytes, 0o600); syncDirectory(path);
  const proof = fileFence(receiptPath, 262144, 0o600);
  const verifyFiles = () => { auditVerify(); checkpoint.verify(); intent.verify(); proof.verify(); };
  verifyFiles();
  return { receipt, verify: verifyFiles, verifyImages: (query, opts) => verifyPublicLlmRetentionImages(receipt, query, opts, verifyFiles) };
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
// Capture before any asynchronous qualification. Existing readers retain their
// validation rules, but may not silently rebase operational values onto new bytes.
// JWT bytes remain private: this proof has no serializable content or digest.
export function captureOpenAiPreflightState(root) {
  const state = join(root, STATE), proofs = [], absent = [];
  for (const name of ['profile.json', 'scan-jwt', 'compose.images.json', 'compose.cve.json', 'llm-profile.json', 'compose.llm-env.json']) {
    const path = join(state, name);
    if (has(path)) proofs.push(fileFence(path, name === 'scan-jwt' ? 96 : 16384, 0o600));
    else { safe(!['profile.json', 'scan-jwt', 'compose.images.json', 'llm-profile.json', 'compose.llm-env.json'].includes(name)); absent.push(path); }
  }
  const verify = () => { for (const p of proofs) p.verify(); for (const p of absent) safe(!has(p)); };
  verify();
  const profile = readProfile(root), priorSelection = readPublicLlmBinding(root);
  const jwt = proofs.find(p => p.path === join(state, 'scan-jwt')).bytes;
  safe(profile !== undefined && priorSelection !== null && /^[a-f0-9]{96}$/.test(jwt));
  safe(JSON.stringify(priorSelection) === proofs.find(p => p.path === join(state, 'llm-profile.json')).bytes);
  verify();
  return { profile, priorSelection, jwt, verify,
    // Per-path proofs preserve the existing publication rebind: only the three
    // intentionally replaced nonsecret files may advance; JWT/profile never do.
    fences: [...proofs.map(p => ({ path: p.path, verify: p.verify })),
      ...absent.map(path => ({ path, verify() { safe(!has(path)); } }))] };
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
  safe(new RegExp(`^${PROJECT}-llm-[a-f0-9]{32}-(?:(?:continued|initialize-current|rebuild-current|init-exit-current|admit-current|api-current|rollout-current|existing-build-current)-)?(?:fenced|before-api|after-api|initialize|check)$`).test(name) && imageId(image) && ['backup', 'initialize', 'check'].includes(purpose));
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

// Current schema support is deliberately separate from llmFingerprint/nativeSource:
// those exported function/program bytes are part of historical exact recovery identity.
export const PUBLIC_LLM_SUMMARY_MIGRATION_ACK = '--ack-history-summary-v3-to-v4';
export function currentHistorySchema(db) {
  const version = String(db.pragma('user_version', { simple: true }));
  safe(String(db.pragma('application_id', { simple: true })) === '1145655602' && ['3', '4'].includes(version));
  const objects = db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE tbl_name='llm_summary' OR name IN ('llm_summary','sqlite_autoindex_llm_summary_1') ORDER BY type,name,tbl_name,sql").raw().all();
  const sql = 'CREATE TABLE llm_summary(\n  scope TEXT PRIMARY KEY CHECK(length(scope)=64),\n  content TEXT NOT NULL CHECK(length(CAST(content AS BLOB))<=69632),\n  content_hash TEXT NOT NULL CHECK(length(content_hash)=64)) STRICT';
  safe(equal(objects, version === '3' ? [] : [
    ['index', 'sqlite_autoindex_llm_summary_1', 'llm_summary', null],
    ['table', 'llm_summary', 'llm_summary', sql],
  ]));
  if (version === '4') {
    const totals = db.prepare('SELECT count(*) n,coalesce(sum(length(CAST(content AS BLOB))),0) bytes,coalesce(max(length(CAST(content AS BLOB))),0) largest FROM llm_summary').get();
    safe(BigInt(totals.n) <= 64n && BigInt(totals.bytes) <= 2097152n && BigInt(totals.largest) <= 69632n);
  }
  return Number(version);
}
function currentLlmFingerprint(DB, io, crypto, path, kind, empty = false) {
  safe(['history', 'quota', 'auth', 'ledger'].includes(kind));
  const db = new DB(path, { readonly: true, fileMustExist: true, timeout: 2000 });
  try {
    db.defaultSafeIntegers(true); db.pragma('query_only=ON'); db.exec('BEGIN');
    safe(db.pragma('integrity_check', { simple: true }) === 'ok' && db.pragma('foreign_key_check').length === 0);
    const versions = [db.pragma('application_id', { simple: true }), db.pragma('user_version', { simple: true })];
    if (kind === 'auth' || kind === 'ledger') safe(String(versions[1]) === (kind === 'auth' ? '0' : '15'));
    else if (kind === 'history') currentHistorySchema(db);
    else safe(equal(versions.map(String), ['1145655601', '1']));
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
      if (empty) {
        safe(db.prepare('SELECT count(*) n FROM history_head').get().n === 0n && db.prepare('SELECT count(*) n FROM history_completion_space').get().n === 0n);
        if (String(versions[1]) === '4') safe(db.prepare('SELECT count(*) n FROM llm_summary').get().n === 0n);
      }
    } else if (empty) safe(db.prepare('SELECT count(*) n FROM quota_attempt').get().n === 0n && db.prepare('SELECT clock FROM quota_meta WHERE id=1').get().clock === 0n);
    db.exec('ROLLBACK'); return h.digest('hex');
  } finally { db.close(); }
}
// Host/offline callers have a current counterpart too; the historical export
// remains v3-only because exact recovery embeds backupLlmSqlite.toString().
export async function currentBackupLlmSqlite(DB, io, crypto, paths, output) {
  const exists = p => io.lstatSync(p, { throwIfNoEntry: false }) !== undefined;
  const pair = ['auth', 'ledger'].map(r => exists(paths[r])); safe(pair[0] === pair[1]);
  if (!pair[0]) { for (const p of Object.values(paths)) for (const suffix of ['-journal', '-wal', '-shm']) safe(!exists(p + suffix)); return null; }
  const result = {};
  for (const [role, kind] of [['auth', 'history'], ['ledger', 'quota']]) {
    const s = io.lstatSync(paths[role]); safe(s.uid === process.getuid() && (s.mode & 0o7777) === 0o600 && s.size <= (kind === 'history' ? 8 : 64) * 1024 ** 2);
    const copy = copyStableSqlite(io, crypto, paths[role], output + '/source-' + role);
    let db;
    try {
      db = new DB(copy.path, { fileMustExist: true }); db.pragma('query_only=ON'); db.pragma('integrity_check');
      const before = currentLlmFingerprint(DB, io, crypto, copy.path, kind);
      const target = output + '/' + role + '.sqlite'; safe(!exists(target)); await db.backup(target); io.chmodSync(target, 0o600);
      safe(currentLlmFingerprint(DB, io, crypto, target, kind) === before); copy.verify();
      const fd = io.openSync(target, io.constants.O_RDONLY | io.constants.O_NOFOLLOW), h = crypto.createHash('sha256'), b = Buffer.alloc(65536);
      try { let n; while ((n = io.readSync(fd, b, 0, b.length, null))) h.update(b.subarray(0, n)); io.fsyncSync(fd); } finally { io.closeSync(fd); }
      result[role] = { logicalSha256: before, sha256: h.digest('hex'), bytes: io.statSync(target).size, integrity: 'ok' };
    } finally { db?.close(); copy.verify(); copy.cleanup(); }
  }
  return result;
}
const currentNativeSource = nativeSource.replace('const llmFingerprint=' + llmFingerprint.toString(),
  'const currentHistorySchema=' + currentHistorySchema.toString() + ';const llmFingerprint=' + currentLlmFingerprint.toString())
    .replace('const backupLlmSqlite=' + backupLlmSqlite.toString(), 'const currentLlmFingerprint=llmFingerprint;const backupLlmSqlite=' + currentBackupLlmSqlite.toString());
export const PUBLIC_LLM_CURRENT_BACKUP_PROGRAM = PUBLIC_LLM_BACKUP_PROGRAM.replace(nativeSource, currentNativeSource);

// Host-side sealed exports must never be opened by SQLite directly. A native
// backup can retain WAL header [2,2]; even a readonly open then creates -wal/-shm.
// Keep native/historical helper programs unchanged. Only disposable copies may
// acquire SQLite sidecars, and the original is checked as a sealed byte source.
export function sealedSnapshotDatabase(DB) { return privateSnapshotDatabase(DB, true); }
function privateSnapshotDatabase(DB, sealedOnly) {
  safe(typeof DB === 'function' && typeof sealedOnly === 'boolean');
  return function SealedSnapshot(path, options) {
    safe(options?.readonly === true && options.fileMustExist === true && resolve(path) === path &&
      fs.realpathSync(dirname(path)) === dirname(path));
    const sealed = () => {
      const s = fs.lstatSync(path);
      safe(s.isFile() && !s.isSymbolicLink() && s.nlink === 1 && s.uid === process.getuid() && (s.mode & 0o7777) === 0o600);
      for (const suffix of sealedOnly ? ['-journal', '-wal', '-shm'] : ['-journal']) safe(!has(path + suffix));
    };
    sealed();
    // Generic host fingerprints may inspect an existing WAL family. Stable copy
    // includes WAL contents; additionally fence SHM without opening the source.
    // Sealed audit admission never uses this allowance.
    const shm = has(path + '-shm') ? sourceFileFence(path + '-shm') : null;
    const verifyShm = () => { safe(has(path + '-shm') === Boolean(shm)); shm?.verify(); };
    const temp = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'public-sealed-snapshot-'))); fs.chmodSync(temp, 0o700);
    let copy;
    const release = () => {
      try { copy?.verify(); sealed(); verifyShm(); }
      finally { try { copy?.cleanup(); } finally { fs.rmdirSync(temp); } }
    };
    let db;
    try {
      // Existing bounded stream copy supplies O_NOFOLLOW, exact metadata/content
      // fences, disk headroom and a private directory with constrained cleanup.
      copy = copyStableSqlite(fs, crypto, path, join(temp, 'source')); sealed(); verifyShm();
      db = new DB(copy.path, options);
    } catch (error) { release(); throw error; }
    const close = db.close.bind(db); let closed = false;
    Object.defineProperty(db, 'close', { value() {
      if (!closed) { closed = true; try { close(); } finally { release(); } }
      return db;
    } });
    return db;
  };
}

// Public host reader also supports stable WAL families, without creating or
// deleting any source sidecars. Migration admission remains strictly sealed.
// The lexical core stays identical for native programs and summary recovery.
function privateCurrentLlmFingerprint(DB, io, crypto, path, kind, empty = false) {
  return currentLlmFingerprint(privateSnapshotDatabase(DB, false), io, crypto, path, kind, empty);
}
export { privateCurrentLlmFingerprint as currentLlmFingerprint };

export const PUBLIC_AUTH_A3_MIGRATION_ACK = '--ack-auth-a2-to-a3';
// Independent expected migration, not extracted from the candidate constructor.
// SQL whitespace is intentional: full sqlite_master bytes participate in the fingerprint.
export const PUBLIC_AUTH_A3_DDL = `CREATE TABLE IF NOT EXISTS user_auth_state (
          user_id TEXT PRIMARY KEY REFERENCES users(id), generation INTEGER NOT NULL CHECK(generation>0)
        );
        INSERT OR IGNORE INTO user_auth_state SELECT id,1 FROM users;
        CREATE TABLE IF NOT EXISTS password_resets (
          token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL UNIQUE REFERENCES users(id),
          generation INTEGER NOT NULL, expires_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS password_resets_expiry ON password_resets(expires_at);`;

// Schema classification only; never accepts a partial migration or extra object on
// either new table. All old objects/rows remain covered by the full fingerprint.
export function publicAuthSchema(db) {
  const need = v => { if (!v) throw Error('AUTH_SCHEMA_REFUSED'); };
  need(String(db.pragma('user_version', { simple: true })) === '0');
  for (const table of ['users', 'sessions', 'auth_attempts', 'trusted_sessions', 'browser_access'])
    need(db.prepare("SELECT count(*) n FROM sqlite_master WHERE type='table' AND name=?").get(table).n.toString() === '1');
  const rows = db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE tbl_name IN ('user_auth_state','password_resets') OR name IN ('user_auth_state','password_resets','password_resets_expiry','sqlite_autoindex_user_auth_state_1','sqlite_autoindex_password_resets_1','sqlite_autoindex_password_resets_2') ORDER BY type,name").raw().all();
  if (rows.length === 0) return 2;
  const expected = [
    ['index', 'password_resets_expiry', 'password_resets', 'CREATE INDEX password_resets_expiry ON password_resets(expires_at)'],
    ['index', 'sqlite_autoindex_password_resets_1', 'password_resets', null],
    ['index', 'sqlite_autoindex_password_resets_2', 'password_resets', null],
    ['index', 'sqlite_autoindex_user_auth_state_1', 'user_auth_state', null],
    ['table', 'password_resets', 'password_resets', 'CREATE TABLE password_resets ( token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL UNIQUE REFERENCES users(id), generation INTEGER NOT NULL, expires_at INTEGER NOT NULL )'],
    ['table', 'user_auth_state', 'user_auth_state', 'CREATE TABLE user_auth_state ( user_id TEXT PRIMARY KEY REFERENCES users(id), generation INTEGER NOT NULL CHECK(generation>0) )'],
  ];
  const normalize = list => list.map(row => row.map(v => typeof v === 'string' ? v.replace(/\s+/g, ' ').trim() : v));
  need(JSON.stringify(normalize(rows)) === JSON.stringify(expected));
  return 3;
}

// Only disposable copies are writable. The independent SQL defines the sole
// permitted delta; the real candidate constructor must produce it twice exactly.
export function qualifyPublicAuthSnapshot(root, { DB, snapshotPath, environment, migrate }) {
  safe(typeof migrate === 'boolean' && resolve(root) === root && fs.realpathSync(root) === root &&
    resolve(snapshotPath) === snapshotPath && fs.realpathSync(dirname(snapshotPath)) === dirname(snapshotPath));
  const keys = ['AUTH_ORIGIN', 'AUTH_ALLOW_INSECURE_LOCAL_HTTP', 'SCAN_BROWSER_ALLOWED_USER_IDS', 'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS'];
  safe(equal(Object.keys(environment).sort(), [...keys].sort()) && keys.every(k => typeof environment[k] === 'string'));
  safe((fs.lstatSync(snapshotPath).mode & 0o7777) === 0o600);
  const mainGuard = sourceFileFence(snapshotPath);
  const guard = { verify() { mainGuard.verify(); for (const suffix of ['-journal', '-wal', '-shm']) safe(!has(snapshotPath + suffix)); } };
  guard.verify();
  const SnapshotDB = sealedSnapshotDatabase(DB);
  const before = currentLlmFingerprint(SnapshotDB, fs, crypto, snapshotPath, 'auth');
  const source = new SnapshotDB(snapshotPath, { readonly: true, fileMustExist: true, timeout: 2000 });
  try { safe(publicAuthSchema(source) === (migrate ? 2 : 3)); } finally { source.close(); }
  const temp = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'public-auth-qualification-'))); fs.chmodSync(temp, 0o700);
  try {
    const expectedPath = join(temp, 'expected.sqlite'), actualPath = join(temp, 'actual.sqlite');
    for (const p of [expectedPath, actualPath]) {
      fs.copyFileSync(snapshotPath, p, fs.constants.COPYFILE_EXCL); fs.chmodSync(p, 0o600); guard.verify();
      safe(currentLlmFingerprint(DB, fs, crypto, p, 'auth') === before);
    }
    if (migrate) {
      const expected = new DB(expectedPath, { fileMustExist: true, timeout: 2000 });
      try {
        expected.pragma('foreign_keys=ON'); expected.transaction(() => expected.exec(PUBLIC_AUTH_A3_DDL)).immediate();
        safe(publicAuthSchema(expected) === 3 && expected.prepare('SELECT count(*) n FROM password_resets').get().n === 0);
      } finally { expected.close(); }
    }
    const expected = currentLlmFingerprint(DB, fs, crypto, expectedPath, 'auth');
    safe(migrate ? expected !== before : expected === before);
    const code = `import fs from 'node:fs';
      try{const {path,env}=JSON.parse(fs.readFileSync(0,'utf8'));Object.assign(process.env,env,{AUTH_DB_PATH:path});
        const {AuthStore}=await import('./src/auth/auth.store.ts');const store=new AuthStore();
        try{store.assertAvailable();}finally{store.onModuleDestroy();}
      }catch{process.exitCode=70;}`;
    for (let pass = 0; pass < 2; pass++) {
      const r = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code], {
        cwd: join(root, 'server/api'), env: { PATH: process.env.PATH }, input: JSON.stringify({ path: actualPath, env: environment }),
        encoding: 'utf8', timeout: 30000, maxBuffer: 65536,
      });
      safe(r.status === 0 && r.signal === null && !r.error && r.stdout === '');
      safe(currentLlmFingerprint(DB, fs, crypto, actualPath, 'auth') === expected); guard.verify();
    }
    safe(currentLlmFingerprint(SnapshotDB, fs, crypto, snapshotPath, 'auth') === before); guard.verify();
    return { version: 1, migration: migrate ? 'auth-a2-to-a3' : 'none', before, expected, constructorPasses: 2 };
  } catch { throw Error('PUBLIC auth snapshot incompatible/HOLD; details withheld.'); }
  finally { fs.rmSync(temp, { recursive: true, force: true }); guard.verify(); }
}

// Header-only preflight: no SQLite open, SHM creation, application imports or raw output.
// A concurrent journal/source change refuses; the later sealed B0 is authoritative.
export function publicLlmHistoryHeader(io) {
  const need = v => { if (!v) throw Error('HISTORY_HEADER_REFUSED'); };
  const path = '/auth/llm-history.sqlite', quota = '/auth/llm-usage.sqlite';
  const exists = p => io.lstatSync(p, { throwIfNoEntry: false }) !== undefined;
  need(exists(path) === exists(quota));
  for (const p of [path, quota]) for (const suffix of ['-journal', '-wal', '-shm']) {
    if (p === path || !exists(path)) need(!exists(p + suffix));
  }
  if (!exists(path)) return { ready: true, historyVersion: null };
  const stamp = s => [s.dev, s.ino, s.uid, s.mode, s.nlink, s.size, s.mtimeMs, s.ctimeMs];
  const before = io.lstatSync(path);
  need(before.isFile() && !before.isSymbolicLink() && before.uid === process.getuid() && before.nlink === 1 &&
    (before.mode & 0o7777) === 0o600 && before.size >= 4096 && before.size <= 8388608);
  const fd = io.openSync(path, io.constants.O_RDONLY | io.constants.O_NOFOLLOW | io.constants.O_NONBLOCK);
  try {
    const b = Buffer.alloc(100); need(io.readSync(fd, b, 0, b.length, 0) === b.length);
    need(b.subarray(0, 16).equals(Buffer.from('SQLite format 3\0')) && b.readUInt16BE(16) === 4096 && b.readUInt32BE(68) === 1145655602);
    const version = b.readUInt32BE(60); need([3, 4].includes(version));
    need(JSON.stringify(stamp(before)) === JSON.stringify(stamp(io.fstatSync(fd))) && JSON.stringify(stamp(before)) === JSON.stringify(stamp(io.lstatSync(path))));
    for (const suffix of ['-journal', '-wal', '-shm']) need(!exists(path + suffix));
    return { ready: true, historyVersion: version };
  } finally { io.closeSync(fd); }
}
export const PUBLIC_LLM_SCHEMA_PREFLIGHT_PROGRAM = helperImports + safeSource +
  'const header=' + publicLlmHistoryHeader.toString() + ';const currentHistorySchema=' + currentHistorySchema.toString() +
  ';const copyStableSqlite=' + copyStableSqlite.toString() +
  ";const timer=setTimeout(()=>process.exit(71),120000);try{process.umask(0o077);const receipt=header(io);if(receipt.historyVersion!==null){const copy=copyStableSqlite(io,crypto,'/auth/llm-history.sqlite','/backup/schema-source');let db;try{db=new DB(copy.path,{readonly:true,fileMustExist:true,timeout:2000});db.pragma('query_only=ON');safe(currentHistorySchema(db)===receipt.historyVersion);safe(db.pragma('integrity_check',{simple:true})==='ok'&&db.pragma('foreign_key_check').length===0);}finally{db?.close();copy.verify();copy.cleanup();}safe(header(io).historyVersion===receipt.historyVersion);}" +
  writeReady + "save('/backup/ready.json',receipt);clearTimeout(timer);" + keeper + "}catch{process.exit(70);}";
export const PUBLIC_LLM_SUMMARY_MIGRATE_PROGRAM = helperImports + safeSource +
  'const currentHistorySchema=' + currentHistorySchema.toString() + ';const header=' + publicLlmHistoryHeader.toString() +
  ";const timer=setTimeout(()=>process.exit(71),120000);try{process.umask(0o077);safe(header(io).historyVersion===3);const before=new DB('/auth/llm-history.sqlite',{readonly:true,fileMustExist:true});try{safe(currentHistorySchema(before)===3);safe(before.pragma('integrity_check',{simple:true})==='ok'&&before.pragma('foreign_key_check').length===0);safe(before.prepare(\"SELECT count(*) n FROM history_head WHERE json_extract(content,'$.pending') IS NOT NULL\").get().n===0);safe(before.prepare('SELECT count(*) n FROM history_completion_space').get().n===0);}finally{before.close();}" +
  "const {HistoryStore}=await import('./src/llm/history-store.ts');const store=new HistoryStore('/auth/llm-history.sqlite');try{store.migrateSummarySchema();}finally{store.close();}safe(header(io).historyVersion===4);const after=new DB('/auth/llm-history.sqlite',{readonly:true,fileMustExist:true});try{safe(currentHistorySchema(after)===4);safe(after.prepare('SELECT count(*) n FROM llm_summary').get().n===0);}finally{after.close();}for(const path of ['/auth/llm-history.sqlite','/auth']){const fd=io.openSync(path,io.constants.O_RDONLY|io.constants.O_NOFOLLOW);try{io.fsyncSync(fd);}finally{io.closeSync(fd);}}" +
  writeReady + "save('/backup/ready.json',{ready:true,migration:'history-summary-v3-to-v4'});clearTimeout(timer);" + keeper + "}catch{process.exit(70);}";
// New purpose only: historical preflight/helper program identities stay unchanged.
export const PUBLIC_AUTH_SCHEMA_PREFLIGHT_PROGRAM = helperImports + safeSource +
  'const copyStableSqlite=' + copyStableSqlite.toString() + ';const publicAuthSchema=' + publicAuthSchema.toString() +
  ";const timer=setTimeout(()=>process.exit(71),120000);try{process.umask(0o077);const copy=copyStableSqlite(io,crypto,'/auth/auth.sqlite','/backup/auth-schema');let db,authVersion;try{db=new DB(copy.path,{readonly:true,fileMustExist:true,timeout:2000});db.pragma('query_only=ON');safe(db.pragma('integrity_check',{simple:true})==='ok'&&db.pragma('foreign_key_check').length===0);authVersion=publicAuthSchema(db);}finally{db?.close();copy.verify();copy.cleanup();}" +
  writeReady + "save('/backup/ready.json',{ready:true,authVersion});clearTimeout(timer);" + keeper + "}catch{process.exit(70);}";
function currentHelperProgram(purpose) {
  const programs = { 'auth-schema-preflight': PUBLIC_AUTH_SCHEMA_PREFLIGHT_PROGRAM, backup: PUBLIC_LLM_CURRENT_BACKUP_PROGRAM, initialize: PUBLIC_LLM_INITIALIZE_PROGRAM,
    check: PUBLIC_LLM_CHECK_PROGRAM, 'schema-preflight': PUBLIC_LLM_SCHEMA_PREFLIGHT_PROGRAM, 'migrate-summary': PUBLIC_LLM_SUMMARY_MIGRATE_PROGRAM };
  safe(Object.hasOwn(programs, purpose)); return programs[purpose];
}
function currentHelperName(name, purpose) {
  const match = new RegExp(`^${PROJECT}-llm-(?:[a-f0-9]{32}|76eb7a61e0da2e108210bc773b964d35-summary-current)-(fenced|post-migration|before-api|after-api|initialize|check|schema-preflight|auth-schema-preflight|migrate-summary)$`).exec(name);
  safe(match && (purpose === 'backup' ? ['fenced', 'post-migration', 'before-api', 'after-api'].includes(match[1]) : match[1] === purpose));
}
export function currentPublicLlmHelperArguments(name, image, purpose = 'backup') {
  currentHelperName(name, purpose); safe(imageId(image));
  const args = backupArguments(name, image); args[args.length - 1] = currentHelperProgram(purpose);
  args.splice(args.indexOf(image) + 1, 0, '--import', 'tsx');
  args.splice(args.indexOf('--workdir'), 0, '--env', 'TMPDIR=/backup');
  if (['initialize', 'check', 'migrate-summary'].includes(purpose)) {
    const at = args.indexOf(`type=volume,src=${PROJECT}_auth_accounts,dst=/auth,readonly,volume-nocopy`); safe(at >= 0);
    args[at] = `type=volume,src=${PROJECT}_auth_accounts,dst=/auth,volume-nocopy`;
    if (purpose !== 'migrate-summary') args.splice(args.indexOf('--workdir'), 0, ...Object.entries(PUBLIC_LLM_ENV).flatMap(([k, v]) => ['--env', `${k}=${v}`]));
  }
  return args;
}
export function validateCurrentPublicLlmHelper(c, name, image, purpose, state) {
  currentHelperName(name, purpose);
  safe(c.RestartCount === 0 && c.State?.Paused !== true && equal(c.Config.Cmd, ['--import', 'tsx', '--input-type=module', '-e', currentHelperProgram(purpose)]) && equal(c.Args, c.Config.Cmd));
  const copy = structuredClone(c); copy.Config.Cmd = ['--input-type=module', '-e', RECOVERY_BACKUP]; copy.Args = copy.Config.Cmd;
  safe(equal(envMap(copy.Config.Env), { ...envMap(image.Config.Env), ...(['initialize', 'check'].includes(purpose) ? PUBLIC_LLM_ENV : {}), TMPDIR: '/backup' })); copy.Config.Env = image.Config.Env;
  if (['initialize', 'check', 'migrate-summary'].includes(purpose)) {
    const m = copy.HostConfig.Mounts.filter(m => m.Target === '/auth'), o = copy.Mounts.filter(m => m.Destination === '/auth');
    safe(m.length === 1 && o.length === 1 && (!Object.hasOwn(m[0], 'ReadOnly') || m[0].ReadOnly === false) && o[0].RW === true); m[0].ReadOnly = true; o[0].RW = false;
  }
  validateBackupHelper(copy, name, image, 'backup', state);
}

// Separate v5 exports: never alter historical serialized helper/function bytes.
export function reservationHistorySchema(db) {
  const version = String(db.pragma('user_version', { simple: true }));
  safe(String(db.pragma('application_id', { simple: true })) === '1145655602' && ['4', '5'].includes(version));
  const objects = db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE tbl_name='llm_summary' OR name IN ('llm_summary','sqlite_autoindex_llm_summary_1') ORDER BY type,name,tbl_name,sql").raw().all();
  const sql = 'CREATE TABLE llm_summary(\n  scope TEXT PRIMARY KEY CHECK(length(scope)=64),\n  content TEXT NOT NULL CHECK(length(CAST(content AS BLOB))<=69632),\n  content_hash TEXT NOT NULL CHECK(length(content_hash)=64)) STRICT';
  safe(equal(objects, [['index', 'sqlite_autoindex_llm_summary_1', 'llm_summary', null], ['table', 'llm_summary', 'llm_summary', sql]]));
  const totals = db.prepare('SELECT count(*) n,coalesce(sum(length(CAST(content AS BLOB))),0) bytes,coalesce(max(length(CAST(content AS BLOB))),0) largest FROM llm_summary').get();
  safe(BigInt(totals.n) <= 64n && BigInt(totals.bytes) <= 2097152n && BigInt(totals.largest) <= 69632n);
  return Number(version);
}
function reservationFingerprint(DB, io, crypto, path, kind) {
  safe(['history', 'quota', 'auth', 'ledger'].includes(kind));
  const db = new DB(path, { readonly: true, fileMustExist: true, timeout: 2000 });
  try {
    db.defaultSafeIntegers(true); db.pragma('query_only=ON'); db.exec('BEGIN');
    safe(db.pragma('integrity_check', { simple: true }) === 'ok' && db.pragma('foreign_key_check').length === 0);
    const versions = [db.pragma('application_id', { simple: true }), db.pragma('user_version', { simple: true })];
    if (kind === 'auth' || kind === 'ledger') safe(String(versions[1]) === (kind === 'auth' ? '0' : '15'));
    else if (kind === 'history') reservationHistorySchema(db);
    else safe(equal(versions.map(String), ['1145655601', '1']));
    const schema = db.prepare('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name,tbl_name,sql').raw().all();
    safe(schema.length > 0 && schema.length <= 512 && !schema.some(row => /^CREATE\s+VIRTUAL\s+TABLE/i.test(row[3] ?? '')));
    const h = crypto.createHash('sha256'); h.update(sqliteTypedRow(versions)); h.update(sqliteTypedRow(schema.flat()));
    let bytes = 0, rows = 0;
    for (const entry of schema.filter(r => r[0] === 'table')) {
      const table = entry[1]; safe(/^[a-z_][a-z0-9_]*$/.test(table)); h.update(table);
      for (const row of db.prepare(`SELECT rowid,* FROM "${table}" ORDER BY rowid`).safeIntegers(true).raw().iterate()) {
        const text = sqliteTypedRow(row); bytes += Buffer.byteLength(text); safe(bytes <= 256 * 1024 ** 2 && ++rows <= 250000); h.update(text); h.update('\n');
      }
    }
    if (kind === 'history') safe(db.prepare("SELECT count(*) n FROM history_head WHERE json_extract(content,'$.pending') IS NOT NULL").get().n === 0n);
    db.exec('ROLLBACK'); return h.digest('hex');
  } finally { db.close(); }
}
export function reservationLlmFingerprint(DB, io, crypto, path, kind) {
  return reservationFingerprint(sealedSnapshotDatabase(DB), io, crypto, path, kind);
}
export function reservationHistoryHeader(io) {
  const need = v => { if (!v) throw Error('HISTORY_HEADER_REFUSED'); };
  const path = '/auth/llm-history.sqlite';
  const exists = p => io.lstatSync(p, { throwIfNoEntry: false }) !== undefined;
  need(exists(path) && exists('/auth/llm-usage.sqlite'));
  for (const suffix of ['-journal', '-wal', '-shm']) need(!exists(path + suffix));
  const stamp = s => [s.dev, s.ino, s.uid, s.mode, s.nlink, s.size, s.mtimeMs, s.ctimeMs];
  const before = io.lstatSync(path);
  need(before.isFile() && !before.isSymbolicLink() && before.uid === process.getuid() && before.nlink === 1 &&
    (before.mode & 0o7777) === 0o600 && before.size >= 4096 && before.size <= 8388608);
  const fd = io.openSync(path, io.constants.O_RDONLY | io.constants.O_NOFOLLOW | io.constants.O_NONBLOCK);
  try {
    const b = Buffer.alloc(100); need(io.readSync(fd, b, 0, b.length, 0) === b.length);
    need(b.subarray(0, 16).equals(Buffer.from('SQLite format 3\0')) && b.readUInt16BE(16) === 4096 && b.readUInt32BE(68) === 1145655602);
    const version = b.readUInt32BE(60); need([4, 5].includes(version));
    need(JSON.stringify(stamp(before)) === JSON.stringify(stamp(io.fstatSync(fd))) && JSON.stringify(stamp(before)) === JSON.stringify(stamp(io.lstatSync(path))));
    for (const suffix of ['-journal', '-wal', '-shm']) need(!exists(path + suffix));
    return { ready: true, historyVersion: version };
  } finally { io.closeSync(fd); }
}
export const PUBLIC_LLM_RESERVATION_HEADER_PROGRAM = "const io=require('node:fs');const header=" + reservationHistoryHeader.toString() + ";try{process.stdout.write(JSON.stringify(header(io)));}catch{process.exitCode=70;}";
const reservationNativeSource = currentNativeSource
  .replace('const currentHistorySchema=' + currentHistorySchema.toString(), 'const reservationHistorySchema=' + reservationHistorySchema.toString())
  .replace('const llmFingerprint=' + currentLlmFingerprint.toString(), 'const llmFingerprint=' + reservationFingerprint.toString());
export const PUBLIC_LLM_RESERVATION_BACKUP_PROGRAM = PUBLIC_LLM_BACKUP_PROGRAM.replace(nativeSource, reservationNativeSource);
export const PUBLIC_LLM_RESERVATION_MIGRATE_PROGRAM = helperImports + safeSource +
  'const header=' + reservationHistoryHeader.toString() + ';const reservationHistorySchema=' + reservationHistorySchema.toString() +
  ";const timer=setTimeout(()=>process.exit(71),120000);try{process.umask(0o077);safe(header(io).historyVersion===4);const {HistoryStore}=await import('./src/llm/history-store.ts');HistoryStore.migrateSummaryReservations({path:'/auth/llm-history.sqlite'});safe(header(io).historyVersion===5);const db=new DB('/auth/llm-history.sqlite',{readonly:true,fileMustExist:true});try{safe(reservationHistorySchema(db)===5);safe(db.pragma('integrity_check',{simple:true})==='ok'&&db.pragma('foreign_key_check').length===0);}finally{db.close();}for(const path of ['/auth/llm-history.sqlite','/auth']){const fd=io.openSync(path,io.constants.O_RDONLY|io.constants.O_NOFOLLOW);try{io.fsyncSync(fd);}finally{io.closeSync(fd);}}" +
  writeReady + "save('/backup/ready.json',{ready:true,migration:'history-reservations-v4-to-v5',from:4,to:5});clearTimeout(timer);" + keeper + "}catch{process.exit(70);}";
function reservationHelperProgram(name, purpose) {
  const match = new RegExp(`^${PROJECT}-llm-[a-f0-9]{32}-(fenced|post-migration|before-api|after-api|migrate-history-v4-to-v5)$`).exec(name);
  safe(match && (purpose === 'backup' ? match[1] !== 'migrate-history-v4-to-v5' : purpose === 'migrate-history-v4-to-v5' && match[1] === purpose));
  return purpose === 'backup' ? PUBLIC_LLM_RESERVATION_BACKUP_PROGRAM : PUBLIC_LLM_RESERVATION_MIGRATE_PROGRAM;
}
export function reservationPublicLlmHelperArguments(name, image, purpose = 'backup') {
  const program = reservationHelperProgram(name, purpose); safe(imageId(image));
  const args = backupArguments(name, image); args[args.length - 1] = program;
  args.splice(args.indexOf(image) + 1, 0, '--import', 'tsx');
  args.splice(args.indexOf('--workdir'), 0, '--env', 'TMPDIR=/backup');
  if (purpose === 'migrate-history-v4-to-v5') {
    const label = args.indexOf('org.diplom.recovery-purpose=backup'); safe(label > 0 && args[label - 1] === '--label');
    args[label] = 'org.diplom.recovery-purpose=' + purpose;
    const at = args.indexOf(`type=volume,src=${PROJECT}_auth_accounts,dst=/auth,readonly,volume-nocopy`); safe(at >= 0);
    args[at] = `type=volume,src=${PROJECT}_auth_accounts,dst=/auth,volume-nocopy`;
  }
  return args;
}
export function validateReservationPublicLlmHelper(c, name, image, purpose, state) {
  const program = reservationHelperProgram(name, purpose);
  safe(c.Config?.Labels?.['org.diplom.recovery-purpose'] === purpose);
  safe(c.RestartCount === 0 && c.State?.Paused !== true && equal(c.Config.Cmd, ['--import', 'tsx', '--input-type=module', '-e', program]) && equal(c.Args, c.Config.Cmd));
  const copy = structuredClone(c); copy.Config.Cmd = ['--input-type=module', '-e', RECOVERY_BACKUP]; copy.Args = copy.Config.Cmd;
  safe(equal(envMap(copy.Config.Env), { ...envMap(image.Config.Env), TMPDIR: '/backup' })); copy.Config.Env = image.Config.Env;
  if (purpose === 'migrate-history-v4-to-v5') {
    const m = copy.HostConfig.Mounts.filter(m => m.Target === '/auth'), o = copy.Mounts.filter(m => m.Destination === '/auth');
    safe(m.length === 1 && o.length === 1 && (!Object.hasOwn(m[0], 'ReadOnly') || m[0].ReadOnly === false) && o[0].RW === true);
    m[0].ReadOnly = true; o[0].RW = false;
    // Project only the already-authorized migration identity into the historical backup validator.
    copy.Config.Labels['org.diplom.recovery-purpose'] = 'backup';
  }
  validateBackupHelper(copy, name, image, 'backup', state);
}
// Independent preservation oracle: no candidate constructor/decoder is trusted here.
export function verifyHistoryReservationMigration({ DB, beforePath, afterPath }) {
  const SnapshotDB = sealedSnapshotDatabase(DB);
  const before = reservationFingerprint(SnapshotDB, fs, crypto, beforePath, 'history');
  const after = reservationFingerprint(SnapshotDB, fs, crypto, afterPath, 'history');
  const stores = [];
  try {
    for (const path of [beforePath, afterPath]) {
      const db = new SnapshotDB(path, { readonly: true, fileMustExist: true, timeout: 2000 }); stores.push(db);
      db.defaultSafeIntegers(true); db.pragma('query_only=ON'); db.exec('BEGIN');
    }
    const [old, next] = stores; safe(reservationHistorySchema(old) === 4 && reservationHistorySchema(next) === 5);
    const sql = 'SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name,tbl_name,sql';
    const schema = old.prepare(sql).raw().all(); safe(equal(schema, next.prepare(sql).raw().all()));
    let bytes = 0, rows = 0;
    for (const [, table] of schema.filter(r => r[0] === 'table')) {
      safe(/^[a-z_][a-z0-9_]*$/.test(table)); const query = `SELECT rowid,* FROM "${table}" ORDER BY rowid`;
      const a = old.prepare(query).raw().iterate(), b = next.prepare(query).raw().iterate();
      try {
        for (;;) {
          const x = a.next(), y = b.next(); safe(x.done === y.done); if (x.done) break;
          const row = sqliteTypedRow(x.value); bytes += Buffer.byteLength(row); safe(bytes <= 256 * 1024 ** 2 && ++rows <= 250000);
          safe(row === sqliteTypedRow(y.value));
        }
      } finally { a.return?.(); b.return?.(); }
    }
    for (const db of stores) db.exec('ROLLBACK');
  } finally { stores.forEach(db => db.close()); }
  safe(reservationFingerprint(SnapshotDB, fs, crypto, beforePath, 'history') === before && reservationFingerprint(SnapshotDB, fs, crypto, afterPath, 'history') === after);
  return Object.freeze({ version: 1, migration: 'history-reservations-v4-to-v5', from: 4, to: 5, before, after, allRowsPreserved: true });
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
  if (originalBaseline) safe(equal(baseline.core, originalBaseline.core) && (admission ? baseline.llm !== null && (admissionContext.rolloutOnly ? equal(baseline.llm, originalBaseline.llm) : baseline.empty === true && (originalBaseline.llm === null || equal(baseline.llm, originalBaseline.llm))) : equal(baseline.llm, originalBaseline.llm)));
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

export function capturePublicLlmSource(root, { openai = false, moduleapi = false } = {}) {
  safe(typeof openai === 'boolean' && typeof moduleapi === 'boolean' && !(openai && moduleapi));
  checkIgnores(root);
  if (moduleapi) for (const name of ['gateway/moduleapi.Dockerfile', 'moduleapi-api.Dockerfile', 'moduleapi-secret-init.Dockerfile'])
    safe(!has(join(root, 'server/deploy', name + '.dockerignore')));
  if (openai) for (const name of ['gateway/openai.Dockerfile', 'openai-api.Dockerfile'])
    safe(!has(join(root, 'server/deploy', name + '.dockerignore')));
  for (const file of ['public-stand.Dockerfile', 'gateway/openrouter.Dockerfile']) safe(!has(join(root, 'server/deploy', file + '.dockerignore')));
  const ignore = readBounded(join(root, '.dockerignore'), 131072).split(/\r?\n/).map(s => s.trim());
  safe(['.env', '.env.*', '**/.env', '**/.env.*', '**/*.local', '.local-auth', '.local-stand', '.local-public-images/'].every(s => ignore.includes(s)) && !ignore.some(s => s.startsWith('!')));
  const paths = ['package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml', 'index.html', 'admin.html', 'vite.config.ts', 'tsconfig.json', '.gitignore', '.dockerignore',
    'server/api/package.json', 'server/api/tsconfig.json', 'server/deploy/trust/db-signing-key.pub.pem',
    'server/deploy/compose.public-images.yaml', 'server/deploy/compose.public-llm.yaml',
    'server/deploy/public-stand.Dockerfile', 'server/deploy/public-stand.nginx.conf', 'server/deploy/api.Dockerfile',
    'server/deploy/worker.Dockerfile', 'server/deploy/gateway/Dockerfile', 'server/deploy/gateway/proxy.py',
    'server/deploy/gateway/openrouter.Dockerfile', 'server/deploy/gateway/openrouter.py'];
  if (openai) paths.push('server/deploy/gateway/openai.Dockerfile', 'server/deploy/gateway/openai.py',
    'server/deploy/openai-api.Dockerfile', OPENAI_DEPLOYMENT.bootstrap, 'server/deploy/openai-secret-init.py',
    'scripts/openai-secret-provision.py', 'scripts/public-llm-config.py');
  if (openai) {
    safe(has(join(root, OPENAI_DEPLOYMENT.bootstrap)));
    const legacyDockerfile = readBounded(join(root, 'server/deploy/api.Dockerfile'), 16384);
    const extendedDockerfile = readBounded(join(root, 'server/deploy/openai-api.Dockerfile'), 16384);
    safe(extendedDockerfile === legacyDockerfile.replace('WORKDIR /app/server/api\n',
      'COPY server/deploy/openai-secret-bootstrap.mjs server/deploy/openai-secret-bootstrap.mjs\nWORKDIR /app/server/api\n'));
  }
  if (moduleapi) {
    paths.push('server/deploy/gateway/moduleapi.Dockerfile', 'server/deploy/gateway/moduleapi.py',
      'server/deploy/moduleapi-api.Dockerfile', MODULEAPI_SLOT_DEPLOYMENT.bootstrap,
      'server/deploy/moduleapi-secret-init.py', 'server/deploy/moduleapi-secret-init.Dockerfile',
      'scripts/moduleapi-secret-provision.py', 'scripts/public-llm-config.py');
    const legacyDockerfile = readBounded(join(root, 'server/deploy/api.Dockerfile'), 16384);
    const extendedDockerfile = readBounded(join(root, 'server/deploy/moduleapi-api.Dockerfile'), 16384);
    safe(extendedDockerfile === legacyDockerfile.replace('WORKDIR /app/server/api\n',
      'COPY server/deploy/moduleapi-secret-bootstrap.mjs server/deploy/moduleapi-secret-bootstrap.mjs\nWORKDIR /app/server/api\n'));
  }
  const executionProofs = new Map(), executionDirectories = new Map();
  const discover = moduleapi ? discoverModuleApiExecutionClosure : discoverOpenAiExecutionClosure;
  const executionClosure = openai || moduleapi ? discover(root, name => {
    const path = join(root, name);
    for (let p = dirname(path); ; p = dirname(p)) {
      safe(p === root || p.startsWith(root + '/'));
      if (!executionDirectories.has(p)) {
        const s = fs.lstatSync(p); safe(s.isDirectory() && !s.isSymbolicLink() && s.uid === process.getuid() && !(s.mode & 0o022));
        executionDirectories.set(p, { dev: s.dev, ino: s.ino, uid: s.uid, mode: s.mode });
      }
      if (p === root) break;
    }
    const proof = sourceFileFence(path); safe(!(proof.snapshot.mode & 0o022) && proof.snapshot.size <= 1024 ** 2);
    const text = readBounded(path, 1024 ** 2); safe(hash(text) === proof.snapshot.digest); proof.verify();
    executionProofs.set(path, proof); paths.push(name); return text;
  }) : null;
  const directories = [];
  const walk = p => {
    const s = fs.lstatSync(join(root, p)); safe(!s.isSymbolicLink());
    if (s.isDirectory()) {
      const names = fs.readdirSync(join(root, p)).sort(); directories.push({ p, dev: s.dev, ino: s.ino, names });
      for (const n of names) walk(p + '/' + n);
    } else { safe(s.isFile() && s.size <= 16 * 1024 ** 2); paths.push(p); }
  };
  for (const p of ['src', 'public', 'server/api/src', 'server/runtime/src']) walk(p);
  const files = [...new Set(paths)].map(p => executionProofs.get(join(root, p)) ?? sourceFileFence(join(root, p)));
  const overlay = JSON.parse(readBounded(join(root, 'server/deploy/compose.public-llm.yaml'), 16384));
  overlay.services['llm-egress'].build.context = root; safe(equal(overlay, publicLlmStaticOverlay(root)));
  const nginx = readBounded(join(root, 'server/deploy/public-stand.nginx.conf'), 65536);
  safe(nginx.includes('set $history_ingress_enabled 1;') && nginx.includes('set $runtime_ingress_enabled 0;') && nginx.includes('context|usage|readiness'));
  return { manifest: { files: files.map(f => ({ path: f.path.slice(root.length + 1), ...f.snapshot })), directories,
    ...(executionClosure ? { executionClosure } : {}) }, verify() {
    checkIgnores(root); for (const f of files) f.verify();
    for (const [path, initial] of executionDirectories) {
      const s = fs.lstatSync(path); safe(s.isDirectory() && !s.isSymbolicLink() && equal(initial, { dev: s.dev, ino: s.ino, uid: s.uid, mode: s.mode }));
    }
    for (const d of directories) { const s = fs.lstatSync(join(root, d.p)); safe(s.isDirectory() && !s.isSymbolicLink() && s.dev === d.dev && s.ino === d.ino && equal(fs.readdirSync(join(root, d.p)).sort(), d.names)); }
  } };
}
const sourceFence = (root, options) => capturePublicLlmSource(root, options).verify;
function control(c) {
  assertNoOpenAiDockerSecret(c.Config);
  const x = structuredClone(c.Config); if (x.Env) x.Env = x.Env.filter(v => !v.startsWith('SCAN_JWT_SECRET='));
  return hash({ Name: c.Name, Image: c.Image, Path: c.Path, Args: c.Args, Config: x, HostConfig: c.HostConfig,
    Mounts: [...c.Mounts].sort((a, b) => a.Destination.localeCompare(b.Destination)) });
}
function epoch(c) { return [c.Id, c.State.StartedAt, c.State.FinishedAt, c.State.Pid, c.RestartCount, c.State.Running, c.State.Status, c.State.ExitCode, c.State.Error]; }
function cleanStopped(c) {
  // Historical gateways and nginx may exit by SIGTERM.
  // Writers and one-shot initializers must still prove a clean exit0.
  const exits = ['egress', 'llm-egress', 'openai-egress', 'web'].includes(role(c)) ? [0, 143] : [0];
  safe(!c.State.Running && c.State.Status === 'exited' && exits.includes(c.State.ExitCode) && c.State.Pid === 0 && c.RestartCount === 0 &&
    !c.State.OOMKilled && !c.State.Dead && !c.State.Restarting && !c.State.Paused && !c.State.Error);
}
// One operational replacement of the already restored legacy stateless gateways.
// Not a general stopped-container rule and never usable by continuation/recovery CLIs.

export function validateLegacyGatewayStop({ before, after, events, submittedMs, stopOutput, writers }) {
  const name = role(before), target = LEGACY_GATEWAY_STOP_IDS[name];
  safe(target && before.Id === target[0] && before.Image === target[1] && after.Id === before.Id && after.Image === before.Image);
  safe(before.Mounts.length === 0 && after.Mounts.length === 0 && before.HostConfig.ReadonlyRootfs === true && before.State.Running && before.State.Status === 'running' && before.RestartCount === 0);
  assertNoOpenAiDockerSecret(before.Config); assertNoOpenAiDockerSecret(after.Config);
  // GPG_KEY is the public signing-key identifier inherited from the validated
  // Python image; container admission already checks every exact environment value.
  safe(before.Config.Env.every(v => v.startsWith('GPG_KEY=') || !/(?:KEY|TOKEN|PASSWORD|SECRET)/i.test(v.split('=', 1)[0])));
  safe(!before.State.OOMKilled && !before.State.Error && !before.State.Dead && !before.State.Paused && !before.State.Restarting);
  safe(control(before) === control(after) && after.State.StartedAt === before.State.StartedAt && after.State.ExitCode === 137 && !after.State.Running && after.State.Status === 'exited' && after.State.Pid === 0 && after.RestartCount === 0 && !after.State.OOMKilled && !after.State.Error && !after.State.Dead && !after.State.Paused && !after.State.Restarting);
  safe(Array.isArray(writers) && equal(writers.map(role).sort(), ['api', 'web', 'worker']));
  for (const writer of writers) cleanStopped(writer);
  safe(stopOutput.trim() === before.Id && Number.isSafeInteger(submittedMs));
  safe(Array.isArray(events) && events.length === 3 && events.every(e => equal(Object.keys(e).sort(), ['action','exit','id','signal','time']) && e.id === before.Id && Number.isSafeInteger(e.time)));
  const [term, kill, die] = events, start = Math.floor(submittedMs / 1000);
  safe(term.action === 'kill' && term.signal === '15' && term.exit === null && term.time >= start && term.time <= start + 5);
  safe(kill.action === 'kill' && kill.signal === '9' && kill.exit === null && kill.time - term.time >= 29 && kill.time - term.time <= 40);
  safe(die.action === 'die' && die.signal === null && die.exit === '137' && die.time >= kill.time && die.time <= kill.time + 5 && Math.abs(Date.parse(after.State.FinishedAt) / 1000 - die.time) < 2);
  return { version: 1, acknowledgement: LEGACY_GATEWAY_STOP_ACK, role: name, id: before.Id, image: before.Image, submittedMs, events, stoppedEpoch: epoch(after), stateless: true, writersClean: true };
}
// Diagnostics are data, never additional stop/recovery authority. No foreign
// message, stack, command, environment, config, stdout or stderr is serialized.
const stopDiagnostics = new WeakMap();
export const publicStopDiagnostic = error => stopDiagnostics.get(error) ?? null;
const stopNumber = value => Number.isSafeInteger(value) && Math.abs(value) <= 8640000000000000 ? value : null;
const stopBytes = value => typeof value === 'string' ? Math.min(Buffer.byteLength(value), 16 * 1024 ** 2) : null;
export function createPublicStopTrace(roleName, append, { now = () => performance.now(), wall = Date.now } = {}) {
  safe(['web','api','worker','egress','llm-egress'].includes(roleName) && typeof append === 'function');
  let sequence = 0;
  const emit = (step, state, started, detail = {}) => {
    const row = { version: 1, role: roleName, sequence: ++sequence, step, state,
      wallMs: stopNumber(wall()), elapsedMs: stopNumber(Math.max(0, Math.floor(now() - started))), detail };
    validatePublicStopDiagnostic(row); append(Object.freeze(row)); return row;
  };
  const start = (step, begin) => {
    safe(PUBLIC_STOP_DIAGNOSTIC_STEPS.includes(step)); const started = now();
    const journal = (state, detail) => {
      try { return emit(step, state, started, detail); }
      catch (error) {
        if (error && typeof error === 'object') stopDiagnostics.set(error, Object.freeze({ step, cause: 'JOURNAL', role: roleName }));
        throw error;
      }
    };
    journal('BEGIN', begin);
    return { pass: detail => journal('PASS', detail), fail(error) {
      const docker = isolatedDockerDiagnostic(error), code = ownValue(error, 'code');
      const cause = publicStopDiagnostic(error)?.cause ?? docker?.cause ?? (error instanceof SyntaxError ? 'JSON' : ['EIO','ENOSPC','EACCES','EPERM','ENOENT','EEXIST','ELOOP','EROFS','EMFILE','ENFILE'].includes(code) ? 'FILESYSTEM' : 'UNKNOWN');
      const diagnostic = Object.freeze({ step, cause, role: roleName });
      if (error && typeof error === 'object' && !stopDiagnostics.has(error)) stopDiagnostics.set(error, diagnostic);
      try { emit(step, 'FAIL', started, { cause, ...(docker ? { exitCode: docker.exitCode, signal: docker.signal, stdoutBytes: docker.stdoutBytes, stderrBytes: docker.stderrBytes } : {}) }); }
      catch { /* The original failure remains HOLD even if evidence storage fails. */ }
      throw error;
    } };
  };
  return {
    async step(step, work, project = () => ({}), begin = {}) {
      const entry = start(step, begin);
      try { const result = await work(); entry.pass(project(result)); return result; }
      catch (error) { return entry.fail(error); }
    },
    sync(step, work, project = () => ({})) {
      const entry = start(step, {});
      try { const result = work(); entry.pass(project(result)); return result; }
      catch (error) { return entry.fail(error); }
    },
  };
}
export function createPublicStopJournal(auditPath, roleName, verifyLock) {
  safe(['web','api','worker','egress','llm-egress'].includes(roleName));
  const verifyAudit = directoryFence(auditPath), parent = join(auditPath, 'stop-diagnostics');
  verifyLock(); verifyAudit();
  if (!has(parent)) { fs.mkdirSync(parent, { mode: 0o700 }); syncDirectory(auditPath); }
  const verifyParent = directoryFence(parent), path = join(parent, roleName);
  safe(!has(path)); fs.mkdirSync(path, { mode: 0o700 }); syncDirectory(parent);
  const verifyDirectory = directoryFence(path), proofs = [];
  const verify = () => {
    verifyLock(); verifyAudit(); verifyParent(); verifyDirectory();
    safe(equal(fs.readdirSync(path).sort(), proofs.map(p => p.name)));
    for (const proof of proofs) proof.file.verify();
  };
  return { role: roleName, verify, append(row) {
    validatePublicStopDiagnostic(row); safe(row.role === roleName && row.sequence === proofs.length + 1);
    verify(); const name = String(row.sequence).padStart(4, '0') + '.json', target = join(path, name);
    writeExclusive(target, JSON.stringify(row), 0o600); syncDirectory(path);
    proofs.push({ name, file: fileFence(target, 4096, 0o600) }); verify();
  } };
}
const plainStopTrace = { step: async (_step, work) => work(), sync: (_step, work) => work() };
// Same dispatch checks and timeout calculation as the ordinary preflight wrapper.
// Injected adapters let offline tests exercise the entire failure boundary, not
// merely a predicate fed with a successful stop result reconstructed afterward.
export function dispatchPublicLlmStopDocker({ args, extra = {}, trace = plainStopTrace, prefix,
  fence, endpoint, end, now, run, options }) {
  safe(['STOP','INSPECT','EVENTS'].includes(prefix));
  // No additional microtask/await between the source fence and engine dispatch.
  trace.sync(prefix + '_FENCE', fence);
  const timeout = trace.sync(prefix + '_TIMEOUT', () => {
    safe((extra.env?.DOCKER_HOST ?? endpoint) === endpoint && now() < end);
    return publicLlmDockerTimeout(extra.timeout ?? 30000, end, now());
  }, timeout => ({ requestedTimeoutMs: stopNumber(extra.timeout ?? 30000), effectiveTimeoutMs: stopNumber(timeout), remainingMs: stopNumber(Math.floor(end - now())) }));
  return trace.step(prefix + '_ENGINE', () => run(args, { ...options, ...extra, timeout }));
}
export async function inspectPublicLlmStop({ id, d, validate, trace = plainStopTrace }) {
  const text = await d(['container','inspect',id], {}, trace, 'INSPECT');
  const rows = await trace.step('INSPECT_PARSE', () => JSON.parse(text));
  await trace.step('INSPECT_CARDINALITY', () => safe(Array.isArray(rows) && rows.length === 1 && rows[0]?.Id === id));
  await trace.step('INSPECT_VALIDATOR', () => validate(rows[0]));
  await trace.step('INSPECT_COMMAND', () => {
    const command = [...(rows[0].Config.Entrypoint ?? []), ...rows[0].Config.Cmd];
    safe(rows[0].Path === command[0] && equal(rows[0].Args, command.slice(1)));
  });
  return rows[0];
}
export async function executePublicLlmStop({ name, stoppedStand, legacyGatewayStop, peers, peerModels, healthy,
  verifyPeers, users, census, record, addRecordFence, d, inspect, acknowledgedGatewayStops,
  trace = plainStopTrace, wall = Date.now }) {
  await trace.step('VERIFY_PEERS', verifyPeers); await trace.step('VERIFY_CONSUMERS', users);
  healthy.delete(name); const c = peers.get(name), a = peerModels.get(name);
  if (stoppedStand) { await trace.step('CLEAN_STOPPED', () => cleanStopped(c)); return; }
  const eligible = legacyGatewayStop && Object.hasOwn(LEGACY_GATEWAY_STOP_IDS, name);
  if (eligible) {
    await trace.step('WRITERS_CLEAN', () => { for (const writer of ['web','api','worker']) cleanStopped(peers.get(writer)); });
    await trace.step('CENSUS', census);
  }
  const submittedMs = wall();
  if (eligible) {
    const file = 'legacy-stop-' + name + '-submission.json';
    await trace.step('SUBMISSION_RECORD', () => record(file, { version: 1, id: c.Id, image: c.Image, submittedMs, acknowledgement: LEGACY_GATEWAY_STOP_ACK }));
    await trace.step('SUBMISSION_FENCE', () => addRecordFence(file));
  }
  const stopOutput = await trace.step('STOP_CALL', () => d(['container','stop','--time',name === 'api' ? '60' : '30',c.Id],
    { timeout: name === 'api' ? 75000 : 45000 }, trace, 'STOP'), text => ({ stdoutBytes: stopBytes(text), stdoutMatchesId: typeof text === 'string' && text.trim() === c.Id }));
  const stopped = await trace.step('INSPECT_CALL', () => inspect(c.Id, name, a.model, a.images, a.selection, trace), c => ({
    running: c.State.Running === true, oom: c.State.OOMKilled === true, exitCode: stopNumber(c.State.ExitCode), restartCount: stopNumber(c.RestartCount),
    startedMs: stopNumber(Date.parse(c.State.StartedAt)), finishedMs: stopNumber(Date.parse(c.State.FinishedAt)) }));
  await trace.step('CONTROL_EQUAL', () => safe(control(c) === control(stopped)));
  if (eligible && stopped.State.ExitCode === 137) {
    const untilMs = Date.parse(stopped.State.FinishedAt) + 1000;
    const args = await trace.step('EVENTS_ARGUMENTS', () => ['events','--since',new Date(submittedMs).toISOString(),'--until',new Date(untilMs).toISOString(),
      '--filter','type=container','--filter','container='+c.Id,'--filter','event=kill','--filter','event=die',
      '--format','{"id":{{json .Actor.ID}},"action":{{json .Action}},"signal":{{json .Actor.Attributes.signal}},"exit":{{json .Actor.Attributes.exitCode}},"time":{{json .Time}}}'],
      () => ({ sinceMs: stopNumber(submittedMs), untilMs: stopNumber(untilMs), untilAheadMs: stopNumber(untilMs-wall()) }));
    const text = await trace.step('EVENTS_CALL', () => d(args, { timeout: 15000 }, trace, 'EVENTS'), text => ({ stdoutBytes: stopBytes(text) }));
    const events = await trace.step('EVENTS_PARSE', () => text.trim().split('\n').filter(Boolean).map(line => JSON.parse(line)), events => ({
      eventCount: events.length, firstEventMs: stopNumber(events[0]?.time * 1000), lastEventMs: stopNumber(events.at(-1)?.time * 1000), eventIdsMatch: events.every(e => e?.id === c.Id) }));
    const proof = await trace.step('PROOF_VALIDATE', () => validateLegacyGatewayStop({ before: c, after: stopped, events, submittedMs, stopOutput,
      writers: ['web','api','worker'].map(n => peers.get(n)) }));
    const file = 'legacy-stop-' + name + '-verified.json';
    await trace.step('PROOF_RECORD', () => record(file, proof));
    acknowledgedGatewayStops.set(c.Id, proof);
    await trace.step('PROOF_FENCE', () => addRecordFence(file));
  } else await trace.step('CLEAN_STOPPED', () => cleanStopped(stopped));
  await trace.step('PEER_COMMIT', () => peers.set(name, stopped));
}
function ownOne(inventory, name) { const a = inventory.containers.filter(c => role(c) === name); safe(a.length === 1); return a[0]; }
export function validateAuditHistory(root) {
  const parent = join(root, STATE, 'llm-deployments');
  if (has(parent)) {
    directory(parent, 0o700); const names = fs.readdirSync(parent);
    safe(names.length < DEPLOYMENT_ACTIVE_LIMIT && names.every(n => /^deploy-[a-f0-9]{32}$/.test(n)));
    for (const n of names) { directory(join(parent, n), 0o700); safe(equal(privateJson(readBounded(join(parent, n, 'complete.json'), 4096, 0o600)), { version: 1, project: PROJECT, preserved: true })); }
  }
  const disk = fs.statfsSync(has(parent) ? parent : join(root, STATE)); safe(disk.bavail * disk.bsize >= 4 * 1024 ** 3);
}
export function validateCurrentAuditHistory(root) {
  validateAuditHistory(root);
  const catalog = captureDeploymentCatalog(root);
  safe(catalog.active.length + catalog.archived.length < DEPLOYMENT_TOTAL_LIMIT);
  catalog.verify();
}
function privateAudit(root) {
  validateCurrentAuditHistory(root);
  const parent = join(root, STATE, 'llm-deployments');
  if (!has(parent)) { fs.mkdirSync(parent, { mode: 0o700 }); syncDirectory(join(root, STATE)); }
  const nonce = crypto.randomBytes(16).toString('hex'), path = join(parent, 'deploy-' + nonce);
  safe(!captureDeploymentCatalog(root).entries.some(e => e.name === 'deploy-' + nonce));
  fs.mkdirSync(path, { mode: 0o700 }); syncDirectory(parent);
  const parentVerify = directoryFence(parent), auditVerify = directoryFence(path);
  return { path, nonce, verify() { parentVerify(); auditVerify(); } };
}

// Reusable four-store bridge for the future CVE owner. Context owns peer/image/
// writer checks; this factory always uses the concrete validated helper/export.
export function createPublicLlmPreservation({ DB, root, lock, audit, helper, verifyState, continued = false, initializedCurrent = false, rebuiltCurrent = false, initExitCurrent = false, admitCurrent = false, apiCurrent = false, rolloutCurrent = false, existingBuildCurrent = false }) {
  safe(typeof DB === 'function' && typeof helper === 'function' && typeof verifyState === 'function');
  safe(resolve(root) === root && lock.path === join(root, STATE, '.operation.lock') &&
    dirname(audit) === join(root, STATE, 'llm-deployments') && /^deploy-[a-f0-9]{32}$/.test(audit.slice(audit.lastIndexOf('/') + 1)));
  checkIgnores(root); lock.verify();
  const auditVerify = directoryFence(audit), parentVerify = directoryFence(dirname(audit));
  safe([continued, initializedCurrent, rebuiltCurrent, initExitCurrent, admitCurrent, apiCurrent, rolloutCurrent, existingBuildCurrent].every(v => typeof v === 'boolean') && [continued, initializedCurrent, rebuiltCurrent, initExitCurrent, admitCurrent, apiCurrent, rolloutCurrent, existingBuildCurrent].filter(Boolean).length <= 1);
  const output = existingBuildCurrent ? join(audit, 'existing-build-current') : rolloutCurrent ? join(audit, 'rollout-current') : apiCurrent ? join(audit, 'api-current') : admitCurrent ? join(audit, 'admit-current') : initExitCurrent ? join(audit, 'init-exit-current') : rebuiltCurrent ? join(audit, 'rebuild-current') : initializedCurrent ? join(audit, 'initialize-current') : continued ? join(audit, 'continued') : audit;
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

// Current-only capture adds an explicit B1 phase. Historical capture/phase lists
// above remain unchanged and cannot authorize a schema transition.
export function createCurrentPublicLlmPreservation({ DB, root, lock, audit, helper, verifyState, migrateSummary = false, summaryRecovery = false }) {
  safe(typeof DB === 'function' && typeof helper === 'function' && typeof verifyState === 'function' && typeof migrateSummary === 'boolean');
  safe(resolve(root) === root && lock.path === join(root, STATE, '.operation.lock') &&
    dirname(audit) === join(root, STATE, 'llm-deployments') && /^deploy-[a-f0-9]{32}$/.test(audit.split('/').at(-1)));
  safe(typeof summaryRecovery === 'boolean' && (!summaryRecovery || migrateSummary && audit.endsWith('/deploy-76eb7a61e0da2e108210bc773b964d35')));
  checkIgnores(root); lock.verify();
  const auditVerify = directoryFence(audit), parentVerify = directoryFence(dirname(audit));
  const destination = summaryRecovery ? join(audit, 'summary-current') : audit, destinationVerify = directoryFence(destination);
  const phases = ['fenced', ...(migrateSummary ? ['post-migration'] : []), 'before-api', 'after-api'];
  let next = 0;
  return async phase => {
    safe(phase === phases[next]); parentVerify(); auditVerify(); destinationVerify(); lock.verify(); await verifyState();
    const dir = join(destination, phase); fs.mkdirSync(dir, { mode: 0o700 }); syncDirectory(destination);
    const present = await helper(phase, 'backup', async (id, d, check, receipt) => {
      safe(receipt.ready === true && typeof receipt.llmPresent === 'boolean');
      for (const group of ['core', ...(receipt.llmPresent ? ['llm'] : [])]) {
        const destination = join(dir, group); fs.mkdirSync(destination, { mode: 0o700 }); syncDirectory(dir);
        const dispatch = request => d(['container', 'exec', id, 'node', '-e', PUBLIC_LLM_EXPORT_PROGRAM, JSON.stringify({ group, request })]);
        // Exact summary recovery retains its original reader/transfer identity.
        const read = summaryRecovery
          ? async request => { await check(); return JSON.parse(await dispatch(request)); }
          : request => readCurrentBackupExport({ request, check, dispatch, phase, group });
        const manifest = await read({ action: 'manifest' }); validateExportManifest(manifest);
        writeExclusive(join(destination, 'private-manifest.json'), JSON.stringify(manifest), 0o600); syncDirectory(destination);
        for (const role of ['auth', 'ledger']) {
          const options = { dir: destination, role, manifest, readChunk: read, verify: check };
          if (summaryRecovery) await transferBackupSnapshot(options);
          else await transferCurrentBackupSnapshot({ ...options, phase, group });
        }
        safe(equal(manifest, await read({ action: 'manifest' }))); syncDirectory(destination);
      }
      return receipt.llmPresent;
    });
    await verifyState(); lock.verify(); parentVerify(); auditVerify();
    const paths = { auth: join(dir, 'core/auth.sqlite'), ledger: join(dir, 'core/ledger.sqlite') };
    // Preserve the frozen summary recovery reader; current normal deployments
    // inspect all four transferred snapshots without SQLite touching the evidence.
    const SnapshotDB = summaryRecovery ? DB : sealedSnapshotDatabase(DB);
    await recoverySqlite(SnapshotDB, fs, crypto, paths, null);
    const core = Object.fromEntries(Object.entries(paths).map(([kind, path]) => [kind, { logicalSha256: currentLlmFingerprint(SnapshotDB, fs, crypto, path, kind) }]));
    let llm = null, empty = false, historyVersion = null;
    if (present) {
      const history = join(dir, 'llm/auth.sqlite'), quota = join(dir, 'llm/ledger.sqlite');
      llm = { history: currentLlmFingerprint(SnapshotDB, fs, crypto, history, 'history'), quota: currentLlmFingerprint(SnapshotDB, fs, crypto, quota, 'quota') };
      const db = new SnapshotDB(history, { readonly: true, fileMustExist: true });
      try { historyVersion = currentHistorySchema(db); } finally { db.close(); }
      if (phase === 'before-api') try {
        currentLlmFingerprint(SnapshotDB, fs, crypto, history, 'history', true); currentLlmFingerprint(SnapshotDB, fs, crypto, quota, 'quota', true);
        // Fresh bootstrap has no previous LLM baseline: opaque tables must not
        // masquerade as empty native stores, including in schema v4.
        const h = new SnapshotDB(history, { readonly: true, fileMustExist: true });
        try {
          safe(equal(h.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").pluck().all(),
            ['history_completion_space', 'history_head', 'history_meta', ...(historyVersion === 4 ? ['llm_summary'] : [])]));
          safe(h.prepare("SELECT count(*) n FROM sqlite_master WHERE type IN ('trigger','view')").get().n === 0);
        } finally { h.close(); }
        assertAdmissionStoreEmpty(SnapshotDB, quota, 'quota'); empty = true;
      } catch { /* Existing state is compared in full; nothing is erased. */ }
    }
    next++; return { core, llm, empty, historyVersion };
  };
}

// The only permitted inequality: exact v3->v4 schema addition, empty new table,
// identical old schema/typed rows (including rowid, BLOBs and incarnation).
// No table is omitted from normal fingerprints or from subsequent equality.
export function verifyPublicLlmSummaryMigration({ DB, before, after, beforeDirectory, afterDirectory }) {
  safe(before.historyVersion === 3 && after.historyVersion === 4 && before.llm && after.llm);
  safe(equal(before.core, after.core) && before.llm.quota === after.llm.quota);
  const verifySnapshot = (snapshot, dir) => {
    for (const [kind, relative] of [['auth', 'core/auth.sqlite'], ['ledger', 'core/ledger.sqlite'], ['history', 'llm/auth.sqlite'], ['quota', 'llm/ledger.sqlite']])
      safe(currentLlmFingerprint(DB, fs, crypto, join(dir, relative), kind) === (kind === 'auth' || kind === 'ledger' ? snapshot.core[kind].logicalSha256 : snapshot.llm[kind]));
  };
  verifySnapshot(before, beforeDirectory); verifySnapshot(after, afterDirectory);
  const paths = [join(beforeDirectory, 'llm/auth.sqlite'), join(afterDirectory, 'llm/auth.sqlite')];
  const guards = paths.map(sourceFileFence), stores = [];
  try {
    for (const path of paths) {
      for (const suffix of ['-journal', '-wal', '-shm']) safe(!has(path + suffix));
      const db = new DB(path, { readonly: true, fileMustExist: true, timeout: 2000 }); stores.push(db);
      db.defaultSafeIntegers(true); db.pragma('query_only=ON'); db.exec('BEGIN');
    }
    const [old, next] = stores; safe(currentHistorySchema(old) === 3 && currentHistorySchema(next) === 4);
    safe(next.prepare('SELECT count(*) n FROM llm_summary').get().n === 0n);
    const sql = 'SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name,tbl_name,sql';
    const oldSchema = old.prepare(sql).raw().all(), newSchema = next.prepare(sql).raw().all();
    // currentHistorySchema has already proved these EXACT two added objects.
    safe(newSchema.length === oldSchema.length + 2 && equal(oldSchema, newSchema.filter(r => r[2] !== 'llm_summary')));
    let bytes = 0, rows = 0;
    for (const [, table] of oldSchema.filter(r => r[0] === 'table')) {
      safe(/^[a-z_][a-z0-9_]*$/.test(table));
      const query = `SELECT rowid,* FROM "${table}" ORDER BY rowid`;
      const a = old.prepare(query).raw().iterate(), b = next.prepare(query).raw().iterate();
      try {
        for (;;) {
          const x = a.next(), y = b.next(); safe(x.done === y.done); if (x.done) break;
          const row = sqliteTypedRow(x.value); bytes += Buffer.byteLength(row); safe(bytes <= 256 * 1024 ** 2 && ++rows <= 250000);
          safe(row === sqliteTypedRow(y.value));
        }
      } finally { a.return?.(); b.return?.(); }
    }
    for (const db of stores) db.exec('ROLLBACK');
    guards.forEach(g => g.verify());
  } finally { stores.forEach(db => db.close()); }
  verifySnapshot(before, beforeDirectory); verifySnapshot(after, afterDirectory);
  return { version: 1, migration: 'history-summary-v3-to-v4', from: 3, to: 4, oldStoresPreserved: true, newTableEmpty: true };
}

export async function executeCurrentPublicLlmMaintenance(ops, { migrateSummary = false, originalBaseline = null } = {}) {
  safe(typeof migrateSummary === 'boolean');
  for (const key of ['preflight', 'intent', 'stop', 'drain', 'snapshot', 'candidate', 'initialize', 'startRetained', 'up', 'ready', 'publish', 'complete', 'validateBaseline', ...(migrateSummary ? ['migrateSummary', 'verifyMigration'] : [])]) safe(typeof ops[key] === 'function');
  safe(originalBaseline === null || migrateSummary && originalBaseline.historyVersion === 3 && originalBaseline.llm !== null);
  await ops.preflight(); await ops.intent();
  if (originalBaseline === null) { await ops.stop('web'); await ops.stop('api'); await ops.drain(); await ops.stop('worker'); }
  const original = await ops.snapshot('fenced');
  if (originalBaseline !== null) safe(equal(original, originalBaseline));
  await ops.validateBaseline(original);
  await ops.candidate();
  let baseline = original;
  if (migrateSummary) {
    safe(original.historyVersion === 3 && original.llm !== null);
    await ops.migrateSummary();
    const migrated = await ops.snapshot('post-migration');
    await ops.verifyMigration(original, migrated); baseline = migrated;
  }
  await ops.initialize(baseline.llm === null);
  await ops.startRetained(); await ops.up('llm-egress'); await ops.up('worker'); await ops.ready('worker');
  const initialized = await ops.snapshot('before-api');
  safe(equal(baseline.core, initialized.core));
  if (baseline.llm === null) safe(initialized.llm !== null && initialized.empty === true && initialized.historyVersion === 4);
  else safe(equal(baseline.llm, initialized.llm) && baseline.historyVersion === initialized.historyVersion);
  await ops.up('api'); await ops.ready('api');
  const final = await ops.snapshot('after-api');
  safe(equal(initialized.core, final.core) && equal(initialized.llm, final.llm) && initialized.historyVersion === final.historyVersion);
  await ops.publish(); await ops.up('web'); await ops.ready('web'); await ops.complete();
  return { outcome: 'ready', generationVerified: false, historyMigrated: migrateSummary };
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
    'preflight-history-schema': 'PUBLIC_HISTORY_SCHEMA_OR_MIGRATION_ACK_REJECTED',
  'build-source': 'PUBLIC_BUILD_SOURCE_REJECTED', 'build-config': 'PUBLIC_BUILD_CONFIG_REJECTED', 'build-pins': 'PUBLIC_BUILD_PINS_REJECTED',
  'build-retained-images': 'PUBLIC_RETAINED_IMAGE_METADATA_REJECTED',
  'build-image-retention': 'PUBLIC_IMAGE_RETENTION_REJECTED',
  ...Object.fromEntries(['api', 'worker', 'web', 'llm-egress'].map(n => ['build-submit-' + n, 'PUBLIC_BUILD_SUBMISSION_REJECTED'])),
  ...Object.fromEntries(['auth-volume-init', 'scan-volume-init', 'api', 'worker', 'web', 'egress', 'llm-egress'].map(n => ['build-image-' + n, 'PUBLIC_BUILD_IMAGE_REJECTED'])),
  'continue-check': 'PUBLIC_CONTINUATION_CHECK_REJECTED',
});

const publicLlmConfigIntent = migration => JSON.stringify({ version: 1, project: PROJECT,
  command: migration === 'timeout' ? 'public-llm-config-30-to-90' : migration === 'nvidia' ? 'public-llm-config-xing90-to-nvidia-v1' : migration === 'dots' ? 'public-llm-config-nvidia90-to-dots-v1' : 'public-llm-config-dots2048-to-report4096-v1', lifecycle: false });
const PUBLIC_LLM_CONFIG_PYTHON = '/usr/bin/python3';
function publicLlmPythonFence() {
  // Fixed OS-managed interpreter, never PATH discovery or a user-writable shim.
  const stamp = s => [s.dev, s.ino, s.uid, s.mode, s.nlink, s.size, s.mtimeMs, s.ctimeMs];
  const paths = ['/usr', '/usr/bin', PUBLIC_LLM_CONFIG_PYTHON].map(path => {
    const s = fs.lstatSync(path);
    safe((path === PUBLIC_LLM_CONFIG_PYTHON ? s.isFile() : s.isDirectory()) && s.uid === 0 && !(s.mode & 0o022) && fs.realpathSync(path) === path);
    return { path, identity: stamp(s) };
  });
  fs.accessSync(PUBLIC_LLM_CONFIG_PYTHON, fs.constants.X_OK);
  return () => { for (const p of paths) safe(equal(stamp(fs.lstatSync(p.path)), p.identity)); };
}
// Config-only coordinator entry: no Docker, JWT, database or credential access.
export function upgradePublicLlmTimeout(options) { return upgradePublicLlmConfig('timeout', options); }
export function migratePublicLlmNvidia(options) { return upgradePublicLlmConfig('nvidia', options); }
export function migratePublicLlmDots(options) { return upgradePublicLlmConfig('dots', options); }
export function migratePublicLlmReport4k(options) { return upgradePublicLlmConfig('report4k', options); }
function upgradePublicLlmConfig(migration, { root = ROOT, home = homedir(), log = console.log, spawn = spawnSync } = {}) {
  safe(resolve(root) === root && fs.realpathSync(root) === root &&
    !resolve(home, '.local/state/diplom-public-images/llm').startsWith(root + '/'));
  const verifyPython = publicLlmPythonFence();
  const sources = ['public-llm-stand.mjs', 'public-llm-config.py'].map(n => sourceFileFence(join(root, 'scripts', n)));
  const lock = acquireLock(root), intentPath = join(lock.path, 'mutation.json');
  let hold = false, failed = false, fd, writer, intentFd, intentIdentity;
  try {
    lock.verify(); sources.forEach(s => s.verify());
    validateAuditHistory(root);
    safe(readPublicLlmBinding(root)?.version === (migration === 'timeout' ? 1 : migration === 'nvidia' ? 2 : migration === 'dots' ? 3 : 4));
    const binding = ['llm-profile.json', 'compose.llm-env.json'].map(n => fileFence(join(root, STATE, n), 16384, 0o600));
    const fence = () => { lock.verify(); verifyPython(); sources.forEach(s => s.verify()); binding.forEach(f => f.verify()); };
    fd = fs.openSync(lock.path, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    const opened = fs.fstatSync(fd), current = fs.lstatSync(lock.path);
    safe(opened.dev === current.dev && opened.ino === current.ino);
    const call = (phase, eligibility) => {
      fence();
      if (phase === 'commit') hold = true;
      const result = spawn(PUBLIC_LLM_CONFIG_PYTHON, ['-I', '-S', '-B', join(root, 'scripts/public-llm-config.py'), `--coordinator-${phase}-${migration}`], {
        cwd: root, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', HOME: home, LANG: 'C', TZ: 'UTC' }, timeout: 10000, maxBuffer: 4096,
        stdio: ['pipe', 'pipe', 'pipe', fd, ...(phase === 'commit' ? [intentFd] : [])], encoding: 'utf8',
        input: JSON.stringify({ sources: Object.fromEntries(sources.map(s => [s.path.split('/').at(-1), s.snapshot.digest])),
          ...(phase === 'commit' ? { eligibility } : {}) }),
      });
      fence(); safe(!result.error && result.status === 0 && result.signal === null);
      return result.stdout;
    };
    // A check child has no mutation authority. Deterministic ineligibility leaves no intent/HOLD.
    const eligibility = privateJson(call('check'));
    safe(equal(Object.keys(eligibility).sort(), ['config', 'directory', 'eligible', 'version']) && eligibility.version === 1 && eligibility.eligible === true &&
      [['directory', 4], ['config', 8]].every(([k, n]) => Array.isArray(eligibility[k]) && eligibility[k].length === n && eligibility[k].every(v => typeof v === 'string' && /^[0-9]+$/.test(v))));
    fence(); safe(equal(fs.readdirSync(lock.path), []));
    writer = fs.openSync(intentPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    intentIdentity = fs.fstatSync(writer); fs.fchmodSync(writer, 0o600);
    fs.writeFileSync(writer, publicLlmConfigIntent(migration)); fs.fsyncSync(writer); syncDirectory(lock.path);
    const intent = fileFence(intentPath, 1024, 0o600);
    intentFd = fs.openSync(intentPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    safe(fs.fstatSync(intentFd).ino === intentIdentity.ino && fs.fstatSync(intentFd).dev === intentIdentity.dev);
    fence(); intent.verify(); safe(equal(fs.readdirSync(lock.path), ['mutation.json']));
    // From dispatch onwards a child can create backups or commit: every failure is HOLD.
    call('commit', eligibility); intent.verify(); hold = false;
  } catch {
    failed = true;
  } finally {
    if (!hold) {
      try {
        lock.verify();
        if (intentIdentity) {
          safe(equal(fs.readdirSync(lock.path), ['mutation.json']));
          const s = fs.lstatSync(intentPath);
          safe(s.isFile() && s.nlink === 1 && s.dev === intentIdentity.dev && s.ino === intentIdentity.ino && s.uid === process.getuid());
          fs.unlinkSync(intentPath); syncDirectory(lock.path);
        }
        safe(equal(fs.readdirSync(lock.path), [])); lock.release();
      } catch { hold = true; failed = true; }
    }
    for (const value of [intentFd, writer, fd]) if (value !== undefined) fs.closeSync(value);
  }
  if (failed) throw Error(`PUBLIC LLM config upgrade ${hold ? 'HOLD' : 'refused'}; no automatic retry, cleanup or rollback.`);
  log(`Public nonsecret LLM config ${migration === 'timeout' ? 'upgraded 30s to 90s' : migration === 'nvidia' ? 'migrated Xing90 to NVIDIA non-ZDR/no-training' : migration === 'dots' ? 'migrated NVIDIA90 to Dots non-ZDR/no-training (prompts retained)' : 'migrated Dots2048 to report4096 non-ZDR/no-training (prompts retained)'}; original backup retained. Runtime unchanged; ordinary reviewed up --build required.`);
  return { configUpgraded: true, lifecycle: false };
}

// v6 implementation lives in this already-audited module: no hidden dynamic
// loader or expanded frozen recovery import allowlist. Public facade re-exports it.
const providerKey = k => k.startsWith('OPENAI_') || k.startsWith('LLM_') || k.startsWith('OPENROUTER_');
const normalizedService = s => {
  const x = structuredClone(s); if (x.entrypoint === null) delete x.entrypoint;
  for (const d of Object.values(x.depends_on ?? {})) { if (d.required === true) delete d.required; if (d.restart === false) delete d.restart; }
  for (const [n, v] of Object.entries(x.networks ?? {})) if (equal(v, {}) || equal(v, { priority: 0 })) x.networks[n] = null;
  for (const k of ['mem_limit', 'memswap_limit']) if (k in x) x[k] = String(x[k]);
  return x;
};
const normalizedNetwork = n => {
  const x = structuredClone(n); if (x.driver === 'bridge') delete x.driver; if (x.internal === false) delete x.internal; if (equal(x.ipam, {})) delete x.ipam;
  return x;
};
export function openAiStaticOverlay(root) {
  const gateway = structuredClone(publicLlmStaticOverlay(root).services['llm-egress']);
  gateway.image = `${PROJECT}-openai-egress:local`; gateway.build.dockerfile = 'server/deploy/gateway/openai.Dockerfile';
  gateway.command = [...OPENAI_DEPLOYMENT.gatewayCommand]; gateway.networks = { openai_internal: null, openai_uplink: null };
  return { services: { api: { build: { dockerfile: 'server/deploy/openai-api.Dockerfile' },
      ulimits: { core: { soft: 0, hard: 0 } }, networks: { openai_internal: null },
    depends_on: { 'openai-egress': { condition: 'service_started' } } }, 'openai-egress': gateway },
    networks: Object.fromEntries(OPENAI_DEPLOYMENT.networks.map(n => [n, { name: `${PROJECT}_${n}`, labels: { [LABEL]: 'v1' }, ...(n.endsWith('_internal') ? { internal: true } : {}) }])) };
}
function applyOpenAiOperations(model, selection) {
  if (!selection.operations) return model;
  safe(selection.operations === PUBLIC_IMAGE_OPERATIONS);
  for (const name of PUBLIC_IMAGE_OPERATION_ROLES) {
    model.services[name] ??= {};
    model.services[name].logging = structuredClone(PUBLIC_IMAGE_LOGGING);
  }
  model.services.egress.command = [...PUBLIC_IMAGE_EGRESS_COMMAND];
  return model;
}
export function openAiEnvironmentOverlay(selection) {
  const s = validateOpenAiDeployment(selection), prior = publicLlmEnvironmentOverlay(s.openrouter), overlay = openAiStaticOverlay('../..');
  return applyOpenAiOperations({ services: { ...prior.services, ...overlay.services, api: { ...prior.services.api, ...overlay.services.api,
    environment: openAiEnvironment(s, publicLlmSelectedEnvironment(s.openrouter)),
    ...(s.credentialVolume ? { entrypoint: [...OPENAI_DEPLOYMENT.entrypoint], command: [...OPENAI_DEPLOYMENT.command] } : {}),
    ...(s.credentialVolume ? { volumes: [...(prior.services.api.volumes ?? []), {
      type: 'volume', source: OPENAI_DEPLOYMENT.volumeKey, target: OPENAI_DEPLOYMENT.mount, read_only: true, volume: { nocopy: true },
    }] } : {}) } }, networks: overlay.networks,
    ...((prior.volumes || s.credentialVolume) ? { volumes: { ...prior.volumes,
      ...(s.credentialVolume ? { [OPENAI_DEPLOYMENT.volumeKey]: { name: s.credentialVolume, external: true } } : {}) } } : {}) }, s);
}
export function expectedOpenAiConfig(root, cve, selection) {
  const s = validateOpenAiDeployment(selection), model = expectedPublicLlmConfig(root, cve, s.openrouter);
  const overlay = openAiEnvironmentOverlay(s), topology = openAiStaticOverlay(root);

  for (const k of Object.keys(model.services.api.environment).filter(providerKey)) delete model.services.api.environment[k];
  Object.assign(model.services.api.environment, overlay.services.api.environment);
  model.services.api.build.dockerfile = 'server/deploy/openai-api.Dockerfile';
  model.services.api.ulimits = { core: { soft: 0, hard: 0 } };
  if (s.credentialVolume) { model.services.api.entrypoint = [...OPENAI_DEPLOYMENT.entrypoint]; model.services.api.command = [...OPENAI_DEPLOYMENT.command]; }
  Object.assign(model.services.api.networks, topology.services.api.networks);
  Object.assign(model.services.api.depends_on, topology.services.api.depends_on);
  if (s.credentialVolume) model.services.api.volumes.push(overlay.services.api.volumes.at(-1));
  model.services['openai-egress'] = topology.services['openai-egress']; Object.assign(model.networks, topology.networks);
  Object.assign(model.volumes, overlay.volumes); return applyOpenAiOperations(model, s);
}
export function validateOpenAiConfig(value, root, cve, selection, images) {
  const s = validateOpenAiDeployment(selection), expected = expectedOpenAiConfig(root, cve, s), copy = structuredClone(value);
  for (const group of ['services', 'networks', 'volumes']) safe(equal(Object.keys(copy[group] ?? {}).sort(), Object.keys(expected[group]).sort()));
  if (s.operations) {
    for (const name of PUBLIC_IMAGE_OPERATION_ROLES) {
      safe(equal(copy.services[name].logging, PUBLIC_IMAGE_LOGGING));
      delete copy.services[name].logging; delete expected.services[name].logging;
    }
    safe(equal(copy.services.egress.command, PUBLIC_IMAGE_EGRESS_COMMAND));
    copy.services.egress.command = ['python', '-I', 'proxy.py'];
    expected.services.egress.command = copy.services.egress.command;
  }
  if (images) {
    safe(equal(Object.keys(images).sort(), Object.keys(expected.services).sort()));
    for (const [n, image] of Object.entries(images)) { validatePublicLlmImage(image, n); expected.services[n].image = image.Id; }
  }
  safe(equal(normalizedService(copy.services['openai-egress']), expected.services['openai-egress'])); delete copy.services['openai-egress'];
  for (const n of OPENAI_DEPLOYMENT.networks) { safe(equal(normalizedNetwork(copy.networks[n]), expected.networks[n])); delete copy.networks[n]; }
  const api = copy.services.api, legacy = expectedPublicLlmConfig(root, cve, s.openrouter).services.api;
  safe(equal(Object.fromEntries(Object.entries(api.environment ?? {}).filter(([k]) => providerKey(k))), publicLlmSelectedEnvironment(s)));
  for (const k of Object.keys(api.environment).filter(providerKey)) delete api.environment[k];
  Object.assign(api.environment, publicLlmSelectedEnvironment(s.openrouter));
  safe(api.build.dockerfile === 'server/deploy/openai-api.Dockerfile'); api.build.dockerfile = legacy.build.dockerfile;
  // Compose omits both zero-valued limits when rendering JSON. Accept only
  // that exact representation; source overlays and container limits stay explicit.
  safe(equal(api.ulimits, { core: {} }) || equal(api.ulimits, { core: { soft: 0, hard: 0 } })); delete api.ulimits;
  if (s.credentialVolume) { safe(equal(api.entrypoint, OPENAI_DEPLOYMENT.entrypoint) && equal(api.command, OPENAI_DEPLOYMENT.command)); api.entrypoint = legacy.entrypoint; api.command = legacy.command; }
  safe(normalizedService(api).networks.openai_internal === null); delete api.networks.openai_internal;
  safe(equal(normalizedService(api).depends_on['openai-egress'], { condition: 'service_started' })); delete api.depends_on['openai-egress'];
  if (s.credentialVolume) {
    safe(equal(copy.volumes[OPENAI_DEPLOYMENT.volumeKey], expected.volumes[OPENAI_DEPLOYMENT.volumeKey])); delete copy.volumes[OPENAI_DEPLOYMENT.volumeKey];
    safe(equal(api.volumes.filter(m => m.target === OPENAI_DEPLOYMENT.mount), expected.services.api.volumes.filter(m => m.target === OPENAI_DEPLOYMENT.mount)));
    api.volumes = api.volumes.filter(m => m.target !== OPENAI_DEPLOYMENT.mount);
  }
  validatePublicLlmConfig(copy, root, cve, s.openrouter, images && Object.fromEntries(Object.entries(images).filter(([n]) => n !== 'openai-egress')));
}
// Validates every extra field before removing it; unknown fields survive to the base validator.
export function stripOpenAiContainer(item, name, spec, image, selection) {
  const s = validateOpenAiDeployment(selection), c = structuredClone(item), im = structuredClone(image), model = structuredClone(spec);
  assertNoOpenAiDockerSecret(c.Config);
  if (s.operations && PUBLIC_IMAGE_OPERATION_ROLES.includes(name)) {
    safe(equal(model.logging, PUBLIC_IMAGE_LOGGING) &&
      equal(c.HostConfig.LogConfig, { Type: PUBLIC_IMAGE_LOGGING.driver, Config: PUBLIC_IMAGE_LOGGING.options }));
    delete model.logging;
    c.HostConfig.LogConfig = { Type: 'json-file', Config: {} };
    if (name === 'egress') {
      safe(equal(model.command, PUBLIC_IMAGE_EGRESS_COMMAND) && equal(c.Config.Cmd, PUBLIC_IMAGE_EGRESS_COMMAND) &&
        c.Path === PUBLIC_IMAGE_EGRESS_COMMAND[0] && equal(c.Args, PUBLIC_IMAGE_EGRESS_COMMAND.slice(1)));
      model.command = ['python', '-I', 'proxy.py']; c.Config.Cmd = model.command;
      c.Path = 'python'; c.Args = model.command.slice(1);
    }
  }
  if (name === 'api') {
    const env = envMap(c.Config.Env);
    safe(equal(Object.fromEntries(Object.entries(env).filter(([k]) => providerKey(k))), publicLlmSelectedEnvironment(s)));
    for (const k of Object.keys(env).filter(providerKey)) delete env[k]; Object.assign(env, publicLlmSelectedEnvironment(s.openrouter));
    c.Config.Env = Object.entries(env).map(([k, v]) => `${k}=${v}`);
    safe(model.build.dockerfile === 'server/deploy/openai-api.Dockerfile'); model.build.dockerfile = 'server/deploy/api.Dockerfile';
    safe(equal(model.ulimits, { core: { soft: 0, hard: 0 } }) && equal(c.HostConfig.Ulimits, [{ Name: 'core', Soft: 0, Hard: 0 }]));
    delete model.ulimits; delete c.HostConfig.Ulimits;
    if (s.credentialVolume) {
      const command = [...OPENAI_DEPLOYMENT.entrypoint, ...OPENAI_DEPLOYMENT.command];
      safe(equal(c.Config.Entrypoint, OPENAI_DEPLOYMENT.entrypoint) && equal(model.entrypoint, OPENAI_DEPLOYMENT.entrypoint) &&
        equal(c.Config.Cmd, OPENAI_DEPLOYMENT.command) && equal(model.command, OPENAI_DEPLOYMENT.command) && c.Path === command[0] && equal(c.Args, command.slice(1)));
      c.Config.Entrypoint = ['docker-entrypoint.sh']; model.entrypoint = c.Config.Entrypoint;
      c.Path = 'docker-entrypoint.sh'; c.Args = [...OPENAI_DEPLOYMENT.command];
    }
    for (const k of Object.keys(model.environment).filter(providerKey)) delete model.environment[k]; Object.assign(model.environment, publicLlmSelectedEnvironment(s.openrouter));
    safe(Object.hasOwn(c.NetworkSettings.Networks, `${PROJECT}_openai_internal`)); delete c.NetworkSettings.Networks[`${PROJECT}_openai_internal`];
    if (c.HostConfig.NetworkMode === `${PROJECT}_openai_internal`) c.HostConfig.NetworkMode = `${PROJECT}_auth_internal`;
    safe(normalizedService(model).networks.openai_internal === null &&
      equal(normalizedService(model).depends_on['openai-egress'], { condition: 'service_started' }));
    delete model.networks.openai_internal; delete model.depends_on['openai-egress'];
    if (s.credentialVolume) {
      const declarations = c.HostConfig.Mounts.filter(m => m.Target === OPENAI_DEPLOYMENT.mount), mounts = c.Mounts.filter(m => m.Destination === OPENAI_DEPLOYMENT.mount);
      safe(declarations.length === 1 && mounts.length === 1); const d = declarations[0], m = mounts[0];
      safe(d.Type === 'volume' && d.Source === s.credentialVolume && d.ReadOnly === true &&
        (equal(d.VolumeOptions, { NoCopy: true }) || equal(d.VolumeOptions, { NoCopy: true, DriverConfig: {} })) &&
        Object.keys(d).every(k => ['Type', 'Source', 'Target', 'ReadOnly', 'VolumeOptions'].includes(k)) &&
        m.Type === 'volume' && m.Name === s.credentialVolume && m.RW === false && !m.SubPath && (!m.Propagation || m.Propagation === 'rprivate'));
      c.HostConfig.Mounts = c.HostConfig.Mounts.filter(m => m.Target !== OPENAI_DEPLOYMENT.mount); c.Mounts = c.Mounts.filter(m => m.Destination !== OPENAI_DEPLOYMENT.mount);
      model.volumes = model.volumes.filter(m => m.target !== OPENAI_DEPLOYMENT.mount);
    }
  }
  if (name === 'openai-egress') {
    safe(c.Name === `/${PROJECT}-openai-egress-1` && role(c) === name && owned(c.Config.Labels));
    safe(equal(c.Config.Cmd, OPENAI_DEPLOYMENT.gatewayCommand) && equal(model.command, OPENAI_DEPLOYMENT.gatewayCommand) && c.Path === 'python' && equal(c.Args, OPENAI_DEPLOYMENT.gatewayCommand.slice(1)));
    validatePublicLlmImage(im, name);
    safe(equal(Object.keys(c.NetworkSettings.Networks).sort(), OPENAI_DEPLOYMENT.networks.map(n => `${PROJECT}_${n}`).sort()));
    const map = { [`${PROJECT}_openai_internal`]: `${PROJECT}_llm_internal`, [`${PROJECT}_openai_uplink`]: `${PROJECT}_llm_uplink` };
    safe(Object.hasOwn(map, c.HostConfig.NetworkMode)); c.HostConfig.NetworkMode = map[c.HostConfig.NetworkMode];
    c.NetworkSettings.Networks = Object.fromEntries(Object.entries(c.NetworkSettings.Networks).map(([k, v]) => [map[k], v]));
    c.Name = `/${PROJECT}-llm-egress-1`; c.Config.Labels['com.docker.compose.service'] = 'llm-egress';
    c.Config.Cmd = ['python', '-I', 'openrouter.py', ...(s.openrouter.version >= 2 ? ['--public-90s'] : [])];
    im.Config.Cmd = ['python', '-I', 'openrouter.py']; model.command = c.Config.Cmd; c.Path = 'python'; c.Args = c.Config.Cmd.slice(1);
    name = 'llm-egress';
  }
  return { item: c, name, spec: model, image: im };
}
export async function inspectOpenAiNamespace(run, options, root, cve, selection, extra) {
  const s = validateOpenAiDeployment(selection), model = expectedOpenAiConfig(root, cve, s);
  const one = async (kind, id) => { const rows = JSON.parse(await run([kind, 'inspect', id], options)); safe(rows.length === 1); return rows[0]; };
  const gateway = await one('container', `${PROJECT}-openai-egress-1`), image = await one('image', gateway.Image);
  validatePublicLlmContainer(gateway, 'openai-egress', model.services['openai-egress'], image, model, extra, s);
  const api = await one('container', `${PROJECT}-api-1`), apiImage = await one('image', api.Image);
  validatePublicLlmContainer(api, 'api', model.services.api, apiImage, model, extra, s);
  const networks = [];
  for (const name of OPENAI_DEPLOYMENT.networks) {
    const n = await one('network', `${PROJECT}_${name}`);
    safe(n.Name === `${PROJECT}_${name}` && owned(n.Labels) && n.Driver === 'bridge' && Boolean(n.Internal) === name.endsWith('_internal') &&
      !n.Attachable && !n.Ingress && !n.EnableIPv6 && equal(n.Options ?? {}, {}) && (!n.IPAM || n.IPAM.Driver === 'default' && equal(n.IPAM.Options ?? {}, {})));
    networks.push(n);
  }
  let volume;
  if (s.credentialVolume) {
    volume = await one('volume', s.credentialVolume); validateOpenAiVolume(volume, s);
    const ids = (await run(['container', 'ls', '--all', '--filter', `volume=${s.credentialVolume}`, '--format', '{{.ID}}', '--no-trunc'], options)).trim().split('\n').filter(Boolean);
    safe(equal(ids, [api.Id])); const m = api.Mounts.find(m => m.Destination === OPENAI_DEPLOYMENT.mount);
    safe(m.Source === volume.Mountpoint && m.Driver === 'local');
  }
  let observedTag = false;
  const originals = new Map([['api', api]]);
  const wrapped = async (args, opts) => {
    const text = await run(args, opts);
    if (args[1] === 'ls' && ['container', 'network'].includes(args[0])) {
      const remove = args[0] === 'container' ? [`${PROJECT}-openai-egress-1`] : OPENAI_DEPLOYMENT.networks.map(n => `${PROJECT}_${n}`);
      return text.split('\n').filter(row => !remove.includes(row.split('\t')[0])).join('\n');
    }
    if (args[0] === 'image' && args[1] === 'ls') {
      const tag = `${PROJECT}-openai-egress:local`;
      if (text.split('\n').includes(tag)) { validatePublicLlmImage(await one('image', tag), 'openai-egress'); observedTag = true; }
      return text.split('\n').filter(row => row !== tag).join('\n');
    }
    if (args[0] === 'container' && args[1] === 'inspect') {
      const rows = JSON.parse(text); safe(rows.length === 1);
      if (role(rows[0]) === 'api') {
        safe(control(rows[0]) === control(api) && equal(epoch(rows[0]), epoch(api)));
        validatePublicLlmContainer(rows[0], 'api', model.services.api, apiImage, model, extra, s);
        return JSON.stringify([stripOpenAiContainer(rows[0], 'api', model.services.api, apiImage, s).item]);
      }
      const name = role(rows[0]);
      if (s.operations && PUBLIC_IMAGE_OPERATION_ROLES.includes(name)) {
        const previous = originals.get(name);
        if (previous) safe(control(previous) === control(rows[0]) && equal(epoch(previous), epoch(rows[0])));
        const im = extra.images?.[name] ?? await one('image', rows[0].Image);
        validatePublicLlmContainer(rows[0], name, model.services[name], im, model, extra, s);
        originals.set(name, rows[0]);
        return JSON.stringify([stripOpenAiContainer(rows[0], name, model.services[name], im, s).item]);
      }
    }
    return text;
  };
  const legacyImages = extra.images && Object.fromEntries(Object.entries(extra.images).filter(([n]) => n !== 'openai-egress'));
  const out = await inspectPublicLlmNamespace(wrapped, options, root, cve, s.openrouter, { ...extra, images: legacyImages });
  out.containers = out.containers.map(c => originals.get(role(c)) ?? c); out.containers.push(gateway); out.networks.push(...networks);
  if (volume) out.volumes.push(volume);
  if (observedTag) out.images.push(`${PROJECT}-openai-egress:local`);
  for (const n of networks) {
    const members = out.containers.filter(c => c.State.Running && Object.hasOwn(c.NetworkSettings.Networks, n.Name));
    safe(equal(Object.keys(n.Containers ?? {}).sort(), members.map(c => c.Id).sort()));
    safe(members.every(c => role(c) === 'openai-egress' || n.Internal && role(c) === 'api'));
  }
  return out;
}

// v7 replaces the historical gateway SLOT, not the provider identity. Its own
// descriptor and guards are checked before projecting only common base invariants.
const moduleApiProviderKey = key => providerKey(key) || key.startsWith('MODULEAPI_') || key.startsWith('MODULE_API_');
const moduleApiAlias = 'moduleapi-egress';
const moduleApiSlot = 'openai-egress';
function normalizedModuleApiService(service) {
  const copy = normalizedService(service);
  for (const network of Object.values(copy.networks ?? {})) {
    if (network && typeof network === 'object' && network.priority === 0) delete network.priority;
  }
  return copy;
}
export function moduleApiStaticOverlay(root) {
  const gateway = structuredClone(publicLlmStaticOverlay(root).services['llm-egress']);
  gateway.image = `${PROJECT}-${moduleApiSlot}:local`;
  gateway.build.dockerfile = 'server/deploy/gateway/moduleapi.Dockerfile';
  gateway.command = [...MODULEAPI_SLOT_DEPLOYMENT.gatewayCommand];
  gateway.networks = { openai_internal: { aliases: [moduleApiAlias] }, openai_uplink: null };
  return { services: { api: { build: { dockerfile: 'server/deploy/moduleapi-api.Dockerfile' },
    ulimits: { core: { soft: 0, hard: 0 } }, networks: { openai_internal: null },
    depends_on: { [moduleApiSlot]: { condition: 'service_started' } } }, [moduleApiSlot]: gateway },
    networks: Object.fromEntries(MODULEAPI_SLOT_DEPLOYMENT.networks.map(name => [name, {
      name: `${PROJECT}_${name}`, labels: { [LABEL]: 'v1' }, ...(name.endsWith('_internal') ? { internal: true } : {}),
    }])) };
}
export function moduleApiEnvironmentOverlay(selection) {
  const s = validateModuleApiDeployment(selection), prior = publicLlmEnvironmentOverlay(s.openrouter), topology = moduleApiStaticOverlay('../..');
  return applyOpenAiOperations({ services: { ...prior.services, ...topology.services, api: {
    ...prior.services.api, ...topology.services.api,
    environment: moduleApiEnvironment(s, publicLlmSelectedEnvironment(s.openrouter)),
    ...(s.credentialVolume ? { entrypoint: [...MODULEAPI_SLOT_DEPLOYMENT.entrypoint], command: [...MODULEAPI_SLOT_DEPLOYMENT.command] } : {}),
    volumes: [...(prior.services.api.volumes ?? []), ...(s.credentialVolume ? [{ type: 'volume', source: MODULEAPI_SLOT_DEPLOYMENT.volumeKey,
      target: MODULEAPI_SLOT_DEPLOYMENT.mount, read_only: true, volume: { nocopy: true } }] : [])],
  } }, networks: topology.networks, volumes: { ...prior.volumes,
    ...(s.openai.credentialVolume ? { [OPENAI_DEPLOYMENT.volumeKey]: { name: s.openai.credentialVolume, external: true } } : {}),
    ...(s.credentialVolume ? { [MODULEAPI_SLOT_DEPLOYMENT.volumeKey]: { name: s.credentialVolume, external: true } } : {}),
  } }, s);
}
export function expectedModuleApiConfig(root, cve, selection) {
  const s = validateModuleApiDeployment(selection), model = expectedPublicLlmConfig(root, cve, s.openrouter);
  const overlay = moduleApiEnvironmentOverlay(s), topology = moduleApiStaticOverlay(root);
  for (const key of Object.keys(model.services.api.environment).filter(moduleApiProviderKey)) delete model.services.api.environment[key];
  Object.assign(model.services.api.environment, overlay.services.api.environment);
  model.services.api.build.dockerfile = 'server/deploy/moduleapi-api.Dockerfile';
  model.services.api.ulimits = { core: { soft: 0, hard: 0 } };
  if (s.credentialVolume) { model.services.api.entrypoint = [...MODULEAPI_SLOT_DEPLOYMENT.entrypoint]; model.services.api.command = [...MODULEAPI_SLOT_DEPLOYMENT.command]; }
  Object.assign(model.services.api.networks, topology.services.api.networks);
  Object.assign(model.services.api.depends_on, topology.services.api.depends_on);
  if (s.credentialVolume) model.services.api.volumes.push(overlay.services.api.volumes.at(-1));
  model.services[moduleApiSlot] = topology.services[moduleApiSlot]; Object.assign(model.networks, topology.networks);
  Object.assign(model.volumes, overlay.volumes); return applyOpenAiOperations(model, s);
}
export function validateModuleApiConfig(value, root, cve, selection, images) {
  const s = validateModuleApiDeployment(selection), expected = expectedModuleApiConfig(root, cve, s), copy = structuredClone(value);
  for (const group of ['services', 'networks', 'volumes']) safe(equal(Object.keys(copy[group] ?? {}).sort(), Object.keys(expected[group]).sort()));
  for (const name of PUBLIC_IMAGE_OPERATION_ROLES) {
    safe(equal(copy.services[name].logging, PUBLIC_IMAGE_LOGGING));
    delete copy.services[name].logging; delete expected.services[name].logging;
  }
  safe(equal(copy.services.egress.command, PUBLIC_IMAGE_EGRESS_COMMAND));
  copy.services.egress.command = ['python', '-I', 'proxy.py']; expected.services.egress.command = copy.services.egress.command;
  if (images) {
    safe(equal(Object.keys(images).sort(), Object.keys(expected.services).sort()));
    for (const [name, image] of Object.entries(images)) { validatePublicLlmImage(image, name, s); expected.services[name].image = image.Id; }
  }
  safe(equal(normalizedModuleApiService(copy.services[moduleApiSlot]), expected.services[moduleApiSlot])); delete copy.services[moduleApiSlot];
  for (const name of MODULEAPI_SLOT_DEPLOYMENT.networks) { safe(equal(normalizedNetwork(copy.networks[name]), expected.networks[name])); delete copy.networks[name]; }
  const api = copy.services.api, legacy = expectedPublicLlmConfig(root, cve, s.openrouter).services.api;
  safe(equal(Object.fromEntries(Object.entries(api.environment ?? {}).filter(([key]) => moduleApiProviderKey(key))), publicLlmSelectedEnvironment(s)));
  for (const key of Object.keys(api.environment).filter(moduleApiProviderKey)) delete api.environment[key];
  Object.assign(api.environment, publicLlmSelectedEnvironment(s.openrouter));
  safe(api.build.dockerfile === 'server/deploy/moduleapi-api.Dockerfile'); api.build.dockerfile = legacy.build.dockerfile;
  safe(equal(api.ulimits, { core: {} }) || equal(api.ulimits, { core: { soft: 0, hard: 0 } })); delete api.ulimits;
  if (s.credentialVolume) {
    safe(equal(api.entrypoint, MODULEAPI_SLOT_DEPLOYMENT.entrypoint) && equal(api.command, MODULEAPI_SLOT_DEPLOYMENT.command));
    api.entrypoint = legacy.entrypoint; api.command = legacy.command;
    safe(equal(api.volumes.filter(m => m.target === MODULEAPI_SLOT_DEPLOYMENT.mount), expected.services.api.volumes.filter(m => m.target === MODULEAPI_SLOT_DEPLOYMENT.mount)));
    api.volumes = api.volumes.filter(m => m.target !== MODULEAPI_SLOT_DEPLOYMENT.mount);
  }
  safe(normalizedService(api).networks.openai_internal === null); delete api.networks.openai_internal;
  safe(equal(normalizedService(api).depends_on[moduleApiSlot], { condition: 'service_started' })); delete api.depends_on[moduleApiSlot];
  for (const key of [OPENAI_DEPLOYMENT.volumeKey, MODULEAPI_SLOT_DEPLOYMENT.volumeKey]) if (Object.hasOwn(expected.volumes, key)) {
    safe(equal(copy.volumes[key], expected.volumes[key])); delete copy.volumes[key];
  }
  // Old secret declarations may remain, never old secret mounts. Unknown mounts
  // and all other extra authority survive this projection to the base validator.
  validatePublicLlmConfig(copy, root, cve, s.openrouter, images && Object.fromEntries(Object.entries(images).filter(([name]) => name !== moduleApiSlot)));
}
function validateModuleApiAliases(container, name) {
  for (const [network, endpoint] of Object.entries(container.NetworkSettings?.Networks ?? {})) {
    const internalSlot = name === moduleApiSlot && network === `${PROJECT}_openai_internal`;
    const allowed = new Set([name, container.Name.slice(1), container.Id, container.Id.slice(0, 12), ...(internalSlot ? [moduleApiAlias] : [])]);
    const aliases = endpoint.Aliases ?? [];
    safe(Array.isArray(aliases) && new Set(aliases).size === aliases.length && aliases.every(alias => allowed.has(alias)));
    // Stopped endpoints may have no live DNS names; the fixed Compose alias is
    // still checked below. A running slot must expose the exact internal alias.
    if (internalSlot && container.State?.Running) safe(aliases.includes(moduleApiAlias));
    if (endpoint.DNSNames != null) safe(Array.isArray(endpoint.DNSNames) && endpoint.DNSNames.every(alias => allowed.has(alias)));
  }
}
export function stripModuleApiContainer(item, name, spec, image, selection) {
  const s = validateModuleApiDeployment(selection), c = structuredClone(item), im = structuredClone(image), model = structuredClone(spec);
  assertNoModuleApiDockerSecret(c.Config); validateModuleApiAliases(c, name);
  if (s.openai.credentialVolume) safe(!(c.Mounts ?? []).some(m => m.Name === s.openai.credentialVolume) &&
    !(c.HostConfig.Mounts ?? []).some(m => m.Source === s.openai.credentialVolume));
  if (PUBLIC_IMAGE_OPERATION_ROLES.includes(name)) {
    safe(equal(model.logging, PUBLIC_IMAGE_LOGGING) && equal(c.HostConfig.LogConfig, { Type: PUBLIC_IMAGE_LOGGING.driver, Config: PUBLIC_IMAGE_LOGGING.options }));
    delete model.logging; c.HostConfig.LogConfig = { Type: 'json-file', Config: {} };
    if (name === 'egress') {
      safe(equal(model.command, PUBLIC_IMAGE_EGRESS_COMMAND) && equal(c.Config.Cmd, PUBLIC_IMAGE_EGRESS_COMMAND) && c.Path === PUBLIC_IMAGE_EGRESS_COMMAND[0] && equal(c.Args, PUBLIC_IMAGE_EGRESS_COMMAND.slice(1)));
      model.command = ['python', '-I', 'proxy.py']; c.Config.Cmd = model.command; c.Path = 'python'; c.Args = model.command.slice(1);
    }
  }
  if (name === 'api') {
    const env = envMap(c.Config.Env);
    safe(equal(Object.fromEntries(Object.entries(env).filter(([key]) => moduleApiProviderKey(key))), publicLlmSelectedEnvironment(s)));
    for (const key of Object.keys(env).filter(moduleApiProviderKey)) delete env[key]; Object.assign(env, publicLlmSelectedEnvironment(s.openrouter));
    c.Config.Env = Object.entries(env).map(([key, value]) => `${key}=${value}`);
    safe(model.build.dockerfile === 'server/deploy/moduleapi-api.Dockerfile'); model.build.dockerfile = 'server/deploy/api.Dockerfile';
    safe(equal(model.ulimits, { core: { soft: 0, hard: 0 } }) && equal(c.HostConfig.Ulimits, [{ Name: 'core', Soft: 0, Hard: 0 }])); delete model.ulimits; delete c.HostConfig.Ulimits;
    if (s.credentialVolume) {
      const command = [...MODULEAPI_SLOT_DEPLOYMENT.entrypoint, ...MODULEAPI_SLOT_DEPLOYMENT.command];
      safe(equal(c.Config.Entrypoint, MODULEAPI_SLOT_DEPLOYMENT.entrypoint) && equal(model.entrypoint, MODULEAPI_SLOT_DEPLOYMENT.entrypoint) &&
        equal(c.Config.Cmd, MODULEAPI_SLOT_DEPLOYMENT.command) && equal(model.command, MODULEAPI_SLOT_DEPLOYMENT.command) && c.Path === command[0] && equal(c.Args, command.slice(1)));
      c.Config.Entrypoint = ['docker-entrypoint.sh']; model.entrypoint = c.Config.Entrypoint; c.Path = 'docker-entrypoint.sh'; c.Args = [...MODULEAPI_SLOT_DEPLOYMENT.command];
      const declarations = c.HostConfig.Mounts.filter(m => m.Target === MODULEAPI_SLOT_DEPLOYMENT.mount), mounts = c.Mounts.filter(m => m.Destination === MODULEAPI_SLOT_DEPLOYMENT.mount);
      safe(declarations.length === 1 && mounts.length === 1); const d = declarations[0], m = mounts[0];
      safe(d.Type === 'volume' && d.Source === s.credentialVolume && d.ReadOnly === true &&
        (equal(d.VolumeOptions, { NoCopy: true }) || equal(d.VolumeOptions, { NoCopy: true, DriverConfig: {} })) &&
        Object.keys(d).every(key => ['Type', 'Source', 'Target', 'ReadOnly', 'VolumeOptions'].includes(key)) &&
        m.Type === 'volume' && m.Name === s.credentialVolume && m.RW === false && !m.SubPath && (!m.Propagation || m.Propagation === 'rprivate'));
      c.HostConfig.Mounts = c.HostConfig.Mounts.filter(m => m.Target !== MODULEAPI_SLOT_DEPLOYMENT.mount); c.Mounts = c.Mounts.filter(m => m.Destination !== MODULEAPI_SLOT_DEPLOYMENT.mount);
      model.volumes = model.volumes.filter(m => m.target !== MODULEAPI_SLOT_DEPLOYMENT.mount);
    }
    for (const key of Object.keys(model.environment).filter(moduleApiProviderKey)) delete model.environment[key]; Object.assign(model.environment, publicLlmSelectedEnvironment(s.openrouter));
    safe(Object.hasOwn(c.NetworkSettings.Networks, `${PROJECT}_openai_internal`)); delete c.NetworkSettings.Networks[`${PROJECT}_openai_internal`];
    if (c.HostConfig.NetworkMode === `${PROJECT}_openai_internal`) c.HostConfig.NetworkMode = `${PROJECT}_auth_internal`;
    safe(normalizedService(model).networks.openai_internal === null && equal(normalizedService(model).depends_on[moduleApiSlot], { condition: 'service_started' }));
    delete model.networks.openai_internal; delete model.depends_on[moduleApiSlot];
  }
  if (name === moduleApiSlot) {
    safe(c.Name === `/${PROJECT}-${moduleApiSlot}-1` && role(c) === moduleApiSlot && owned(c.Config.Labels));
    safe(equal(c.Config.Cmd, MODULEAPI_SLOT_DEPLOYMENT.gatewayCommand) && equal(model.command, MODULEAPI_SLOT_DEPLOYMENT.gatewayCommand) &&
      c.Path === 'python' && equal(c.Args, MODULEAPI_SLOT_DEPLOYMENT.gatewayCommand.slice(1)));
    validatePublicLlmImage(im, moduleApiSlot, s);
    safe(equal(normalizedModuleApiService({ networks: model.networks }).networks, { openai_internal: { aliases: [moduleApiAlias] }, openai_uplink: null }));
    safe(equal(Object.keys(c.NetworkSettings.Networks).sort(), MODULEAPI_SLOT_DEPLOYMENT.networks.map(n => `${PROJECT}_${n}`).sort()));
    const map = { [`${PROJECT}_openai_internal`]: `${PROJECT}_llm_internal`, [`${PROJECT}_openai_uplink`]: `${PROJECT}_llm_uplink` };
    safe(Object.hasOwn(map, c.HostConfig.NetworkMode)); c.HostConfig.NetworkMode = map[c.HostConfig.NetworkMode];
    c.NetworkSettings.Networks = Object.fromEntries(Object.entries(c.NetworkSettings.Networks).map(([key, value]) => [map[key], value]));
    c.Name = `/${PROJECT}-llm-egress-1`; c.Config.Labels['com.docker.compose.service'] = 'llm-egress';
    c.Config.Cmd = publicLlmGatewayCommand(s.openrouter); im.Config.Cmd = ['python', '-I', 'openrouter.py']; model.command = c.Config.Cmd;
    c.Path = 'python'; c.Args = c.Config.Cmd.slice(1); name = 'llm-egress';
  }
  return { item: c, name, spec: model, image: im };
}
// Resolve an ORIGINAL owning reference, not a borrowing completion or an own
// :local name. No new import edge into frozen recovery/source closures is needed.
function captureModuleApiLocalImageCustody(root, image) {
  const parent = join(root, STATE, 'deploy-adapter-v1'), proofs = [], directories = [];
  const capture = (path, cap = 262144) => {
    const info = fs.lstatSync(path);
    safe(info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && info.uid === process.getuid() && (info.mode & 0o7777) === 0o600);
    const proof = fileFence(path, cap, 0o600);
    const verify = () => { const current = fs.lstatSync(path);
      safe(current.isFile() && !current.isSymbolicLink() && current.nlink === 1 && current.uid === info.uid); proof.verify(); };
    proofs.push({ verify }); verify(); return proof;
  };
  const directoryProof = path => {
    directory(path, 0o700); const info = fs.lstatSync(path), names = fs.readdirSync(path).sort();
    const verify = () => { directory(path, 0o700); const current = fs.lstatSync(path);
      safe(current.dev === info.dev && current.ino === info.ino && current.uid === info.uid && equal(fs.readdirSync(path).sort(), names)); };
    directories.push(verify); return names;
  };
  const verify = () => { directories.forEach(check => check()); proofs.forEach(proof => proof.verify()); };
  if (has(parent)) {
    const names = directoryProof(parent); safe(names.length <= 48 && names.every(name => /^[a-f0-9]{32}$/.test(name)));
    for (const nonce of names) {
      const dir = join(parent, nonce); directoryProof(dir);
      const completion = capture(join(dir, 'complete.json')), record = privateJson(completion.bytes);
      safe(record.project === PROJECT && record.nonce === nonce && [2, 3, 4].includes(record.version) &&
        ['published', 'old-restored', 'pre-mutation-aborted'].includes(record.outcome) && Array.isArray(record.references) && record.references.length <= 12);
      const references = record.references.filter(ref => ref.name === moduleApiSlot && ref.image === image.Id);
      if (!references.length) continue;
      safe([3, 4].includes(record.version) && record.referenceCustody && Array.isArray(record.evidence) && record.evidence.length <= 256 &&
        new Set(record.evidence.map(entry => entry.path)).size === record.evidence.length);
      const sealed = name => {
        const proof = capture(join(dir, name)), matches = record.evidence.filter(entry => entry.path === name);
        safe(matches.length === 1 && equal(matches[0], { path: name, bytes: Buffer.byteLength(proof.bytes), sha256: hash(proof.bytes) }));
        return privateJson(proof.bytes);
      };
      safe(equal(directoryProof(join(dir, 'operation.lock')), ['deploy-adapter-owner.json']));
      safe(equal(privateJson(capture(join(dir, 'operation.lock/deploy-adapter-owner.json')).bytes), { version: 2, nonce, kind: 'preserving-deployment' }));
      const custody = sealed('reference-custody.json'), intent = sealed('intent.json');
      safe(equal(custody, record.referenceCustody) && equal(intent.referenceCustody, custody) && intent.nonce === nonce &&
        intent.project === PROJECT && intent.kind === 'preserving-deployment' && intent.version === 2 &&
        [1, 2].includes(custody.version) && Array.isArray(custody.old) && Array.isArray(custody.candidates) &&
        custody.old.length > 0 && custody.old.length <= 6 && custody.candidates.length === custody.old.length &&
        record.version === (custody.version === 2 ? 4 : 3) &&
        new Set(custody.old.map(row => row.name)).size === custody.old.length &&
        custody.candidates.every((row, index) => row.name === custody.old[index].name));
      for (const ref of references) {
        const old = custody.old.find(row => row.name === moduleApiSlot), candidate = custody.candidates.find(row => row.name === moduleApiSlot);
        safe(equal(Object.keys(ref).sort(), ['image', 'name', 'tag']));
        if (old?.ownership === 'owned' && old.image === image.Id && old.tag === ref.tag) {
          safe(equal(Object.keys(old).sort(), ['image', 'name', 'ownership', 'tag']) &&
            ref.tag === `dip-deploy-${moduleApiSlot}:old-${nonce}` &&
            intent.old?.some(row => row.role === moduleApiSlot && row.image === image.Id));
          verify(); return { reference: ref.tag, verify };
        }
        if (custody.version === 1 && candidate && candidate.tag === ref.tag) {
          safe(equal(Object.keys(candidate).sort(), ['name', 'tag']) && ref.tag === `dip-deploy-${moduleApiSlot}:candidate-${nonce}`);
          const built = sealed(`built-${moduleApiSlot}.json`);
          safe(built.role === moduleApiSlot && built.image === image.Id && built.tag === ref.tag && built.oldImage === old?.image && built.oldTag === old?.tag);
          verify(); return { reference: ref.tag, verify };
        }
      }
    }
  }
  // A legacy retained reference has its own checkpoint/receipt seal. Match exact
  // ID AND Config before it can authorize an old provider's image validator.
  const retained = capturePublicLlmRetentions(root);
  for (const receipt of retained.receipts) {
    const row = receipt.images[moduleApiSlot];
    if (row && equal(row.image, { Id: image.Id, Os: image.Os, Config: image.Config })) {
      const check = () => { verify(); retained.verify(); };
      check(); return { reference: row.tag, verify: check };
    }
  }
  safe(false);
}
export async function inspectModuleApiNamespace(run, options, root, cve, selection, extra = {}) {
  const s = validateModuleApiDeployment(selection), model = expectedModuleApiConfig(root, cve, s);
  const one = async (kind, id) => { const rows = JSON.parse(await run([kind, 'inspect', id], options)); safe(rows.length === 1); return rows[0]; };
  const gateway = await one('container', `${PROJECT}-${moduleApiSlot}-1`), image = await one('image', gateway.Image);
  validatePublicLlmContainer(gateway, moduleApiSlot, model.services[moduleApiSlot], image, model, extra, s);
  const api = await one('container', `${PROJECT}-api-1`), apiImage = await one('image', api.Image);
  validatePublicLlmContainer(api, 'api', model.services.api, apiImage, model, extra, s);
  const networks = [], volumes = [];
  for (const name of MODULEAPI_SLOT_DEPLOYMENT.networks) {
    const n = await one('network', `${PROJECT}_${name}`);
    safe(n.Name === `${PROJECT}_${name}` && owned(n.Labels) && n.Driver === 'bridge' && Boolean(n.Internal) === name.endsWith('_internal') &&
      !n.Attachable && !n.Ingress && !n.EnableIPv6 && equal(n.Options ?? {}, {}) && (!n.IPAM || n.IPAM.Driver === 'default' && equal(n.IPAM.Options ?? {}, {}))); networks.push(n);
  }
  for (const [volumeName, current] of [[s.openai.credentialVolume, false], [s.credentialVolume, true]]) if (volumeName) {
    const volume = await one('volume', volumeName);
    if (current) validateModuleApiVolume(volume, s); else validateOpenAiVolume(volume, s.openai);
    const ids = (await run(['container', 'ls', '--all', '--filter', `volume=${volumeName}`, '--format', '{{.ID}}', '--no-trunc'], options)).trim().split('\n').filter(Boolean);
    safe(equal(ids, current ? [api.Id] : []));
    if (current) { const m = api.Mounts.find(m => m.Destination === MODULEAPI_SLOT_DEPLOYMENT.mount); safe(m.Source === volume.Mountpoint && m.Driver === 'local'); }
    volumes.push(volume);
  }
  const originals = new Map([['api', api]]), localCustody = []; let observedTag = false;
  const wrapped = async (args, opts) => {
    localCustody.forEach(verify => verify());
    const text = await run(args, opts);
    if (args[1] === 'ls' && ['container', 'network'].includes(args[0])) {
      const remove = args[0] === 'container' ? [`${PROJECT}-${moduleApiSlot}-1`] : MODULEAPI_SLOT_DEPLOYMENT.networks.map(n => `${PROJECT}_${n}`);
      return text.split('\n').filter(row => !remove.includes(row.split('\t')[0])).join('\n');
    }
    if (args[0] === 'image' && args[1] === 'ls') {
      const tag = `${PROJECT}-${moduleApiSlot}:local`;
      if (text.split('\n').includes(tag)) {
        const local = await one('image', tag);
        safe(Array.isArray(local.RepoTags) && local.RepoTags.includes(tag));
        if (local.Id === image.Id) {
          safe(equal(local.Config, image.Config) && local.Os === image.Os);
          validatePublicLlmImage(local, moduleApiSlot, s);
        } else {
          const custody = captureModuleApiLocalImageCustody(root, local); localCustody.push(custody.verify);
          for (const reference of [local.Id, custody.reference]) {
            custody.verify(); const retained = await one('image', reference); custody.verify();
            safe(retained.Id === local.Id && retained.Os === local.Os && equal(retained.Config, local.Config) &&
              Array.isArray(retained.RepoTags) && retained.RepoTags.includes(custody.reference) && retained.RepoTags.includes(tag));
          }
          // Provider selection follows immutable ID/config/tag + original seal.
          validatePublicLlmRetainedImage(local, moduleApiSlot, s); custody.verify();
        }
        observedTag = true;
      }
      return text.split('\n').filter(row => row !== tag).join('\n');
    }
    if (args[0] === 'container' && args[1] === 'inspect') {
      const rows = JSON.parse(text); safe(rows.length === 1); const name = role(rows[0]);
      if (name === 'api' || PUBLIC_IMAGE_OPERATION_ROLES.includes(name)) {
        const previous = originals.get(name); if (previous) safe(control(previous) === control(rows[0]) && equal(epoch(previous), epoch(rows[0])));
        const im = name === 'api' ? apiImage : extra.images?.[name] ?? await one('image', rows[0].Image);
        validatePublicLlmContainer(rows[0], name, model.services[name], im, model, extra, s); originals.set(name, rows[0]);
        return JSON.stringify([stripModuleApiContainer(rows[0], name, model.services[name], im, s).item]);
      }
    }
    return text;
  };
  const legacyImages = extra.images && Object.fromEntries(Object.entries(extra.images).filter(([name]) => name !== moduleApiSlot));
  const out = await inspectPublicLlmNamespace(wrapped, options, root, cve, s.openrouter, { ...extra, images: legacyImages });
  out.containers = out.containers.map(c => originals.get(role(c)) ?? c); out.containers.push(gateway); out.networks.push(...networks); out.volumes.push(...volumes);
  localCustody.forEach(verify => verify());
  if (observedTag) out.images.push(`${PROJECT}-${moduleApiSlot}:local`);
  for (const n of networks) {
    const members = out.containers.filter(c => c.State.Running && Object.hasOwn(c.NetworkSettings.Networks, n.Name));
    safe(equal(Object.keys(n.Containers ?? {}).sort(), members.map(c => c.Id).sort()));
    safe(members.every(c => role(c) === moduleApiSlot || n.Internal && role(c) === 'api'));
  }
  return out;
}

// Explicit v6 only. No bootstrap/reset. Auth A3 is a separately acknowledged,
// constructor-qualified additive delta; every other byte of logical state is equal.
export async function executeOpenAiMaintenance(ops, { upgradeWorkerEgress = false, migrateAuth = false } = {}) {
  safe(typeof upgradeWorkerEgress === 'boolean' && typeof migrateAuth === 'boolean');
  for (const key of ['preflight', 'intent', 'stop', 'drain', 'snapshot', 'validateBaseline', 'candidate', 'verifyExistingStores', 'startRetained', 'resumeExisting', 'up', 'ready', 'publish', 'complete']) safe(typeof ops[key] === 'function');
  await ops.preflight(); await ops.intent(); await ops.stop('web'); await ops.stop('api'); await ops.drain(); await ops.stop('worker');
  if (upgradeWorkerEgress) { await ops.stop('egress'); await ops.stop('llm-egress'); }
  const baseline = await ops.snapshot('fenced'); safe(baseline.llm !== null && baseline.historyVersion === 4); await ops.validateBaseline(baseline);
  await ops.candidate(); const auth = await ops.verifyExistingStores();
  if (migrateAuth) safe(auth?.version === 1 && auth.migration === 'auth-a2-to-a3' && auth.constructorPasses === 2 &&
    auth.before === baseline.core.auth.logicalSha256 && /^[a-f0-9]{64}$/.test(auth.expected) && auth.expected !== auth.before);
  if (upgradeWorkerEgress) { await ops.up('egress'); await ops.up('llm-egress'); }
  else { await ops.startRetained(); await ops.resumeExisting('llm-egress'); }
  await ops.up('openai-egress');
  if (upgradeWorkerEgress) await ops.up('worker'); else await ops.resumeExisting('worker');
  await ops.ready('worker');
  const sameStores = (a, b) => equal(a.core, b.core) && equal(a.llm, b.llm) && a.historyVersion === b.historyVersion;
  const before = await ops.snapshot('before-api'); safe(sameStores(baseline, before));
  await ops.up('api'); await ops.ready('api');
  const after = await ops.snapshot('after-api');
  const expected = structuredClone(before);
  if (migrateAuth) expected.core.auth.logicalSha256 = auth.expected;
  safe(sameStores(expected, after));
  await ops.publish(); await ops.up('web'); await ops.ready('web'); await ops.complete();
  return { outcome: 'ready', generationVerified: false, historyMigrated: false, ...(migrateAuth ? { authMigrated: true } : {}) };
}

export async function publicLlmStand(argv, { root = ROOT, home = homedir(), run = runIsolatedDocker, ambient = process.env,
  Database, sleep = ms => new Promise(r => setTimeout(r, ms)), now = () => performance.now(), request = fetch, log = console.log, onDiagnostic, checkSource = checkPublicLlmSourceBuild, existingBuildContinuation } = {}) {
  const [command, ...flags] = argv;
  const openai = command === 'up-openai';
  const upgradeWorkerEgress = openai && flags.includes(PUBLIC_IMAGE_OPERATIONS_ACK);
  const migrateAuth = openai && flags.includes(PUBLIC_AUTH_A3_MIGRATION_ACK);
  const legacyGatewayStop = flags.includes(LEGACY_GATEWAY_STOP_ACK);
  safe(!legacyGatewayStop || openai && upgradeWorkerEgress && !existingBuildContinuation);
  if (/^(?:check|continue)-current-|^continue-(?:existing|summary)-build$/.test(command ?? '') &&
      has(join(root, STATE, 'llm-profile.json'))) safe(readPublicLlmBinding(root)?.version !== 6);
  // Prepared only by the separate exact-audit entry point. No new loader edge
  // in the historical current-build checker and no generic CLI unlock.
  let continuation;
  if (existingBuildContinuation) {
    const summary = existingBuildContinuation.summaryRecovery === true;
    safe((summary ? command === 'continue-summary-build' && flags.length === 7 && flags[1] === 'deploy-76eb7a61e0da2e108210bc773b964d35' && flags[6] === PUBLIC_LLM_SUMMARY_MIGRATION_ACK : command === 'continue-existing-build' && flags.length === 6 && ['deploy-2c9ed08b8269264b09bf14eb6189a649', 'deploy-1cb54172f8cd83708f64067371069fa5'].includes(flags[1])) && flags[0] === '--audit' && flags[2] === '--review' && /^[a-f0-9]{64}$/.test(flags[3] ?? '') && flags[4] === '--ack-reviewed-current-source' && flags[5] === '--ack-retire-only-unavailable-peers');
    continuation = existingBuildContinuation;
    safe(continuation.existingBuildOnly === true && continuation.root === root && continuation.auditName === flags[1] && continuation.review === flags[3]);
    validatePublicLlmExistingBuildSelection(continuation.auditName, continuation.priorSelection, continuation.selection);
    continuation.verify(); continuation.checkPrefix();
  }
  if (['check-current-rollout', 'continue-current-rollout'].includes(command)) {
    const checking = command === 'check-current-rollout';
    safe(flags[0] === '--audit' && (checking ? flags.length === 2 : flags.length === 7 && flags[2] === '--review' && /^[a-f0-9]{64}$/.test(flags[3] ?? '') && flags[4] === '--ack-reviewed-current-source' && flags[5] === '--ack-retire-only-unavailable-api' && flags[6] === '--ack-retire-only-unavailable-web'));
    const module = await import('./public-llm-rollout-completion.mjs');
    continuation = await module.preparePublicLlmRolloutCompletion({ root, home, audit: flags[1], run, ambient, Database, checkSource });
    if (checking) { log(JSON.stringify(continuation.summary)); return continuation.summary; }
    safe(continuation.review === flags[3]); admissionContexts.add(continuation);
  }
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
  if (command === 'migrate-config-report4k') {
    safe(equal(flags, ['--ack-public-dots2048-to-report4096']));
    return migratePublicLlmReport4k({ root, home, log });
  }
  if (command === 'migrate-config-dots') {
    safe(equal(flags, ['--ack-public-nvidia90-to-dots-non-zdr']));
    return migratePublicLlmDots({ root, home, log });
  }
  if (command === 'migrate-config-nvidia') {
    safe(equal(flags, ['--ack-public-xing90-to-nvidia-non-zdr']));
    return migratePublicLlmNvidia({ root, home, log });
  }
  if (command === 'upgrade-config-timeout') {
    safe(equal(flags, ['--ack-public-config-30-to-90']));
    return upgradePublicLlmTimeout({ root, home, log });
  }
  safe(Boolean(continuation) || openai && equal(flags, ['--ack-public-maintenance', '--build', '--ack-openai-extension',
    ...(flags.includes('--ack-openai-activation') ? ['--ack-openai-activation'] : []),
        ...(upgradeWorkerEgress ? [PUBLIC_IMAGE_OPERATIONS_ACK] : []), ...(migrateAuth ? [PUBLIC_AUTH_A3_MIGRATION_ACK] : []), ...(legacyGatewayStop ? [LEGACY_GATEWAY_STOP_ACK] : [])]) ||
    ['plan', 'plan-openai', 'status', 'up'].includes(command) && (command === 'up' ? flags.includes('--ack-public-maintenance') &&
    flags.every(f => ['--ack-public-maintenance', '--build', PUBLIC_LLM_SUMMARY_MIGRATION_ACK].includes(f)) && new Set(flags).size === flags.length : flags.length === 0));
  const summaryRecovery = continuation?.summaryRecovery === true;
  const migrateSummary = summaryRecovery || !continuation && flags.includes(PUBLIC_LLM_SUMMARY_MIGRATION_ACK);
  safe(!migrateSummary || summaryRecovery || command === 'up' && flags.includes('--build'));
  safe(resolve(root) === root && fs.realpathSync(root) === root);
  if (command === 'plan-openai') {
    log('Offline v6 plan: 8 services/8 networks; API-only private ENV volume bootstrap; four-store RO preservation; web last. No Docker/config/secret read.');
    return { services: 8, ownNetworks: 8, secret: 'api-bootstrap-env-only', generationVerified: false };
  }
  if (command === 'plan') {
    log('Source plan only: 7 fixed services, 6 own networks; API-only optional external readonly key volume. No Docker or key/config read.');
    return { services: 7, ownNetworks: 6, keyMount: 'only-after-provisioning-receipt', generationVerified: false };
  }
  if (command === 'status') { const s = readPublicLlmBinding(root); log(s ? `Public LLM profile recorded; key volume ${s.keyVolume ? 'supplied' : 'unavailable'}; not a runtime/credential verification.` : 'No public LLM profile recorded.'); return; }
  safe(!resolve(home, '.local/state/diplom-public-images/llm').startsWith(root + '/'));
  const settings = loadPublicLlmSettings(home, { openai }); // Approved non-secret config/receipt only.
  safe(!openai || settings.selection.environment.OPENAI_ENABLED !== 'true' || flags.includes('--ack-openai-activation'));
  // Historical HOLD continuations are not a timing-upgrade path.
  safe(!continuation || settings.selection.version === 1 || continuation.existingBuildOnly === true &&
      (continuation.auditName === 'deploy-1cb54172f8cd83708f64067371069fa5' || summaryRecovery && continuation.auditName === 'deploy-76eb7a61e0da2e108210bc773b964d35') && equal(settings.selection, continuation.selection));
  let archivedLock;
  const verifyHeldLock = continuation ? directoryFence(continuation.lockPath) : null;
  const lock = continuation ? { path: continuation.lockPath, verify: verifyHeldLock,
    release() { if (archivedLock) { archivedLock(); return; } verifyHeldLock(); fs.rmdirSync(continuation.lockPath); syncDirectory(join(root, STATE)); } } : acquireLock(root);
  const verifyPublicState = directoryFence(join(root, STATE)); let hold = Boolean(continuation), phase = 'preflight', audit, stage, candidateImages, before, priorImages, profile, priorSelection, jwt, d, options, endpoint, verifySource;
  const records = new Set(), peers = new Map(), peerModels = new Map(), healthy = new Set();
  const acknowledgedGatewayStops = new Map(), stopJournals = [];
    const preflightNonce = continuation ? null : crypto.randomBytes(16).toString('hex');
    let preflightHistoryVersion, preflightAuthVersion;
  let failedHelper = continuation?.initialize?.failed ?? null;
    let openAiVolumeAuthority, keyVolumeAuthority, stoppedStand = false, staleHelper = continuation?.initialize?.retired ? null : continuation?.initialize ?? null;
  const outputPrefix = summaryRecovery ? 'summary-current' : continuation?.existingBuildOnly ? 'existing-build-current' : continuation?.rolloutOnly ? 'rollout-current' : continuation?.apiOnly ? 'api-current' : continuation?.admissionOnly ? 'admit-current' : continuation?.initialize?.failed ? 'init-exit-current' : continuation?.initialize?.retired ? 'rebuild-current' : continuation?.initialize ? 'initialize-current' : 'continued';
  const recordName = name => continuation?.initialize || continuation?.existingBuildOnly ? outputPrefix + '-' + name : name;
  const fences = [], candidateFences = [];
  let verifyStage, readinessFailure, retainedRestarted = false, retainedReferences;
  const fence = () => {
      verifyPublicState(); lock.verify(); continuation?.verifyExecution(); continuation?.initialize?.verify();
      if (continuation?.existingBuildOnly) {
        continuation.verifyStable();
        if (verifyStage) {
          safe(equal(fs.readdirSync(lock.path).sort(), [...continuation.originalFiles.map(f => f.path.split('/').at(-1)), 'llm-candidate', outputPrefix, ...records].sort()));
          safe(equal(fs.readdirSync(stage).sort(), candidateFences.filter(f => dirname(f.path) === stage).map(f => f.path.split('/').at(-1)).sort()));
          safe(equal(fs.readdirSync(audit.path).sort(), ['fenced', ...(summaryRecovery ? ['history-schema-preflight.json'] : []), outputPrefix].sort()));
        }
      }
      settings.verify(); verifySource?.(); audit?.verify(); verifyStage?.(); retainedReferences?.verify(); for (const f of [...fences, ...candidateFences, ...stopJournals]) f.verify();
      if (stopJournals.length) safe(equal(fs.readdirSync(join(audit.path, 'stop-diagnostics')).sort(), stopJournals.map(j => j.role).sort()));
    };
  const record = (name, value) => { lock.verify(); continuation?.verifyExecution(); const target = recordName(name); writeExclusive(join(lock.path, target), JSON.stringify(value), 0o600); records.add(target); syncDirectory(lock.path); };
  const inspect = async (id, name, model, images, selection, trace) => {
    if (trace && openai && !continuation) return inspectPublicLlmStop({ id, d, trace,
      validate: c => validatePublicLlmContainer(c, name, model.services[name], images[name], model, { secret: jwt, images }, selection) });
    const a = JSON.parse(await d(['container', 'inspect', id])); safe(a.length === 1 && a[0].Id === id);
    if (continuation?.existingBuildOnly && !(name === 'egress' && retainedRestarted) && id === continuation.inventory.containers.find(c => role(c) === name)?.Id) {
      continuation.validateOriginalPeer(a[0], name);
    } else if (continuation?.replacement && !continuation.admissionOnly && name === 'worker' && id === continuation.inventory.containers.find(c => role(c) === 'worker').Id) {
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
      if (!current.State.Running) {
        const proof = acknowledgedGatewayStops.get(current.Id);
        if (proof) safe(legacyGatewayStop && equal(epoch(current), proof.stoppedEpoch) && current.Mounts.length === 0 && current.State.ExitCode === 137);
        else cleanStopped(current);
      }
      if (healthy.has(name)) safe(current.State.Health?.Status === 'healthy');
    }
    // A replaced volume must be rejected before any helper mounts it, not only
    // in the final namespace comparison after reading a different data source.
    for (const volume of before?.volumes.filter(v => v.Name.startsWith(PROJECT + '_')) ?? []) {
      const rows = JSON.parse(await d(['volume', 'inspect', volume.Name])); safe(rows.length === 1 && equal(rows[0], volume));
    }
    if (continuation?.existingBuildOnly || openai) for (const network of before.networks) {
      const rows = JSON.parse(await d(['network', 'inspect', network.Name]));
      safe(rows.length === 1 && rows[0].Id === network.Id && equal({ ...rows[0], Containers: {} }, { ...network, Containers: {} }));
      safe(equal(Object.keys(rows[0].Containers ?? {}).sort(), [...peers.values()].filter(c => c.State.Running && Object.hasOwn(c.NetworkSettings.Networks, network.Name)).map(c => c.Id).sort()));
    }
    if (openAiVolumeAuthority) {
      const rows = JSON.parse(await d(['volume', 'inspect', settings.selection.credentialVolume]));
      safe(rows.length === 1 && equal(rows[0], openAiVolumeAuthority));
      const ids = (await d(['container', 'ls', '--all', '--no-trunc', '--filter', `volume=${settings.selection.credentialVolume}`, '--format', '{{.ID}}'])).trim().split('\n').filter(Boolean);
      const consumers = [...peers.values()].filter(c => c.Mounts.some(m => m.Type === 'volume' && m.Name === settings.selection.credentialVolume));
      safe(consumers.every(c => role(c) === 'api') && equal(ids.sort(), consumers.map(c => c.Id).sort()));
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
  // Current normal up retains its original image authority through reopening,
  // even after a helper/container switches to a candidate image. Retagging is
  // expected during build; loss or drift of pinned execution metadata is not.
  // Historical continuations keep their separately qualified retire-only rules.
  const verifyRetainedImages = async () => {
    if (summaryRecovery) { await continuation.verifySummaryImages(d); return; }
    if (continuation) return;
    fence();
    for (const [name, image] of Object.entries(priorImages)) {
      const rows = JSON.parse(await d(['image', 'inspect', image.Id]));
      safe(rows.length === 1 && rows[0].Id === image.Id && rows[0].Os === image.Os && equal(rows[0].Config, image.Config));
      validatePublicLlmImage(rows[0], name);
    }
    if (retainedReferences) await retainedReferences.verifyImages(d, options);
    fence();
  };
  const helper = async (suffix, purpose, work = async () => undefined) => {
    fence(); await verifyPeers(); await verifyRetainedImages(); await users(); await census();
    safe(audit || !continuation && ['schema-preflight', 'auth-schema-preflight'].includes(purpose));
        const image = ['schema-preflight', 'auth-schema-preflight'].includes(purpose) || purpose === 'backup' && suffix === 'fenced' ? (continuation?.backupImage ?? priorImages.api) : candidateImages.api;
    const imageRows = JSON.parse(await d(['image', 'inspect', image.Id]));
    safe(imageRows.length === 1 && imageRows[0].Id === image.Id && imageRows[0].Os === image.Os && equal(imageRows[0].Config, image.Config));
    validateImage(imageRows[0], 'api'); // Retagging may change RepoTags, never immutable execution defaults.
    const recordedSuffix = (continuation ? outputPrefix + '-' : '') + suffix;
    const name = `${PROJECT}-llm-${audit?.nonce ?? preflightNonce}-${recordedSuffix}`;
    if (!continuation || summaryRecovery) record(`helper-${recordedSuffix}-submission.json`, { version: 1, name, image: image.Id, purpose });
    const id = (await d((continuation && !summaryRecovery ? publicLlmHelperArguments : currentPublicLlmHelperArguments)(name, image.Id, purpose))).trim(); safe(containerId(id));
    let authority, execution;
    const check = async state => {
      fence(); const rows = JSON.parse(await d(['container', 'inspect', id])); safe(rows.length === 1);
      const c = rows[0]; safe(c.Id === id); (continuation && !summaryRecovery ? validatePublicLlmHelper : validateCurrentPublicLlmHelper)(c, name, image, purpose, state);
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
    if (summaryRecovery && purpose === 'backup' && suffix === 'fenced') await continuation.verifySummaryHelperSource(id, d, () => check('running'));
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
        if (continuation.existingBuildOnly) { continuation.checkPrefix(); await continuation.revalidate(); }
        profile = continuation.profile; priorSelection = continuation.rolloutOnly || continuation.existingBuildOnly ? continuation.priorSelection : null; jwt = loadSecret(root, true); before = continuation.inventory; priorImages = continuation.images;
        stage = continuation.existingBuildOnly ? join(lock.path, outputPrefix) : continuation.initialize ? join(lock.path, continuation.rolloutOnly ? 'rollout-current' : continuation.apiOnly ? 'api-current' : continuation.admissionOnly ? 'admit-current' : continuation.initialize.failed ? 'init-exit-current' : continuation.initialize.retired ? 'llm-rebuild-candidate' : 'llm-initialize-candidate') : continuation.stage; options = continuation.options; endpoint = continuation.endpoint;
        verifySource = sourceFence(root); fences.push(...continuation.stateFiles, ...continuation.proofs); candidateFences.push(...continuation.candidateFiles);
        const deadline = now() + 20 * 60 * 1000;
        d = (args, extra = {}) => { fence(); safe((extra.env?.DOCKER_HOST ?? endpoint) === endpoint && now() < deadline); return run(args, { ...options, ...extra, timeout: publicLlmDockerTimeout(extra.timeout ?? 30000, deadline, now()) }); };
        const model = expectedPublicLlmConfig(root, profile.cve, priorSelection);
        if (continuation.rolloutOnly || continuation.existingBuildOnly) keyVolumeAuthority = continuation.keyVolumeAuthority;
        if (continuation.existingBuildOnly) { validatePublicLlmExistingBuildSelection(continuation.auditName, priorSelection, settings.selection); stoppedStand = !before.containers.find(c => role(c) === 'egress').State.Running; }
        for (const c of before.containers) {
                  const name = role(c), admittedPeer = continuation.admissionOnly && ['worker', 'llm-egress'].includes(name);
                  peers.set(name, c); peerModels.set(name, admittedPeer ? { model: nextModel(), images: continuation.initialize.candidateImages, selection: settings.selection } : { model, images: priorImages, selection: continuation.existingBuildOnly ? priorSelection : null });
                }
        await verifyPeers(); await census(); await users(); return;
      }
      phase = 'preflight-history'; assertReconciliationHistory(root);
      const capturedState = openai ? captureOpenAiPreflightState(root) : null;
      if (capturedState) fences.push(...capturedState.fences);
      phase = 'preflight-profile'; profile = capturedState ? capturedState.profile : readProfile(root); safe(profile !== undefined && (!profile.cve || profile.version === 2));
      phase = 'preflight-binding'; priorSelection = capturedState ? capturedState.priorSelection : readPublicLlmBinding(root); safe(priorSelection !== null || flags.includes('--build'));
      if (openai) settings.selection = selectOpenAiOperations(settings.selection, priorSelection, upgradeWorkerEgress);
      validatePublicLlmTransition(priorSelection, settings.selection);
      // Prior immutable images need not implement the next policy or trusted gateway flag.
      safe(!priorSelection || priorSelection.version === settings.selection.version || flags.includes('--build'));
      phase = 'preflight-source'; verifySource = sourceFence(root, { openai });
      // Missing bootstrap or incompatible runtime configuration refuses BEFORE Docker or fencing writers.
      if (openai) { const q = await checkSource(root, { openai: settings.selection }); fence(); safe(q?.openai === true && q?.typescript === true && q?.bundle === true); }
      phase = 'preflight-jwt'; jwt = capturedState ? capturedState.jwt : loadSecret(root, true);
      phase = 'preflight-state-files'; if (!capturedState) for (const p of ['profile.json', 'scan-jwt', 'compose.images.json', ...(profile.cve ? ['compose.cve.json'] : []),
        ...(priorSelection ? ['llm-profile.json', 'compose.llm-env.json'] : [])]) fences.push(fileFence(join(root, STATE, p)));
      phase = 'preflight-engine'; const baseEnv = dockerEnvironment(ambient), rawEndpoint = baseEnv.DOCKER_HOST && !baseEnv.DOCKER_CONTEXT ? baseEnv.DOCKER_HOST :
        JSON.parse(await run(['context', 'inspect', ...(baseEnv.DOCKER_CONTEXT ? [baseEnv.DOCKER_CONTEXT] : []), '--format', '{{json .Endpoints.docker.Host}}'], { root, env: baseEnv }));
      safe(typeof rawEndpoint === 'string' && /^unix:\/\/\/[^\s\0]+$/.test(rawEndpoint)); endpoint = rawEndpoint;
      const env = { ...baseEnv, DOCKER_HOST: endpoint, COMPOSE_DISABLE_ENV_FILE: '1' }; for (const k of ['DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']) delete env[k];
      options = { root, env }; const end = now() + 20 * 60 * 1000;
      d = (args, extra = {}, trace, prefix) => {
        if (trace && openai) return dispatchPublicLlmStopDocker({ args, extra, trace, prefix, fence, endpoint, end, now, run, options });
        fence(); safe((extra.env?.DOCKER_HOST ?? endpoint) === endpoint && now() < end);
        return run(args, { ...options, ...extra, timeout: publicLlmDockerTimeout(extra.timeout ?? 30000, end, now()) });
      };
      phase = 'preflight-pins'; const priorModel = expectedPublicLlmConfig(root, profile.cve, priorSelection), pins = JSON.parse(readBounded(join(root, STATE, 'compose.images.json'), 16384, 0o600));
      safe(equal(Object.keys(pins), ['services']) && equal(Object.keys(pins.services).sort(), Object.keys(priorModel.services).sort())); priorImages = {};
      for (const name of Object.keys(priorModel.services)) {
        safe(['auth-volume-init', 'scan-volume-init', 'egress', 'worker', 'api', 'web', 'llm-egress', ...(openai ? ['openai-egress'] : [])].includes(name)); phase = 'preflight-images-' + name;
        const id = pins.services[name]?.image; safe(imageId(id) && equal(pins.services[name], { image: id }));
        // No container-config/tag recovery if a historical image ID cannot be inspected.
        const a = JSON.parse(await d(['image', 'inspect', id])); safe(a.length === 1 && a[0].Id === id); validatePublicLlmImage(a[0], name); priorImages[name] = a[0];
      }
      phase = 'preflight-namespace'; before = await inspectCurrentPublicLlmNamespace(d, options, root, profile.cve, priorSelection, { secret: jwt, images: priorImages });
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
      if (legacyGatewayStop) {
        safe(!stoppedStand && priorSelection?.version === 6 && !Object.hasOwn(priorSelection, 'operations'));
        for (const [name, [id, image]] of Object.entries(LEGACY_GATEWAY_STOP_IDS)) {
          const c = peers.get(name); safe(c.Id === id && c.Image === image && c.Mounts.length === 0 && c.HostConfig.ReadonlyRootfs === true);
        }
      }
      if (!stoppedStand) { safe(peers.get('api').State.Health?.Status === 'healthy'); healthy.add('api'); }
      phase = 'preflight-key-volume'; if (settings.selection.keyVolume) {
        const rows = JSON.parse(await d(['volume', 'inspect', settings.selection.keyVolume])); safe(rows.length === 1);
        const v = rows[0]; validatePublicLlmKeyVolume(v, settings.selection);
        keyVolumeAuthority = v; // Metadata only; never mount/open/read a key to qualify it.
      }
      if (openai && settings.selection.credentialVolume) {
        phase = 'preflight-openai-volume';
        const rows = JSON.parse(await d(['volume', 'inspect', settings.selection.credentialVolume])); safe(rows.length === 1);
        validateOpenAiVolume(rows[0], settings.selection); openAiVolumeAuthority = rows[0];
      }
      phase = 'preflight-sqlite'; const DB = Database ?? requireApi('better-sqlite3'); const probe = new DB(':memory:'); probe.close();
      phase = 'preflight-peers'; await verifyPeers();
      phase = 'preflight-census'; await census();
      phase = 'preflight-consumers'; await users();
      // Budget/partial generations are checked before any live fence or build.
      phase = 'preflight-backup-history'; validateCurrentAuditHistory(root);
      if (openai && flags.includes('--build')) {
        const retained = capturePublicLlmRetentions(root);
        safe(retained.tags.length + retentionRoles({ version: 2, deployment: { prior: priorSelection, next: settings.selection } }).length <= DEPLOYMENT_RETAINED_REFERENCE_LIMIT);
        retained.verify();
      }
      phase = 'preflight-history-schema';
      // Lifecycle is limited to one keyless RO helper; no application fence yet.
      // An uncertain submission retains its intent/lock, never retries or cleans up.
      hold = true;
      const receipt = await helper('schema-preflight', 'schema-preflight', async (_id, _d, _check, value) => value);
      for (const name of ['helper-schema-preflight-submission.json', 'helper-schema-preflight.json']) {
        safe(records.has(name)); fs.unlinkSync(join(lock.path, name)); records.delete(name);
      }
      syncDirectory(lock.path); hold = false;
      safe(equal(Object.keys(receipt).sort(), ['historyVersion', 'ready']) && receipt.ready === true && [null, 3, 4].includes(receipt.historyVersion));
      preflightHistoryVersion = receipt.historyVersion;
      if (openai) safe(preflightHistoryVersion === 4 && !migrateSummary);
      safe(priorSelection ? preflightHistoryVersion !== null : preflightHistoryVersion === null);
      // A new ack is authority for exactly v3 -> v4, not a replay/no-op on v4.
      safe(migrateSummary ? preflightHistoryVersion === 3 : preflightHistoryVersion !== 3);
      if (openai) {
        phase = 'preflight-auth-schema'; hold = true;
        const auth = await helper('auth-schema-preflight', 'auth-schema-preflight', async (_id, _d, _check, value) => value);
        for (const name of ['helper-auth-schema-preflight-submission.json', 'helper-auth-schema-preflight.json']) {
          safe(records.has(name)); fs.unlinkSync(join(lock.path, name)); records.delete(name);
        }
        syncDirectory(lock.path); hold = false;
        safe(equal(Object.keys(auth).sort(), ['authVersion', 'ready']) && auth.ready === true && [2, 3].includes(auth.authVersion));
        preflightAuthVersion = auth.authVersion;
        // Not a no-op/replay permission and not a schema-drift exemption.
        safe(preflightAuthVersion === (migrateAuth ? 2 : 3));
      }
    },
    async intent() {
      if (continuation) {
        continuation.verify(); continuation.initialize?.checkPrefix(); // Final exclusive-prefix and execution-closure fence.
        if (continuation.existingBuildOnly) { await continuation.revalidate(); continuation.verify(); continuation.checkPrefix(); }
        phase = 'continue-intent'; record('continue.json', { version: 1, command, audit: continuation.auditName, review: continuation.review,
          sourceReview: 'explicit-current-source-not-historical', retireOnlyWorker: Boolean(continuation.replacement),
          ...(continuation.initialize ? { retireOnlyApi: Boolean(continuation.apiReplacement), retireOnlyWeb: Boolean(continuation.webReplacement), backupHelperBasis: continuation.summary.backupHelperBasis } : {}) });
        record('continuation-checkpoint.json', continuation.reviewEvidence);
        const parentVerify = directoryFence(dirname(continuation.auditPath)), auditVerify = directoryFence(continuation.auditPath);
        audit = { path: continuation.auditPath, nonce: continuation.nonce, verify() { parentVerify(); auditVerify(); } };
        fs.mkdirSync(join(audit.path, outputPrefix), { mode: 0o700 });
        writeExclusive(join(audit.path, outputPrefix, 'review.json'), JSON.stringify(continuation.reviewEvidence), 0o600);
        syncDirectory(join(audit.path, outputPrefix)); syncDirectory(audit.path);
        if (continuation.initialize || continuation.existingBuildOnly) {
          fs.mkdirSync(stage, { mode: 0o700 }); syncDirectory(lock.path);
          for (const name of ['compose.cve.json', 'compose.llm-env.json']) {
            writeExclusive(join(stage, name), readBounded(join(continuation.stage, name), 16384, 0o600), 0o600);
            candidateFences.push(fileFence(join(stage, name)));
          }
          syncDirectory(stage);
        }
        verifyStage = directoryFence(stage);
        if (summaryRecovery) {
          snapshot = createCurrentPublicLlmPreservation({ DB: Database ?? requireApi('better-sqlite3'), root, lock, audit: audit.path, helper, migrateSummary: true, summaryRecovery: true,
            verifyState: async () => { await verifyPeers(); await verifyRetainedImages(); await users(); await census(); } });
          return;
        }
        snapshot = createPublicLlmPreservation({ DB: Database ?? requireApi('better-sqlite3'), root, lock, audit: audit.path, helper, continued: !continuation.initialize && !continuation.existingBuildOnly, existingBuildCurrent: Boolean(continuation.existingBuildOnly), initializedCurrent: Boolean(continuation.initialize && !continuation.initialize.retired), rebuiltCurrent: Boolean(continuation.initialize?.retired && !continuation.initialize.failed && !continuation.admissionOnly), initExitCurrent: Boolean(continuation.initialize?.failed), admitCurrent: Boolean(continuation.admissionOnly && !continuation.apiOnly && !continuation.rolloutOnly), apiCurrent: Boolean(continuation.apiOnly), rolloutCurrent: Boolean(continuation.rolloutOnly),
          verifyState: async () => { await verifyPeers(); await users(); await census(); } });
        return;
      }
      hold = true; record('mutation.json', { version: 1, project: PROJECT, command: upgradeWorkerEgress ? 'public-openai-worker-egress-upgrade' : openai ? 'public-openai-up' : 'public-llm-up', phase: 'fence-web', endpoint,
              ...(migrateAuth ? { authMigration: 'auth-a2-to-a3', authMigrationAck: PUBLIC_AUTH_A3_MIGRATION_ACK } : {}) });
      audit = privateAudit(root); stage = join(lock.path, 'llm-candidate'); fs.mkdirSync(stage, { mode: 0o700 }); syncDirectory(lock.path);
      verifyStage = directoryFence(stage);
      if (profile.cve) writeExclusive(join(stage, 'compose.cve.json'), readBounded(join(root, STATE, 'compose.cve.json'), 16384, 0o600), 0o600);
      writeExclusive(join(stage, 'compose.llm-env.json'), JSON.stringify(publicLlmEnvironmentOverlay(settings.selection)), 0o600);
      for (const name of fs.readdirSync(stage)) candidateFences.push(fileFence(join(stage, name)));
      writeExclusive(join(audit.path, 'history-schema-preflight.json'), JSON.stringify({ version: 1, historyVersion: preflightHistoryVersion, migrateSummary }), 0o600); syncDirectory(audit.path);
            snapshot = createCurrentPublicLlmPreservation({ DB: Database ?? requireApi('better-sqlite3'), root, lock, audit: audit.path, helper, migrateSummary, verifyState: async () => { await verifyPeers(); await users(); await census(); } });
    },
    async stop(name) {
      phase = 'stop-' + name;
      if (openai && !continuation) {
        const journal = createPublicStopJournal(audit.path, name, () => lock.verify()); stopJournals.push(journal);
        return executePublicLlmStop({ name, stoppedStand, legacyGatewayStop, peers, peerModels, healthy,
          verifyPeers, users, census, record, addRecordFence: file => fences.push(fileFence(join(lock.path, file))),
          d, inspect, acknowledgedGatewayStops, trace: createPublicStopTrace(name, row => journal.append(row), { now }) });
      }
      await verifyPeers(); await users();
      healthy.delete(name);
      const c = peers.get(name), a = peerModels.get(name);
      if (stoppedStand) { cleanStopped(c); return; }
      const eligible = legacyGatewayStop && Object.hasOwn(LEGACY_GATEWAY_STOP_IDS, name);
      if (eligible) {
        for (const writer of ['web', 'api', 'worker']) cleanStopped(peers.get(writer));
        await census();
      }
      const submittedMs = Date.now();
      if (eligible) {
        record('legacy-stop-' + name + '-submission.json', { version: 1, id: c.Id, image: c.Image, submittedMs, acknowledgement: LEGACY_GATEWAY_STOP_ACK });
        fences.push(fileFence(join(lock.path, 'legacy-stop-' + name + '-submission.json')));
      }
      const stopOutput = await d(['container', 'stop', '--time', name === 'api' ? '60' : '30', c.Id], { timeout: name === 'api' ? 75000 : 45000 });
      const stopped = await inspect(c.Id, name, a.model, a.images, a.selection); safe(control(c) === control(stopped));
      if (eligible && stopped.State.ExitCode === 137) {
        const events = (await d(['events', '--since', new Date(submittedMs).toISOString(), '--until', new Date(Date.parse(stopped.State.FinishedAt) + 1000).toISOString(), '--filter', 'type=container', '--filter', 'container=' + c.Id, '--filter', 'event=kill', '--filter', 'event=die', '--format', '{"id":{{json .Actor.ID}},"action":{{json .Action}},"signal":{{json .Actor.Attributes.signal}},"exit":{{json .Actor.Attributes.exitCode}},"time":{{json .Time}}}'], { timeout: 15000 })).trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
        const proof = validateLegacyGatewayStop({ before: c, after: stopped, events, submittedMs, stopOutput, writers: ['web', 'api', 'worker'].map(n => peers.get(n)) });
        record('legacy-stop-' + name + '-verified.json', proof); acknowledgedGatewayStops.set(c.Id, proof);
        fences.push(fileFence(join(lock.path, 'legacy-stop-' + name + '-verified.json')));
      } else cleanStopped(stopped);
      peers.set(name, stopped);
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
        async validateBaseline(value) {
          if (summaryRecovery) { safe(equal(value, continuation.baseline) && value.historyVersion === 3); return; }
          safe(!continuation && value.historyVersion === preflightHistoryVersion && (migrateSummary ? value.historyVersion === 3 && value.llm !== null : value.historyVersion === 4 || value.llm === null));
        },
        async migrateSummary() {
          safe((!continuation || summaryRecovery) && migrateSummary && fencedBaseline.historyVersion === 3 && fencedBaseline.llm !== null);
          phase = 'migrate-summary'; await verifyPeers(); await users(); await census();
          for (const name of ['web', 'api', 'worker']) cleanStopped(peers.get(name));
          const intent = { version: 1, project: PROJECT, migration: 'history-summary-v3-to-v4', from: 3, to: 4,
            baseline: 'fenced', target: 'post-migration', image: candidateImages.api.Id, rollback: 'separate-pre-reopening-qualification-required' };
          const evidence = summaryRecovery ? join(audit.path, outputPrefix) : audit.path;
          writeExclusive(join(evidence, 'history-migration-intent.json'), JSON.stringify(intent), 0o600); syncDirectory(evidence);
          record('history-migration-intent.json', intent);
          await helper('migrate-summary', 'migrate-summary', async (_id, _d, _check, receipt) => {
            safe(equal(receipt, { ready: true, migration: 'history-summary-v3-to-v4' }));
          });
        },
        async verifyMigration(original, migrated) {
          safe((!continuation || summaryRecovery) && migrateSummary); phase = 'verify-history-migration';
          await verifyPeers(); await users(); await census();
          const evidence = summaryRecovery ? join(audit.path, outputPrefix) : audit.path;
          const receipt = verifyPublicLlmSummaryMigration({ DB: Database ?? requireApi('better-sqlite3'), before: original, after: migrated,
            beforeDirectory: join(evidence, 'fenced'), afterDirectory: join(evidence, 'post-migration') });
          writeExclusive(join(evidence, 'history-migration-verified.json'), JSON.stringify(receipt), 0o600); syncDirectory(evidence);
          record('history-migration-verified.json', receipt);
        },
    async candidate() {
      if (summaryRecovery) {
        phase = 'summary-candidate-pins'; await verifyPeers(); await verifyRetainedImages(); await users(); await census();
        safe(equal(fencedBaseline, continuation.baseline)); candidateImages = continuation.summaryCandidates;
        writeExclusive(join(stage, 'compose.images.json'), JSON.stringify({ services: Object.fromEntries(Object.entries(candidateImages).map(([name, im]) => [name, { image: im.Id }])) }), 0o600); syncDirectory(stage);
        candidateFences.push(fileFence(join(stage, 'compose.images.json')));
        const pinned = JSON.parse(await d(stageArgs(['config', '--format', 'json']), { env: { ...options.env, SCAN_JWT_SECRET: CONFIG_SECRET } }));
        validatePublicLlmConfig(pinned, root, profile.cve, settings.selection, candidateImages); fence(); return;
      }
      if (continuation?.admissionOnly) {
        phase = continuation.rolloutOnly ? 'rollout-current-pins' : 'admit-current-pins'; continuation.initialize.verifyImageSource(); candidateImages = continuation.initialize.candidateImages;
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
      const qualified = await checkSource(root, openai ? { openai: settings.selection } : undefined);
      safe(qualified?.typescript === true && qualified?.bundle === true && (!openai || qualified.openai === true));
      phase = 'build-config'; const rendered = JSON.parse(await d(publicLlmComposeArguments(root, ['config', '--format', 'json'], { cve: Boolean(profile.cve), directory: stage, pinned: false }), { env: { ...options.env, SCAN_JWT_SECRET: CONFIG_SECRET } }));
      validatePublicLlmConfig(rendered, root, profile.cve, settings.selection);
      if (continuation || flags.includes('--build')) {
        const jwtStat = fs.lstatSync(join(root, STATE, 'scan-jwt'));
        record('build-checkpoint.json', { version: openai ? 2 : 1,
                  ...(openai ? { deployment: validateOpenAiBuildDeployment({ prior: priorSelection, next: settings.selection }) } : {}),
                  phase: 'validated-before-build', source: capturePublicLlmSource(root, { openai }).manifest,
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
      // Existing seven-service current upgrades only; first LLM activation has
      // no prior llm-egress image and retains its original bootstrap contract.
      if (!continuation && priorSelection && flags.includes('--build')) {
        phase = 'build-image-retention'; await verifyPeers(); await verifyRetainedImages(); await users(); await census();
        retainedReferences = await retainPublicLlmBuildImages({ root, audit: 'deploy-' + audit.nonce, images: priorImages, run: d, options, verify: fence });
      }
      if (openai) for (const name of [...(upgradeWorkerEgress ? ['worker', 'egress'] : []), 'api', 'web', 'openai-egress']) {
        phase = 'build-submit-' + name; await verifyPeers(); await verifyRetainedImages(); await users(); await census();
        try { await d(publicLlmComposeArguments(root, ['build', name], { cve: Boolean(profile.cve), directory: stage, pinned: false }),
          { env: { ...options.env, SCAN_JWT_SECRET: CONFIG_SECRET }, timeout: 600000 }); }
        catch { record('build-failure.json', { version: 2, phase, role: name, category: 'guard' }); throw Error('PUBLIC OpenAI build boundary rejected.'); }
        fence(); await verifyPeers(); await verifyRetainedImages();
      }
      if (!openai && (continuation || flags.includes('--build'))) for (const name of ['api', 'worker', 'web', 'llm-egress']) {
        phase = 'build-submit-' + name;
        if (continuation?.existingBuildOnly) { await verifyPeers(); await users(); await census(); fence(); }
        if (retainedReferences) { await verifyPeers(); await verifyRetainedImages(); await users(); await census(); }
        try { await d(publicLlmComposeArguments(root, ['build', name], { cve: Boolean(profile.cve), directory: stage, pinned: false }), { env: { ...options.env, SCAN_JWT_SECRET: CONFIG_SECRET }, timeout: 600000 }); }
        catch (error) {
          const category = continuation?.existingBuildOnly && ownValue(error, 'category') === 'storage_io' ? 'storage_io' : ['timeout', 'docker_unavailable', 'network_pool', 'resources', 'runtime_health', 'image', 'unclassified'].includes(error?.category) ? error.category : 'guard';
          const cause = ownValue(error, 'buildCause');
          record('build-failure.json', { version: 1, phase, role: name, category, ...(continuation?.existingBuildOnly && ['timeout', 'docker_unavailable', 'resources', 'storage_io', 'dependency_install', 'typescript', 'base_image_resolution', 'build_context', 'build_network', 'unclassified'].includes(cause) ? { cause } : {}) }); throw Error('PUBLIC LLM build boundary rejected.');
        }
        if (continuation?.existingBuildOnly) { fence(); await verifyPeers(); await users(); await census(); }
      }
      if (!continuation) { phase = 'build-retained-images'; await verifyRetainedImages(); }
      candidateImages = {};
      for (const [name, spec] of Object.entries(nextModel().services)) {
        phase = 'build-image-' + name;
        const ref = !continuation && !flags.includes('--build') || name.endsWith('volume-init') || name === 'egress' && !upgradeWorkerEgress || openai && (name === 'llm-egress' || name === 'worker' && !upgradeWorkerEgress) ? priorImages[name].Id : spec.image;
        const a = JSON.parse(await d(['image', 'inspect', ref])); safe(a.length === 1); validatePublicLlmImage(a[0], name); candidateImages[name] = a[0];
      }
      phase = 'build-pins'; writeExclusive(join(stage, 'compose.images.json'), JSON.stringify({ services: Object.fromEntries(Object.entries(candidateImages).map(([n, im]) => [n, { image: im.Id }])) }), 0o600); syncDirectory(stage);
      candidateFences.push(fileFence(join(stage, 'compose.images.json')));
      const pinned = JSON.parse(await d(stageArgs(['config', '--format', 'json']), { env: { ...options.env, SCAN_JWT_SECRET: CONFIG_SECRET } }));
      validatePublicLlmConfig(pinned, root, profile.cve, settings.selection, candidateImages); fence(); await verifyPeers();
    },
    async verifyExistingStores() {
      safe(openai && priorSelection !== null && fencedBaseline.llm !== null && fencedBaseline.historyVersion === 4);
      phase = 'verify-existing-stores'; await verifyPeers(); await verifyRetainedImages(); await users(); await census();
      // Run the candidate source's actual constructor on a disposable copy of the
      // captured store. Never give QuotaLedger the live volume or audit snapshot.
      phase = 'verify-existing-quota'; fence();
      const quotaSnapshot = join(audit.path, 'fenced/llm/ledger.sqlite'), DB = Database ?? requireApi('better-sqlite3');
      const SnapshotDB = sealedSnapshotDatabase(DB);
      safe(currentLlmFingerprint(SnapshotDB, fs, crypto, quotaSnapshot, 'quota') === fencedBaseline.llm.quota);
      safe(checkOpenAiQuotaSnapshot(root, { selection: settings.selection, snapshotPath: quotaSnapshot }).compatible === true);
      fence(); safe(currentLlmFingerprint(SnapshotDB, fs, crypto, quotaSnapshot, 'quota') === fencedBaseline.llm.quota);
      phase = 'verify-existing-auth'; fence();
      const authSnapshot = join(audit.path, 'fenced/core/auth.sqlite');
      safe(preflightAuthVersion === (migrateAuth ? 2 : 3));
      safe(currentLlmFingerprint(SnapshotDB, fs, crypto, authSnapshot, 'auth') === fencedBaseline.core.auth.logicalSha256);
      const publicEnvironment = nextModel().services.api.environment;
      const environment = Object.fromEntries(['AUTH_ORIGIN', 'AUTH_ALLOW_INSECURE_LOCAL_HTTP',
        'SCAN_BROWSER_ALLOWED_USER_IDS', 'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS'].map(k => [k, publicEnvironment[k]]));
      const auth = qualifyPublicAuthSnapshot(root, { DB, snapshotPath: authSnapshot, environment, migrate: migrateAuth });
      safe(auth.before === fencedBaseline.core.auth.logicalSha256);
      if (migrateAuth) {
        const path = join(audit.path, 'auth-schema-migration.json');
        writeExclusive(path, JSON.stringify(auth), 0o600); syncDirectory(audit.path); fences.push(fileFence(path, 4096, 0o600));
      } else safe(auth.expected === auth.before);
      fence(); await verifyPeers(); await verifyRetainedImages(); await users(); await census();
      return auth;
    },
    async initialize(fresh) {
      phase = fresh ? 'initialize' : 'check'; safe(!fresh || priorSelection === null);
      if (summaryRecovery) { safe(!fresh); await verifyPeers(); await verifyRetainedImages(); await users(); await census(); return; }
      if (continuation?.existingBuildOnly) {
        // No writable initializer/check helper for existing durable stores. The
        // readonly fenced/before-api/after-api snapshots are the verification.
        safe(!fresh && priorSelection !== null && fencedBaseline.llm !== null && equal(fencedBaseline.llm, continuation.baseline.llm));
        await verifyPeers(); await users(); await census(); return;
      }
      await helper(fresh ? 'initialize' : 'check', fresh ? 'initialize' : 'check');
    },
    async startRetained() {
      if (!stoppedStand) return;
      phase = 'start-retained'; await verifyPeers(); await verifyRetainedImages(); await users(); await census();
      const c = peers.get('egress'), a = peerModels.get('egress'), image = priorImages.egress;
      cleanStopped(c);
      const rows = JSON.parse(await d(['image', 'inspect', image.Id]));
      safe(rows.length === 1 && rows[0].Id === image.Id && rows[0].Os === image.Os && equal(rows[0].Config, image.Config));
      validatePublicLlmImage(rows[0], 'egress');
      await d(['container', 'start', c.Id]);
      if (continuation?.existingBuildOnly) retainedRestarted = true;
      const current = await inspect(c.Id, 'egress', a.model, a.images, a.selection);
      safe(control(c) === control(current) && current.State.Running && current.State.Status === 'running' && current.State.ExitCode === 0 &&
        Number.isSafeInteger(current.State.Pid) && current.State.Pid > 0 && current.RestartCount === 0 &&
        !current.State.Paused && !current.State.OOMKilled && !current.State.Dead && !current.State.Restarting && !current.State.Error &&
        current.State.StartedAt !== c.State.StartedAt && Number.isFinite(Date.parse(current.State.StartedAt)));
      peers.set('egress', current); await verifyPeers(); await users(); await census();
    },
    async resumeExisting(name) {
      safe(openai && ['worker', 'llm-egress'].includes(name));
      phase = 'resume-retained-' + name; await verifyPeers(); await verifyRetainedImages(); await users(); await census();
      const previous = peers.get(name), authority = peerModels.get(name);
      if (previous.State.Running) return;
      cleanStopped(previous); await d(['container', 'start', previous.Id]);
      const current = await inspect(previous.Id, name, authority.model, authority.images, authority.selection);
      safe(control(previous) === control(current) && current.State.Running && current.State.Status === 'running' &&
        Number.isSafeInteger(current.State.Pid) && current.State.Pid > 0 && current.RestartCount === 0 &&
        !current.State.Paused && !current.State.Dead && !current.State.Restarting && !current.State.OOMKilled && !current.State.Error &&
        current.State.StartedAt !== previous.State.StartedAt && Number.isFinite(Date.parse(current.State.StartedAt)));
      peers.set(name, current); await verifyPeers(); await users(); await census();
    },
    async up(name) {
      safe(!openai || ['openai-egress', 'api', 'web', ...(upgradeWorkerEgress ? ['worker', 'egress', 'llm-egress'] : [])].includes(name));
      phase = 'up-' + name; await verifyPeers(); await verifyRetainedImages(); await users(); healthy.delete(name);
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
          const workerProbe = name === 'worker' && settings.selection.operations ? `
                      import * as nativeZlib from 'node:zlib';
                      import {PUBLIC_IMAGE_RESOURCE_POLICY as resourcePolicy, PUBLIC_IMAGE_CHECKS_VERSION as checksVersion, PUBLIC_IMAGE_LIMITS as imageLimits} from './src/oci/public-image-policy.ts';
                      import {publicResourceEnvelope} from './src/worker/worker-runtime.ts';
                      if(typeof nativeZlib.createZstdDecompress!=='function'||resourcePolicy!=='public-hub-resources-v2'||checksVersion!=='trivy-0.69.3-public-archive-v2'||
                        imageLimits.compressedLayer!==256*1024**2||imageLimits.compressedTotal!==768*1024**2||imageLimits.wireBytes!==800*1024**2||
                        imageLimits.expandedLayer!==512*1024**2||imageLimits.expandedTotal!==1024**3||imageLimits.scratchBytes!==2*1024**3||
                        imageLimits.deadlineMs!==180000||!publicResourceEnvelope())throw Error('public-image-runtime');
                    ` : '';
                    const code = workerProbe + (name === 'api' ? PUBLIC_LLM_GATEWAY_PROBE + (openai ? PUBLIC_LLM_GATEWAY_PROBE.replaceAll('llmGateway', 'openAiGateway').replaceAll('connectLlmGateway', 'connectOpenAiGateway').replaceAll('llm-egress', 'openai-egress') : '') : '') + reportProbe;
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
      phase = 'publish'; await verifyPeers(); await verifyRetainedImages(); await users(); await census();
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
      phase = 'postflight-peers'; await verifyPeers(); await verifyRetainedImages(); await census(); await users();
      phase = 'postflight-namespace';
      const after = continuation
        ? await inspectPublicLlmNamespace(d, options, root, profile.cve, settings.selection, { secret: jwt, images: candidateImages })
        : await inspectCurrentPublicLlmNamespace(d, options, root, profile.cve, settings.selection, { secret: jwt, images: candidateImages }, 'deploy-' + audit.nonce);
      phase = 'postflight-storage';
      safe(after.containers.length === (openai ? 8 : 7) && after.networks.length === (openai ? 8 : 6) &&
        after.volumes.length === (settings.selection.keyVolume ? 3 : 2) + (openai && settings.selection.credentialVolume ? 1 : 0));
      if (openai) for (const name of ['auth-volume-init', 'scan-volume-init', ...(upgradeWorkerEgress ? [] : ['worker', 'egress', 'llm-egress'])])
        safe(ownOne(after, name).Id === ownOne(before, name).Id);
      for (const c of after.containers) {
        if (role(c).endsWith('volume-init')) cleanStopped(c);
        else safe(c.State.Running && c.State.Status === 'running' && !c.State.Paused && !c.State.Dead && !c.State.Restarting && !c.State.OOMKilled && c.RestartCount === 0);
      }
      safe(ownOne(after, 'api').State.Health?.Status === 'healthy');
      for (const v of before.volumes.filter(v => v.Name.startsWith(PROJECT + '_'))) safe(after.volumes.some(n => equal(n, v)));
      for (const n of before.networks) { const current = after.networks.find(x => x.Name === n.Name); safe(current && current.Id === n.Id && equal({ ...current, Containers: {} }, { ...n, Containers: {} })); }
      phase = 'postflight-receipt';
      if (acknowledgedGatewayStops.size) {
        fence(); const value = { version: 1, acknowledgement: LEGACY_GATEWAY_STOP_ACK, stops: [...acknowledgedGatewayStops.values()] };
        validateLegacyGatewayStopArchive(value, JSON.parse(readBounded(join(lock.path, 'build-checkpoint.json'), 16 * 1024 ** 2, 0o600)));
        writeExclusive(join(audit.path, 'legacy-gateway-stops.json'), JSON.stringify(value), 0o600); syncDirectory(audit.path);
      }
      if (records.has(recordName('build-checkpoint.json'))) writeExclusive(join(audit.path, continuation ? outputPrefix + '/build-checkpoint.json' : 'build-checkpoint.json'), readBounded(join(lock.path, recordName('build-checkpoint.json')), 16 * 1024 ** 2, 0o600), 0o600);
      if (continuation?.initialize || continuation?.existingBuildOnly) {
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
    const result = openai ? await executeOpenAiMaintenance(ops, { upgradeWorkerEgress, migrateAuth }) : continuation && !summaryRecovery
          ? await executePublicLlmMaintenance(ops, continuation.baseline ?? null, continuation.admissionOnly ? continuation : null)
          : await executeCurrentPublicLlmMaintenance(ops, { migrateSummary, originalBaseline: summaryRecovery ? continuation.baseline : null });
    log(`Public LLM local deployment READY; key ${(openai ? settings.selection.credentialVolume : settings.selection.keyVolume) ? 'supplied, generation unverified' : 'unavailable (operator setup required)'}; accounts/reports/JWT/history/quota preserved.`);
    return result;
  } catch (error) {
    if ((continuation?.admissionOnly || summaryRecovery) && records.has(recordName('continue.json'))) {
      try {
        record('failure.json', { version: 1, phase, ...finiteFailure(error, 'maintenance'), ...(readinessFailure ? { readiness: readinessFailure } : {}) });
      } catch { /* Preserve HOLD even when a failed source fence prevents diagnostics. */ }
    }
    const stopDiagnostic = publicStopDiagnostic(error);
    const boundary = ownValue(error, 'boundary'), category = ownValue(error, 'category');
    const metadataDiagnostic = continuation?.existingBuildOnly && ['api', 'auth-volume-init', 'egress', 'llm-egress', 'scan-volume-init', 'web', 'worker'].some(name => boundary === 'prior-image-inspect-' + name) && ['image', 'timeout', 'docker_unavailable', 'network_pool', 'resources', 'runtime_health', 'unclassified', 'storage_io', 'guard'].includes(category);
    if (typeof onDiagnostic === 'function') {
      // Only finite internal enums, never an Error/stack/command/config value.
      const diagnostic = PUBLIC_LLM_PREFLIGHT_DIAGNOSTICS[phase];
      try {
        if (stopDiagnostic) onDiagnostic(Object.freeze({ phase, ...stopDiagnostic }));
        else if (metadataDiagnostic) onDiagnostic(Object.freeze({ phase: boundary, reason: category === 'storage_io' ? 'DockerIO' : category }));
        else if (diagnostic) onDiagnostic(Object.freeze({ phase, reason: diagnostic }));
      } catch { /* Diagnostics cannot change refusal/lock handling. */ }
    }
    const failure = new Error(`PUBLIC LLM maintenance ${hold ? 'HOLD' : 'refused'}; phase=${phase}; details withheld. No automatic retry, cleanup, rollback or secret rotation.`);
    if (metadataDiagnostic) { failure.boundary = boundary; failure.category = category; }
    if (stopDiagnostic) stopDiagnostics.set(failure, stopDiagnostic);
    throw failure;
  } finally { if (!hold) lock.release(); }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  publicLlmStand(process.argv.slice(2)).catch(error => {
    const stopDiagnostic = publicStopDiagnostic(error);
    if (stopDiagnostic) console.error('PUBLIC LLM stop diagnostic ' + JSON.stringify(stopDiagnostic));
    const safeMessage = /^PUBLIC LLM maintenance (?:HOLD|refused); phase=[a-z-]+; details withheld\. No automatic retry, cleanup, rollback or secret rotation\.$/.test(error?.message ?? '');
    if (error?.reason === 'REBUILD_PRIOR_BUILD_FAILURE_REJECTED') { console.error('PUBLIC LLM rebuild refused; phase=prior-build-failure; existing failure receipt preserved; no retry permitted.'); process.exitCode = 1; }
    else console.error(safeMessage ? error.message : 'PUBLIC LLM integration refused/HOLD; details withheld. Review the shared public operation lock; never delete uncertainty evidence automatically.'); process.exitCode = 1;
  });
}
