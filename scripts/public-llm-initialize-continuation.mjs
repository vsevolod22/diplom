// One reviewed current-source rebuild after the exact created/never-started HOLD.
// No unlock, retry, historical recovery, key access or Docker lifecycle in this checker.
import * as fs from 'node:fs';
import { execFile } from 'node:child_process';
import * as crypto from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PROJECT, STATE, runIsolatedDocker, readProfile, LABEL, copyStableSqlite, recoverySqlite, validateExportManifest } from './public-image-stand.mjs';
import { validatePublicLlmImage, validatePublicLlmContainer, validatePublicLlmHelper, llmFingerprint, PUBLIC_LLM_ENV, capturePublicLlmSource, expectedPublicLlmConfig, assertAdmissionStoreEmpty } from './public-llm-stand.mjs';
import { PUBLIC_READY_PROBE } from './refresh-public-cve.mjs';
import { privateFile, byteFile, directoryIdentity, publicLlmSecretlessControl, preparePublicLlmBuildContinuation } from './public-llm-build-continuation.mjs';

export const INITIALIZE_HOLD = Object.freeze({
  audit: 'deploy-8d83a8806715c2f0fa575efedee1b0af',
  id: '8ac5fd9616bec19db55e8832700f7c777daef65f067dc4bd365cf0a8dfb8fec6',
  image: 'sha256:62aecce04965c159ccd8aae03b1b62e0cfcdca557021f1a75fbf3164b8e8cc3a',
  originalWebImage: 'sha256:b357e1b0a30fdf242d2b987e1bb3b37789b20db6ff2ab515f02785adef8cd211',
  staleWebImage: 'sha256:4abf767d89a53fe0cc5ae6cc529fc291d5cce8e46844dd387a840634895ed0a2',
});
export const INIT_EXIT_HOLD = Object.freeze({
  id: '60719343c4b567cc20c4cc6d79cd1edfb765b2830fe6098be9281ef10c860615',
  image: 'sha256:baaa16f620fde9e0ef090641b6f0418289188e637b3ccfbcb173ffef3e2e7512',
  startedAt: '2026-10-21T21:26:52.398056302Z', finishedAt: '2026-10-21T21:26:52.713089219Z',
});
export const ADMIT_HOLD = Object.freeze({
  worker: { id: '29da7c139abbd22eb0a6479407d5423fea967025354c6e2a6517150077701346', image: 'sha256:7ef6b061848a5f24343fe627389ecdcc9794e0a7e7e264350c5bd7e7be35cc4a', startedAt: '2026-10-21T21:55:35.823898252Z' },
  gateway: { id: '31bf4d77e46f6dc3d79aaf47ec1b52d54dab911c6a4c6340acbf984030a8aa1d', image: 'sha256:2c34dba54c7572b5254478b7c9de8352c79f73324f2a0f8fd094079adca65f5f', startedAt: '2026-10-21T21:55:30.078297472Z' },
  api: '7c1d0907a96a49ab78e556141d1bb4bb52730275c23795374fe54ba53b95dfdd', web: 'f73ea9fbd3de46568ab67b091e9af427d3c30249a56e515ac4e2c20d5ba2f185',
  initializer: 'c792697ca4403f1dc22ff4dd5c87d091e7e31361374d07c151e978e5d852897e',
});
export const API_HOLD = Object.freeze({
  backup: '2ead4f5b02407b5a18d3dea5d9caa3f9eddb25b89a5b2d4c423366e2b9ac6ca1',
  failure: { version: 1, phase: 'ready-worker', category: 'guard', frames: [{ module: 'public-llm-stand', line: 946 }, { module: 'public-llm-stand', line: 451 }, { module: 'public-llm-stand', line: 1011 }] },
});
const canonical = v => Array.isArray(v) ? v.map(canonical) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k => [k, canonical(v[k])])) : v;
const equal = (a, b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
const digest = v => crypto.createHash('sha256').update(JSON.stringify(canonical(v))).digest('hex');
const need = v => { if (!v) throw Error('PUBLIC LLM created-initializer check refused; details withheld.'); };
const names = p => fs.readdirSync(p).sort();
const zero = v => v === '0001-01-01T00:00:00Z';

export async function preparePublicLlmInitializeContinuation(options) {
  need(options.audit === INITIALIZE_HOLD.audit);
  const context = await preparePublicLlmBuildContinuation({ ...options, createdInitializerOnly: true });
  need(context.replacement && context.initialize);
  return context;
}

export async function preparePublicLlmRebuildContinuation(options) {
  need(options.audit === INITIALIZE_HOLD.audit);
  const context = await preparePublicLlmBuildContinuation({ ...options, createdInitializerOnly: true, postRetirementOnly: true });
  need(context.initialize?.retired && context.replacement && context.apiReplacement && context.webReplacement);
  return context;
}

export async function preparePublicLlmInitExitContinuation(options) {
  need(options.audit === INITIALIZE_HOLD.audit);
  const context = await preparePublicLlmBuildContinuation({ ...options, createdInitializerOnly: true, postRetirementOnly: true, failedInitializerOnly: true });
  need(context.initialize?.failed && context.replacement && context.apiReplacement && context.webReplacement);
  return context;
}

export async function preparePublicLlmAdmitContinuation(options) {
  need(options.audit === INITIALIZE_HOLD.audit);
  const context = await preparePublicLlmBuildContinuation({ ...options, createdInitializerOnly: true, postRetirementOnly: true, failedInitializerOnly: true, admissionOnly: true });
  need(context.initialize?.admission && !context.initialize.failed && context.apiReplacement && context.webReplacement && context.inventory.containers.length === 7);
  return context;
}
export async function preparePublicLlmApiContinuation(options) {
  need(options.audit === INITIALIZE_HOLD.audit);
  const context = await preparePublicLlmBuildContinuation({ ...options, createdInitializerOnly: true, postRetirementOnly: true, failedInitializerOnly: true, admissionOnly: true, apiOnly: true });
  need(context.apiOnly && context.initialize?.apiBaseline?.llm && context.admissionOnly);
  return context;
}
function admissionPeer(c, name, images, model) {
  const fixed = name === 'worker' ? ADMIT_HOLD.worker : ADMIT_HOLD.gateway;
  need(c.Id === fixed.id && c.Image === fixed.image && c.State.StartedAt === fixed.startedAt && c.State.Running === true && c.State.Status === 'running' && c.State.Pid > 0 && c.RestartCount === 0 && c.State.ExitCode === 0 && zero(c.State.FinishedAt) && !c.State.Error && !c.State.OOMKilled && !c.State.Dead && !c.State.Paused && !c.State.Restarting);
  validatePublicLlmContainer(c, name, model.services[name], images[name], model, { images }, { version: 1, keyVolume: null });
}

export function classifyInitExitFailure(text) {
  need(typeof text === 'string' && text.length <= 524288 && /ENOENT/.test(text) && /syscall: ['\"]mkdir['\"]/.test(text) && /path: ['\"]\/tmp\/tsx-65532['\"]/.test(text) && /tsx\/dist\//.test(text));
  return { category: 'TSX_CACHE_ENOENT_MKDIR', path: '/tmp/tsx-65532' };
}
async function readInitExitFailure(run, options) {
  let text;
  if (run !== runIsolatedDocker) text = await run(['container', 'logs', '--tail', '300', INIT_EXIT_HOLD.id], options);
  else text = await new Promise((resolve, reject) => execFile('docker', ['container', 'logs', '--tail', '300', INIT_EXIT_HOLD.id], { cwd: options.root, env: options.env, timeout: 15000, maxBuffer: 524288, encoding: 'utf8' }, (error, stdout, stderr) => error ? reject(Error('Init-exit log classification refused.')) : resolve(stdout + '\n' + stderr)));
  return classifyInitExitFailure(text); // Never return/store raw output.
}
function validateHistoricalInitExit(c, image) {
  const name = `${PROJECT}-llm-${INITIALIZE_HOLD.audit.slice(7)}-rebuild-current-initialize`;
  need(c.Id === INIT_EXIT_HOLD.id && c.Image === INIT_EXIT_HOLD.image && image.Id === INIT_EXIT_HOLD.image && c.Name === '/' + name);
  need(Number.isFinite(Date.parse(c.Created)) && c.State.Status === 'exited' && c.State.Running === false && c.State.Pid === 0 && c.State.ExitCode === 1 && c.RestartCount === 0 && c.State.StartedAt === INIT_EXIT_HOLD.startedAt && c.State.FinishedAt === INIT_EXIT_HOLD.finishedAt && !c.State.Error);
  const map = entries => { need(new Set(entries.map(s => s.slice(0, s.indexOf('=')))).size === entries.length); return Object.fromEntries(entries.map(s => [s.slice(0, s.indexOf('=')), s.slice(s.indexOf('=') + 1)])); };
  need(equal(map(c.Config.Env), { ...map(image.Config.Env), ...PUBLIC_LLM_ENV }));
  // ONLY this exact historical helper may be projected from the old Env policy.
  const projected = structuredClone(c); projected.Config.Env = [...c.Config.Env.filter(s => !s.startsWith('TMPDIR=')), 'TMPDIR=/backup'];
  validatePublicLlmHelper(projected, name, image, 'initialize', 'exited');
}

async function heldCoreBackup(core, Database) {
  const directoryCheck = directoryIdentity(core), coreNames = names(core), files = [];
  need(coreNames.every(n => /^(?:auth|ledger)\.sqlite(?:-wal|-shm)?$/.test(n) || n === 'private-manifest.json'));
  const manifestFile = privateFile(join(core, 'private-manifest.json'), 65536), manifest = JSON.parse(manifestFile.bytes);
  files.push(manifestFile); validateExportManifest(manifest);
  for (const name of coreNames.filter(n => n !== 'private-manifest.json')) {
    const proof = byteFile(join(core, name)); files.push(proof);
    if (['auth.sqlite', 'ledger.sqlite'].includes(name)) need(proof.sha256 === manifest.receipt[name.split('.')[0]].sha256);
  }
  const temporary = fs.mkdtempSync(join(tmpdir(), 'public-llm-held-core-')), copies = {};
  let baseline;
  try {
    for (const r of ['auth', 'ledger']) copies[r] = copyStableSqlite(fs, crypto, join(core, r + '.sqlite'), join(temporary, r));
    const paths = Object.fromEntries(Object.entries(copies).map(([r, c]) => [r, c.path]));
    const restored = await recoverySqlite(Database, fs, crypto, paths, null);
    for (const r of ['auth', 'ledger']) need(restored[r].logicalSha256 === manifest.receipt[r].logicalSha256);
    baseline = { core: Object.fromEntries(Object.entries(paths).map(([r, p]) => [r, { logicalSha256: llmFingerprint(Database, fs, crypto, p, r) }])), llm: null, empty: false };
    for (const c of Object.values(copies)) c.verify();
  } finally { for (const c of Object.values(copies)) c.cleanup(); fs.rmSync(temporary, { recursive: true, force: true }); }
  return { files, baseline, verify() { directoryCheck(); need(equal(names(core), coreNames)); files.forEach(f => f.verify()); } };
}

async function heldAdmissionBackup(path, Database) {
  const core = await heldCoreBackup(join(path, 'core'), Database), llm = join(path, 'llm');
  const directories = [directoryIdentity(path), directoryIdentity(llm)];
  need(equal(names(path), ['core', 'llm']) && equal(names(llm), ['auth.sqlite', 'ledger.sqlite', 'private-manifest.json']));
  const manifestFile = privateFile(join(llm, 'private-manifest.json'), 65536), manifest = JSON.parse(manifestFile.bytes);
  validateExportManifest(manifest);
  const files = [manifestFile, ...['auth', 'ledger'].map(r => byteFile(join(llm, r + '.sqlite')))];
  const fingerprints = {};
  for (const [role, kind] of [['auth', 'history'], ['ledger', 'quota']]) {
    const proof = files.find(f => f.path.endsWith('/' + role + '.sqlite'));
    need(proof.sha256 === manifest.receipt[role].sha256 && proof.identity.size === manifest.receipt[role].bytes);
    fingerprints[kind] = llmFingerprint(Database, fs, crypto, proof.path, kind, true);
    need(fingerprints[kind] === manifest.receipt[role].logicalSha256);
    assertAdmissionStoreEmpty(Database, proof.path, kind);
  }
  const verify = () => { core.verify(); directories.forEach(v => v()); need(equal(names(path), ['core', 'llm']) && equal(names(llm), ['auth.sqlite', 'ledger.sqlite', 'private-manifest.json'])); files.forEach(f => f.verify()); };
  verify(); return { files: [...core.files, ...files], baseline: { core: core.baseline.core, llm: fingerprints, empty: true }, verify };
}
// Recheck saved authority except the three explicitly reviewed host-only modules.
// Their prior hashes stay evidence; today's full execution closure is reviewed anew.
function savedAdmissionProofs(root, review) {
  const changed = new Set(['scripts/public-llm-stand.mjs', 'scripts/public-llm-build-continuation.mjs', 'scripts/public-llm-initialize-continuation.mjs']);
  need(Array.isArray(review.original) && Array.isArray(review.state));
  const verify = () => {
    for (const p of [...review.state, ...review.original]) {
      need(typeof p.path === 'string' && !p.path.startsWith('/') && !p.path.split('/').includes('..'));
      if (changed.has(p.path)) continue;
      const path = join(root, p.path), s = fs.lstatSync(path), stamp = { dev: String(s.dev), ino: String(s.ino), mode: s.mode, uid: s.uid, nlink: s.nlink, size: s.size, mtime: s.mtimeMs, ctime: s.ctimeMs };
      // Retained SQLite SHM bytes are unchanged; only its advisory timestamps may
            // differ across historical readonly inspections. Main/WAL stay exact, and
            // this checker's freshly captured SHM proof remains strict during execution.
            const shm = new RegExp('^\\.local-public-images/llm-deployments/' + INITIALIZE_HOLD.audit + '/(?:fenced|(?:continued|initialize-current|rebuild-current|init-exit-current)/fenced)/core/(?:auth|ledger)\\.sqlite-shm$').test(p.path);
            need(!s.isSymbolicLink() && Object.entries(p.identity).every(([k, v]) => shm && ['mtime', 'ctime'].includes(k) || stamp[k] === v));
      if (p.content !== undefined) need(privateFile(path, 16 * 1024 ** 2).bytes === p.content);
      if (p.sha256) need(byteFile(path, !p.path.startsWith('scripts/') && !p.path.startsWith('server/')).sha256 === p.sha256);
    }
  };
  verify(); return verify;
}

// Policy projection ONLY: this never certifies unavailable original API metadata.
// Bound to this created-initializer prefix and its actually inspected stale API.
function validateRetiredApi(c, pinnedId, replacement, model, images, secret, initExit = false) {
  need(c.Config?.Labels?.['com.docker.compose.service'] === 'api' && c.Image === pinnedId && c.Config.Image === pinnedId);
  need(replacement.Id === (initExit ? INIT_EXIT_HOLD.image : INITIALIZE_HOLD.image) && replacement.Id !== pinnedId);
  const s = c.State;
  need(s.Status === 'exited' && s.Running === false && s.Pid === 0 && s.ExitCode === 0 && c.RestartCount === 0 && !s.Paused && !s.Restarting && !s.OOMKilled && !s.Dead && !s.Error);
  need(!zero(s.StartedAt) && Number.isFinite(Date.parse(s.StartedAt)) && Number.isFinite(Date.parse(s.FinishedAt)) && Date.parse(s.FinishedAt) >= Date.parse(s.StartedAt));
  validatePublicLlmImage(replacement, 'api');
  const command = [...(c.Config.Entrypoint ?? []), ...c.Config.Cmd]; need(c.Path === command[0] && equal(c.Args, command.slice(1)));
  const projected = structuredClone(c); projected.Image = replacement.Id; projected.Config.Image = replacement.Id;
  validatePublicLlmContainer(projected, 'api', model.services.api, replacement, model, { secret, images: { ...images, api: replacement } }, null);
}

// Web is policy-only, NEVER a backup executor. Both identities are exact literals.
function validateRetiredWeb(c, pinnedId, replacement, model, images, initExitImage = null) {
  need(pinnedId === INITIALIZE_HOLD.originalWebImage && replacement.Id === (initExitImage ?? INITIALIZE_HOLD.staleWebImage));
  need(c.Config?.Labels?.['com.docker.compose.service'] === 'web' && c.Image === pinnedId && c.Config.Image === pinnedId);
  const s = c.State;
  need(s.Status === 'exited' && s.Running === false && s.Pid === 0 && [0, 143].includes(s.ExitCode) && c.RestartCount === 0 && !s.Paused && !s.Restarting && !s.OOMKilled && !s.Dead && !s.Error);
  need(!zero(s.StartedAt) && Number.isFinite(Date.parse(s.StartedAt)) && Number.isFinite(Date.parse(s.FinishedAt)) && Date.parse(s.FinishedAt) >= Date.parse(s.StartedAt));
  validatePublicLlmImage(replacement, 'web');
  const command = [...(c.Config.Entrypoint ?? []), ...c.Config.Cmd]; need(c.Path === command[0] && equal(c.Args, command.slice(1)));
  const projected = structuredClone(c); projected.Image = replacement.Id; projected.Config.Image = replacement.Id;
  validatePublicLlmContainer(projected, 'web', model.services.web, replacement, model, { images: { ...images, web: replacement } }, null);
}

// Called by the shared build checker only for this exact prefix. All saved bytes
// are evidence, NOT a claim that the stale image was built from today's source.
export async function readCreatedInitializerPrefix({ root, audit, Database, postRetirementOnly = false, failedInitializerOnly = false, admissionOnly = false, apiOnly = false }) {
  need(audit === INITIALIZE_HOLD.audit);
  const lock = join(root, STATE, '.operation.lock'), archive = join(root, STATE, 'llm-deployments', audit);
  const lockNames = ['build-checkpoint.json', 'continuation-checkpoint.json', 'continue.json', 'helper-continued-fenced.json', 'helper-continued-initialize.json', 'helper-fenced.json', 'llm-candidate', 'mutation.json'];
  const rebuildNames = ['initialize-current-build-checkpoint.json', 'initialize-current-continuation-checkpoint.json', 'initialize-current-continue.json', 'initialize-current-helper-initialize-current-fenced.json', 'initialize-current-retired-initializer.json', 'llm-initialize-candidate'];
  const exitNames = ['rebuild-current-build-checkpoint.json', 'rebuild-current-continuation-checkpoint.json', 'rebuild-current-continue.json', 'rebuild-current-helper-rebuild-current-fenced.json', 'rebuild-current-helper-rebuild-current-initialize.json', 'llm-rebuild-candidate'];
  const admitNames = ['init-exit-current-continuation-checkpoint.json', 'init-exit-current-continue.json', 'init-exit-current-helper-init-exit-current-fenced.json', 'init-exit-current-helper-init-exit-current-initialize.json', 'init-exit-current-retired-failed-initializer.json', 'init-exit-current'];
  const apiNames = ['admit-current', 'admit-current-continuation-checkpoint.json', 'admit-current-continue.json', 'admit-current-failure.json', 'admit-current-helper-admit-current-fenced.json'];
  need(!apiOnly || admissionOnly);
  const checkPrefix = () => {
    if (postRetirementOnly && names(lock).includes('initialize-current-build-failure.json')) {
      const error = Error('PUBLIC LLM rebuild refused: prior build-failure receipt exists.'); error.reason = 'REBUILD_PRIOR_BUILD_FAILURE_REJECTED'; throw error;
    }
    need(equal(names(lock), [...lockNames, ...(postRetirementOnly ? rebuildNames : []), ...(failedInitializerOnly ? exitNames : []), ...(admissionOnly ? admitNames : []), ...(apiOnly ? apiNames : [])].sort()));
    need(equal(names(archive), ['continued', 'fenced', ...(postRetirementOnly ? ['initialize-current'] : []), ...(failedInitializerOnly ? ['rebuild-current'] : []), ...(admissionOnly ? ['init-exit-current'] : []), ...(apiOnly ? ['admit-current'] : [])].sort()));
    if (apiOnly) {
      need(equal(names(join(lock, 'admit-current')), ['compose.cve.json', 'compose.images.json', 'compose.llm-env.json']));
      need(equal(names(join(archive, 'admit-current')), ['fenced', 'review.json']) && equal(names(join(archive, 'admit-current/fenced')), ['core', 'llm']));
    }
    if (admissionOnly) {
      need(failedInitializerOnly && equal(names(join(lock, 'init-exit-current')), ['compose.cve.json', 'compose.images.json', 'compose.llm-env.json']));
      need(equal(names(join(archive, 'init-exit-current')), ['fenced', 'review.json']) && equal(names(join(archive, 'init-exit-current/fenced')), ['core']));
    }
    if (failedInitializerOnly) {
      need(postRetirementOnly && equal(names(join(lock, 'llm-rebuild-candidate')), ['compose.cve.json', 'compose.images.json', 'compose.llm-env.json']));
      need(equal(names(join(archive, 'rebuild-current')), ['fenced', 'review.json']) && equal(names(join(archive, 'rebuild-current/fenced')), ['core']));
    }
    if (postRetirementOnly) {
      need(equal(names(join(lock, 'llm-initialize-candidate')), ['compose.cve.json', 'compose.llm-env.json']));
      need(equal(names(join(archive, 'initialize-current')), ['fenced', 'review.json']));
      need(equal(names(join(archive, 'initialize-current/fenced')), ['core']));
    }
    need(equal(names(join(archive, 'fenced')), ['core']));
    need(equal(names(join(archive, 'continued')), ['fenced', 'review.json']));
    need(equal(names(join(archive, 'continued/fenced')), ['core']));
    need(equal(names(join(lock, 'llm-candidate')), ['compose.cve.json', 'compose.images.json', 'compose.llm-env.json']));
  };
  checkPrefix();
  const directories = ['continued', 'continued/fenced', 'continued/fenced/core', ...(postRetirementOnly ? ['initialize-current', 'initialize-current/fenced', 'initialize-current/fenced/core'] : [])].map(n => directoryIdentity(join(archive, n)));
  if (postRetirementOnly) directories.push(directoryIdentity(join(lock, 'llm-initialize-candidate')));
  const files = ['continue.json', 'continuation-checkpoint.json', 'build-checkpoint.json', 'helper-continued-fenced.json', 'helper-continued-initialize.json'].map(n => privateFile(join(lock, n), 16 * 1024 ** 2));
  const values = Object.fromEntries(files.map(f => [f.path.split('/').at(-1), JSON.parse(f.bytes)]));
  const intent = values['continue.json'], checkpoint = values['continuation-checkpoint.json'], build = values['build-checkpoint.json'];
  need(equal(Object.keys(intent).sort(), ['audit', 'command', 'retireOnlyWorker', 'review', 'sourceReview', 'version']));
  need(intent.version === 1 && intent.audit === audit && intent.command === 'continue-current-build' && intent.sourceReview === 'explicit-current-source-not-historical' && intent.retireOnlyWorker === true);
  need(intent.review === digest(checkpoint) && checkpoint.audit === audit && checkpoint.version === 1);
  const review = privateFile(join(archive, 'continued/review.json'), 16 * 1024 ** 2); files.push(review);
  need(review.bytes === files[1].bytes);
  need(build.version === 1 && build.phase === 'validated-before-build' && build.sourceBasis === 'explicit-reviewed-current' && build.retirementPolicy?.executeOriginal === false);
  const helper = values['helper-continued-initialize.json'];
  need(equal(helper, { id: INITIALIZE_HOLD.id, image: INITIALIZE_HOLD.image, purpose: 'initialize' }));
  const backupHelper = values['helper-continued-fenced.json'];
  need(equal(Object.keys(backupHelper).sort(), ['id', 'image', 'purpose']) && /^[a-f0-9]{64}$/.test(backupHelper.id) && backupHelper.id !== helper.id && backupHelper.purpose === 'backup');
  const pinsFile = privateFile(join(lock, 'llm-candidate/compose.images.json')); files.push(pinsFile);
  const pins = JSON.parse(pinsFile.bytes);
  need(equal(Object.keys(pins), ['services']) && equal(Object.keys(pins.services).sort(), ['api', 'auth-volume-init', 'egress', 'llm-egress', 'scan-volume-init', 'web', 'worker']));
  for (const v of Object.values(pins.services)) need(equal(Object.keys(v), ['image']) && /^sha256:[a-f0-9]{64}$/.test(v.image));
  need(pins.services.api.image === helper.image);

  const continuedBackup = await heldCoreBackup(join(archive, 'continued/fenced/core'), Database), baseline = continuedBackup.baseline;
  files.push(...continuedBackup.files);
  let initializeBackup, rebuildBackup, retiredEvidence, lastBackupHelper, cancelledReview, cancelledBuild, completedBuild, completedReview, failedReceipt, completedBackupHelper, currentPins, admitBackup, admitReview, initializationReceipt, admitBackupHelper, apiReview, apiBackup;
  if (failedInitializerOnly) {
    for (const p of ['rebuild-current', 'rebuild-current/fenced']) directories.push(directoryIdentity(join(archive, p)));
    directories.push(directoryIdentity(join(lock, 'llm-rebuild-candidate')));
    const proofFiles = exitNames.filter(n => n.endsWith('.json')).map(n => privateFile(join(lock, n), 16 * 1024 ** 2)); files.push(...proofFiles);
    const saved = Object.fromEntries(proofFiles.map(f => [f.path.split('/').at(-1), JSON.parse(f.bytes)]));
    completedReview = saved['rebuild-current-continuation-checkpoint.json']; completedBuild = saved['rebuild-current-build-checkpoint.json']; failedReceipt = saved['rebuild-current-helper-rebuild-current-initialize.json']; completedBackupHelper = saved['rebuild-current-helper-rebuild-current-fenced.json'];
    need(equal(saved['rebuild-current-continue.json'], { version: 1, command: 'continue-current-rebuild', audit, review: digest(completedReview), sourceReview: 'explicit-current-source-not-historical', retireOnlyWorker: true, retireOnlyApi: true, retireOnlyWeb: true, backupHelperBasis: 'validated-stale-candidate-api' }));
    need(completedReview.audit === audit && completedReview.continuation === 'post-retirement-pre-pins-current-source' && equal(completedReview.baseline, baseline));
    need(equal(failedReceipt, { id: INIT_EXIT_HOLD.id, image: INIT_EXIT_HOLD.image, purpose: 'initialize' }));
    need(equal(Object.keys(completedBackupHelper).sort(), ['id', 'image', 'purpose']) && /^[a-f0-9]{64}$/.test(completedBackupHelper.id) && completedBackupHelper.id !== failedReceipt.id && completedBackupHelper.purpose === 'backup' && completedBackupHelper.image === INITIALIZE_HOLD.image);
    const reviewProof = privateFile(join(archive, 'rebuild-current/review.json'), 16 * 1024 ** 2); files.push(reviewProof);
    need(reviewProof.bytes === proofFiles.find(f => f.path.endsWith('/rebuild-current-continuation-checkpoint.json')).bytes);
    for (const n of ['compose.cve.json', 'compose.images.json', 'compose.llm-env.json']) {
      const f = privateFile(join(lock, 'llm-rebuild-candidate', n)); files.push(f);
      if (n === 'compose.images.json') currentPins = JSON.parse(f.bytes);
      else need(f.bytes === privateFile(join(lock, 'llm-candidate', n)).bytes);
    }
    need(equal(Object.keys(currentPins), ['services']) && equal(Object.keys(currentPins.services).sort(), Object.keys(pins.services).sort()));
    for (const v of Object.values(currentPins.services)) need(equal(Object.keys(v), ['image']) && /^sha256:[a-f0-9]{64}$/.test(v.image));
    need(currentPins.services.api.image === INIT_EXIT_HOLD.image && completedBuild.version === 1 && completedBuild.phase === 'validated-before-build' && completedBuild.sourceBasis === 'explicit-reviewed-current' && completedBuild.backupHelperBasis === 'validated-stale-candidate-api');
    rebuildBackup = await heldCoreBackup(join(archive, 'rebuild-current/fenced/core'), Database); files.push(...rebuildBackup.files);
    need(equal(rebuildBackup.baseline, baseline) && equal(completedBuild.baseline, baseline));
    need(equal(capturePublicLlmSource(root).manifest, completedBuild.source));
  }
  if (admissionOnly) {
    for (const p of ['init-exit-current', 'init-exit-current/fenced']) directories.push(directoryIdentity(join(archive, p)));
    directories.push(directoryIdentity(join(lock, 'init-exit-current')));
    const proofs = admitNames.filter(n => n.endsWith('.json')).map(n => privateFile(join(lock, n), 16 * 1024 ** 2)); files.push(...proofs);
    const values = Object.fromEntries(proofs.map(f => [f.path.split('/').at(-1), JSON.parse(f.bytes)])); admitReview = values['init-exit-current-continuation-checkpoint.json'];
    need(equal(values['init-exit-current-continue.json'], { version: 1, command: 'continue-current-init-exit', audit, review: digest(admitReview), sourceReview: 'explicit-current-source-not-historical', retireOnlyWorker: true, retireOnlyApi: true, retireOnlyWeb: true, backupHelperBasis: 'validated-current-candidate-api' }));
    need(admitReview.continuation === 'exact-init-exit-current-source' && admitReview.audit === audit && equal(admitReview.currentPins, currentPins));
    need(equal(values['init-exit-current-retired-failed-initializer.json'], admitReview.failedInitializer));
    need(equal(admitReview.failedInitializer.identity, failedReceipt) && equal(admitReview.failedInitializer.classification, { category: 'TSX_CACHE_ENOENT_MKDIR', path: '/tmp/tsx-65532' }));
    initializationReceipt = values['init-exit-current-helper-init-exit-current-initialize.json'];
    need(equal(initializationReceipt, { id: ADMIT_HOLD.initializer, image: INIT_EXIT_HOLD.image, purpose: 'initialize' }));
    admitBackupHelper = values['init-exit-current-helper-init-exit-current-fenced.json'];
    need(equal(Object.keys(admitBackupHelper).sort(), ['id', 'image', 'purpose']) && /^[a-f0-9]{64}$/.test(admitBackupHelper.id) && admitBackupHelper.image === INIT_EXIT_HOLD.image && admitBackupHelper.purpose === 'backup');
    const r = privateFile(join(archive, 'init-exit-current/review.json'), 16 * 1024 ** 2); files.push(r); need(r.bytes === proofs.find(f => f.path.endsWith('/init-exit-current-continuation-checkpoint.json')).bytes);
    for (const n of ['compose.cve.json', 'compose.images.json', 'compose.llm-env.json']) { const f = privateFile(join(lock, 'init-exit-current', n)); files.push(f); need(f.bytes === privateFile(join(lock, 'llm-rebuild-candidate', n)).bytes); }
    admitBackup = await heldCoreBackup(join(archive, 'init-exit-current/fenced/core'), Database); files.push(...admitBackup.files); need(equal(admitBackup.baseline, baseline) && equal(admitReview.baseline, baseline));
  }
  if (apiOnly) {
    directories.push(directoryIdentity(join(lock, 'admit-current')), directoryIdentity(join(archive, 'admit-current')));
    const proofs = apiNames.filter(n => n.endsWith('.json')).map(n => { const path = join(lock, n), f = privateFile(path, n === 'admit-current-continuation-checkpoint.json' ? 32 * 1024 ** 2 : 16384), proof = byteFile(path); f.verify(); return { ...proof, bytes: f.bytes }; }); files.push(...proofs);
    const saved = Object.fromEntries(proofs.map(f => [f.path.split('/').at(-1), JSON.parse(f.bytes)]));
    apiReview = saved['admit-current-continuation-checkpoint.json'];
    need(equal(saved['admit-current-failure.json'], API_HOLD.failure));
    need(equal(saved['admit-current-continue.json'], { version: 1, command: 'continue-current-admit', audit, review: digest(apiReview), sourceReview: 'explicit-current-source-not-historical', retireOnlyWorker: true, retireOnlyApi: true, retireOnlyWeb: true, backupHelperBasis: 'validated-current-candidate-api' }));
    need(apiReview.audit === audit && apiReview.continuation === 'exact-post-init-pre-api-admission' && equal(apiReview.baseline, baseline) && equal(apiReview.currentPins, currentPins));
    need(equal(apiReview.source, completedBuild.source) && equal(apiReview.settings, { version: 1, keyVolume: null }));
    const review = byteFile(join(archive, 'admit-current/review.json')); files.push(review);
    const checkpointProof = proofs.find(f => f.path.endsWith('/admit-current-continuation-checkpoint.json'));
    need(review.sha256 === checkpointProof.sha256 && review.identity.size === checkpointProof.identity.size);
    need(equal(saved['admit-current-helper-admit-current-fenced.json'], { id: API_HOLD.backup, image: INIT_EXIT_HOLD.image, purpose: 'backup' }));
    for (const n of ['compose.cve.json', 'compose.images.json', 'compose.llm-env.json']) { const f = privateFile(join(lock, 'admit-current', n)); files.push(f); need(f.bytes === privateFile(join(lock, 'init-exit-current', n)).bytes); }
    apiBackup = await heldAdmissionBackup(join(archive, 'admit-current/fenced'), Database); files.push(...apiBackup.files);
    need(equal(apiBackup.baseline.core, baseline.core));
    savedAdmissionProofs(root, apiReview); // Historical comparison once; newly captured proofs fence every execution boundary.
  }
  if (postRetirementOnly) {
    const priorFiles = rebuildNames.filter(n => n.endsWith('.json')).map(n => privateFile(join(lock, n), 16 * 1024 ** 2)); files.push(...priorFiles);
    const prior = Object.fromEntries(priorFiles.map(f => [f.path.split('/').at(-1), JSON.parse(f.bytes)]));
    const priorReview = prior['initialize-current-continuation-checkpoint.json'], priorIntent = prior['initialize-current-continue.json']; cancelledReview = priorReview;
    need(equal(priorIntent, { version: 1, command: 'continue-current-initialize', audit, review: digest(priorReview), sourceReview: 'explicit-current-source-not-historical', retireOnlyWorker: true, retireOnlyApi: true, retireOnlyWeb: true, backupHelperBasis: 'validated-stale-candidate-api' }));
    need(priorReview.audit === audit && priorReview.continuation === 'created-initializer-only-current-source' && equal(priorReview.baseline, baseline));
    const priorReviewFile = privateFile(join(archive, 'initialize-current/review.json'), 16 * 1024 ** 2); files.push(priorReviewFile);
    need(priorReviewFile.bytes === priorFiles.find(f => f.path.endsWith('/initialize-current-continuation-checkpoint.json')).bytes);
    retiredEvidence = prior['initialize-current-retired-initializer.json']; need(equal(retiredEvidence, priorReview.staleCandidate));
    need(equal(retiredEvidence.identity, helper) && equal(retiredEvidence.pins, pins));
    const state = retiredEvidence.control.state;
    need(retiredEvidence.control.id === helper.id && retiredEvidence.control.image === helper.image && retiredEvidence.control.restartCount === 0 && state.Status === 'created' && state.Running === false && state.Pid === 0 && state.ExitCode === 0 && zero(state.StartedAt) && zero(state.FinishedAt) && !state.Error);
    lastBackupHelper = prior['initialize-current-helper-initialize-current-fenced.json'];
    need(equal(Object.keys(lastBackupHelper).sort(), ['id', 'image', 'purpose']) && /^[a-f0-9]{64}$/.test(lastBackupHelper.id) && lastBackupHelper.id !== helper.id && lastBackupHelper.image === INITIALIZE_HOLD.image && lastBackupHelper.purpose === 'backup');
    for (const name of ['compose.cve.json', 'compose.llm-env.json']) {
      const proof = privateFile(join(lock, 'llm-initialize-candidate', name)); files.push(proof);
      need(proof.bytes === privateFile(join(lock, 'llm-candidate', name)).bytes);
    }
    initializeBackup = await heldCoreBackup(join(archive, 'initialize-current/fenced/core'), Database); files.push(...initializeBackup.files);
    const previousBuild = prior['initialize-current-build-checkpoint.json']; cancelledBuild = previousBuild;
    need(previousBuild.version === 1 && previousBuild.phase === 'validated-before-build' && previousBuild.sourceBasis === 'explicit-reviewed-current' && previousBuild.backupHelperBasis === 'validated-stale-candidate-api' && previousBuild.backupImageId === INITIALIZE_HOLD.image);
    need(equal(initializeBackup.baseline, baseline) && equal(previousBuild.baseline, baseline));
    need(previousBuild.retirementPolicy?.executeOriginal === false && previousBuild.apiRetirementPolicy?.executeOriginal === false && previousBuild.webRetirementPolicy?.executeOriginal === false);
  }
  need(equal(build.baseline, baseline) && equal(checkpoint.baseline, baseline));
  need(backupHelper.image === checkpoint.priorImageMetadata.api.Id);
  let authority;
  const name = `${PROJECT}-llm-${audit.slice(7)}-continued-initialize`;
  const inspect = async (d, runtime) => {
    const images = {};
    for (const [r, pin] of Object.entries((failedInitializerOnly ? currentPins : pins).services)) {
      const rows = JSON.parse(await d(['image', 'inspect', pin.image]));
      need(rows.length === 1 && rows[0].Id === pin.image); validatePublicLlmImage(rows[0], r); images[r] = rows[0];
    }
    need(!(await d(['container', 'ls', '--all', '--no-trunc', '--filter', `id=${backupHelper.id}`, '--format', '{{.ID}}'])).trim());
    const check = async run => {
      const rows = JSON.parse(await run(['container', 'inspect', helper.id])); need(rows.length === 1);
      const c = rows[0]; need(c.Id === helper.id && Number.isFinite(Date.parse(c.Created)));
      validatePublicLlmHelper(c, name, images.api, 'initialize', 'created');
      need(c.State.Running === false && c.State.Pid === 0 && c.State.ExitCode === 0 && zero(c.State.StartedAt) && zero(c.State.FinishedAt) && !c.State.Error);
      for (const m of c.Mounts.filter(m => m.Type === 'volume')) {
        const volumes = JSON.parse(await run(['volume', 'inspect', m.Name]));
        need(volumes.length === 1 && m.Driver === 'local' && m.Source === volumes[0].Mountpoint);
      }
      const current = publicLlmSecretlessControl(c);
      // Env is validated above but is never persisted or printed by this path.
      delete current.config.Env;
      current.mounts.sort((a, b) => a.Destination.localeCompare(b.Destination));
      current.host.Mounts.sort((a, b) => a.Target.localeCompare(b.Target));
      if (authority) need(equal(authority, current)); else authority = current;
    };
    if (postRetirementOnly) {
      result.checkHelper = async run => {
        for (const id of [helper.id, lastBackupHelper.id]) need(!(await run(['container', 'ls', '--all', '--no-trunc', '--filter', `id=${id}`, '--format', '{{.ID}}'])).trim());
      };
      await result.checkHelper(d); authority = retiredEvidence.control;
    } else { await check(d); result.checkHelper = check; }
    result.backupImage = images.api; // Actual runtime-inspected metadata, never a saved-checkpoint reconstruction.
    result.policyApiImage = images.api;
    if (failedInitializerOnly) {
      const candidates = {};
      for (const [role, pin] of Object.entries(currentPins.services)) { const rows = JSON.parse(await d(['image', 'inspect', pin.image])); need(rows.length === 1 && rows[0].Id === pin.image); validatePublicLlmImage(rows[0], role); candidates[role] = rows[0]; }
      need(!(await d(['container', 'ls', '--all', '--no-trunc', '--filter', `id=${completedBackupHelper.id}`, '--format', '{{.ID}}'])).trim());
      const name = `${PROJECT}-llm-${audit.slice(7)}-rebuild-current-initialize`;
      let control;
      const check = async query => {
        const rows = JSON.parse(await query(['container', 'inspect', INIT_EXIT_HOLD.id])); need(rows.length === 1); const c = rows[0]; validateHistoricalInitExit(c, candidates.api);
        for (const m of c.Mounts.filter(m => m.Type === 'volume')) { const v = JSON.parse(await query(['volume', 'inspect', m.Name])); need(v.length === 1 && m.Driver === 'local' && m.Source === v[0].Mountpoint); }
        const next = publicLlmSecretlessControl(c); delete next.config.Env;
        if (control) need(equal(control, next)); else control = next;
      };
      if (!admissionOnly) { await check(d); const classification = await readInitExitFailure(runtime.run, runtime.options);
      result.failed = { id: INIT_EXIT_HOLD.id, name, check, confirmFailure: () => readInitExitFailure(runtime.run, runtime.options), evidence: { identity: failedReceipt, control, classification, environmentPolicy: 'historical-old-env-only-not-current' } }; }
      result.currentPins = currentPins; result.candidateImages = candidates; result.backupImage = candidates.api;
    }
    if (admissionOnly) {
      const model = expectedPublicLlmConfig(root, readProfile(root).cve, { version: 1, keyVolume: null });
      const rows = JSON.parse(await d(['container', 'inspect', ADMIT_HOLD.gateway.id])); need(rows.length === 1); admissionPeer(rows[0], 'llm-egress', images, model);
      const networks = [];
      for (const suffix of ['llm_internal', 'llm_uplink']) {
        const values = JSON.parse(await d(['network', 'inspect', PROJECT + '_' + suffix])); need(values.length === 1); const n = values[0];
        need(n.Name === PROJECT + '_' + suffix && n.Labels?.[LABEL] === 'v1' && n.Labels?.['com.docker.compose.project'] === PROJECT && n.Driver === 'bridge' && Boolean(n.Internal) === suffix.endsWith('_internal') && !n.Attachable && !n.Ingress && !n.EnableIPv6 && equal(n.Options ?? {}, {}) && (!n.IPAM || n.IPAM.Driver === 'default' && equal(n.IPAM.Options ?? {}, {})) && equal(Object.keys(n.Containers ?? {}), [ADMIT_HOLD.gateway.id])); networks.push(n);
      }
      result.admitExtra = { gateway: rows[0], networks };
      const oldWorker = admitReview.peers.find(p => p.config.Labels['com.docker.compose.service'] === 'worker'); need(oldWorker && oldWorker.id !== ADMIT_HOLD.worker.id);
      result.checkHelper = async query => { for (const id of [helper.id, INIT_EXIT_HOLD.id, initializationReceipt.id, admitBackupHelper.id, oldWorker.id, ...(apiOnly ? [API_HOLD.backup] : [])]) need(!(await query(['container', 'ls', '--all', '--no-trunc', '--filter', `id=${id}`, '--format', '{{.ID}}'])).trim()); };
      await result.checkHelper(d);
    }
    result.webPolicyImage = images.web;
    result.evidence = failedInitializerOnly ? retiredEvidence : { identity: helper, control: authority, pins, imageMetadata: Object.fromEntries(Object.entries(images).map(([r, im]) => [r, { Id: im.Id, Os: im.Os, Config: { ...im.Config, Env: undefined } }])) };
  };
  const result = { helper, pins, files, baseline, inspect, checkPrefix, retired: postRetirementOnly, admission: admissionOnly, apiBaseline: apiBackup?.baseline, apiFailure: apiOnly ? API_HOLD.failure : null, currentPins, failedId: admissionOnly ? ADMIT_HOLD.gateway.id : failedInitializerOnly ? INIT_EXIT_HOLD.id : null, originalWebImage: INITIALIZE_HOLD.originalWebImage,
    verifyOriginalState(originalPins, inventory) {
      if (!postRetirementOnly) return;
      need(equal(cancelledBuild.pins, originalPins));
      const retained = peers => peers.filter(p => !['worker', 'llm-egress'].includes(p.config.Labels['com.docker.compose.service']));
      const samePeers = (a, b) => { const sort = peers => [...peers].sort((x, y) => x.id.localeCompare(y.id)); return equal(sort(admissionOnly ? retained(a) : a), sort(admissionOnly ? retained(b) : b)); };
      if (failedInitializerOnly) { need(equal(completedBuild.pins, originalPins)); need(samePeers(completedReview.peers, inventory.containers.map(publicLlmSecretlessControl))); }
      if (apiOnly) need(equal(apiReview.peers, inventory.containers.map(publicLlmSecretlessControl)));
            if (admissionOnly) { need(samePeers(admitReview.peers, inventory.containers.map(publicLlmSecretlessControl))); need(inventory.containers.some(c => c.Id === ADMIT_HOLD.api) && inventory.containers.some(c => c.Id === ADMIT_HOLD.web)); }
      need(cancelledBuild.retirementPolicy.workerId === originalPins.services.worker.image && cancelledBuild.apiRetirementPolicy.apiId === originalPins.services.api.image && cancelledBuild.apiRetirementPolicy.validationImageId === INITIALIZE_HOLD.image);
      need(cancelledBuild.webRetirementPolicy.originalId === originalPins.services.web.image && cancelledBuild.webRetirementPolicy.validationImageId === INITIALIZE_HOLD.staleWebImage && cancelledBuild.webRetirementPolicy.metadataUnavailable === true);
      const sort = peers => [...peers].sort((a, b) => a.id.localeCompare(b.id));
      need(samePeers(cancelledReview.peers, inventory.containers.map(publicLlmSecretlessControl)));
    },
    validateAdmissionPeer(c, name) { need(admissionOnly); admissionPeer(c, name, result.candidateImages, expectedPublicLlmConfig(root, readProfile(root).cve, { version: 1, keyVolume: null })); },
    async verifyReadiness(run, options) {
      need(admissionOnly); const id = ADMIT_HOLD.worker.id;
      const before = JSON.parse(await run(['container', 'inspect', id], options)); need(before.length === 1); result.validateAdmissionPeer(before[0], 'worker');
      const receipt = JSON.parse(await run(['container', 'exec', id, 'node', '--import', 'tsx', '--input-type=module', '-e', PUBLIC_READY_PROBE], { ...options, timeout: 45000 })); const cve = readProfile(root).cve;
      need(receipt.ready === true && receipt.manifest === cve.manifestDigest && receipt.bundle === cve.artifactSha256);
      const after = JSON.parse(await run(['container', 'inspect', id], options)); need(after.length === 1 && equal(publicLlmSecretlessControl(before[0]), publicLlmSecretlessControl(after[0])));
    },
    validateRetiredWeb(c, pinnedId, model, images) { validateRetiredWeb(c, pinnedId, result.webPolicyImage, model, images, failedInitializerOnly ? currentPins.services.web.image : null); },
    validateRetiredApi(c, pinnedId, model, images, secret) { validateRetiredApi(c, pinnedId, result.policyApiImage ?? result.backupImage, model, images, secret, failedInitializerOnly); },
    verifyImageSource() { need(failedInitializerOnly && equal(capturePublicLlmSource(root).manifest, completedBuild.source)); },
    withoutHelper(text) { if (admissionOnly) return text.split('\n').filter(line => ![ADMIT_HOLD.gateway.id, PROJECT + '-llm-egress-1'].includes(line.split('\t')[0])).join('\n'); if (failedInitializerOnly) return text.split('\n').filter(line => ![INIT_EXIT_HOLD.id, `${PROJECT}-llm-${audit.slice(7)}-rebuild-current-initialize`].includes(line.split('\t')[0])).join('\n'); return postRetirementOnly ? text : text.split('\n').filter(line => ![helper.id, name].includes(line.split('\t')[0])).join('\n'); },
    verify() { directories.forEach(v => v()); continuedBackup.verify(); initializeBackup?.verify(); rebuildBackup?.verify(); admitBackup?.verify(); apiBackup?.verify(); if (failedInitializerOnly) result.verifyImageSource(); files.forEach(f => f.verify()); },
  };
  result.verify(); return result;
}
