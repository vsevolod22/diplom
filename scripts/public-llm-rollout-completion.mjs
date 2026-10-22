// Exact completion of the 22 October normal rollout, never a generic resume.
import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import { homedir, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createRequire } from 'node:module';
import { PROJECT, STATE, CONFIG_SECRET, readProfile, loadSecret, runIsolatedDocker, copyStableSqlite, recoverySqlite, validateExportManifest } from './public-image-stand.mjs';
import { dockerEnvironment } from './local-stand.mjs';
import { capturePublicLlmSource, readPublicLlmBinding, loadPublicLlmSettings, expectedPublicLlmConfig, publicLlmEnvironmentOverlay, publicLlmComposeArguments, validatePublicLlmImage, validatePublicLlmContainer, validatePublicLlmConfig, validatePublicLlmKeyVolume, inspectPublicLlmNamespace, llmFingerprint } from './public-llm-stand.mjs';
import { privateFile, byteFile, directoryIdentity, capturePublicLlmExecutionClosure, publicLlmSecretlessControl } from './public-llm-build-continuation.mjs';
import { checkPublicLlmSourceBuild } from './public-llm-source-build.mjs';
import { PUBLIC_READY_PROBE } from './refresh-public-cve.mjs';
const require = createRequire(new URL('../server/api/package.json', import.meta.url));
export const ROLLOUT_HOLD = Object.freeze({
  audit: 'deploy-830b7aa07d1c9a728de1a957829e43c2',
  worker: { id: '6b2dd4c1e86221788bb2ce106b7d364a71923867469413859752befb5c6c204e', image: 'sha256:74b6801574e7ee7838668a7183efaa2dcd00827551d803cd81a7d164278e4279', startedAt: '2026-10-22T22:22:09.629269922Z' },
  gateway: { id: '660bd9867e413b704ac05a7d87f9d4fbd3b5f9ffdb0bd71196dcffa0095d8b2f', image: 'sha256:ed51df52f8a92f4966e688d6b4b4337e6522f8b41139a105ef6fc80d93430912', startedAt: '2026-10-22T22:22:06.269369337Z' },
  api: { id: '134bd5883720ce4977a739f3b2133179582e30b47682aa1e901edde1f3cca96c', image: 'sha256:baaa16f620fde9e0ef090641b6f0418289188e637b3ccfbcb173ffef3e2e7512', candidate: 'sha256:6455195912168d52774955a6f9fb72e8618622b1f9c62bf0a0740a33c7e87ba0' },
  web: { id: 'ebee425d39994ec7d5cb9c5de8c67c29b35f7535c520c0e2b58bb419385bf363', image: 'sha256:1f53451df413f13e3ca0b2df38b1bd90ce9066c69b594843d07239c1b4205fcd', candidate: 'sha256:e387b1bdf93a77d6264aeb629dd10c34e3f9261e364d7ce03cccf926294af832' },
  backup: '8c665e684470a97995b56452732d05d168f9e2c47cfb87af710dde59a74d5777',
  check: 'fa169f26b3753f2272c7c0c9391f5d8bac66c603cbf879387ee552ef41663690',
  keyVolume: 'diplom-public-8081-llm-key-3215ef165d7e4b2bac657766fdd83796',
});
const canonical = v => Array.isArray(v) ? v.map(canonical) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k => [k, canonical(v[k])])) : v;
const equal = (a, b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
const hash = v => crypto.createHash('sha256').update(typeof v === 'string' ? v : JSON.stringify(canonical(v))).digest('hex');
const need = v => { if (!v) throw Error('PUBLIC LLM exact rollout completion refused; details withheld.'); };
const names = path => fs.readdirSync(path).sort();
const role = c => c.Config.Labels['com.docker.compose.service'];
const control = c => { const config = structuredClone(c.Config); config.Env = config.Env.filter(v => !v.startsWith('SCAN_JWT_SECRET=')); return hash({ Name: c.Name, Image: c.Image, Path: c.Path, Args: c.Args, Config: config, HostConfig: c.HostConfig, Mounts: [...c.Mounts].sort((a, b) => a.Destination.localeCompare(b.Destination)) }); };
const epoch = c => [c.Id, c.State.StartedAt, c.State.FinishedAt, c.State.Pid, c.RestartCount, c.State.Running, c.State.Status, c.State.ExitCode, c.State.Error];
const stopped = c => need(c.State.Status === 'exited' && !c.State.Running && c.State.Pid === 0 && c.RestartCount === 0 && [0, ...(role(c) === 'web' ? [143] : [])].includes(c.State.ExitCode) && !c.State.Paused && !c.State.Dead && !c.State.Restarting && !c.State.OOMKilled && !c.State.Error);

// Only exported backups are opened, through stable private copies; never live DBs.
async function storedBaseline(path, Database, recorded) {
  const files = [], directories = [directoryIdentity(path)];
  need(equal(names(path), ['core', 'llm']));
  const scratch = fs.mkdtempSync(join(tmpdir(), 'public-rollout-baseline-')), copies = {}, fingerprints = {};
  try {
    for (const group of ['core', 'llm']) {
      const dir = join(path, group); directories.push(directoryIdentity(dir)); const entries = names(dir);
      need(entries.every(n => /^(?:auth|ledger)\.sqlite(?:-wal|-shm)?$/.test(n) || n === 'private-manifest.json'));
      const manifestFile = privateFile(join(dir, 'private-manifest.json'), 65536), manifest = JSON.parse(manifestFile.bytes); validateExportManifest(manifest); files.push(manifestFile);
      for (const n of entries.filter(n => n !== 'private-manifest.json')) files.push(byteFile(join(dir, n)));
      const paths = {};
      for (const r of ['auth', 'ledger']) {
        const proof = files.find(f => f.path === join(dir, r + '.sqlite'));
        need(proof && proof.sha256 === manifest.receipt[r].sha256 && proof.identity.size === manifest.receipt[r].bytes);
        const key = group + '-' + r, copy = copyStableSqlite(fs, crypto, proof.path, join(scratch, key)); copies[key] = copy; paths[r] = copy.path;
      }
      if (group === 'core') {
        const restored = await recoverySqlite(Database, fs, crypto, paths, null);
        for (const r of ['auth', 'ledger']) need(restored[r].logicalSha256 === manifest.receipt[r].logicalSha256);
        fingerprints.core = Object.fromEntries(Object.entries(paths).map(([r, p]) => [r, { logicalSha256: llmFingerprint(Database, fs, crypto, p, r) }]));
      } else {
        fingerprints.llm = {};
        for (const [r, kind] of [['auth', 'history'], ['ledger', 'quota']]) { const value = llmFingerprint(Database, fs, crypto, paths[r], kind); need(value === manifest.receipt[r].logicalSha256); fingerprints.llm[kind] = value; }
      }
      directories.push(() => need(equal(names(dir), entries)));
    }
    need(recorded.llm !== null && equal(fingerprints.core, recorded.core) && equal(fingerprints.llm, recorded.llm));
    for (const c of Object.values(copies)) c.verify();
  } finally { for (const c of Object.values(copies)) c.cleanup(); fs.rmSync(scratch, { recursive: true, force: true }); }
  const verify = () => { directories.forEach(v => v()); files.forEach(f => f.verify()); };
  verify(); return { files, verify, baseline: { ...fingerprints, empty: false } };
}

export async function preparePublicLlmRolloutCompletion({ root, home = homedir(), audit, run = runIsolatedDocker, ambient = process.env, Database = require('better-sqlite3'), checkSource = checkPublicLlmSourceBuild }) {
  need(audit === ROLLOUT_HOLD.audit && resolve(root) === root && fs.realpathSync(root) === root);
  const state = join(root, STATE), lockPath = join(state, '.operation.lock'), auditPath = join(state, 'llm-deployments', audit), stage = join(lockPath, 'llm-candidate');
  const dirs = [state, lockPath, join(state, 'llm-deployments'), auditPath, stage, join(auditPath, 'before-api')].map(directoryIdentity);
  const checkPrefix = () => {
    need(equal(names(lockPath), ['build-checkpoint.json', 'helper-check.json', 'helper-fenced.json', 'llm-candidate', 'mutation.json']));
    need(equal(names(auditPath), ['before-api', 'fenced']) && names(join(auditPath, 'before-api')).length === 0);
    need(equal(names(stage), ['compose.cve.json', 'compose.images.json', 'compose.llm-env.json']));
    const audits = names(join(state, 'llm-deployments')); need(audits.length <= 16 && audits.every(n => /^deploy-[a-f0-9]{32}$/.test(n)));
    need(equal(audits.filter(n => !fs.existsSync(join(state, 'llm-deployments', n, 'complete.json'))), [audit]));
    need(!names(state).some(n => n.startsWith('.llm-pending-') || n.endsWith('.lock') && n !== '.operation.lock'));
  };
  checkPrefix(); const disk = fs.statfsSync(state); need(disk.bavail * disk.bsize >= 4 * 1024 ** 3);
  const execution = capturePublicLlmExecutionClosure(root), source = capturePublicLlmSource(root), settings = loadPublicLlmSettings(home);
  need(equal(settings.selection, { version: 1, keyVolume: ROLLOUT_HOLD.keyVolume }));
  const priorSelection = readPublicLlmBinding(root); need(equal(priorSelection, { version: 1, keyVolume: null }));
  const stateFiles = ['profile.json', 'scan-jwt', 'compose.images.json', 'compose.cve.json', 'llm-profile.json', 'compose.llm-env.json'].map(n => privateFile(join(state, n)));
  const originalFiles = ['mutation.json', 'build-checkpoint.json', 'helper-fenced.json', 'helper-check.json'].map(n => privateFile(join(lockPath, n), 16 * 1024 ** 2));
  const [mutation, build, backup, checked] = originalFiles.map(f => JSON.parse(f.bytes));
  need(equal(mutation, { version: 1, project: PROJECT, command: 'public-llm-up', phase: 'fence-web', endpoint: mutation.endpoint }));
  const profile = readProfile(root), pins = JSON.parse(stateFiles.find(f => f.path.endsWith('/compose.images.json')).bytes);
  need(profile.version === 2 && profile.cve && equal(build.publicProfile, profile) && build.phase === 'validated-before-build' && build.version === 1 && build.sourceBasis === 'validated-before-build' && build.retirementPolicy === null && equal(build.pins, pins) && equal(build.source, source.manifest) && build.baseline.llm !== null);
  const jwtFile = stateFiles.find(f => f.path.endsWith('/scan-jwt')), jwtIdentity = Object.fromEntries(Object.entries(jwtFile.identity).filter(([k]) => ['dev', 'ino', 'mode', 'uid', 'size', 'mtime', 'ctime'].includes(k)));
  need(equal(jwtIdentity, build.jwtIdentity)); // No JWT value or hash is persisted in review evidence.
  need(equal(backup, { id: ROLLOUT_HOLD.backup, image: ROLLOUT_HOLD.api.image, purpose: 'backup' }) && equal(checked, { id: ROLLOUT_HOLD.check, image: ROLLOUT_HOLD.api.candidate, purpose: 'check' }));
  const candidateFiles = ['compose.cve.json', 'compose.images.json', 'compose.llm-env.json'].map(n => privateFile(join(stage, n)));
  need(candidateFiles[0].bytes === stateFiles.find(f => f.path.endsWith('/compose.cve.json')).bytes && equal(JSON.parse(candidateFiles[2].bytes), publicLlmEnvironmentOverlay(settings.selection)));
  const currentPins = JSON.parse(candidateFiles[1].bytes), roles = ['api', 'auth-volume-init', 'egress', 'llm-egress', 'scan-volume-init', 'web', 'worker'];
  for (const p of [pins, currentPins]) { need(equal(Object.keys(p), ['services']) && equal(Object.keys(p.services).sort(), roles)); for (const v of Object.values(p.services)) need(equal(Object.keys(v), ['image']) && /^sha256:[a-f0-9]{64}$/.test(v.image)); }
  for (const n of ['api', 'web']) need(pins.services[n].image === ROLLOUT_HOLD[n].image && currentPins.services[n].image === ROLLOUT_HOLD[n].candidate);
  need(currentPins.services.worker.image === ROLLOUT_HOLD.worker.image && currentPins.services['llm-egress'].image === ROLLOUT_HOLD.gateway.image);
  for (const n of ['auth-volume-init', 'scan-volume-init', 'egress']) need(currentPins.services[n].image === pins.services[n].image);
  const env = dockerEnvironment(ambient), endpoint = env.DOCKER_HOST && !env.DOCKER_CONTEXT ? env.DOCKER_HOST : JSON.parse(await run(['context', 'inspect', '--format', '{{json .Endpoints.docker.Host}}'], { root, env, timeout: 10000 }));
  need(typeof endpoint === 'string' && endpoint.startsWith('unix:///') && endpoint === mutation.endpoint);
  env.DOCKER_HOST = endpoint; env.COMPOSE_DISABLE_ENV_FILE = '1'; for (const k of ['DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']) delete env[k];
  const options = { root, env }, imageIds = new Set([...Object.values(currentPins.services), ...Object.values(pins.services)].map(v => v.image));
  const containerIds = new Set([ROLLOUT_HOLD.worker.id, ROLLOUT_HOLD.gateway.id, ROLLOUT_HOLD.api.id, ROLLOUT_HOLD.web.id]);
  const end = Date.now() + 180000; let calls = 0;
  const d = async args => {
    need(++calls <= 240 && Date.now() < end); const [kind, op, ref] = args;
    const invoke = a => run(a, { ...options, timeout: Math.max(1, Math.min(15000, end - Date.now())) });
    if (kind === 'image' && op === 'inspect') { need(imageIds.has(ref) || /^dip-public-images-(?:api|worker|web|egress|llm-egress):local$/.test(ref)); return invoke(args); }
    if (kind === 'image' && op === 'ls') return invoke([...args, '--filter', 'reference=' + PROJECT + '-*']);
    if (['container', 'volume', 'network'].includes(kind) && op === 'ls') {
      const filter = args.find(a => a.startsWith('id=') || a.startsWith('volume='));
      if (filter) { need([`id=${backup.id}`, `id=${checked.id}`, `volume=${PROJECT}_auth_accounts`, `volume=${PROJECT}_scan_ledger`, `volume=${ROLLOUT_HOLD.keyVolume}`].includes(filter)); return invoke(args); }
      need(!args.includes('--filter'));
      const a = await invoke([...args, '--filter', `name=${kind === 'container' ? '^/' : '^'}${PROJECT}${kind === 'container' ? '-' : '_'}`]), b = await invoke([...args, '--filter', 'label=com.docker.compose.project=' + PROJECT]);
      return [...new Set((a + '\n' + b).split('\n').filter(Boolean))].join('\n');
    }
    if (kind === 'container' && op === 'inspect') {
      need(containerIds.has(ref) || new RegExp('^' + PROJECT + '-(?:api|web|worker|egress|llm-egress|auth-volume-init|scan-volume-init)-1$').test(ref));
      const text = await invoke(args); const rows = JSON.parse(text); need(rows.length === 1 && rows[0].Name.startsWith('/' + PROJECT + '-')); containerIds.add(rows[0].Id); return text;
    }
    if (['volume', 'network'].includes(kind) && op === 'inspect') { need(ref.startsWith(PROJECT + '_') || kind === 'volume' && ref === ROLLOUT_HOLD.keyVolume); return invoke(args); }
    need(false);
  };
  const candidateImages = {};
  for (const [name, pin] of Object.entries(currentPins.services)) {
    const rows = JSON.parse(await d(['image', 'inspect', pin.image])); need(rows.length === 1 && rows[0].Id === pin.image); validatePublicLlmImage(rows[0], name); candidateImages[name] = rows[0];
  }
  // ONLY missing-image classification permits retire-only projection. Timeouts,
  // daemon errors or unsafe candidate metadata never become a fallback.
  for (const name of ['api', 'web']) {
    let unavailable = false;
    try { await d(['image', 'inspect', pins.services[name].image]); }
    catch (error) { if (error?.category !== 'image') throw error; unavailable = true; }
    need(unavailable);
  }
  const jwt = loadSecret(root, true), priorModel = expectedPublicLlmConfig(root, profile.cve, priorSelection), nextModel = expectedPublicLlmConfig(root, profile.cve, settings.selection);
  const retire = (c, name) => {
    const fixed = ROLLOUT_HOLD[name]; need(c.Id === fixed.id && c.Image === fixed.image && c.Config.Image === fixed.image && role(c) === name); stopped(c);
    const recorded = build.peers.find(p => p.name === name); need(recorded && recorded.id === c.Id && recorded.image === c.Image && recorded.control === control(c) && equal(recorded.epoch, epoch(c)));
    const projection = structuredClone(c); projection.Image = candidateImages[name].Id; projection.Config.Image = projection.Image;
    validatePublicLlmContainer(projection, name, priorModel.services[name], candidateImages[name], priorModel, { secret: jwt, images: candidateImages }, priorSelection);
    return projection;
  };
  const real = new Map();
  const projected = async args => {
    const text = await d(args);
    if (args[0] === 'container' && args[1] === 'inspect') {
      const rows = JSON.parse(text); need(rows.length === 1); const c = rows[0]; real.set(role(c), c);
      if (['api', 'web'].includes(role(c))) return JSON.stringify([retire(c, role(c))]);
    }
    return text;
  };
  const inventory = await inspectPublicLlmNamespace(projected, options, root, profile.cve, priorSelection, { secret: jwt, images: candidateImages });
  inventory.containers = inventory.containers.map(c => real.get(role(c)) ?? c);
  need(inventory.containers.length === 7 && inventory.networks.length === 6 && inventory.volumes.length === 2);
  for (const c of inventory.containers) {
    const name = role(c), command = [...(c.Config.Entrypoint ?? []), ...c.Config.Cmd]; need(c.Path === command[0] && equal(c.Args, command.slice(1)));
    if (['api', 'web'].includes(name)) { retire(c, name); continue; }
    validatePublicLlmContainer(c, name, priorModel.services[name], candidateImages[name], priorModel, { secret: jwt, images: candidateImages }, priorSelection);
    const fixed = name === 'worker' ? ROLLOUT_HOLD.worker : name === 'llm-egress' ? ROLLOUT_HOLD.gateway : null;
    if (fixed) need(c.Id === fixed.id && c.Image === fixed.image && c.State.StartedAt === fixed.startedAt && c.State.FinishedAt === '0001-01-01T00:00:00Z' && c.State.Running && c.State.Status === 'running' && c.State.Pid > 0 && c.State.ExitCode === 0 && c.RestartCount === 0 && !c.State.Paused && !c.State.Restarting && !c.State.OOMKilled && !c.State.Dead && !c.State.Error);
    else { const old = build.peers.find(p => p.name === name); need(old && c.Id === old.id && control(c) === old.control && equal(epoch(c), old.epoch)); }
  }
  for (const receipt of [backup, checked]) need(!(await d(['container', 'ls', '--all', '--no-trunc', '--filter', 'id=' + receipt.id, '--format', '{{.ID}}'])).trim());
  const volume = JSON.parse(await d(['volume', 'inspect', ROLLOUT_HOLD.keyVolume])); need(volume.length === 1); validatePublicLlmKeyVolume(volume[0], settings.selection);
  need(!(await d(['container', 'ls', '--all', '--no-trunc', '--filter', 'volume=' + ROLLOUT_HOLD.keyVolume, '--format', '{{.ID}}'])).trim());
  need(!inventory.containers.some(c => c.Mounts.some(m => m.Destination === '/run/secrets' || m.Name === ROLLOUT_HOLD.keyVolume)));
  const rendered = JSON.parse(await run(publicLlmComposeArguments(root, ['config', '--format', 'json'], { cve: true, directory: stage }), { ...options, env: { ...env, SCAN_JWT_SECRET: CONFIG_SECRET }, timeout: 15000 }));
  validatePublicLlmConfig(rendered, root, profile.cve, settings.selection, candidateImages);
  const stored = await storedBaseline(join(auditPath, 'fenced'), Database, build.baseline);
  const qualified = await checkSource(root); need(qualified.typescript && qualified.bundle); source.verify();
  const proofs = [...execution.directoryProofs, ...execution.programs, ...originalFiles, ...stored.files];
  // Published descriptor files are rebound only by the shared publish operation.
  // Its state fences own those files; stable historical evidence never rebinds.
  const verifyStable = () => { dirs.forEach(v => v()); execution.verify(); source.verify(); settings.verify(); candidateFiles.forEach(f => f.verify()); originalFiles.forEach(f => f.verify()); stored.verify(); };
  const verify = () => { verifyStable(); stateFiles.forEach(f => f.verify()); };
  verify();
  const workerBefore = JSON.parse(await d(['container', 'inspect', ROLLOUT_HOLD.worker.id]))[0];
  const readiness = JSON.parse(await run(['container', 'exec', ROLLOUT_HOLD.worker.id, 'node', '--import', 'tsx', '--input-type=module', '-e', PUBLIC_READY_PROBE], { ...options, timeout: 120000 }));
  need(readiness.ready === true && readiness.manifest === profile.cve.manifestDigest && readiness.bundle === profile.cve.artifactSha256);
  const workerAfter = JSON.parse(await d(['container', 'inspect', ROLLOUT_HOLD.worker.id]))[0];
  need(equal(publicLlmSecretlessControl(workerBefore), publicLlmSecretlessControl(workerAfter)) && equal(publicLlmSecretlessControl(workerAfter), publicLlmSecretlessControl(inventory.containers.find(c => role(c) === 'worker')))); verify();
  const reviewEvidence = { version: 1, audit, endpoint, continuation: 'exact-normal-rollout-post-build-pre-api', source: source.manifest, executionClosure: execution.manifest, settings: settings.selection, priorSelection, baseline: stored.baseline, currentPins, missingPriorMetadata: ['api', 'web'], backupHelperBasis: 'validated-current-candidate-api',
    state: stateFiles.map(f => ({ path: f.path.slice(root.length + 1), identity: f.identity, ...(f.path.endsWith('/scan-jwt') ? {} : { sha256: hash(f.bytes) }) })),
    original: proofs.map(f => ({ path: f.path.slice(root.length + 1), identity: f.identity, ...(f.sha256 ? { sha256: f.sha256 } : f.bytes !== undefined ? { sha256: hash(f.bytes) } : {}) })),
    candidate: candidateFiles.map(f => ({ path: f.path.slice(root.length + 1), identity: f.identity, sha256: hash(f.bytes) })),
    retirementPolicy: Object.fromEntries(['api', 'web'].map(name => [name, { originalId: ROLLOUT_HOLD[name].id, originalImage: ROLLOUT_HOLD[name].image, validationImage: candidateImages[name].Id, metadataUnavailable: true, executeOriginal: false }])),
    peers: inventory.containers.map(publicLlmSecretlessControl), volumes: inventory.volumes, networks: inventory.networks, keyVolumeAuthority: volume[0],
    candidateImages: Object.fromEntries(Object.entries(candidateImages).map(([n, im]) => [n, { Id: im.Id, Os: im.Os, Config: im.Config }])) };
  const review = hash(reviewEvidence);
  return { root, auditPath, auditName: audit, nonce: audit.slice(7), stage, lockPath, endpoint, options, profile, priorSelection, selection: settings.selection, pins, images: candidateImages, apiReplacement: candidateImages.api, webReplacement: candidateImages.web, admissionOnly: true, rolloutOnly: true, backupImage: candidateImages.api, keyVolumeAuthority: volume[0], inventory, baseline: stored.baseline, review, reviewEvidence, stateFiles, proofs, originalFiles, candidateFiles, verify, verifyExecution: execution.verify,
    initialize: { retired: true, candidateImages, currentPins, checkPrefix, verify: verifyStable, verifyImageSource() { source.verify(); need(equal(source.manifest, build.source)); },
      async checkHelper(query) { for (const receipt of [backup, checked]) need(!(await query(['container', 'ls', '--all', '--no-trunc', '--filter', 'id=' + receipt.id, '--format', '{{.ID}}'])).trim()); },
      validateRetiredApi(c) { retire(c, 'api'); }, validateRetiredWeb(c) { retire(c, 'web'); } },
    summary: { audit, review, command: 'check-current-rollout', lifecycle: false, services: 7, apiWebStopped: true, existingWorkerReady: true, sourceClosure: qualified, candidateImageSourceMatches: true, executionModules: execution.programs.length, missingPriorMetadata: ['api', 'web'], apiRetirementOnly: true, webRetirementOnly: true, backupHelperBasis: 'validated-current-candidate-api', baselineBasis: 'retained-nonempty-fenced-four-stores', requiresInitialization: false, requiresCurrentBuild: false, keyVolumeApiOnlyReadonly: true, keyVolumeConsumersBeforeApi: 0 } };
}
