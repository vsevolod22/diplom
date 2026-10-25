#!/usr/bin/env node
// Exact normal-build HOLD, not an unlock/retry facility. Import is inert.
// The separate entry point intentionally leaves the historical loader whitelist alone.
import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire, isBuiltin } from 'node:module';
import ts from 'typescript';
import { PROJECT, STATE, LABEL, CONFIG_SECRET, readProfile, runIsolatedDocker, copyStableSqlite, recoverySqlite, validateExportManifest } from './public-image-stand.mjs';
import { dockerEnvironment } from './local-stand.mjs';
import { capturePublicLlmSource, readPublicLlmBinding, loadPublicLlmSettings, expectedPublicLlmConfig, publicLlmEnvironmentOverlay, publicLlmComposeArguments, validatePublicLlmConfig, validatePublicLlmImage, validatePublicLlmContainer, validatePublicLlmKeyVolume, llmFingerprint, publicLlmStand } from './public-llm-stand.mjs';
import { privateFile, byteFile, directoryIdentity, capturePublicLlmExecutionClosure, PUBLIC_LLM_EXECUTION_MODULES, publicLlmSecretlessControl } from './public-llm-build-continuation.mjs';

export const EXISTING_BUILD_HOLD = Object.freeze({ audit: 'deploy-2c9ed08b8269264b09bf14eb6189a649', phase: 'build-submit-worker' });
const SELF = 'scripts/public-llm-existing-build-continuation.mjs';
const requireApi = createRequire(new URL('../server/api/package.json', import.meta.url));
const canonical = v => Array.isArray(v) ? v.map(canonical) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k => [k, canonical(v[k])])) : v;
const equal = (a, b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
const hash = v => crypto.createHash('sha256').update(typeof v === 'string' ? v : JSON.stringify(canonical(v))).digest('hex');
const need = v => { if (!v) throw Error('PUBLIC LLM exact existing-build continuation refused; details withheld.'); };
const names = p => fs.readdirSync(p).sort();
const has = p => fs.lstatSync(p, { throwIfNoEntry: false }) !== undefined;
const roles = ['api', 'auth-volume-init', 'egress', 'llm-egress', 'scan-volume-init', 'web', 'worker'];
const replaceable = ['api', 'worker', 'web', 'llm-egress'];
const role = c => c.Config?.Labels?.['com.docker.compose.service'];
const owned = labels => labels?.[LABEL] === 'v1' && labels?.['com.docker.compose.project'] === PROJECT;
const control = c => { const config = structuredClone(c.Config); config.Env = config.Env.filter(v => !v.startsWith('SCAN_JWT_SECRET=')); return hash({ Name: c.Name, Image: c.Image, Path: c.Path, Args: c.Args, Config: config, HostConfig: c.HostConfig, Mounts: [...c.Mounts].sort((a, b) => a.Destination.localeCompare(b.Destination)) }); };
const epoch = c => [c.Id, c.State.StartedAt, c.State.FinishedAt, c.State.Pid, c.RestartCount, c.State.Running, c.State.Status, c.State.ExitCode, c.State.Error];
const stopped = c => need(c.State.Status === 'exited' && c.State.Running === false && c.State.Pid === 0 && c.RestartCount === 0 && (['web', 'egress', 'llm-egress'].includes(role(c)) ? [0, 143] : [0]).includes(c.State.ExitCode) && !c.State.Paused && !c.State.OOMKilled && !c.State.Dead && !c.State.Restarting && !c.State.Error);

// Existing audited transitive closure + exactly this new entry. No import edge is
// added to the old launcher: its check-current-* routes keep their old whitelist.
export function captureExistingBuildExecution(root) {
  const old = capturePublicLlmExecutionClosure(root), path = join(root, SELF);
  const self = byteFile(path, false, { maxBytes: 1024 ** 2, captureText: true });
  const source = ts.createSourceFile(SELF, self.text, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS), edges = [];
  need(source.parseDiagnostics.length === 0);
  const dependency = spec => {
    if (spec.startsWith('.')) {
      need(/^\.\/[a-z-]+\.mjs$/.test(spec)); const target = 'scripts/' + spec.slice(2);
      need(PUBLIC_LLM_EXECUTION_MODULES.includes(target) && old.manifest.modules.includes(target)); edges.push(SELF + ' -> ' + target);
    } else need(isBuiltin(spec) || ['typescript', 'better-sqlite3'].includes(spec));
  };
  const requireNames = new Set(['require', 'requireApi']), createNames = new Set(['createRequire']), declarations = [];
  const collect = node => {
    if (ts.isImportDeclaration(node) && node.moduleSpecifier.text === 'node:module' && node.importClause?.namedBindings && ts.isNamedImports(node.importClause.namedBindings)) for (const e of node.importClause.namedBindings.elements) if ((e.propertyName ?? e.name).text === 'createRequire') createNames.add(e.name.text);
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) declarations.push(node);
    ts.forEachChild(node, collect);
  };
  collect(source);
  for (let changed = true, rounds = 0; changed;) {
    need(++rounds <= 32); changed = false;
    for (const d of declarations) {
      const e = d.initializer;
      if (!requireNames.has(d.name.text) && (ts.isIdentifier(e) && requireNames.has(e.text) || ts.isCallExpression(e) && ts.isIdentifier(e.expression) && createNames.has(e.expression.text))) { requireNames.add(d.name.text); changed = true; }
    }
  }
  const visit = node => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier) { need(ts.isStringLiteralLike(node.moduleSpecifier)); dependency(node.moduleSpecifier.text); }
    if (ts.isCallExpression(node)) {
      const e = node.expression, loader = e.kind === ts.SyntaxKind.ImportKeyword || ts.isIdentifier(e) && requireNames.has(e.text) || ts.isCallExpression(e) && ts.isIdentifier(e.expression) && createNames.has(e.expression.text) || ts.isPropertyAccessExpression(e) && e.name.text === 'resolve' && ts.isIdentifier(e.expression) && requireNames.has(e.expression.text);
      if (loader) { need(node.arguments.length === 1 && ts.isStringLiteralLike(node.arguments[0])); dependency(node.arguments[0].text); }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  const programs = [...old.programs, self], verify = () => { old.verify(); self.verify(); };
  verify(); return { programs, directoryProofs: old.directoryProofs, verify, manifest: { entries: [...old.manifest.entries, SELF], modules: [...old.manifest.modules, SELF].sort(), edges: [...old.manifest.edges, ...edges].sort() } };
}

// Only exported, fenced backup COPIES are opened. The original four-store
// checkpoint is authoritative even when a retag removed an original image ID.
async function storedBaseline(path, Database, recorded) {
  const files = [], dirs = [directoryIdentity(path)], listing = names(path);
  need(equal(listing, ['core', 'llm']));
  const scratch = fs.mkdtempSync(join(tmpdir(), 'public-existing-build-')), copies = {}, baseline = { core: {}, llm: {}, empty: false };
  try {
    for (const group of ['core', 'llm']) {
      const dir = join(path, group), entries = names(dir); dirs.push(directoryIdentity(dir), () => need(equal(names(dir), entries)));
      need(['auth.sqlite', 'ledger.sqlite', 'private-manifest.json'].every(n => entries.includes(n)) && entries.every(n => /^(?:auth|ledger)\.sqlite(?:-wal|-shm)?$/.test(n) || n === 'private-manifest.json'));
      const proof = privateFile(join(dir, 'private-manifest.json'), 65536), manifest = JSON.parse(proof.bytes); files.push(proof); validateExportManifest(manifest);
      for (const n of entries.filter(n => n !== 'private-manifest.json')) files.push(byteFile(join(dir, n)));
      const paths = {};
      for (const r of ['auth', 'ledger']) {
        const f = files.find(f => f.path === join(dir, r + '.sqlite'));
        need(f.sha256 === manifest.receipt[r].sha256 && f.identity.size === manifest.receipt[r].bytes);
        const key = group + '-' + r; copies[key] = copyStableSqlite(fs, crypto, f.path, join(scratch, key)); paths[r] = copies[key].path;
      }
      if (group === 'core') {
        const restored = await recoverySqlite(Database, fs, crypto, paths, null);
        for (const r of ['auth', 'ledger']) { need(restored[r].logicalSha256 === manifest.receipt[r].logicalSha256); baseline.core[r] = { logicalSha256: llmFingerprint(Database, fs, crypto, paths[r], r) }; }
      } else for (const [r, kind] of [['auth', 'history'], ['ledger', 'quota']]) {
        baseline.llm[kind] = llmFingerprint(Database, fs, crypto, paths[r], kind);
        need(baseline.llm[kind] === manifest.receipt[r].logicalSha256);
        let empty = true; try { llmFingerprint(Database, fs, crypto, paths[r], kind, true); } catch { empty = false; }
        need(!empty); // Neither store may be relabelled as first-enable/empty.
      }
    }
    need(equal(baseline, recorded)); for (const c of Object.values(copies)) c.verify();
  } finally { for (const c of Object.values(copies)) c.cleanup(); fs.rmSync(scratch, { recursive: true, force: true }); }
  const verify = () => { need(equal(names(path), listing)); dirs.forEach(v => v()); files.forEach(f => f.verify()); };
  verify(); return { files, baseline, verify };
}

function metadataReader(run, options, pins, helper, keyVolume) {
  const ids = new Set(), imageIds = new Set(Object.values(pins.services).map(p => p.image));
  const end = Date.now() + 120000; let calls = 0;
  return async args => {
    need(++calls <= 240 && Date.now() < end); const [kind, op, ref] = args;
    const invoke = a => run(a, { ...options, timeout: Math.max(1, Math.min(15000, end - Date.now())) });
    if (kind === 'image' && op === 'inspect') { need(imageIds.has(ref) || replaceable.some(n => ref === `${PROJECT}-${n}:local`) || ref === `${PROJECT}-egress:local`); return invoke(args); }
    if (kind === 'image' && op === 'ls') return invoke([...args, '--filter', `reference=${PROJECT}-*`]);
    if (['container', 'volume', 'network'].includes(kind) && op === 'ls') {
      const filter = args.find(a => a.startsWith('id=') || a.startsWith('volume='));
      if (filter) { need([`id=${helper.id}`, `volume=${PROJECT}_auth_accounts`, `volume=${PROJECT}_scan_ledger`, `volume=${keyVolume}`].includes(filter)); return invoke(args); }
      need(!args.includes('--filter'));
      const a = await invoke([...args, '--filter', `name=${kind === 'container' ? '^/' : '^'}${PROJECT}${kind === 'container' ? '-' : '_'}`]);
      const b = await invoke([...args, '--filter', `label=com.docker.compose.project=${PROJECT}`]);
      return [...new Set((a + '\n' + b).split('\n').filter(Boolean))].join('\n');
    }
    if (kind === 'container' && op === 'inspect') {
      need(ids.has(ref) || roles.some(n => ref === `${PROJECT}-${n}-1`)); const text = await invoke(args), rows = JSON.parse(text);
      need(rows.length === 1 && roles.some(n => rows[0].Name === `/${PROJECT}-${n}-1`)); ids.add(rows[0].Id); return text;
    }
    if (kind === 'volume' && op === 'inspect') { need([`${PROJECT}_auth_accounts`, `${PROJECT}_scan_ledger`, keyVolume].includes(ref)); return invoke(args); }
    if (kind === 'network' && op === 'inspect') { need(['auth_internal', 'scan_internal', 'registry_uplink', 'web_edge', 'llm_internal', 'llm_uplink'].some(n => ref === `${PROJECT}_${n}`)); return invoke(args); }
    need(false); // No exec/logs/create/build/start/stop/rm and no arbitrary metadata.
  };
}

const ownValue = (error, key) => error && (typeof error === 'object' || typeof error === 'function') ? Object.getOwnPropertyDescriptor(error, key)?.value : undefined;
const metadataCategories = ['image', 'timeout', 'docker_unavailable', 'network_pool', 'resources', 'runtime_health', 'unclassified', 'storage_io', 'guard'];
export function existingBuildMetadataDiagnostic(error) {
  const boundary = ownValue(error, 'boundary'), category = ownValue(error, 'category');
  if (!roles.some(name => boundary === 'prior-image-inspect-' + name) || !metadataCategories.includes(category)) return null;
  return Object.freeze({ boundary, category: category === 'storage_io' ? 'DockerIO' : category });
}
export async function inspectExistingBuildPriorImage(query, name, image) {
  need(roles.includes(name) && /^sha256:[a-f0-9]{64}$/.test(image));
  try { return await query(['image', 'inspect', image]); }
  catch (error) {
    const category = ownValue(error, 'category'), failure = Error('PUBLIC LLM prior image inspection refused; details withheld.');
    failure.boundary = 'prior-image-inspect-' + name;
    failure.category = metadataCategories.includes(category) ? category : 'guard';
    // No raw error/cause/output/reference is carried across this boundary.
    throw failure;
  }
}

export async function preparePublicLlmExistingBuildContinuation({ root, home = homedir(), audit, run = runExistingBuildDocker, ambient = process.env, Database = requireApi('better-sqlite3') }) {
  need(audit === EXISTING_BUILD_HOLD.audit && resolve(root) === root && fs.realpathSync(root) === root && !resolve(home, '.local/state/diplom-public-images/llm').startsWith(root + '/'));
  const state = join(root, STATE), lockPath = join(state, '.operation.lock'), auditPath = join(state, 'llm-deployments', audit), stage = join(lockPath, 'llm-candidate');
  const dirs = [state, lockPath, join(state, 'llm-deployments'), auditPath, stage].map(directoryIdentity);
  const checkPrefix = () => {
    dirs.forEach(v => v());
    need(equal(names(lockPath), ['build-checkpoint.json', 'build-failure.json', 'helper-fenced.json', 'llm-candidate', 'mutation.json']));
    need(equal(names(auditPath), ['fenced']) && equal(names(stage), ['compose.cve.json', 'compose.llm-env.json']));
    const audits = names(join(state, 'llm-deployments')); need(audits.length <= 16 && audits.every(n => /^deploy-[a-f0-9]{32}$/.test(n)));
    need(equal(audits.filter(n => !has(join(state, 'llm-deployments', n, 'complete.json'))), [audit]));
    need(!names(state).some(n => n.startsWith('.llm-pending-') || n.endsWith('.lock') && n !== '.operation.lock'));
  };
  checkPrefix(); const disk = fs.statfsSync(state); need(disk.bavail * disk.bsize >= 4 * 1024 ** 3);
  const execution = captureExistingBuildExecution(root), source = capturePublicLlmSource(root), settings = loadPublicLlmSettings(home), priorSelection = readPublicLlmBinding(root);
  need(priorSelection?.keyVolume && equal(priorSelection, settings.selection));
  const stateFiles = ['profile.json', 'scan-jwt', 'compose.images.json', 'compose.cve.json', 'llm-profile.json', 'compose.llm-env.json'].map(n => privateFile(join(state, n)));
  const originalFiles = ['mutation.json', 'build-checkpoint.json', 'build-failure.json', 'helper-fenced.json'].map(n => privateFile(join(lockPath, n), 16 * 1024 ** 2));
  const [mutation, build, failure, helper] = originalFiles.map(f => JSON.parse(f.bytes));
  need(equal(mutation, { version: 1, project: PROJECT, command: 'public-llm-up', phase: 'fence-web', endpoint: mutation.endpoint }));
  need(equal(failure, { version: 1, phase: EXISTING_BUILD_HOLD.phase, role: 'worker', category: 'unclassified' }));
  need(equal(Object.keys(helper).sort(), ['id', 'image', 'purpose']) && helper.purpose === 'backup' && /^[a-f0-9]{64}$/.test(helper.id));
  const profile = readProfile(root), pins = JSON.parse(stateFiles.find(f => f.path.endsWith('/compose.images.json')).bytes);
  need(profile?.version === 2 && profile.cve && equal(Object.keys(pins), ['services']) && equal(Object.keys(pins.services).sort(), roles));
  for (const p of Object.values(pins.services)) need(equal(Object.keys(p), ['image']) && /^sha256:[a-f0-9]{64}$/.test(p.image));
  need(equal(Object.keys(build).sort(), ['baseline', 'imageMetadata', 'jwtIdentity', 'peers', 'phase', 'pins', 'publicProfile', 'retirementPolicy', 'source', 'sourceBasis', 'version']));
  need(build.version === 1 && build.phase === 'validated-before-build' && build.sourceBasis === 'validated-before-build' && build.retirementPolicy === null && equal(build.pins, pins) && equal(build.publicProfile, profile) && build.baseline?.llm && build.baseline.empty === false && equal(Object.keys(build.imageMetadata).sort(), roles));
  need(helper.image === pins.services.api.image && Array.isArray(build.peers) && equal(build.peers.map(p => p.name).sort(), roles));
  const jwtFile = stateFiles.find(f => f.path.endsWith('/scan-jwt'));
  need(/^[a-f0-9]{96}$/.test(jwtFile.bytes));
    need(equal(Object.fromEntries(Object.entries(jwtFile.identity).filter(([k]) => ['dev', 'ino', 'mode', 'uid', 'size', 'mtime', 'ctime'].includes(k))), build.jwtIdentity));
  const candidateFiles = ['compose.cve.json', 'compose.llm-env.json'].map(n => privateFile(join(stage, n)));
  need(candidateFiles[0].bytes === stateFiles.find(f => f.path.endsWith('/compose.cve.json')).bytes && equal(JSON.parse(candidateFiles[1].bytes), publicLlmEnvironmentOverlay(priorSelection)));
  const stored = await storedBaseline(join(auditPath, 'fenced'), Database, build.baseline);
  const env = dockerEnvironment(ambient), endpoint = env.DOCKER_HOST && !env.DOCKER_CONTEXT ? env.DOCKER_HOST : JSON.parse(await run(['context', 'inspect', ...(env.DOCKER_CONTEXT ? [env.DOCKER_CONTEXT] : []), '--format', '{{json .Endpoints.docker.Host}}'], { root, env, timeout: 10000 }));
  need(typeof endpoint === 'string' && /^unix:\/\/\/[^\s\0]+$/.test(endpoint) && endpoint === mutation.endpoint);
  env.DOCKER_HOST = endpoint; env.COMPOSE_DISABLE_ENV_FILE = '1'; for (const k of ['DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']) delete env[k];
  const options = { root, env }, model = expectedPublicLlmConfig(root, profile.cve, priorSelection);
  const images = {}, missing = [], taggedImages = {};
  const query = metadataReader(run, options, pins, helper, priorSelection.keyVolume);
  for (const name of roles) {
    const saved = build.imageMetadata[name]; need(equal(Object.keys(saved).sort(), ['Config', 'Id', 'Os']) && saved.Id === pins.services[name].image);
    // Validate persisted defaults as historical policy evidence, NOT as proof
    // that the original image is present or is permitted to execute.
    if (replaceable.includes(name)) validatePublicLlmImage(saved, name);
    let rows;
    try { rows = JSON.parse(await inspectExistingBuildPriorImage(query, name, saved.Id)); }
    catch (error) { if (!replaceable.includes(name) || error?.category !== 'image') throw error; missing.push(name); continue; }
    need(rows.length === 1 && equal({ Id: rows[0].Id, Os: rows[0].Os, Config: rows[0].Config }, saved)); validatePublicLlmImage(rows[0], name); images[name] = rows[0];
  }
  // Retained services MUST have live metadata; missing deployable peers are only
  // compared with the durable pre-build record, never selected for execution.
  const validateOriginalPeer = (c, name) => {
    const saved = build.peers.find(p => p.name === name), command = [...(c.Config.Entrypoint ?? []), ...c.Config.Cmd];
    need(saved && role(c) === name && c.Name === `/${PROJECT}-${name}-1` && owned(c.Config.Labels) && /^[a-f0-9]{64}$/.test(c.Id) && c.Config.Image === pins.services[name].image && saved.id === c.Id && saved.image === c.Image && saved.control === control(c) && equal(saved.epoch, epoch(c)) && c.Path === command[0] && equal(c.Args, command.slice(1)));
    if (['api', 'worker', 'web'].includes(name) || name.endsWith('volume-init') || !c.State.Running) stopped(c);
    else need(['egress', 'llm-egress'].includes(name) && c.State.Status === 'running' && Number.isSafeInteger(c.State.Pid) && c.State.Pid > 0 && c.RestartCount === 0 && !c.State.Paused && !c.State.OOMKilled && !c.State.Restarting && !c.State.Dead && !c.State.Error);
    // Reapply independent runtime policy using actual persisted defaults when
    // unavailable. No fabricated inspect result, replacement ID or tag is
    // substituted for a missing original; it remains retire-only throughout.
    if (name === 'api') need(c.Config.Env.filter(v => v.startsWith('SCAN_JWT_SECRET=')).length === 1 && c.Config.Env.includes('SCAN_JWT_SECRET=' + jwtFile.bytes));
    validatePublicLlmContainer(c, name, model.services[name], images[name] ?? build.imageMetadata[name], model, { images: images[name] ? images : build.imageMetadata, secret: jwtFile.bytes }, priorSelection);
  };
  const inspectRuntime = async q => {
    const inventory = { containers: [], volumes: [], networks: [], images: [] };
    for (const kind of ['container', 'volume', 'network']) {
      const format = `{{.${kind === 'container' ? 'Names' : 'Name'}}}\t{{.Label "com.docker.compose.project"}}`;
      const lines = (await q([kind, 'ls', ...(kind === 'container' ? ['--all'] : []), '--format', format])).trim().split('\n').filter(Boolean).map(s => s.split('\t'));
      const allowed = kind === 'container' ? roles.map(n => `${PROJECT}-${n}-1`) : kind === 'volume' ? ['auth_accounts', 'scan_ledger'].map(n => `${PROJECT}_${n}`) : Object.values(model.networks).map(n => n.name);
      need(equal(lines.map(r => r[0]).sort(), [...allowed].sort()) && lines.every(r => r.length === 2 && r[1] === PROJECT));
      for (const [name] of lines) {
        const rows = JSON.parse(await q([kind, 'inspect', name])); need(rows.length === 1); const v = rows[0]; need(owned(kind === 'container' ? v.Config?.Labels : v.Labels));
        if (kind === 'container') { validateOriginalPeer(v, role(v)); inventory.containers.push(v); }
        else {
          need(v.Name === name && v.Driver === (kind === 'volume' ? 'local' : 'bridge') && equal(v.Options ?? {}, {}));
          if (kind === 'volume') need(v.Scope === 'local' && typeof v.Mountpoint === 'string' && v.Mountpoint.startsWith('/') && !/[\x00-\x1f\x7f]/.test(v.Mountpoint));
          else need(Boolean(v.Internal) === name.endsWith('_internal') && !v.Attachable && !v.Ingress && !v.EnableIPv6 && (!v.IPAM || v.IPAM.Driver === 'default' && equal(v.IPAM.Options ?? {}, {})));
          inventory[kind === 'volume' ? 'volumes' : 'networks'].push(v);
        }
      }
    }
    const key = JSON.parse(await q(['volume', 'inspect', priorSelection.keyVolume])); need(key.length === 1); validatePublicLlmKeyVolume(key[0], priorSelection); inventory.volumes.push(key[0]);
    for (const v of inventory.volumes) {
      const ids = (await q(['container', 'ls', '--all', '--no-trunc', '--filter', `volume=${v.Name}`, '--format', '{{.ID}}'])).trim().split('\n').filter(Boolean);
      const consumers = inventory.containers.filter(c => c.Mounts.some(m => m.Type === 'volume' && m.Name === v.Name));
      need(equal(ids.sort(), consumers.map(c => c.Id).sort()));
      if (v.Name === priorSelection.keyVolume) need(consumers.length === 1 && role(consumers[0]) === 'api');
      for (const c of consumers) for (const m of c.Mounts.filter(m => m.Type === 'volume' && m.Name === v.Name)) need(m.Source === v.Mountpoint && m.Driver === 'local');
    }
    for (const n of inventory.networks) need(equal(Object.keys(n.Containers ?? {}).sort(), inventory.containers.filter(c => c.State.Running && Object.hasOwn(c.NetworkSettings.Networks, n.Name)).map(c => c.Id).sort()));
    need(!(await q(['container', 'ls', '--all', '--no-trunc', '--filter', `id=${helper.id}`, '--format', '{{.ID}}'])).trim());
    const tags = (await q(['image', 'ls', '--format', '{{.Repository}}:{{.Tag}}'])).trim().split('\n').filter(Boolean);
    for (const tag of [...new Set(tags)].sort()) {
      const name = [...replaceable, 'egress'].find(n => tag === `${PROJECT}-${n}:local`); need(name);
      const rows = JSON.parse(await q(['image', 'inspect', tag])); need(rows.length === 1); validatePublicLlmImage(rows[0], name); inventory.images.push({ name, Id: rows[0].Id, Os: rows[0].Os, Config: rows[0].Config }); taggedImages[name] = rows[0];
    }
    inventory.containers.sort((a, b) => role(a).localeCompare(role(b))); inventory.volumes.sort((a, b) => a.Name.localeCompare(b.Name)); inventory.networks.sort((a, b) => a.Name.localeCompare(b.Name));
    return inventory;
  };
  const inventory = await inspectRuntime(query), backupImage = images.api ?? taggedImages.api;
  need(backupImage); validatePublicLlmImage(backupImage, 'api');
  // Config rendering is inert, uses a dummy JWT and disables dotenv explicitly.
  const rendered = JSON.parse(await run(publicLlmComposeArguments(root, ['config', '--format', 'json'], { cve: true, directory: stage, pinned: false }), { ...options, env: { ...env, SCAN_JWT_SECRET: CONFIG_SECRET }, timeout: 15000 }));
  validatePublicLlmConfig(rendered, root, profile.cve, priorSelection);
  const proofs = [...execution.directoryProofs, ...execution.programs, ...originalFiles, ...stored.files];
  const verifyStable = () => { dirs.forEach(v => v()); execution.verify(); source.verify(); settings.verify(); originalFiles.forEach(f => f.verify()); candidateFiles.forEach(f => f.verify()); stored.verify(); };
  const verify = () => { verifyStable(); stateFiles.forEach(f => f.verify()); };
  const runtimeEvidence = v => ({ ...v, containers: v.containers.map(publicLlmSecretlessControl) });
  const runtime = runtimeEvidence(inventory);
  const revalidate = async () => {
    verify(); checkPrefix(); const q = metadataReader(run, options, pins, helper, priorSelection.keyVolume);
    for (const name of roles) {
      let rows; try { rows = JSON.parse(await inspectExistingBuildPriorImage(q, name, pins.services[name].image)); }
      catch (error) { if (missing.includes(name) && error?.category === 'image') continue; throw error; }
      need(!missing.includes(name) && rows.length === 1 && equal({ Id: rows[0].Id, Os: rows[0].Os, Config: rows[0].Config }, build.imageMetadata[name])); validatePublicLlmImage(rows[0], name);
    }
    need(equal(runtimeEvidence(await inspectRuntime(q)), runtime)); verify(); checkPrefix();
  };
  verify(); checkPrefix();
  const proofEvidence = f => ({ path: f.path.slice(root.length + 1), identity: f.identity, ...(f.sha256 ? { sha256: f.sha256 } : f.bytes !== undefined && !f.path.endsWith('/scan-jwt') ? { sha256: hash(f.bytes) } : {}) });
  const reviewEvidence = { version: 1, audit, continuation: 'exact-existing-llm-normal-build-worker-hold', endpoint, source: source.manifest, executionClosure: execution.manifest, settings: settings.selection, priorSelection, baseline: stored.baseline,
    original: proofs.map(proofEvidence), state: stateFiles.map(proofEvidence), candidate: candidateFiles.map(proofEvidence), runtime,
    missingPriorMetadata: missing.sort(), retirementPolicy: missing.map(name => ({ name, image: pins.services[name].image, basis: 'durable-pre-build-checkpoint-controls-and-epoch', executeOriginal: false })),
    priorImageMetadata: Object.fromEntries(Object.entries(images).map(([n, im]) => [n, { Id: im.Id, Os: im.Os, Config: im.Config }])), backupHelper: { Id: backupImage.Id, Os: backupImage.Os, Config: backupImage.Config }, initialization: 'forbidden-existing-four-stores' };
  const review = hash(reviewEvidence);
  return { root, auditName: audit, nonce: audit.slice(7), auditPath, lockPath, stage, options, endpoint, profile, priorSelection, selection: settings.selection, pins, images, inventory, backupImage, keyVolumeAuthority: inventory.volumes.find(v => v.Name === priorSelection.keyVolume), baseline: stored.baseline,
    existingBuildOnly: true, review, reviewEvidence, originalFiles, stateFiles, candidateFiles, proofs, verify, verifyStable, verifyExecution: execution.verify, checkPrefix, revalidate, validateOriginalPeer,
    summary: { audit, review, command: 'check-existing-build', lifecycle: false, services: 7, missingPriorMetadata: missing, baselineBasis: 'durable-pre-build-checkpoint-and-original-fenced-four-stores', requiresCurrentBuild: true, requiresInitialization: false, keyVolumeApiOnlyReadonly: true, executionModules: execution.programs.length, liveStoresCompared: false, mandatoryPreBuildNetworkNoneComparison: true } };
}

// Raw Docker failure output never leaves this adapter. Finite hints are NOT
// continuation authority; the original unclassified receipt is left untouched.
export function classifyExistingBuildCause(error, stdout = '', stderr = '') {
  const bounded = v => typeof v === 'string' ? v.slice(0, 32768) + '\n' + v.slice(-32768) : '';
  const text = (bounded(stdout) + '\n' + bounded(stderr)).toLowerCase();
  if (error?.killed) return 'timeout';
  if (error?.code === 'EIO' || /input\/output error|\bi\/o error\b/.test(text)) return 'storage_io';
  if (error?.code === 'ENOENT' || /cannot connect to the docker daemon|is the docker daemon running/.test(text)) return 'docker_unavailable';
  if (/no space left on device|out of memory|cannot allocate memory/.test(text)) return 'resources';
  if (/err_pnpm|pnpm.*(?:error|failed)|frozen-lockfile/.test(text)) return 'dependency_install';
  if (/error ts[0-9]{4}|typescript.*error/.test(text)) return 'typescript';
  if (/failed to resolve|manifest unknown|pull access denied/.test(text)) return 'base_image_resolution';
  if (/failed to compute cache key|failed to calculate checksum|not found.*build context/.test(text)) return 'build_context';
  if (/network is unreachable|temporary failure in name resolution|tls handshake timeout/.test(text)) return 'build_network';
  return 'unclassified';
}
export function runExistingBuildDocker(args, options, execute = execFile) {
  const building = args[0] === 'compose' && args.at(-2) === 'build' && replaceable.includes(args.at(-1));
  if (!building) {
    if (!(args.length === 3 && args[0] === 'image' && args[1] === 'inspect')) return runIsolatedDocker(args, options, execute);
    let storageIo = false;
    // Keep the existing metadata adapter's categories, especially image vs
    // unclassified. Observe IO locally without a second dispatch or fallback.
    const observe = (program, received, settings, done) => {
      try { return execute(program, received, settings, (error, stdout, stderr) => {
        storageIo = Boolean(error) && classifyExistingBuildCause(error, stdout, stderr) === 'storage_io';
        done(error, stdout, stderr);
      }); } catch (error) { storageIo = classifyExistingBuildCause(error) === 'storage_io'; throw error; }
    };
    return runIsolatedDocker(args, options, observe).catch(error => {
      if (!storageIo) throw error;
      const failure = Error('PUBLIC LLM Docker metadata IO failure; output withheld.'); failure.category = 'storage_io'; throw failure;
    });
  }
  return new Promise((resolveOutput, reject) => {
    const refused = (error, stdout, stderr) => { const e = Error('PUBLIC LLM existing build failed; output withheld.'); e.buildCause = classifyExistingBuildCause(error, stdout, stderr); e.category = ['timeout', 'resources', 'docker_unavailable', 'storage_io'].includes(e.buildCause) ? e.buildCause : 'unclassified'; reject(e); };
    try { execute('docker', args, { cwd: options.root, env: options.env, timeout: options.timeout, killSignal: 'SIGKILL', maxBuffer: 1024 ** 2, encoding: 'utf8' }, (error, stdout, stderr) => error ? refused(error, stdout, stderr) : resolveOutput('')); }
    catch (error) { refused(error); }
  });
}

// Check/continue commands live here, so old launcher import scans are unchanged.
// The normal launcher owns every lifecycle boundary; this module only prepares
// read-only authority and passes it into that shared flow after exact-token review.
export async function publicLlmExistingBuildStand(argv, { root = dirname(dirname(fileURLToPath(import.meta.url))), run = runExistingBuildDocker, log = console.log, ...options } = {}) {
  const [command, ...flags] = argv, checking = command === 'check-existing-build';
  need((checking || command === 'continue-existing-build') && flags[0] === '--audit' && flags[1] === EXISTING_BUILD_HOLD.audit && (checking ? flags.length === 2 : flags.length === 6 && flags[2] === '--review' && /^[a-f0-9]{64}$/.test(flags[3] ?? '') && flags[4] === '--ack-reviewed-current-source' && flags[5] === '--ack-retire-only-unavailable-peers'));
  const context = await preparePublicLlmExistingBuildContinuation({ ...options, root, run, audit: flags[1] });
  if (checking) { log(JSON.stringify(context.summary)); return context.summary; }
  need(context.review === flags[3]);
  return publicLlmStand(argv, { ...options, root, run, log, existingBuildContinuation: context });
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) publicLlmExistingBuildStand(process.argv.slice(2)).catch(error => {
  const diagnostic = existingBuildMetadataDiagnostic(error);
  console.error('PUBLIC LLM exact existing-build continuation refused/HOLD; ' + (diagnostic ? `boundary=${diagnostic.boundary}; category=${diagnostic.category}; ` : '') + 'details withheld. Original evidence retained; no automatic retry.'); process.exitCode = 1;
});
