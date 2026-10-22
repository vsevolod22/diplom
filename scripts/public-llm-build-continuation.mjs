// Reviewed continuation of THIS launcher's pre-initialization build HOLD only.
// Checking never writes the public state, opens live DBs, executes a container or builds an image.
import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import { tmpdir, homedir } from 'node:os';
import { join, resolve, dirname, relative } from 'node:path';
import { createRequire, isBuiltin } from 'node:module';
import ts from 'typescript';
import {
  PROJECT, STATE, CONFIG_SECRET, readProfile, loadSecret, runIsolatedDocker,
  copyStableSqlite, recoverySqlite, validateExportManifest,
} from './public-image-stand.mjs';
import { dockerEnvironment } from './local-stand.mjs';
import { directory, readBounded } from './setup-local-cve.mjs';
import {
  capturePublicLlmSource, readPublicLlmBinding, loadPublicLlmSettings, expectedPublicLlmConfig,
  publicLlmEnvironmentOverlay, publicLlmComposeArguments, validatePublicLlmConfig,
  validatePublicLlmImage, validatePublicLlmContainer, inspectPublicLlmNamespace, llmFingerprint,
} from './public-llm-stand.mjs';
import { checkPublicLlmSourceBuild } from './public-llm-source-build.mjs';

const require = createRequire(new URL('../server/api/package.json', import.meta.url));
const canonical = v => Array.isArray(v) ? v.map(canonical) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k => [k, canonical(v[k])])) : v;
const eq = (a, b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
const digest = v => crypto.createHash('sha256').update(JSON.stringify(canonical(v))).digest('hex');
const fail = reason => { const e = Error('PUBLIC LLM current-build check refused; details withheld.'); e.reason = reason; throw e; };
const need = (v, reason = 'CURRENT_BUILD_AUTHORITY_REJECTED') => { if (!v) fail(reason); };
const has = p => fs.lstatSync(p, { throwIfNoEntry: false }) !== undefined;
const names = p => fs.readdirSync(p).sort();
const role = c => c.Config.Labels['com.docker.compose.service'];
const stamp = s => ({ dev: String(s.dev), ino: String(s.ino), mode: s.mode, uid: s.uid, nlink: s.nlink, size: s.size, mtime: s.mtimeMs, ctime: s.ctimeMs });
export function privateFile(path, cap = 16384) {
  const before = fs.lstatSync(path), text = readBounded(path, cap, 0o600), after = fs.lstatSync(path);
  need(eq(stamp(before), stamp(after))); const initial = stamp(after);
  return { path, bytes: text, identity: initial, verify() { need(eq(stamp(fs.lstatSync(path)), initial) && readBounded(path, cap, 0o600) === text); } };
}
export function byteFile(path, privateMode = true, { maxBytes = 256 * 1024 ** 2, captureText = false } = {}) {
  const initial = fs.lstatSync(path); need(initial.isFile() && !initial.isSymbolicLink() && initial.nlink === 1 && initial.uid === process.getuid() && (privateMode ? (initial.mode & 0o777) === 0o600 : !(initial.mode & 0o022)) && initial.size <= maxBytes);
  let text;
  const read = (capture = false) => {
    const pieces = capture ? [] : null;
    const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK), h = crypto.createHash('sha256'), b = Buffer.alloc(65536); let total = 0;
    try {
      need(eq(stamp(fs.fstatSync(fd)), stamp(initial)));
      let n; while ((n = fs.readSync(fd, b, 0, b.length, null))) { total += n; need(total <= initial.size); h.update(b.subarray(0, n)); if (pieces) pieces.push(Buffer.from(b.subarray(0, n))); }
      need(total === initial.size && eq(stamp(fs.fstatSync(fd)), stamp(initial)) && eq(stamp(fs.lstatSync(path)), stamp(initial)));
      if (pieces) text = Buffer.concat(pieces).toString('utf8');
      return h.digest('hex');
    } finally { fs.closeSync(fd); }
  };
  const sha256 = read(captureText); return { path, identity: stamp(initial), sha256, ...(captureText ? { text } : {}), verify() { need(read() === sha256); } };
}
// Audited FIRST-PARTY execution boundary, not a directory scan. Literal imports
// may traverse only these modules; additions/nonliteral loaders fail closed.
// Container API/runtime and web sources are separately fenced in source.manifest;
// Node/npm dependencies remain bound by the existing manifests and lockfile.
export const PUBLIC_LLM_EXECUTION_MODULES = Object.freeze([
  'scripts/local-stand.mjs', 'scripts/public-cve-bridge-capacity.mjs',
  'scripts/public-cve-bridge-runtime.mjs', 'scripts/public-cve-bridge.mjs',
  'scripts/public-cve-provision.mjs', 'scripts/public-image-stand-profile.mjs',
  'scripts/public-image-stand.mjs', 'scripts/public-llm-build-continuation.mjs',
  'scripts/public-llm-source-build.mjs', 'scripts/public-llm-stand.mjs', 'scripts/public-llm-initialize-continuation.mjs',
  'scripts/public-refresh-cve-preservation.mjs', 'scripts/refresh-local-cve.mjs',
  'scripts/refresh-public-cve.mjs', 'scripts/setup-local-cve.mjs',
  'server/deploy/trust/fetch-db-layer.mjs',
]);
const EXECUTION_ENTRIES = Object.freeze(['scripts/public-llm-stand.mjs', 'scripts/public-llm-build-continuation.mjs', 'scripts/public-llm-source-build.mjs']);
export function capturePublicLlmExecutionClosure(root) {
  need(resolve(root) === root && fs.realpathSync(root) === root, 'CURRENT_BUILD_EXECUTION_ROOT_REJECTED');
  const permitted = new Set(PUBLIC_LLM_EXECUTION_MODULES), modules = new Map(), directories = new Map(), edges = new Set(), todo = [...EXECUTION_ENTRIES];
  let totalBytes = 0, importSites = 0;
  const guardParents = path => {
    for (let p = root, parts = relative(root, dirname(path)).split('/').filter(Boolean), i = -1; i < parts.length; i++) {
      if (i >= 0) p = join(p, parts[i]);
      if (!directories.has(p)) {
        const s = fs.lstatSync(p); need(s.isDirectory() && !s.isSymbolicLink() && s.uid === process.getuid() && !(s.mode & 0o022), 'CURRENT_BUILD_EXECUTION_DIRECTORY_REJECTED');
        const identity = { dev: String(s.dev), ino: String(s.ino), uid: s.uid, mode: s.mode }, path = p;
        directories.set(path, { path, identity, verify() { const s = fs.lstatSync(path); need(s.isDirectory() && !s.isSymbolicLink() && eq({ dev: String(s.dev), ino: String(s.ino), uid: s.uid, mode: s.mode }, identity), 'CURRENT_BUILD_EXECUTION_DIRECTORY_REJECTED'); } });
      }
      directories.get(p).verify();
    }
  };
  while (todo.length) {
    const name = todo.shift(); if (modules.has(name)) continue;
    need(permitted.has(name) && modules.size < 32, 'CURRENT_BUILD_EXECUTION_IMPORT_REJECTED');
    const path = join(root, name); guardParents(path);
    const proof = byteFile(path, false, { maxBytes: 1024 ** 2, captureText: true });
    totalBytes += proof.identity.size; need(totalBytes <= 4 * 1024 ** 2, 'CURRENT_BUILD_EXECUTION_BUDGET_REJECTED');
    const source = ts.createSourceFile(name, proof.text, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
    need(source.parseDiagnostics.length === 0, 'CURRENT_BUILD_EXECUTION_PARSE_REJECTED');
    modules.set(name, proof);
    const requireNames = new Set(['require', 'requireApi']), createNames = new Set(['createRequire']), declarations = [];
    const collect = node => {
      if (ts.isImportDeclaration(node) && node.moduleSpecifier.text === 'node:module' && node.importClause?.namedBindings && ts.isNamedImports(node.importClause.namedBindings)) {
        for (const e of node.importClause.namedBindings.elements) if ((e.propertyName ?? e.name).text === 'createRequire') createNames.add(e.name.text);
      }
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) declarations.push(node);
      ts.forEachChild(node, collect);
    };
    collect(source);
    for (let changed = true, rounds = 0; changed;) {
      need(++rounds <= 32, 'CURRENT_BUILD_EXECUTION_BUDGET_REJECTED'); changed = false;
      for (const d of declarations) {
        const e = d.initializer;
        if (!requireNames.has(d.name.text) && (ts.isIdentifier(e) && requireNames.has(e.text) || ts.isCallExpression(e) && ts.isIdentifier(e.expression) && createNames.has(e.expression.text))) { requireNames.add(d.name.text); changed = true; }
      }
    }
    const dependency = specifier => {
      need(++importSites <= 512, 'CURRENT_BUILD_EXECUTION_BUDGET_REJECTED');
      if (specifier.startsWith('.')) {
        need(/^(?:\.\/|\.\.\/)[a-zA-Z0-9_./-]+\.mjs$/.test(specifier), 'CURRENT_BUILD_EXECUTION_IMPORT_REJECTED');
        const target = relative(root, resolve(dirname(path), specifier));
        need(permitted.has(target), 'CURRENT_BUILD_EXECUTION_IMPORT_REJECTED');
        edges.add(name + ' -> ' + target); need(edges.size <= 256, 'CURRENT_BUILD_EXECUTION_BUDGET_REJECTED'); todo.push(target);
      } else need(isBuiltin(specifier) || ['typescript', 'typescript/bin/tsc', 'better-sqlite3'].includes(specifier), 'CURRENT_BUILD_EXECUTION_IMPORT_REJECTED');
    };
    const visit = node => {
      if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier) { need(ts.isStringLiteralLike(node.moduleSpecifier), 'CURRENT_BUILD_EXECUTION_IMPORT_REJECTED'); dependency(node.moduleSpecifier.text); }
      if (ts.isCallExpression(node)) {
        const e = node.expression;
        const loader = e.kind === ts.SyntaxKind.ImportKeyword || ts.isIdentifier(e) && requireNames.has(e.text) ||
          ts.isCallExpression(e) && ts.isIdentifier(e.expression) && createNames.has(e.expression.text) ||
          ts.isPropertyAccessExpression(e) && e.name.text === 'resolve' && ts.isIdentifier(e.expression) && requireNames.has(e.expression.text);
        if (loader) { need(node.arguments.length === 1 && ts.isStringLiteralLike(node.arguments[0]), 'CURRENT_BUILD_EXECUTION_NONLITERAL_REJECTED'); dependency(node.arguments[0].text); }
      }
      ts.forEachChild(node, visit);
    };
    visit(source); proof.verify();
  }
  const programs = [...modules].sort(([a], [b]) => a.localeCompare(b)).map(([, p]) => p);
  const directoryProofs = [...directories.values()].sort((a, b) => a.path.localeCompare(b.path));
  const verify = () => { for (const d of directoryProofs) d.verify(); for (const p of programs) p.verify(); };
  verify(); return { programs, directoryProofs, verify, manifest: { entries: EXECUTION_ENTRIES, modules: [...modules.keys()].sort(), edges: [...edges].sort() } };
}

export function directoryIdentity(path) {
  directory(path, 0o700); const a = fs.lstatSync(path);
  return () => { directory(path, 0o700); const b = fs.lstatSync(path); need(a.dev === b.dev && a.ino === b.ino); };
}
function clean(c) {
  need(c.State.Status === 'exited' && !c.State.Running && c.State.Pid === 0 && c.RestartCount === 0 && !c.State.Paused && !c.State.OOMKilled && !c.State.Dead && !c.State.Restarting && !c.State.Error);
  need((['web', 'egress'].includes(role(c)) ? [0, 143] : [0]).includes(c.State.ExitCode));
}
export function publicLlmSecretlessControl(c) {
  const v = structuredClone(c);
  v.Config.Env = v.Config.Env.filter(x => !x.startsWith('SCAN_JWT_SECRET='));
  delete v.State.Health; // Running API is forbidden; old health logs are not review material.
  if (v.HostConfig?.Mounts) v.HostConfig.Mounts.sort((a, b) => a.Target.localeCompare(b.Target));
  return { id: v.Id, image: v.Image, created: v.Created, restartCount: v.RestartCount, path: v.Path, args: v.Args,
    config: v.Config, host: v.HostConfig, mounts: [...v.Mounts].sort((a, b) => a.Destination.localeCompare(b.Destination)), state: v.State, networks: v.NetworkSettings.Networks };
}

// This is explicitly NOT reconstruction of unavailable original image metadata.
// The stopped worker is retire-only. Its controls are checked against a real,
// validated replacement image's policy, and it is never an execution/helper image.
export function validateRetiredPublicLlmWorker(c, pinnedId, replacement, model, images) {
  need(role(c) === 'worker' && c.Image === pinnedId && c.Config.Image === pinnedId && replacement.Id !== pinnedId);
  clean(c); validatePublicLlmImage(replacement, 'worker');
  const command = [...(c.Config.Entrypoint ?? []), ...c.Config.Cmd]; need(c.Path === command[0] && eq(c.Args, command.slice(1)), 'CURRENT_BUILD_EXECUTABLE_REJECTED');
  const projected = structuredClone(c); projected.Image = replacement.Id; projected.Config.Image = replacement.Id;
  validatePublicLlmContainer(projected, 'worker', model.services.worker, replacement, model, { images: { ...images, worker: replacement } }, null);
}

// Scoped listings cover BOTH own names and own project labels. Consumers of the
// two public volumes are also included, never arbitrary old-holder inspection.
export function publicLlmReadOnlyMetadata(run, options, pinnedIds, { limit = 180, helperId = null } = {}) {
  let calls = 0; const deadline = Date.now() + 120000, containerIds = new Set(helperId ? [helperId] : []);
  return async args => {
    need(++calls <= limit && Date.now() < deadline, 'CURRENT_BUILD_METADATA_BUDGET');
    const [kind, op, ref] = args;
    const invoke = a => run(a, { ...options, timeout: Math.max(1, Math.min(15000, deadline - Date.now())) });
    if (kind === 'image' && op === 'inspect' && (pinnedIds.has(ref) || /^dip-public-images-(?:api|worker|web|egress|llm-egress):local$/.test(ref))) return invoke(args);
    if (kind === 'image' && op === 'ls') return invoke([...args, '--filter', `reference=${PROJECT}-*`]);
    if (['container', 'volume', 'network'].includes(kind) && op === 'ls') {
      const filter = args.find(x => x.startsWith('volume=') || x.startsWith('id='));
      if (filter) { need(filter.startsWith('id=') && /^[a-f0-9]{64}$/.test(filter.slice(3)) || [`volume=${PROJECT}_auth_accounts`, `volume=${PROJECT}_scan_ledger`].includes(filter)); return invoke(args); }
      need(!args.includes('--filter'));
      const a = await invoke([...args, '--filter', `name=${kind === 'container' ? '^/' : '^'}${PROJECT}${kind === 'container' ? '-' : '_'}`]);
      const b = await invoke([...args, '--filter', `label=com.docker.compose.project=${PROJECT}`]);
      return [...new Set((a + '\n' + b).split('\n').filter(Boolean))].join('\n');
    }
    if (kind === 'container' && op === 'inspect' && (containerIds.has(ref) || /^dip-public-images-(?:auth-volume-init|scan-volume-init|egress|worker|api|web)-1$/.test(ref))) {
      const text = await invoke(args); for (const c of JSON.parse(text)) if (c.Name.startsWith('/' + PROJECT + '-')) containerIds.add(c.Id); return text;
    }
    if (['volume', 'network'].includes(kind) && op === 'inspect' && ref.startsWith(PROJECT + '_')) return invoke(args);
    fail('CURRENT_BUILD_READ_ONLY_OPERATION_REJECTED');
  };
}

export async function preparePublicLlmBuildContinuation({ root, home = homedir(), audit, run = runIsolatedDocker, ambient = process.env,
  Database = require('better-sqlite3'), checkSource = checkPublicLlmSourceBuild, createdInitializerOnly = false, postRetirementOnly = false, failedInitializerOnly = false, admissionOnly = false, apiOnly = false }) {
  need(resolve(root) === root && fs.realpathSync(root) === root, 'CURRENT_BUILD_ROOT_REJECTED');
  need(/^deploy-[a-f0-9]{32}$/.test(audit), 'CURRENT_BUILD_AUDIT_ARGUMENT');
  const state = join(root, STATE), lockPath = join(state, '.operation.lock'), auditPath = join(state, 'llm-deployments', audit), stage = join(lockPath, 'llm-candidate');
  const directoryChecks = [state, lockPath, join(state, 'llm-deployments'), auditPath, stage, join(auditPath, 'fenced'), join(auditPath, 'fenced/core')].map(directoryIdentity);
  const disk = fs.statfsSync(state); need(disk.bavail * disk.bsize >= 4 * 1024 ** 3, 'CURRENT_BUILD_DISK_BUDGET_REJECTED');
  const execution = capturePublicLlmExecutionClosure(root), programs = execution.programs;
  const initialize = createdInitializerOnly ? await (await import('./public-llm-initialize-continuation.mjs')).readCreatedInitializerPrefix({ root, audit, Database, postRetirementOnly, failedInitializerOnly, admissionOnly, apiOnly }) : null;
  if (!initialize) {
    need(eq(names(lockPath), ['helper-fenced.json', 'llm-candidate', 'mutation.json']), 'CURRENT_BUILD_PREFIX_REJECTED');
    need(eq(names(auditPath), ['fenced']) && eq(names(join(auditPath, 'fenced')), ['core']), 'CURRENT_BUILD_BACKUP_PREFIX_REJECTED');
  }
  const audits = names(join(state, 'llm-deployments')); need(audits.length <= 16 && audits.every(n => /^deploy-[a-f0-9]{32}$/.test(n)), 'CURRENT_BUILD_AUDIT_BUDGET_REJECTED');
  const partials = audits.filter(n => !has(join(state, 'llm-deployments', n, 'complete.json')));
  need(eq(partials, [audit]), 'CURRENT_BUILD_NOT_UNIQUE');
  need(!names(state).some(n => n.endsWith('.lock') && n !== '.operation.lock') && !names(state).some(n => n.startsWith('.llm-pending-')));
  const originalFiles = ['mutation.json', 'helper-fenced.json'].map(n => privateFile(join(lockPath, n)));
  const mutation = JSON.parse(originalFiles[0].bytes), helper = JSON.parse(originalFiles[1].bytes);
  need(eq(Object.keys(mutation).sort(), ['command', 'endpoint', 'phase', 'project', 'version']) && mutation.version === 1 && mutation.project === PROJECT && mutation.command === 'public-llm-up' && mutation.phase === 'fence-web');
  need(eq(Object.keys(helper).sort(), ['id', 'image', 'purpose']) && helper.purpose === 'backup' && /^[a-f0-9]{64}$/.test(helper.id));
  const profile = readProfile(root), selection = loadPublicLlmSettings(home), priorSelection = readPublicLlmBinding(root);
  need(profile?.version === 2 && profile.cve && priorSelection === null && selection.selection.keyVolume === null, 'CURRENT_BUILD_SCOPE_REJECTED');
  need(eq(names(stage), ['compose.cve.json', ...(initialize ? ['compose.images.json'] : []), 'compose.llm-env.json']));
  const candidateFiles = ['compose.cve.json', 'compose.llm-env.json', ...(initialize ? ['compose.images.json'] : [])].map(n => privateFile(join(stage, n)));
  need(candidateFiles[0].bytes === readBounded(join(state, 'compose.cve.json'), 16384, 0o600));
  need(eq(JSON.parse(candidateFiles[1].bytes), publicLlmEnvironmentOverlay(selection.selection)));
  const stateFiles = ['profile.json', 'scan-jwt', 'compose.images.json', 'compose.cve.json'].map(n => privateFile(join(state, n)));
  const pins = JSON.parse(stateFiles[2].bytes), model = expectedPublicLlmConfig(root, profile.cve, null);
  need(eq(Object.keys(pins), ['services']) && eq(Object.keys(pins.services).sort(), Object.keys(model.services).sort()));
  for (const p of Object.values(pins.services)) need(eq(Object.keys(p), ['image']) && /^sha256:[a-f0-9]{64}$/.test(p.image));
  need(helper.image === pins.services.api.image);
  const env = dockerEnvironment(ambient), endpoint = env.DOCKER_HOST && !env.DOCKER_CONTEXT ? env.DOCKER_HOST : JSON.parse(await run(['context', 'inspect', '--format', '{{json .Endpoints.docker.Host}}'], { root, env, timeout: 10000 }));
  need(typeof endpoint === 'string' && endpoint.startsWith('unix:///') && endpoint === mutation.endpoint, 'CURRENT_BUILD_ENDPOINT_REJECTED');
  env.DOCKER_HOST = endpoint; env.COMPOSE_DISABLE_ENV_FILE = '1'; for (const k of ['DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']) delete env[k];
  const options = { root, env }, d = publicLlmReadOnlyMetadata(run, options, new Set([...Object.values(pins.services).map(v => v.image), ...(initialize ? Object.values(initialize.pins.services).map(v => v.image) : []), ...(initialize?.currentPins ? Object.values(initialize.currentPins.services).map(v => v.image) : [])]), { limit: failedInitializerOnly ? 220 : 180, helperId: initialize?.failedId ?? initialize?.helper.id }), images = {}, missing = [];
  if (initialize) await initialize.inspect(d, { run, options });
  for (const [name, p] of Object.entries(pins.services)) {
    let a; try { a = JSON.parse(await d(['image', 'inspect', p.image])); } catch (e) { if (!(name === 'worker' || initialize && (name === 'api' || name === 'web' && p.image === initialize.originalWebImage)) || e?.category !== 'image') throw e; missing.push(name); continue; }
    need(a.length === 1 && a[0].Id === p.image); validatePublicLlmImage(a[0], name); images[name] = a[0];
  }
  let replacement;
  if (missing.includes('worker')) { const a = JSON.parse(await d(['image', 'inspect', `${PROJECT}-worker:local`])); need(a.length === 1); replacement = a[0]; validatePublicLlmImage(replacement, 'worker'); need(replacement.Id !== pins.services.worker.image); }
  const apiReplacement = initialize && missing.includes('api') ? (initialize.policyApiImage ?? initialize.backupImage) : null;
  const webReplacement = initialize && missing.includes('web') ? initialize.webPolicyImage : null;
  const real = new Map(), jwt = loadSecret(root, true);
  const projectedRun = async args => {
    const raw = await d(args), text = initialize && args[0] === 'container' && args[1] === 'ls' ? initialize.withoutHelper(raw) : raw;
    if (admissionOnly && args[0] === 'network' && args[1] === 'ls') return text.split('\n').filter(line => ![PROJECT + '_llm_internal', PROJECT + '_llm_uplink'].includes(line.split('\t')[0])).join('\n');
        if (args[0] === 'image' && args[1] === 'ls' && text.split('\n').includes(`${PROJECT}-llm-egress:local`)) {
      const a = JSON.parse(await d(['image', 'inspect', `${PROJECT}-llm-egress:local`])); need(a.length === 1); validatePublicLlmImage(a[0], 'llm-egress');
      return text.split('\n').filter(n => n !== `${PROJECT}-llm-egress:local`).join('\n');
    }
    if (args[0] === 'container' && args[1] === 'inspect') {
      const a = JSON.parse(text); need(a.length === 1); real.set(role(a[0]), structuredClone(a[0]));
      if (admissionOnly && role(a[0]) === 'worker') { initialize.validateAdmissionPeer(a[0], 'worker'); return JSON.stringify(a); }
            if (replacement && role(a[0]) === 'worker') { validateRetiredPublicLlmWorker(a[0], pins.services.worker.image, replacement, model, images); a[0].Image = replacement.Id; a[0].Config.Image = replacement.Id; return JSON.stringify(a); }
      if (apiReplacement && role(a[0]) === 'api') { initialize.validateRetiredApi(a[0], pins.services.api.image, model, images, jwt); a[0].Image = apiReplacement.Id; a[0].Config.Image = apiReplacement.Id; return JSON.stringify(a); }
      if (webReplacement && role(a[0]) === 'web') { initialize.validateRetiredWeb(a[0], pins.services.web.image, model, images); a[0].Image = webReplacement.Id; a[0].Config.Image = webReplacement.Id; return JSON.stringify(a); }
    }
    return text;
  };
  // Additional replacement ID is now an explicitly validated own public image.
  const projectionImages = { ...images, ...(replacement ? { worker: replacement } : {}), ...(apiReplacement ? { api: apiReplacement } : {}), ...(webReplacement ? { web: webReplacement } : {}) };
  const inspectRun = async args => args[0] === 'image' && args[1] === 'inspect' && replacement && args[2] === replacement.Id ? JSON.stringify([replacement]) : projectedRun(args);
  const inventory = await inspectPublicLlmNamespace(inspectRun, options, root, profile.cve, null, { secret: jwt, images: projectionImages });
  inventory.containers = inventory.containers.map(c => real.get(role(c)) ?? c);
    if (admissionOnly) { inventory.containers.push(initialize.admitExtra.gateway); inventory.networks.push(...initialize.admitExtra.networks); }
  initialize?.verifyOriginalState?.(pins, inventory);
  need(inventory.containers.length === (admissionOnly ? 7 : 6) && inventory.volumes.length === 2 && inventory.networks.length === (admissionOnly ? 6 : 4));
  for (const c of inventory.containers) {
    const command = [...(c.Config.Entrypoint ?? []), ...c.Config.Cmd]; need(c.Path === command[0] && eq(c.Args, command.slice(1)), 'CURRENT_BUILD_EXECUTABLE_REJECTED');
    if (admissionOnly && ['worker', 'llm-egress'].includes(role(c))) initialize.validateAdmissionPeer(c, role(c));
    else if (role(c) === 'egress') need(c.State.Running && c.State.Status === 'running' && c.RestartCount === 0 && !c.State.OOMKilled && !c.State.Paused && !c.State.Restarting && !c.State.Dead);
    else clean(c);
  }
  need(!(await d(['container', 'ls', '--all', '--no-trunc', '--filter', `id=${helper.id}`, '--format', '{{.ID}}'])).trim(), 'CURRENT_BUILD_OLD_HELPER_PRESENT');
  const configText = await run(publicLlmComposeArguments(root, ['config', '--format', 'json'], { cve: true, directory: stage, pinned: false }), { ...options, env: { ...env, SCAN_JWT_SECRET: CONFIG_SECRET }, timeout: 15000 });
  validatePublicLlmConfig(JSON.parse(configText), root, profile.cve, selection.selection);
  const source = capturePublicLlmSource(root); const sourceResult = await checkSource(root); need(sourceResult.typescript && sourceResult.bundle, 'CURRENT_BUILD_SOURCE_CLOSURE_REJECTED'); source.verify();
  const manifestFile = privateFile(join(auditPath, 'fenced/core/private-manifest.json'), 65536), manifest = JSON.parse(manifestFile.bytes); validateExportManifest(manifest);
  const backups = ['auth', 'ledger'].map(r => byteFile(join(auditPath, 'fenced/core', r + '.sqlite')));
  const sidecars = ['auth', 'ledger'].flatMap(r => ['-wal', '-shm'].map(s => join(auditPath, 'fenced/core', r + '.sqlite' + s))).filter(has).map(p => byteFile(p));
  const coreNames = names(join(auditPath, 'fenced/core'));
  need(coreNames.every(n => /^(?:auth|ledger)\.sqlite(?:-wal|-shm)?$/.test(n) || n === 'private-manifest.json'));
  for (let i = 0; i < backups.length; i++) need(backups[i].sha256 === manifest.receipt[['auth', 'ledger'][i]].sha256, 'CURRENT_BUILD_BACKUP_BYTES_REJECTED');
  const temp = fs.mkdtempSync(join(tmpdir(), 'public-llm-held-backup-')), copies = {};
  let baseline;
  try {
    for (const r of ['auth', 'ledger']) copies[r] = copyStableSqlite(fs, crypto, join(auditPath, 'fenced/core', r + '.sqlite'), join(temp, r));
    const paths = Object.fromEntries(Object.entries(copies).map(([r, c]) => [r, c.path]));
    const restored = await recoverySqlite(Database, fs, crypto, paths, null);
    for (const r of ['auth', 'ledger']) need(restored[r].logicalSha256 === manifest.receipt[r].logicalSha256, 'CURRENT_BUILD_BACKUP_RESTORE_REJECTED');
    baseline = { core: Object.fromEntries(Object.entries(paths).map(([r, p]) => [r, { logicalSha256: llmFingerprint(Database, fs, crypto, p, r) }])), llm: null, empty: false };
    for (const c of Object.values(copies)) c.verify();
  } finally { for (const c of Object.values(copies)) c.cleanup(); fs.rmSync(temp, { recursive: true, force: true }); }
  if (initialize) need(eq(initialize.baseline.core, baseline.core) && initialize.baseline.llm === null, 'CURRENT_INITIALIZE_BACKUPS_DIFFER');
  const proofs = [...execution.directoryProofs, ...originalFiles, ...candidateFiles, manifestFile, ...backups, ...sidecars, ...programs, ...(initialize?.files ?? [])], verify = () => { execution.verify(); initialize?.verify(); need(eq(names(join(auditPath, 'fenced/core')), coreNames)); for (const v of directoryChecks) v(); for (const f of proofs) f.verify(); source.verify(); selection.verify(); };
  verify(); for (const f of stateFiles) f.verify();
  if (admissionOnly) { await initialize.verifyReadiness(run, options); verify(); }
  if (apiOnly) { need(initialize.apiBaseline?.llm && initialize.apiBaseline.empty === true); baseline = initialize.apiBaseline; }
  const reviewEvidence = { version: 1, audit, endpoint, ...(initialize ? { continuation: apiOnly ? 'exact-post-admit-timeout-pre-api' : admissionOnly ? 'exact-post-init-pre-api-admission' : failedInitializerOnly ? 'exact-init-exit-current-source' : postRetirementOnly ? 'post-retirement-pre-pins-current-source' : 'created-initializer-only-current-source', staleCandidate: initialize.evidence } : {}), source: source.manifest, executionClosure: execution.manifest, settings: selection.selection, baseline,
    // JWT metadata only, never its value or a digest of it.
    state: stateFiles.map(f => ({ path: f.path.slice(root.length + 1), identity: f.identity, ...(f.path.endsWith('/scan-jwt') ? {} : { content: f.bytes }) })),
    original: proofs.map(f => ({ path: f.path.slice(root.length + 1), identity: f.identity, ...(f.sha256 ? { sha256: f.sha256 } : { content: f.bytes }) })),
    peers: inventory.containers.map(publicLlmSecretlessControl), volumes: inventory.volumes, networks: inventory.networks,
    priorImageMetadata: Object.fromEntries(Object.entries(images).map(([n, im]) => [n, { Id: im.Id, Os: im.Os, Config: im.Config }])),
    retireOnlyWorker: replacement ? { originalId: pins.services.worker.image, replacement: { Id: replacement.Id, Os: replacement.Os, Config: replacement.Config } } : null,
    ...(initialize ? { backupHelperBasis: failedInitializerOnly ? 'validated-current-candidate-api' : 'validated-stale-candidate-api', backupImageId: initialize.backupImage.Id,
          ...(failedInitializerOnly ? { ...(admissionOnly ? { admissionOnly: true, ...(apiOnly ? { apiOnly: true, previousFailure: initialize.apiFailure, baselineBasis: 'admit-current-fenced-four-stores', authorizedHostChanges: ['scripts/public-llm-stand.mjs', 'scripts/public-llm-build-continuation.mjs', 'scripts/public-llm-initialize-continuation.mjs'] } : {}) } : { failedInitializer: initialize.failed.evidence }), currentPins: initialize.currentPins, currentCandidateImageMetadata: Object.fromEntries(Object.entries(initialize.candidateImages).map(([role, im]) => [role, { Id: im.Id, Os: im.Os, Config: { ...im.Config, Env: undefined } }])) } : {}),
      retireOnlyApi: apiReplacement ? { originalId: pins.services.api.image, validationImageId: apiReplacement.Id, executeOriginal: false } : null,
      retireOnlyWeb: webReplacement ? { originalId: pins.services.web.image, validationImageId: webReplacement.Id, metadataUnavailable: true, executeOriginal: false } : null } : {}) };
  const review = digest(reviewEvidence);
  return { root, auditPath, auditName: audit, nonce: audit.slice(7), stage, lockPath, endpoint, options, profile, selection: selection.selection,
    pins, images, replacement, apiReplacement, webReplacement, admissionOnly, apiOnly, backupImage: initialize?.backupImage, inventory, baseline, review, reviewEvidence, originalFiles, candidateFiles, stateFiles, proofs, verify, initialize, verifyExecution: execution.verify, verifyDirectories: () => directoryChecks.forEach(v => v()),
    summary: { audit, review, sourceClosure: sourceResult, executionModules: programs.length, originalSourceBaseline: 'not-persisted-requires-explicit-current-source-review',
      missingPriorMetadata: missing.sort(), workerRetirementOnly: Boolean(replacement), fencedBackupVerified: true, services: admissionOnly ? 7 : 6, webApiWorkerStopped: !admissionOnly, ...(admissionOnly ? { apiWebStopped: true, existingWorkerReady: true, initializedEmptySnapshotRequired: true } : {}), lifecycle: false,
      ...(initialize ? { command: apiOnly ? 'check-current-api' : admissionOnly ? 'check-current-admit' : failedInitializerOnly ? 'check-current-init-exit' : postRetirementOnly ? 'check-current-rebuild' : 'check-current-initialize', ...(postRetirementOnly ? { retiredInitializerAbsent: true, initializeBackupVerified: true } : {}), apiRetirementOnly: Boolean(apiReplacement), webRetirementOnly: Boolean(webReplacement), backupHelperBasis: failedInitializerOnly ? 'validated-current-candidate-api' : 'validated-stale-candidate-api', ...(failedInitializerOnly ? { rebuildBackupVerified: true, candidateImageSourceMatches: true, ...(admissionOnly ? { initExitBackupVerified: true, requiresInitialization: false, ...(apiOnly ? { admitBackupVerified: true, exactPriorFailure: 'ready-worker-guard-946', baselineBasis: 'admit-current-fenced-four-stores' } : {}) } : { failedInitializer: initialize.failed.id }) } : {}), continuedBackupVerified: true, staleInitializer: initialize.helper.id, staleCandidateIsCurrentSource: false, requiresCurrentBuild: !failedInitializerOnly } : {}) } };
}
