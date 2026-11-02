// Current-only deployment archive reader. No Docker, database open or writes.
import * as fs from 'node:fs';
import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';
import { isDeepStrictEqual as equal } from 'node:util';
import { PROJECT, STATE } from './public-image-stand.mjs';
import { directory, readBounded } from './setup-local-cve.mjs';
import { validateOpenAiBuildDeployment, assertNoOpenAiDockerSecret, PUBLIC_IMAGE_OPERATIONS } from './public-llm-source-build.mjs';

export const DEPLOYMENT_ARCHIVE = 'llm-deployments-archive';
export const DEPLOYMENT_ARCHIVE_OPERATIONS = 'llm-deployment-archive-operations';
// Resource budget v2: the combined catalog may use both existing location
// capacities. This does not change receipt formats or recovery authority;
// the policy bytes are bound by the existing execution source closure.
export const DEPLOYMENT_CAPACITY_POLICY = Object.freeze({
  version: 2, active: 32, archived: 16, total: 48, archiveBatch: 8, retainedReferences: 128,
});
export const DEPLOYMENT_ACTIVE_LIMIT = DEPLOYMENT_CAPACITY_POLICY.active;
export const DEPLOYMENT_ARCHIVE_BATCH = DEPLOYMENT_CAPACITY_POLICY.archiveBatch;
export const DEPLOYMENT_ARCHIVE_LIMIT = DEPLOYMENT_CAPACITY_POLICY.archived;
export const DEPLOYMENT_TOTAL_LIMIT = DEPLOYMENT_CAPACITY_POLICY.total;
export const DEPLOYMENT_RETAINED_REFERENCE_LIMIT = DEPLOYMENT_CAPACITY_POLICY.retainedReferences;
export const LEGACY_GATEWAY_STOP_ACK = '--ack-exact-stateless-gateway-stop-03abeabc';
export const LEGACY_GATEWAY_STOP_IDS = Object.freeze({
  egress: Object.freeze(['6f0c9cf6259938d35e13bfb78ad515f424d4ce3e7420a92c0e0d7b8cfa25ac55', 'sha256:ce9ff52cb3aa1c5f6011bec9c239c6446a1c385f30256a9cc85fc00f436c889f']),
  'llm-egress': Object.freeze(['b4ef3b7a86349686de8425d91e9fbc64afa2ce1e16ae7f7bfc0ad48d0450500a', 'sha256:bc498e780d996ab556d6729ccbf67884699d1435af3d0b46ca657502c2725ced']),
});
export const deploymentName = value => typeof value === 'string' && /^deploy-[a-f0-9]{32}$/.test(value);
export const archiveHash = value => createHash('sha256').update(typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value)).digest('hex');
export const archiveSafe = ok => { if (!ok) throw Error('PUBLIC deployment archive refused/HOLD; details withheld.'); };
export const archiveExists = path => fs.lstatSync(path, { throwIfNoEntry: false }) !== undefined;
const safe = archiveSafe;
// Explicit denylist is independent of layout: never relocate frozen identities.
export const FROZEN_DEPLOYMENTS = Object.freeze([
  'deploy-8d83a8806715c2f0fa575efedee1b0af', 'deploy-830b7aa07d1c9a728de1a957829e43c2',
  'deploy-2c9ed08b8269264b09bf14eb6189a649', 'deploy-1cb54172f8cd83708f64067371069fa5',
  'deploy-76eb7a61e0da2e108210bc773b964d35', 'deploy-172233a7b4b082b6b721a0e476bcd2d4',
  'deploy-ae36659bf3268f7e6cb93d8d070ac77d',
]);
export function archiveDirectory(path) {
  directory(path, 0o700);
  const stat = fs.lstatSync(path), names = fs.readdirSync(path).sort();
  const verify = () => {
    directory(path, 0o700); const next = fs.lstatSync(path);
    safe(next.dev === stat.dev && next.ino === stat.ino && equal(fs.readdirSync(path).sort(), names));
  };
  return { path, names, dev: stat.dev, ino: stat.ino, verify };
}
export function archiveFile(path, cap = 16 * 1024 ** 2) {
  const stamp = s => [s.dev, s.ino, s.uid, s.mode, s.nlink, s.size, s.mtimeMs, s.ctimeMs];
  const before = stamp(fs.lstatSync(path)), bytes = readBounded(path, cap, 0o600);
  safe(equal(before, stamp(fs.lstatSync(path))));
  return { path, bytes, digest: archiveHash(bytes), verify() {
    safe(equal(before, stamp(fs.lstatSync(path))) && readBounded(path, cap, 0o600) === bytes);
  } };
}
export function completedDeployment(path) {
  const proof = archiveFile(join(path, 'complete.json'), 4096);
  safe(equal(JSON.parse(proof.bytes), { version: 1, project: PROJECT, preserved: true }));
  return proof;
}
export function validateLegacyGatewayStopArchive(value, build) {
  safe(equal(Object.keys(value).sort(), ['acknowledgement','stops','version']) && value.version === 1 && value.acknowledgement === LEGACY_GATEWAY_STOP_ACK);
  safe(build.version === 2 && build.deployment.prior.version === 6 && !build.deployment.prior.operations && build.deployment.next.operations === PUBLIC_IMAGE_OPERATIONS);
  safe(Array.isArray(value.stops) && value.stops.length > 0 && value.stops.length <= 2 && new Set(value.stops.map(v => v.role)).size === value.stops.length);
  for (const proof of value.stops) {
    safe(equal(Object.keys(proof).sort(), ['acknowledgement','events','id','image','role','stateless','stoppedEpoch','submittedMs','version','writersClean']));
    const target = LEGACY_GATEWAY_STOP_IDS[proof.role], peer = build.peers.find(p => p.name === proof.role);
    safe(target && peer && proof.id === target[0] && proof.image === target[1] && peer.id === proof.id && peer.image === proof.image && equal(peer.epoch, proof.stoppedEpoch));
    safe(proof.version === 1 && proof.acknowledgement === LEGACY_GATEWAY_STOP_ACK && proof.stateless === true && proof.writersClean === true && Number.isSafeInteger(proof.submittedMs));
    const e = proof.stoppedEpoch;
    safe(Array.isArray(e) && e.length === 9 && e[0] === proof.id && Number.isFinite(Date.parse(e[1])) && Number.isFinite(Date.parse(e[2])) && equal(e.slice(3), [0,0,false,'exited',137,'']));
    safe(Array.isArray(proof.events) && proof.events.length === 3 && proof.events.every(v => equal(Object.keys(v).sort(), ['action','exit','id','signal','time']) && v.id === proof.id && Number.isSafeInteger(v.time)));
    const [term, kill, die] = proof.events, start = Math.floor(proof.submittedMs / 1000);
    safe(term.action === 'kill' && term.signal === '15' && term.exit === null && term.time >= start && term.time <= start + 5);
    safe(kill.action === 'kill' && kill.signal === '9' && kill.exit === null && kill.time - term.time >= 29 && kill.time - term.time <= 40);
    safe(die.action === 'die' && die.signal === null && die.exit === '137' && die.time >= kill.time && die.time <= kill.time + 5 && Math.abs(Date.parse(e[2]) / 1000 - die.time) < 2);
  }
}
export const PUBLIC_STOP_DIAGNOSTIC_STEPS = Object.freeze([
  'VERIFY_PEERS','VERIFY_CONSUMERS','WRITERS_CLEAN','CENSUS','SUBMISSION_RECORD','SUBMISSION_FENCE',
  'STOP_CALL','STOP_FENCE','STOP_TIMEOUT','STOP_ENGINE','INSPECT_CALL','INSPECT_FENCE','INSPECT_TIMEOUT','INSPECT_ENGINE',
  'INSPECT_PARSE','INSPECT_CARDINALITY','INSPECT_VALIDATOR','INSPECT_COMMAND','CONTROL_EQUAL',
  'EVENTS_ARGUMENTS','EVENTS_CALL','EVENTS_FENCE','EVENTS_TIMEOUT','EVENTS_ENGINE','EVENTS_PARSE',
  'PROOF_VALIDATE','PROOF_RECORD','PROOF_FENCE','CLEAN_STOPPED','PEER_COMMIT',
]);
export function validatePublicStopDiagnostic(row) {
  safe(row && equal(Object.keys(row).sort(), ['detail','elapsedMs','role','sequence','state','step','version','wallMs']));
  safe(row.version === 1 && ['web','api','worker','egress','llm-egress'].includes(row.role) && PUBLIC_STOP_DIAGNOSTIC_STEPS.includes(row.step));
  safe(['BEGIN','PASS','FAIL'].includes(row.state) && Number.isSafeInteger(row.sequence) && row.sequence >= 1 && row.sequence <= 256);
  const number = n => n === null || Number.isSafeInteger(n) && Math.abs(n) <= 8640000000000000;
  safe(number(row.wallMs) && number(row.elapsedMs) && (row.elapsedMs === null || row.elapsedMs >= 0));
  safe(row.detail && typeof row.detail === 'object' && !Array.isArray(row.detail));
  const numbers = ['stdoutBytes','stderrBytes','exitCode','restartCount','startedMs','finishedMs','sinceMs','untilMs','untilAheadMs',
    'requestedTimeoutMs','effectiveTimeoutMs','remainingMs','eventCount','firstEventMs','lastEventMs'];
  const booleans = ['stdoutMatchesId','running','oom','eventIdsMatch'];
  for (const [key,value] of Object.entries(row.detail)) {
    if (numbers.includes(key)) {
      safe(number(value));
      if (value !== null && ['stdoutBytes','stderrBytes'].includes(key)) safe(value >= 0 && value <= 64 * 1024 ** 2);
      if (value !== null && ['eventCount','restartCount'].includes(key)) safe(value >= 0 && value <= 16 * 1024 ** 2);
      if (value !== null && key === 'exitCode') safe(value >= 0 && value <= 255);
      if (value !== null && ['requestedTimeoutMs','effectiveTimeoutMs'].includes(key)) safe(value >= 1 && value <= 75000);
    }
    else if (booleans.includes(key)) safe(typeof value === 'boolean');
    else if (key === 'cause') safe(['OUTPUT_LIMIT','TIMEOUT','SPAWN','EXIT_NONZERO','DOCKER_FAILURE','JSON','FILESYSTEM','UNKNOWN','JOURNAL'].includes(value));
    else if (key === 'signal') safe(value === null || ['SIGKILL','SIGTERM','SIGABRT','SIGPIPE','SIGSEGV','SIGINT'].includes(value));
    else safe(false);
  }
  safe(Buffer.byteLength(JSON.stringify(row)) <= 4096);
}
function stopDiagnosticHistory(path) {
  const parent = archiveDirectory(path), proofs = [parent];
  safe(parent.names.length > 0 && parent.names.length <= 5 && parent.names.every(n => ['web','api','worker','egress','llm-egress'].includes(n)));
  for (const role of parent.names) {
    const dir = archiveDirectory(join(path, role)); proofs.push(dir);
    safe(dir.names.length > 0 && dir.names.length <= 256);
    const rows = dir.names.map((name,index) => {
      safe(name === String(index + 1).padStart(4,'0') + '.json');
      const file = archiveFile(join(dir.path,name),4096), row = JSON.parse(file.bytes); proofs.push(file);
      validatePublicStopDiagnostic(row); safe(row.sequence === index + 1 && row.role === role && row.state !== 'FAIL'); return row;
    });
    const stack = [];
    for (const row of rows) {
      if (row.state === 'BEGIN') stack.push(row.step);
      else safe(stack.pop() === row.step);
    }
    safe(stack.length === 0 && rows[0].step === 'VERIFY_PEERS' && rows[0].state === 'BEGIN');
    safe(rows.at(-1).state === 'PASS' && ['PEER_COMMIT','CLEAN_STOPPED'].includes(rows.at(-1).step));
  }
  return { verify() { proofs.forEach(p => p.verify()); } };
}
export function ordinaryDeployment(path, name) {
  safe(deploymentName(name) && !FROZEN_DEPLOYMENTS.includes(name));
  const dir = archiveDirectory(path), required = ['after-api', 'before-api', 'build-checkpoint.json', 'complete.json', 'fenced'];
  const optional = ['history-schema-preflight.json', 'image-retention-intent.json', 'image-retention.json', 'auth-schema-migration.json', 'legacy-gateway-stops.json', 'stop-diagnostics'];
  safe(required.every(n => dir.names.includes(n)) && dir.names.every(n => required.includes(n) || optional.includes(n)));
  safe(dir.names.includes('image-retention-intent.json') === dir.names.includes('image-retention.json'));
  const complete = completedDeployment(path), checkpoint = archiveFile(join(path, 'build-checkpoint.json'));
  const build = JSON.parse(checkpoint.bytes);
  safe(equal(Object.keys(build).sort(), ['baseline', ...(build.version === 2 ? ['deployment'] : []), 'imageMetadata', 'jwtIdentity', 'peers', 'phase', 'pins', 'publicProfile', 'retirementPolicy', 'source', 'sourceBasis', 'version']) &&
    [1, 2].includes(build.version) && build.phase === 'validated-before-build' && build.sourceBasis === 'validated-before-build' && build.retirementPolicy === null);
  if (build.version === 2) {
    validateOpenAiBuildDeployment(build.deployment);
    safe(build.baseline?.historyVersion === 4 && build.baseline.llm !== null && typeof build.imageMetadata === 'object');
    for (const image of Object.values(build.imageMetadata)) assertNoOpenAiDockerSecret(image?.Config);
  }
  const proofs = [complete, checkpoint];
  if (dir.names.includes('stop-diagnostics')) proofs.push(stopDiagnosticHistory(join(path, 'stop-diagnostics')));
  if (dir.names.includes('legacy-gateway-stops.json')) {
    const p = archiveFile(join(path, 'legacy-gateway-stops.json'), 16384);
    validateLegacyGatewayStopArchive(JSON.parse(p.bytes), build); proofs.push(p);
  }
  if (dir.names.includes('history-schema-preflight.json')) {
    const p = archiveFile(join(path, 'history-schema-preflight.json'), 4096), v = JSON.parse(p.bytes);
    safe(equal(Object.keys(v).sort(), ['historyVersion', 'migrateSummary', 'version']) && v.version === 1 &&
      [3, 4].includes(v.historyVersion) && v.migrateSummary === false && build.baseline?.historyVersion === v.historyVersion);
    proofs.push(p);
  }
  if (dir.names.includes('auth-schema-migration.json')) {
    const p = archiveFile(join(path, 'auth-schema-migration.json'), 4096), v = JSON.parse(p.bytes);
    safe(build.version === 2 && build.deployment.next.version === 6 &&
      equal(Object.keys(v).sort(), ['before', 'constructorPasses', 'expected', 'migration', 'version']) &&
      v.version === 1 && v.migration === 'auth-a2-to-a3' && v.constructorPasses === 2 &&
      typeof v.before === 'string' && /^[a-f0-9]{64}$/.test(v.before) &&
      typeof v.expected === 'string' && /^[a-f0-9]{64}$/.test(v.expected) && v.expected !== v.before &&
      v.before === build.baseline?.core?.auth?.logicalSha256);
    proofs.push(p);
  }
  return { checkpoint, build, verify() { dir.verify(); proofs.forEach(p => p.verify()); } };
}

// Catalog membership is a durable receipt, not a generic alternate-path lookup.
// An incomplete move has no completed operation and is rejected even if its
// .operation.lock was removed externally. No archived audit can be active too.
export function captureDeploymentCatalog(root) {
  safe(resolve(root) === root && fs.realpathSync(root) === root);
  const state = join(root, STATE); directory(state, 0o700);
  const stateId = fs.lstatSync(state), guards = [], absent = [];
  const readDirectory = (path, pattern, cap) => {
    if (!archiveExists(path)) { absent.push(path); return []; }
    const d = archiveDirectory(path); safe(d.dev === stateId.dev && d.names.length <= cap && d.names.every(n => pattern.test(n))); guards.push(d); return d.names;
  };
  const activePath = join(state, 'llm-deployments'), archivePath = join(state, DEPLOYMENT_ARCHIVE), operationsPath = join(state, DEPLOYMENT_ARCHIVE_OPERATIONS);
  const active = readDirectory(activePath, /^deploy-[a-f0-9]{32}$/, DEPLOYMENT_ACTIVE_LIMIT);
  const archived = readDirectory(archivePath, /^deploy-[a-f0-9]{32}$/, DEPLOYMENT_ARCHIVE_LIMIT);
  const operations = readDirectory(operationsPath, /^[a-f0-9]{64}$/, DEPLOYMENT_ARCHIVE_LIMIT);
  safe(active.length + archived.length <= DEPLOYMENT_TOTAL_LIMIT && !active.some(n => archived.includes(n)));
  const authorized = [], records = [];
  for (const review of operations) {
    const dir = archiveDirectory(join(operationsPath, review)); safe(equal(dir.names, ['complete.json', 'intent.json'])); guards.push(dir);
    const intent = archiveFile(join(dir.path, 'intent.json'), 4 * 1024 ** 2), complete = archiveFile(join(dir.path, 'complete.json'), 4096);
    const v = JSON.parse(intent.bytes), c = JSON.parse(complete.bytes);
    safe(equal(Object.keys(v).sort(), ['command', 'plan', 'project', 'review', 'version']) && v.version === 1 && v.project === PROJECT &&
      v.command === 'archive-completed-deployments' && v.review === review && archiveHash(v.plan) === review && v.plan.root === root &&
      equal(Object.keys(v.plan).sort(), ['catalog', 'cve', 'root', 'selected', 'source', 'trees', 'version']) && v.plan.version === 1 &&
      Array.isArray(v.plan.selected) && v.plan.selected.length > 0 && v.plan.selected.length <= DEPLOYMENT_ARCHIVE_BATCH &&
      v.plan.selected.every(deploymentName) && equal(v.plan.selected, [...new Set(v.plan.selected)].sort()));
    safe(equal(c, { version: 1, project: PROJECT, review, archived: v.plan.selected, preserved: true }) &&
      Array.isArray(v.plan.trees) && equal(v.plan.trees.map(t => t.name), v.plan.selected));
    for (const name of v.plan.selected) {
      safe(archived.includes(name) && !authorized.includes(name)); authorized.push(name);
      const ordinary = ordinaryDeployment(join(archivePath, name), name); guards.push(ordinary);
      const tree = v.plan.trees?.find(t => t.name === name);
      safe(tree && Array.isArray(tree.files) && Array.isArray(tree.directories));
      const rootTree = tree.directories.find(d => d.path === '');
      const rootDir = archiveDirectory(join(archivePath, name)); guards.push(rootDir);
      safe(rootTree && rootTree.dev === rootDir.dev && rootTree.ino === rootDir.ino && equal(rootTree.names, rootDir.names));
      for (const file of rootDir.names.filter(n => n.endsWith('.json'))) {
        const proof = archiveFile(join(rootDir.path, file));
        safe(tree.files.filter(f => f.path === file && f.digest === proof.digest).length === 1); guards.push(proof);
      }
    }
    guards.push(intent, complete); records.push({ review, intent: intent.digest, complete: complete.digest });
  }
  safe(equal(authorized.sort(), archived));
  const entries = [...active.map(name => ({ name, path: join(activePath, name), archived: false })),
    ...archived.map(name => ({ name, path: join(archivePath, name), archived: true }))];
  for (const entry of entries) { directory(entry.path, 0o700); const s = fs.lstatSync(entry.path); safe(s.dev === stateId.dev); }
  const verify = () => {
    directory(state, 0o700); const s = fs.lstatSync(state); safe(s.dev === stateId.dev && s.ino === stateId.ino);
    absent.forEach(path => safe(!archiveExists(path))); guards.forEach(g => g.verify());
  };
  verify(); return { active, archived, entries, records, verify };
}
