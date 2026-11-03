// Docker/state boundary for the new pipeline. Importing this file is inert.
// No historical lifecycle, incident adoption, lock deletion or DB rollback.
import * as fs from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { homedir } from 'node:os';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual as equal } from 'node:util';
import { PROJECT, STATE, LABEL, IMAGE_LABEL, ORIGIN, readProfile, acquireLock,
  runIsolatedDocker, isolatedDockerDiagnostic, CONFIG_SECRET } from './public-image-stand.mjs';
import { readPublicLlmBinding, loadPublicLlmSettings, expectedPublicLlmConfig,
  validatePublicLlmContainer, validatePublicLlmImage, validatePublicLlmTransition,
  capturePublicLlmSource, qualifyPublicAuthSnapshot, capturePublicLlmRetentions,
    publicLlmEnvironmentOverlay, validatePublicLlmConfig,
    publicAuthSchema, PUBLIC_LLM_GATEWAY_PROBE,
    reservationPublicLlmHelperArguments, validateReservationPublicLlmHelper, PUBLIC_LLM_RESERVATION_HEADER_PROGRAM,
    reservationLlmFingerprint, verifyHistoryReservationMigration } from './public-llm-stand.mjs';
import { captureDeploymentCatalog, DEPLOYMENT_TOTAL_LIMIT, DEPLOYMENT_RETAINED_REFERENCE_LIMIT } from './public-llm-deployment-catalog.mjs';
import { assertNoOpenAiDockerSecret, checkPublicLlmSourceBuild, validateOpenAiVolume, selectOpenAiOperations } from './public-llm-source-build.mjs';
import { writeExclusive, syncDirectory } from './setup-local-cve.mjs';
import { PUBLIC_DRAIN_PROBE, PUBLIC_READY_PROBE } from './refresh-public-cve.mjs';
import { createAdapterSnapshots, qualifyAdapterStoreCopies } from './deploy-adapter-stores.mjs';
import { requireDeploySupervisor, inspectDeploySupervisor } from './deploy-supervisor.mjs';
import { deploymentAuthority, deploymentFileIdentity, createEngineJournal, readEngineJournal } from './deploy-authority.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const ROLES = Object.freeze(['api','worker','web','egress','llm-egress','openai-egress']);
const AUTH_SOURCE = Object.freeze(['src/auth/auth.store.ts','src/auth/auth.controller.ts']);
const RECORDS = 'deploy-adapter-v1';
const diagnostics = new WeakMap(), authQualifications = new WeakSet(), historyQualifications = new WeakSet();
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const role = c => c.Config?.Labels?.['com.docker.compose.service'];
const exists = path => fs.lstatSync(path, { throwIfNoEntry: false }) !== undefined;
const id = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const imageId = value => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value);
const safeCode = code => typeof code === 'string' && /^[A-Z][A-Z0-9_]{1,79}$/.test(code);
const plain = value => value && Object.getPrototypeOf(value) === Object.prototype;
function refuse(code) {
  if (!safeCode(code)) code = 'ADAPTER_REFUSED';
  const error = new Error(code); diagnostics.set(error, Object.freeze({ code })); throw error;
}
function need(ok, code) { if (!ok) refuse(code); }
function safeError(code, error) {
  if (diagnostics.has(error)) return error;
  const docker = isolatedDockerDiagnostic(error), failure = new Error(code);
  diagnostics.set(failure, Object.freeze({ code, ...(docker ? {
    cause: docker.cause, exitCode: docker.exitCode, signal: docker.signal,
    stdoutBytes: docker.stdoutBytes, stderrBytes: docker.stderrBytes,
  } : {}) }));
  return failure;
}
export function deployAdapterDiagnostic(error) { return diagnostics.get(error) ?? Object.freeze({ code: 'ADAPTER_REFUSED' }); }
export const DEPLOY_ADAPTER_CAPABILITIES = Object.freeze({ version: 2, status: true, prepare: true, buildCandidate: true,
  singleLease: true, webCompatibility: true, applyWeb: true, applyApp: true, recover: false,
    recoverHistoryV5Prestart: true, recoveryCheckpointVersion: 3,
  liveQualified: false, noAutomaticDatabaseRollback: true });

export function deploymentTargets(mode, services) {
  need(['web','app'].includes(mode) && Array.isArray(services) && services.length > 0 && services.length <= ROLES.length &&
    new Set(services).size === services.length && services.every(n => ROLES.includes(n)), 'TARGETS_INVALID');
  need(mode !== 'web' || equal(services, ['web']), 'WEB_ONLY_TARGET_REQUIRED');
  need(mode !== 'app' || services.includes('api'), 'APP_API_REQUIRED');
  return Object.freeze([...services].sort());
}
function protectedDirectory(path) {
  const s = fs.lstatSync(path);
  need(s.isDirectory() && !s.isSymbolicLink() && s.uid === process.getuid() && (s.mode & 0o7777) === 0o700, 'STATE_DIRECTORY_UNSAFE');
  return () => { const next = fs.lstatSync(path); need(next.isDirectory() && !next.isSymbolicLink() && next.dev === s.dev && next.ino === s.ino && next.uid === s.uid && next.mode === s.mode, 'DIRECTORY_CHANGED'); };
}
function captureFile(path, { privateMode = true, limit = 16384 } = {}) {
  const stamp = s => [s.dev,s.ino,s.mode,s.uid,s.nlink,s.size,s.mtimeMs,s.ctimeMs];
  const before = fs.lstatSync(path);
  need(before.isFile() && !before.isSymbolicLink() && before.nlink === 1 && before.uid === process.getuid() && before.size <= limit &&
    (!privateMode || (before.mode & 0o7777) === 0o600), 'FILE_UNSAFE');
  const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  let bytes;
  try { need(equal(stamp(before),stamp(fs.fstatSync(fd))), 'FILE_CHANGED'); bytes = fs.readFileSync(fd); }
  finally { fs.closeSync(fd); }
  const verify = () => {
    const s = fs.lstatSync(path); need(equal(stamp(s),stamp(before)), 'FILE_CHANGED');
    const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    try { need(equal(stamp(fs.fstatSync(fd)),stamp(before)) && fs.readFileSync(fd).equals(bytes), 'FILE_CHANGED'); }
    finally { fs.closeSync(fd); }
  };
  verify(); return { bytes, verify };
}
function evidenceIndex(directory) {
  const entries=[];let total=0;
  const walk=(dir,prefix='',depth=0)=>{need(depth<=5,'EVIDENCE_DEPTH');protectedDirectory(dir);
    for(const name of fs.readdirSync(dir).sort()){
      need(/^[a-zA-Z0-9_.-]{1,100}$/.test(name),'EVIDENCE_NAME');
      if(!prefix&&['complete.json','operation.lock'].includes(name))continue;
      const path=join(dir,name),relative=prefix+name,s=fs.lstatSync(path);
      need(!s.isSymbolicLink()&&s.uid===process.getuid(),'EVIDENCE_OWNER');
      if(s.isDirectory()){entries.push({path:relative,directory:true});walk(path,relative+'/',depth+1);continue;}
      need(s.isFile()&&s.nlink===1&&(s.mode&0o7777)===0o600&&s.size<=256*1024**2,'EVIDENCE_FILE');
      total+=s.size;need(total<=4*1024**3&&entries.length<256,'EVIDENCE_CAPACITY');
      const fd=fs.openSync(path,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW),h=createHash('sha256'),b=Buffer.alloc(65536);
      try{let n;while((n=fs.readSync(fd,b,0,b.length,null)))h.update(b.subarray(0,n));}finally{fs.closeSync(fd);}
      const after=fs.lstatSync(path);need(equal([s.dev,s.ino,s.size,s.mtimeMs,s.ctimeMs],[after.dev,after.ino,after.size,after.mtimeMs,after.ctimeMs]),'EVIDENCE_CHANGED');
      entries.push({path:relative,bytes:s.size,sha256:h.digest('hex')});
    }};walk(directory);return entries;
}
function captureBuildHistory(root, own = null) {
  const parent=join(root,STATE,RECORDS),present=exists(parent),names=present?fs.readdirSync(parent).filter(n=>n!==own).sort():[];
  need(names.length<DEPLOYMENT_TOTAL_LIMIT&&names.every(n=>/^[a-f0-9]{32}$/.test(n)),'ADAPTER_HISTORY_CAPACITY_OR_NAMES');
  const guards=[],references=[];
  if(present)guards.push(protectedDirectory(parent));
  for(const nonce of names){
    const dir=join(parent,nonce);guards.push(protectedDirectory(dir));
    const proof=captureFile(join(dir,'complete.json'),{limit:262144}),r=JSON.parse(proof.bytes);guards.push(proof.verify);
    need(r.version===2&&r.nonce===nonce&&r.project===PROJECT&&['published','old-restored','pre-mutation-aborted'].includes(r.outcome)&&Array.isArray(r.references)&&Array.isArray(r.evidence),'ADAPTER_HISTORY_INCOMPLETE');
    need(equal(evidenceIndex(dir),r.evidence),'ADAPTER_HISTORY_EVIDENCE_CHANGED');
    const owner=captureFile(join(dir,'operation.lock/deploy-adapter-owner.json'));
    need(equal(JSON.parse(owner.bytes),{version:2,nonce,kind:'preserving-deployment'}),'ADAPTER_HISTORY_OWNER_MISMATCH');guards.push(owner.verify);
    need(equal(fs.readdirSync(join(dir,'operation.lock')),['deploy-adapter-owner.json']),'ADAPTER_HISTORY_LOCK_ARCHIVE_INVALID');
    for(const row of r.references){need(ROLES.includes(row.name)&&imageId(row.image)&&[ `dip-deploy-${row.name}:old-${nonce}`,`dip-deploy-${row.name}:candidate-${nonce}`].includes(row.tag),'ADAPTER_HISTORY_REFERENCE_INVALID');references.push(row);}
    // Capture metadata after full byte validation; retained history is never changed by this attempt.
    const rootEntries=fs.readdirSync(dir).sort();guards.push(()=>need(equal(fs.readdirSync(dir).sort(),rootEntries),'ADAPTER_HISTORY_CHANGED'));
        const stamps=r.evidence.map(e=>{const path=join(dir,e.path),s=fs.lstatSync(path);return {path,stamp:[s.dev,s.ino,s.mode,s.nlink,s.size,s.mtimeMs,s.ctimeMs]};});
    guards.push(()=>{for(const {path,stamp} of stamps){const s=fs.lstatSync(path);need(equal(stamp,[s.dev,s.ino,s.mode,s.nlink,s.size,s.mtimeMs,s.ctimeMs]),'ADAPTER_HISTORY_CHANGED');}});
  }
  need(references.length<=DEPLOYMENT_RETAINED_REFERENCE_LIMIT&&new Set(references.map(r=>r.tag)).size===references.length,'IMAGE_REFERENCE_CAPACITY');
  const verify=()=>{guards.forEach(g=>g());need(equal(exists(parent)?fs.readdirSync(parent).filter(n=>n!==own).sort():[],names),'ADAPTER_HISTORY_CHANGED');};
  verify();return {references,verify,count:names.length};
}
function loadConfiguration(root, home, desired, upgradeOperations = false) {
  need(typeof upgradeOperations === 'boolean' && (!upgradeOperations || desired), 'OPERATIONS_FLAG_INVALID');
  const state = join(root, STATE), verifyDirectory = protectedDirectory(state);
  need(!fs.readdirSync(state).some(n=>n.startsWith('.adapter-pending-')||n.startsWith('.llm-pending-')),'CONFIG_PUBLICATION_PENDING');
  const files = ['profile.json','llm-profile.json','compose.images.json','compose.llm-env.json'];
  if (exists(join(state,'compose.cve.json'))) files.push('compose.cve.json');
  const proofs = files.map(name => captureFile(join(state,name)));
  const profile = readProfile(root), selection = readPublicLlmBinding(root);
  need(profile && selection?.version === 6, 'PUBLISHED_V6_REQUIRED');
  const model = expectedPublicLlmConfig(root, profile.cve, selection);
  const pins = JSON.parse(proofs[2].bytes);
  need(plain(pins) && equal(Object.keys(pins),['services']) && plain(pins.services) &&
    equal(Object.keys(pins.services).sort(),Object.keys(model.services).sort()) &&
    Object.values(pins.services).every(v => plain(v) && equal(Object.keys(v),['image']) && imageId(v.image)), 'PINS_INVALID');
  const settings = desired ? loadPublicLlmSettings(home,{openai:true}) : null;
  const next = settings ? selectOpenAiOperations(settings.selection,selection,upgradeOperations) : selection;
  if (settings) validatePublicLlmTransition(selection,next);
  const verify = () => { verifyDirectory(); proofs.forEach(p => p.verify()); settings?.verify(); };
  verify(); return { profile, selection, model, pins, next, verify,
      rebind(name) {const i=files.indexOf(name);need(['compose.images.json','compose.llm-env.json','llm-profile.json'].includes(name)&&i>=0,'CONFIG_REBIND_SCOPE');
        verifyDirectory();proofs.forEach((p,j)=>{if(j!==i)p.verify();});settings?.verify();proofs[i]=captureFile(join(state,name));verify();} };
}
function assertCommand(c) {
  const args = [...(c.Config.Entrypoint ?? []),...c.Config.Cmd];
  need(c.Path === args[0] && equal(c.Args,args.slice(1)), 'CONTAINER_COMMAND_DRIFT');
}
function processState(c) {
  return [c.Id,c.Image,c.State.StartedAt,c.State.FinishedAt,c.State.Running,c.State.Status,c.State.Pid,c.RestartCount];
}
function healthy(c) {
  const s = c.State;
  return s?.Running === true && s.Status === 'running' && Number.isSafeInteger(s.Pid) && s.Pid > 0 && c.RestartCount === 0 &&
    !s.OOMKilled && !s.Paused && !s.Dead && !s.Restarting && !s.Error && (role(c) !== 'api' || s.Health?.Status === 'healthy');
}
function control(c) {
  // Keep private bytes only in memory for comparisons; never hash Config/Env.
  return { Id:c.Id, Image:c.Image, Name:c.Name, Path:c.Path, Args:c.Args, Config:c.Config,
    HostConfig:c.HostConfig, Mounts:[...c.Mounts].sort((a,b)=>a.Destination.localeCompare(b.Destination)) };
}
export function assertFourStoreTransition(before, after, authQualification = null, historyQualification = null) {
  need([4,5].includes(before?.historyVersion) && [4,5].includes(after?.historyVersion) && before.llm && after.llm &&
    equal(Object.keys(before.core ?? {}).sort(),['auth','ledger']) && equal(Object.keys(after.core ?? {}).sort(),['auth','ledger']) &&
    equal(Object.keys(before.llm).sort(),['history','quota']) && equal(Object.keys(after.llm).sort(),['history','quota']) &&
    [before,after].every(v => Object.values(v.llm).every(id) && Object.values(v.core).every(p => plain(p) && equal(Object.keys(p),['logicalSha256']) && id(p.logicalSha256))), 'FOUR_STORES_REQUIRED');
  need(equal(before.core.ledger,after.core.ledger) && before.llm.quota===after.llm.quota, 'STORE_MISMATCH');
  if(historyQualification===null) need(before.historyVersion===after.historyVersion && before.llm.history===after.llm.history,'HISTORY_STORE_MISMATCH');
  else need(historyQualifications.has(historyQualification) && before.historyVersion===4 && after.historyVersion===5 &&
    historyQualification.migration==='history-reservations-v4-to-v5' && historyQualification.allRowsPreserved===true &&
    historyQualification.before===before.llm.history && historyQualification.after===after.llm.history &&
    (!authQualification || authQualification.migration==='none'), 'HISTORY_MIGRATION_MISMATCH');
  if (!authQualification || authQualification.migration === 'none') need(equal(before.core.auth,after.core.auth), 'AUTH_STORE_MISMATCH');
  else {
    need(authQualifications.has(authQualification) && authQualification.version === 1 && authQualification.migration === 'auth-a2-to-a3' && authQualification.constructorPasses === 2 &&
      id(authQualification.before) && id(authQualification.expected) && authQualification.before !== authQualification.expected &&
      equal(before.core.auth,{logicalSha256:authQualification.before}) && equal(after.core.auth,{logicalSha256:authQualification.expected}), 'AUTH_MIGRATION_MISMATCH');
  }
}
// Bind the one permitted version inequality to independently inspected sealed B0/B1.
export function qualifyAdapterHistoryMigration({DB,before,after,beforeDirectory,afterDirectory}) {
  for(const [snapshot,directory] of [[before,beforeDirectory],[after,afterDirectory]]) {
    for(const [kind,path] of [['auth','core/auth.sqlite'],['ledger','core/ledger.sqlite'],['history','llm/auth.sqlite'],['quota','llm/ledger.sqlite']]) {
      const expected=['auth','ledger'].includes(kind)?snapshot.core[kind].logicalSha256:snapshot.llm[kind];
      need(reservationLlmFingerprint(DB,fs,{createHash},join(directory,path),kind)===expected,'HISTORY_PROOF_SNAPSHOT_MISMATCH');
    }
  }
  const proof=verifyHistoryReservationMigration({DB,beforePath:join(beforeDirectory,'llm/auth.sqlite'),afterPath:join(afterDirectory,'llm/auth.sqlite')});
  historyQualifications.add(proof);assertFourStoreTransition(before,after,null,proof);return proof;
}
// Qualification is copy-only; this is NOT a live migration, startup or rollback.
export function qualifyAdapterAuthCopy(root, options) {
  const prefix = join(root,STATE,RECORDS) + '/';
  need(typeof options?.snapshotPath === 'string' && options.snapshotPath.startsWith(prefix) &&
    /^[a-f0-9]{32}\/snapshots\/fenced\/core\/auth\.sqlite$/.test(options.snapshotPath.slice(prefix.length)), 'OWNED_FENCED_SNAPSHOT_REQUIRED');
  const result = Object.freeze(qualifyPublicAuthSnapshot(root, options)); authQualifications.add(result); return result;
}

// Stdout is informational after a settled exit-zero dispatch and authoritative
// inspect. Allow silence or the exact known warning, never arbitrary extra text.
function stopAcknowledgement(output, before) {
  if(typeof output!=='string')return 'non-text';
  let text=output.trim();
  const warning='Flag --time has been deprecated, use --timeout instead';
  const deprecated=text===warning||text.startsWith(warning+'\n')||text.startsWith(warning+'\r\n');
  if(deprecated)text=text.slice(warning.length).trim();
  if(text==='')return deprecated?'deprecated-warning':'empty';
  if(id(before?.Id)&&text===before.Id)return deprecated?'deprecated-warning':'id';
  const name=before?.Name;
  if(typeof name==='string'&&/^\/[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(name)&&
    (text===name||text===name.slice(1)))return deprecated?'deprecated-warning':'name';
  return 'unexpected';
}

function lifecycleObservation(output, reference) {
  return {dispatch:'exit-zero',acknowledgement:stopAcknowledgement(output,reference),
    stdoutBytes:typeof output==='string'?Buffer.byteLength(output):null,
    deprecatedTimeWarning:typeof output==='string'&&output.includes('Flag --time has been deprecated, use --timeout instead')};
}
function requireLifecycleOutput(observation, code) {
  need(['empty','id','name','deprecated-warning'].includes(observation.acknowledgement),code);
}

// Classification only: no stop/start and no authority to retry an uncertain action.
// Submission time must be sampled from the SAME daemon, not the host wall clock.
export function classifyStatelessGatewayStop({ before, after, stopOutput, events, daemonSubmittedMs, writers, drain }) {
  const name = role(before);
  need(['egress','llm-egress','openai-egress'].includes(name) && id(before.Id) && before.Id===after?.Id &&
    imageId(before.Image) && equal(control(before),control(after)), 'GATEWAY_ID_OR_CONTROL_DRIFT');
  assertNoOpenAiDockerSecret(before.Config); assertNoOpenAiDockerSecret(after.Config);
  need(before.Mounts.length===0 && after.Mounts.length===0 && before.HostConfig.ReadonlyRootfs===true &&
    before.Config.Env.every(e=>e.startsWith('GPG_KEY=')||!/(?:KEY|TOKEN|PASSWORD|SECRET)/i.test(e.split('=',1)[0])), 'GATEWAY_NOT_STATELESS');
  const stopped = c => c.State?.Running===false && c.State.Status==='exited' && c.State.Pid===0 && c.RestartCount===0 &&
    !c.State.OOMKilled && !c.State.Dead && !c.State.Paused && !c.State.Restarting && !c.State.Error;
  need(healthy(before) && stopped(after) && before.State.StartedAt===after.State.StartedAt &&
    ['id','name'].includes(stopAcknowledgement(stopOutput,before)), 'GATEWAY_STOP_NOT_PROVEN');
  need(Array.isArray(writers) && equal(writers.map(role).sort(),['api','web','worker']) && writers.every(c=>stopped(c)&&
    (role(c)==='web'?[0,143]:[0]).includes(c.State.ExitCode)) && equal(drain,{jobs:0,leases:0,outbox:0}), 'WRITERS_NOT_QUIESCENT');
  if([0,143].includes(after.State.ExitCode))return Object.freeze({warning:false,exitCode:after.State.ExitCode});
  need(after.State.ExitCode===137 && Number.isSafeInteger(daemonSubmittedMs) && Array.isArray(events) && events.length===3 &&
    events.every(e=>plain(e)&&equal(Object.keys(e).sort(),['action','exit','id','signal','time'])&&e.id===before.Id&&Number.isSafeInteger(e.time)), 'GATEWAY_FORCE_STOP_UNPROVEN');
  const [term,kill,die]=events,start=Math.floor(daemonSubmittedMs/1000);
  need(term.action==='kill'&&term.signal==='15'&&term.exit===null&&term.time>=start&&term.time<=start+5&&
    kill.action==='kill'&&kill.signal==='9'&&kill.exit===null&&kill.time-term.time>=29&&kill.time-term.time<=40&&
    die.action==='die'&&die.signal===null&&die.exit==='137'&&die.time>=kill.time&&die.time<=kill.time+5&&
    Math.abs(Date.parse(after.State.FinishedAt)/1000-die.time)<2, 'GATEWAY_FORCE_STOP_EVENTS_INVALID');
  return Object.freeze({warning:true,code:'STATELESS_GATEWAY_FORCED_STOP',exitCode:137});
}

function sourceContract(root) {
  const frontend = captureFile(join(root,'src/shared/api/auth/accountSecurity.ts'),{privateMode:false,limit:1024**2});
  need(['change-password','revoke-all','password-reset/status'].every(s=>frontend.bytes.toString().includes(s)), 'WEB_CONTRACT_UNKNOWN');
  const files = AUTH_SOURCE.map(name=>captureFile(join(root,'server/api',name),{privateMode:false,limit:1024**2}));
  const sum = createHash('sha256'); for (let i=0;i<files.length;i++) sum.update(AUTH_SOURCE[i]).update('\0').update(files[i].bytes).update('\0');
  return { name:'auth-a3-source-v1', digest:sum.digest('hex'), verify(){frontend.verify();files.forEach(f=>f.verify());} };
}
export const AUTH_SCHEMA_PROBE = `const DB=require('better-sqlite3');const classify=${publicAuthSchema.toString()};let db;try{db=new DB('/auth/auth.sqlite',{readonly:true,fileMustExist:true,timeout:1000});db.pragma('query_only=ON');db.exec('BEGIN');process.stdout.write(JSON.stringify({version:classify(db)}));db.exec('ROLLBACK');}catch{process.exitCode=70;}finally{db?.close();}`;
const READY_FILE_PROBE = "const fs=require('node:fs');try{process.stdout.write(fs.readFileSync('/backup/ready.json','utf8'));}catch{process.stdout.write('{}');}";
const CVE_READY_CONDITION = "if(e.SCAN_VULN_ENABLED!=='true'||!await chainReady())throw Error('not ready');";
function cveReadyProbe() {
  need(PUBLIC_READY_PROBE.split(CVE_READY_CONDITION).length===2,'CVE_PROBE_CONTRACT_CHANGED');
  return PUBLIC_READY_PROBE.replace(CVE_READY_CONDITION,"if(e.SCAN_VULN_ENABLED!=='true')throw Error('CVE_CONFIG');if(!await chainReady()){console.log('{\"ready\":false,\"reason\":\"CHAIN_NOT_READY\"}');}else{")+ '\n}';
}
export const ADAPTER_READY_PROBE = `import {chainReady} from './src/scans/scan-readiness.ts';try{if(!await chainReady()){console.log('{"ready":false,"reason":"CHAIN_NOT_READY"}');}else{console.log('{"ready":true}');}}catch{process.exitCode=70;}`;
export const WEB_BACKEND_SOURCE_PROBE = `const fs=require('node:fs'),crypto=require('node:crypto');try{const h=crypto.createHash('sha256');for(const p of ${JSON.stringify(AUTH_SOURCE)}){const s=fs.lstatSync(p);if(!s.isFile()||s.isSymbolicLink()||s.size>1048576)throw Error();h.update(p).update('\\0').update(fs.readFileSync(p)).update('\\0');}process.stdout.write(JSON.stringify({version:1,source:h.digest('hex')}));}catch{process.exitCode=70;}`;

export function createDeployAdapter({ root = ROOT, home = homedir(), run = runIsolatedDocker,
  now = () => performance.now(), context = 'desktop-linux', Database,
  sleep = ms => new Promise(r=>setTimeout(r,ms)), http = fetch,
  checkSource = checkPublicLlmSourceBuild } = {}) {
  const plans = new WeakMap(), leases = new WeakMap(); let activeDeadline = null, leaseDeadline = null, engineJournal = null;
  const database = () => Database ?? createRequire(join(root,'server/api/package.json'))('better-sqlite3');
  const bounded = (work, budget) => async (...args) => {
    need(activeDeadline === null, 'ADAPTER_OPERATION_IN_PROGRESS');
    need(Number.isFinite(now()), 'CLOCK_INVALID'); activeDeadline = now() + budget;
    try { return await work(...args); } finally { activeDeadline = null; }
  };
  function rootCheck() { need(resolve(root) === root && fs.realpathSync(root) === root && context === 'desktop-linux', 'ROOT_OR_CONTEXT_INVALID'); }
  const clientEnv = () => ({ PATH:'/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin', HOME:home, COMPOSE_DISABLE_ENV_FILE:'1' });
  async function request(args, options, code, timeout = 30000) {
    need(activeDeadline !== null, 'ADAPTER_DEADLINE_MISSING');
    const remaining = Math.floor(Math.min(timeout, activeDeadline - now(), leaseDeadline === null ? Infinity : leaseDeadline - now())); need(remaining > 0, 'ADAPTER_DEADLINE');
    engineJournal?.submit(code);
    try { const result = await run(args,{...options,timeout:remaining}); need(now() < activeDeadline && (leaseDeadline===null||now()<leaseDeadline), 'ADAPTER_DEADLINE'); engineJournal?.settle(); return result; }
    catch(error) { throw safeError(code,error); }
  }
  async function connect() {
    const text = await request(['context','inspect',context,'--format','{{json .Endpoints.docker.Host}}'],{root,env:clientEnv()},'DOCKER_CONTEXT_FAILED');
    const endpoint = JSON.parse(text);
    need(typeof endpoint === 'string' && /^unix:\/\/\/[^\s\0]+$/.test(endpoint), 'LOCAL_DAEMON_REQUIRED');
    const options = {root,env:{...clientEnv(),DOCKER_HOST:endpoint}};
    const info = async () => {
      const result = JSON.parse(await request(['info','--format','{"id":{{json .ID}},"memory":{{json .MemTotal}},"cpus":{{json .NCPU}}}'],options,'DOCKER_INFO_FAILED'));
      need(plain(result) && equal(Object.keys(result).sort(),['cpus','id','memory']) && typeof result.id === 'string' && /^[a-zA-Z0-9:-]{8,128}$/.test(result.id) &&
        Number.isSafeInteger(result.memory) && result.memory>0 && Number.isSafeInteger(result.cpus) && result.cpus>0, 'DAEMON_METADATA_INVALID');
      return result;
    };
    const initial = await info();
    return {options,initial,verify:async()=>need(equal(await info(),initial),'DAEMON_CHANGED')};
  }
  async function namespace(config, connection, plan = null, helper = null) {
    config.verify(); const model = config.model, names = Object.keys(model.services).sort(), options = connection.options;
    const query = async (args, code) => request(args,options,code);
    const containers = JSON.parse(await query(['container','inspect',...names.map(n=>`${PROJECT}-${n}-1`)],'CONTAINER_INSPECT_FAILED'));
    need(Array.isArray(containers) && containers.length === names.length && new Set(containers.map(c=>c.Id)).size===names.length &&
      equal(containers.map(role).sort(),names) && containers.every(c=>id(c.Id)), 'NAMESPACE_CARDINALITY');
    const ids = (await query(['container','ls','--all','--filter',`label=com.docker.compose.project=${PROJECT}`,'--format','{{.ID}}','--no-trunc'],'CONTAINER_CENSUS_FAILED')).trim().split('\n').filter(Boolean).sort();
    need(equal(ids,[...containers.map(c=>c.Id),...(helper?[helper.Id]:[])].sort()),'UNOWNED_OR_EXTRA_CONTAINER');
        const named=(await query(['container','ls','--all','--filter',`name=${PROJECT}`,'--format','{{.ID}}','--no-trunc'],'CONTAINER_NAME_CENSUS_FAILED')).trim().split('\n').filter(Boolean).sort();
        need(equal(named,ids),'NAMESPACE_NAME_COLLISION');
    const imageRows = JSON.parse(await query(['image','inspect',...new Set(containers.map(c=>c.Image))],'IMAGE_INSPECT_FAILED'));
    need(Array.isArray(imageRows) && imageRows.length === new Set(containers.map(c=>c.Image)).size && new Set(imageRows.map(i=>i.Id)).size===imageRows.length,'IMAGE_CARDINALITY');
    const images = {};
    for(const c of containers){const n=role(c);images[n]=imageRows.find(i=>i.Id===c.Image);need(c.Image===(plan?.peers.get(n)?.Image??config.pins.services[n].image),'PUBLISHED_IMAGE_DRIFT');}
    for(const c of containers){const n=role(c),a=plan?.authorities.get(n)??{model,selection:config.selection};validatePublicLlmContainer(c,n,a.model.services[n],images[n],a.model,{images,...(plan?.jwt?{secret:plan.jwt.bytes.toString()}: {})},a.selection);assertCommand(c);
      if(n.endsWith('volume-init'))need(c.State.Running===false&&c.State.Status==='exited'&&c.State.ExitCode===0&&c.State.Pid===0&&c.RestartCount===0&&!c.State.OOMKilled&&!c.State.Error,'INITIALIZER_STATE_INVALID');
    }
    const netNames = Object.values(model.networks).map(n=>n.name), volumeNames = Object.values(model.volumes).map(v=>v.name);
    const listedNetworks=(await query(['network','ls','--filter',`label=com.docker.compose.project=${PROJECT}`,'--format','{{.Name}}'],'NETWORK_CENSUS_FAILED')).trim().split('\n').filter(Boolean).sort();
    need(equal(listedNetworks,[...netNames].sort()),'UNOWNED_OR_EXTRA_NETWORK');
    const networks = JSON.parse(await query(['network','inspect',...netNames],'NETWORK_INSPECT_FAILED'));
    const volumes = JSON.parse(await query(['volume','inspect',...volumeNames],'VOLUME_INSPECT_FAILED'));
    need(Array.isArray(networks)&&networks.length===netNames.length&&equal(networks.map(n=>n.Name).sort(),[...netNames].sort()),'NETWORK_CARDINALITY');
    need(Array.isArray(volumes)&&volumes.length===volumeNames.length&&equal(volumes.map(v=>v.Name).sort(),[...volumeNames].sort()),'VOLUME_CARDINALITY');
    for(const n of networks){const spec=Object.values(model.networks).find(v=>v.name===n.Name);
      need(n.Driver==='bridge'&&n.Labels?.[LABEL]==='v1'&&n.Labels?.['com.docker.compose.project']===PROJECT&&Boolean(n.Internal)===Boolean(spec.internal)&&!n.Attachable&&!n.Ingress&&!n.EnableIPv6&&equal(n.Options??{},{}),'NETWORK_POLICY');
      const members=containers.filter(c=>c.State.Running&&Object.hasOwn(c.NetworkSettings.Networks,n.Name));
      need(equal(Object.keys(n.Containers??{}).sort(),members.map(c=>c.Id).sort()),'NETWORK_FOREIGN_MEMBER');
      for(const c of members)need(c.NetworkSettings.Networks[n.Name].NetworkID===n.Id&&n.Containers[c.Id].Name===c.Name.slice(1),'NETWORK_ENDPOINT_DRIFT');
    }
    for(const v of volumes){need(v.Driver==='local'&&v.Scope==='local'&&equal(v.Options??{},{}),'VOLUME_POLICY');
          const spec=Object.values(model.volumes).find(s=>s.name===v.Name);
          if(v.Name===config.selection.credentialVolume)validateOpenAiVolume(v,config.selection);
          else if(!spec.external)need(v.Labels?.[LABEL]==='v1'&&v.Labels?.['com.docker.compose.project']===PROJECT,'VOLUME_OWNERSHIP');
      const consumers=[...containers,...(helper?[helper]:[])].filter(c=>c.Mounts.some(m=>m.Type==='volume'&&m.Name===v.Name));
      const actual=(await query(['container','ls','--all','--filter',`volume=${v.Name}`,'--format','{{.ID}}','--no-trunc'],'VOLUME_CONSUMERS_FAILED')).trim().split('\n').filter(Boolean).sort();
      need(equal(actual,consumers.map(c=>c.Id).sort()),'VOLUME_FOREIGN_CONSUMER');
      for(const c of consumers)need(c.Mounts.filter(m=>m.Name===v.Name).every(m=>m.Source===v.Mountpoint&&m.Driver==='local'),'VOLUME_MOUNT_DRIFT');
    }
    await connection.verify(); config.verify(); return {containers,images,networks,volumes};
  }
  function noLock() { need(!exists(join(root,STATE,'.operation.lock')),'SHARED_OPERATION_HOLD'); }
  async function stable(plan) {
    plan.config.verify(); plan.source.verify(); plan.self.verify(); plan.entryProofs.forEach(p=>p.verify()); plan.contract.verify(); plan.catalog.verify(); plan.retentions.verify(); plan.history.verify(); plan.lock?.verify();
    if(!plan.lock)noLock();
    const current=await namespace(plan.config,plan.connection);
    need(equal(current.containers.map(control),plan.before.containers.map(control))&&
      equal(current.containers.map(processState),plan.before.containers.map(processState))&&
      equal(current.networks,plan.before.networks)&&equal(current.volumes,plan.before.volumes),'RUNTIME_CHANGED_DURING_BUILD');
    need(current.containers.filter(c=>!role(c).endsWith('volume-init')).every(healthy),'OLD_SITE_NOT_HEALTHY');
    await retained(plan);return current;
  }
  function planFor(token) { const plan=plans.get(token);need(plan,'PLAN_NOT_OWNED');return plan; }
  async function status() {
    try {rootCheck();const hold=exists(join(root,STATE,'.operation.lock'));const config=loadConfiguration(root,home,false),connection=await connect();
      const observed=await namespace(config,connection);
      return Object.freeze({version:1,project:PROJECT,origin:ORIGIN,hold,reason:hold?'SHARED_OPERATION_HOLD':null,
        daemon:connection.initial.id,memoryBytes:connection.initial.memory,cpus:connection.initial.cpus,
        services:observed.containers.map(c=>({name:role(c),id:c.Id,image:c.Image,running:c.State.Running===true,healthy:healthy(c),restartCount:c.RestartCount})),
        networks:observed.networks.length,volumes:observed.volumes.length,capabilities:DEPLOY_ADAPTER_CAPABILITIES});
    } catch(error){throw safeError('STATUS_REFUSED',error);}
  }
  async function prepare({mode,services,lease,upgradeOperations=false,migrateHistoryV4ToV5=false}={}) {
    try {rootCheck();const owned=lease?ownedLease(lease):null;if(!owned)noLock();else {need(!owned.plan,'PREFLIGHT_ALREADY_PREPARED');need(mode!=='app'||owned.supervisor,'APP_SUPERVISOR_REQUIRED');}const targets=deploymentTargets(mode,services);
      need(typeof upgradeOperations === 'boolean' && typeof migrateHistoryV4ToV5 === 'boolean', 'OPERATIONS_FLAG_INVALID');
      need(!migrateHistoryV4ToV5 || mode==='app' && !upgradeOperations && targets.includes('api') && targets.every(n=>['web','api'].includes(n)), 'HISTORY_MIGRATION_SCOPE');
      need(!upgradeOperations || mode === 'app' && equal(targets,[...ROLES].sort()), 'OPERATIONS_UPGRADE_REQUIRES_ALL_APP_TARGETS');
      const config=loadConfiguration(root,home,true,upgradeOperations);
      need(mode!=='web'||equal(config.selection,config.next),'WEB_REQUIRES_UNCHANGED_RUNTIME_CONFIG');
      const next=expectedPublicLlmConfig(root,config.profile.cve,config.next);
      if(!equal(config.selection,config.next))need(ROLES.every(n=>targets.includes(n)),'CONFIG_CHANGE_REQUIRES_ALL_APP_TARGETS');
      const source=capturePublicLlmSource(root,{openai:true}),self=captureFile(fileURLToPath(import.meta.url),{privateMode:false,limit:1024**2});
      const entryProofs=['deploy.mjs','deploy-core.mjs','deploy-adapter-stores.mjs','public-llm-stand.mjs','deploy-supervisor.mjs','deploy-authority.mjs'].map(name=>captureFile(join(root,'scripts',name),{privateMode:false,limit:1024**2}));
      const contract=sourceContract(root),catalog=captureDeploymentCatalog(root),retentions=capturePublicLlmRetentions(root),history=captureBuildHistory(root,owned?.nonce);
      source.verify();
      need(catalog.entries.length+history.count<DEPLOYMENT_TOTAL_LIMIT,'HISTORICAL_CATALOG_CAPACITY');
      const disk=fs.statfsSync(join(root,STATE));need(disk.bavail*disk.bsize>=4*1024**3,'DISK_HEADROOM');
      const connection=await connect(),before=await namespace(config,connection);
            const requiredMemory=Object.values(next.services).filter(s=>s.restart!=='no').reduce((sum,s)=>sum+Number(s.mem_limit),0);
            need(Number.isSafeInteger(requiredMemory)&&requiredMemory<=connection.initial.memory,'DAEMON_MEMORY_BUDGET');
      for(const receipt of retentions.receipts) for(const [name,row] of Object.entries(receipt.images)) {
        retentions.verify();
        const values=JSON.parse(await request(['image','inspect',row.tag],connection.options,'RETAINED_IMAGE_VERIFY_FAILED'));
        need(values.length===1&&values[0].Id===row.image.Id&&equal(values[0].Config,row.image.Config)&&values[0].RepoTags?.includes(row.tag),'RETAINED_IMAGE_CHANGED');
        validatePublicLlmImage(values[0],name);retentions.verify();
      }
      for(const ref of history.references){const values=JSON.parse(await request(['image','inspect',ref.tag],connection.options,'RETAINED_IMAGE_VERIFY_FAILED'));
        need(values.length===1&&values[0].Id===ref.image&&values[0].RepoTags?.includes(ref.tag),'RETAINED_IMAGE_CHANGED');validatePublicLlmImage(values[0],ref.name);}
      need(before.containers.filter(c=>!role(c).endsWith('volume-init')).every(healthy),'OLD_SITE_NOT_HEALTHY');
      const tags=(await request(['image','ls','--filter',`label=${IMAGE_LABEL}=${PROJECT}`,'--format','{{.Repository}}:{{.Tag}}'],connection.options,'IMAGE_REFERENCES_FAILED')).trim().split('\n').filter(Boolean);
      need(tags.length+targets.length*2<=DEPLOYMENT_RETAINED_REFERENCE_LIMIT,'IMAGE_REFERENCE_CAPACITY');
      const plan={mode,targets,config,next,source,self,entryProofs,contract,catalog,retentions,history,connection,before,phase:'prepared',apiReady:true,
              ...(owned?{lease,lock:owned.lock,nonce:owned.nonce,audit:owned.audit,record:owned.record,proofs:owned.proofs,owner:owned.owner}:{}),
              peers:new Map(before.containers.map(c=>[role(c),c])),authorities:new Map(before.containers.map(c=>[role(c),{model:config.model,selection:config.selection}]))};
            if(owned)owned.plan=plan;
            let authVersion=3;
            if(mode==='app'){
              const text=await request(['container','exec',plan.peers.get('api').Id,'node','-e',AUTH_SCHEMA_PROBE],connection.options,'AUTH_SCHEMA_PROBE_FAILED',5000);
              const schema=JSON.parse(text);need(plain(schema)&&equal(Object.keys(schema),['version'])&&[2,3].includes(schema.version),'AUTH_SCHEMA_UNSUPPORTED');authVersion=schema.version;
            }
            plan.migration=mode==='app'&&authVersion===2;
            plan.historyMigration='none';plan.historyVersion=null;plan.historyConsent=migrateHistoryV4ToV5;
            if(mode==='app') {
              const text=await request(['container','exec',plan.peers.get('api').Id,'node','-e',PUBLIC_LLM_RESERVATION_HEADER_PROGRAM],connection.options,'HISTORY_SCHEMA_PROBE_FAILED',5000);
              const schema=JSON.parse(text);need(plain(schema)&&equal(Object.keys(schema).sort(),['historyVersion','ready'])&&schema.ready===true&&[4,5].includes(schema.historyVersion),'HISTORY_SCHEMA_UNSUPPORTED');
              plan.historyVersion=schema.historyVersion;
              plan.historyMigration=schema.historyVersion===4?'history-reservations-v4-to-v5':'none';
              need(!migrateHistoryV4ToV5 || !plan.migration,'HISTORY_AUTH_MIGRATION_CONFLICT');
              if(plan.historyMigration!=='none') need(!plan.migration&&!upgradeOperations&&equal(config.selection,config.next)&&targets.every(n=>['web','api'].includes(n)),'HISTORY_MIGRATION_SCOPE');
            }
            for(const n of ROLES.filter(n=>!targets.includes(n)))need(equal(config.model.services[n],next.services[n]),'NON_TARGET_CONFIG_CHANGE');
            need(equal(config.model.networks,next.networks)&&equal(config.model.volumes,next.volumes),'TOPOLOGY_CHANGE_UNSUPPORTED');
      if(mode==='web'){
        const api=before.containers.find(c=>role(c)==='api');
        const proof=JSON.parse(await request(['container','exec',api.Id,'node','-e',WEB_BACKEND_SOURCE_PROBE],connection.options,'BACKEND_SOURCE_PROBE_FAILED',5000));
        need(plain(proof)&&equal(Object.keys(proof).sort(),['source','version'])&&proof.version===1&&proof.source===contract.digest,'WEB_BACKEND_A3_COMPATIBILITY_UNPROVEN');
      }
      await stable(plan);const token=Object.freeze({version:2,mode,services:targets,interruptedServices:Object.freeze(mode==='web'?['web']:[...new Set([...targets,'web','api','worker'])].sort()),
              migration:plan.migration,historyMigration:plan.historyMigration,historyVersion:plan.historyVersion,...(config.next.operations?{operations:config.next.operations}:{}),upgradeOperations,rollbackSafe:mode==='web',old:Object.freeze({images:Object.fromEntries(targets.map(n=>[n,before.images[n].Id]))}),
              availableCapabilities:Object.freeze([contract.name]),backendContract:contract.name,lifecycleSupported:true});plans.set(token,plan);plan.token=token;return token;
    }catch(error){throw safeError('PREFLIGHT_REFUSED',error);}
  }
  async function buildCandidate(token) {
    const plan=planFor(token);need(plan.phase==='prepared','ATTEMPT_NOT_REPLAYABLE');
    try {ownedLease(plan.lease);await stable(plan);plan.phase='building';plan.buildMutation=false;
      const {nonce,record,proofs}=plan;
      const sourceManifest=plan.source.manifest.files.map(f=>({path:f.path,digest:f.digest}));
      record('intent.json',{version:2,kind:'preserving-deployment',project:PROJECT,nonce,mode:plan.mode,services:plan.targets,
        daemon:plan.connection.initial.id,source:digest(JSON.stringify(sourceManifest)),adapter:digest(plan.self.bytes),entrySources:plan.entryProofs.map(p=>digest(p.bytes)),backendSource:plan.contract.digest,
        old:plan.targets.map(n=>({role:n,id:plan.before.containers.find(c=>role(c)===n).Id,image:plan.before.images[n].Id})),lifecycle:false});
      // Compilation/COPY qualification belongs to build, never read-only planning.
      const qualification=await checkSource(root,{openai:plan.config.next});
      need(qualification?.typescript===true&&qualification.bundle===true&&qualification.openai===true,'SOURCE_BUILD_QUALIFICATION');await stable(plan);
      const end=now()+30*60*1000,candidates={};plan.candidateImages={...plan.before.images};
      const call=async(args,code,requested=30000)=>{await stable(plan);plan.owner.verify();proofs.forEach(p=>p.verify());
        const timeout=Math.floor(Math.min(requested,end-now()));need(timeout>0,'BUILD_DEADLINE');
        const result=await request(args,plan.connection.options,code,timeout);await stable(plan);return result;};
      for(const name of plan.targets){
        const oldTag=`dip-deploy-${name}:old-${nonce}`,tag=`dip-deploy-${name}:candidate-${nonce}`;
        for(const ref of [oldTag,tag])need((await call(['image','ls','--filter',`reference=${ref}`,'--format','{{.ID}}'],'IMAGE_TAG_CHECK_FAILED')).trim()==='','IMAGE_TAG_ALREADY_PRESENT');
        record(`retain-${name}-submission.json`,{role:name,image:plan.before.images[name].Id,tag:oldTag});
        plan.buildMutation=true;await call(['image','tag',plan.before.images[name].Id,oldTag],'OLD_IMAGE_RETENTION_FAILED');
        const retained=JSON.parse(await call(['image','inspect',oldTag],'OLD_IMAGE_VERIFY_FAILED'));
        need(retained.length===1&&retained[0].Id===plan.before.images[name].Id&&equal(retained[0].Config,plan.before.images[name].Config),'OLD_IMAGE_CHANGED');
        record(`build-${name}-submission.json`,{role:name,tag,oldTag,lifecycle:false});
        const build=plan.next.services[name].build;need(build?.context===root&&typeof build.dockerfile==='string'&&!build.dockerfile.includes('..'),'BUILD_SPEC_INVALID');
        await call(['build','--pull=false','--file',join(root,build.dockerfile),'--label',`${LABEL}=v1`,'--label',`${IMAGE_LABEL}=${PROJECT}`,'--tag',tag,root],'CANDIDATE_BUILD_FAILED',20*60*1000);
        const rows=JSON.parse(await call(['image','inspect',tag],'CANDIDATE_IMAGE_INSPECT_FAILED'));
        need(rows.length===1,'CANDIDATE_IMAGE_CARDINALITY');validatePublicLlmImage(rows[0],name);assertNoOpenAiDockerSecret(rows[0].Config);
        plan.candidateImages[name]=rows[0];candidates[name]=Object.freeze({image:rows[0].Id,tag,oldImage:plan.before.images[name].Id,oldTag});
        record(`built-${name}.json`,{role:name,...candidates[name]});
      }
      await stable(plan);record('built.json',{version:1,nonce,outcome:'candidate-built-old-site-unchanged',candidates,lifecycle:false});
      plan.phase='built';plan.candidates=candidates;return Object.freeze({version:1,attempt:nonce,mode:plan.mode,candidates:Object.freeze(candidates),lifecycle:false,lockRetained:true});
    }catch(error){plan.phase=plan.buildMutation?'hold':'prebuild-failed';const failure=safeError(plan.buildMutation?'BUILD_HOLD':'BUILD_REFUSED',error);
      try{plan.record?.('failure.json',{version:1,...deployAdapterDiagnostic(failure),lifecycle:false});}catch{/* Keep uncertain lock/evidence. */}
      throw failure;}
  }
  function ownedLease(token) {
    const state=leases.get(token);need(state&&!state.released,'LEASE_NOT_OWNED');state.supervisor?.verify();state.lock.verify();state.owner.verify();
    need(equal(fs.readdirSync(state.lock.path),['deploy-adapter-owner.json']),'LEASE_FOREIGN_CONTENT');return state;
  }
  function guard(p) {
    ownedLease(p.lease);p.config.verify();p.source.verify();p.self.verify();p.entryProofs.forEach(f=>f.verify());
    p.contract.verify();p.catalog.verify();p.retentions.verify();p.history.verify();p.proofs.forEach(f=>f.verify());p.jwt?.verify();p.extraGuard?.();
  }
  function contextPlan(ctx) {
    const p=planFor(ctx.plan);need(p.lease===ctx.lease&&p.mode===ctx.mode&&equal([...ctx.services].sort(),p.targets),'CONTEXT_NOT_OWNED');guard(p);return p;
  }
  async function acquire(ctx) {
    rootCheck();const supervisor=ctx?.mode==='app'?requireDeploySupervisor(root):null;
    noLock();const history=captureBuildHistory(root);history.verify();
    const lock=acquireLock(root),nonce=randomBytes(16).toString('hex'),parent=join(root,STATE,RECORDS);leaseDeadline=now()+3600000;
    // An error after acquisition intentionally leaves an unowned HOLD, never guessed recovery.
    if(!exists(parent)){fs.mkdirSync(parent,{mode:0o700});syncDirectory(join(root,STATE));}
    protectedDirectory(parent);const audit=join(parent,nonce);fs.mkdirSync(audit,{mode:0o700});syncDirectory(parent);
    writeExclusive(join(lock.path,'deploy-adapter-owner.json'),JSON.stringify({version:2,nonce,kind:'preserving-deployment'}),0o600);syncDirectory(lock.path);
    const owner=captureFile(join(lock.path,'deploy-adapter-owner.json')),auditGuard=protectedDirectory(audit),proofs=[];
    const record=(name,value)=>{lock.verify();owner.verify();auditGuard();proofs.forEach(p=>p.verify());
      need(/^[a-z][a-z0-9-]{0,79}\.json$/.test(name),'JOURNAL_NAME_INVALID');
      const bytes=JSON.stringify(value);need(Buffer.byteLength(bytes)<=262144,'JOURNAL_SIZE');
      writeExclusive(join(audit,name),bytes,0o600);syncDirectory(audit);proofs.push(captureFile(join(audit,name),{limit:262144}));};
    record('lease.json',{version:2,project:PROJECT,nonce});
    const token=Object.freeze({version:2,nonce});
    const state={lock,nonce,audit,owner,proofs,record,released:false,supervisor};leases.set(token,state);
    if(supervisor){
      record('supervisor.json',{version:1,session:supervisor.session,identity:supervisor.identity});
      engineJournal=createEngineJournal(join(audit,'engine.jsonl'),()=>{supervisor.verify();lock.verify();owner.verify();});
      state.engineJournal=engineJournal;
    }
    return token;
  }
  async function peers(p) {
    guard(p);const expected=[...p.peers.values()];
    const rows=JSON.parse(await request(['container','inspect',...expected.map(c=>c.Id)],p.connection.options,'PEER_INSPECT_FAILED'));
    need(Array.isArray(rows)&&rows.length===expected.length&&new Set(rows.map(c=>c.Id)).size===rows.length,'PEER_CARDINALITY');
    for(const old of expected){const c=rows.find(r=>r.Id===old.Id);need(c&&equal(control(c),control(old))&&equal(processState(c),processState(old)),'PEER_CHANGED');
      const a=p.authorities.get(role(c));validatePublicLlmContainer(c,role(c),a.model.services[role(c)],p.images?.[role(c)]??p.before.images[role(c)],a.model,{images:p.images??p.before.images,...(p.jwt?{secret:p.jwt.bytes.toString()}: {})},a.selection);assertCommand(c);
      need(!c.State.OOMKilled&&!c.State.Paused&&!c.State.Restarting&&!c.State.Dead&&!c.State.Error&&c.RestartCount===0&&(!p.apiReady||role(c)!=='api'||healthy(c)),'PEER_UNHEALTHY');
    }guard(p);return rows;
  }
  async function boundary(p, helper=null) {
    await peers(p);const found=await namespace(p.config,p.connection,p,helper);
    for(const v of p.before.volumes)need(found.volumes.some(n=>equal(n,v)),'VOLUME_REPLACED');
    for(const n of p.before.networks){const current=found.networks.find(v=>v.Name===n.Name);need(current&&equal({...current,Containers:{}},{...n,Containers:{}}),'NETWORK_REPLACED');}
    await retained(p);guard(p);
  }
  async function retained(p) {
    const refs=[...p.retentions.receipts.flatMap(r=>Object.entries(r.images).map(([name,v])=>({name,tag:v.tag,image:v.image.Id,config:v.image.Config}))),
      ...p.history.references,...Object.entries(p.candidates??{}).flatMap(([name,r])=>[{name,tag:r.tag,image:r.image},{name,tag:r.oldTag,image:r.oldImage}])];
    const fence=()=>{if(p.lease)guard(p);else{p.config.verify();p.source.verify();p.self.verify();p.entryProofs.forEach(f=>f.verify());p.contract.verify();p.catalog.verify();p.retentions.verify();p.history.verify();}};
    fence();need(refs.length<=DEPLOYMENT_RETAINED_REFERENCE_LIMIT&&new Set(refs.map(r=>r.tag)).size===refs.length,'RETAINED_REFERENCE_SCOPE');
    if(refs.length){const rows=JSON.parse(await request(['image','inspect',...refs.map(r=>r.tag)],p.connection.options,'RETAINED_IMAGE_INSPECT_FAILED'));
      need(rows.length===refs.length,'RETAINED_IMAGE_CARDINALITY');
      for(let i=0;i<refs.length;i++){const ref=refs[i],image=rows[i];need(image.Id===ref.image&&image.RepoTags?.includes(ref.tag)&&(!ref.config||equal(image.Config,ref.config)),'RETAINED_IMAGE_CHANGED');validatePublicLlmImage(image,ref.name);}
    }
    const inventory=(await request(['image','ls','--filter',`label=${IMAGE_LABEL}=${PROJECT}`,'--format','{{.Repository}}:{{.Tag}}'],p.connection.options,'IMAGE_REFERENCE_CENSUS_FAILED')).trim().split('\n').filter(Boolean);
    need(inventory.length<=DEPLOYMENT_RETAINED_REFERENCE_LIMIT&&refs.every(r=>inventory.includes(r.tag)),'IMAGE_REFERENCE_CAPACITY_OR_LOSS');fence();
  }
  function save(p,name,value) {p.record(name,value);return join(p.audit,name);}
  function compose(p,recipe,args) {return ['compose','--env-file','/dev/null','--project-directory',root,'-p',PROJECT,'-f',recipe,...args];}
  function recipe(model,images) {
    const value=structuredClone(model);
    for(const [name,s]of Object.entries(value.services)){s.image=images[name].Id;if(name==='api')s.environment.SCAN_JWT_SECRET='${SCAN_JWT_SECRET:?required}';}
    return value;
  }
  async function rendered(p,path,model,selection,images) {
    guard(p);const raw=await request(compose(p,path,['config','--format','json']),{...p.connection.options,env:{...p.connection.options.env,SCAN_JWT_SECRET:CONFIG_SECRET}},'COMPOSE_RENDER_FAILED');
    const value=JSON.parse(raw);validatePublicLlmConfig(value,root,p.config.profile.cve,selection,images);
    need(equal(Object.keys(value.services).sort(),Object.keys(model.services).sort()),'COMPOSE_SERVICE_SCOPE');guard(p);
  }
  async function validate(ctx) {
    const p=contextPlan(ctx);need(p.phase==='built'&&ctx.candidate?.attempt===p.nonce,'CANDIDATE_NOT_OWNED');await stable(p);
    p.oldRecipe=save(p,'recipe-old.json',recipe(p.config.model,p.before.images));
    p.newRecipe=save(p,'recipe-candidate.json',recipe(p.next,p.candidateImages));
    await rendered(p,p.oldRecipe,p.config.model,p.config.selection,p.before.images);
    await rendered(p,p.newRecipe,p.next,p.config.next,p.candidateImages);
    p.images={...p.before.images};p.phase='validated';await stable(p);
    return {valid:true,requiredCapabilities:[p.contract.name],availableCapabilities:[p.contract.name]};
  }
  async function drainCounts(p) {
    await peers(p);const w=p.peers.get('worker');need(healthy(w),'DRAIN_WORKER_UNHEALTHY');
    const r=JSON.parse(await request(['container','exec',w.Id,'node','-e',PUBLIC_DRAIN_PROBE],p.connection.options,'DRAIN_PROBE_FAILED',5000));
    need(plain(r)&&equal(Object.keys(r).sort(),['jobs','leases','outbox'])&&Object.values(r).every(n=>Number.isSafeInteger(n)&&n>=0),'DRAIN_RECEIPT_INVALID');return r;
  }
  async function waitForIdle(ctx) {
    const started=now(),budget=ctx.options?.drainTimeoutMs??30000,previousDeadline=activeDeadline;
    need(Number.isSafeInteger(budget)&&budget>=1&&budget<=300000&&previousDeadline!==null,'DRAIN_BUDGET_INVALID');
    const end=Math.min(started+budget,previousDeadline,leaseDeadline??Infinity);
    // Scope the shared request deadline so peer inspections AND the drain probe
    // consume one budget. Await settlement; never race a still-running operation.
    activeDeadline=end;
    try {
      const p=contextPlan(ctx);
      do {
        need(!ctx.signal?.aborted,'DRAIN_ABORTED');need(now()<end,'DRAIN_TIMEOUT');
        const counts=await drainCounts(p);
        need(!ctx.signal?.aborted,'DRAIN_ABORTED');need(now()<end,'DRAIN_TIMEOUT');
        if(Object.values(counts).every(n=>n===0)){p.drain=counts;return {idle:true};}
        const pause=Math.min(500,Math.floor(end-now()));need(pause>0,'DRAIN_TIMEOUT');await sleep(pause);
      }while(true);
    }finally{activeDeadline=previousDeadline;}
  }
  async function prepareRecovery(ctx) {
    const p=contextPlan(ctx);need(p.phase==='validated','CANDIDATE_NOT_VALIDATED');await stable(p);
    if(p.mode==='app'){
      p.jwt=captureFile(join(root,STATE,'scan-jwt'),{limit:96});need(/^[a-f0-9]{96}$/.test(p.jwt.bytes.toString()),'JWT_FORMAT');
      need(p.peers.get('api').Config.Env.includes('SCAN_JWT_SECRET='+p.jwt.bytes.toString()),'JWT_BINDING_CHANGED');
    }
    save(p,'recovery.json',{version:2,nonce:p.nonce,project:PROJECT,daemon:p.connection.initial.id,services:p.targets,interruptedServices:p.token.interruptedServices,
      oldRecipe:'recipe-old.json',candidateRecipe:'recipe-candidate.json',old:p.before.containers.map(c=>({role:role(c),id:c.Id,image:c.Image,startedAt:c.State.StartedAt})),
      migration:p.migration,historyMigration:p.historyMigration,historyVersion:p.historyVersion,
      historyRecovery:'guarded-hold-no-automatic-resume',oldBinaryAfterHistoryV5:false,automaticDatabaseRollback:false});
    if(p.historyMigration!=='none') {
      const lease=ownedLease(p.lease);need(lease.supervisor&&engineJournal,'HISTORY_SUPERVISOR_REQUIRED');
      save(p,'authority-v3.json',{version:3,project:PROJECT,nonce:p.nonce,supervisor:lease.supervisor.identity,
        files:recoveryFileSet(p),authority:deploymentAuthority(p.before)});
    }
    p.phase='recovery';return {durable:true,attempt:p.nonce};
  }
  const cleanStopped = c => c.State.Running===false&&c.State.Status==='exited'&&c.State.Pid===0&&c.RestartCount===0&&
    !c.State.OOMKilled&&!c.State.Paused&&!c.State.Dead&&!c.State.Restarting&&!c.State.Error&&
    (role(c)==='web'?[0,143]:[0]).includes(c.State.ExitCode);
  async function inspectChanged(p,name,previous,{recreated=false,old=false,stopped=false}={}) {
    const rows=JSON.parse(await request(['container','inspect',`${PROJECT}-${name}-1`],p.connection.options,'CHANGED_CONTAINER_INSPECT_FAILED'));
    need(rows.length===1,'CHANGED_CONTAINER_CARDINALITY');const c=rows[0],a=old?{model:p.config.model,selection:p.config.selection}:{model:p.next,selection:p.config.next};
    const image=(recreated?(old?p.before.images:p.candidateImages):p.images)[name];
    validatePublicLlmContainer(c,name,a.model.services[name],image,a.model,{images:old?p.before.images:p.candidateImages,...(p.jwt?{secret:p.jwt.bytes.toString()}: {})},a.selection);assertCommand(c);
    need(id(c.Id)&&c.Image===image.Id&&c.RestartCount===0&&!c.State.OOMKilled&&!c.State.Paused&&!c.State.Dead&&!c.State.Restarting&&!c.State.Error,'CHANGED_CONTAINER_STATE');
    if(recreated)need(c.Id!==previous.Id,'RECREATE_NOT_PROVEN');else need(equal(control(c),control(previous)),'RETAINED_CONTROL_CHANGED');
    if(p.mode==='web'&&name==='web'&&recreated&&!old){
      need(p.pending?.settled===true&&p.pending.name==='web'&&p.pending.old===false&&p.pending.previous.Id===previous.Id,'WEB_CANDIDATE_DISPATCH_UNPROVEN');
      need(Date.parse(c.Created)>0&&Date.parse(c.State.StartedAt)>=Date.parse(c.Created)&&c.State.StartedAt!==previous.State.StartedAt,'WEB_CANDIDATE_EPOCH_INVALID');
      // Bind the successfully dispatched candidate BEFORE requiring it to stay running.
      // An exited candidate is not READY; this identity only permits guarded web rollback.
      save(p,'start-web-identified.json',{id:c.Id,image:c.Image,created:c.Created,startedAt:c.State.StartedAt});
      p.webCandidate=c;p.pending.identified=c.Id;
    }
    if(stopped)need(c.State.Running===false&&c.State.Pid===0&&c.State.StartedAt===previous.State.StartedAt,'STOP_NOT_PROVEN');
    else need(c.State.Running===true&&c.State.Status==='running'&&c.State.Pid>0&&c.State.StartedAt!==previous.State.StartedAt,'START_NOT_PROVEN');
    return c;
  }
  async function stop(p,name) {
    await boundary(p);const before=p.peers.get(name);need(healthy(before),'STOP_REQUIRES_HEALTHY');
    const gateway=['egress','llm-egress','openai-egress'].includes(name);
    let submitted;
    if(gateway){const text=await request(['info','--format','{{json .SystemTime}}'],p.connection.options,'DAEMON_CLOCK_FAILED');submitted=Date.parse(JSON.parse(text));need(Number.isSafeInteger(submitted),'DAEMON_CLOCK_INVALID');}
    save(p,'stop-'+name+'-submission.json',{role:name,id:before.Id,image:before.Image,...(gateway?{daemonSubmittedMs:submitted}:{})});
    // --time is deprecated and can add CLI warning output; use the canonical flag.
    const output=await request(['container','stop','--timeout','30',before.Id],p.connection.options,'STOP_DISPATCH_FAILED',45000);
    const observation=lifecycleObservation(output,before);
    // Inspect even when stdout is unexpected: text alone cannot prove a stop failed.
    // Use the PREVIOUS authority when stopping a retained service, never candidate defaults.
    const rows=JSON.parse(await request(['container','inspect',before.Id],p.connection.options,'STOP_INSPECT_FAILED'));need(Array.isArray(rows)&&rows.length===1,'STOP_CARDINALITY');const after=rows[0];
    const sameControl=equal(control(before),control(after)),sameStart=before.State.StartedAt===after.State.StartedAt;
    save(p,'stop-'+name+'-observation.json',{role:name,...observation,
      sameControl,sameStart,exited:after.State.Status==='exited',running:after.State.Running===true,zeroPid:after.State.Pid===0,
      cleanWriterStop:!gateway&&cleanStopped(after),
      exitCode:Number.isInteger(after.State.ExitCode)&&after.State.ExitCode>=0&&after.State.ExitCode<=255?after.State.ExitCode:null});
    need(after.Id===before.Id&&after.Image===before.Image&&sameControl&&sameStart,'STOP_CONTROL_CHANGED');assertCommand(after);
    need(after.State.Running===false&&after.State.Status==='exited'&&after.State.Pid===0&&after.RestartCount===0&&
      !after.State.OOMKilled&&!after.State.Paused&&!after.State.Dead&&!after.State.Restarting&&!after.State.Error,'STOP_NOT_PROVEN');
    if(!gateway)need(cleanStopped(after),'WRITER_NOT_CLEANLY_STOPPED');
    requireLifecycleOutput(observation,'STOP_OUTPUT_INVALID');
    if(gateway){let events=[];
      if(after.State.ExitCode===137){
        // Relative CLI deadline is finite; --until is in the daemon's already-past clock, not FinishedAt+future.
        await sleep(100);
                const time=Date.parse(JSON.parse(await request(['info','--format','{{json .SystemTime}}'],p.connection.options,'DAEMON_CLOCK_FAILED')));
        need(Number.isSafeInteger(time)&&time>Date.parse(after.State.FinishedAt)&&time-submitted<=120000,'EVENT_CLOCK_INVALID');
        const text=await request(['events','--since',String(Math.floor(submitted/1000)),'--until',String(time/1000),
          '--filter','type=container','--filter',`container=${before.Id}`,'--format','{{json .}}'],p.connection.options,'STOP_EVENTS_FAILED',10000);
        need(Buffer.byteLength(text)<=65536,'EVENT_LIMIT');const rows=text.trim().split('\n').filter(Boolean).map(s=>JSON.parse(s));
        need(rows.length<=32,'EVENT_COUNT');events=rows.filter(e=>['kill','die'].includes(e.Action)).map(e=>({action:e.Action,id:e.Actor?.ID,signal:e.Actor?.Attributes?.signal??null,exit:e.Actor?.Attributes?.exitCode??null,time:e.time}));
      }
      // Normalize only after exit-zero dispatch, same stopped-instance proof and
      // allowed informational stdout. The classifier still requires 137 event proof.
      const result=classifyStatelessGatewayStop({before,after,stopOutput:before.Id,events,daemonSubmittedMs:submitted,writers:['web','api','worker'].map(n=>p.peers.get(n)),drain:p.drain});
      save(p,'stop-'+name+'-proof.json',{role:name,id:after.Id,...result});
    }
    p.peers.set(name,after);if(name==='api')p.apiReady=false;save(p,'stop-'+name+'-complete.json',{id:after.Id,exit:after.State.ExitCode,startedAt:after.State.StartedAt,finishedAt:after.State.FinishedAt});await boundary(p);
  }
  async function fenceAdmissions(ctx) {
    const p=contextPlan(ctx);need(p.mode==='app'&&p.phase==='recovery','FENCE_STAGE');p.phase='fencing';p.mutated=true;
    await stop(p,'web');await stop(p,'api');await waitForIdle(ctx);await stop(p,'worker');
    p.phase='fenced';save(p,'fenced.json',{writers:['web','api','worker'],drain:p.drain});return {fenced:true};
  }
  async function backupHelper(p,phase,work,{purpose='backup',image=p.before.images.api}={}) {
    await boundary(p);const name=`${PROJECT}-llm-${p.nonce}-${phase}`;
    save(p,'helper-'+phase+'-submission.json',{name,image:image.Id,purpose});
    const helperId=(await request(reservationPublicLlmHelperArguments(name,image.Id,purpose),p.connection.options,'HELPER_CREATE_FAILED')).trim();need(id(helperId),'HELPER_ID');
    save(p,'helper-'+phase+'-created.json',{id:helperId});let authority,epoch,latest;
    const check=async state=>{
      guard(p);const expected=[...p.peers.values()],rows=JSON.parse(await request(['container','inspect',helperId,...expected.map(c=>c.Id)],p.connection.options,'HELPER_BATCH_INSPECT_FAILED'));
      need(rows.length===expected.length+1&&new Set(rows.map(c=>c.Id)).size===rows.length,'HELPER_BATCH_CARDINALITY');
      const c=rows.find(c=>c.Id===helperId);need(c,'HELPER_MISSING');validateReservationPublicLlmHelper(c,name,image,purpose,state);
      // Observed helper create/start transition: false -> null; strict policy above permits only these values.
      need([null,false].includes(c.HostConfig.OomKillDisable),'HELPER_OOM_POLICY');
      const ctl=control(c);ctl.HostConfig={...ctl.HostConfig,OomKillDisable:false};
      if(authority)need(equal(ctl,authority),'HELPER_CONTROL_CHANGED');else authority=ctl;
      if(state==='running'){const e=[c.State.StartedAt,c.State.Pid,c.RestartCount];if(epoch)need(equal(e,epoch),'HELPER_EPOCH_CHANGED');else epoch=e;}
      if(state==='exited')need(c.State.ExitCode===0&&c.State.StartedAt===epoch[0],'HELPER_EXIT_INVALID');
      for(const previous of expected){const current=rows.find(c=>c.Id===previous.Id);need(current&&equal(control(current),control(previous))&&equal(processState(current),processState(previous)),'PEER_CHANGED_DURING_EXPORT');
        const a=p.authorities.get(role(current));validatePublicLlmContainer(current,role(current),a.model.services[role(current)],p.images[role(current)],a.model,{images:p.images,...(p.jwt?{secret:p.jwt.bytes.toString()}: {})},a.selection);assertCommand(current);need(!p.apiReady||role(current)!=='api'||healthy(current),'API_HEALTH_LOST_DURING_EXPORT');}
      for(const m of c.Mounts.filter(m=>m.Type==='volume'))need(p.before.volumes.some(v=>v.Name===m.Name&&v.Mountpoint===m.Source&&m.Driver==='local'),'HELPER_VOLUME_CHANGED');
      latest=c;guard(p);
    };
    await check('created');await boundary(p,latest);const created=latest;
    save(p,'helper-'+phase+'-start-submission.json',{id:helperId});
    const startOutput=await request(['container','start',helperId],p.connection.options,'HELPER_START_FAILED');
    const startObservation=lifecycleObservation(startOutput,created);
    save(p,'helper-'+phase+'-start-observation.json',startObservation);
    await check('running');
    need(latest.State.StartedAt!==created.State.StartedAt&&Date.parse(latest.State.StartedAt)>0,'HELPER_START_NOT_PROVEN');
    requireLifecycleOutput(startObservation,'HELPER_START_OUTPUT');await boundary(p,latest);
    const end=now()+120000;let receipt;
    do{await check('running');receipt=JSON.parse(await request(['container','exec',helperId,'node','-e',READY_FILE_PROBE],p.connection.options,'HELPER_READY_FAILED',5000));
      need(now()<end,'HELPER_READY_TIMEOUT');if(receipt.ready===true)break;need(equal(receipt,{}),'HELPER_NOT_READY');await sleep(500);
    }while(true);
    const result=await work(helperId,args=>{guard(p);return request(args,p.connection.options,'SNAPSHOT_EXPORT_FAILED');},()=>check('running'),receipt);
    await check('running');await boundary(p,latest);save(p,'helper-'+phase+'-stop-submission.json',{id:helperId});
    const stopOutput=await request(['container','stop','--timeout','10',helperId],p.connection.options,'HELPER_STOP_FAILED',20000);
    const stopObservation=lifecycleObservation(stopOutput,latest);
    save(p,'helper-'+phase+'-stop-observation.json',stopObservation);
    await check('exited');requireLifecycleOutput(stopObservation,'HELPER_STOP_OUTPUT');await boundary(p,latest);
    save(p,'helper-'+phase+'-remove-submission.json',{id:helperId,exit:0});
    const removeOutput=await request(['container','rm',helperId],p.connection.options,'HELPER_REMOVE_FAILED');
    const removeObservation=lifecycleObservation(removeOutput,latest);
    save(p,'helper-'+phase+'-remove-observation.json',removeObservation);
    // A failed inspect is not absence. Require a successful, exact namespace census.
    const inventory=(await request(['container','ls','--all','--filter',`label=com.docker.compose.project=${PROJECT}`,
      '--format','{{.ID}}','--no-trunc'],p.connection.options,'HELPER_REMOVE_CENSUS_FAILED')).trim().split('\n').filter(Boolean).sort();
    need(!inventory.includes(helperId)&&equal(inventory,[...p.peers.values()].map(c=>c.Id).sort()),'HELPER_REMOVE_NOT_PROVEN');
    requireLifecycleOutput(removeObservation,'HELPER_REMOVE_OUTPUT');await boundary(p);
    save(p,'helper-'+phase+'-complete.json',{id:helperId,exit:0,removed:true,namespaceVerified:true});return result;
  }
  async function snapshot(ctx) {
    const p=contextPlan(ctx);need(p.phase==='fenced','SNAPSHOT_STAGE');
    const directory=join(p.audit,'snapshots');fs.mkdirSync(directory,{mode:0o700});syncDirectory(p.audit);
    p.snapshots=createAdapterSnapshots({DB:database(),directory,helper:(phase,work)=>backupHelper(p,phase,work),guard:()=>guard(p),record:p.record,
      historyVersion:p.historyVersion,migrateHistory:p.historyMigration!=='none'});
    p.baseline=await p.snapshots.capture('fenced');assertFourStoreTransition(p.baseline,p.baseline);p.phase='snapshotted';
    return {durable:true,attempt:p.nonce,stores:structuredClone(p.baseline)};
  }
  async function qualifyState(ctx) {
    const p=contextPlan(ctx);need(p.phase==='snapshotted'&&ctx.snapshot?.attempt===p.nonce&&ctx.expectedMigration===p.migration,'QUALIFICATION_STAGE');
    await boundary(p);p.snapshots.verify();const dir=join(p.audit,'snapshots/fenced');

    const environment=Object.fromEntries(['AUTH_ORIGIN','AUTH_ALLOW_INSECURE_LOCAL_HTTP','SCAN_BROWSER_ALLOWED_USER_IDS','SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS'].map(k=>[k,p.next.services.api.environment[k]]));
    p.auth=qualifyAdapterAuthCopy(root,{DB:database(),snapshotPath:join(dir,'core/auth.sqlite'),environment,migrate:p.migration});
    need(p.auth.before===p.baseline.core.auth.logicalSha256&&(p.auth.migration==='auth-a2-to-a3')===p.migration,'AUTH_COPY_EXPECTATION');
    const stores=qualifyAdapterStoreCopies({root,DB:database(),directory:dir,environment:p.config.next.environment,baseline:p.baseline,verify:()=>p.snapshots.verify(),migrateHistory:p.historyMigration!=='none'});
    p.expectedHistory=stores.historyProof;
    p.snapshots.verify();save(p,'qualification.json',{auth:p.auth,...stores,liveMigration:false});p.phase='qualified';return {qualified:true,migration:p.migration,historyMigration:p.historyMigration};
  }
  function recoveryFileSet(p) {
    const files=['profile.json','llm-profile.json','compose.images.json','compose.llm-env.json',...(p.config.profile.cve?['compose.cve.json']:[])];
    const state=join(root,STATE), history=[];
    // Metadata-only historical identities: old records may contain image Config.Env.
    // Never reserialize or hash that content into a recovery checkpoint.
    const walk=(path,relative,depth=0)=>{
      need(depth<=6&&history.length<4096,'RECOVERY_HISTORY_LIMIT');const s=fs.lstatSync(path);
      need(!s.isSymbolicLink()&&s.uid===process.getuid(),'RECOVERY_HISTORY_OWNER');
      if(s.isDirectory()){
        need((s.mode&0o7777)===0o700,'RECOVERY_HISTORY_MODE');
        const names=fs.readdirSync(path).filter(n=>relative===RECORDS?n!==p.nonce:true).sort();
        history.push({path:relative,dev:s.dev,ino:s.ino,mode:s.mode,names});
        for(const n of names){need(/^[a-zA-Z0-9_.-]{1,100}$/.test(n),'RECOVERY_HISTORY_NAME');walk(join(path,n),relative+'/'+n,depth+1);}
      }else{
        need(s.isFile()&&s.nlink===1&&(s.mode&0o7777)===0o600,'RECOVERY_HISTORY_FILE');
        history.push({path:relative,stamp:[s.dev,s.ino,s.uid,s.mode,s.nlink,s.size,s.mtimeMs,s.ctimeMs]});
      }
    };
    // Catalog paths are established by its strict parser; include ancestor names/identities.
    const roots=new Set([RECORDS,...p.catalog.entries.map(e=>e.path.slice(state.length+1).split('/')[0])]);
    for(const name of [...roots].sort()) if(exists(join(state,name)))walk(join(state,name),name);
    return {config:Object.fromEntries(files.map(n=>[n,deploymentFileIdentity(join(state,n))])),
      jwt:deploymentFileIdentity(join(state,'scan-jwt'),{secret:true}),history,
      catalog:{active:p.catalog.active,archived:p.catalog.archived,records:p.catalog.records},
      references:p.history.references};
  }
  function operationIdentity(path) {
    const s=fs.lstatSync(path);protectedDirectory(path);
    return {dev:s.dev,ino:s.ino,owner:deploymentFileIdentity(join(path,'deploy-adapter-owner.json'))};
  }
  async function checkpointPrestart(p) {
    need(p.historyMigration==='history-reservations-v4-to-v5'&&p.postMigration&&p.historyProof,'PRESTART_MIGRATION_PROOF');
    await boundary(p);p.snapshots.verify();
    need(['web','api','worker'].every(n=>cleanStopped(p.peers.get(n))),'PRESTART_WRITERS');
    const authority=deploymentAuthority(await namespace(p.config,p.connection,p));
    const initial=JSON.parse(captureFile(join(p.audit,'authority-v3.json'),{limit:262144}).bytes);
    const files=recoveryFileSet(p);need(equal(files,initial.files),'PRESTART_FILE_DRIFT');
    const lease=ownedLease(p.lease),engine=engineJournal.checkpoint();
    const evidence=evidenceIndex(p.audit).filter(e=>e.path!=='engine.jsonl');
    save(p,'history-v5-prestart.json',{version:3,kind:'history-v5-prestart',project:PROJECT,nonce:p.nonce,
      supervisor:{identity:lease.supervisor.identity,session:lease.supervisor.session},operation:operationIdentity(p.lock.path),daemon:p.connection.initial,
      source:digest(JSON.stringify(p.source.manifest.files.map(f=>({path:f.path,digest:f.digest})))),
      adapter:digest(p.self.bytes),entrySources:p.entryProofs.map(f=>digest(f.bytes)),services:p.targets,
      files,authority,evidence,engine,before:p.baseline,after:p.postMigration,proof:p.historyProof});
  }
  async function ready(p,name) {
    const end=now()+120000,previousDeadline=activeDeadline;activeDeadline=Math.min(activeDeadline,end);
    try {do{await peers(p);const c=p.peers.get(name);
      const rows=JSON.parse(await request(['container','inspect',c.Id],p.connection.options,'READINESS_INSPECT_FAILED'));need(rows.length===1,'READINESS_CARDINALITY');const current=rows[0];
      need(equal(control(current),control(c))&&equal(processState(current),processState(c)),'READINESS_EPOCH_CHANGED');
      if(name==='worker'||name==='api'&&current.State.Health?.Status==='healthy'){
        const gateway=name==='api'?PUBLIC_LLM_GATEWAY_PROBE+PUBLIC_LLM_GATEWAY_PROBE.replaceAll('llmGateway','openAiGateway').replaceAll('connectLlmGateway','connectOpenAiGateway').replaceAll('llm-egress','openai-egress'):'';
        const worker=name==='worker'&&p.authorities.get(name).selection.operations?`import * as z from 'node:zlib';import {PUBLIC_IMAGE_RESOURCE_POLICY as policy,PUBLIC_IMAGE_CHECKS_VERSION as checks,PUBLIC_IMAGE_LIMITS as limits} from './src/oci/public-image-policy.ts';import {publicResourceEnvelope} from './src/worker/worker-runtime.ts';if(typeof z.createZstdDecompress!=='function'||policy!=='public-hub-resources-v2'||checks!=='trivy-0.69.3-public-archive-v2'||limits.compressedLayer!==256*1024**2||limits.compressedTotal!==768*1024**2||limits.wireBytes!==800*1024**2||limits.expandedLayer!==512*1024**2||limits.expandedTotal!==1024**3||limits.scratchBytes!==2*1024**3||limits.deadlineMs!==180000||!publicResourceEnvelope())throw Error('RESOURCE_CONTRACT');`:'';
                const program=worker+gateway+(p.config.profile.cve?cveReadyProbe():ADAPTER_READY_PROBE);
        const r=JSON.parse(await request(['container','exec',current.Id,'node','--import','tsx','--input-type=module','-e',program],p.connection.options,'READINESS_EXEC_FAILED',15000));
        if(r.ready===true){if(p.config.profile.cve)need(r.manifest===p.config.profile.cve.manifestDigest&&r.bundle===p.config.profile.cve.artifactSha256,'READINESS_CVE_BINDING');return;}
        need(equal(r,{ready:false,reason:'CHAIN_NOT_READY'}),'READINESS_FATAL');
      }
      need(now()<end,'READINESS_DEADLINE');await sleep(500);
    }while(true);}finally{activeDeadline=previousDeadline;}
  }
  async function startService(p,name,{old=false}={}) {
    await boundary(p);const previous=p.peers.get(name),replace=p.targets.includes(name);
    need(replace||cleanStopped(previous),'RESUME_REQUIRES_CLEAN_STOP');
    save(p,(old?'restore-':'start-')+name+'-submission.json',{role:name,previous:previous.Id,image:(old?p.before.images:p.candidateImages)[name].Id,recreate:replace});
    p.pending={name,previous,old,settled:false};let resumeObservation;
    if(replace){const recipePath=old?p.oldRecipe:p.newRecipe;
      await request(compose(p,recipePath,['up','-d','--no-deps','--no-build','--pull','never','--force-recreate',name]),
        {...p.connection.options,env:{...p.connection.options.env,SCAN_JWT_SECRET:p.jwt?.bytes.toString()??CONFIG_SECRET}},'SERVICE_RECREATE_FAILED',120000);
    }else {
      const output=await request(['container','start',previous.Id],p.connection.options,'SERVICE_RESUME_FAILED');
      resumeObservation=lifecycleObservation(output,previous);
      save(p,'start-'+name+'-observation.json',{role:name,...resumeObservation});
    }
    p.pending.settled=true;
    // Unchanged resumed peers retain their original model, even during a mixed old/new transition.
    let current;
    if(replace)current=await inspectChanged(p,name,previous,{recreated:true,old});
    else {const rows=JSON.parse(await request(['container','inspect',previous.Id],p.connection.options,'SERVICE_RESUME_INSPECT_FAILED'));need(Array.isArray(rows)&&rows.length===1,'SERVICE_RESUME_CARDINALITY');current=rows[0];
      need(equal(control(previous),control(current))&&current.State.Running===true&&current.State.Status==='running'&&
        Number.isSafeInteger(current.State.Pid)&&current.State.Pid>0&&current.State.StartedAt!==previous.State.StartedAt&&Date.parse(current.State.StartedAt)>0&&
        current.RestartCount===0&&!current.State.OOMKilled&&!current.State.Paused&&!current.State.Dead&&!current.State.Restarting&&!current.State.Error,'RESUME_IDENTITY');
      requireLifecycleOutput(resumeObservation,'SERVICE_START_OUTPUT');}
    p.peers.set(name,current);if(replace){p.images[name]=(old?p.before.images:p.candidateImages)[name];p.authorities.set(name,{model:old?p.config.model:p.next,selection:old?p.config.selection:p.config.next});}
    p.pending=null;save(p,(old?'restore-':'start-')+name+'-complete.json',{role:name,id:current.Id,image:current.Image,startedAt:current.State.StartedAt});await boundary(p);
    if(['api','worker'].includes(name)){await ready(p,name);if(name==='api')p.apiReady=true;}
  }
  async function switchServices(ctx) {
    const p=contextPlan(ctx);need(ctx.recovery?.attempt===p.nonce,'RECOVERY_NOT_OWNED');
    if(p.mode==='web'){need(p.phase==='recovery','WEB_SWITCH_STAGE');await stable(p);p.mutated=true;p.phase='switching';await startService(p,'web');}
    else {need(p.phase==='qualified'&&ctx.qualification?.qualified===true&&ctx.migrationAttempted===p.migration&&
      ctx.historyMigrationAttempted===(p.historyMigration!=='none'),'APP_SWITCH_STAGE');p.phase='switching';
      if(p.historyMigration!=='none') {
        need(p.historyConsent===true&&ctx.options?.migrateHistoryV4ToV5===true&&p.expectedHistory&&['web','api','worker'].every(n=>cleanStopped(p.peers.get(n))),'HISTORY_MIGRATION_NOT_AUTHORIZED');
        await boundary(p);p.snapshots.verify();p.historyMigrationAttempted=true;
        save(p,'history-migration-intent.json',{version:1,migration:p.historyMigration,from:4,to:5,candidateImage:p.candidateImages.api.Id,
          source:digest(JSON.stringify(p.source.manifest.files.map(f=>({path:f.path,digest:f.digest})))),baseline:p.baseline,expected:p.expectedHistory,
          recovery:'guarded-hold-no-old-binary-or-stale-restore'});
        await backupHelper(p,'migrate-history-v4-to-v5',async (_id,_dispatch,check,receipt)=>{
          await check();need(equal(receipt,{ready:true,migration:p.historyMigration,from:4,to:5}),'HISTORY_MIGRATION_RECEIPT');
        },{purpose:'migrate-history-v4-to-v5',image:p.candidateImages.api});
        const after=await p.snapshots.capture('post-migration');
        const proof=qualifyAdapterHistoryMigration({DB:database(),before:p.baseline,after,beforeDirectory:join(p.audit,'snapshots/fenced'),afterDirectory:join(p.audit,'snapshots/post-migration')});
        need(equal(proof,p.expectedHistory),'HISTORY_MIGRATION_EXPECTATION');p.historyProof=proof;p.postMigration=after;
        save(p,'history-migration-complete.json',{version:1,proof,candidateImage:p.candidateImages.api.Id,before:p.baseline,after});
        await checkpointPrestart(p);
      }
      await forwardApp(p);
    }p.phase='switched';return {switched:true};
  }
  async function forwardApp(p) {
    const baseline=p.postMigration??p.baseline;
    for(const n of ['egress','llm-egress','openai-egress'].filter(n=>p.targets.includes(n))){await stop(p,n);await startService(p,n);}
    await startService(p,'worker');const beforeApi=await p.snapshots.capture('before-api');assertFourStoreTransition(baseline,beforeApi);
    await startService(p,'api');const afterApi=await p.snapshots.capture('after-api');assertFourStoreTransition(baseline,afterApi,p.auth);p.after=afterApi;
    save(p,'preservation.json',{version:2,before:p.baseline,postMigration:p.postMigration??null,historyProof:p.historyProof??null,after:afterApi,auth:p.auth,allFourStores:true});
    await startService(p,'web');
  }
  async function health(ctx) {
    const p=contextPlan(ctx);need(['switched','restored'].includes(p.phase),'HEALTH_STAGE');await boundary(p);
    const rows=JSON.parse(await request(['container','inspect',...[...p.peers.values()].map(c=>c.Id)],p.connection.options,'FINAL_HEALTH_INSPECT_FAILED'));
    need(rows.length===p.peers.size&&new Set(rows.map(c=>c.Id)).size===rows.length&&equal(rows.map(c=>c.Id).sort(),[...p.peers.values()].map(c=>c.Id).sort())&&rows.filter(c=>!role(c).endsWith('volume-init')).every(healthy),'FINAL_HEALTH_INVALID');
    for(const [path,status]of [['/',200],['/api/v1/auth/me',401],['/api/v1/browser/scans/00000000-0000-0000-0000-000000000000/llm/readiness',401]]){
      guard(p);const r=await http(ORIGIN+path,{redirect:'error',signal:AbortSignal.timeout(5000)});await r.body?.cancel();need(r.status===status,'HTTP_READINESS_FAILED');}
    if(p.mode==='app'){p.snapshots.verify();assertFourStoreTransition(p.postMigration??p.baseline,p.after,p.auth);}await boundary(p);
    p.healthTarget=ctx.target;p.phase=ctx.target==='old'?'restored-healthy':'healthy';return {healthy:true};
  }
  async function publishReceipt(ctx) {
    const p=contextPlan(ctx);need(p.phase==='healthy'&&ctx.publishAttempted===true&&ctx.receipt?.historyMigration===p.historyMigration,'PUBLICATION_STAGE');await boundary(p);
    if(p.mode==='app'){p.snapshots.verify();assertFourStoreTransition(p.postMigration??p.baseline,p.after,p.auth);}
    p.phase='publishing';
    const pins={services:Object.fromEntries([...p.peers].map(([name,c])=>[name,{image:c.Image}]))};
    const outputs=[['compose.images.json',pins],...(p.mode==='app'?[['compose.llm-env.json',publicLlmEnvironmentOverlay(p.config.next)],['llm-profile.json',p.config.next]]:[])];
    save(p,'publication-submission.json',{version:2,targets:outputs.map(([name])=>name),pins});
    for(const [name,value]of outputs){guard(p);const path=join(root,STATE,name),pending=join(root,STATE,'.adapter-pending-'+name);
      need(!exists(pending),'PUBLICATION_PENDING_PRESENT');writeExclusive(pending,JSON.stringify(value),0o600);fs.renameSync(pending,path);syncDirectory(join(root,STATE));
      // Rebind just this intentional replacement; all other protected files keep their original byte fences.
      p.config.rebind(name);
    }
    p.config=loadConfiguration(root,home,false);need(equal(p.config.selection,p.nextSelection??p.authorities.get('api').selection),'PUBLISHED_SELECTION_MISMATCH');
    await boundary(p);need(ctx.receipt?.healthy===true&&typeof ctx.receipt.verified==='boolean'&&Number.isFinite(Date.parse(ctx.receipt.completedAt)),'RECEIPT_INVALID');
        save(p,'published.json',{version:2,project:PROJECT,nonce:p.nonce,mode:p.mode,services:p.targets,interruptedServices:p.token.interruptedServices,
          migration:p.migration,historyMigration:p.historyMigration,historyProof:p.historyProof??null,verified:ctx.receipt.verified,healthy:true,completedAt:ctx.receipt.completedAt,pins,stores:p.after??null});p.phase='published';return {published:true};
  }
  async function reconcileWebRollback(p) {
    guard(p);const identified=p.webCandidate;
    need(identified&&identified.Image===p.candidateImages.web.Id,'WEB_CANDIDATE_NOT_IDENTIFIED');
    if(p.pending)need(p.pending.name==='web'&&p.pending.old===false&&p.pending.settled===true&&p.pending.identified===identified.Id&&
      p.pending.previous.Id===p.before.containers.find(c=>role(c)==='web').Id,'WEB_DISPATCH_UNCERTAIN');
    else need(p.peers.get('web').Id===identified.Id,'WEB_REGISTERED_CANDIDATE_CHANGED');
    const rows=JSON.parse(await request(['container','inspect',identified.Id],p.connection.options,'WEB_ROLLBACK_INSPECT_FAILED'));
    need(Array.isArray(rows)&&rows.length===1,'WEB_ROLLBACK_CARDINALITY');const current=rows[0];
    need(current.Id===identified.Id&&equal(control(current),control(identified))&&current.Created===identified.Created&&
      current.State.StartedAt===identified.State.StartedAt&&current.RestartCount===0&&!current.State.OOMKilled&&
      !current.State.Paused&&!current.State.Dead&&!current.State.Restarting&&!current.State.Error,'WEB_ROLLBACK_IDENTITY_CHANGED');
    validatePublicLlmContainer(current,'web',p.next.services.web,p.candidateImages.web,p.next,{images:p.candidateImages},p.config.next);assertCommand(current);
    const exited=current.State.Running===false&&current.State.Status==='exited'&&current.State.Pid===0&&
      Number.isInteger(current.State.ExitCode)&&current.State.ExitCode>=0&&current.State.ExitCode<=255&&
      Date.parse(current.State.FinishedAt)>=Date.parse(current.State.StartedAt);
    need(healthy(current)||exited,'WEB_ROLLBACK_STATE_UNSAFE');
    // Only the identified web's running -> exited transition can be reconciled.
    // All backend controls/epochs, ownership, namespaces, mounts and source fences stay exact.
    need(equal(processState(current),processState(identified))&&current.State.ExitCode===identified.State.ExitCode||
      identified.State.Running===true&&identified.State.Status==='running'&&exited,'WEB_ROLLBACK_EPOCH_CHANGED');
    const reconciled={...p,peers:new Map(p.peers),images:{...p.images,web:p.candidateImages.web},authorities:new Map(p.authorities)};
    reconciled.peers.set('web',current);reconciled.authorities.set('web',{model:p.next,selection:p.config.next});
    await boundary(reconciled);guard(p);
    save(p,'web-rollback-reconciled.json',{id:current.Id,image:current.Image,created:current.Created,startedAt:current.State.StartedAt,
      status:current.State.Status,finishedAt:current.State.FinishedAt,exitCode:current.State.ExitCode,composeSettled:true});
    p.peers=reconciled.peers;p.images=reconciled.images;p.authorities=reconciled.authorities;p.pending=null;
  }
  async function restoreOld(ctx) {
    const p=contextPlan(ctx);need(p.mode==='web'&&p.mutated&&!ctx.publishAttempted&&ctx.recovery?.attempt===p.nonce&&
      ['switching','switched'].includes(p.phase),'WEB_RESTORE_STAGE');
    await reconcileWebRollback(p);p.phase='restoring';await startService(p,'web',{old:true});p.phase='restored';return {restored:true};
  }
  async function release(ctx) {
    const state=ownedLease(ctx.lease),p=state.plan;
    need(!ctx.publishAttempted||p?.phase==='published','PUBLICATION_HOLD');
    need(!ctx.fenceAttempted||p?.phase==='published','APP_FENCE_HOLD');
    need(!ctx.switchAttempted||['published','restored-healthy'].includes(p?.phase),'SWITCH_HOLD');
    if(p){if(p.mutated)await boundary(p);else await stable(p);}
    state.proofs.forEach(f=>f.verify());state.engineJournal?.checkpoint();
    // Partial/uncertain image builds cannot be represented as a completed deployment.
    need(!p||!['building','hold'].includes(p.phase),'BUILD_HOLD');
    const references=Object.entries(p?.candidates??{}).flatMap(([name,r])=>[{name,tag:r.tag,image:r.image},{name,tag:r.oldTag,image:r.oldImage}]);
    state.record('complete.json',{version:2,project:PROJECT,nonce:state.nonce,outcome:p?.phase==='published'?'published':p?.phase==='restored-healthy'?'old-restored':'pre-mutation-aborted',references,evidence:evidenceIndex(state.audit)});
    ownedLease(ctx.lease);need(!exists(join(state.audit,'operation.lock')),'LOCK_ARCHIVE_COLLISION');
    fs.renameSync(state.lock.path,join(state.audit,'operation.lock'));syncDirectory(state.audit);syncDirectory(join(root,STATE));state.released=true;leaseDeadline=null;engineJournal=null;return {released:true};
  }
  async function readRecovery(options, supervisor = null) {
    rootCheck();need(engineJournal===null,'RECOVERY_FRESH_EXECUTOR_REQUIRED');
    need(/^[a-f0-9]{32}$/.test(options?.audit??''),'RECOVERY_EXACT_AUDIT_REQUIRED');
    const nonce=options.audit,audit=join(root,STATE,RECORDS,nonce),lockPath=join(root,STATE,'.operation.lock');
    const auditGuard=protectedDirectory(audit),lockGuard=protectedDirectory(lockPath);
    const owner=captureFile(join(lockPath,'deploy-adapter-owner.json'));
    need(equal(JSON.parse(owner.bytes),{version:2,nonce,kind:'preserving-deployment'})&&equal(fs.readdirSync(lockPath),['deploy-adapter-owner.json']),'RECOVERY_OWNER_MISMATCH');
    need(!exists(join(audit,'recovery-v5'))&&!exists(join(audit,'complete.json')),'RECOVERY_ALREADY_ATTEMPTED');
    const checkpoint=captureFile(join(audit,'history-v5-prestart.json'),{limit:262144});
    const cp=JSON.parse(checkpoint.bytes),checkpointDigest=digest(checkpoint.bytes);
    need(cp.version===3&&cp.kind==='history-v5-prestart'&&cp.project===PROJECT&&cp.nonce===nonce,'RECOVERY_CHECKPOINT_REQUIRED');
    need(options.checkpoint===undefined||options.checkpoint===checkpointDigest,'RECOVERY_CHECKPOINT_MISMATCH');
    need(!options.apply||options.checkpoint===checkpointDigest,'RECOVERY_CHECKPOINT_SELECTION_REQUIRED');
    need(equal(operationIdentity(lockPath),cp.operation),'RECOVERY_LOCK_IDENTITY');
    const osIdentity=supervisor?supervisor.identity:inspectDeploySupervisor(root);
    need(equal(osIdentity,cp.supervisor.identity)&&(!supervisor||supervisor.session!==cp.supervisor.session),'RECOVERY_SUPERVISOR_IDENTITY');
    const names=fs.readdirSync(audit).sort();
    need(!names.some(n=>/^(start-|restore-|publication-|published|preservation|complete)/.test(n)),'RECOVERY_NOT_PRESTART');
    const journal=readEngineJournal(join(audit,'engine.jsonl'));
    need(Number.isSafeInteger(cp.engine.count)&&cp.engine.count>0&&cp.engine.count<=journal.count&&
      Number.isSafeInteger(cp.engine.bytes)&&journal.ends[cp.engine.count-1]===cp.engine.bytes&&
      digest(journal.bytes.subarray(0,cp.engine.bytes))===cp.engine.sha256,'RECOVERY_ENGINE_PREFIX');
    // Between the B1 checkpoint and the first durable start intent the original
    // executor may only finish read-only boundary inspections. Even a settled
    // unexpected dispatch is not permission to enter the prestart branch.
    const prestartReads=new Set(['PEER_INSPECT_FAILED','CONTAINER_INSPECT_FAILED','CONTAINER_CENSUS_FAILED',
      'CONTAINER_NAME_CENSUS_FAILED','IMAGE_INSPECT_FAILED','NETWORK_CENSUS_FAILED','NETWORK_INSPECT_FAILED',
      'VOLUME_INSPECT_FAILED','VOLUME_CONSUMERS_FAILED','DOCKER_INFO_FAILED','RETAINED_IMAGE_INSPECT_FAILED','IMAGE_REFERENCE_CENSUS_FAILED']);
    need(journal.codes.slice(cp.engine.count).every(code=>prestartReads.has(code)),'RECOVERY_POST_CHECKPOINT_DISPATCH');
    const evidence=evidenceIndex(audit).filter(e=>!['engine.jsonl','history-v5-prestart.json','failure-switchservices.json'].includes(e.path));
    need(equal(evidence,cp.evidence),'RECOVERY_EVIDENCE_DRIFT');
    const originalEvidence=evidenceIndex(audit),proofs=[owner,checkpoint];
    const read=name=>{const f=captureFile(join(audit,name),{limit:262144});proofs.push(f);return JSON.parse(f.bytes);};
    const authority=read('authority-v3.json'),intent=read('intent.json'),recovery=read('recovery.json'),built=read('built.json');
    const completion=read('history-migration-complete.json'),migration=read('history-migration-intent.json');
    need(equal(read('lease.json'),{version:2,project:PROJECT,nonce})&&
      equal(read('supervisor.json'),{version:1,session:cp.supervisor.session,identity:cp.supervisor.identity})&&
      /^[a-f0-9]{64}$/.test(cp.supervisor.session),'RECOVERY_ORIGINAL_SUPERVISOR');
    need(authority.version===3&&authority.project===PROJECT&&authority.nonce===nonce&&equal(authority.supervisor,cp.supervisor.identity)&&equal(authority.files,cp.files),'RECOVERY_PROSPECTIVE_AUTHORITY');
    need(intent.kind==='preserving-deployment'&&intent.nonce===nonce&&intent.mode==='app'&&recovery.nonce===nonce&&recovery.migration===false&&
      recovery.historyVersion===4&&recovery.historyMigration==='history-reservations-v4-to-v5','RECOVERY_SCOPE');
    const targets=deploymentTargets('app',cp.services);need(targets.every(n=>['web','api'].includes(n))&&equal(targets,intent.services)&&equal(targets,recovery.services),'RECOVERY_TARGET_SCOPE');
    need(built.nonce===nonce&&built.outcome==='candidate-built-old-site-unchanged'&&equal(Object.keys(built.candidates).sort(),targets),'RECOVERY_CANDIDATES');
    need(equal(completion.before,cp.before)&&equal(completion.after,cp.after)&&equal(completion.proof,cp.proof)&&cp.before.historyVersion===4&&cp.after.historyVersion===5&&
      migration.from===4&&migration.to===5&&migration.migration===recovery.historyMigration&&equal(migration.baseline,cp.before)&&equal(migration.expected,cp.proof)&&
      completion.candidateImage===built.candidates.api.image&&migration.candidateImage===completion.candidateImage,'RECOVERY_MIGRATION_EVIDENCE');
    for(const phase of ['migrate-history-v4-to-v5','post-migration']){
      const receipt=read('helper-'+phase+'-complete.json');need(id(receipt.id)&&receipt.exit===0&&receipt.removed===true&&receipt.namespaceVerified===true,'RECOVERY_HELPER_UNSETTLED');
    }
    for(const name of ['web','api','worker']){
      const stopped=read('stop-'+name+'-complete.json'),current=cp.authority.containers.find(c=>c.role===name),original=authority.authority.containers.find(c=>c.role===name);
      need(current&&original&&stopped.id===current.Id&&current.Id===original.Id&&
        stopped.startedAt===current.process[0]&&stopped.startedAt===original.process[0]&&stopped.finishedAt===current.process[1]&&
        stopped.exit===current.process[6]&&(name==='web'?[0,143]:[0]).includes(stopped.exit),'RECOVERY_WRITER_STOP');
    }
    // Retain the exact published profile, including an existing pinned CVE binding.
    // No refresh, reprovisioning or configuration transition is part of recovery.
    const config=loadConfiguration(root,home,false);
    const next=expectedPublicLlmConfig(root,config.profile.cve,config.selection),source=capturePublicLlmSource(root,{openai:true});
    const self=captureFile(fileURLToPath(import.meta.url),{privateMode:false,limit:1024**2});
    const entryProofs=['deploy.mjs','deploy-core.mjs','deploy-adapter-stores.mjs','public-llm-stand.mjs','deploy-supervisor.mjs','deploy-authority.mjs'].map(n=>captureFile(join(root,'scripts',n),{privateMode:false,limit:1024**2}));
    const sourceDigest=digest(JSON.stringify(source.manifest.files.map(f=>({path:f.path,digest:f.digest}))));
    need(sourceDigest===cp.source&&sourceDigest===intent.source&&sourceDigest===migration.source&&digest(self.bytes)===cp.adapter&&cp.adapter===intent.adapter&&
      equal(entryProofs.map(f=>digest(f.bytes)),cp.entrySources)&&equal(cp.entrySources,intent.entrySources),'RECOVERY_SOURCE_DRIFT');
    const contract=sourceContract(root),catalog=captureDeploymentCatalog(root),retentions=capturePublicLlmRetentions(root),history=captureBuildHistory(root,nonce);
    need(contract.digest===intent.backendSource,'RECOVERY_CONTRACT_DRIFT');
    const shell={nonce,config,catalog,history};need(equal(recoveryFileSet(shell),cp.files),'RECOVERY_FILE_IDENTITY_DRIFT');
    const verifyOriginal=()=>{
      auditGuard();lockGuard();owner.verify();checkpoint.verify();proofs.forEach(f=>f.verify());
      need(equal(operationIdentity(lockPath),cp.operation),'RECOVERY_LOCK_CHANGED');
      const current=evidenceIndex(audit).filter(e=>e.path!=='recovery-v5'&&!e.path.startsWith('recovery-v5/'));
      need(equal(current,originalEvidence),'RECOVERY_ORIGINAL_EVIDENCE_CHANGED');
    };
    verifyOriginal();const connection=await connect();need(equal(connection.initial,cp.daemon)&&connection.initial.id===intent.daemon,'RECOVERY_DAEMON_CHANGED');
    const before=await namespace(config,connection);
    need(equal(deploymentAuthority(before),cp.authority),'RECOVERY_AUTHORITY_CHANGED');
    need(before.containers.filter(c=>['web','api','worker'].includes(role(c))).every(cleanStopped)&&
      before.containers.filter(c=>!['web','api','worker'].includes(role(c))&&!role(c).endsWith('volume-init')).every(healthy),'RECOVERY_PEERS_NOT_STOPPED');
    const candidateImages={...before.images};
    for(const name of targets){
      const row=built.candidates[name];need(imageId(row.image)&&row.oldImage===before.images[name].Id&&row.tag===`dip-deploy-${name}:candidate-${nonce}`&&row.oldTag===`dip-deploy-${name}:old-${nonce}`,'RECOVERY_IMAGE_BINDING');
      const images=JSON.parse(await request(['image','inspect',row.image],connection.options,'RECOVERY_IMAGE_INSPECT_FAILED'));
      need(images.length===1&&images[0].Id===row.image,'RECOVERY_IMAGE_CARDINALITY');validatePublicLlmImage(images[0],name);assertNoOpenAiDockerSecret(images[0].Config);candidateImages[name]=images[0];
    }
    const oldRecipe=join(audit,'recipe-old.json'),newRecipe=join(audit,'recipe-candidate.json');
    need(equal(read('recipe-old.json'),recipe(config.model,before.images))&&equal(read('recipe-candidate.json'),recipe(next,candidateImages)),'RECOVERY_RECIPE_CHANGED');
    const p={mode:'app',nonce,audit,targets,config,next,source,self,entryProofs,contract,catalog,retentions,history,connection,before,
      peers:new Map(before.containers.map(c=>[role(c),c])),authorities:new Map(before.containers.map(c=>[role(c),{model:config.model,selection:config.selection}])),
      images:{...before.images},candidateImages,candidates:built.candidates,oldRecipe,newRecipe,apiReady:false,mutated:true,
      migration:false,historyMigration:recovery.historyMigration,historyVersion:4,historyConsent:true,
      baseline:cp.before,postMigration:cp.after,auth:null,extraGuard:verifyOriginal,proofs};
    // Revalidate immutable image/config references and all protected inputs; no helper or SQL in a plan.
    await retained(p);source.verify();self.verify();entryProofs.forEach(f=>f.verify());config.verify();catalog.verify();retentions.verify();history.verify();verifyOriginal();
    need(equal(recoveryFileSet(p),cp.files),'RECOVERY_PLAN_CHANGED');
    if(!supervisor)need(equal(inspectDeploySupervisor(root),osIdentity),'RECOVERY_SUPERVISOR_CHANGED');
    return {p,cp,checkpointDigest,owner,lockGuard,auditGuard,originalAudit:audit};
  }
  async function planRecovery({options}) {
    const {p,checkpointDigest}=await readRecovery(options);
    return {eligible:true,audit:p.nonce,checkpoint:checkpointDigest,phase:'v5-committed-prestart',services:p.targets,
      currentStores:'not-inspected-requires-fresh-B1-equality-on-apply',migrationReplay:false};
  }
  async function applyRecovery({options}) {
    const supervisor=requireDeploySupervisor(root),data=await readRecovery(options,supervisor);
    const {p,cp,checkpointDigest,owner,lockGuard,originalAudit}=data;
    // Recompute the private proof from sealed B0/B1, never deserialize a trusted brand.
    p.historyProof=qualifyAdapterHistoryMigration({DB:database(),before:cp.before,after:cp.after,
      beforeDirectory:join(originalAudit,'snapshots/fenced'),afterDirectory:join(originalAudit,'snapshots/post-migration')});
    need(equal(p.historyProof,cp.proof),'RECOVERY_INDEPENDENT_PROOF');p.extraGuard();supervisor.verify();
    const audit=join(originalAudit,'recovery-v5');fs.mkdirSync(audit,{mode:0o700});syncDirectory(originalAudit);
    const auditGuard=protectedDirectory(audit),proofs=p.proofs;
    const lock={path:join(root,STATE,'.operation.lock'),verify:lockGuard};
    const record=(name,value)=>{
      supervisor.verify();lock.verify();owner.verify();auditGuard();proofs.forEach(f=>f.verify());p.extraGuard();
      need(/^[a-z][a-z0-9-]{0,79}\.json$/.test(name),'RECOVERY_RECORD_NAME');const bytes=JSON.stringify(value);need(Buffer.byteLength(bytes)<=262144,'RECOVERY_RECORD_SIZE');
      writeExclusive(join(audit,name),bytes,0o600);syncDirectory(audit);proofs.push(captureFile(join(audit,name),{limit:262144}));
    };
    record('adoption.json',{version:3,nonce:p.nonce,checkpoint:checkpointDigest,supervisor:{identity:supervisor.identity,session:supervisor.session},phase:'v5-committed-prestart'});
    engineJournal=createEngineJournal(join(audit,'engine.jsonl'),()=>{supervisor.verify();lock.verify();owner.verify();p.extraGuard();});
    const lease=Object.freeze({version:3,nonce:p.nonce,recovery:true});leaseDeadline=now()+3600000;
    const state={lock,nonce:p.nonce,audit:originalAudit,owner,proofs,supervisor,engineJournal,released:false,plan:p,
      record(name,value){need(name==='complete.json','RECOVERY_ROOT_WRITE_FORBIDDEN');p.extraGuard();supervisor.verify();writeExclusive(join(originalAudit,name),JSON.stringify(value),0o600);syncDirectory(originalAudit);}};
    leases.set(lease,state);Object.assign(p,{lease,lock,owner,record,audit,phase:'qualified'});
    const token=Object.freeze({version:3,mode:'app',services:p.targets,interruptedServices:['api','web','worker']});p.token=token;plans.set(token,p);
    p.jwt=captureFile(join(root,STATE,'scan-jwt'),{limit:96});need(/^[a-f0-9]{96}$/.test(p.jwt.bytes.toString())&&p.peers.get('api').Config.Env.includes('SCAN_JWT_SECRET='+p.jwt.bytes.toString()),'RECOVERY_JWT_BINDING');
    const ctx={options,mode:'app',services:p.targets,interruptedServices:token.interruptedServices,lease,plan:token,fenceAttempted:true,switchAttempted:true,historyMigrationAttempted:true,publishAttempted:false};
    try {
      await boundary(p);const directory=join(audit,'snapshots');fs.mkdirSync(directory,{mode:0o700});syncDirectory(audit);
      p.snapshots=createAdapterSnapshots({DB:database(),directory,helper:(phase,work)=>backupHelper(p,phase,work,{image:p.candidateImages.api}),guard:()=>guard(p),record,historyVersion:5,migrateHistory:false});
      const fresh=await p.snapshots.capture('fenced');assertFourStoreTransition(p.postMigration,fresh);save(p,'current-b1-equality.json',{version:1,stores:fresh});
      p.phase='switching';await forwardApp(p);p.phase='switched';await health({...ctx,target:'candidate'});
      ctx.receipt={version:1,mode:'app',services:p.targets,interruptedServices:token.interruptedServices,migration:false,historyMigration:p.historyMigration,
        verified:false,healthy:true,completedAt:new Date().toISOString()};ctx.publishAttempted=true;
      await publishReceipt(ctx);await release(ctx);
      return {recovered:true,audit:p.nonce,checkpoint:checkpointDigest,phase:'published',migrationReplay:false};
    }catch(error){
      try{record('failure.json',{version:1,phase:p.phase,...deployAdapterDiagnostic(error)});}catch{/* Never destroy evidence to report an error. */}
      throw error;
    }
  }
  const methods={acquireLock:acquire,releaseLock:release,
    preflight:ctx=>prepare({mode:ctx.mode,services:ctx.services,lease:ctx.lease,upgradeOperations:ctx.options?.upgradeOperations,migrateHistoryV4ToV5:ctx.options?.migrateHistoryV4ToV5}),
    build:ctx=>{contextPlan(ctx);return buildCandidate(ctx.plan);},validateCandidate:validate,
    verify:async ctx=>{const p=contextPlan(ctx);need(p.phase==='validated','VERIFY_STAGE');await stable(p);return {valid:true};},
    waitForIdle,prepareRecovery,fenceAdmissions,snapshot,qualifyState,switchServices,health,publishReceipt,restoreOld};
  return Object.freeze({capabilities:()=>DEPLOY_ADAPTER_CAPABILITIES,status:bounded(status,120000),prepare:bounded(prepare,300000),
    planRecovery:bounded(planRecovery,300000),applyRecovery:bounded(applyRecovery,1800000),
    ...Object.fromEntries(Object.entries(methods).map(([name,fn])=>[name,bounded(async ctx=>{
      try{return await fn(ctx);}catch(error){const failure=safeError('ADAPTER_'+name.toUpperCase()+'_FAILED',error);
        const p=ctx?.lease&&leases.get(ctx.lease)?.plan;
        try{p?.record('failure-'+name.toLowerCase()+'.json',deployAdapterDiagnostic(failure));}catch{/* Preserve original failure and HOLD. */}throw failure;}
    },['build','switchServices','snapshot'].includes(name)?1800000: name==='waitForIdle'?310000:300000)]))});
}
// CLI adapter: injected Docker/clock/database/http are library-only qualification seams.
// The CLI supplies options, never code or arbitrary commands.
export async function createAdapter(options = {}) {
  const adapter = createDeployAdapter(options);
  const coreError = code => { const error = new Error(code); error.code = code; return error; };
  const translate = async (work, fallback) => {
    try { return await work(); } catch (error) {
      const { code } = deployAdapterDiagnostic(error);
      const mapped = code === 'SHARED_OPERATION_HOLD' ? 'DEPLOY_LOCKED' :
        code === 'WEB_BACKEND_A3_COMPATIBILITY_UNPROVEN' ? 'DEPLOY_COMPATIBILITY' :
        ['HISTORY_MIGRATION_SCOPE','HISTORY_AUTH_MIGRATION_CONFLICT'].includes(code) ? 'DEPLOY_HISTORY_MIGRATION_SCOPE' :
        code === 'TARGETS_INVALID' || code === 'WEB_ONLY_TARGET_REQUIRED' || code === 'APP_API_REQUIRED' || code === 'OPERATIONS_UPGRADE_REQUIRES_ALL_APP_TARGETS' || code === 'OPERATIONS_FLAG_INVALID' ? 'DEPLOY_SCOPE' : fallback;
      throw coreError(mapped);
    }
  };
  const codes={planRecovery:'RECOVERY',applyRecovery:'RECOVERY',acquireLock:'LOCKED',releaseLock:'UNLOCK',preflight:'PREFLIGHT',build:'BUILD',validateCandidate:'CANDIDATE',verify:'VERIFY',
    waitForIdle:'DRAIN',prepareRecovery:'RECOVERY',fenceAdmissions:'FENCE',snapshot:'SNAPSHOT',qualifyState:'QUALIFY',switchServices:'SWITCH',health:'HEALTH',publishReceipt:'RECEIPT',restoreOld:'RESTORE'};
  return Object.freeze({
    async status() {return translate(async()=>{const r=await adapter.status();return {ready:r.services.filter(c=>!c.name.endsWith('volume-init')).every(c=>c.healthy),locked:r.hold};},'DEPLOY_STATUS');},
    ...Object.fromEntries(Object.entries(codes).map(([name,code])=>[name,ctx=>translate(()=>adapter[name](ctx),'DEPLOY_'+code)])),
  });
}
export default createDeployAdapter;
