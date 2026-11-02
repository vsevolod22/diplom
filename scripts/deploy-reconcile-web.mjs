#!/usr/bin/env node
// Explicit completion of a compensated stopped-web or fenced-writers adapter attempt.
// No Docker mutation, database access, source replacement, or automatic recovery.
import * as fs from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual as equal } from 'node:util';
import * as http from 'node:http';
import { PROJECT, STATE, LABEL, CONFIG_SECRET, readProfile, runIsolatedDocker, assertReconciliationHistory } from './public-image-stand.mjs';
import { capturePublicLlmSource, readPublicLlmBinding, expectedPublicLlmConfig, publicLlmEnvironmentOverlay,
  validatePublicLlmContainer, validatePublicLlmImage, validatePublicLlmKeyVolume, capturePublicLlmRetentions, validateCurrentAuditHistory } from './public-llm-stand.mjs';
import { captureDeploymentCatalog, DEPLOYMENT_TOTAL_LIMIT, DEPLOYMENT_RETAINED_REFERENCE_LIMIT } from './public-llm-deployment-catalog.mjs';
import { privateFile, byteFile, directoryIdentity } from './public-llm-build-continuation.mjs';
import { writeExclusive, syncDirectory } from './setup-local-cve.mjs';
import { SAFE_INSPECT, decodeInspect, restoredControl } from './deploy-reconcile-restored.mjs';
import { validateOpenAiVolume } from './public-llm-source-build.mjs';

const ROOT=dirname(dirname(fileURLToPath(import.meta.url))), SELF='scripts/deploy-reconcile-web.mjs';
const ROLES=['api','egress','llm-egress','openai-egress','web','worker'];
const ALL=[...ROLES,'auth-volume-init','scan-volume-init'].sort();
const GUARD='.recover-build-and-redeploy.lock';
const need=(v,c)=>{if(!v)throw Error('WEB_RECONCILE_'+c);};
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const image=v=>typeof v==='string'&&/^sha256:[a-f0-9]{64}$/.test(v);
const names=p=>fs.readdirSync(p).sort();
const exists=p=>fs.lstatSync(p,{throwIfNoEntry:false})!==undefined;
const canonical=v=>Array.isArray(v)?v.map(canonical):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
const hash=v=>createHash('sha256').update(typeof v==='string'||Buffer.isBuffer(v)?v:JSON.stringify(canonical(v))).digest('hex');
const stamp=s=>[s.dev,s.ino,s.uid,s.mode,s.nlink,s.size,s.mtimeMs,s.ctimeMs];
const epoch=c=>[c.Id,c.State.StartedAt,c.State.FinishedAt,c.State.Pid,c.RestartCount,c.State.Running,c.State.Status,c.State.ExitCode,c.State.Error];
const lines=s=>s.trim().split('\n').filter(Boolean).sort();

// Same representation and exclusion rules as captureBuildHistory/evidenceIndex.
// No snapshot is admissible in the attempt being reconciled. Older completed
// histories are independently byte-validated, never modified.
export function webReconcileEvidenceIndex(directory) {
  const entries=[];let total=0;
  const walk=(dir,prefix='',depth=0)=>{
    need(depth<=5,'EVIDENCE_DEPTH');directoryIdentity(dir)();
    for(const name of names(dir)){
      need(/^[a-zA-Z0-9_.-]{1,100}$/.test(name),'EVIDENCE_NAME');
      if(!prefix&&['complete.json','operation.lock'].includes(name))continue;
      const path=join(dir,name),relative=prefix+name,s=fs.lstatSync(path);
      need(!s.isSymbolicLink()&&s.uid===process.getuid(),'EVIDENCE_OWNER');
      if(s.isDirectory()){entries.push({path:relative,directory:true});walk(path,relative+'/',depth+1);continue;}
      total+=s.size;need(total<=4*1024**3&&entries.length<256,'EVIDENCE_CAPACITY');
      const proof=byteFile(path,true,{maxBytes:256*1024**2});
      entries.push({path:relative,bytes:s.size,sha256:proof.sha256});
    }
  };walk(directory);return entries;
}
export function validateWebReconcileHistory(root, exclude=null) {
  const parent=join(root,STATE,'deploy-adapter-v1'),attempts=names(parent).filter(n=>n!==exclude),proofs=[],references=[];
  need(attempts.length<DEPLOYMENT_TOTAL_LIMIT&&attempts.every(n=>/^[a-f0-9]{32}$/.test(n)),'HISTORY_CAPACITY');
  for(const nonce of attempts){
    const dir=join(parent,nonce),proof=privateFile(join(dir,'complete.json'),262144),r=JSON.parse(proof.bytes);
    need(r.version===2&&r.nonce===nonce&&r.project===PROJECT&&['published','old-restored','pre-mutation-aborted'].includes(r.outcome)&&Array.isArray(r.references)&&equal(webReconcileEvidenceIndex(dir),r.evidence),'HISTORY_INCOMPLETE');
    const owner=privateFile(join(dir,'operation.lock/deploy-adapter-owner.json'));
    need(equal(JSON.parse(owner.bytes),{version:2,nonce,kind:'preserving-deployment'})&&equal(names(join(dir,'operation.lock')),['deploy-adapter-owner.json']),'HISTORY_OWNER');
    for(const row of r.references){need(ROLES.includes(row.name)&&image(row.image)&&[`dip-deploy-${row.name}:old-${nonce}`,`dip-deploy-${row.name}:candidate-${nonce}`].includes(row.tag),'HISTORY_REFERENCE');references.push(row);}
    proofs.push(proof,owner);
  }
  need(references.length<=DEPLOYMENT_RETAINED_REFERENCE_LIMIT&&new Set(references.map(v=>v.tag)).size===references.length,'HISTORY_REFERENCE_CAPACITY');
  return {references,count:attempts.length,verify(){proofs.forEach(p=>p.verify());need(equal(names(parent).filter(n=>n!==exclude),attempts),'HISTORY_CHANGED');}};
}

export function validateWebCompensationRecords(read, listing, nonce, historicalIntent, branch='web') {
  need(['web','fenced-writers'].includes(branch),'BRANCH');
  const fenced=branch==='fenced-writers';
  const intent=read('intent.json'),recovery=read('recovery.json'),built=read('built.json'),comp=read(fenced?'compensation-old-restored.json':'compensation-web-restored.json'),submission=read(fenced?'compensation-restore-authority.json':'compensation-web-start-submission.json');
  need(intent.version===2&&intent.kind==='preserving-deployment'&&intent.project===PROJECT&&intent.nonce===nonce&&intent.mode==='app'&&intent.lifecycle===false,'INTENT');
  need([intent.source,intent.adapter,intent.backendSource,...intent.entrySources].every(hex)&&intent.entrySources.length===3,'HISTORICAL_SOURCE_BINDING');
  const targets=intent.services;
  need(Array.isArray(targets)&&targets.length>0&&targets.includes('api')&&new Set(targets).size===targets.length&&targets.every(n=>ROLES.includes(n)),'TARGETS');
  need(equal(read('lease.json'),{version:2,project:PROJECT,nonce}),'LEASE');
  need(recovery.version===2&&recovery.project===PROJECT&&recovery.nonce===nonce&&recovery.daemon===intent.daemon&&equal(recovery.services,targets)&&equal(recovery.interruptedServices,[...new Set([...targets,'web','api','worker'])].sort())&&recovery.oldRecipe==='recipe-old.json'&&recovery.candidateRecipe==='recipe-candidate.json'&&typeof recovery.migration==='boolean'&&recovery.automaticDatabaseRollback===false,'RECOVERY');
  need(equal(recovery.old.map(v=>v.role).sort(),ALL)&&new Set(recovery.old.map(v=>v.id)).size===8&&recovery.old.every(v=>hex(v.id)&&image(v.image)&&Number.isFinite(Date.parse(v.startedAt))),'OLD_IDENTITIES');
  need(equal(intent.old,targets.map(role=>{const c=recovery.old.find(v=>v.role===role);return {role,id:c.id,image:c.image};})),'OLD_INTENT');
  if(fenced)validateFencedWriterCompensation(read,listing,nonce,recovery,comp,submission);
  else {
  const expected=['lease.json','intent.json','recovery.json','recipe-old.json','recipe-candidate.json','built.json','failure-fenceadmissions.json','stop-web-submission.json','compensation-web-start-submission.json','compensation-web-restored.json',...targets.flatMap(n=>['retain-'+n+'-submission.json','build-'+n+'-submission.json','built-'+n+'.json'])].sort();
  need(equal(listing,expected),'UNEXPECTED_STAGE'); // Reject even a partial later stage.
  need(equal(read('failure-fenceadmissions.json'),{code:'STOP_OUTPUT_INVALID'}),'FAILURE_STAGE');
  const web=recovery.old.find(v=>v.role==='web');
  need(equal(read('stop-web-submission.json'),{role:'web',id:web.id,image:web.image}),'STOP_SUBMISSION');
  need(submission.version===1&&submission.nonce===nonce&&submission.operation==='start-same-old-web-only'&&submission.id===web.id&&submission.image===web.image&&submission.priorStartedAt===web.startedAt&&submission.authority==='explicit-user-restore-only'&&submission.originalStopDiagnostic==='STOP_OUTPUT_INVALID'&&submission.originalStopStdoutAvailable===false&&submission.lockRetained===true,'COMPENSATION_SUBMISSION');
  need(comp.version===1&&comp.nonce===nonce&&comp.outcome==='old-web-restored-lock-retained'&&comp.id===web.id&&comp.image===web.image&&comp.startedAt!==web.startedAt&&Number.isFinite(Date.parse(comp.startedAt))&&comp.web===200&&comp.auth===401&&comp.backendEpochsUnchanged===true&&comp.normalizedControlsMatchArchivedAuthority===true&&comp.firstPostcheck==='CONTROL_CHANGED'&&comp.startDispatchCount===1&&comp.migration===false&&comp.lockRetained===true&&comp.terminalizationAuthorized===false,'COMPENSATION_RESULT');
  need(equal(submission.backendEpochs.map(v=>v.id).sort(),recovery.old.filter(v=>v.role!=='web').map(v=>v.id).sort()),'BACKEND_EPOCHS');
  for(const p of submission.backendEpochs){const old=recovery.old.find(v=>v.id===p.id);need(p.epoch.length===9&&p.epoch[0]===old.id&&p.epoch[1]===old.startedAt,'BACKEND_EPOCH_BINDING');}
  }
  need(built.version===1&&built.nonce===nonce&&built.outcome==='candidate-built-old-site-unchanged'&&built.lifecycle===false&&equal(Object.keys(built.candidates).sort(),[...targets].sort()),'BUILT');
  const references=[];
  for(const name of targets){
    const c=built.candidates[name],old=recovery.old.find(v=>v.role===name);
    need(image(c.image)&&c.oldImage===old.image&&c.tag===`dip-deploy-${name}:candidate-${nonce}`&&c.oldTag===`dip-deploy-${name}:old-${nonce}`,'CANDIDATE_REFERENCE');
    need(equal(read('built-'+name+'.json'),{role:name,...c})&&equal(read('retain-'+name+'-submission.json'),{role:name,image:old.image,tag:c.oldTag})&&equal(read('build-'+name+'-submission.json'),{role:name,tag:c.tag,oldTag:c.oldTag,lifecycle:false}),'BUILD_RECEIPTS');
    references.push({name,tag:c.tag,image:c.image},{name,tag:c.oldTag,image:c.oldImage});
  }
  need(hex(historicalIntent),'HISTORICAL_INTENT');return {intent,recovery,built,comp,submission,references};
}
const WRITERS=['web','api','worker'];
const PROBE_RECORDS=['create-submission','created','start-submission','control-difference','stop-submission','remove-submission','retired'].map(n=>'probe-helper-'+n+'.json');

// Separate admission: never reinterpret a stopped-web-only receipt as writer recovery.
export function validateFencedWriterCompensation(read,listing,nonce,recovery,comp,authority){
  const common=['lease.json','intent.json','recovery.json','recipe-old.json','recipe-candidate.json','built.json',...recovery.services.flatMap(n=>['retain-'+n+'-submission.json','build-'+n+'-submission.json','built-'+n+'.json'])];
  const stage=['snapshots','failure-snapshot.json','fenced.json','helper-fenced-submission.json','helper-fenced-created.json','helper-fenced-start-submission.json','compensation-restore-authority.json','compensation-helper-stop-submission.json','compensation-helper-remove-submission.json','compensation-helper-retired.json','compensation-api-healthy.json','compensation-old-restored.json',...WRITERS.flatMap(n=>['stop-'+n+'-submission.json','stop-'+n+'-observation.json','stop-'+n+'-complete.json','compensation-start-'+n+'-submission.json','compensation-started-'+n+'.json'])];
  need(equal(listing,[...common,...stage,...PROBE_RECORDS].sort()),'FENCED_UNEXPECTED_STAGE');
  need(equal(read('failure-snapshot.json'),{code:'HELPER_CONTROL_CHANGED'})&&equal(read('fenced.json'),{writers:WRITERS,drain:{jobs:0,outbox:0,leases:0}}),'FENCED_FAILURE');
  need(authority.version===1&&authority.nonce===nonce&&authority.operation==='retire-exact-ro-helper-and-start-same-old-writers'&&authority.publishedConfigUnchanged===true&&authority.lockRetained===true,'FENCED_AUTHORITY');
  need(Array.isArray(authority.old)&&equal(authority.old.map(v=>v.id).sort(),recovery.old.map(v=>v.id).sort()),'FENCED_OLD_SET');
  const api=recovery.old.find(v=>v.role==='api'),h=authority.helper;
  need(hex(h?.id)&&!recovery.old.some(v=>v.id===h.id)&&h.image===api.image&&h.name===PROJECT+'-llm-'+nonce+'-fenced'&&h.status==='running'&&h.exit===0&&h.network==='none'&&h.originalMountsReadOnly===true&&h.policyValidated===true&&Number.isFinite(Date.parse(h.startedAt)),'FENCED_HELPER_AUTHORITY');
  need(equal(read('helper-fenced-submission.json'),{name:h.name,image:h.image,purpose:'backup'})&&equal(read('helper-fenced-created.json'),{id:h.id})&&equal(read('helper-fenced-start-submission.json'),{id:h.id}),'FENCED_HELPER_START');
  need(equal(read('compensation-helper-stop-submission.json'),{id:h.id})&&equal(read('compensation-helper-remove-submission.json'),{id:h.id,exit:0,originalMountsReadOnly:true})&&equal(read('compensation-helper-retired.json'),{id:h.id,exit:0,removed:true}),'FENCED_MAIN_HELPER_RETIREMENT');
  const started={};
  for(const old of recovery.old){
    const prior=authority.old.find(v=>v.id===old.id),e=prior.epoch;
    need(prior.image===old.image&&hex(prior.control)&&Array.isArray(e)&&e.length===9&&e[0]===old.id&&e[1]===old.startedAt&&e[4]===0&&e[7]===0&&e[8]==='','FENCED_OLD_BINDING');
    if(!WRITERS.includes(old.role))continue;
    const n=old.role,stop=read('stop-'+n+'-complete.json'),obs=read('stop-'+n+'-observation.json'),res=read('compensation-started-'+n+'.json');
    need(equal(read('stop-'+n+'-submission.json'),{role:n,id:old.id,image:old.image})&&equal(stop,{id:old.id,exit:0,startedAt:old.startedAt,finishedAt:e[2]})&&Number.isFinite(Date.parse(e[2]))&&e[3]===0&&e[5]===false&&e[6]==='exited','FENCED_CLEAN_STOP');
    need(obs.role===n&&obs.dispatch==='exit-zero'&&['id','name','empty'].includes(obs.acknowledgement)&&Number.isSafeInteger(obs.stdoutBytes)&&obs.stdoutBytes>=0&&obs.stdoutBytes<=65536&&typeof obs.deprecatedTimeWarning==='boolean'&&obs.sameControl===true&&obs.sameStart===true&&obs.exited===true&&obs.running===false&&obs.zeroPid===true&&obs.cleanWriterStop===true&&obs.exitCode===0,'FENCED_STOP_OBSERVATION');
    need(equal(read('compensation-start-'+n+'-submission.json'),{id:old.id,image:old.image,operation:'start-same-old-id'}),'FENCED_RESTART_SUBMISSION');
    const a=res.epoch;need(res.id===old.id&&res.image===old.image&&Array.isArray(a)&&a.length===9&&a[0]===old.id&&Date.parse(a[1])>Date.parse(e[2])&&a[1]!==old.startedAt&&a[2]===e[2]&&Number.isSafeInteger(a[3])&&a[3]>0&&a[4]===0&&a[5]===true&&a[6]==='running'&&a[7]===0&&a[8]==='','FENCED_RESTART_EPOCH');
    need(Date.parse(h.startedAt)>=Date.parse(e[2]),'FENCED_HELPER_AFTER_STOP');started[n]=a[1];
  }
  need(Date.parse(started.worker)<=Date.parse(started.api)&&Date.parse(started.api)<=Date.parse(started.web),'FENCED_RESTART_ORDER');
  need(equal(read('compensation-api-healthy.json'),{id:api.id,healthy:true}),'FENCED_API_HEALTH');
  need(equal(comp,{version:1,nonce,outcome:'old-writers-restored-lock-retained',web:200,auth:401,apiHealthy:true,startedSameOldIds:['worker','api','web'],helperRemoved:h.id,gatewaysUnchanged:true,publishedConfigUnchanged:true,migration:false,databaseRestore:false,snapshotResumed:false,lockRetained:true}),'FENCED_COMPENSATION');
  // The diagnostic probe is not the main backup helper. Its 137 is not a clean
  // writer/helper stop exception and cannot qualify the main helper retirement.
  const pc=read('probe-helper-created.json'),ps=read('probe-helper-create-submission.json'),pd=read('probe-helper-control-difference.json'),pr=read('probe-helper-remove-submission.json'),pt=read('probe-helper-retired.json');
  need(hex(pc.id)&&pc.id!==h.id&&!recovery.old.some(v=>v.id===pc.id)&&pc.image===api.image&&typeof pc.name==='string'&&new RegExp('^'+PROJECT+'-llm-[a-f0-9]{32}-fenced$').test(pc.name)&&pc.name!==h.name,'PROBE_IDENTITY');
  need(equal(ps,{version:1,purpose:'create-start-control-difference-no-real-stores',name:pc.name,image:pc.image,volumeMounts:0,bindMounts:0,network:'none',processDeadlineMs:30000})&&equal(read('probe-helper-start-submission.json'),{id:pc.id})&&equal(read('probe-helper-stop-submission.json'),{id:pc.id}),'PROBE_ISOLATION');
  need(equal(pd,{version:1,id:pc.id,image:pc.image,adapterControlEqual:false,changedFields:['HostConfig.OomKillDisable'],createdMounts:[],startedMounts:[],memorySwappiness:{before:null,after:null},oomKillDisable:{before:false,after:null},realStoreMounts:0,network:'none'}),'PROBE_DIFFERENCE');
  need(equal(pr,{version:1,id:pc.id,image:pc.image,name:pc.name,daemon:recovery.daemon,exitCode:137,oomKilled:false,restartCount:0,network:'none',realStoreMounts:0,cleanExit:false,action:'remove-exited-owned-disposable-no-force',submittedAt:pr.submittedAt})&&Number.isFinite(Date.parse(pr.submittedAt)),'PROBE_REMOVAL');
  need(equal(pt,{version:1,id:pc.id,removed:true,exitCode:137,cleanExit:false,originalEvidencePreserved:true,retiredAt:pt.retiredAt})&&Date.parse(pt.retiredAt)>=Date.parse(pr.submittedAt),'PROBE_RETIRED');
}

// These existing private append-only records predate reconciliation. Bind their
// filesystem ordering as well as their bytes; do not invent missing timestamps.
export function validateFencedWriterRecordOrder(mtime){
  const order=['stop-web-submission.json','stop-web-observation.json','stop-web-complete.json','stop-api-submission.json','stop-api-observation.json','stop-api-complete.json','stop-worker-submission.json','stop-worker-observation.json','stop-worker-complete.json','fenced.json','helper-fenced-submission.json','helper-fenced-created.json','helper-fenced-start-submission.json','failure-snapshot.json','compensation-restore-authority.json','compensation-helper-stop-submission.json','compensation-helper-remove-submission.json','compensation-helper-retired.json','compensation-start-worker-submission.json','compensation-started-worker.json','compensation-start-api-submission.json','compensation-started-api.json','compensation-api-healthy.json','compensation-start-web-submission.json','compensation-started-web.json','compensation-old-restored.json',...PROBE_RECORDS];
  let last=-Infinity;for(const name of order){const time=mtime(name);need(Number.isFinite(time)&&time>=last,'FENCED_RECORD_ORDER');last=time;}
}
function httpStatus(path,timeout){return new Promise((resolveStatus,reject)=>{const r=http.get({host:'127.0.0.1',port:8081,path,agent:false},res=>{const code=res.statusCode;res.destroy();resolveStatus(code);});const timer=setTimeout(()=>r.destroy(),timeout);r.on('error',()=>reject(Error('WEB_RECONCILE_HTTP')));r.on('close',()=>clearTimeout(timer));});}

export async function prepareWebReconciliation({attempt,historicalIntent,branch='web',root=ROOT,run=runIsolatedDocker,request=httpStatus,home=process.env.HOME}={}) {
  need(/^[a-f0-9]{32}$/.test(attempt)&&hex(historicalIntent)&&resolve(root)===root&&fs.realpathSync(root)===root,'ARGUMENTS');
  const state=join(root,STATE),parent=join(state,'deploy-adapter-v1'),audit=join(parent,attempt),lock=join(state,'.operation.lock'),guard=join(state,GUARD);
  const archiveParent=join(state,'exact-recovery-compensations'),guardArchive=join(archiveParent,'adapter-web-'+attempt);
  const end=performance.now()+240000,time=()=>{const left=Math.floor(end-performance.now());need(left>0,'DEADLINE');return left;};
  const source=capturePublicLlmSource(root,{openai:true});
  const sourceFiles=[SELF,'scripts/deploy-reconcile-restored.mjs','scripts/deploy-adapter.mjs','scripts/deploy-adapter-stores.mjs','scripts/deploy-core.mjs','scripts/deploy.mjs'].map(p=>({path:p,proof:byteFile(join(root,p),false,{maxBytes:1024**2})}));
  const sourceDigest=hash({manifest:source.manifest,modules:sourceFiles.map(p=>({path:p.path,sha256:p.proof.sha256}))});
  need(['web','fenced-writers'].includes(branch),'BRANCH');
  const fenced=branch==='fenced-writers',initial=names(audit),proofs=initial.filter(n=>fenced&&n==='snapshots'?false:true).map(n=>{need(/^[a-z][a-z0-9-]+\.json$/.test(n),'JOURNAL_LAYOUT');return privateFile(join(audit,n),262144);}),read=n=>{const p=proofs.find(p=>p.path===join(audit,n));need(p,'MISSING_RECORD');return JSON.parse(p.bytes);};
  // No host export was completed. The RO helper may have read/copied DBs internally.
  const snapshotDirs=fenced?[join(audit,'snapshots'),join(audit,'snapshots/fenced')]:[];
  const snapshotFences=snapshotDirs.map(directoryIdentity);
  const snapshotFence=()=>{snapshotFences.forEach(f=>f());if(fenced)need(equal(names(snapshotDirs[0]),['fenced'])&&names(snapshotDirs[1]).length===0,'HOST_SNAPSHOT_NOT_EMPTY');};
  snapshotFence();
  need(hash(proofs.find(p=>p.path===join(audit,'intent.json'))?.bytes??'')===historicalIntent,'HISTORICAL_INTENT');
  const records=validateWebCompensationRecords(read,initial,attempt,historicalIntent,branch),{intent,recovery,built,comp,submission,references}=records;
  need(submission.recoveryDigest===hash(proofs.find(p=>p.path===join(audit,'recovery.json')).bytes),'RECOVERY_DIGEST');
  if(fenced)validateFencedWriterRecordOrder(n=>fs.lstatSync(join(audit,n)).mtimeMs);
  const owner=privateFile(join(lock,'deploy-adapter-owner.json'));
  need(equal(JSON.parse(owner.bytes),{version:2,nonce:attempt,kind:'preserving-deployment'})&&equal(names(lock),['deploy-adapter-owner.json']),'LOCK_OWNER');
  const configFiles=['profile.json','llm-profile.json','compose.images.json','compose.llm-env.json','compose.cve.json'].map(n=>privateFile(join(state,n)));
  const profile=readProfile(root),selection=readPublicLlmBinding(root),model=expectedPublicLlmConfig(root,profile.cve,selection),pins=JSON.parse(configFiles[2].bytes);
  need(equal(JSON.parse(configFiles[3].bytes),publicLlmEnvironmentOverlay(selection)),'PUBLISHED_ENV');
  const expected=structuredClone(model);
  for(const [name,s]of Object.entries(expected.services)){const old=recovery.old.find(v=>v.role===name);need(old&&pins.services[name].image===old.image,'PUBLISHED_PIN');s.image=old.image;if(name==='api')s.environment.SCAN_JWT_SECRET='${SCAN_JWT_SECRET:?required}';}
  need(equal(read('recipe-old.json'),expected),'PUBLISHED_RECIPE');
  // Candidate recipe is retained evidence, not authority to switch services.
  // Validate its immutable images and topology; no constructor or migration runs.
  const candidateRecipe=read('recipe-candidate.json');
  need(equal(candidateRecipe.networks,expected.networks)&&equal(candidateRecipe.volumes,expected.volumes)&&equal(Object.keys(candidateRecipe.services).sort(),ALL),'CANDIDATE_TOPOLOGY');
  for(const n of ALL)need(candidateRecipe.services[n].image===(built.candidates[n]?.image??pins.services[n].image),'CANDIDATE_PIN');
  need(candidateRecipe.services.api.environment.SCAN_JWT_SECRET==='${SCAN_JWT_SECRET:?required}','CANDIDATE_SECRET_PLACEHOLDER');
  const jwt=join(state,'scan-jwt'),jwtStamp=stamp(fs.lstatSync(jwt));
  const catalog=captureDeploymentCatalog(root),retentions=capturePublicLlmRetentions(root),history=validateWebReconcileHistory(root,attempt);
  need(catalog.entries.length+history.count+1<=DEPLOYMENT_TOTAL_LIMIT&&history.count+1<DEPLOYMENT_TOTAL_LIMIT,'CATALOG_CAPACITY');
  validateCurrentAuditHistory(root);assertReconciliationHistory(root);
  const legacyRefs=retentions.receipts.flatMap(r=>Object.entries(r.images).map(([name,v])=>({name,tag:v.tag,image:v.image.Id,config:v.image.Config})));
  const refs=[...legacyRefs,...history.references,...references];
  need(refs.length<=DEPLOYMENT_RETAINED_REFERENCE_LIMIT&&new Set(refs.map(r=>r.tag)).size===refs.length,'RETENTION_CAPACITY');
  const dirs=[state,parent,audit,lock].map(directoryIdentity),archiveParentFence=exists(archiveParent)?directoryIdentity(archiveParent):()=>need(!exists(archiveParent),'ARCHIVE_PARENT_CHANGED');
  const added=[];let claimed=false,moved=false;
  const stable=()=>{time();source.verify();sourceFiles.forEach(p=>p.proof.verify());configFiles.forEach(p=>p.verify());need(equal(stamp(fs.lstatSync(jwt)),jwtStamp),'JWT_METADATA_CHANGED');catalog.verify();retentions.verify();history.verify();};
  const fence=()=>{stable();snapshotFence();need(!moved,'LOCK_ALREADY_MOVED');dirs.forEach(f=>f());owner.verify();proofs.forEach(f=>f.verify());need(equal(names(audit),[...initial,...added].sort())&&equal(names(lock),['deploy-adapter-owner.json']),'JOURNAL_CHANGED');need(equal(names(state).filter(n=>n.endsWith('.lock')),['.operation.lock',...(claimed?[GUARD]:[])].sort()),'OTHER_GUARD');need(!names(state).some(n=>/^(\.adapter-pending-|\.llm-pending-|\.profile\.pending|\.compose\.)/.test(n)),'PENDING_CONFIG');};
  fence();archiveParentFence();need(!exists(guardArchive),'ARCHIVE_EXISTS');
  const env={PATH:'/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',HOME:home,COMPOSE_DISABLE_ENV_FILE:'1'};
  const query=async args=>{fence();let out;try{out=await run(args,{root,env,timeout:Math.min(15000,time())});}catch{throw Error('WEB_RECONCILE_DOCKER_'+args[0].toUpperCase());}fence();return out;};
  const endpoint=JSON.parse(await query(['context','inspect','desktop-linux','--format','{{json .Endpoints.docker.Host}}']));need(/^unix:\/\/\/[^\s\0]+$/.test(endpoint),'ENDPOINT');env.DOCKER_HOST=endpoint;
  const ids=recovery.old.map(v=>v.id),imageIds=[...new Set(recovery.old.map(v=>v.image))],netNames=Object.values(model.networks).map(n=>n.name),volNames=Object.values(model.volumes).map(v=>v.name);
  const safeInspect=async(kind,ids,field)=>decodeInspect(await query([kind,'inspect',...ids,'--format',SAFE_INSPECT]),ids,field);
  const topology=async(kind,ids)=>{const rows=JSON.parse(await query([kind,'inspect',...ids]));need(rows.length===ids.length&&equal(rows.map(v=>v.Name).sort(),[...ids].sort()),'TOPOLOGY_CARDINALITY');return rows.sort((a,b)=>a.Name.localeCompare(b.Name));};
  const census=async kind=>{const base=[kind,'ls',...(kind==='container'?['--all','--no-trunc']:[]),'--format',kind==='container'?'{{.ID}}':'{{.Name}}'];const a=await query([...base,'--filter','label=com.docker.compose.project='+PROJECT]),b=await query([...base,'--filter','name='+(kind==='container'?'^/':'^')+PROJECT+(kind==='container'?'-':'_')]);return [...new Set([...lines(a),...lines(b)])].sort();};
  let observation;
  const verify=async()=>{
    need(JSON.parse(await query(['info','--format','{{json .ID}}']))===recovery.daemon,'DAEMON');
    if(fenced)for(const id of [submission.helper.id,read('probe-helper-created.json').id])need(lines(await query(['container','ls','--all','--no-trunc','--filter','id='+id,'--format','{{.ID}}'])).length===0,'RETIRED_HELPER_PRESENT');
    need(equal(await census('container'),[...ids].sort())&&equal(await census('network'),[...netNames].sort())&&equal(await census('volume'),volNames.filter(n=>n.startsWith(PROJECT+'_')).sort()),'NAMESPACE');
    const images=await safeInspect('image',imageIds,'Id'),byRole=Object.fromEntries(recovery.old.map(v=>[v.role,images.find(i=>i.Id===v.image)])),containers=await safeInspect('container',ids,'Id');
    for(const c of containers){
      const old=recovery.old.find(v=>v.id===c.Id),name=old.role,projected=structuredClone(c);if(name==='api')projected.Config.Env.push('SCAN_JWT_SECRET='+CONFIG_SECRET);
      validatePublicLlmImage(byRole[name],name);validatePublicLlmContainer(projected,name,model.services[name],byRole[name],model,{images:byRole,secret:CONFIG_SECRET},selection);
      need(c.Image===old.image&&c.Name==='/'+PROJECT+'-'+name+'-1'&&c.Config.Labels['com.docker.compose.project']===PROJECT&&c.Config.Labels['com.docker.compose.service']===name,'CONTAINER_IDENTITY');
      restoredControl(c);const s=c.State,running=!name.endsWith('volume-init');
      need(!s.OOMKilled&&!s.Paused&&!s.Restarting&&!s.Dead&&!s.Error&&c.RestartCount===0&&s.ExitCode===0&&s.Running===running&&s.Status===(running?'running':'exited')&&(running?s.Pid>0:s.Pid===0),'PROCESS');
      if(name==='api')need(s.Health.Status==='healthy','API_HEALTH');
      if(fenced){const prior=submission.old.find(v=>v.id===c.Id),current=['worker','api','web'].includes(name)?read('compensation-started-'+name+'.json'):prior;need(restoredControl(c)===prior.control&&equal(epoch(c),current.epoch),'RESTORED_CONTROL_EPOCH');}
      else if(name==='web')need(s.StartedAt===comp.startedAt,'WEB_EPOCH');else need(equal(epoch(c),submission.backendEpochs.find(v=>v.id===c.Id).epoch),'BACKEND_EPOCH');
    }
    const networks=await topology('network',netNames),volumes=await topology('volume',volNames);
    for(const n of networks){const spec=Object.values(model.networks).find(v=>v.name===n.Name);need(n.Driver==='bridge'&&n.Labels?.[LABEL]==='v1'&&n.Labels?.['com.docker.compose.project']===PROJECT&&Boolean(n.Internal)===Boolean(spec.internal)&&!n.Attachable&&!n.Ingress&&!n.EnableIPv6&&equal(n.Options??{},{}),'NETWORK_POLICY');const members=containers.filter(c=>c.State.Running&&Object.hasOwn(c.NetworkSettings.Networks,n.Name));need(equal(Object.keys(n.Containers??{}).sort(),members.map(c=>c.Id).sort()),'NETWORK_USERS');for(const c of members)need(c.NetworkSettings.Networks[n.Name].NetworkID===n.Id&&n.Containers[c.Id].Name===c.Name.slice(1),'NETWORK_ENDPOINT');}
    for(const v of volumes){need(v.Driver==='local'&&v.Scope==='local'&&equal(v.Options??{},{}),'VOLUME_POLICY');if(v.Name===selection.credentialVolume)validateOpenAiVolume(v,selection);else if(v.Name===selection.keyVolume)validatePublicLlmKeyVolume(v,selection);else need(v.Labels?.[LABEL]==='v1'&&v.Labels?.['com.docker.compose.project']===PROJECT,'VOLUME_OWNER');const users=containers.filter(c=>c.Mounts.some(m=>m.Type==='volume'&&m.Name===v.Name));need(equal(lines(await query(['container','ls','--all','--no-trunc','--filter','volume='+v.Name,'--format','{{.ID}}'])),users.map(c=>c.Id).sort()),'VOLUME_USERS');for(const c of users)need(c.Mounts.filter(m=>m.Name===v.Name).every(m=>m.Source===v.Mountpoint&&m.Driver==='local'),'VOLUME_MOUNT');}
    for(const ref of refs){need(ROLES.includes(ref.name)&&image(ref.image)&&/^(dip-public-images-[a-z-]+:retained-[a-f0-9]{32}|dip-deploy-[a-z-]+:(old|candidate)-[a-f0-9]{32})$/.test(ref.tag),'REFERENCE_SCOPE');const rows=lines(await query(['image','inspect',ref.tag,'--format',SAFE_INSPECT])).map(JSON.parse);need(rows.length===1,'REFERENCE_CARDINALITY');const im=decodeInspect(JSON.stringify(rows[0]),[ref.image],'Id')[0];validatePublicLlmImage(im,ref.name);need(im.RepoTags?.includes(ref.tag)&&(!ref.config||equal(im.Config,ref.config)),'RETAINED_IMAGE');}
    const current={peers:containers.map(c=>({id:c.Id,image:c.Image,control:restoredControl(c),epoch:epoch(c)})).sort((a,b)=>a.id.localeCompare(b.id)),networks,volumes};
    if(observation)need(equal(current,observation),'RUNTIME_CHANGED');else observation=current;
    for(const [path,code]of [['/',200],['/api/v1/auth/me',401]])need(await request(path,Math.min(5000,time()))===code,'HTTP_STATUS');fence();
  };
  await verify();
  const authority={version:1,kind:fenced?'adapter-fenced-writers-restored-reconciliation':'adapter-stopped-web-only-reconciliation',attempt,historicalIntent,historicalSource:{source:intent.source,adapter:intent.adapter,entrySources:intent.entrySources,backendSource:intent.backendSource},currentSource:sourceDigest,entry:sourceFiles[0].proof.sha256,originalEvidence:webReconcileEvidenceIndex(audit),owner:{digest:hash(owner.bytes),identity:owner.identity},published:configFiles.map(p=>({name:p.path.slice(state.length+1),digest:hash(p.bytes),identity:p.identity})),jwtIdentity:jwtStamp,observation,references,compensationFirstPostcheck:comp.firstPostcheck};
  const review=hash(authority),summary={outcome:'WEB_RECONCILIATION_CHECKED_NOT_APPLIED',branch,hostSnapshotCompleted:false,helperMayHaveReadStores:fenced,attempt,review,source:sourceDigest,entry:sourceFiles[0].proof.sha256,historicalIntent,historicalAdapter:intent.adapter,currentAdapter:sourceFiles.find(p=>p.path==='scripts/deploy-adapter.mjs').proof.sha256,services:8,networks:netNames.length,volumes:volNames.length,retainedReferences:refs.length,web:200,auth:401,api:'healthy',lockRetained:true,lifecycle:false,databaseRead:false,quiescenceClaimed:false};
  const record=(name,value)=>{fence();writeExclusive(join(audit,name),JSON.stringify(value),0o600);syncDirectory(audit);added.push(name);proofs.push(privateFile(join(audit,name),262144));};
  return {summary,async apply(binding){
    need(equal(binding,{review,source:sourceDigest}),'REVIEW_BINDING');await verify();fence();archiveParentFence();
    fs.mkdirSync(guard,{mode:0o700});writeExclusive(join(guard,'intent.json'),JSON.stringify({version:1,attempt,review,source:sourceDigest,command:fenced?'reconcile-fenced-writers-restored':'reconcile-stopped-web-only'}),0o600);syncDirectory(guard);syncDirectory(state);claimed=true;
    const guardIdentity=directoryIdentity(guard),guardIntent=privateFile(join(guard,'intent.json'));
    const guardFence=()=>{guardIdentity();guardIntent.verify();need(equal(names(guard),['intent.json']),'GUARD_CHANGED');};
    record('reconciliation-authority.json',authority);
    record('reconciliation-result.json',{version:1,attempt,review,source:sourceDigest,outcome:'old-restored',web:200,auth:401,backendEpochsUnchanged:!fenced,restoredWriterEpochsVerified:fenced,hostSnapshotCompleted:false,helperMayHaveReadStores:fenced,firstPostcheck:comp.firstPostcheck,lifecycle:false,migration:false,databaseRead:false,quiescenceClaimed:false});
    await verify();guardFence();
    if(!exists(archiveParent)){fs.mkdirSync(archiveParent,{mode:0o700});syncDirectory(state);}else archiveParentFence();
    need(!exists(guardArchive)&&fs.lstatSync(archiveParent).dev===fs.lstatSync(lock).dev,'ARCHIVE_DESTINATION');fs.mkdirSync(guardArchive,{mode:0o700});syncDirectory(archiveParent);
    // Crash here leaves BOTH recognized guards. complete.json is never interpreted
    // as permission to remove a lock; the history reader also requires its archive.
    record('complete.json',{version:2,project:PROJECT,nonce:attempt,outcome:'old-restored',references,evidence:webReconcileEvidenceIndex(audit)});
    fence();guardFence();fs.renameSync(lock,join(audit,'operation.lock'));syncDirectory(audit);syncDirectory(state);moved=true;
    const archivedOwner=privateFile(join(audit,'operation.lock/deploy-adapter-owner.json'));need(archivedOwner.bytes===owner.bytes&&equal(names(join(audit,'operation.lock')),['deploy-adapter-owner.json']),'ARCHIVED_OWNER');
    stable();proofs.forEach(p=>p.verify());validateWebReconcileHistory(root);validateCurrentAuditHistory(root);assertReconciliationHistory(root);guardFence();
    // No audit entries may be added after complete.json: evidenceIndex must remain exact.
    fs.renameSync(guard,join(guardArchive,'operation.lock'));syncDirectory(guardArchive);syncDirectory(state);
    return {...summary,outcome:'WEB_ATTEMPT_RECONCILED',lockRetained:false,receipt:STATE+'/deploy-adapter-v1/'+attempt+'/complete.json',guardArchive:STATE+'/exact-recovery-compensations/adapter-web-'+attempt+'/operation.lock'};
  }};
}
export async function webReconciliationCli(argv){const [command,...a]=argv;const check=['check','check-fenced-writers'].includes(command),fenced=['check-fenced-writers','apply-fenced-writers'].includes(command);need(['check','apply','check-fenced-writers','apply-fenced-writers'].includes(command)&&a[0]==='--attempt'&&a[2]==='--historical-intent'&&(check?a.length===4:a.length===9&&a[4]==='--review'&&a[6]==='--source'&&a[8]===(fenced?'--ack-reconcile-restored-writers':'--ack-reconcile-restored-web')),'ARGUMENTS');const p=await prepareWebReconciliation({attempt:a[1],historicalIntent:a[3],branch:fenced?'fenced-writers':'web'});return check?p.summary:p.apply({review:a[5],source:a[7]});}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))webReconciliationCli(process.argv.slice(2)).then(v=>console.log(JSON.stringify(v))).catch(e=>{console.error(JSON.stringify({outcome:'WEB_RECONCILIATION_REFUSED_OR_HOLD',code:/^WEB_RECONCILE_[A-Z_]+$/.test(e.message)?e.message:'WEB_RECONCILE_VALIDATION',noRetry:true}));process.exitCode=1;});
