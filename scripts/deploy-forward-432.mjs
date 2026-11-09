// Exact forward-only continuation. No import-time state/engine/credential access.
import * as fs from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual as equal } from 'node:util';

export const EXACT_FORWARD_432 = Object.freeze({
  audit:'432eff6daa07752b1e11365b43ecd3fa',
  source:'57a6dbb9c11501db93b0bb4fc5ed66998784c599159c29ec296d7c7d465fac2a',
  adapter:'c822dd10591c0e8bd06246b6ca628556724a33ba92f82c86b849603c8a151bd5',
  worker:{id:'cc46dff439e7770fd8c7d3d7e9c7c1a2c0d5bd041029edefd7c820ef09d9e390',image:'sha256:8cdd234cf7adb03c9563a16d692bd32bcbe2501da479d38a5f3a1d63fa8e6dc9',startedAt:'2026-11-08T20:12:09.415661799Z'},
  gateway:{id:'7e692434825ed2a1a59f2d296e7410e4ad9c69c691a8031e3da6357ae4d7866b',image:'sha256:df212bf06d0331f0b485934c6e1442ed4330a0c734885a73a4a8f7b123925bfc',startedAt:'2026-11-08T20:12:01.905974212Z'},
});
export const FORWARD_432_CHILD='forward-ready-worker-432';
const sha=b=>createHash('sha256').update(b).digest('hex');
const failures=new WeakMap();
export const forward432Diagnostic=error=>failures.get(error)??null;
const need=(ok,code='FORWARD_432_REFUSED')=>{if(!ok){const e=Error(code);failures.set(e,{code});throw e;}};
const role=c=>c.Config?.Labels?.['com.docker.compose.service'];
const hash=v=>sha(JSON.stringify(v));
const failure={code:'READINESS_EXEC_FAILED',cause:'TIMEOUT',exitCode:null,signal:'SIGKILL',stdoutBytes:0,stderrBytes:0};
const targets=['api','openai-egress','web'];
const interrupted=['api','openai-egress','web','worker'];
const reads=new Set(['PEER_INSPECT_FAILED','CONTAINER_INSPECT_FAILED','CONTAINER_CENSUS_FAILED','CONTAINER_NAME_CENSUS_FAILED','IMAGE_INSPECT_FAILED','NETWORK_CENSUS_FAILED','NETWORK_INSPECT_FAILED','VOLUME_INSPECT_FAILED','VOLUME_CONSUMERS_FAILED','DOCKER_INFO_FAILED','RETAINED_IMAGE_INSPECT_FAILED','IMAGE_REFERENCE_CENSUS_FAILED','READINESS_INSPECT_FAILED','SERVICE_RESUME_INSPECT_FAILED']);
const prefix=Object.freeze([
  ...targets.flatMap(n=>['borrow-'+n+'.json','build-'+n+'-submission.json','built-'+n+'.json']),
  'built.json','engine.jsonl','failure-switchservices.json','fenced.json',
  ...['complete','created','remove-observation','remove-submission','start-observation','start-submission','stop-observation','stop-submission','submission'].map(n=>'helper-fenced-'+n+'.json'),
  'intent.json','lease.json','qualification.json','recipe-candidate.json','recipe-old.json','recovery.json','reference-custody.json','snapshot-fenced.json','snapshots',
  'start-openai-egress-complete.json','start-openai-egress-submission.json','start-worker-complete.json','start-worker-observation.json','start-worker-submission.json',
  ...['api','web','worker','openai-egress'].flatMap(n=>['stop-'+n+'-complete.json','stop-'+n+'-observation.json','stop-'+n+'-submission.json']),
  'stop-openai-egress-proof.json','supervisor.json',
].sort());

// The sole unfinished dispatch must be the reviewed read-only readiness exec.
// Never append a fabricated settlement to the original journal.
export function qualifyForward432Journal(text) {
  need(typeof text==='string'&&Buffer.byteLength(text)<=4*1024**2&&text.endsWith('\n'),'FORWARD_JOURNAL_BYTES');
  const rows=text.slice(0,-1).split('\n').map(s=>JSON.parse(s));
  need(rows.length>1&&rows.length<=20001&&rows.length%2===1,'FORWARD_JOURNAL_PENDING');
  const codes=[];
  for(let i=0;i<rows.length;i+=2){
    const a=rows[i];need(equal(Object.keys(a).sort(),['code','seq','state'])&&a.seq===i/2+1&&a.state==='submitted'&&/^[A-Z][A-Z0-9_]{1,79}$/.test(a.code),'FORWARD_JOURNAL_ROW');
    codes.push(a.code);
    if(i+1<rows.length)need(equal(rows[i+1],{seq:a.seq,state:'settled',exit:0}),'FORWARD_JOURNAL_SETTLEMENT');
  }
  need(codes.at(-1)==='READINESS_EXEC_FAILED','FORWARD_JOURNAL_NOT_READONLY');
  const resume=codes.lastIndexOf('SERVICE_RESUME_FAILED');
  need(resume>=0&&codes.slice(resume+1,-1).every(c=>reads.has(c)),'FORWARD_POST_WORKER_DISPATCH');
  need(codes.filter(c=>c==='SERVICE_RESUME_FAILED').length===1&&codes.filter(c=>c==='SERVICE_RECREATE_FAILED').length===1&&
      codes.filter(c=>c==='HELPER_CREATE_FAILED').length===1&&codes.filter(c=>c==='HELPER_START_FAILED').length===1&&codes.filter(c=>c==='HELPER_REMOVE_FAILED').length===1&&
      !codes.some(c=>/MIGRAT|PUBLICATION|RESTORE/.test(c))&&codes.slice(0,resume).includes('SERVICE_RECREATE_FAILED'),'FORWARD_LIFECYCLE_PREFIX');
  return {sha256:sha(text),settled:codes.length-1,pending:{seq:codes.length,code:'READINESS_EXEC_FAILED',readOnly:true,settlementUnknown:true}};
}

// Called only by createDeployAdapter's bounded exact seam, never by normal apply.
export async function runExactForward432(api, options={}) {
  const apply=options.apply===true;
  need((options.apply===undefined||typeof options.apply==='boolean')&&Object.keys(options).every(k=>['audit','apply','review','ackForwardOnly'].includes(k))&&options.audit===EXACT_FORWARD_432.audit&&
    (!apply||options.ackForwardOnly===true&&/^[a-f0-9]{64}$/.test(options.review??'')),'FORWARD_EXACT_ARGUMENTS');
  api.rootCheck();
  const supervisor=apply?api.requireSupervisor():null;
  const supervisorIdentity=supervisor?.identity??api.inspectSupervisor();
  const original=join(api.root,api.STATE,'deploy-adapter-v1',options.audit),child=join(original,FORWARD_432_CHILD);
  const lockPath=join(api.root,api.STATE,'.operation.lock');
  const originalGuard=api.protectedDirectory(original),lockGuard=api.protectedDirectory(lockPath);
  need(!fs.existsSync(child)&&equal(fs.readdirSync(original).sort(),prefix),'FORWARD_EXACT_PREFIX');
  const proofs=[],read=name=>{const f=api.captureFile(join(original,name),{limit:name==='engine.jsonl'?4*1024**2:262144});proofs.push(f);return name==='engine.jsonl'?f.bytes.toString():JSON.parse(f.bytes);};
  const owner=api.captureFile(join(lockPath,'deploy-adapter-owner.json'));
  need(equal(JSON.parse(owner.bytes),{version:2,nonce:options.audit,kind:'preserving-deployment'})&&equal(fs.readdirSync(lockPath),['deploy-adapter-owner.json']),'FORWARD_LOCK_OWNER');
  const intent=read('intent.json'),recovery=read('recovery.json'),built=read('built.json'),qualification=read('qualification.json'),baseline=read('snapshot-fenced.json');
  need(equal(read('failure-switchservices.json'),failure),'FORWARD_EXACT_TIMEOUT');
  const journal=qualifyForward432Journal(read('engine.jsonl'));
  const oldSupervisor=read('supervisor.json');
  need(oldSupervisor.version===1&&equal(oldSupervisor.identity,supervisorIdentity)&&/^[a-f0-9]{64}$/.test(oldSupervisor.session)&&(!apply||oldSupervisor.session!==supervisor.session),'FORWARD_SUPERVISOR');
  need(equal(read('lease.json'),{version:2,project:api.PROJECT,nonce:options.audit}),'FORWARD_LEASE');
  need(intent.version===2&&intent.kind==='preserving-deployment'&&intent.project===api.PROJECT&&intent.nonce===options.audit&&intent.mode==='app'&&equal(intent.services,targets)&&intent.lifecycle===false&&
    intent.source===EXACT_FORWARD_432.source&&intent.adapter===EXACT_FORWARD_432.adapter,'FORWARD_ORIGINAL_SOURCE');
  need(recovery.version===2&&recovery.project===api.PROJECT&&recovery.nonce===options.audit&&recovery.daemon===intent.daemon&&equal(recovery.services,targets)&&equal(recovery.interruptedServices,interrupted)&&
    recovery.migration===false&&recovery.historyMigration==='none'&&recovery.historyVersion===5&&recovery.automaticDatabaseRollback===false&&
    recovery.oldRecipe==='recipe-old.json'&&recovery.candidateRecipe==='recipe-candidate.json','FORWARD_ORIGINAL_SCOPE');
  need(built.version===1&&built.nonce===options.audit&&built.outcome==='candidate-built-old-site-unchanged'&&built.lifecycle===false&&equal(Object.keys(built.candidates).sort(),targets),'FORWARD_BUILT_SCOPE');
  need(qualification.auth?.migration==='none'&&qualification.auth.constructorPasses===2&&qualification.auth.before===qualification.auth.expected&&
    qualification.constructorPasses===2&&qualification.ledgerUnchanged===true&&qualification.historyUnchanged===true&&qualification.quotaUnchanged===true&&qualification.historyProof===null&&qualification.liveMigration===false&&
    baseline.historyVersion===5&&baseline.core.auth.logicalSha256===qualification.auth.before,'FORWARD_QUALIFICATION');
  api.assertFourStoreTransition(baseline,baseline);
  const completedHelper=read('helper-fenced-complete.json');
  need(completedHelper.exit===0&&completedHelper.removed===true&&completedHelper.namespaceVerified===true,'FORWARD_HELPER_UNSETTLED');
  need(equal(fs.readdirSync(join(original,'snapshots')),['fenced'])&&equal(fs.readdirSync(join(original,'snapshots/fenced')).sort(),['core','llm']),'FORWARD_SNAPSHOT_PREFIX');
  const resumed=read('start-worker-complete.json'),gateway=read('start-openai-egress-complete.json');
  need(equal(resumed,{role:'worker',...EXACT_FORWARD_432.worker})&&equal(gateway,{role:'openai-egress',...EXACT_FORWARD_432.gateway}),'FORWARD_STARTED_RECEIPTS');
  need(equal(read('start-worker-submission.json'),{role:'worker',previous:resumed.id,image:resumed.image,recreate:false}),'FORWARD_WORKER_RESUME');
  const gatewaySubmission=read('start-openai-egress-submission.json');
  need(gatewaySubmission.role==='openai-egress'&&gatewaySubmission.recreate===true&&gatewaySubmission.image===gateway.image&&gatewaySubmission.previous===recovery.old.find(c=>c.role==='openai-egress')?.id,'FORWARD_GATEWAY_RECEIPT');
  const evidence=api.evidenceIndex(original),stamps=evidence.map(e=>{const path=join(original,e.path),s=fs.lstatSync(path);return {path,stamp:[s.dev,s.ino,s.mode,s.uid,s.nlink,s.size,s.mtimeMs,s.ctimeMs],directory:!!e.directory};});
  let childCreated=false,terminal=false;
  const verifyOriginal=()=>{
    originalGuard();lockGuard();owner.verify();proofs.forEach(f=>f.verify());
    need(equal(fs.readdirSync(original).filter(n=>!(childCreated&&n===FORWARD_432_CHILD)&&!(terminal&&n==='complete.json')).sort(),prefix),'FORWARD_ORIGINAL_PREFIX_CHANGED');
    for(const {path,stamp,directory}of stamps){const s=fs.lstatSync(path);need(equal([s.dev,s.ino,s.mode,s.uid,s.nlink,s.size,s.mtimeMs,s.ctimeMs],stamp)&&s.isDirectory()===directory,'FORWARD_ORIGINAL_EVIDENCE_CHANGED');}
  };
  const config=api.loadConfiguration(true),next=api.expectedConfig(config.profile.cve,config.next);
  need(config.selection.version===6&&config.next.version===7,'FORWARD_PROVIDER_SCOPE');
  const source=api.captureSource(),self=api.captureSelf(),entryProofs=api.captureEntries();
  need(hash(source.manifest.files.map(f=>({path:f.path,digest:f.digest})))===intent.source&&equal(entryProofs.map(f=>sha(f.bytes)),intent.entrySources),'FORWARD_PUBLIC_SOURCE_CHANGED');
  const codeProofs=['deploy-forward-432.mjs','deploy-forward-432-cli.mjs'].map(n=>api.captureFile(join(api.root,'scripts',n),{privateMode:false,limit:1024**2}));
  const contract=api.sourceContract(),catalog=api.catalog(),retentions=api.retentions(),history=api.history(options.audit,catalog,retentions);
  need(contract.digest===intent.backendSource,'FORWARD_BACKEND_CONTRACT');
  const custody=api.validateCustody(read('reference-custody.json'),options.audit,history.references);
  need(equal(custody,intent.referenceCustody)&&equal(custody,built.referenceCustody)&&equal(custody,recovery.referenceCustody),'FORWARD_CUSTODY');
  api.custodyCompletion(custody,options.audit,built.candidates);
  const oldModel=read('recipe-old.json'),newModel=read('recipe-candidate.json');
  const connection=await api.connect();need(connection.initial.id===intent.daemon,'FORWARD_DAEMON');
  const names=Object.keys(config.model.services).sort();
  need(recovery.old.length===8&&equal(recovery.old.map(c=>c.role).sort(),names)&&new Set(recovery.old.map(c=>c.id)).size===8,'FORWARD_ORIGINAL_PEERS');
  const current=JSON.parse(await api.request(['container','inspect',...names.map(n=>`${api.PROJECT}-${n}-1`)],connection.options,'FORWARD_PEER_INSPECT_FAILED'));
  need(current.length===8&&equal(current.map(role).sort(),names)&&new Set(current.map(c=>c.Id)).size===8,'FORWARD_CURRENT_PEERS');
  const oldImages={},candidateImages={};
  for(const n of names){
    const old=recovery.old.find(c=>c.role===n);need(config.pins.services[n].image===old.image,'FORWARD_PUBLISHED_IMAGE');
    const rows=JSON.parse(await api.request(['image','inspect',old.image],connection.options,'FORWARD_OLD_IMAGE_FAILED'));need(rows.length===1&&rows[0].Id===old.image,'FORWARD_OLD_IMAGE_ID');
    api.validateImage(rows[0],n,config.selection);oldImages[n]=rows[0];candidateImages[n]=rows[0];
  }
  for(const n of targets){const row=built.candidates[n],old=custody.old.find(r=>r.name===n);
    need(row.oldImage===oldImages[n].Id&&row.oldImage===old.image&&row.oldTag===old.tag,'FORWARD_OLD_CUSTODY_BINDING');
    const rows=JSON.parse(await api.request(['image','inspect',row.image],connection.options,'FORWARD_CANDIDATE_IMAGE_FAILED'));
    need(rows.length===1&&rows[0].Id===row.image&&rows[0].RepoTags?.includes(row.tag),'FORWARD_CANDIDATE_IMAGE_ID');api.validateImage(rows[0],n,config.next);candidateImages[n]=rows[0];
  }
  need(equal(oldModel,api.recipe(config.model,oldImages))&&equal(newModel,api.recipe(next,candidateImages)),'FORWARD_RECIPE_CHANGED');
  need(built.candidates['openai-egress'].image===gateway.image,'FORWARD_STARTED_IMAGE');
  need(equal(intent.old,targets.map(n=>{const c=recovery.old.find(c=>c.role===n);return {role:n,id:c.id,image:c.image};})),'FORWARD_TARGET_ORIGINS');
  const authorities=new Map(),images={...oldImages,'openai-egress':candidateImages['openai-egress']};
  for(const c of current){const n=role(c),old=recovery.old.find(r=>r.role===n),started=n==='worker'?resumed:n==='openai-egress'?gateway:null;
    need(c.Id===(started?.id??old.id)&&c.Image===(started?.image??old.image)&&c.State.StartedAt===(started?.startedAt??old.startedAt),'FORWARD_PEER_EPOCH');
    if(n==='api'||n==='web'){
      const stopped=read('stop-'+n+'-complete.json');need(api.cleanStopped(c)&&c.State.ExitCode===0&&stopped.id===c.Id&&stopped.exit===0&&stopped.startedAt===c.State.StartedAt&&stopped.finishedAt===c.State.FinishedAt,'FORWARD_STOPPED_WRITER');
    }else if(!n.endsWith('volume-init'))need(api.healthy(c),'FORWARD_RUNNING_PEER');
    authorities.set(n,{model:n==='openai-egress'?next:config.model,selection:n==='openai-egress'?config.next:config.selection});
  }
  const jwt=api.captureFile(join(api.root,api.STATE,'scan-jwt'),{limit:96});
  need(/^[a-f0-9]{96}$/.test(jwt.bytes.toString())&&current.find(c=>role(c)==='api').Config.Env.includes('SCAN_JWT_SECRET='+jwt.bytes.toString()),'FORWARD_JWT_BINDING');
  proofs.push(jwt,...codeProofs);
  const verify=()=>{verifyOriginal();config.verify();source.verify();self.verify();entryProofs.forEach(f=>f.verify());catalog.verify();retentions.verify();history.verify();};
  verify();
  const p={mode:'app',nonce:options.audit,targets,config,next,source,self,entryProofs,contract,catalog,retentions,history,connection,
    before:{containers:current,images:oldImages,networks:[],volumes:[]},referenceCustody:custody,custodyNonce:options.audit,
    peers:new Map(current.map(c=>[role(c),c])),authorities,images,candidateImages,candidates:built.candidates,
    oldRecipe:join(original,'recipe-old.json'),newRecipe:join(original,'recipe-candidate.json'),apiReady:false,mutated:true,
    migration:false,historyMigration:'none',historyVersion:5,historyConsent:false,baseline,auth:null,jwt,extraGuard:verifyOriginal,proofs};
  const observed=await api.namespace(config,connection,p);p.before={...observed,images:oldImages};
  await api.retained(p);verify();
  const authority={version:1,kind:'exact-forward-ready-worker-432',audit:options.audit,originalSource:intent.source,originalAdapter:intent.adapter,
    qualifiedAdapter:sha(self.bytes),adapterDelta:{basis:'fresh-review-token-for-explicit-exact-seam-and-ready-exec-60s',prior:intent.adapter,next:sha(self.bytes)},code:codeProofs.map(f=>sha(f.bytes)),source:intent.source,entrySources:intent.entrySources,
    evidence:hash(evidence),journal,lock:api.operationIdentity(lockPath),supervisor:supervisorIdentity,
    historicalAuthority:'original-recovery-identities-plus-persisted-start-receipts',currentControlsBasis:'new-current-validated-not-historical-controls',
    current:api.authority(observed),published:config.selection,desired:config.next,baseline,referenceCustody:custody};
  const review=hash(authority);
  if(!apply)return {eligible:true,audit:options.audit,review,phase:'worker-resumed-gateway-replaced',historicalControls:false,restartWorker:false,replaceGateway:false,migrationReplay:false,lifecycle:false};
  need(options.review===review,'FORWARD_REVIEW_MISMATCH');verify();supervisor.verify();
  const environment=Object.fromEntries(['AUTH_ORIGIN','AUTH_ALLOW_INSECURE_LOCAL_HTTP','SCAN_BROWSER_ALLOWED_USER_IDS','SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS'].map(k=>[k,next.services.api.environment[k]]));
  p.auth=api.qualifyAuth({snapshotPath:join(original,'snapshots/fenced/core/auth.sqlite'),environment,migrate:false});
  need(p.auth.migration==='none'&&p.auth.before===baseline.core.auth.logicalSha256&&p.auth.expected===p.auth.before,'FORWARD_AUTH_BASELINE');
  const stores=api.qualifyStores({directory:join(original,'snapshots/fenced'),environment:config.next.environment,baseline,verify,migrateHistory:false});
  need(stores.historyUnchanged&&stores.quotaUnchanged&&stores.ledgerUnchanged,'FORWARD_ORIGINAL_STORES');
  verify();fs.mkdirSync(child,{mode:0o700});childCreated=true;api.syncDirectory(original);
  const childGuard=api.protectedDirectory(child);
  const record=(name,value)=>{supervisor.verify();lockGuard();owner.verify();childGuard();verify();
    need(/^[a-z][a-z0-9-]{0,79}\.json$/.test(name),'FORWARD_RECORD_NAME');
    const bytes=api.boundedRecord(name,value);api.writeExclusive(join(child,name),bytes,0o600);api.syncDirectory(child);proofs.push(api.captureFile(join(child,name),{limit:api.recordLimit(name)}));};
  record('adoption.json',{...authority,review,newSupervisorSession:supervisor.session});
  const ctx=api.installForward(p,{original,child,owner,lockGuard,supervisor,record,verifyOriginal,
    writeCompletion(name,value){need(name==='complete.json'&&!terminal&&p.phase==='published','FORWARD_TERMINAL_SCOPE');verify();terminal=true;api.writeExclusive(join(original,name),api.boundedRecord(name,value),0o600);api.syncDirectory(original);}});
  try{
    await api.boundary(p);await api.ready(p,'worker');record('ready-worker.json',{id:resumed.id,startedAt:resumed.startedAt,ready:true,restarted:false});
    const directory=join(child,'snapshots');fs.mkdirSync(directory,{mode:0o700});api.syncDirectory(child);
    p.snapshots=api.snapshots(p,directory,record);
    const fresh=await p.snapshots.capture('fenced');api.assertFourStoreTransition(baseline,fresh);record('fresh-original-equality.json',{version:1,equalOriginal:true,stores:fresh});
    const beforeApi=await p.snapshots.capture('before-api');api.assertFourStoreTransition(baseline,beforeApi);
    p.phase='switching';await api.startService(p,'api');
    p.after=await p.snapshots.capture('after-api');api.assertFourStoreTransition(baseline,p.after,p.auth);
    record('preservation.json',{version:1,baseline,after:p.after,allFourStores:true,migration:false});
    await api.startService(p,'web');p.phase='switched';await api.health({...ctx,target:'candidate'});
    ctx.receipt={version:1,mode:'app',services:targets,interruptedServices:interrupted,migration:false,historyMigration:'none',verified:false,healthy:true,completedAt:new Date().toISOString()};ctx.publishAttempted=true;
    await api.publish(ctx);await api.release(ctx);
    return {recovered:true,audit:options.audit,review,phase:'published',restartWorker:false,replaceGateway:false,migrationReplay:false,generationVerified:false};
  }catch(error){try{record('failure.json',{version:1,phase:p.phase,...(forward432Diagnostic(error)??api.diagnostic(error))});}catch{/* Preserve uncertain evidence and original lock. */}throw error;}
}
