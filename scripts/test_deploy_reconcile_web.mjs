// Run: node --experimental-vm-modules --test scripts/test_deploy_reconcile_web.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as vm from 'node:vm';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { createHash } from 'node:crypto';

const source = fs.readFileSync(new URL('./deploy-reconcile-web.mjs', import.meta.url), 'utf8');
const restoredSource = fs.readFileSync(new URL('./deploy-reconcile-restored.mjs', import.meta.url), 'utf8');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const project = 'synthetic';
const attempt = 'a'.repeat(32);
const roles = ['api','auth-volume-init','egress','llm-egress','openai-egress','scan-volume-init','web','worker'];
const epoch = c => [c.Id,c.State.StartedAt,c.State.FinishedAt,c.State.Pid,c.RestartCount,c.State.Running,c.State.Status,c.State.ExitCode,c.State.Error];

async function fixture(t) {
  assert.equal(typeof vm.SourceTextModule,'function','Run with --experimental-vm-modules');
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(),'web-reconcile-offline-')));
  t.after(() => fs.rmSync(root,{recursive:true,force:true}));
  const state = join(root,'synthetic-state'), audit = join(state,'deploy-adapter-v1',attempt);
  const lock = join(state,'.operation.lock'), guard = join(state,'.recover-build-and-redeploy.lock');
  const guardArchive = join(state,'exact-recovery-compensations','adapter-web-'+attempt,'operation.lock');
  const put = (path,value) => { fs.mkdirSync(dirname(path),{recursive:true,mode:0o700}); fs.writeFileSync(path,JSON.stringify(value),{mode:0o600}); };
  const privateFile = path => {
    // Any accidental secret/database read is a test failure, even in the fixture.
    assert.ok(path.startsWith(root+'/'));
    assert.ok(!path.endsWith('/scan-jwt') && !path.endsWith('.sqlite'));
    const bytes = fs.readFileSync(path,'utf8'), stat = fs.lstatSync(path);
    const identity = [stat.dev,stat.ino,stat.mode,stat.size,stat.mtimeMs,stat.ctimeMs];
    return {path,bytes,identity,verify() {
      const s = fs.lstatSync(path);
      assert.deepEqual([s.dev,s.ino,s.mode,s.size,s.mtimeMs,s.ctimeMs],identity);
      assert.equal(fs.readFileSync(path,'utf8'),bytes);
    }};
  };
  const noOp = () => {};
  const byteFile = path => {
    if (path.startsWith(join(root,'scripts')+'/')) return {sha256:'b'.repeat(64),verify:noOp};
    const proof = privateFile(path); return {...proof,sha256:hash(proof.bytes)};
  };
  const directoryIdentity = path => {
    const s = fs.lstatSync(path), identity = [s.dev,s.ino,s.mode];
    return () => { const now=fs.lstatSync(path); assert.deepEqual([now.dev,now.ino,now.mode],identity); };
  };
  const containers = roles.map((role,i) => {
    const running = !role.endsWith('volume-init');
    return {Id:(i+1).toString(16).repeat(64),Image:'sha256:'+'c'.repeat(64),Name:`/${project}-${role}-1`,Path:'synthetic',Args:[],Config:{Entrypoint:['synthetic'],Cmd:[],Env:[],Labels:{'com.docker.compose.project':project,'com.docker.compose.service':role}},HostConfig:{},Mounts:[],NetworkSettings:{Networks:{}},RestartCount:0,State:{StartedAt:role==='web'?'2026-01-02T00:00:00Z':'2026-01-01T00:00:00Z',FinishedAt:'',Pid:running?42:0,Running:running,Status:running?'running':'exited',ExitCode:0,Error:'',Health:{Status:'healthy'}}};
  });
  // Small topology: orchestration/history are real; imported topology validators
  // and source capture are fakes, not a qualification of the deployment model.
  const model = {services:Object.fromEntries(roles.map(n=>[n,{image:containers[0].Image,environment:n==='api'?{SCAN_JWT_SECRET:'${SCAN_JWT_SECRET:?required}'}:{}}])),networks:{},volumes:{}};
  const old = containers.map(c=>({role:c.Config.Labels['com.docker.compose.service'],id:c.Id,image:c.Image,startedAt:'2026-01-01T00:00:00Z'}));
  const web = old.find(c=>c.role==='web'), apiOld = old.find(c=>c.role==='api');
  const candidate = {image:'sha256:'+'d'.repeat(64),oldImage:apiOld.image,tag:`dip-deploy-api:candidate-${attempt}`,oldTag:`dip-deploy-api:old-${attempt}`};
  const intent = {version:2,kind:'preserving-deployment',project,nonce:attempt,mode:'app',lifecycle:false,source:'b'.repeat(64),adapter:'b'.repeat(64),backendSource:'b'.repeat(64),entrySources:Array(3).fill('b'.repeat(64)),services:['api'],daemon:'fake-daemon',old:[{role:'api',id:apiOld.id,image:apiOld.image}]};
  const recovery = {version:2,project,nonce:attempt,daemon:intent.daemon,services:['api'],interruptedServices:['api','web','worker'],oldRecipe:'recipe-old.json',candidateRecipe:'recipe-candidate.json',migration:false,automaticDatabaseRollback:false,old};
  const records = {
    'intent.json':intent,'lease.json':{version:2,project,nonce:attempt},'recovery.json':recovery,
    'recipe-old.json':model,'recipe-candidate.json':{...model,services:{...model.services,api:{...model.services.api,image:candidate.image}}},
    'built.json':{version:1,nonce:attempt,outcome:'candidate-built-old-site-unchanged',lifecycle:false,candidates:{api:candidate}},
    'failure-fenceadmissions.json':{code:'STOP_OUTPUT_INVALID'},'stop-web-submission.json':{role:'web',id:web.id,image:web.image},
    'compensation-web-start-submission.json':{version:1,nonce:attempt,operation:'start-same-old-web-only',id:web.id,image:web.image,priorStartedAt:web.startedAt,authority:'explicit-user-restore-only',originalStopDiagnostic:'STOP_OUTPUT_INVALID',originalStopStdoutAvailable:false,lockRetained:true,recoveryDigest:hash(JSON.stringify(recovery)),backendEpochs:containers.filter(c=>c.Id!==web.id).map(c=>({id:c.Id,epoch:epoch(c)}))},
    'compensation-web-restored.json':{version:1,nonce:attempt,outcome:'old-web-restored-lock-retained',id:web.id,image:web.image,startedAt:containers.find(c=>c.Id===web.id).State.StartedAt,web:200,auth:401,backendEpochsUnchanged:true,normalizedControlsMatchArchivedAuthority:true,firstPostcheck:'CONTROL_CHANGED',startDispatchCount:1,migration:false,lockRetained:true,terminalizationAuthorized:false},
    'built-api.json':{role:'api',...candidate},'retain-api-submission.json':{role:'api',image:apiOld.image,tag:candidate.oldTag},'build-api-submission.json':{role:'api',tag:candidate.tag,oldTag:candidate.oldTag,lifecycle:false},
  };
  for (const [name,value] of Object.entries(records)) put(join(audit,name),value);
  const owner = {version:2,nonce:attempt,kind:'preserving-deployment'};
  put(join(lock,'deploy-adapter-owner.json'),owner);
  for (const [name,value] of Object.entries({'profile.json':{},'llm-profile.json':{},'compose.images.json':{services:model.services},'compose.llm-env.json':{},'compose.cve.json':{},'scan-jwt':{synthetic:'metadata-only'}})) put(join(state,name),value);
  let failGuardMove = false;
  const moves = [], calls = [];
  const modules = {
    'node:fs':{...fs,renameSync(from,to) {
      moves.push([from,to]);
      if (from===guard && failGuardMove) throw Error('synthetic guard move failure');
      fs.renameSync(from,to);
    }},
    'node:crypto':await import('node:crypto'),'node:path':await import('node:path'),'node:url':await import('node:url'),'node:util':await import('node:util'),
    'node:http':{get(){throw Error('Real HTTP forbidden');}},
    './public-image-stand.mjs':{PROJECT:project,STATE:'synthetic-state',LABEL:'synthetic-label',CONFIG_SECRET:'fake-placeholder',readProfile:()=>({cve:{}}),runIsolatedDocker(){throw Error('Real Docker forbidden');},assertReconciliationHistory:noOp},
    './public-llm-stand.mjs':{capturePublicLlmSource:()=>({manifest:[],verify:noOp}),readPublicLlmBinding:()=>({}),expectedPublicLlmConfig:()=>structuredClone(model),publicLlmEnvironmentOverlay:()=>({}),validatePublicLlmContainer:noOp,validatePublicLlmImage:noOp,validatePublicLlmKeyVolume:noOp,capturePublicLlmRetentions:()=>({receipts:[],verify:noOp}),validateCurrentAuditHistory:noOp,validateLlmSelection:noOp},
    './public-llm-deployment-catalog.mjs':{DEPLOYMENT_TOTAL_LIMIT:20,DEPLOYMENT_RETAINED_REFERENCE_LIMIT:20,captureDeploymentCatalog:()=>({entries:[],verify:noOp})},
    './public-llm-build-continuation.mjs':{privateFile,byteFile,directoryIdentity},
    './setup-local-cve.mjs':{writeExclusive:(p,v,mode)=>fs.writeFileSync(p,v,{flag:'wx',mode}),syncDirectory:noOp},
    './public-llm-source-build.mjs':{validateOpenAiVolume:noOp},
    './local-stand.mjs':{dockerEnvironment:()=>({})},
    './public-image-stand-profile.mjs':{publicImageCveConfig:()=>({})},
  };
  const make = (text,name) => new vm.SourceTextModule(text,{identifier:`file:///offline/scripts/${name}`,initializeImportMeta(meta){meta.url=`file:///offline/scripts/${name}`;}});
  const restoredModule = make(restoredSource,'deploy-reconcile-restored.mjs');
  const link = specifier => {
    if (specifier==='./deploy-reconcile-restored.mjs') return restoredModule;
    assert.ok(Object.hasOwn(modules,specifier),`Unexpected import ${specifier}`);
    const exports=modules[specifier];
    return new vm.SyntheticModule(Object.keys(exports),function(){for(const [key,value] of Object.entries(exports))this.setExport(key,value);});
  };
  await restoredModule.link(link);
  await restoredModule.evaluate();
  const module = make(source,'deploy-reconcile-web.mjs');
  await module.link(link); await module.evaluate();
  const wire = c => JSON.stringify({...c,Config:{...c.Config,Env:[...c.Config.Env,null],__keyPresent:false,__end:null},__end:null});
  const run = async args => {
    calls.push(args);
    const [kind,action] = args;
    if (kind==='context') return JSON.stringify('unix:///synthetic.sock');
    if (kind==='info') return JSON.stringify(intent.daemon);
    if (action==='ls') return args.some(a=>a.startsWith('id='))?'':kind==='container'?containers.map(c=>c.Id).join('\n'):'';
    assert.equal(action,'inspect','Only read-only runtime calls allowed');
    if (kind==='container') return containers.map(wire).join('\n');
    if (kind==='image') {
      const ref=args[2], retained=ref.startsWith('dip-deploy-');
      return wire({Id:ref===candidate.tag?candidate.image:apiOld.image,RepoTags:retained?[ref]:[],Config:{Env:[]}});
    }
    return '[]';
  };
  const prepare = (branch='web') => module.namespace.prepareWebReconciliation({attempt,historicalIntent:hash(JSON.stringify(intent)),branch,root,run,request:async path=>path==='/'?200:401,home:root});
  const configureFenced = () => {
    for (const name of ['failure-fenceadmissions.json','stop-web-submission.json','compensation-web-start-submission.json','compensation-web-restored.json']) fs.unlinkSync(join(audit,name));
    fs.mkdirSync(join(audit,'snapshots/fenced'),{recursive:true,mode:0o700});
    const stoppedAt='2026-01-01T01:00:00Z', helperAt='2026-01-01T02:00:00Z';
    const helper={id:'e'.repeat(64),image:apiOld.image,name:`${project}-llm-${attempt}-fenced`,status:'running',exit:0,network:'none',originalMountsReadOnly:true,policyValidated:true,startedAt:helperAt};
    const prior=containers.map(c=>{
      const role=c.Config.Labels['com.docker.compose.service'], e=epoch(c);
      e[1]=old.find(v=>v.id===c.Id).startedAt;
      if (['web','api','worker'].includes(role)) {
        e[2]=stoppedAt; e[3]=0; e[5]=false; e[6]='exited';
        c.State.StartedAt='2026-01-02T00:00:00Z'; c.State.FinishedAt=stoppedAt;
      }
      return {id:c.Id,image:c.Image,control:restoredModule.namespace.restoredControl(c),epoch:e};
    });
    const rows={
      'fenced.json':{writers:['web','api','worker'],drain:{jobs:0,outbox:0,leases:0}},
      'failure-snapshot.json':{code:'HELPER_CONTROL_CHANGED'},
      'helper-fenced-submission.json':{name:helper.name,image:helper.image,purpose:'backup'},
      'helper-fenced-created.json':{id:helper.id},'helper-fenced-start-submission.json':{id:helper.id},
      'compensation-restore-authority.json':{version:1,nonce:attempt,operation:'retire-exact-ro-helper-and-start-same-old-writers',publishedConfigUnchanged:true,lockRetained:true,old:prior,helper,recoveryDigest:hash(JSON.stringify(recovery))},
      'compensation-helper-stop-submission.json':{id:helper.id},
      'compensation-helper-remove-submission.json':{id:helper.id,exit:0,originalMountsReadOnly:true},
      'compensation-helper-retired.json':{id:helper.id,exit:0,removed:true},
      'compensation-api-healthy.json':{id:apiOld.id,healthy:true},
      'compensation-old-restored.json':{version:1,nonce:attempt,outcome:'old-writers-restored-lock-retained',web:200,auth:401,apiHealthy:true,startedSameOldIds:['worker','api','web'],helperRemoved:helper.id,gatewaysUnchanged:true,publishedConfigUnchanged:true,migration:false,databaseRestore:false,snapshotResumed:false,lockRetained:true},
    };
    for(const role of ['web','api','worker']) {
      const c=containers.find(c=>c.Config.Labels['com.docker.compose.service']===role);
      rows[`stop-${role}-submission.json`]={role,id:c.Id,image:c.Image};
      rows[`stop-${role}-observation.json`]={role,dispatch:'exit-zero',acknowledgement:'id',stdoutBytes:65,deprecatedTimeWarning:false,sameControl:true,sameStart:true,exited:true,running:false,zeroPid:true,cleanWriterStop:true,exitCode:0};
      rows[`stop-${role}-complete.json`]={id:c.Id,exit:0,startedAt:'2026-01-01T00:00:00Z',finishedAt:stoppedAt};
      rows[`compensation-start-${role}-submission.json`]={id:c.Id,image:c.Image,operation:'start-same-old-id'};
      rows[`compensation-started-${role}.json`]={id:c.Id,image:c.Image,epoch:epoch(c)};
    }
    const probe={id:'f'.repeat(64),image:apiOld.image,name:`${project}-llm-${'b'.repeat(32)}-fenced`};
    Object.assign(rows,{
      'probe-helper-create-submission.json':{version:1,purpose:'create-start-control-difference-no-real-stores',name:probe.name,image:probe.image,volumeMounts:0,bindMounts:0,network:'none',processDeadlineMs:30000},
      'probe-helper-created.json':probe,'probe-helper-start-submission.json':{id:probe.id},'probe-helper-stop-submission.json':{id:probe.id},
      'probe-helper-control-difference.json':{version:1,id:probe.id,image:probe.image,adapterControlEqual:false,changedFields:['HostConfig.OomKillDisable'],createdMounts:[],startedMounts:[],memorySwappiness:{before:null,after:null},oomKillDisable:{before:false,after:null},realStoreMounts:0,network:'none'},
      'probe-helper-remove-submission.json':{version:1,...probe,daemon:recovery.daemon,exitCode:137,oomKilled:false,restartCount:0,network:'none',realStoreMounts:0,cleanExit:false,action:'remove-exited-owned-disposable-no-force',submittedAt:'2026-01-03T00:00:00Z'},
      'probe-helper-retired.json':{version:1,id:probe.id,removed:true,exitCode:137,cleanExit:false,originalEvidencePreserved:true,retiredAt:'2026-01-03T00:00:01Z'},
    });
    for(const [name,value] of Object.entries(rows)) {
      put(join(audit,name),value);
      // Equal filesystem timestamps satisfy nondecreasing append order without sleeps.
      fs.utimesSync(join(audit,name),1767225600,1767225600);
    }
  };
  return {root,audit,lock,guard,guardArchive,prepare,configureFenced,api:module.namespace,moves,calls,put,owner,failMove:()=>{failGuardMove=true;}};
}

const binding = p => ({review:p.summary.review,source:p.summary.source});

test('complete v2 old-restored is history-compatible and archives guard last',async t=>{
  const f=await fixture(t), ownerBytes=fs.readFileSync(join(f.lock,'deploy-adapter-owner.json'));
  const originals=fs.readdirSync(f.audit).map(name=>[name,fs.readFileSync(join(f.audit,name))]);
  const p=await f.prepare(), result=await p.apply(binding(p));
  assert.equal(result.outcome,'WEB_ATTEMPT_RECONCILED');
  const complete=JSON.parse(fs.readFileSync(join(f.audit,'complete.json')));
  assert.equal(complete.version,2); assert.equal(complete.outcome,'old-restored');
  assert.deepEqual(complete.evidence,f.api.webReconcileEvidenceIndex(f.audit));
  const history=f.api.validateWebReconcileHistory(f.root); history.verify();
  assert.equal(history.count,1); assert.equal(history.references.length,2);
  for(const [name,bytes] of originals) assert.deepEqual(fs.readFileSync(join(f.audit,name)),bytes);
  assert.deepEqual(fs.readFileSync(join(f.audit,'operation.lock/deploy-adapter-owner.json')),ownerBytes);
  assert.deepEqual(f.moves,[[f.lock,join(f.audit,'operation.lock')],[f.guard,f.guardArchive]]);
  assert.ok(fs.existsSync(join(f.guardArchive,'intent.json')));
  assert.ok(!fs.existsSync(f.guard)&&!fs.existsSync(f.lock));
});

test('later-stage journal and foreign lock authority refuse before runtime or moves',async t=>{
  const f=await fixture(t), extra=join(f.audit,'stop-api-submission.json');
  f.put(extra,{});
  await assert.rejects(f.prepare(),/WEB_RECONCILE_UNEXPECTED_STAGE/);
  fs.unlinkSync(extra);
  f.put(join(f.lock,'deploy-adapter-owner.json'),{...f.owner,nonce:'f'.repeat(32)});
  await assert.rejects(f.prepare(),/WEB_RECONCILE_LOCK_OWNER/);
  assert.deepEqual(f.calls,[]); assert.deepEqual(f.moves,[]);
  assert.ok(!fs.existsSync(f.guard));
});

test('failure after operation-lock move leaves recognized HOLD and valid history',async t=>{
  const f=await fixture(t), p=await f.prepare(); f.failMove();
  await assert.rejects(p.apply(binding(p)),/synthetic guard move failure/);
  const intent=JSON.parse(fs.readFileSync(join(f.guard,'intent.json')));
  assert.equal(intent.command,'reconcile-stopped-web-only'); assert.equal(intent.attempt,attempt);
  assert.ok(fs.existsSync(join(f.audit,'operation.lock/deploy-adapter-owner.json')));
  assert.ok(!fs.existsSync(f.lock)&&!fs.existsSync(f.guardArchive));
  const history=f.api.validateWebReconcileHistory(f.root); history.verify(); assert.equal(history.count,1);
  assert.equal(f.moves.at(-1)[0],f.guard);
});

test('fenced-writer restoration rejects exports/later stages then completes real history with probe evidence',async t=>{
  const f=await fixture(t); f.configureFenced();
  const exportPath=join(f.audit,'snapshots/fenced/export.json');
  f.put(exportPath,{synthetic:true});
  await assert.rejects(f.prepare('fenced-writers'),/WEB_RECONCILE_HOST_SNAPSHOT_NOT_EMPTY/);
  fs.unlinkSync(exportPath);
  const later=join(f.audit,'candidate-api-start-submission.json');
  f.put(later,{});
  await assert.rejects(f.prepare('fenced-writers'),/WEB_RECONCILE_FENCED_UNEXPECTED_STAGE/);
  fs.unlinkSync(later);
  assert.deepEqual(f.calls,[]); assert.deepEqual(f.moves,[]);
  const originals=fs.readdirSync(f.audit).filter(n=>n.endsWith('.json')).map(n=>[n,fs.readFileSync(join(f.audit,n))]);
  const p=await f.prepare('fenced-writers');
  assert.equal(p.summary.branch,'fenced-writers');
  assert.equal(p.summary.hostSnapshotCompleted,false);
  assert.equal(p.summary.helperMayHaveReadStores,true);
  const result=await p.apply(binding(p));
  assert.equal(result.outcome,'WEB_ATTEMPT_RECONCILED');
  for(const [name,bytes] of originals) assert.deepEqual(fs.readFileSync(join(f.audit,name)),bytes);
  const receipt=JSON.parse(fs.readFileSync(join(f.audit,'complete.json')));
  assert.equal(receipt.version,2); assert.equal(receipt.outcome,'old-restored');
  assert.deepEqual(receipt.evidence,f.api.webReconcileEvidenceIndex(f.audit));
  assert.ok(receipt.evidence.some(e=>e.path==='probe-helper-retired.json'));
  assert.deepEqual(fs.readdirSync(join(f.audit,'snapshots/fenced')),[]);
  const history=f.api.validateWebReconcileHistory(f.root); history.verify();
  assert.equal(history.count,1); assert.equal(history.references.length,2);
  assert.deepEqual(f.moves,[[f.lock,join(f.audit,'operation.lock')],[f.guard,f.guardArchive]]);
  const guardIntent=JSON.parse(fs.readFileSync(join(f.guardArchive,'intent.json')));
  assert.equal(guardIntent.command,'reconcile-fenced-writers-restored');
});
