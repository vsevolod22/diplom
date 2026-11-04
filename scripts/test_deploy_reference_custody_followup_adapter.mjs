// Follow-up source qualification uses only fake engine/HTTP and test-owned state.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { adapterFixture } from './test_deploy_history_v5_batch26_fixture.mjs';
import { runDeployment } from './deploy-core.mjs';
import { deployAdapterDiagnostic } from './deploy-adapter.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
const options={mode:'app',services:['web','api'],apply:true,migrateHistoryV4ToV5:true};
const roles=['api','worker','web','egress','llm-egress','openai-egress'];
const read=p=>JSON.parse(fs.readFileSync(p));
function audits(f){return fs.readdirSync(join(f.stand,'deploy-adapter-v1')).map(n=>join(f.stand,'deploy-adapter-v1',n));}
function seed(f,{metadataFiles=0}={}){
  const base=join(f.stand,'deploy-adapter-v1');fs.mkdirSync(base,{mode:0o700});let remaining=119,extra=metadataFiles;
  for(let n=0;remaining>0;n++){
    const nonce=(n+1).toString(16).padStart(32,'0'),dir=join(base,nonce),references=[],evidence=[];
    fs.mkdirSync(dir,{mode:0o700});fs.mkdirSync(join(dir,'operation.lock'),{mode:0o700});
    fs.writeFileSync(join(dir,'operation.lock/deploy-adapter-owner.json'),JSON.stringify({version:2,nonce,kind:'preserving-deployment'}),{mode:0o600});
    for(const name of roles)for(const kind of ['old','candidate'])if(remaining>0){const image=f.pins().services[name].image,tag=`dip-deploy-${name}:${kind}-${nonce}`;f.images.get(image).RepoTags.push(tag);references.push({name,image,tag});remaining--;}
    for(let i=0;i<220&&extra>0;i++,extra--){const path='metadata-'+String(i).padStart(4,'0')+'.json',bytes=Buffer.from('{}');fs.writeFileSync(join(dir,path),bytes,{mode:0o600});evidence.push({path,bytes:bytes.length,sha256:hash(bytes)});}
    fs.writeFileSync(join(dir,'complete.json'),JSON.stringify({version:2,project:'dip-public-images',nonce,outcome:'published',references,evidence}),{mode:0o600});
  }
  assert.equal(extra,0);const tags=new Set([...f.images.values()].flatMap(i=>i.RepoTags));let i=0;
  while(tags.size<126){const tag='fixture-extra:initial-'+i++;f.images.get(f.pins().services.api.image).RepoTags.push(tag);tags.add(tag);}
}
async function originalBuiltAbort(f){
  const original=f.adapter.prepareRecovery;
  f.adapter.prepareRecovery=async ctx=>{
    await original(ctx);
    const dir=join(f.stand,'deploy-adapter-v1',ctx.candidate.attempt);
    // Model the settled pre-fence JOURNAL_SIZE acknowledgement, not an engine
    // failure or partial migration. The production origin selector authenticates
    // the actual completed/evidence-bound receipt before permitting reuse.
    fs.writeFileSync(join(dir,'failure-preparerecovery.json'),JSON.stringify({code:'JOURNAL_SIZE'}),{mode:0o600});
    throw Object.assign(Error('synthetic original record limit'),{code:'DEPLOY_RECOVERY'});
  };
  const result=await runDeployment(f.adapter,options);assert.equal(result.ok,false);assert.equal(result.lock,'released');assert.ok(!f.events.includes('stop:web'));
  f.adapter.prepareRecovery=original;
  const dir=audits(f).find(p=>fs.existsSync(join(p,'failure-preparerecovery.json')));
  const complete=read(join(dir,'complete.json'));assert.equal(complete.version,3);assert.equal(complete.outcome,'pre-mutation-aborted');assert.equal(complete.references.length,2);
  return {dir,nonce:complete.nonce,complete,bytes:fs.readFileSync(join(dir,'complete.json'))};
}
for(const recover of [false,true])test('zero-headroom original built candidates reused '+(recover?'through sealed v4 prestart recovery':'normal publication')+' with current qualification, no new build/tag',async t=>{
  let f,qualifications=0,armed=false,crashed=false;
  f=await adapterFixture(t,{qualificationHook(){qualifications++;},clockHook(){
    if(!f||!armed||crashed)return;
    if(audits(f).some(dir=>fs.existsSync(join(dir,'history-v5-prestart.json'))&&!fs.existsSync(join(dir,'complete.json')))){
      crashed=true;throw Error('synthetic sealed reused-candidate executor loss');
    }
  }});seed(f);
  const origin=await originalBuiltAbort(f);assert.equal(qualifications,1);
  const originalCalls=f.calls.length,oldImages=Object.fromEntries([...f.images].map(([id,row])=>[id,[...row.RepoTags]]));
  fs.appendFileSync(join(f.root,'scripts/deploy-reference-custody.mjs'),'\n// new orchestration only, not shipped COPY source\n');
  const plan=await f.rawAdapter.prepare({mode:'app',services:['api','web'],migrateHistoryV4ToV5:true});
  assert.equal(plan.referenceCustody.version,2);assert.equal(plan.newReferenceCount,0);assert.ok(plan.referenceCustody.candidates.every(r=>r.origin.nonce===origin.nonce));
  assert.equal(qualifications,1,'read-only planning is not build qualification');
  armed=recover;
  const result=await runDeployment(f.adapter,options);
  if(recover){
    assert.equal(crashed,true);assert.equal(result.ok,false);assert.equal(result.lock,'retained');f.releaseSupervisor();
    const dir=audits(f).find(p=>fs.existsSync(join(p,'history-v5-prestart.json'))&&!fs.existsSync(join(p,'complete.json'))),nonce=dir.split('/').at(-1),fresh=f.freshAdapter();
    const plan=await fresh.planRecovery({options:{audit:nonce}});assert.equal(plan.eligible,true);f.acquireSupervisor();
    assert.equal((await fresh.applyRecovery({options:{audit:nonce,apply:true,checkpoint:plan.checkpoint}})).recovered,true);
  }else assert.equal(result.ok,true,JSON.stringify({result,diagnostics:f.diagnostics}));
  assert.equal(qualifications,2,'current genuine build qualification seam must be rerun before adoption');
  assert.ok(!f.calls.slice(originalCalls).some(c=>c[0]==='build'||c[0]==='image'&&c[1]==='tag'));
  assert.deepEqual(Object.fromEntries([...f.images].map(([id,row])=>[id,row.RepoTags])),oldImages);
  assert.deepEqual(fs.readFileSync(join(origin.dir,'complete.json')),origin.bytes,'original sealed receipt remains byte-identical');
  const dir=audits(f).find(p=>fs.existsSync(join(p,'complete.json'))&&read(join(p,'complete.json')).version===4),complete=read(join(dir,'complete.json'));
  assert.equal(complete.references.length,0);assert.equal(complete.borrowedReferences.length,4);assert.equal(complete.reuseOrigin.nonce,origin.nonce);
  const proof=read(join(dir,'candidate-reuse.json'));assert.equal(proof.source.originalSource,proof.source.currentSource);
  assert.notDeepEqual(proof.source.originalEntrySources,proof.source.currentEntrySources,'old orchestration must not be relabeled current');
  for(const name of ['intent.json','built.json','recovery.json','history-v5-prestart.json',recover?'recovery-v5/published.json':'published.json'])assert.deepEqual(read(join(dir,name)).referenceCustody,complete.referenceCustody);
  assert.equal(f.events.filter(e=>e==='migration:dispatch').length,1);assert.equal(f.locked(),false);
});
test('current build qualification failure prevents adoption/fence even with valid sealed candidate metadata',async t=>{
  let reject=false,qualifications=0;const f=await adapterFixture(t,{qualificationHook(){qualifications++;if(reject)throw Error('synthetic current compile failure');}});seed(f);
  const origin=await originalBuiltAbort(f);reject=true;const calls=f.calls.length;
  const result=await runDeployment(f.adapter,options);assert.equal(result.ok,false);assert.equal(qualifications,2);assert.ok(!f.events.includes('stop:web'));
  assert.ok(!f.calls.slice(calls).some(c=>c[0]==='build'||c[0]==='image'&&c[1]==='tag'));assert.deepEqual(fs.readFileSync(join(origin.dir,'complete.json')),origin.bytes);
  assert.equal(f.locked(),false);
});
for(const fault of ['shipped-source','same-id-restart','candidate-tag-loss'])test('sealed candidate proof refuses '+fault+' before new lock or image dispatch',async t=>{
  const f=await adapterFixture(t);seed(f);const origin=await originalBuiltAbort(f),calls=f.calls.length,names=audits(f).sort();
  if(fault==='shipped-source')fs.appendFileSync(join(f.root,'src/main.tsx'),'\n// changed shipped bytes\n');
  if(fault==='same-id-restart')f.containers().find(c=>f.role(c)==='api').State.StartedAt='2026-11-04T18:00:00.000Z';
  if(fault==='candidate-tag-loss'){const row=origin.complete.references[0];f.images.get(row.image).RepoTags=f.images.get(row.image).RepoTags.filter(t=>t!==row.tag);}
  await assert.rejects(f.rawAdapter.prepare({mode:'app',services:['api','web'],migrateHistoryV4ToV5:true}));
  assert.equal(f.locked(),false);assert.deepEqual(audits(f).sort(),names);assert.deepEqual(fs.readFileSync(join(origin.dir,'complete.json')),origin.bytes);
  assert.ok(!f.calls.slice(calls).some(c=>c[0]==='build'||c[0]==='image'&&c[1]==='tag'));
});
test('oversized full authority/checkpoint preview refuses before lock/build and cannot consume the last image names',async t=>{
  const f=await adapterFixture(t);seed(f);
  // Unknown neutral engine metadata remains identity evidence; never trim it to
  // obtain admission. This synthetically exercises the independent byte bound.
  f.containers().find(c=>f.role(c)==='api').HostConfig['x'.repeat(7*1024**2)]=null;
  await assert.rejects(f.rawAdapter.prepare({mode:'app',services:['api','web'],migrateHistoryV4ToV5:true}),e=>deployAdapterDiagnostic(e).code==='RECOVERY_RECORD_CAPACITY');
  const count=audits(f).length,result=await runDeployment(f.adapter,options);assert.equal(result.ok,false);assert.equal(f.locked(),false);assert.equal(audits(f).length,count);
  assert.ok(!f.calls.some(c=>c[0]==='build'||c[0]==='image'&&c[1]==='tag'||c[0]==='create'));
});

test('full >256KiB historical metadata authority is admitted before build and written without dropping fields',async t=>{
  const f=await adapterFixture(t);seed(f,{metadataFiles:1600});
  const acquired=await f.rawAdapter.acquireLock({mode:'app',services:['api','web'],options}),ctx={mode:'app',services:['api','web'],options,lease:acquired};
  ctx.plan=await f.rawAdapter.preflight(ctx);ctx.candidate=await f.rawAdapter.build(ctx);await f.rawAdapter.validateCandidate(ctx);await f.rawAdapter.prepareRecovery(ctx);
  const dir=join(f.stand,'deploy-adapter-v1',ctx.candidate.attempt),bytes=fs.readFileSync(join(dir,'authority-v3.json')),record=JSON.parse(bytes);
  assert.ok(bytes.length>262144,'must reproduce the actual old writer mismatch');assert.ok(record.files.history.length>=1600);
  assert.equal(record.files.history.filter(r=>r.path.endsWith('.json')&&r.path.includes('/metadata-')).length,1600);
  await f.rawAdapter.releaseLock(ctx);assert.equal(f.locked(),false);
});
