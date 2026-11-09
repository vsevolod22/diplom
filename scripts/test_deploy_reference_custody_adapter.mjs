// Real adapter + real isolated SQLite, injected engine/HTTP only. No Docker process.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { adapterFixture } from './test_deploy_history_v5_batch26_fixture.mjs';
import { runDeployment } from './deploy-core.mjs';
import { deployAdapterDiagnostic } from './deploy-adapter.mjs';
import { parseImageInventory } from './deploy-reference-custody.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
const roles=['api','worker','web','egress','llm-egress','openai-egress'];
const options={mode:'app',services:['web','api'],apply:true,migrateHistoryV4ToV5:true};
function seedHistory(f,count=119) {
  const parent=join(f.stand,'deploy-adapter-v1');fs.mkdirSync(parent,{mode:0o700});
  const originals=[];
  for(let i=0;count>0;i++){
    const nonce=(i+1).toString(16).padStart(32,'0'),dir=join(parent,nonce),references=[];
    fs.mkdirSync(dir,{mode:0o700});fs.mkdirSync(join(dir,'operation.lock'),{mode:0o700});
    fs.writeFileSync(join(dir,'operation.lock/deploy-adapter-owner.json'),JSON.stringify({version:2,nonce,kind:'preserving-deployment'}),{mode:0o600});
    for(const name of roles)for(const kind of ['old','candidate'])if(count>0){
      const image=f.pins().services[name].image,tag=`dip-deploy-${name}:${kind}-${nonce}`;
      f.images.get(image).RepoTags.push(tag);references.push({name,tag,image});count--;
    }
    const path=join(dir,'complete.json'),bytes=JSON.stringify({version:2,project:'dip-public-images',nonce,outcome:'published',references,evidence:[]});
    fs.writeFileSync(path,bytes,{mode:0o600});originals.push({path,bytes});
  }
  return originals;
}
function fillInventory(f,count,{dangling=1}={}) {
  const tags=new Set([...f.images.values()].flatMap(i=>i.RepoTags));let n=0;
  const image=f.images.get(f.pins().services.api.image);
  while(tags.size<count){const tag='fixture-extra:alias-'+n++;image.RepoTags.push(tag);tags.add(tag);}
  assert.equal(tags.size,count);
  for(let i=0;i<dangling;i++){const id='sha256:'+hash('dangling-'+i);f.images.set(id,{Id:id,RepoTags:[]});}
}
function attempts(f){return fs.readdirSync(join(f.stand,'deploy-adapter-v1')).map(n=>join(f.stand,'deploy-adapter-v1',n));}
function read(path){return JSON.parse(fs.readFileSync(path));}
function completed(f){return attempts(f).map(dir=>({dir,...read(join(dir,'complete.json'))})).find(r=>r.version===3);}
function engineInventory(f){return parseImageInventory([...f.images.values()].flatMap(i=>(i.RepoTags.length?i.RepoTags:['<none>:<none>']).map(tag=>tag+'\t'+i.Id)).join('\n'));}
test('254 concrete +1 untagged /247 required: genuine adapter4→5 borrows2/builds2/completes3; all old receipts untouched',async t=>{
  const f=await adapterFixture(t),originals=seedHistory(f,247);fillInventory(f,254);
  const plan=await f.rawAdapter.prepare({mode:'app',services:['web','api'],migrateHistoryV4ToV5:true});
  assert.equal(plan.newReferenceCount,2);assert.ok(plan.referenceCustody.old.every(r=>r.ownership==='borrowed'));
  assert.equal(f.locked(),false);assert.equal(f.calls.some(c=>['tag','build','create','up','stop'].includes(c[0])),false);
  const result=await runDeployment(f.adapter,options);assert.equal(result.ok,true,JSON.stringify({result,diagnostics:f.diagnostics}));
  assert.equal(result.receipt.historyMigration,'history-reservations-v4-to-v5');assert.equal(f.locked(),false);
  const complete=completed(f);assert.ok(complete);assert.equal(complete.references.length,2);assert.equal(complete.borrowedReferences.length,2);
  assert.equal(f.calls.filter(c=>c[0]==='image'&&c[1]==='tag').length,0,'borrowed tags are NEVER retagged');
  assert.equal(f.calls.filter(c=>c[0]==='build').length,2);
  const census=engineInventory(f);assert.equal(census.concrete.size,256);assert.equal(census.untagged.size,1);
  for(const name of ['intent.json','built.json','recovery.json','published.json','history-v5-prestart.json'])assert.deepEqual(read(join(complete.dir,name)).referenceCustody,complete.referenceCustody,name+' same custody');
  assert.deepEqual(read(join(complete.dir,'authority-v3.json')).files.referenceCustody,complete.referenceCustody);
  const cp=read(join(complete.dir,'history-v5-prestart.json'));assert.equal(cp.files.references.length,247);assert.equal(cp.entrySources.length,7);
    const retained=originals.flatMap(({bytes})=>{
        const record=JSON.parse(bytes);
        return record.references.map(r=>({...r,origin:{kind:'adapter-completion',nonce:record.nonce,sha256:hash(bytes)}}));
      });
    assert.deepEqual(cp.files.references,retained.slice().sort((a,b)=>a.tag.localeCompare(b.tag)));
    for(const r of retained)assert.equal(census.concrete.get(r.tag),r.image);
  assert.equal(f.events.indexOf('migration:committed')<f.events.indexOf('up:api'),true);
  for(const {path,bytes}of originals)assert.equal(fs.readFileSync(path,'utf8'),bytes);
  const statusPlan=await f.rawAdapter.prepare({mode:'app',services:['web','api']}).catch(e=>e);
  // History parsing accepts the NEW completion; a further two-tag build legitimately
  // refuses at256, rather than losing the original obligations or reusing candidates.
  assert.equal(deployAdapterDiagnostic(statusPlan).code,'IMAGE_REFERENCE_CAPACITY');
});
for(const count of [255,256])test('actual read-only plan refuses '+count+' concrete before lock/fence/write',async t=>{
  const f=await adapterFixture(t);seedHistory(f,2);fillInventory(f,count);
  const before=attempts(f).flatMap(dir=>fs.readdirSync(dir).map(n=>dir+'/'+n));
  await assert.rejects(f.rawAdapter.prepare({mode:'app',services:['api','web'],migrateHistoryV4ToV5:true}),e=>deployAdapterDiagnostic(e).code==='IMAGE_REFERENCE_CAPACITY');
  assert.equal(f.locked(),false);assert.deepEqual(attempts(f).flatMap(dir=>fs.readdirSync(dir).map(n=>dir+'/'+n)),before);
  const applied=await runDeployment(f.adapter,options);assert.equal(applied.ok,false);assert.equal(f.locked(),false);
  assert.deepEqual(attempts(f).flatMap(dir=>fs.readdirSync(dir).map(n=>dir+'/'+n)),before,'APPLY capacity refusal is also before shared lock/attempt writes');
  assert.ok(!f.calls.some(c=>c[0]==='build'||c[0]==='create'||c[0]==='image'&&c[1]==='tag'||c[0]==='container'&&['start','stop'].includes(c[1])));
});
test('former128 adapter boundary now admits a plan without losing retained references or writing a fence',async t=>{
  const f=await adapterFixture(t),originals=seedHistory(f,119);fillInventory(f,128);
  const before=attempts(f);
  const plan=await f.rawAdapter.prepare({mode:'app',services:['api','web'],migrateHistoryV4ToV5:true});
  assert.equal(plan.newReferenceCount,2);assert.ok(plan.referenceCustody.old.every(r=>r.ownership==='borrowed'));
  assert.equal(engineInventory(f).concrete.size,128);assert.equal(f.locked(),false);assert.deepEqual(attempts(f),before);
  for(const {path,bytes}of originals){assert.equal(fs.readFileSync(path,'utf8'),bytes);for(const r of JSON.parse(bytes).references)assert.equal(engineInventory(f).concrete.get(r.tag),r.image);}
  assert.ok(!f.calls.some(c=>c[0]==='build'||c[0]==='create'||c[0]==='image'&&['tag','rm','prune'].includes(c[1])||c[0]==='container'&&['start','stop'].includes(c[1])));
});
test('no original old-image authority falls back to4 new owned tags and v3 completion',async t=>{
  const f=await adapterFixture(t,{historyVersion:5});const result=await runDeployment(f.adapter,{...options,migrateHistoryV4ToV5:false});
  assert.equal(result.ok,true,JSON.stringify({result,diagnostics:f.diagnostics}));
  const complete=completed(f);assert.equal(complete.references.length,4);assert.equal(complete.borrowedReferences.length,0);
  assert.equal(f.calls.filter(c=>c[0]==='image'&&c[1]==='tag').length,2);
  assert.ok(complete.referenceCustody.old.every(r=>r.ownership==='owned'));
});
test('borrowed tag loss between first and second build retains HOLD with original tags/evidence, no fence or retag',async t=>{
  let lost=false;const f=await adapterFixture(t,{engineHook({args,images,events}){
    if(!lost&&events.includes('build:api')&&args[0]==='image'&&args[1]==='ls'&&args.includes('--no-trunc')){
      const tag=`dip-deploy-web:old-${'1'.padStart(32,'0')}`;
      for(const image of images.values())if(image.RepoTags.includes(tag)){image.RepoTags=image.RepoTags.filter(v=>v!==tag);lost=true;}
    }
  }});seedHistory(f,12);fillInventory(f,126);
  const result=await runDeployment(f.adapter,options);assert.equal(lost,true);assert.equal(result.ok,false);assert.equal(result.lock,'retained');
  assert.ok(f.locked());assert.equal(f.calls.filter(c=>c[0]==='build').length,1);assert.equal(f.calls.filter(c=>c[0]==='image'&&c[1]==='tag').length,0);
  assert.ok(!f.events.includes('stop:web'));assert.ok(attempts(f).some(dir=>fs.existsSync(join(dir,'reference-custody.json'))&&!fs.existsSync(join(dir,'complete.json'))));
});
test('failure after first borrowed candidate build preserves all119 old obligations, HOLD and no cleanup',async t=>{
  let failed=false;const f=await adapterFixture(t,{engineHook({args,events}){
    if(args[0]==='build'&&events.includes('build:api')){failed=true;throw Error('synthetic second build failure');}
  }});const originals=seedHistory(f);fillInventory(f,126);
  const result=await runDeployment(f.adapter,options);assert.equal(failed,true);assert.equal(result.ok,false);assert.equal(result.lock,'retained');assert.ok(f.locked());
  assert.equal(f.calls.filter(c=>c[0]==='image'&&c[1]==='tag').length,0);
  assert.ok(!f.calls.some(c=>c[0]==='image'&&['rm','prune'].includes(c[1])));assert.ok(!f.events.includes('stop:web'));
  for(const {path,bytes}of originals)assert.equal(fs.readFileSync(path,'utf8'),bytes);
  assert.equal(engineInventory(f).concrete.size,127);
});
test('borrowed custody survives sealed4→5 prestart plan+recovery without migration replay or oldtag minting',async t=>{
  let f,crashed=false;f=await adapterFixture(t,{clockHook(){
    if(!f||crashed)return;
    const audit=attempts(f).find(dir=>fs.existsSync(join(dir,'history-v5-prestart.json'))&&!fs.existsSync(join(dir,'complete.json')));
    if(audit){crashed=true;throw Error('synthetic executor loss after sealed checkpoint, before first start submission');}
  }});
  const originals=seedHistory(f);fillInventory(f,126);
  const result=await runDeployment(f.adapter,options);assert.equal(crashed,true);assert.equal(result.ok,false);assert.equal(result.lock,'retained');
  assert.ok(!f.events.some(e=>e.startsWith('up:')));assert.equal(f.events.filter(e=>e==='migration:dispatch').length,1);
  const dir=attempts(f).find(dir=>fs.existsSync(join(dir,'history-v5-prestart.json'))),nonce=dir.split('/').at(-1);
  assert.ok(!fs.readdirSync(dir).some(n=>n.startsWith('start-')));
  const cp=read(join(dir,'history-v5-prestart.json'));assert.ok(cp.referenceCustody.old.every(r=>r.ownership==='borrowed'));
  assert.equal(cp.files.references.length,119);assert.ok(cp.files.references.every(r=>!Object.hasOwn(r,'config')));
  f.releaseSupervisor();
    const fresh=f.freshAdapter(),plan=await fresh.planRecovery({options:{audit:nonce}});
  assert.equal(plan.eligible,true);assert.equal(plan.migrationReplay,false);
  const borrowed=cp.referenceCustody.old.find(r=>r.name==='api'),oldImage=f.images.get(borrowed.image),savedTags=[...oldImage.RepoTags];
  oldImage.RepoTags=oldImage.RepoTags.filter(tag=>tag!==borrowed.tag);
  await assert.rejects(fresh.planRecovery({options:{audit:nonce}}),'recovery must not trust a lost borrowed tag');
  assert.ok(!fs.existsSync(join(dir,'recovery-v5')));assert.ok(f.locked());
  oldImage.RepoTags=savedTags;
  f.acquireSupervisor();
  const recovered=await fresh.applyRecovery({options:{audit:nonce,checkpoint:plan.checkpoint,apply:true}});
  assert.equal(recovered.recovered,true);assert.equal(f.locked(),false);
  assert.equal(f.events.filter(e=>e==='migration:dispatch').length,1,'committed migration must not replay');
  assert.equal(f.calls.filter(c=>c[0]==='image'&&c[1]==='tag').length,0);
  const complete=completed(f);assert.equal(complete.references.length,2);assert.equal(complete.borrowedReferences.length,2);
  assert.deepEqual(complete.referenceCustody,cp.referenceCustody);
  assert.deepEqual(read(join(dir,'recovery-v5/published.json')).referenceCustody,cp.referenceCustody);
  for(const {path,bytes}of originals)assert.equal(fs.readFileSync(path,'utf8'),bytes);
});

for(const fault of ['origin-receipt','helper-source','new-external-tag','same-id-restart','retarget-borrowed'])test('build revalidation rejects '+fault+' with no automatic cleanup/fence',async t=>{
  let f,changed=false,originals;
  f=await adapterFixture(t,{engineHook({args,events,images,containers}){
    if(!f||changed||!events.includes('build:api')||args[0]!=='container'||args[1]!=='inspect')return;
    changed=true;
    if(fault==='origin-receipt')fs.appendFileSync(originals[0].path,' ');
    if(fault==='helper-source')fs.appendFileSync(join(f.root,'scripts/deploy-reference-custody.mjs'),'\n// synthetic source drift\n');
    if(fault==='new-external-tag'){
          assert.equal(engineInventory(f).concrete.size,255,'first build consumes one of two reserved names');
          const i=images.get(f.pins().services.api.image);i.RepoTags.push('fixture-extra:unexpected-1','fixture-extra:unexpected-2');
          assert.equal(new Set([...images.values()].flatMap(i=>i.RepoTags)).size,257,'external tags cross the concrete256 bound');
        }
    if(fault==='same-id-restart')containers.find(c=>f.role(c)==='api').State.StartedAt='2026-11-04T12:00:00.000Z';
    if(fault==='retarget-borrowed'){
      const tag=`dip-deploy-web:old-${'1'.padStart(32,'0')}`;
      for(const i of images.values())i.RepoTags=i.RepoTags.filter(v=>v!==tag);
      images.get(f.pins().services.api.image).RepoTags.push(tag);
    }
  }});originals=seedHistory(f);fillInventory(f,254);
  const result=await runDeployment(f.adapter,options);
  assert.equal(changed,true);assert.equal(result.ok,false);assert.equal(result.lock,'retained');assert.ok(f.locked());
  assert.equal(f.calls.filter(c=>c[0]==='image'&&c[1]==='tag').length,0);assert.ok(!f.events.includes('stop:web'));
  assert.ok(!f.calls.some(c=>c[0]==='image'&&['rm','prune'].includes(c[1])));
  if(fault==='new-external-tag'){
    assert.equal(f.calls.filter(c=>c[0]==='build').length,1);
    assert.ok(!f.events.some(e=>e.startsWith('stop:')||e.startsWith('up:')),'overflow refuses before runtime fence/start');
    for(const {path,bytes}of originals)assert.equal(fs.readFileSync(path,'utf8'),bytes);
    for(const {bytes}of originals)for(const r of JSON.parse(bytes).references)assert.ok(f.images.get(r.image).RepoTags.includes(r.tag));
  }
});

test('actual plan independently refuses17 untagged images even with concrete headroom',async t=>{
  const f=await adapterFixture(t);seedHistory(f,2);fillInventory(f,124,{dangling:17});
  await assert.rejects(f.rawAdapter.prepare({mode:'app',services:['api','web'],migrateHistoryV4ToV5:true}),e=>deployAdapterDiagnostic(e).code==='UNTAGGED_IMAGE_CAPACITY');
  assert.equal(f.locked(),false);assert.ok(!f.calls.some(c=>c[0]==='build'||c[0]==='create'));
});
