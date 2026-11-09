// Offline only: disposable fake-engine incident; production guards/SQL/helper code.
import test,{after} from 'node:test';
import { tmpdir } from 'node:os';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { join,dirname } from 'node:path';
import { fileURLToPath,pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { EXACT_FORWARD_432,qualifyForward432Journal } from './deploy-forward-432.mjs';
import { parseForward432,forward432Main } from './deploy-forward-432-cli.mjs';
import { createDeployAdapter } from './deploy-adapter.mjs';
import { runDeployment } from './deploy-core.mjs';
import { runIsolatedDocker } from './public-image-stand.mjs';
const ROOT=dirname(dirname(fileURLToPath(import.meta.url)));
const DB=createRequire(new URL('../server/api/package.json',import.meta.url))('better-sqlite3');
const sha=b=>createHash('sha256').update(b).digest('hex');
const read=p=>JSON.parse(fs.readFileSync(p));
const journal=(last='READINESS_EXEC_FAILED',tail=[])=>[
 ...['HELPER_CREATE_FAILED','HELPER_START_FAILED','HELPER_REMOVE_FAILED','SERVICE_RECREATE_FAILED','SERVICE_RESUME_FAILED'].flatMap((code,i)=>[{seq:i+1,state:'submitted',code},{seq:i+1,state:'settled',exit:0}]),
 {seq:6,state:'submitted',code:last},...tail].map(r=>JSON.stringify(r)).join('\n')+'\n';
test('only exact pending read-only journal is admitted, never mutation or fabricated settle',()=>{
 const out=qualifyForward432Journal(journal());assert.equal(out.pending.readOnly,true);assert.equal(out.pending.settlementUnknown,true);
 for(const text of [journal('SERVICE_RECREATE_FAILED'),journal('HELPER_START_FAILED'),journal('READINESS_EXEC_FAILED',[{seq:6,state:'settled',exit:0}]),journal().slice(0,-1),'',journal().replace('"seq":2','"seq":99')])assert.throws(()=>qualifyForward432Journal(text));
});
test('exact CLI parser/default inert and sanitized output',async()=>{
 assert.deepEqual(parseForward432([]),{help:true});
 assert.equal(parseForward432(['check','--audit',EXACT_FORWARD_432.audit]).apply,false);
 assert.equal(parseForward432(['continue','--audit',EXACT_FORWARD_432.audit,'--review','a'.repeat(64),'--ack-forward-only']).apply,true);
 for(const args of [['check'],['check','--audit','b'.repeat(32)],['continue','--audit',EXACT_FORWARD_432.audit],['check','--audit',EXACT_FORWARD_432.audit,'--review','a'.repeat(64)],['check','--audit',EXACT_FORWARD_432.audit,'--apply']])assert.throws(()=>parseForward432(args));
 const logs=[];assert.equal(await forward432Main([],{factory:()=>assert.fail('inert'),log:s=>logs.push(s)}),0);
 assert.equal(await forward432Main(['check','--audit',EXACT_FORWARD_432.audit],{factory:()=>({exactForward432:()=>{throw Error('PRIVATE_SENTINEL');}}),log:s=>logs.push(s)}),1);
 assert.ok(!logs.join('\n').includes('PRIVATE_SENTINEL'));
});

// Extend ONLY a test fixture's return shape to expose its fake transport. No
// production predicate is rewritten; no real Docker executable is ever invoked.
let fixtureModule;
async function fixtureLibrary(){
 if(fixtureModule)return fixtureModule;
 const url=new URL('./moduleapi-slot-transition-fixture.mjs',import.meta.url);
 let code=fs.readFileSync(url,'utf8');
 assert.equal(code.split('return {adapter,operationNonces,publicRun').length,2);
 code=code.replace('return {adapter,operationNonces,publicRun','return {transport,adapter,operationNonces,publicRun');
 const boundary=code.indexOf('const ROOT =');
 code=code.slice(0,boundary).replace(/from '(\.\/[^']+)'/g,(_,p)=>'from '+JSON.stringify(new URL(p,url).href))+code.slice(boundary);
 code=code.replace('const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));','const ROOT = '+JSON.stringify(ROOT)+';');
 const directory=fs.mkdtempSync(join(tmpdir(),'forward432-fixture-library-'));after(()=>fs.rmSync(directory,{recursive:true,force:true}));
 const path=join(directory,'fixture.mjs');fs.writeFileSync(path,code);
 fixtureModule=await import(pathToFileURL(path).href);return fixtureModule;
}
async function incident(t,{tamper=null}={}){
 const {adapterFixture}=await fixtureLibrary();let f;
 f=await adapterFixture(t,{engineHook:info=>tamper?.(info)});
 // Genuine directly owned synthetic history allows the next attempt to borrow
 // all three old images, as in the exact incident. Existing reader seals it.
 const nonce='1'.repeat(32),parent=join(f.stand,'deploy-adapter-v1'),dir=join(parent,nonce);
 fs.mkdirSync(join(dir,'operation.lock'),{recursive:true,mode:0o700});
 fs.writeFileSync(join(dir,'operation.lock/deploy-adapter-owner.json'),JSON.stringify({version:2,nonce,kind:'preserving-deployment'}),{mode:0o600});
 const references=['api','openai-egress','web'].map(name=>{const image=f.pins().services[name].image,tag=`dip-deploy-${name}:old-${nonce}`;f.images.get(image).RepoTags.push(tag);return {name,tag,image};});
 fs.writeFileSync(join(dir,'complete.json'),JSON.stringify({version:2,project:'dip-public-images',nonce,outcome:'published',references,evidence:[]}),{mode:0o600});
 let fail=true;
 const run=async(args,options)=>{
  const worker=f.containers().find(c=>f.role(c)==='worker');
  if(fail&&f.events.includes('start:worker')&&args[0]==='container'&&args[1]==='exec'&&args[2]===worker.Id&&args.includes('--input-type=module')){
   fail=false;return runIsolatedDocker(args,options,(_exe,_args,_opts,cb)=>cb(Object.assign(Error('synthetic timeout'),{killed:true,signal:'SIGKILL'}),'',''));
  }
  return f.transport(args,options);
 };
 const make=Factory=>Factory({root:f.root,home:f.home,run,Database:DB,checkSource:async()=>({typescript:true,bundle:true,moduleapi:true}),http:async url=>({status:new URL(url).pathname==='/'?200:401,body:{cancel:async()=>{}}})});
 const original=make(createDeployAdapter),result=await runDeployment(original,{mode:'app',services:['api','web','openai-egress'],apply:true});
 assert.equal(fail,false,JSON.stringify(result));assert.equal(result.ok,false);assert.equal(result.phase,'switchServices');assert.equal(result.lock,'retained');
 const audits=fs.readdirSync(parent).filter(n=>n!==nonce);assert.equal(audits.length,1);
 const audit=audits[0],path=join(parent,audit),intent=read(join(path,'intent.json'));
 assert.deepEqual(read(join(path,'failure-switchservices.json')),{code:'READINESS_EXEC_FAILED',cause:'TIMEOUT',exitCode:null,signal:'SIGKILL',stdoutBytes:0,stderrBytes:0});
 const worker=read(join(path,'start-worker-complete.json')),gateway=read(join(path,'start-openai-egress-complete.json'));
 const contract={audit,source:intent.source,adapter:intent.adapter,worker:{id:worker.id,image:worker.image,startedAt:worker.startedAt},gateway:{id:gateway.id,image:gateway.image,startedAt:gateway.startedAt}};
 // Rebind ONLY the exact incident constants in a disposable copy. All authority,
 // prefix, journal, source, store and lifecycle guards remain byte-for-byte.
 const modulePath=join(f.root,'scripts/deploy-forward-432.mjs'),code=fs.readFileSync(modulePath,'utf8');
 const start=code.indexOf('export const EXACT_FORWARD_432 = Object.freeze('),end=code.indexOf('\nexport const FORWARD_432_CHILD',start);
 assert.ok(start>=0&&end>start);
 fs.writeFileSync(modulePath,code.slice(0,start)+'export const EXACT_FORWARD_432 = Object.freeze('+JSON.stringify(contract)+');'+code.slice(end));
 const copied=await import(pathToFileURL(join(f.root,'scripts/deploy-adapter.mjs')).href+'?fixture='+audit);
 f.releaseSupervisor();
 return {f,run,original:path,audit,make:()=>make(copied.createDeployAdapter)};
}

test('actual exact continuation: timeout→new supervisor→fresh equality→API→after equality→webLAST→valid custody completion', {timeout:180000},async t=>{
 const {f,original,audit,make}=await incident(t);
 const originalJournal=fs.readFileSync(join(original,'engine.jsonl')),originalFailure=fs.readFileSync(join(original,'failure-switchservices.json'));
 const worker=structuredClone(f.containers().find(c=>f.role(c)==='worker')),gateway=structuredClone(f.containers().find(c=>f.role(c)==='openai-egress'));
 const offset=f.events.length,reader=make(),plan=await reader.exactForward432({audit,apply:false});assert.equal(plan.eligible,true);assert.equal(plan.lifecycle,false);
 assert.equal(f.events.length,offset,'check does not create/start/stop');
 f.acquireSupervisor();
 await assert.rejects(make().exactForward432({audit,apply:true,review:'0'.repeat(64),ackForwardOnly:true}),/FORWARD_REVIEW_MISMATCH/);
 assert.ok(!fs.existsSync(join(original,'forward-ready-worker-432')));
 const result=await make().exactForward432({audit,apply:true,review:plan.review,ackForwardOnly:true});assert.equal(result.recovered,true);assert.equal(result.phase,'published');
 assert.equal(f.locked(),false);f.verifyStores();
 assert.deepEqual(f.containers().find(c=>f.role(c)==='worker'),worker);assert.deepEqual(f.containers().find(c=>f.role(c)==='openai-egress'),gateway);
 const events=f.events.slice(offset);assert.deepEqual(events.filter(e=>e.startsWith('up:')),['up:api','up:web']);assert.ok(!events.some(e=>e.startsWith('build:')||e.startsWith('stop:')&&e!=='stop:helper'||e==='start:worker'));
 assert.deepEqual(events.filter(e=>e.startsWith('snapshot:')),['snapshot:fenced','snapshot:before-api','snapshot:after-api']);
 assert.ok(events.indexOf('snapshot:before-api')<events.indexOf('up:api'));assert.ok(events.indexOf('snapshot:after-api')<events.indexOf('up:web'));
 assert.deepEqual(fs.readFileSync(join(original,'engine.jsonl')),originalJournal);assert.deepEqual(fs.readFileSync(join(original,'failure-switchservices.json')),originalFailure);
 const complete=read(join(original,'complete.json'));assert.equal(complete.outcome,'published');assert.equal(complete.referenceCustody.old.length,3);assert.equal(complete.borrowedReferences.length,3);
 assert.ok(fs.existsSync(join(original,'operation.lock/deploy-adapter-owner.json')));
 assert.equal(read(join(f.stand,'llm-profile.json')).version,7);
 await assert.rejects(make().exactForward432({audit,apply:true,review:plan.review,ackForwardOnly:true}));
});

test('current epoch/control or forbidden prefix mutation refuses before adoption and any new lifecycle', {timeout:120000},async t=>{
 const {f,original,audit,make}=await incident(t);const offset=f.events.length;
 const worker=f.containers().find(c=>f.role(c)==='worker'),epoch=worker.State.StartedAt;
 worker.State.StartedAt='2026-01-01T00:00:00Z';await assert.rejects(make().exactForward432({audit,apply:false}),/FORWARD_PEER_EPOCH/);worker.State.StartedAt=epoch;
 fs.writeFileSync(join(original,'start-api-submission.json'),'{}',{mode:0o600});await assert.rejects(make().exactForward432({audit,apply:false}),/FORWARD_EXACT_PREFIX/);
 assert.equal(f.events.length,offset);assert.equal(f.locked(),true);
});

test('fresh quota drift holds with original failure preserved before candidate API/web', {timeout:120000},async t=>{
 const {f,original,audit,make}=await incident(t);const plan=await make().exactForward432({audit,apply:false});
 // Same original capture remains immutable; only the test-owned live store changes.
 const db=new DB(f.paths.quota);db.exec('CREATE TABLE forward_drift(value INTEGER)');db.close();
 const offset=f.events.length;f.acquireSupervisor();
 await assert.rejects(make().exactForward432({audit,apply:true,review:plan.review,ackForwardOnly:true}));
 assert.ok(!f.events.slice(offset).includes('up:api'));assert.ok(!f.events.slice(offset).includes('up:web'));assert.equal(f.locked(),true);
 assert.ok(!fs.existsSync(join(original,'complete.json')));assert.ok(fs.existsSync(join(original,'forward-ready-worker-432/failure.json')));
});
