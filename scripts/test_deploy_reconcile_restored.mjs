// Run: node --experimental-vm-modules --test scripts/test_deploy_reconcile_restored.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as vm from 'node:vm';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { createHash } from 'node:crypto';

const source = fs.readFileSync(new URL('./deploy-reconcile-restored.mjs', import.meta.url), 'utf8');
const canonical = v => Array.isArray(v) ? v.map(canonical) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k => [k, canonical(v[k])])) : v;
const hash = v => createHash('sha256').update(typeof v === 'string' ? v : JSON.stringify(canonical(v))).digest('hex');
const stamp = s => [s.dev,s.ino,s.uid,s.mode,s.nlink,s.size,s.mtimeMs,s.ctimeMs];
const roles = ['api','auth-volume-init','egress','llm-egress','openai-egress','scan-volume-init','web','worker'];
const phases = ['fenced','before-api','after-api'];
const started = ['egress','worker','api','web'];
const project = 'synthetic';
const audit = 'deploy-' + 'a'.repeat(32);
const restoreEntry = 'scripts/public-images-v6-restore-fixture.mjs';
const guardName = '.recover-build-and-redeploy.lock';

async function fixture(t) {
  assert.equal(typeof vm.SourceTextModule, 'function', 'Run with --experimental-vm-modules');
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'reconcile-offline-')));
  t.after(() => fs.rmSync(root, { recursive:true, force:true }));
  const state = join(root, 'synthetic-state');
  const incident = join(state, 'llm-deployments', audit);
  const restored = join(incident, 'restore-existing-v6');
  const lock = join(state, '.operation.lock');
  const target = join(state, 'exact-recovery-compensations', 'restored-' + audit.slice(7));
  const guard = join(state, guardName);
  const mkdir = p => fs.mkdirSync(p, { recursive:true, mode:0o700 });
  const put = (p, v) => { mkdir(dirname(p)); fs.writeFileSync(p, JSON.stringify(v), { mode:0o600 }); };
  const moves = [];
  let failLockMove = false, foreign = false, uncertain = false;
  const privateFile = p => {
    const bytes = fs.readFileSync(p, 'utf8'), identity = stamp(fs.lstatSync(p));
    return { path:p, bytes, identity, verify() {
      assert.deepEqual(stamp(fs.lstatSync(p)), identity);
      assert.equal(fs.readFileSync(p, 'utf8'), bytes);
    } };
  };
  const noOp = () => {};
  const modules = {
    'node:fs': { ...fs, renameSync(from,to) {
      moves.push([from,to]);
      if (failLockMove && from === lock) throw Error('synthetic rename failure');
      fs.renameSync(from,to);
    } },
    'node:crypto': await import('node:crypto'),
    'node:path': await import('node:path'),
    'node:url': await import('node:url'),
    'node:util': await import('node:util'),
    'node:http': { get() { throw Error('HTTP must be injected'); } },
    './public-image-stand.mjs': { PROJECT:project, STATE:'synthetic-state', runIsolatedDocker() { throw Error('Docker must be injected'); }, assertReconciliationHistory:noOp },
    './local-stand.mjs': { dockerEnvironment:() => ({}) },
    './public-image-stand-profile.mjs': { publicImageCveConfig:(_root,cve) => cve },
    './public-llm-build-continuation.mjs': { privateFile, byteFile:() => ({ sha256:'b'.repeat(64), verify:noOp }), directoryIdentity:p => {
      const s = fs.lstatSync(p), identity = [s.dev,s.ino,s.uid,s.mode];
      return () => { const current = fs.lstatSync(p); assert.deepEqual([current.dev,current.ino,current.uid,current.mode], identity); };
    } },
    './setup-local-cve.mjs': { writeExclusive:(p,v,mode) => fs.writeFileSync(p,v,{flag:'wx',mode}), syncDirectory:noOp },
    './public-llm-stand.mjs': { capturePublicLlmSource:() => ({ digest:'synthetic-source', verify:noOp }), validateCurrentAuditHistory:noOp, validatePublicLlmImage:noOp, validateLlmSelection:noOp, publicLlmEnvironmentOverlay:() => ({synthetic:true}) },
    './public-llm-deployment-catalog.mjs': { captureDeploymentCatalog:() => ({active:[audit],verify:noOp}) },
  };
  // Use the host realm: cross-realm prototypes would invalidate strict equality.
  // The synthetic identifier prevents the module's CLI entrypoint from running.
  const module = new vm.SourceTextModule(source, { identifier:'file:///offline/scripts/deploy-reconcile-restored.mjs', initializeImportMeta(meta) { meta.url = 'file:///offline/scripts/deploy-reconcile-restored.mjs'; } });
  await module.link(specifier => {
    assert.ok(Object.hasOwn(modules,specifier), `Unexpected import: ${specifier}`);
    const exports = modules[specifier];
    return new vm.SyntheticModule(Object.keys(exports), function() {
      for (const [key,value] of Object.entries(exports)) this.setExport(key,value);
    });
  });
  await module.evaluate();
  const api = module.namespace;
  const containers = roles.map((name,i) => {
    const running = !name.endsWith('volume-init');
    return { Id:(i+1).toString(16).repeat(64), Image:'sha256:'+'c'.repeat(64), Name:`/${project}-${name}-1`, Path:'synthetic', Args:[], Config:{Entrypoint:['synthetic'],Cmd:[],Env:[],Labels:{'com.docker.compose.project':project,'com.docker.compose.service':name}}, HostConfig:{PortBindings:name==='web'?{'8080/tcp':[{HostIp:'127.0.0.1',HostPort:'8081'}]}:{}}, Mounts:[], NetworkSettings:{Networks:{}}, RestartCount:0, State:{StartedAt:'start',FinishedAt:'finish',Pid:running?42:0,Running:running,Status:running?'running':'exited',ExitCode:0,Error:'',Health:{Status:'healthy'}} };
  });
  const epoch = c => [c.Id,c.State.StartedAt,c.State.FinishedAt,c.State.Pid,c.RestartCount,c.State.Running,c.State.Status,c.State.ExitCode,c.State.Error];
  const peers = containers.map(c => ({name:c.Config.Labels['com.docker.compose.service'],id:c.Id,image:c.Image,control:api.restoredControl(c),epoch:epoch(c)}));
  const volumes = Array.from({length:4},(_,i) => ({Name:`${project}_v${i}`}));
  const networks = Array.from({length:8},(_,i) => ({Name:`${project}_n${i}`,Containers:{}}));
  put(join(state,'scan-jwt'), {synthetic:'metadata-only'});
  const selection = {version:6};
  const profile = {version:2,cve:{}};
  const saved = {version:1,audit,source:'d'.repeat(64),entry:'b'.repeat(64),endpoint:'unix:///synthetic.sock',daemon:'synthetic-daemon',peers,volumes,networks,selection,profile,pins:{},jwtIdentity:stamp(fs.lstatSync(join(state,'scan-jwt'))),originalEvidence:[]};
  const review = hash(saved);
  put(join(restored,'authority.json'),saved);
  put(join(restored,'restored-existing-v6.json'),{version:1,audit,review,source:saved.source,entry:saved.entry,outcome:'restored-old-v6-maintenance-hold',preserved:true,authSchema:'A2',migration:false,publishedProfileUnchanged:true,lockRetained:true,web:200,auth:401});
  put(join(lock,'mutation.json'),{version:1,project,command:'public-openai-worker-egress-upgrade',phase:'fence-web',endpoint:saved.endpoint,authMigration:'auth-a2-to-a3',authMigrationAck:'--ack-auth-a2-to-a3'});
  put(join(lock,'legacy-stop-egress-submission.json'),{});
  for (const name of ['compose.cve.json','compose.llm-env.json']) put(join(lock,'llm-candidate',name),{});
  put(join(incident,'history-schema-preflight.json'),{});
  for (const name of started) {
    const p = peers.find(p => p.name===name);
    put(join(restored,`start-${name}-submission.json`),{id:p.id,image:p.image,operation:'start-same-id'});
    put(join(restored,`started-${name}.json`),{id:p.id,epoch:p.epoch});
  }
  for (const name of ['worker','api','web']) put(join(restored,`ready-${name}.json`),name==='web'?{web:200,auth:401}:{ready:true});
  for (const phase of phases) {
    for (const group of ['core','llm']) for (const name of ['auth.sqlite','ledger.sqlite','private-manifest.json']) {
      const path = join(restored,phase,group,name); mkdir(dirname(path)); fs.writeFileSync(path,'{}',{mode:0o600});
    }
    put(join(restored,`verified-${phase}.json`),{version:1,authSchema:'A2',equalB0:true,stores:{historyVersion:4,llm:{}}});
    const helper = {id:'e'.repeat(64),image:peers[0].image};
    put(join(restored,`helper-${phase}.json`),helper);
    put(join(restored,`helper-${phase}-retired.json`),{id:helper.id,exit:0});
    put(join(restored,`helper-${phase}-submission.json`),{version:1,name:`${project}-llm-${review.slice(0,32)}-${phase}`,image:helper.image,purpose:'backup'});
    for (const step of ['start','stop','remove']) put(join(restored,`helper-${phase}-${step}-submission.json`),{id:helper.id});
  }
  for (const [name,value] of Object.entries({'llm-profile.json':selection,'profile.json':{...profile,project},'compose.images.json':{},'compose.llm-env.json':{synthetic:true},'compose.cve.json':{}})) put(join(state,name),value);
  const wire = c => JSON.stringify({...c,Config:{...c.Config,Env:[...c.Config.Env,null],__keyPresent:false,__end:null},__end:null});
  const calls = [];
  const run = async args => {
    calls.push(args);
    if (uncertain) throw Error('synthetic unavailable daemon');
    const [kind,action] = args;
    if (kind==='info') return JSON.stringify(saved.daemon);
    if (action==='ls') {
      if (args.some(a => a.startsWith('volume='))) return '';
      return (kind==='container'? [...peers.map(p=>p.id),...(foreign?['f'.repeat(64)]:[])] : kind==='network'?networks.map(n=>n.Name):volumes.map(v=>v.Name)).join('\n');
    }
    assert.equal(action,'inspect','Only read-only Docker commands allowed');
    if (kind==='container') return containers.map(wire).join('\n');
    if (kind==='image') return wire({Id:peers[0].image,Config:{Env:[]}});
    return JSON.stringify(kind==='volume'?volumes:networks);
  };
  const prepare = () => api.prepareRestoredReconciliation({audit,restoreReview:review,restoreEntry,root,run,request:async path => path==='/'?200:401,ambient:{}});
  return {api,prepare,incident,lock,target,guard,moves,calls,containers,peers,put,restored,failMove:()=>{failLockMove=true;},foreign:()=>{foreign=true;},uncertain:()=>{uncertain=true;}};
}

function snapshot(path) {
  const result = [];
  const walk = (p,rel) => {
    const s = fs.lstatSync(p);
    result.push([rel,s.ino,s.mode,s.isDirectory()?null:fs.readFileSync(p,'hex')]);
    if (s.isDirectory()) for (const n of fs.readdirSync(p).sort()) walk(join(p,n),join(rel,n));
  };
  walk(path,''); return result;
}

test('complete archive preserves incident and lock; recognized guard moves last', async t => {
  const f = await fixture(t), incident = snapshot(f.incident), lock = snapshot(f.lock);
  const prepared = await f.prepare();
  const result = await prepared.apply({review:prepared.summary.review,source:prepared.summary.source});
  assert.equal(result.outcome,'RESTORED_INCIDENT_ARCHIVED');
  assert.deepEqual(snapshot(join(f.target,'incident')),incident);
  assert.deepEqual(snapshot(join(f.target,'operation.lock')),lock);
  assert.deepEqual(f.moves.map(([from])=>from),[f.incident,f.lock,f.guard]);
  assert.ok(fs.existsSync(join(f.target,'archive-operation.lock','intent.json')));
  assert.equal(fs.existsSync(f.guard),false);
  assert.equal(fs.existsSync(f.lock),false);
  assert.equal(fs.existsSync(f.incident),false);
});

test('mid-archive failure retains recognized HOLD guard and original operation lock', async t => {
  const f = await fixture(t), incident = snapshot(f.incident), lock = snapshot(f.lock);
  const prepared = await f.prepare(); f.failMove();
  await assert.rejects(prepared.apply({review:prepared.summary.review,source:prepared.summary.source}),/synthetic rename failure/);
  assert.deepEqual(snapshot(join(f.target,'incident')),incident);
  assert.deepEqual(snapshot(f.lock),lock);
  const intent = JSON.parse(fs.readFileSync(join(f.guard,'intent.json'),'utf8'));
  assert.equal(intent.kind,'restored-v6-archive-only');
  assert.equal(intent.audit,audit);
  assert.equal(f.moves.some(([from])=>from===f.guard),false);
});

test('review identity and changed receipt refuse before archival', async t => {
  const f = await fixture(t), prepared = await f.prepare();
  await assert.rejects(prepared.apply({review:'0'.repeat(64),source:prepared.summary.source}),/RECONCILE_REVIEW_BINDING/);
  f.put(join(f.restored,'ready-web.json'),{web:503,auth:401});
  await assert.rejects(prepared.apply({review:prepared.summary.review,source:prepared.summary.source}));
  assert.deepEqual(f.moves,[]);
  assert.equal(fs.existsSync(f.guard),false);
  assert.ok(fs.existsSync(f.incident) && fs.existsSync(f.lock));
});

test('foreign inventory and uncertain daemon refuse apply without archival', async t => {
  const f = await fixture(t), prepared = await f.prepare();
  const binding = {review:prepared.summary.review,source:prepared.summary.source};
  f.foreign();
  await assert.rejects(prepared.apply(binding),/RECONCILE_FOREIGN_CONTAINER/);
  f.uncertain();
  await assert.rejects(prepared.apply(binding),/RECONCILE_DOCKER_INFO/);
  assert.deepEqual(f.moves,[]);
  assert.equal(fs.existsSync(f.guard),false);
  assert.ok(fs.existsSync(f.incident) && fs.existsSync(f.lock));
});
