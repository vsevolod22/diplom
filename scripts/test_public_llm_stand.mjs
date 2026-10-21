import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import {
  PUBLIC_LLM_ENV, parsePublicLlmConfig, validateLlmSelection, loadPublicLlmSettings, readPublicLlmBinding, publicLlmEnvironmentOverlay,
  publicLlmStaticOverlay, expectedPublicLlmConfig, validatePublicLlmConfig, publicLlmComposeArguments,
  validatePublicLlmImage, validatePublicLlmContainer, inspectPublicLlmNamespace,
  PUBLIC_LLM_INITIALIZE_PROGRAM, PUBLIC_LLM_CHECK_PROGRAM, PUBLIC_LLM_BACKUP_PROGRAM,
  publicLlmHelperArguments, llmFingerprint, backupLlmSqlite, executePublicLlmMaintenance, publicLlmStand,
} from './public-llm-stand.mjs';
import { PROJECT, STATE, LABEL, expectedConfig, acquireLock, recoverySqlite, backupExportOperation, publicImageStand } from './public-image-stand.mjs';
import { fixture } from './public-refresh-cve-fixtures.mjs';
import { checkPublicLlmSourceBuild } from './public-llm-source-build.mjs';
import { publicLlmSecretlessControl, preparePublicLlmBuildContinuation, capturePublicLlmExecutionClosure, PUBLIC_LLM_EXECUTION_MODULES } from './public-llm-build-continuation.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
let qualifiedSource;
const sourceQualification = () => qualifiedSource ??= checkPublicLlmSourceBuild(ROOT);
const DB = createRequire(new URL('../server/api/package.json', import.meta.url))('better-sqlite3');
const selection = { version: 1, keyVolume: null };
const keySelection = { version: 1, keyVolume: 'diplom-public-8081-llm-key-' + 'a'.repeat(32) };
function temporary(t) { const p = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'public-llm-stand-'))); t.after(() => fs.rmSync(p, { recursive: true, force: true })); return p; }
function settings(t, withReceipt = false) {
  const home = temporary(t), path = join(home, '.local/state/diplom-public-images/llm');
  fs.mkdirSync(path, { recursive: true, mode: 0o700 });
  fs.writeFileSync(join(path, 'llm.env'), Object.entries(PUBLIC_LLM_ENV).map(([k,v])=>`${k}=${v}`).join('\n') + '\n', { mode: 0o600 });
  // A denied key sentinel proves the integration never opens/stats the host key.
  fs.symlinkSync('/nonexistent-forbidden-key', join(path, 'openrouter.key'));
  if (withReceipt) fs.writeFileSync(join(path, 'key-volume.json'), JSON.stringify({ version: 1, volume: keySelection.keyVolume,
    uid: 65532, gid: 65532, fileMode: '0400', directoryMode: '0500', target: '/run/secrets/public_openrouter_key', initializerImage: 'sha256:' + 'f'.repeat(64) }), { mode: 0o600 });
  return { home, path };
}

test('CURRENT review mount order is stable without dropping mount authority or mutating inspection', () => {
  const c = { Config: { Env: ['SAFE=1', 'SCAN_JWT_SECRET=synthetic'] }, State: { Status: 'exited', Health: {} },
    NetworkSettings: { Networks: {} }, Mounts: [
      { Destination: '/z', Source: '/own/z', RW: false, Propagation: 'rprivate' },
      { Destination: '/a', Source: '/own/a', RW: false, Propagation: 'rprivate' },
    ] };
  const before = structuredClone(c), projection = publicLlmSecretlessControl(c);
  c.Mounts.reverse();
  assert.deepEqual(publicLlmSecretlessControl(c), projection);
  c.Mounts.reverse();
  assert.deepEqual(c, before);
  for (const [field, value] of [['Source', '/foreign'], ['RW', true], ['Propagation', 'shared']]) {
    const changed = structuredClone(c); changed.Mounts[0][field] = value;
    assert.notDeepEqual(publicLlmSecretlessControl(changed), projection);
  }
});

test('external nonsecret allowlist exactly matches CONFIG; duplicate/unknown/key/expansion/paid values refuse', () => {
  const text = fs.readFileSync(join(ROOT, 'scripts/public-llm-config.py'), 'utf8').match(/CONFIG = """([\s\S]*?)"""/)[1];
  assert.deepEqual(parsePublicLlmConfig(text), PUBLIC_LLM_ENV);
  for (const bad of [text + '\nOPENROUTER_API_KEY=synthetic', text + '\nLLM_ENABLED=true', text.replace('LLM_REQUEST_PRICE_USD=0', 'LLM_REQUEST_PRICE_USD=1'),
    text.replace('LLM_PROVIDER_ALLOWLIST=phala', 'LLM_PROVIDER_ALLOWLIST=novita'), text + '\nNODE_OPTIONS=--inspect', text.replace('LLM_ENABLED=true', 'LLM_ENABLED=$ENABLED')])
    assert.throws(() => parsePublicLlmConfig(bad));
});

test('missing-key and provisioned metadata selection never read a host key; config/receipt fences hold', t => {
  for (const supplied of [false, true]) {
    const f = settings(t, supplied), s = loadPublicLlmSettings(f.home);
    assert.deepEqual(s.selection, supplied ? keySelection : selection); s.verify();
    fs.appendFileSync(join(f.path, 'llm.env'), '# changed\n'); assert.throws(s.verify);
  }
  for (const value of [{ version: 1, keyVolume: 'dip-local-full_auth_accounts' }, { ...selection, path: '/private' }, { version: 2, keyVolume: null }]) assert.throws(() => validateLlmSelection(value));
});

test('settings fences reject receipt changes, file replacement and ancestor aliasing without touching host key', t => {
  for (const mutation of [
    f => fs.writeFileSync(join(f.path, 'key-volume.json'), '{}', { mode: 0o600 }),
    f => { const p = join(f.path, 'llm.env'); const bytes = fs.readFileSync(p); fs.renameSync(p, p + '.prior'); fs.writeFileSync(p, bytes, { mode: 0o600 }); },
    f => { fs.renameSync(f.path, f.path + '.prior'); fs.symlinkSync(f.path + '.prior', f.path); },
    f => fs.chmodSync(f.path, 0o755),
  ]) { const f = settings(t), s = loadPublicLlmSettings(f.home); mutation(f); assert.throws(s.verify); }
  const f = settings(t, true), s = loadPublicLlmSettings(f.home); fs.unlinkSync(join(f.path, 'key-volume.json')); assert.throws(s.verify);
});

test('binding absent is supported; orphan/pending/unsafe state or incoherent env/profile refuses', t => {
  const root = temporary(t), state = join(root, STATE);
  assert.equal(readPublicLlmBinding(root), null); fs.mkdirSync(state, { mode: 0o700 }); assert.equal(readPublicLlmBinding(root), null);
  const overlay = join(state, 'compose.llm-env.json'), profile = join(state, 'llm-profile.json');
  fs.writeFileSync(overlay, JSON.stringify(publicLlmEnvironmentOverlay(selection)), { mode: 0o600 }); assert.throws(() => readPublicLlmBinding(root));
  fs.writeFileSync(profile, JSON.stringify(selection), { mode: 0o600 }); assert.deepEqual(readPublicLlmBinding(root), selection);
  fs.writeFileSync(overlay, JSON.stringify(publicLlmEnvironmentOverlay(keySelection))); assert.throws(() => readPublicLlmBinding(root));
  fs.writeFileSync(overlay, JSON.stringify(publicLlmEnvironmentOverlay(selection)));
  fs.writeFileSync(join(state, '.llm-pending-profile'), ''); assert.throws(() => readPublicLlmBinding(root)); fs.unlinkSync(join(state, '.llm-pending-profile'));
  fs.renameSync(state, state + '.prior'); fs.symlinkSync(state + '.prior', state); assert.throws(() => readPublicLlmBinding(root));
});

test('fixed static overlay, exact seven-service model, six networks and optional API-only readonly key', () => {
  const actual = JSON.parse(fs.readFileSync(join(ROOT, 'server/deploy/compose.public-llm.yaml'), 'utf8'));
  actual.services['llm-egress'].build.context = ROOT;
  assert.deepEqual(actual, publicLlmStaticOverlay(ROOT));
  for (const s of [selection, keySelection]) {
    const model = expectedPublicLlmConfig(ROOT, null, s); validatePublicLlmConfig(model, ROOT, null, s);
    assert.equal(Object.keys(model.services).length, 7); assert.equal(Object.keys(model.networks).length, 6);
    assert.equal(model.networks.llm_internal.internal, true); assert.equal(model.networks.llm_uplink.internal, undefined);
    assert.deepEqual(Object.keys(model.services['llm-egress'].networks), ['llm_internal','llm_uplink']);
    assert.equal(model.services.worker.networks.llm_internal, undefined); assert.equal(model.services.web.networks.llm_internal, undefined);
    assert.equal(model.services.web.build.dockerfile, 'server/deploy/public-stand.Dockerfile');
    assert.equal(model.services.api.environment.OPENROUTER_API_KEY, undefined);
    for (const [name, spec] of Object.entries(model.services)) {
      const mount = spec.volumes?.find(m => m.target === '/run/secrets');
      assert.equal(Boolean(mount), name === 'api' && Boolean(s.keyVolume));
      if (mount) { assert.equal(mount.read_only, true); assert.deepEqual(mount.volume, { nocopy: true }); }
    }
  }
  assert.deepEqual(expectedPublicLlmConfig(ROOT), expectedConfig(ROOT));
});
for (const [name, change] of Object.entries({
  'foreign-env': m => { m.services.api.environment.OPENROUTER_API_KEY = 'synthetic'; },
  'worker-egress': m => { m.services.worker.networks.llm_internal = null; },
  'api-uplink': m => { m.services.api.networks.llm_uplink = null; },
  'gateway-host-port': m => { m.services['llm-egress'].ports = [{ published: '8080', target: 8080 }]; },
  'gateway-extra-cap': m => { m.services['llm-egress'].cap_add = ['NET_ADMIN']; },
  'common-web': m => { m.services.web.build.dockerfile = 'server/deploy/stand.Dockerfile'; },
  'rw-key': m => { m.services.api.volumes.find(v=>v.target==='/run/secrets').read_only = false; },
  'copy-up': m => { m.services.api.volumes.find(v=>v.target==='/run/secrets').volume.nocopy = false; },
  'foreign-key-volume': m => { m.volumes.public_llm_key.name = 'retained'; },
  'extra-overlay': m => { m.services.api.env_file = ['/private']; },
})) test(`independent public model rejects ${name}`, () => {
  const model = expectedPublicLlmConfig(ROOT, null, keySelection); change(model);
  assert.throws(() => validatePublicLlmConfig(model, ROOT, null, keySelection));
});

test('CVE current and candidate selectors preserve exact LLM overlay order before image pins', () => {
  for (const cve of [false, true]) {
    const args = publicLlmComposeArguments(ROOT, ['up','-d','api'], { cve });
    const files = args.filter((_,i)=>args[i-1]==='-f');
    assert.deepEqual(files, [join(ROOT,'server/deploy/compose.public-images.yaml'), ...(cve?[join(ROOT,STATE,'compose.cve.json')]:[]),
      join(ROOT,'server/deploy/compose.public-llm.yaml'), join(ROOT,STATE,'compose.llm-env.json'),join(ROOT,STATE,'compose.images.json')]);
    assert.equal(args[args.indexOf('--env-file')+1], '/dev/null');
  }
  const next=publicLlmComposeArguments(ROOT,[],{cve:true,prospectiveCve:true});
  assert.equal(next.filter((_,i)=>next[i-1]==='-f')[1],join(ROOT,STATE,'.operation.lock/candidate.cve.json'));
  assert(next.includes(join(ROOT,STATE,'compose.llm-env.json')));assert(next.includes(join(ROOT,STATE,'compose.images.json')));
  assert.throws(()=>publicLlmComposeArguments(ROOT, [], { directory: '/private' }));
  assert.throws(()=>publicLlmComposeArguments(ROOT, [], { directory: join(ROOT,STATE,'.operation.lock/arbitrary') }));
  assert.throws(()=>publicLlmComposeArguments(ROOT, [], { prospectiveCve: true }));
});

function extendedFixture(t, s = selection) {
  const f = fixture(t), cve = f.current.cve ?? f.current;
  // The shared fixture's real binding is exposed by its persisted profile.
  const binding = JSON.parse(fs.readFileSync(join(f.stand,'profile.json'))).cve;
  // Avoid importing any LOCAL profile path: fixture uses a public v2 release.
  const baseApi = f.containers.find(c=>c.Config.Labels['com.docker.compose.service']==='api');
  const releaseDir = baseApi.Mounts.find(m=>m.Destination==='/opt/release').Source;
  const publicKeyPath = baseApi.Mounts.find(m=>m.Destination==='/opt/local-db-trust/public.pem').Source;
  const bound = { ...binding, releaseHostDir: releaseDir, publicKeyPath };
  const model = expectedPublicLlmConfig(f.root, bound, s);
  f.images['llm-egress'] = structuredClone(f.images.egress); f.images['llm-egress'].Id = 'sha256:' + 'e'.repeat(64);
  f.images['llm-egress'].RepoTags = [`${PROJECT}-llm-egress:local`]; f.images['llm-egress'].Config.Cmd = ['python','-I','openrouter.py'];
  f.containers = Object.entries(model.services).map(([name,spec],i)=> {
    const c = f.makeContainer(name,spec,i);
    if (name==='llm-egress') c.Config.Env = f.images['llm-egress'].Config.Env;
    for (const m of c.Mounts.filter(m=>m.Type==='volume')) { m.Driver='local'; m.Source=`/fixture/volumes/${m.Name}`; }
    if (name==='api' && s.keyVolume) {
      const d = c.HostConfig.Mounts.find(m=>m.Target==='/run/secrets'), m = c.Mounts.find(m=>m.Destination==='/run/secrets');
      d.Source=s.keyVolume; d.VolumeOptions={NoCopy:true}; m.Name=s.keyVolume; m.Source=`/fixture/volumes/${s.keyVolume}`;
    }
    return c;
  });
  f.networks = Object.values(model.networks).map(n=>({Name:n.name,Id:crypto.createHash('sha256').update(n.name).digest('hex'),Driver:'bridge',Labels:{[LABEL]:'v1','com.docker.compose.project':PROJECT},Internal:Boolean(n.internal),Options:null,
    Containers:Object.fromEntries(f.containers.filter(c=>c.State.Running&&c.NetworkSettings.Networks[n.name]).map(c=>[c.Id,{}]))}));
  return { ...f, model, bound, s };
}

test('runtime extension projection retains base env/capability/namespace checks, including unknown env', t => {
  const f = extendedFixture(t, keySelection);
  for (const c of f.containers) {
    const name=c.Config.Labels['com.docker.compose.service']; validatePublicLlmImage(f.images[name],name);
    validatePublicLlmContainer(c,name,f.model.services[name],f.images[name],f.model,{images:f.images},f.s);
  }
  const api=f.containers.find(c=>c.Name.endsWith('-api-1'));
  for (const mutate of [c=>c.Config.Env.push('NODE_OPTIONS=--inspect'), c=>c.Config.Env.push('OPENROUTER_API_KEY=synthetic'),
    c=>c.HostConfig.Privileged=true, c=>c.HostConfig.Mounts.find(m=>m.Target==='/run/secrets').ReadOnly=false,
    c=>c.NetworkSettings.Networks[`${PROJECT}_llm_uplink`]={}]) {
    const c=structuredClone(api); mutate(c); assert.throws(()=>validatePublicLlmContainer(c,'api',f.model.services.api,f.images.api,f.model,{images:f.images},f.s));
  }
});

test('seven-service namespace inspector validates extension and delegates all original resources', async t => {
  const f=extendedFixture(t);
  const observed=await inspectPublicLlmNamespace(f.docker,{root:f.root,env:{DOCKER_HOST:f.endpoint},timeout:30000},f.root,f.bound,f.s,{images:f.images});
  assert.equal(observed.containers.length,7);assert.equal(observed.networks.length,6);
});

test('public nginx owns history gate1/runtime0, bounded exact readiness GET, access logs off; common file untouched', () => {
  const common=fs.readFileSync(join(ROOT,'server/deploy/stand.nginx.conf'),'utf8'), own=fs.readFileSync(join(ROOT,'server/deploy/public-stand.nginx.conf'),'utf8');
  assert.match(common,/set \$history_ingress_enabled 0;/); assert.match(own,/set \$history_ingress_enabled 1;/); assert.match(own,/set \$runtime_ingress_enabled 0;/);
  const block=own.match(/location ~ "[^"\n]*llm\/\(\?:context\|usage\|readiness\)\$" \{([\s\S]*?)\n        \}/)[1];
  assert.match(block,/limit_except GET/); assert.match(block,/access_log off;/);
  assert.match(own,/proxy_buffering off;/); assert.match(own,/client_max_body_size 8k;/);
  const docker=fs.readFileSync(join(ROOT,'server/deploy/public-stand.Dockerfile'),'utf8');
  assert.match(docker,/COPY server\/deploy\/public-stand.nginx.conf/); assert.match(docker,/USER 101:101/);
  assert.doesNotMatch(docker,/COPY \. \./); assert.match(docker,/COPY src \.\/src/); assert.match(docker,/tsconfig.public.json/);
    assert.match(docker,/COPY server\/runtime\/src\/contract.ts server\/runtime\/src\/runtime-json.ts/);
  assert.doesNotMatch(docker,/\.local|openrouter.key|llm.env/);
});

function steps(fault) {
  const calls=[], core={auth:{logicalSha256:'a'},ledger:{logicalSha256:'b'}}, llm={history:'h',quota:'q'};
  const ops={}; for(const name of ['preflight','intent','stop','drain','candidate','initialize','startRetained','up','ready','publish','complete']) ops[name]=async value=>{ calls.push([name,value]); if(fault===name)throw Error('synthetic'); };
  ops.snapshot=async phase=>{ calls.push(['snapshot',phase]); return {core:structuredClone(core),llm:phase==='fenced'?null:structuredClone(llm),empty:true}; };
  return {ops,calls};
}
test('maintenance proves historical metadata before build; fences web/API, drains, stops, real backup before replacement and opens admission LAST', async () => {
  const f=steps(); assert.equal((await executePublicLlmMaintenance(f.ops)).outcome,'ready');
  assert.deepEqual(f.calls,[['preflight',undefined],['intent',undefined],['stop','web'],['stop','api'],['drain',undefined],['stop','worker'],['snapshot','fenced'],['candidate',undefined],['initialize',true],['startRetained',undefined],['up','llm-egress'],['up','worker'],['ready','worker'],['snapshot','before-api'],['up','api'],['ready','api'],['snapshot','after-api'],['publish',undefined],['up','web'],['ready','web'],['complete',undefined]]);
});
for(const fault of ['preflight','intent','stop','drain','candidate','initialize','startRetained','ready','publish']) test(`maintenance ${fault} fault stops without fallback/retry/opening admission`,async()=>{
  const f=steps(fault); await assert.rejects(executePublicLlmMaintenance(f.ops)); assert.equal(f.calls.filter(c=>c[0]===fault).length,1); assert(!f.calls.some(c=>c[0]==='complete'));
  if(fault==='preflight') assert.deepEqual(f.calls,[['preflight',undefined]]);
});
test('typed preservation mismatch or nonempty bootstrap never starts API/web',async()=>{
  for(const corrupt of ['core','empty']) { const f=steps(); const original=f.ops.snapshot; f.ops.snapshot=async phase=>{const x=await original(phase);if(phase==='before-api')if(corrupt==='core')x.core.auth.logicalSha256='changed';else x.empty=false;return x;};await assert.rejects(executePublicLlmMaintenance(f.ops));assert(!f.calls.some(c=>c[0]==='up'&&['api','web'].includes(c[1]))); }
});

test('after-API history/quota or account/report mutation cannot publish/open web',async()=>{
  for(const group of ['core','llm']){
    const f=steps(),capture=f.ops.snapshot;f.ops.snapshot=async phase=>{const v=await capture(phase);if(phase==='after-api')v[group]={changed:'typed'};return v;};
    await assert.rejects(executePublicLlmMaintenance(f.ops));assert(!f.calls.some(c=>c[0]==='publish'||c[0]==='up'&&c[1]==='web'));
  }
});

test('helper commands are UID65532/networknone, only new stores writable on initialize, never secret mount/JWT env',()=>{
  for(const purpose of ['backup','initialize','check']) {
    const name=`${PROJECT}-llm-${'a'.repeat(32)}-${purpose==='backup'?'fenced':purpose}`,args=publicLlmHelperArguments(name,'sha256:'+'b'.repeat(64),purpose),text=JSON.stringify(args);
    assert.equal(args[args.indexOf('--network')+1],'none'); assert.equal(args[args.indexOf('--user')+1],'65532:65532'); assert(args.includes('--read-only'));
    assert(!text.includes('SCAN_JWT_SECRET')); assert(!text.includes('type=volume,src=diplom-public-8081-llm-key'));
    assert(args.includes(`type=volume,src=${PROJECT}_scan_ledger,dst=/data,readonly,volume-nocopy`));
    assert(args.includes(`type=volume,src=${PROJECT}_auth_accounts,dst=/auth,${purpose==='backup'?'readonly,':''}volume-nocopy`));
  }
});

function runNative(program, paths, env=PUBLIC_LLM_ENV) {
  let code=program.replaceAll('/auth/',paths.auth+'/').replaceAll('/data/',paths.data+'/').replaceAll('/backup',paths.backup)
    .replace("process.on('SIGTERM',()=>process.exit(0));",'').replace('setTimeout(()=>process.exit(73),300000);','');
  return spawnSync(process.execPath,['--import','tsx','--input-type=module','-e',code],{cwd:join(ROOT,'server/api'),env:{...env},encoding:'utf8',timeout:20000});
}
function nativeFixture(t) {
  const root=temporary(t),paths={auth:join(root,'auth'),data:join(root,'data'),backup:join(root,'backup')}; for(const p of Object.values(paths))fs.mkdirSync(p,{mode:0o700});
  const auth=new DB(join(paths.auth,'auth.sqlite')); auth.exec('CREATE TABLE users(id TEXT,password TEXT); CREATE TABLE sessions(id TEXT); CREATE TABLE trusted_sessions(id TEXT); CREATE TABLE browser_access(id TEXT); CREATE TABLE auth_attempts(id TEXT);');auth.close();
  const ledger=new DB(join(paths.data,'ledger.sqlite')); ledger.exec("CREATE TABLE scans(state TEXT); CREATE TABLE outbox(delivered_at TEXT); CREATE TABLE reports(n INTEGER,b BLOB);INSERT INTO reports VALUES(9007199254740993,X'000102');PRAGMA user_version=15;");ledger.close();
  for(const p of [join(paths.auth,'auth.sqlite'),join(paths.data,'ledger.sqlite')])fs.chmodSync(p,0o600);
  return paths;
}
test('real operator init creates only new stores; repeat/mixed/missing check refuses with no reset or provider/key reads',t=>{
  const p=nativeFixture(t),before=[fs.readFileSync(join(p.auth,'auth.sqlite')),fs.readFileSync(join(p.data,'ledger.sqlite'))];
  const r=runNative(PUBLIC_LLM_INITIALIZE_PROGRAM,p); assert.equal(r.status,0,r.stderr); assert.equal(r.stdout,'');
  assert.deepEqual([fs.readFileSync(join(p.auth,'auth.sqlite')),fs.readFileSync(join(p.data,'ledger.sqlite'))],before);
  const initial=[fs.readFileSync(join(p.auth,'llm-history.sqlite')),fs.readFileSync(join(p.auth,'llm-usage.sqlite'))];
  assert.equal(runNative(PUBLIC_LLM_INITIALIZE_PROGRAM,p).status,70); assert.deepEqual([fs.readFileSync(join(p.auth,'llm-history.sqlite')),fs.readFileSync(join(p.auth,'llm-usage.sqlite'))],initial);
  fs.unlinkSync(join(p.backup,'ready.json')); assert.equal(runNative(PUBLIC_LLM_CHECK_PROGRAM,p).status,0);
  fs.unlinkSync(join(p.auth,'llm-usage.sqlite')); assert.equal(runNative(PUBLIC_LLM_INITIALIZE_PROGRAM,p).status,70); assert.equal(runNative(PUBLIC_LLM_CHECK_PROGRAM,p).status,70);
});

for (const mutation of ['mixed-stores', 'swapped-stores', 'wrong-namespace', 'pending-history', 'orphan-journal']) test(`real strict LLM backup namespace rejects ${mutation} without resetting state`, async t => {
  const p=nativeFixture(t), output=join(p.backup,'strict'); fs.mkdirSync(output,{mode:0o700});
  if(mutation==='orphan-journal') fs.writeFileSync(join(p.auth,'llm-history.sqlite-wal'),'synthetic',{mode:0o600});
  else {
    assert.equal(runNative(PUBLIC_LLM_INITIALIZE_PROGRAM,p).status,0);
    if(mutation==='mixed-stores') fs.unlinkSync(join(p.auth,'llm-usage.sqlite'));
    if(mutation==='swapped-stores') { const h=join(p.auth,'llm-history.sqlite'),q=join(p.auth,'llm-usage.sqlite');fs.renameSync(h,h+'.old');fs.renameSync(q,h);fs.renameSync(h+'.old',q); }
    if(mutation==='wrong-namespace') {const db=new DB(join(p.auth,'llm-history.sqlite'));db.pragma('application_id=42');db.close();}
    if(mutation==='pending-history') {const db=new DB(join(p.auth,'llm-history.sqlite'));db.exec("INSERT INTO history_head VALUES('owner/scan','epoch',0,'{\"pending\":{\"status\":\"pending\"}}','synthetic-hash')");db.close();}
  }
  const files=fs.readdirSync(p.auth).sort(),bytes=files.map(n=>fs.readFileSync(join(p.auth,n)));
  await assert.rejects(backupLlmSqlite(DB,fs,crypto,{auth:join(p.auth,'llm-history.sqlite'),ledger:join(p.auth,'llm-usage.sqlite')},output));
  assert.deepEqual(fs.readdirSync(p.auth).sort(),files); assert.deepEqual(files.map(n=>fs.readFileSync(join(p.auth,n))),bytes);
});

test('real four-store stable backup/restore exports auth/report and durable LLM/quota; all-table typed INTEGER/BLOB mutation detected',async t=>{
  const p=nativeFixture(t); assert.equal(runNative(PUBLIC_LLM_INITIALIZE_PROGRAM,p).status,0); fs.unlinkSync(join(p.backup,'ready.json'));
  const extra=new DB(join(p.auth,'llm-history.sqlite'));extra.exec("CREATE TABLE opaque(n INTEGER,b BLOB,t TEXT);INSERT INTO opaque VALUES(9007199254740993,X'000102','untrusted history');");extra.close();
  const result=runNative(PUBLIC_LLM_BACKUP_PROGRAM,p); assert.equal(result.status,0,result.stderr); assert.equal(result.stdout,'');
  const ready=JSON.parse(fs.readFileSync(join(p.backup,'ready.json')));assert.deepEqual(ready,{ready:true,llmPresent:true});
  for(const group of ['core','llm'])for(const role of ['auth','ledger']) {
    const manifest=backupExportOperation(fs,crypto,{action:'manifest'},{backup:join(p.backup,group),auth:join(p.auth,group==='core'?'auth.sqlite':'llm-history.sqlite'),ledger:join(group==='core'?p.data:p.auth,group==='core'?'ledger.sqlite':'llm-usage.sqlite')});
    assert.equal(manifest.receipt[role].integrity,'ok');assert.equal(fs.statSync(join(p.backup,group,role+'.sqlite')).mode&0o777,0o600);
  }
  const file=join(p.backup,'llm/auth.sqlite'),initial=llmFingerprint(DB,fs,crypto,file,'history');
  const db=new DB(file);db.exec("UPDATE opaque SET b=X'000103'");db.close(); assert.notEqual(llmFingerprint(DB,fs,crypto,file,'history'),initial);
  const db2=new DB(file);db2.exec("UPDATE opaque SET b=X'000102',n=9007199254740992");db2.close();assert.notEqual(llmFingerprint(DB,fs,crypto,file,'history'),initial);
  const auth=join(p.backup,'core/auth.sqlite'),before=llmFingerprint(DB,fs,crypto,auth,'auth');
  const authDb=new DB(auth);authDb.pragma('application_id=42');authDb.close();assert.notEqual(llmFingerprint(DB,fs,crypto,auth,'auth'),before);
});

function concreteFixture(t) {
  const f=fixture(t), state=settings(t), paths=nativeFixture(t), allImages=new Map(), events=[], programs=new Map();
  const profile=JSON.parse(fs.readFileSync(join(f.stand,'profile.json'))), baseApi=f.containers.find(c=>c.Name.endsWith('-api-1'));
  const cve={...profile.cve,releaseHostDir:baseApi.Mounts.find(m=>m.Destination==='/opt/release').Source,publicKeyPath:baseApi.Mounts.find(m=>m.Destination==='/opt/local-db-trust/public.pem').Source};
  for(const image of Object.values(f.images)) allImages.set(image.Id,structuredClone(image));
  const files=[...PUBLIC_LLM_EXECUTION_MODULES,'package.json','pnpm-lock.yaml','pnpm-workspace.yaml','index.html','admin.html','vite.config.ts','tsconfig.json','.dockerignore','server/deploy/compose.public-images.yaml','server/deploy/compose.public-llm.yaml',
    'server/api/package.json','server/api/tsconfig.json','server/deploy/trust/db-signing-key.pub.pem',
    'server/deploy/public-stand.Dockerfile','server/deploy/public-stand.nginx.conf','server/deploy/api.Dockerfile','server/deploy/worker.Dockerfile',
    'server/deploy/gateway/Dockerfile','server/deploy/gateway/proxy.py','server/deploy/gateway/openrouter.Dockerfile','server/deploy/gateway/openrouter.py'];
  for(const p of files){fs.mkdirSync(dirname(join(f.root,p)),{recursive:true});fs.copyFileSync(join(ROOT,p),join(f.root,p));}
  for(const p of ['src','public','server/api/src','server/runtime/src','src/admin-app/features'])fs.mkdirSync(join(f.root,p),{recursive:true});
  // Actual repository regression: source placeholders can be empty and assets
  // can contain non-UTF8 bytes; neither is nonempty private configuration.
  fs.writeFileSync(join(f.root,'src/admin-app/features/.gitkeep'),'');
  fs.writeFileSync(join(f.root,'public/source-fixture.bin'),Buffer.from([0x80]));
  let generation=0, clock=0, helper;
  const tick=()=>new Date(Date.UTC(2026,9,21,0,0,++clock)).toISOString();
  const binding=()=>{const p=join(f.stand,'llm-profile.json');return fs.existsSync(p)?JSON.parse(fs.readFileSync(p)):null;};
  const attachments=()=>{for(const n of f.networks)n.Containers=Object.fromEntries(f.containers.filter(c=>c.State.Running&&c.NetworkSettings.Networks[n.Name]).map(c=>[c.Id,{}]));};
  const materialize=(name,spec)=>{
    const image=allImages.get(spec.image); assert(image, 'Compose must consume immutable pins, not mutable fixture role defaults');
    const previous=f.images[name]; f.images[name]=image;
    const c=f.makeContainer(name,spec,8,++generation); f.images[name]=previous;
    const command=[...(c.Config.Entrypoint??[]),...c.Config.Cmd];c.Path=command[0];c.Args=command.slice(1);
    if(name==='llm-egress')c.Config.Env=f.images[name].Config.Env;
    for(const m of c.Mounts.filter(m=>m.Type==='volume')){m.Driver='local';m.Source=`/fixture/volumes/${m.Name}`;}
    if(name==='api'&&spec.volumes.some(m=>m.target==='/run/secrets')){
      const selected=keySelection.keyVolume,d=c.HostConfig.Mounts.find(m=>m.Target==='/run/secrets'),m=c.Mounts.find(m=>m.Destination==='/run/secrets');d.Source=selected;d.VolumeOptions={NoCopy:true};m.Name=selected;m.Source=`/fixture/volumes/${selected}`;
    }
    return c;
  };
  for(const c of f.containers){const command=[...(c.Config.Entrypoint??[]),...c.Config.Cmd];c.Path=command[0];c.Args=command.slice(1);for(const m of c.Mounts.filter(m=>m.Type==='volume')){m.Driver='local';m.Source=`/fixture/volumes/${m.Name}`;}}
  f.builds=0; f.serviceStops=[]; f.serviceStarts=[]; f.submissions=[];
  const run=async(args,options)=>{
    if(f.llmFault==='missing-prior-image'&&args[0]==='image'&&args[1]==='inspect'&&args[2]===f.images.api.Id)throw Error('synthetic image unavailable');
    assert(!args.some(v=>/dip-local-full|\.local-stand|\.local-auth/.test(v)));events.push(args.slice(0,2).join(':'));f.submissions.push(args.slice());
    if(args[0]==='context')return JSON.stringify('unix:///fixture/docker.sock');
    if(args[0]==='compose'){
      const envFile=args.filter((_,i)=>args[i-1]==='-f').find(p=>p.endsWith('compose.llm-env.json'));
      const selected=JSON.parse(fs.readFileSync(envFile)).volumes?keySelection:selection;
      const model=expectedPublicLlmConfig(f.root,cve,selected);
      if(args.includes('config')){
        const pins=args.filter((_,i)=>args[i-1]==='-f').find(p=>p.endsWith('compose.images.json'));
        if(pins)for(const[n,v]of Object.entries(JSON.parse(fs.readFileSync(pins)).services))model.services[n].image=v.image;
        return JSON.stringify(model);
      }
      if(args.includes('build')){
        f.builds++; assert(events.includes('container:stop'));
        const requested=args.slice(args.indexOf('build')+1);assert.equal(requested.length,1);assert(['api','worker','web','llm-egress'].includes(requested[0]));
        f.beforeBuild?.(requested[0]);
        for(const name of requested){
          const image=structuredClone(f.images[name==='llm-egress'?'egress':name]);
          if(name==='llm-egress')image.Config.Cmd=['python','-I','openrouter.py'];
          image.Id='sha256:'+crypto.createHash('sha256').update('new-'+name).digest('hex');image.RepoTags=[`${PROJECT}-${name}:local`];
          if(f.images[name])allImages.get(f.images[name].Id).RepoTags=[];
          f.images[name]=image;allImages.set(image.Id,structuredClone(image));
        }
        f.afterBuild?.(requested[0]); return '';
      }
      if(args.includes('up')){
        const pins=args.filter((_,i)=>args[i-1]==='-f').find(p=>p.endsWith('compose.images.json')); assert(pins);
        for(const[n,v]of Object.entries(JSON.parse(fs.readFileSync(pins)).services))model.services[n].image=v.image;
        const name=args.at(-1);assert(['api','worker','web','llm-egress'].includes(name));
        f.containers=f.containers.filter(c=>!c.Name.endsWith('-'+name+'-1'));f.containers.push(materialize(name,model.services[name]));
        for(const n of Object.values(model.networks))if(!f.networks.some(v=>v.Name===n.name))f.networks.push({Name:n.name,Id:crypto.createHash('sha256').update(n.name).digest('hex'),Driver:'bridge',Labels:{[LABEL]:'v1','com.docker.compose.project':PROJECT},Internal:Boolean(n.internal),Options:null,Containers:{}});
        attachments();return '';
      }
      throw Error('unexpected Compose');
    }
    if(args[0]==='image'){
      if(args[1]==='ls')return [...new Set([...allImages.values()].flatMap(im=>im.RepoTags))].join('\n');
      const im=allImages.get(args[2])??[...allImages.values()].find(im=>im.RepoTags.includes(args[2]));if(!im){const e=Error('synthetic image unavailable');e.category='image';throw e;}return JSON.stringify([im]);
    }
    if(args[0]==='volume'){
      if(args[1]==='ls')return f.volumes.map(v=>`${v.Name}\t${v.Labels['com.docker.compose.project']??''}`).join('\n');
      const v=f.volumes.find(v=>v.Name===args[2]);assert(v);return JSON.stringify([v]);
    }
    if(args[0]==='network'){
      if(args[1]==='ls')return f.networks.map(n=>`${n.Name}\t${PROJECT}`).join('\n');
      const n=f.networks.find(n=>n.Name===args[2]);assert(n);return JSON.stringify([n]);
    }
    if(args[0]==='create'){
      assert(!helper);const name=args[args.indexOf('--name')+1],id='sha256:'+args.join(' ').split('sha256:')[1]?.slice(0,64);
      const image=allImages.get(id);assert(image);const program=args.at(-1),backup=join(paths.backup,'helper-'+programs.size);fs.mkdirSync(backup,{mode:0o700});
      const base=structuredClone(f.containers.find(c=>c.Name.endsWith('-api-1')));
      helper={...base,Id:crypto.createHash('sha256').update(name).digest('hex'),Name:'/'+name,Image:image.Id,Created:'2026-10-21T00:00:00Z',RestartCount:0,Path:'node',Args:args.slice(args.indexOf(image.Id)+1),
        Config:{...image.Config,Image:image.Id,Entrypoint:['node'],Cmd:args.slice(args.indexOf(image.Id)+1),Labels:{[LABEL]:'v1','com.docker.compose.project':PROJECT,'org.diplom.recovery-helper':'v1','org.diplom.recovery-purpose':'backup'}},
        State:{Status:'created',Running:false,Pid:0,ExitCode:0,StartedAt:'0001-01-01T00:00:00Z',Restarting:false,OOMKilled:false,Dead:false},NetworkSettings:{Networks:{},Ports:{}}};
      const init=program!==PUBLIC_LLM_BACKUP_PROGRAM;
      if(init)helper.Config.Env=[...image.Config.Env,...Object.entries(PUBLIC_LLM_ENV).map(([k,v])=>`${k}=${v}`)];
      Object.assign(helper.HostConfig,{Memory:1073741824,MemorySwap:1073741824,NanoCpus:1e9,PidsLimit:32,NetworkMode:'none',PortBindings:{},RestartPolicy:{Name:'no',MaximumRetryCount:0},Tmpfs:{'/backup':'rw,noexec,nosuid,uid=65532,gid=65532,size=512m'},Mounts:[['auth_accounts','/auth'],['scan_ledger','/data']].map(([k,target])=>({Type:'volume',Source:`${PROJECT}_${k}`,Target:target,ReadOnly:target==='/auth'?!init:true,VolumeOptions:{NoCopy:true}}))});
      helper.Mounts=helper.HostConfig.Mounts.map(m=>({Type:'volume',Name:m.Source,Source:`/fixture/volumes/${m.Source}`,Driver:'local',Destination:m.Target,RW:!m.ReadOnly,Propagation:'rprivate'}));
      helper.HostConfig.OomKillDisable=null;
      helper.HostConfig.Mounts.forEach(m=>{m.VolumeOptions.DriverConfig={};});
      if(f.llmFault==='unsafe-helper')helper.HostConfig.Mounts[0].ReadOnly=false;
      if(f.llmFault==='helper-env')helper.Config.Env.push('NODE_OPTIONS=--inspect');
      if(f.llmFault==='helper-source')helper.Mounts[0].Source='/foreign/source';
      if(f.llmFault==='helper-args')helper.Args=[...helper.Args,'unexpected'];
      if(f.llmFault==='helper-host')helper.HostConfig.CustomAuthority=true;
      programs.set(helper.Id,{program,backup});f.containers.push(helper);return helper.Id+'\n';
    }
    if(args[0]==='container'){
      if(args[1]==='ls'){
        let cs=f.containers.filter(c=>args.includes('--all')||c.State.Running);const vf=args.find(v=>v.startsWith('volume='));if(vf)cs=cs.filter(c=>c.Mounts.some(m=>m.Name===vf.slice(7)));const id=args.find(v=>v.startsWith('id='));if(id)cs=cs.filter(c=>c.Id===id.slice(3));
        const fmt=args[args.indexOf('--format')+1];
        return cs.map(c=>{const id=args.includes('--no-trunc')?c.Id:c.Id.slice(0,12),project=c.Config.Labels['com.docker.compose.project'];return fmt==='{{.ID}}'?id:fmt.startsWith('{{.ID}}\t')?`${id}\t${c.Name.slice(1)}\t${project}`:`${c.Name.slice(1)}\t${project}`;}).join('\n');
      }
      if(args[1]==='stop'){
        const containers=f.containers.filter(c=>args.includes(c.Id));assert(containers.length>0);
        for(const c of containers){
          const name=c.Config.Labels['com.docker.compose.service'];if(name)f.serviceStops.push(name);
          const exit=['web','egress','llm-egress'].includes(name)?143:0;
          c.State={...c.State,Status:'exited',Running:false,Pid:0,FinishedAt:tick(),ExitCode:f.llmFault==='unclean-worker'&&name==='worker'?137:exit};
          if(name==='api')c.State.Health={Status:'unhealthy'};
          f.afterStop?.(name);
        }
        attachments();return '';
      }
      const c=f.containers.find(c=>c.Id===args[2]||c.Id===args.at(-1)||c.Name==='/'+args[2]);assert(c,args.join(' '));
      if(args[1]==='inspect')return JSON.stringify([c]);
      if(args[1]==='rm'){f.containers=f.containers.filter(v=>v.Id!==c.Id);helper=null;return '';}
      if(args[1]==='start'){
        assert.equal(c.State.Running,false);
        const p=programs.get(c.Id);
        c.State={...c.State,Status:'running',Running:true,Pid:123,ExitCode:0,StartedAt:tick(),FinishedAt:'0001-01-01T00:00:00Z'};
        if(p){
          c.NetworkSettings.Networks={none:{}}; c.HostConfig.OomKillDisable=false;
          if(f.llmFault==='helper-running-args')c.Args=[...c.Args,'unexpected'];
          const r=runNative(p.program,{...paths,backup:p.backup});assert.equal(r.status,0,r.stderr);
        }else{
          assert.equal(c.Config.Labels['com.docker.compose.service'],'egress','only the retained readonly registry gateway may restart');
          f.serviceStarts.push(c.Id);
        }
        attachments();return '';
      }
      if(args[1]==='exec'){
        assert(c.State.Running,'native Docker refuses exec into a stopped container');
        const p=programs.get(c.Id);
        if(p){
          if(args.at(-1).startsWith('{')&&args.at(-1).includes('"group"')){
            const x=JSON.parse(args.at(-1)),request=x.request;if(request.action==='chunk')request.stamp.uid=String(process.getuid());
            const v=backupExportOperation(fs,crypto,request,{backup:join(p.backup,x.group),auth:join(paths.auth,x.group==='core'?'auth.sqlite':'llm-history.sqlite'),ledger:join(x.group==='core'?paths.data:paths.auth,x.group==='core'?'ledger.sqlite':'llm-usage.sqlite')});
            if(request.action==='manifest')for(const r of ['auth','ledger']){v.files[r].uid='65532';for(const f of v.sources[r])f.stamp.uid='65532';}return JSON.stringify(v);
          }
          return fs.readFileSync(join(p.backup,'ready.json'),'utf8');
        }
        if(args.at(-1).includes('AS jobs'))return '{"jobs":0,"leases":0,"outbox":0}';
        if(f.llmFault==='late-api-health'&&args.at(-1).includes('llmGatewayReady'))c.State.Health={Status:'unhealthy'};
        return JSON.stringify({ready:true,manifest:cve.manifestDigest,bundle:cve.artifactSha256});
      }
    }
    throw Error('unexpected fake engine operation');
  };
  return {f,state,paths,run,events,allImages,bound:cve};
}

test('LOCAL execution closure includes transitive/static/dynamic edges and cycles without evaluating module text',t=>{
  const x=concreteFixture(t),path=join(x.f.root,'scripts/local-stand.mjs');
  fs.appendFileSync(path,'\nglobalThis.LOCAL_CLOSURE_MUST_NOT_EXECUTE = true;\n');
  const closure=capturePublicLlmExecutionClosure(x.f.root);closure.verify();
  assert.deepEqual(closure.manifest.modules,[...PUBLIC_LLM_EXECUTION_MODULES].sort());
  assert(closure.manifest.edges.includes('scripts/public-image-stand.mjs -> scripts/public-cve-bridge-runtime.mjs'));
  assert(closure.manifest.edges.includes('scripts/refresh-local-cve.mjs -> server/deploy/trust/fetch-db-layer.mjs'));
  assert(closure.manifest.edges.includes('scripts/public-cve-provision.mjs -> scripts/refresh-public-cve.mjs'));
  assert.equal(globalThis.LOCAL_CLOSURE_MUST_NOT_EXECUTE,undefined);
});
for(const [label,extra]of [
  ['outside-boundary',"\nimport '../.local-stand/private.mjs';\n"],
  ['unaudited-local',"\nexport * from './unreviewed-module.mjs';\n"],
  ['nonliteral-import',"\nconst target='./local-stand.mjs'; import(target);\n"],
  ['nonliteral-require-alias',"\nconst load=require; const target='./local-stand.mjs'; load(target);\n"],
])test(`LOCAL execution closure rejects ${label} before arbitrary lookup/execution`,t=>{
  const x=concreteFixture(t);fs.appendFileSync(join(x.f.root,'scripts/public-llm-build-continuation.mjs'),extra);
  assert.throws(()=>capturePublicLlmExecutionClosure(x.f.root),e=>/^CURRENT_BUILD_EXECUTION_(?:IMPORT|NONLITERAL)_REJECTED$/.test(e.reason));
  assert.equal(x.f.submissions.length,0);
});
test('LOCAL execution closure rejects aliased program directories and bounded oversized source',t=>{
  const x=concreteFixture(t),closure=capturePublicLlmExecutionClosure(x.f.root),scripts=join(x.f.root,'scripts');
  fs.renameSync(scripts,scripts+'.original');fs.symlinkSync(scripts+'.original',scripts,'dir');
  assert.throws(closure.verify);assert.throws(()=>capturePublicLlmExecutionClosure(x.f.root));
  fs.unlinkSync(scripts);fs.renameSync(scripts+'.original',scripts);
  fs.appendFileSync(join(scripts,'local-stand.mjs'),' '.repeat(1024**2));assert.throws(()=>capturePublicLlmExecutionClosure(x.f.root));
});

async function heldBuildFixture(t) {
  const x=concreteFixture(t),originalWorker=structuredClone(x.f.images.worker),oldWorker=originalWorker.Id,canary='PRIVATE_BUILD_LOG_CANARY';
  x.f.afterBuild=name=>{if(name==='worker')x.allImages.delete(oldWorker);};
  x.f.beforeBuild=name=>{if(name==='web'){const e=Error(canary);e.category='resources';throw e;}};
  const options={root:x.f.root,home:x.state.home,run:x.run,ambient:{HOME:x.state.home,PATH:process.env.PATH},Database:DB,checkSource:sourceQualification,sleep:async()=>{},request:async()=>new Response(null,{status:401}),log:()=>{}};
  await assert.rejects(publicLlmStand(['up','--build','--ack-public-maintenance'],options),/phase=build-submit-web;/);
  const failure=join(x.f.stand,'.operation.lock/build-failure.json');
  assert.deepEqual(JSON.parse(fs.readFileSync(failure)),{version:1,phase:'build-submit-web',role:'web',category:'resources'});assert(!fs.readFileSync(failure,'utf8').includes(canary));
  // Reproduce the actual legacy HOLD, whose old launcher saved no failure record.
  // This removal is confined to disposable synthetic test state, never live code.
  fs.unlinkSync(failure);fs.unlinkSync(join(x.f.stand,'.operation.lock/build-checkpoint.json'));x.f.beforeBuild=null;x.f.afterBuild=null;
  const audit=fs.readdirSync(join(x.f.stand,'llm-deployments'))[0];
  return {...x,options,audit,originalWorker};
}

test('CURRENT build: read-only checker binds source/state/backups/epochs; reviewed retirement-only continuation completes native preservation without old worker metadata fallback',async t=>{
  const x=await heldBuildFixture(t),origin=join(x.f.stand,'llm-deployments',x.audit,'fenced/core'),originNames=fs.readdirSync(origin).sort();
  const originBytes=originNames.map(n=>fs.readFileSync(join(origin,n)));
  const at=x.f.submissions.length,ctx=await preparePublicLlmBuildContinuation({...x.options,audit:x.audit});
  assert.deepEqual(ctx.summary.missingPriorMetadata,['worker']);assert(ctx.summary.workerRetirementOnly);assert(ctx.summary.fencedBackupVerified);
  const ctx2=await preparePublicLlmBuildContinuation({...x.options,audit:x.audit});assert.equal(ctx.review,ctx2.review);
  assert(x.f.submissions.slice(at).every(a=>['context','image','container','network','volume'].includes(a[0])&&['inspect','ls'].includes(a[1])||a[0]==='compose'&&a.includes('config')));
  assert.deepEqual(fs.readdirSync(origin).sort(),originNames);assert.deepEqual(originNames.map(n=>fs.readFileSync(join(origin,n))),originBytes);
  await assert.rejects(publicLlmStand(['continue-current-build','--audit',x.audit,'--review',ctx.review,'--ack-reviewed-current-source'],x.options));
  const beforeLife=x.f.submissions.length;
  const result=await publicLlmStand(['continue-current-build','--audit',x.audit,'--review',ctx.review,'--ack-reviewed-current-source','--ack-retire-only-unavailable-worker'],x.options);
  assert.equal(result.outcome,'ready');assert(!fs.existsSync(join(x.f.stand,'.operation.lock')));assert(fs.existsSync(join(x.f.stand,'llm-deployments',x.audit,'complete.json')));
  assert.deepEqual(originNames.map(n=>fs.readFileSync(join(origin,n))),originBytes);
  assert(fs.existsSync(join(x.f.stand,'llm-deployments',x.audit,'continued/original-operation/mutation.json')));
  const secret=fs.readFileSync(join(x.f.stand,'scan-jwt'),'utf8');
  for(const p of ['continued/review.json','continued/build-checkpoint.json'])assert(!fs.readFileSync(join(x.f.stand,'llm-deployments',x.audit,p),'utf8').includes(secret),'JWT values must never enter checkpoint/review evidence');
  for(const p of ['fenced','before-api','after-api'])assert(fs.existsSync(join(x.f.stand,'llm-deployments',x.audit,'continued',p,'core/auth.sqlite')));
  const actions=x.f.submissions.slice(beforeLife),firstBuild=actions.findIndex(a=>a[0]==='compose'&&a.includes('build'));
  assert(firstBuild>0);assert(actions.slice(0,firstBuild).some(a=>a[0]==='create'&&a.at(-1)===PUBLIC_LLM_BACKUP_PROGRAM));
  assert(!actions.some(a=>a[0]==='container'&&['start','exec'].includes(a[1])&&a.includes(ctx.inventory.containers.find(c=>c.Name.endsWith('-worker-1')).Id)));
});

test('CURRENT build with available original metadata requires no retirement exception and rejects a spurious retirement acknowledgement',async t=>{
  const x=await heldBuildFixture(t);x.originalWorker.RepoTags=[];x.allImages.set(x.originalWorker.Id,x.originalWorker);
  const ctx=await preparePublicLlmBuildContinuation({...x.options,audit:x.audit});assert.equal(ctx.summary.workerRetirementOnly,false);assert.deepEqual(ctx.summary.missingPriorMetadata,[]);
  await assert.rejects(publicLlmStand(['continue-current-build','--audit',x.audit,'--review',ctx.review,'--ack-reviewed-current-source','--ack-retire-only-unavailable-worker'],x.options));
  assert.equal((await publicLlmStand(['continue-current-build','--audit',x.audit,'--review',ctx.review,'--ack-reviewed-current-source'],x.options)).outcome,'ready');
});

for(const drift of ['source','program','pins','jwt','backup','epoch','executable','candidate','later-phase'])test(`CURRENT build ${drift}: stale review/prefix refuses without lifecycle and original lock remains`,async t=>{
  const x=await heldBuildFixture(t),ctx=await preparePublicLlmBuildContinuation({...x.options,audit:x.audit});
  if(drift==='source')fs.appendFileSync(join(x.f.root,'server/deploy/public-stand.Dockerfile'),'\n# changed\n');
  if(drift==='program')fs.appendFileSync(join(x.f.root,'scripts/public-llm-build-continuation.mjs'),'\n// changed\n');
  if(drift==='executable')x.f.containers.find(c=>c.Name.endsWith('-api-1')).Path='unreviewed';
  if(drift==='pins')fs.appendFileSync(join(x.f.stand,'compose.images.json'),'\n');
  if(drift==='jwt')fs.writeFileSync(join(x.f.stand,'scan-jwt'),'cd'.repeat(48));
  if(drift==='backup'){const p=join(x.f.stand,'llm-deployments',x.audit,'fenced/core/auth.sqlite');const b=fs.readFileSync(p);b[100]^=1;fs.writeFileSync(p,b);}
  if(drift==='epoch')x.f.containers.find(c=>c.Name.endsWith('-api-1')).State.StartedAt='2026-10-19T00:00:00Z';
  if(drift==='candidate')fs.appendFileSync(join(x.f.stand,'.operation.lock/llm-candidate/compose.llm-env.json'),'\n');
  if(drift==='later-phase')fs.writeFileSync(join(x.f.stand,'.operation.lock/llm-candidate/compose.images.json'),'{}',{mode:0o600});
  const at=x.f.submissions.length;
  await assert.rejects(publicLlmStand(['continue-current-build','--audit',x.audit,'--review',ctx.review,'--ack-reviewed-current-source','--ack-retire-only-unavailable-worker'],x.options));
  assert(x.f.submissions.slice(at).every(a=>['context','image','container','network','volume'].includes(a[0])&&['inspect','ls'].includes(a[1])||a[0]==='compose'&&a.includes('config')));
  assert(fs.existsSync(join(x.f.stand,'.operation.lock/mutation.json')));assert(!fs.existsSync(join(x.f.stand,'.operation.lock/continue.json')));
});

for(const module of ['public-image-stand.mjs','local-stand.mjs','setup-local-cve.mjs','refresh-public-cve.mjs','public-image-stand-profile.mjs','refresh-local-cve.mjs','public-cve-bridge-runtime.mjs','public-refresh-cve-preservation.mjs','../server/deploy/trust/fetch-db-layer.mjs'])test(`CURRENT execution dependency ${module}: stale token/runtime proof fails before continue intent or lifecycle`,async t=>{
  const x=await heldBuildFixture(t),ctx=await preparePublicLlmBuildContinuation({...x.options,audit:x.audit});
  assert.equal(ctx.summary.executionModules,PUBLIC_LLM_EXECUTION_MODULES.length);
  fs.appendFileSync(join(x.f.root,'scripts',module),'\n// execution dependency drift\n');
  assert.throws(ctx.verifyExecution);assert.throws(ctx.verify);
  const at=x.f.submissions.length;
  await assert.rejects(publicLlmStand(['continue-current-build','--audit',x.audit,'--review',ctx.review,'--ack-reviewed-current-source','--ack-retire-only-unavailable-worker'],x.options));
  assert(x.f.submissions.slice(at).every(a=>['context','image','container','network','volume'].includes(a[0])&&['inspect','ls'].includes(a[1])||a[0]==='compose'&&a.includes('config')));
  assert(!fs.existsSync(join(x.f.stand,'.operation.lock/continue.json')));assert(fs.existsSync(join(x.f.stand,'.operation.lock/mutation.json')));
});
test('CURRENT execution dependency drift after final read-only preflight is rechecked before the exclusive continue intent',async t=>{
  const x=await heldBuildFixture(t),ctx=await preparePublicLlmBuildContinuation({...x.options,audit:x.audit});let changed=false;
  const run=async(args,options)=>{
    const text=await x.run(args,options);
    if(!changed&&options.timeout>15000&&args[0]==='container'&&args[1]==='ls'&&!args.includes('--all')&&args.includes('volume='+PROJECT+'_scan_ledger')){
      fs.appendFileSync(join(x.f.root,'scripts/setup-local-cve.mjs'),'\n// last preflight boundary drift\n');changed=true;
    }
    return text;
  };
  const at=x.f.submissions.length;
  await assert.rejects(publicLlmStand(['continue-current-build','--audit',x.audit,'--review',ctx.review,'--ack-reviewed-current-source','--ack-retire-only-unavailable-worker'],{...x.options,run}));
  assert(changed);assert(!fs.existsSync(join(x.f.stand,'.operation.lock/continue.json')));assert(!fs.existsSync(join(x.f.stand,'llm-deployments',x.audit,'continued')));
  assert(x.f.submissions.slice(at).every(a=>['context','image','container','network','volume'].includes(a[0])&&['inspect','ls'].includes(a[1])||a[0]==='compose'&&a.includes('config')));
});

test('CURRENT build live-store drift is caught against original native backup before build/init/start; new continuation HOLD cannot be automatically retried',async t=>{
  const x=await heldBuildFixture(t),ctx=await preparePublicLlmBuildContinuation({...x.options,audit:x.audit}),db=new DB(join(x.paths.data,'ledger.sqlite'));db.exec("UPDATE reports SET b=X'FF'");db.close();
  const at=x.f.submissions.length;
  const args=['continue-current-build','--audit',x.audit,'--review',ctx.review,'--ack-reviewed-current-source','--ack-retire-only-unavailable-worker'];
  await assert.rejects(publicLlmStand(args,x.options));
  const actions=x.f.submissions.slice(at);assert(!actions.some(a=>a[0]==='compose'&&a.includes('build')||a[0]==='compose'&&a.includes('up')));
  assert(!actions.some(a=>a[0]==='create'&&a.at(-1)===PUBLIC_LLM_INITIALIZE_PROGRAM));assert(fs.existsSync(join(x.f.stand,'.operation.lock/continue.json')));
  const count=x.f.submissions.length;await assert.rejects(publicLlmStand(args,x.options));assert.equal(x.f.submissions.length,count);
});

test('source fencing accepts real empty tracked placeholders, but detects lossy-UTF8-equivalent binary byte drift before intent',async t=>{
  const x=concreteFixture(t),diagnostics=[],file=join(x.f.root,'public/source-fixture.bin');
  assert.equal(fs.statSync(join(x.f.root,'src/admin-app/features/.gitkeep')).size,0);
  assert.equal(Buffer.from([0x80]).toString('utf8'),Buffer.from([0x81]).toString('utf8'),'this drift defeated the former text hash');
  const run=async(args,options)=>{if(args[0]==='context')fs.writeFileSync(file,Buffer.from([0x81]));return x.run(args,options);};
  await assert.rejects(publicLlmStand(['up','--build','--ack-public-maintenance'],{root:x.f.root,home:x.state.home,run,ambient:{HOME:x.state.home,PATH:process.env.PATH},Database:DB,checkSource:sourceQualification,onDiagnostic:d=>diagnostics.push(d),log:()=>{}}),/phase=preflight-images-auth-volume-init;/);
  assert.deepEqual(diagnostics,[{phase:'preflight-images-auth-volume-init',reason:'PUBLIC_PRIOR_IMAGE_REJECTED'}]);
  assert.equal(x.f.submissions.length,1);assert.equal(x.f.submissions[0][0],'context');assert.equal(x.f.builds,0);
  assert(!fs.existsSync(join(x.f.stand,'.operation.lock')));
});

for(const fault of ['source','jwt','engine','image'])test(`safe preflight ${fault} substage emits only finite diagnostic, no raw error/command/Env or JWT hash`,async t=>{
  const x=concreteFixture(t),diagnostics=[],canary='DIAGNOSTIC_PRIVATE_SCANNER_CREDENTIAL_CANARY';
  if(fault==='source'){const p=join(x.f.root,'src/admin-app/features/.gitkeep');fs.unlinkSync(p);fs.symlinkSync('/forbidden-source',p);}
  if(fault==='jwt')fs.truncateSync(join(x.f.stand,'scan-jwt'),0);
  if(fault==='image')x.f.llmFault='missing-prior-image';
  const run=async(args,options)=>{if(fault==='engine')throw new Error(canary);return x.run(args,options);};
  let failure;try{await publicLlmStand(['up','--build','--ack-public-maintenance'],{root:x.f.root,home:x.state.home,run,ambient:{HOME:x.state.home,PATH:process.env.PATH},Database:DB,checkSource:sourceQualification,onDiagnostic:d=>{assert(Object.isFrozen(d));diagnostics.push(d);if(fault==='engine')throw Error(canary);},log:()=>{}});}catch(e){failure=e;}
  const expected={source:['preflight-source','PUBLIC_SOURCE_REJECTED'],jwt:['preflight-jwt','PUBLIC_JWT_UNAVAILABLE'],engine:['preflight-engine','PUBLIC_ENGINE_REJECTED'],image:['preflight-images-api','PUBLIC_PRIOR_IMAGE_REJECTED']}[fault];
  assert(failure);assert(failure.message.includes('phase='+expected[0]+';'));assert.deepEqual(diagnostics,[{phase:expected[0],reason:expected[1]}]);
  assert.doesNotMatch(failure.stack+JSON.stringify(diagnostics),/DIAGNOSTIC_PRIVATE|forbidden-source|NODE_OPTIONS|SCAN_JWT_SECRET|sha256:/);
  assert.equal(failure.cause,undefined);assert.equal(x.f.builds,0);assert.deepEqual(x.f.serviceStops,[]);assert(!fs.existsSync(join(x.f.stand,'.operation.lock')));
});

test('empty private config remains invalid even though empty source placeholders are supported',async t=>{
  const x=concreteFixture(t);fs.truncateSync(join(x.state.path,'llm.env'),0);
  await assert.rejects(publicLlmStand(['up','--build','--ack-public-maintenance'],{root:x.f.root,home:x.state.home,run:x.run,log:()=>{}}));
  assert.equal(x.f.submissions.length,0);assert(!fs.existsSync(join(x.f.stand,'.operation.lock')));
});

for (const shape of ['omitted', 'false', 'true', 'null', 'string', 'observed-readonly']) test(`CONCRETE initializer writable auth declaration ${shape}: exact daemon default normalization`, async t => {
  const x = concreteFixture(t);
  const run = async (args, options) => {
    const text = await x.run(args, options);
    if (args[0] === 'create' && args.at(-1) === PUBLIC_LLM_INITIALIZE_PROGRAM) {
      const c = x.f.containers.find(c => c.Id === text.trim());
      const mount = c.HostConfig.Mounts.find(m => m.Target === '/auth');
      if (shape === 'omitted') delete mount.ReadOnly;
      if (shape === 'true') mount.ReadOnly = true;
      if (shape === 'null') mount.ReadOnly = null;
      if (shape === 'string') mount.ReadOnly = 'false';
      if (shape === 'observed-readonly') c.Mounts.find(m => m.Destination === '/auth').RW = false;
    }
    return text;
  };
  const action = publicLlmStand(['up', '--build', '--ack-public-maintenance'], { root: x.f.root, home: x.state.home, run,
    ambient: { PATH: process.env.PATH, HOME: x.state.home }, Database: DB, checkSource: sourceQualification,
    request: async () => new Response(null, { status: 401 }), sleep: async () => {}, log: () => {} });
  if (['omitted', 'false'].includes(shape)) assert.equal((await action).outcome, 'ready');
  else {
    await assert.rejects(action, /phase=initialize;/);
    const helper = x.f.containers.find(c => c.Name.endsWith('-initialize'));
    assert.equal(helper.State.Status, 'created');
    assert(!x.f.submissions.some(a => a[0] === 'container' && a[1] === 'start' && a[2] === helper.Id));
    assert.equal(x.f.containers.find(c => c.Name.endsWith('-web-1')).State.Running, false);
    assert(fs.existsSync(join(x.f.stand, '.operation.lock/mutation.json')));
  }
});

test('CONCRETE maintenance: real four-store export/restore plus strict fake engine validates missing-key deployment and single later key activation',async t=>{
  const x=concreteFixture(t),logs=[];
  const options={root:x.f.root,home:x.state.home,run:x.run,ambient:{PATH:process.env.PATH,HOME:x.state.home},Database:DB,checkSource:sourceQualification,request:async()=>new Response(null,{status:401}),sleep:async()=>{},log:v=>logs.push(v)};
  const oldBackups=join(x.f.stand,'cve-backups');fs.mkdirSync(oldBackups,{mode:0o700});
  for(let i=0;i<4;i++){const p=join(oldBackups,'refresh-'+String(i).repeat(32));fs.mkdirSync(p,{mode:0o700});fs.writeFileSync(join(p,'complete.json'),JSON.stringify({version:1,project:PROJECT,preserved:true}),{mode:0o600});}
  assert.equal((await publicLlmStand(['up','--build','--ack-public-maintenance'],options)).outcome,'ready');
  assert.equal(fs.readdirSync(oldBackups).length,4);
  assert(logs.at(-1).includes('key unavailable'));assert(!fs.existsSync(join(x.f.stand,'.operation.lock')));
  assert.equal(JSON.parse(fs.readFileSync(join(x.f.stand,'llm-profile.json'))).keyVolume,null);
  // Still no host key: only an approved nonsecret receipt and independent volume metadata.
  fs.writeFileSync(join(x.state.path,'key-volume.json'),JSON.stringify({version:1,volume:keySelection.keyVolume,uid:65532,gid:65532,fileMode:'0400',directoryMode:'0500',target:'/run/secrets/public_openrouter_key',initializerImage:'sha256:'+'f'.repeat(64)}),{mode:0o600});
  x.f.volumes.push({Name:keySelection.keyVolume,Driver:'local',Scope:'local',Options:null,Labels:{'diplom.public-llm':'key-v1'},Mountpoint:`/fixture/volumes/${keySelection.keyVolume}`});
  const beforePins=fs.readFileSync(join(x.f.stand,'compose.images.json'),'utf8');
  // Removing mutable service tags must not affect a no-build key activation.
  for(const im of x.allImages.values())im.RepoTags=im.RepoTags.filter(tag=>tag==='busybox:1.37.0');
  assert.equal((await publicLlmStand(['up','--ack-public-maintenance'],options)).outcome,'ready');
  assert(logs.at(-1).includes('generation unverified'));assert.equal(JSON.parse(fs.readFileSync(join(x.f.stand,'llm-profile.json'))).keyVolume,keySelection.keyVolume);
  assert.equal(fs.readdirSync(join(x.f.stand,'llm-deployments')).length,2);
  assert.equal(fs.readFileSync(join(x.f.stand,'compose.images.json'),'utf8'),beforePins); assert.equal(x.f.builds,4);
});

for(const supplied of [false,true]) test(`CONCRETE actual main stop→up, key ${supplied?'mounted':'absent'}: network-none native preservation before any application restart`,async t=>{
  const x=concreteFixture(t),options={root:x.f.root,home:x.state.home,run:x.run,ambient:{HOME:x.state.home,PATH:process.env.PATH},Database:DB,checkSource:sourceQualification,sleep:async()=>{},request:async()=>new Response(null,{status:401}),log:()=>{}};
  if(supplied){
    fs.writeFileSync(join(x.state.path,'key-volume.json'),JSON.stringify({version:1,volume:keySelection.keyVolume,uid:65532,gid:65532,fileMode:'0400',directoryMode:'0500',target:'/run/secrets/public_openrouter_key',initializerImage:'sha256:'+'f'.repeat(64)}),{mode:0o600});
    x.f.volumes.push({Name:keySelection.keyVolume,Driver:'local',Scope:'local',Options:null,Labels:{'diplom.public-llm':'key-v1'},Mountpoint:`/fixture/volumes/${keySelection.keyVolume}`});
  }
  await publicLlmStand(['up','--build','--ack-public-maintenance'],options);
  const seed=runNative("import {HistoryStore} from './src/llm/history-store.ts';const h=new HistoryStore('/auth/llm-history.sqlite');h.snapshot('a'.repeat(32),'00000000-0000-0000-0000-000000000001');h.close();",x.paths);assert.equal(seed.status,0,seed.stderr);
  const auth=new DB(join(x.paths.auth,'auth.sqlite'));auth.exec("INSERT INTO users VALUES('same-owner','synthetic-password')");auth.close();
  const quota=new DB(join(x.paths.auth,'llm-usage.sqlite'));quota.exec('UPDATE quota_meta SET clock=123 WHERE id=1');quota.close();
  const stores={auth:join(x.paths.auth,'auth.sqlite'),ledger:join(x.paths.data,'ledger.sqlite'),history:join(x.paths.auth,'llm-history.sqlite'),quota:join(x.paths.auth,'llm-usage.sqlite')};
  const fingerprints=()=>Object.fromEntries(Object.entries(stores).map(([kind,p])=>[kind,llmFingerprint(DB,fs,crypto,p,kind)]));
  const initial=fingerprints(),pins=fs.readFileSync(join(x.f.stand,'compose.images.json'),'utf8'),jwt=fs.readFileSync(join(x.f.stand,'scan-jwt'),'utf8');
  const prior=x.f.containers.map(c=>structuredClone(c)),egress=prior.find(c=>c.Config.Labels['com.docker.compose.service']==='egress');
  const stopped=await publicImageStand(['stop'],options);assert.equal(stopped.containers?.length??stopped.length,7);
  assert(x.f.containers.every(c=>!c.State.Running));assert.equal(x.f.containers.find(c=>c.Name.endsWith('-api-1')).State.Health.Status,'unhealthy');
  assert(!fs.existsSync(join(x.f.stand,'.operation.lock')));
  const stops=x.f.serviceStops.length,at=x.f.submissions.length,audits=new Set(fs.readdirSync(join(x.f.stand,'llm-deployments')));
  for(const im of x.allImages.values())im.RepoTags=im.RepoTags.filter(tag=>tag==='busybox:1.37.0');
  assert.equal((await publicImageStand(['up'],{...options,llmOptions:{home:x.state.home,Database:DB,checkSource:sourceQualification}})).outcome,'ready');
  assert.equal(x.f.builds,4);assert.equal(x.f.serviceStops.length,stops,'already-stopped peers must not be stopped again');
  assert.deepEqual(x.f.serviceStarts,[egress.Id]);
  const restarted=x.f.containers.find(c=>c.Id===egress.Id);assert(restarted?.State.Running);assert.equal(restarted.Image,egress.Image);assert.deepEqual(restarted.Config,egress.Config);assert.deepEqual(restarted.HostConfig,egress.HostConfig);
  const submitted=x.f.submissions.slice(at),start=submitted.findIndex(a=>a[0]==='container'&&a[1]==='start'&&a[2]===egress.Id);
  assert(start>0);assert(submitted.slice(0,start).some(a=>a[0]==='create'&&a.at(-1)===PUBLIC_LLM_BACKUP_PROGRAM));
  assert(submitted.slice(0,start).some(a=>a[1]==='exec'&&a.at(-1).includes('"group":"llm"')),'real four-store export must precede registry restart');
  assert(!submitted.some(a=>a[1]==='exec'&&prior.some(c=>c.Id===a[2])),'no exec on any stopped original service');
  assert.deepEqual(fingerprints(),initial);assert.equal(fs.readFileSync(join(x.f.stand,'compose.images.json'),'utf8'),pins);assert.equal(fs.readFileSync(join(x.f.stand,'scan-jwt'),'utf8'),jwt);
  const next=fs.readdirSync(join(x.f.stand,'llm-deployments')).filter(n=>!audits.has(n));assert.equal(next.length,1);
  for(const phase of ['fenced','before-api','after-api'])for(const[kind,p]of Object.entries({auth:'core/auth.sqlite',ledger:'core/ledger.sqlite',history:'llm/auth.sqlite',quota:'llm/ledger.sqlite'}))assert.equal(llmFingerprint(DB,fs,crypto,join(x.f.stand,'llm-deployments',next[0],phase,p),kind),initial[kind]);
  assert(!fs.existsSync(join(x.f.stand,'.operation.lock')));assert.equal(x.f.containers.length,7);
  assert(x.f.containers.filter(c=>!c.Name.includes('volume-init')).every(c=>c.State.Running));
});

function stoppedFixture(t){
  const x=concreteFixture(t);
  for(const c of x.f.containers)if(!c.Name.includes('volume-init'))c.State={...c.State,Running:false,Status:'exited',ExitCode:0,Pid:0,FinishedAt:'2026-10-20T00:00:00Z',Health:{Status:'unhealthy'}};
  for(const n of x.f.networks)n.Containers={};
  return x;
}
for(const fault of ['mixed-running','writer-sigterm','oom','restart','paused','pid','created','error','never-started','missing-image','unsafe-env','existing-hold'])test(`CONCRETE stopped preflight ${fault}: refuses without lifecycle/helper/build or uncertainty recovery`,async t=>{
  const x=stoppedFixture(t),api=x.f.containers.find(c=>c.Name.endsWith('-api-1'));
  if(fault==='mixed-running'){const c=x.f.containers.find(c=>c.Name.endsWith('-egress-1'));c.State={...c.State,Running:true,Status:'running',Pid:100};}
  if(fault==='writer-sigterm')api.State.ExitCode=143;
  if(fault==='oom')api.State.OOMKilled=true;
  if(fault==='restart')api.RestartCount=1;
  if(fault==='paused')api.State.Paused=true;
  if(fault==='pid')api.State.Pid=123;
  if(fault==='created')api.State.Status='created';
  if(fault==='error')api.State.Error='synthetic runtime fault';
  if(fault==='never-started')api.State.StartedAt='0001-01-01T00:00:00Z';
  if(fault==='missing-image')x.f.llmFault='missing-prior-image';
  if(fault==='unsafe-env')api.Config.Env.push('NODE_OPTIONS=--inspect');
  if(fault==='existing-hold'){fs.mkdirSync(join(x.f.stand,'.operation.lock'),{mode:0o700});fs.writeFileSync(join(x.f.stand,'.operation.lock/mutation.json'),'existing-uncertainty',{mode:0o600});}
  await assert.rejects(publicLlmStand(['up','--build','--ack-public-maintenance'],{root:x.f.root,home:x.state.home,run:x.run,ambient:{HOME:x.state.home,PATH:process.env.PATH},Database:DB,checkSource:sourceQualification,log:()=>{}}));
  assert.equal(x.f.builds,0);assert.deepEqual(x.f.serviceStops,[]);assert.deepEqual(x.f.serviceStarts,[]);assert(!x.f.submissions.some(a=>a[0]==='create'||a[0]==='compose'));
  assert.equal(fs.existsSync(join(x.f.stand,'.operation.lock')),fault==='existing-hold');
  if(fault==='existing-hold')assert.equal(fs.readFileSync(join(x.f.stand,'.operation.lock/mutation.json'),'utf8'),'existing-uncertainty');
});

test('CONCRETE stopped stand with undrained ledger refuses in the original network-none backup before starting any application',async t=>{
  const x=stoppedFixture(t),db=new DB(join(x.paths.data,'ledger.sqlite'));db.exec('INSERT INTO outbox VALUES(NULL)');db.close();
  await assert.rejects(publicLlmStand(['up','--build','--ack-public-maintenance'],{root:x.f.root,home:x.state.home,run:x.run,ambient:{HOME:x.state.home,PATH:process.env.PATH},Database:DB,checkSource:sourceQualification,log:()=>{}}));
  assert.equal(x.f.builds,0);assert.deepEqual(x.f.serviceStarts,[]);assert.deepEqual(x.f.serviceStops,[]);
  assert(x.f.submissions.some(a=>a[0]==='create'&&a.at(-1)===PUBLIC_LLM_BACKUP_PROGRAM));
  assert(!x.f.submissions.some(a=>a[0]==='compose'||a[1]==='exec'&&x.f.containers.some(c=>c.Id===a[2]&&c.Config.Labels['com.docker.compose.service'])));
  assert(fs.existsSync(join(x.f.stand,'.operation.lock/mutation.json')));assert(x.f.containers.filter(c=>c.Config.Labels['com.docker.compose.service']).every(c=>!c.State.Running));
});

for(const fault of ['missing-prior-image','unclean-worker','unsafe-helper','helper-env','helper-source','helper-args','helper-host','helper-running-args']) test(`CONCRETE ${fault}: refuses before build, retains HOLD only after mutation`,async t=>{
  const x=concreteFixture(t);x.f.llmFault=fault;
  await assert.rejects(publicLlmStand(['up','--build','--ack-public-maintenance'],{root:x.f.root,home:x.state.home,run:x.run,ambient:{HOME:x.state.home,PATH:process.env.PATH},Database:DB,checkSource:sourceQualification,sleep:async()=>{},log:()=>{}}));
  assert.equal(x.f.builds,0);assert.equal(fs.existsSync(join(x.f.stand,'.operation.lock/mutation.json')),fault!=='missing-prior-image');
  if(fault==='missing-prior-image')assert.deepEqual(x.f.serviceStops,[]);
});

for (const fault of ['image-config-drift', 'late-api-health']) test(`CONCRETE ${fault}: immutable execution defaults and post-ready health remain guarded with web closed`, async t => {
  const x = concreteFixture(t), originalApi = x.f.images.api.Id;
  if (fault === 'image-config-drift') x.f.afterBuild = () => { x.allImages.get(originalApi).Config.Env.push('NODE_OPTIONS=--inspect'); };
  else x.f.llmFault = fault;
  await assert.rejects(publicLlmStand(['up', '--build', '--ack-public-maintenance'], { root:x.f.root, home:x.state.home, run:x.run, ambient:{ HOME:x.state.home, PATH:process.env.PATH }, Database:DB,checkSource:sourceQualification, sleep:async()=>{}, log:()=>{} }));
  assert.equal(x.f.builds, 4); assert.equal(x.f.containers.find(c=>c.Name.endsWith('-web-1')).State.Running, false);
  assert(!fs.existsSync(join(x.f.stand, 'llm-profile.json'))); assert(fs.existsSync(join(x.f.stand, '.operation.lock/mutation.json')));
});

for (const change of ['source-content', 'source-membership', 'source-inode', 'manifest', 'external-config', 'profile', 'volume-metadata']) test(`CONCRETE ${change}: source/config authority drift holds after web fence without build or admission`, async t => {
  const x = concreteFixture(t);
  x.f.afterStop = name => {
    if (name !== 'web') return;
    const file = join(x.f.root, 'server/deploy/public-stand.Dockerfile');
    if (change === 'source-content') fs.appendFileSync(file, '\n# drift\n');
    if (change === 'source-membership') fs.writeFileSync(join(x.f.root, 'server/api/src/unreviewed.ts'), '');
    if (change === 'source-inode') { const bytes = fs.readFileSync(file); fs.renameSync(file,file+'.prior'); fs.writeFileSync(file,bytes); }
    if (change === 'manifest') fs.appendFileSync(join(x.f.root, 'server/api/package.json'), '\n');
    if (change === 'external-config') fs.appendFileSync(join(x.state.path, 'llm.env'), '# drift\n');
    if (change === 'profile') fs.appendFileSync(join(x.f.stand, 'profile.json'), '\n');
    if (change === 'volume-metadata') x.f.volumes.find(v=>v.Name===`${PROJECT}_auth_accounts`).Options={device:'/foreign'};
  };
  await assert.rejects(publicLlmStand(['up', '--build', '--ack-public-maintenance'], { root:x.f.root, home:x.state.home, run:x.run, ambient:{ HOME:x.state.home, PATH:process.env.PATH }, Database:DB,checkSource:sourceQualification, sleep:async()=>{}, log:()=>{} }));
  assert.equal(x.f.builds, 0); assert.deepEqual(x.f.serviceStops, ['web']); assert(fs.existsSync(join(x.f.stand,'.operation.lock/mutation.json')));
});

for (const fault of ['driver', 'options', 'labels', 'foreign-consumer', 'incomplete-backup']) test(`CONCRETE ${fault}: candidate key metadata/backup history refuses before first stop`, async t => {
  const x = concreteFixture(t);
  fs.writeFileSync(join(x.state.path,'key-volume.json'), JSON.stringify({version:1,volume:keySelection.keyVolume,uid:65532,gid:65532,fileMode:'0400',directoryMode:'0500',target:'/run/secrets/public_openrouter_key',initializerImage:'sha256:'+'f'.repeat(64)}), {mode:0o600});
  const v = {Name:keySelection.keyVolume, Driver:'local', Scope:'local', Options:null, Labels:{'diplom.public-llm':'key-v1'}, Mountpoint:`/fixture/volumes/${keySelection.keyVolume}`};
  if (fault === 'driver') v.Driver = 'foreign';
  if (fault === 'options') v.Options = {device:'/foreign'};
  if (fault === 'labels') v.Labels = {};
  x.f.volumes.push(v);
  if (fault === 'foreign-consumer') { const c = structuredClone(x.f.containers.find(c=>c.Name.endsWith('-api-1'))); c.Id = '9'.repeat(64); c.Name='/foreign-1'; c.Config.Labels={'com.docker.compose.project':'foreign'}; c.Mounts=[{Type:'volume',Name:v.Name}]; x.f.containers.push(c); }
  if (fault === 'incomplete-backup') fs.mkdirSync(join(x.f.stand, 'llm-deployments/deploy-'+'a'.repeat(32)), {recursive:true,mode:0o700});
  await assert.rejects(publicLlmStand(['up','--build','--ack-public-maintenance'],{root:x.f.root,home:x.state.home,run:x.run,ambient:{HOME:x.state.home,PATH:process.env.PATH},Database:DB,checkSource:sourceQualification,log:()=>{}}));
  assert.deepEqual(x.f.serviceStops, []); assert.equal(x.f.builds, 0); assert(!fs.existsSync(join(x.f.stand,'.operation.lock')));
});

test('shared public lock excludes this new launcher, plan is import-safe/no Docker/no approved state reads',async t=>{
  const f=fixture(t),state=settings(t),lock=acquireLock(f.root),calls=[];
  await assert.rejects(publicLlmStand(['up','--build','--ack-public-maintenance'],{root:f.root,home:state.home,run:async()=>{calls.push('docker');throw Error();}}));
  assert.deepEqual(calls,[]);lock.release();
  const logs=[];assert.equal((await publicLlmStand(['plan'],{root:ROOT,home:'/nonexistent-forbidden-home',run:async()=>{throw Error('Docker forbidden');},log:x=>logs.push(x)})).services,7);assert.equal(logs.length,1);
});
