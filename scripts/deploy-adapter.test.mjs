// Fixture library only: no registered tests and no automatic execution.
// All Docker/HTTP operations are fakes; SQLite and constructors use test-owned temp paths.
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import fsDefault from 'node:fs';
import * as crypto from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import { spawnSync } from 'node:child_process';
import { fixture } from './public-refresh-cve-fixtures.mjs';
import { PROJECT, STATE, LABEL, backupExportOperation, CONFIG_SECRET, runIsolatedDocker } from './public-image-stand.mjs';
import { expectedPublicLlmConfig, publicLlmEnvironmentOverlay, PUBLIC_LLM_ENV, PUBLIC_LLM_CURRENT_BACKUP_PROGRAM, capturePublicLlmSource, readPublicLlmBinding, loadPublicLlmSettings, PUBLIC_LLM_GATEWAY_PROBE } from './public-llm-stand.mjs';
import { createDeployAdapter, deployAdapterDiagnostic, WEB_BACKEND_SOURCE_PROBE, AUTH_SCHEMA_PROBE, ADAPTER_READY_PROBE } from './deploy-adapter.mjs';
import { PUBLIC_LLM_EXECUTION_MODULES } from './public-llm-build-continuation.mjs';
import { OPENAI_DEPLOYMENT, PUBLIC_IMAGE_OPERATIONS, validateOpenAiDeployment } from './public-llm-source-build.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const DB = createRequire(join(ROOT, 'server/api/package.json'))('better-sqlite3');
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const clone = value => structuredClone(value);
const role = c => c.Config.Labels['com.docker.compose.service'];
function temporary(t) {
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'fast-deploy-test-')));
  t.after(() => fs.rmSync(root, { recursive: true, force: true })); return root;
}
function selection() {
  const environment = { LLM_PROVIDER: 'openai', OPENAI_ENABLED: 'true', OPENAI_MODEL: OPENAI_DEPLOYMENT.model,
    OPENAI_ROUTING_APPROVED: 'true', OPENAI_RETENTION: 'no-training', OPENAI_POLICY_REVISION: 'independent-v1',
    OPENAI_ACCOUNTING_REVISION: 'independent-v1', OPENAI_MONETARY_LIMIT: 'uncapped',
    OPENAI_INPUT_PRICE_MICROS_PER_MILLION: '1000000', OPENAI_OUTPUT_PRICE_MICROS_PER_MILLION: '2000000',
    OPENAI_TIMEOUT_MS: '1000', OPENAI_REQUEST_BYTES: '65536', OPENAI_RESPONSE_BYTES: '8192',
    OPENAI_INPUT_TOKENS: '4096', OPENAI_OUTPUT_TOKENS: '256', OPENAI_FINDINGS: '100', OPENAI_MAX_CONCURRENT: '2',
    LLM_QUOTA_ENABLED: 'true', LLM_QUOTA_REVISION: 'independent-v1', LLM_QUOTA_WINDOW: 'utc-day', LLM_QUOTA_MONETARY_LIMIT: 'uncapped',
    LLM_QUOTA_USER_INPUT: '100000', LLM_QUOTA_USER_OUTPUT: '10000', LLM_QUOTA_SCAN_INPUT: '100000', LLM_QUOTA_SCAN_OUTPUT: '10000',
    LLM_QUOTA_WARNING_PERCENT: '80', LLM_QUOTA_REQUEST_INPUT: '4096', LLM_QUOTA_OBSERVATION_TOKENS: '65536',
    LLM_QUOTA_OBSERVATION_COST_MICROS: '1000000', LLM_QUOTA_RECEIPT_MS: '30000', LLM_QUOTA_REPLAY_DAYS: '7',
    LLM_QUOTA_MAX_ROWS: '100', LLM_QUOTA_DB_BYTES: '1048576', LLM_QUOTA_DISK_HEADROOM_BYTES: '134217728',
    LLM_QUOTA_BUSY_MS: '10', LLM_QUOTA_CLEANUP_BATCH: '10' };
  return { version: 6, provider: 'OpenAI', keyVolume: null, openrouter: { version: 1, keyVolume: null },
    monetaryLimit: 'uncapped', credentialVolume: 'openai-secrets', environment };
}
function sources(root) {
  const files = [...PUBLIC_LLM_EXECUTION_MODULES, 'package.json','pnpm-lock.yaml','pnpm-workspace.yaml','index.html','admin.html','vite.config.ts','tsconfig.json','.gitignore','.dockerignore',
    'server/api/package.json','server/api/tsconfig.json','server/deploy/trust/db-signing-key.pub.pem',
    'server/deploy/compose.public-images.yaml','server/deploy/compose.public-llm.yaml','server/deploy/public-stand.Dockerfile',
    'server/deploy/public-stand.nginx.conf','server/deploy/api.Dockerfile','server/deploy/worker.Dockerfile','server/deploy/openai-api.Dockerfile',
    'server/deploy/openai-secret-bootstrap.mjs','server/deploy/openai-secret-init.py'];
  for (const name of fs.readdirSync(join(ROOT,'scripts'))) if (/\.(mjs|py)$/.test(name) && !/(?:^test_|\.test\.)/.test(name)) files.push('scripts/'+name);
  for (const name of fs.readdirSync(join(ROOT,'server/deploy/gateway'))) if (/\.(py|Dockerfile)$/.test(name) || name === 'Dockerfile') files.push('server/deploy/gateway/'+name);
  for (const name of files) { fs.mkdirSync(dirname(join(root,name)),{recursive:true,mode:0o700}); fs.copyFileSync(join(ROOT,name),join(root,name)); }
  for (const name of ['src','public','server/api/src','server/runtime/src']) fs.cpSync(join(ROOT,name),join(root,name),{recursive:true});
  fs.symlinkSync(join(ROOT,'node_modules'),join(root,'node_modules'),'dir');
  fs.symlinkSync(join(ROOT,'server/api/node_modules'),join(root,'server/api/node_modules'),'dir');
}
function child(root, code, input) {
  const result=spawnSync(process.execPath,['--import','tsx','--input-type=module','-e',code],{
    cwd:join(root,'server/api'),env:{PATH:'/usr/bin:/bin'},input:JSON.stringify(input),encoding:'utf8',timeout:10000,maxBuffer:65536});
  assert.equal(result.error,undefined); assert.equal(result.status,0,'fixture constructor/helper failed: '+result.stderr); return result;
}
export async function adapterFixture(t, { failedStart = null, publishedOperations = false, stopStdout = 'id', stopFault = null, helperTransition = null } = {}) {
  // Reuse metadata constructors only. Synthetic release files are not activated;
  // reset to the non-CVE profile before invoking any new adapter method.
  const f=fixture(t), root=f.root, home=temporary(t); sources(root);
    // Capacity is part of this fake environment, not the developer's free disk.
    const statfs = fsDefault.statfsSync;
    const capacityMock = t.mock.method(fsDefault, 'statfsSync', (...args) => ({ ...statfs(...args), bavail: 8 * 1024 ** 2, bsize: 4096 }));
    syncBuiltinESMExports();
    t.after(() => { capacityMock.mock.restore(); syncBuiltinESMExports(); });
  fs.writeFileSync(join(f.stand,'profile.json'),JSON.stringify({version:1,project:PROJECT,cve:null}));
  fs.rmSync(join(f.stand,'compose.cve.json'));
  const configured=validateOpenAiDeployment(selection());
    const s=validateOpenAiDeployment({ ...configured, ...(publishedOperations ? { operations: PUBLIC_IMAGE_OPERATIONS } : {}) });
    const settings=join(home,'.local/state/diplom-public-images/llm');
  fs.mkdirSync(settings,{recursive:true,mode:0o700});
  const write=(path,value)=>fs.writeFileSync(path,typeof value==='string'?value:JSON.stringify(value),{mode:0o600});
  write(join(settings,'llm.env'),Object.entries(PUBLIC_LLM_ENV).map(([k,v])=>`${k}=${v}`).join('\n')+'\n');
  write(join(settings,'openai-deployment.json'),configured);
  write(join(f.stand,'llm-profile.json'),s); write(join(f.stand,'compose.llm-env.json'),publicLlmEnvironmentOverlay(s));
  const model=expectedPublicLlmConfig(root,null,s);
  for(const [name,cmd]of [['llm-egress',['python','-I','openrouter.py']],['openai-egress',[...OPENAI_DEPLOYMENT.gatewayCommand]]]){
    f.images[name]=clone(f.images.egress);f.images[name].Id='sha256:'+sha(name);f.images[name].RepoTags=[`${PROJECT}-${name}:local`];f.images[name].Config.Cmd=cmd;
  }
  const allImages=new Map(Object.values(f.images).map(i=>[i.Id,clone(i)])), events=[],diagnostics=[],helperTransitions=[];
  let generation=10, tick=0;
  const timestamp=()=>new Date(Date.UTC(2026,10,1,0,0,++tick)).toISOString();
  const materialize=(name,spec,image)=>{
    const previous=f.images[name];f.images[name]=image;const c=f.makeContainer(name,spec,8,++generation);f.images[name]=previous;
    c.Config.Entrypoint=spec.entrypoint??c.Config.Entrypoint;
    if(name.endsWith('egress'))c.Config.Env=[...image.Config.Env];
    const command=[...(c.Config.Entrypoint??[]),...c.Config.Cmd];c.Path=command[0];c.Args=command.slice(1);
    if(spec.ulimits)c.HostConfig.Ulimits=[{Name:'core',Soft:0,Hard:0}];
    if(spec.logging)c.HostConfig.LogConfig={Type:spec.logging.driver,Config:clone(spec.logging.options)};
    for(const mount of c.Mounts.filter(m=>m.Type==='volume')){
      const declaration=c.HostConfig.Mounts.find(m=>m.Target===mount.Destination);
      if(mount.Destination==='/run/openai-secrets'){declaration.Source='openai-secrets';declaration.VolumeOptions={NoCopy:true};mount.Name='openai-secrets';}
      mount.Driver='local';mount.Source='/fixture/volumes/'+mount.Name;
    }
    c.Created=timestamp();c.State.StartedAt=timestamp();c.State.FinishedAt=name.endsWith('volume-init')?timestamp():'0001-01-01T00:00:00Z';return c;
  };
  f.containers=Object.entries(model.services).map(([name,spec])=>materialize(name,spec,allImages.get(f.images[name].Id)));
  f.networks=Object.values(model.networks).map(n=>({Name:n.name,Id:sha(n.name),Driver:'bridge',Labels:{[LABEL]:'v1','com.docker.compose.project':PROJECT},Internal:Boolean(n.internal),Options:null,Containers:{}}));
  f.volumes=Object.values(model.volumes).map(v=>({Name:v.name,Driver:'local',Scope:'local',Mountpoint:'/fixture/volumes/'+v.name,Options:null,
    Labels:v.external?{'org.diplom.openai-secret':'v1','org.diplom.openai-secret.claim':'f'.repeat(32)}:{[LABEL]:'v1','com.docker.compose.project':PROJECT}}));
  f.attachments();write(join(f.stand,'compose.images.json'),{services:Object.fromEntries(f.containers.map(c=>[role(c),{image:c.Image}]))});
  const data=temporary(t);fs.mkdirSync(join(data,'auth'));fs.mkdirSync(join(data,'data'));
  const paths={auth:join(data,'auth/auth.sqlite'),ledger:join(data,'data/ledger.sqlite'),history:join(data,'auth/llm-history.sqlite'),quota:join(data,'auth/llm-usage.sqlite')};
  const authEnv=Object.fromEntries(['AUTH_ORIGIN','AUTH_ALLOW_INSECURE_LOCAL_HTTP','SCAN_BROWSER_ALLOWED_USER_IDS','SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS'].map(k=>[k,model.services.api.environment[k]]));
  child(root,`import fs from 'node:fs';import {ScanLedger} from './src/ledger/ledger.ts';import {HistoryStore} from './src/llm/history-store.ts';import {QuotaLedger} from './src/llm/quota-ledger.ts';import {quotaPolicyFromEnvironment} from './src/llm/quota-policy.ts';const {paths,authEnv,env}=JSON.parse(fs.readFileSync(0,'utf8'));Object.assign(process.env,authEnv,{AUTH_DB_PATH:paths.auth});const {AuthStore}=await import('./src/auth/auth.store.ts');const a=new AuthStore();a.assertAvailable();a.onModuleDestroy();const l=new ScanLedger(paths.ledger);l.close();const h=new HistoryStore(paths.history,true);h.close();const q=new QuotaLedger(paths.quota,quotaPolicyFromEnvironment(env),Date.now,true);q.close();`,{paths,authEnv,env:s.environment});
  for(const path of Object.values(paths)) {fs.chmodSync(path,0o600);const db=new DB(path);db.exec("CREATE TABLE deploy_test_evidence(value BLOB);INSERT INTO deploy_test_evidence VALUES(X'0001ff')");db.close();}
  const original=Object.fromEntries(Object.entries(paths).map(([k,p])=>[k,fs.readFileSync(p)]));
  const helpers=new Map();const calls=[];
  const lookup=(kind,ref)=>kind==='image'?allImages.get(ref)??[...allImages.values()].find(i=>i.RepoTags.includes(ref)):f[kind+'s'].find(c=>c.Id===ref||c.Name===ref||c.Name==='/'+ref);
  const backendHash=crypto.createHash('sha256');for(const name of ['src/auth/auth.store.ts','src/auth/auth.controller.ts'])backendHash.update(name).update('\0').update(fs.readFileSync(join(root,'server/api',name))).update('\0');
  const sourceHash=backendHash.digest('hex');
  const run=async(args,options)=>{
    calls.push([...args]);assert.ok(options.timeout>0);assert.ok(!args.some(a=>/dip-local-full|\.local-auth/.test(a)));
    if(args[0]==='context')return JSON.stringify('unix:///fixture/docker.sock');
    if(args[0]==='info')return JSON.stringify({id:'test-daemon-1234',memory:32*1024**3,cpus:8});
    if(['container','image','network','volume'].includes(args[0])&&args[1]==='inspect'){
      const rows=args.slice(2).map(ref=>lookup(args[0],ref));assert.ok(rows.every(Boolean),'unknown fake inspect identity');
            if(args[0]==='container' && args.length===3 && events.includes('stop:web') && role(rows[0])==='web') {
              const observed=clone(rows[0]);
              if(stopFault==='identity')observed.Id=sha('wrong-post-stop-identity');
              if(stopFault==='control')observed.Config.Cmd=['unapproved-command'];
              if(stopFault==='started-at')observed.State.StartedAt=timestamp();
              return JSON.stringify([observed]);
            }
            return JSON.stringify(rows);
    }
    if(args[0]==='image'){
      if(args[1]==='ls'){const reference=args.find(a=>a.startsWith('reference='))?.slice(10);return [...allImages.values()].flatMap(i=>i.RepoTags).filter(t=>!reference||t===reference).join('\n');}
      assert.equal(args[1],'tag');const image=lookup('image',args[2]);assert.ok(image);image.RepoTags.push(args[3]);return '';
    }
    if(args[0]==='build'){
      const tag=args[args.indexOf('--tag')+1],name=tag.match(/^dip-deploy-(.+):candidate-/)[1];
      assert.ok(f.containers.filter(c=>['api','web','worker'].includes(role(c))).every(c=>c.State.Running),'OLD must serve during build');
      const image=clone(f.images[name]);image.Id='sha256:'+sha('candidate-'+name);image.RepoTags=[tag];allImages.set(image.Id,image);events.push('build:'+name);return '';
    }
    if(args[0]==='compose'){
      const path=args[args.indexOf('-f')+1],recipe=JSON.parse(fs.readFileSync(path));
      if(args.includes('config')){recipe.services.api.environment.SCAN_JWT_SECRET=CONFIG_SECRET;return JSON.stringify(recipe);}
      assert.ok(args.includes('up')&&args.includes('--no-deps')&&args.includes('--no-build')&&args.includes('never'));
      const name=args.at(-1),spec=recipe.services[name],image=lookup('image',spec.image);assert.ok(image);
      const current=materialize(name,spec,image);
            if(name===failedStart && path.endsWith('recipe-candidate.json')) {
              current.State={...current.State,Running:false,Status:'exited',Pid:0,ExitCode:1,FinishedAt:timestamp()};
              events.push('failed-start:'+name);
            }
            f.containers=f.containers.filter(c=>role(c)!==name);f.containers.push(current);f.attachments();events.push('up:'+name);return '';
    }
    if(['network','volume'].includes(args[0])&&args[1]==='ls')return f[args[0]+'s'].map(n=>n.Name).join('\n');
    if(args[0]==='create'){
      const name=args[args.indexOf('--name')+1],image=lookup('image',args.find(a=>a.startsWith('sha256:'))),backup=temporary(t);
      assert.ok(args.includes('--read-only')&&args[args.indexOf('--network')+1]==='none');
      const c=clone(f.containers.find(c=>role(c)==='api'));
      Object.assign(c,{Id:sha(name),Name:'/'+name,Image:image.Id,Created:timestamp(),Path:'node',Args:args.slice(args.indexOf(image.Id)+1)});
      c.Config={...clone(image.Config),Image:image.Id,Entrypoint:['node'],Cmd:c.Args,Env:[...image.Config.Env,'TMPDIR=/backup'],Labels:{[LABEL]:'v1','com.docker.compose.project':PROJECT,'org.diplom.recovery-helper':'v1','org.diplom.recovery-purpose':'backup'}};
      c.State={Status:'created',Running:false,Pid:0,ExitCode:0,StartedAt:'0001-01-01T00:00:00Z'};c.NetworkSettings={Networks:{},Ports:{}};
      Object.assign(c.HostConfig,{Memory:1073741824,MemorySwap:1073741824,NanoCpus:1e9,PidsLimit:32,NetworkMode:'none',PortBindings:{},RestartPolicy:{Name:'no',MaximumRetryCount:0},Tmpfs:{'/backup':'rw,noexec,nosuid,uid=65532,gid=65532,size=512m'},Mounts:[['auth_accounts','/auth'],['scan_ledger','/data']].map(([name,target])=>({Type:'volume',Source:PROJECT+'_'+name,Target:target,ReadOnly:true,VolumeOptions:{NoCopy:true,DriverConfig:{}}}))});
      delete c.HostConfig.Ulimits;c.HostConfig.OomKillDisable=false;c.Mounts=c.HostConfig.Mounts.map(m=>({Type:'volume',Name:m.Source,Source:'/fixture/volumes/'+m.Source,Driver:'local',Destination:m.Target,RW:false,Propagation:'rprivate'}));
      helpers.set(c.Id,{backup,phase:name.split('-').slice(-2).join('-'),program:args.at(-1),created:clone(c)});f.containers.push(c);return c.Id+'\n';
    }
    if(args[0]==='container'){
      if(args[1]==='ls'){
        const volume=args.find(a=>a.startsWith('volume='))?.slice(7);
        return f.containers.filter(c=>!volume||c.Mounts.some(m=>m.Name===volume)).map(c=>c.Id).join('\n');
      }
      const c=lookup('container',args[1]==='stop'?args.at(-1):args[2]);assert.ok(c,'unknown fake container');const name=role(c)??'helper',h=helpers.get(c.Id);
      if(args[1]==='start'){
        c.State={...c.State,Running:true,Status:'running',Pid:123,ExitCode:0,StartedAt:timestamp(),FinishedAt:'0001-01-01T00:00:00Z'};
        if(h){c.NetworkSettings.Networks={none:{}};c.HostConfig.OomKillDisable=false;
          // a7 same-image evidence: the sole benign control delta is false -> null.
          if(helperTransition)c.HostConfig.OomKillDisable=null;
          if(helperTransition==='oom-true')c.HostConfig.OomKillDisable=true;
          if(helperTransition==='readonly-drift')c.HostConfig.ReadonlyRootfs=false;
          if(helperTransition==='mount-drift'){
            c.HostConfig.Mounts[0].ReadOnly=false;c.Mounts[0].RW=true;
          }
          helperTransitions.push({created:h.created,running:clone(c)});
          assert.equal(h.program,PUBLIC_LLM_CURRENT_BACKUP_PROGRAM);
          const program=h.program.replaceAll('/auth/',join(data,'auth')+'/').replaceAll("'/auth'",JSON.stringify(join(data,'auth'))).replaceAll('/data/',join(data,'data')+'/').replaceAll('/backup',h.backup).replace("process.on('SIGTERM',()=>process.exit(0));",'').replace('setTimeout(()=>process.exit(73),300000);','');
          child(root,program,{});const phase=c.Name.match(/-(fenced|before-api|after-api)$/)?.[1];events.push('snapshot:'+phase);
        }
        f.attachments();events.push('start:'+name);return c.Id+'\n';
      }
      if(args[1]==='stop'){
              c.State={...c.State,Running:false,Status:'exited',Pid:0,ExitCode:0,FinishedAt:timestamp()};
              if(name==='web' && stopFault==='nonclean')c.State.ExitCode=137;
              f.attachments();events.push('stop:'+name);
              if(name==='web' && stopFault==='dispatch')throw Object.assign(Error('synthetic uncertain stop dispatch'),{code:1,stdout:c.Id+'\n'});
              return stopStdout === 'empty' ? '' : c.Id+'\n';
            }
      if(args[1]==='rm'){assert.ok(h);f.containers=f.containers.filter(item=>item!==c);helpers.delete(c.Id);return c.Id+'\n';}
      assert.equal(args[1],'exec');assert.equal(c.State.Running,true);
      if(h){
        if(args.at(-1).startsWith('{')){
          const {group,request}=JSON.parse(args.at(-1));if(request.action==='chunk')request.stamp.uid=String(process.getuid());
          const value=backupExportOperation(fs,crypto,request,{backup:join(h.backup,group),auth:group==='core'?paths.auth:paths.history,ledger:group==='core'?paths.ledger:paths.quota});
          if(request.action==='manifest')for(const r of ['auth','ledger']){value.files[r].uid='65532';for(const source of value.sources[r])source.stamp.uid='65532';}return JSON.stringify(value);
        }
        return fs.readFileSync(join(h.backup,'ready.json'),'utf8');
      }
      if(args.at(-1)===WEB_BACKEND_SOURCE_PROBE)return JSON.stringify({version:1,source:sourceHash});
      if(args.at(-1)===AUTH_SCHEMA_PROBE)return '{"version":3}';
      if(args.at(-1).includes('AS jobs'))return '{"jobs":0,"leases":0,"outbox":0}';
      const gateways = name === 'api' ? PUBLIC_LLM_GATEWAY_PROBE + PUBLIC_LLM_GATEWAY_PROBE.replaceAll('llmGateway','openAiGateway').replaceAll('connectLlmGateway','connectOpenAiGateway').replaceAll('llm-egress','openai-egress') : '';
            assert.ok(['api','worker'].includes(name)&&args.includes('--input-type=module'),'unknown fake exec');
            assert.equal(args.at(-1),gateways+ADAPTER_READY_PROBE,'only the reviewed readiness program is supported');return '{"ready":true}';
    }
    assert.fail('unsupported fake engine command '+args.slice(0,2).join(' '));
  };
  assert.deepEqual(readPublicLlmBinding(root),s);
  assert.deepEqual(loadPublicLlmSettings(home,{openai:true}).selection,configured);
  capturePublicLlmSource(root,{openai:true}).verify();
  // Exercise the production process wrapper too: this executor never spawns Docker.
    // execFile's callback has separate stdout/stderr; only stdout reaches the adapter.
    const transport = (args, options) => runIsolatedDocker(args, options, (executable, argv, execution, callback) => {
      assert.equal(executable, 'docker'); assert.deepEqual(argv, args);
      Promise.resolve().then(() => run(argv, { root: execution.cwd, env: execution.env, timeout: execution.timeout }))
        .then(stdout => callback(null, stdout, 'synthetic Docker stderr warning\n'), error => {
          diagnostics.push({fakeEngineFailure:error.message}); callback(error, error.stdout ?? '', 'synthetic fake-engine failure');
        });
    });
    const actual=createDeployAdapter({root,home,run:transport,Database:DB,checkSource:async()=>({typescript:true,bundle:true,openai:true}),
    http:async url=>{assert.ok(url.startsWith('http://127.0.0.1:8081/'));return {status:new URL(url).pathname==='/'?200:401,body:{cancel:async()=>{}}};}});
  // Keep the real implementation and its finite diagnostics, translating exactly
  // at the same boundary as createAdapter without hiding the diagnostic from tests.
  const codes={acquireLock:'LOCKED',releaseLock:'UNLOCK',preflight:'PREFLIGHT',build:'BUILD',validateCandidate:'CANDIDATE',verify:'VERIFY',waitForIdle:'DRAIN',prepareRecovery:'RECOVERY',fenceAdmissions:'FENCE',snapshot:'SNAPSHOT',qualifyState:'QUALIFY',switchServices:'SWITCH',health:'HEALTH',publishReceipt:'RECEIPT',restoreOld:'RESTORE'};
  const adapter=Object.fromEntries(Object.entries(codes).map(([name,code])=>[name,async ctx=>{
    try{return await actual[name](ctx);}catch(error){diagnostics.push({method:name,...deployAdapterDiagnostic(error)});throw Object.assign(Error('withheld'),{code:'DEPLOY_'+code});}
  }]));
  return {adapter,rawAdapter:actual,publishedSelection:clone(s),configuredSelection:clone(configured),events,calls,diagnostics,helperTransitions,role,containers:()=>f.containers,locked:()=>fs.existsSync(join(f.stand,'.operation.lock')),

        pins:()=>JSON.parse(fs.readFileSync(join(f.stand,'compose.images.json'))),verifyStores(){for(const [kind,path]of Object.entries(paths))assert.deepEqual(fs.readFileSync(path),original[kind],kind+' live bytes changed');}};
}
