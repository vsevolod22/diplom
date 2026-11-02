#!/usr/bin/env node
// Archive-only completion of a reviewed restore receipt. No Docker mutation,
// secret-file reads, database reads, or claim that today's stores equal old data.
import * as fs from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual as equal } from 'node:util';
import * as http from 'node:http';
import { PROJECT, STATE, runIsolatedDocker, assertReconciliationHistory } from './public-image-stand.mjs';
import { dockerEnvironment } from './local-stand.mjs';
import { publicImageCveConfig } from './public-image-stand-profile.mjs';
import { privateFile, byteFile, directoryIdentity } from './public-llm-build-continuation.mjs';
import { writeExclusive, syncDirectory } from './setup-local-cve.mjs';
import { capturePublicLlmSource, validateCurrentAuditHistory, validatePublicLlmImage, validateLlmSelection, publicLlmEnvironmentOverlay } from './public-llm-stand.mjs';
import { captureDeploymentCatalog } from './public-llm-deployment-catalog.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const SELF = 'scripts/deploy-reconcile-restored.mjs';
const GUARD = '.recover-build-and-redeploy.lock';
const ROLES = ['api','auth-volume-init','egress','llm-egress','openai-egress','scan-volume-init','web','worker'];
const PHASES = ['fenced','before-api','after-api'];
const STARTED = ['egress','worker','api','web'];
const hex = v => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const need = (v, code) => { if (!v) throw Error(code); };
const canonical = v => Array.isArray(v) ? v.map(canonical) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k => [k,canonical(v[k])])) : v;
const hash = v => createHash('sha256').update(typeof v === 'string' ? v : JSON.stringify(canonical(v))).digest('hex');
const stamp = s => [s.dev,s.ino,s.uid,s.mode,s.nlink,s.size,s.mtimeMs,s.ctimeMs];
const names = p => fs.readdirSync(p).sort();
const exists = p => fs.lstatSync(p,{throwIfNoEntry:false}) !== undefined;
const epoch = c => [c.Id,c.State.StartedAt,c.State.FinishedAt,c.State.Pid,c.RestartCount,c.State.Running,c.State.Status,c.State.ExitCode,c.State.Error];
const lines = s => s.trim().split('\n').filter(Boolean).sort();

// Docker's inspect formatter receives a map. Remove secret fields BEFORE bytes
// leave Docker CLI, rather than reading the JWT and redacting it after capture.
// Image Config uses the same projection; OPENAI_API_KEY presence is a refusal.
export const SAFE_INSPECT = '{ {{range $k,$v := .}}{{if eq $k "Config"}}"Config":{ {{range $ck,$cv := $v}}{{if eq $ck "Env"}}"Env":[{{range $ev := $cv}}{{if and (ne (index (split $ev "=") 0) "SCAN_JWT_SECRET") (ne (index (split $ev "=") 0) "OPENAI_API_KEY")}}{{json $ev}},{{end}}{{end}}null],"__keyPresent":{{ $present := false }}{{range $ev := $cv}}{{if eq (index (split $ev "=") 0) "OPENAI_API_KEY"}}{{$present = true}}{{end}}{{end}}{{$present}},{{else}}{{json $ck}}:{{json $cv}},{{end}}{{end}}"__end":null},{{else if eq $k "State"}}"State":{"Status":{{json $v.Status}},"Running":{{json $v.Running}},"Paused":{{json $v.Paused}},"Restarting":{{json $v.Restarting}},"OOMKilled":{{json $v.OOMKilled}},"Dead":{{json $v.Dead}},"Pid":{{json $v.Pid}},"ExitCode":{{json $v.ExitCode}},"Error":{{json $v.Error}},"StartedAt":{{json $v.StartedAt}},"FinishedAt":{{json $v.FinishedAt}},"Health":{"Status":{{if index $v "Health"}}{{json (index $v "Health").Status}}{{else}}null{{end}}}},{{else}}{{json $k}}:{{json $v}},{{end}}{{end}}"__end":null}';
export function decodeInspect(text, refs, field) {
  const rows = lines(text).map(s => JSON.parse(s));
  need(rows.length === refs.length, 'RECONCILE_CARDINALITY');
  for (const c of rows) {
    delete c.__end;
    if (c.Config) {
      need(c.Config.__keyPresent === false, 'RECONCILE_DOCKER_SECRET');
      delete c.Config.__keyPresent; delete c.Config.__end;
      need(Array.isArray(c.Config.Env) && c.Config.Env.at(-1) === null, 'RECONCILE_FORMAT');
      c.Config.Env.pop();
    }
  }
  need(equal(rows.map(c => c[field]).sort(), [...refs].sort()), 'RECONCILE_IDENTITIES');
  return rows;
}
export function restoredControl(c) {
  const command = [...(c.Config.Entrypoint ?? []), ...(c.Config.Cmd ?? [])];
  need(c.Path === command[0] && equal(c.Args,command.slice(1)), 'RECONCILE_COMMAND');
  need(c.Config.Env.every(v => !/^(SCAN_JWT_SECRET|OPENAI_API_KEY)=/.test(v)), 'RECONCILE_SECRET_PROJECTION');
  return hash({Name:c.Name,Image:c.Image,Path:c.Path,Args:c.Args,Config:c.Config,HostConfig:c.HostConfig,
    Mounts:[...c.Mounts].sort((a,b) => a.Destination.localeCompare(b.Destination))});
}
export function validateRestoredPeer(c, expected) {
  need(c.Id === expected.id && c.Image === expected.image && restoredControl(c) === expected.control && equal(epoch(c),expected.epoch), 'RECONCILE_PEER_DRIFT');
  const running = !expected.name.endsWith('volume-init'), s = c.State;
  need(c.Name === '/'+PROJECT+'-'+expected.name+'-1' && c.Config.Labels['com.docker.compose.project'] === PROJECT && c.Config.Labels['com.docker.compose.service'] === expected.name, 'RECONCILE_OWNERSHIP');
  need(c.RestartCount === 0 && !s.OOMKilled && !s.Paused && !s.Restarting && !s.Dead && !s.Error && s.ExitCode === 0 && s.Running === running && s.Status === (running?'running':'exited') && (running?s.Pid>0:s.Pid===0), 'RECONCILE_PROCESS');
  if (expected.name === 'api') need(s.Health?.Status === 'healthy','RECONCILE_API_HEALTH');
  const ports = c.HostConfig.PortBindings ?? {};
  need(equal(ports,expected.name === 'web' ? {'8080/tcp':[{HostIp:'127.0.0.1',HostPort:'8081'}]} : {}),'RECONCILE_PORTS');
}

// Opaque retained SQLite files are bound by inode/metadata, never opened. JSON
// evidence is byte-bound. Rename keeps those files and all directory entries.
function evidenceSeal(base) {
  const entries = []; let bytes = 0;
  function walk(rel='') {
    need(entries.length < 128,'RECONCILE_EVIDENCE_BOUND');
    const path=join(base,rel),s=fs.lstatSync(path);
    need(!s.isSymbolicLink() && s.uid===process.getuid(),'RECONCILE_EVIDENCE_OWNER');
    if(s.isDirectory()) {
      need((s.mode&0o777)===0o700,'RECONCILE_EVIDENCE_MODE');
      const listing=names(path); entries.push({path:rel,directory:true,identity:[s.dev,s.ino,s.uid,s.mode],names:listing});
      for(const n of listing) walk(rel?rel+'/'+n:n);
    } else {
      need(s.isFile() && s.nlink===1 && (s.mode&0o777)===0o600,'RECONCILE_EVIDENCE_FILE');
      bytes+=s.size;need(bytes<=1024**3,'RECONCILE_EVIDENCE_BOUND');
      const opaque=/^(restore-existing-v6\/)?(fenced|before-api|after-api)\/(core|llm)\/(auth|ledger)\.sqlite$/.test(rel);
      need(opaque || rel.endsWith('.json'),'RECONCILE_EVIDENCE_TYPE');
      entries.push({path:rel,directory:false,identity:stamp(s),digest:opaque?null:hash(privateFile(path,4*1024**2).bytes)});
    }
  }
  walk();
  const verifyAt=target=>{for(const e of entries){const p=join(target,e.path),s=fs.lstatSync(p);need(!s.isSymbolicLink(),'RECONCILE_EVIDENCE_SYMLINK');if(e.directory)need(equal([s.dev,s.ino,s.uid,s.mode],e.identity)&&equal(names(p),e.names),'RECONCILE_EVIDENCE_DIRECTORY');else {need(equal(stamp(s),e.identity),'RECONCILE_EVIDENCE_CHANGED');if(e.digest!==null)need(hash(privateFile(p,4*1024**2).bytes)===e.digest,'RECONCILE_EVIDENCE_BYTES');}}};
  verifyAt(base); return {digest:hash(entries),verifyAt};
}
function status(path, timeout) {
  return new Promise((resolveStatus,reject)=>{
    const req=http.get({host:'127.0.0.1',port:8081,path,agent:false,headers:{Connection:'close'}},res=>{const code=res.statusCode;res.destroy();resolveStatus(code);});
    const timer=setTimeout(()=>req.destroy(Error('RECONCILE_HTTP_TIMEOUT')),timeout);
    req.on('error',()=>reject(Error('RECONCILE_HTTP')));req.on('close',()=>clearTimeout(timer));
  });
}

export async function prepareRestoredReconciliation({audit,restoreReview,restoreEntry,root=ROOT,run=runIsolatedDocker,request=status,ambient=process.env}={}) {
  need(/^deploy-[a-f0-9]{32}$/.test(audit)&&hex(restoreReview)&&/^scripts\/public-images-v6-restore-[a-z0-9]+\.mjs$/.test(restoreEntry),'RECONCILE_ARGUMENTS');
  need(resolve(root)===root&&fs.realpathSync(root)===root,'RECONCILE_ROOT');
  const end=performance.now()+180000, time=()=>{const left=Math.floor(end-performance.now());need(left>0,'RECONCILE_DEADLINE');return left;};
  const state=join(root,STATE),incident=join(state,'llm-deployments',audit),lock=join(state,'.operation.lock'),restored=join(incident,'restore-existing-v6');
  const guard=join(state,GUARD),archiveParent=join(state,'exact-recovery-compensations'),target=join(archiveParent,'restored-'+audit.slice(7));
  const source=capturePublicLlmSource(root,{openai:true}),self=byteFile(join(root,SELF),false),restoreSource=byteFile(join(root,restoreEntry),false);
  const sourceHash=hash({source:source.digest??source.manifest,entry:self.sha256,restoreEntry:restoreSource.sha256});
  const files=[],read=(p,cap=4*1024**2)=>{const f=privateFile(p,cap);files.push(f);return JSON.parse(f.bytes);};
  const saved=read(join(restored,'authority.json')),receipt=read(join(restored,'restored-existing-v6.json')),marker=read(join(lock,'mutation.json'));
  need(hash(saved)===restoreReview&&saved.audit===audit&&saved.version===1&&hex(saved.source)&&saved.entry===restoreSource.sha256,'RECONCILE_RESTORE_AUTHORITY');
  need(equal(receipt,{version:1,audit,review:restoreReview,source:saved.source,entry:saved.entry,outcome:'restored-old-v6-maintenance-hold',preserved:true,authSchema:'A2',migration:false,publishedProfileUnchanged:true,lockRetained:true,web:200,auth:401}),'RECONCILE_RESTORE_RECEIPT');
  need(equal(marker,{version:1,project:PROJECT,command:'public-openai-worker-egress-upgrade',phase:'fence-web',endpoint:saved.endpoint,authMigration:'auth-a2-to-a3',authMigrationAck:'--ack-auth-a2-to-a3'}),'RECONCILE_MARKER');
  need(/^unix:\/\/\/[^\s\0]+$/.test(saved.endpoint)&&typeof saved.daemon==='string','RECONCILE_ENDPOINT');
  need(equal(names(incident),['history-schema-preflight.json','restore-existing-v6'])&&equal(names(lock),['legacy-stop-egress-submission.json','llm-candidate','mutation.json']),'RECONCILE_PENDING_WORK');
  const expectedNames=['authority.json','restored-existing-v6.json',...['worker','api','web'].map(n=>'ready-'+n+'.json'),...STARTED.flatMap(n=>['start-'+n+'-submission.json','started-'+n+'.json']),...PHASES.flatMap(n=>[n,'verified-'+n+'.json','helper-'+n+'.json',...['submission','start-submission','stop-submission','remove-submission','retired'].map(s=>'helper-'+n+'-'+s+'.json')])].sort();
  need(equal(names(restored),expectedNames),'RECONCILE_RESTORE_INCOMPLETE');
    need(equal(names(join(lock,'llm-candidate')),['compose.cve.json','compose.llm-env.json']),'RECONCILE_STAGE_FILES');
    for(const phase of PHASES){
      need(equal(names(join(restored,phase)),['core','llm']),'RECONCILE_SNAPSHOT_LAYOUT');
      for(const group of ['core','llm'])need(equal(names(join(restored,phase,group)),['auth.sqlite','ledger.sqlite','private-manifest.json']),'RECONCILE_SNAPSHOT_LAYOUT');
    }
  need(equal(saved.peers.map(p=>p.name).sort(),ROLES)&&saved.peers.every(p=>hex(p.id)&&/^sha256:[a-f0-9]{64}$/.test(p.image)&&hex(p.control)),'RECONCILE_PEERS');
  const peers=saved.peers.map(p=>structuredClone(p));
  for(const p of peers) if(STARTED.includes(p.name)) {
    need(equal(read(join(restored,'start-'+p.name+'-submission.json')),{id:p.id,image:p.image,operation:'start-same-id'}),'RECONCILE_START_SUBMISSION');
    const started=read(join(restored,'started-'+p.name+'.json'));need(equal(Object.keys(started).sort(),['epoch','id'])&&started.id===p.id,'RECONCILE_STARTED');p.epoch=started.epoch;
  }
  for(const n of ['worker','api','web'])need(equal(read(join(restored,'ready-'+n+'.json')),n==='web'?{web:200,auth:401}:{ready:true}),'RECONCILE_READY_RECEIPT');
  let baseline;
  for(const phase of PHASES) {
    const v=read(join(restored,'verified-'+phase+'.json'));
    need(v.version===1&&v.authSchema==='A2'&&v.equalB0===true&&v.stores?.historyVersion===4&&v.stores.llm!==null,'RECONCILE_STORE_RECEIPT');
    if(baseline)need(equal(v.stores,baseline),'RECONCILE_HISTORICAL_STORES');baseline=v.stores;
    const h=read(join(restored,'helper-'+phase+'.json'));need(hex(h.id)&&h.image===peers.find(p=>p.name==='api').image,'RECONCILE_HELPER');
    need(equal(read(join(restored,'helper-'+phase+'-retired.json')),{id:h.id,exit:0}),'RECONCILE_HELPER_NOT_RETIRED');
        need(equal(read(join(restored,'helper-'+phase+'-submission.json')),{version:1,name:PROJECT+'-llm-'+restoreReview.slice(0,32)+'-'+phase,image:h.image,purpose:'backup'}),'RECONCILE_HELPER_SUBMISSION');
        for(const step of ['start','stop','remove'])need(equal(read(join(restored,'helper-'+phase+'-'+step+'-submission.json')),{id:h.id}),'RECONCILE_HELPER_SUBMISSION');
  }
  const selection=read(join(state,'llm-profile.json')),rawProfile=read(join(state,'profile.json')),pins=read(join(state,'compose.images.json'));
  need(equal(Object.keys(rawProfile).sort(),['cve','project','version'])&&rawProfile.project===PROJECT&&rawProfile.version===2,'RECONCILE_PROFILE');
  const profile={version:rawProfile.version,cve:publicImageCveConfig(root,rawProfile.cve,rawProfile.version)};
  validateLlmSelection(selection);
  need(equal(read(join(state,'compose.llm-env.json')),publicLlmEnvironmentOverlay(selection)),'RECONCILE_PUBLISHED_ENV');
  need(equal(read(join(state,'compose.cve.json')),read(join(lock,'llm-candidate/compose.cve.json'))),'RECONCILE_PUBLISHED_CVE');
  need(selection.version===6&&!Object.hasOwn(selection,'operations')&&equal(selection,saved.selection)&&equal(profile,saved.profile)&&equal(pins,saved.pins),'RECONCILE_PUBLISHED_DRIFT');
  const jwtPath=join(state,'scan-jwt');need(equal(stamp(fs.lstatSync(jwtPath)),saved.jwtIdentity),'RECONCILE_JWT_IDENTITY');
  // The saved authority binds only known nonsecret records, never arbitrary paths.
  for(const e of saved.originalEvidence) {
    need(typeof e.path==='string'&&!e.path.includes('..')&&/^(?:\.operation\.lock\/(?:mutation\.json|legacy-stop-egress-submission\.json|llm-candidate\/compose\.(?:cve|llm-env)\.json)|compose\.images\.json|llm-deployments(?:-archive)?\/deploy-[a-f0-9]{32}\/(?:complete|history-schema-preflight)\.json|exact-recovery-compensations\/images-v6-[a-f0-9]{32}\/(?:terminalized-v6\.json|incident\/terminalize-restored-v6\/authority\.json))$/.test(e.path),'RECONCILE_EVIDENCE_PATH');
    const f=privateFile(join(state,e.path),4*1024**2);need(equal(f.identity,e.identity)&&hash(f.bytes)===e.digest,'RECONCILE_ORIGINAL_CHANGED');files.push(f);
  }
  const auditSeal=evidenceSeal(incident),lockSeal=evidenceSeal(lock),catalog=captureDeploymentCatalog(root);
  need(catalog.active.includes(audit),'RECONCILE_CATALOG');assertReconciliationHistory(root);
  const dirs=[state,dirname(incident),incident,lock,restored,join(lock,'llm-candidate')].map(directoryIdentity);
  const parentGuard=exists(archiveParent)?directoryIdentity(archiveParent):()=>need(!exists(archiveParent),'RECONCILE_ARCHIVE_PARENT');
  let archival=false;
  const publishedFiles=files.filter(f=>!f.path.startsWith(incident+'/')&&!f.path.startsWith(lock+'/'));
    const stable=()=>{time();source.verify();self.verify();restoreSource.verify();publishedFiles.forEach(f=>f.verify());need(equal(stamp(fs.lstatSync(jwtPath)),saved.jwtIdentity),'RECONCILE_JWT_CHANGED');};
  const fence=()=>{stable();need(!archival,'RECONCILE_ARCHIVAL_STARTED');dirs.forEach(f=>f());files.forEach(f=>f.verify());catalog.verify();parentGuard();auditSeal.verifyAt(incident);lockSeal.verifyAt(lock);need(!exists(target)&&!names(state).some(n=>n.endsWith('.lock')&&n!=='.operation.lock'),'RECONCILE_OTHER_OPERATION');};
  fence();
  const env=dockerEnvironment(ambient);delete env.DOCKER_CONTEXT;delete env.DOCKER_TLS_VERIFY;delete env.DOCKER_CERT_PATH;env.DOCKER_HOST=saved.endpoint;env.COMPOSE_DISABLE_ENV_FILE='1';
  const volumeNames=saved.volumes.map(v=>v.Name),networkNames=saved.networks.map(n=>n.Name);
  need(saved.volumes.length===4&&saved.networks.length===8&&new Set(volumeNames).size===4&&new Set(networkNames).size===8&&networkNames.every(n=>n.startsWith(PROJECT+'_')),'RECONCILE_TOPOLOGY');
  const dispatch=async args=>{fence();let out;try{out=await run(args,{root,env,timeout:Math.min(15000,time())});}catch{throw Error('RECONCILE_DOCKER_'+args.slice(0,args[0]==='info'?1:2).join('_').toUpperCase());}fence();return out;};
  const inspect=async(kind,refs,field)=>{
      if(kind==='container'||kind==='image')return decodeInspect(await dispatch([kind,'inspect',...refs,'--format',SAFE_INSPECT]),refs,field);
      // Volume/network inspect contain topology metadata, not process Env. Their
      // CLI formatters use typed structs instead of the inspect map above.
      const rows=JSON.parse(await dispatch([kind,'inspect',...refs]));
      need(Array.isArray(rows)&&rows.length===refs.length&&equal(rows.map(v=>v[field]).sort(),[...refs].sort()),'RECONCILE_IDENTITIES');return rows;
    };
  const inventory=async kind=>{
    const fmt=kind==='container'?'{{.ID}}':'{{.Name}}',base=[kind,'ls',...(kind==='container'?['--all','--no-trunc']:[]),'--format',fmt];
    const a=await dispatch([...base,'--filter','name='+(kind==='container'?'^/':'^')+PROJECT+(kind==='container'?'-':'_')]);
    const b=await dispatch([...base,'--filter','label=com.docker.compose.project='+PROJECT]);
    return [...new Set([...lines(a),...lines(b)])].sort();
  };
  const verify=async()=>{
    need(JSON.parse(await dispatch(['info','--format','{{json .ID}}']))===saved.daemon,'RECONCILE_DAEMON');
    // Enumerate only this namespace before inspecting exact receipt-owned IDs.
    need(equal(await inventory('container'),peers.map(p=>p.id).sort()),'RECONCILE_FOREIGN_CONTAINER');
    need(equal(await inventory('network'),[...networkNames].sort()),'RECONCILE_FOREIGN_NETWORK');
    need(equal(await inventory('volume'),volumeNames.filter(n=>n.startsWith(PROJECT+'_')).sort()),'RECONCILE_FOREIGN_VOLUME');
    const containers=await inspect('container',peers.map(p=>p.id),'Id');
    for(const p of peers) validateRestoredPeer(containers.find(c=>c.Id===p.id),p);
    const images=await inspect('image',[...new Set(peers.map(p=>p.image))],'Id');
    for(const p of peers)validatePublicLlmImage(images.find(i=>i.Id===p.image),p.name);
    const volumes=await inspect('volume',volumeNames,'Name');
    need(equal([...volumes].sort((a,b)=>a.Name.localeCompare(b.Name)),[...saved.volumes].sort((a,b)=>a.Name.localeCompare(b.Name))),'RECONCILE_VOLUME_DRIFT');
    const networks=await inspect('network',networkNames,'Name');
    for(const n of networks) {
      const old=saved.networks.find(x=>x.Name===n.Name);
      need(equal({...n,Containers:{}},{...old,Containers:{}}),'RECONCILE_NETWORK_DRIFT');
      need(equal(Object.keys(n.Containers??{}).sort(),containers.filter(c=>c.State.Running&&Object.hasOwn(c.NetworkSettings.Networks,n.Name)).map(c=>c.Id).sort()),'RECONCILE_NETWORK_USERS');
    }
    for(const v of volumeNames) {
      const users=lines(await dispatch(['container','ls','--all','--no-trunc','--filter','volume='+v,'--format','{{.ID}}']));
      need(equal(users,containers.filter(c=>c.Mounts.some(m=>m.Type==='volume'&&m.Name===v)).map(c=>c.Id).sort()),'RECONCILE_VOLUME_USERS');
    }
    for(const [path,code] of [['/',200],['/api/v1/auth/me',401]])need(await request(path,Math.min(5000,time()))===code,'RECONCILE_HTTP_STATUS');
    fence();
  };
  await verify();
  const authority={version:1,kind:'restored-v6-archive-only',audit,restoreReview,source:sourceHash,entry:self.sha256,evidence:{incident:auditSeal.digest,lock:lockSeal.digest},peers,daemon:saved.daemon,selection,pins,jwtIdentity:saved.jwtIdentity};
  const review=hash(authority);
  const summary={outcome:'ARCHIVE_ONLY_QUALIFIED_NOT_APPLIED',audit,review,source:sourceHash,entry:self.sha256,restoreReview,services:8,networks:8,volumes:4,api:'healthy',web:200,auth:401,lockRetained:true,lifecycle:false,liveStoresRead:false,historicalEqualityClaimed:false};
  return {summary,async apply(binding){
    need(equal(binding,{review,source:sourceHash}),'RECONCILE_REVIEW_BINDING');await verify();fence();
    // A recognized second lock exists before either original tree moves. All
    // failures after this point leave HOLD; there is no automatic resume path.
    fs.mkdirSync(guard,{mode:0o700});writeExclusive(join(guard,'intent.json'),JSON.stringify(authority),0o600);syncDirectory(guard);syncDirectory(state);
    const guardSeal=evidenceSeal(guard);archival=true;
    stable();auditSeal.verifyAt(incident);lockSeal.verifyAt(lock);parentGuard();
    if(!exists(archiveParent)){fs.mkdirSync(archiveParent,{mode:0o700});syncDirectory(state);}
    need(fs.lstatSync(archiveParent).dev===fs.lstatSync(incident).dev&&!exists(target),'RECONCILE_ARCHIVE_DEVICE');
    fs.mkdirSync(target,{mode:0o700});syncDirectory(archiveParent);
    fs.renameSync(incident,join(target,'incident'));syncDirectory(dirname(incident));syncDirectory(target);
    auditSeal.verifyAt(join(target,'incident'));lockSeal.verifyAt(lock);stable();validateCurrentAuditHistory(root);assertReconciliationHistory(root);
    const result={...summary,outcome:'RESTORED_INCIDENT_ARCHIVED',archive:'exact-recovery-compensations/restored-'+audit.slice(7),lockRetained:false,publishedProfileUnchanged:true,migration:false,storePreservation:'prior-restore-receipts; no fresh comparison',evidence:authority.evidence};
    writeExclusive(join(target,'archived-restored.json'),JSON.stringify(result),0o600);syncDirectory(target);
    const resultFile=privateFile(join(target,'archived-restored.json'),65536);
    guardSeal.verifyAt(guard);auditSeal.verifyAt(join(target,'incident'));lockSeal.verifyAt(lock);stable();
    fs.renameSync(lock,join(target,'operation.lock'));syncDirectory(target);syncDirectory(state);
    lockSeal.verifyAt(join(target,'operation.lock'));auditSeal.verifyAt(join(target,'incident'));resultFile.verify();guardSeal.verifyAt(guard);stable();validateCurrentAuditHistory(root);assertReconciliationHistory(root);
    fs.renameSync(guard,join(target,'archive-operation.lock'));syncDirectory(target);syncDirectory(state);
    return result;
  }};
}

export async function reconciliationCli(argv) {
  const [command,...a]=argv;need(['check','apply'].includes(command),'RECONCILE_ARGUMENTS');
  need(a[0]==='--audit'&&a[2]==='--restore-review'&&a[4]==='--restore-entry'&&(command==='check'?a.length===6:a.length===11&&a[6]==='--review'&&a[8]==='--source'&&a[10]==='--ack-archive-only'),'RECONCILE_ARGUMENTS');
  const prepared=await prepareRestoredReconciliation({audit:a[1],restoreReview:a[3],restoreEntry:a[5]});
  return command==='check'?prepared.summary:prepared.apply({review:a[7],source:a[9]});
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))reconciliationCli(process.argv.slice(2)).then(v=>console.log(JSON.stringify(v))).catch(e=>{console.error(JSON.stringify({outcome:'RECONCILE_REFUSED_OR_HOLD',code:/^RECONCILE_[A-Z_]+$/.test(e.message)?e.message:'RECONCILE_VALIDATION',noRetry:true}));process.exitCode=1;});
