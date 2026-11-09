import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { PROJECT, STATE, historicalIdentityMatches, assertReconciliationHistory, acquireLock } from './public-image-stand.mjs';
const hash = value => createHash('sha256').update(value).digest('hex');
const fileId = path => { const s=fs.lstatSync(path); return {dev:s.dev,ino:s.ino}; };
const dirId = path => {const s=fs.lstatSync(path); return {...fileId(path),uid:s.uid,mode:s.mode};};
function fixture(t) {
  const root=fs.realpathSync(fs.mkdtempSync(join(tmpdir(),'deployment-remount-')));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const state=join(root,STATE); fs.mkdirSync(state,{mode:0o700});
  const archive=join(state,'reconciliations','build-only-'+'a'.repeat(32));fs.mkdirSync(archive,{recursive:true,mode:0o700});
  const original=join(archive,'original-operation.lock'),guard=join(archive,'reconciliation-operation.lock');
  fs.mkdirSync(original,{mode:0o700});fs.mkdirSync(guard,{mode:0o700});
  const save=(path,value)=>fs.writeFileSync(path,JSON.stringify(value),{mode:0o600});
  const marker=join(original,'mutation.json'),mutation={version:1,project:PROJECT,command:'up',phase:'build-pull-start-outcome-unconfirmed'};save(marker,mutation);
  // Simulate a prior mount number in the immutable completed receipt. The real
  // files retain their actual current dev/inode and are never mocked/rebound.
  const old = value => ({...value,dev:value.dev+1});
  const ack={version:1,project:PROJECT,operation:'NOT_EXECUTED_SERVICES',acknowledgement:'--ack-no-services',originalOutcome:'HOLD_PRESERVED',
    originalMutationSha256:hash(JSON.stringify(mutation)),profileSha256:'b'.repeat(64),sourceSha256:'c'.repeat(64),
    originalLockIdentity:old(dirId(original)),originalMarkerIdentity:old(fileId(marker)),cve:null,
    images:Object.fromEntries(['egress','worker','api','web'].map(name=>[name,'sha256:'+'d'.repeat(64)])),imageContainerReferences:0,
    endpoint:'unix:///synthetic-docker.sock',endpointProvenance:'operator-acknowledged-legacy-marker',namespace:{containers:0,volumes:0,networks:0},jwtPreserved:true,at:'2026-11-09T00:00:00.000Z'};
  save(join(archive,'acknowledgement.json'),ack);
  save(join(guard,'intent.json'),{version:1,project:PROJECT,command:'reconcile-build-only',archive:archive.split('/').at(-1),originalMutationSha256:ack.originalMutationSha256});
  save(join(archive,'completion.json'),{version:1,project:PROJECT,operation:ack.operation,archive:archive.split('/').at(-1),originalMutationSha256:ack.originalMutationSha256,acknowledgementSha256:hash(JSON.stringify(ack))});
  return {root,state,archive,marker,original,ack};
}
test('completed historical receipt survives only mount-number changes',()=>{
  const current={dev:2,ino:10,uid:501,mode:16832};
  assert.equal(historicalIdentityMatches({...current,dev:1},current,2),true);
  assert.equal(historicalIdentityMatches(current,current,2),true);
  for(const change of [{ino:11},{uid:502},{mode:16877},{extra:true},{dev:3}])
    assert.equal(historicalIdentityMatches({...current,dev:1},{...current,...change},2),false);
  for(const bad of [null,{}, {dev:NaN,ino:10}, {dev:1,ino:-1}, {dev:1,ino:10,extra:true}])
    assert.equal(historicalIdentityMatches(bad,{dev:2,ino:10},2),false);
});
test('actual completed reconciliation history accepts remount without rewriting receipts', t=>{
  const f=fixture(t),path=join(f.archive,'acknowledgement.json'),before=fs.readFileSync(path);
  assertReconciliationHistory(f.root);assert.deepEqual(fs.readFileSync(path),before);
  const lock=acquireLock(f.root);lock.verify();lock.release();
  assert.equal(fs.existsSync(join(f.state,'.operation.lock')),false);
});
test('historical remount does not permit replacement of a marker with identical bytes',t=>{
  const f=fixture(t),bytes=fs.readFileSync(f.marker);fs.renameSync(f.marker,join(f.root,'original-marker'));
  fs.writeFileSync(f.marker,bytes,{mode:0o600});assert.throws(()=>assertReconciliationHistory(f.root));
});
test('historical remount does not permit a changed marker hash or incomplete completion',t=>{
  const f=fixture(t);fs.writeFileSync(f.marker,'{}');assert.throws(()=>assertReconciliationHistory(f.root));
  fs.unlinkSync(join(f.archive,'completion.json'));assert.throws(()=>assertReconciliationHistory(f.root));
});
test('active operation lock still rejects a replaced directory',t=>{
  const f=fixture(t),lock=acquireLock(f.root);fs.renameSync(lock.path,join(f.root,'owned-original-lock'));
  fs.mkdirSync(lock.path,{mode:0o700});assert.throws(lock.verify);assert.throws(lock.release);
});
