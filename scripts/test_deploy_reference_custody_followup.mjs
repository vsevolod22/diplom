import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { boundedDeploymentRecord, deploymentRecordLimit, precheckRecoveryRecordCapacity, candidateSourceEquivalence,
  RECOVERY_AUTHORITY_RECORD_LIMIT, DEPLOY_RECORD_LIMIT, RECOVERY_FUTURE_RECORD_RESERVE,
  createReferenceCustody, custodyCompletionReferences, completionReferences, retainedReferenceHistory } from './deploy-reference-custody.mjs';
const sha=v=>createHash('sha256').update(v).digest('hex'),image=v=>'sha256:'+sha(v),nonce='a'.repeat(32),next='b'.repeat(32);
const files=[{path:'server/api/src/main.ts',digest:sha('api')},{path:'src/main.tsx',digest:sha('web')},{path:'scripts/public-llm-stand.mjs',digest:sha('operations')}];
const source=sha(JSON.stringify(files));
function equivalence(extra={}) { return candidateSourceEquivalence({originalSource:source,files,originalAdapter:sha('old adapter'),originalEntrySources:Array(7).fill(sha('old entry')),currentAdapter:sha('new adapter'),currentEntrySources:Array(7).fill(sha('new entry')),...extra}); }
for(const name of ['authority-v3.json','history-v5-prestart.json'])test(name+' exact-name bounded large writer/read contract preserves every field',()=>{
  const value={version:3,files:{history:Array.from({length:1600},(_,i)=>({path:'retained/'+i+'/private-metadata.json',stamp:[1,2,3,4,5,6,7,8],unchanged:'x'.repeat(100)}))},authority:{containers:[{allControlFields:true}]}};
  const bytes=boundedDeploymentRecord(name,value);assert.ok(Buffer.byteLength(bytes)>DEPLOY_RECORD_LIMIT);assert.ok(Buffer.byteLength(bytes)<RECOVERY_AUTHORITY_RECORD_LIMIT);
  assert.deepEqual(JSON.parse(bytes),value);assert.equal(deploymentRecordLimit(name),8*1024**2);
  assert.throws(()=>boundedDeploymentRecord(name,{data:'x'.repeat(RECOVERY_AUTHORITY_RECORD_LIMIT)}),/JOURNAL_SIZE/);
});
for(const name of ['complete.json','intent.json','built.json','recovery.json','prefix-authority-v3.json','authority-v3.json.extra','recovery-v5/authority-v3.json'])test(name+' ordinary record limit is NOT raised',()=>{
  assert.equal(deploymentRecordLimit(name),262144);assert.throws(()=>boundedDeploymentRecord(name,{data:'x'.repeat(262144)}),/JOURNAL_SIZE/);
});
test('full authority/checkpoint prebuild preview includes bounded future receipts and rejects before writes',()=>{
  const value={files:{history:Array.from({length:1600},(_,i)=>({path:'retained/'+i,stamp:Array(8).fill(9007199254740991)}))},authority:{containers:[]}};
  const result=precheckRecoveryRecordCapacity(value,{...value,before:null,after:null,proof:null,evidence:[]});
  assert.ok(result.authorityBytes>262144);assert.equal(result.futureBytes,RECOVERY_FUTURE_RECORD_RESERVE);
  assert.throws(()=>precheckRecoveryRecordCapacity(value,{data:'x'.repeat(RECOVERY_AUTHORITY_RECORD_LIMIT-RECOVERY_FUTURE_RECORD_RESERVE)}),/RECOVERY_RECORD_CAPACITY/);
});
test('record byte limits are inclusive and shared at exact ±1 boundaries',()=>{
  for(const name of ['complete.json','authority-v3.json','history-v5-prestart.json']){
    const limit=deploymentRecordLimit(name),value={data:'x'.repeat(limit-11)};
    assert.equal(Buffer.byteLength(boundedDeploymentRecord(name,value)),limit);
    assert.throws(()=>boundedDeploymentRecord(name,{data:value.data+'x'}),/JOURNAL_SIZE/);
  }
});
test('checkpoint prebuild reserve has an exact inclusive byte boundary',()=>{
  const limit=RECOVERY_AUTHORITY_RECORD_LIMIT-RECOVERY_FUTURE_RECORD_RESERVE,value={data:'x'.repeat(limit-11)};
  assert.equal(precheckRecoveryRecordCapacity({},value).checkpointBytes,limit);
  assert.throws(()=>precheckRecoveryRecordCapacity({},{data:value.data+'x'}),/RECOVERY_RECORD_CAPACITY/);
});
test('source proof distinguishes historical orchestration from exact requalified shipped source',()=>{
  const proof=equivalence();assert.equal(proof.originalSource,proof.currentSource);assert.notEqual(proof.originalAdapter,proof.currentAdapter);
  assert.notDeepEqual(proof.originalEntrySources,proof.currentEntrySources);assert.equal(proof.shippedFiles.length,2);
  assert.ok(!proof.shippedFiles.some(r=>r.path.startsWith('scripts/')));assert.equal(proof.shippedSource,sha(JSON.stringify(proof.shippedFiles)));
});
for(const fault of ['api','web','lockfile','new-file','removed-file','order','forged-digest'])test('candidate source proof fails closed: '+fault,()=>{
  const changed=structuredClone(files);
  if(fault==='api')changed[0].digest=sha('changed');if(fault==='web')changed[1].digest=sha('changed');
  if(fault==='lockfile')changed.push({path:'pnpm-lock.yaml',digest:sha('changed')});if(fault==='new-file')changed.push({path:'src/new.ts',digest:sha('changed')});
  if(fault==='removed-file')changed.pop();if(fault==='order')changed.reverse();
  assert.throws(()=>equivalence({files:changed,...(fault==='forged-digest'?{originalSource:sha('self-asserted')}: {})}),/CANDIDATE_SOURCE_EQUIVALENCE_UNPROVEN/);
});
function originRecord() { return {version:2,nonce,references:['api','web'].flatMap(name=>[{name,image:image('old '+name),tag:`dip-deploy-${name}:old-${nonce}`},{name,image:image(name),tag:`dip-deploy-${name}:candidate-${nonce}`}])}; }
function borrowedCandidate() {
  const record=originRecord(),origin={nonce,sha256:sha(JSON.stringify(record)),record},references=retainedReferenceHistory({completions:[origin]});
  const candidateReferences=references.filter(r=>r.tag.includes(':candidate-'));
  const custody=createReferenceCustody({nonce:next,targets:['api','web'],published:{api:image('old api'),web:image('old web')},runtime:{api:image('old api'),web:image('old web')},references,candidateReferences});
  const candidates=Object.fromEntries(custody.old.map(r=>[r.name,{oldTag:r.tag,oldImage:r.image,tag:candidateReferences.find(c=>c.name===r.name).tag,image:image(r.name)}]));
  return {origin,references,custody,candidates};
}
test('new custody2/completion4 borrows original old+candidate tags with zero newly owned names',()=>{
  const {origin,custody,candidates}=borrowedCandidate();assert.equal(custody.version,2);
  const record={version:4,nonce:next,referenceCustody:custody,...custodyCompletionReferences(custody,next,candidates)};
  assert.equal(record.references.length,0);assert.equal(record.borrowedReferences.length,4);assert.equal(completionReferences(record,next).borrowed.length,4);
  const history=retainedReferenceHistory({completions:[origin,{nonce:next,sha256:sha('borrower'),record}]});assert.equal(history.length,4);
  assert.ok(history.every(r=>r.origin.nonce===nonce),'borrower does not become original authority');
});
for(const fault of ['origin','image','role','own-nonce','not-candidate','extra-field','wrong-completion-version','borrow-chain'])test('borrowed candidate custody refuses '+fault,()=>{
  const {origin,custody,candidates}=borrowedCandidate(),row=custody.candidates[0];
  if(fault==='origin')row.origin.sha256=sha('forged');if(fault==='image')row.image=image('wrong');if(fault==='role')row.name='worker';
  if(fault==='own-nonce')row.origin.nonce=next;if(fault==='not-candidate')row.tag=`dip-deploy-api:old-${nonce}`;if(fault==='extra-field')row.extra=true;
  if(fault==='borrow-chain')row.origin={kind:'adapter-completion',nonce:'c'.repeat(32),sha256:sha('borrower')};
  assert.throws(()=>{
    const record={version:fault==='wrong-completion-version'?3:4,nonce:next,referenceCustody:custody,...custodyCompletionReferences(custody,next,candidates)};
    retainedReferenceHistory({completions:[origin,{nonce:next,sha256:sha('new'),record}]});
  });
});
