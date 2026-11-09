import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { completionReferences, retainedReferenceHistory, referenceUnion, createReferenceCustody,
  validateReferenceCustody, custodyCompletionReferences, parseImageInventory, assertImageCapacity,
  IMAGE_REFERENCE_LIMIT, UNTAGGED_IMAGE_LIMIT, IMAGE_INVENTORY_ROW_LIMIT } from './deploy-reference-custody.mjs';
const sha = s=>createHash('sha256').update(s).digest('hex');
const image = s=>'sha256:'+sha(s);
const nonce = 'a'.repeat(32), next = 'b'.repeat(32), third = 'c'.repeat(32);
const oldRecord = {version:2,nonce,references:['api','web'].map(name=>({name,tag:`dip-deploy-${name}:candidate-${nonce}`,image:image(name)}))};
const original = {nonce,sha256:sha(JSON.stringify(oldRecord)),record:oldRecord};
const history = ()=>retainedReferenceHistory({completions:[original]});
function build(custody) { return Object.fromEntries(custody.old.map(r=>[r.name,{image:image('new-'+r.name),tag:custody.candidates.find(v=>v.name===r.name).tag,oldTag:r.tag,oldImage:r.image}])); }
function prospective(refs=history(),n=next) { return createReferenceCustody({nonce:n,targets:['api','web'],published:{api:image('api'),web:image('web')},runtime:{api:image('api'),web:image('web')},references:refs}); }
function completed(custody=prospective(),n=next) { return {version:3,nonce:n,referenceCustody:custody,...custodyCompletionReferences(custody,n,build(custody))}; }
const inventory = count=>Array.from({length:count},(_,i)=>`fixture/image:${i}\t${image('inventory-'+i)}`).join('\n');
test('legacy v2 own-nonce references remain unchanged; foreign old tag still rejected',()=>{
  const bytes=JSON.stringify(oldRecord);assert.deepEqual(completionReferences(oldRecord,nonce),{owned:oldRecord.references,borrowed:[]});
  history();assert.equal(JSON.stringify(oldRecord),bytes);
  assert.throws(()=>completionReferences({...oldRecord,references:[{...oldRecord.references[0],tag:`dip-deploy-api:old-${next}`}]},nonce),/OWNED_REFERENCE_INVALID/);
});
test('two verified same-role old images borrow direct original custody; only two newly owned tags',()=>{
  const custody=prospective(),record=completed(custody);assert.ok(custody.old.every(r=>r.ownership==='borrowed'));
  assert.equal(record.references.length,2);assert.equal(record.borrowedReferences.length,2);
  const refs=retainedReferenceHistory({completions:[original,{nonce:next,sha256:sha('next'),record}]});
  assert.equal(refs.length,4);assert.deepEqual(refs.filter(r=>oldRecord.references.some(v=>v.tag===r.tag)),history());
});
test('missing verified same-role custody falls back to a newly owned old alias',()=>{
  const custody=prospective(history().filter(r=>r.name==='api')),record=completed(custody);
  assert.equal(custody.old.find(r=>r.name==='web').ownership,'owned');assert.equal(record.references.length,3);assert.equal(record.borrowedReferences.length,1);
  assert.equal(prospective([]).old.filter(r=>r.ownership==='owned').length,2);
});
test('same image used under another role does not authorize borrowing',()=>{
  const refs=history().filter(r=>r.name==='web').map(r=>({...r,image:image('api')}));
  assert.equal(prospective(refs).old.find(r=>r.name==='api').ownership,'owned');
});
for (const field of ['published','runtime']) test('old '+field+' image mismatch fails before custody selection',()=>{
  const args={nonce:next,targets:['api'],published:{api:image('api')},runtime:{api:image('api')},references:history()};args[field].api=image('wrong');
  assert.throws(()=>createReferenceCustody(args),/CUSTODY_OLD_IMAGE_MISMATCH/);
});
for (const fault of ['origin-digest','origin-nonce','missing-origin','role','image','tag','borrow-chain','self','duplicate','extra']) test('forged borrowed provenance rejected: '+fault,()=>{
  const record=completed(),r=record.borrowedReferences[0];
  if(fault==='origin-digest')r.origin.sha256=sha('forged');
  if(fault==='origin-nonce')r.origin.nonce=third;
  if(fault==='missing-origin')delete r.origin;
  if(fault==='role')r.name='worker';
  if(fault==='image')r.image=image('forged');
  if(fault==='tag')r.tag=`dip-deploy-api:old-${third}`;
  if(fault==='borrow-chain')r.origin={kind:'adapter-completion',nonce:next,sha256:sha('next')};
  if(fault==='self')r.origin={kind:'adapter-completion',nonce:next,sha256:sha('self')};
  if(fault==='duplicate')record.borrowedReferences.push(structuredClone(r));
  if(fault==='extra')r.origin.arbitrary='not authority';
  assert.throws(()=>retainedReferenceHistory({completions:[original,{nonce:next,sha256:sha('next'),record}]}));
});
test('missing original owner completion never becomes a valid borrow grant',()=>{
  assert.throws(()=>retainedReferenceHistory({completions:[{nonce:next,sha256:sha('next'),record:completed()}]}),/BORROWED_ORIGIN_MISMATCH/);
});
test('legacy retention provenance participates without changing its owning receipt',()=>{
  const legacy=[{name:'api',tag:'retained-api:old-fixture',image:image('api'),origin:{kind:'llm-retention',audit:'deploy-'+nonce,sha256:sha('receipt')}}];
  const record=completed(prospective(legacy));
  assert.equal(record.borrowedReferences.length,1);
  assert.equal(retainedReferenceHistory({legacy,completions:[{nonce:next,sha256:sha('next'),record}]}).length,4);
  assert.throws(()=>retainedReferenceHistory({legacy:[{...legacy[0],origin:{...legacy[0].origin,sha256:sha('changed')}}],completions:[{nonce:next,sha256:sha('next'),record}]}),/BORROWED_ORIGIN_MISMATCH/);
});
test('same tag consistent uses deduplicate, same image distinct tags do not',()=>{
  const r=history()[0];assert.equal(referenceUnion([r,structuredClone(r)]).length,1);
  assert.equal(referenceUnion([r,{...r,tag:'fixture-api:other'}]).length,2);
  for(const bad of [{...r,image:image('different')},{...r,name:'worker'}])assert.throws(()=>referenceUnion([r,bad]),/REFERENCE_CONFLICT/);
  assert.throws(()=>retainedReferenceHistory({completions:[original,original]}),/OWNED_REFERENCE_DUPLICATE/);
});
for(const count of [252,253,254,255,256])test('concrete boundary '+count+' plus two candidate names at bounded256',()=>{
  const observed=parseImageInventory(inventory(count)+'\n<none>:<none>\t'+image('dangling'));
  assert.equal(observed.concrete.size,count);assert.equal(observed.untagged.size,1);
  const action=()=>assertImageCapacity(observed,[],['dip-deploy-api:candidate-'+next,'dip-deploy-web:candidate-'+next]);
  if(count<=254)assert.equal(action(),true);else assert.throws(action,/IMAGE_REFERENCE_CAPACITY/);
});
test('former128 boundary retains every reference with room for two candidate names',()=>{
  const references=Array.from({length:128},(_,i)=>({name:'web',tag:`fixture/image:${i}`,image:image('inventory-'+i)}));
  const before=structuredClone(references),observed=parseImageInventory(inventory(128));
  assert.equal(referenceUnion(references).length,128);
  assert.equal(assertImageCapacity(observed,references,['dip-deploy-api:candidate-'+next,'dip-deploy-web:candidate-'+next]),true);
  assert.deepEqual(references,before);
});
test('untagged cap is independent, finite and enforced before deduplication hides rows',()=>{
  assert.equal(IMAGE_REFERENCE_LIMIT,256);assert.equal(UNTAGGED_IMAGE_LIMIT,16);assert.equal(IMAGE_INVENTORY_ROW_LIMIT,272);
  const rows=Array.from({length:UNTAGGED_IMAGE_LIMIT},(_,i)=>'<none>:<none>\t'+image('dangling-'+i));
  assert.equal(parseImageInventory(inventory(256)+'\n'+rows.join('\n')).untagged.size,16);
  assert.throws(()=>parseImageInventory([...rows,'<none>:<none>\t'+image('extra')].join('\n')),/UNTAGGED_IMAGE_CAPACITY/);
  assert.throws(()=>parseImageInventory(Array(IMAGE_INVENTORY_ROW_LIMIT+1).fill(rows[0]).join('\n')),/IMAGE_INVENTORY_ROWS/);
  assert.equal(parseImageInventory(Array(IMAGE_INVENTORY_ROW_LIMIT).fill(rows[0]).join('\n')).untagged.size,1);
});
for(const row of ['<none>:tag\t'+image('x'),'fixture/image:<none>\t'+image('x'),'fixture/image:tag','fixture/image:tag\tbad','\nfixture/image:tag\t'+image('x'),'fixture/image:tag\t'+image('x')+'\textra','fixture/image:tag\t'+image('x')+'\t','fixture/image:tag\t'+image('x')+' ','fixture/image:tag\t'+image('x')+'\n\n'])test('malformed inventory is not silently filtered: '+JSON.stringify(row),()=>assert.throws(()=>parseImageInventory(row),/IMAGE_INVENTORY_INVALID/));
test('census binds required tag to exact image; canonical aliases count separately',()=>{
  const r=history()[0],text=`${r.tag}\t${r.image}\nfixture-api:local\t${r.image}`;
  assert.equal(parseImageInventory(text+'\n'+text).concrete.size,2);
  assert.equal(assertImageCapacity(parseImageInventory(text),[r]),true);
  assert.throws(()=>assertImageCapacity(parseImageInventory(inventory(2)),[r]),/IMAGE_REFERENCE_CAPACITY_OR_LOSS/);
  assert.throws(()=>parseImageInventory(text+`\n${r.tag}\t${image('other')}`),/IMAGE_INVENTORY_CONFLICT/);
  assert.throws(()=>assertImageCapacity(parseImageInventory(text),[r],[r.tag]),/IMAGE_TAG_ALREADY_PRESENT/);
});
for(const fault of ['candidate-tag','old-image','old-tag','missing-role'])test('build custody mismatch fails: '+fault,()=>{
  const custody=prospective(),candidates=build(custody);
  if(fault==='candidate-tag')candidates.api.tag='fixture:wrong';
  if(fault==='old-image')candidates.api.oldImage=image('wrong');
  if(fault==='old-tag')candidates.api.oldTag='fixture:wrong';
  if(fault==='missing-role')delete candidates.api;
  assert.throws(()=>custodyCompletionReferences(custody,next,candidates));
});
test('recovery validation binds same original references, not a caller assertion',()=>{
  const custody=prospective();assert.deepEqual(validateReferenceCustody(custody,next,history()),custody);
  assert.throws(()=>validateReferenceCustody(custody,next,[]),/BORROWED_ORIGIN_MISMATCH/);
  const changed=structuredClone(custody);changed.old[0].origin.sha256=sha('changed');
  assert.throws(()=>validateReferenceCustody(changed,next,history()),/BORROWED_ORIGIN_MISMATCH/);
});
