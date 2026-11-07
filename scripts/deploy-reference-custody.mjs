// Pure custody contracts. Callers must independently authenticate receipt bytes,
// their original owner/evidence and fresh engine metadata before using these values.
import { isDeepStrictEqual as equal } from 'node:util';
import { createHash } from 'node:crypto';

export const REFERENCE_CUSTODY_VERSION = 1;
export const REFERENCE_COMPLETION_VERSION = 3;
export const CANDIDATE_CUSTODY_VERSION = 2;
export const CANDIDATE_COMPLETION_VERSION = 4;
export const DEPLOY_RECORD_LIMIT = 262144;
export const RECOVERY_AUTHORITY_RECORD_LIMIT = 8 * 1024 ** 2;
// Existing store/proof/evidence records are individually bounded at256KiB.
// Reserve four such records plus process/engine envelope growth before build.
export const RECOVERY_FUTURE_RECORD_RESERVE = 4 * DEPLOY_RECORD_LIMIT + 65536;
export function deploymentRecordLimit(name) {
  return ['authority-v3.json','history-v5-prestart.json'].includes(name) ? RECOVERY_AUTHORITY_RECORD_LIMIT : DEPLOY_RECORD_LIMIT;
}
export function boundedDeploymentRecord(name,value) {
  const bytes=JSON.stringify(value);need(typeof bytes==='string'&&Buffer.byteLength(bytes)<=deploymentRecordLimit(name),'JOURNAL_SIZE');return bytes;
}
export function precheckRecoveryRecordCapacity(authority,checkpoint) {
  const a=Buffer.byteLength(boundedDeploymentRecord('authority-v3.json',authority));
  const c=Buffer.byteLength(boundedDeploymentRecord('history-v5-prestart.json',checkpoint));
  need(c+RECOVERY_FUTURE_RECORD_RESERVE<=RECOVERY_AUTHORITY_RECORD_LIMIT,'RECOVERY_RECORD_CAPACITY');
  return {version:1,authorityBytes:a,checkpointBytes:c,futureBytes:RECOVERY_FUTURE_RECORD_RESERVE,limit:RECOVERY_AUTHORITY_RECORD_LIMIT};
}
export const IMAGE_REFERENCE_LIMIT = 128;
export const UNTAGGED_IMAGE_LIMIT = 16;
export const IMAGE_INVENTORY_ROW_LIMIT = IMAGE_REFERENCE_LIMIT + UNTAGGED_IMAGE_LIMIT;
export const ADAPTER_HISTORY_LIMIT = 48;
export function assertAdapterHistoryCapacity(count,{reserve=0}={}) {
  need(Number.isSafeInteger(count) && count >= 0 && (reserve === 0 || reserve === 1) &&
    count + reserve <= ADAPTER_HISTORY_LIMIT,'ADAPTER_HISTORY_CAPACITY');
}
const ROLES = ['api','worker','web','egress','llm-egress','openai-egress'];
const plain = v => v !== null && typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype;
const keys = (v, expected) => plain(v) && equal(Object.keys(v).sort(), [...expected].sort());
const nonceValid = v => typeof v === 'string' && /^[a-f0-9]{32}$/.test(v);
const shaValid = v => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const imageValid = v => typeof v === 'string' && /^sha256:[a-f0-9]{64}$/.test(v);
const tagValid = v => typeof v === 'string' && /^[a-z0-9][a-z0-9./:_-]{0,254}:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(v) && !v.includes('<none>');
const failures = new WeakMap();
export function referenceCustodyDiagnostic(error) { return failures.get(error); }
function need(ok, code) { if (!ok) { const error=new Error(code); failures.set(error,code); throw error; } }
function refValid(r) { return plain(r) && ROLES.includes(r.name) && tagValid(r.tag) && imageValid(r.image); }
const base = r => ({ name:r.name, tag:r.tag, image:r.image });
function originValid(o) {
  return keys(o,['kind',o?.kind === 'adapter-completion' ? 'nonce' : 'audit','sha256']) && shaValid(o.sha256) &&
    (o.kind === 'adapter-completion' ? nonceValid(o.nonce) : o.kind === 'llm-retention' && /^deploy-[a-f0-9]{32}$/.test(o.audit));
}
function ownTag(name, kind, nonce) { return `dip-deploy-${name}:${kind}-${nonce}`; }

// Equal uses of one concrete name may be shared, but never conflicting bindings.
// Different names for the same image are distinct obligations.
export function referenceUnion(references) {
  need(Array.isArray(references) && references.length <= IMAGE_REFERENCE_LIMIT * 3, 'REFERENCE_SCOPE');
  const result = new Map();
  for (const r of references) {
    need(refValid(r),'REFERENCE_INVALID');
    const prior = result.get(r.tag);
    need(!prior || prior.name === r.name && prior.image === r.image &&
      (!prior.config || !r.config || equal(prior.config,r.config)), 'REFERENCE_CONFLICT');
    result.set(r.tag, prior ? { ...r, ...prior, ...(r.config ? {config:r.config} : {}) } : r);
  }
  need(result.size <= IMAGE_REFERENCE_LIMIT,'IMAGE_REFERENCE_CAPACITY');
  return [...result.values()].sort((a,b) => a.tag.localeCompare(b.tag));
}

export function completionReferences(record, nonce) {
  need(plain(record) && [2,REFERENCE_COMPLETION_VERSION,CANDIDATE_COMPLETION_VERSION].includes(record.version) && record.nonce === nonce && nonceValid(nonce) &&
    Array.isArray(record.references) && record.references.length <= ROLES.length * 2, 'COMPLETION_REFERENCE_SCOPE');
  for (const r of record.references) need((record.version===2 || keys(r,['name','tag','image'])) && refValid(r) &&
    ['old','candidate'].some(kind => r.tag === ownTag(r.name,kind,nonce)), 'OWNED_REFERENCE_INVALID');
  need(new Set(record.references.map(r=>r.tag)).size === record.references.length,'OWNED_REFERENCE_DUPLICATE');
  if (record.version === 2) return {owned:record.references,borrowed:[]};
  need(Array.isArray(record.borrowedReferences) && record.borrowedReferences.length <= ROLES.length * (record.version===4?2:1),'BORROWED_REFERENCE_SCOPE');
  for (const r of record.borrowedReferences) need(keys(r,['name','tag','image','origin']) && refValid(r) && originValid(r.origin),'BORROWED_REFERENCE_INVALID');
  need(new Set(record.borrowedReferences.map(r=>r.tag)).size === record.borrowedReferences.length,'BORROWED_REFERENCE_DUPLICATE');
  if (record.referenceCustody === null) need(record.references.length === 0 && record.borrowedReferences.length === 0,'EMPTY_CUSTODY_REQUIRED');
  else {
    const custody = validateReferenceCustody(record.referenceCustody,nonce);
    need(record.version===(custody.version===2?4:3),'COMPLETION_CUSTODY_VERSION');
        const borrowed = [...custody.old,...(custody.version===2?custody.candidates:[])].filter(r=>r.ownership==='borrowed').map(r=>({...base(r),origin:r.origin}));
    need(equal(record.borrowedReferences,borrowed),'COMPLETION_BORROWED_MISMATCH');
    const expected = [...custody.old.filter(r=>r.ownership==='owned').map(base),
      ...custody.candidates.filter(r=>r.ownership!=='borrowed').map(r=>record.references.find(v=>v.name===r.name&&v.tag===r.tag))];
    need(expected.every(Boolean) && equal(referenceUnion(expected).map(base),referenceUnion(record.references).map(base)),'COMPLETION_OWNED_MISMATCH');
  }
  return {owned:record.references,borrowed:record.borrowedReferences};
}

// Origins are direct original owning receipts. A borrowing completion never
// becomes an origin for the borrowed reference; cycles cannot grant authority.
export function retainedReferenceHistory({legacy=[],completions=[]}={}) {
  need(Array.isArray(legacy) && Array.isArray(completions) && completions.length <= 64,'REFERENCE_HISTORY_SCOPE');
  const owned = [...legacy], uses = [];
  for (const r of legacy) need(refValid(r) && originValid(r.origin) && r.origin.kind==='llm-retention','LEGACY_ORIGIN_INVALID');
  for (const {nonce,sha256,record} of completions) {
    need(shaValid(sha256),'COMPLETION_DIGEST_INVALID');
    const refs = completionReferences(record,nonce);
    owned.push(...refs.owned.map(r=>({...r,origin:{kind:'adapter-completion',nonce,sha256}})));
    uses.push(...refs.borrowed);
  }
  need(new Set(owned.map(r=>r.tag)).size === owned.length,'OWNED_REFERENCE_DUPLICATE');
  const union = referenceUnion(owned);
  for (const r of uses) {
    const owner = union.find(v=>v.tag===r.tag);
    need(owner && owner.name===r.name && owner.image===r.image && equal(owner.origin,r.origin),'BORROWED_ORIGIN_MISMATCH');
  }
  return union;
}

export function createReferenceCustody({nonce,targets,published,runtime,references,candidateReferences=null}) {
  need(nonceValid(nonce) && Array.isArray(targets) && targets.length > 0 && targets.length <= ROLES.length &&
    new Set(targets).size===targets.length && targets.every(n=>ROLES.includes(n)), 'CUSTODY_TARGETS');
  const union = referenceUnion(references);
  const old = targets.map(name=>{
    need(imageValid(published[name]) && runtime[name]===published[name],'CUSTODY_OLD_IMAGE_MISMATCH');
    const match = union.find(r=>r.name===name && r.image===published[name]);
    if (match) need(originValid(match.origin),'CUSTODY_ORIGIN_REQUIRED');
    return {name,image:published[name],tag:match?.tag ?? ownTag(name,'old',nonce),ownership:match?'borrowed':'owned',...(match?{origin:match.origin}:{})};
  });
  if(candidateReferences){
      need(candidateReferences.length===targets.length,'CANDIDATE_REUSE_SCOPE');
      const candidates=targets.map(name=>{const row=candidateReferences.find(r=>r.name===name);
        need(row&&row.origin?.kind==='adapter-completion'&&references.some(r=>r.name===name&&r.tag===row.tag&&r.image===row.image&&equal(r.origin,row.origin)),'CANDIDATE_REUSE_ORIGIN');
        return {...base(row),ownership:'borrowed',origin:row.origin};});
      return validateReferenceCustody({version:CANDIDATE_CUSTODY_VERSION,old,candidates},nonce,references);
    }
    return validateReferenceCustody({version:REFERENCE_CUSTODY_VERSION,old,candidates:targets.map(name=>({name,tag:ownTag(name,'candidate',nonce)}))},nonce);
}
export function validateReferenceCustody(custody,nonce,references=null) {
  need(nonceValid(nonce) && keys(custody,['version','old','candidates']) && [REFERENCE_CUSTODY_VERSION,CANDIDATE_CUSTODY_VERSION].includes(custody.version) &&
    Array.isArray(custody.old) && custody.old.length>0 && custody.old.length<=ROLES.length && Array.isArray(custody.candidates) &&
    custody.candidates.length===custody.old.length,'CUSTODY_INVALID');
  const names = new Set();
  for (const r of custody.old) {
    need(refValid(r) && !names.has(r.name) && ['owned','borrowed'].includes(r.ownership) &&
      keys(r,['name','tag','image','ownership',...(r.ownership==='borrowed'?['origin']:[])]),'CUSTODY_OLD_INVALID');
    names.add(r.name);
    if (r.ownership==='owned') need(r.tag===ownTag(r.name,'old',nonce),'CUSTODY_OWNED_TAG');
    else {
      need(originValid(r.origin) && !['old','candidate'].some(kind=>r.tag===ownTag(r.name,kind,nonce)),'CUSTODY_BORROWED_ORIGIN');
      if (references) need(references.some(v=>v.name===r.name&&v.tag===r.tag&&v.image===r.image&&equal(v.origin,r.origin)),'BORROWED_ORIGIN_MISMATCH');
    }
  }
  need(custody.candidates.every((r,i)=>r.name===custody.old[i].name && (custody.version===1 ? keys(r,['name','tag'])&&r.tag===ownTag(r.name,'candidate',nonce) :
      keys(r,['name','tag','image','ownership','origin'])&&refValid(r)&&r.ownership==='borrowed'&&originValid(r.origin)&&r.origin.kind==='adapter-completion'&&
      r.origin.nonce!==nonce&&r.tag===ownTag(r.name,'candidate',r.origin.nonce)&&(!references||references.some(v=>v.name===r.name&&v.tag===r.tag&&v.image===r.image&&equal(v.origin,r.origin))))),'CUSTODY_CANDIDATE_INVALID');
  need(new Set([...custody.old,...custody.candidates].map(r=>r.tag)).size===custody.old.length*2,'CUSTODY_TAG_DUPLICATE');
  return structuredClone(custody);
}
export function custodyCompletionReferences(custody,nonce,candidates) {
  validateReferenceCustody(custody,nonce);
  need(plain(candidates) && equal(Object.keys(candidates).sort(),custody.old.map(r=>r.name).sort()),'CUSTODY_BUILD_SCOPE');
  const references = [], borrowedReferences = [];
  for (const old of custody.old) {
    const row = candidates[old.name], expected = custody.candidates.find(r=>r.name===old.name);
    need(plain(row) && imageValid(row.image) && row.tag===expected.tag && row.oldTag===old.tag && row.oldImage===old.image,'CUSTODY_BUILD_BINDING');
    if(expected.ownership==='borrowed'){
          need(row.image===expected.image,'CUSTODY_CANDIDATE_IMAGE');borrowedReferences.push({...base(expected),origin:expected.origin});
        }else references.push({name:old.name,tag:row.tag,image:row.image});
    if (old.ownership==='owned') references.push(base(old));
    else borrowedReferences.push({...base(old),origin:old.origin});
  }
  const order=[...custody.old,...(custody.version===2?custody.candidates:[])].map(r=>r.tag);
  borrowedReferences.sort((a,b)=>order.indexOf(a.tag)-order.indexOf(b.tag));
  return {references,borrowedReferences};
}

// A sealed historical intent commits ordered path/digests, not the old file
// identities or current orchestration. Equality is recomputed, never asserted.
export function candidateSourceEquivalence({originalSource,files,originalAdapter,originalEntrySources,currentAdapter,currentEntrySources}) {
  need(shaValid(originalSource)&&Array.isArray(files)&&files.length>0&&files.length<=4096&&
    files.every(r=>keys(r,['path','digest'])&&typeof r.path==='string'&&r.path.length<=512&&!r.path.startsWith('/')&&!r.path.split('/').some(p=>!p||p==='.'||p==='..')&&shaValid(r.digest))&&
    new Set(files.map(r=>r.path)).size===files.length,'CANDIDATE_SOURCE_PROOF');
  const source=createHash('sha256').update(JSON.stringify(files)).digest('hex');
  need(source===originalSource,'CANDIDATE_SOURCE_EQUIVALENCE_UNPROVEN');
  need([originalAdapter,currentAdapter].every(shaValid)&&[originalEntrySources,currentEntrySources].every(rows=>Array.isArray(rows)&&rows.length===7&&rows.every(shaValid)),'CANDIDATE_ORCHESTRATION_PROOF');
  // Conservative build/COPY-input superset: extra deployment build inputs may
  // be included, but no source can be excluded from the original commitment.
  const shippedFiles=files.filter(r=>/^(src\/|public\/|server\/api\/|server\/runtime\/|server\/deploy\/)|^(package\.json|pnpm-lock\.yaml|pnpm-workspace\.yaml|index\.html|admin\.html|vite\.config\.ts|tsconfig\.json)$/.test(r.path));
  return {version:1,basis:'exact-sealed-ordered-source-path-digests',originalSource,currentSource:source,
    originalAdapter,originalEntrySources,currentAdapter,currentEntrySources,shippedFiles,
    shippedSource:createHash('sha256').update(JSON.stringify(shippedFiles)).digest('hex')};
}

// --no-trunc engine output is intentionally bounded BEFORE deduplication. Dangling
// image IDs are independent liabilities, not silently filtered concrete names.
export function parseImageInventory(text) {
  need(typeof text==='string' && Buffer.byteLength(text)<=131072,'IMAGE_INVENTORY_BYTES');
  const lines = text === '' ? [] : (text.endsWith('\n') ? text.slice(0,-1) : text).split('\n');
  need(lines.length<=IMAGE_INVENTORY_ROW_LIMIT,'IMAGE_INVENTORY_ROWS');
  const concrete = new Map(), untagged = new Set();
  for (const line of lines) {
    const fields=line.split('\t');need(fields.length===2 && imageValid(fields[1]),'IMAGE_INVENTORY_INVALID');
    const [tag,image]=fields;
    if (tag==='<none>:<none>') untagged.add(image);
    else {need(tagValid(tag),'IMAGE_INVENTORY_INVALID');need(!concrete.has(tag)||concrete.get(tag)===image,'IMAGE_INVENTORY_CONFLICT');concrete.set(tag,image);}
  }
  need(concrete.size<=IMAGE_REFERENCE_LIMIT,'IMAGE_REFERENCE_CAPACITY');
  need(untagged.size<=UNTAGGED_IMAGE_LIMIT,'UNTAGGED_IMAGE_CAPACITY');
  return {concrete,untagged,rows:lines.length};
}
export function assertImageCapacity(inventory,references,plannedTags=[]) {
  const refs=referenceUnion(references);
  need(refs.every(r=>inventory.concrete.get(r.tag)===r.image),'IMAGE_REFERENCE_CAPACITY_OR_LOSS');
  need(Array.isArray(plannedTags) && new Set(plannedTags).size===plannedTags.length && plannedTags.every(tag=>tagValid(tag)&&!inventory.concrete.has(tag)),'IMAGE_TAG_ALREADY_PRESENT');
  need(inventory.concrete.size+plannedTags.length<=IMAGE_REFERENCE_LIMIT,'IMAGE_REFERENCE_CAPACITY');
  return true;
}
