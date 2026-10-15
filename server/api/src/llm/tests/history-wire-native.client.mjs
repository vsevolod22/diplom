// Dependency-free, raw-target internal wire checker. --self-test opens no sockets.
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { readFileSync, readSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export const CANARY = 'CANARY-history-wire-public';
const ORIGIN = 'http://127.0.0.1:8080';
const accounts = [
  { email: 'history-wire-a@qualification.invalid', password: 'history-wire-public-password-a-123' },
  { email: 'history-wire-b@qualification.invalid', password: 'history-wire-public-password-b-123' },
];
const QUESTION = 'Explain the reported finding.';
const TEXT = 'Investigate this finding before accepting the image.';
const HASH = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const missingId = '00000000-0000-4000-8000-000000000001';
// Node comma-joins upstream and nginx Cache-Control fields. Validate only the
// frozen JSON/NDJSON directives; duplicates never remove a required directive.
export function validateCacheControl(value, representation) {
  assert(representation === 'json' || representation === 'ndjson');
  assert(typeof value === 'string' && value.length > 0 && value.length <= 128 && Buffer.byteLength(value) <= 128);
  assert(/^[A-Za-z, \t-]+$/.test(value));
  const directives = value.split(','); assert(directives.length <= 4);
  const required = representation === 'ndjson' ? ['no-store', 'no-transform'] : ['no-store'];
  const parsed = directives.map(part => {
    assert(/^[ \t]*(?:no-store|no-transform)[ \t]*$/i.test(part));
    const directive = part.replace(/^[ \t]+|[ \t]+$/g, '').toLowerCase();
    assert(required.includes(directive)); return directive;
  });
  for (const directive of required) assert(parsed.includes(directive));
  return true;
}
export function exact(value, keys) {
  assert(value && typeof value === 'object' && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort());
}
// Scan tokens before JSON.parse: duplicate escaped keys are rejected at every depth.
export function strictJSON(buffer) {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
  let i = 0;
  const ws = () => { while (/\s/.test(text[i] ?? '') && i < text.length) i++; };
  const str = () => {
    const start = i; assert.equal(text[i++], '"');
    while (i < text.length) { const c = text[i++]; if (c === '\\') { i++; continue; }
      if (c === '"') return JSON.parse(text.slice(start, i)); }
    assert.fail();
  };
  const value = depth => {
    assert(depth <= 32); ws();
    if (text[i] === '"') { str(); return; }
    if (text[i] === '{') {
      i++; ws(); const keys = new Set(); if (text[i] === '}') { i++; return; }
      while (true) { ws(); const k = str(); assert(!keys.has(k)); keys.add(k); ws(); assert.equal(text[i++], ':');
        value(depth + 1); ws(); const c = text[i++]; if (c === '}') return; assert.equal(c, ','); }
    }
    if (text[i] === '[') {
      i++; ws(); if (text[i] === ']') { i++; return; }
      while (true) { value(depth + 1); ws(); const c = text[i++]; if (c === ']') return; assert.equal(c, ','); }
    }
    const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(i));
    assert(match); i += match[0].length;
  };
  value(0); ws(); assert.equal(i, text.length); return JSON.parse(text);
}
export function stateGuard(s) {
  exact(s, ['owner','foreign','scanId','epoch','turnId','mutationId','decisionId','digest','platform','reportVersion',
    'consentPolicyVersion','incarnation','fingerprintDigest','reportDigest','accessIncarnation','historyInode','historyDevice']);
  for (const k of ['scanId','epoch','turnId','mutationId','decisionId','incarnation']) assert(UUID.test(s[k]));
  for (const k of ['owner','foreign','accessIncarnation']) assert(/^[a-f0-9]{32}$/.test(s[k]));
  for (const k of ['reportVersion','consentPolicyVersion','fingerprintDigest','reportDigest']) assert(HASH.test(s[k]));
  assert(/^sha256:[a-f0-9]{64}$/.test(s.digest)); assert.equal(s.platform, 'linux/amd64');
  assert.notEqual(s.owner, s.foreign); assert.notEqual(s.scanId.toUpperCase(), s.scanId);
  for (const k of ['historyInode','historyDevice']) assert(Number.isSafeInteger(s[k]) && s[k] >= 0);
}
export function cookieHeader(variant, cookies) {
  if (variant === 'anonymous' || !cookies.length) return null;
  return variant === 'foreign' ? cookies[1] : variant === 'cookie-duplicate' ? cookies[0]+'; '+cookies[0] : cookies[0];
}
const binding = s => ({ scanId: s.scanId, digest: s.digest, platform: s.platform, reportVersion: s.reportVersion });
export const chat = s => ({ epoch: s.epoch, revision: 0, mutationId: s.mutationId, reportVersion: s.reportVersion,
  question: QUESTION, consent: { accepted: true, policyVersion: s.consentPolicyVersion } });
export const decision = s => ({ epoch: s.epoch, revision: 2, mutationId: s.decisionId, reportVersion: s.reportVersion,
  text: TEXT, findingIds: ['secret-0-0'] });
export function padded(body, bytes) {
  const raw = Buffer.from(JSON.stringify(body)); assert(raw.length <= bytes);
  return Buffer.concat([raw, Buffer.alloc(bytes - raw.length, 32)]);
}
export function frame(buffer, s) {
  assert(buffer.length <= 196608 && buffer.length <= 8192 && buffer.at(-1) === 10);
  assert.equal(buffer.subarray(0, -1).indexOf(10), -1);
  const value = strictJSON(buffer.subarray(0, -1));
  assert.deepEqual(value, { v: 1, deliveryMode: 'validated-completed-reply', nativeProviderStream: false,
    ...binding(s), epoch: s.epoch, revision: 3, mutationId: s.mutationId, turnId: s.turnId,
    type: 'done', seq: 0, outcome: 'duplicate', state: 'failed' });
  return { frameCount: 1, bytes: buffer.length, sha256: createHash('sha256').update(buffer).digest('hex'),
    fatalUtf8: true, exactKeys: true, lf: true, cleanEof: true, statusOnly: true };
}
function publicHistory(value, s, revision) {
  exact(value, [...Object.keys(binding(s)), 'epoch','revision','turns','decisions','pending','retention']);
  for (const [k, v] of Object.entries(binding(s))) assert.equal(value[k], v);
  assert.equal(value.epoch, s.epoch); assert.equal(value.revision, revision); assert.equal(value.pending, null);
  assert.equal(value.turns.length, 1); assert.equal(value.decisions.length, revision === 2 ? 0 : 1);
  const turn = value.turns[0]; exact(turn, ['id','mutationId','state','question','report','createdAt']);
  assert.equal(turn.id, s.turnId); assert.equal(turn.mutationId, s.mutationId); assert.equal(turn.state, 'failed');
  assert.equal(turn.question, QUESTION); assert.deepEqual(turn.report, binding(s)); assert(Number.isSafeInteger(turn.createdAt));
  if (revision === 3) {
    const d = value.decisions[0]; exact(d, ['id','mutationId','kind','text','report','sources']);
    assert(UUID.test(d.id)); assert.equal(d.mutationId, s.decisionId); assert.equal(d.kind, 'user-decision');
    assert.equal(d.text, TEXT); assert.deepEqual(d.report, binding(s)); assert.equal(d.sources.length, 1);
    exact(d.sources[0], [...Object.keys(binding(s)), 'finding']);
    for (const [k,v] of Object.entries(binding(s))) assert.equal(d.sources[0][k], v);
    exact(d.sources[0].finding,['check','findingId','severity','ruleId','line','evidenceRef']);
        assert.deepEqual(d.sources[0].finding,{check:'secret',findingId:'secret-0-0',severity:'UNKNOWN',
          ruleId:'rule-0123456789abcdef',line:1,evidenceRef:'result-0-secret-0'});
  }
  assert.equal(typeof value.retention, 'string'); return value;
}
export function aliases(base, endpoint, scanId) {
  return endpoint === 'chat' ? [base+'/chat/',base+'/chat?probe=1',base.replace(scanId,scanId.toUpperCase())+'/chat',
    base+'/CHAT',base+'/chat/unknown',base+'/%63hat',base+'//chat',base+'/./chat',base+'/x/../chat'] :
    [base+'/history/decision/',base+'/history/decision?probe=1',base.replace(scanId,scanId.toUpperCase())+'/history/decision',
    base+'/History/decision',base+'/history/decision/unknown',base+'/history/%64ecision',base+'/history//decision',
    base+'/history/./decision',base+'/history/x/../decision'];
}
export function matrix(s) {
  const base = '/api/v1/browser/scans/'+s.scanId+'/llm', c = chat(s), d = decision(s);
  const list = []; const add = (id, path, body, options = {}) => list.push({ id, method: 'POST', path, body, ...options });
  for (const [ep, body] of [['chat',c],['history/decision',d]]) {
    const short = ep === 'chat' ? 'chat' : 'decision', path = base+'/'+ep;
    aliases(base,short,s.scanId).forEach((p,i) => add(short+'-alias-'+i,p,body));
    for (const variant of ['anonymous','authorization','origin-missing','origin-foreign','origin-duplicate','cookie-duplicate'])
      add(short+'-'+variant,path,body,{ variant, expected: variant === 'anonymous' ? 401 : variant === 'authorization' ? 403 : null });
    add(short+'-8193',path,padded(body,8193),{ expected: 413 });
    for (const variant of ['chunked','gzip','expect','utf8','json']) add(short+'-'+variant,path,body,{ variant });
  }
  for (const ep of ['history','chat/context','chat/usage']) {
    for (const variant of ['anonymous','foreign']) list.push({ id: 'read-'+ep.replace('/','-')+'-'+variant,
      method: 'GET', path: base+'/'+ep, variant, expected: variant === 'anonymous' ? 401 : 404 });
    list.push({ id: 'method-'+ep.replace('/','-'), method: 'POST', path: base+'/'+ep, body: d });
  }
  list.push({ id:'method-chat', method:'GET', path:base+'/chat' });
  list.push({ id:'read-missing', method:'GET', path:base.replace(s.scanId,missingId)+'/history', expected:404 });
  add('auth-empty-observation',base+'/chat',c,{ variant:'authorization-empty', observation:true });
  add('auth-duplicate',base+'/chat',c,{ variant:'authorization-duplicate' });
  const { consent, ...omitted } = c; add('consent-omitted',base+'/chat',omitted,{ expected:400 });
  add('consent-false',base+'/chat',{...c,consent:{...consent,accepted:false}},{ expected:403 });
  add('owner-extra',base+'/chat',{...c,owner:s.owner},{ expected:400 });
  for (const [id,body] of [['policy',{...c,consent:{...consent,policyVersion:'0'.repeat(64)}}],
    ['report',{...c,reportVersion:'0'.repeat(64)}],['question',{...c,question:'Explain a different finding.'}],
    ['revision',{...c,revision:3}],['epoch',{...c,epoch:missingId}]]) add('chat-conflict-'+id,base+'/chat',body,{ expected:409 });
  add('decision-conflict-text',base+'/history/decision',{...d,text:'Investigate a different finding.'},{ expected:409 });
  add('decision-stale',base+'/history/decision',{...d,mutationId:missingId},{ expected:409 });
  add('decision-foreign-finding',base+'/history/decision',{...d,mutationId:missingId,revision:3,findingIds:['foreign-finding']},{ expected:400 });
  for (const [i,accept] of ['application/x-ndjson,application/json','application/x-ndjson; charset=utf-8'].entries())
    add('accept-'+i,base+'/chat',c,{ accept,expected:406 });
  list.push({id:'runtime-excluded',method:'GET',path:'/api/v1/browser/runtime/capabilities',expected:404});
  list.push({id:'jwt-scans-excluded',method:'GET',path:'/api/v1/scans/'+s.scanId,expected:404});
  add('auth-513','/api/v1/auth/login',padded(accounts[0],513),{expected:415});
  add('summary-1025',base+'/summary',padded({reportVersion:s.reportVersion,consent:{accepted:false,policyVersion:s.consentPolicyVersion}},1025),{expected:413});
  assert.equal(new Set(list.map(v => v.id)).size, list.length); assert(list.length + 24 <= 128);
  return list;
}

async function run(phase, s, budgetMs) {
  stateGuard(s); assert(phase === 'disabled' || phase === 'replay');
  assert(Number.isInteger(budgetMs) && budgetMs > 0 && budgetMs <= 240000);
  const until = performance.now() + budgetMs; let calls = 0, total = 0; const vectors = []; const cookies = [];
  const exchange = (method, path, body, overrides = {}) => new Promise((resolve, reject) => {
    assert(++calls <= 128); assert(performance.now() < until);
    let raw = body === undefined ? undefined : Buffer.isBuffer(body) ? body : Buffer.from(JSON.stringify(body));
    const variant = overrides.variant, h = ['Host','web:8080','Connection','close'];
    const cookie = cookieHeader(variant, cookies); if (cookie) h.push('Cookie', cookie);
    if (method === 'POST' && variant !== 'origin-missing') h.push('Origin',variant === 'origin-foreign' ? 'http://foreign.invalid' : ORIGIN);
    if (variant === 'origin-duplicate') h.push('Origin',ORIGIN);
    if (variant === 'authorization' || variant === 'authorization-duplicate') h.push('Authorization','Bearer fixture-denied');
    if (variant === 'authorization-duplicate') h.push('Authorization','Bearer fixture-denied');
    if (variant === 'authorization-empty') h.push('Authorization','');
    if (variant === 'utf8') raw = Buffer.concat([Buffer.from('{"'+CANARY+'":"'),Buffer.from([0xff]),Buffer.from('"}')]);
    if (variant === 'json') raw = Buffer.from('{"'+CANARY+'":');
    if (raw) {
      h.push('Content-Type','application/json');
      if (variant === 'chunked') h.push('Transfer-Encoding','chunked'); else h.push('Content-Length',String(raw.length));
    }
    if (variant === 'gzip') h.push('Content-Encoding','gzip');
    if (variant === 'expect') h.push('Expect','100-continue');
    h.push('Accept',overrides.accept ?? 'application/json');
    let settled = false; const timer = setTimeout(() => finish(new Error('bounded-wire-timeout')), Math.min(5000,until-performance.now()));
    const finish = (error,result) => { if (settled) return; settled = true; clearTimeout(timer);
      if (error) {
              req.destroy();
              if (['chunked','gzip','expect','utf8','json'].includes(variant) && ['ECONNRESET','EPIPE'].includes(error.code))
                resolve({status:0,headers:{},body:Buffer.alloc(0),closed:true});
              else reject(error);
            } else resolve(result); };
    const req = http.request({hostname:'web',port:8080,method,path,headers:h,agent:false,maxHeaderSize:16384}, res => {
      const chunks = []; let bytes = 0;
      res.on('data', b => { bytes += b.length; total += b.length;
        if (bytes > 524288 || total > 4194304) finish(new Error('bounded-wire-size')); else chunks.push(b); });
      res.once('aborted', () => finish(new Error('bounded-wire-abort')));
      res.once('error', error => finish(error));
      res.once('end', () => finish(null,{status:res.statusCode,headers:res.headers,body:Buffer.concat(chunks)}));
    });
    req.once('error', error => finish(error)); req.end(raw);
  });
  const record = (id,r) => {
    vectors.push({id,status:r.status,bytes:r.body.length,category:r.closed ? 'connection-closed' : r.status >= 200 && r.status < 300 ? 'success' : 'refusal'});
    assert(vectors.length <= 128);
  };
  const json = r => { validateCacheControl(r.headers['cache-control'], 'json'); return strictJSON(r.body); };
  let ready = false;
  for (let i=0;i<4;i++) {
    const r = await exchange('GET','/api/v1/auth/me'); record('readiness-'+i,r);
    if (r.status === 401) { assert.deepEqual(json(r),{errorCode:'UNAUTHORIZED'}); ready=true; break; }
    assert([502,503,504].includes(r.status)); if (i<3) await new Promise(resolve => setTimeout(resolve,1700));
  }
  assert(ready);
  for (let i=0;i<2;i++) {
    const r = await exchange('POST','/api/v1/auth/login',accounts[i],{variant:'anonymous'}); record('login-'+i,r); assert.equal(r.status,200);
    const user = json(r); assert.equal(user.id,i===0?s.owner:s.foreign);
    const values = r.headers['set-cookie']; assert(Array.isArray(values) && values.length===1);
    const cookie = values[0].split(';')[0]; assert(/^demo_session=[A-Za-z0-9_-]{43}$/.test(cookie)); cookies.push(cookie);
  }
  const base = '/api/v1/browser/scans/'+s.scanId+'/llm';
  const head = async revision => { const r = await exchange('GET',base+'/history'); assert.equal(r.status,200); return publicHistory(json(r),s,revision); };
  const before = await head(phase==='disabled'?2:3);
  for (const ep of ['chat/context','chat/usage']) {
    const r=await exchange('GET',base+'/'+ep); record(ep.replace('/','-'),r); assert.equal(r.status,200); const v=json(r);
    for(const [k,value] of Object.entries(binding(s))) assert.equal(v[k],value);
    if(ep==='chat/context') { exact(v,[...Object.keys(binding(s)),'epoch','revision','enabled','policyVersion','disclosure','limits','deliveryMode','pending']);
          assert.equal(v.epoch,s.epoch); assert.equal(v.revision,phase==='disabled'?2:3); assert.equal(v.pending,false);
          assert.deepEqual(v.limits,{questionBytes:2048,bodyBytes:8192}); assert.equal(v.deliveryMode,'completed-response');
          assert.equal(v.enabled,phase==='replay'); assert.equal(v.policyVersion,phase==='replay'?s.consentPolicyVersion:null);
      if(phase==='disabled') assert.equal(v.disclosure,null);
            else assert.deepEqual(v.disclosure,{provider:'OpenRouter',model:'apodex/apodex-1.1-mini:free',providers:['novita/bf16'],
              region:'global',retention:'no-storage',operatorApprovedRouting:true,providerComplianceNotProvenByDeclaration:true,
              requestBudgetUsd:0,freeOnly:true,maxPrice:{prompt:0,completion:0,request:0},
              data:'Sanitized scanner findings and coverage; no raw evidence or credentials.',
              sentData:'Cleaned question, all user history/accepted decisions and selected findings with complete coverage.',
              localRetention:'Durable owner+scan history until separately authorized operator lifecycle; capacity can refuse; context cache only, not output cache.'}); }
    else { exact(v,[...Object.keys(binding(s)),'available','admission']); assert.equal(v.available,false); assert.deepEqual(v.admission,{status:'unavailable'}); }
  }
  let frameReceipt = null;
  if(phase==='disabled') {
    const d=decision(s), r=await exchange('POST',base+'/history/decision',d); record('actual-decision',r); assert.equal(r.status,200);
    publicHistory(json(r),s,3);
    const duplicate=await exchange('POST',base+'/history/decision',d); record('decision-duplicate',duplicate); assert.equal(duplicate.status,200);
    const value=json(duplicate); exact(value,['duplicate','id','state','epoch','revision']);
    assert.equal(value.duplicate,true); assert.equal(value.state,'completed'); assert.equal(value.epoch,s.epoch); assert.equal(value.revision,3); assert(UUID.test(value.id));
    for(const [id,body] of [['decision-changed',{...d,text:'Investigate a different finding.'}],['decision-stale',{...d,mutationId:missingId}]]) {
      const r=await exchange('POST',base+'/history/decision',body); record(id,r); assert.equal(r.status,409);
    }
    await head(3);
  } else {
    for(const [id,body,accept] of [['ndjson-original',chat(s),'application/x-ndjson'],['json-original',chat(s),'application/json'],
      ['ndjson-8192',padded(chat(s),8192),'application/x-ndjson']]) {
      const r=await exchange('POST',base+'/chat',body,{accept}); record(id,r); assert.equal(r.status,200);
      if(accept==='application/x-ndjson') {
        validateCacheControl(r.headers['cache-control'], 'ndjson');
        assert(/^application\/x-ndjson(?:;\s*charset=utf-8)?$/i.test(r.headers['content-type']));
        const receipt=frame(r.body,s); if(id==='ndjson-original') frameReceipt=receipt;
      } else assert.deepEqual(json(r),{duplicate:true,id:s.turnId,state:'failed',epoch:s.epoch,revision:3});
    }
    const h=await exchange('HEAD',base+'/history'); record('head-control',h); assert.equal(h.status,200); assert.equal(h.body.length,0);
    const reference = await head(3);
    for(const v of matrix(s)) {
      const r=await exchange(v.method,v.path,v.body,v); record(v.id,r);
      if(v.expected!==undefined && v.expected!==null) assert.equal(r.status,v.expected);
      else if(!v.observation) assert(!(r.status>=200 && r.status<300));
      if(v.observation && r.status===200) assert.deepEqual(json(r),{duplicate:true,id:s.turnId,state:'failed',epoch:s.epoch,revision:3});
      if(r.status===404 && v.id.startsWith('read-')) assert.deepEqual(json(r),{errorCode:'SCAN_NOT_FOUND'});
      assert(!r.body.includes(Buffer.from(CANARY)));
    }
    assert.deepEqual(await head(3),reference); assert.deepEqual(reference,before);
  }
  assert(calls<=128); return {kind:'history-wire-probe',phase,passed:true,httpCalls:calls,capturedBytes:total,vectors,
    frame:frameReceipt,originalRevision:0,currentRevision:3,noPrivateFingerprintDisclosure:true,
    mountedFixtureBytesQualified:true,productionClientAcceptance:false,wholeAcceptance:false};
}
export function cacheControlSelfTest() {
  const merged = values => {
    const response = new http.IncomingMessage(null), headers = {};
    for (const value of values) response._addHeaderLine('Cache-Control', value, headers);
    return headers['cache-control'];
  };
  const jsonHeader = merged(['no-store', 'no-store']);
  const ndjsonHeader = merged(['no-store, no-transform', 'no-store']);
  assert.equal(jsonHeader, 'no-store, no-store');
  assert.equal(ndjsonHeader, 'no-store, no-transform, no-store');
  const positives = [
    ['json', 'no-store'], ['json', jsonHeader], ['json', 'NO-STORE,\t no-store'],
    ['ndjson', 'no-store, no-transform'], ['ndjson', ndjsonHeader],
    ['ndjson', 'no-transform, NO-STORE'], ['ndjson', 'no-store, no-transform, no-store, no-transform'],
    ['json', ' '.repeat(120) + 'no-store'],
  ];
  for (const [mode, header] of positives) assert.equal(validateCacheControl(header, mode), true);
  const negatives = [undefined, null, [], ['no-store'], {}, 1, '', ' ', 'no-store,', ',no-store',
    'no-store,,no-store', 'no-store;no-store', 'no-store=1', '"no-store"', 'no-store\r\n', 'no-store\0',
    'no-store\u00a0', 'no-store, public', 'no-store, private', 'no-store, max-age=0',
    'no-store, max-age=60', 'no-store, no-cache', 'no-store, must-revalidate',
    Array(5).fill('no-store').join(','), ' '.repeat(121) + 'no-store', 'x'.repeat(129),
  ];
  for (const mode of ['json', 'ndjson']) for (const header of negatives)
    assert.throws(() => validateCacheControl(header, mode));
  for (const header of ['no-store', 'no-store, no-store', 'no-transform', 'no-transform, no-transform'])
    assert.throws(() => validateCacheControl(header, 'ndjson'));
  assert.throws(() => validateCacheControl('no-store, no-transform', 'json'));
  assert.throws(() => validateCacheControl('no-store', 'unknown'));
  return {passed:true,pure:true,socketsOpened:false,positiveVectors:positives.length,
    negativeVectors:negatives.length*2+6,headerBytesMaximum:128,directivesMaximum:4,
    nodeMergedJsonVerified:true,nodeMergedNdjsonVerified:true,ndjsonNoTransformRequired:true};
}
export function selfTest() {
  cacheControlSelfTest();
  const s={owner:'a'.repeat(32),foreign:'b'.repeat(32),scanId:'12345678-abcd-4000-8000-123456789abc',epoch:'12345678-abcd-4000-8000-123456789abd',
    turnId:'12345678-abcd-4000-8000-123456789abe',mutationId:'12345678-abcd-4000-8000-123456789abf',decisionId:'12345678-abcd-4000-8000-123456789ac0',
    digest:'sha256:'+'a'.repeat(64),platform:'linux/amd64',reportVersion:'c'.repeat(64),consentPolicyVersion:'d'.repeat(64),
    incarnation:'12345678-abcd-4000-8000-123456789ac1',fingerprintDigest:'e'.repeat(64),reportDigest:'f'.repeat(64),accessIncarnation:'c'.repeat(32),historyInode:1,historyDevice:1};
  stateGuard(s); assert.equal(padded(chat(s),8192).length,8192); assert.equal(matrix(s).length,72);
  const cookies = ['demo_session=public-fixture-a','demo_session=public-fixture-b'];
  assert.equal(cookieHeader('anonymous', cookies), null); assert.equal(cookieHeader('anonymous', []), null);
  assert.equal(cookieHeader(undefined,cookies),cookies[0]); assert.equal(cookieHeader('foreign',cookies),cookies[1]);
  assert.equal(cookieHeader('cookie-duplicate',cookies),cookies[0]+'; '+cookies[0]);
  const good=Buffer.from(JSON.stringify({v:1,deliveryMode:'validated-completed-reply',nativeProviderStream:false,...binding(s),epoch:s.epoch,
    revision:3,mutationId:s.mutationId,turnId:s.turnId,type:'done',seq:0,outcome:'duplicate',state:'failed'})+'\n');
  frame(good,s);
  for(const bad of [good.subarray(0,-1),Buffer.concat([good,good]),Buffer.from('{"v":1,"\\u0076":1}\n'),
    Buffer.concat([Buffer.from([0xff]),good]),Buffer.from(good.toString().replace('"seq":0','"seq":1')),
    Buffer.from(good.toString().replace('"state":"failed"','"state":"completed"')),
    Buffer.from(good.toString().replace('"v":1','"v":1,"inputHash":"CANARY-private"'))]) assert.throws(()=>frame(bad,s));
  assert.throws(()=>strictJSON(Buffer.from('{"x":{"a":1,"a":2}}')));
  assert(aliases('/S/llm','chat','S').includes('/S/llm/x/../chat'));
  return {passed:true,pure:true,socketsOpened:false,vectors:matrix(s).length,framingNegativeVectors:7,independentLoginCookieOmitted:true,cacheControlContractVerified:true};
}
if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  try {
    if(process.argv.length===3 && process.argv[2]==='--self-test') process.stdout.write(JSON.stringify(selfTest())+'\n');
    else {
      assert.equal(process.argv.length,3); const parts=[];let size=0;
      while(true){const b=Buffer.alloc(4096),n=readSync(0,b,0,b.length,null);if(!n)break;size+=n;assert(size<=65536);parts.push(b.subarray(0,n));}
      const spec=strictJSON(Buffer.concat(parts));exact(spec,['state','budgetMs','clientSha256']);
            assert(HASH.test(spec.clientSha256));
            assert.equal(createHash('sha256').update(readFileSync(new URL(import.meta.url))).digest('hex'),spec.clientSha256);
      const result=await run(process.argv[2],spec.state,spec.budgetMs);
      const encoded=JSON.stringify(result);assert(Buffer.byteLength(encoded)<=65536);process.stdout.write(encoded+'\n');
    }
  } catch { process.stdout.write('{"kind":"history-wire-probe-refusal","passed":false}\n');process.exitCode=1; }
}
