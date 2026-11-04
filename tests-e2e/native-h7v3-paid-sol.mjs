// Inert unless a strict mode and its coordinator acknowledgements are supplied.
// Same own account/context/scan only. Never registers, logs in, scans or retries generation.
import { createHash, randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { mkdir, readFile, writeFile, open, rename, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { BROWSER_ARGS, allowedApiGet } from './public-product-live.mjs';
export const SCAN='305a55de-6d94-4af6-a653-2bd117e1ec85';
export const MODEL='gpt-5.4-mini-2026-03-17';
export const ORIGIN='http://127.0.0.1:8081';
export const BASE=`/api/v1/browser/scans/${SCAN}`;
export const QUESTION='С каких находок этого отчёта начать проверку и какое ограничение покрытия важно учитывать? Ответь по-русски с источниками.';
const ROOT=fileURLToPath(new URL('../',import.meta.url));
const DIR=join(ROOT,'test-results/native-h7v3-paid-sol');
const BINDING=['scanId','digest','platform','reportVersion'];
const HASH=/^[a-f0-9]{64}$/;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const exact=(v,keys)=>!!v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...keys].sort().join(',');
export const fingerprint=v=>{const ordered=x=>Array.isArray(x)?x.map(ordered):x&&typeof x==='object'?Object.fromEntries(Object.keys(x).sort().map(k=>[k,ordered(x[k])])):x;return createHash('sha256').update(JSON.stringify(ordered(v))).digest('hex');};
export function need(v,code){if(!v)throw Error(code);}
export function modeOf(args){
 const modes={preflight:['--preflight','--ack-coordinator-postdeploy-go'],generate:['--generate','--ack-coordinator-paid-go','--ack-paid-uncapped','--ack-one-summary-one-chat'],verify:['--verify-reload','--ack-coordinator-readonly-go'],'resume-chat':['--resume-chat','--ack-coordinator-cleanup-go','--ack-coordinator-chat-go','--ack-paid-uncapped','--ack-one-chat-only']};
 if(!args.length)return 'inert';
 for(const [mode,flags]of Object.entries(modes))if(JSON.stringify(args)===JSON.stringify(flags))return mode;
 throw Error('INVALID_MODE_OR_ACKS');
}
export function policyMatches(c){const d=c?.disclosure;return c?.enabled===true&&HASH.test(c.policyVersion??'')&&d?.provider==='OpenAI'&&d.model===MODEL&&d.monetaryLimit==='uncapped'&&d.requestBudgetMicros===null&&d.userBudgetMicros===null&&d.scanBudgetMicros===null&&d.costBasis==='server-estimated-configured-rates-not-invoice'&&d.retention==='no-training'&&d.zeroDataRetentionVerified===false;}
export function readinessMatches(r,c){return r?.localReady===true&&r.status==='locally-configured'&&Array.isArray(r.blockers)&&r.blockers.length===0&&r.provider?.name==='OpenAI'&&r.provider.model===MODEL&&r.provider.status==='configured-unprobed'&&r.provider.liveVerified===false&&r.credential==='environment-valid'&&r.accounting==='configured'&&r.history==='available'&&r.quota==='available'&&r.requiresConsent===true&&r.acceptsCredentials===false&&r.generationVerified===false&&BINDING.every(k=>r[k]===c[k]);}
export function allowedRead(url){let u;try{u=new URL(url);}catch{return false;}if(u.origin!==ORIGIN||u.username||u.password||u.hash)return false;
 if(!u.search&&([`/scans/${SCAN}`,'/account','/api/v1/auth/me','/favicon.ico'].includes(u.pathname)||/^\/assets\/[A-Za-z0-9._/-]+\.(?:js|css|svg|png|webp|woff2?)$/.test(u.pathname)))return true;
 return u.pathname.startsWith(BASE+'/')&&allowedApiGet(url,new Set([SCAN]))||u.pathname===BASE&&!u.search;
}
export const CORPUS_LIMIT=50;
export const CORPUS_MAX_PAGES=9;
export const MANUAL_GET_PLAN=Object.freeze({initialContexts:3,initialHistory:1,missingSummary:1,status:1,corpus:CORPUS_MAX_PAGES,summaryDurable:1,summaryReload:1,chatContexts:3,chatDurable:1,finalReload:2});
export const FULL_PAIR_MANUAL_GETS=Object.values(MANUAL_GET_PLAN).reduce((a,b)=>a+b,0); // 23; one spare, never an unbounded retry.
export const MANUAL_GET_BUDGET=24;
export function corpusSuffix(cursor){need(Number.isSafeInteger(cursor)&&cursor>=0&&cursor%CORPUS_LIMIT===0&&cursor<CORPUS_LIMIT*CORPUS_MAX_PAGES,'CORPUS_CURSOR');return `/vuln?cursor=${cursor}&limit=${CORPUS_LIMIT}`;}
export async function collectVulnCorpus(read,expectedCount){
 need(Number.isSafeInteger(expectedCount)&&expectedCount>0&&expectedCount<=CORPUS_LIMIT*CORPUS_MAX_PAGES,'CORPUS_COUNT_BOUND');
 const findings=new Map();let cursor=0;
 for(let page=0;page<CORPUS_MAX_PAGES;page++){
  const v=await read(corpusSuffix(cursor));need(Array.isArray(v.findings)&&v.findings.length<=CORPUS_LIMIT,'CORPUS_PAGE_BOUND');
  need(v.findingCount===expectedCount,'CORPUS_COUNT_CHANGED');
  for(const f of v.findings){need(/^vuln-[a-f0-9]{64}$/.test(f?.findingId??'')&&!findings.has(f.findingId),'CORPUS_DUPLICATE_OR_INVALID_ID');findings.set(f.findingId,f);}
  need(findings.size<=expectedCount,'CORPUS_EXTRA_ROWS');
  if(v.nextCursor===null){need(findings.size===expectedCount,'INCOMPLETE_CORPUS');return {findings,pages:page+1};}
  need(v.findings.length===CORPUS_LIMIT&&v.nextCursor===cursor+v.findings.length,'CORPUS_CURSOR_PROGRESS');cursor=v.nextCursor;
 }
 throw Error('INCOMPLETE_CORPUS');
}
export function evidenceRecordName(mode,id){need(['preflight','generate','verify','resume-chat'].includes(mode)&&UUID.test(id),'EVIDENCE_RECORD_ID');return `${mode}-${id}-evidence.json`;}
export function safeDeniedRoute(url,method){
 let u;try{u=new URL(url);}catch{return {origin:'invalid',method:'OTHER',path:'/:unrecognized'};}
 const safeMethod=['GET','POST','HEAD','PUT','PATCH','DELETE'].includes(method)?method:'OTHER';
 if(u.origin!==ORIGIN)return {origin:'foreign',method:safeMethod,path:'/:foreign'};
 const suffix=u.pathname.startsWith(BASE)?u.pathname.slice(BASE.length):null;
 const own=['','/events','/results','/sbom','/vuln','/llm/context','/llm/readiness','/llm/history','/llm/summary','/llm/chat','/llm/chat/context','/llm/usage','/llm/chat/usage'];
 const path=suffix!==null&&own.includes(suffix)?`/api/v1/browser/scans/:own${suffix}`:u.pathname.startsWith('/api/v1/browser/scans/')?'/api/v1/browser/scans/:other':u.pathname.startsWith('/assets/')?'/assets/:asset':u.pathname==='/account'?'/account':u.pathname===`/scans/${SCAN}`?'/scans/:own':'/:unrecognized';
 return {origin:'same',method:safeMethod,path}; // Never query/body/userinfo or unknown path text.
}
export const RESUME_GET_PLAN=Object.freeze({summaryBefore:1,summaryReload:1,initialContexts:3,initialHistory:1,status:1,corpus:9,freshContexts:3,freshHistory:1,chatDurable:1,finalReload:2});
export const resumeEligible=s=>s?.summary===1&&s.chat===0&&s.summarySucceeded===true&&typeof s.summaryHash==='string'&&HASH.test(s.summaryHash);
export async function disableAutomationUi(page,step=()=>{}){
 step('account-navigation');await page.goto(ORIGIN+'/account');
 const details=page.locator('details.demo-auth__preferences');step('preferences-disclosure');await details.waitFor({state:'visible'});
 if(await details.getAttribute('open')===null)await details.locator(':scope > summary').click();
 need(await details.getAttribute('open')!==null,'PREFERENCES_DISCLOSURE_NOT_OPEN');
 const prefs=details.getByRole('region',{name:'Настройки отчётов',exact:true});await prefs.waitFor({state:'visible'});
 step('summary-select-off');const summary=prefs.getByLabel('ИИ-разбор',{exact:true});await summary.selectOption('off');
 step('language-select-original');const language=prefs.getByLabel('Язык исходных описаний уязвимостей',{exact:true});await language.selectOption('original');
 step('preferences-save');await prefs.getByRole('button',{name:'Сохранить настройки отчётов',exact:true}).click();await prefs.getByRole('status').waitFor({state:'visible'});
 need((await prefs.getByRole('status').innerText()).includes('Настройки сохранены')&&await summary.inputValue()==='off'&&await language.inputValue()==='original','PREFERENCE_SAVE');step('preferences-off-confirmed');
}
export class OneShotGate{
 constructor(state,persist,{chatOnly=false}={}){this.state=state;this.persist=persist;this.permit=null;this.halted=false;this.chatOnly=chatOnly;}
 arm(kind,c){need(!this.chatOnly||kind==='chat'&&resumeEligible(this.state),'RESUME_CHAT_ONLY');need(!this.halted&&!this.permit&&['summary','chat'].includes(kind)&&policyMatches(c),'PERMIT_POLICY');need(this.state[kind]===0&&(kind==='summary'||this.state.summary===1&&this.state.summarySucceeded===true),'NO_RETRY_OR_CHAT_BEFORE_SUMMARY');this.permit={kind,c};}
 async consume(path,body){const p=this.permit;if(this.halted||!p||this.chatOnly&&p.kind!=='chat'||path!==`${BASE}/llm/${p.kind}`||!body||this.state[p.kind]!==0)return false;
  const keys=p.kind==='summary'?['reportVersion','consent']:['epoch','revision','mutationId','reportVersion','question','consent'];
  if(!exact(body,keys)||body.reportVersion!==p.c.reportVersion||!exact(body.consent,['accepted','policyVersion'])||body.consent.accepted!==true||body.consent.policyVersion!==p.c.policyVersion)return false;
  if(p.kind==='chat'&&(body.epoch!==p.c.epoch||body.revision!==p.c.revision||!UUID.test(body.mutationId??'')||body.question!==QUESTION))return false;
  this.permit=null;this.state[p.kind]=1; // Spend before I/O; even a failed flush must never dispatch/retry.
  try{await this.persist();}catch{this.halted=true;throw Error('DISPATCH_LEDGER_WRITE_FAILED');}return p.kind;
 }
}
export async function contracts(){process.env.TSX_DISABLE_CACHE='1';const require=createRequire(join(ROOT,'server/api/package.json'));const manifest=require('tsx/package.json');const {tsImport}=await import(pathToFileURL(join(dirname(require.resolve('tsx/package.json')),manifest.exports['./esm/api'].import.default)).href);const load=p=>tsImport(join(ROOT,p),{parentURL:import.meta.url,tsconfig:join(ROOT,'tsconfig.json')});return {summary:await load('src/shared/api/scans/llmSummaryClient.ts'),chat:await load('src/shared/api/scans/llmChatContract.ts'),language:await load('server/api/src/llm/remediation-identifiers.ts')};}
const same=(a,b)=>BINDING.every(k=>a?.[k]===b?.[k]);
async function run(mode){
 process.umask(0o077);await mkdir(DIR,{recursive:true,mode:0o700});const lock=await open(join(DIR,'runner.lock'),'wx',0o600);let browser,timer,state,cleanupAutomation;let generationOpen=mode==='generate';
 const runId=randomUUID(),record=evidenceRecordName(mode,runId);let logCreated=false;
  let log={mode,runId,evidenceRecord:record,requests:0,maxRequests:320,manualGets:0,maxManualGets:MANUAL_GET_BUDGET,fullPairPlannedManualGets:FULL_PAIR_MANUAL_GETS,denied:0,deniedRoutes:[],postAttempts:0,dispatched:0,pageErrors:0,phase:'prepare',status:'NOT_RUN'};
 const saveState=async()=>{const temp=join(DIR,'state.tmp');await writeFile(temp,JSON.stringify(state),{mode:0o600});await rename(temp,join(DIR,'state.json'));};
 const saveLog=async()=>{need(logCreated,'EVIDENCE_NOT_CREATED');await writeFile(join(DIR,record),JSON.stringify(log,null,2),{mode:0o600});};
 let gate;
 try{
  await writeFile(join(DIR,record),JSON.stringify(log,null,2),{mode:0o600,flag:'wx'});logCreated=true;
  try{state=JSON.parse(await readFile(join(DIR,'state.json'),'utf8'));}catch(e){if(e.code!=='ENOENT')throw e;state={summary:0,chat:0,summarySucceeded:false};}
  need(Number.isSafeInteger(state.summary)&&[0,1].includes(state.summary)&&[0,1].includes(state.chat),'LEDGER_INVALID');
  if(mode==='generate')need(state.summary===0&&state.chat===0,'PRIOR_DISPATCH_NO_GENERATION_RETRY');
  if(mode==='resume-chat')need(resumeEligible(state),'RESUME_REQUIRES_EXISTING_SUMMARY_AND_UNSPENT_CHAT');
    gate=new OneShotGate(state,saveState,{chatOnly:mode==='resume-chat'});if(mode!=='generate')gate.halted=true;
  const tools=await contracts();const {chromium}=await import('@playwright/test');
  browser=await chromium.launchPersistentContext(join(ROOT,'test-results/native-h7v3-sol/browser'),{headless:true,args:[...BROWSER_ARGS],serviceWorkers:'block',acceptDownloads:false,viewport:{width:1280,height:960},reducedMotion:'reduce'});
  timer=setTimeout(()=>{gate.halted=true;void browser.close();},360000);timer.unref();
  await browser.routeWebSocket('**/*',socket=>{log.denied++;gate.halted=true;socket.close();});
  await browser.route('**/*',async route=>{
   const r=route.request(),u=new URL(r.url());const deny=async()=>{log.denied++;if(log.deniedRoutes.length<8)log.deniedRoutes.push(safeDeniedRoute(r.url(),r.method()));gate.halted=true;await route.abort();};
   if(++log.requests>log.maxRequests||u.origin!==ORIGIN||u.username||u.password||u.hash||r.redirectedFrom())return deny();
   if(r.method()==='GET')return allowedRead(r.url())?route.continue():deny();
   log.postAttempts++;
   if(!generationOpen||!['generate','resume-chat'].includes(mode)||r.method()!=='POST'||u.search||mode==='resume-chat'&&u.pathname!==BASE+'/llm/chat')return deny();
   let body;try{body=r.postDataJSON();}catch{return deny();}
   try{if(!await gate.consume(u.pathname,body))return deny();}catch{await deny();return;}
   log.dispatched++;log[u.pathname===BASE+'/llm/chat'?'chatConsentAccepted':'summaryConsentAccepted']=true;await saveLog();return route.continue();
  });
  for(const old of browser.pages())await old.close();const page=await browser.newPage();page.setDefaultTimeout(20000);page.on('pageerror',()=>log.pageErrors++);
  const get=async suffix=>{need(++log.manualGets<=log.maxManualGets,'MANUAL_GET_BUDGET');return page.evaluate(async path=>{const r=await fetch(path,{signal:AbortSignal.timeout(12000)});let value;try{value=await r.json();}catch{value=null;}return {status:r.status,value};},BASE+suffix);};
  const ok=async suffix=>{const r=await get(suffix);need(r.status===200,`GET_${r.status}`);return r.value;};
  async function paidUi(panel){await panel.waitFor({state:'visible'});const d=panel.getByLabel('Условия OpenAI',{exact:true});await d.waitFor({state:'visible'});const text=await d.innerText();need(text.includes(MODEL)&&text.includes('без локального денежного лимита')&&text.includes('не бесплатный режим')&&text.includes('ZDR'),'PAID_DISCLOSURE_UI_MISMATCH');const detail=d.locator('details');if(await detail.getAttribute('open')===null)await detail.locator(':scope > summary').click();return true;}
  async function contexts(){const c=tools.summary.summaryContextSchema.parse(await ok('/llm/context')),h=tools.chat.chatContextSchema.parse(await ok('/llm/chat/context')),r=tools.chat.chatReadinessSchema.parse(await ok('/llm/readiness'));need(c.scanId===SCAN&&c.digest==='sha256:abe13b25e07ccaedcc8797120c37781f0462a0f0682105cf2d8b8d6f99070d55'&&same(c,h)&&policyMatches(c)&&policyMatches(h)&&readinessMatches(r,c)&&!h.pending,'CURRENT_PAID_POLICY_OR_READINESS');return {c,h,r};}
  async function automationOff(){await disableAutomationUi(page,step=>{log.cleanupStep=step;});}
  cleanupAutomation=automationOff;
  if(mode==='resume-chat'){log.phase='automation-off';await automationOff();log.automationDisabled=true;need(log.postAttempts===0&&log.denied===0,'CLEANUP_NOT_GET_ONLY');}
    log.phase='report';await page.goto(`${ORIGIN}/scans/${SCAN}`);await page.locator('.scan-report-overview').waitFor();
  const summaryPanel=page.locator('.scan-a1__ai'),chatPanel=page.getByRole('region',{name:'Чат по отчёту',exact:true});
  if(mode==='verify'){
   need(state.summaryHash&&state.historyHash&&state.summarySucceeded&&state.chat===1,'NO_COMPLETED_PAIR_TO_VERIFY');
   gate.halted=true;const s=tools.summary.summaryReplySchema.parse(await ok('/llm/summary')),h=tools.chat.chatHistorySchema.parse(await ok('/llm/history'));need(fingerprint(s)===state.summaryHash&&fingerprint(h)===state.historyHash,'DURABLE_HASH_MISMATCH');await page.reload();const s2=await ok('/llm/summary'),h2=await ok('/llm/history');need(fingerprint(s2)===state.summaryHash&&fingerprint(h2)===state.historyHash,'RELOAD_CHANGED');await page.getByLabel('ИИ-разбор отчёта',{exact:true}).waitFor({state:'visible'});await chatPanel.getByRole('heading',{name:'Ответ · проверьте по источникам',exact:true}).waitFor({state:'visible'});log.reloadUiRestored=true;log.reloadZeroPost=log.postAttempts===0&&log.denied===0;need(log.reloadZeroPost,'RELOAD_POST_ATTEMPT');log.status='VERIFIED_GET_ONLY';
  }else if(mode==='resume-chat'){
   log.phase='existing-summary';const existing=tools.summary.summaryReplySchema.parse(await ok('/llm/summary'));need(fingerprint(existing)===state.summaryHash,'EXISTING_SUMMARY_HASH_CHANGED');
   await page.getByLabel('ИИ-разбор отчёта',{exact:true}).waitFor({state:'visible'});await page.reload();need(fingerprint(tools.summary.summaryReplySchema.parse(await ok('/llm/summary')))===state.summaryHash,'SUMMARY_RELOAD_CHANGED');
   need(log.postAttempts===0&&log.denied===0,'SUMMARY_RELOAD_NOT_GET_ONLY');log.summaryReloadZeroPost=true;log.summaryHashPreserved=true;
   const first=await contexts();need(same(first.c,existing),'EXISTING_SUMMARY_BINDING_CHANGED');
   const before=tools.chat.chatHistorySchema.parse(await ok('/llm/history'));need(!before.pending&&before.turns.length===0&&before.epoch===first.h.epoch&&before.revision===first.h.revision,'EXISTING_HISTORY_OR_PENDING');
   log.phase='native-corpus';const snapshot=await ok('');need(snapshot.state==='completed'&&snapshot.perCheck?.secret?.findingCount===0,'UNEXPECTED_SCAN_OR_SECRET_DATA');
   const corpus=new Map((snapshot.config?.findings??[]).map(f=>[f.findingId,f]));const native=await collectVulnCorpus(ok,snapshot.perCheck?.vuln?.findingCount);for(const [id,f]of native.findings)corpus.set(id,f);log.corpus={limit:50,pages:native.pages,vulnFindings:native.findings.size,complete:true};
   log.phase='fresh-chat-consent';const fresh=await contexts();need(same(fresh.c,existing)&&fresh.h.policyVersion===first.h.policyVersion&&fingerprint(fresh.h.disclosure)===fingerprint(first.h.disclosure),'CHAT_POLICY_CHANGED');
   const stable=tools.chat.chatHistorySchema.parse(await ok('/llm/history'));need(!stable.pending&&stable.turns.length===0&&stable.epoch===fresh.h.epoch&&stable.revision===fresh.h.revision,'EXISTING_HISTORY_OR_PENDING');
   await paidUi(chatPanel);need((await chatPanel.locator('#scan-chat-send-help').innerText()).includes('платный запрос OpenAI'),'CURRENT_CHAT_CONSENT_UI_MISSING');
   log.readiness={localReady:true,provider:'OpenAI',model:MODEL,monetaryLimit:'uncapped',requiresConsent:true,liveVerified:false};log.paidDisclosureUi=true;
   await chatPanel.getByRole('textbox',{name:'Вопрос чату',exact:true}).fill(QUESTION);need(resumeEligible(state)&&log.denied===0&&log.postAttempts===0,'RESUME_PREREQUISITES_CHANGED');
   log.phase='one-chat';gate.halted=false;gate.arm('chat',fresh.h);generationOpen=true;
   const pending=page.waitForResponse(res=>res.request().method()==='POST'&&new URL(res.url()).pathname===BASE+'/llm/chat',{timeout:140000}).catch(()=>null);
   await chatPanel.getByRole('button',{name:'Отправить вопрос',exact:true}).click();const response=await pending;generationOpen=false;gate.halted=true;need(response,'DISPATCH_UNKNOWN_NO_RETRY');log.chatHttpStatus=response.status();
   const wire=await response.text();need(Buffer.byteLength(wire)<=196608,'GENERATION_WIRE_BOUND');
   if(response.status()!==200){try{const v=JSON.parse(wire);if(typeof v.errorCode==='string'&&/^[A-Z0-9_]{1,80}$/.test(v.errorCode))log.chatApplicationError=v.errorCode;}catch{}throw Error('CHAT_HTTP_FAILED_NO_RETRY');}
   const parser=tools.chat.createChatFrameParser(fresh.h,response.request().postDataJSON().mutationId);need(wire.endsWith('\n')&&!wire.endsWith('\n\n'),'CHAT_EOF');const lines=wire.slice(0,-1).split('\n');need(lines.length<=52,'CHAT_FRAME_BOUND');for(const line of lines){need(Buffer.byteLength(line)<8192,'CHAT_FRAME_BOUND');parser.accept(JSON.parse(line));}
   const answer=parser.finish();if(answer.errorCode){log.chatApplicationError=answer.errorCode;throw Error('CHAT_APPLICATION_FAILED_NO_RETRY');}need(answer.reply&&!answer.duplicate,'CHAT_NOT_COMPLETED_NO_RETRY');
   const facts=answer.reply.sources.map(s=>s.finding);need(facts.length>0,'EMPTY_CITATIONS');for(const f of facts){const raw=corpus.get(f.findingId);need(raw,'CITATION_NOT_IN_NATIVE_REPORT');for(const key of ['cveId','ecosystem','severity','packageName','installedVersion','fixedVersion','provenanceRef','ruleId','classification','location'])if(key in f)need(f[key]===raw[key],'CITED_SCANNER_FACT_MISMATCH');}
   need(!tools.language.publicReportLanguageFailure(answer.reply.text,facts),'RUSSIAN_LANGUAGE_GUARD');
   log.phase='chat-durability';const after=tools.chat.chatHistorySchema.parse(await ok('/llm/history'));need(!after.pending&&after.turns.length===1&&after.turns[0].state==='completed'&&after.turns[0].id===answer.turnId&&fingerprint(after.turns[0].reply)===fingerprint(answer.reply),'CHAT_NOT_DURABLE');
   await chatPanel.getByRole('heading',{name:'Ответ · проверьте по источникам',exact:true}).waitFor({state:'visible'});need((await chatPanel.innerText()).includes(answer.reply.text),'CHAT_TEXT_NOT_VISIBLE');
   const details=chatPanel.getByText(`Источники (${facts.length})`,{exact:true}).locator('..');if(await details.getAttribute('open')===null)await details.locator(':scope > summary').click();const codes=await details.locator('code').allTextContents();for(const f of facts)for(const key of ['packageName','installedVersion','ecosystem','fixedVersion','ruleId','location','classification'])if(typeof f[key]==='string')need(codes.includes(f[key]),'CITED_FACT_NOT_VISIBLE');
   state.historyHash=fingerprint(after);await saveState();log.chat={languageGuardPassed:true,citationsNativeVerified:true,uiVisible:true,sourceCount:facts.length,historyHash:state.historyHash};
   log.phase='reload';const postCount=log.postAttempts;await page.reload();need(fingerprint(await ok('/llm/summary'))===state.summaryHash&&fingerprint(await ok('/llm/history'))===state.historyHash,'PAIR_RELOAD_CHANGED');need(log.postAttempts===postCount&&log.postAttempts===1&&log.denied===0,'RELOAD_POST_ATTEMPT');
   log.reloadZeroPost=true;log.summaryHashPreserved=true;log.semanticHumanReview='NOT_PERFORMED_BY_SCRIPT';log.status='RESUMED_PAIR_VERIFIED';
  }else{
   const {c,h,r}=await contexts();await paidUi(summaryPanel);await paidUi(chatPanel);
   const help=await summaryPanel.locator('#scan-summary-send-help').innerText(),chatHelp=await chatPanel.locator('#scan-chat-send-help').innerText();need(help.includes('платный')&&help.includes('Старое бесплатное согласие не применяется')&&chatHelp.includes('платный запрос OpenAI'),'CURRENT_CONSENT_UI_MISSING');
   const history=tools.chat.chatHistorySchema.parse(await ok('/llm/history'));need(history.turns.length===0&&!history.pending,'EXISTING_HISTORY_NO_GENERATION');
   log.readiness={localReady:r.localReady,provider:'OpenAI',model:MODEL,monetaryLimit:'uncapped',requiresConsent:r.requiresConsent,liveVerified:false};log.paidDisclosureUi=true;log.consentAccepted=false;
   const proof={at:Date.now(),scanId:SCAN,reportVersion:c.reportVersion,summaryPolicy:c.policyVersion,chatPolicy:h.policyVersion,disclosureHash:fingerprint([c.disclosure,h.disclosure]),paidDisclosureUi:true};
   if(mode==='preflight'){
    const missing=await get('/llm/summary');need(missing.status===404&&missing.value?.errorCode==='LLM_SUMMARY_MISSING','SUMMARY_ALREADY_EXISTS_OR_UNAVAILABLE');need(log.postAttempts===0&&log.denied===0,'PREFLIGHT_MUTATION_ATTEMPT');await writeFile(join(DIR,'preflight.json'),JSON.stringify(proof),{mode:0o600});log.status='READY_FOR_SEPARATE_PAID_GO';
   }else{
    const before=JSON.parse(await readFile(join(DIR,'preflight.json'),'utf8'));need(Date.now()-before.at>=0&&Date.now()-before.at<=900000&&['scanId','reportVersion','summaryPolicy','chatPolicy','disclosureHash','paidDisclosureUi'].every(k=>before[k]===proof[k]),'PREFLIGHT_STALE_OR_POLICY_CHANGED');
    const missing=await get('/llm/summary');need(missing.status===404&&missing.value?.errorCode==='LLM_SUMMARY_MISSING','SUMMARY_ALREADY_EXISTS_OR_UNAVAILABLE');
    // Read public scanner facts in memory only, never persisted as artifacts.
    const snapshot=await ok('');need(snapshot.state==='completed'&&snapshot.perCheck?.secret?.findingCount===0,'UNEXPECTED_SCAN_OR_SECRET_DATA');const corpus=new Map();for(const f of snapshot.config?.findings??[])corpus.set(f.findingId,f);
    const native=await collectVulnCorpus(ok,snapshot.perCheck?.vuln?.findingCount);for(const [id,f]of native.findings)corpus.set(id,f);log.corpus={limit:CORPUS_LIMIT,pages:native.pages,vulnFindings:native.findings.size,complete:true};
    function validateFacts(facts){need(facts.length>0,'EMPTY_CITATIONS');for(const f of facts){const raw=corpus.get(f.findingId);need(raw,'CITATION_NOT_IN_NATIVE_REPORT');for(const key of ['cveId','ecosystem','severity','packageName','installedVersion','fixedVersion','provenanceRef','ruleId','classification','location'])if(key in f)need(f[key]===raw[key],'CITED_SCANNER_FACT_MISMATCH');}}
    function language(text,facts){need(!tools.language.publicReportLanguageFailure(text,facts),'RUSSIAN_LANGUAGE_GUARD');}
    async function sourceDetails(details,facts){if(await details.getAttribute('open')===null)await details.locator(':scope > summary').click();const codes=await details.locator('code').allTextContents();for(const f of facts)for(const k of ['packageName','installedVersion','ecosystem','fixedVersion','ruleId','location','classification'])if(typeof f[k]==='string')need(codes.includes(f[k]),'CITED_FACT_NOT_VISIBLE');}
    async function generate(kind,admitted,click){gate.arm(kind,admitted);const pending=page.waitForResponse(res=>res.request().method()==='POST'&&new URL(res.url()).pathname===`${BASE}/llm/${kind}`,{timeout:140000}).catch(()=>null);if(kind==='summary')log.summaryConsentInteraction=true;await click();const response=await pending;need(response,'DISPATCH_UNKNOWN_NO_RETRY');log[`${kind}HttpStatus`]=response.status();need(response.status()===200,'GENERATION_HTTP_FAILED_NO_RETRY');const raw=await response.text();need(Buffer.byteLength(raw)<=196608,'GENERATION_WIRE_BOUND');if(kind==='summary')return tools.summary.summaryReplySchema.parse(JSON.parse(raw));const parser=tools.chat.createChatFrameParser(admitted,response.request().postDataJSON().mutationId);need(raw.endsWith('\n')&&!raw.endsWith('\n\n'),'CHAT_EOF');const lines=raw.slice(0,-1).split('\n');need(lines.length<=52,'CHAT_FRAME_BOUND');for(const line of lines){need(Buffer.byteLength(line)<8192,'CHAT_FRAME_BOUND');parser.accept(JSON.parse(line));}const result=parser.finish();need(result.reply&&!result.duplicate&&!result.errorCode,'CHAT_NOT_COMPLETED_NO_RETRY');return result;}
    log.phase='summary';const summary=await generate('summary',c,()=>summaryPanel.getByRole('button',{name:'Включить платный авторазбор OpenAI',exact:true}).click());need(same(summary,c),'SUMMARY_BINDING');validateFacts(summary.scannerFacts);for(const p of summary.hypotheses)language(p.text,summary.scannerFacts.filter(f=>p.citations.includes(f.findingId)));
    const output=page.getByLabel('ИИ-разбор отчёта',{exact:true});await output.waitFor({state:'visible'});const explanation=output.locator('details.scan-summary-explanation');if(await explanation.getAttribute('open')===null)await explanation.locator(':scope > summary').click();for(let i=0;i<summary.hypotheses.length;i++){const p=summary.hypotheses[i];need((await output.innerText()).includes(p.text),'SUMMARY_TEXT_NOT_VISIBLE');const d=explanation.getByText(`На чём основан абзац ${i+1} · находок: ${p.citations.length}`,{exact:true}).locator('..');await sourceDetails(d,summary.scannerFacts.filter(f=>p.citations.includes(f.findingId)));}
    need(fingerprint(await ok('/llm/summary'))===fingerprint(summary),'SUMMARY_NOT_DURABLE');state.summarySucceeded=true;state.summaryHash=fingerprint(summary);await saveState();log.summary={languageGuardPassed:true,citationsNativeVerified:true,uiVisible:true,paragraphs:summary.hypotheses.length,hash:state.summaryHash};
    // Turn automation OFF through normal UI before any reload. POST gate is unarmed here.
    log.phase='automation-off';await automationOff();log.automationDisabled=true;await page.goto(`${ORIGIN}/scans/${SCAN}`);await page.reload();need(fingerprint(await ok('/llm/summary'))===state.summaryHash&&state.chat===0&&log.denied===0,'SUMMARY_RELOAD_CHANGED_OR_POST');log.summaryReloadZeroPost=true;
    const current=await contexts();need(same(current.c,c)&&current.h.policyVersion===h.policyVersion,'CHAT_POLICY_CHANGED');await paidUi(chatPanel);
    log.phase='chat';await chatPanel.getByRole('textbox',{name:'Вопрос чату',exact:true}).fill(QUESTION);const answer=await generate('chat',current.h,()=>chatPanel.getByRole('button',{name:'Отправить вопрос',exact:true}).click());const facts=answer.reply.sources.map(s=>s.finding);validateFacts(facts);language(answer.reply.text,facts);const after=tools.chat.chatHistorySchema.parse(await ok('/llm/history'));need(!after.pending&&after.turns.length===1&&after.turns[0].state==='completed'&&after.turns[0].id===answer.turnId&&fingerprint(after.turns[0].reply)===fingerprint(answer.reply),'CHAT_NOT_DURABLE');
    await chatPanel.getByRole('heading',{name:'Ответ · проверьте по источникам',exact:true}).waitFor({state:'visible'});need((await chatPanel.innerText()).includes(answer.reply.text),'CHAT_TEXT_NOT_VISIBLE');await sourceDetails(chatPanel.getByText(`Источники (${facts.length})`,{exact:true}).locator('..'),facts);state.historyHash=fingerprint(after);await saveState();log.chat={languageGuardPassed:true,citationsNativeVerified:true,uiVisible:true,sourceCount:facts.length,historyHash:state.historyHash};
    gate.halted=true;log.phase='reload';const beforePosts=log.postAttempts;await page.reload();need(fingerprint(await ok('/llm/summary'))===state.summaryHash&&fingerprint(await ok('/llm/history'))===state.historyHash,'PAIR_RELOAD_CHANGED');need(log.postAttempts===beforePosts&&log.denied===0,'RELOAD_POST_ATTEMPT');log.reloadZeroPost=true;log.consentAccepted=true;log.semanticHumanReview='NOT_PERFORMED_BY_SCRIPT';log.status='SCOPED_PAIR_VERIFIED';
   }
  }
  need(log.pageErrors===0&&log.denied===0,'PAGE_OR_REQUEST_GUARD');
  if(['RESUMED_PAIR_VERIFIED','VERIFIED_GET_ONLY'].includes(log.status)){
   log.phase='safe-visual-screenshots';log.visualScreenshots=[];
   for(const width of [375,1280]){await page.setViewportSize({width,height:960});await page.getByLabel('ИИ-разбор отчёта',{exact:true}).waitFor({state:'visible'});const explanation=summaryPanel.locator('details.scan-summary-explanation');if(await explanation.getAttribute('open')!==null)await explanation.locator(':scope > summary').click();
    for(const [name,node,mask]of [['overview',page.locator('.scan-report-overview'),[]],['summary',summaryPanel,[summaryPanel.locator('details.scan-summary-explanation')]],['chat-receipt',chatPanel.locator('article'),[chatPanel.locator('article > p'),chatPanel.locator('article > div'),chatPanel.locator('textarea')]]]){const file=`${mode}-${runId}-${name}-${width}.png`;await node.screenshot({path:join(DIR,file),mask});log.visualScreenshots.push(file);}
   }
   log.visualReview='SCREENSHOTS_CAPTURED_NOT_YET_REVIEWED';
  }
 }catch(e){generationOpen=false;if(gate)gate.halted=true;log.status='BLOCKED_OR_PARTIAL';log.failure={phase:log.phase,type:e.name,code:/^[A-Z0-9_]{1,80}$/.test(e.message)?e.message:'SCHEMA_UI_OR_IO_FAILURE'};
  if(mode==='generate'&&(state?.summary===1||log.summaryConsentInteraction)&&!log.automationDisabled&&cleanupAutomation){try{await cleanupAutomation();log.automationDisabled=true;}catch{log.automationCleanupUnconfirmed=true;}}
 }
 finally{clearTimeout(timer);await browser?.close();log.browserClosed=true;log.ledger=state?{summary:state.summary,chat:state.chat,summarySucceeded:state.summarySucceeded}:null;if(logCreated)await saveLog();await lock.close();await unlink(join(DIR,'runner.lock'));console.log(JSON.stringify(log));}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){const mode=modeOf(process.argv.slice(2));if(mode==='inert')console.log('INERT: no browser/HTTP. Modes: --preflight --ack-coordinator-postdeploy-go | --generate --ack-coordinator-paid-go --ack-paid-uncapped --ack-one-summary-one-chat | --verify-reload --ack-coordinator-readonly-go | --resume-chat --ack-coordinator-cleanup-go --ack-coordinator-chat-go --ack-paid-uncapped --ack-one-chat-only');else await run(mode);}
