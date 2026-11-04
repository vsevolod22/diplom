// Diagnostic projections only: no body/text/identity/header passthrough.
import { createRequire } from 'node:module';
import { dirname,join } from 'node:path';
import { fileURLToPath,pathToFileURL } from 'node:url';
const ROOT=fileURLToPath(new URL('../',import.meta.url));
export const HEADER_NAMES=Object.freeze(['x-llm-failure-phase','x-llm-failure-reason','x-llm-grounding-predicate','x-llm-grounding-index','x-llm-grounding-source-relation','x-llm-grounding-lexical-class','x-llm-grounding-boundary-class','x-llm-language-reason','x-llm-language-index','x-llm-language-token-class','x-llm-provider-status','x-llm-provider-error-code','x-llm-provider-error-param']);
// Selected application codes from llm-exception.filter.ts:8-13, additionally
// constrained by shared llmJsonErrorSchema. Unknown uppercase text is NOT a code.
const APPLICATION_CODES=Object.freeze(['LLM_UNAVAILABLE','LLM_HISTORY_CAPACITY','LLM_HISTORY_CONFLICT','LLM_HISTORY_UNAVAILABLE','LLM_QUOTA_UNAVAILABLE','LLM_QUOTA_EXCEEDED','LLM_INVALID_RESPONSE','LLM_CONTEXT_LIMIT','LLM_STALE_REPORT','LLM_STALE_POLICY','LLM_CONSENT_REQUIRED','LLM_INVALID_REQUEST','LLM_REPORT_UNAVAILABLE','LLM_CONFIGURATION_UNAVAILABLE','LLM_CAPACITY']);
const data=(v,k)=>{try{return v&&typeof v==='object'?Object.getOwnPropertyDescriptor(v,k)?.value:undefined;}catch{return undefined;}};
function plain(v,depth=0){try{if(v===null||['string','number','boolean'].includes(typeof v))return true;if(depth>8||!v||typeof v!=='object')return false;if(Array.isArray(v))return v.length<=100&&v.every(x=>plain(x,depth+1));if(Object.getPrototypeOf(v)!==Object.prototype&&Object.getPrototypeOf(v)!==null)return false;const keys=Reflect.ownKeys(v);return keys.length<=40&&keys.every(k=>typeof k==='string'&&Object.hasOwn(Object.getOwnPropertyDescriptor(v,k),'value')&&plain(data(v,k),depth+1));}catch{return false;}}
export async function diagnosticContracts(){process.env.TSX_DISABLE_CACHE='1';const require=createRequire(join(ROOT,'server/api/package.json')),m=require('tsx/package.json');const {tsImport}=await import(pathToFileURL(join(dirname(require.resolve('tsx/package.json')),m.exports['./esm/api'].import.default)).href);const load=p=>tsImport(join(ROOT,p),{parentURL:import.meta.url,tsconfig:join(ROOT,'tsconfig.json')});return {diagnostic:await load('server/api/src/llm/provider-diagnostic.ts'),grounding:await load('server/api/src/llm/grounding-witness.ts'),language:await load('server/api/src/llm/language-rejection.ts'),http:await load('server/api/src/llm/openai-http-diagnostic.ts'),chat:await load('src/shared/api/scans/llmChatContract.ts'),public:await load('src/shared/api/scans/llmPublicContract.ts')};}
export function finiteHeaders(input,c){
 const get=k=>{const v=data(input,k);return typeof v==='string'&&v.length<=128?v:undefined;};
 const phase=get('x-llm-failure-phase'),reason=get('x-llm-failure-reason');
 if(!c.diagnostic.FAILURE_PHASES.includes(phase)||!c.diagnostic.FAILURE_REASONS.includes(reason))return {};
 const target={},index=s=>typeof s==='string'&&/^(?:[0-9]|1[01])$/.test(s)?Number(s):undefined;
 const gi=index(get('x-llm-grounding-index')),li=index(get('x-llm-language-index'));
 if(phase==='grounding'&&reason==='unknown_identifier'&&c.diagnostic.GROUNDING_PREDICATES.includes(get('x-llm-grounding-predicate'))&&gi!==undefined){const witness=c.grounding.finiteGroundingWitness({sourceRelation:get('x-llm-grounding-source-relation'),lexicalClass:get('x-llm-grounding-lexical-class'),boundaryClass:get('x-llm-grounding-boundary-class')});c.diagnostic.diagnoseGrounding(target,get('x-llm-grounding-predicate'),gi,witness);}
 else if(phase==='language'&&reason==='not_russian'&&li!==undefined){const rejection=c.language.finiteLanguageRejection({reason:get('x-llm-language-reason'),tokenClass:get('x-llm-language-token-class')});if(rejection)c.diagnostic.diagnoseLanguage(target,rejection,li);else c.diagnostic.diagnose(target,phase,reason);}
 else c.diagnostic.diagnose(target,phase,reason);
 const status=get('x-llm-provider-status');if(phase==='headers'&&reason==='http_error'&&typeof status==='string'&&/^(?:20[1-9]|2[1-9][0-9]|[3-5][0-9]{2})$/.test(status)){const body=new TextEncoder().encode(JSON.stringify({error:{code:get('x-llm-provider-error-code'),param:get('x-llm-provider-error-param')}}));c.http.diagnoseOpenAiHttp(target,Number(status),body);}
 // tsImport seams can instantiate distinct WeakMaps; project each factory's
  // own finite result rather than relying on cross-module annotation identity.
  return {...c.diagnostic.diagnosticHeaders(target),...c.http.openAiHttpHeaders(target)};
}
export function finiteFailure(value,c){
 if(!plain(value))return null;
 const provider=c.public.providerErrorSchema.safeParse(value);if(provider.success)return {errorCode:provider.data.errorCode,...(provider.data.providerFailure?{providerFailure:provider.data.providerFailure}:{})};
 const legacy=c.public.llmJsonErrorSchema.safeParse(value);if(!legacy.success||!APPLICATION_CODES.includes(legacy.data.errorCode)||data(value,'providerFailure')!==undefined)return null;
 return {errorCode:legacy.data.errorCode};
}
export function finiteErrorFrame(value,c){
 if(!plain(value)||data(value,'type')!=='error')return null;
 const parsed=c.chat.chatFrameSchema.safeParse(value);if(!parsed.success||parsed.data.type!=='error')return null;
 const f=parsed.data;return {failure:{errorCode:f.errorCode,...(f.providerFailure?{providerFailure:f.providerFailure}:{})},receipt:f.receipt};
}
export function finiteReceiptFrame(value,c){if(!plain(value)||data(value,'type')!=='usage')return null;const parsed=c.chat.chatFrameSchema.safeParse(value);return parsed.success&&parsed.data.type==='usage'?{...parsed.data.usage}:null;}
export async function captureResponseDiagnostics(response,c,publish){
 const values={};let headerReadFailed=false;
 for(const name of HEADER_NAMES){try{const v=await response.headerValue(name);if(typeof v==='string')values[name]=v;}catch{headerReadFailed=true;}}
 const status=response.status();const meta={httpStatus:Number.isInteger(status)&&status>=100&&status<=599?status:null,headers:finiteHeaders(values,c),headerReadFailed,bodyInspection:'not-read',terminalFailureCaptured:false,usageReceiptCaptured:false};
 await publish(structuredClone(meta)); // Before body/DTO/parser exceptions can discard diagnostics.
 let raw;try{raw=await response.text();}catch{meta.bodyInspection='unavailable';await publish(structuredClone(meta));throw Error('RESPONSE_BODY_UNAVAILABLE');}
 if(typeof raw!=='string'||Buffer.byteLength(raw)>196608){meta.bodyInspection='over-bound';await publish(structuredClone(meta));throw Error('CHAT_WIRE_BOUND');}
 let type='';try{type=await response.headerValue('content-type')??'';}catch{}
 if(/^application\/x-ndjson(?:;|$)/i.test(type)){
  meta.bodyInspection='ndjson';const lines=raw.endsWith('\n')?raw.slice(0,-1).split('\n'):[];
  if(!lines.length||lines.length>c.chat.CHAT_DELIVERY.frames||lines.some(x=>Buffer.byteLength(x)>=c.chat.CHAT_DELIVERY.lineBytes)){meta.bodyInspection='ndjson-bound-or-eof-invalid';}
  else for(const line of lines){let frame;try{frame=JSON.parse(line);}catch{meta.bodyInspection='ndjson-invalid-json';continue;}const failure=finiteErrorFrame(frame,c),receipt=finiteReceiptFrame(frame,c);if(failure){meta.terminal={source:'ndjson-error-frame',...failure};meta.terminalFailureCaptured=true;}else if(data(frame,'type')==='error')meta.invalidErrorFrame=true;if(receipt){meta.usageReceipt=receipt;meta.usageReceiptCaptured=true;}}
 }else{
  meta.bodyInspection='json';try{const value=JSON.parse(raw),root=finiteFailure(value,c),nested=finiteFailure(data(value,'failure'),c);if(root)meta.applicationFailure=root;if(nested){meta.terminal={source:'json-terminal-failure',failure:nested};meta.terminalFailureCaptured=true;}else if(data(value,'failure')!==undefined)meta.invalidTerminalFailure=true;}catch{meta.bodyInspection='invalid-json';}
 }
 await publish(structuredClone(meta));return {raw,diagnostics:meta}; // raw is EPHEMERAL for original parser, never publish/log it.
}
export const safeRunnerFailure=e=>({type:['Error','TimeoutError','ZodError','TypeError','SyntaxError','RangeError'].includes(e?.name)?e.name:'Error',code:new Set(['CHAT_HTTP_FAILED_NO_RETRY','CHAT_APPLICATION_FAILED_NO_RETRY','CHAT_WIRE_BOUND','CHAT_EOF','CHAT_FRAME_BOUND','CHAT_NOT_COMPLETED_NO_RETRY','RESPONSE_BODY_UNAVAILABLE','RECOVERY_ALREADY_SPENT_NO_RETRY','DIAGNOSTIC_ALREADY_SPENT_NO_RETRY','PRIOR_LEDGER_MISMATCH','CURRENT_POLICY_OR_READINESS','EXISTING_SUMMARY_HASH_CHANGED','HISTORY_NOT_EMPTY_OR_BINDING_CHANGED','HISTORY_NOT_ONE_FAILED_REV2','FAILED_TURN_CHANGED','PRE_DISPATCH_BINDING_OR_HISTORY_CHANGED','USAGE_BASELINE_UNAVAILABLE_OR_STALE','RUSSIAN_LANGUAGE_GUARD','CHAT_NOT_DURABLE','PAGE_OR_REQUEST_GUARD','AUTOMATION_NOT_OFF','APPEND_ONLY_INTENT_FAILED_NO_RETRY']).has(e?.message)?e.message:'UI_SCHEMA_OR_IO_FAILURE'});
