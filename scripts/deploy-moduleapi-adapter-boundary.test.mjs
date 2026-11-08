// Synthetic configuration only. No actual home/state, engine, key, provider or network.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createDeployAdapter, adapterGatewayProbe, deployAdapterDiagnostic } from './deploy-adapter.mjs';
import { OPENAI_DEPLOYMENT, validateOpenAiDeployment, validateModuleApiDeployment } from './public-llm-source-build.mjs';
import { PROJECT, STATE } from './public-image-stand.mjs';
import { PUBLIC_LLM_ENV, PUBLIC_LLM_GATEWAY_PROBE, expectedPublicLlmConfig, publicLlmEnvironmentOverlay, capturePublicLlmSource } from './public-llm-stand.mjs';
import { loadCveRuntime } from './public-cve-bridge-runtime.mjs';

const ROOT=dirname(dirname(fileURLToPath(import.meta.url)));
function selections() {
  const environment={
    LLM_PROVIDER:'openai',OPENAI_ENABLED:'true',OPENAI_MODEL:OPENAI_DEPLOYMENT.model,
    OPENAI_ROUTING_APPROVED:'true',OPENAI_RETENTION:'no-training',OPENAI_POLICY_REVISION:'adapter-test-v1',
    OPENAI_ACCOUNTING_REVISION:'adapter-test-v1',OPENAI_MONETARY_LIMIT:'uncapped',
    OPENAI_INPUT_PRICE_MICROS_PER_MILLION:'1000000',OPENAI_OUTPUT_PRICE_MICROS_PER_MILLION:'2000000',
    OPENAI_TIMEOUT_MS:'1000',OPENAI_REQUEST_BYTES:'65536',OPENAI_RESPONSE_BYTES:'8192',
    OPENAI_INPUT_TOKENS:'4096',OPENAI_OUTPUT_TOKENS:'256',OPENAI_FINDINGS:'100',OPENAI_MAX_CONCURRENT:'2',
    LLM_QUOTA_ENABLED:'true',LLM_QUOTA_REVISION:'adapter-test-v1',LLM_QUOTA_WINDOW:'utc-day',LLM_QUOTA_MONETARY_LIMIT:'uncapped',
    LLM_QUOTA_USER_INPUT:'100000',LLM_QUOTA_USER_OUTPUT:'10000',LLM_QUOTA_SCAN_INPUT:'100000',LLM_QUOTA_SCAN_OUTPUT:'10000',
    LLM_QUOTA_WARNING_PERCENT:'80',LLM_QUOTA_REQUEST_INPUT:'4096',LLM_QUOTA_OBSERVATION_TOKENS:'65536',
    LLM_QUOTA_OBSERVATION_COST_MICROS:'1000000',LLM_QUOTA_RECEIPT_MS:'30000',LLM_QUOTA_REPLAY_DAYS:'7',
    LLM_QUOTA_MAX_ROWS:'100',LLM_QUOTA_DB_BYTES:'1048576',LLM_QUOTA_DISK_HEADROOM_BYTES:'134217728',
    LLM_QUOTA_BUSY_MS:'10',LLM_QUOTA_CLEANUP_BATCH:'10',LLM_QUOTA_LIFETIME_USER_COST_MICROS:'5000000',
  };
  const prior=validateOpenAiDeployment({version:6,provider:'OpenAI',keyVolume:null,openrouter:{version:1,keyVolume:null},
    monetaryLimit:'uncapped',credentialVolume:'openai-secrets',environment,operations:'public-images-v2'});
  const next=validateModuleApiDeployment({version:7,provider:'ModuleAPI',keyVolume:null,openrouter:prior.openrouter,openai:prior,
    monetaryLimit:'uncapped',credentialVolume:'moduleapi-secrets',operations:prior.operations,
    environment:{...Object.fromEntries(Object.entries(environment).map(([k,v])=>[k.replace(/^OPENAI_/,'MODULEAPI_'),v])),
      LLM_PROVIDER:'moduleapi',MODULEAPI_MODEL:'gpt-5.4-mini',MODULEAPI_RETENTION:'unknown'}});
  return {prior,next};
}
function configuration(t,{publishedV7=false,desiredV7=true}={}) {
  const root=fs.realpathSync(fs.mkdtempSync(join(tmpdir(),'adapter-moduleapi-boundary-')));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const home=join(root,'home'),state=join(root,STATE),settings=join(home,'.local/state/diplom-public-images/llm');
  fs.mkdirSync(state,{mode:0o700});fs.mkdirSync(settings,{recursive:true,mode:0o700});
  fs.mkdirSync(join(root,'server/deploy'),{recursive:true});
  fs.copyFileSync(join(ROOT,'server/deploy/compose.public-images.yaml'),join(root,'server/deploy/compose.public-images.yaml'));
  const {prior,next}=selections(),published=publishedV7?next:prior;
  const write=(path,value)=>fs.writeFileSync(path,typeof value==='string'?value:JSON.stringify(value),{mode:0o600});
  write(join(state,'profile.json'),{version:1,project:PROJECT,cve:null});
  write(join(state,'llm-profile.json'),published);
  write(join(state,'compose.llm-env.json'),publicLlmEnvironmentOverlay(published));
  const model=expectedPublicLlmConfig(root,null,published);
  write(join(state,'compose.images.json'),{services:Object.fromEntries(Object.keys(model.services).map(n=>[n,{image:'sha256:'+'a'.repeat(64)}]))});
  write(join(settings,'llm.env'),Object.entries(PUBLIC_LLM_ENV).map(([k,v])=>k+'='+v).join('\n')+'\n');
  write(join(settings,'openai-deployment.json'),prior);
  if(desiredV7)write(join(settings,'moduleapi-deployment.json'),next);
  let engineCalls=0;
  const adapter=createDeployAdapter({root,home,run:async()=>{engineCalls++;assert.fail('engine must not run for a refused scope');},
    checkSource:async()=>assert.fail('source qualifier must not run for a refused scope')});
  return {adapter,root,state,engineCalls:()=>engineCalls};
}

test('legacy v6 gateway readiness program is byte-identical',()=>{
  assert.equal(adapterGatewayProbe({version:6}),PUBLIC_LLM_GATEWAY_PROBE+PUBLIC_LLM_GATEWAY_PROBE
    .replaceAll('llmGateway','openAiGateway').replaceAll('connectLlmGateway','connectOpenAiGateway').replaceAll('llm-egress','openai-egress'));
});
test('v7 readiness addresses only the fixed ModuleAPI DNS alias and existing OpenRouter gateway',()=>{
  const probe=adapterGatewayProbe({version:7});
  assert.equal(probe,PUBLIC_LLM_GATEWAY_PROBE+PUBLIC_LLM_GATEWAY_PROBE
    .replaceAll('llmGateway','moduleApiGateway').replaceAll('connectLlmGateway','connectModuleApiGateway').replaceAll('llm-egress','moduleapi-egress'));
  assert.ok(!probe.includes('openai-egress'));
  assert.ok(probe.includes('moduleapi-egress')&&probe.includes('llm-egress'));
});
for(const services of [['api'],['api','web'],['api','openai-egress']])test('v6→v7 refuses missing transition target: '+services.join(','),async t=>{
  const f=configuration(t);
  await assert.rejects(f.adapter.prepare({mode:'app',services}),e=>deployAdapterDiagnostic(e).code==='MODULEAPI_TRANSITION_SCOPE');
  assert.equal(f.engineCalls(),0);assert.ok(!fs.existsSync(join(f.state,'.operation.lock')));
});
test('v6→v7 refuses explicit auth migration consent even when no migration has been detected',async t=>{
  const f=configuration(t);
  await assert.rejects(f.adapter.prepare({mode:'app',services:['api','web','openai-egress'],migrate:true}),
    e=>deployAdapterDiagnostic(e).code==='MODULEAPI_TRANSITION_SCOPE');
  assert.equal(f.engineCalls(),0);assert.ok(!fs.existsSync(join(f.state,'.operation.lock')));
});
test('v6→v7 refuses concurrent history migration before any engine call',async t=>{
  const f=configuration(t);
  await assert.rejects(f.adapter.prepare({mode:'app',services:['api','web','openai-egress'],migrateHistoryV4ToV5:true}),
    e=>deployAdapterDiagnostic(e).code==='HISTORY_MIGRATION_SCOPE');
  assert.equal(f.engineCalls(),0);
});
test('v6→v7 refuses concurrent operations upgrade before any engine call',async t=>{
  const f=configuration(t);
  await assert.rejects(f.adapter.prepare({mode:'app',services:['api','worker','web','egress','llm-egress','openai-egress'],upgradeOperations:true}));
  assert.equal(f.engineCalls(),0);assert.ok(!fs.existsSync(join(f.state,'.operation.lock')));
});
test('v7 cannot implicitly roll back through absent desired ModuleAPI config',async t=>{
  const f=configuration(t,{publishedV7:true,desiredV7:false});
  await assert.rejects(f.adapter.prepare({mode:'app',services:['api','web','openai-egress']}));
  assert.equal(f.engineCalls(),0);assert.ok(!fs.existsSync(join(f.state,'.operation.lock')));
});
test('v7 publication loads through actual CVE binder and fences its separate public bootstrap',async t=>{
  const f=configuration(t,{publishedV7:true});
  // Copy only the enumerated PUBLIC closure, never state/home/credentials.
  const source=capturePublicLlmSource(ROOT,{moduleapi:true});
  for(const entry of source.manifest.files){
    const destination=join(f.root,entry.path);
    fs.mkdirSync(dirname(destination),{recursive:true});
    fs.copyFileSync(join(ROOT,entry.path),destination);
  }
  for(const entry of source.manifest.directories)fs.mkdirSync(join(f.root,entry.p),{recursive:true});
  source.verify();
  const runtime=await loadCveRuntime(f.root);
  assert.equal(runtime.selection.version,7);
  assert.equal(runtime.roles.length,8);assert.equal(runtime.networks.length,8);
  assert.ok(runtime.roles.includes('openai-egress')&&!runtime.roles.includes('moduleapi-egress'));
  assert.ok(runtime.volumes.includes('openai-secrets')&&runtime.volumes.includes('moduleapi-secrets'));
  assert.deepEqual(runtime.model(null).services['openai-egress'].networks.openai_internal,{aliases:['moduleapi-egress']});
  runtime.verify();
  fs.appendFileSync(join(f.root,'server/deploy/moduleapi-secret-bootstrap.mjs'),'\n// synthetic tamper\n');
  assert.throws(runtime.verify,'actual binder must fence new bootstrap source');
  assert.equal(f.engineCalls(),0);
});

test('web-only cannot publish a pending provider transition',async t=>{
  const f=configuration(t);
  await assert.rejects(f.adapter.prepare({mode:'web',services:['web']}),
    e=>deployAdapterDiagnostic(e).code==='WEB_REQUIRES_UNCHANGED_RUNTIME_CONFIG');
  assert.equal(f.engineCalls(),0);
});
