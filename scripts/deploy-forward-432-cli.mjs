#!/usr/bin/env node
// Exact incident CLI; default/help inert. No ordinary apply/recovery fallback.
import { dirname,join,resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { EXACT_FORWARD_432,forward432Diagnostic } from './deploy-forward-432.mjs';
import { hasDeploySupervisor,DEPLOY_SUPERVISOR_PROGRAM } from './deploy-supervisor.mjs';
const ROOT=dirname(dirname(fileURLToPath(import.meta.url)));
export const FORWARD_432_HELP='Usage: node scripts/deploy-forward-432-cli.mjs check|continue --audit '+EXACT_FORWARD_432.audit+' [--review <64hex> --ack-forward-only]\nExact forward-only worker-ready continuation; check is observational. Continue requires a newly reviewed token and OS supervisor. No rebuild, gateway replacement, worker restart, migration or DB rollback. Any uncertainty HOLD; never retry/unlock automatically.';
export function parseForward432(argv){
  if(argv.length===0||argv.length===1&&['--help','-h'].includes(argv[0]))return {help:true};
  const [command,...args]=argv;if(!['check','continue'].includes(command))throw Error('FORWARD_USAGE');
  const value={apply:command==='continue'},seen=new Set();
  for(let i=0;i<args.length;i++){
    const flag=args[i];if(seen.has(flag))throw Error('FORWARD_USAGE');seen.add(flag);
    if(flag==='--audit'||flag==='--review'){const next=args[++i];if(!next||next.startsWith('--'))throw Error('FORWARD_USAGE');value[flag.slice(2)]=next;}
    else if(flag==='--ack-forward-only')value.ackForwardOnly=true;
    else throw Error('FORWARD_USAGE');
  }
  if(value.audit!==EXACT_FORWARD_432.audit)throw Error('FORWARD_USAGE');
    if(value.apply? !/^[a-f0-9]{64}$/.test(value.review??'')||value.ackForwardOnly!==true : seen.has('--review')||seen.has('--ack-forward-only'))throw Error('FORWARD_USAGE');
  return value;
}
export async function forward432Main(argv=process.argv.slice(2),{root=ROOT,factory,log=console.log}={}){
  let options;
  try{options=parseForward432(argv);}catch{log(JSON.stringify({ok:false,code:'FORWARD_432_USAGE',lifecycle:false}));return 1;}
  if(options.help){log(FORWARD_432_HELP);return 0;}
  if(options.apply&&!factory&&!hasDeploySupervisor()){
    // Same reviewed supervisor protocol, existing inode only; launch THIS fixed CLI.
    const env={...process.env};delete env.DIP_DEPLOY_SUPERVISOR_FD;delete env.DIP_DEPLOY_SUPERVISOR_SESSION;
    return await new Promise(done=>{
      const child=spawn('/usr/bin/python3',['-I','-c',DEPLOY_SUPERVISOR_PROGRAM,root,join(root,'.local-public-images'),process.execPath,fileURLToPath(import.meta.url),'recover',...argv],{cwd:root,env,stdio:'inherit'});
      child.once('error',()=>{log(JSON.stringify({ok:false,code:'FORWARD_SUPERVISOR_UNAVAILABLE',hold:true}));done(1);});
      child.once('exit',(code,signal)=>done(!signal&&Number.isInteger(code)?code:1));
    });
  }
  try{
    const create=factory??(await import('./deploy-adapter.mjs')).createDeployAdapter;
    const result=await create({root}).exactForward432(options);log(JSON.stringify({ok:true,...result}));return 0;
  }catch(error){log(JSON.stringify({ok:false,...(forward432Diagnostic(error)??{code:'FORWARD_432_REFUSED_OR_HOLD'}),audit:EXACT_FORWARD_432.audit,hold:true,retry:false}));return 1;}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))process.exitCode=await forward432Main();
