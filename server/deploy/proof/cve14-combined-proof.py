#!/usr/bin/env python3
"""Review candidate: actual isolated LOCAL HTTP -> outbox -> Trivy -> SQL/owner/reload.

Default/--plan and --self-test are PUBLIC-source-only, no writes, Docker, sockets,
5/subprocesses or release/credential reads. --execute is PARENT ONLY AFTER approval
of this EXACT script SHA256, sourceSnapshotSha256 and a cached gateway image ID.
--diagnose-build is separately PARENT-gated on exact script/source hashes, LOCAL
context and NEW scratch; build only, no gateway/release/port/Compose/runtime.
No commit required. No LIVE discovery, env/key/userDB read, private helper import,
OpenRouter/UI build, signer, provisioner, Docker restart or shared prune.

Executable scope: ordinary LOCAL consumer on existing internal networks; ONLY the
verified production CONNECT gateway is dual-homed. Production archive-process.ts
uses real offline Trivy fixed argv/minimal env; an OWN /proc observer checks them.
No injected readiness/runner/clock/DB trust, alternate registry or fabricated result.

Explicit inputs: existing unchanged authentic DB release directory, local enrolled
Docker context, exact cached production gateway image ID. Missing inputs/cache or
policy/dependency/source mismatch fails closed. Execute creates fresh OWN volumes,
JWT/accounts/quota, uses ordinary cookie login at literal 127.0.0.1:18083, then
recreates ONLY OWN API and verifies the SAME report/ledger/policy. No LIVE acceptance.

600 seconds total including reserved cleanup; all commands/output/HTTP bounded.
Success removes OWN containers/networks/volumes by verified exact IDs/names. Failure
stops OWN containers, retains OWN resources + private recovery manifest + sanitized
hash-sealed evidence. No automatic DB restore, retry, resource widening or raw logs.
Unique build tags/cache remain (no shared-image cleanup). Content seal != signature.
"""
from __future__ import annotations
import argparse
import errno
from datetime import datetime, timezone
import hashlib
import http.client
from http.client import HTTPException
import json
import os
import posixpath
from pathlib import Path
import re
import secrets
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
SELF = Path(__file__).resolve()
PORT = 18083
ORIGIN = 'http://127.0.0.1:18083'
WORKER = 'sha256:8748cbebba753603d79f320c2fb476c46ab676ce12e0aa08bee0021a3e14e57a'
INGRESS = 'sha256:1659b39c98d5183c91feae78a8d9eb1d4c6ee527d541c1e1d74dfe842adee8c0'
INGRESS_CONFIG = 'server/deploy/stand.nginx.conf'
INGRESS_CONFIG_SHA = '52a2aef79bafa3da69fcc2e6a6b86867d4f9fb662003791a5531394a8a35344a'
INGRESS_COPY = 'public-stand.nginx.conf'
INGRESS_DEST = '/etc/nginx/nginx.conf'
INGRESS_TMPFS = 'rw,noexec,nosuid,uid=101,gid=101,size=16m'
INGRESS_ENV_KEYS = {'PATH','NGINX_VERSION','NJS_VERSION','NJS_RELEASE','PKG_RELEASE','DYNPKG_RELEASE'}
RESOURCE_LIMITS = {'containers':6,'networks':4,'volumes':2}
# Last OWN overlay: ordinary Compose port merging would retain base port8080.
PORT_OVERRIDE = b'services:\n  api:\n    ports: !override []\n  web:\n    ports: !override ["127.0.0.1:18083:8080"]\n    tmpfs: !override ["/tmp:rw,noexec,nosuid,uid=101,gid=101,size=16m"]\n'
POLICY = 'cve-db-updated-at-14d-v2'
TARGET = {'registry': 'registry-1.docker.io', 'repository': 'library/nginx',
          'digest': 'sha256:0dcc88822d45581e65ae329f8be769762bf628d3b2bb7d2a077d4aa5c98b30e3',
          'configDigest': 'sha256:dc73b49f5124cf2ee538dfbdfbd121f0b4ccdcb20fea30f3a81bd477c02e2bb5',
          'platform': 'linux/amd64'}
BINDING = {'qualificationId': 'nginx-local-0dcc-v1', 'version': 1,
           'configDigest': TARGET['configDigest'], 'profileVersion': 'nginx-alpine-amd64-v2-candidate',
           'checksVersion': 'trivy-0.69.3-archive-v1',
           'resourcePolicyVersion': 'nginx-archive-resources-v1', 'scannerVersion': '0.69.3'}
CHECKS = ['secret', 'sbom', 'vuln']
DB = {'envelopeVersion': 1, 'signer': 'local-db-operator-v1', 'schemaVersion': 2,
      'manifestDigest': 'sha256:a7ace06d6bb43a23fab1b9cae2a02c0b3e856006f2de75bb0c9661e655e3b74e',
      'source': 'ghcr.io/aquasecurity/trivy-db@sha256:a7ace06d6bb43a23fab1b9cae2a02c0b3e856006f2de75bb0c9661e655e3b74e',
      'artifactSha256': 'd1a4a72fd13d091df875e820112ea147d70e996e1017ef5c8ff434ac7c0c454d',
      'dbSha256': '5f4b978a55284b1997dc31e9f2fc3f4f1abae80829f51451ade221d5675a69b9',
      'metadataSha256': '733145f3bb63cfec2634cff132ab55dd2918ef0387c1b62366908a8571119c4c',
      'updatedAt': '2026-10-07T07:38:55.515026687Z', 'downloadedAt': '2026-10-07T08:02:58.068983Z',
      'nextUpdate': '2026-10-08T07:38:55.515026457Z'}
SPKI_SHA = 'd75c6f6b2384de68978090fc837387ab4f3e878ee004bccf27ea98a84fbee078'
PEM_SHA = '052573290dfffd8b79af351845ccdecf8846df17afa98e2f6fa5600ccbf4f6e6'
UNTIL = '2026-10-21T07:38:55.515026687Z'
BASES = ('compose.stand.yaml', 'compose.stand.vuln.local.yaml', 'compose.stand.nginx.local.yaml')
INPUTS = ('package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml', 'server/api/package.json',
          'server/api/tsconfig.json', 'server/deploy/trust/db-signing-key.pub.pem',
          'server/deploy/gateway/proxy.py', 'server/deploy/gateway/Dockerfile',
          *('server/deploy/' + p for p in BASES), INGRESS_CONFIG)
PROOFS = {'server/deploy/proof/cve-advisory-evidence.json':
          '60cabda3a67bcaf706b49b9cff786649ae8b338f1267b7762b41bca84f034567',
          'server/deploy/proof/nginx-local-evidence.json':
          'cd14137e36a853f6870060f88dca96416fcb8f8071f4a8b01a35d23c1134fcb9'}
OFF = {'LLM_ENABLED': 'false', 'LLM_ROUTING_APPROVED': 'false',
       'LLM_QUOTA_ENABLED': 'false', 'LLM_HISTORY_ENABLED': 'false'}
HEX = re.compile(r'[a-f0-9]{64}\Z')
IMAGE = re.compile(r'sha256:[a-f0-9]{64}\Z')
UUID = re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\Z')
MAX_FILE, MAX_TOTAL, MAX_FILES = 4 * 1024 ** 2, 32 * 1024 ** 2, 2048
TOTAL_SECONDS, WORK_SECONDS = 600, 535
SOURCE_TREES = ('server/api/src', 'server/runtime/src', 'server/broker/src')
SOURCE_LEAVES = ('src/shared/api/scans/runtimeTransport.ts',)
SOURCE_SUFFIXES = {'.ts', '.tsx', '.mts', '.cts', '.js', '.mjs', '.cjs', '.json'}
BUILD_SECONDS, BUILD_OUTPUT_CAP = 220, 4 * 1024 ** 2
DIAGNOSTIC_SECONDS = 300
INIT_DIAGNOSTIC_SECONDS, INIT_LOG_CAP = 8, 65536
INIT_FAILURE_CODES = ('own_init_shape_refused', 'own_init_state_refused', 'own_init_fresh_not_empty',
                      'own_init_postcondition_failed', 'own_init_chmod_eperm', 'own_init_chown_eperm',
                      'own_init_io_failed')
DIAGNOSTIC_ROWS, DIAGNOSTIC_LINES, DIAGNOSTIC_LINE_BYTES = 32, 32768, 4096
TS_CODES = ('TS2307', 'TS2550', 'TS7006', 'TS7016', 'TS2339', 'TS2322', 'TS2345', 'TS2769', 'TS18046')
DESKTOP_BIND_POLICY = 'desktop-exact-literal-or-host-mnt-v1'
COMPOSE_PHASES = ('before-storage','after-storage')
COMPOSE_CAPTURE_CAP, COMPOSE_DIAGNOSTIC_SCAN_BYTES, COMPOSE_DIAGNOSTIC_CAP = 2 * 1024 ** 2, 32768, 1024
COMPOSE_PUBLIC_FIELDS = ('security_opt','cap_drop','cap_add','ports','tmpfs','platform','entrypoint',
                         'volumes','networks','environment','mem_limit','memswap_limit','cpus','pids_limit')
COMPOSE_PUBLIC_SERVICES = ('api','web','worker','egress','auth-volume-init','scan-volume-init')
PROTOCOL_DIAGNOSTIC_CAP = 1024
PROTOCOL_SUBPHASES = ('isolation-qualification','chain-readiness','ingress-qualification',
                      'ingress-host-readiness','ingress-recreated-readiness','ordinary-owner-login',
                      'ordinary-foreign-login','ordinary-unlisted-login','image-eligibility',
                      'observer-start','actual-http-combined')
HTTP_STAGES = ('request','response-headers','response-body','json-decode','complete')
HTTP_OPERATIONS = ('connection-create','signal-read','signal-install','timer-arm','connection-connect',
                   'request-send','response-headers','response-body','json-decode',
                   'timer-disarm','signal-restore','connection-close')
HTTP_CLEANUP_OPERATIONS = ('timer-disarm','signal-restore','connection-close')
HTTP_ERRNO_CLASSES = ('EPERM','EACCES','ECONNREFUSED','EINVAL')
PROTOCOL_EXCEPTION_CLASSES = ('http_timeout','http_disconnected','connection_reset','json_decode_error',
                              'unicode_decode_error','missing_key','type_error','value_error','os_error',
                              'subprocess_error','other_protocol_error')
# Conservative literal-import check, not a substitute for the unchanged TypeScript compiler.
RELATIVE_IMPORT = re.compile(r'''\b(?:from\s*|import\s*\(\s*|require\s*\(\s*|import\s*)["'](\.[^"'\r\n]+)["']''')


class Refusal(Exception):
    pass


def require(ok, code):
    if not ok:
        raise Refusal(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode()


def utc():
    return datetime.now(timezone.utc).isoformat()


def source_path(relative):
    return (relative in SOURCE_LEAVES or
            any(relative.startswith(tree + '/') for tree in SOURCE_TREES)) and Path(relative).suffix in SOURCE_SUFFIXES


def public_read(relative):
    require(re.fullmatch(r'[A-Za-z0-9_./-]+', relative) and
            not any(part.startswith('.') for part in Path(relative).parts) and
            (relative in INPUTS or relative in PROOFS or source_path(relative)), 'private_path_denied')
    path = ROOT
    for part in Path(relative).parts[:-1]:
        path /= part
        require(stat.S_ISDIR(path.lstat().st_mode), 'linked_public_directory')
    fd = os.open(ROOT / relative, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_FILE, 'public_file_bound')
        data = bytearray()
        while len(data) <= MAX_FILE:
            chunk = os.read(fd, min(65536, MAX_FILE + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        require(len(data) == before.st_size and all(getattr(before, k) == getattr(after, k)
                for k in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')), 'source_drift')
        return bytes(data)
    finally:
        os.close(fd)


def validate_source_closure(data):
    # Resolve ONLY against frozen, explicitly allowlisted bytes. Never open an import's path.
    for name, raw in data.items():
        if not source_path(name) or Path(name).suffix == '.json':
            continue
        text = raw.decode('utf8')
        for specifier in RELATIVE_IMPORT.findall(text):
            require(re.fullmatch(r'[A-Za-z0-9_./-]+', specifier), 'unsupported_source_import')
            target = posixpath.normpath(posixpath.join(posixpath.dirname(name), specifier))
            require(not target.startswith('../') and not target.startswith('/') and
                    not any(part.startswith('.') for part in Path(target).parts), 'private_source_import')
            suffix = Path(target).suffix
            candidates = [target]
            if suffix == '.js': candidates += [target[:-3] + '.ts', target[:-3] + '.tsx', target[:-3] + '.d.ts']
            elif suffix == '.mjs': candidates += [target[:-4] + '.mts', target[:-4] + '.d.mts']
            elif suffix == '.cjs': candidates += [target[:-4] + '.cts', target[:-4] + '.d.cts']
            elif not suffix: candidates += [target + '.ts', target + '.tsx', target + '/index.ts']
            require(any(p in data and source_path(p) for p in candidates), 'public_source_closure_missing')


def inventory():
    paths = list(INPUTS) + list(SOURCE_LEAVES)
    for tree in SOURCE_TREES:
        root = ROOT
        for part in Path(tree).parts:
            root /= part
            require(stat.S_ISDIR(root.lstat().st_mode), 'linked_source_root')
        for directory, directories, files in os.walk(root, followlinks=False):
            for name in directories:
                require(not name.startswith('.') and stat.S_ISDIR((Path(directory) / name).lstat().st_mode),
                        'linked_source_directory')
            for name in files:
                path = Path(directory) / name
                require(not name.startswith('.') and stat.S_ISREG(path.lstat().st_mode), 'unsafe_source_file')
                if path.suffix in SOURCE_SUFFIXES:
                    paths.append(path.relative_to(ROOT).as_posix())
                    require(len(paths) <= MAX_FILES, 'source_count_bound')
    data, total = {}, 0
    for p in sorted(paths):
        b = public_read(p)
        total += len(b)
        require(total <= MAX_TOTAL, 'source_bytes_bound')
        data[p] = b
    validate_source_closure(data)
    hashes = {p: sha(b) for p, b in data.items()}
    require(hashes[INGRESS_CONFIG] == INGRESS_CONFIG_SHA, 'ingress_public_config_changed')
    require(hashes['server/deploy/trust/db-signing-key.pub.pem'] == PEM_SHA, 'anchor_changed')
    require(POLICY.encode() in data['server/api/src/worker/cve-db-policy.mjs'], 'cve14_source_missing')
    return data, hashes, sha(canonical(hashes))


def stable_inventory():
    first, first_hashes, first_sha = inventory()
    second, second_hashes, second_sha = inventory()
    require(first_hashes == second_hashes and first_sha == second_sha, 'source_changed_during_inventory')
    return second, second_hashes, second_sha


def history():
    parsed = {}
    for p, expected in PROOFS.items():
        raw = public_read(p)
        require(sha(raw) == expected, 'historical_proof_changed')
        parsed[p] = json.loads(raw)
    e = parsed['server/deploy/proof/cve-advisory-evidence.json']
    report = next(r for r in e['reports'] if r['name'] == 'archive-combined')
    receipt = e['companions']['archive-combined']['receipt']
    require(report['dbStored'] == DB and report['checks'] == CHECKS and
            all(receipt[k] == v for k, v in TARGET.items()), 'historical_identity_changed')
    return receipt


# All generated JS runs ONLY in the newly built OWN image. Relative imports are
# absolute to copied /app sources; no host/private helper is loaded.
JS_COMMON = r"""
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {createHash,createPublicKey} from 'node:crypto';
const c=x=>Array.isArray(x)?'['+x.map(c).join(',')+']':x!==null&&typeof x==='object'?
 '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+c(x[k])).join(',')+'}':JSON.stringify(x);
const hash=x=>createHash('sha256').update(c(x)).digest('hex');
const bytes=b=>createHash('sha256').update(b).digest('hex');
const spec=JSON.parse(fs.readFileSync('/proof/spec.json','utf8'));
const input=()=>{const b=fs.readFileSync(0);assert(b.length<=32768);return JSON.parse(b)};
const safe=x=>console.log(JSON.stringify(x));
"""
QUALIFY_JS = JS_COMMON + r"""
import {spawnSync} from 'node:child_process';
assert.equal(process.getuid(),65532);assert.equal(process.getgid(),65532);
const map=JSON.parse(fs.readFileSync('/proof/source-map.json','utf8'));
for(const [name,expected] of Object.entries(map.files)){
 const p='/app/'+name,s=fs.lstatSync(p);assert(s.isFile()&&!s.isSymbolicLink()&&s.size<=4194304);
 assert.equal(bytes(fs.readFileSync(p)),expected);
}
const listed=[];const walk=p=>{for(const ent of fs.readdirSync(p,{withFileTypes:true})){
 assert(!ent.isSymbolicLink());const q=p+'/'+ent.name;if(ent.isDirectory())walk(q);
 else {assert(ent.isFile());listed.push(q.slice(5));}}};
assert.deepEqual(map.sourceTrees,['server/api/src','server/runtime/src','server/broker/src']);
assert.deepEqual(map.sourceLeaves,['src/shared/api/scans/runtimeTransport.ts']);
for(const tree of map.sourceTrees){listed.length=0;walk('/app/'+tree);
 assert.deepEqual(listed.sort(),Object.keys(map.files).filter(p=>p.startsWith(tree+'/')).sort());}
for(const leaf of map.sourceLeaves)assert(Object.hasOwn(map.files,leaf));
const key=createPublicKey(fs.readFileSync('/app/server/deploy/trust/db-signing-key.pub.pem'));
assert.equal(bytes(key.export({type:'spki',format:'der'})),spec.publicSpkiSha256);
const v=spawnSync('/usr/local/bin/trivy',['--version'],{timeout:5000,maxBuffer:4096,
 env:{PATH:'/usr/local/bin:/usr/bin:/bin',HOME:'/tmp'},stdio:['ignore','pipe','ignore']});
assert.equal(v.status,0);assert.match(v.stdout.toString(),/^Version: 0\.69\.3\r?$/m);
const counters=Object.fromEntries(['memory.max','memory.swap.max','memory.current','memory.peak',
 'memory.events','cpu.max','pids.max'].map(k=>[k,fs.readFileSync('/sys/fs/cgroup/'+k,'utf8').trim()]));
assert.deepEqual(fs.readdirSync('/opt/release').sort(),['bundle.bin','db','descriptor.json','descriptor.sig']);
assert.deepEqual(fs.readdirSync('/opt/release/db').sort(),['metadata.json','trivy.db']);
if(process.argv[2]==='worker')for(const [k,v] of Object.entries({'memory.max':'1073741824',
 'memory.swap.max':'0','cpu.max':'100000 100000','pids.max':'128'}))assert.equal(counters[k],v);
for(const [k,v] of Object.entries(spec.off))assert.equal(process.env[k],v);
for(const p of ['/app/server/.env.local','/app/.local-auth','/app/server/api/.env','/var/run/docker.sock'])
 assert(!fs.existsSync(p));
for(const k of ['OPENROUTER_API_KEY','LLM_HISTORY_REVISION','LLM_HISTORY_AUTHORITY','NODE_OPTIONS',
 'NODE_TLS_REJECT_UNAUTHORIZED','NODE_EXTRA_CA_CERTS'])assert.equal(Object.hasOwn(process.env,k),false);
safe({sourceSnapshotSha256:map.sourceSnapshotSha256,files:Object.keys(map.files).length,
 scannerVersion:'0.69.3',publicSpkiSha256:spec.publicSpkiSha256,counters,actualUtc:new Date().toISOString()});
"""
PROVISION_JS = JS_COMMON + r"""
import {AuthStore} from '/app/server/api/src/auth/auth.store.ts';
import {ScanLedger} from '/app/server/api/src/ledger/ledger.ts';
import {QuotaLedger} from '/app/server/api/src/llm/quota-ledger.ts';
const request=input();assert.equal(request.accounts.length,3);
assert.equal(fs.readdirSync('/auth').length,0);assert.equal(fs.readdirSync('/data').length,0);
const auth=new AuthStore(),ids=[];
try{for(const account of request.accounts){const user=await auth.register(account.email,account.password);
 assert(user);ids.push(user.id);}}finally{auth.onModuleDestroy();}
const ledger=new ScanLedger('/data/ledger.sqlite');assert.equal(ledger.pending().length,0);ledger.close();
assert(!fs.existsSync('/auth/llm-usage.sqlite'));
// Explicit synthetic fixture policy; no provider activation or runtime flag changes.
const policy={revision:'cve14-disposable-quota-v1',version:'0'.repeat(64),
 user:{input:262144,output:16384,costMicros:0},scan:{input:65536,output:8192,costMicros:0},
 warningPercent:80,requestInput:65536,observationTokens:1048576,observationCostMicros:1000000,
 receiptMs:300000,replayDays:7,maxRows:100000,dbBytes:67108864,diskHeadroomBytes:134217728,
 busyMs:1000,cleanupBatch:256};
new QuotaLedger('/auth/llm-usage.sqlite',policy,Date.now,true).close();
assert(!fs.existsSync('/auth/llm-history.sqlite'));safe({ids}); // captured privately, NEVER evidence
"""
ADMISSION_JS = JS_COMMON + r"""
import {createRequire} from 'node:module';
const Database=createRequire('/app/server/api/package.json')('better-sqlite3');
const {scanId,subject}=input();const db=new Database('/data/ledger.sqlite',{readonly:true,fileMustExist:true});
db.pragma('query_only=ON');try{safe(db.transaction(()=>{
 assert.equal(db.pragma('user_version',{simple:true}),14);
 const row=db.prepare('SELECT s.state,o.attempts,o.delivered_at,p.policy,p.result_contract_version,e.binding FROM scans s JOIN outbox o ON o.scan_id=s.id JOIN scan_cve_policy p ON p.scan_id=s.id JOIN scan_execution_profiles e ON e.scan_id=s.id WHERE s.id=? AND s.subject=?').get(scanId,subject);
 assert(row);assert(['queued','running','completed'].includes(row.state));assert(row.attempts>=0&&row.attempts<=1);
 assert.equal(row.policy,spec.dbPolicyName);assert.equal(row.result_contract_version,2);
 assert.deepEqual(JSON.parse(row.binding),spec.binding);
 return {state:row.state,attempts:row.attempts,outboxPresent:true,profilePresent:true,
  policy:row.policy,resultContractVersion:2,actualUtc:new Date().toISOString()};
 })());}finally{db.close();}
"""
READY_JS = r"""
import{chainReady}from'/app/server/api/src/scans/scan-readiness.ts';
import{localWorkerReady}from'/app/server/api/src/oci/nginx-local-profile.ts';
console.log(JSON.stringify({ready:await chainReady()&&await localWorkerReady()}));
"""
# Observe only OWN worker PID namespace. No raw argv/env/path is written or emitted.
OBSERVER_JS = JS_COMMON + r"""
const end=Date.now()+180000,seen=new Map();
while(Date.now()<end&&seen.size<3){
 for(const name of fs.readdirSync('/proc')){if(!/^\d+$/.test(name))continue;
  let args;try{args=fs.readFileSync('/proc/'+name+'/cmdline').toString().split('\0').filter(Boolean)}catch{continue}
  if(args[0]!=='/usr/local/bin/trivy'||args[1]!=='image')continue;
  assert.equal(args.length,17);
  const archive=args[3];assert.match(archive,/^\/tmp\/trivy\/jobs\/[a-f0-9-]{36}\/image.tar$/);
  const dir=archive.slice(0,-10),scanner=args[5],format=args[7];
  const check=format==='cyclonedx'?'sbom':scanner;assert(['secret','sbom','vuln'].includes(check));
  assert.deepEqual(args,['/usr/local/bin/trivy','image','--input',archive,'--scanners',
   check==='sbom'?'secret':check,'--format',check==='sbom'?'cyclonedx':'json','--list-all-pkgs',
   '--skip-db-update','--skip-java-db-update','--offline-scan','--cache-dir',dir+'/cache',
   '--timeout','120s','--quiet']);
  let environment;try{environment=fs.readFileSync('/proc/'+name+'/environ').toString().split('\0').filter(Boolean)}catch{continue}
  const env=Object.fromEntries(environment.map(v=>{const i=v.indexOf('=');return[v.slice(0,i),v.slice(i+1)]}));
  assert.deepEqual(env,{PATH:'/usr/local/bin:/usr/bin:/bin',HOME:dir,TMPDIR:dir});
  seen.set(check,{check,argvSha256:hash(args),minimalEnvironment:true,offline:true});
 }
 await new Promise(r=>setTimeout(r,20));
}
const value={complete:seen.size===3,observations:[...seen.values()].sort((a,b)=>a.check<b.check?-1:1),
 actualUtc:new Date().toISOString()};
fs.writeFileSync('/data/cve14-observed.json',JSON.stringify(value),{mode:0o600,flag:'wx'});
"""
SQL_JS = JS_COMMON + r"""
import {createRequire} from 'node:module';
const Database=createRequire('/app/server/api/package.json')('better-sqlite3');
import {validateArchiveReport} from '/app/server/api/src/worker/archive-result-contract.ts';
import {validateDbPolicyReceipt,operatorUsableUntil,CURRENT_DB_POLICY} from '/app/server/api/src/worker/cve-db-policy.mjs';
const {scanId,subject}=input();
const db=new Database('/data/ledger.sqlite',{readonly:true,fileMustExist:true});db.pragma('query_only=ON');
let result;
try{result=db.transaction(()=>{
 assert.equal(db.pragma('user_version',{simple:true}),14);assert.equal(db.pragma('integrity_check',{simple:true}),'ok');
 assert.equal(db.pragma('foreign_key_check').length,0);
 for(const t of ['scans','outbox','scan_execution_profiles','scan_cve_policy','scan_archive_results'])
  assert.equal(db.prepare('SELECT count(*) n FROM '+t).get().n,1);
 const row=db.prepare('SELECT * FROM scans WHERE id=? AND subject=?').get(scanId,subject);assert(row);
 for(const k of ['registry','repository','digest','platform'])assert.equal(row[k],spec.target[k]);
 assert.equal(row.state,'completed');assert(row.terminal_at);assert.equal(row.scope,'image');
 assert.equal(row.checks,JSON.stringify(spec.checks));
 const outbox=db.prepare('SELECT * FROM outbox WHERE scan_id=?').get(scanId);
 assert.equal(outbox.attempts,1);assert(outbox.delivered_at);assert.equal(outbox.lease_until,null);
 const policy=db.prepare('SELECT policy,result_contract_version FROM scan_cve_policy WHERE scan_id=?').get(scanId);
 assert.deepEqual(policy,{policy:CURRENT_DB_POLICY,result_contract_version:2});
 const binding=JSON.parse(db.prepare('SELECT binding FROM scan_execution_profiles WHERE scan_id=?').get(scanId).binding);
 assert.deepEqual(binding,spec.binding);
 const saved=db.prepare('SELECT attempt,report FROM scan_archive_results WHERE scan_id=?').get(scanId);
 assert.equal(saved.attempt,outbox.attempts);const report=JSON.parse(saved.report);
 validateArchiveReport(report,spec.checks,CURRENT_DB_POLICY);
 assert.equal(report.scannerVersion,'0.69.3');assert.deepEqual(report.vuln.db,spec.db);
 validateDbPolicyReceipt(report.vuln.db,report.vuln.dbPolicy,report.checkedAt,CURRENT_DB_POLICY);
 assert.equal(operatorUsableUntil(report.vuln.db),spec.usableUntil);
 for(const k of spec.checks)assert.equal(report[k].outcome,'checked');
 for(const [k,v] of Object.entries(spec.historicalReceipt))assert.deepEqual(report.receipt[k],v);
 assert.equal(report.vuln.os.outcome,'checked');
 assert.deepEqual(report.vuln.node,{outcome:'unsupported',reason:'NODE_INVENTORY_ABSENT'});
 const terminal=db.prepare("SELECT count(*) n FROM scan_events WHERE scan_id=? AND state IN ('completed','partial','failed','cancelled')").get(scanId);
 assert.equal(terminal.n,1);
 const ids=report.vuln.findings.map(f=>f.findingId);assert.equal(new Set(ids).size,ids.length);
 const findings=[...report.vuln.findings].sort((a,b)=>a.findingId<b.findingId?-1:1);
 const tuples=report.sbom.sbom.components.map(x=>[x.ecosystem,x.name,x.version]).sort((a,b)=>c(a)<c(b)?-1:1);
 assert(ids.length>0&&tuples.length>0);assert.equal(new Set(tuples.map(c)).size,tuples.length);
 const schema=db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name").all();
 const stable={};for(const {name} of schema.filter(x=>x.type==='table')){
  assert.match(name,/^[a-zA-Z0-9_]+$/);const rows=db.prepare('SELECT * FROM "'+name+'"').all();assert(rows.length<=10000);
  stable[name]={count:rows.length,sha256:hash(rows.map(hash).sort())};
 }
 return {scanId,attempts:1,schema:14,atomicTerminal:true,policy,binding,receipt:report.receipt,
  workerCheckedAt:report.checkedAt,dbPolicy:report.vuln.dbPolicy,db:report.vuln.db,
  usableUntil:operatorUsableUntil(report.vuln.db),findingsSha256:hash(findings),
  findingIdsSha256:hash(ids.sort()),cveCount:ids.length,sbomTuplesSha256:hash(tuples),sbomCount:tuples.length,
  secretFindingsSha256:hash(report.secret.findings),secretCount:report.secret.findings.length,
  logicalLedgerSha256:hash({schema,tables:stable}),storedReportSha256:hash(report)};
 })();}finally{db.close();}
const quota='/auth/llm-usage.sqlite',q=new Database(quota,{readonly:true,fileMustExist:true});
try{assert.equal(q.pragma('integrity_check',{simple:true}),'ok');assert.equal(q.pragma('application_id',{simple:true}),1145655601);
 assert.equal(q.pragma('user_version',{simple:true}),1);assert.equal(q.prepare('SELECT count(*) n FROM quota_attempt').get().n,0);
 result.quotaSha256=bytes(fs.readFileSync(quota));}finally{q.close();}
assert(!fs.existsSync('/auth/llm-history.sqlite'));
safe(result);
"""
GATEWAY_QUALIFY = "import hashlib,json,pathlib; print(json.dumps({'proxySha256':hashlib.sha256(pathlib.Path('/opt/gateway/proxy.py').read_bytes()).hexdigest()}))"


def dockerfile(base, hashes):
    deps = {p: hashes[p] for p in INPUTS[:4]}
    check = "console.log('CVE14_BUILD_PHASE:dependency-manifests');const f=require('node:fs'),c=require('node:crypto');for(const[p,h]of Object.entries(" + json.dumps(deps) + ")){let b;try{b=f.readFileSync('/app/'+p)}catch{throw Error('dependency_manifest_unavailable')}if(c.createHash('sha256').update(b).digest('hex')!==h)throw Error('dependency_drift')}"
    trees = ' '.join('/app/' + p for p in SOURCE_TREES)
    replace = 'RUN rm -rf ' + trees + '\n'
    replace += ''.join('COPY ' + p + ' /app/' + p + '\n' for p in SOURCE_TREES + SOURCE_LEAVES)
    return ('FROM ' + base + '\nUSER 0:0\nWORKDIR /app\nRUN node -e ' + json.dumps(check) + '\n'
            + replace +
            'COPY server/api/tsconfig.json /app/server/api/tsconfig.json\n'
            'COPY server/deploy/trust/db-signing-key.pub.pem /app/server/deploy/trust/db-signing-key.pub.pem\n'
            'COPY proof /proof\nRUN chmod -R a+rX /proof ' + trees + ' && '
            'chmod a+r /app/server/api/tsconfig.json /app/server/deploy/trust/db-signing-key.pub.pem ' +
            ' '.join('/app/' + p for p in SOURCE_LEAVES) + ' && '
            'chmod a+rx /app/server/runtime /app/server/broker /app/src /app/src/shared '
            '/app/src/shared/api /app/src/shared/api/scans\n'
            'RUN echo CVE14_BUILD_PHASE:api-typecheck && pnpm --filter @diplom/scan-api typecheck\n'
            'RUN echo CVE14_BUILD_PHASE:sqlite-abi && node -e "require(\'./server/api/node_modules/better-sqlite3\')(\':memory:\').close()"\n'
            'WORKDIR /app/server/api\nUSER 65532:65532\nENTRYPOINT []\n'
            'CMD ["node","--import","tsx","src/oci/nginx-local.main.ts"]\n')


def plan(hashes, source_sha):
    return {'kind': 'cve14-combined-executable-candidate', 'executed': False,
            'scriptSha256': sha(SELF.read_bytes()), 'sourceSnapshotSha256': source_sha,
            'sourceFiles': hashes, 'sourceHashConvention': 'SHA256(sorted-key compact UTF8 path->SHA256 map)',
            'sourceTrees': SOURCE_TREES, 'sourceLeaves': SOURCE_LEAVES,
            'buildDiagnostic': {'mode':'--diagnose-build','budgetSeconds':DIAGNOSTIC_SECONDS,
                                'commandSeconds':BUILD_SECONDS,'outputBytes':BUILD_OUTPUT_CAP,
                                'rows':DIAGNOSTIC_ROWS,'tsCodes':TS_CODES,
                                'noReleaseGatewayPortComposeOrRuntime':True,
                                'requiresExactScriptSourceContextAndNewScratch':True},
            'daemonBindSource': {'argument':'--daemon-bind-source-prefix','default':'',
                                 'allowed':['','/host_mnt'],'optInContext':'desktop-linux',
                                 'requiresUnixLinuxDaemon':True,'optInHostRoot':'/Users/',
                                 'exactPairsOnly':True,'authenticatedMountedBytesBeforeClaim':True},
            'daemonBindPolicy': {'argument':'--daemon-bind-source-policy','default':'',
                                 'allowed':['',DESKTOP_BIND_POLICY],'exclusiveWithPrefix':True,
                                 'optInContext':'desktop-linux','requiresUnixLinuxDaemon':True,
                                 'optInHostRoot':'/Users/','oneExactChoicePerDestination':True,
                                 'authenticatedMountedBytesBeforeClaim':True},
            'composeDiagnostic': {'phases':COMPOSE_PHASES,'commandSeconds':15,
                                  'captureBytes':COMPOSE_CAPTURE_CAP,'scanBytes':COMPOSE_DIAGNOSTIC_SCAN_BYTES,
                                  'outputBytes':COMPOSE_DIAGNOSTIC_CAP,'publicFields':COMPOSE_PUBLIC_FIELDS,
                                  'noRawOutputOrAdditionalCommands':True},
            'protocolDiagnostic': {'outputBytes':PROTOCOL_DIAGNOSTIC_CAP,'subphases':PROTOCOL_SUBPHASES,
                                   'httpStages':HTTP_STAGES,'exceptionClasses':PROTOCOL_EXCEPTION_CLASSES,
                                   'httpOperations':HTTP_OPERATIONS,'errnoClasses':HTTP_ERRNO_CLASSES,
                                   'cleanupFailureRows':3,'primaryExceptionPreserved':True},
            'ingress': {'imageArgument':'--ingress-image','requiredExactImage':INGRESS,
                        'publicSource':INGRESS_CONFIG,'configSha256':INGRESS_CONFIG_SHA,
                        'scratchCopy':INGRESS_COPY,'mountDestination':INGRESS_DEST,
                        'unchangedPublicBytes':True,'mountedHashRequired':True,
                        'composeBindRepresentations':['explicit-false','empty-bind-map'],
                        'composeBindRequiresGeneratedFalseAndQualifiedCopy':True,
                        'composeBindIsNotMountedIdentity':True,
                        'composeMemoryRepresentations':['exact-integer','exact-decimal-string'],
                        'composeMemoryRepresentationIsNotRuntimeQualification':True,
                        'nativeQualification':['nginx -v','nginx -t'],
                        'apiNetworks':['auth_internal','scan_internal'],'apiPublishedPorts':[],
                        'webNetworks':['auth_internal','web_edge'],'publishedPort':'127.0.0.1:18083:8080',
                        'finalOverrideSha256':sha(PORT_OVERRIDE),'requiresComposeOverrideSupport':True,
                        'user':'101:101','readonly':True,'caps':'ALL dropped','tmpfs':INGRESS_TMPFS,
                        'securityOptSource':'pinned compose.stand.yaml; exact resolved/runtime guards unchanged',
                        'memory':268435456,'swap':0,'cpu':1,'pids':128,
                        'resourceCounts':RESOURCE_LIMITS,'runtimeAndHistoryIngressFlags':0,
                        'initialHostGetAttempts':1,'recreatedHostGetAttempts':12,
                        'recreatedHostGetSeconds':15,'transientStatuses':[502,503,504],
                        'hostGetRoute':'/api/v1/auth/me','requiredStatus':401,'noStore':True,
                        'noPostResendOrExecHttp':True,'noBrowserHostPortAcceptanceClaim':True},
            'commitRequired': False, 'immutableDependencyBase': WORKER,
            'freshSourceForApiAndConsumer': True, 'target': TARGET, 'binding': BINDING,
            'checks': CHECKS, 'db': DB, 'publicSpkiSha256': SPKI_SHA, 'usableUntil': UNTIL,
            'origin': ORIGIN, 'composition': ['server/deploy/' + p for p in BASES],
            'gateway': 'parent-pinned cached production image; unchanged CONNECT policy/source; no URL-forwarding semantics',
            'budgetSeconds': TOTAL_SECONDS, 'workerResources': {'memory': 1073741824, 'swap': 0, 'cpu': 1, 'pids': 128},
            'runtimeFlags': OFF, 'noUiOrModel': True, 'noPrivateHelpersOrEnvRead': True,
            'executionRequirements': ['exact script/source hash approval', 'explicit LOCAL Docker context (unix endpoint)',
                                      'existing unchanged release absolute path', 'cached gateway exact sha256 image ID',
                                      'explicit approved cached ingress exact sha256 image ID',
                                      'port18083 free checked only AFTER approval', 'new exclusive absolute scratch outside repo'],
            'failurePolicy': 'stop exact OWN containers; retain own volumes/resources and private recovery manifest; nonzero sealed evidence',
            'successPolicy': 'remove verified OWN exact containers/networks/volumes; unique image tags/cache retained',
            'limitations': ['not executed/qualified yet', 'HTTP owner report/recreation, not DOM/Chromium',
                            'no separately invoked companion/full scanner-stdout baseline; real worker process observed',
                            'no LIVE preservation measurements or existing LIVE-account acceptance',
                            'Node inventory unsupported; no npm-positive claim', 'no independent Aqua publisher signature',
                            'registry image downloads through approved gateway may consume bandwidth/rate limits']}


def plain_absolute(text):
    p = Path(text)
    require(p.is_absolute() and p == p.resolve() and not any(ch in text for ch in ',\r\n'), 'unsafe_absolute_path')
    for q in [*reversed(p.parents), p]:
        require(not q.is_symlink(), 'linked_absolute_path')
    return p


def release_layout(release):
    # Metadata ONLY on the explicitly approved PUBLIC release, before any mount.
    # Reject extra files (including any private key/env), links and writable bytes;
    # never open a signing key or infer a path from an operator environment file.
    require({e.name for e in os.scandir(release)} == {'descriptor.json','descriptor.sig','bundle.bin','db'},
            'release_layout_not_public_only')
    dbdir = release/'db'
    require(stat.S_ISDIR(dbdir.lstat().st_mode) and
            {e.name for e in os.scandir(dbdir)} == {'metadata.json','trivy.db'}, 'release_db_layout')
    for directory in (release,dbdir):
        require(not directory.lstat().st_mode & 0o222, 'release_directory_writable')
    limits={'descriptor.json':4096,'descriptor.sig':64,'bundle.bin':512*1024**2,
            'db/metadata.json':4096,'db/trivy.db':2*1024**3}
    for relative,limit in limits.items():
        st=(release/relative).lstat()
        require(stat.S_ISREG(st.st_mode) and not st.st_mode & 0o222 and 0<st.st_size<=limit,
                'release_file_layout_or_mode')


def validate_bind_source_prefix(prefix, context):
    require(prefix in ('', '/host_mnt'), 'unsupported_daemon_bind_source_prefix')
    require(not prefix or context == 'desktop-linux', 'daemon_bind_prefix_context_refused')


def release_bind_pairs(release, role, prefix=''):
    # Construct expectations only; never strip/resolve a reported daemon source.
    require(prefix in ('', '/host_mnt'), 'unsupported_daemon_bind_source_prefix')
    require(role in ('api','worker','egress'), 'unsafe_container_role')
    if prefix:
        require(release.parts[:2] == ('/', 'Users') and len(release.parts) >= 4 and
                '..' not in release.parts, 'daemon_bind_prefix_host_path_refused')
    pairs = {(prefix + str(release), '/opt/release')} if role != 'egress' else set()
    if role == 'worker': pairs.add((prefix + str(release / 'db'), '/tmp/trivy/db'))
    return pairs


def validate_bind_source_policy(policy, prefix, context):
    require(policy in ('', DESKTOP_BIND_POLICY), 'unsupported_daemon_bind_source_policy')
    require(not policy or not prefix, 'daemon_bind_policy_prefix_conflict')
    require(not policy or context == 'desktop-linux', 'daemon_bind_policy_context_refused')


def release_bind_candidates(release, role, prefix='', policy=''):
    require(policy in ('', DESKTOP_BIND_POLICY), 'unsupported_daemon_bind_source_policy')
    require(not policy or not prefix, 'daemon_bind_policy_prefix_conflict')
    # Both alternatives are constructed from the approved host path; observed
    # daemon paths are matched verbatim, never stripped or normalized.
    prefixes = ('','/host_mnt') if policy else (prefix,)
    return {pair:('host-mnt' if candidate_prefix else 'literal')
            for candidate_prefix in prefixes
            for pair in release_bind_pairs(release,role,candidate_prefix)}


def validate_local_daemon(runner, context):
    runner.local_daemon_validated = False
    require(runner.docker == ['docker','--context',context], 'daemon_context_mismatch')
    require(runner.text(['context','inspect',context,'--format','{{.Endpoints.docker.Host}}']).startswith('unix://'),
            'nonlocal_docker_context')
    require(runner.text(['info','--format','{{.OSType}}'],seconds=10) == 'linux', 'linux_daemon_required')
    runner.local_daemon_validated = True


def approve(args, proposal):
    # This gate precedes ANY Docker, socket/port check, scratch creation or release metadata read.
    require(args.reviewed_script_sha256 == proposal['scriptSha256'], 'script_not_approved')
    require(args.reviewed_source_sha256 == proposal['sourceSnapshotSha256'], 'source_not_approved')
    require(args.docker_context and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', args.docker_context), 'context_required')
    prefix, policy = getattr(args,'daemon_bind_source_prefix',''), getattr(args,'daemon_bind_source_policy','')
    validate_bind_source_prefix(prefix,args.docker_context)
    validate_bind_source_policy(policy,prefix,args.docker_context)
    require(getattr(args,'ingress_image',None) == INGRESS, 'cached_ingress_pin_required')
    require(args.gateway_image and IMAGE.fullmatch(args.gateway_image), 'cached_gateway_pin_required')
    require(args.release_dir and args.scratch_dir, 'explicit_paths_required')
    release, scratch = plain_absolute(args.release_dir), plain_absolute(args.scratch_dir)
    release_bind_candidates(release,'api',prefix,policy)
    require(stat.S_ISDIR(release.lstat().st_mode), 'release_directory_missing')
    release_layout(release)
    require(not scratch.exists() and scratch.parent.is_dir() and not scratch.is_relative_to(ROOT), 'scratch_not_new')
    require(not scratch.is_relative_to(release) and not release.is_relative_to(scratch), 'release_scratch_overlap')
    mode = scratch.parent.stat().st_mode
    require(not mode & 0o022 or mode & stat.S_ISVTX, 'unsafe_scratch_parent')
    return release, scratch


def build_diagnostics(stdout, stderr, paths, code, termination=None):
    """Reduce bounded OWN build capture to finite labels and exact approved source paths."""
    require(len(stdout) + len(stderr) <= BUILD_OUTPUT_CAP, 'diagnostic_input_bound')
    require(termination in (None, 'command_timeout', 'command_output_bound', 'protocol_deadline'),
            'invalid_diagnostic_termination')
    allowed = {p for p in paths if source_path(p)}
    phases, classes, rows = set(), set(), set()
    count, truncated = 0, False
    diagnostic = re.compile(r'^([A-Za-z0-9_./-]{1,256})\(([0-9]{1,6}),([0-9]{1,6})\): error (TS[0-9]{4,5}):')
    for capture in (stdout, stderr):
        for raw in capture.splitlines():
            count += 1
            if count > DIAGNOSTIC_LINES:
                truncated = True
                break
            if len(raw) > DIAGNOSTIC_LINE_BYTES:
                truncated = True
                continue
            line = raw.decode('utf8', errors='replace')
            line = re.sub(r'^#[0-9]{1,6} [0-9]{1,6}(?:\.[0-9]{1,6})? ', '', line)
            if line in ('CVE14_BUILD_PHASE:dependency-manifests', 'CVE14_BUILD_PHASE:api-typecheck',
                        'CVE14_BUILD_PHASE:sqlite-abi'):
                phases.add(line.split(':', 1)[1])
            if line == 'Error: dependency_drift': classes.add('dependency_manifest_mismatch')
            if line == 'Error: dependency_manifest_unavailable': classes.add('dependency_manifest_unavailable')
            match = diagnostic.match(line)
            if not match:
                continue
            path, row, column, ts_code = match.groups()
            resolved = posixpath.normpath(path[5:] if path.startswith('/app/') else path if path in allowed else
                                          posixpath.join('server/api', path))
            # No messages, import specifiers, arbitrary paths or unknown diagnostic codes escape.
            if resolved not in allowed or ts_code not in TS_CODES:
                continue
            entry = (resolved, int(row), int(column), ts_code)
            if len(rows) < DIAGNOSTIC_ROWS: rows.add(entry)
            elif entry not in rows: truncated = True
    if code != 0:
        if termination: classes.add(termination)
        if 'sqlite-abi' in phases: classes.add('sqlite_abi_failed')
        elif 'api-typecheck' in phases: classes.add('api_typecheck_failed')
        if rows: classes.add('typescript_diagnostics')
        if not classes: classes.add('unclassified_build_failure')
    return {'version':1,'exitCode':code if type(code) is int and -255 <= code <= 255 else None,
            'observedPhases':sorted(phases),'classifications':sorted(classes),
            'typescript':[{'path':p,'line':r,'column':c,'code':t} for p,r,c,t in sorted(rows)],
            'truncated':truncated,'rawOutputIncluded':False}


def compose_config_diagnostics(stdout, stderr, code, phase, termination=None):
    require(phase in COMPOSE_PHASES and len(stdout)+len(stderr) <= COMPOSE_CAPTURE_CAP and
            termination in (None,'command_timeout','command_output_bound','protocol_deadline'),
            'invalid_compose_diagnostic_scope')
    result = {'version':1,'phase':phase,'exitCode':code if type(code) is int and -255 <= code <= 255 else None,
              'captureBytes':len(stdout)+len(stderr),'truncated':len(stdout)+len(stderr) > COMPOSE_DIAGNOSTIC_SCAN_BYTES,
              'classification':'config_command_succeeded' if code == 0 else 'unclassified_compose_failure',
              'publicService':None,'publicField':None,'jsonValid':None,'rawOutputIncluded':False}
    if termination:
        result['classification'] = termination
    elif code != 0:
        raw = (stderr+b'\n'+stdout)[:COMPOSE_DIAGNOSTIC_SCAN_BYTES].decode('utf8',errors='replace')
        services, fields = '|'.join(map(re.escape,COMPOSE_PUBLIC_SERVICES)), '|'.join(map(re.escape,COMPOSE_PUBLIC_FIELDS))
        match = re.search(r'\bservices\.('+services+r')\.('+fields+r')\b',raw)
        if match and any(token in raw.lower() for token in ('must be','invalid type','is not allowed','additional property')):
            result.update(classification='compose_public_schema_field_refused',publicService=match[1],publicField=match[2])
            if match[2] == 'security_opt' and re.search(
                    re.escape(match[0])+r' array items\[[0-9]{1,3},[0-9]{1,3}\] must be unique\b',raw):
                result['classification'] = 'compose_security_opt_duplicate'
        elif '!override' in raw and any(token in raw.lower() for token in ('unknown tag','unsupported tag','could not determine a constructor')):
            result['classification'] = 'compose_override_tag_unsupported'
    require(len(canonical(result)) <= COMPOSE_DIAGNOSTIC_CAP,'compose_diagnostic_bound')
    return result


class Runner:
    """Bounded subprocess IO; never prints argv/env/stdout/stderr or arbitrary exception text."""
    def __init__(self, context, started):
        self.docker = ['docker', '--context', context]
        self.local_daemon_validated = False
        self.started = started
        self.work_deadline, self.total_deadline = started + WORK_SECONDS, started + TOTAL_SECONDS
        self.environment = {k: os.environ[k] for k in ('PATH', 'HOME') if k in os.environ}
        self.calls = 0
        self.last_build_diagnostics = None
        self.last_initializer_log_codes = None
        self.last_json_error_class = None
        self.last_nginx_diagnostic = None
        self.last_compose_diagnostics = None

    def nginx(self, cid, kind):
        require(kind in ('version','syntax'), 'unsafe_nginx_diagnostic_scope')
        self.last_nginx_diagnostic = None
        self.run(['exec',cid,'nginx','-v' if kind == 'version' else '-t'],
                 seconds=5,cap=8192,nginx_kind=kind)
        return self.last_nginx_diagnostic

    def initializer_log(self, cid):
        self.last_initializer_log_codes = None
        self.run(['logs','--tail','64',cid],seconds=2,cap=INIT_LOG_CAP,initializer_log=True)
        return self.last_initializer_log_codes

    def build(self, context, image_tag, platform, hashes):
        return self.run(['build','--network','none','--pull=false','--progress=plain',
                         '--platform',platform,'-t',image_tag,str(context)],
                        seconds=BUILD_SECONDS,cap=BUILD_OUTPUT_CAP,build_paths=tuple(hashes))

    def run(self, args, seconds=15, data=None, cap=2 * 1024 ** 2, cleanup=False, check=True, env=None,
            build_paths=None, initializer_log=False, nginx_kind=None, compose_phase=None):
        if compose_phase is not None:
            require(compose_phase in COMPOSE_PHASES and len(args) == 18 and
                    args[:2] == ['compose','--project-name'] and
                    re.fullmatch(r'dip-cve14-proof-[a-f0-9]{16}',args[2]) and args[3] == '--env-file' and
                    args[5:15:2] == ['-f'] * 5 and args[-3:] == ['config','--format','json'] and
                    seconds == 15 and cap == COMPOSE_CAPTURE_CAP and data is None and not cleanup and check and
                    env is None and build_paths is None and not initializer_log and nginx_kind is None,
                    'unsafe_compose_diagnostic_scope')
            scratch = Path(args[4]).parent
            require(scratch.is_absolute() and '..' not in scratch.parts and args[4] == str(scratch/'own.env') and
                    args[6:15:2] == [str(scratch/name) for name in (*BASES,'isolation.json','ports.override.yaml')],
                    'unsafe_compose_diagnostic_scope')
            self.last_compose_diagnostics = None
        if nginx_kind is not None:
            require(nginx_kind in ('version','syntax') and len(args) == 4 and
                    args == ['exec',args[1],'nginx','-v' if nginx_kind == 'version' else '-t'] and
                    HEX.fullmatch(args[1]) and seconds == 5 and cap == 8192 and
                    data is None and not cleanup and env is None and build_paths is None and
                    not initializer_log, 'unsafe_nginx_diagnostic_scope')
        if initializer_log:
            require(len(args) == 4 and args[:3] == ['logs','--tail','64'] and HEX.fullmatch(args[3]) and
                    seconds == 2 and cap == INIT_LOG_CAP and data is None and not cleanup and
                    env is None and build_paths is None, 'unsafe_initializer_diagnostic_scope')
        if build_paths is not None:
            require(args[:5] == ['build','--network','none','--pull=false','--progress=plain'] and
                    seconds == BUILD_SECONDS and cap == BUILD_OUTPUT_CAP and data is None and
                    not cleanup and env is None, 'unsafe_build_diagnostic_scope')
        deadline = min(time.monotonic() + seconds, self.total_deadline if cleanup else self.work_deadline)
        require(deadline > time.monotonic(), 'protocol_deadline')
        self.calls += 1
        process = subprocess.Popen(self.docker + list(args), cwd=ROOT, env=env or self.environment,
                                   stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        buffers = {'stdout': bytearray(), 'stderr': bytearray()}
        termination = None
        try:
            with selectors.DefaultSelector() as selector:
                for name, stream in [('stdout', process.stdout), ('stderr', process.stderr)]:
                    os.set_blocking(stream.fileno(), False); selector.register(stream, selectors.EVENT_READ, name)
                if data is not None:
                    require(len(data) <= 32768, 'stdin_bound')
                    os.set_blocking(process.stdin.fileno(), False)
                    selector.register(process.stdin, selectors.EVENT_WRITE, 'stdin'); offset = 0
                while selector.get_map():
                    require(time.monotonic() < deadline, 'command_timeout')
                    for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                        if key.data == 'stdin':
                            offset += os.write(key.fileobj.fileno(), data[offset:])
                            if offset == len(data):
                                selector.unregister(key.fileobj); key.fileobj.close()
                        else:
                            chunk = os.read(key.fileobj.fileno(), 65536)
                            if chunk:
                                require(sum(map(len, buffers.values())) + len(chunk) <= cap, 'command_output_bound')
                                buffers[key.data].extend(chunk)
                            else:
                                selector.unregister(key.fileobj); key.fileobj.close()
            code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            if check:
                require(code == 0, 'isolated_command_failed')
            return bytes(buffers['stdout']), code
        except Refusal as error:
            if str(error) in ('command_timeout','command_output_bound','protocol_deadline'):
                termination = str(error)
            raise
        finally:
            if process.poll() is None:
                # The CLI/plugin process group belongs only to this bounded invocation.
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                try: process.wait(timeout=0.5)
                except subprocess.TimeoutExpired: pass
            if compose_phase is not None:
                self.last_compose_diagnostics = compose_config_diagnostics(
                    buffers['stdout'],buffers['stderr'],process.poll(),compose_phase,termination)
            if build_paths is not None:
                self.last_build_diagnostics = build_diagnostics(
                    buffers['stdout'],buffers['stderr'],build_paths,process.poll(),termination)
            if initializer_log:
                self.last_initializer_log_codes = initializer_log_codes(buffers['stdout'],buffers['stderr'])
            if nginx_kind is not None:
                self.last_nginx_diagnostic = nginx_diagnostic(
                    nginx_kind,buffers['stdout'],buffers['stderr'],process.poll(),termination)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None: stream.close()

    def json(self, args, **kw):
        self.last_json_error_class = None
        raw, _ = self.run(args, **kw)
        try: value = json.loads(raw)
        except ValueError as error:
            self.last_json_error_class = protocol_exception_class(error)
            if kw.get('compose_phase') is not None:
                self.last_compose_diagnostics['jsonValid'] = False
            raise Refusal('invalid_private_command_json') from None
        if kw.get('compose_phase') is not None:
            self.last_compose_diagnostics['jsonValid'] = True
        return value

    def text(self, args, **kw):
        return self.run(args, **kw)[0].decode('utf8').strip()


def write_new(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out: out.write(data)


def context_files(data, hashes, source_sha, base, receipt):
    spec = {'target': TARGET, 'binding': BINDING, 'checks': CHECKS, 'db': DB, 'off': OFF,
            'historicalReceipt': receipt, 'publicSpkiSha256': SPKI_SHA, 'usableUntil': UNTIL,
            'dbPolicyName': POLICY}
    embedded = {p: hashes[p] for p in hashes if p in INPUTS[:6] or source_path(p)}
    files = {p: b for p, b in data.items() if p in embedded}
    files.update({'Dockerfile': dockerfile(base, hashes).encode(),
                  'proof/spec.json': canonical(spec),
                  'proof/source-map.json': canonical({'files': embedded, 'sourceSnapshotSha256': source_sha,
                                                                        'sourceTrees':SOURCE_TREES,'sourceLeaves':SOURCE_LEAVES}),
                  'proof/qualify.mjs': QUALIFY_JS.encode(), 'proof/provision.mjs': PROVISION_JS.encode(),
                  'proof/admission.mjs': ADMISSION_JS.encode(),
                  'proof/ready.mjs': READY_JS.encode(), 'proof/observe.mjs': OBSERVER_JS.encode(),
                  'proof/sql.mjs': SQL_JS.encode()})
    return files


def make_context(scratch, data, hashes, source_sha, base, receipt):
    files = context_files(data,hashes,source_sha,base,receipt)
    context = scratch / 'context'
    context.mkdir(mode=0o700)
    for p, b in files.items(): write_new(context / p, b)
    return context, sha(canonical({p: sha(b) for p, b in sorted(files.items())}))


INITIALIZER_JS = r"""
const fs=require('node:fs'),path='/data';
const fail=code=>{throw new Error(code)};
const directory=s=>s.isDirectory()&&!s.isSymbolicLink();
const ready=s=>directory(s)&&s.uid===65532&&s.gid===65532&&(s.mode&0o7777)===0o700;
try{
 const before=fs.lstatSync(path);
 if(!directory(before))fail('own_init_shape_refused');
 if(!ready(before)){
  if(before.uid!==0||before.gid!==0||![0o755,0o700].includes(before.mode&0o7777)||
     process.getuid()!==0||process.getgid()!==0)fail('own_init_state_refused');
  if(fs.readdirSync(path).length!==0)fail('own_init_fresh_not_empty');
  fs.chmodSync(path,0o700);fs.chownSync(path,65532,65532);
  if(!ready(fs.lstatSync(path)))fail('own_init_postcondition_failed');
 }
}catch(error){
 let code='own_init_io_failed';
 if(['own_init_shape_refused','own_init_state_refused','own_init_fresh_not_empty',
     'own_init_postcondition_failed'].includes(error?.message))code=error.message;
 else if(error?.code==='EPERM'&&error?.path===path){
  if(error.syscall==='chmod')code='own_init_chmod_eperm';
  else if(error.syscall==='chown')code='own_init_chown_eperm';
 }
 console.error('OWN_INIT_FAILURE:'+code);process.exit(1);
}
"""


def initializer_log_codes(stdout, stderr):
    require(len(stdout) + len(stderr) <= INIT_LOG_CAP, 'initializer_diagnostic_input_bound')
    markers = {'OWN_INIT_FAILURE:'+code:code for code in INIT_FAILURE_CODES}
    return sorted({markers[line] for raw in (stdout,stderr) for line in raw.decode('utf8',errors='replace').splitlines()
                   if line in markers})


def overlay(image, gateway, ids, worker_platform=None, gateway_platform=None,
            ingress=INGRESS, ingress_config=None, ingress_platform=None):
    init = INITIALIZER_JS
    services = {name: {'image': image, 'pull_policy': 'never', 'entrypoint': ['node'],
                       'command': ['-e', init], 'user': '0:0', 'read_only': True}
                for name in ('auth-volume-init', 'scan-volume-init')}
    services.update({'api': {'image': image, 'pull_policy': 'never', 'restart': 'no',
                             'ports': [],
                             'environment': {**OFF, 'SCAN_BROWSER_ALLOWED_USER_IDS': ','.join(ids[:2]),
                                             'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS': 'false',
                                             'SCAN_JWT_ISSUER': 'cve14-disposable',
                                             'SCAN_JWT_AUDIENCE': 'cve14-disposable'}},
                     'worker': {'image': image, 'pull_policy': 'never', 'restart': 'no', 'environment': OFF},
                     'egress': {'image': gateway, 'pull_policy': 'never', 'restart': 'no'}})
    if worker_platform:
        for name in ('api','worker','auth-volume-init','scan-volume-init'):
            services[name]['platform'] = worker_platform
    if gateway_platform:
        services['egress']['platform'] = gateway_platform
    services['web'] = {'image':ingress,'pull_policy':'never','restart':'no','entrypoint':['nginx'],
                       'command':['-g','daemon off;'],'user':'101:101','read_only':True,
                       # Avoid a redundant base NNP sequence; resolved/runtime guards still require it.
                       'cap_drop':['ALL'],
                       'mem_limit':'256m','memswap_limit':'256m','cpus':1,'pids_limit':128}
    if ingress_config is not None:
        services['web']['volumes'] = [{'type':'bind','source':str(ingress_config),'target':INGRESS_DEST,
                                      'read_only':True,'bind':{'create_host_path':False}}]
    if ingress_platform: services['web']['platform'] = ingress_platform
    return canonical({'services': services})


def diagnose_own_initializers(runner, project, image):
    # Selective metadata only: never serialize Config.Env, State.Error or health logs.
    require(re.fullmatch(r'dip-cve14-proof-[a-f0-9]{16}',project) and IMAGE.fullmatch(image),
            'unsafe_initializer_diagnostic_identity')
    fmt = ('{"id":{{json .Id}},"name":{{json .Name}},"project":'
           '{{json (index .Config.Labels "com.docker.compose.project")}},"service":'
           '{{json (index .Config.Labels "com.docker.compose.service")}},"image":{{json .Image}},'
           '"status":{{json .State.Status}},"exitCode":{{json .State.ExitCode}},'
           '"oomKilled":{{json .State.OOMKilled}}}')
    previous = runner.work_deadline
    runner.work_deadline = min(previous,time.monotonic()+INIT_DIAGNOSTIC_SECONDS)
    rows, unavailable = [], False
    try:
        for role in ('auth-volume-init','scan-volume-init'):
            try:
                ids = runner.text(['container','ls','-aq','--no-trunc','--filter',
                                   'label=com.docker.compose.project='+project,'--filter',
                                   'label=com.docker.compose.service='+role],seconds=2,cap=4096).split()
                require(len(ids) == 1 and HEX.fullmatch(ids[0]),'initializer_identity_unavailable')
                info = runner.json(['container','inspect','--format',fmt,ids[0]],seconds=2,cap=4096)
                require(info['id'] == ids[0] and info['project'] == project and info['service'] == role and
                        info['name'] == '/'+project+'-'+role+'-1' and info['image'] == image,
                        'foreign_initializer_refused')
                require(info['status'] in ('created','running','exited','dead') and
                        type(info['exitCode']) is int and 0 <= info['exitCode'] <= 255 and
                        type(info['oomKilled']) is bool,'invalid_initializer_state')
                codes = runner.initializer_log(ids[0]) if info['status'] == 'exited' and info['exitCode'] != 0 else []
                rows.append({'role':role,'status':info['status'],'exitCode':info['exitCode'],
                             'oomKilled':info['oomKilled'],'codes':codes})
            except (Refusal,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
                unavailable = True
    finally:
        runner.work_deadline = previous
    return {'version':1,'initializers':rows,'unavailable':unavailable,'rawOutputIncluded':False}


def owned_resources(runner, project, cleanup=False):
    selector = 'label=com.docker.compose.project=' + project
    resources = {'containers': runner.text(['container', 'ls', '-aq', '--no-trunc', '--filter', selector], cleanup=cleanup).split(),
                 'networks': runner.text(['network', 'ls', '-q', '--no-trunc', '--filter', selector], cleanup=cleanup).split(),
                 'volumes': runner.text(['volume', 'ls', '-q', '--filter', selector], cleanup=cleanup).split()}
    require_resource_counts(resources)
    return resources


def require_empty_namespace(runner, project):
    require(not any(owned_resources(runner,project).values()), 'project_collision')
    # Reject even UNLABELED pre-existing names; never adopt an existing volume.
    for kind,names in [('volume',[project+'_auth_accounts',project+'_scan_ledger']),
                       ('network',[project+'_'+n for n in ('auth_internal','scan_internal','registry_uplink','web_edge')])]:
        for name in names:
            raw,code=runner.run([kind,'inspect',name],check=False)
            require(code==1 and raw.strip()==b'[]', 'preexisting_or_unavailable_namespace')


def own_label(info, project):
    return (info.get('Config', {}).get('Labels') or info.get('Labels') or {}).get('com.docker.compose.project') == project


DB_INODE_JS = "const fs=require('node:fs');for(const n of ['trivy.db','metadata.json']){const a=fs.statSync('/opt/release/db/'+n),b=fs.lstatSync('/tmp/trivy/db/'+n);if(a.dev!==b.dev||a.ino!==b.ino||!b.isFile()||b.isSymbolicLink())process.exit(1)}console.log('same-ro-db')"


def qualify_mounted_release(runner, cid, role):
    qualification = runner.json(['exec',cid,'node','--import','tsx','/proof/qualify.mjs',role],seconds=20)
    verified = runner.json(['exec',cid,'node','--import','tsx','src/worker/verify-vuln-db-release.ts',
                            '/opt/release',DB['manifestDigest'],DB['artifactSha256']],seconds=90)
    require(verified['kind'] == 'authenticated-release-usability-only' and verified['db'] == DB and
            verified['resultContractVersion'] == 2 and verified['dbPolicy']['policy'] == POLICY and
            verified['dbPolicy']['version'] == 2 and verified['usableUntil'] == UNTIL and
            verified['scannerChecked'] is False and verified['admissionChecked'] is False,
            'authenticated_release_mismatch')
    if role == 'worker':
        require(runner.text(['exec',cid,'node','-e',DB_INODE_JS]) == 'same-ro-db', 'db_mount_identity')
    receipt = {key:verified[key] for key in ('kind','db','resultContractVersion','usableUntil')}
    receipt['dbPolicy'] = {key:verified['dbPolicy'][key] for key in ('version','policy')}
    return qualification, receipt


def verify_container(runner, cid, project, image, release, role, daemon_bind_source_prefix='', daemon_bind_source_policy=''):
    validate_bind_source_prefix(daemon_bind_source_prefix,runner.docker[2])
    validate_bind_source_policy(daemon_bind_source_policy,daemon_bind_source_prefix,runner.docker[2])
    require(not daemon_bind_source_prefix or runner.local_daemon_validated, 'daemon_bind_prefix_unvalidated')
    require(not daemon_bind_source_policy or runner.local_daemon_validated, 'daemon_bind_policy_unvalidated')
    expected_binds = release_bind_candidates(release,role,daemon_bind_source_prefix,daemon_bind_source_policy)
    require(HEX.fullmatch(cid), 'unsafe_container_id')
    info = runner.json(['container', 'inspect', cid])[0]
    require(own_label(info, project) and info['Image'] == image and
            info['Name'].startswith('/'+project+'-'), 'foreign_container_or_image')
    h, config = info['HostConfig'], info['Config']
    require(config['User'] == '65532:65532' and h['ReadonlyRootfs'] and h['CapDrop'] == ['ALL'] and
            'no-new-privileges:true' in h['SecurityOpt'], 'runtime_privilege_boundary')
    require(not h['Privileged'] and not h['PidMode'] and not h['IpcMode'].startswith('host') and
            not h.get('CapAdd') and not config.get('Entrypoint'), 'host_namespace_or_capability_forbidden')
    chosen_binds = {}
    for mount in info['Mounts']:
        if mount['Type'] == 'volume':
            require(mount['Name'] in {project + '_auth_accounts', project + '_scan_ledger'}, 'foreign_volume')
        elif mount['Type'] == 'bind':
            pair = (mount['Source'], mount['Destination'])
            require(mount['RW'] is False and pair in expected_binds and
                    mount['Destination'] not in chosen_binds, 'unsafe_bind')
            chosen_binds[mount['Destination']] = expected_binds[pair]
        else: require(mount['Type'] == 'tmpfs', 'unexpected_mount')
    require(set(chosen_binds) == {destination for _,destination in expected_binds}, 'release_bind_set_mismatch')
    nets = info['NetworkSettings']['Networks']
    expected = {'worker': {'scan_internal'}, 'api': {'auth_internal', 'scan_internal'},
                'egress': {'scan_internal', 'registry_uplink'}}[role]
    require(set(nets) == {project + '_' + n for n in expected}, 'unexpected_network')
    for name, settings in nets.items():
        net = runner.json(['network', 'inspect', settings['NetworkID']])[0]
        require(own_label(net, project) and net['Internal'] == (not name.endswith('_registry_uplink')), 'network_not_isolated')
    env = dict(v.split('=', 1) for v in config['Env'])
    for key in ('OPENROUTER_API_KEY', 'NODE_OPTIONS', 'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_EXTRA_CA_CERTS'):
        require(key not in env, 'secret_or_tls_override_present')
    if role != 'egress':
        require(all(env.get(k) == v for k, v in OFF.items()), 'runtime_flags_not_off')
        require(env.get('SCAN_VULN_MANIFEST_DIGEST') == DB['manifestDigest'] and
                env.get('SCAN_VULN_ARTIFACT_SHA256') == DB['artifactSha256'], 'runtime_pin_mismatch')
        require(env.get('SCAN_VULN_RELEASE_DIR') == '/opt/release' and env.get('SCAN_VULN_ENABLED') == 'true', 'release_not_selected')
        require(any(m['Destination'] == '/opt/release' and not m['RW'] for m in info['Mounts']), 'release_not_ro')
    if role == 'worker':
        require([h[k] for k in ('Memory', 'MemorySwap', 'NanoCpus', 'PidsLimit')] ==
                [1073741824, 1073741824, 1000000000, 128], 'worker_resource_mismatch')
        require(h['Tmpfs'] == {'/tmp': 'rw,noexec,nosuid,size=16m',
                               '/tmp/trivy': 'rw,noexec,nosuid,uid=65532,gid=65532,size=512m'}, 'worker_scratch_mismatch')
        require(any(m['Destination'] == '/tmp/trivy/db' and not m['RW'] for m in info['Mounts']), 'db_not_ro')
        require(config['Cmd'] == ['node', '--import', 'tsx', 'src/worker/nginx-local-worker.main.ts'], 'wrong_local_worker')
    if role == 'api':
        require(config['Cmd'] == ['node', '--import', 'tsx', 'src/oci/nginx-local.main.ts'], 'wrong_local_api')
    require(not h['PortBindings'], 'unexpected_published_port')
    if role == 'egress':
        require(config['Cmd'] == ['python', '-I', 'proxy.py'] and config['WorkingDir'] == '/opt/gateway',
                'wrong_production_gateway_entrypoint')
    # A daemon path representation is not proof of mounted bytes. No positive
    # isolation/equivalence receipt is returned until source + signed DB qualify.
    qualification, receipt = qualify_mounted_release(runner,cid,role) if role != 'egress' else (None,None)
    result = {'imageId': image, 'nonroot': True, 'rootReadonly': True, 'capsDropped': True,
              'ownNetworksOnly': True, 'noEngineSocketOrPrivateBind': True,'bindRepresentations':chosen_binds}
    if qualification is not None:
        result.update(sourceQualification=qualification,mountedReleaseAuthenticated=True,mountedReleaseReceipt=receipt,
                      bindRepresentation=daemon_bind_source_policy or ('explicit-host-mnt' if daemon_bind_source_prefix else 'literal'))
        if role == 'worker': result['sameDbInode'] = True
    return result


def require_resource_counts(resources, complete=False):
    require(set(resources) == set(RESOURCE_LIMITS) and all(
        len(values) == len(set(values)) and len(values) <= RESOURCE_LIMITS[k]
        for k,values in resources.items()), 'own_resource_count_bound')
    if complete:
        require({k:len(v) for k,v in resources.items()} == RESOURCE_LIMITS, 'own_resource_count_mismatch')


def ingress_bind_candidates(config_path, prefix='', policy=''):
    require(config_path.name == INGRESS_COPY, 'ingress_public_copy_path')
    # Reuse the finite Users/prefix constructor, not observed-source normalization.
    return {(source,INGRESS_DEST):representation for (source,_),representation in
            release_bind_candidates(config_path,'api',prefix,policy).items()}


def ingress_public_copy(scratch, data):
    raw = data[INGRESS_CONFIG]
    require(sha(raw) == INGRESS_CONFIG_SHA, 'ingress_public_config_changed')
    path = scratch / INGRESS_COPY
    write_new(path,raw); path.chmod(0o444)
    require(plain_absolute(str(path)) == path and stat.S_ISREG(path.lstat().st_mode) and
            path.lstat().st_mode & 0o7777 == 0o444, 'ingress_public_copy_shape')
    return path


def qualify_ingress_image(info):
    config = info['Config']
    require(info['Id'] == INGRESS and info['Os'] == 'linux' and info['Architecture'] in ('amd64','arm64'),
            'cached_ingress_image_unqualified')
    require(config.get('User') == '101:101' and
            config.get('Entrypoint') in (None,[],['/docker-entrypoint.sh'],['docker-entrypoint.sh']) and
            not config.get('OnBuild') and not config.get('Volumes'), 'cached_ingress_configuration')
    require(all(v.split('=',1)[0] in INGRESS_ENV_KEYS for v in config.get('Env',[])),
            'cached_ingress_sensitive_env')
    return info['Os']+'/'+info['Architecture']


def verify_ingress_compose_bind(volumes, config_path, generated_overlay):
    # Only the observed empty-map serialization, not a generic absent/default-false rule.
    expected = {'type':'bind','source':str(config_path),'target':INGRESS_DEST,
                'read_only':True,'bind':{'create_host_path':False}}
    require(type(volumes) is list and len(volumes) == 1 and type(volumes[0]) is dict,
            'ingress_compose_bind')
    mount = volumes[0]
    require(set(mount) == set(expected) and mount['type'] == 'bind' and
            mount['source'] == expected['source'] and mount['target'] == INGRESS_DEST and
            mount['read_only'] is True and type(mount['bind']) is dict and
            (mount['bind'] == {} or
             (set(mount['bind']) == {'create_host_path'} and mount['bind']['create_host_path'] is False)),
            'ingress_compose_bind')
    require(type(generated_overlay) is bytes and 0 < len(generated_overlay) <= 32768,
            'ingress_compose_input')
    try:
        generated = json.loads(generated_overlay)
        inputs = generated['services']['web']['volumes']
    except (ValueError,KeyError,TypeError):
        raise Refusal('ingress_compose_input') from None
    require(canonical(generated) == generated_overlay and inputs == [expected] and
            inputs[0]['read_only'] is True and inputs[0]['bind']['create_host_path'] is False,
            'ingress_compose_input')
    # execute obtains this path from the hash-pinned ingress_public_copy before either model check.
    require(config_path.name == INGRESS_COPY and plain_absolute(str(config_path)) == config_path,
            'ingress_public_copy_shape')
    info = config_path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_mode & 0o7777 == 0o444,'ingress_public_copy_shape')
    return 'empty-bind-map' if mount['bind'] == {} else 'explicit-false'


def ingress_compose_memory(value):
    # Only the confirmed Compose JSON representations of the SAME 256MiB limit.
    return ((type(value) is int and value == 268435456) or
            (type(value) is str and value == '268435456'))


def verify_ingress_topology(topology, project, image, gateway, config_path, generated_overlay=None):
    services, networks, volumes = topology['services'],topology['networks'],topology['volumes']
    expected_images = {role:image for role in ('api','worker','auth-volume-init','scan-volume-init')}
    expected_images.update(egress=gateway,web=INGRESS)
    require(topology['name'] == project and set(services) == set(expected_images) and
            set(networks) == {'auth_internal','scan_internal','registry_uplink','web_edge'} and
            set(volumes) == {'auth_accounts','scan_ledger'} and
            all(not v.get('external') and v.get('name') == project+'_'+k for k,v in volumes.items()),
            'foreign_compose_topology')
    for role,expected_image in expected_images.items():
        require(services[role]['image'] == expected_image and not services[role].get('env_file'),
                'composition_image_or_env_mismatch')
        if role != 'web': require(not services[role].get('ports'), 'unexpected_published_port')
    for role,names in {'api':{'auth_internal','scan_internal'},'worker':{'scan_internal'},
                       'egress':{'scan_internal','registry_uplink'},'web':{'auth_internal','web_edge'}}.items():
        require(set(services[role]['networks']) == names, 'compose_network_mismatch')
    for name,network in networks.items():
        require(not network.get('external') and network.get('name') == project+'_'+name and
                bool(network.get('internal',False)) == (name in ('auth_internal','scan_internal')),
                'compose_network_not_isolated')
    web = services['web']
    require(web['ports'] == [{'host_ip':'127.0.0.1','target':8080,'published':str(PORT),
                             'protocol':'tcp','mode':'ingress'}], 'ingress_port_override_required')
    bind_representation = verify_ingress_compose_bind(web['volumes'],config_path,generated_overlay)
    require(not web.get('environment') and web['entrypoint'] == ['nginx'] and
            web['command'] == ['-g','daemon off;'] and web['user'] == '101:101' and
            web['read_only'] is True and web['cap_drop'] == ['ALL'] and not web.get('cap_add') and
            web['security_opt'] == ['no-new-privileges:true'] and not web.get('privileged') and
            not web.get('pid') and not web.get('network_mode') and
            web['tmpfs'] == ['/tmp:'+INGRESS_TMPFS] and ingress_compose_memory(web['mem_limit']) and
            ingress_compose_memory(web['memswap_limit']) and float(web['cpus']) == 1 and web['pids_limit'] == 128,
            'ingress_compose_boundary')
    return bind_representation


def nginx_diagnostic(kind, stdout, stderr, code, termination=None):
    require(kind in ('version','syntax') and len(stdout)+len(stderr) <= 8192 and
            termination in (None,'command_timeout','command_output_bound','protocol_deadline'),
            'unsafe_nginx_diagnostic')
    # Exact static public native output only, never a runtime error parser.
    lines = stdout.splitlines()+stderr.splitlines()
    expected = [b'nginx version: nginx/1.27.5'] if kind == 'version' else [
        b'nginx: the configuration file /etc/nginx/nginx.conf syntax is ok',
        b'nginx: configuration file /etc/nginx/nginx.conf test is successful']
    valid = code == 0 and termination is None and lines == expected
    return {'kind':kind,'status':'qualified' if valid else 'refused','nativeExitZero':code == 0,
            'exactPublicOutput':valid,'rawOutputIncluded':False}


def verify_web_container(runner, cid, project, config_path, config_sha, prefix='', policy=''):
    validate_bind_source_prefix(prefix,runner.docker[2])
    validate_bind_source_policy(policy,prefix,runner.docker[2])
    require(not (prefix or policy) or runner.local_daemon_validated, 'daemon_bind_policy_unvalidated')
    expected = ingress_bind_candidates(config_path,prefix,policy)
    require(config_sha == INGRESS_CONFIG_SHA and HEX.fullmatch(cid), 'unsafe_ingress_identity')
    info = runner.json(['container','inspect',cid])[0]
    config, host = info['Config'],info['HostConfig']
    require(info['Id'] == cid and info['Name'] == '/'+project+'-web-1' and info['Image'] == INGRESS and
            own_label(info,project) and config['Labels'].get('com.docker.compose.service') == 'web',
            'foreign_ingress_or_image')
    require(config['User'] == '101:101' and config['Entrypoint'] == ['nginx'] and
            config['Cmd'] == ['-g','daemon off;'] and host['ReadonlyRootfs'] is True and
            host['CapDrop'] == ['ALL'] and not host.get('CapAdd') and
            host['SecurityOpt'] == ['no-new-privileges:true'] and not host['Privileged'] and
            not host['PidMode'] and not host['IpcMode'].startswith('host') and
            not host.get('Devices') and not host.get('DeviceRequests'), 'ingress_privilege_boundary')
    require(all(v.split('=',1)[0] in INGRESS_ENV_KEYS for v in config.get('Env',[])), 'ingress_private_env')
    require([host[k] for k in ('Memory','MemorySwap','NanoCpus','PidsLimit')] ==
            [268435456,268435456,1000000000,128] and host['Tmpfs'] == {'/tmp':INGRESS_TMPFS},
            'ingress_resource_boundary')
    require(host['PortBindings'] == {'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':str(PORT)}]},
            'ingress_loopback_binding')
    chosen, tmpfs_seen = {}, set()
    for mount in info['Mounts']:
        if mount['Type'] == 'bind':
            pair = mount['Source'],mount['Destination']
            require(pair in expected and mount['RW'] is False and mount['Destination'] not in chosen,
                    'unsafe_ingress_bind')
            chosen[mount['Destination']] = expected[pair]
        else:
            require(mount['Type'] == 'tmpfs' and mount['Destination'] == '/tmp' and mount['RW'] is True and
                    '/tmp' not in tmpfs_seen, 'unexpected_ingress_mount')
            tmpfs_seen.add('/tmp')
    require(set(chosen) == {INGRESS_DEST}, 'ingress_bind_set_mismatch')
    nets = info['NetworkSettings']['Networks']
    require(set(nets) == {project+'_auth_internal',project+'_web_edge'}, 'ingress_network_boundary')
    for name,settings in nets.items():
        network = runner.json(['network','inspect',settings['NetworkID']])[0]
        require(own_label(network,project) and network['Name'] == name and
                network['Internal'] is name.endswith('_auth_internal'), 'ingress_network_not_isolated')
    # Do not claim equivalence from mount metadata alone: qualify mounted bytes first.
    digest = runner.text(['exec',cid,'sha256sum',INGRESS_DEST],seconds=5,cap=256)
    require(digest == config_sha+'  '+INGRESS_DEST, 'ingress_mounted_config_mismatch')
    qualifications = [runner.nginx(cid,kind) for kind in ('version','syntax')]
    require(all(row['status'] == 'qualified' for row in qualifications), 'ingress_native_qualification_failed')
    return {'imageId':INGRESS,'configSha256':config_sha,'mountedPublicConfigVerified':True,
            'bindRepresentations':chosen,'nativeQualification':qualifications,'nonroot':True,
            'rootReadonly':True,'capsDropped':True,'ownNetworksOnly':True,'privateEnvironmentAbsent':True,
            'noEngineSocketOrPrivateBind':True,'runtimeAndHistoryIngressFlags':0}


def proxy_host_ready(http, recreated=False):
    attempts = 12 if recreated else 1
    end = min(http.runner.work_deadline,time.monotonic()+15)
    for attempt in range(1,attempts+1):
        require(time.monotonic() < end, 'ingress_readiness_deadline')
        status,headers,_ = http.call('GET','/api/v1/auth/me',proxy_readiness=True)
        require(headers.get('cache-control') == 'no-store' and 'set-cookie' not in headers,
                'ingress_readiness_contract')
        if status == 401: return {'status':401,'noStore':True,'attempts':attempt,'hostTransport':True}
        require(recreated and status in (502,503,504), 'ingress_host_not_ready')
        if attempt < attempts: time.sleep(min(0.5,max(0,end-time.monotonic())))
    raise Refusal('ingress_host_not_ready')


def protocol_exception_class(error, runner=None):
    # No message, args, raw type name, errno, partial body or traceback is serialized.
    json_class = getattr(runner,'last_json_error_class',None)
    if isinstance(error,Refusal) and json_class in ('json_decode_error','unicode_decode_error','value_error'):
        return json_class
    for kind, label in ((http.client.RemoteDisconnected,'http_disconnected'),
                        (TimeoutError,'http_timeout'),(ConnectionResetError,'connection_reset'),
                        (json.JSONDecodeError,'json_decode_error'),(UnicodeDecodeError,'unicode_decode_error'),
                        (KeyError,'missing_key'),(TypeError,'type_error'),(ValueError,'value_error'),
                        (OSError,'os_error'),(subprocess.SubprocessError,'subprocess_error')):
        if isinstance(error,kind): return label
    return 'other_protocol_error'


def http_failure_record(operation, error):
    value = error.errno if isinstance(error,OSError) else None
    label = {errno.EPERM:'EPERM',errno.EACCES:'EACCES',errno.ECONNREFUSED:'ECONNREFUSED',
             errno.EINVAL:'EINVAL'}.get(value) if type(value) is int else None
    return {'operation':operation,'exceptionClass':protocol_exception_class(error),'errnoClass':label}


class ProtocolTrace:
    def __init__(self):
        self.subphase, self.exception_class = None, None
        self.readiness_attempts, self.readiness_shape_valid = 0, None

    def enter(self, subphase):
        require(subphase in PROTOCOL_SUBPHASES, 'unsafe_protocol_subphase')
        self.subphase = subphase

    def readiness(self, query):
        self.readiness_attempts += 1
        self.readiness_shape_valid = None
        require(self.readiness_attempts <= 20, 'readiness_attempt_bound')
        value = query()
        self.readiness_shape_valid = (type(value) is dict and len(value) == 1 and set(value) == {'ready'} and
                                      type(value['ready']) is bool)
        require(self.readiness_shape_valid, 'invalid_readiness_shape')
        return value['ready']

    def failed(self, error, runner):
        self.exception_class = protocol_exception_class(error,runner)

    def snapshot(self, client):
        require(self.subphase is None or self.subphase in PROTOCOL_SUBPHASES, 'unsafe_protocol_diagnostic')
        require(self.exception_class is None or self.exception_class in PROTOCOL_EXCEPTION_CLASSES,
                'unsafe_protocol_diagnostic')
        require(type(self.readiness_attempts) is int and 0 <= self.readiness_attempts <= 20 and
                (self.readiness_shape_valid is None or type(self.readiness_shape_valid) is bool),
                'unsafe_protocol_diagnostic')
        if client:
            require(type(client.count) is int and 0 <= client.count <= 65535, 'unsafe_protocol_diagnostic')
            if client.last is not None:
                row = client.last
                require(set(row) == {'stage','status','responseBytes','noStore','jsonContentType','cookiePresent'} and
                        row['stage'] in HTTP_STAGES, 'unsafe_protocol_diagnostic')
                require(row['status'] is None or type(row['status']) is int and 100 <= row['status'] <= 599,
                        'unsafe_protocol_diagnostic')
                require(row['responseBytes'] is None or type(row['responseBytes']) is int and
                        0 <= row['responseBytes'] <= 2 * 1024 ** 2 + 1, 'unsafe_protocol_diagnostic')
                require(all(row[k] is None or type(row[k]) is bool
                            for k in ('noStore','jsonContentType','cookiePresent')), 'unsafe_protocol_diagnostic')
        operation = getattr(client,'operation',None) if client else None
        primary = getattr(client,'primary_failure',None) if client else None
        cleanup = getattr(client,'cleanup_failures',[]) if client else []
        require(operation is None or operation in HTTP_OPERATIONS, 'unsafe_protocol_diagnostic')
        require(type(cleanup) is list and len(cleanup) <= 3, 'unsafe_protocol_diagnostic')
        for failure in ([primary] if primary is not None else []) + cleanup:
            require(type(failure) is dict and set(failure) == {'operation','exceptionClass','errnoClass'} and
                    failure['operation'] in HTTP_OPERATIONS and
                    failure['exceptionClass'] in PROTOCOL_EXCEPTION_CLASSES and
                    (failure['errnoClass'] is None or failure['errnoClass'] in HTTP_ERRNO_CLASSES),
                    'unsafe_protocol_diagnostic')
        require(all(row['operation'] in HTTP_CLEANUP_OPERATIONS for row in cleanup) and
                len({row['operation'] for row in cleanup}) == len(cleanup), 'unsafe_protocol_diagnostic')
        result = {'version':2,'subphase':self.subphase,'readinessAttempts':self.readiness_attempts,
                  'readinessShapeValid':self.readiness_shape_valid,'httpCalls':client.count if client else 0,
                  'lastHttp':client.last if client else None,'exceptionClass':self.exception_class,
                  'httpOperation':operation,'httpPrimaryFailure':primary,'httpCleanupFailures':cleanup,
                  'rawOutputIncluded':False}
        require(len(canonical(result)) <= PROTOCOL_DIAGNOSTIC_CAP, 'protocol_diagnostic_bound')
        return result


class Http:
    def __init__(self, runner):
        self.runner = runner; self.count = 0; self.last = None
        self.operation = self.primary_failure = None
        self.cleanup_failures = []; self.cleanup_failed = False

    def call(self, method, path, cookie=None, body=None, origin=ORIGIN, proxy_readiness=False):
        require(not proxy_readiness or (method == 'GET' and path == '/api/v1/auth/me' and
                cookie is None and body is None and origin == ORIGIN), 'unsafe_proxy_readiness')
        require(not self.cleanup_failed, 'http_cleanup_failed')
        self.operation = self.primary_failure = None; self.cleanup_failures = []
        self.last = {'stage':'request','status':None,'responseBytes':None,
                     'noStore':None,'jsonContentType':None,'cookiePresent':None}
        require(path.startswith('/api/v1/') and '\r' not in path and '\n' not in path, 'unsafe_http_route')
        remaining = self.runner.work_deadline - time.monotonic()
        require(remaining > 0, 'protocol_deadline')
        headers = {'Origin': origin}
        if cookie: headers['Cookie'] = cookie
        payload = None
        if body is not None: payload = canonical(body); headers['Content-Type'] = 'application/json'
        self.count += 1
        connection, primary_error, result = None, None, None
        old_alarm, handler_installed, timer_disarmed = None, False, False
        def http_deadline(_signum, _frame):
            raise Refusal('http_absolute_timeout')
        try:
            self.operation = 'connection-create'
            connection = http.client.HTTPConnection('127.0.0.1', PORT, timeout=min(5, remaining))
            self.operation = 'signal-read'; old_alarm = signal.getsignal(signal.SIGALRM)
            self.operation = 'signal-install'; signal.signal(signal.SIGALRM, http_deadline)
            handler_installed = True
            self.operation = 'timer-arm'; signal.setitimer(signal.ITIMER_REAL, min(5, remaining))
            self.operation = 'connection-connect'; connection.connect()
            self.operation = 'request-send'; connection.request(method, path, body=payload, headers=headers)
            self.last['stage'] = 'response-headers'; self.operation = 'response-headers'
            response = connection.getresponse()
            self.last['status'] = response.status if type(response.status) is int and 100 <= response.status <= 599 else None
            headers = {k.lower(): v for k, v in response.getheaders()}
            self.last.update(noStore=headers.get('cache-control') == 'no-store',
                             jsonContentType=bool(re.fullmatch(r'application/json(?:\s*;\s*charset=utf-8)?\s*',
                                                              headers.get('content-type',''),re.I)),
                             cookiePresent='set-cookie' in headers)
            self.last['stage'] = 'response-body'; self.operation = 'response-body'
            raw = response.read(2 * 1024 ** 2 + 1)
            self.last['responseBytes'] = len(raw)
            require(len(raw) <= 2 * 1024 ** 2, 'http_output_bound')
            require(headers.get('cache-control') == 'no-store', 'missing_no_store')
            self.last['stage'] = 'json-decode'; self.operation = 'json-decode'
            # Only unauthenticated readiness may encounter native nginx transient HTML.
            # Never suppress JSON errors for login, admission or any ordinary request.
            value = None if proxy_readiness and response.status in (502,503,504) else json.loads(raw) if raw else None
            self.last['stage'] = 'complete'
            result = response.status, headers, value
        except BaseException as error:
            primary_error = error
            self.primary_failure = http_failure_record(self.operation,error)
        finally:
            if handler_installed:
                try:
                    signal.setitimer(signal.ITIMER_REAL, 0); timer_disarmed = True
                except BaseException as error:
                    self.cleanup_failures.append(http_failure_record('timer-disarm',error))
                # Never restore a possibly terminating old handler unless disarm succeeded.
                if timer_disarmed:
                    try: signal.signal(signal.SIGALRM, old_alarm)
                    except BaseException as error:
                        self.cleanup_failures.append(http_failure_record('signal-restore',error))
            if connection is not None:
                try: connection.close()
                except BaseException as error:
                    self.cleanup_failures.append(http_failure_record('connection-close',error))
            self.cleanup_failed = bool(self.cleanup_failures)
        if primary_error is not None: raise primary_error
        require(not self.cleanup_failed, 'http_cleanup_failed')
        return result

    def login(self, account):
        status, headers, _ = self.call('POST', '/api/v1/auth/login', body=account)
        require(status == 200, 'ordinary_login_failed')
        cookie = headers.get('set-cookie', '').split(';')[0]
        require(re.fullmatch(r'demo_session=[A-Za-z0-9_-]{43}', cookie), 'invalid_session_cookie')
        return cookie

    def get(self, path, cookie):
        status, _, value = self.call('GET', path, cookie)
        require(status == 200, 'owner_get_failed')
        return value


def collect(http, scan_id, owner, foreign):
    base = '/api/v1/browser/scans/' + scan_id
    status = http.get(base, owner)
    require(status['scanId'] == scan_id and status['state'] == 'completed' and status['checks'] == CHECKS and
            status['digest'] == TARGET['digest'] and status['platform'] == TARGET['platform'] and
            status['imageProfile']['qualified'] is True and status['executedQualification'] == BINDING, 'invalid_owner_status')
    for key in CHECKS:
        require(status['perCheck'][key]['outcome'] == 'checked', 'independent_check_not_checked')
    require(status['perCheck']['vuln']['resultContractVersion'] == 2, 'status_not_v2')
    payload = {'status': status}; arrays = {}; cvemeta = None
    for route, array_key in [('results', 'findings'), ('sbom', 'components'), ('vuln', 'findings')]:
        cursor, values, pages = 0, [], []
        for _ in range(256):
            page = http.get(base + '/' + route + '?limit=17&cursor=' + str(cursor), owner)
            require(isinstance(page[array_key], list) and len(page[array_key]) <= 17, 'invalid_page')
            if route == 'vuln':
                require(set(page) == {'outcome','coverage','image','platform','findings','findingCount','nextCursor',
                                      'db','os','node','scannerVersion','checkedAt','resultContractVersion','dbPolicy',
                                      'usableUntil','workerCheckedAt'}, 'invalid_v2_page_shape')
                require(page['outcome'] == 'checked' and page['coverage'] == 'image' and page['db'] == DB and
                        page['resultContractVersion'] == 2 and page['usableUntil'] == UNTIL and
                        page['scannerVersion'] == '0.69.3', 'invalid_v2_metadata')
                require(type(page['workerCheckedAt']) is int and page['workerCheckedAt'] > 0, 'invalid_worker_time')
                seconds, milliseconds = divmod(page['workerCheckedAt'], 1000)
                actual_iso = datetime.fromtimestamp(seconds, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + f'.{milliseconds:03d}Z'
                require(page['checkedAt'] == actual_iso, 'rewritten_checked_at')
                require(page['dbPolicy']['policy'] == POLICY and page['dbPolicy']['version'] == 2 and
                        page['dbPolicy']['evaluatedAt'] >= page['workerCheckedAt'], 'invalid_policy_receipt')
                meta = {k: page[k] for k in ('db','dbPolicy','workerCheckedAt','usableUntil')}
                if cvemeta is None: cvemeta = meta
                else: require(meta == cvemeta, 'policy_changed_between_pages')
            if route == 'results':
                require(set(page) == {'findings','nextCursor','coverage'} and
                        page['coverage']['check'] == 'secret' and page['coverage']['outcome'] == 'checked' and
                        page['coverage']['scannerVersion'] == '0.69.3', 'invalid_secret_page')
            if route == 'sbom':
                require(set(page) == {'outcome','coverage','image','platform','os','components','componentCount',
                                      'nextCursor','scannerVersion','checkedAt'}, 'invalid_sbom_shape')
                require(page['outcome'] == 'checked' and page['scannerVersion'] == '0.69.3' and
                        page['image'] == TARGET['registry']+'/'+TARGET['repository']+'@'+TARGET['digest'] and
                        page['platform'] == TARGET['platform'], 'invalid_sbom_metadata')
            pages.append(page); values.extend(page[array_key]); next_cursor = page['nextCursor']
            if next_cursor is None: break
            require(type(next_cursor) is int and next_cursor == len(values) and next_cursor > cursor, 'cursor_not_advancing')
            cursor = next_cursor
        else: raise Refusal('page_count_bound')
        if route != 'results':
            total = pages[0]['findingCount' if route == 'vuln' else 'componentCount']
            require(type(total) is int and total == len(values) and all(p['findingCount' if route == 'vuln' else 'componentCount'] == total for p in pages), 'page_total_mismatch')
        payload[route] = pages; arrays[route] = values
        for suffix in ('', '/' + route):
            require(http.call('GET', base + suffix, foreign)[0] == 404, 'foreign_owner_not_hidden')
            require(http.call('GET', base + suffix)[0] == 401, 'anonymous_not_denied')
    require(arrays['vuln'] and arrays['sbom'], 'positive_inventory_missing')
    for key,route,count_key in [('secret','results','findingCount'),('sbom','sbom','componentCount'),('vuln','vuln','findingCount')]:
        require(status['perCheck'][key][count_key] == len(arrays[route]), 'status_total_mismatch')
        require(status['perCheck'][key]['checkedAt'] == payload['vuln'][0]['checkedAt'], 'sibling_time_mismatch')
    require({k:status['perCheck']['vuln'][k] for k in cvemeta} == cvemeta, 'status_policy_mismatch')
    for page in payload['results']:
        require(page['coverage']['findingCount'] == len(arrays['results']) and
                page['coverage']['checkedAt'] == payload['vuln'][0]['checkedAt'], 'secret_total_mismatch')
    ids = [f['findingId'] for f in arrays['vuln']]
    require(len(set(ids)) == len(ids), 'duplicate_cve_ids')
    tuples = sorted(([x['ecosystem'],x['name'],x['version']] for x in arrays['sbom']), key=lambda x: canonical(x))
    require(len({canonical(t) for t in tuples}) == len(tuples), 'duplicate_sbom_tuples')
    return {'apiSha256': sha(canonical(payload)), 'cveCount': len(ids), 'sbomCount': len(tuples),
            'findingsSha256': sha(canonical(sorted(arrays['vuln'], key=lambda f: f['findingId']))),
            'findingIdsSha256': sha(canonical(sorted(ids))), 'sbomTuplesSha256': sha(canonical(tuples)),
            'secretFindingsSha256': sha(canonical(arrays['results'])), 'secretCount': len(arrays['results']),
            'metadata': cvemeta, 'pages': {k: len(payload[k]) for k in ('results','sbom','vuln')}}


def compare(api, sql):
    for k in ('cveCount','sbomCount','findingsSha256','findingIdsSha256','sbomTuplesSha256',
              'secretFindingsSha256','secretCount'):
        require(api[k] == sql[k], 'sql_api_full_set_mismatch')
    require(api['metadata'] == {k: sql[k] for k in ('db','dbPolicy','workerCheckedAt','usableUntil')}, 'sql_api_receipt_mismatch')


def cleanup_owned(runner, project, success):
    resources = owned_resources(runner, project, cleanup=True)
    failures = []
    # No all-container inventory: every candidate came from this exact random project label.
    for cid in resources['containers']:
        try:
            require(HEX.fullmatch(cid), 'unsafe_cleanup_id')
            info = runner.json(['container','inspect',cid], cleanup=True)[0]
            require(info['Id']==cid and own_label(info, project) and info['Name'].startswith('/'+project+'-'), 'foreign_cleanup_container')
            runner.run(['container','rm','-f',cid] if success else ['container','stop','--time','2',cid],
                       seconds=5, cleanup=True)
        except (Refusal,OSError,ValueError,KeyError): failures.append('own_container_cleanup_failed')
    if success and not failures:
        for nid in resources['networks']:
            try:
                require(HEX.fullmatch(nid), 'unsafe_cleanup_id')
                info = runner.json(['network','inspect',nid], cleanup=True)[0]
                require(info['Id']==nid and own_label(info,project) and not info.get('Containers') and
                        info['Name'] in {project+'_'+n for n in ('auth_internal','scan_internal','registry_uplink','web_edge')},
                        'unsafe_cleanup_network')
                runner.run(['network','rm',nid], seconds=5, cleanup=True)
            except (Refusal,OSError,ValueError,KeyError): failures.append('own_network_cleanup_failed')
        for volume in resources['volumes']:
            try:
                require(volume in {project+'_auth_accounts', project+'_scan_ledger'}, 'unsafe_cleanup_volume')
                info = runner.json(['volume','inspect',volume], cleanup=True)[0]
                require(own_label(info,project), 'foreign_cleanup_volume')
                runner.run(['volume','rm',volume], seconds=5, cleanup=True)
            except (Refusal,OSError,ValueError,KeyError): failures.append('own_volume_cleanup_failed')
    remaining = owned_resources(runner,project,cleanup=True)
    if success: require(not failures and not any(remaining.values()), 'own_cleanup_incomplete')
    return {'removed':success and not failures,'retainedOnFailure':not success,'failures':failures,
            'remainingCounts':{k:len(v) for k,v in remaining.items()}}, remaining


def approve_build(args, proposal):
    # Build diagnostics cannot inherit full-proof inputs or touch release metadata/ports.
    require(args.reviewed_script_sha256 == proposal['scriptSha256'], 'script_not_approved')
    require(args.reviewed_source_sha256 == proposal['sourceSnapshotSha256'], 'source_not_approved')
    require(args.docker_context and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',args.docker_context),
            'context_required')
    require(not args.gateway_image and not getattr(args,'ingress_image',None) and not args.release_dir and
            not getattr(args,'daemon_bind_source_prefix','') and
            not getattr(args,'daemon_bind_source_policy',''), 'build_only_inputs_required')
    require(args.scratch_dir, 'explicit_paths_required')
    scratch = plain_absolute(args.scratch_dir)
    require(not scratch.exists() and scratch.parent.is_dir() and not scratch.is_relative_to(ROOT),
            'scratch_not_new')
    mode = scratch.parent.stat().st_mode
    require(not mode & 0o022 or mode & stat.S_ISVTX, 'unsafe_scratch_parent')
    return scratch


def diagnose_build(args, data, hashes, proposal, receipt):
    scratch = approve_build(args,proposal)
    started = time.monotonic(); runner = Runner(args.docker_context,started)
    runner.work_deadline = runner.total_deadline = started + DIAGNOSTIC_SECONDS
    evidence = {'kind':'isolated-cve14-build-diagnostic','startedAt':utc(),
                'scriptSha256':proposal['scriptSha256'],'sourceSnapshotSha256':proposal['sourceSnapshotSha256'],
                'liveTouched':False,'wholeAcceptance':False,'runtimeProofExecuted':False,
                'passed':False,'phase':'build-only-preflight','failures':[],
                'buildCacheAndUniqueTagsRetained':True,'noRuntimeResourcesCreated':True}
    created, success = False, False
    try:
        scratch.mkdir(mode=0o700); created = True
        require(runner.text(['context','inspect',args.docker_context,'--format','{{.Endpoints.docker.Host}}']).startswith('unix://'),
                'nonlocal_docker_context')
        require(runner.text(['info','--format','{{.OSType}}'],seconds=10) == 'linux','linux_daemon_required')
        info = runner.json(['image','inspect',WORKER])[0]
        config = info['Config']
        require(info['Id'] == WORKER and info['Os'] == 'linux' and info['Architecture'] in ('amd64','arm64'),
                'cached_image_unqualified')
        require(config.get('Entrypoint') in (None,[],['docker-entrypoint.sh']) and
                not config.get('OnBuild') and not config.get('Volumes'),'cached_build_configuration')
        for value in config.get('Env',[]):
            require(not value.split('=',1)[0].startswith(('SCAN_','AUTH_','LLM_','OPENROUTER_',
                                                         'NODE_OPTIONS','NODE_TLS_','NODE_EXTRA_CA')),
                    'cached_image_sensitive_env')
        platform = info['Os']+'/'+info['Architecture']
        suffix = secrets.token_hex(8)
        base_tag, image_tag = 'dip-cve14-diag-base-'+suffix+':local','dip-cve14-diag-snapshot-'+suffix+':local'
        context, context_sha = make_context(scratch,data,hashes,proposal['sourceSnapshotSha256'],base_tag,receipt)
        evidence.update(runtimePlatform=platform,contextSha256=context_sha,
                        dockerfileSha256=sha(dockerfile(base_tag,hashes).encode()))
        runner.run(['image','tag',WORKER,base_tag])
        require(runner.text(['image','inspect','--format','{{.Id}}',base_tag]) == WORKER,'base_alias_drift')
        evidence['phase'] = 'new-dirty-source-build'
        runner.build(context,image_tag,platform,hashes)
        image = runner.text(['image','inspect','--format','{{.Id}}',image_tag])
        require(IMAGE.fullmatch(image) and image != WORKER,'new_image_missing')
        actual = runner.json(['image','inspect',image])[0]
        require(actual['Os']+'/'+actual['Architecture'] == platform,'new_image_platform_mismatch')
        evidence['imageId'] = image
        success = True
    except (Refusal,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        evidence['failures'].append(str(error) if isinstance(error,Refusal) else 'isolated_protocol_failed')
    finally:
        if runner.last_build_diagnostics is not None:
            evidence['buildDiagnostics'] = runner.last_build_diagnostics
        evidence.update(passed=success and not evidence['failures'],finishedAt=utc(),
                        elapsedSeconds=round(time.monotonic()-started,3),dockerCalls=runner.calls)
        packet = {'payload':evidence,'payloadCanonicalSha256':sha(canonical(evidence)),
                  'sealMeaning':'content hash, not signature or parent acceptance'}
        require(len(canonical(packet)) <= 131072,'evidence_bound')
        if created: write_new(scratch/'sanitized-evidence.json',canonical(packet))
        print(json.dumps(packet))
    return 0 if evidence['passed'] else 1


def execute(args, data, hashes, proposal, receipt):
    release, scratch = approve(args, proposal)
    started = time.monotonic(); runner = Runner(args.docker_context, started)
    bind_prefix, bind_policy = getattr(args,'daemon_bind_source_prefix',''), getattr(args,'daemon_bind_source_policy','')
    evidence = {'kind':'isolated-cve14-combined-proof','startedAt':utc(),'scriptSha256':proposal['scriptSha256'],
                'sourceSnapshotSha256':proposal['sourceSnapshotSha256'],'liveTouched':False,'wholeAcceptance':False,
                'daemonBindSourcePrefix':bind_prefix,'daemonBindSourcePolicy':bind_policy,
                'passed':False,'phase':'preflight','failures':[]}
    project = 'dip-cve14-proof-' + secrets.token_hex(8)
    resources, created, success, scope_claimed, startup_completed = {}, False, False, False, False
    trace, http = ProtocolTrace(), None
    try:
        scratch.mkdir(mode=0o700); created = True
        validate_local_daemon(runner,args.docker_context)
        require_empty_namespace(runner,project)
        scope_claimed = True
        # Literal loopback only, no probe before parent review. Docker bind also fails closed on a race.
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as probe:
            probe.bind(('127.0.0.1',PORT))
        cached_platforms = {}
        for image in (WORKER,args.gateway_image,args.ingress_image):
            info = runner.json(['image','inspect',image])[0]
            require(info['Id'] == image and info['Os'] == 'linux' and info['Architecture'] in ('amd64','arm64'),
                    'cached_image_unqualified')
            cached_platforms[image] = info['Os']+'/'+info['Architecture']
            if image == INGRESS:
                cached_platforms[image] = qualify_ingress_image(info)
                continue
            allowed_entrypoints = (None, [], ['docker-entrypoint.sh']) if image == WORKER else (None, [])
            require(info['Config'].get('Entrypoint') in allowed_entrypoints, 'cached_entrypoint_override')
            if image == WORKER:
                require(not info['Config'].get('OnBuild') and not info['Config'].get('Volumes'),
                        'cached_build_configuration')
            if image == args.gateway_image:
                require(info['Config']['Cmd'] == ['python','-I','proxy.py'] and
                        info['Config']['WorkingDir'] == '/opt/gateway' and
                        info['Config']['User'] == '65532:65532', 'cached_gateway_configuration')
            for v in info['Config'].get('Env',[]):
                require(not v.split('=',1)[0].startswith(('SCAN_','AUTH_','LLM_','OPENROUTER_','NODE_OPTIONS','NODE_TLS_','NODE_EXTRA_CA')), 'cached_image_sensitive_env')
        worker_platform, gateway_platform = cached_platforms[WORKER], cached_platforms[args.gateway_image]
        ingress_platform = cached_platforms[INGRESS]
        evidence['runtimePlatforms'] = {'dependencyBase':worker_platform,'gateway':gateway_platform,
                                        'ingress':ingress_platform,'scannedTarget':TARGET['platform']}
        gateway = runner.json(['run','--rm','--pull=never','--platform',gateway_platform,
                               '--name',project+'-gateway-qualifier',
                               '--label','com.docker.compose.project='+project,'--network','none','--read-only',
                               '--user','65532:65532','--cap-drop','ALL','--security-opt','no-new-privileges=true',
                               '--memory','256m','--memory-swap','256m','--cpus','1','--pids-limit','128',
                               '--entrypoint','python',args.gateway_image,'-I','-c',GATEWAY_QUALIFY],seconds=15)
        require(gateway == {'proxySha256':hashes['server/deploy/gateway/proxy.py']}, 'gateway_source_mismatch')
        base_tag = 'dip-cve14-base-' + project[16:] + ':local'
        image_tag = 'dip-cve14-snapshot-' + project[16:] + ':local'
        context, context_sha = make_context(scratch,data,hashes,proposal['sourceSnapshotSha256'],base_tag,receipt)
        runner.run(['image','tag',WORKER,base_tag])
        require(runner.text(['image','inspect','--format','{{.Id}}',base_tag]) == WORKER,'base_alias_drift')
        evidence['phase'] = 'new-dirty-source-build'
        runner.build(context,image_tag,worker_platform,hashes)
        image = runner.text(['image','inspect','--format','{{.Id}}',image_tag])
        require(IMAGE.fullmatch(image) and image != WORKER, 'new_image_missing')
        actual_image = runner.json(['image','inspect',image])[0]
        require(actual_image['Os']+'/'+actual_image['Architecture'] == worker_platform, 'new_image_platform_mismatch')
        evidence.update(imageId=image,gatewayImageId=args.gateway_image,contextSha256=context_sha,
                        dockerfileSha256=sha(dockerfile(base_tag,hashes).encode()))
        # Copy only PUBLIC bases into private OWN scratch; interpolation gets ONLY generated values.
        for name in BASES: write_new(scratch/name,data['server/deploy/'+name])
        ingress_config = ingress_public_copy(scratch,data)
        ingress_bind_candidates(ingress_config,bind_prefix,bind_policy)
        override_path = scratch/'ports.override.yaml'; write_new(override_path,PORT_OVERRIDE)
        evidence.update(ingressImageId=INGRESS,ingressConfigSha256=hashes[INGRESS_CONFIG],
                        portsOverrideSha256=sha(PORT_OVERRIDE))
        env_path = scratch/'own.env'
        generated = {'SCAN_JWT_SECRET':secrets.token_hex(32),'AUTH_ORIGIN':ORIGIN,
                     'AUTH_ALLOW_INSECURE_LOCAL_HTTP':'true','SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS':'false',
                     'SCAN_VULN_RELEASE_HOST_DIR':str(release),'SCAN_VULN_MANIFEST_DIGEST':DB['manifestDigest'],
                     'SCAN_VULN_ARTIFACT_SHA256':DB['artifactSha256']}
        require(all('\n' not in v and '\r' not in v and not any(c in v for c in '$#\'"') for v in generated.values()), 'unsafe_generated_env_value')
        write_new(env_path,('\n'.join(k+'='+v for k,v in generated.items())+'\n').encode())
        overlay_path = scratch/'isolation.json'
        overlay_bytes = overlay(image,args.gateway_image,[],worker_platform,gateway_platform,
                                args.ingress_image,ingress_config,ingress_platform)
        write_new(overlay_path,overlay_bytes)
        compose = ['compose','--project-name',project,'--env-file',str(env_path)]
        for name in BASES: compose += ['-f',str(scratch/name)]
        compose += ['-f',str(overlay_path),'-f',str(override_path)]
        # Explicit env file and filtered environment: no .env.local or ambient secrets.
        def cmd(args_, **kw): return runner.run(compose+args_,**kw)
        def cj(args_, **kw): return runner.json(compose+args_,**kw)
        evidence['phase'] = 'own-compose-config-before-storage'
        topology = cj(['config','--format','json'],seconds=15,cap=COMPOSE_CAPTURE_CAP,compose_phase='before-storage')
        evidence['ingressComposeBindBeforeStorage'] = verify_ingress_topology(
            topology,project,image,args.gateway_image,ingress_config,generated_overlay=overlay_bytes)
        evidence['phase'] = 'own-empty-storage-provision'
        cmd(['up','-d','--no-build','--pull','never','auth-volume-init','scan-volume-init'],seconds=25)
        resources = owned_resources(runner,project)
        accounts = [{'email':'cve14-'+secrets.token_hex(10)+'@qualification.invalid','password':secrets.token_hex(24)} for _ in range(3)]
        provision = cj(['run','--rm','--no-deps','-T','--entrypoint','node','api','--import','tsx','/proof/provision.mjs'],
                       seconds=25,data=canonical({'accounts':accounts}))
        ids = provision['ids']; require(len(ids)==3 and len(set(ids))==3 and all(re.fullmatch('[a-f0-9]{32}',v) for v in ids),'invalid_synthetic_accounts')
        # This is our exclusively created overlay, not an existing/user file.
        overlay_bytes = overlay(image,args.gateway_image,ids,worker_platform,gateway_platform,
                                args.ingress_image,ingress_config,ingress_platform)
        overlay_path.write_bytes(overlay_bytes); overlay_path.chmod(0o600)
        evidence['phase'] = 'own-compose-config-after-storage'
        evidence['ingressComposeBindAfterStorage'] = verify_ingress_topology(
            cj(['config','--format','json'],seconds=15,cap=COMPOSE_CAPTURE_CAP,compose_phase='after-storage'),
            project,image,args.gateway_image,ingress_config,generated_overlay=overlay_bytes)
        evidence['phase'] = 'isolated-startup'
        cmd(['up','-d','--no-build','--pull','never','--wait','--wait-timeout','35','egress','worker','api','web'],seconds=45)
        startup_completed = True
        cids = {name:runner.text(compose+['ps','-q',name]) for name in ('api','worker','egress')}
        web_cid = runner.text(compose+['ps','-q','web'])
        resources = owned_resources(runner,project); require_resource_counts(resources,complete=True)
        trace.enter('isolation-qualification')
        evidence['isolation'] = {name:verify_container(runner,cids[name],project,
                                  args.gateway_image if name=='egress' else image,release,name,bind_prefix,bind_policy)
                                  for name in cids}
        evidence['sourceQualification'] = {role:evidence['isolation'][role].pop('sourceQualification')
                                           for role in ('api','worker')}
        trace.enter('ingress-qualification')
        evidence['isolation']['web'] = verify_web_container(
            runner,web_cid,project,ingress_config,hashes[INGRESS_CONFIG],bind_prefix,bind_policy)
        trace.enter('chain-readiness')
        for _ in range(20):
            if trace.readiness(lambda:runner.json(['exec',cids['api'],'node','--import','tsx','/proof/ready.mjs'])): break
            time.sleep(0.5)
        else: raise Refusal('real_chain_not_ready')
        http = Http(runner)
        trace.enter('ingress-host-readiness'); evidence['ingressHostReadiness'] = proxy_host_ready(http)
        trace.enter('ordinary-owner-login'); owner = http.login(accounts[0])
        trace.enter('ordinary-foreign-login'); foreign = http.login(accounts[1])
        trace.enter('ordinary-unlisted-login'); unlisted = http.login(accounts[2])
        body = {'imageReference':TARGET['registry']+'/'+TARGET['repository']+'@'+TARGET['digest'],
                'checks':CHECKS,'scope':'image','idempotencyKey':'cve14-own-'+secrets.token_hex(12)}
        route = '/api/v1/browser/scans'
        trace.enter('image-eligibility')
        eligibility = http.call('POST',route+'/images/eligibility',owner,
                                {'imageReference':body['imageReference'],'checks':CHECKS})
        require(eligibility[0]==200 and eligibility[2]['eligible'] and eligibility[2]['qualificationId']==BINDING['qualificationId'],'actual_eligibility_failed')
        trace.enter('observer-start')
        runner.run(['exec','-d',cids['worker'],'node','--import','tsx','/proof/observe.mjs'],seconds=10)
        trace.enter('actual-http-combined')
        evidence['phase'] = 'actual-http-combined'
        status,_,receipt_http = http.call('POST',route,owner,body)
        require(status==202 and UUID.fullmatch(receipt_http['scanId']),'admission_not_202')
        scan_id = receipt_http['scanId']; evidence['scanId'] = scan_id
        evidence['admissionLedger'] = runner.json(['exec','-i',cids['api'],'node','--import','tsx','/proof/admission.mjs'],
                        data=canonical({'scanId':scan_id,'subject':ids[0]}),seconds=15)
        poll_end = min(runner.work_deadline,time.monotonic()+165)
        while time.monotonic()<poll_end:
            state = http.get(route+'/'+scan_id,owner)['state']
            if state in ('completed','failed','partial','cancelled'): break
            time.sleep(0.5)
        else: raise Refusal('queue_poll_timeout')
        require(state=='completed','real_combined_not_completed')
        replay = http.call('POST',route,owner,body)
        require(replay[0]==202 and replay[2]['scanId']==scan_id,'replay_changed_id')
        require(http.call('POST',route,owner,{**body,'checks':['secret']})[0]==409,'different_intent_not_conflict')
        require(http.call('POST',route,None,body)[0]==401,'anonymous_admission')
        require(http.call('POST',route,unlisted,body)[0]==403,'unlisted_admission')
        require(http.call('POST',route,owner,body,origin='https://foreign.invalid')[0]==403,'foreign_origin_admission')
        for bad in ({**body,'checks':['sbom','vuln']},{**body,'checks':['config']},
                    {**body,'imageReference':body['imageReference'].replace(TARGET['digest'],'sha256:'+'0'*64)},
                    {**body,'unexpected':True}):
            require(http.call('POST',route,owner,bad)[0]==400,'unsupported_before_replay')
        api = collect(http,scan_id,owner,foreign)
        sql = runner.json(['exec','-i',cids['api'],'node','--import','tsx','/proof/sql.mjs'],
                          data=canonical({'scanId':scan_id,'subject':ids[0]}),seconds=20)
        compare(api,sql)
        require(collect(http,scan_id,owner,foreign)==api,'same_report_reload_changed')
        observed = runner.json(['exec',cids['worker'],'node','-e',"console.log(require('node:fs').readFileSync('/data/cve14-observed.json','utf8'))"],seconds=10)
        require(observed['complete'] and {v['check'] for v in observed['observations']}==set(CHECKS),'fixed_argv_observation_incomplete')
        evidence.update(report=sql,ownerApi=api,scannerProcess=observed,actualOwnerLogin=True,
                        httpAdmission=True,allPagesSqlEqual=True,sameIdReload=True)
        evidence['phase'] = 'same-ledger-api-recreation'
        old_api = cids['api']; cmd(['up','-d','--no-build','--pull','never','--no-deps','--force-recreate',
                                  '--wait','--wait-timeout','25','api'],seconds=35)
        cids['api'] = runner.text(compose+['ps','-q','api']); require(cids['api']!=old_api,'api_not_recreated')
        resources = owned_resources(runner,project)
        trace.enter('isolation-qualification')
        evidence['recreatedApiIsolation'] = verify_container(runner,cids['api'],project,image,release,'api',bind_prefix,bind_policy)
        trace.enter('ingress-recreated-readiness')
        evidence['ingressRecreatedReadiness'] = proxy_host_ready(http,recreated=True)
        trace.enter('ordinary-owner-login'); owner = http.login(accounts[0])
        trace.enter('ordinary-foreign-login'); foreign = http.login(accounts[1])
        trace.enter('actual-http-combined')
        after_api = collect(http,scan_id,owner,foreign)
        after_sql = runner.json(['exec','-i',cids['api'],'node','--import','tsx','/proof/sql.mjs'],
                                data=canonical({'scanId':scan_id,'subject':ids[0]}),seconds=20)
        compare(after_api,after_sql); require(api==after_api and sql==after_sql,'historical_report_policy_changed')
        evidence.update(sameIdAfterRecreation=True,logicalLedgerUnchanged=True,quotaUnchanged=True,
                        historicalPolicyUnchanged=True,httpCalls=http.count)
        for role in ('api','worker'):
            verified = runner.json(['exec',cids[role],'node','--import','tsx','src/worker/verify-vuln-db-release.ts',
                                    '/opt/release',DB['manifestDigest'],DB['artifactSha256']],seconds=90)
            require(verified['db']==DB,'release_changed_during_proof')
        evidence['resourcesAfter'] = runner.json(['exec',cids['worker'],'node','--import','tsx','/proof/qualify.mjs','worker'],seconds=20)['counters']
        success = True
    except (Refusal,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError,HTTPException) as error:
        trace.failed(error,runner)
        evidence['failures'].append(str(error) if isinstance(error,Refusal) else 'isolated_protocol_failed')
        if evidence['phase'] == 'isolated-startup' and not startup_completed:
            evidence['startupDiagnostics'] = diagnose_own_initializers(runner,project,image)
            if any(row['status'] == 'exited' and row['exitCode'] != 0
                   for row in evidence['startupDiagnostics']['initializers']):
                evidence['failures'].append('own_initializer_failed')
    finally:
        if runner.last_build_diagnostics is not None:
            evidence['buildDiagnostics'] = runner.last_build_diagnostics
        if getattr(runner,'last_compose_diagnostics',None) is not None:
            evidence['composeConfigDiagnostics'] = runner.last_compose_diagnostics
        if getattr(runner,'last_nginx_diagnostic',None) is not None:
            evidence['ingressNativeDiagnostic'] = runner.last_nginx_diagnostic
        if created:
            if scope_claimed:
                try:
                    evidence['cleanup'],resources = cleanup_owned(runner,project,success)
                except (Refusal,OSError,ValueError,KeyError) as error:
                    evidence['failures'].append('own_cleanup_incomplete'); success=False
                    # No LIVE or broad discovery fallback on unavailable daemon/deadline.
            else:
                evidence['cleanup']={'skippedUnclaimedNamespace':True,'foreignResourcesTouched':False}
            manifest = {'project':project,'dockerContext':args.docker_context,'sourceSnapshotSha256':proposal['sourceSnapshotSha256'],
                        'resources':resources,'scratch':str(scratch),'privateSyntheticMaterial':True,
                        'recoveryRule':'Inspect EACH exact recorded ID/name for this project label and prefix before removal; stale/missing IDs are not replacements.',
                        'removalOrder':['exact-own-container-IDs','exact-own-network-IDs','exact-own-volume-names'],
                        'forbidden':['all-container-discovery','shared-prune','LIVE-volume-or-container','env-or-key-read']}
            write_new(scratch/'own-recovery.json',canonical(manifest))
        evidence.update(passed=success and not evidence['failures'],finishedAt=utc(),
                        elapsedSeconds=round(time.monotonic()-started,3),dockerCalls=runner.calls,
                        limitations=proposal['limitations'][1:])
        evidence['protocolDiagnostics'] = trace.snapshot(http)
        evidence['httpCalls'] = http.count if http else 0
        seal = sha(canonical(evidence)); packet = {'payload':evidence,'payloadCanonicalSha256':seal,
                                                  'sealMeaning':'content hash, not signature or parent acceptance'}
        require(len(canonical(packet))<=131072,'evidence_bound')
        if created: write_new(scratch/'sanitized-evidence.json',canonical(packet))
        print(json.dumps({'kind':evidence['kind'],'passed':evidence['passed'],'failures':evidence['failures'],
                          'evidencePath':str(scratch/'sanitized-evidence.json') if created else None,
                          'artifactSha256':sha(canonical(packet)),'payloadCanonicalSha256':seal,
                          'elapsedSeconds':evidence['elapsedSeconds']}))
    return 0 if evidence['passed'] else 1


def self_test():
    require(CHECKS==['secret','sbom','vuln'] and len(OFF)==4,'wrong_fixture_policy')
    require(sha(canonical({'a':1,'b':2}))==sha(canonical({'b':2,'a':1})),'unstable_hash')
    require(UUID.fullmatch('00000000-0000-4000-8000-000000000000') and not UUID.fullmatch('not-an-id'),'uuid_guard')
    dummy={'scriptSha256':'a'*64,'sourceSnapshotSha256':'b'*64}
    args=argparse.Namespace(reviewed_script_sha256='wrong',reviewed_source_sha256='b'*64)
    try: approve(args,dummy)
    except Refusal as e: require(str(e)=='script_not_approved','review_gate_order')
    else: raise Refusal('review_gate_bypassed')
    require(WORK_SECONDS<TOTAL_SECONDS and PORT==18083,'protocol_bounds')
    require('--offline-scan' in OBSERVER_JS and 'validateArchiveReport' in SQL_JS,'missing_receipt_checks')
    fixture_id='00000000-0000-4000-8000-000000000000'
    millis=1791446400123
    stamp=datetime.fromtimestamp(millis//1000,timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')+'.123Z'
    meta={'db':DB,'dbPolicy':{'version':2,'policy':POLICY,'evaluatedAt':millis+1,
          'status':'stale-but-usable','warnings':['DB_PUBLICATION_OVERDUE']},
          'workerCheckedAt':millis,'usableUntil':UNTIL}
    image=TARGET['registry']+'/'+TARGET['repository']+'@'+TARGET['digest']
    checked={'outcome':'checked','checkedAt':stamp}
    status={'scanId':fixture_id,'state':'completed','checks':CHECKS,'digest':TARGET['digest'],
            'platform':TARGET['platform'],'imageProfile':{'qualified':True},'executedQualification':BINDING,
            'perCheck':{'secret':{**checked,'findingCount':0},'sbom':{**checked,'componentCount':1},
                        'vuln':{**checked,**meta,'findingCount':1,'resultContractVersion':2}}}
    pages={'results':{'findings':[],'nextCursor':None,'coverage':{'check':'secret','outcome':'checked',
                     'scannerVersion':'0.69.3','findingCount':0,'checkedAt':stamp}},
           'sbom':{'outcome':'checked','coverage':'image','image':image,'platform':TARGET['platform'],
                   'os':{'name':'alpine','version':'3.23.3'},'components':[{'ecosystem':'apk','name':'synthetic','version':'1'}],
                   'componentCount':1,'nextCursor':None,'scannerVersion':'0.69.3','checkedAt':stamp},
           'vuln':{'outcome':'checked','coverage':'image','image':image,'platform':TARGET['platform'],
                   'findings':[{'findingId':'synthetic-cve-id'}],'findingCount':1,'nextCursor':None,
                   'os':{'outcome':'checked'},'node':{'outcome':'unsupported','reason':'NODE_INVENTORY_ABSENT'},
                   'scannerVersion':'0.69.3','checkedAt':stamp,'resultContractVersion':2,**meta}}
    class FakeHttp:
        def get(self,path,cookie):
            route=path.split('?')[0].rsplit('/',1)[-1]
            return pages[route] if route in pages else status
        def call(self,method,path,cookie=None): return (404 if cookie else 401,{},None)
    api=collect(FakeHttp(),fixture_id,'synthetic-owner','synthetic-foreign')
    sql={k:api[k] for k in ('cveCount','sbomCount','findingsSha256','findingIdsSha256',
                          'sbomTuplesSha256','secretFindingsSha256','secretCount')}
    sql.update(meta);compare(api,sql)
    pages['vuln']['resultContractVersion']=1
    try: collect(FakeHttp(),fixture_id,'synthetic-owner','synthetic-foreign')
    except Refusal as e: require(str(e)=='invalid_v2_metadata','v2_refusal_missing')
    else: raise Refusal('legacy_page_accepted')
    generated=json.loads(overlay('sha256:'+'a'*64,'sha256:'+'b'*64,['synthetic-id']))
    require(all(generated['services']['api']['environment'][k]==v for k,v in OFF.items()),'overlay_flag_drift')
    require(generated['services']['api']['ports']==[] and
            generated['services']['web']['image']==INGRESS and
            PORT_OVERRIDE.count(b'127.0.0.1:18083:8080')==1,'overlay_port_drift')
    project='dip-cve14-proof-'+'0'*16
    cid,nid='c'*64,'d'*64
    volume=project+'_scan_ledger'
    class FakeRunner:
        def __init__(self, populated=True, foreign=False, collision=False):
            self.resources={'containers':[cid] if populated else [],'networks':[nid] if populated else [],
                            'volumes':[volume] if populated else []}
            self.foreign,self.collision,self.actions=foreign,collision,[]
        def text(self,args,**kw):
            assert args[-2:]==['--filter','label=com.docker.compose.project='+project]
            if args[0]!='volume': assert '--no-trunc' in args
            key={'container':'containers','network':'networks','volume':'volumes'}[args[0]]
            return '\n'.join(self.resources[key])
        def json(self,args,**kw):
            assert args[1]=='inspect'
            labels={'com.docker.compose.project':'foreign' if self.foreign else project}
            if args[0]=='container':
                assert args[2]==cid
                return [{'Id':cid,'Name':'/'+project+'-worker-1','Config':{'Labels':labels}}]
            if args[0]=='network':
                assert args[2]==nid
                return [{'Id':nid,'Name':project+'_scan_internal','Labels':labels,'Containers':{}}]
            assert args==['volume','inspect',volume]
            return [{'Name':volume,'Labels':labels}]
        def run(self,args,**kw):
            if args[1]=='inspect':
                assert not kw['check'] and args[0] in ('volume','network')
                return (b'[{}]',0) if self.collision else (b'[]',1)
            assert kw['cleanup'] and args[1] in ('rm','stop')
            self.actions.append(args)
            if args[1]=='rm': self.resources[{'container':'containers','network':'networks','volume':'volumes'}[args[0]]]=[]
            return b'',0
    empty=FakeRunner(populated=False);require_empty_namespace(empty,project)
    for mock,code in [(FakeRunner(),'project_collision'),
                      (FakeRunner(populated=False,collision=True),'preexisting_or_unavailable_namespace')]:
        try: require_empty_namespace(mock,project)
        except Refusal as error: require(str(error)==code and not mock.actions,'unsafe_collision_cleanup')
        else: raise Refusal('collision_accepted')
    own=FakeRunner();clean,left=cleanup_owned(own,project,True)
    require(clean['removed'] and not any(left.values()) and
            own.actions==[['container','rm','-f',cid],['network','rm',nid],['volume','rm',volume]],'exact_cleanup_failed')
    stopped=FakeRunner();clean,left=cleanup_owned(stopped,project,False)
    require(clean['retainedOnFailure'] and all(left.values()) and
            stopped.actions==[['container','stop','--time','2',cid]],'failure_resources_not_retained')
    foreign=FakeRunner(foreign=True);clean,left=cleanup_owned(foreign,project,False)
    require(not foreign.actions and clean['failures']==['own_container_cleanup_failed'],'foreign_cleanup_permitted')
    return {'kind':'pure-candidate-self-test','passed':True,'dockerCalled':False,'socketsOpened':False,
            'syntheticCollectorPositiveAndLegacyRefusal':True,'syntheticSqlApiHashComparison':True,
            'reviewGateBeforeProbes':True,'mockedCollisionAndExactIdCleanup':True,'runtimeProofExecuted':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group()
    mode.add_argument('--plan',action='store_true')
    mode.add_argument('--self-test',action='store_true')
    mode.add_argument('--execute',action='store_true',help='parent only AFTER exact script/source/gateway review')
    mode.add_argument('--diagnose-build',action='store_true',help='parent only AFTER exact script/source/context/scratch review; no runtime')
    parser.add_argument('--reviewed-script-sha256'); parser.add_argument('--reviewed-source-sha256')
    parser.add_argument('--docker-context'); parser.add_argument('--gateway-image')
    parser.add_argument('--ingress-image',help='execute only: exact approved cached OWN nginx ingress image ID')
    parser.add_argument('--release-dir'); parser.add_argument('--scratch-dir')
    bind_mode=parser.add_mutually_exclusive_group()
    bind_mode.add_argument('--daemon-bind-source-prefix',default='',
                           help='execute only: explicit /host_mnt representation for validated desktop-linux /Users release')
    bind_mode.add_argument('--daemon-bind-source-policy',default='',
                           help='execute only: desktop-exact-literal-or-host-mnt-v1 for validated desktop-linux /Users release')
    args=parser.parse_args()
    try:
        require(args.execute or not (args.daemon_bind_source_prefix or args.daemon_bind_source_policy or args.ingress_image),
                'execute_arguments_without_execute')
        if args.self_test: print(json.dumps(self_test())); return 0
        data,hashes,source_sha=stable_inventory(); receipt=history(); proposal=plan(hashes,source_sha)
        if args.execute: return execute(args,data,hashes,proposal,receipt)
        if args.diagnose_build: return diagnose_build(args,data,hashes,proposal,receipt)
        require(not any((args.reviewed_script_sha256,args.reviewed_source_sha256,args.docker_context,
                         args.gateway_image,args.ingress_image,args.release_dir,args.scratch_dir,
                         args.daemon_bind_source_prefix,args.daemon_bind_source_policy)),
                'execute_arguments_without_execute')
        print(json.dumps(proposal,indent=2)); return 0
    except (Refusal,OSError,ValueError,KeyError,StopIteration,TypeError) as error:
        print(json.dumps({'kind':'cve14-combined-executable-candidate','passed':False,
                          'reason':str(error) if isinstance(error,Refusal) else 'candidate_input_unavailable'})); return 1


if __name__=='__main__':
    sys.exit(main())
