#!/usr/bin/env python3
"""REVIEW CANDIDATE: one synthetic image qualification; never a stand controller.

prepare is daemon-free. run requires a fresh independent review, an explicit
Unix Engine endpoint and exact packet pin. No real volumes/Env/credentials or app
entrypoints are used. Three sequential OWN containers, total wall budget240s,
UID65532/capsALL dropped/netnone/ROroot/memory2GiB/swap-total2GiB/CPU1/PIDs64.
Only public RO file binds and fresh synthetic tmpfs; no pulls/builds/retries.
Failure retains packet and all created IDs. Successful cleanup checks actual
immutable ID/image/name/OWN label plus the complete creation envelope; no rm -f.
Source/import resolution is tested WITHOUT evaluating application bodies. This
is NOT full external-package execution, startup/listener/provider qualification,
actual-state resource admission, or production approval. No automatic recovery.

Separate *-diagnostic modes: ONE fresh NEW API only, 90s actor /45s program,
retained on every outcome, two public RO binds, /backup2GiB + /tmp128MiB.
The consumed R2 payload stays byte-for-byte frozen; its permission is NOT reused.
Diagnostic run emits only code/ok/checkpoint/reason; never qualification success.
Caller MUST impose a90s fence too: client kill is not daemon cancellation proof.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time
from types import MappingProxyType

OLD = 'sha256:487c3909d3eeee08d60840a81c1adeb61c292aee0a31df17b2a8cf92f6dbb58c'
API = 'sha256:4b3a3d4b3c2658ec9a36209afcac69eda2b64cef6e055a5e2716e2602e5338d1'
WORKER = 'sha256:891b5adccbe469345cea585e75dc71c6d3bf93405c5a18386795af1b012b314d'
IMAGES = {'old': OLD, 'api': API, 'worker': WORKER}
AGGREGATE = '29c3ca5bd186d625cc102e2f7e43b4f1e8e168ba3372cabd7840cc21b6676a37'
STAGE = Path('/private/tmp/dip-public-source-overlay-context-20261012-gpt61-overlay-r2')
STAGE_SHA = '94f8e853696afb4c50218fb8f281765cd33be32768711f6a2292ff860c5f4e4f'
HELPER_SHA = '323ca629483f92896634ada79d2c8f098d9ff885464eb24ba9d86bb75e563dee'
TEST_SHA = 'f9668e4f288a712969bf50199f38464b3d854d28d3dc4d4e58647c9c7d59453e'
MIB = 1024 ** 2
GIB = 1024 ** 3
CAP = 65536
LABEL = 'io.diplom.synthetic-preservation-qualification'
HEX = re.compile(r'[a-f0-9]{64}\Z')
ROLES = ('old', 'api', 'worker')
FILES = ('qualification.mjs', 'snapshot.mjs', 'sources.json')
TMPFS = {'/backup': 'rw,noexec,nosuid,nodev,size=2147483648,mode=0700,uid=65532,gid=65532',
         '/tmp': 'rw,noexec,nosuid,nodev,size=134217728,mode=0700,uid=65532,gid=65532',
         '/source/auth': 'rw,noexec,nosuid,nodev,size=16777216,mode=0700,uid=65532,gid=65532',
         '/source/data': 'rw,noexec,nosuid,nodev,size=16777216,mode=0700,uid=65532,gid=65532'}
CLEAN_ENV = ('PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
             'HOME=/tmp', 'TMPDIR=/tmp', 'TSX_DISABLE_CACHE=1')

# Only new synthetic files are opened as SQLite. PUBLIC OLD source literals,
# pinned before extraction, build natural13 (not a14 DB relabelled13).
QUALIFICATION_JS = r'''import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {spawnSync} from 'node:child_process';
import {fileURLToPath,pathToFileURL} from 'node:url';
const mode=process.argv[2], duration=Number(process.argv[3]);
const started=Date.now(); const timer=setTimeout(()=>process.exit(1),duration).unref();
const sha=b=>createHash('sha256').update(b).digest('hex');
const req=createRequire('/app/server/api/package.json');
const settings={AUTH_ORIGIN:null,AUTH_ALLOW_INSECURE_LOCAL_HTTP:null,SCAN_BROWSER_ALLOWED_USER_IDS:null,SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS:null};
const fail=()=>{process.stdout.write('{"code":"QUALIFICATION_REFUSED","ok":false}\n');process.exitCode=1;};
function read(p,cap=4*1024**2){const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const s=fs.fstatSync(fd);assert(s.isFile()&&s.nlink===1&&s.size<=cap);const b=fs.readFileSync(fd);const a=fs.fstatSync(fd);assert.deepEqual([a.dev,a.ino,a.size,a.mtimeMs,a.ctimeMs],[s.dev,s.ino,s.size,s.mtimeMs,s.ctimeMs]);assert.equal(fs.lstatSync(p).ino,s.ino);return b;}finally{fs.closeSync(fd);}}
function old(p,pin){const b=read(p);assert.equal(sha(b),pin);return b.toString('utf8');}
function make(DB,p,sql){assert(!fs.existsSync(p));const db=new DB(p);db.exec(sql);db.close();fs.chmodSync(p,0o600);}
function remaining(){const ms=duration-(Date.now()-started)-1000;assert(ms>0);return Math.min(ms,20000);}
function cli(args,code,input){const out=spawnSync(process.execPath,['/snapshot.mjs',...args],{cwd:'/app/server/api',env:Object.fromEntries(['PATH','HOME','TMPDIR','TSX_DISABLE_CACHE'].map(k=>[k,process.env[k]])),input:input?JSON.stringify(settings):undefined,timeout:remaining(),maxBuffer:2048,encoding:'utf8'});assert.equal(out.error,undefined);assert.equal(out.status,0);assert.equal(out.stderr,'');assert.equal(out.stdout,JSON.stringify({code,ok:true})+'\n');}
function native(DB){assert.equal(process.getuid(),65532);assert.equal(process.getgid(),65532);assert.equal(process.platform,'linux');assert.equal(process.arch,'arm64');assert.deepEqual(Object.keys(process.env).sort(),['HOME','PATH','TMPDIR','TSX_DISABLE_CACHE']);const p='/tmp/native.sqlite';make(DB,p,'CREATE TABLE n(v); INSERT INTO n VALUES(7)');const db=new DB(p,{readonly:true,fileMustExist:true});assert.equal(db.prepare('SELECT v FROM n').get().v,7);const sqlite=db.prepare('SELECT sqlite_version() AS v').get().v;db.close();const binaries=Object.keys(req.cache).filter(p=>p.endsWith('.node'));assert.equal(binaries.length,1);return {node:process.version,abi:process.versions.modules,sqlite,betterSqlite:JSON.parse(read(req.resolve('better-sqlite3/package.json'))).version,nativeSha256:sha(read(binaries[0],32*1024**2)),nodeSha256:sha(read(process.execPath,128*1024**2))};}
async function storage(DB){
 const auth=old('/app/server/api/src/auth/auth.store.ts','b39f54808f63e07959ead476bf61a574cd3a4d288d96cbb5035b1bfecb24d4f0');
 const ledger=old('/app/server/api/src/ledger/ledger.ts','9b0b3cce477da38aa91aeba2946a9b1ab334615f9b3f3a5d8273a45b36c14626');
 const quota=old('/app/server/api/src/llm/quota-ledger.ts','155418a95000ea0f3e6ee380a2371b5f9035ed2d53453a21a995c6d6c74712be');
 const a=/this\.db\.exec\(`([^`]*)`\)/.exec(auth)[1]; assert(!a.includes('${'));
 const blocks=[...ledger.slice(ledger.indexOf('constructor(filename'),ledger.indexOf('this.orm =')).matchAll(/this\.db\.exec\(`([^`]*)`\)/g)].map(m=>m[1]); assert.equal(blocks.length,13);assert(blocks.every(b=>!b.includes('${')));
 const q=/this\.db\.exec\(`([^`]*)`\)/.exec(quota)[1].replace('${APPLICATION}','1145655601');assert(!q.includes('${'));
 make(DB,'/source/auth/auth.sqlite',a+`INSERT INTO users VALUES('${'a'.repeat(32)}','synthetic-only','${'b'.repeat(32)}',zeroblob(64)); INSERT INTO sessions VALUES('${'c'.repeat(64)}','${'a'.repeat(32)}',1234567890,NULL); INSERT INTO auth_attempts VALUES('synthetic-bucket',2,1234567890);`);
 const l=new DB('/source/data/ledger.sqlite');l.pragma('foreign_keys=OFF');l.exec('BEGIN IMMEDIATE');for(const b of blocks)l.exec(b);l.exec('COMMIT');l.pragma('foreign_keys=ON');assert.equal(l.pragma('user_version',{simple:true}),13);
 l.exec(`INSERT INTO scans(id,subject,idempotency_key,registry,repository,digest,platform,state,checks) VALUES('synthetic-scan','synthetic-owner','synthetic-key','invalid.local','synthetic','sha256:synthetic','linux/amd64','completed','["vuln"]'); INSERT INTO outbox VALUES('synthetic-scan','done',3,123,456); INSERT INTO scan_archive_results VALUES('synthetic-scan',1,' unicode-я exact '); INSERT INTO scan_events(scan_id,state) VALUES('synthetic-scan','completed');`);l.close();fs.chmodSync('/source/data/ledger.sqlite',0o600);
 make(DB,'/source/auth/llm-usage.sqlite',q+`UPDATE quota_meta SET clock=123456789; INSERT INTO quota_attempt VALUES('synthetic-attempt','${'a'.repeat(64)}','${'b'.repeat(64)}','${'c'.repeat(64)}','${'d'.repeat(64)}','${'e'.repeat(64)}','{}',0,1234567890,'fault',17,0,0,17,0,0,'synthetic-private-canary');`);
 const quotaBytes=read('/source/auth/llm-usage.sqlite');
 // An idle connection keeps real committed WAL evidence present. No active
 // transaction or further fixture writes overlap capture/plan/apply/compare.
 const held=new DB('/source/auth/auth.sqlite');held.pragma('journal_mode=WAL');held.pragma('wal_autocheckpoint=0');held.prepare('INSERT INTO users VALUES(?,?,?,?)').run('1'.repeat(32),'synthetic-WAL-only','2'.repeat(32),Buffer.alloc(64,1));assert(fs.statSync('/source/auth/auth.sqlite-wal').size>32);
 fs.mkdirSync('/tmp/partial',{mode:0o700});for(const label of ['auth','data']){fs.mkdirSync('/tmp/partial/'+label,{mode:0o700});for(const n of fs.readdirSync('/source/'+label))fs.copyFileSync('/source/'+label+'/'+n,'/tmp/partial/'+label+'/'+n,fs.constants.COPYFILE_EXCL);}
 const before=read('/source/auth/auth.sqlite-wal');
 cli(['capture','--preservation-migration','/backup/pre'],'CAPTURED');assert.deepEqual(read('/source/auth/auth.sqlite-wal'),before);
 cli(['plan-migration','--preservation-migration','/backup/pre'],'PLANNED',true);
 cli(['apply-migration','--preservation-migration','/backup/pre'],'MIGRATED');
 cli(['capture','--preservation-migration','/backup/post'],'CAPTURED');
 cli(['compare-migrated','--preservation-migration','/backup/pre','/backup/post'],'MIGRATION_MATCH');
 cli(['compatibility','--preservation-migration','/backup/post'],'COMPATIBLE',true);
 assert.deepEqual(read('/source/auth/llm-usage.sqlite'),quotaBytes);
 const post=JSON.parse(read('/backup/post/manifest.json',32*1024**2));assert.equal(post.stores.find(s=>s.path==='auth/auth.sqlite').logical.tables.find(t=>t.name==='users').rows,2);held.close();
 // One small additional SYNTHETIC partial-commit case, no production switch.
 const {createSnapshotter}=await import('/snapshot.mjs');const backup='/backup/partial-backup';fs.mkdirSync(backup,{mode:0o700});let rw=0;
 function injected(p,o){assert.notEqual(p,'/tmp/partial/auth/llm-usage.sqlite');const db=new DB(p,o);if(['/tmp/partial/auth/auth.sqlite','/tmp/partial/data/ledger.sqlite'].includes(p))rw++;if(p==='/tmp/partial/data/ledger.sqlite'){const exec=db.exec.bind(db);db.exec=sql=>{if(sql==='COMMIT')throw Error('synthetic-only');return exec(sql);};}return db;}
 const api=createSnapshotter({Database:injected,sourceRoots:{auth:'/tmp/partial/auth',data:'/tmp/partial/data'},backupRoot:backup,preservationMigration:true});const pre=backup+'/pre';assert.deepEqual(await api.capture(pre),{code:'CAPTURED',ok:true});assert.deepEqual(await api.planMigration(pre,Buffer.from(JSON.stringify(settings))),{code:'PLANNED',ok:true});assert.deepEqual(await api.applyMigration(pre),{code:'IO_FAILURE',ok:false});assert.equal(rw,2);assert(fs.existsSync(backup+'/migration/apply-attempt.json'));assert(!fs.existsSync(backup+'/migration/applied.json'));assert.equal((await api.applyMigration(pre)).ok,false);assert.equal(rw,2);
 const check=new DB('/tmp/partial/data/ledger.sqlite',{readonly:true,fileMustExist:true});assert.equal(check.pragma('user_version',{simple:true}),13);check.close();const committed=new DB('/tmp/partial/auth/auth.sqlite',{readonly:true,fileMustExist:true});assert.equal(committed.prepare('SELECT count(*) AS n FROM trusted_sessions').get().n,1);assert.equal(committed.prepare('SELECT count(*) AS n FROM browser_access').get().n,1);committed.close();assert.deepEqual(read('/tmp/partial/auth/llm-usage.sqlite'),quotaBytes);
}
async function closure(role){
 const manifest=JSON.parse(read('/sources.json',65536));assert.equal(manifest.aggregate,'29c3ca5bd186d625cc102e2f7e43b4f1e8e168ba3372cabd7840cc21b6676a37');assert.equal(manifest.files.length,108);
 const files=new Map(manifest.files.map(f=>['/app/'+f.path,f]));for(const [p,f]of files){const b=read(p);assert.equal(b.length,f.bytes);assert.equal(sha(b),f.sha256);}
 const ts=req('typescript');const entry=role==='api'?'/app/server/api/src/oci/nginx-local.main.ts':'/app/server/api/src/worker/nginx-local-worker.main.ts';
 const queue=[entry],seen=new Set(),edges=[],deps=new Map();
 while(queue.length){const p=queue.shift();if(seen.has(p))continue;assert(files.has(p));seen.add(p);assert(seen.size<=108);const source=read(p).toString('utf8');const ast=ts.createSourceFile(p,source,ts.ScriptTarget.Latest,true);assert.equal(ast.parseDiagnostics.length,0);const requests=[];
 function visit(n){if(ts.isImportDeclaration(n)||ts.isExportDeclaration(n)){if(n.moduleSpecifier&&!n.isTypeOnly&&!n.importClause?.isTypeOnly){assert(ts.isStringLiteral(n.moduleSpecifier));requests.push(n.moduleSpecifier.text);}}else if(ts.isCallExpression(n)&&(n.expression.kind===ts.SyntaxKind.ImportKeyword||(ts.isIdentifier(n.expression)&&n.expression.text==='require'))){assert.equal(n.arguments.length,1);assert(ts.isStringLiteral(n.arguments[0]));requests.push(n.arguments[0].text);}ts.forEachChild(n,visit);}visit(ast);
 for(const spec of requests){const url=import.meta.resolve(spec,pathToFileURL(p).href);if(spec.startsWith('node:')){assert.equal(url,spec);continue;}assert(url.startsWith('file:'));const actual=fileURLToPath(url);if(spec.startsWith('.')){const base=path.resolve(path.dirname(p),spec),expected=files.has(base)?base:base.replace(/\.js$/,'.ts');assert(files.has(expected));assert.equal(actual,expected);if(expected.endsWith('.ts'))assert(!fs.existsSync(expected.slice(0,-3)+'.js'));queue.push(expected);edges.push([p,spec,actual]);}else{const real=fs.realpathSync(actual);assert(real.startsWith('/app/node_modules/')||real.startsWith('/app/server/api/node_modules/'));deps.set(spec,{resolved:real,sha256:sha(read(real,8*1024**2))});}assert(edges.length+deps.size<=1024);}
 }
 const wrapper='/usr/local/bin/docker-entrypoint.sh';const entrypoint=fs.existsSync(wrapper)?{path:wrapper,sha256:sha(read(wrapper,65536))}:null;
 return {entry,launchCommand:['node','--import','tsx',path.relative('/app/server/api',entry)],entrypoint,sourceFiles:seen.size,edges,dependencies:Object.fromEntries([...deps].sort()),tsx:JSON.parse(read(req.resolve('tsx/package.json'))).version,typescript:ts.version,appBodiesEvaluated:false,externalPackageBodiesQualified:false};
}
try{assert(['old','api','worker'].includes(mode));assert(Number.isInteger(duration)&&duration>0&&duration<=240000);const DB=req('better-sqlite3');const info=native(DB);let proof;if(mode==='old'){await storage(DB);proof={sixCliOperations:true,committedWalRetained:true,quotaBytesUnchanged:true,partialCommitHold:true};}else proof=await closure(mode);const result=JSON.stringify({code:'SYNTHETIC_QUALIFIED',ok:true,role:mode,native:info,proof});assert(Buffer.byteLength(result)<65536);process.stdout.write(result+'\n');}catch{fail();}finally{clearTimeout(timer);}
'''


def need(ok):
    if not ok:
        raise ValueError('QUALIFICATION_REFUSED')


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_file(p, cap=4*MIB):
    p = Path(p)
    need(p.is_absolute() and str(p.resolve()) == str(p))
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and 0 < s.st_size <= cap)
        raw = bytearray()
        while len(raw) <= cap:
            b = os.read(fd, min(65536, cap + 1 - len(raw)))
            if not b:
                break
            raw.extend(b)
        identity = lambda x: (x.st_dev,x.st_ino,x.st_size,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_mtime_ns,x.st_ctime_ns)
        need(len(raw) == s.st_size and identity(os.fstat(fd)) == identity(s) and identity(os.lstat(p)) == identity(s))
        return bytes(raw)
    finally:
        os.close(fd)


def packet_name(p):
    need(p.is_absolute() and p.parent == Path('/private/tmp') and
         re.fullmatch(r'dip-preservation-images-[a-z0-9-]{1,64}', p.name))


def sync_directory(p):
    fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(p, raw, mode=0o600):
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
        os.fsync(fd)
    finally:
        os.close(fd)
    # Persist the exclusive filename BEFORE returning to Engine/create/start.
    # A failure retains partial material and propagates; never retry/adopt it.
    sync_directory(p.parent)


def build_packet(packet):
    """Daemon-free bounded public reads; no writes, fixture/import/native execution."""
    packet_name(packet)
    manifest = read_file(STAGE/'overlay-manifest.json', CAP)
    need(sha(manifest) == STAGE_SHA)
    m = json.loads(manifest)
    files = [f for f in m['context_files'] if f['path'].endswith(('.ts','.mjs'))]
    need(len(files) == 108 and m['source_sha256'] == AGGREGATE and sha(canonical(files)) == AGGREGATE)
    for f in files:
        need(re.fullmatch(r'server/(api|runtime)/src/[A-Za-z0-9_./-]+\.(ts|mjs)', f['path']) and '..' not in f['path'])
        raw = read_file(STAGE/f['path'])
        need(len(raw) == f['bytes'] and sha(raw) == f['sha256'])
    root = Path(__file__).resolve().parent
    need(sha(read_file(root.parent/'compose.stand.nginx.local.yaml')) == 'f6587a7a355ac1c51610d65f1851223a72b9e0e64e09f548c3e8faca0ab0e3a6')
    helper = read_file(root/'sqlite_state_snapshot.mjs')
    need(sha(helper) == HELPER_SHA and sha(read_file(root/'sqlite_state_snapshot.test.mjs')) == TEST_SHA)
    payloads = {'qualification.mjs': QUALIFICATION_JS.encode(), 'snapshot.mjs': helper,
                'sources.json': canonical({'aggregate':AGGREGATE,'files':files})}
    plan = {'format':'synthetic-preservation-images-v1','images':IMAGES,'aggregate':AGGREGATE,
            'files':{name:sha(raw) for name,raw in payloads.items()},'authorSha256':sha(read_file(Path(__file__).resolve())),
            'helperSha256':HELPER_SHA,'stageSha256':STAGE_SHA,'qualified':False,
            'totalSeconds':240,'fixturesOnly':True,'appStartup':False}
    return payloads, plan


def prepare(packet):
    payloads, plan = build_packet(packet)
    packet.mkdir(mode=0o700)  # Exclusive: failure outputs are never adopted/reused.
    sync_directory(packet.parent)  # Persist the packet name itself, not only its children.
    (packet/'client').mkdir(mode=0o700)  # Empty Docker config: no host credentials/context adoption.
    for name, raw in payloads.items():
        write_new(packet/name, raw, 0o444)  # Public file-only RO binds, host parent stays0700.
    write_new(packet/'plan.json', canonical(plan))
    sync_directory(packet)
    return sha(canonical(plan))


def load_packet(packet, expected):
    packet_name(packet)
    s = os.lstat(packet)
    need(stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode) == 0o700 and s.st_uid == os.getuid())
    raw = read_file(packet/'plan.json', CAP)
    need(HEX.fullmatch(expected) and sha(raw) == expected)
    p = json.loads(raw)
    need(raw == canonical(p) and p['format'] == 'synthetic-preservation-images-v1' and p['images'] == IMAGES and
         p['aggregate'] == AGGREGATE and p['qualified'] is False and p['totalSeconds'] == 240 and
         p['fixturesOnly'] is True and p['appStartup'] is False and p['helperSha256'] == HELPER_SHA and
         p['authorSha256'] == sha(read_file(Path(__file__).resolve())) and set(p['files']) == set(FILES))
    need(set(os.listdir(packet)) == {*FILES,'plan.json','client'})
    need(not os.listdir(packet/'client'))
    for name, pin in p['files'].items():
        need(HEX.fullmatch(pin) and sha(read_file(packet/name)) == pin and stat.S_IMODE(os.lstat(packet/name).st_mode) == 0o444)
    return p


def command(packet, role, label, duration):
    need(role in ROLES and HEX.fullmatch(label) and 0 < duration <= 240000)
    args = ['create','--name','dip-preservation-qual-'+role+'-'+label[:16], '--label',LABEL+'='+label,
            '--pull','never','--platform','linux/arm64','--user','65532:65532','--network','none',
            '--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--memory','2147483648',
            '--memory-swap','2147483648','--cpus','1','--pids-limit','64','--workdir','/app/server/api',
            '--entrypoint','/usr/bin/env']
    for target, options in TMPFS.items():
        args += ['--tmpfs',target+':'+options]
    for name in FILES:
        args += ['--mount',f'type=bind,src={packet/name},dst=/{name},readonly']
    argv = ['-i',*CLEAN_ENV,'node']
    if role != 'old':
        argv += ['--import','tsx','--experimental-import-meta-resolve']
    return args + [IMAGES[role],*argv,'/qualification.mjs',role,str(duration)]


# No private Env is read. Docker context/credential config is isolated; an explicit
# reviewed Unix endpoint is mandatory, never guessed/fallen back to by run.
class Docker:
    def __init__(self, packet, endpoint, deadline):
        need(re.fullmatch(r'unix:///[A-Za-z0-9_./-]+', endpoint) and '..' not in endpoint)
        self.prefix = ['docker','--config',str(packet/'client'),'--host',endpoint]
        self.deadline = deadline
        self.env = {'PATH':'/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin','HOME':str(packet/'client')}

    def call(self, args, timeout=20):
        limit = min(float(timeout), self.deadline-time.monotonic())
        need(limit > 0)
        proc = subprocess.Popen(self.prefix+list(args), env=self.env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        selector = selectors.DefaultSelector()
        output = {proc.stdout:bytearray(),proc.stderr:bytearray()}
        for stream in output:
            selector.register(stream, selectors.EVENT_READ)
        end = time.monotonic()+limit
        try:
            while selector.get_map():
                need(time.monotonic() < end)
                for key, _ in selector.select(min(0.1,max(0,end-time.monotonic()))):
                    b = os.read(key.fileobj.fileno(),8192)
                    if not b:
                        selector.unregister(key.fileobj)
                    else:
                        output[key.fileobj].extend(b)
                        need(sum(map(len,output.values())) <= CAP)
            need(proc.wait(timeout=max(0.001,end-time.monotonic())) == 0)
            need(not output[proc.stderr])
            return bytes(output[proc.stdout])
        finally:
            selector.close()
            if proc.poll() is None:
                proc.kill()  # CLI only: NOT cancellation/daemon/container proof.
            proc.wait()
            for stream in output:
                stream.close()

    def inspect(self, ident):
        # Deliberately excludes .Config.Env and all logs/private state.
        template = '{{json .Id}}\n{{json .Image}}\n{{json .Name}}\n{{json .State}}\n{{json .Config.Labels}}\n{{json .HostConfig}}\n{{json .Mounts}}\n{{json .Config.Entrypoint}}\n{{json .Config.Cmd}}\n{{json .Config.User}}\n{{json .Config.WorkingDir}}'
        return [json.loads(line) for line in self.call(['container','inspect','--format',template,ident]).splitlines()]


def guard(record, ident, packet, role, label, argv, state):
    need(HEX.fullmatch(ident) and len(record) == 11)
    cid,image,name,status,labels,host,mounts,entry,cmd,user,cwd = record
    need(cid == ident and image == IMAGES[role] and name == '/dip-preservation-qual-'+role+'-'+label[:16] and
         labels.get(LABEL) == label and not any(k.startswith('com.docker.compose.') for k in labels) and
         user == '65532:65532' and cwd == '/app/server/api' and
         entry == ['/usr/bin/env'] and cmd == argv[argv.index(IMAGES[role])+1:])
    need(host['ReadonlyRootfs'] is True and host['NetworkMode'] == 'none' and
         host['CapDrop'] == ['ALL'] and not host.get('CapAdd') and not host['Privileged'] and
         host['SecurityOpt'] == ['no-new-privileges:true'] and host['Memory'] == 2*GIB and
         host['MemorySwap'] == 2*GIB and host['NanoCpus'] == 10**9 and host['PidsLimit'] == 64 and
         host['Tmpfs'] == TMPFS and not host.get('AutoRemove') and not host.get('PortBindings') and
         not host.get('Binds') and not host.get('Devices') and not host.get('DeviceRequests') and
         host.get('RestartPolicy',{}).get('Name') == 'no')
    binds = [m for m in mounts if m['Type'] == 'bind']
    need(len(binds) == 3 and all(m['RW'] is False and
         m['Source'] == str(packet/Path(m['Destination']).name) and m['Destination'] in ['/'+n for n in FILES]
         for m in binds) and {m['Destination'] for m in binds} == {'/'+n for n in FILES})
    need(all(m['Type'] == 'bind' or m['Type'] == 'tmpfs' and m['Destination'] in TMPFS for m in mounts))
    need(len({m['Destination'] for m in mounts}) == len(mounts) and len(mounts) <= 7)
    need(status['Status'] == state and not status['Running'] and not status['Paused'] and not status.get('Restarting'))
    if state == 'exited':
        need(status['ExitCode'] == 0 and not status['OOMKilled'] and status.get('Error','') == '')


def run(packet, expected, review, endpoint):
    need(re.fullmatch(r'DIP-ARTF-[1-9][0-9]{0,8}', review))  # Parent must verify CONTENT/applicability, not ID shape.
    load_packet(packet, expected)
    write_new(packet/'attempt.json', canonical({'review':review,'packetSha256':expected,'once':True}))
    deadline = time.monotonic()+240
    docker = Docker(packet, endpoint, deadline)
    owned, results = [], {}
    # NO pulls, discovery/adoption, stand/container enumeration or real mount sources.
    for role in ROLES:
        metadata = docker.call(['image','inspect','--format','{{json .Id}}\n{{json .Os}}\n{{json .Architecture}}\n{{json .Config.WorkingDir}}\n{{json .Config.Volumes}}\n{{json .Config.Entrypoint}}\n{{json .Config.Cmd}}',IMAGES[role]])
        image = [json.loads(x) for x in metadata.splitlines()]
        need(len(image) == 7 and image[:4] == [IMAGES[role],'linux','arm64','/app/server/api'] and
             not image[4] and image[5] in (None,[],['docker-entrypoint.sh']) and
             (image[6] is None or isinstance(image[6],list) and all(isinstance(v,str) and len(v)<=256 for v in image[6])))
        write_new(packet/(role+'-image.json'),canonical({'id':image[0],'platform':'linux/arm64',
                  'workingDir':image[3],'volumes':image[4],'entrypoint':image[5],'cmd':image[6]}))
        for name,pin in json.loads(read_file(packet/'plan.json',CAP))['files'].items():
            need(name in FILES and sha(read_file(packet/name)) == pin)
        need(sha(read_file(packet/'plan.json',CAP)) == expected)
        duration = 120000 if role == 'old' else 45000
        need(deadline-time.monotonic() > duration/1000+10)
        argv = command(packet, role, expected, duration)
        ident = docker.call(argv).decode('ascii').strip()
        need(HEX.fullmatch(ident))
        owned.append((role,ident,argv))
        write_new(packet/(role+'-id.json'),canonical({'role':role,'id':ident,'image':IMAGES[role]}))
        guard(docker.inspect(ident),ident,packet,role,expected,argv,'created')
        raw = docker.call(['start','--attach',ident],duration/1000+5)
        result = json.loads(raw)
        need(result['code']=='SYNTHETIC_QUALIFIED' and result['ok'] is True and result['role']==role and
             set(result)=={'code','ok','role','native','proof'})
        native = result['native']
        need(set(native) == {'node','abi','sqlite','betterSqlite','nativeSha256','nodeSha256'} and
             native['betterSqlite'] == '12.11.1' and HEX.fullmatch(native['nativeSha256']) and
             HEX.fullmatch(native['nodeSha256']) and all(isinstance(v,str) and len(v)<=128 for v in native.values()))
        if role == 'old':
            need(result['proof'] == {'sixCliOperations':True,'committedWalRetained':True,'quotaBytesUnchanged':True,'partialCommitHold':True})
        else:
            proof = result['proof']
            entry = 'src/oci/nginx-local.main.ts' if role == 'api' else 'src/worker/nginx-local-worker.main.ts'
            need(proof['entry'] == '/app/server/api/'+entry and proof['launchCommand'] == ['node','--import','tsx',entry] and
                 proof['appBodiesEvaluated'] is False and proof['externalPackageBodiesQualified'] is False and
                 0 < proof['sourceFiles'] <= 108 and len(proof['edges']) <= 1024)
            if image[5] == ['docker-entrypoint.sh']:
                need(proof['entrypoint']['path'] == '/usr/local/bin/docker-entrypoint.sh' and HEX.fullmatch(proof['entrypoint']['sha256']))
        if role == 'api':
            need(native == results['old']['native'])  # Source-only overlay must inherit identical OLD API binaries.
        guard(docker.inspect(ident),ident,packet,role,expected,argv,'exited')
        write_new(packet/(role+'-result.json'),canonical(result))
        results[role]=result
    # If ANY phase/guard/export fails, execution leaves ALL IDs/packet retained.
    # Cleanup occurs only on joint success, exact OWN exited0 guard, no rm -f.
    for role,ident,argv in owned:
        guard(docker.inspect(ident),ident,packet,role,expected,argv,'exited')
        docker.call(['rm',ident])
    write_new(packet/'result.json',canonical({'code':'SYNTHETIC_QUALIFIED','ok':True,'results':results,
                                             'originalStateAccessed':False,'applicationStartupProven':False}))


# Consumed R2 definitions remain frozen evidence, NEVER a retry/adoption route.
FROZEN_R2 = {
    'authorSha256':'b8ad1416359c640e527902708c31a3f11a37f81f43179266f65dbb399c8826dc',
    'testSha256':'390ab91bcfe3039c6337efd6772260bfd6399f83d158a8b6e0977e63a0d57e21',
    'packetSha256':'63e05982518de8ca7c24bf7610f5381bd208dae30ad060f42e76a602079b7f3e',
    'programSha256':'7f0059634023fdd5a8e55a4a89d594fd016481ab13fa04b6e556fd344d26e23b',
}
DIAG_LABEL = 'io.diplom.synthetic-api-diagnostic'
DIAG_FILES = ('qualification.mjs','sources.json')
DIAG_TMPFS = {k:v for k,v in TMPFS.items() if k in ('/backup','/tmp')}
CHECKPOINTS = frozenset(('BOOTSTRAP','NATIVE_DEPENDENCY','NATIVE_CONTEXT','NATIVE_SMOKE','NATIVE_ADDON',
    'NATIVE_PACKAGE','NATIVE_BINARY','MANIFEST','SOURCE_INVENTORY','TS_DEPENDENCY','GRAPH_PARSE',
    'GRAPH_SPECIFIER','GRAPH_RESOLVE','GRAPH_EXPECTED','GRAPH_SHADOW','GRAPH_DEPENDENCY','LOADER_METADATA',
    'COMPLETE','HOST_PACKET','HOST_ATTEMPT','HOST_IMAGE','HOST_CREATE','HOST_CREATED_GUARD','HOST_START',
    'HOST_EXITED_GUARD','HOST_RECEIPT'))
REASONS = frozenset(('PASS','ASSERTION','DEPENDENCY_LOAD','CONTEXT','MISSING','NOT_REGULAR','MULTILINK',
    'OVERSIZE','IDENTITY_CHANGED','READ_FAILED','SQLITE_VALUE','ADDON_COUNT','ADDON_FILE','PACKAGE_METADATA',
    'PACKAGE_VERSION','BINARY_FILE','MANIFEST_SHAPE','SOURCE_SIZE','SOURCE_HASH','PARSE_DIAGNOSTIC',
    'NONLITERAL_IMPORT','RESOLVE_ERROR','NOT_FILE_URL','RESOLVE_MISMATCH','EXPECTED_MISSING','SHADOW',
    'DEPENDENCY_ESCAPE','GRAPH_LIMIT','TIME_LIMIT','PRELOAD_OR_PROTOCOL','INVALID_RECEIPT','GUARD_REFUSED'))


def diagnostic_program():
    """Instrument frozen native/closure checks; never evaluate application bodies."""
    need(sha(QUALIFICATION_JS.encode()) == FROZEN_R2['programSha256'])
    native = next(line for line in QUALIFICATION_JS.splitlines() if line.startswith('function native(DB)'))
    make = next(line for line in QUALIFICATION_JS.splitlines() if line.startswith('function make(DB,p,sql)'))
    graph = QUALIFICATION_JS[QUALIFICATION_JS.index('async function closure(role)'):QUALIFICATION_JS.index("try{assert(['old','api','worker']")]
    def insert(text, old, new):
        need(text.count(old) == 1)
        return text.replace(old,new)
    native = insert(native,"function native(DB){","function native(DB){mark('NATIVE_CONTEXT','CONTEXT');")
    native = insert(native,"const p='/tmp/native.sqlite';","mark('NATIVE_SMOKE','SQLITE_VALUE');const p='/tmp/native.sqlite';")
    native = insert(native,'const binaries=',"mark('NATIVE_ADDON','ADDON_COUNT');const binaries=")
    native = insert(native,"betterSqlite:JSON.parse(read(req.resolve('better-sqlite3/package.json'))).version",
                    "betterSqlite:at('NATIVE_PACKAGE','PACKAGE_METADATA',()=>JSON.parse(read(req.resolve('better-sqlite3/package.json'))).version)")
    native = insert(native,'nativeSha256:sha(read(binaries[0],32*1024**2))',
                    "nativeSha256:at('NATIVE_ADDON','ADDON_FILE',()=>sha(read(binaries[0],32*1024**2)))")
    native = insert(native,'nodeSha256:sha(read(process.execPath,128*1024**2))',
                    "nodeSha256:at('NATIVE_BINARY','BINARY_FILE',()=>sha(read(process.execPath,128*1024**2)))")
    graph = insert(graph,' const manifest='," mark('MANIFEST','MANIFEST_SHAPE');const manifest=")
    graph = insert(graph,'const b=read(p);assert.equal(b.length,f.bytes);assert.equal(sha(b),f.sha256);',
                   "mark('SOURCE_INVENTORY','SOURCE_SIZE');const b=read(p);assert.equal(b.length,f.bytes);mark('SOURCE_INVENTORY','SOURCE_HASH');assert.equal(sha(b),f.sha256);")
    graph = insert(graph," const ts=req('typescript');"," mark('TS_DEPENDENCY','DEPENDENCY_LOAD');const ts=req('typescript');")
    graph = insert(graph,'assert(files.has(p));seen.add(p);assert(seen.size<=108);',
                       "mark('GRAPH_EXPECTED','EXPECTED_MISSING');assert(files.has(p));seen.add(p);mark('GRAPH_DEPENDENCY','GRAPH_LIMIT');assert(seen.size<=108);")
    graph = insert(graph,'const ast=ts.createSourceFile(',"mark('GRAPH_PARSE','PARSE_DIAGNOSTIC');const ast=ts.createSourceFile(")
    graph = insert(graph,' function visit(n){'," function visit(n){mark('GRAPH_SPECIFIER','NONLITERAL_IMPORT');")
    graph = insert(graph,'const url=import.meta.resolve(',"mark('GRAPH_RESOLVE','RESOLVE_ERROR');const url=import.meta.resolve(")
    graph = insert(graph,"assert(url.startsWith('file:'));","mark('GRAPH_RESOLVE','NOT_FILE_URL');assert(url.startsWith('file:'));")
    graph = insert(graph,'assert(files.has(expected));assert.equal(actual,expected);',
                   "mark('GRAPH_EXPECTED','EXPECTED_MISSING');assert(files.has(expected));mark('GRAPH_RESOLVE','RESOLVE_MISMATCH');assert.equal(actual,expected);")
    graph = insert(graph,"if(expected.endsWith('.ts'))assert(!fs.existsSync(expected.slice(0,-3)+'.js'));",
                   "if(expected.endsWith('.ts')){mark('GRAPH_SHADOW','SHADOW');assert(!fs.existsSync(expected.slice(0,-3)+'.js'));}")
    graph = insert(graph,'const real=fs.realpathSync(actual);',"mark('GRAPH_DEPENDENCY','DEPENDENCY_ESCAPE');const real=fs.realpathSync(actual);")
    graph = insert(graph,'assert(edges.length+deps.size<=1024);',"mark('GRAPH_DEPENDENCY','GRAPH_LIMIT');assert(edges.length+deps.size<=1024);")
    graph = insert(graph," const wrapper='/usr/local/bin/docker-entrypoint.sh';"," mark('LOADER_METADATA','PACKAGE_METADATA');const wrapper='/usr/local/bin/docker-entrypoint.sh';")
    header = r'''import rawAssert from 'node:assert/strict';
import fs from 'node:fs';import path from 'node:path';import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';import {fileURLToPath,pathToFileURL} from 'node:url';
let checkpoint='BOOTSTRAP',reason='CONTEXT';let timer;const failureReason=Symbol('closedReason');
function mark(c,r){checkpoint=c;reason=r;}
function reject(r){const e=new Error('Diagnostic refused');e[failureReason]=r;throw e;}
function ensure(v,r){if(!v)reject(r);}
const assert=new Proxy(rawAssert,{apply(t,self,args){try{return Reflect.apply(t,self,args);}catch{reject(reason);}},get(t,k){const v=t[k];return typeof v==='function'?(...args)=>{try{return Reflect.apply(v,t,args);}catch{reject(reason);}}:v;}});
function at(c,r,fn){mark(c,r);return fn();}
const sha=b=>createHash('sha256').update(b).digest('hex');
const req=createRequire('/app/server/api/package.json');
function read(p,cap=4*1024**2){let fd;try{fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);const s=fs.fstatSync(fd);ensure(s.isFile(),'NOT_REGULAR');ensure(s.nlink===1,'MULTILINK');ensure(s.size<=cap,'OVERSIZE');const b=fs.readFileSync(fd);const a=fs.fstatSync(fd);mark(checkpoint,'IDENTITY_CHANGED');assert.deepEqual([a.dev,a.ino,a.size,a.mtimeMs,a.ctimeMs],[s.dev,s.ino,s.size,s.mtimeMs,s.ctimeMs]);assert.equal(fs.lstatSync(p).ino,s.ino);return b;}catch(e){if(e?.[failureReason])throw e;reject(e?.code==='ENOENT'?'MISSING':'READ_FAILED');}finally{if(fd!==undefined)fs.closeSync(fd);}}
function emit(ok,c,r){process.stdout.write(JSON.stringify({code:'API_PROBE_CLASSIFIED',ok,checkpoint:c,reason:r})+'\n');process.exitCode=ok?0:1;}
'''
    # read restores the caller's default reason after checking stable public bytes.
    header = header.replace("const b=fs.readFileSync(fd);const a=", "const saved=reason;const b=fs.readFileSync(fd);const a=")
    header = header.replace('assert.equal(fs.lstatSync(p).ino,s.ino);return b;', 'assert.equal(fs.lstatSync(p).ino,s.ino);reason=saved;return b;')
    tail = r'''try{assert.equal(process.argv[2],'api');assert.equal(Number(process.argv[3]),45000);timer=setTimeout(()=>{emit(false,checkpoint,'TIME_LIMIT');process.exit(1);},45000).unref();mark('NATIVE_DEPENDENCY','DEPENDENCY_LOAD');const DB=req('better-sqlite3');const info=native(DB);mark('NATIVE_PACKAGE','PACKAGE_VERSION');assert.equal(info.betterSqlite,'12.11.1');const proof=await closure('api');mark('LOADER_METADATA','PACKAGE_METADATA');assert.equal(proof.entry,'/app/server/api/src/oci/nginx-local.main.ts');assert.deepEqual(proof.launchCommand,['node','--import','tsx','src/oci/nginx-local.main.ts']);assert.equal(proof.appBodiesEvaluated,false);assert.equal(proof.externalPackageBodiesQualified,false);emit(true,'COMPLETE','PASS');}catch(e){emit(false,checkpoint,e?.[failureReason]??reason);}finally{if(timer)clearTimeout(timer);}
'''
    return header+make+'\n'+native+'\n'+graph+tail


DIAGNOSTIC_JS = diagnostic_program()


def diagnostic_report(ok, checkpoint, reason):
    need(type(ok) is bool and checkpoint in CHECKPOINTS and reason in REASONS)
    need((ok and checkpoint == 'COMPLETE' and reason == 'PASS') or (not ok and reason != 'PASS'))
    return {'code':'API_PROBE_CLASSIFIED','ok':ok,'checkpoint':checkpoint,'reason':reason}


def parse_diagnostic(raw):
    def closed(pairs):
        d={}
        for k,v in pairs:
            need(k not in d);d[k]=v
        return d
    need(len(raw)<=2048)
    value=json.loads(raw,object_pairs_hook=closed)
    need(type(value) is dict and set(value)=={'code','ok','checkpoint','reason'} and value['code']=='API_PROBE_CLASSIFIED')
    return diagnostic_report(value['ok'],value['checkpoint'],value['reason'])


def diagnostic_name(packet):
    packet_name(packet)
    need(re.fullmatch(r'dip-preservation-images-api-diagnostic-[a-z0-9-]{1,40}',packet.name))


def build_diagnostic(packet):
    diagnostic_name(packet)
    public,_=build_packet(packet)  # Bounded public provenance only; no old packet/state/phase access.
    payloads={'qualification.mjs':DIAGNOSTIC_JS.encode(),'sources.json':public['sources.json']}
    plan={'format':'new-api-public-diagnostic-v1','packet':str(packet),'image':API,'aggregate':AGGREGATE,
          'files':{n:sha(b) for n,b in payloads.items()},'authorSha256':sha(read_file(Path(__file__).resolve())),
          'frozenR2':FROZEN_R2,'actorSeconds':90,'programMs':45000,'qualified':False}
    return payloads,plan


def prepare_diagnostic(packet):
    payloads,plan=build_diagnostic(packet)
    packet.mkdir(mode=0o700);sync_directory(packet.parent)
    (packet/'client').mkdir(mode=0o700)
    for n,b in payloads.items():write_new(packet/n,b,0o444)
    write_new(packet/'plan.json',canonical(plan));sync_directory(packet)
    return sha(canonical(plan))


def diagnostic_entries(directory):
    entries=set()
    with os.scandir(directory) as stream:
        for entry in stream:
            need(len(entries)<8);entries.add(entry.name)
    return entries


def load_diagnostic(packet,expected):
    diagnostic_name(packet)
    s=os.lstat(packet);need(stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode)==0o700 and s.st_uid==os.getuid())
    raw=read_file(packet/'plan.json',CAP);need(HEX.fullmatch(expected) and sha(raw)==expected)
    plan=json.loads(raw)
    need(raw==canonical(plan) and plan['format']=='new-api-public-diagnostic-v1' and plan['packet']==str(packet) and plan['image']==API and
         plan['aggregate']==AGGREGATE and plan['frozenR2']==FROZEN_R2 and plan['actorSeconds']==90 and
         plan['programMs']==45000 and plan['qualified'] is False and plan['authorSha256']==sha(read_file(Path(__file__).resolve())) and
         set(plan['files'])==set(DIAG_FILES))
    need(set(plan)=={'format','packet','image','aggregate','files','authorSha256','frozenR2','actorSeconds','programMs','qualified'})
    client=packet/'client';cs=os.lstat(client)
    need(stat.S_ISDIR(cs.st_mode) and stat.S_IMODE(cs.st_mode)==0o700 and cs.st_uid==os.getuid() and str(client.resolve())==str(client))
    need(diagnostic_entries(packet)=={*DIAG_FILES,'plan.json','client'} and not diagnostic_entries(client))
    for n,pin in plan['files'].items():
        need(HEX.fullmatch(pin) and sha(read_file(packet/n))==pin and stat.S_IMODE(os.lstat(packet/n).st_mode)==0o444)
    need(plan['files']['qualification.mjs']==sha(DIAGNOSTIC_JS.encode()))
    return plan


def diagnostic_command(packet,label):
    diagnostic_name(packet);need(HEX.fullmatch(label))
    original=command(packet,'api',label,45000)
    args=[];i=0
    while i<len(original):
        item=original[i]
        if item in ('--name','--label'):
            args += [item,('dip-preservation-api-diagnostic-'+label[:16]) if item=='--name' else DIAG_LABEL+'='+label];i+=2
        elif item=='--tmpfs' and original[i+1].split(':',1)[0] not in DIAG_TMPFS:i+=2
        elif item=='--mount' and 'dst=/snapshot.mjs,' in original[i+1]:i+=2
        else:args.append(item);i+=1
    return args


class DiagnosticDocker(Docker):
    def attach_probe(self,ident):
        """A nonzero DIAGNOSTIC probe can carry its closed failure enum. No logs."""
        need(HEX.fullmatch(ident));end=min(self.deadline,time.monotonic()+45)
        proc=subprocess.Popen(self.prefix+['start','--attach',ident],env=self.env,stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        selector=selectors.DefaultSelector();out={proc.stdout:bytearray(),proc.stderr:bytearray()}
        for stream in out:selector.register(stream,selectors.EVENT_READ)
        try:
            while selector.get_map():
                need(time.monotonic()<end)
                for key,_ in selector.select(min(0.1,max(0,end-time.monotonic()))):
                    b=os.read(key.fileobj.fileno(),8192)
                    if not b:selector.unregister(key.fileobj)
                    else:out[key.fileobj].extend(b);need(sum(map(len,out.values()))<=CAP)
            rc=proc.wait(timeout=max(0.001,end-time.monotonic()))
            return rc,bytes(out[proc.stdout]),bool(out[proc.stderr])  # Raw stderr is NEVER returned/persisted.
        finally:
            selector.close()
            if proc.poll() is None:proc.kill()  # Client only, not daemon cancellation.
            proc.wait()
            for stream in out:stream.close()


def diagnostic_guard(record,ident,packet,label,argv,state):
    need(HEX.fullmatch(ident) and len(record)==11)
    cid,image,name,status,labels,host,mounts,entry,cmd,user,cwd=record
    need(cid==ident and image==API and name=='/dip-preservation-api-diagnostic-'+label[:16] and
         labels.get(DIAG_LABEL)==label and not any(k.startswith('com.docker.compose.') for k in labels) and
         user=='65532:65532' and cwd=='/app/server/api' and entry==['/usr/bin/env'] and cmd==argv[argv.index(API)+1:])
    need(host['ReadonlyRootfs'] is True and host['NetworkMode']=='none' and host['CapDrop']==['ALL'] and
         not host.get('CapAdd') and not host['Privileged'] and host['SecurityOpt']==['no-new-privileges:true'] and
         host['Memory']==2*GIB and host['MemorySwap']==2*GIB and host['NanoCpus']==10**9 and host['PidsLimit']==64 and
         host['Tmpfs']==DIAG_TMPFS and not host.get('AutoRemove') and not host.get('PortBindings') and not host.get('Binds') and
         not host.get('Devices') and not host.get('DeviceRequests') and host.get('RestartPolicy',{}).get('Name')=='no')
    binds=[m for m in mounts if m['Type']=='bind']
    need(len(binds)==2 and {m['Destination'] for m in binds}=={'/'+n for n in DIAG_FILES} and
         all(m['RW'] is False and m['Source']==str(packet/Path(m['Destination']).name) for m in binds))
    need(all(m['Type']=='bind' or m['Type']=='tmpfs' and m['Destination'] in DIAG_TMPFS for m in mounts) and
         len({m['Destination'] for m in mounts})==len(mounts) and len(mounts)<=4)
    need(state in ('created','exited') and status['Status']==state and status['Running'] is False and
         status['Paused'] is False and not status.get('Restarting') and status['OOMKilled'] is False and status.get('Error','')=='')
    need(type(status['ExitCode']) is int and 0<=status['ExitCode']<=255)
    if state=='created':need(status['ExitCode']==0)


def run_diagnostic(packet,expected,review,endpoint):
    checkpoint='HOST_PACKET'
    try:
        need(re.fullmatch(r'DIP-ARTF-[1-9][0-9]{0,8}',review));plan=load_diagnostic(packet,expected)
        checkpoint='HOST_ATTEMPT';write_new(packet/'attempt.json',canonical({'review':review,'packetSha256':expected,'once':True}))
        docker=DiagnosticDocker(packet,endpoint,time.monotonic()+90)
        checkpoint='HOST_IMAGE'
        image=[json.loads(x) for x in docker.call(['image','inspect','--format','{{json .Id}}\n{{json .Os}}\n{{json .Architecture}}\n{{json .Config.WorkingDir}}\n{{json .Config.Volumes}}',API],10).splitlines()]
        need(image==[API,'linux','arm64','/app/server/api',None] or image==[API,'linux','arm64','/app/server/api',{}])
        write_new(packet/'image.json',canonical({'image':API,'platform':'linux/arm64'}))
        for n,pin in plan['files'].items():need(sha(read_file(packet/n))==pin)
        need(sha(read_file(packet/'plan.json',CAP))==expected and docker.deadline-time.monotonic()>70)
        checkpoint='HOST_CREATE';argv=diagnostic_command(packet,expected)
        ident=docker.call(argv,10).decode('ascii').strip();need(HEX.fullmatch(ident))
        write_new(packet/'api-id.json',canonical({'id':ident,'image':API,'label':expected}))
        checkpoint='HOST_CREATED_GUARD';diagnostic_guard(docker.inspect(ident),ident,packet,expected,argv,'created')
        need(docker.deadline-time.monotonic()>50)
        checkpoint='HOST_START';rc,raw,stderr_present=docker.attach_probe(ident)
        checkpoint='HOST_EXITED_GUARD';record=docker.inspect(ident);diagnostic_guard(record,ident,packet,expected,argv,'exited')
        need(type(rc) is int and rc==record[3]['ExitCode'])
        checkpoint='HOST_RECEIPT'
        if not raw and rc!=0:report=diagnostic_report(False,'BOOTSTRAP','PRELOAD_OR_PROTOCOL')
        else:
            report=parse_diagnostic(raw);need(not stderr_present and rc==(0 if report['ok'] else 1))
        write_new(packet/'result.json',canonical(report))
        return report  # ALWAYS retain this ONE fresh container; no cleanup/restart/qualification bits.
    except Exception:
        return diagnostic_report(False,checkpoint,'GUARD_REFUSED')


DIAG_ACTIONS = ('preview-diagnostic','prepare-diagnostic','run-diagnostic')


def diagnostic_main():
    """Separate explicit authority/namespace. No fallback to the consumed run."""
    class ClosedParser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError('DIAGNOSTIC_ARGUMENTS_REFUSED')
    checkpoint='HOST_PACKET'
    try:
        parser=ClosedParser(add_help=False)
        parser.add_argument('action',choices=DIAG_ACTIONS)
        parser.add_argument('--packet',type=Path,required=True)
        parser.add_argument('--expected-packet-sha256')
        parser.add_argument('--independent-review-evidence')
        parser.add_argument('--docker-host')
        parser.add_argument('--authorize-new-api-diagnostic-once',action='store_true')
        flags=[a for a in sys.argv[2:] if a.startswith('--')]
        need(len(flags)==len(set(flags)) and not any('=' in a for a in flags))
        args=parser.parse_args()
        if args.action=='run-diagnostic':
            need(args.authorize_new_api_diagnostic_once and args.expected_packet_sha256 and
                 args.independent_review_evidence and args.docker_host)
            report=run_diagnostic(args.packet,args.expected_packet_sha256,args.independent_review_evidence,args.docker_host)
            sys.stdout.write(canonical(report).decode('ascii'));return 0 if report['ok'] else 1
        need(not args.authorize_new_api_diagnostic_once and args.expected_packet_sha256 is None and
             args.independent_review_evidence is None and args.docker_host is None)
        if args.action=='preview-diagnostic':
            _,plan=build_diagnostic(args.packet);pin=sha(canonical(plan))
            report={'code':'DIAGNOSTIC_PLANNED','ok':True,'packetSha256':pin,'qualified':False,
                    'actorSeconds':90,'programMs':45000,'createArgv':diagnostic_command(args.packet,pin)}
        else:
            report={'code':'DIAGNOSTIC_PREPARED','ok':True,'packetSha256':prepare_diagnostic(args.packet),'qualified':False}
        sys.stdout.write(canonical(report).decode('ascii'));return 0
    except Exception:
        sys.stdout.write(canonical(diagnostic_report(False,checkpoint,'GUARD_REFUSED')).decode('ascii'));return 1


# Consumed486 diagnostic is immutable provenance, not new execution authority.
FROZEN_DIAGNOSTIC = {
    'authorSha256':'4286c91605641f2dcab11099a82de6152c4d03a247477849a47715c4408d7686',
    'testSha256':'d0716589f0c31bac6fa549d870c0ee7062c8f85bedbe6dc82586e70b065b720f',
    'programSha256':'cceb9ab7d0fd077215f6c2ae5589868c2c666deb3c398c7dce619c47c1a7a7d9',
    'packetSha256':'4adcedae84691d3dd9e76b1684bd11f9c2c42cfb1c1faefa7407886331aaeeb8',
}
NEW_ROLES = ('api','worker')
NEW_IMAGES = {r:IMAGES[r] for r in NEW_ROLES}
NEW_LABEL = 'io.diplom.synthetic-new-source-closure'
NEW_ACTIONS = ('preview-new-closure','prepare-new-closure','run-new-closure')

# ONLY the realpath of a resolved external package entry calls this reader.
# Its immutable image-layer provenance is established by BOTH host guards:
# pinned image + RO root + exact mounts, with no mount into either /app root.
# Payload/source/binary/metadata/private readers retain nlink===1 unchanged.
PUBLIC_ENTRY_READ_JS = r'''function readPackageEntry(p,cap){
 ensure(Number.isSafeInteger(cap)&&cap>0&&cap<=8*1024**2,'OVERSIZE');
 ensure(path.isAbsolute(p)&&path.normalize(p)===p&&
   (p.startsWith('/app/node_modules/')||p.startsWith('/app/server/api/node_modules/')),'DEPENDENCY_ESCAPE');
 ensure(fs.realpathSync(p)===p,'DEPENDENCY_ESCAPE');
 const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
 try{
  const s=fs.fstatSync(fd,{bigint:true});
  ensure(s.isFile(),'NOT_REGULAR');ensure(s.nlink>=1n,'MULTILINK');
  ensure(s.size>=0n&&s.size<=BigInt(cap),'OVERSIZE');
  const b=Buffer.alloc(Number(s.size)+1);let used=0;
  while(used<b.length){const n=fs.readSync(fd,b,used,Math.min(65536,b.length-used),null);if(n===0)break;used+=n;}
  ensure(BigInt(used)===s.size,'IDENTITY_CHANGED');
  const identity=x=>[x.dev,x.ino,x.nlink,x.mode,x.size,x.mtimeNs,x.ctimeNs,x.uid,x.gid];
  const a=fs.fstatSync(fd,{bigint:true}),l=fs.lstatSync(p,{bigint:true});
  ensure(a.isFile()&&l.isFile(),'NOT_REGULAR');
  ensure(identity(a).every((v,i)=>v===identity(s)[i])&&identity(l).every((v,i)=>v===identity(s)[i]),'IDENTITY_CHANGED');
  ensure(fs.realpathSync(p)===p,'DEPENDENCY_ESCAPE');return b.subarray(0,used);
 }finally{fs.closeSync(fd);}
}
'''


def continuation_program():
    need(sha(DIAGNOSTIC_JS.encode())==FROZEN_DIAGNOSTIC['programSha256'])
    prefix,tail=DIAGNOSTIC_JS.split("try{assert.equal(process.argv[2],'api');",1)
    needle='sha256:sha(read(real,8*1024**2))'
    need(prefix.count(needle)==1)
    prefix=prefix.replace(needle,'sha256:sha(readPackageEntry(real,8*1024**2))')
    # Remove ONLY the diagnostic emitter; all native/graph/strict read predicates remain.
    emitter="function emit(ok,c,r){process.stdout.write(JSON.stringify({code:'API_PROBE_CLASSIFIED',ok,checkpoint:c,reason:r})+'\\n');process.exitCode=ok?0:1;}"
    need(prefix.count(emitter)==1);prefix=prefix.replace(emitter,'')
    tail=r'''const role=process.argv[2];
function emitPhase(ok,details){process.stdout.write(JSON.stringify({code:'NEW_SOURCE_PHASE',ok,role,...details})+'\n');process.exitCode=ok?0:1;}
try{
 assert(['api','worker'].includes(role));assert.equal(Number(process.argv[3]),45000);
 timer=setTimeout(()=>{emitPhase(false,{checkpoint,reason:'TIME_LIMIT'});process.exit(1);},45000).unref();
 mark('NATIVE_DEPENDENCY','DEPENDENCY_LOAD');const DB=req('better-sqlite3');const info=native(DB);
 mark('NATIVE_PACKAGE','PACKAGE_VERSION');assert.equal(info.betterSqlite,'12.11.1');
 const proof=await closure(role);mark('LOADER_METADATA','PACKAGE_METADATA');
 const entry=role==='api'?'src/oci/nginx-local.main.ts':'src/worker/nginx-local-worker.main.ts';
 assert.equal(proof.entry,'/app/server/api/'+entry);assert.deepEqual(proof.launchCommand,['node','--import','tsx',entry]);
 assert.equal(proof.appBodiesEvaluated,false);assert.equal(proof.externalPackageBodiesQualified,false);
 assert(Buffer.byteLength(JSON.stringify({native:info,proof}))<60000);
 emitPhase(true,{native:info,proof});
}catch(e){emitPhase(false,{checkpoint,reason:e?.[failureReason]??reason});}finally{if(timer)clearTimeout(timer);}
'''
    return prefix+PUBLIC_ENTRY_READ_JS+tail


FROZEN_CONTINUATION_R1 = {
    'authorSha256':'11e3ebffea38f29e5d26becffeb9a20b6081f032afbb9251394e7b1e97b9a7e2',
    'testSha256':'f0ac8f188ad2ecf8c48220e792d46d2cb0353eb94861e3292288724d7e8ab8c1',
    'programSha256':'b5ba8a2e990bdfc37fac74d52d7c3364c69d22efb07a99d37ef4438385b766c9',
    'packetSha256':'807589e9fdb1de9e310262a7555426c059dc08029f59fe4c6597516ee04da42e',
}
CONTINUATION_R1_JS = continuation_program()

# This reuses ONLY the bounded stable-FD/path body, never the broad entry whitelist.
# Fixed kind determines the cap; callers cannot supply an arbitrary cap/path class.
PUBLIC_LOADER_READ_JS = r'''function readLoaderMetadata(kind,p){
 ensure(kind==='tsx'||kind==='entrypoint','DEPENDENCY_ESCAPE');
 const cap=kind==='tsx'?4*1024**2:65536;
 ensure(path.isAbsolute(p)&&path.normalize(p)===p,'DEPENDENCY_ESCAPE');
 if(kind==='tsx'){
  ensure(p===fs.realpathSync(req.resolve('tsx/package.json'))&&p.endsWith('/tsx/package.json')&&
   (p.startsWith('/app/node_modules/')||p.startsWith('/app/server/api/node_modules/')),'DEPENDENCY_ESCAPE');
 }else ensure(p==='/usr/local/bin/docker-entrypoint.sh','DEPENDENCY_ESCAPE');
 ensure(fs.realpathSync(p)===p,'DEPENDENCY_ESCAPE');
''' + PUBLIC_ENTRY_READ_JS[PUBLIC_ENTRY_READ_JS.index(' const fd='):]


def continuation_r2_program():
    need(sha(CONTINUATION_R1_JS.encode())==FROZEN_CONTINUATION_R1['programSha256'])
    program=CONTINUATION_R1_JS
    def replace(old,new):
        nonlocal program
        need(program.count(old)==1);program=program.replace(old,new)
    replace("sha256:sha(read(wrapper,65536))","sha256:sha(readLoaderMetadata('entrypoint',wrapper))")
    replace("JSON.parse(read(req.resolve('tsx/package.json'))).version",
            "JSON.parse(readLoaderMetadata('tsx',fs.realpathSync(req.resolve('tsx/package.json')))).version")
    # Host first requires the inherited public image entrypoint contract. Missing
    # wrapper cannot silently pass as a null proof under that contract.
    replace("const entrypoint=fs.existsSync(wrapper)?{path:wrapper,sha256:",
            "assert(fs.existsSync(wrapper));const entrypoint={path:wrapper,sha256:")
    replace("sha(readLoaderMetadata('entrypoint',wrapper))}:null;",
            "sha(readLoaderMetadata('entrypoint',wrapper))};")
    return program+PUBLIC_LOADER_READ_JS


CONTINUATION_JS = continuation_r2_program()


def continuation_name(packet):
    packet_name(packet)
    need(packet.name=='dip-preservation-images-new-closure-20261013-r2')


def continuation_build(packet):
    continuation_name(packet)
    raw=read_file(STAGE/'overlay-manifest.json',CAP);need(sha(raw)==STAGE_SHA)
    manifest=json.loads(raw);files=[f for f in manifest['context_files'] if f['path'].endswith(('.ts','.mjs'))]
    need(len(files)==108 and manifest['source_sha256']==AGGREGATE and sha(canonical(files))==AGGREGATE)
    for f in files:
        need(re.fullmatch(r'server/(api|runtime)/src/[A-Za-z0-9_./-]+\.(ts|mjs)',f['path']) and '..' not in f['path'])
        b=read_file(STAGE/f['path']);need(len(b)==f['bytes'] and sha(b)==f['sha256'])
    payloads={'qualification.mjs':CONTINUATION_JS.encode(),'sources.json':canonical({'aggregate':AGGREGATE,'files':files})}
    plan={'format':'new-source-closure-v2','packet':str(packet),'images':NEW_IMAGES,'aggregate':AGGREGATE,
          'stageSha256':STAGE_SHA,'files':{n:sha(b) for n,b in payloads.items()},
          'authorSha256':sha(read_file(Path(__file__).resolve())),
          'frozenR2':FROZEN_R2,'frozenDiagnostic':FROZEN_DIAGNOSTIC,'frozenContinuationR1':FROZEN_CONTINUATION_R1,
          'actorSeconds':150,'programMs':45000,
          'oldNativeEqualityProven':False,'appStartup':False}
    return payloads,plan


def continuation_prepare(packet):
    payloads,plan=continuation_build(packet)
    packet.mkdir(mode=0o700);sync_directory(packet.parent)
    (packet/'client').mkdir(mode=0o700)
    for n,b in payloads.items():write_new(packet/n,b,0o444)
    write_new(packet/'plan.json',canonical(plan));sync_directory(packet)
    return sha(canonical(plan))


def continuation_load(packet,expected):
    continuation_name(packet);s=os.lstat(packet)
    need(stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode)==0o700 and s.st_uid==os.getuid())
    raw=read_file(packet/'plan.json',CAP);need(HEX.fullmatch(expected) and sha(raw)==expected)
    p=json.loads(raw)
    need(raw==canonical(p) and set(p)=={'format','packet','images','aggregate','stageSha256','files','authorSha256',
         'frozenR2','frozenDiagnostic','frozenContinuationR1','actorSeconds','programMs','oldNativeEqualityProven','appStartup'})
    need(p['format']=='new-source-closure-v2' and p['packet']==str(packet) and p['images']==NEW_IMAGES and
         p['aggregate']==AGGREGATE and p['stageSha256']==STAGE_SHA and p['frozenR2']==FROZEN_R2 and
         p['frozenDiagnostic']==FROZEN_DIAGNOSTIC and p['frozenContinuationR1']==FROZEN_CONTINUATION_R1 and
         p['actorSeconds']==150 and p['programMs']==45000 and
         p['oldNativeEqualityProven'] is False and p['appStartup'] is False and
         p['authorSha256']==sha(read_file(Path(__file__).resolve())) and set(p['files'])==set(DIAG_FILES))
    client=packet/'client';cs=os.lstat(client)
    need(stat.S_ISDIR(cs.st_mode) and stat.S_IMODE(cs.st_mode)==0o700 and cs.st_uid==os.getuid() and str(client.resolve())==str(client))
    need(diagnostic_entries(packet)=={*DIAG_FILES,'plan.json','client'} and not diagnostic_entries(client))
    for n,pin in p['files'].items():
        need(HEX.fullmatch(pin) and sha(read_file(packet/n))==pin and stat.S_IMODE(os.lstat(packet/n).st_mode)==0o444)
    need(p['files']['qualification.mjs']==sha(CONTINUATION_JS.encode()))
    return p


def continuation_command(packet,role,label):
    continuation_name(packet);need(role in NEW_ROLES and HEX.fullmatch(label))
    original=command(packet,role,label,45000);args=[];i=0
    while i<len(original):
        item=original[i]
        if item in ('--name','--label'):
            value='dip-preservation-new-closure-'+role+'-'+label[:16] if item=='--name' else NEW_LABEL+'='+label
            args.extend((item,value));i+=2
        elif item=='--tmpfs' and original[i+1].split(':',1)[0] not in DIAG_TMPFS:i+=2
        elif item=='--mount' and 'dst=/snapshot.mjs,' in original[i+1]:i+=2
        else:args.append(item);i+=1
    return args


def continuation_guard(record,ident,packet,role,label,argv,state):
    need(role in NEW_ROLES and HEX.fullmatch(ident) and len(record)==11)
    cid,image,name,status,labels,host,mounts,entry,cmd,user,cwd=record
    need(cid==ident and image==NEW_IMAGES[role] and name=='/dip-preservation-new-closure-'+role+'-'+label[:16] and
         labels.get(NEW_LABEL)==label and not any(k.startswith('com.docker.compose.') for k in labels) and
         user=='65532:65532' and cwd=='/app/server/api' and entry==['/usr/bin/env'] and cmd==argv[argv.index(NEW_IMAGES[role])+1:])
    need(host['ReadonlyRootfs'] is True and host['NetworkMode']=='none' and host['CapDrop']==['ALL'] and
         not host.get('CapAdd') and not host['Privileged'] and host['SecurityOpt']==['no-new-privileges:true'] and
         host['Memory']==2*GIB and host['MemorySwap']==2*GIB and host['NanoCpus']==10**9 and host['PidsLimit']==64 and
         host['Tmpfs']==DIAG_TMPFS and not host.get('AutoRemove') and not host.get('PortBindings') and not host.get('Binds') and
         not host.get('Devices') and not host.get('DeviceRequests') and host.get('RestartPolicy',{}).get('Name')=='no')
    binds=[m for m in mounts if m['Type']=='bind']
    need(len(binds)==2 and {m['Destination'] for m in binds}=={'/'+n for n in DIAG_FILES} and
         all(m['RW'] is False and m['Source']==str(packet/Path(m['Destination']).name) for m in binds))
    need(all(m['Type']=='bind' or m['Type']=='tmpfs' and m['Destination'] in DIAG_TMPFS for m in mounts) and
         len({m['Destination'] for m in mounts})==len(mounts) and len(mounts)<=4)
    need(state in ('created','exited') and status['Status']==state and status['Running'] is False and
         status['Paused'] is False and not status.get('Restarting') and status['OOMKilled'] is False and status.get('Error','')=='')
    need(type(status['ExitCode']) is int and 0<=status['ExitCode']<=255)
    if state=='created':need(status['ExitCode']==0)


def continuation_report(ok,role,checkpoint,reason):
    diagnostic_report(ok,checkpoint,reason)
    need(role in (*NEW_ROLES,'none','both') and (not ok or role=='both'))
    return {'code':'NEW_SOURCE_CONTINUATION','ok':ok,'role':role,'checkpoint':checkpoint,'reason':reason}


def continuation_phase(raw,role):
    def closed(pairs):
        result={}
        for k,v in pairs:need(k not in result);result[k]=v
        return result
    need(role in NEW_ROLES and len(raw)<=CAP)
    r=json.loads(raw,object_pairs_hook=closed)
    need(type(r) is dict and r.get('code')=='NEW_SOURCE_PHASE' and r.get('role')==role and type(r.get('ok')) is bool)
    if not r['ok']:
        need(len(raw)<=2048 and set(r)=={'code','ok','role','checkpoint','reason'})
        diagnostic_report(False,r['checkpoint'],r['reason']);return r
    need(set(r)=={'code','ok','role','native','proof'})
    n=r['native'];need(type(n) is dict and set(n)=={'node','abi','sqlite','betterSqlite','nativeSha256','nodeSha256'})
    need(all(isinstance(v,str) and len(v)<=128 for v in n.values()) and n['betterSqlite']=='12.11.1' and
         HEX.fullmatch(n['nativeSha256']) and HEX.fullmatch(n['nodeSha256']))
    p=r['proof'];entry='src/oci/nginx-local.main.ts' if role=='api' else 'src/worker/nginx-local-worker.main.ts'
    need(type(p) is dict and set(p)=={'entry','launchCommand','entrypoint','sourceFiles','edges','dependencies','tsx','typescript',
         'appBodiesEvaluated','externalPackageBodiesQualified'})
    need(p['entry']=='/app/server/api/'+entry and p['launchCommand']==['node','--import','tsx',entry] and
         p['appBodiesEvaluated'] is False and p['externalPackageBodiesQualified'] is False and
         type(p['sourceFiles']) is int and 0<p['sourceFiles']<=108 and type(p['edges']) is list and
         type(p['dependencies']) is dict and len(p['edges'])+len(p['dependencies'])<=1024 and
         all(isinstance(p[k],str) and 0<len(p[k])<=128 for k in ('tsx','typescript')))
    for edge in p['edges']:
        need(type(edge) is list and len(edge)==3 and all(isinstance(v,str) and len(v)<=4096 for v in edge))
    for spec,d in p['dependencies'].items():
        need(isinstance(spec,str) and len(spec)<=4096 and type(d) is dict and set(d)=={'resolved','sha256'} and
             isinstance(d['resolved'],str) and len(d['resolved'])<=4096 and
             d['resolved'].startswith(('/app/node_modules/','/app/server/api/node_modules/')) and HEX.fullmatch(d['sha256']))
    need(p['entrypoint'] is None or type(p['entrypoint']) is dict and set(p['entrypoint'])=={'path','sha256'} and
         p['entrypoint']['path']=='/usr/local/bin/docker-entrypoint.sh' and HEX.fullmatch(p['entrypoint']['sha256']))
    return r


class ContinuationDocker(DiagnosticDocker):
    def call(self,args,timeout=5):
        return super().call(args,min(timeout,5))


def continuation_run(packet,expected,review,endpoint):
    checkpoint='HOST_PACKET';role='none';deadline=time.monotonic()+150
    try:
        need(re.fullmatch(r'DIP-ARTF-[1-9][0-9]{0,8}',review));plan=continuation_load(packet,expected)
        checkpoint='HOST_ATTEMPT';write_new(packet/'attempt.json',canonical({'review':review,'packetSha256':expected,'once':True}))
        docker=ContinuationDocker(packet,endpoint,deadline)
        for index,role in enumerate(NEW_ROLES):
            future=(len(NEW_ROLES)-index-1)*65
            checkpoint='HOST_IMAGE';need(deadline-time.monotonic()>future+70)
            image=[json.loads(x) for x in docker.call(['image','inspect','--format','{{json .Id}}\n{{json .Os}}\n{{json .Architecture}}\n{{json .Config.WorkingDir}}\n{{json .Config.Volumes}}\n{{json .Config.Entrypoint}}',NEW_IMAGES[role]]).splitlines()]
            need(image in ([NEW_IMAGES[role],'linux','arm64','/app/server/api',None,['docker-entrypoint.sh']],
                           [NEW_IMAGES[role],'linux','arm64','/app/server/api',{},['docker-entrypoint.sh']]))
            write_new(packet/(role+'-image.json'),canonical({'image':NEW_IMAGES[role],'platform':'linux/arm64'}))
            for n,pin in plan['files'].items():need(sha(read_file(packet/n))==pin)
            need(sha(read_file(packet/'plan.json',CAP))==expected)
            checkpoint='HOST_CREATE';argv=continuation_command(packet,role,expected)
            ident=docker.call(argv).decode('ascii').strip();need(HEX.fullmatch(ident))
            write_new(packet/(role+'-id.json'),canonical({'id':ident,'image':NEW_IMAGES[role],'role':role,'label':expected}))
            checkpoint='HOST_CREATED_GUARD';continuation_guard(docker.inspect(ident),ident,packet,role,expected,argv,'created')
            checkpoint='HOST_START';need(deadline-time.monotonic()>future+55)
            rc,raw,stderr_present=docker.attach_probe(ident)
            checkpoint='HOST_EXITED_GUARD';record=docker.inspect(ident)
            continuation_guard(record,ident,packet,role,expected,argv,'exited');need(type(rc) is int and rc==record[3]['ExitCode'])
            checkpoint='HOST_RECEIPT'
            if not raw and rc!=0:
                result=continuation_report(False,role,'BOOTSTRAP','PRELOAD_OR_PROTOCOL')
                write_new(packet/'result.json',canonical(result));return result
            phase=continuation_phase(raw,role);need(not stderr_present and rc==(0 if phase['ok'] else 1))
            if phase['ok']:need(phase['proof']['entrypoint'] is not None)
            write_new(packet/(role+'-result.json'),canonical(phase))
            if not phase['ok']:
                result=continuation_report(False,role,phase['checkpoint'],phase['reason'])
                write_new(packet/'result.json',canonical(result));return result
        result=continuation_report(True,'both','COMPLETE','PASS')
        write_new(packet/'result.json',canonical(result));return result
    except Exception:
        return continuation_report(False,role,checkpoint,'GUARD_REFUSED')
    # Every actor/packet remains retained. No old receipt access/native-equality claim.


def continuation_main():
    class ClosedParser(argparse.ArgumentParser):
        def error(self,message):raise ValueError('CONTINUATION_ARGUMENTS_REFUSED')
    try:
        parser=ClosedParser(add_help=False);parser.add_argument('action',choices=NEW_ACTIONS)
        parser.add_argument('--packet',type=Path,required=True);parser.add_argument('--expected-packet-sha256')
        parser.add_argument('--independent-review-evidence');parser.add_argument('--docker-host')
        parser.add_argument('--authorize-new-source-continuation-once',action='store_true')
        flags=[a for a in sys.argv[2:] if a.startswith('--')];need(len(flags)==len(set(flags)) and not any('=' in a for a in flags))
        args=parser.parse_args()
        if args.action=='run-new-closure':
            need(args.authorize_new_source_continuation_once and args.expected_packet_sha256 and args.independent_review_evidence and args.docker_host)
            r=continuation_run(args.packet,args.expected_packet_sha256,args.independent_review_evidence,args.docker_host)
        else:
            need(not args.authorize_new_source_continuation_once and args.expected_packet_sha256 is None and args.independent_review_evidence is None and args.docker_host is None)
            if args.action=='preview-new-closure':
                _,p=continuation_build(args.packet);pin=sha(canonical(p))
                r={'code':'NEW_CLOSURE_PLANNED','ok':True,'packetSha256':pin,'actorSeconds':150,'programMs':45000,
                   'oldNativeEqualityProven':False,'createArgv':{role:continuation_command(args.packet,role,pin) for role in NEW_ROLES}}
            else:r={'code':'NEW_CLOSURE_PREPARED','ok':True,'packetSha256':continuation_prepare(args.packet),'oldNativeEqualityProven':False}
        sys.stdout.write(canonical(r).decode('ascii'));return 0 if r['ok'] else 1
    except Exception:
        sys.stdout.write(canonical(continuation_report(False,'none','HOST_PACKET','GUARD_REFUSED')).decode('ascii'));return 1


# Accepted R2 API evidence; no execution/adoption of either retained actor.
ACCEPTED_R2 = {
    'authorSha256':'f312e7e406ad043c92c640a1331f03482ad5829d3b751b507d7c38d996a292d7',
    'testSha256':'a506887b1b4243d09013dc68b5be6d8e314a56daec3f27751bf2367c0a88856c',
    'programSha256':'7e70b804209408e3dd5773fd7f4ec23b61eee506df04c9c24d9c5ccf114ffa9a',
    'packetSha256':'dc136179f6e783938dc4aa5989b05862d2142b0e2b061936f01538be74413e48',
    'apiReceiptSha256':'e9377042807fbaa1f8c4025f577d162a92cebb6cfdd6647c32d2e2345415c227',
}
ACCEPTED_API_ROOT = Path('/private/tmp/dip-preservation-images-new-closure-20261013-r2')
WORKER_LABEL = 'io.diplom.synthetic-worker-source-closure'
WORKER_FILES = (*DIAG_FILES,'api-accepted-result.json')
WORKER_ACTIONS = ('preview-worker-closure','prepare-worker-closure','run-worker-closure')
need(sha(CONTINUATION_JS.encode())==ACCEPTED_R2['programSha256'])
need(CONTINUATION_JS.count("assert(['api','worker'].includes(role));")==1)
WORKER_JS = CONTINUATION_JS.replace("assert(['api','worker'].includes(role));","assert.equal(role,'worker');")


def worker_name(packet):
    packet_name(packet)
    need(packet.name=='dip-preservation-images-worker-closure-20261013-r1')


def accepted_api():
    """Only the explicitly accepted public synthetic receipt; never old actors/logs."""
    root=ACCEPTED_API_ROOT;s=os.lstat(root)
    need(stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700 and str(root.resolve())==str(root))
    path=root/'api-result.json';s=os.lstat(path)
    need(s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o600)
    raw=read_file(path,CAP);need(sha(raw)==ACCEPTED_R2['apiReceiptSha256'])
    proof=continuation_phase(raw,'api');need(proof['ok'] is True and proof['proof']['entrypoint'] is not None and raw==canonical(proof))
    return raw


def worker_build(packet):
    worker_name(packet)
    raw=read_file(STAGE/'overlay-manifest.json',CAP);need(sha(raw)==STAGE_SHA)
    m=json.loads(raw);files=[f for f in m['context_files'] if f['path'].endswith(('.ts','.mjs'))]
    need(len(files)==108 and m['source_sha256']==AGGREGATE and sha(canonical(files))==AGGREGATE)
    for f in files:
        need(re.fullmatch(r'server/(api|runtime)/src/[A-Za-z0-9_./-]+\.(ts|mjs)',f['path']) and '..' not in f['path'])
        b=read_file(STAGE/f['path']);need(len(b)==f['bytes'] and sha(b)==f['sha256'])
    payloads={'qualification.mjs':WORKER_JS.encode(),'sources.json':canonical({'aggregate':AGGREGATE,'files':files}),
              'api-accepted-result.json':accepted_api()}
    p={'format':'worker-source-closure-v1','packet':str(packet),'image':WORKER,'aggregate':AGGREGATE,'stageSha256':STAGE_SHA,
       'files':{n:sha(b) for n,b in payloads.items()},'authorSha256':sha(read_file(Path(__file__).resolve())),
       'acceptedR2':ACCEPTED_R2,'labelPolicy':'exact-image-baseline-plus-own-v1','actorSeconds':90,'programMs':45000,
       'oldNativeEqualityProven':False,'appStartup':False}
    return payloads,p


def worker_prepare(packet):
    payloads,p=worker_build(packet)
    packet.mkdir(mode=0o700);sync_directory(packet.parent);(packet/'client').mkdir(mode=0o700)
    for n,b in payloads.items():write_new(packet/n,b,0o444 if n in DIAG_FILES else 0o600)
    write_new(packet/'plan.json',canonical(p));sync_directory(packet)
    return sha(canonical(p))


def worker_load(packet,expected):
    worker_name(packet);s=os.lstat(packet)
    need(stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700)
    raw=read_file(packet/'plan.json',CAP);need(HEX.fullmatch(expected) and sha(raw)==expected)
    p=json.loads(raw)
    need(raw==canonical(p) and set(p)=={'format','packet','image','aggregate','stageSha256','files','authorSha256','acceptedR2',
         'labelPolicy','actorSeconds','programMs','oldNativeEqualityProven','appStartup'})
    need(p['format']=='worker-source-closure-v1' and p['packet']==str(packet) and p['image']==WORKER and
         p['aggregate']==AGGREGATE and p['stageSha256']==STAGE_SHA and p['acceptedR2']==ACCEPTED_R2 and
         p['labelPolicy']=='exact-image-baseline-plus-own-v1' and p['actorSeconds']==90 and p['programMs']==45000 and
         p['oldNativeEqualityProven'] is False and p['appStartup'] is False and
         p['authorSha256']==sha(read_file(Path(__file__).resolve())) and set(p['files'])==set(WORKER_FILES))
    client=packet/'client';s=os.lstat(client)
    need(stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode)==0o700 and s.st_uid==os.getuid() and str(client.resolve())==str(client))
    need(diagnostic_entries(packet)=={*WORKER_FILES,'plan.json','client'} and not diagnostic_entries(client))
    for n,pin in p['files'].items():
        need(HEX.fullmatch(pin) and sha(read_file(packet/n))==pin and
             stat.S_IMODE(os.lstat(packet/n).st_mode)==(0o444 if n in DIAG_FILES else 0o600))
    need(p['files']['qualification.mjs']==sha(WORKER_JS.encode()) and
         p['files']['api-accepted-result.json']==ACCEPTED_R2['apiReceiptSha256'])
    # Rebind the accepted original public receipt without running the API/image.
    need(read_file(packet/'api-accepted-result.json',CAP)==accepted_api())
    return p


def worker_command(packet,label):
    worker_name(packet);need(HEX.fullmatch(label))
    original=command(packet,'worker',label,45000);args=[];i=0
    while i<len(original):
        item=original[i]
        if item in ('--name','--label'):
            value='dip-preservation-worker-closure-'+label[:16] if item=='--name' else WORKER_LABEL+'='+label
            args.extend((item,value));i+=2
        elif item=='--tmpfs' and original[i+1].split(':',1)[0] not in DIAG_TMPFS:i+=2
        elif item=='--mount' and 'dst=/snapshot.mjs,' in original[i+1]:i+=2
        else:args.append(item);i+=1
    return args


def frozen_image_labels(labels):
    labels={} if labels is None else labels
    need(type(labels) is dict and len(labels)<=128 and len(canonical(labels))<=32768)
    need(all(isinstance(k,str) and 0<len(k)<=1024 and isinstance(v,str) and len(v)<=4096 and
             not k.startswith('io.diplom.synthetic-') for k,v in labels.items()))
    return MappingProxyType(dict(labels))


def worker_guard(record,ident,packet,label,argv,baseline,state):
    need(isinstance(baseline,MappingProxyType) and HEX.fullmatch(ident) and len(record)==11)
    frozen_image_labels(dict(baseline))  # Reject reserved OWN labels, including forged baselines.
    cid,image,name,status,labels,host,mounts,entry,cmd,user,cwd=record
    need(cid==ident and image==WORKER and name=='/dip-preservation-worker-closure-'+label[:16] and
         labels=={**baseline,WORKER_LABEL:label} and user=='65532:65532' and cwd=='/app/server/api' and
         entry==['/usr/bin/env'] and cmd==argv[argv.index(WORKER)+1:])
    need(host['ReadonlyRootfs'] is True and host['NetworkMode']=='none' and host['CapDrop']==['ALL'] and
         not host.get('CapAdd') and not host['Privileged'] and host['SecurityOpt']==['no-new-privileges:true'] and
         host['Memory']==2*GIB and host['MemorySwap']==2*GIB and host['NanoCpus']==10**9 and host['PidsLimit']==64 and
         host['Tmpfs']==DIAG_TMPFS and not host.get('AutoRemove') and not host.get('PortBindings') and not host.get('Binds') and
         not host.get('Devices') and not host.get('DeviceRequests') and host.get('RestartPolicy',{}).get('Name')=='no')
    binds=[m for m in mounts if m['Type']=='bind']
    need(len(binds)==2 and {m['Destination'] for m in binds}=={'/'+n for n in DIAG_FILES} and
         all(m['RW'] is False and m['Source']==str(packet/Path(m['Destination']).name) for m in binds))
    need(all(m['Type']=='bind' or m['Type']=='tmpfs' and m['Destination'] in DIAG_TMPFS for m in mounts) and
         len({m['Destination'] for m in mounts})==len(mounts) and len(mounts)<=4)
    need(state in ('created','exited') and status['Status']==state and status['Running'] is False and
         status['Paused'] is False and not status.get('Restarting') and status['OOMKilled'] is False and status.get('Error','')=='')
    need(type(status['ExitCode']) is int and 0<=status['ExitCode']<=255)
    if state=='created':need(status['ExitCode']==0)


def worker_report(ok,checkpoint,reason):
    diagnostic_report(ok,checkpoint,reason)
    return {'code':'WORKER_SOURCE_CONTINUATION','ok':ok,'checkpoint':checkpoint,'reason':reason}


def worker_run(packet,expected,review,endpoint):
    checkpoint='HOST_PACKET';deadline=time.monotonic()+90
    try:
        need(re.fullmatch(r'DIP-ARTF-[1-9][0-9]{0,8}',review));p=worker_load(packet,expected)
        checkpoint='HOST_ATTEMPT';write_new(packet/'attempt.json',canonical({'review':review,'packetSha256':expected,'once':True}))
        docker=ContinuationDocker(packet,endpoint,deadline)
        checkpoint='HOST_IMAGE';need(deadline-time.monotonic()>75)
        template='[{{json .Id}},{{json .Os}},{{json .Architecture}},{{json (index .Config "WorkingDir")}},{{json (index .Config "Volumes")}},{{json (index .Config "Entrypoint")}},{{json (index .Config "Labels")}}]'
        image=json.loads(docker.call(['image','inspect','--format',template,WORKER]))
        need(type(image) is list and len(image)==7 and image[:4]==[WORKER,'linux','arm64','/app/server/api'] and
             image[4] in (None,{}) and image[5]==['docker-entrypoint.sh'])
        baseline=frozen_image_labels(image[6])
        frozen=canonical({'image':WORKER,'labels':dict(baseline),'packetSha256':expected});freeze_pin=sha(frozen)
        write_new(packet/'worker-image.json',frozen)  # PRIVATE, durable exact baseline BEFORE create.
        for n,pin in p['files'].items():need(sha(read_file(packet/n))==pin)
        need(sha(read_file(packet/'plan.json',CAP))==expected and deadline-time.monotonic()>65)
        checkpoint='HOST_CREATE';argv=worker_command(packet,expected)
        ident=docker.call(argv).decode('ascii').strip();need(HEX.fullmatch(ident))
        write_new(packet/'worker-id.json',canonical({'id':ident,'image':WORKER,'label':expected}))
        checkpoint='HOST_CREATED_GUARD';worker_guard(docker.inspect(ident),ident,packet,expected,argv,baseline,'created')
        need(sha(read_file(packet/'worker-image.json',CAP))==freeze_pin)
        checkpoint='HOST_START';need(deadline-time.monotonic()>55)
        rc,raw,stderr_present=docker.attach_probe(ident)
        checkpoint='HOST_EXITED_GUARD';record=docker.inspect(ident)
        worker_guard(record,ident,packet,expected,argv,baseline,'exited');need(type(rc) is int and rc==record[3]['ExitCode'])
        checkpoint='HOST_RECEIPT';need(sha(read_file(packet/'worker-image.json',CAP))==freeze_pin)
        if not raw and rc!=0:result=worker_report(False,'BOOTSTRAP','PRELOAD_OR_PROTOCOL')
        else:
            phase=continuation_phase(raw,'worker');need(not stderr_present and rc==(0 if phase['ok'] else 1))
            if phase['ok']:need(phase['proof']['entrypoint'] is not None)
            write_new(packet/'worker-result.json',canonical(phase))
            result=worker_report(phase['ok'],'COMPLETE' if phase['ok'] else phase['checkpoint'],'PASS' if phase['ok'] else phase['reason'])
        write_new(packet/'result.json',canonical(result));return result
    except Exception:
        return worker_report(False,checkpoint,'GUARD_REFUSED')
    # Every outcome retains the fresh actor. No retained worker/API/OLD operations.


def worker_main():
    class ClosedParser(argparse.ArgumentParser):
        def error(self,message):raise ValueError('WORKER_ARGUMENTS_REFUSED')
    try:
        parser=ClosedParser(add_help=False);parser.add_argument('action',choices=WORKER_ACTIONS)
        parser.add_argument('--packet',type=Path,required=True);parser.add_argument('--expected-packet-sha256')
        parser.add_argument('--independent-review-evidence');parser.add_argument('--docker-host')
        parser.add_argument('--authorize-worker-continuation-once',action='store_true')
        flags=[a for a in sys.argv[2:] if a.startswith('--')];need(len(flags)==len(set(flags)) and not any('=' in a for a in flags))
        args=parser.parse_args()
        if args.action=='run-worker-closure':
            need(args.authorize_worker_continuation_once and args.expected_packet_sha256 and args.independent_review_evidence and args.docker_host)
            r=worker_run(args.packet,args.expected_packet_sha256,args.independent_review_evidence,args.docker_host)
        else:
            need(not args.authorize_worker_continuation_once and args.expected_packet_sha256 is None and args.independent_review_evidence is None and args.docker_host is None)
            if args.action=='preview-worker-closure':
                _,p=worker_build(args.packet);pin=sha(canonical(p))
                r={'code':'WORKER_CLOSURE_PLANNED','ok':True,'packetSha256':pin,'actorSeconds':90,'programMs':45000,
                   'acceptedApiReceiptSha256':ACCEPTED_R2['apiReceiptSha256'],'oldNativeEqualityProven':False,'createArgv':worker_command(args.packet,pin)}
            else:r={'code':'WORKER_CLOSURE_PREPARED','ok':True,'packetSha256':worker_prepare(args.packet),'oldNativeEqualityProven':False}
        sys.stdout.write(canonical(r).decode('ascii'));return 0 if r['ok'] else 1
    except Exception:
        sys.stdout.write(canonical(worker_report(False,'HOST_PACKET','GUARD_REFUSED')).decode('ascii'));return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action',required=True)
    for action in ('preview','prepare'):
        prep = sub.add_parser(action)
        prep.add_argument('--packet',type=Path,required=True)
    execute = sub.add_parser('run')
    execute.add_argument('--packet',type=Path,required=True)
    execute.add_argument('--expected-packet-sha256',required=True)
    execute.add_argument('--independent-review-evidence',required=True)
    execute.add_argument('--docker-host',required=True)
    execute.add_argument('--authorize-synthetic-docker-once',action='store_true',required=True)
    args=parser.parse_args()
    try:
        if args.action=='preview':
            _,plan=build_packet(args.packet);pin=sha(canonical(plan))
            print(json.dumps({'code':'PLANNED','ok':True,'packetSha256':pin,'qualified':False,
                  'createArgv':{r:command(args.packet,r,pin,120000 if r=='old' else 45000) for r in ROLES}},sort_keys=True))
        elif args.action=='prepare':
            pin=prepare(args.packet)
            print(json.dumps({'code':'PREPARED','ok':True,'packetSha256':pin,'qualified':False},sort_keys=True))
        else:
            run(args.packet,args.expected_packet_sha256,args.independent_review_evidence,args.docker_host)
            print('{"code":"SYNTHETIC_QUALIFIED","ok":true}')
        return 0
    except Exception:
        print('{"code":"QUALIFICATION_REFUSED","ok":false}')
        return 1


if __name__=='__main__':
    action=sys.argv[1] if len(sys.argv)>1 else None
    raise SystemExit(worker_main() if action in WORKER_ACTIONS else continuation_main() if action in NEW_ACTIONS else diagnostic_main() if action in DIAG_ACTIONS else main())
