"""Injected preservation release gate. No CLI, subprocess transport or app startup.

Factory: make_release_gate(repo, runner, *, deadline, attempt_id). runner is the
Controller.run callable: (argv, timeout=..., cap=...) -> bytes; its shared
.deadline, when present, is also obeyed. The parent owns endpoint isolation,
exclusive-window authority, source review and the outer hard wall-clock fence.

verify uses ONE new actor (90s total cooperative budget, including seal/cleanup).
Only on success is that exact guarded, exited actor removed. Failure best-effort
stops a still-guarded running actor within remaining budget and RETAINS identity;
no adoption, restart, retry, force-rm or prune. Up to THREE host-only rechecks
match the controller's HOLD/pair/web boundaries: all bytes and
inode/permission/ancestry metadata must still equal the authenticated seal and
production-computed usableUntil must not have passed. It creates no second actor.

Only the explicitly requested public release is read, with directory-relative
NOFOLLOW FDs, fixed layout, <=512MiB bundle / <=2GiB DB, 64KiB streaming buffers.
No SQLite, application, controller, env-file or signing-material imports/reads.
Returned random32-byte capability is process-local and must remain PRIVATE.
Recheck exposes only last_recheck_stage and ReleaseRefused.fixed_stage plus
fixed_category (PREDICATE_REFUSED or UNEXPECTED); other operations leave these
exception attributes None. The adapter must retain this verified module's exact
ReleaseRefused class and must not inspect or serialize suppressed exception context.
Release/metadata/receipt contents and exceptions are never printed by this module.
Kernel I/O is not preemptible by cooperative deadline checks: parent supervision
and its hard timeout are required, as for the existing controller runner.
"""
import copy
import datetime
import hashlib
import hmac
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import time

MODULE = 'server/deploy/trust/verify_preservation_release.py'
TEST = 'server/deploy/trust/test_verify_preservation_release.py'
API = 'sha256:4b3a3d4b3c2658ec9a36209afcac69eda2b64cef6e055a5e2716e2602e5338d1'
WORKER = 'sha256:891b5adccbe469345cea585e75dc71c6d3bf93405c5a18386795af1b012b314d'
AGGREGATE = '29c3ca5bd186d625cc102e2f7e43b4f1e8e168ba3372cabd7840cc21b6676a37'
TRUST = 'd75c6f6b2384de68978090fc837387ab4f3e878ee004bccf27ea98a84fbee078'
POLICY = 'cve-db-updated-at-14d-v2'
LABEL = 'io.diplom.preservation-release-verifier'
HEX = re.compile(r'[a-f0-9]{64}\Z')
BOUNDS = {'descriptor.json': 4096, 'descriptor.sig': 64,
          'bundle.bin': 512 * 1024**2, 'db/metadata.json': 4096,
          'db/trivy.db': 2 * 1024**3}
SOURCE_PINS = {
    '/app/server/api/src/worker/vuln-db-bundle.ts':
        'fc5501614adf7f421b1e06e7e25a61976141ffb1466917c7e1ee41fa36338f67',
    '/app/server/api/src/worker/cve-db-policy.mjs':
        '685829a0c33509dbf115bd8cd60489ee72358f8181c44649448baa6408088207'}
ENV = ('PATH=/usr/local/bin:/usr/bin:/bin', 'HOME=/tmp', 'TMPDIR=/tmp', 'TSX_DISABLE_CACHE=1')
TMPFS = {'/tmp': 'rw,noexec,nosuid,nodev,size=134217728,mode=0700,uid=65532,gid=65532'}
BIND_OPTIONS = {'Propagation': 'rprivate', 'NonRecursive': False,
                'CreateMountpoint': False, 'ReadOnlyNonRecursive': False,
                'ReadOnlyForceRecursive': False}
REQUEST_KEYS = frozenset(('version', 'actor_image', 'candidate_worker_image', 'source',
                          'manifest', 'artifact', 'policy', 'trusted_spki_sha256',
                          'source_aggregate', 'verifier_sources'))
IDENTITY_KEYS = frozenset(('envelopeVersion', 'signer', 'source', 'schemaVersion',
                           'artifactSha256', 'metadataSha256', 'dbSha256',
                           'manifestDigest', 'updatedAt', 'downloadedAt', 'nextUpdate'))
IMAGE_FORMAT = ('{"id":{{json .Id}},"os":{{json .Os}},"arch":{{json .Architecture}},'
                '"labels":{{json .Config.Labels}},"volumes":{{json .Config.Volumes}}}')
INSPECT_FORMAT = ('{"id":{{json .Id}},"image":{{json .Image}},"name":{{json .Name}},'
                  '"labels":{{json .Config.Labels}},"state":{{json .State}},'
                  '"host":{{json .HostConfig}},"mounts":{{json .Mounts}},'
                  '"entry":{{json .Config.Entrypoint}},"cmd":{{json .Config.Cmd}},'
                  '"user":{{json .Config.User}},"cwd":{{json .Config.WorkingDir}},'
                  '"stop":{{json .Config.StopTimeout}},'
                  '"health_disabled":{{if .Config.Healthcheck}}'
                  '{{if eq (json .Config.Healthcheck) "{\\"Test\\":[\\"NONE\\"]}"}}'
                  'true{{else}}false{{end}}{{else}}false{{end}}}')

# Fixed inline entry point, bound by this module pin. The inherited manual CLI
# is NOT imported or executed. Source pins cover both actual imported modules;
# immutable image ID binds their already-reviewed 108-file profile/dependencies.
PROGRAM = r'''import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHash,createPublicKey} from 'node:crypto';
const sha=b=>createHash('sha256').update(b).digest('hex');
const stamp=s=>[s.dev,s.ino,s.mode,s.nlink,s.uid,s.gid,s.size,s.mtimeNs,s.ctimeNs].map(String);
const same=(a,b)=>assert.deepEqual(stamp(a),stamp(b));
let timer;
try {
 const q=JSON.parse(process.argv[1]);
 assert.equal(process.argv.length,2);
 assert.equal(process.getuid(),65532);assert.equal(process.getgid(),65532);
 assert.equal(process.platform,'linux');assert.equal(process.arch,'arm64');
 assert.deepEqual(Object.keys(process.env).sort(),['HOME','PATH','TMPDIR','TSX_DISABLE_CACHE']);
 assert(Number.isSafeInteger(q.ms)&&q.ms>0&&q.ms<=80000);
 timer=setTimeout(()=>process.exit(1),q.ms);
 const expires=process.hrtime.bigint()+BigInt(q.ms)*1000000n;
 const tick=()=>assert(process.hrtime.bigint()<=expires);
 const entries=(path,expected)=>{
  tick();const dir=fs.opendirSync(path,{bufferSize:1}),seen=new Set();
  try{for(let i=0;i<=expected.length;i++){
   tick();const entry=dir.readSync();
   if(entry===null){assert.deepEqual([...seen].sort(),expected);return;}
   assert(expected.includes(entry.name)&&!seen.has(entry.name));seen.add(entry.name);
  }assert.fail();}finally{dir.closeSync();}
 };
 const read=(p,cap,single=false)=>{
  assert.equal(fs.realpathSync(p),p);
  const before=fs.lstatSync(p,{bigint:true});
  assert(before.isFile()&&before.nlink>=1n&&(!single||before.nlink===1n)&&before.size>0n&&before.size<=BigInt(cap));
  const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  try{same(before,fs.fstatSync(fd,{bigint:true}));const b=fs.readFileSync(fd);
   assert(b.length<=cap&&BigInt(b.length)===before.size);
   same(before,fs.fstatSync(fd,{bigint:true}));same(before,fs.lstatSync(p,{bigint:true}));return b;
  }finally{fs.closeSync(fd);}
 };
 const limits={'descriptor.json':4096,'descriptor.sig':64,'bundle.bin':536870912,'db/metadata.json':4096,'db/trivy.db':2147483648};
 const inventory=()=>{
  for(const p of ['/','/opt','/opt/release','/opt/release/db']){
   const s=fs.lstatSync(p,{bigint:true});assert(s.isDirectory()&&!s.isSymbolicLink());
   if(p.startsWith('/opt/release'))assert.equal(s.mode&0o222n,0n);
  }
  entries('/opt/release',['bundle.bin','db','descriptor.json','descriptor.sig']);
  entries('/opt/release/db',['metadata.json','trivy.db']);
  const out={},seen=new Set();
  for(const [p,cap] of Object.entries(limits)){
   const s=fs.lstatSync('/opt/release/'+p,{bigint:true}),id=String(s.dev)+':'+String(s.ino);
   assert(s.isFile()&&s.nlink===1n&&s.size>0n&&s.size<=BigInt(cap)&&!(s.mode&0o7222n)&&!seen.has(id));
   assert(p!=='descriptor.sig'||s.size===64n);seen.add(id);out[p]=stamp(s);
  }
  for(const p of ['/opt/release','/opt/release/db'])out[p]=stamp(fs.lstatSync(p,{bigint:true}));
  return out;
 };
 const before=inventory();
 const pins={
 '/app/server/api/src/worker/vuln-db-bundle.ts':'fc5501614adf7f421b1e06e7e25a61976141ffb1466917c7e1ee41fa36338f67',
 '/app/server/api/src/worker/cve-db-policy.mjs':'685829a0c33509dbf115bd8cd60489ee72358f8181c44649448baa6408088207'};
 for(const [p,pin]of Object.entries(pins))assert.equal(sha(read(p,65536,true)),pin);
 assert(!fs.existsSync('/app/server/api/src/worker/vuln-db-bundle.js'));
 const pem=read('/app/server/deploy/trust/db-signing-key.pub.pem',16384);
 const key=createPublicKey(pem);assert.equal(key.asymmetricKeyType,'ed25519');
 assert.equal(sha(key.export({type:'spki',format:'der'})),'d75c6f6b2384de68978090fc837387ab4f3e878ee004bccf27ea98a84fbee078');
 const {preflightVulnDbBundle}=await import('file:///app/server/api/src/worker/vuln-db-bundle.ts');
 const {CURRENT_DB_POLICY,evaluateDbPolicy,operatorUsableUntil}=await import('file:///app/server/api/src/worker/cve-db-policy.mjs');
 assert.equal(CURRENT_DB_POLICY,'cve-db-updated-at-14d-v2');
 const verified=await preflightVulnDbBundle({directory:'/opt/release',trustedPublicKeyPem:pem.toString('utf8'),
  expectedSigner:'local-db-operator-v1',expectedSource:'ghcr.io/aquasecurity/trivy-db@'+q.manifest,
  expectedSchemaVersion:2,expectedArtifactSha256:q.artifact,expectedManifestDigest:q.manifest,policy:CURRENT_DB_POLICY});
 assert.equal(verified.kind,'envelope-preflight-only');
 const id=verified.identity;
 assert.equal(sha(Buffer.from(JSON.stringify(id))),q.files['descriptor.json']);
 assert.equal(sha(read('/opt/release/descriptor.sig',64,true)),q.files['descriptor.sig']);
 assert.equal(id.artifactSha256,q.files['bundle.bin']);
 assert.equal(id.metadataSha256,q.files['db/metadata.json']);assert.equal(id.dbSha256,q.files['db/trivy.db']);
 assert.deepEqual(inventory(),before);
 const receipt=evaluateDbPolicy(id,CURRENT_DB_POLICY);
 const result={code:'RELEASE_AUTHENTICATED',ok:true,identity:id,policy:CURRENT_DB_POLICY,
  evaluatedAt:receipt.evaluatedAt,usableUntil:operatorUsableUntil(id)};
 const raw=JSON.stringify(result)+'\n';assert(Buffer.byteLength(raw)<=16384);process.stdout.write(raw);
} catch {process.stdout.write('{"code":"RELEASE_REFUSED","ok":false}\n');process.exitCode=1;}
finally {clearTimeout(timer);}
'''


RECHECK_STAGES = frozenset(('CAPABILITY_REQUEST', 'SOURCE_PINS', 'CLOCK_BEFORE',
                            'INVENTORY_READ', 'INVENTORY_EQUALITY', 'CLOCK_AFTER'))
RECHECK_CATEGORIES = frozenset(('PREDICATE_REFUSED', 'UNEXPECTED'))


class ReleaseRefused(Exception):
    def __init__(self, *, fixed_stage=None, fixed_category=None):
        if (fixed_stage is not None and fixed_stage not in RECHECK_STAGES or
                fixed_category is not None and fixed_category not in RECHECK_CATEGORIES):
            raise ValueError('INVALID_RELEASE_REFUSAL')
        self.fixed_stage, self.fixed_category = fixed_stage, fixed_category
        super().__init__('RELEASE_REFUSED')


def need(value):
    if not value:
        raise ReleaseRefused()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def decode(raw, cap=16384):
    need(type(raw) is bytes and 0 < len(raw) <= cap)
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out)
            out[key] = value
        return out
    def invalid(_):
        raise ReleaseRefused()
    return json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs,
                      parse_float=invalid, parse_constant=invalid)


def stamp(value):
    return [value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def plain_path(value):
    need(type(value) is str and 1 < len(value.encode('utf-8')) <= 4096 and
         value.startswith('/') and not value.startswith('//') and
         str(PurePosixPath(value)) == value and
         not any(part in ('.', '..') for part in value.split('/')) and
         not any(ord(c) < 32 or ord(c) == 127 or c in ',"' for c in value))
    return Path(value)


def open_chain(value, tick):
    """Open only ancestor metadata, never enumerate ancestor contents."""
    path = plain_path(value)
    fds, states = [], []
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fds.append(fd)
        states.append(('/', stamp(os.fstat(fd))))
        current = ''
        for part in path.parts[1:]:
            tick()
            before = os.stat(part, dir_fd=fds[-1], follow_symlinks=False)
            need(stat.S_ISDIR(before.st_mode))
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1])
            fds.append(fd)
            after = os.fstat(fd)
            need(stamp(after) == stamp(before))
            # Owner/root-controlled ancestry; root-owned sticky temp ancestors
            # are tolerated, but sealed release/db directories themselves aren't.
            need(not after.st_mode & 0o022 or
                 after.st_uid == 0 and bool(after.st_mode & stat.S_ISVTX))
            current += '/' + part
            states.append((current, stamp(after)))
        return fds, states
    except BaseException:
        for fd in reversed(fds):
            os.close(fd)
        raise


def read_fd(parent, name, cap, tick, *, sealed):
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= cap)
    if sealed:
        need(not before.st_mode & 0o7222 and before.st_mode & 0o004)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        need(stamp(os.fstat(fd)) == stamp(before))
        digest, size = hashlib.sha256(), 0
        while True:
            tick()
            block = os.read(fd, min(65536, cap + 1 - size))
            if not block:
                break
            size += len(block)
            need(size <= cap)
            digest.update(block)
        need(size == before.st_size and stamp(os.fstat(fd)) == stamp(before) and
             stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)) == stamp(before))
        return {'stat': stamp(before), 'sha256': digest.hexdigest()}
    finally:
        os.close(fd)


def exact_entries(fd, expected, tick):
    """Consume at most expected+1 entries; close even on deadline/refusal."""
    tick()
    with os.scandir(fd) as entries:
        seen = set()
        for _ in range(len(expected) + 1):
            tick()
            try:
                entry = next(entries)
            except StopIteration:
                need(seen == expected)
                return
            need(entry.name in expected and entry.name not in seen)
            seen.add(entry.name)
        raise ReleaseRefused()


def inventory(source, tick):
    """Hash ONLY five existing, immutable public release files, without raw output."""
    fds, ancestors = open_chain(source, tick)
    dbfd = None
    try:
        root = fds[-1]
        need(not os.fstat(root).st_mode & 0o7222 and os.fstat(root).st_mode & 0o005 == 0o005)
        exact_entries(root, {'descriptor.json', 'descriptor.sig', 'bundle.bin', 'db'}, tick)
        before = os.stat('db', dir_fd=root, follow_symlinks=False)
        need(stat.S_ISDIR(before.st_mode) and not before.st_mode & 0o7222 and
             before.st_mode & 0o005 == 0o005)
        dbfd = os.open('db', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        need(stamp(os.fstat(dbfd)) == stamp(before))
        exact_entries(dbfd, {'metadata.json', 'trivy.db'}, tick)
        files = {}
        for name, cap in BOUNDS.items():
            files[name] = read_fd(dbfd if name.startswith('db/') else root,
                                  name.split('/')[-1], cap, tick, sealed=True)
        need(files['descriptor.sig']['stat'][6] == 64)
        ids = [(v['stat'][0], v['stat'][1]) for v in files.values()]
        need(len(set(ids)) == len(ids))
        need(stamp(os.fstat(dbfd)) == stamp(before) and
             stamp(os.stat('db', dir_fd=root, follow_symlinks=False)) == stamp(before))
        exact_entries(root, {'descriptor.json', 'descriptor.sig', 'bundle.bin', 'db'}, tick)
        exact_entries(dbfd, {'metadata.json', 'trivy.db'}, tick)
        # Reopen the literal full chain: retaining an unlinked old FD isn't proof.
        again, current = open_chain(source, tick)
        try:
            need(current == ancestors and [stamp(os.fstat(fd)) for fd in fds] ==
                 [s for _, s in ancestors])
        finally:
            for fd in reversed(again):
                os.close(fd)
        return {'ancestors': ancestors, 'db': stamp(before), 'files': files}
    finally:
        if dbfd is not None:
            os.close(dbfd)
        for fd in reversed(fds):
            os.close(fd)


def source_digest(path, tick):
    fds, _ = open_chain(str(path.parent), tick)
    try:
        return read_fd(fds[-1], path.name, 65536, tick, sealed=False)['sha256']
    finally:
        for fd in reversed(fds):
            os.close(fd)


def until_ns(value):
    # Parse a threshold COMPUTED BY production operatorUsableUntil, not a second
    # implementation of evaluateDbPolicy. Preserve its nine fractional digits.
    need(type(value) is str)
    match = re.fullmatch(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d{9})Z', value)
    need(match is not None)
    instant = datetime.datetime.strptime(match[1], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=datetime.timezone.utc)
    return int(instant.timestamp()) * 10**9 + int(match[2])


class ReleaseGate:
    def __init__(self, repo, runner, *, deadline, attempt_id, clock=time.monotonic, wall_ns=time.time_ns):
        need(callable(runner) and callable(clock) and callable(wall_ns) and
             type(deadline) in (int, float) and math.isfinite(deadline) and
             type(attempt_id) is str and re.fullmatch(r'[a-f0-9]{32}', attempt_id))
        self.repo = plain_path(str(Path(repo).absolute()))
        need(self.repo / MODULE == Path(__file__).absolute())
        self.run, self.deadline, self.clock, self.wall_ns = runner, deadline, clock, wall_ns
        self.attempt_id = attempt_id
        self.name = 'dip-preservation-release-' + attempt_id
        self.id = None
        self._used = self._failed = self._may_exist = False
        self._rechecks = 0
        self._last_recheck_stage = None
        self._until = min(deadline, clock() + 90)
        self._baseline = self._cmd = self._request = self._sealed = self._capability = None
        self._sources = {name: source_digest(self.repo / name, self._tick) for name in (MODULE, TEST)}

    @property
    def sources(self):
        return dict(self._sources)

    @property
    def last_recheck_stage(self):
        """None before recheck, otherwise one closed RECHECK_STAGES identifier."""
        return self._last_recheck_stage

    @property
    def retained(self):
        # PRIVATE supervisory identity, never a reason to adopt a preexisting actor.
        return {'name': self.name, 'id': self.id} if self._may_exist else None

    def _remaining(self):
        outer = getattr(self.run, 'deadline', self.deadline)
        need(type(outer) in (int, float) and math.isfinite(outer))
        left = min(self._until, self.deadline, outer) - self.clock()
        need(left > 0)
        return left

    def _tick(self):
        self._remaining()

    def _call(self, args, *, cap=16384, reserve=0):
        left = self._remaining() - reserve
        need(left > 0)
        raw = self.run(tuple(args), timeout=min(left, 90), cap=cap)
        need(type(raw) is bytes and len(raw) <= cap)
        self._tick()
        return raw

    def _validate(self, request):
        need(type(request) is dict and set(request) == REQUEST_KEYS)
        need(type(request['version']) is int and request['version'] == 1 and
             request['actor_image'] == API and request['candidate_worker_image'] == WORKER and
             request['source_aggregate'] == AGGREGATE and request['policy'] == POLICY and
             request['trusted_spki_sha256'] == TRUST and request['verifier_sources'] == self.sources)
        need(type(request['verifier_sources']) is dict and
             set(request['verifier_sources']) == {MODULE, TEST})
        plain_path(request['source'])
        need(type(request['manifest']) is str and re.fullmatch(r'sha256:[a-f0-9]{64}', request['manifest']) and
             type(request['artifact']) is str and HEX.fullmatch(request['artifact']))
        need(all(source_digest(self.repo / p, self._tick) == pin for p, pin in self._sources.items()))

    def _image(self):
        info = decode(self._call(('docker', 'image', 'inspect', '--format', IMAGE_FORMAT, API)))
        need(type(info) is dict and set(info) == {'id', 'os', 'arch', 'labels', 'volumes'} and
             info['id'] == API and info['os'] == 'linux' and info['arch'] == 'arm64' and
             info['volumes'] in (None, {}))
        labels = {} if info['labels'] is None else info['labels']
        need(type(labels) is dict and LABEL not in labels and len(labels) <= 128 and
             all(type(k) is str and type(v) is str and len(k) <= 256 and len(v) <= 4096
                 for k, v in labels.items()))
        self._baseline = dict(labels)

    def _command(self, request, captured):
        payload = canonical({'manifest': request['manifest'], 'artifact': request['artifact'],
                             'files': {k: v['sha256'] for k, v in captured['files'].items()},
                             'ms': min(80000, int((self._remaining() - 8) * 1000))}).decode('ascii')
        need(json.loads(payload)['ms'] > 0)
        self._cmd = ['-i', *ENV, '/usr/local/bin/node', '--import', 'tsx', '--input-type=module',
                     '--eval', PROGRAM, '--', payload]
        return ('docker', 'create', '--name', self.name, '--label', LABEL + '=' + self.attempt_id,
                '--pull', 'never', '--platform', 'linux/arm64', '--user', '65532:65532',
                '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt',
                'no-new-privileges:true', '--memory', '2147483648', '--memory-swap', '2147483648',
                '--cpus', '1', '--pids-limit', '64', '--restart', 'no', '--log-driver', 'none',
                '--ipc', 'none', '--no-healthcheck', '--stop-timeout', '1', '--workdir', '/app/server/api',
                '--entrypoint', '/usr/bin/env', '--tmpfs', '/tmp:' + TMPFS['/tmp'],
                '--mount', 'type=bind,src=' + request['source'] +
                ',dst=/opt/release,readonly,bind-propagation=rprivate', API, *self._cmd)

    def _inspect(self):
        need(type(self.id) is str and HEX.fullmatch(self.id))
        return decode(self._call(('docker', 'container', 'inspect', '--format', INSPECT_FORMAT, self.id)), 65536)

    def _guard(self, info, state=None):
        need(type(info) is dict and set(info) == {'id', 'image', 'name', 'labels', 'state', 'host',
                                                'mounts', 'entry', 'cmd', 'user', 'cwd', 'stop', 'health_disabled'})
        need(info['id'] == self.id and info['image'] == API and info['name'] == '/' + self.name and
             info['labels'] == dict(self._baseline, **{LABEL: self.attempt_id}) and
             info['entry'] == ['/usr/bin/env'] and info['cmd'] == self._cmd and
             info['user'] == '65532:65532' and info['cwd'] == '/app/server/api' and
             type(info['stop']) is int and info['stop'] == 1 and info['health_disabled'] is True)
        host = info['host']
        need(type(host) is dict and host['ReadonlyRootfs'] is True and host['NetworkMode'] == 'none' and
             host['CapDrop'] == ['ALL'] and not host.get('CapAdd') and host['Privileged'] is False and
             host['SecurityOpt'] == ['no-new-privileges:true'] and host['Memory'] == 2 * 1024**3 and
             host['MemorySwap'] == 2 * 1024**3 and host['NanoCpus'] == 10**9 and host['PidsLimit'] == 64 and
             host['Tmpfs'] == TMPFS and host['AutoRemove'] is False and
             host['RestartPolicy'] == {'Name': 'no', 'MaximumRetryCount': 0} and
             host['LogConfig'] == {'Type': 'none', 'Config': {}} and host['IpcMode'] == 'none' and
             host.get('PidMode', '') == '' and host.get('UTSMode', '') == '' and
             not any(host.get(k) for k in ('Binds', 'Devices', 'DeviceRequests', 'VolumesFrom',
                                          'PortBindings', 'PublishAllPorts', 'Links', 'ExtraHosts')))
        spec = {'Type': 'bind', 'Source': self._request['source'], 'Target': '/opt/release',
                'ReadOnly': True, 'BindOptions': BIND_OPTIONS}
        # Moby v28 mount.BindOptions uses json omitempty for these four false
        # defaults: absence means false, never permission to create a source.
        # https://github.com/moby/moby/blob/v28.0.1/api/types/mount/mount.go
        observed = copy.deepcopy(host.get('Mounts'))
        need(type(observed) is list and len(observed) == 1 and type(observed[0]) is dict)
        options = observed[0].get('BindOptions')
        need(type(options) is dict and set(options) <= set(BIND_OPTIONS) and
             options.get('Propagation') == 'rprivate')
        for key in set(BIND_OPTIONS) - {'Propagation'}:
            need(key not in options or options[key] is False)
            options[key] = False
        # Canonical comparison rejects numeric 0/1 masquerading as booleans.
        need(canonical(observed) == canonical([spec]))
        mounts = info['mounts']
        need(type(mounts) is list and 1 <= len(mounts) <= 2 and
             len({m['Destination'] for m in mounts}) == len(mounts))
        binds = [m for m in mounts if m['Type'] == 'bind']
        need(len(binds) == 1 and binds[0]['Source'] == self._request['source'] and
             binds[0]['Destination'] == '/opt/release' and binds[0]['RW'] is False and
             binds[0]['Propagation'] == 'rprivate')
        need(all(m['Type'] == 'bind' or m['Type'] == 'tmpfs' and m['Destination'] == '/tmp' for m in mounts))
        current = info['state']
        need(type(current) is dict and current['Status'] in ('created', 'running', 'exited') and
             current['Running'] is (current['Status'] == 'running') and
             current['Paused'] is False and current['Restarting'] is False and
             current['Dead'] is False and current['OOMKilled'] is False and current['Error'] == '')
        if state is not None:
            need(current['Status'] == state and current['ExitCode'] == 0)

    def _result(self, raw, captured):
        result = decode(raw)
        need(type(result) is dict and set(result) == {'code', 'ok', 'identity', 'policy', 'evaluatedAt', 'usableUntil'} and
             result['code'] == 'RELEASE_AUTHENTICATED' and result['ok'] is True and result['policy'] == POLICY and
             type(result['evaluatedAt']) is int and result['evaluatedAt'] > 0)
        identity, request = result['identity'], self._request
        need(type(identity) is dict and set(identity) == IDENTITY_KEYS and
             type(identity['envelopeVersion']) is int and identity['envelopeVersion'] == 1 and
             type(identity['schemaVersion']) is int and identity['schemaVersion'] == 2 and
             identity['signer'] == 'local-db-operator-v1' and identity['source'] ==
             'ghcr.io/aquasecurity/trivy-db@' + request['manifest'] and
             identity['manifestDigest'] == request['manifest'] and identity['artifactSha256'] == request['artifact'])
        need(all(type(identity[k]) is str and HEX.fullmatch(identity[k]) for k in
                 ('artifactSha256', 'metadataSha256', 'dbSha256')))
        files = captured['files']
        need(files['bundle.bin']['sha256'] == identity['artifactSha256'] and
             files['db/metadata.json']['sha256'] == identity['metadataSha256'] and
             files['db/trivy.db']['sha256'] == identity['dbSha256'])
        # JS authenticates its canonical descriptor serialization against this
        # host hash; do not duplicate Ed25519 or freshness policy in Python.
        expiry = until_ns(result['usableUntil'])
        need(self._wall_start <= self.wall_ns() <= expiry and
             abs(result['evaluatedAt'] * 10**6 - self.wall_ns()) <= 5 * 10**9)
        return expiry

    def _stop_failed(self):
        if self.id is None:
            return
        try:
            info = self._inspect()
            self._guard(info)
            if info['state']['Running']:
                need(self._call(('docker', 'stop', '--time', '1', self.id)).strip() == self.id.encode())
            # Deliberately retain the exact failed actor, never rm or retry it.
        except BaseException:
            pass  # Parent retains identity and MUST HOLD if cancellation is unproved.

    def verify(self, request):
        # Reject reuse WITHOUT even re-inspecting or re-stopping a retained actor.
        need(not self._used and not self._failed)
        self._used = True  # consumed even on refusal/uncertain create
        try:
            self._until = min(self.deadline, self.clock() + 90)
            self._wall_start = self.wall_ns()
            self._validate(request)
            self._request = copy.deepcopy(request)
            captured = inventory(request['source'], self._tick)
            need(captured['files']['bundle.bin']['sha256'] == request['artifact'])
            self._image()
            need(self._call(('docker', 'ps', '-aq', '--no-trunc', '--filter', 'name=^/' + self.name + '$')).strip() == b'')
            command = self._command(request, captured)
            self._may_exist = True  # BEFORE create: an ambiguous client failure is consumed.
            raw = self._call(command, cap=4096)
            need(HEX.fullmatch(raw.strip().decode('ascii')))
            self.id = raw.strip().decode('ascii')
            self._guard(self._inspect(), 'created')
            output = self._call(('docker', 'start', '--attach', self.id), reserve=5)
            self._guard(self._inspect(), 'exited')
            expiry = self._result(output, captured)
            need(inventory(request['source'], self._tick) == captured)
            self._guard(self._inspect(), 'exited')
            need(self._call(('docker', 'rm', self.id)).strip() == self.id.encode())
            self.id = None
            self._may_exist = False
            self._tick()
            self._last_wall = self.wall_ns()
            need(self._wall_start <= self._last_wall <= expiry)
            self._sealed = (captured, expiry)
            self._capability = secrets.token_bytes(32)
            return self._capability
        except BaseException:
            self._failed = True
            self._stop_failed()
            raise ReleaseRefused() from None

    def recheck(self, request, seal):
        self._last_recheck_stage = 'CAPABILITY_REQUEST'
        try:
            # Current controller has THREE boundaries: before HOLD/stop, before
            # API+worker replacement, before web replacement. No actor is rerun.
            need(self._sealed is not None and not self._failed and self._rechecks < 3)
            self._rechecks += 1
            self._until = min(self.deadline, self.clock() + 90)
            need(type(seal) is bytes and hmac.compare_digest(seal, self._capability) and request == self._request)
            captured, expiry = self._sealed
            self._last_recheck_stage = 'SOURCE_PINS'
            self._validate(request)
            self._last_recheck_stage = 'CLOCK_BEFORE'
            before = self.wall_ns()
            need(self._last_wall <= before <= expiry)
            self._last_recheck_stage = 'INVENTORY_READ'
            observed = inventory(request['source'], self._tick)
            self._last_recheck_stage = 'INVENTORY_EQUALITY'
            need(observed == captured)
            self._last_recheck_stage = 'CLOCK_AFTER'
            after = self.wall_ns()
            need(before <= after <= expiry)
            self._last_wall = after
            return None
        except BaseException as exc:
            self._failed = True
            # Only our exact known predicate exception earns that category.
            # Unknown errors remain UNEXPECTED, without exposing their type/text.
            category = ('PREDICATE_REFUSED' if type(exc) is ReleaseRefused and
                        exc.fixed_category in (None, 'PREDICATE_REFUSED') else 'UNEXPECTED')
            raise ReleaseRefused(fixed_stage=self._last_recheck_stage,
                                 fixed_category=category) from None


def make_release_gate(repo, runner, *, deadline, attempt_id):
    """Factory for explicit parent injection; never dynamically load the controller."""
    try:
        return ReleaseGate(repo, runner, deadline=deadline, attempt_id=attempt_id)
    except BaseException:
        raise ReleaseRefused() from None
