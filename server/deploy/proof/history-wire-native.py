#!/usr/bin/env python3
"""PUBLIC candidate; default --plan/--self-test never starts processes or writes.

--execute is a separate parent-only authority on this exact five-file/source/config/
manifest freeze and cached images. No CVE lifecycle import, build, pull, install,
provider, host HTTP, production client, private store or existing scratch adoption.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time

ROOT = Path(__file__).absolute().parents[3]
SELF = Path(__file__).absolute()
NEW = ('server/deploy/proof/history-wire-native.py', 'server/deploy/proof/test_history_wire_native.py',
       'server/api/src/llm/tests/history-wire-native.seed.ts', 'server/api/src/llm/tests/history-wire-native.api.ts',
       'server/api/src/llm/tests/history-wire-native.client.mjs')
SEED, API, CLIENT = NEW[2:]
CONFIG = 'server/deploy/stand.nginx.conf'
CONFIG_SHA = '52a2aef79bafa3da69fcc2e6a6b86867d4f9fb662003791a5531394a8a35344a'
SNAPSHOT = 'e4efad5ff9ef56040e1d341311599d8bb19da874af94b5bf1eaffa97b7ed6334'
IMAGE = 'sha256:c09ce4c8e6185784fad2c263b462952092fa89058d16363ebd543e0cd4bbd50d'
NGINX = 'sha256:1659b39c98d5183c91feae78a8d9eb1d4c6ee527d541c1e1d74dfe842adee8c0'
DOCKER = Path('/opt/homebrew/bin/docker')
CLI_TARGET = Path('/opt/homebrew/Cellar/docker/28.1.1/bin/docker')
CLI_LINK = '../Cellar/docker/28.1.1/bin/docker'
HOST = 'unix:///Users/vsevolod/.docker/run/docker.sock'
INPUTS = ('package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml', 'server/api/package.json',
          'server/api/tsconfig.json', 'server/deploy/trust/db-signing-key.pub.pem',
          'server/deploy/gateway/proxy.py', 'server/deploy/gateway/Dockerfile',
          'server/deploy/compose.stand.yaml', 'server/deploy/compose.stand.vuln.local.yaml',
          'server/deploy/compose.stand.nginx.local.yaml', CONFIG)
TREES = ('server/api/src', 'server/runtime/src', 'server/broker/src')
LEAF = 'src/shared/api/scans/runtimeTransport.ts'
SUFFIXES = {'.ts', '.tsx', '.mts', '.cts', '.js', '.mjs', '.cjs', '.json'}
HEX = re.compile(r'[a-f0-9]{64}\Z')
ID = re.compile(r'[a-f0-9]{64}\Z')
UUID = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z')
NAME = re.compile(r'dip-history-wire-[a-f0-9]{16}\Z')
POLICY = 'desktop-exact-literal-or-host-mnt-v1'
TOTAL, WORK, CALLS, HTTP, CAP, AGGREGATE = 300, 240, 80, 128, 65536, 4 * 1024**2
LABEL = 'dip.history-wire.project'
RUN_LABEL = 'dip.history-wire.run'
MIB = 1024**2
ENV = {'AUTH_DB_PATH': '/auth/auth.sqlite', 'SCAN_LEDGER_PATH': '/data/scans.sqlite',
       'AUTH_ORIGIN': 'http://127.0.0.1:8080', 'AUTH_ALLOW_INSECURE_LOCAL_HTTP': 'true',
       'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS': 'false', 'SCAN_BROWSER_ALLOWED_USER_IDS': '',
       'LLM_ENABLED': 'false', 'LLM_ROUTING_APPROVED': 'false', 'LLM_QUOTA_ENABLED': 'false',
       'LLM_HISTORY_ENABLED': 'true', 'LLM_HISTORY_REVISION': 'owner-history-v1',
       'LLM_HISTORY_AUTHORITY': 'single-api-quiesced-terminal-v1',
       'SCAN_JWT_SECRET': 'history-wire-public-fixture-jwt-not-production-v1',
       'SCAN_JWT_ISSUER': 'history-wire-fixture', 'SCAN_JWT_AUDIENCE': 'history-wire-fixture',
       'PORT': '3001', 'SCAN_BIND_ADDRESS': '0.0.0.0'}
IMAGE_ENV_KEYS = {'PATH', 'NODE_VERSION', 'YARN_VERSION', 'PNPM_HOME', 'PNPM_VERSION', 'NODE_ENV',
                  'NGINX_VERSION', 'NJS_VERSION', 'NJS_RELEASE', 'PKG_RELEASE', 'DYNPKG_RELEASE'}
SLOTS = {'volume-init': (0, 64, 250000000, 16, 'none'),
         'seed': (65532, 128, 500000000, 32, 'none'),
         'api': (65532, 512, 1000000000, 128, 'backend'),
         'web': (101, 128, 500000000, 32, 'backend'),
         'probe': (65532, 128, 500000000, 32, 'probe')}
INIT_JS = """const a=require('node:assert/strict'),f=require('node:fs');process.umask(0o077);
for(const p of ['/auth','/data']){const s=f.lstatSync(p);a(s.isDirectory()&&!s.isSymbolicLink());a.equal(f.realpathSync(p),p);
if(s.uid===65532&&s.gid===65532&&(s.mode&4095)===448)continue;
a.equal(s.uid,0);a.equal(s.gid,0);a.equal(s.mode&4095,493);a.deepEqual(f.readdirSync(p),[]);
f.chmodSync(p,448);f.chownSync(p,65532,65532);const q=f.lstatSync(p);a.equal(q.uid,65532);a.equal(q.gid,65532);a.equal(q.mode&4095,448)}
process.stdout.write('{"kind":"history-wire-volume-init","prepared":true}\\n')"""
WEB_CHECK = "sha256sum /etc/nginx/nginx.conf && nginx -v && nginx -t -c /etc/nginx/nginx.conf"
INSPECT = ('{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},'
           '"labels":{{json .Config.Labels}},"user":{{json .Config.User}},'
           '"entrypoint":{{json .Config.Entrypoint}},"cmd":{{json .Config.Cmd}},'
           '"cwd":{{json .Config.WorkingDir}},"host":{{json .HostConfig}},'
           '"mounts":{{json .Mounts}},"networks":{{json .NetworkSettings.Networks}},'
           '"state":{{json .State}}}')


class Refusal(Exception):
    """Only fixed codes from this candidate, never a raw process error."""


class RuntimeQualifierRefusal(Refusal):
    """Primary fixed code plus all failed fixed labels; never inspected values."""
    def __init__(self, code, diagnostics):
        super().__init__(code)
        self.diagnostics = diagnostics


class ReportingRefusal(Refusal):
    def __init__(self, code, diagnostic):
        super().__init__(code)
        self.diagnostic = diagnostic


class SeedDiagnosticRefusal(Refusal):
    def __init__(self, diagnostics):
        super().__init__('seed_checkpoint_refused')
        self.diagnostics = diagnostics


SEED_ENTRY_STEPS = ('entry_read','entry_parse','entry_argv','entry_mode')
SEED_COMMON_STEPS = ('input_schema','environment_uid','environment_gid','environment_auth_path',
    'environment_scan_path','environment_flags','environment_private_names','environment_volume_stat',
    'environment_volume_mode','environment_volume_canonical','environment_volume_distinct','quota_absent',
    'source_fixture_shape','source_fixture_stat','source_fixture_hash','source_map_read','source_map_identity',
    'source_embedded_path','source_embedded_stat','source_embedded_hash','source_tree','receipt_encode',
    'metadata_file','metadata_headroom','metadata_other_files','metadata_sidecars','metadata_schema','metadata_counts','metadata_close',
    'access_open','access_read','access_close','state_schema','state_uuids','state_ids','state_hashes','state_binding','state_inode')
SEED_SETUP_STEPS = ('fresh_auth_empty','fresh_scan_empty','history_runtime_construct','history_missing_open',
    'history_missing_close','history_missing_assert','initialize_spawn','initialize_status','initialize_error_signal',
    'initialize_stderr','initialize_stdout','initialize_identity','existing_spawn','existing_status','existing_error_signal',
    'existing_stdout','existing_stderr','existing_hash','existing_inode','auth_register_open','auth_register_owner',
    'auth_register_foreign','auth_register_assert','auth_register_close','auth_allowlist_finalize','auth_login_open',
    'auth_login_owner','auth_login_close','ledger_open','history_open','history_writer','report_construct','report_enqueue',
    'report_claim','report_finish','report_pending','report_projection','history_original_head','history_descriptor',
    'history_access_incarnation','history_begin','history_begin_revision','history_fail','history_failed_head','history_metadata',
    'state_construct','state_validate','setup_close_history','setup_close_ledger')
SEED_AUDIT_STEPS = ('audit_state','audit_allowlist','audit_ledger','audit_history_open','audit_head','audit_metadata',
    'audit_writer','audit_identity','audit_shape','audit_turn','audit_fingerprints','audit_original_request','audit_projection',
    'audit_report','audit_decision','audit_close_history','audit_close_ledger')
SEED_ERROR_CLASSES = ('Error','AssertionError','TypeError','RangeError','SyntaxError','SqliteError',
    'ServiceUnavailableException','UnauthorizedException','ForbiddenException','ConflictException',
    'BadRequestException','InternalServerErrorException','other_error','non_error')
SEED_ERROR_CODES = ('none','other','ERR_ASSERTION','ERR_MODULE_NOT_FOUND','MODULE_NOT_FOUND','ERR_DLOPEN_FAILED',
    'ERR_UNKNOWN_FILE_EXTENSION','ERR_INVALID_ARG_TYPE','SQLITE_ERROR','SQLITE_CANTOPEN','SQLITE_READONLY','SQLITE_FULL',
    'SQLITE_BUSY','SQLITE_CORRUPT','EPERM','EACCES','ENOENT','ETIMEDOUT','ENOBUFS','EAGAIN','ENOMEM')


INITIALIZER_CAPTURE_BYTES = 32768
SEED_DIAGNOSTIC_BYTES = 2048
SEED_NODE_FLAGS = ('loader','transform','spawn_eagain','worker_init','uv_thread','go_thread','esbuild_stopped','esbuild_binary')
OWN_PIDS_FILES = ('max','current','peak','events')
OWN_PIDS_COUNTER_MAX = 1000000
SEED_NODE_CLASSES = ('Error','AssertionError','TypeError','RangeError','SyntaxError','ReferenceError',
    'SqliteError','TransformError','TSError','ServiceUnavailableException')
SEED_NODE_CODES = ('ERR_ASSERTION','ERR_MODULE_NOT_FOUND','MODULE_NOT_FOUND','ERR_DLOPEN_FAILED',
    'ERR_UNKNOWN_FILE_EXTENSION','ERR_INVALID_ARG_TYPE','ERR_REQUIRE_ESM','ERR_REQUIRE_CYCLE_MODULE',
    'ERR_PACKAGE_PATH_NOT_EXPORTED','ERR_UNSUPPORTED_DIR_IMPORT','ERR_INVALID_MODULE_SPECIFIER',
    'SQLITE_ERROR','SQLITE_CANTOPEN','SQLITE_READONLY','SQLITE_FULL','SQLITE_BUSY','SQLITE_CORRUPT','EPERM','EACCES','ENOENT',
        'EAGAIN','ENOMEM','ERR_WORKER_INIT_FAILED')
SEED_NODE_FRAME_PATHS = {'fixture_seed':SEED,'fixture_api':API,'fixture_client':CLIENT,
    'fixture_runner':NEW[0],'fixture_tests':NEW[1],'history_init':'server/api/src/llm/history-init.ts',
    'history_runtime':'server/api/src/llm/history-runtime.ts','history_store':'server/api/src/llm/history-store.ts'}


def require(condition, code):
    if not condition:
        raise Refusal(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def closed_json(raw):
    require(len(raw) <= CAP, 'receipt_bound')
    def pairs(entries):
        obj = {}
        for k, v in entries:
            require(k not in obj, 'duplicate_json_key'); obj[k] = v
        return obj
    try:
        return json.loads(raw.decode('utf8'), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refusal('nonfinite_json')))
    except (UnicodeError, ValueError, TypeError):
        raise Refusal('invalid_public_json') from None


def plain(path, exists=True):
    p = Path(path)
    require(p.is_absolute() and str(p) == str(path) and '..' not in p.parts, 'nonliteral_path')
    parts = p.parts if exists else p.parts[:-1]
    current = Path(parts[0])
    for part in parts[1:]:
        current /= part
        require(not stat.S_ISLNK(current.lstat().st_mode), 'linked_path')
    if exists:
        require(p.resolve() == p, 'noncanonical_path')
    return p


def public_read(name):
    require(name in INPUTS or name in NEW or name == LEAF or
            any(name.startswith(t + '/') for t in TREES) and Path(name).suffix in SUFFIXES, 'public_allowlist')
    require(re.fullmatch(r'[A-Za-z0-9_./-]+', name) and not any(p.startswith('.') for p in Path(name).parts), 'public_path')
    path = plain(str(ROOT / name))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd); require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 4*MIB, 'public_bound')
        chunks, size = [], 0
        while size <= 4*MIB:
            part = os.read(fd, min(CAP, 4*MIB+1-size))
            if not part: break
            chunks.append(part); size += len(part)
        after = os.fstat(fd)
        require(size == before.st_size and all(getattr(before,k)==getattr(after,k)
                for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')), 'public_drift')
        return b''.join(chunks)
    finally:
        os.close(fd)


def inventory():
    paths = list(INPUTS) + [LEAF]
    for tree in TREES:
        plain(str(ROOT / tree))
        for directory, dirs, names in os.walk(ROOT / tree, followlinks=False):
            for name in dirs:
                require(not name.startswith('.') and stat.S_ISDIR((Path(directory)/name).lstat().st_mode), 'source_directory')
            for name in names:
                p = Path(directory)/name; rel = p.relative_to(ROOT).as_posix()
                require(not name.startswith('.') and stat.S_ISREG(p.lstat().st_mode), 'source_file')
                if p.suffix in SUFFIXES and rel not in NEW:
                    paths.append(rel);require(len(paths)<=2048,'source_path_bound')
    require(len(paths) == len(set(paths)) == 244, 'source_count')
    data, total = {}, 0
    for p in sorted(paths):
        raw=public_read(p);total+=len(raw);require(total<=32*MIB,'source_total');data[p]=raw
    hashes = {p:sha(b) for p,b in data.items()}
    require(sha(canonical(hashes)) == SNAPSHOT, 'production_snapshot_drift')
    require(hashes[CONFIG] == CONFIG_SHA, 'nginx_base_drift')
    embedded = {p:h for p,h in hashes.items() if p in INPUTS[:6] or p == LEAF or any(p.startswith(t+'/') for t in TREES)}
    require(len(embedded) == 238, 'embedded_count')
    fixtures = {p:public_read(p) for p in NEW}
    return data, hashes, embedded, fixtures


def enabled_config(base):
    require(sha(base) == CONFIG_SHA, 'nginx_base_drift')
    old = b'set $history_ingress_enabled 0;'
    require(base.count(old) == 1 and base.count(b'set $runtime_ingress_enabled 0;') == 1, 'nginx_gate_shape')
    new = base.replace(old,b'set $history_ingress_enabled 1;',1)
    require(new.replace(b'set $history_ingress_enabled 1;',old,1)==base, 'nginx_diff')
    return new


def manifest():
    return {'kind':'history-wire-native-contract-v1','services': {
        role:{'uid':v[0],'gid':v[0],'memory':v[1]*MIB,'memorySwap':v[1]*MIB,'nanoCpus':v[2],
              'pids':v[3],'networks':([] if v[4]=='none' else ['backend','probe'] if role=='web' else [v[4]]),
              'readonlyRootfs':True,'noNewPrivileges':True,'drop':['ALL'],'add':['CHOWN'] if role=='volume-init' else [],
              'tmpfsBytes':16*MIB,'ports':[]} for role,v in SLOTS.items()},
        'networks':{'backend':{'internal':True},'probe':{'internal':True}},'volumes':['auth','scan'],
        'publicEnvironment':ENV,'servingAllowlist':'finalized-generated-A,B-before-bootstrap',
        'mountContract':{'volume-init':['auth:/auth:rw:nocopy','scan:/data:rw:nocopy'],
            'seed':['auth:/auth:rw:nocopy','scan:/data:rw:nocopy',SEED+':ro'],
            'api':['auth:/auth:rw:nocopy','scan:/data:rw:nocopy',SEED+':ro',API+':ro'],
            'web':['new-qualified-enabled-public-config:/etc/nginx/nginx.conf:ro'],'probe':[CLIENT+':ro']},
        'images':{'node':IMAGE,'nginx':NGINX},'baseConfigSha256':CONFIG_SHA,'snapshotSha256':SNAPSHOT,
        'fiveFileWriteSet':NEW,'bounds':{'totalSeconds':TOTAL,'workSeconds':WORK,'cleanupSeconds':TOTAL-WORK,
            'dockerCalls':CALLS,'httpCalls':HTTP,'peakContainers':6,'createdContainerIds':10,
            'commandSeconds':20,'stopSeconds':10,'httpSeconds':5,'captureBytes':CAP,'aggregateBytes':AGGREGATE},
        'authority':'implementation-only; independent-review and new parent-execution approval required',
        'actualLocalModule':True,'actualParentIngress':True,'syntheticTerminalReport':True,
        'syntheticFailedTurn':True,'syntheticReplayPolicy':True,'unchangedProductionMainExecuted':False,
        'providerAttemptProven':False,'wholeAcceptance':False,'liveTouched':False,'hostCapture':False,
        'productionClientAcceptance':False,'quotaFundedGenerationAcceptance':False}


def plan():
    data, hashes, embedded, fixtures = inventory()
    m = manifest(); config = enabled_config(data[CONFIG])
    return {'kind':'history-wire-native-review-candidate','executed':False,'manifest':m,
            'manifestSha256':sha(canonical(m)), 'sourceSnapshotSha256':SNAPSHOT,'sourceFiles':hashes,
            'embeddedFiles':embedded,'fixtureSha256':{p:sha(b) for p,b in fixtures.items()},
            'fixtureFreezeSha256':sha(canonical({p:sha(b) for p,b in fixtures.items()})),
            'baseConfigSha256':CONFIG_SHA,'enabledConfigSha256':sha(config),
            'daemonBindPolicy':{'default':'literal','optIn':POLICY,'context':'desktop-linux','hostPrefix':'/Users/'},
            'executionApproved':False,
            'initializerProbe':{'captureBytes':INITIALIZER_CAPTURE_BYTES,'childTimeoutMs':10000,'failureJsonBytes':SEED_DIAGNOSTIC_BYTES,
                'nodeFlags':SEED_NODE_FLAGS,'cgroupNamespaceRequired':'private','pidsRoot':'/sys/fs/cgroup',
                'pidsFiles':['pids.'+k for k in OWN_PIDS_FILES],'counterSchema':'[present,bounded,value]',
                'counterMax':OWN_PIDS_COUNTER_MAX,'readsBeforeChildAndAfterFailureOnly':True,'hostFallback':False}}


def bind_candidates(source, policy, context):
    require(policy in ('literal',POLICY), 'bind_policy')
    require(context == 'desktop-linux', 'desktop_context')
    require(str(source).startswith('/Users/') and '..' not in Path(source).parts, 'bind_host_path')
    return [str(source)] if policy=='literal' else [str(source),'/host_mnt'+str(source)]


def validate_tool():
    require(DOCKER.is_symlink() and os.readlink(DOCKER) == CLI_LINK, 'docker_link')
    plain(str(CLI_TARGET))
    s = CLI_TARGET.lstat(); require(stat.S_ISREG(s.st_mode) and bool(s.st_mode&0o111), 'docker_target')
    for p in (DOCKER.parent,): plain(str(p))


def approve(args, p):
    require(args.execute and args.parent_execution_authorized, 'new_parent_authority_required')
    require(args.reviewed_fixture_sha256 == p['fixtureFreezeSha256'], 'fixture_not_reviewed')
    require(args.reviewed_source_sha256 == SNAPSHOT, 'source_not_reviewed')
    require(args.reviewed_manifest_sha256 == p['manifestSha256'], 'manifest_not_reviewed')
    require(args.reviewed_config_sha256 == p['enabledConfigSha256'], 'config_not_reviewed')
    require(args.api_image==IMAGE and args.ingress_image==NGINX, 'cached_image_pins_required')
    require(args.docker_host==HOST and args.docker_context=='desktop-linux', 'explicit_desktop_endpoint')
    require(NAME.fullmatch(args.project or ''), 'new_project_name')
    require(args.scratch_dir, 'new_scratch_required')
    scratch = plain(args.scratch_dir,False)
    expected_parent = ROOT.parent/'cve14-proof-workspaces'
    require(scratch.parent==expected_parent and not scratch.exists() and not scratch.is_symlink(), 'new_scratch_only')
    require(re.fullmatch(r'run-20[0-9]{6}-history-wire-r[1-9][0-9]*',scratch.name), 'scratch_name')
    require(scratch.parent.is_dir(), 'scratch_parent')
    bind_candidates(scratch/'nginx.enabled.conf',args.daemon_bind_source_policy,args.docker_context)
    for name in NEW[2:]: bind_candidates(ROOT/name,args.daemon_bind_source_policy,args.docker_context)
    return scratch


def mounts(role, scratch, project):
    leaves = {'seed':[SEED], 'api':[SEED,API], 'probe':[CLIENT], 'web':[], 'volume-init':[]}[role]
    result = [{'type':'bind','source':str(ROOT/p),'target':'/app/'+p,'rw':False} for p in leaves]
    if role=='web': result.append({'type':'bind','source':str(scratch/'nginx.enabled.conf'),'target':'/etc/nginx/nginx.conf','rw':False})
    if role in ('volume-init','seed','api'):
        result += [{'type':'volume','source':project+'-'+v,'target':t,'rw':True} for v,t in [('auth','/auth'),('scan','/data')]]
    return result


def descriptor(role, phase, scratch, project, state=None):
    require(role in SLOTS, 'role'); uid, memory, cpu, pids, net = SLOTS[role]
    image = NGINX if role=='web' else IMAGE
    if role=='web': entry, command, cwd = '/usr/sbin/nginx',['-g','daemon off;','-c','/etc/nginx/nginx.conf'],'/'
    elif role=='volume-init': entry, command, cwd = '/usr/local/bin/node',['-e',INIT_JS],'/app/server/api'
    elif role=='probe': entry, command, cwd = '/usr/local/bin/node',['/app/'+CLIENT,phase],'/app/server/api'
    else: entry, command, cwd = '/usr/local/bin/node',['--import','tsx','src/llm/tests/'+Path(API if role=='api' else SEED).name,phase],'/app/server/api'
    env = dict(ENV) if role in ('seed','api') else {}
    if state: state_guard(state); env['SCAN_BROWSER_ALLOWED_USER_IDS'] = state['owner']+','+state['foreign']
    return {'role':role,'phase':phase,'uid':uid,'image':image,'entry':entry,'command':command,'cwd':cwd,
            'memory':memory*MIB,'cpu':cpu,'pids':pids,'network':net,'env':env,'mounts':mounts(role,scratch,project),
            'tmpfs':f'rw,nosuid,nodev,noexec,size=16777216,mode=1777,uid={uid},gid={uid}'}


def create_argv(d, name, project):
    a = ['container','create','--pull','never','--name',name,'--label',LABEL+'='+project,'--label',RUN_LABEL+'='+project,
         '--user',str(d['uid'])+':'+str(d['uid']),'--read-only','--security-opt','no-new-privileges=true',
         '--cap-drop','ALL','--memory',str(d['memory']),'--memory-swap',str(d['memory']),
         '--cpus',str(d['cpu']/1000000000),'--pids-limit',str(d['pids']),
         '--tmpfs','/tmp:'+d['tmpfs'],'--log-driver','json-file','--log-opt','max-size=1m','--log-opt','max-file=1',
         '--workdir',d['cwd'],'--entrypoint',d['entry'],'--stop-timeout','10']
    if d['role']=='volume-init': a += ['--cap-add','CHOWN']
    a += ['--network','none' if d['network']=='none' else project+'-'+d['network']]
    if d['role']=='api': a += ['--network-alias','api']
    if d['role'] != 'web': a += ['--interactive']
    for k,v in sorted(d['env'].items()): a += ['--env',k+'='+v]
    for m in d['mounts']:
        value = 'type='+m['type']+',source='+m['source']+',target='+m['target']
        value += ',readonly' if not m['rw'] else ',volume-nocopy'
        a += ['--mount',value]
    return a+[d['image']]+d['command']


def own_identity(v, project, name):
    require(type(v['id'])==str and ID.fullmatch(v['id']) and v['name']=='/'+name, 'container_identity')
    require(v['labels'].get(LABEL)==project and v['labels'].get(RUN_LABEL)==project, 'own_labels')


def qualify_container(v, d, project, name, policy, context):
    # Evaluate every fixed predicate on the already captured inspection. These
    # same predicates gate admission; diagnostics cannot silently bypass one.
    checks = []
    def check(label, code, predicate):
        try: passed = bool(predicate())
        except (Refusal, KeyError, TypeError, ValueError, AttributeError): passed = False
        checks.append((label, code, passed))
    check('id', 'container_identity', lambda: type(v['id'])==str and ID.fullmatch(v['id']))
    check('name', 'container_identity', lambda: v['name']=='/'+name)
    check('project_label', 'own_labels', lambda: v['labels'].get(LABEL)==project)
    check('run_label', 'own_labels', lambda: v['labels'].get(RUN_LABEL)==project)
    for key, value in (('image',d['image']),('user',f"{d['uid']}:{d['uid']}"),('entrypoint',[d['entry']]),
                       ('cmd',d['command']),('cwd',d['cwd'])):
        check(key, 'container_program', lambda key=key, value=value: v[key]==value)
    h = v.get('host', {}) if type(v)==dict else {}
    check('readonly', 'root_boundary', lambda: h['ReadonlyRootfs'] is True)
    check('privileged', 'root_boundary', lambda: h['Privileged'] is False)
    if d['role']=='seed': check('cgroup_namespace','seed_cgroup_namespace',lambda: h['CgroupnsMode']=='private')
    check('nnp', 'nnp_boundary', lambda: h['SecurityOpt'] in (['no-new-privileges'],['no-new-privileges=true']))
    check('cap_drop', 'caps_boundary', lambda: h['CapDrop']==['ALL'])
    # Docker may report the originally granted singleton CHOWN as CAP_CHOWN.
    # No prefix normalization, extra capability, or other role addition allowed.
    check('cap_add', 'caps_boundary', lambda: type(h['CapAdd'])==list and h['CapAdd'] in (['CHOWN'],['CAP_CHOWN'])
          if d['role']=='volume-init' else h['CapAdd'] is None or type(h['CapAdd'])==list and h['CapAdd']==[])
    for label, key, value in (('memory','Memory',d['memory']),('memory_swap','MemorySwap',d['memory']),
                              ('cpu','NanoCpus',d['cpu']),('pids','PidsLimit',d['pids'])):
        check(label, 'resource_boundary', lambda key=key, value=value: type(h[key])==int and h[key]==value)
    check('tmpfs', 'tmp_log_boundary', lambda: h['Tmpfs']=={'/tmp':d['tmpfs']})
    check('log', 'tmp_log_boundary', lambda: h['LogConfig']=={'Type':'json-file','Config':{'max-size':'1m','max-file':'1'}})
    for label, key in (('ports','PortBindings'),('publish_all','PublishAllPorts'),('extra_hosts','ExtraHosts'),
                       ('devices','Devices'),('device_requests','DeviceRequests'),('links','Links'),('volumes_from','VolumesFrom')):
        check(label, 'external_boundary', lambda key=key: not h.get(key))
    check('pid', 'namespace_boundary', lambda: h.get('PidMode','')=='')
    check('ipc', 'namespace_boundary', lambda: h.get('IpcMode')=='private')
    check('uts', 'namespace_boundary', lambda: not h.get('UTSMode'))
    check('network_mode', 'network_mode', lambda: h.get('NetworkMode')==('none' if d['network']=='none' else project+'-'+d['network']))
    check('autoremove', 'no_restart', lambda: not h.get('AutoRemove'))
    check('restart', 'no_restart', lambda: h.get('RestartPolicy')=={'Name':'no','MaximumRetryCount':0})
    for label, key in (('sysctls','Sysctls'),('device_rules','DeviceCgroupRules'),('init','Init')):
        check(label, 'extra_authority', lambda key=key: not h.get(key))
    expected_nets = set() if d['network']=='none' else {project+'-'+d['network']}
    if d['role']=='web': expected_nets.add(project+'-probe')
    # Docker records a synthetic none network even though there is no network attachment.
    check('network_set', 'network_boundary', lambda: set(v['networks'])==({'none'} if d['network']=='none' else expected_nets))
    expected = {m['target']:m for m in d['mounts']}
    observed = v.get('mounts') if type(v)==dict else None
    check('mount_count', 'mount_count', lambda: type(observed)==list and len(observed)==len(expected))
    check('mount_dest', 'mount_destination', lambda: all(m['Destination'] in expected for m in observed)
          and len({m['Destination'] for m in observed})==len(observed))
    check('mount_type', 'mount_type_rw', lambda: all(m['Type']==expected[m['Destination']]['type'] for m in observed))
    check('mount_rw', 'mount_type_rw', lambda: all(m['RW'] is expected[m['Destination']]['rw'] for m in observed))
    check('volume_name', 'volume_identity', lambda: all(m['Name']==expected[m['Destination']]['source'] for m in observed
          if expected[m['Destination']]['type']=='volume'))
    check('bind_source', 'bind_source', lambda: all(sum(m['Source']==x for x in bind_candidates(expected[m['Destination']]['source'],policy,context))==1
          for m in observed if expected[m['Destination']]['type']=='bind'))
    check('mount_missing', 'mount_missing', lambda: {m['Destination'] for m in observed}==set(expected))
    check('state', 'container_state', lambda: v['state']['Status'] in ('created','running','exited'))
    check('oom', 'container_state', lambda: not v['state'].get('OOMKilled'))
    failed = [label for label, _, passed in checks if not passed]
    if failed:
        diagnostics = {'failed':failed,'checked':len(checks),'rawValuesIncluded':False}
        require(len(canonical(diagnostics))<=1024, 'runtime_diagnostic_bound')
        raise RuntimeQualifierRefusal(next(code for _, code, passed in checks if not passed), diagnostics)
    representations = {m['Destination']:('literal' if m['Source']==expected[m['Destination']]['source'] else 'desktop_host_mnt')
                       for m in observed if m['Type']=='bind'}
    return {'qualified':True,'role':d['role'],'phase':d['phase'],'representations':representations,
            'readonlyRootfs':True,'noNewPrivileges':True,'noPorts':True,'exactNetworks':True,'exactMounts':True}


def state_guard(s):
    keys = {'owner','foreign','scanId','epoch','turnId','mutationId','decisionId','digest','platform','reportVersion',
            'consentPolicyVersion','incarnation','fingerprintDigest','reportDigest','accessIncarnation','historyInode','historyDevice'}
    require(type(s)==dict and set(s)==keys,'state_schema')
    for k in ('owner','foreign','accessIncarnation'): require(type(s[k])==str and re.fullmatch('[a-f0-9]{32}',s[k]),'state_id')
    for k in ('scanId','epoch','turnId','mutationId','decisionId','incarnation'): require(type(s[k])==str and UUID.fullmatch(s[k]),'state_uuid')
    for k in ('reportVersion','consentPolicyVersion','fingerprintDigest','reportDigest'): require(type(s[k])==str and HEX.fullmatch(s[k]),'state_hash')
    require(type(s['digest'])==str and re.fullmatch('sha256:[a-f0-9]{64}',s['digest']) and s['platform']=='linux/amd64','state_binding')
    require(s['owner']!=s['foreign'],'state_owners')
    for k in ('historyInode','historyDevice'): require(type(s[k])==int and 0<=s[k]<=2**53-1,'state_inode')


def empty_node_diagnostic():
    return {'class':'none','code':'none','frame':None,'flags':dict.fromkeys(SEED_NODE_FLAGS,False)}


def pids_probe(value, phase, step, children):
    if value is None: return
    require(type(value)==dict and set(value)=={'kind','before','after'},'seed_pids_schema')
    require(phase=='setup' and type(value['kind'])==str and value['kind'] in ('initialize','existing_refusal'),'seed_pids_phase')
    require(step.startswith('initialize_' if value['kind']=='initialize' else 'existing_') and
            (len(children)<=1 if value['kind']=='initialize' else 1<=len(children)<=2),'seed_pids_step')
    for sample in (value['before'],value['after']):
        require(type(sample)==dict and set(sample)==set(OWN_PIDS_FILES),'seed_pids_sample')
        for key,row in sample.items():
            require(type(row)==list and len(row)==3 and type(row[0])==bool and type(row[1])==bool,'seed_pids_counter')
            if not row[1]: require(row[2] is None,'seed_pids_unbounded')
            else:
                require(row[0] is True and (type(row[2])==int and 0<=row[2]<=OWN_PIDS_COUNTER_MAX or
                        key=='max' and type(row[2])==str and row[2]=='max'),'seed_pids_value')
            require(row[0] or row[1] is False and row[2] is None,'seed_pids_presence')


def receipt(raw, kind, phase=None):
    v=closed_json(raw.strip()); require(type(v)==dict and v.get('kind')==kind,'receipt_kind')
    if kind=='history-wire-volume-init': require(canonical(v)==canonical({'kind':kind,'prepared':True}),'init_receipt')
    elif kind=='history-wire-seed-refusal':
        require(len(raw)<=SEED_DIAGNOSTIC_BYTES+1 and len(canonical(v))<=SEED_DIAGNOSTIC_BYTES,'seed_diagnostic_bound')
        require(set(v)=={'kind','passed','phase','step','errorClass','errorCode','initializers','initializerPids','cleanupFailed','rawValuesIncluded'},'seed_diagnostic_schema')
        require(v['passed'] is False and v['rawValuesIncluded'] is False and type(v['cleanupFailed'])==bool,'seed_diagnostic_flags')
        require(type(v['phase'])==str and v['phase'] in ('entry',phase) and phase in ('setup','audit'),'seed_diagnostic_phase')
        steps=SEED_ENTRY_STEPS if v['phase']=='entry' else SEED_COMMON_STEPS+(SEED_SETUP_STEPS if phase=='setup' else SEED_AUDIT_STEPS)
        require(type(v['step'])==str and v['step'] in steps,'seed_diagnostic_step')
        require(type(v['errorClass'])==str and v['errorClass'] in SEED_ERROR_CLASSES and
                type(v['errorCode'])==str and v['errorCode'] in SEED_ERROR_CODES,'seed_diagnostic_error')
        children=v['initializers'];require(type(children)==list and len(children)<=2,'seed_initializer_count')
        require(not children or v['phase']=='setup','seed_initializer_phase')
        flags=('stdoutExpectedMatch','stderrExpectedMatch','stdoutEmpty','stderrEmpty','stdoutBounded','stderrBounded')
        for i,row in enumerate(children):
            require(type(row)==dict and set(row)=={'kind','exit','signal','error','node',*flags},'seed_initializer_schema')
            require(row['kind']==('initialize' if i==0 else 'existing_refusal') and type(row['exit'])==str and
                    row['exit'] in ('zero','one','other','none','invalid') and type(row['signal'])==str and
                    row['signal'] in ('none','sigterm','sigkill','other') and type(row['error'])==str and
                    row['error'] in ('none','ETIMEDOUT','ENOBUFS','EPERM','EACCES','ENOENT','EAGAIN','ENOMEM','other'),'seed_initializer_enum')
            require(all(type(row[k])==bool for k in flags),'seed_initializer_flags')
            node=row['node'];require(type(node)==dict and set(node)=={'class','code','frame','flags'},'seed_node_schema')
            require(type(node['class'])==str and node['class'] in SEED_NODE_CLASSES+('none','ambiguous') and
                    type(node['code'])==str and node['code'] in SEED_NODE_CODES+('none','ambiguous'),'seed_node_enum')
            require(type(node['flags'])==dict and set(node['flags'])==set(SEED_NODE_FLAGS) and
                    all(type(flag)==bool for flag in node['flags'].values()),'seed_node_flags')
            frame=node['frame']
            if frame is not None:
                require(type(frame)==list and len(frame)==2 and type(frame[0])==str and frame[0] in SEED_NODE_FRAME_PATHS and
                        type(frame[1])==int and 1<=frame[1]<=4096,'seed_node_frame')
                require(frame[1]<=len(public_read(SEED_NODE_FRAME_PATHS[frame[0]]).decode('utf8').splitlines()),'seed_node_source_line')
            if not row['stderrBounded'] or row['stderrEmpty'] or row['stderrExpectedMatch']:
                require(canonical(node)==canonical(empty_node_diagnostic()),'seed_node_consistency')
            for stream in ('stdout','stderr'):
                require(not row[stream+'Empty'] or row[stream+'Bounded'],'seed_initializer_consistency')
                if row[stream+'ExpectedMatch']:
                    empty=(stream=='stderr') if i==0 else (stream=='stdout')
                    require(row[stream+'Bounded'] and row[stream+'Empty'] is empty,'seed_initializer_consistency')
        pids_probe(v['initializerPids'],v['phase'],v['step'],children)
    elif kind=='history-wire-setup':
        flags=('missingHistoryRefused','initializerSucceeded','existingInitializerRefusedUnchanged','embeddedSourceQualified',
               'syntheticTerminalReport','syntheticFailedTurn','quotaAbsent','mountedFixtureBytesQualified','fullSynchronous')
        require(set(v)=={'kind','state','revisions',*flags} and all(v[k] is True for k in flags) and canonical(v['revisions'])==b'[0,1,2]','setup_receipt')
        state_guard(v['state'])
    elif kind=='history-wire-audit':
        fixed={'kind':kind,'preserved':True,'mountedFixtureBytesQualified':True,'revision':3,'turns':1,'decisions':1,'quotaAbsent':True,'pendingAbsent':True,
               'fingerprintsPreserved':True,'incarnationAndInodePreserved':True,'originalRequestPreserved':True,
               'reportAndDecisionSourcesPreserved':True,'schema':3,'application':1145655602,'pageSize':4096,
               'deleteJournal':True,'fullSynchronous':True,'privateRegularFile':True,'nonalias':True,'headroom':True}
        require(canonical(v)==canonical(fixed),'audit_receipt')
    elif kind=='history-wire-api-final':
        require(canonical(v)==canonical({'kind':kind,'phase':phase,'closed':True,'providerLookups':0,'providerFault':False,'quotaAbsent':True}),'final_receipt')
    elif kind=='history-wire-api-ready':
        flags=('localSingleton','authSingleton','runtimeSingleton','controllersUnique','runtimeStoreAbsent','runtimeLiveAbsent',
               'rawIntakeConfigured','embeddedSourceQualified','mountedFixtureBytesQualified','fullSynchronous','quotaAbsent')
        require(set(v)=={'kind','phase','providerLookups','providerFault','unchangedProductionMainExecuted','syntheticReplayPolicy',*flags}
                and v['phase']==phase and all(v[k] is True for k in flags) and type(v['providerLookups'])==int and v['providerLookups']==0
                and v['providerFault'] is False and v['unchangedProductionMainExecuted'] is False
                and v['syntheticReplayPolicy'] is (phase=='replay'),'ready_receipt')
    elif kind=='history-wire-probe':
        require(set(v)=={'kind','phase','passed','httpCalls','capturedBytes','vectors','frame','originalRevision','currentRevision',
                         'noPrivateFingerprintDisclosure','mountedFixtureBytesQualified','productionClientAcceptance','wholeAcceptance'},'probe_schema')
        require(v['phase']==phase and v['passed'] is True and v['originalRevision']==0 and v['currentRevision']==3
                and v['noPrivateFingerprintDisclosure'] is True and v['productionClientAcceptance'] is False
                and v['wholeAcceptance'] is False and v['mountedFixtureBytesQualified'] is True,'probe_flags')
        require(type(v['httpCalls'])==int and 0<v['httpCalls']<=HTTP and type(v['capturedBytes'])==int and 0<=v['capturedBytes']<=AGGREGATE,'probe_bound')
        require(type(v['vectors'])==list and len(v['vectors'])<=HTTP,'vector_bound')
        for row in v['vectors']:
            require(type(row)==dict and set(row)=={'id','status','bytes','category'} and row['id'] in VECTOR_IDS,'vector_schema')
            require(type(row['status'])==int and (100<=row['status']<=599 or row['status']==0 and row['category']=='connection-closed' and
                                row['id'] in {s+'-'+k for s in ('chat','decision') for k in ('chunked','gzip','expect','utf8','json')}) and type(row['bytes'])==int and 0<=row['bytes']<=524288
                    and row['category'] in ('success','refusal','connection-closed'),'vector_value')
        require(len({r['id'] for r in v['vectors']})==len(v['vectors']),'vector_unique')
        if phase=='replay':
            require({r['id'] for r in v['vectors']} >= MATRIX_IDS | {'ndjson-original','json-original','ndjson-8192','head-control'},'matrix_incomplete')
            f=v['frame']; require(type(f)==dict and set(f)=={'frameCount','bytes','sha256','fatalUtf8','exactKeys','lf','cleanEof','statusOnly'} and
                    f['frameCount']==1 and type(f['bytes'])==int and 0<f['bytes']<=8192 and HEX.fullmatch(f['sha256']) and
                    all(f[k] is True for k in ('fatalUtf8','exactKeys','lf','cleanEof','statusOnly')),'frame_receipt')
        else: require(v['frame'] is None,'disabled_frame')
    else: raise Refusal('unknown_receipt')
    return v


def seed_outcome(raw, command_exit, state, phase, diagnostic=None):
    # Called only after the OWN seed's full runtime qualification. Never adopt
    # a failure packet as a successful setup/audit or parse raw runtime errors.
    if diagnostic is not None: diagnostic.boundary='qualifier'
    try:
        gate=privacy(raw);require(gate['bounded'] and gate['reflectionAbsent'],'oneshot_reflection')
        require(type(command_exit)==int and type(state.get('ExitCode'))==int and state.get('Status')=='exited','oneshot_clean_exit')
        if command_exit==0:
            require(state['ExitCode']==0,'oneshot_clean_exit')
            if diagnostic is not None: diagnostic.boundary='public_decode'
            value=receipt(raw,'history-wire-setup' if phase=='setup' else 'history-wire-audit',phase)
            if diagnostic is not None: diagnostic.qualified()
            return value
        require(command_exit==1 and state['ExitCode']==1,'isolated_command_failed')
        if diagnostic is not None: diagnostic.boundary='public_decode'
        try: diagnostics=receipt(raw,'history-wire-seed-refusal',phase)
        except Refusal: raise Refusal('seed_refusal_receipt_refused') from None
        if diagnostic is not None:
            diagnostic.qualified();diagnostic.boundary='qualifier'
        raise SeedDiagnosticRefusal(diagnostics)
    except (Refusal,OSError,ValueError,KeyError,TypeError,UnicodeError,subprocess.SubprocessError) as error:
        if diagnostic is not None and not diagnostic.event_recorded:
            if not isinstance(error,SeedDiagnosticRefusal):diagnostic.state['responseQualified']=False
            diagnostic.record(diagnostic.boundary,'decode_refusal' if diagnostic.boundary=='public_decode' else 'qualifier_refusal',error)
        raise


MATRIX_IDS = ({f'{s}-alias-{i}' for s in ('chat','decision') for i in range(9)} |
              {s+'-'+v for s in ('chat','decision') for v in ('anonymous','authorization','origin-missing','origin-foreign','origin-duplicate','cookie-duplicate','8193','chunked','gzip','expect','utf8','json')} |
              {'read-'+e+'-'+v for e in ('history','chat-context','chat-usage') for v in ('anonymous','foreign')} |
              {'method-'+e for e in ('history','chat-context','chat-usage','chat')} |
              {'read-missing','auth-empty-observation','auth-duplicate','consent-omitted','consent-false','owner-extra',
               'decision-conflict-text','decision-stale','decision-foreign-finding','accept-0','accept-1',
               'runtime-excluded','jwt-scans-excluded','auth-513','summary-1025'} |
              {'chat-conflict-'+k for k in ('policy','report','question','revision','epoch')})
VECTOR_IDS = MATRIX_IDS | {'readiness-'+str(i) for i in range(4)} | {'login-0','login-1','chat-context','chat-usage',
             'actual-decision','decision-duplicate','decision-changed','ndjson-original','json-original','ndjson-8192','head-control'}


def privacy(raw):
    tokens=(b'CANARY-history-wire-public',b'demo_session=',b'history-wire-public-password-',
            b'Bearer fixture-denied',b'fixture-provider-tripwire')
    return {'bounded':len(raw)<=CAP,'reflectionAbsent':not any(t in raw for t in tokens),'rawLogsPublished':False}


DIAGNOSTIC_OPERATIONS = ('inspect_two_images','desktop_info','label_collision_containers',
    'label_collision_networks','label_collision_volumes','name_collision_containers',
    'name_collision_networks','name_collision_volumes','create_volume_auth','create_volume_scan',
    'inspect_two_volumes','create_network_backend','create_network_probe','inspect_two_networks',
    'cleanup_discovery','cleanup_qualification','cleanup_stop','cleanup_retention','local_supervision','unknown')
DIAGNOSTIC_BOUNDARIES = ('before_spawn','spawn','capture_setup','stdin','drain','cli_exit',
    'public_decode','qualifier','supervision','unknown')
DIAGNOSTIC_REASONS = ('call_budget','work_deadline','command_deadline','stdin_bound','stdin_closed',
    'capture_per_call_bound','capture_aggregate_bound','cli_nonzero','spawn_error','capture_setup_error',
    'decode_refusal','qualifier_refusal','supervision_error','reporting_refusal','unknown')
DIAGNOSTIC_CLASSES = ('os_error','broken_pipe','value_error','key_error','type_error','unicode_error',
    'subprocess_error','selector_error','none','other','unavailable')
DIAGNOSTIC_ERRNOS = ('permission_denied','operation_not_permitted','connection_refused','no_such_file',
    'resource_temporarily_unavailable','no_buffer_space','none','other','unavailable')
DIAGNOSTIC_RECORD_KEYS = {'operation','boundary','reason','attemptOrdinal','ordinalState','spawned',
    'exitKind','exitValue','exceptionClass','errno','mergedBytes','mergedBytesState','captureComplete',
    'perCallBoundHit','aggregateBoundHit','deadlineHit','stdinState'}
DIAGNOSTIC_LOCAL_KEYS = ('childCreated','captureRegistered','captureSetupComplete','directChildReaped',
    'pipesClosed','selectorClosed','processGroupAbsent')
DIAGNOSTIC_FALLBACK = b'{"primaryUnavailable":true,"rawValuesIncluded":false,"recordsPartial":true,"reportingRefused":true,"rootCauseEstablished":false,"v":1}'


class FailureMetadata:
    """Observed bookkeeping only. Frozen JSON bytes cannot retain raw/mutable references."""
    def __init__(self):
        self.primary = None; self.secondary = None; self.secondary_state = 'none'
        self.partial = False; self.saved_state = None; self.saved_local = None
        self.begin('unknown',False,None)
    def begin(self, operation, mutating, ordinal):
        self.operation = operation if type(operation)==str and operation in DIAGNOSTIC_OPERATIONS else 'unknown'
        self.mutating = mutating is True
        self.ordinal = ordinal if type(ordinal)==int and 1<=ordinal<=81 else None
        self.ordinal_state = 'within_configured_budget' if self.ordinal is not None else 'unavailable'
        self.state = {'attempted':True,'spawned':False,'cliCompleted':None,'responseQualified':None,
                      'mutationDisposition':'unavailable' if self.mutating else 'not_applicable'}
        self.local = dict.fromkeys(DIAGNOSTIC_LOCAL_KEYS)
        self.local.update(childCreated=False,captureRegistered=False,captureSetupComplete=False)
        self.boundary = 'before_spawn'; self.stdin = 'not_started'; self.exit = None; self.event_recorded = False
        self.size = None; self.complete = None; self.per_call = None; self.aggregate = None; self.deadline = None
    def qualified(self):
        self.state['responseQualified'] = True
        if self.mutating: self.state['mutationDisposition'] = 'qualified_record'
    def observe_capture(self, capture):
        # No poll/probe here: use only return/EOF/accounting already observed by the caller.
        self.size = len(capture.raw)
        self.exit = capture.observed_exit
        self.complete = capture.complete
        if capture.observed_exit is not None:
            self.state['cliCompleted'] = True; self.local['directChildReaped'] = True
        self.per_call = self.size>CAP; self.aggregate = capture.budget.aggregate>AGGREGATE
    def record(self, boundary, reason, error=None, secondary=False, operation=None):
        cls, number = 'none', 'none'
        trusted_os = (OSError,BrokenPipeError,PermissionError,FileNotFoundError,ProcessLookupError,
                      ConnectionRefusedError,BlockingIOError,TimeoutError,InterruptedError)
        if error is not None:
            t = type(error); cls, number = 'other', 'unavailable'
            if any(t is kind for kind in trusted_os):
                cls = 'broken_pipe' if t is BrokenPipeError else 'os_error'
                value = OSError.errno.__get__(error)
                number = 'none' if value is None else 'unavailable' if type(value) is not int else {
                    errno.EACCES:'permission_denied',errno.EPERM:'operation_not_permitted',
                    errno.ECONNREFUSED:'connection_refused',errno.ENOENT:'no_such_file',
                    errno.EAGAIN:'resource_temporarily_unavailable',errno.ENOBUFS:'no_buffer_space'}.get(value,'other')
            elif any(t is kind for kind in (ValueError,KeyError,TypeError,UnicodeError,UnicodeDecodeError,UnicodeEncodeError,
                       subprocess.SubprocessError,subprocess.TimeoutExpired,subprocess.CalledProcessError)):
                cls = {ValueError:'value_error',KeyError:'key_error',TypeError:'type_error',
                       UnicodeError:'unicode_error',UnicodeDecodeError:'unicode_error',UnicodeEncodeError:'unicode_error',
                       subprocess.SubprocessError:'subprocess_error',subprocess.TimeoutExpired:'subprocess_error',
                       subprocess.CalledProcessError:'subprocess_error'}[t]; number = 'none'
            elif any(t is kind for kind in (Refusal,RuntimeQualifierRefusal,SeedDiagnosticRefusal)):
                cls, number = 'other', 'unavailable'
        exit_value = self.exit if type(self.exit)==int and -255<=self.exit<=255 else None
        exit_kind = ('unavailable' if self.exit is None else 'other' if exit_value is None else
                     'zero' if exit_value==0 else 'signaled' if exit_value<0 else 'nonzero')
        size = self.size if type(self.size)==int and 0<=self.size<=CAP else None
        record = {'operation':self.operation if operation is None else operation,'boundary':boundary,'reason':reason,
            'attemptOrdinal':self.ordinal,'ordinalState':self.ordinal_state,'spawned':self.state['spawned'],
            'exitKind':exit_kind,'exitValue':exit_value,'exceptionClass':cls,'errno':number,
            'mergedBytes':size,'mergedBytesState':'unavailable' if self.size is None else 'exact' if size is not None else 'exceeded',
            'captureComplete':self.complete,'perCallBoundHit':self.per_call,'aggregateBoundHit':self.aggregate,
            'deadlineHit':self.deadline,'stdinState':self.stdin}
        self.partial = True; self.event_recorded = True
        raw = canonical(record)
        if self.primary is None and not secondary:
            self.primary = raw; self.saved_state = canonical(self.state); self.saved_local = canonical(self.local)
        elif self.secondary is None:
            self.secondary = raw; self.secondary_state = 'one_observed'
        else: self.secondary_state = 'more_observed'
    def freeze_context(self):
        # Finite observations only; no capture, exception or mutable raw references.
        keys=('operation','mutating','ordinal','ordinal_state','state','local','stdin','boundary',
              'exit','size','complete','per_call','aggregate','deadline')
        return canonical({key:getattr(self,key) for key in keys})
    def restore_context(self, raw):
        value=json.loads(raw)
        keys={'operation','mutating','ordinal','ordinal_state','state','local','stdin','boundary',
              'exit','size','complete','per_call','aggregate','deadline'}
        require(type(value)==dict and set(value)==keys,'diagnostic_context')
        for key in keys:setattr(self,key,value[key])
        # Receipt interpretation is a new event, not propagation of the CLI refusal.
        self.event_recorded=False
    def encode(self):
        if self.primary is None:
            self.partial=True;return DIAGNOSTIC_FALLBACK
        try:
            value = {'v':1,'primary':json.loads(self.primary) if self.primary is not None else None,
                'secondary':json.loads(self.secondary) if self.secondary is not None else None,
                'secondaryState':self.secondary_state,
                'operationState':json.loads(self.saved_state) if self.saved_state is not None else self.state,
                'localSupervision':json.loads(self.saved_local) if self.saved_local is not None else self.local,
                'recordsPartial':self.partial or self.primary is None,'rootCauseEstablished':False,'rawValuesIncluded':False}
            self.validate(value); raw = canonical(value)
            require(len(raw)<=2048,'diagnostic_bound')
            return raw
        except (Refusal,ValueError,TypeError,KeyError,UnicodeError):
            self.partial = True
            return DIAGNOSTIC_FALLBACK
    @staticmethod
    def validate(v):
        require(type(v)==dict and set(v)=={'v','primary','secondary','secondaryState','operationState',
            'localSupervision','recordsPartial','rootCauseEstablished','rawValuesIncluded'},'diagnostic_schema')
        require(type(v['v'])==int and v['v']==1 and v['rootCauseEstablished'] is False and
            v['rawValuesIncluded'] is False and type(v['recordsPartial'])==bool,'diagnostic_flags')
        require(type(v['secondaryState'])==str and v['secondaryState'] in ('none','one_observed','more_observed','unavailable'),'diagnostic_secondary')
        require((v['secondary'] is None)==(v['secondaryState'] in ('none','unavailable')),'diagnostic_secondary')
        require(v['primary'] is not None or v['recordsPartial'] is True and type(v['secondary'])==dict and
                    v['secondary'].get('reason')=='reporting_refusal','diagnostic_primary')
        for row in (v['primary'],v['secondary']):
            if row is None: continue
            require(type(row)==dict and set(row)==DIAGNOSTIC_RECORD_KEYS,'diagnostic_record')
            domains = {'operation':DIAGNOSTIC_OPERATIONS,'boundary':DIAGNOSTIC_BOUNDARIES,'reason':DIAGNOSTIC_REASONS,
                'ordinalState':('within_configured_budget','rejected_budget','unavailable'),
                'exitKind':('zero','nonzero','signaled','other','unavailable'),'exceptionClass':DIAGNOSTIC_CLASSES,
                'errno':DIAGNOSTIC_ERRNOS,'mergedBytesState':('exact','exceeded','unavailable'),
                'stdinState':('not_started','closed_normally','closed_error','timeout','unavailable')}
            require(all(type(row[k])==str and row[k] in domain for k,domain in domains.items()),'diagnostic_enum')
            for k,lo,hi in (('attemptOrdinal',1,81),('exitValue',-255,255),('mergedBytes',0,CAP)):
                require(row[k] is None or type(row[k])==int and lo<=row[k]<=hi,'diagnostic_integer')
            require(all(row[k] is None or type(row[k])==bool for k in ('spawned','captureComplete',
                'perCallBoundHit','aggregateBoundHit','deadlineHit')),'diagnostic_boolean')
            require((row['attemptOrdinal'] is None)==(row['ordinalState']=='unavailable'),'diagnostic_ordinal')
            require((row['mergedBytes'] is not None)==(row['mergedBytesState']=='exact'),'diagnostic_capture')
            require(row['mergedBytesState']!='exceeded' or row['perCallBoundHit'] is True and
                row['captureComplete'] is not True,'diagnostic_capture')
            require((row['exitValue'] is None)==(row['exitKind'] in ('other','unavailable')),'diagnostic_exit')
            if row['exitValue'] is not None:
                require(row['exitKind']==('zero' if row['exitValue']==0 else 'signaled' if row['exitValue']<0 else 'nonzero'),'diagnostic_exit')
            require(row['captureComplete'] is not True or row['mergedBytesState']=='exact' and
                row['perCallBoundHit'] is False and row['aggregateBoundHit'] is False and row['exitKind']!='unavailable','diagnostic_complete')
            require(row['exitKind']=='unavailable' or row['spawned'] is True,'diagnostic_exit_spawn')
            require(row['reason']!='cli_nonzero' or row['boundary']=='cli_exit' and row['spawned'] is True and
                row['exitKind'] in ('nonzero','signaled','other'),'diagnostic_cli_failure')
            require(row['reason']!='call_budget' or row['boundary']=='before_spawn' and row['spawned'] is False and
                row['ordinalState'] in ('rejected_budget','unavailable') and row['exitKind']=='unavailable','diagnostic_budget')
        state, local = v['operationState'], v['localSupervision']
        require(type(state)==dict and set(state)=={'attempted','spawned','cliCompleted','responseQualified','mutationDisposition'},'diagnostic_state')
        require(all(state[k] is None or type(state[k])==bool for k in ('attempted','spawned','cliCompleted','responseQualified')),'diagnostic_state')
        require(type(state['mutationDisposition'])==str and state['mutationDisposition'] in (
            'not_applicable','possible','qualified_record','unavailable'),'diagnostic_mutation')
        require(state['mutationDisposition']!='qualified_record' or state['responseQualified'] is True and
                    state['spawned'] is True and state['cliCompleted'] is True,'diagnostic_mutation')
        require(type(local)==dict and set(local)==set(DIAGNOSTIC_LOCAL_KEYS) and
            all(x is None or type(x)==bool for x in local.values()),'diagnostic_supervision')
        if v['primary'] is not None:
            require(v['primary']['spawned'] is state['spawned'],'diagnostic_spawn')
            require(v['primary']['exitValue'] is None or state['cliCompleted'] is True,'diagnostic_exit')
        require(state['spawned'] is not True or local['childCreated'] is True,'diagnostic_spawn')
        require(state['spawned'] is not False or state['cliCompleted'] is not True and
            state['responseQualified'] is not True and local['childCreated'] is not True and
            local['captureRegistered'] is not True and local['captureSetupComplete'] is not True and
            local['directChildReaped'] is not True,'diagnostic_unspawned')
        require(local['childCreated'] is not False or state['cliCompleted'] is not True and
            local['directChildReaped'] is not True and local['captureRegistered'] is not True and
            local['captureSetupComplete'] is not True,'diagnostic_uncreated')
        require(state['cliCompleted'] is not True or state['spawned'] is True and local['childCreated'] is True and
            local['directChildReaped'] is True,'diagnostic_completed_child')
        require(local['directChildReaped'] is not True or state['spawned'] is True and
            local['childCreated'] is True and state['cliCompleted'] is True,'diagnostic_reaped_child')
        require(local['captureSetupComplete'] is not True or local['captureRegistered'] is True and
            state['spawned'] is True and local['childCreated'] is True,'diagnostic_capture_setup')
        require(local['captureRegistered'] is not True or local['captureSetupComplete'] is True and
            state['spawned'] is True and local['childCreated'] is True,'diagnostic_capture_registered')
        require(state['responseQualified'] is not True or state['cliCompleted'] is True,'diagnostic_qualified_response')
        if v['primary'] is not None and v['primary']['captureComplete'] is True:
            require(state['cliCompleted'] is True and local['captureRegistered'] is True and
                local['captureSetupComplete'] is True,'diagnostic_capture_complete')
        require(not (state['responseQualified'] is not True or state['mutationDisposition'] in ('possible','unavailable')) or
            v['recordsPartial'] is True,'diagnostic_partial')
        require(len(canonical(v))<=2048,'diagnostic_bound')


class Capture:
    def __init__(self, proc, budget, deadline):
        self.proc,self.budget,self.deadline=proc,budget,deadline
        self.observed_exit=None; self.complete=False
        d=budget.diagnostic
        self.context={k:getattr(d,k) for k in ('operation','mutating','ordinal','ordinal_state','state','local','stdin')}
        self.selector=selectors.DefaultSelector(); self.raw=bytearray()
        os.set_blocking(proc.stdout.fileno(),False); self.selector.register(proc.stdout,selectors.EVENT_READ)
    def activate_metadata(self):
        if hasattr(self,'context'):
            d=self.budget.diagnostic
            for k,value in self.context.items():setattr(d,k,value)
            d.boundary='drain';d.deadline=None
            d.observe_capture(self)
    def pump(self, seconds=0):
        for key,_ in self.selector.select(seconds):
            part=os.read(key.fileobj.fileno(),4096)
            if part:
                self.budget.aggregate+=len(part); self.raw.extend(part)
                self.budget.diagnostic.observe_capture(self)
                if len(self.raw)>CAP or self.budget.aggregate>AGGREGATE:
                    self.budget.diagnostic.record('drain','capture_per_call_bound' if len(self.raw)>CAP else 'capture_aggregate_bound')
                require(len(self.raw)<=CAP and self.budget.aggregate<=AGGREGATE,'capture_bound')
            else: self.selector.unregister(key.fileobj)
    def wait_exit(self):
        self.activate_metadata()
        while True:
            status=self.proc.poll()
            if type(status)==int:
                self.observed_exit=status
                if hasattr(self,'budget'):self.budget.diagnostic.observe_capture(self)
            if status is not None and not self.selector.get_map():break
            if time.monotonic()>=self.deadline:
                if hasattr(self,'budget'):
                    self.budget.diagnostic.observe_capture(self); self.budget.diagnostic.deadline=True
                    self.budget.diagnostic.record('drain','command_deadline')
                raise Refusal('command_deadline')
            self.pump(.025)
        require(type(self.proc.returncode)==int,'command_exit_shape')
        self.observed_exit=self.proc.returncode; self.complete=True
        if hasattr(self,'budget'): self.budget.diagnostic.observe_capture(self)
        return bytes(self.raw),self.proc.returncode
    def wait(self):
        raw,exit_code=self.wait_exit()
        if exit_code!=0 and hasattr(self,'budget'):
            self.budget.diagnostic.record('cli_exit','cli_nonzero')
        require(exit_code==0,'isolated_command_failed'); return raw
    def kill(self):
        self.activate_metadata()
        status=self.proc.poll()
        if type(status)==int:
            self.observed_exit=status
            if hasattr(self,'budget'):self.budget.diagnostic.observe_capture(self)
        if status is None:
            try: os.killpg(self.proc.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            status=self.proc.wait(timeout=2)
            if type(status)==int:self.observed_exit=status
            self.budget.diagnostic.observe_capture(self)
            self.budget.diagnostic.local['directChildReaped']=True
        self.selector.close()
        if hasattr(self,'budget'): self.budget.diagnostic.local['selectorClosed']=True


class Runner:
    def __init__(self,args,scratch,started=None):
        self.args,self.scratch=args,scratch; self.started=time.monotonic() if started is None else started;self.calls=0;self.aggregate=0
        self.cleanup=False;self.captures=[];self.diagnostic=FailureMetadata();self.seed_context=None
    def remaining(self):
        return self.started+(TOTAL if self.cleanup else WORK)-time.monotonic()
    def start(self,a,input_bytes=b'',persistent=False,operation='unknown',mutating=False):
        self.diagnostic.begin(operation,mutating,None)
        require(type(a)==list and a and a[0] in {'info','image','container','network','volume'},'docker_command_family')
        self.calls+=1;self.diagnostic.begin(operation,mutating,self.calls)
        if self.calls>(CALLS if self.cleanup else CALLS-15):
            if self.diagnostic.ordinal is not None:self.diagnostic.ordinal_state='rejected_budget'
            self.diagnostic.record('before_spawn','call_budget');raise Refusal('docker_budget')
        left=self.remaining()
        if left<=0:
            self.diagnostic.deadline=True;self.diagnostic.record('before_spawn','work_deadline');raise Refusal('work_deadline')
        if len(input_bytes)>CAP:
            self.diagnostic.record('before_spawn','stdin_bound');raise Refusal('stdin_bound')
        env={'PATH':'/opt/homebrew/bin:/usr/bin:/bin','HOME':str(self.scratch/'public-home'),
             'DOCKER_CONFIG':str(self.scratch/'public-docker-config'),'LANG':'C','LC_ALL':'C'}
        cmd=[str(DOCKER),'--config',env['DOCKER_CONFIG'],'--host',HOST]+a
        self.diagnostic.boundary='spawn'
        self.diagnostic.state['spawned']=None;self.diagnostic.local['childCreated']=None
        try:
            proc=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                                  env=env,cwd=ROOT,start_new_session=True)
        except (OSError,ValueError,TypeError,subprocess.SubprocessError) as error:
            self.diagnostic.state['spawned']=None;self.diagnostic.local['childCreated']=None
            self.diagnostic.record('spawn','spawn_error',error);raise
        self.diagnostic.state['spawned']=True;self.diagnostic.local['childCreated']=True
        if mutating:self.diagnostic.state['mutationDisposition']='possible'
        self.diagnostic.boundary='capture_setup'
        try: capture=Capture(proc,self,time.monotonic()+(left if persistent else min(20,left)))
        except (Refusal,OSError,ValueError,KeyError,TypeError,UnicodeError,subprocess.SubprocessError) as error:
            self.diagnostic.record('capture_setup','capture_setup_error',error);raise
        self.captures.append(capture)
        self.diagnostic.local.update(captureRegistered=True,captureSetupComplete=True)
        self.diagnostic.boundary='stdin';self.diagnostic.stdin='unavailable';capture.context['stdin']='unavailable'
        try:
            os.set_blocking(proc.stdin.fileno(),False); offset=0; input_deadline=time.monotonic()+min(20,left)
            while offset<len(input_bytes):
                if time.monotonic()>=input_deadline:
                    self.diagnostic.stdin='timeout';self.diagnostic.deadline=True
                    self.diagnostic.observe_capture(capture);self.diagnostic.record('stdin','command_deadline')
                    raise Refusal('stdin_deadline')
                try: offset+=os.write(proc.stdin.fileno(),input_bytes[offset:offset+4096])
                except BlockingIOError: capture.pump(.025)
            proc.stdin.close();self.diagnostic.stdin='closed_normally';capture.context['stdin']='closed_normally'
        except (BrokenPipeError,OSError,Refusal) as error:
            if self.diagnostic.stdin!='timeout':self.diagnostic.stdin='closed_error'
            capture.context['stdin']=self.diagnostic.stdin
            self.diagnostic.observe_capture(capture)
            if type(error) is not Refusal:
                self.diagnostic.record('stdin','stdin_closed',error)
            elif not self.diagnostic.event_recorded:self.diagnostic.record('stdin','unknown',error)
            try:capture.kill()
            except (Refusal,OSError,ValueError,KeyError,TypeError,UnicodeError,subprocess.SubprocessError) as cleanup_error:
                self.diagnostic.record('supervision','supervision_error',cleanup_error,secondary=True,operation='local_supervision');raise
            raise Refusal('stdin_closed') from None
        self.diagnostic.boundary='drain'
        return capture
    def run(self,a,input_bytes=b'',operation='unknown',mutating=False):
        c=self.start(a,input_bytes,operation=operation,mutating=mutating)
        try:return c.wait()
        except (Refusal,OSError,ValueError,KeyError,TypeError,UnicodeError,subprocess.SubprocessError) as error:
            self.diagnostic.observe_capture(c)
            if not self.diagnostic.event_recorded:self.diagnostic.record('drain','unknown',error)
            raise
        finally:
            try:c.kill()
            except (Refusal,OSError,ValueError,KeyError,TypeError,UnicodeError,subprocess.SubprocessError) as error:
                self.diagnostic.record('supervision','supervision_error',error,operation='local_supervision');raise
    def seed_run(self,cid,input_bytes):
        require(type(cid)==str and ID.fullmatch(cid),'seed_container_id')
        self.seed_context=None
        c=self.start(['container','start','--attach','--interactive',cid],input_bytes)
        try:
            value=c.wait_exit();self.diagnostic.observe_capture(c)
            if value[1]!=0 and not self.diagnostic.event_recorded:
                self.diagnostic.record('cli_exit','cli_nonzero')
            self.seed_context=self.diagnostic.freeze_context()
            return value
        except (Refusal,OSError,ValueError,KeyError,TypeError,UnicodeError,subprocess.SubprocessError) as error:
            self.diagnostic.observe_capture(c)
            if not self.diagnostic.event_recorded:self.diagnostic.record('drain','unknown',error)
            raise
        finally:
            try:c.kill()
            except (Refusal,OSError,ValueError,KeyError,TypeError,UnicodeError,subprocess.SubprocessError) as error:
                self.diagnostic.record('supervision','supervision_error',error,operation='local_supervision');raise
    def json(self,a,operation='unknown'):
        raw=self.run(a,operation=operation);self.diagnostic.boundary='public_decode'
        try:value=closed_json(raw)
        except (Refusal,ValueError,TypeError) as error:
            self.diagnostic.state['responseQualified']=False
            self.diagnostic.record('public_decode','decode_refusal',error);raise
        self.diagnostic.boundary='qualifier';return value
    def rows(self,a,operation='unknown'):
        raw=self.run(a,operation=operation);require(len(raw)<=CAP,'rows_bound')
        self.diagnostic.boundary='public_decode'
        try:value=[closed_json(line) for line in raw.splitlines() if line]
        except (Refusal,ValueError,TypeError) as error:
            self.diagnostic.state['responseQualified']=False
            self.diagnostic.record('public_decode','decode_refusal',error)
            if isinstance(error,Refusal):raise
            raise Refusal('rows_shape') from None
        self.diagnostic.boundary='qualifier';return value


def image_qualification(r):
    # Env NAMES only; never Config.Env values/current Docker config/auth.
    template='{{.Id}}|{{.Os}}|{{.Architecture}}{{range .Config.Env}}|{{index (split . "=") 0}}{{end}}'
    raw=r.run(['image','inspect','--format',template,IMAGE,NGINX],operation='inspect_two_images')
    r.diagnostic.boundary='public_decode'
    rows=raw.decode('ascii').splitlines();r.diagnostic.boundary='qualifier'
    require(len(rows)==2,'image_count')
    for row,pin in zip(rows,(IMAGE,NGINX)):
        fields=row.split('|');require(fields[:3]==[pin,'linux','arm64'],'cached_image_identity')
        require(len(fields[3:])==len(set(fields[3:])) and set(fields[3:])<=IMAGE_ENV_KEYS,'image_private_environment')
    r.diagnostic.qualified()
    v=r.json(['info','--format','{"os":{{json .OSType}},"operatingSystem":{{json .OperatingSystem}}}'],operation='desktop_info')
    require(v['os']=='linux' and v['operatingSystem']=='Docker Desktop','desktop_engine')
    r.diagnostic.qualified()
    return {'exactCachedImages':True,'linuxArm64':True,'privateEnvironmentAbsent':True,'desktopLinux':True}


def discover(r,project):
    filt=['--filter','label='+LABEL+'='+project]
    raw=r.run(['container','ls','--all','--quiet','--no-trunc']+filt,operation='cleanup_discovery' if r.cleanup else 'label_collision_containers')
    r.diagnostic.boundary='public_decode';c=raw.decode('ascii').splitlines()
    raw=r.run(['network','ls','--quiet','--no-trunc']+filt,operation='cleanup_discovery' if r.cleanup else 'label_collision_networks')
    r.diagnostic.boundary='public_decode';n=raw.decode('ascii').splitlines()
    raw=r.run(['volume','ls','--quiet']+filt,operation='cleanup_discovery' if r.cleanup else 'label_collision_volumes')
    r.diagnostic.boundary='public_decode';v=raw.decode('ascii').splitlines()
    # This conjunct spans three responses; it cannot blame the final volume call.
    r.diagnostic.operation='cleanup_discovery' if r.cleanup else 'unknown';r.diagnostic.ordinal=None
    r.diagnostic.ordinal_state='unavailable';r.diagnostic.boundary='qualifier'
    require(all(ID.fullmatch(x) for x in c+n) and all(x in (project+'-auth',project+'-scan') for x in v),'discovery_shape')
    r.diagnostic.qualified();return c,n,v


def qualify_networks(r,project,ids):
    items=r.json(['network','inspect']+ids,operation='cleanup_qualification' if r.cleanup else 'inspect_two_networks'); require(len(items)==2,'network_count')
    for v in items:
        require(v['Id'] in ids and v['Name'] in (project+'-backend',project+'-probe') and v['Internal'] is True
                and v['Driver']=='bridge' and not v['Attachable'] and not v['Ingress']
                and v['Labels'].get(LABEL)==project and v['Labels'].get(RUN_LABEL)==project,'internal_network')
    r.diagnostic.qualified();return True


def qualify_volumes(r,project):
    names=[project+'-auth',project+'-scan'];items=r.json(['volume','inspect']+names,operation='cleanup_qualification' if r.cleanup else 'inspect_two_volumes')
    require(len(items)==2,'volume_count')
    for v in items:
        require(v['Name'] in names and v['Driver']=='local' and not v['Options'] and
                v['Labels'].get(LABEL)==project and v['Labels'].get(RUN_LABEL)==project,'fresh_volume')
    r.diagnostic.qualified();return True


def write_operand(path,raw,mode=0o444):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:os.write(fd,raw);os.fchmod(fd,mode)
    finally:os.close(fd)
    require(sha(path.read_bytes())==sha(raw),'operand_drift')


def execute(args,p,started=None):
    started=time.monotonic() if started is None else started
    scratch=approve(args,p);validate_tool()
    data,hashes,embedded,fixtures=inventory();require({x:sha(b) for x,b in fixtures.items()}==p['fixtureSha256'],'freeze_drift')
    os.mkdir(scratch,0o700)
    for name in ('public-home','public-docker-config'):os.mkdir(scratch/name,0o700)
    write_operand(scratch/'public-docker-config'/'config.json',b'{}\n',0o600)
    config=enabled_config(data[CONFIG]);write_operand(scratch/'nginx.enabled.conf',config)
    write_operand(scratch/'public-manifest.json',canonical(p))
    generated={str(path.name):sha(path.read_bytes()) for path in (scratch/'nginx.enabled.conf',scratch/'public-manifest.json')}
    project=args.project;r=Runner(args,scratch,started)
    def abort_signal(signum, frame):
        if not r.cleanup: raise Refusal('parent_signal_stopped')
    previous_handlers={sig:signal.signal(sig,abort_signal) for sig in (signal.SIGINT,signal.SIGTERM)}
    evidence={'kind':'history-wire-native-evidence','passed':False,'executed':False,'phase':'preflight',
              'project':project,'fixtureFreezeSha256':p['fixtureFreezeSha256'],'fixtureSha256':p['fixtureSha256'],
              'sourceSnapshotSha256':SNAPSHOT,'manifestSha256':p['manifestSha256'],
              'enabledConfigSha256':sha(config),'generatedOperandSha256':generated,'wholeAcceptance':False,'liveTouched':False,'hostCapture':False,
              'providerCalled':False,'productionClientAcceptance':False,'quotaFundedGenerationAcceptance':False,
              'actualProviderAttemptProven':False,'unchangedProductionMainExecuted':False,
              'qualifications':[],'failures':[],'cleanup':{'claimed':False}}
    active={};created={};netids=[];volume_names=[];claimed=False;success=False;http_calls=0;peak_containers=0
    def checked_create(role,phase,state=None):
        nonlocal peak_containers
        require(len(created)<10 and len(active)<6,'container_count_bound')
        d=descriptor(role,phase,scratch,project,state)
        suffix=(phase if role in ('api','probe') else str(len(created)))
        name=project+'-'+role+'-'+suffix
        for m in d['mounts']:
            if m['type']=='bind':
                path=plain(m['source']);s=path.lstat();require(stat.S_ISREG(s.st_mode) and s.st_nlink==1,'public_bind_file')
                expected=sha(config) if role=='web' else p['fixtureSha256'][path.relative_to(ROOT).as_posix()]
                if role=='web':
                    require(0<s.st_size<=CAP and s.st_mode&0o7777==0o444,'public_config_bound')
                    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                    try:raw=os.read(fd,CAP+1)
                    finally:os.close(fd)
                    require(len(raw)<=CAP and len(raw)==s.st_size,'public_config_drift')
                else:raw=public_read(path.relative_to(ROOT).as_posix())
                require(sha(raw)==expected,'bind_bytes_drift')
        raw=r.run(create_argv(d,name,project),mutating=True).strip();r.diagnostic.boundary='public_decode'
        decoded=raw.decode('ascii');r.diagnostic.boundary='qualifier';require(ID.fullmatch(decoded),'created_id')
        cid=raw.decode('ascii');created[cid]=(d,name);active[cid]=(d,name);peak_containers=max(peak_containers,len(active))
        r.diagnostic.qualified()
        if role=='web':r.run(['network','connect','--alias','web',project+'-probe',cid])
        v=r.rows(['container','inspect','--format',INSPECT,cid]);require(len(v)==1,'container_inspect')
        evidence['qualifications'].append(qualify_container(v[0],d,project,name,args.daemon_bind_source_policy,args.docker_context))
        return cid
    def remove(cid):
        r.run(['container','rm',cid]);active.pop(cid)
    def oneshot(role,phase,input_value,state=None):
        cid=checked_create(role,phase,state)
        stdin=canonical(input_value) if input_value is not None else b''
        if role=='seed': raw,command_exit=r.seed_run(cid,stdin)
        else: raw=r.run(['container','start','--attach','--interactive',cid],stdin)
        observed=r.rows(['container','inspect','--format',INSPECT,cid])[0]
        d,name=active[cid]
        r.diagnostic.boundary='qualifier'
        try:qualify_container(observed,d,project,name,args.daemon_bind_source_policy,args.docker_context)
        except (Refusal,OSError,ValueError,KeyError,TypeError,UnicodeError,subprocess.SubprocessError) as error:
            if not r.diagnostic.event_recorded:
                r.diagnostic.state['responseQualified']=False
                r.diagnostic.record('qualifier','qualifier_refusal',error)
            raise
        if role=='seed':
            r.diagnostic.restore_context(r.seed_context)
            value=seed_outcome(raw,command_exit,observed['state'],phase,diagnostic=r.diagnostic);remove(cid);return value
        require(observed['state']['Status']=='exited' and observed['state']['ExitCode']==0,'oneshot_clean_exit')
        kind={'volume-init':'history-wire-volume-init','seed':'history-wire-setup' if phase=='setup' else 'history-wire-audit','probe':'history-wire-probe'}[role]
        privacy_gate=privacy(raw);require(privacy_gate['bounded'] and privacy_gate['reflectionAbsent'],'oneshot_reflection')
        value=receipt(raw,kind,phase);remove(cid);return value
    def stop_api(cid,capture,phase):
        r.run(['container','stop','--time','10',cid]);raw=capture.wait()
        require(privacy(raw)['reflectionAbsent'],'api_log_reflection')
        lines=raw.splitlines();require(len(lines)==2,'api_log_shape')
        ready=receipt(lines[0],'history-wire-api-ready',phase);final=receipt(lines[1],'history-wire-api-final',phase)
        v=r.rows(['container','inspect','--format',INSPECT,cid])[0]
        qualify_container(v,active[cid][0],project,active[cid][1],args.daemon_bind_source_policy,args.docker_context)
        require(v['state']['Status']=='exited' and v['state']['ExitCode']==0,'api_clean_exit')
        remove(cid);return {'ready':ready,'final':final,'reflectionAbsent':True,'rawLogsPublished':False}
    try:
        evidence['executed']=True
        evidence['images']=image_qualification(r)
        c,n,v=discover(r,project);require(not c and not n and not v,'preexisting_namespace')
        for family in ('container','network','volume'):
            argv=[family,'ls']+(['--all'] if family=='container' else [])+['--quiet','--filter','name='+project]
            raw=r.run(argv,operation={'container':'name_collision_containers','network':'name_collision_networks','volume':'name_collision_volumes'}[family])
            r.diagnostic.boundary='qualifier';require(not raw.strip(),'preexisting_exact_names');r.diagnostic.qualified()
        # Docker create itself refuses conflicting exact names, even without matching labels.
        claimed=True;evidence['cleanup']['claimed']=True
        for vname in ('auth','scan'):
            name=project+'-'+vname
            result=r.run(['volume','create','--driver','local','--label',LABEL+'='+project,'--label',RUN_LABEL+'='+project,name],
                operation={'auth':'create_volume_auth','scan':'create_volume_scan'}[vname],mutating=True).strip()
            r.diagnostic.boundary='qualifier';require(result==name.encode(),'volume_name');volume_names.append(name);r.diagnostic.qualified()
        qualify_volumes(r,project)
        for network in ('backend','probe'):
            result=r.run(['network','create','--internal','--driver','bridge','--label',LABEL+'='+project,'--label',RUN_LABEL+'='+project,project+'-'+network],
                operation={'backend':'create_network_backend','probe':'create_network_probe'}[network],mutating=True).strip()
            r.diagnostic.boundary='public_decode';decoded=result.decode('ascii');r.diagnostic.boundary='qualifier'
            require(ID.fullmatch(decoded),'network_id');netids.append(decoded);r.diagnostic.qualified()
        qualify_networks(r,project,netids)
        evidence['executed']=True;evidence['phase']='fresh-initialization'
        evidence['volumeInit']=oneshot('volume-init','initialize',None)
        seed_fixtures={SEED:p['fixtureSha256'][SEED]}
        api_fixtures={name:p['fixtureSha256'][name] for name in (SEED,API)}
        setup=oneshot('seed','setup',{'files':embedded,'fixtures':seed_fixtures});state=setup['state'];evidence['setup']=setup
        evidence['phase']='native-ingress'
        web=checked_create('web','serve');r.run(['container','start',web])
        check=r.run(['container','exec',web,'/bin/sh','-c',WEB_CHECK])
        expected=sha(config).encode()+b'  /etc/nginx/nginx.conf\n'
        require(check.startswith(expected) and b'nginx version: nginx/1.27.5\n' in check and
                b'configuration file /etc/nginx/nginx.conf test is successful' in check and privacy(check)['reflectionAbsent'],'native_nginx_qualification')
        evidence['nginx']={'version':'1.27.5','syntaxPassed':True,'mountedBytesSha256':sha(config),'native':True,'historyGate':1,'runtimeGate':0}
        for phase in ('disabled','replay'):
            evidence['phase']=phase+'-api'
            cid=checked_create('api',phase,state)
            capture=r.start(['container','start','--attach','--interactive',cid],canonical({'files':embedded,'fixtures':api_fixtures,'state':state}),True)
            until=time.monotonic()+min(20,r.remaining())
            while b'\n' not in capture.raw:
                require(time.monotonic()<until and capture.proc.poll() is None,'api_startup_receipt');capture.pump(.025)
            receipt(bytes(capture.raw).splitlines()[0],'history-wire-api-ready',phase)
            result=oneshot('probe',phase,{'state':state,'clientSha256':p['fixtureSha256'][CLIENT],'budgetMs':max(1,int(min(19,r.remaining())*1000))})
            http_calls+=result['httpCalls'];require(http_calls<=HTTP,'aggregate_http_bound');evidence[phase+'Probe']=result
            evidence[phase+'Api']=stop_api(cid,capture,phase)
            evidence[phase+'Audit']=oneshot('seed','audit',{'state':state,'files':embedded,'fixtures':seed_fixtures},state)
        evidence['phase']='privacy-and-final-state'
        web_logs=r.run(['container','logs',web]);gate=privacy(web_logs);require(gate['bounded'] and gate['reflectionAbsent'],'web_log_reflection')
        evidence['webLogPrivacy']=gate
        r.run(['container','stop','--time','10',web])
        _, final_hashes, _, final_fixtures=inventory()
        require(final_hashes==hashes and {x:sha(b) for x,b in final_fixtures.items()}==p['fixtureSha256'],'final_freeze_drift')
        success=True
    except Refusal as error:
        if not r.diagnostic.event_recorded:
            if r.diagnostic.boundary=='qualifier':r.diagnostic.state['responseQualified']=False
            r.diagnostic.record(r.diagnostic.boundary,'qualifier_refusal' if r.diagnostic.boundary=='qualifier' else 'unknown',error)
        evidence['failures'].append(str(error))
        if isinstance(error,RuntimeQualifierRefusal): evidence['runtimeQualifierDiagnostics']=error.diagnostics
        if isinstance(error,SeedDiagnosticRefusal): evidence['seedDiagnostics']=error.diagnostics
    except (OSError,ValueError,KeyError,TypeError,UnicodeError,subprocess.SubprocessError) as error:
        if not r.diagnostic.event_recorded:
            r.diagnostic.record(r.diagnostic.boundary,'decode_refusal' if r.diagnostic.boundary=='public_decode' else 'unknown',error)
        evidence['failures'].append('bounded_internal_failure')
    finally:
        r.cleanup=True
        if claimed:
            try:
                # Requalify EACH recorded active ID before stop/removal. Never act on unknown IDs.
                if active:
                    values=r.rows(['container','inspect','--format',INSPECT]+list(active),operation='cleanup_qualification')
                    require({v['id'] for v in values}==set(active),'cleanup_identity')
                    for v in values:
                        d,name=active[v['id']];own_identity(v,project,name)
                        if success:
                            qualify_container(v,d,project,name,args.daemon_bind_source_policy,args.docker_context)
                            require(v['state']['Status']=='exited' and v['state']['ExitCode']==0,'final_clean_exit')
                    running=[v['id'] for v in values if v['state']['Status']=='running']
                    if running:r.run(['container','stop','--time','10']+running,operation='cleanup_stop',mutating=True)
                    if success:r.run(['container','rm']+list(active),operation='cleanup_retention',mutating=True);active.clear()
                if success:
                    qualify_networks(r,project,netids);qualify_volumes(r,project)
                    r.run(['network','rm']+netids,operation='cleanup_retention',mutating=True);r.run(['volume','rm']+volume_names,operation='cleanup_retention',mutating=True)
                c,n,v=discover(r,project)
                require(not success or not c and not n and not v,'cleanup_residue')
                require(set(c)<=set(active) and set(n)<=set(netids) and set(v)<=set(volume_names),'unknown_owned_resource')
                evidence['cleanup']={'claimed':True,'successRemoved':success,'containers':len(c),'networks':len(n),'volumes':len(v),
                                     'stoppedRetentionOnFailure':not success,'foreignResourcesTouched':False}
            except (Refusal,OSError,ValueError,KeyError,TypeError,UnicodeError,subprocess.SubprocessError) as error:
                r.diagnostic.partial=True
                if not r.diagnostic.event_recorded:
                    r.diagnostic.record(r.diagnostic.boundary,'qualifier_refusal' if r.diagnostic.boundary=='qualifier' else 'unknown',error)
                if isinstance(error,RuntimeQualifierRefusal): evidence.setdefault('runtimeQualifierDiagnostics',error.diagnostics)
                success=False;evidence['failures'].append('own_cleanup_incomplete')
                evidence['cleanup']={'claimed':True,'countsUnavailable':True,'foreignResourcesTouched':False}
        for c in r.captures:
            try:c.kill()
            except (OSError,subprocess.SubprocessError) as error:
                r.diagnostic.record('supervision','supervision_error',error,operation='local_supervision')
                success=False;evidence['failures'].append('local_supervision_incomplete')
        evidence.update(passed=success and not evidence['failures'],dockerCalls=r.calls,httpCalls=http_calls,
                        createdContainerIds=len(created),peakContainers=peak_containers,
                        recordedOwnContainerIds=list(created),recordedOwnNetworkIds=netids,recordedOwnVolumeNames=volume_names,
                        captureBytes=r.aggregate,elapsedMilliseconds=int((time.monotonic()-r.started)*1000))
        for sig, handler in previous_handlers.items():signal.signal(sig,handler)
        if evidence['failures']:evidence['failureMetadata']=json.loads(r.diagnostic.encode())
        try:
            require(len(canonical(evidence))<=CAP,'evidence_bound')
            write_operand(scratch/'sanitized-evidence.json',canonical(evidence),0o600)
        except (Refusal,OSError,ValueError,KeyError,TypeError,UnicodeError) as error:
            r.diagnostic.begin('unknown',False,None)
            r.diagnostic.state.update(spawned=None,cliCompleted=None,responseQualified=None)
            r.diagnostic.local=dict.fromkeys(DIAGNOSTIC_LOCAL_KEYS)
            r.diagnostic.record('unknown','reporting_refusal',error,operation='unknown')
            # Preserve the legacy outer refusal and emit only the bounded closed envelope.
            code=error.args[0] if type(error) is Refusal else 'public_preflight_refused'
            raise ReportingRefusal(code,json.loads(r.diagnostic.encode())) from None
    return evidence


def self_test():
    require(len(NEW)==5 and len(SLOTS)==5 and len(MATRIX_IDS)==72,'finite_contract')
    require(sha(canonical(manifest()))==sha(canonical(manifest())),'canonical_hash')
    require('chmodSync(p,448);f.chownSync' in INIT_JS and 'continue;' in INIT_JS,'minimal_init')
    require(ENV['LLM_ENABLED']=='false' and ENV['LLM_QUOTA_ENABLED']=='false' and ENV['LLM_HISTORY_ENABLED']=='true','off_policy')
    for bad in ('/evil','/host_mnt/Users/x/conf/../other'):
        try:bind_candidates(bad,POLICY,'desktop-linux')
        except Refusal:pass
        else:raise Refusal('alias_guard')
    require(privacy(b'CANARY-history-wire-public')['reflectionAbsent'] is False,'privacy_guard')
    return {'passed':True,'pure':True,'engineCalls':0,'sourceWrites':0,'matrixVectors':72}


def main():
    started=time.monotonic()
    parser=argparse.ArgumentParser(description=__doc__)
    modes=parser.add_mutually_exclusive_group();modes.add_argument('--plan',action='store_true');modes.add_argument('--self-test',action='store_true');modes.add_argument('--execute',action='store_true')
    parser.add_argument('--parent-execution-authorized',action='store_true')
    for name in ('reviewed-fixture-sha256','reviewed-source-sha256','reviewed-manifest-sha256','reviewed-config-sha256',
                 'api-image','ingress-image','docker-host','docker-context','project','scratch-dir'):parser.add_argument('--'+name)
    parser.add_argument('--daemon-bind-source-policy',choices=('literal',POLICY),default='literal')
    args=parser.parse_args()
    try:
        result=self_test() if args.self_test else execute(args,plan(),started) if args.execute else plan()
        print(canonical(result).decode('ascii'))
        return 0 if not args.execute or result['passed'] else 1
    except Refusal as error:
        value={'kind':'history-wire-native-refusal','passed':False,'executed':False,'code':str(error),'wholeAcceptance':False}
        if isinstance(error,ReportingRefusal):value['failureMetadata']=error.diagnostic
        print(canonical(value).decode('ascii'));return 1
    except (OSError,ValueError,KeyError,TypeError,UnicodeError):
        print('{"kind":"history-wire-native-refusal","passed":false,"executed":false,"code":"public_preflight_refused","wholeAcceptance":false}');return 1


if __name__=='__main__':
    raise SystemExit(main())
