#!/usr/bin/env python3
"""PUBLIC parser diagnostic candidate. Default/--plan: read-only, no subprocesses.

--execute is parent-only after NEW exact helper/proof/source approval and public
Docker.app executable metadata review. One Compose config, no real Engine endpoint,
private env/profile/account/recovery reads, service execution or proof acceptance.
Creates/removes only a fresh public-synthetic diagnostic directory under the fixed
proof workspace parent. Captures remain memory-only; stdout is finite JSON <=1KiB.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types

SELF = Path(__file__).absolute()
ROOT = SELF.parents[3]
PROOF = SELF.with_name('cve14-combined-proof.py')
WORKSPACES = ROOT.parent / 'cve14-proof-workspaces'
R9 = WORKSPACES / 'run-20261010-proof-r9'
PORTS = R9 / 'ports.override.yaml'
PROOF_SHA = '2ce06c6ddc7ee86abb1c0e2755bb38993ff83e43384c134d76ce3b47a928c33b'
SOURCE_SHA = 'e4efad5ff9ef56040e1d341311599d8bb19da874af94b5bf1eaffa97b7ed6334'
PORTS_SHA = 'b48f6d38c95ebcfa63fc7ffd9b8d3441bb5368cef71208814e136b1b0d3e70f5'
IMAGE = 'sha256:edc9f4875438b5caba2722a67ccf1508fa001db4199b0ef3362bf1b767ce1260'
GATEWAY = 'sha256:2b9eff3b381979c82bf42c310fcd7941805d42adeda67c8814143d6503490655'
DOCKER = Path('/opt/homebrew/bin/docker')
PLUGIN_DIR = Path('/Applications/Docker.app/Contents/Resources/cli-plugins')
CLI_TARGET = Path('/opt/homebrew/Cellar/docker/28.1.1/bin/docker')
PLUGIN_TARGET = Path('/Applications/Docker.app/Contents/Resources/bin/docker-compose')
PROJECT = 'dip-cve14-public-parse'
SECONDS, CAP, RESULT_CAP = 5, 32768, 1024
VOLUME_COUNT_MAX = 8
KEYS = ('memswap_limit','mem_limit','ports','tmpfs','platform','entrypoint','command',
        'volumes','networks','environment','pull_policy','restart','image','user',
        'read_only','cap_drop','cap_add','security_opt','cpus','pids_limit','network_mode')
ROLES = ('api','web','worker','egress','auth-volume-init','scan-volume-init')
VARIABLES = ('SCAN_JWT_SECRET','AUTH_ORIGIN','SCAN_VULN_RELEASE_HOST_DIR',
             'SCAN_VULN_MANIFEST_DIGEST','SCAN_VULN_ARTIFACT_SHA256')
CLASSES = ('compose_public_model_matches','compose_override_tag_unsupported','compose_yaml_syntax_refused',
           'compose_ports_schema_refused','compose_tmpfs_schema_refused',
           'compose_resources_schema_refused','compose_public_schema_field_refused',
           'compose_public_interpolation_missing','compose_format_flag_unsupported',
           'compose_plugin_unavailable','compose_daemon_contact_refused',
           'compose_stdout_json_invalid','compose_topology_contract_refused',
           'command_timeout','command_output_bound','command_io_failed',
           'unclassified_compose_failure')
SETUP_CODES = ('helper_not_approved','frozen_inputs_not_approved','public_plugin_directory_refused',
               'public_plugin_unavailable','public_docker_unavailable','public_tool_link_refused',
               'public_tool_metadata_refused','unapproved_public_tool','unapproved_public_read',
               'linked_or_missing_public_directory','public_file_shape','public_source_drift',
               'frozen_proof_changed','public_ports_changed','public_inputs_mismatch',
               'frozen_source_changed','public_base_env_file_refused','unsafe_public_workspace_parent',
               'unsafe_public_diagnostic_directory','public_cleanup_refused',
               'public_diagnostic_directory_replaced','public_stdin_bound','invalid_capture_shape',
               'unsafe_public_classification','public_arguments_refused','execute_arguments_without_execute')


class Refusal(Exception):
    pass


def require(ok, code):
    if not ok:
        raise Refusal(code)


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def directories_plain(path):
    for directory in reversed(path.parents):
        require(stat.S_ISDIR(directory.lstat().st_mode), 'linked_or_missing_public_directory')


def public_read(path, limit):
    require(path in (SELF,PROOF,PORTS), 'unapproved_public_read')
    directories_plain(path)
    fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit, 'public_file_shape')
        raw = bytearray()
        while len(raw) <= limit:
            block = os.read(fd,min(65536,limit+1-len(raw)))
            if not block: break
            raw.extend(block)
        after = os.fstat(fd)
        require(len(raw) == before.st_size and all(getattr(before,k) == getattr(after,k)
                for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')), 'public_source_drift')
        return bytes(raw)
    finally:
        os.close(fd)


def public_tool(path, target, permitted_links):
    # Only fixed system-code leaves; never resolve/follow an arbitrary reported link.
    require(path in (DOCKER,PLUGIN_DIR/'docker-compose'), 'unapproved_public_tool')
    directories_plain(path)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        require(os.readlink(path) in permitted_links, 'public_tool_link_refused')
        directories_plain(target)
        info = target.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_mode & 0o111 and not info.st_mode & 0o022,
            'public_tool_metadata_refused')


def qualify_tools(plugin_dir):
    require(plugin_dir == str(PLUGIN_DIR), 'public_plugin_directory_refused')
    try:
        public_tool(DOCKER,CLI_TARGET,('../Cellar/docker/28.1.1/bin/docker',))
    except FileNotFoundError:
        raise Refusal('public_docker_unavailable') from None
    try:
        public_tool(PLUGIN_DIR/'docker-compose',PLUGIN_TARGET,(str(PLUGIN_TARGET),'../bin/docker-compose'))
    except FileNotFoundError:
        raise Refusal('public_plugin_unavailable') from None


def frozen_inputs():
    raw = public_read(PROOF,512*1024)
    require(sha(raw) == PROOF_SHA, 'frozen_proof_changed')
    ports = public_read(PORTS,4096)
    require(sha(ports) == PORTS_SHA, 'public_ports_changed')
    # Compile exactly verified bytes, not a second loader read. Never invoke main/execute.
    proof = types.ModuleType('frozen_public_cve14_proof')
    proof.__file__ = str(PROOF)
    exec(compile(raw,str(PROOF),'exec'),proof.__dict__)
    require(proof.ROOT == ROOT and ports == proof.PORT_OVERRIDE, 'public_inputs_mismatch')
    data,hashes,source = proof.stable_inventory()
    require(source == SOURCE_SHA, 'frozen_source_changed')
    require(all(b'env_file:' not in data['server/deploy/'+name] for name in proof.BASES),
            'public_base_env_file_refused')
    return proof,hashes


def public_environment(home, config, proof):
    return {'PATH':'/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin','HOME':str(home),
            'DOCKER_CONFIG':str(config),'TMPDIR':str(home.parent),
            'COMPOSE_DISABLE_ENV_FILE':'true',
            'SCAN_JWT_SECRET':'PUBLIC_DIAGNOSTIC_NOT_A_SECRET_'+'0'*40,
            'AUTH_ORIGIN':proof.ORIGIN,'AUTH_ALLOW_INSECURE_LOCAL_HTTP':'true',
            'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS':'false',
            'SCAN_VULN_RELEASE_HOST_DIR':'/tmp/cve14-public-release-placeholder',
            'SCAN_VULN_MANIFEST_DIGEST':proof.DB['manifestDigest'],
            'SCAN_VULN_ARTIFACT_SHA256':proof.DB['artifactSha256']}


def compose_argv(config, proof):
    args = [str(DOCKER),'--config',str(config),'--host','unix:///dev/null','compose',
            '--env-file','/dev/null','--project-name',PROJECT,'--project-directory',str(R9)]
    for name in proof.BASES: args += ['-f',str(ROOT/'server/deploy'/name)]
    return args+['-f','-','-f',str(PORTS),'config','--format','json']


@contextmanager
def own_public_directory():
    directories_plain(WORKSPACES/'public-placeholder')
    info = WORKSPACES.lstat()
    require(stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o022, 'unsafe_public_workspace_parent')
    path = Path(tempfile.mkdtemp(prefix='cve14-compose-public-diag-',dir=WORKSPACES))
    before = path.lstat()
    require(stat.S_ISDIR(before.st_mode) and before.st_mode & 0o7777 == 0o700,
            'unsafe_public_diagnostic_directory')
    try:
        yield path
    finally:
        primary = sys.exc_info()[0] is not None
        try:
            directories_plain(path)
            parent,after = WORKSPACES.lstat(),path.lstat()
            require(stat.S_ISDIR(after.st_mode) and
                    (info.st_dev,info.st_ino) == (parent.st_dev,parent.st_ino) and
                    (before.st_dev,before.st_ino) == (after.st_dev,after.st_ino),
                    'public_diagnostic_directory_replaced')
            require(shutil.rmtree.avoids_symlink_attacks, 'public_cleanup_refused')
            shutil.rmtree(path)
        except Exception:
            # Never delete a replaced directory or mask the primary failure.
            if not primary:
                raise Refusal('public_cleanup_refused') from None


def capture(config, home, proof, stdin):
    require(len(stdin) <= CAP, 'public_stdin_bound')
    args,env = compose_argv(config,proof),public_environment(home,config,proof)
    end = time.monotonic()+SECONDS
    process = None
    buffers = {'stdout':bytearray(),'stderr':bytearray()}
    code,termination = None,None
    try:
        process = subprocess.Popen(args,cwd=home.parent,env=env,stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        with selectors.DefaultSelector() as selector:
            for key,stream in (('stdin',process.stdin),('stdout',process.stdout),('stderr',process.stderr)):
                os.set_blocking(stream.fileno(),False)
                selector.register(stream,selectors.EVENT_WRITE if key == 'stdin' else selectors.EVENT_READ,key)
            offset = 0
            while selector.get_map():
                require(time.monotonic() < end, 'command_timeout')
                for key,_ in selector.select(min(0.05,max(0,end-time.monotonic()))):
                    if key.data == 'stdin':
                        try: offset += os.write(key.fileobj.fileno(),stdin[offset:])
                        except BlockingIOError: continue
                        if offset == len(stdin): selector.unregister(key.fileobj); key.fileobj.close()
                    else:
                        try: block = os.read(key.fileobj.fileno(),4096)
                        except BlockingIOError: continue
                        if block:
                            require(sum(map(len,buffers.values()))+len(block) <= CAP, 'command_output_bound')
                            buffers[key.data].extend(block)
                        else: selector.unregister(key.fileobj); key.fileobj.close()
            require(time.monotonic() < end, 'command_timeout')
            code = process.wait(timeout=max(0.001,end-time.monotonic()))
    except Refusal as error:
        termination = str(error)
    except subprocess.TimeoutExpired:
        termination = 'command_timeout'
    except (OSError,subprocess.SubprocessError):
        termination = 'command_io_failed'
    finally:
        if process is not None:
            # Kill only the session/group created by this invocation, even if its leader exited.
            try: os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            except OSError: termination = termination or 'command_io_failed'
            try: process.wait(timeout=0.25)
            except (subprocess.SubprocessError,OSError): termination = termination or 'command_io_failed'
            for stream in (process.stdin,process.stdout,process.stderr):
                try: stream.close()
                except OSError: termination = termination or 'command_io_failed'
    return bytes(buffers['stdout']),bytes(buffers['stderr']),code,termination


def classify(stderr):
    text = stderr.decode('utf8',errors='replace')
    low = text.lower()
    field = None
    # Extract only a finite public key, never a raw path, line, role or unknown field.
    roles,keys = '|'.join(map(re.escape,ROLES)),'|'.join(map(re.escape,KEYS))
    match = re.search(r'\bservices\.(?:'+roles+r')\.('+keys+r')\b',text)
    if match: field = match[1]
    if field is None:
        match = re.search(r'\bservices\.(?:'+roles+r')[ :]+Additional property ('+keys+r') is not allowed\b',text)
        if match: field = match[1]
    if '!override' in text and any(x in low for x in ('unknown tag','unsupported tag','could not determine a constructor')):
        return 'compose_override_tag_unsupported',field
    if 'unknown flag: --format' in text: return 'compose_format_flag_unsupported',field
    if any(x in low for x in ("'compose' is not a docker command",'unknown command: docker compose',
                             'unknown command "compose" for "docker"')):
        return 'compose_plugin_unavailable',field
    if 'unix:///dev/null' in text and any(x in low for x in ('cannot connect to the docker daemon',
                                                           'failed to connect','connection refused','not a socket')):
        return 'compose_daemon_contact_refused',field
    if any('required variable '+name+' is missing' in text for name in VARIABLES):
        return 'compose_public_interpolation_missing',field
    schema = any(x in low for x in ('must be','additional property','invalid type','invalid port','is not allowed'))
    if schema and field:
        if field == 'ports': return 'compose_ports_schema_refused',field
        if field == 'tmpfs': return 'compose_tmpfs_schema_refused',field
        if field in ('memswap_limit','mem_limit','cpus','pids_limit'):
            return 'compose_resources_schema_refused',field
        return 'compose_public_schema_field_refused',field
    if 'yaml:' in low and any(x in low for x in ('mapping values are not allowed','did not find expected',
                                                'could not find expected','cannot unmarshal')):
        return 'compose_yaml_syntax_refused',field
    return 'unclassified_compose_failure',field


def web_volume_shape(value, proof):
    # Observe representation only; do not normalize it or grant topology acceptance.
    keys = ('type','source','target','read_only','bind')
    result = {'volumesList':False,'count':None,'countBounded':False,'objects':None,'binds':None,
              'sourceMatches':None,'targetMatches':None,'readonlyMatches':None,'tripleMatches':None,
              'singleObject':False,'keys':dict.fromkeys(keys,False),'extraKeys':None,
              'bindObject':None,'bindExtraKeys':None,'createHostPath':'invalid','exactShape':False}
    if type(value) is not dict or type(value.get('services')) is not dict:
        return result
    web = value['services'].get('web')
    if type(web) is not dict or type(web.get('volumes')) is not list:
        return result
    volumes = web['volumes']; result['volumesList'] = True
    if len(volumes) > VOLUME_COUNT_MAX:
        return result
    result.update(count=len(volumes),countBounded=True)
    mounts = [mount for mount in volumes if type(mount) is dict]
    source,target = str(ROOT/proof.INGRESS_CONFIG),proof.INGRESS_DEST
    result.update(objects=len(mounts),binds=sum(m.get('type') == 'bind' for m in mounts),
                  sourceMatches=sum(m.get('source') == source for m in mounts),
                  targetMatches=sum(m.get('target') == target for m in mounts),
                  readonlyMatches=sum(m.get('read_only') is True for m in mounts),
                  tripleMatches=sum(m.get('source') == source and m.get('target') == target and
                                    m.get('read_only') is True for m in mounts))
    if len(volumes) != 1 or len(mounts) != 1:
        return result
    mount = mounts[0]
    result.update(singleObject=True,keys={key:key in mount for key in keys},extraKeys=bool(set(mount)-set(keys)))
    if 'bind' not in mount:
        result['createHostPath'] = 'absent'
    elif type(mount['bind']) is dict:
        bind = mount['bind']; result.update(bindObject=True,bindExtraKeys=bool(set(bind)-{'create_host_path'}))
        if 'create_host_path' not in bind: result['createHostPath'] = 'absent'
        elif bind['create_host_path'] is False: result['createHostPath'] = 'false'
        elif bind['create_host_path'] is True: result['createHostPath'] = 'true'
    else:
        result['bindObject'] = False
    result['exactShape'] = (mount == {'type':'bind','source':source,'target':target,'read_only':True,
                                     'bind':{'create_host_path':False}} and mount.get('read_only') is True and
                            type(mount.get('bind')) is dict and mount['bind'].get('create_host_path') is False)
    return result


def comparison(predicate):
    try:
        return bool(predicate())
    except (KeyError,TypeError,ValueError,AttributeError,OverflowError):
        return False


def web_boundary(value, proof):
    # One boolean per frozen proof conjunct; never emit observed values or errors.
    def web():
        result = value['services']['web']
        if type(result) is not dict: raise TypeError
        return result
    checks = {
        'envAbsent':lambda:not web().get('environment'),
        'entrypoint':lambda:web()['entrypoint'] == ['nginx'],
        'command':lambda:web()['command'] == ['-g','daemon off;'],
        'user':lambda:web()['user'] == '101:101',
        'readonly':lambda:web()['read_only'] is True,
        'capDrop':lambda:web()['cap_drop'] == ['ALL'],
        'capAddAbsent':lambda:not web().get('cap_add'),
        'nnp':lambda:web()['security_opt'] == ['no-new-privileges:true'],
        'unprivileged':lambda:not web().get('privileged'),
        'pidAbsent':lambda:not web().get('pid'),
        'netModeAbsent':lambda:not web().get('network_mode'),
        'tmpfs':lambda:web()['tmpfs'] == ['/tmp:'+proof.INGRESS_TMPFS],
        'memory':lambda:web()['mem_limit'] == 268435456,
        'memswap':lambda:web()['memswap_limit'] == 268435456,
        'cpu':lambda:float(web()['cpus']) == 1,
        'pids':lambda:web()['pids_limit'] == 128,
    }
    return {label:comparison(check) for label,check in checks.items()}


def topology_failures(value, proof, generated_overlay):
    # Synthetic PUBLIC source path, not the runtime qualified scratch-copy gate.
    def field(name):
        result = value[name]
        if type(result) is not dict: raise TypeError
        return result
    def services(): return field('services')
    def networks(): return field('networks')
    def volumes(): return field('volumes')
    images = {role:IMAGE for role in ('api','worker','auth-volume-init','scan-volume-init')}
    images.update(egress=GATEWAY,web=proof.INGRESS)
    role_networks = {'api':{'auth_internal','scan_internal'},'worker':{'scan_internal'},
                     'egress':{'scan_internal','registry_uplink'},'web':{'auth_internal','web_edge'}}
    def bind_model():
        expected = {'type':'bind','source':str(ROOT/proof.INGRESS_CONFIG),'target':proof.INGRESS_DEST,
                    'read_only':True,'bind':{'create_host_path':False}}
        if type(generated_overlay) is not bytes or not 0 < len(generated_overlay) <= CAP: return False
        generated = json.loads(generated_overlay)
        inputs = generated['services']['web']['volumes']
        if (canonical(generated) != generated_overlay or inputs != [expected] or
                inputs[0]['read_only'] is not True or inputs[0]['bind']['create_host_path'] is not False):
            return False
        mounts = services()['web']['volumes']
        if type(mounts) is not list or len(mounts) != 1 or type(mounts[0]) is not dict: return False
        mount = mounts[0]
        return (set(mount) == set(expected) and mount['type'] == 'bind' and
                mount['source'] == expected['source'] and mount['target'] == expected['target'] and
                mount['read_only'] is True and type(mount['bind']) is dict and
                (mount['bind'] == {} or set(mount['bind']) == {'create_host_path'} and
                 mount['bind']['create_host_path'] is False))
    checks = {
        'foreign_compose_topology':lambda:value['name'] == PROJECT and set(services()) == set(images) and
            set(networks()) == {'auth_internal','scan_internal','registry_uplink','web_edge'} and
            set(volumes()) == {'auth_accounts','scan_ledger'} and
            all(not v.get('external') and v.get('name') == PROJECT+'_'+k for k,v in volumes().items()),
        'composition_image_or_env_mismatch':lambda:all(services()[role]['image'] == image and
            not services()[role].get('env_file') for role,image in images.items()),
        'unexpected_published_port':lambda:all(not services()[role].get('ports') for role in images if role != 'web'),
        'compose_network_mismatch':lambda:all(set(services()[role]['networks']) == names
            for role,names in role_networks.items()),
        'compose_network_not_isolated':lambda:all(not n.get('external') and n.get('name') == PROJECT+'_'+k and
            bool(n.get('internal',False)) == (k in ('auth_internal','scan_internal')) for k,n in networks().items()),
        'ingress_port_override_required':lambda:services()['web']['ports'] ==
            [{'host_ip':'127.0.0.1','target':8080,'published':'18083','protocol':'tcp','mode':'ingress'}],
        'ingress_compose_bind':bind_model,
    }
    return [label for label,check in checks.items() if not comparison(check)]


def memory_representation(value):
    # Literal equality and exact types only; no parsing, coercion or observed-value output.
    result = dict.fromkeys(('memory','memswap'),'other-or-type-invalid')
    if type(value) is not dict or type(value.get('services')) is not dict:
        return result
    web = value['services'].get('web')
    if type(web) is not dict:
        return result
    for label,field in (('memory','mem_limit'),('memswap','memswap_limit')):
        observed = web.get(field)
        if type(observed) is int and observed == 268435456:
            result[label] = 'exact-integer'
        elif type(observed) is str and observed == '268435456':
            result[label] = 'exact-decimal-string'
    return result


def reduce_capture(stdout, stderr, code, termination, proof, generated_overlay=None):
    require(len(stdout)+len(stderr) <= CAP and termination in
            (None,'command_timeout','command_output_bound','command_io_failed'), 'invalid_capture_shape')
    result = {'kind':'public-compose-parser-diagnostic','phase':'public-compose-config',
              'executed':True,'runtimeProofExecuted':False,'rawOutputIncluded':False,
              'exitCode':code if type(code) is int and -255 <= code <= 255 else None,
              'captureBytes':len(stdout)+len(stderr),'classification':None,'publicField':None,
              'jsonValid':False,'webBoundary':None,'topologyFailed':None,'memoryRepresentation':None}
    if termination: result['classification'] = termination
    elif code != 0: result['classification'],result['publicField'] = classify(stderr+b'\n'+stdout)
    else:
        try: value = json.loads(stdout)
        except (ValueError,UnicodeError): result['classification'] = 'compose_stdout_json_invalid'
        else:
            result['jsonValid'] = True
            result['webBoundary'] = web_boundary(value,proof)
            result['memoryRepresentation'] = memory_representation(value)
            result['topologyFailed'] = topology_failures(value,proof,generated_overlay)
            result['classification'] = ('compose_public_model_matches' if not result['topologyFailed'] and
                                        all(result['webBoundary'].values()) else 'compose_topology_contract_refused')
    require(result['classification'] in CLASSES and (result['publicField'] is None or result['publicField'] in KEYS),
            'unsafe_public_classification')
    return result


def plan():
    proof,_ = frozen_inputs()
    return {'kind':'public-compose-parser-diagnostic-plan','executed':False,
            'helperSha256':sha(public_read(SELF,512*1024)),'proofSha256':PROOF_SHA,
            'sourceSnapshotSha256':SOURCE_SHA,'portsOverrideSha256':PORTS_SHA,
            'expectedComposeVersion':'2.34.0-desktop.1','publicPluginDirectory':str(PLUGIN_DIR),
            'dockerExecutable':str(DOCKER),'engineEndpoint':'unix:///dev/null','configCalls':1,
            'commandSeconds':SECONDS,'captureBytes':CAP,'resultBytes':RESULT_CAP,
            'publicOnlySyntheticEnvironment':True,'runtimeProofExecuted':False,
            'webBoundaryConjuncts':16,'allTopologyFailureLabels':True,
                        'memoryEnums':['exact-integer','exact-decimal-string','other-or-type-invalid'],
                        'comparisonIsSyntheticNotRuntimeIdentity':True,'generatedExplicitBindFalseRequired':True}


def execute(args):
    require(args.reviewed_helper_sha256 == sha(public_read(SELF,512*1024)), 'helper_not_approved')
    require(args.reviewed_proof_sha256 == PROOF_SHA and args.reviewed_source_sha256 == SOURCE_SHA,
            'frozen_inputs_not_approved')
    qualify_tools(args.public_plugin_dir)
    proof,_ = frozen_inputs()
    with own_public_directory() as temp:
        home,config = temp/'home',temp/'docker-config'
        home.mkdir(mode=0o700); config.mkdir(mode=0o700)
        fd = os.open(config/'config.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(canonical({'cliPluginsExtraDirs':[str(PLUGIN_DIR)]}))
        stdin = proof.overlay(IMAGE,GATEWAY,[], 'linux/arm64','linux/arm64',
                              proof.INGRESS,ROOT/proof.INGRESS_CONFIG,'linux/arm64')
        result = reduce_capture(*capture(config,home,proof,stdin),proof,stdin)
    return result


class FiniteArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise Refusal('public_arguments_refused')


def main(argv=None):
    parser = FiniteArgumentParser(description=__doc__,add_help=False,allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--plan',action='store_true'); mode.add_argument('--execute',action='store_true')
    parser.add_argument('--public-plugin-dir')
    parser.add_argument('--reviewed-helper-sha256'); parser.add_argument('--reviewed-proof-sha256')
    parser.add_argument('--reviewed-source-sha256')
    try:
        args = parser.parse_args(argv)
        require(args.execute or not any((args.public_plugin_dir,args.reviewed_helper_sha256,
                args.reviewed_proof_sha256,args.reviewed_source_sha256)), 'execute_arguments_without_execute')
        result = execute(args) if args.execute else plan()
    except Exception as error:
        # Only literal local refusal codes; no dynamic text, type, path or argv.
        setup = str(error) if isinstance(error,Refusal) and str(error) in SETUP_CODES else 'public_setup_refused'
        result = {'kind':'public-compose-parser-diagnostic','phase':'public-setup',
                  'classification':setup,'runtimeProofExecuted':False,'rawOutputIncluded':False}
    raw = canonical(result)
    if len(raw)+1 > RESULT_CAP:
        raw = b'{"classification":"public_result_bound","rawOutputIncluded":false}'
        print(raw.decode())
        return 1
    print(raw.decode())
    return 0 if result.get('classification') == 'compose_public_model_matches' or result.get('executed') is False else 1


if __name__ == '__main__':
    sys.exit(main())
