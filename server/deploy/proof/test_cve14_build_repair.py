#!/usr/bin/env python3
"""Pure, bounded regression tests: no Docker, subprocesses, sockets or file writes."""
import argparse
import importlib.util
import inspect
import io
import json
import sys
from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('cve14_candidate', HERE / 'cve14-combined-proof.py')
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)


class SourceClosureTests(unittest.TestCase):
    def fixture(self):
        data = {name: b'public fixture' for name in p.INPUTS}
        data.update({
            'server/api/src/runtime/example.test.ts': b"import { a } from '../../../runtime/src/contract.js'; import '../../../../src/shared/api/scans/runtimeTransport.js';",
            'server/runtime/src/contract.ts': b'export const a = 1;',
            'server/runtime/src/runtime-json.ts': b'export const parse = 1;',
            'server/broker/src/contracts.ts': b'export const b = 1;',
            p.SOURCE_LEAVES[0]: b"export { a } from '../../../../server/runtime/src/contract.js';",
        })
        return data

    def test_relative_nodenext_graph_closes(self):
        p.validate_source_closure(self.fixture())

    def test_missing_sibling_fails_closed(self):
        data = self.fixture()
        del data['server/runtime/src/contract.ts']
        with self.assertRaisesRegex(p.Refusal, '^public_source_closure_missing$'):
            p.validate_source_closure(data)

    def test_missing_leaf_fails_closed(self):
        data = self.fixture()
        del data[p.SOURCE_LEAVES[0]]
        with self.assertRaisesRegex(p.Refusal, '^public_source_closure_missing$'):
            p.validate_source_closure(data)

    def test_transitive_new_unreviewed_public_import_is_not_auto_read(self):
        data = self.fixture()
        data['server/runtime/src/contract.ts'] = b"export * from '../../../unreviewed.ts';"
        with mock.patch.object(p, 'public_read', side_effect=AssertionError('unexpected read')):
            with self.assertRaisesRegex(p.Refusal, '^public_source_closure_missing$'):
                p.validate_source_closure(data)

    def test_private_relative_import_denied_without_read(self):
        data = self.fixture()
        for value in (b"import '../../../.local-auth/private.ts';", b"import './.env.ts';"):
            data['server/runtime/src/contract.ts'] = value
            with mock.patch.object(p, 'public_read', side_effect=AssertionError('unexpected read')):
                with self.assertRaisesRegex(p.Refusal, '^private_source_import$'):
                    p.validate_source_closure(data)

    def test_private_reads_denied_before_open(self):
        with mock.patch.object(p.os, 'open', side_effect=AssertionError('unexpected open')):
            for name in ('server/.env.local', '.local-auth/trust/db-signing-key.pem',
                         'own.env', 'server/runtime/src/../private.ts',
                         'src/shared/api/scans/unreviewed.ts', 'server/runtime/src/private.pem'):
                with self.subTest(name=name), self.assertRaisesRegex(p.Refusal, '^private_path_denied$'):
                    p.public_read(name)

    def test_map_context_copy_and_qualification_same_scope(self):
        data = self.fixture()
        hashes = {name:p.sha(value) for name,value in data.items()}
        files = p.context_files(data,hashes,'a'*64,'reviewed-base:local',{})
        source_map = json.loads(files['proof/source-map.json'])
        expected = {name for name in data if name in p.INPUTS[:6] or p.source_path(name)}
        self.assertEqual(set(source_map['files']),expected)
        self.assertEqual(set(files) - expected, {'Dockerfile','proof/spec.json','proof/source-map.json',
                         'proof/qualify.mjs','proof/provision.mjs','proof/admission.mjs',
                         'proof/ready.mjs','proof/observe.mjs','proof/sql.mjs'})
        dockerfile = files['Dockerfile'].decode()
        self.assertEqual(tuple(source_map['sourceTrees']),p.SOURCE_TREES)
        self.assertEqual(tuple(source_map['sourceLeaves']),p.SOURCE_LEAVES)
        for tree in p.SOURCE_TREES:
            self.assertIn('/app/'+tree,dockerfile.split('RUN rm -rf ',1)[1].split('\n',1)[0])
            self.assertIn('COPY '+tree+' /app/'+tree+'\n',dockerfile)
            self.assertIn(tree,p.QUALIFY_JS)
        for leaf in p.SOURCE_LEAVES:
            self.assertIn('COPY '+leaf+' /app/'+leaf+'\n',dockerfile)
            self.assertIn(leaf,p.QUALIFY_JS)
        self.assertNotIn('COPY . ',dockerfile)
        self.assertNotIn('pnpm install',dockerfile)
        self.assertNotIn('--exclude',dockerfile)
        self.assertIn('pnpm --filter @diplom/scan-api typecheck',dockerfile)
        for name in p.INPUTS[:4]:
            self.assertIn(hashes[name],dockerfile)
        self.assertLess(dockerfile.index('dependency_drift'),dockerfile.index('RUN rm -rf'))
        self.assertLess(dockerfile.index('api-typecheck'),dockerfile.index('sqlite-abi'))

    def test_actual_public_inventory_and_closure(self):
        with mock.patch.object(p.subprocess,'Popen',side_effect=AssertionError('subprocess forbidden')), \
             mock.patch.object(p.socket,'socket',side_effect=AssertionError('socket forbidden')), \
             mock.patch.object(p,'write_new',side_effect=AssertionError('write forbidden')):
            data,hashes,source_sha = p.stable_inventory()
        self.assertEqual(source_sha,p.sha(p.canonical(hashes)))
        for tree in p.SOURCE_TREES:
            self.assertTrue(any(name.startswith(tree+'/') for name in data))
        for leaf in p.SOURCE_LEAVES:
            self.assertIn(leaf,data)
        self.assertIn('server/api/src/runtime/runtime-transport.test.ts',data)
        self.assertLessEqual(len(data),p.MAX_FILES)
        self.assertLessEqual(sum(map(len,data.values())),p.MAX_TOTAL)


class DiagnosticTests(unittest.TestCase):
    path = 'server/api/src/runtime/runtime-api.service.ts'
    outside = 'server/runtime/src/contract.ts'

    def diagnose(self, stdout=b'',stderr=b'',code=1,termination=None):
        return p.build_diagnostics(stdout,stderr,(self.path,self.outside),code,termination)

    def test_exact_dependency_classification(self):
        result = self.diagnose(stderr=b'#4 0.123 CVE14_BUILD_PHASE:dependency-manifests\n#4 0.124 Error: dependency_drift\n')
        self.assertEqual(result['classifications'],['dependency_manifest_mismatch'])
        self.assertEqual(result['observedPhases'],['dependency-manifests'])
        self.assertFalse(result['rawOutputIncluded'])

    def test_manifest_missing_classification(self):
        self.assertEqual(self.diagnose(stderr=b'Error: dependency_manifest_unavailable\n')['classifications'],
                         ['dependency_manifest_unavailable'])

    def test_pinned_ts_paths_only_and_no_messages(self):
        result = self.diagnose(stderr=b'#9 0.1 CVE14_BUILD_PHASE:api-typecheck\n'
            b'#9 0.2 src/runtime/runtime-api.service.ts(9,2): error TS2307: PRIVATE_SENTINEL /secret/key.pem\n'
            b'#9 0.3 ../runtime/src/contract.ts(1,4): error TS2322: PRIVATE_SENTINEL\n'
            b'#9 0.4 /app/server/api/src/runtime/runtime-api.service.ts(4,5): error TS2550: PRIVATE_SENTINEL\n')
        self.assertEqual(len(result['typescript']),3)
        self.assertEqual({r['path'] for r in result['typescript']},{self.path,self.outside})
        self.assertEqual(result['classifications'],['api_typecheck_failed','typescript_diagnostics'])
        encoded = json.dumps(result)
        self.assertNotIn('PRIVATE_SENTINEL',encoded)
        self.assertNotIn('key.pem',encoded)

    def test_hostile_private_unknown_and_ansi_lines_never_escape(self):
        result = self.diagnose(stderr=b'ENV=PRIVATE_SENTINEL\n'
            b'/home/operator/.local-auth/private.ts(1,1): error TS2307: PRIVATE_SENTINEL\n'
            b'../../.local-auth/private.ts(1,1): error TS2307: PRIVATE_SENTINEL\n'
            b'src/runtime/unapproved.ts(1,1): error TS2307: PRIVATE_SENTINEL\n'
            b'src/runtime/runtime-api.service.ts(1,1): error TS99999: PRIVATE_SENTINEL\n'
            b'\x1b[31msrc/runtime/runtime-api.service.ts(1,1): error TS2307: PRIVATE_SENTINEL\n'
            b'RUN echo CVE14_BUILD_PHASE:sqlite-abi\n')
        self.assertEqual(result['typescript'],[])
        self.assertEqual(result['observedPhases'],[])
        self.assertEqual(result['classifications'],['unclassified_build_failure'])
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result))

    def test_rows_bounded_and_deduplicated(self):
        raw = b'\n'.join(('src/runtime/runtime-api.service.ts('+str(i)+',1): error TS2307: PRIVATE_SENTINEL').encode()
                         for i in range(1,100))
        result = self.diagnose(raw)
        self.assertEqual(len(result['typescript']),p.DIAGNOSTIC_ROWS)
        self.assertTrue(result['truncated'])
        self.assertLess(len(p.canonical(result)),16384)
        one = b'src/runtime/runtime-api.service.ts(1,1): error TS2307: PRIVATE_SENTINEL\n'
        self.assertEqual(len(self.diagnose(one,one)['typescript']),1)

    def test_oversized_line_and_line_count_bounded(self):
        result = self.diagnose(b'x'*(p.DIAGNOSTIC_LINE_BYTES+1))
        self.assertTrue(result['truncated'])
        result = self.diagnose(b'x\n'*(p.DIAGNOSTIC_LINES+1))
        self.assertTrue(result['truncated'])

    def test_input_cap_and_termination_allowlist(self):
        with self.assertRaisesRegex(p.Refusal,'^diagnostic_input_bound$'):
            self.diagnose(b'x'*(p.BUILD_OUTPUT_CAP+1))
        with self.assertRaisesRegex(p.Refusal,'^invalid_diagnostic_termination$'):
            self.diagnose(termination='PRIVATE_SENTINEL')
        for value in ('command_timeout','command_output_bound','protocol_deadline'):
            self.assertIn(value,self.diagnose(code=-9,termination=value)['classifications'])

    def test_sqlite_phase_and_success_are_distinct(self):
        self.assertEqual(self.diagnose(stderr=b'CVE14_BUILD_PHASE:sqlite-abi\n')['classifications'],['sqlite_abi_failed'])
        self.assertEqual(self.diagnose(code=0)['classifications'],[])

    def test_build_wrapper_keeps_caps_and_network(self):
        with mock.patch.dict(p.os.environ,{'PATH':'pure','HOME':'/pure'},clear=True):
            runner = p.Runner('parent-local',0)
        with mock.patch.object(runner,'run',return_value=(b'',0)) as run:
            runner.build(Path('/pure-context'),'own:local','linux/arm64',{self.path:'a'*64})
        args,kwargs = run.call_args
        self.assertEqual(args[0],['build','--network','none','--pull=false','--progress=plain',
                                  '--platform','linux/arm64','-t','own:local','/pure-context'])
        self.assertEqual(kwargs,{'seconds':220,'cap':4*1024**2,'build_paths':(self.path,)})


class RunnerCaptureTests(unittest.TestCase):
    def capture(self, stdout, stderr, code=1, timeout=False, initializer=False, nginx_kind=None, compose_phase=None):
        process = mock.Mock()
        process.stdin = None
        process.stdout.fileno.return_value = 101
        process.stderr.fileno.return_value = 102
        process.wait.return_value = code
        process.poll.return_value = code
        chunks = {101:[stdout,b''],102:[stderr,b'']}
        class Selector:
            def __init__(self): self.entries = {}
            def __enter__(self): return self
            def __exit__(self,*args): pass
            def register(self,stream,events,name): self.entries[stream] = mock.Mock(fileobj=stream,data=name)
            def unregister(self,stream): del self.entries[stream]
            def get_map(self): return self.entries
            def select(self,seconds): return [(key,1) for key in list(self.entries.values())]
        def read(stream,size): return chunks[stream].pop(0)
        with mock.patch.dict(p.os.environ,{'PATH':'pure','HOME':'/pure'},clear=True):
            runner = p.Runner('parent-local',0)
        clock = mock.Mock(side_effect=[1,1,999]) if timeout else mock.Mock(return_value=1)
        with mock.patch.object(p.subprocess,'Popen',return_value=process), \
             mock.patch.object(p.selectors,'DefaultSelector',Selector), \
             mock.patch.object(p.os,'set_blocking'), mock.patch.object(p.os,'read',side_effect=read), \
             mock.patch.object(p.time,'monotonic',clock):
            with self.assertRaises(p.Refusal) as error:
                if compose_phase is not None:
                    runner.json(ComposeRepairTests().argv(),seconds=15,cap=p.COMPOSE_CAPTURE_CAP,compose_phase=compose_phase)
                elif nginx_kind is not None:
                    runner.nginx('c'*64,nginx_kind)
                elif initializer:
                    runner.initializer_log('c'*64)
                else:
                    runner.build(Path('/pure-context'),'own:local','linux/arm64',
                                 {'server/api/src/runtime/runtime-api.service.ts':'a'*64})
        result = runner.last_compose_diagnostics if compose_phase is not None else runner.last_nginx_diagnostic if nginx_kind is not None else runner.last_initializer_log_codes if initializer else runner.last_build_diagnostics
        return str(error.exception),result,process

    def test_failed_own_capture_extracts_without_raw_exception(self):
        error,result,process = self.capture(b'PRIVATE_SENTINEL\n',
            b'#5 0.1 CVE14_BUILD_PHASE:api-typecheck\n'
            b'#5 0.2 src/runtime/runtime-api.service.ts(9,2): error TS2307: PRIVATE_SENTINEL\n')
        self.assertEqual(error,'isolated_command_failed')
        self.assertEqual(result['typescript'][0]['code'],'TS2307')
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result))
        # EOF closes the streams; finalization idempotently closes them again.
        self.assertEqual(process.stdout.close.call_count,2)
        self.assertEqual(process.stderr.close.call_count,2)

    def test_capture_overflow_is_bounded_and_classified(self):
        error,result,_ = self.capture(b'x'*(p.BUILD_OUTPUT_CAP+1),b'')
        self.assertEqual(error,'command_output_bound')
        self.assertIn('command_output_bound',result['classifications'])
        self.assertEqual(result['typescript'],[])

    def test_capture_timeout_is_classified_without_raw_output(self):
        error,result,_ = self.capture(b'PRIVATE_SENTINEL',b'',timeout=True)
        self.assertEqual(error,'command_timeout')
        self.assertIn('command_timeout',result['classifications'])
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result))


class InitializerTests(unittest.TestCase):
    def test_overlay_uses_exact_initializer_without_authority_widening(self):
        services = json.loads(p.overlay('sha256:'+'a'*64,'sha256:'+'b'*64,[]))['services']
        for role in ('auth-volume-init','scan-volume-init'):
            self.assertEqual(services[role]['command'],['-e',p.INITIALIZER_JS])
            self.assertEqual(services[role]['user'],'0:0')
            self.assertTrue(services[role]['read_only'])
            for forbidden in ('cap_add','privileged','volumes','network_mode'):
                self.assertNotIn(forbidden,services[role])
        self.assertNotIn('FOWNER',p.INITIALIZER_JS)
        self.assertNotIn('process.env',p.INITIALIZER_JS)
        self.assertNotIn('readFile',p.INITIALIZER_JS)
        self.assertNotIn('console.log',p.INITIALIZER_JS)

    def test_log_allowlist_discards_raw_errors_private_fields_and_suffixes(self):
        for code in p.INIT_FAILURE_CODES:
            marker = ('OWN_INIT_FAILURE:'+code+'\n').encode()
            self.assertEqual(p.initializer_log_codes(marker,marker),[code])
        self.assertEqual(p.initializer_log_codes(b'Error: PRIVATE_SENTINEL\n',
            b'OWN_INIT_FAILURE:own_init_io_failed PRIVATE_SENTINEL\n'
            b'OWN_INIT_FAILURE:PRIVATE_SENTINEL\n'),[])
        with self.assertRaisesRegex(p.Refusal,'^initializer_diagnostic_input_bound$'):
            p.initializer_log_codes(b'x'*(p.INIT_LOG_CAP+1),b'')

    def test_actual_runner_reduces_both_log_streams(self):
        error,codes,_ = RunnerCaptureTests().capture(b'PRIVATE_SENTINEL\n',
            b'OWN_INIT_FAILURE:own_init_chmod_eperm\nPRIVATE_SENTINEL\n',initializer=True)
        self.assertEqual(error,'isolated_command_failed')
        self.assertEqual(codes,['own_init_chmod_eperm'])
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(codes))

    def test_selective_own_diagnostic_identity_and_deadline(self):
        project,image = 'dip-cve14-proof-'+'a'*16,'sha256:'+'b'*64
        class FakeRunner:
            def __init__(self,bad=None): self.work_deadline=1000; self.bad=bad; self.logs=[]; self.inspects=[]
            def text(self,args,**kwargs):
                assert args[:5]==['container','ls','-aq','--no-trunc','--filter']
                assert args[5]=='label=com.docker.compose.project='+project
                assert kwargs=={'seconds':2,'cap':4096}
                return ('c' if args[-1].endswith('auth-volume-init') else 'd')*64
            def json(self,args,**kwargs):
                assert args[:3]==['container','inspect','--format']
                assert '.Env' not in args[3] and '.State.Error' not in args[3] and '.Health' not in args[3]
                self.inspects.append(args)
                role = 'auth-volume-init' if args[-1]=='c'*64 else 'scan-volume-init'
                info={'id':args[-1],'name':'/'+project+'-'+role+'-1','project':project,'service':role,
                      'image':image,'status':'exited','exitCode':1,'oomKilled':False}
                if self.bad: info[self.bad]='PRIVATE_SENTINEL'
                return info
            def initializer_log(self,cid): self.logs.append(cid); return ['own_init_chmod_eperm']
        runner = FakeRunner()
        with mock.patch.object(p.time,'monotonic',return_value=10):
            result=p.diagnose_own_initializers(runner,project,image)
        self.assertEqual(runner.work_deadline,1000)
        self.assertEqual(runner.logs,['c'*64,'d'*64])
        self.assertEqual(len(result['initializers']),2)
        self.assertFalse(result['unavailable'])
        self.assertFalse(result['rawOutputIncluded'])
        for field in ('id','project','service','name','image','status','exitCode','oomKilled'):
            runner=FakeRunner(field)
            result=p.diagnose_own_initializers(runner,project,image)
            self.assertEqual(runner.logs,[])
            self.assertTrue(result['unavailable'])
            self.assertEqual(runner.work_deadline,1000)
            self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result))


class DaemonBindTests(unittest.TestCase):
    release = Path('/Users/pure/public-release')
    project = 'dip-cve14-proof-'+'a'*16
    cid, image = 'b'*64, 'sha256:'+'c'*64

    def fixture(self, role='api', prefix='', context='desktop-linux', validated=True):
        test = self
        labels = {'com.docker.compose.project':self.project}
        binds = [{'Type':'bind','Source':source,'Destination':destination,'RW':False}
                 for source,destination in sorted(p.release_bind_pairs(self.release,role,prefix))]
        mounts = binds + ([{'Type':'volume','Name':self.project+'_scan_ledger',
                           'Destination':'/data','RW':True}] if role != 'egress' else [])
        if role == 'api': mounts.append({'Type':'volume','Name':self.project+'_auth_accounts',
                                        'Destination':'/auth','RW':True})
        networks = {'api':('auth_internal','scan_internal'),'worker':('scan_internal',),
                    'egress':('scan_internal','registry_uplink')}[role]
        host = {'ReadonlyRootfs':True,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges:true'],
                'Privileged':False,'PidMode':'','IpcMode':'private','CapAdd':None,
                'PortBindings':{},
                'Memory':1073741824,'MemorySwap':1073741824,'NanoCpus':1000000000,'PidsLimit':128,
                'Tmpfs':{'/tmp':'rw,noexec,nosuid,size=16m',
                         '/tmp/trivy':'rw,noexec,nosuid,uid=65532,gid=65532,size=512m'}}
        env = {**p.OFF,'SCAN_VULN_MANIFEST_DIGEST':p.DB['manifestDigest'],
               'SCAN_VULN_ARTIFACT_SHA256':p.DB['artifactSha256'],
               'SCAN_VULN_RELEASE_DIR':'/opt/release','SCAN_VULN_ENABLED':'true'}
        command = {'api':['node','--import','tsx','src/oci/nginx-local.main.ts'],
                   'worker':['node','--import','tsx','src/worker/nginx-local-worker.main.ts'],
                   'egress':['python','-I','proxy.py']}[role]
        info = {'Image':self.image,'Name':'/'+self.project+'-'+role+'-1','Mounts':mounts,
                'HostConfig':host,'Config':{'User':'65532:65532','Labels':labels,'Entrypoint':[],
                    'Env':[k+'='+v for k,v in env.items()],'Cmd':command,'WorkingDir':'/opt/gateway'},
                'NetworkSettings':{'Networks':{self.project+'_'+n:{'NetworkID':n} for n in networks}}}
        class FakeRunner:
            def __init__(self):
                self.docker=['docker','--context',context]; self.local_daemon_validated=validated
                self.calls=[]; self.failure=None; self.inode='same-ro-db'
                self.verified={'kind':'authenticated-release-usability-only','db':dict(p.DB),
                    'resultContractVersion':2,'dbPolicy':{'version':2,'policy':p.POLICY},
                    'usableUntil':p.UNTIL,'scannerChecked':False,'admissionChecked':False}
            def json(self,args,**kwargs):
                self.calls.append(args)
                if args[:2]==['container','inspect']:
                    test.assertEqual(args[2],test.cid); return [info]
                if args[:2]==['network','inspect']:
                    return [{'Labels':labels,'Internal':args[-1]!='registry_uplink'}]
                test.assertEqual(args[:5],['exec',test.cid,'node','--import','tsx'])
                if args[5]=='/proof/qualify.mjs':
                    test.assertEqual(args[6],role); test.assertEqual(kwargs,{'seconds':20})
                    if self.failure=='qualify': raise p.Refusal('isolated_command_failed')
                    return {'sourceSnapshotSha256':'d'*64,'files':243}
                test.assertEqual(args[5:],['src/worker/verify-vuln-db-release.ts','/opt/release',
                                          p.DB['manifestDigest'],p.DB['artifactSha256']])
                test.assertEqual(kwargs,{'seconds':90})
                if self.failure=='signature': raise p.Refusal('isolated_command_failed')
                return self.verified
            def text(self,args,**kwargs):
                self.calls.append(args); test.assertEqual(args,['exec',test.cid,'node','-e',p.DB_INODE_JS])
                return self.inode
        return FakeRunner(),info

    def verify(self, runner, role='api', prefix=''):
        return p.verify_container(runner,self.cid,self.project,self.image,self.release,role,prefix)

    def test_literal_default_and_explicit_representation_require_authentication(self):
        for prefix in ('','/host_mnt'):
            for role in ('api','worker','egress'):
                with self.subTest(prefix=prefix,role=role):
                    runner,_=self.fixture(role,prefix)
                    result=self.verify(runner,role,prefix)
                    self.assertTrue(result['noEngineSocketOrPrivateBind'])
                    execs=[args for args in runner.calls if args[0]=='exec']
                    if role=='egress': self.assertEqual(execs,[]); continue
                    self.assertTrue(result['mountedReleaseAuthenticated'])
                    self.assertEqual(result['bindRepresentation'],'explicit-host-mnt' if prefix else 'literal')
                    self.assertEqual(execs[0][5],'/proof/qualify.mjs')
                    self.assertEqual(execs[1][5],'src/worker/verify-vuln-db-release.ts')
                    if role=='worker':
                        self.assertEqual(execs[2][-1],p.DB_INODE_JS); self.assertTrue(result['sameDbInode'])

    def test_unknown_prefix_and_wrong_context_refused_before_metadata(self):
        for prefix in ('/host_mnt/','/run/desktop/mnt/host','/host_mnt/other','PRIVATE_SENTINEL',None):
            runner,_=self.fixture()
            with self.subTest(prefix=prefix), self.assertRaisesRegex(p.Refusal,'^unsupported_daemon_bind_source_prefix$'):
                self.verify(runner,prefix=prefix)
            self.assertEqual(runner.calls,[])
        runner,_=self.fixture(prefix='/host_mnt',context='parent-local')
        with self.assertRaisesRegex(p.Refusal,'^daemon_bind_prefix_context_refused$'):
            self.verify(runner,prefix='/host_mnt')
        self.assertEqual(runner.calls,[])
        args=argparse.Namespace(reviewed_script_sha256='a'*64,reviewed_source_sha256='b'*64,
                                docker_context='parent-local',daemon_bind_source_prefix='/host_mnt')
        with mock.patch.object(p,'plain_absolute',side_effect=AssertionError('metadata forbidden')):
            with self.assertRaisesRegex(p.Refusal,'^daemon_bind_prefix_context_refused$'):
                p.approve(args,{'scriptSha256':'a'*64,'sourceSnapshotSha256':'b'*64})

    def test_prefix_requires_validated_unix_linux_daemon(self):
        runner,_=self.fixture(prefix='/host_mnt',validated=False)
        with self.assertRaisesRegex(p.Refusal,'^daemon_bind_prefix_unvalidated$'):
            self.verify(runner,prefix='/host_mnt')
        self.assertEqual(runner.calls,[])
        for endpoint,os_type,code in (
            ('tcp://remote.invalid:2375','linux','nonlocal_docker_context'),
            ('unix:///pure.sock','windows','linux_daemon_required'),
            ('unix:///pure.sock','linux',None),
        ):
            daemon=mock.Mock(docker=['docker','--context','desktop-linux'])
            daemon.text.side_effect=[endpoint,os_type]
            if code:
                with self.assertRaisesRegex(p.Refusal,'^'+code+'$'):
                    p.validate_local_daemon(daemon,'desktop-linux')
                self.assertFalse(daemon.local_daemon_validated)
            else:
                p.validate_local_daemon(daemon,'desktop-linux')
                self.assertTrue(daemon.local_daemon_validated)

    def test_prefix_only_constructs_exact_users_pairs_without_resolve_or_read(self):
        with mock.patch.object(Path,'resolve',side_effect=AssertionError('resolve forbidden')), \
             mock.patch.object(p.os,'open',side_effect=AssertionError('read forbidden')):
            self.assertEqual(p.release_bind_pairs(self.release,'worker','/host_mnt'),{
                ('/host_mnt/Users/pure/public-release','/opt/release'),
                ('/host_mnt/Users/pure/public-release/db','/tmp/trivy/db')})
            for path in ('/var/public-release','/UsersElsewhere/pure/release','/host_mnt/Users/pure/release',
                         '/Users/pure/../release','/Users/pure','relative'):
                with self.subTest(path=path), self.assertRaisesRegex(p.Refusal,'^daemon_bind_prefix_host_path_refused$'):
                    p.release_bind_pairs(Path(path),'api','/host_mnt')
        path=Path('/Users/pure/public-release')
        with mock.patch.object(Path,'resolve',return_value=path), mock.patch.object(Path,'is_symlink',return_value=True):
            with self.assertRaisesRegex(p.Refusal,'^linked_absolute_path$'):
                p.plain_absolute(str(path))

    def test_wrong_source_alias_suffix_destination_and_rw_refused_before_qualification(self):
        source='/host_mnt'+str(self.release)
        cases=[{'Source':str(self.release)}, {'Source':'/run/desktop/mnt/host'+str(self.release)},
               {'Source':'/host_mnt'+str(self.release)+'-other'}, {'Source':source+'/db'},
               {'Source':source+'/'}, {'Source':source+'/../public-release'},
               {'Source':source+'/db/..'}, {'Source':'/host_mnt'+str(self.release.parent)+'/other'},
               {'Destination':'/opt/release/extra'}, {'Destination':'/tmp/trivy/db'}, {'RW':True}, {'RW':0}]
        for changes in cases:
            runner,info=self.fixture(prefix='/host_mnt'); info['Mounts'][0].update(changes)
            with self.subTest(changes=changes), self.assertRaisesRegex(p.Refusal,'^unsafe_bind$'):
                self.verify(runner,prefix='/host_mnt')
            self.assertFalse(any(args[0]=='exec' for args in runner.calls))
        runner,_=self.fixture(prefix='/host_mnt')
        with self.assertRaisesRegex(p.Refusal,'^unsafe_bind$'): self.verify(runner)
        runner,info=self.fixture('worker','/host_mnt')
        next(m for m in info['Mounts'] if m['Destination']=='/tmp/trivy/db')['Source']=source
        with self.assertRaisesRegex(p.Refusal,'^unsafe_bind$'): self.verify(runner,'worker','/host_mnt')

    def test_missing_extra_and_duplicate_binds_refused(self):
        for action in ('missing','extra','duplicate'):
            runner,info=self.fixture(prefix='/host_mnt')
            if action=='missing': info['Mounts'].pop(0)
            else:
                mount=dict(info['Mounts'][0])
                if action=='extra': mount['Destination']='/baseline.ts'
                info['Mounts'].append(mount)
            with self.subTest(action=action), self.assertRaises(p.Refusal):
                self.verify(runner,prefix='/host_mnt')
            self.assertFalse(any(args[0]=='exec' for args in runner.calls))
        runner,info=self.fixture('egress','/host_mnt')
        info['Mounts'].append({'Type':'bind','Source':'/host_mnt'+str(self.release),
                               'Destination':'/opt/release','RW':False})
        with self.assertRaisesRegex(p.Refusal,'^unsafe_bind$'): self.verify(runner,'egress','/host_mnt')

    def test_source_or_signature_failure_cannot_return_equivalence(self):
        for failure in ('qualify','signature'):
            runner,_=self.fixture(prefix='/host_mnt'); runner.failure=failure
            with self.subTest(failure=failure), self.assertRaisesRegex(p.Refusal,'^isolated_command_failed$'):
                self.verify(runner,prefix='/host_mnt')
            execs=[args for args in runner.calls if args[0]=='exec']
            self.assertEqual(len(execs),1 if failure=='qualify' else 2)

    def test_entire_identity_and_v2_receipt_required_before_equivalence(self):
        for changes in ({'db':{**p.DB,'dbSha256':'0'*64}}, {'resultContractVersion':1},
                        {'kind':'unverified'}, {'dbPolicy':{'version':1,'policy':p.POLICY}},
                        {'usableUntil':'2099-01-01'}, {'scannerChecked':True}, {'admissionChecked':True}):
            runner,_=self.fixture(prefix='/host_mnt'); runner.verified.update(changes)
            with self.subTest(changes=changes), self.assertRaisesRegex(p.Refusal,'^authenticated_release_mismatch$'):
                self.verify(runner,prefix='/host_mnt')

    def test_worker_inode_failure_cannot_return_equivalence(self):
        runner,_=self.fixture('worker','/host_mnt'); runner.inode='wrong-db'
        with self.assertRaisesRegex(p.Refusal,'^db_mount_identity$'): self.verify(runner,'worker','/host_mnt')
        self.assertEqual(runner.calls[-1],['exec',self.cid,'node','-e',p.DB_INODE_JS])
        self.assertIn('a.dev!==b.dev||a.ino!==b.ino||!b.isFile()||b.isSymbolicLink()',p.DB_INODE_JS)

    def test_prefix_is_execute_only_and_plan_declares_finite_authority(self):
        for mode in ('--plan','--self-test','--diagnose-build'):
            output=io.StringIO()
            with mock.patch.object(sys,'argv',['candidate',mode,'--daemon-bind-source-prefix','/host_mnt']), \
                 mock.patch.object(p,'stable_inventory',side_effect=AssertionError('inventory forbidden')), \
                 mock.patch('sys.stdout',output):
                self.assertEqual(p.main(),1)
            self.assertEqual(json.loads(output.getvalue())['reason'],'execute_arguments_without_execute')
        args=argparse.Namespace(reviewed_script_sha256='a'*64,reviewed_source_sha256='b'*64,
                               docker_context='desktop-linux',gateway_image=None,release_dir=None,
                               daemon_bind_source_prefix='/host_mnt')
        with self.assertRaisesRegex(p.Refusal,'^build_only_inputs_required$'):
            p.approve_build(args,{'scriptSha256':'a'*64,'sourceSnapshotSha256':'b'*64})
        authority=p.plan({},'a'*64)['daemonBindSource']
        self.assertEqual(authority['allowed'],['','/host_mnt']); self.assertEqual(authority['default'],'')
        self.assertTrue(authority['authenticatedMountedBytesBeforeClaim'])

    def test_execute_keeps_preflight_qualification_and_recreation_gates(self):
        source=inspect.getsource(p.execute)
        self.assertLess(source.index('approve(args, proposal)'),source.index('Runner('))
        self.assertLess(source.index('validate_local_daemon('),source.index('probe.bind('))
        self.assertLess(source.index("evidence['isolation']"),source.index("evidence['phase'] = 'actual-http-combined'"))
        self.assertIn("release,name,bind_prefix,bind_policy)",source)
        self.assertIn("release,'api',bind_prefix,bind_policy)",source)
        self.assertIn("verified['db']==DB",source)


class DesktopBindPolicyTests(unittest.TestCase):
    policy = 'desktop-exact-literal-or-host-mnt-v1'

    def fixture(self, role='worker', choices=('host-mnt','literal'), **kwargs):
        base = DaemonBindTests()
        runner, info = base.fixture(role=role, **kwargs)
        destinations = ('/opt/release','/tmp/trivy/db') if role=='worker' else ('/opt/release',)
        for destination, choice in zip(destinations, choices):
            for mount in info['Mounts']:
                if mount['Type']=='bind' and mount['Destination']==destination and choice=='host-mnt':
                    mount['Source'] = '/host_mnt'+mount['Source']
        return base, runner, info

    def verify(self, base, runner, role='worker', prefix='', policy=None):
        return p.verify_container(runner,base.cid,base.project,base.image,base.release,role,prefix,
                                  self.policy if policy is None else policy)

    def test_each_exact_alternative_and_all_worker_combinations_are_observed(self):
        for role in ('api','worker','egress'):
            for first in ('literal','host-mnt'):
                for second in ('literal','host-mnt'):
                    with self.subTest(role=role,first=first,second=second):
                        base,runner,_=self.fixture(role,(first,second))
                        result=self.verify(base,runner,role)
                        expected={} if role=='egress' else {'/opt/release':first}
                        if role=='worker': expected['/tmp/trivy/db']=second
                        self.assertEqual(result['bindRepresentations'],expected)
                        if role=='egress':
                            self.assertNotIn('mountedReleaseReceipt',result)
                            self.assertFalse(any(call[0]=='exec' for call in runner.calls))
                            continue
                        self.assertEqual(result['bindRepresentation'],self.policy)
                        self.assertTrue(result['mountedReleaseAuthenticated'])
                        self.assertEqual(result['mountedReleaseReceipt'],{
                            'kind':'authenticated-release-usability-only','db':p.DB,
                            'resultContractVersion':2,'usableUntil':p.UNTIL,
                            'dbPolicy':{'version':2,'policy':p.POLICY}})
                        execs=[call for call in runner.calls if call[0]=='exec']
                        self.assertEqual(execs[0][5],'/proof/qualify.mjs')
                        self.assertEqual(execs[1][5],'src/worker/verify-vuln-db-release.ts')
                        if role=='worker':
                            self.assertTrue(result['sameDbInode'])
                            self.assertEqual(execs[2][-1],p.DB_INODE_JS)

    def test_default_and_prefix_do_not_automatically_accept_mixed_sources(self):
        for prefix in ('','/host_mnt'):
            base,runner,_=self.fixture()
            with self.subTest(prefix=prefix), self.assertRaisesRegex(p.Refusal,'^unsafe_bind$'):
                self.verify(base,runner,prefix=prefix,policy='')
            self.assertFalse(any(call[0]=='exec' for call in runner.calls))

    def test_unknown_policy_context_and_unvalidated_daemon_refused_before_inspect(self):
        for policy in ('unknown',self.policy+'/',None):
            base,runner,_=self.fixture()
            with self.subTest(policy=policy), self.assertRaisesRegex(p.Refusal,'^unsupported_daemon_bind_source_policy$'):
                p.verify_container(runner,base.cid,base.project,base.image,base.release,'worker','',policy)
            self.assertEqual(runner.calls,[])
        for kwargs,code in (({'context':'parent-local'},'daemon_bind_policy_context_refused'),
                            ({'validated':False},'daemon_bind_policy_unvalidated')):
            base,runner,_=self.fixture(**kwargs)
            with self.assertRaisesRegex(p.Refusal,'^'+code+'$'): self.verify(base,runner)
            self.assertEqual(runner.calls,[])
        for endpoint,os_type in (('tcp://remote.invalid:2375','linux'),('unix:///pure.sock','windows')):
            base,runner,_=self.fixture(validated=False)
            with mock.patch.object(runner,'text',side_effect=[endpoint,os_type]):
                with self.assertRaises(p.Refusal): p.validate_local_daemon(runner,'desktop-linux')
            with self.assertRaisesRegex(p.Refusal,'^daemon_bind_policy_unvalidated$'): self.verify(base,runner)
            self.assertEqual(runner.calls,[])

    def test_candidates_are_exact_users_pairs_without_resolve_or_reads(self):
        release=DaemonBindTests.release
        with mock.patch.object(Path,'resolve',side_effect=AssertionError('resolve forbidden')), \
             mock.patch.object(p.os,'open',side_effect=AssertionError('read forbidden')):
            self.assertEqual(p.release_bind_candidates(release,'worker',policy=self.policy),{
                (str(release),'/opt/release'):'literal',
                ('/host_mnt'+str(release),'/opt/release'):'host-mnt',
                (str(release/'db'),'/tmp/trivy/db'):'literal',
                ('/host_mnt'+str(release/'db'),'/tmp/trivy/db'):'host-mnt'})
            for path in ('/var/release','/UsersElsewhere/pure/release','/host_mnt/Users/pure/release',
                         '/Users/pure/../release','/Users/pure','relative'):
                with self.subTest(path=path), self.assertRaises(p.Refusal):
                    p.release_bind_candidates(Path(path),'api',policy=self.policy)

    def test_alias_wrong_source_destination_suffix_and_rw_refused(self):
        release=str(DaemonBindTests.release)
        changes=[{'Source':alias+release} for alias in ('/run/desktop/mnt/host','/unknown','/host_mnt/host_mnt')]
        changes += [{'Source':prefix+release+suffix} for prefix in ('','/host_mnt')
                    for suffix in ('/','-other','/db','/../public-release','/db/..')]
        changes += [{'Source':'/Users/pure/other'},{'Destination':'/opt/release/extra'},
                    {'Destination':'/tmp/trivy/db'},{'RW':True},{'RW':0}]
        for change in changes:
            base,runner,info=self.fixture()
            next(m for m in info['Mounts'] if m['Destination']=='/opt/release').update(change)
            with self.subTest(change=change), self.assertRaisesRegex(p.Refusal,'^unsafe_bind$'):
                self.verify(base,runner)
            self.assertFalse(any(call[0]=='exec' for call in runner.calls))
        base,runner,info=self.fixture()
        next(m for m in info['Mounts'] if m['Destination']=='/tmp/trivy/db')['Source']=release
        with self.assertRaisesRegex(p.Refusal,'^unsafe_bind$'): self.verify(base,runner)

    def test_missing_extra_duplicate_and_double_alternatives_refused(self):
        for action in ('missing','extra','duplicate','double-alternative'):
            base,runner,info=self.fixture()
            mount=next(m for m in info['Mounts'] if m['Destination']=='/opt/release')
            if action=='missing': info['Mounts'].remove(mount)
            else:
                duplicate=dict(mount)
                if action=='extra': duplicate['Destination']='/baseline.ts'
                if action=='double-alternative': duplicate['Source']=str(base.release)
                info['Mounts'].append(duplicate)
            with self.subTest(action=action), self.assertRaises(p.Refusal): self.verify(base,runner)
            self.assertFalse(any(call[0]=='exec' for call in runner.calls))
        base,runner,info=self.fixture('egress')
        info['Mounts'].append({'Type':'bind','Source':str(base.release),'Destination':'/opt/release','RW':False})
        with self.assertRaisesRegex(p.Refusal,'^unsafe_bind$'): self.verify(base,runner,'egress')

    def test_no_receipt_on_qualification_signature_db_or_inode_failure(self):
        for failure in ('qualify','signature'):
            base,runner,_=self.fixture(); runner.failure=failure
            with self.subTest(failure=failure), self.assertRaises(p.Refusal): self.verify(base,runner)
        for key in p.DB:
            base,runner,_=self.fixture(); runner.verified['db'][key]='wrong'
            with self.subTest(dbField=key), self.assertRaisesRegex(p.Refusal,'^authenticated_release_mismatch$'):
                self.verify(base,runner)
        for changes in ({'resultContractVersion':1},{'kind':'unverified'},{'usableUntil':'2099-01-01'},
                        {'dbPolicy':{'version':1,'policy':p.POLICY}},
                        {'dbPolicy':{'version':2,'policy':'wrong'}},{'scannerChecked':True},{'admissionChecked':True}):
            base,runner,_=self.fixture(); runner.verified.update(changes)
            with self.subTest(changes=changes), self.assertRaises(p.Refusal): self.verify(base,runner)
        base,runner,_=self.fixture(); runner.inode='wrong-db'
        with self.assertRaisesRegex(p.Refusal,'^db_mount_identity$'): self.verify(base,runner)

    def test_receipt_discards_unapproved_fields(self):
        base,runner,_=self.fixture()
        runner.verified['unapproved']='PRIVATE_SENTINEL'
        runner.verified['dbPolicy']['unapproved']='PRIVATE_SENTINEL'
        result=self.verify(base,runner)
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result))

    def test_policy_is_execute_only_exclusive_and_pre_metadata_guarded(self):
        for mode in ('--plan','--self-test','--diagnose-build'):
            output=io.StringIO()
            with mock.patch.object(sys,'argv',['candidate',mode,'--daemon-bind-source-policy',self.policy]), \
                 mock.patch.object(p,'stable_inventory',side_effect=AssertionError('inventory forbidden')), \
                 mock.patch('sys.stdout',output):
                self.assertEqual(p.main(),1)
            self.assertEqual(json.loads(output.getvalue())['reason'],'execute_arguments_without_execute')
        with mock.patch.object(sys,'argv',['candidate','--execute','--daemon-bind-source-policy',self.policy,
                                         '--daemon-bind-source-prefix','/host_mnt']), \
             mock.patch('sys.stderr',io.StringIO()), \
             mock.patch.object(p,'stable_inventory',side_effect=AssertionError('inventory forbidden')):
            with self.assertRaises(SystemExit) as error: p.main()
            self.assertEqual(error.exception.code,2)
        proposal={'scriptSha256':'a'*64,'sourceSnapshotSha256':'b'*64}
        for changes,code in (({'daemon_bind_source_prefix':'/host_mnt'},'daemon_bind_policy_prefix_conflict'),
                             ({'docker_context':'parent-local'},'daemon_bind_policy_context_refused')):
            args=GateAndIdentityTests().args(docker_context='desktop-linux',daemon_bind_source_policy=self.policy,
                                             daemon_bind_source_prefix='')
            for key,value in changes.items(): setattr(args,key,value)
            with mock.patch.object(p,'plain_absolute',side_effect=AssertionError('metadata forbidden')):
                with self.assertRaisesRegex(p.Refusal,'^'+code+'$'): p.approve(args,proposal)
        args=GateAndIdentityTests().args(docker_context='desktop-linux',daemon_bind_source_policy=self.policy)
        with self.assertRaisesRegex(p.Refusal,'^build_only_inputs_required$'): p.approve_build(args,proposal)
        authority=p.plan({},'a'*64)['daemonBindPolicy']
        self.assertEqual(authority['allowed'],['',self.policy]); self.assertEqual(authority['default'],'')
        for key in ('exclusiveWithPrefix','requiresUnixLinuxDaemon','oneExactChoicePerDestination',
                    'authenticatedMountedBytesBeforeClaim'):
            self.assertTrue(authority[key])
        self.assertEqual(authority['optInContext'],'desktop-linux')
        self.assertEqual(authority['optInHostRoot'],'/Users/')


class ProtocolInstrumentationTests(unittest.TestCase):
    canary = 'PRIVATE_CANARY_CREDENTIAL_BODY_HEADER_EXCEPTION'

    def http_fixture(self, stage=None, error=None, raw=b'{"ok":true}', status=200, headers=None):
        test = self
        captured = []
        class Response:
            def __init__(self): self.status=status
            def getheaders(self):
                return headers if headers is not None else [('Cache-Control','no-store'),
                    ('Content-Type','application/json; charset=utf-8'),
                    ('Set-Cookie','demo_session='+test.canary),('X-Private',test.canary)]
            def read(self,bound):
                test.assertEqual(bound,2*1024**2+1)
                if stage=='response-body': raise error
                return raw
        class Connection:
            def __init__(self,*args,**kwargs): self.closed=False
            def connect(self): pass
            def request(self,*args,**kwargs):
                captured.append((args,kwargs))
                if stage=='request': raise error
            def getresponse(self):
                if stage=='response-headers': raise error
                return Response()
            def close(self): self.closed=True
        runner=argparse.Namespace(work_deadline=p.time.monotonic()+60,last_json_error_class=None)
        client=p.Http(runner); connection=Connection()
        return runner,client,connection,captured

    def invoke(self, stage=None, error=None, raw=b'{"ok":true}', status=200, headers=None):
        runner,client,connection,captured=self.http_fixture(stage,error,raw,status,headers)
        trace=p.ProtocolTrace(); trace.enter('ordinary-owner-login')
        with mock.patch.object(p.http.client,'HTTPConnection',return_value=connection) as constructor, \
             mock.patch.object(p.signal,'signal'), mock.patch.object(p.signal,'setitimer') as timer, \
             mock.patch.object(p.socket,'socket',side_effect=AssertionError('socket forbidden')), \
             mock.patch.object(p.subprocess,'Popen',side_effect=AssertionError('Docker forbidden')):
            try:
                value=client.call('POST','/api/v1/auth/login',body={'email':self.canary,'password':self.canary})
            except Exception as caught:
                trace.failed(caught,runner); value=None
        self.assertTrue(connection.closed)
        self.assertEqual(constructor.call_args.args,('127.0.0.1',p.PORT))
        self.assertEqual(constructor.call_args.kwargs,{'timeout':5})
        self.assertEqual(timer.call_args_list,[mock.call(p.signal.ITIMER_REAL,5),mock.call(p.signal.ITIMER_REAL,0)])
        record=trace.snapshot(client)
        self.assertLessEqual(len(p.canonical(record)),1024)
        self.assertNotIn(self.canary,json.dumps(record))
        return record,value,captured

    def test_http_transport_failures_have_exact_stage_without_messages(self):
        for stage,error,label in (
            ('request',TimeoutError(self.canary),'http_timeout'),
            ('response-headers',p.http.client.RemoteDisconnected(self.canary),'http_disconnected'),
            ('response-body',ConnectionResetError(self.canary),'connection_reset'),
            ('response-body',p.http.client.IncompleteRead(self.canary.encode(),100),'other_protocol_error'),
        ):
            with self.subTest(stage=stage,label=label):
                record,_,captured=self.invoke(stage,error)
                self.assertEqual(record['exceptionClass'],label)
                self.assertEqual(record['lastHttp']['stage'],stage)
                self.assertEqual(record['httpCalls'],1); self.assertEqual(len(captured),1)
                self.assertIsNone(record['lastHttp']['responseBytes'])
                self.assertEqual(record['lastHttp']['status'],200 if stage=='response-body' else None)

    def test_http_json_decode_and_unicode_failures_are_distinct(self):
        for raw,label in ((b'{'+self.canary.encode(),'json_decode_error'),
                          (b'\xff'+self.canary.encode(),'unicode_decode_error')):
            record,_,_=self.invoke(raw=raw)
            self.assertEqual(record['exceptionClass'],label)
            self.assertEqual(record['lastHttp'],{'stage':'json-decode','status':200,'responseBytes':len(raw),
                                                'noStore':True,'jsonContentType':True,'cookiePresent':True})

    def test_http_success_empty_body_and_overflow_keep_contract_and_cap(self):
        record,value,captured=self.invoke(raw=b'{"value":"'+self.canary.encode()+b'"}')
        self.assertEqual(value[2],{'value':self.canary}); self.assertIsNone(record['exceptionClass'])
        self.assertEqual(record['lastHttp']['stage'],'complete')
        self.assertEqual(captured[0][0],('POST','/api/v1/auth/login'))
        self.assertEqual(captured[0][1]['headers'],{'Origin':p.ORIGIN,'Content-Type':'application/json'})
        record,value,_=self.invoke(raw=b'')
        self.assertIsNone(value[2]); self.assertEqual(record['lastHttp']['responseBytes'],0)
        record,value,_=self.invoke(raw=b'x'*(2*1024**2+1))
        self.assertIsNone(value); self.assertEqual(record['lastHttp']['stage'],'response-body')
        self.assertEqual(record['lastHttp']['responseBytes'],2*1024**2+1)
        record,_,_=self.invoke(headers=[('Cache-Control',self.canary),('Content-Type',self.canary)])
        self.assertFalse(record['lastHttp']['noStore']); self.assertFalse(record['lastHttp']['jsonContentType'])
        self.assertFalse(record['lastHttp']['cookiePresent'])

    def test_readiness_shape_refusal_is_distinct_from_command_json_decode(self):
        with mock.patch.dict(p.os.environ,{'PATH':'pure','HOME':'/pure'},clear=True): runner=p.Runner('pure',0)
        for raw,code,shape in ((b'{'+self.canary.encode(),'json_decode_error',None),
                               (b'\xff'+self.canary.encode(),'unicode_decode_error',None),
                               (b'null','other_protocol_error',False),
                               (b'{}','other_protocol_error',False),
                               (b'{"ready":"'+self.canary.encode()+b'"}','other_protocol_error',False)):
            trace=p.ProtocolTrace(); trace.enter('chain-readiness')
            with mock.patch.object(runner,'run',return_value=(raw,0)):
                with self.assertRaises(p.Refusal) as caught:
                    trace.readiness(lambda:runner.json(['pure-readiness']))
                trace.failed(caught.exception,runner)
            record=trace.snapshot(None)
            self.assertEqual(record['subphase'],'chain-readiness'); self.assertEqual(record['readinessAttempts'],1)
            self.assertIs(record['readinessShapeValid'],shape); self.assertEqual(record['exceptionClass'],code)
            self.assertEqual(record['httpCalls'],0); self.assertIsNone(record['lastHttp'])
            self.assertNotIn(self.canary,json.dumps(record))
        with mock.patch.object(runner,'run',return_value=(b'{"ready":true}',0)):
            self.assertEqual(runner.json(['pure-readiness']),{'ready':True})
        self.assertIsNone(runner.last_json_error_class)

    def test_readiness_exact_booleans_and_existing_twenty_attempt_limit(self):
        trace=p.ProtocolTrace()
        self.assertTrue(trace.readiness(lambda:{'ready':True}))
        for _ in range(19): self.assertFalse(trace.readiness(lambda:{'ready':False}))
        query=mock.Mock(return_value={'ready':True})
        with self.assertRaisesRegex(p.Refusal,'^readiness_attempt_bound$'): trace.readiness(query)
        query.assert_not_called()
        for value in ({'ready':1},{'ready':0},{'ready':None},{'ready':True,'private':self.canary},[True],True):
            with self.subTest(valueType=type(value).__name__), self.assertRaisesRegex(p.Refusal,'^invalid_readiness_shape$'):
                p.ProtocolTrace().readiness(lambda:value)

    def test_exception_allowlist_never_uses_message_args_or_raw_class_name(self):
        class PRIVATE_CANARY_CLASS(Exception):
            def __str__(self): raise AssertionError('message must not be accessed')
        pairs=((TimeoutError(self.canary),'http_timeout'),
               (p.http.client.RemoteDisconnected(self.canary),'http_disconnected'),
               (ConnectionResetError(self.canary),'connection_reset'),
               (json.JSONDecodeError(self.canary,self.canary,0),'json_decode_error'),
               (UnicodeDecodeError('utf8',b'\xff',0,1,self.canary),'unicode_decode_error'),
               (KeyError(self.canary),'missing_key'),(TypeError(self.canary),'type_error'),
               (ValueError(self.canary),'value_error'),(OSError(self.canary),'os_error'),
               (p.subprocess.SubprocessError(self.canary),'subprocess_error'),
               (PRIVATE_CANARY_CLASS(self.canary),'other_protocol_error'))
        self.assertEqual({label for _,label in pairs},set(p.PROTOCOL_EXCEPTION_CLASSES))
        for error,label in pairs:
            self.assertEqual(p.protocol_exception_class(error),label)

    def test_diagnostic_has_fixed_schema_and_rejects_arbitrary_values(self):
        self.assertEqual(p.PROTOCOL_DIAGNOSTIC_CAP,1024)
        self.assertEqual(p.PROTOCOL_SUBPHASES,('isolation-qualification','chain-readiness','ingress-qualification',
                         'ingress-host-readiness','ingress-recreated-readiness','ordinary-owner-login',
                         'ordinary-foreign-login','ordinary-unlisted-login','image-eligibility','observer-start','actual-http-combined'))
        trace=p.ProtocolTrace()
        with self.assertRaisesRegex(p.Refusal,'^unsafe_protocol_subphase$'): trace.enter(self.canary)
        client=argparse.Namespace(count=65535,last={'stage':'complete','status':599,'responseBytes':2*1024**2+1,
                                                   'noStore':True,'jsonContentType':True,'cookiePresent':True})
        trace.enter('ordinary-unlisted-login'); trace.failed(KeyError(self.canary),None)
        self.assertLessEqual(len(p.canonical(trace.snapshot(client))),1024)
        for field in client.last:
            bad=argparse.Namespace(count=1,last={**client.last,field:self.canary})
            with self.subTest(field=field), self.assertRaisesRegex(p.Refusal,'^unsafe_protocol_diagnostic$'):
                trace.snapshot(bad)
        client.last['rawBody']=self.canary
        with self.assertRaisesRegex(p.Refusal,'^unsafe_protocol_diagnostic$'): trace.snapshot(client)

    def test_execute_seals_failure_progress_after_qualification_without_runtime_io(self):
        for failure,label,subphase,stage in (
            ('readiness-shape','other_protocol_error','chain-readiness',None),
            ('http-timeout','http_timeout','ingress-host-readiness','request'),
            ('http-json','json_decode_error','ingress-host-readiness','json-decode'),
        ):
            project='dip-cve14-proof-'+'a'*16; image='sha256:'+'c'*64; gateway='sha256:'+'d'*64
            operations,packets=[],[]
            class FakeRunner:
                def __init__(self,*args):
                    self.calls=0; self.last_build_diagnostics=None; self.last_json_error_class=None
                    self.work_deadline=p.time.monotonic()+535
                def run(self,args,**kwargs): operations.append(args); self.calls+=1; return b'',0
                def build(self,*args): operations.append(['build']); self.calls+=1
                def text(self,args,**kwargs):
                    operations.append(args); self.calls+=1
                    if args[0]=='image': return p.WORKER if args[-1].startswith('dip-cve14-base-') else image
                    return 'e'*64
                def json(self,args,**kwargs):
                    operations.append(args); self.calls+=1
                    if args[0]=='image':
                        if args[-1]==p.WORKER:
                            return [{'Id':p.WORKER,'Os':'linux','Architecture':'arm64','Config':{'Env':[]}}]
                        if args[-1]==gateway:
                            return [{'Id':gateway,'Os':'linux','Architecture':'arm64','Config':{'Env':[],
                                     'Cmd':['python','-I','proxy.py'],'WorkingDir':'/opt/gateway','User':'65532:65532'}}]
                        if args[-1]==p.INGRESS:
                            return [{'Id':p.INGRESS,'Os':'linux','Architecture':'arm64',
                                     'Config':{'User':'101:101','Env':[]}}]
                        return [{'Os':'linux','Architecture':'arm64'}]
                    if args[0]=='run': return {'proxySha256':'f'*64}
                    if args[0]=='exec': return None if failure=='readiness-shape' else {'ready':True}
                    if 'config' in args:
                        return {'name':project,'volumes':{'auth_accounts':{},'scan_ledger':{}},
                                'networks':{'scan_internal':{'internal':True},'auth_internal':{'internal':True}},
                                'services':{role:{'image':gateway if role=='egress' else image}
                                            for role in ('api','worker','egress','auth-volume-init','scan-volume-init')}}
                    return {'ids':['1'*32,'2'*32,'3'*32]}
            _,_,connection,_=self.http_fixture('request' if failure=='http-timeout' else None,
                                              TimeoutError(self.canary),raw=b'{'+self.canary.encode())
            def capture(path,data):
                if path.name=='sanitized-evidence.json': packets.append(json.loads(data))
            args=argparse.Namespace(docker_context='desktop-linux',gateway_image=gateway,
                                    ingress_image=p.INGRESS,daemon_bind_source_prefix='/host_mnt')
            proposal={'scriptSha256':'a'*64,'sourceSnapshotSha256':'b'*64,'limitations':['pure-only']}
            output=io.StringIO()
            with mock.patch.object(p,'approve',return_value=(Path('/pure-release'),Path('/pure-scratch'))), \
                 mock.patch.object(p,'Runner',FakeRunner), mock.patch.object(p,'validate_local_daemon'), \
                 mock.patch.object(p,'require_empty_namespace'), mock.patch.object(p.secrets,'token_hex',side_effect=lambda n:'a'*(2*n)), \
                 mock.patch.object(p,'make_context',return_value=(Path('/pure-context'),'f'*64)), \
                 mock.patch.object(p,'dockerfile',return_value='pure Dockerfile'), mock.patch.object(p,'write_new',side_effect=capture), \
                 mock.patch.object(Path,'mkdir'), mock.patch.object(Path,'write_bytes'), mock.patch.object(Path,'chmod'), \
                 mock.patch.object(p.socket,'socket'), mock.patch.object(p.subprocess,'Popen',side_effect=AssertionError('Docker forbidden')), \
                 mock.patch.object(p,'owned_resources',return_value={'containers':[],'networks':[],'volumes':[]}), \
                 mock.patch.multiple(p,verify_container=mock.Mock(side_effect=lambda *a:{'sourceQualification':{'files':238}}),
                     verify_ingress_topology=mock.Mock(return_value='explicit-false'),require_resource_counts=mock.Mock(),
                     ingress_public_copy=mock.Mock(return_value=Path('/Users/pure/public-stand.nginx.conf')),
                     verify_web_container=mock.Mock(return_value={'pure':True})), \
                 mock.patch.object(p,'cleanup_owned',return_value=({'failures':[],'retainedOnFailure':True},{})), \
                 mock.patch.object(p.http.client,'HTTPConnection',return_value=connection), \
                 mock.patch.object(p.signal,'signal'), mock.patch.object(p.signal,'setitimer'), mock.patch('sys.stdout',output):
                self.assertEqual(p.execute(args,{('server/deploy/'+name):b'pure' for name in p.BASES},
                                           {'server/deploy/gateway/proxy.py':'f'*64,p.INGRESS_CONFIG:p.INGRESS_CONFIG_SHA},proposal,{}),1)
            self.assertEqual(len(packets),1); payload=packets[0]['payload']; record=payload['protocolDiagnostics']
            self.assertFalse(payload['passed']); self.assertEqual(payload['phase'],'isolated-startup')
            self.assertEqual(record['exceptionClass'],label); self.assertEqual(record['subphase'],subphase)
            self.assertEqual(record['readinessAttempts'],1); self.assertLessEqual(len(p.canonical(record)),1024)
            self.assertEqual(payload['httpCalls'],0 if stage is None else 1)
            if stage: self.assertEqual(record['lastHttp']['stage'],stage)
            else: self.assertIsNone(record['lastHttp'])
            self.assertEqual(set(payload['sourceQualification']),{'api','worker'})
            self.assertNotIn(self.canary,json.dumps(packets)); self.assertNotIn(self.canary,output.getvalue())
            self.assertFalse(any('/proof/observe.mjs' in operation for operation in operations))
            self.assertEqual(p.sha(p.canonical(payload)),packets[0]['payloadCanonicalSha256'])

    def test_execute_trace_is_before_operations_and_snapshot_after_cleanup(self):
        source=inspect.getsource(p.execute)
        for label,operation in (
            ('isolation-qualification',"evidence['isolation']"),
            ('chain-readiness','for _ in range(20)'),
            ('ordinary-owner-login','owner = http.login(accounts[0])'),
            ('ordinary-foreign-login','foreign = http.login(accounts[1])'),
            ('ordinary-unlisted-login','unlisted = http.login(accounts[2])'),
            ('image-eligibility',"eligibility = http.call("),
            ('observer-start',"runner.run(['exec','-d'"),
            ('actual-http-combined',"status,_,receipt_http = http.call("),
        ):
            self.assertLess(source.index("trace.enter('"+label+"')"),source.index(operation))
        self.assertLess(source.index('cleanup_owned('),source.index('trace.snapshot(http)'))
        self.assertLess(source.index('trace.snapshot(http)'),source.index('seal = sha(canonical(evidence))'))
        self.assertIn("evidence['httpCalls'] = http.count if http else 0",source)
        self.assertIn('subprocess.SubprocessError,HTTPException)',source)
        self.assertIn('trace.failed(error,runner)',source)
        self.assertIn('time.sleep(0.5)',source)
        self.assertEqual(p.plan({},'a'*64)['protocolDiagnostic']['outputBytes'],1024)


class HttpOperationDiagnosticTests(unittest.TestCase):
    canary = 'PRIVATE_CANARY_OPERATION_ERRNO_BODY_HEADER'

    def run_case(self, failures=None, raw=b'{}'):
        failures = failures or {}; events = []
        def step(operation, result=None):
            events.append(operation)
            if operation in failures: raise failures[operation]
            return result
        response=mock.Mock(status=200)
        response.getheaders.return_value=[('Cache-Control','no-store'),('Content-Type','application/json'),
                                          ('Set-Cookie','demo_session='+'A'*43),('X-Private',self.canary)]
        response.read.side_effect=lambda bound:step('response-body',raw)
        connection=mock.Mock()
        connection.connect.side_effect=lambda:step('connection-connect')
        connection.request.side_effect=lambda *a,**kw:step('request-send')
        connection.getresponse.side_effect=lambda:step('response-headers',response)
        connection.close.side_effect=lambda:step('connection-close')
        def handler(_signal,value):
            return step('signal-restore' if value==p.signal.SIG_DFL else 'signal-install')
        def timer(_timer,value): return step('timer-disarm' if value==0 else 'timer-arm')
        client=p.Http(argparse.Namespace(work_deadline=p.time.monotonic()+30))
        error=result=None; trace=p.ProtocolTrace(); trace.enter('ordinary-owner-login')
        with mock.patch.object(p.http.client,'HTTPConnection',side_effect=lambda *a,**kw:step('connection-create',connection)), \
             mock.patch.object(p.signal,'getsignal',side_effect=lambda *a:step('signal-read',p.signal.SIG_DFL)), \
             mock.patch.object(p.signal,'signal',side_effect=handler) as signal_mock, \
             mock.patch.object(p.signal,'setitimer',side_effect=timer) as timer_mock, \
             mock.patch.object(p.socket,'socket',side_effect=AssertionError('network forbidden')), \
             mock.patch.object(p.socket,'create_connection',side_effect=AssertionError('network forbidden')), \
             mock.patch.object(p.subprocess,'Popen',side_effect=AssertionError('Docker forbidden')):
            try: result=client.call('POST','/api/v1/auth/login',body={'email':self.canary,'password':self.canary})
            except BaseException as caught: error=caught; trace.failed(caught,None)
        if response.read.called: response.read.assert_called_once_with(2*1024**2+1)
        record=trace.snapshot(client)
        self.assertLessEqual(len(p.canonical(record)),1024)
        self.assertNotIn(self.canary,json.dumps(record))
        return client,record,error,result,events,connection,signal_mock,timer_mock

    def test_primary_operation_and_four_errno_classes(self):
        operations=('connection-create','signal-read','signal-install','timer-arm','connection-connect',
                    'request-send','response-headers','response-body')
        for operation in operations:
            for label in p.HTTP_ERRNO_CLASSES:
                original=OSError(getattr(p.errno,label),self.canary)
                with self.subTest(operation=operation,label=label):
                    client,record,error,_,events,connection,_,_=self.run_case({operation:original})
                    self.assertIs(error,original)
                    self.assertEqual(record['httpPrimaryFailure'],{
                        'operation':operation,'exceptionClass':'os_error','errnoClass':label})
                    self.assertEqual(record['httpOperation'],operation)
                    self.assertEqual(record['httpCleanupFailures'],[])
                    self.assertLessEqual(connection.connect.call_count,1)
                    if operation=='connection-connect': self.assertNotIn('request-send',events)
        _,record,error,_,_,_,_,_=self.run_case(raw=b'{'+self.canary.encode())
        self.assertIsInstance(error,json.JSONDecodeError)
        self.assertEqual(record['httpPrimaryFailure'],{
            'operation':'json-decode','exceptionClass':'json_decode_error','errnoClass':None})

    def test_unknown_errno_and_messages_never_escape(self):
        class CanaryError(Exception):
            def __str__(self): raise AssertionError('message forbidden')
        for original in (OSError(987654,self.canary),OSError(self.canary),CanaryError()):
            _,record,error,_,_,_,_,_=self.run_case({'connection-connect':original})
            self.assertIs(error,original); self.assertIsNone(record['httpPrimaryFailure']['errnoClass'])
            self.assertNotIn('987654',json.dumps(record)); self.assertNotIn('CanaryError',json.dumps(record))

    def test_cleanup_failures_preserve_first_primary_and_attempt_close(self):
        for operation in p.HTTP_CLEANUP_OPERATIONS:
            original=OSError(p.errno.EPERM,self.canary); cleanup=OSError(p.errno.EINVAL,self.canary)
            client,record,error,_,events,connection,signal_mock,_=self.run_case({
                'request-send':original,operation:cleanup})
            self.assertIs(error,original); self.assertTrue(client.cleanup_failed)
            self.assertEqual(record['httpPrimaryFailure']['operation'],'request-send')
            self.assertEqual(record['httpPrimaryFailure']['errnoClass'],'EPERM')
            self.assertEqual(record['httpCleanupFailures'],[{
                'operation':operation,'exceptionClass':'os_error','errnoClass':'EINVAL'}])
            self.assertEqual(connection.close.call_count,1)
            if operation=='timer-disarm':
                self.assertNotIn('signal-restore',events); self.assertEqual(signal_mock.call_count,1)
            with mock.patch.object(p.http.client,'HTTPConnection',side_effect=AssertionError('retry forbidden')):
                with self.assertRaisesRegex(p.Refusal,'^http_cleanup_failed$'): client.call('GET','/api/v1/auth/me')
            self.assertEqual(client.primary_failure,record['httpPrimaryFailure'])
        original=OSError(p.errno.EACCES,self.canary)
        _,record,error,_,events,_,_,_=self.run_case({'request-send':original,
            'timer-disarm':OSError(p.errno.EINVAL,self.canary),'connection-close':OSError(p.errno.EPERM,self.canary)})
        self.assertIs(error,original); self.assertEqual(len(record['httpCleanupFailures']),2)
        self.assertNotIn('signal-restore',events)

    def test_cleanup_only_failure_is_fail_closed_not_success(self):
        for operation in p.HTTP_CLEANUP_OPERATIONS:
            _,record,error,result,events,connection,_,_=self.run_case({operation:OSError(p.errno.EINVAL,self.canary)})
            self.assertIsInstance(error,p.Refusal); self.assertEqual(str(error),'http_cleanup_failed')
            self.assertIsNone(result); self.assertIsNone(record['httpPrimaryFailure'])
            self.assertEqual(record['lastHttp']['stage'],'complete')
            self.assertEqual(record['httpCleanupFailures'][0]['operation'],operation)
            self.assertEqual(connection.close.call_count,1)
            if operation=='timer-disarm': self.assertNotIn('signal-restore',events)

    def test_partial_setup_uses_verified_state_guards(self):
        for operation in ('connection-create','signal-read','signal-install','timer-arm'):
            _,_,_,_,events,connection,signal_mock,timer_mock=self.run_case({operation:OSError(p.errno.EINVAL,self.canary)})
            self.assertEqual(connection.close.call_count,0 if operation=='connection-create' else 1)
            if operation!='timer-arm':
                self.assertNotIn('timer-disarm',events); self.assertNotIn('signal-restore',events)
            else:
                self.assertEqual(events[-3:],['timer-disarm','signal-restore','connection-close'])
                self.assertEqual(signal_mock.call_count,2); self.assertEqual(timer_mock.call_count,2)

    def test_success_keeps_bounds_one_connect_and_no_retry(self):
        client,record,error,result,events,connection,_,timer=self.run_case()
        self.assertIsNone(error); self.assertEqual(result[0],200)
        self.assertEqual(client.count,1); self.assertFalse(client.cleanup_failed)
        self.assertEqual(connection.connect.call_count,1); self.assertEqual(connection.request.call_count,1)
        self.assertLess(events.index('connection-connect'),events.index('request-send'))
        self.assertEqual(timer.call_args_list,[mock.call(p.signal.ITIMER_REAL,5),mock.call(p.signal.ITIMER_REAL,0)])

        self.assertEqual(record['httpCleanupFailures'],[])
        self.assertEqual((p.TOTAL_SECONDS,p.WORK_SECONDS,p.PROTOCOL_DIAGNOSTIC_CAP),(600,535,1024))

    def test_schema_maximum_three_rows_and_canary_rejection(self):
        client=p.Http(argparse.Namespace(work_deadline=0)); client.count=65535
        client.last={'stage':'response-headers','status':599,'responseBytes':2*1024**2+1,
                     'noStore':False,'jsonContentType':False,'cookiePresent':False}
        client.operation='response-headers'
        client.primary_failure=p.http_failure_record('response-headers',ConnectionResetError(p.errno.EACCES,self.canary))
        client.cleanup_failures=[p.http_failure_record(op,ConnectionResetError(p.errno.ECONNREFUSED,self.canary))
                                 for op in p.HTTP_CLEANUP_OPERATIONS]
        trace=p.ProtocolTrace(); trace.enter('ordinary-unlisted-login'); trace.readiness_attempts=20
        trace.readiness_shape_valid=False; trace.failed(ConnectionResetError(),None)
        self.assertLessEqual(len(p.canonical(trace.snapshot(client))),1024)
        for row in [client.primary_failure,*client.cleanup_failures]:
            for key in row:
                old=row[key]; row[key]=self.canary
                with self.assertRaisesRegex(p.Refusal,'^unsafe_protocol_diagnostic$'): trace.snapshot(client)
                row[key]=old
        client.cleanup_failures.append(dict(client.cleanup_failures[0]))
        with self.assertRaisesRegex(p.Refusal,'^unsafe_protocol_diagnostic$'): trace.snapshot(client)
        client.cleanup_failures.pop(); client.cleanup_failures[1]=dict(client.cleanup_failures[0])
        with self.assertRaisesRegex(p.Refusal,'^unsafe_protocol_diagnostic$'): trace.snapshot(client)

    def test_real_http_connection_framing_with_fake_socket(self):
        class Sink:
            def __init__(self): self.sent=[]; self.closed=False
            def setsockopt(self,*args): pass
            def sendall(self,data): self.sent.append(bytes(data))
            def makefile(self,*args):
                return io.BytesIO(b'HTTP/1.1 200 OK\r\nCache-Control: no-store\r\nContent-Type: application/json\r\n'
                    b'Content-Length: 2\r\nSet-Cookie: demo_session='+b'A'*43+b'; HttpOnly; SameSite=Lax; Path=/\r\n\r\n{}')
            def close(self): self.closed=True
        sink=Sink(); account={'email':'pure@qualification.invalid','password':self.canary}
        client=p.Http(argparse.Namespace(work_deadline=p.time.monotonic()+30))
        with mock.patch.object(p.socket,'create_connection',return_value=sink) as connect, \
             mock.patch.object(p.socket,'socket',side_effect=AssertionError('network forbidden')), \
             mock.patch.object(p.subprocess,'Popen',side_effect=AssertionError('Docker forbidden')), \
             mock.patch.object(p.signal,'getsignal',return_value=p.signal.SIG_DFL), \
             mock.patch.object(p.signal,'signal'), mock.patch.object(p.signal,'setitimer'):
            self.assertEqual(client.login(account),'demo_session='+'A'*43)
        connect.assert_called_once_with(('127.0.0.1',18083),5,None)
        headers,body=b''.join(sink.sent).split(b'\r\n\r\n',1)
        self.assertEqual(headers.split(b'\r\n')[0],b'POST /api/v1/auth/login HTTP/1.1')
        for header in (b'Host: 127.0.0.1:18083',b'Origin: http://127.0.0.1:18083',
                       b'Content-Type: application/json',b'Content-Length: '+str(len(body)).encode()):
            self.assertIn(b'\r\n'+header+b'\r\n',headers+b'\r\n')
        self.assertEqual(body,p.canonical(account)); self.assertLessEqual(len(body),512); self.assertTrue(sink.closed)
        self.assertNotIn(self.canary,json.dumps(p.ProtocolTrace().snapshot(client)))


class GateAndIdentityTests(unittest.TestCase):
    def args(self,**changes):
        values = dict(reviewed_script_sha256='a'*64,reviewed_source_sha256='b'*64,
                      docker_context='parent-local',gateway_image=None,release_dir=None,scratch_dir='/pure-new-scratch')
        values.update(changes)
        return argparse.Namespace(**values)

    def test_build_hash_gate_precedes_metadata_and_docker(self):
        proposal = {'scriptSha256':'a'*64,'sourceSnapshotSha256':'b'*64}
        for changes,code in (({'reviewed_script_sha256':'wrong'},'script_not_approved'),
                             ({'reviewed_source_sha256':'wrong'},'source_not_approved'),
                             ({'release_dir':'/private'},'build_only_inputs_required'),
                             ({'gateway_image':'sha256:'+'c'*64},'build_only_inputs_required'),
                             ({'ingress_image':p.INGRESS},'build_only_inputs_required')):
            with mock.patch.object(p,'plain_absolute',side_effect=AssertionError('metadata forbidden')), \
                 mock.patch.object(p,'Runner',side_effect=AssertionError('Docker forbidden')):
                with self.assertRaisesRegex(p.Refusal,'^'+code+'$'):
                    p.diagnose_build(self.args(**changes),{},{},proposal,{})

    def test_build_only_control_flow_never_runs_or_composes(self):
        proposal = {'scriptSha256':'a'*64,'sourceSnapshotSha256':'b'*64}
        cached = {'Id':p.WORKER,'Os':'linux','Architecture':'arm64',
                  'Config':{'Entrypoint':['docker-entrypoint.sh'],'Env':[]}}
        image = 'sha256:'+'c'*64
        calls, packets = [], []
        class FakeRunner:
            def __init__(self,*args): self.calls=0; self.last_build_diagnostics=None
            def text(self,args,**kwargs):
                calls.append(args); self.calls+=1
                if args[0]=='context': return 'unix:///pure-context.sock'
                if args[0]=='info': return 'linux'
                return p.WORKER if args[-1].startswith('dip-cve14-diag-base-') else image
            def json(self,args,**kwargs):
                calls.append(args); self.calls+=1
                return [cached] if args[-1]==p.WORKER else [{'Os':'linux','Architecture':'arm64'}]
            def run(self,args,**kwargs): calls.append(args); self.calls+=1; return b'',0
            def build(self,*args):
                calls.append(['build']); self.calls+=1
                self.last_build_diagnostics=p.build_diagnostics(b'',b'',(),0)
        with mock.patch.object(p,'approve_build',return_value=Path('/pure-new-scratch')), \
             mock.patch.object(p,'Runner',FakeRunner), mock.patch.object(Path,'mkdir'), \
             mock.patch.object(p,'make_context',return_value=(Path('/pure-context'),'d'*64)), \
             mock.patch.object(p,'write_new',side_effect=lambda path,data: packets.append(json.loads(data))), \
             mock.patch('builtins.print'), mock.patch.object(p.socket,'socket',side_effect=AssertionError('socket forbidden')):
            self.assertEqual(p.diagnose_build(self.args(),{},dict.fromkeys(p.INPUTS,'e'*64),proposal,{}),0)
        self.assertEqual({args[0] for args in calls},{'context','info','image','build'})
        self.assertTrue(all(args[1] in ('inspect','tag') for args in calls if args[0]=='image'))
        self.assertEqual(len(packets),1)
        self.assertTrue(packets[0]['payload']['passed'])
        self.assertFalse(packets[0]['payload']['runtimeProofExecuted'])
        self.assertFalse(packets[0]['payload']['wholeAcceptance'])
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(packets))

    def test_pure_self_test_never_touches_runtime(self):
        with mock.patch.object(p.subprocess,'Popen',side_effect=AssertionError('subprocess forbidden')), \
             mock.patch.object(p.socket,'socket',side_effect=AssertionError('socket forbidden')), \
             mock.patch.object(p,'write_new',side_effect=AssertionError('write forbidden')):
            self.assertTrue(p.self_test()['passed'])

    def test_signed_db_and_policy_entire_identity_unchanged(self):
        self.assertEqual(p.DB,{
            'envelopeVersion':1,'signer':'local-db-operator-v1','schemaVersion':2,
            'manifestDigest':'sha256:a7ace06d6bb43a23fab1b9cae2a02c0b3e856006f2de75bb0c9661e655e3b74e',
            'source':'ghcr.io/aquasecurity/trivy-db@sha256:a7ace06d6bb43a23fab1b9cae2a02c0b3e856006f2de75bb0c9661e655e3b74e',
            'artifactSha256':'d1a4a72fd13d091df875e820112ea147d70e996e1017ef5c8ff434ac7c0c454d',
            'dbSha256':'5f4b978a55284b1997dc31e9f2fc3f4f1abae80829f51451ade221d5675a69b9',
            'metadataSha256':'733145f3bb63cfec2634cff132ab55dd2918ef0387c1b62366908a8571119c4c',
            'updatedAt':'2026-10-07T07:38:55.515026687Z','downloadedAt':'2026-10-07T08:02:58.068983Z',
            'nextUpdate':'2026-10-08T07:38:55.515026457Z'})
        self.assertEqual(p.POLICY,'cve-db-updated-at-14d-v2')
        self.assertEqual(p.UNTIL,'2026-10-21T07:38:55.515026687Z')
        self.assertEqual(p.PEM_SHA,'052573290dfffd8b79af351845ccdecf8846df17afa98e2f6fa5600ccbf4f6e6')
        self.assertEqual(p.SPKI_SHA,'d75c6f6b2384de68978090fc837387ab4f3e878ee004bccf27ea98a84fbee078')
        self.assertEqual(p.WORKER,'sha256:8748cbebba753603d79f320c2fb476c46ab676ce12e0aa08bee0021a3e14e57a')
        self.assertEqual(p.TARGET['digest'],'sha256:0dcc88822d45581e65ae329f8be769762bf628d3b2bb7d2a077d4aa5c98b30e3')
        self.assertEqual(p.TARGET['configDigest'],'sha256:dc73b49f5124cf2ee538dfbdfbd121f0b4ccdcb20fea30f3a81bd477c02e2bb5')
        self.assertEqual(p.TARGET['platform'],'linux/amd64')
        self.assertEqual((p.TOTAL_SECONDS,p.WORK_SECONDS),(600,535))
        self.assertEqual(p.OFF,{'LLM_ENABLED':'false','LLM_ROUTING_APPROVED':'false',
                               'LLM_QUOTA_ENABLED':'false','LLM_HISTORY_ENABLED':'false'})
        self.assertEqual(p.PROOFS,{
            'server/deploy/proof/cve-advisory-evidence.json':'60cabda3a67bcaf706b49b9cff786649ae8b338f1267b7762b41bca84f034567',
            'server/deploy/proof/nginx-local-evidence.json':'cd14137e36a853f6870060f88dca96416fcb8f8071f4a8b01a35d23c1134fcb9'})


class IngressRepairTests(unittest.TestCase):
    project = 'dip-cve14-proof-'+'a'*16
    cid = 'b'*64
    config_path = Path('/Users/pure/run/public-stand.nginx.conf')
    canary = 'PRIVATE_INGRESS_CANARY'

    def fixture(self, source_prefix=''):
        labels = {'com.docker.compose.project':self.project,'com.docker.compose.service':'web'}
        info = {'Id':self.cid,'Image':p.INGRESS,'Name':'/'+self.project+'-web-1',
                'Config':{'Labels':labels,'User':'101:101','Entrypoint':['nginx'],
                          'Cmd':['-g','daemon off;'],'Env':['NGINX_VERSION=1.27.5','PATH=/usr/bin:/bin']},
                'HostConfig':{'ReadonlyRootfs':True,'CapDrop':['ALL'],'CapAdd':None,
                              'SecurityOpt':['no-new-privileges:true'],'Privileged':False,'PidMode':'',
                              'IpcMode':'private','Memory':268435456,'MemorySwap':268435456,
                              'NanoCpus':1000000000,'PidsLimit':128,'Tmpfs':{'/tmp':p.INGRESS_TMPFS},
                              'PortBindings':{'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':'18083'}]}},
                'Mounts':[{'Type':'bind','Source':source_prefix+str(self.config_path),
                           'Destination':p.INGRESS_DEST,'RW':False}],
                'NetworkSettings':{'Networks':{self.project+'_'+n:{'NetworkID':n}
                                              for n in ('auth_internal','web_edge')}}}
        test = self
        class FakeRunner:
            docker = ['docker','--context','desktop-linux']
            local_daemon_validated = True
            def __init__(self): self.calls=[]; self.digest=p.INGRESS_CONFIG_SHA; self.native_ok=True
            def json(self,args,**kw):
                self.calls.append(args)
                if args[:2]==['container','inspect']: return [info]
                test.assertEqual(args[:2],['network','inspect'])
                name=args[-1]
                return [{'Labels':labels,'Name':test.project+'_'+name,'Internal':name=='auth_internal'}]
            def text(self,args,**kw):
                self.calls.append(args)
                test.assertEqual(args,['exec',test.cid,'sha256sum',p.INGRESS_DEST])
                test.assertEqual(kw,{'seconds':5,'cap':256})
                return self.digest+'  '+p.INGRESS_DEST
            def nginx(self,cid,kind):
                self.calls.append(['native',kind]); test.assertEqual(cid,test.cid)
                return {'status':'qualified' if self.native_ok else 'refused','rawOutputIncluded':False}
        return FakeRunner(),info

    def verify(self,runner,prefix='',policy=''):
        return p.verify_web_container(runner,self.cid,self.project,self.config_path,p.INGRESS_CONFIG_SHA,prefix,policy)

    def topology(self):
        image,gateway='sha256:'+'c'*64,'sha256:'+'d'*64
        services=json.loads(p.overlay(image,gateway,[],ingress_config=self.config_path))['services']
        for role,names in {'api':['auth_internal','scan_internal'],'worker':['scan_internal'],
                           'egress':['scan_internal','registry_uplink'],'web':['auth_internal','web_edge']}.items():
            services[role]['networks']=dict.fromkeys(names,{})
        web=services['web']
        web.update(ports=[{'host_ip':'127.0.0.1','target':8080,'published':'18083','protocol':'tcp','mode':'ingress'}],
                   tmpfs=['/tmp:'+p.INGRESS_TMPFS],mem_limit=268435456,memswap_limit=268435456,
                   security_opt=['no-new-privileges:true'])
        return {'name':self.project,'services':services,
                'volumes':{n:{'name':self.project+'_'+n} for n in ('auth_accounts','scan_ledger')},
                'networks':{n:{'name':self.project+'_'+n,'internal':n in ('auth_internal','scan_internal')}
                            for n in ('auth_internal','scan_internal','registry_uplink','web_edge')}},image,gateway

    def verify_topology(self,topology,image,gateway):
        generated=p.overlay(image,gateway,[],ingress_config=self.config_path)
        with mock.patch.object(p,'plain_absolute',return_value=self.config_path), \
             mock.patch.object(Path,'lstat',return_value=argparse.Namespace(st_mode=p.stat.S_IFREG|0o444)):
            return p.verify_ingress_topology(topology,self.project,image,gateway,self.config_path,
                                            generated_overlay=generated)

    def test_public_inventory_pin_copy_and_api_context_are_disjoint(self):
        with mock.patch.object(p.subprocess,'Popen',side_effect=AssertionError('Docker forbidden')), \
             mock.patch.object(p.socket,'socket',side_effect=AssertionError('socket forbidden')):
            data,hashes,source=p.stable_inventory()
        self.assertEqual(hashes[p.INGRESS_CONFIG],p.INGRESS_CONFIG_SHA)
        self.assertEqual(p.INPUTS[-1],p.INGRESS_CONFIG)
        self.assertEqual(p.INPUTS[:4],('package.json','pnpm-lock.yaml','pnpm-workspace.yaml','server/api/package.json'))
        files=p.context_files(data,hashes,source,'pure-base',{})
        self.assertNotIn(p.INGRESS_CONFIG,files)
        copied=[]
        with mock.patch.object(p,'write_new',side_effect=lambda path,raw:copied.append((path,raw))), \
             mock.patch.object(Path,'chmod') as chmod, mock.patch.object(p,'plain_absolute',return_value=self.config_path), \
             mock.patch.object(Path,'lstat',return_value=argparse.Namespace(st_mode=p.stat.S_IFREG|0o444)):
            self.assertEqual(p.ingress_public_copy(self.config_path.parent,data),self.config_path)
        self.assertEqual(copied,[(self.config_path,data[p.INGRESS_CONFIG])]); chmod.assert_called_once_with(0o444)
        with mock.patch.object(p,'write_new',side_effect=AssertionError('write forbidden')):
            with self.assertRaisesRegex(p.Refusal,'^ingress_public_config_changed$'):
                p.ingress_public_copy(self.config_path.parent,{p.INGRESS_CONFIG:self.canary.encode()})

    def test_exact_pin_required_before_metadata_and_execute_only(self):
        args=argparse.Namespace(reviewed_script_sha256='a'*64,reviewed_source_sha256='b'*64,
                                docker_context='desktop-linux',gateway_image='sha256:'+'d'*64)
        for image in (None,'sha256:'+'e'*64,p.INGRESS+'suffix'):
            args.ingress_image=image
            with mock.patch.object(p,'plain_absolute',side_effect=AssertionError('metadata forbidden')):
                with self.assertRaisesRegex(p.Refusal,'^cached_ingress_pin_required$'):
                    p.approve(args,{'scriptSha256':'a'*64,'sourceSnapshotSha256':'b'*64})
        for mode in ('--plan','--self-test','--diagnose-build'):
            output=io.StringIO()
            with mock.patch.object(sys,'argv',['candidate',mode,'--ingress-image',p.INGRESS]), \
                 mock.patch.object(p,'stable_inventory',side_effect=AssertionError('inventory forbidden')), \
                 mock.patch('sys.stdout',output):
                self.assertEqual(p.main(),1)
            self.assertEqual(json.loads(output.getvalue())['reason'],'execute_arguments_without_execute')

    def test_cached_image_configuration_and_private_env_refused(self):
        good={'Id':p.INGRESS,'Os':'linux','Architecture':'arm64',
              'Config':{'User':'101:101','Entrypoint':['/docker-entrypoint.sh'],'Env':['NGINX_VERSION=1.27.5']}}
        self.assertEqual(p.qualify_ingress_image(good),'linux/arm64')
        for field,value in (('User','0:0'),('OnBuild',['RUN private']),('Volumes',{'/auth':{}}),
                            ('Entrypoint',['private']),('Env',['AUTH_SECRET='+self.canary])):
            bad=json.loads(json.dumps(good)); bad['Config'][field]=value
            with self.subTest(field=field), self.assertRaises(p.Refusal): p.qualify_ingress_image(bad)

    def test_final_override_and_topology_reject_extra_port_and_network(self):
        self.assertEqual(p.PORT_OVERRIDE.count(b'!override'),3)
        self.assertIn(b'ports: !override []',p.PORT_OVERRIDE)
        self.assertIn(b'ports: !override ["127.0.0.1:18083:8080"]',p.PORT_OVERRIDE)
        topology,image,gateway=self.topology()
        self.verify_topology(topology,image,gateway)
        for role,field,value in (('api','ports',[{'target':3001}]),('api','networks',{'auth_internal':{},'scan_internal':{},'web_edge':{}}),
                                 ('web','ports',topology['services']['web']['ports']+[{'target':8080,'published':'8080'}]),
                                 ('web','environment',{'AUTH_SECRET':self.canary}),('web','cap_add',['NET_ADMIN']),
                                 ('web','tmpfs',['/tmp']),('web','volumes',[])):
            bad=json.loads(json.dumps(topology)); bad['services'][role][field]=value
            with self.subTest(role=role,field=field), self.assertRaises(p.Refusal):
                self.verify_topology(bad,image,gateway)

    def test_finite_literal_prefix_mixed_config_mapping_requires_actual_hash(self):
        for source_prefix,prefix,policy in (('','',''),('/host_mnt','/host_mnt',''),
                                           ('','',p.DESKTOP_BIND_POLICY),('/host_mnt','',p.DESKTOP_BIND_POLICY)):
            runner,_=self.fixture(source_prefix)
            result=self.verify(runner,prefix,policy)
            self.assertEqual(result['bindRepresentations'],{p.INGRESS_DEST:'host-mnt' if source_prefix else 'literal'})
            self.assertTrue(result['mountedPublicConfigVerified'])
            self.assertEqual(runner.calls[-3:],[['exec',self.cid,'sha256sum',p.INGRESS_DEST],['native','version'],['native','syntax']])
        runner,_=self.fixture('/host_mnt')
        with self.assertRaises(p.Refusal): self.verify(runner)

    def test_wrong_source_alias_suffix_rw_missing_extra_and_duplicates_refused(self):
        for changes in ({'Source':'/other'+str(self.config_path)},{'Source':str(self.config_path)+'/'},
                        {'Source':str(self.config_path)+'/..'},{'Source':'/run/desktop/mnt/host'+str(self.config_path)},
                        {'Source':str(self.config_path.parent/'different.conf')},{'Destination':'/etc/nginx/other.conf'},
                        {'RW':True},{'RW':0}):
            runner,info=self.fixture(); info['Mounts'][0].update(changes)
            with self.subTest(changes=changes), self.assertRaises(p.Refusal): self.verify(runner,policy=p.DESKTOP_BIND_POLICY)
            self.assertFalse(any(args[0]=='exec' for args in runner.calls))
        for mode in ('missing','duplicate','double-alternative','private-volume','extra-tmpfs'):
            runner,info=self.fixture()
            if mode=='missing': info['Mounts']=[]
            elif mode=='private-volume': info['Mounts'].append({'Type':'volume','Name':self.project+'_auth_accounts'})
            elif mode=='extra-tmpfs': info['Mounts'].append({'Type':'tmpfs','Destination':'/auth','RW':True})
            else:
                duplicate=dict(info['Mounts'][0])
                if mode=='double-alternative': duplicate['Source']='/host_mnt'+duplicate['Source']
                info['Mounts'].append(duplicate)
            with self.subTest(mode=mode), self.assertRaises(p.Refusal): self.verify(runner,policy=p.DESKTOP_BIND_POLICY)

    def test_context_unvalidated_daemon_and_unknown_policy_refused_before_inspect(self):
        for context,validated,prefix,policy in (('other',True,'',p.DESKTOP_BIND_POLICY),
                                               ('desktop-linux',False,'',p.DESKTOP_BIND_POLICY),
                                               ('desktop-linux',True,'/unknown',''),
                                               ('desktop-linux',True,'','unknown')):
            runner,_=self.fixture(); runner.docker=['docker','--context',context]; runner.local_daemon_validated=validated
            with self.assertRaises(p.Refusal): self.verify(runner,prefix,policy)
            self.assertEqual(runner.calls,[])
        with mock.patch.object(Path,'resolve',side_effect=AssertionError('resolve forbidden')), \
             mock.patch.object(p.os,'open',side_effect=AssertionError('read forbidden')):
            self.assertEqual(set(p.ingress_bind_candidates(self.config_path,policy=p.DESKTOP_BIND_POLICY)),
                             {(str(self.config_path),p.INGRESS_DEST),('/host_mnt'+str(self.config_path),p.INGRESS_DEST)})
            with self.assertRaises(p.Refusal): p.ingress_bind_candidates(Path('/var/run/public-stand.nginx.conf'),policy=p.DESKTOP_BIND_POLICY)

    def test_web_privilege_resource_environment_identity_and_network_guards(self):
        for field,value in (('ReadonlyRootfs',False),('CapAdd',['NET_ADMIN']),('Memory',536870912),
                            ('MemorySwap',536870912),('NanoCpus',2000000000),('PidsLimit',256),
                            ('Tmpfs',{'/tmp':'rw'}),('PortBindings',{'8080/tcp':[{'HostIp':'0.0.0.0','HostPort':'18083'}]})):
            runner,info=self.fixture(); info['HostConfig'][field]=value
            with self.subTest(field=field), self.assertRaises(p.Refusal): self.verify(runner)
        for field,value in (('User','0:0'),('Entrypoint',['sh']),('Env',['AUTH_SECRET='+self.canary])):
            runner,info=self.fixture(); info['Config'][field]=value
            with self.subTest(field=field), self.assertRaises(p.Refusal): self.verify(runner)
        runner,info=self.fixture(); info['NetworkSettings']['Networks'][self.project+'_registry_uplink']={'NetworkID':'registry_uplink'}
        with self.assertRaises(p.Refusal): self.verify(runner)
        runner,info=self.fixture(); info['Config']['Labels']['com.docker.compose.service']='api'
        with self.assertRaises(p.Refusal): self.verify(runner)

    def test_hash_and_native_failures_never_return_positive_receipt(self):
        for failure in ('hash','native'):
            runner,_=self.fixture()
            if failure=='hash': runner.digest='0'*64
            else: runner.native_ok=False
            with self.assertRaises(p.Refusal): self.verify(runner)
        version=b'nginx version: nginx/1.27.5\n'
        syntax=b'nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\nnginx: configuration file /etc/nginx/nginx.conf test is successful\n'
        for kind,raw in (('version',version),('syntax',syntax)):
            self.assertEqual(p.nginx_diagnostic(kind,b'',raw,0)['status'],'qualified')
            for capture,code in ((raw+self.canary.encode(),0),(self.canary.encode(),1),(raw,1)):
                reduced=p.nginx_diagnostic(kind,b'',capture,code)
                self.assertEqual(reduced['status'],'refused'); self.assertNotIn(self.canary,json.dumps(reduced))
        with self.assertRaises(p.Refusal): p.nginx_diagnostic('syntax',b'x'*8193,b'',0)

    def test_native_capture_stderr_timeout_caps_and_fixed_command_guard(self):
        capture=RunnerCaptureTests()
        for timeout in (False,True):
            error,result,_=capture.capture(b'',self.canary.encode(),timeout=timeout,nginx_kind='syntax')
            self.assertEqual(error,'command_timeout' if timeout else 'isolated_command_failed')
            self.assertEqual(result['status'],'refused'); self.assertNotIn(self.canary,json.dumps(result))
        error,result,_=capture.capture(b'x'*8193,b'',nginx_kind='version')
        self.assertEqual(error,'command_output_bound'); self.assertEqual(result['status'],'refused')
        with mock.patch.dict(p.os.environ,{'PATH':'pure','HOME':'/pure'},clear=True): runner=p.Runner('pure',0)
        with mock.patch.object(p.subprocess,'Popen',side_effect=AssertionError('Docker forbidden')):
            with self.assertRaisesRegex(p.Refusal,'^unsafe_nginx_diagnostic_scope$'):
                runner.run(['exec',self.cid,'nginx','-T'],seconds=5,cap=8192,nginx_kind='syntax')
        with mock.patch.object(runner,'run') as run:
            runner.nginx(self.cid,'syntax')
        run.assert_called_once_with(['exec',self.cid,'nginx','-t'],seconds=5,cap=8192,nginx_kind='syntax')

    def test_resource_count_limits_and_unique_resources(self):
        complete={k:[str(i) for i in range(n)] for k,n in p.RESOURCE_LIMITS.items()}
        p.require_resource_counts(complete,complete=True)
        for key in complete:
            bad={k:list(v) for k,v in complete.items()}; bad[key].append('extra')
            with self.assertRaises(p.Refusal): p.require_resource_counts(bad)
            bad={k:list(v) for k,v in complete.items()}; bad[key][0]=bad[key][1]
            with self.assertRaises(p.Refusal): p.require_resource_counts(bad)
        with self.assertRaises(p.Refusal): p.require_resource_counts({k:[] for k in complete},complete=True)

    def test_host_readiness_initial_once_and_recreation_get_only_convergence(self):
        client=mock.Mock(runner=argparse.Namespace(work_deadline=p.time.monotonic()+535))
        client.call.return_value=(401,{'cache-control':'no-store'},None)
        self.assertEqual(p.proxy_host_ready(client)['attempts'],1)
        client.call.assert_called_once_with('GET','/api/v1/auth/me',proxy_readiness=True)
        client.call.reset_mock(); client.call.side_effect=[(503,{'cache-control':'no-store'},None),(401,{'cache-control':'no-store'},None)]
        with mock.patch.object(p.time,'sleep'): self.assertEqual(p.proxy_host_ready(client,True)['attempts'],2)
        self.assertEqual(client.call.call_args_list,[mock.call('GET','/api/v1/auth/me',proxy_readiness=True)]*2)
        client.call.reset_mock(); client.call.side_effect=OSError(p.errno.EPERM,self.canary)
        with self.assertRaises(OSError): p.proxy_host_ready(client,True)
        self.assertEqual(client.call.call_count,1)
        client.call.reset_mock(); client.call.side_effect=[(503,{'cache-control':'no-store'},None)]*12
        with mock.patch.object(p.time,'sleep'):
            with self.assertRaises(p.Refusal): p.proxy_host_ready(client,True)
        self.assertEqual(client.call.call_count,12)

    def test_host_readiness_bad_status_cookie_cache_and_initial_transient_fail_closed(self):
        for response in ((200,{'cache-control':'no-store'},None),(401,{},None),
                         (401,{'cache-control':'no-store','set-cookie':self.canary},None),
                         (503,{'cache-control':'no-store'},None)):
            client=mock.Mock(runner=argparse.Namespace(work_deadline=p.time.monotonic()+535))
            client.call.return_value=response
            with self.assertRaises(p.Refusal): p.proxy_host_ready(client)
            self.assertEqual(client.call.call_count,1)
        http=p.Http(argparse.Namespace(work_deadline=0))
        for method,path,cookie in (('POST','/api/v1/auth/me',None),('GET','/api/v1/auth/login',None),('GET','/api/v1/auth/me',self.canary)):
            with self.assertRaisesRegex(p.Refusal,'^unsafe_proxy_readiness$'):
                http.call(method,path,cookie,proxy_readiness=True)
            self.assertEqual(http.count,0)

    def test_transient_html_is_ignored_only_for_unauthenticated_readiness(self):
        trace=ProtocolInstrumentationTests()
        _,_,connection,_=trace.http_fixture(raw=self.canary.encode(),status=503,
                                           headers=[('Cache-Control','no-store')])
        runner=argparse.Namespace(work_deadline=p.time.monotonic()+535)
        with mock.patch.object(p.http.client,'HTTPConnection',return_value=connection), \
             mock.patch.object(p.signal,'getsignal'), mock.patch.object(p.signal,'signal'), mock.patch.object(p.signal,'setitimer'):
            http=p.Http(runner)
            self.assertEqual(http.call('GET','/api/v1/auth/me',proxy_readiness=True)[2],None)
            with self.assertRaises(json.JSONDecodeError): http.call('POST','/api/v1/auth/login',body={'private':self.canary})
            record=p.ProtocolTrace().snapshot(http)
        self.assertNotIn(self.canary,json.dumps(record)); self.assertLessEqual(len(p.canonical(record)),1024)

    def test_execution_order_keeps_signed_identity_before_host_and_never_exec_http(self):
        source=inspect.getsource(p.execute)
        self.assertLess(source.index('verify_container('),source.index('verify_web_container('))
        self.assertLess(source.index('verify_web_container('),source.index('proxy_host_ready(http)'))
        self.assertLess(source.index('proxy_host_ready(http)'),source.index('owner = http.login'))
        self.assertLess(source.index("evidence['recreatedApiIsolation']"),source.index('proxy_host_ready(http,recreated=True)'))
        self.assertIn("'-f',str(override_path)",source)
        self.assertIn("require_resource_counts(resources,complete=True)",source)
        self.assertNotIn("'curl'",source); self.assertNotIn("'wget'",source)
        self.assertEqual((p.TOTAL_SECONDS,p.WORK_SECONDS),(600,535))


class ComposeRepairTests(unittest.TestCase):
    canary = 'PRIVATE_COMPOSE_ENV_MESSAGE_PATH_CANARY'

    def argv(self):
        scratch=Path('/pure-own-scratch')
        result=['compose','--project-name','dip-cve14-proof-'+'a'*16,'--env-file',str(scratch/'own.env')]
        for name in (*p.BASES,'isolation.json','ports.override.yaml'):
            result+=['-f',str(scratch/name)]
        return result+['config','--format','json']

    def test_public_base_nnp_inherited_once_without_other_security_overrides(self):
        base=p.public_read('server/deploy/compose.stand.yaml')
        web=base.split(b'\n  web:\n',1)[1].split(b'\nnetworks:',1)[0]
        self.assertEqual(web.count(b'    security_opt: [no-new-privileges:true]\n'),1)
        for name in p.BASES[1:]:
            self.assertNotIn(b'security_opt',p.public_read('server/deploy/'+name))
        services=json.loads(p.overlay('sha256:'+'a'*64,'sha256:'+'b'*64,[]))['services']
        self.assertTrue(all('security_opt' not in service for service in services.values()))
        # A sequence-append regression vector, NOT an actual Compose parser measurement.
        inherited=['no-new-privileges:true']
        self.assertEqual(inherited+services['web'].get('security_opt',[]),inherited)
        self.assertEqual(inherited+inherited,['no-new-privileges:true']*2)
        self.assertEqual(services['web']['cap_drop'],['ALL'])
        self.assertEqual(services['api']['environment'],{**p.OFF,'SCAN_BROWSER_ALLOWED_USER_IDS':'',
                         'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS':'false','SCAN_JWT_ISSUER':'cve14-disposable',
                         'SCAN_JWT_AUDIENCE':'cve14-disposable'})

    def test_resolved_exact_nnp_still_required_no_duplicate_or_disabled_policy(self):
        fixture=IngressRepairTests(); topology,image,gateway=fixture.topology()
        fixture.verify_topology(topology,image,gateway)
        for value in ([],['no-new-privileges:true']*2,['no-new-privileges:false'],['no-new-privileges:true','seccomp=unconfined']):
            topology['services']['web']['security_opt']=value
            with self.subTest(value=value),self.assertRaises(p.Refusal):
                fixture.verify_topology(topology,image,gateway)
        del topology['services']['web']['security_opt']
        with self.assertRaises((p.Refusal,KeyError)):
            fixture.verify_topology(topology,image,gateway)

    def test_finite_schema_and_duplicate_vectors_no_dynamic_fields(self):
        vectors=[('services.web.security_opt array items[0,1] must be unique','compose_security_opt_duplicate','web','security_opt'),
                 ('services.web.security_opt must be a list','compose_public_schema_field_refused','web','security_opt'),
                 ('services.worker.tmpfs must be a list','compose_public_schema_field_refused','worker','tmpfs'),
                 ('services.unknown.security_opt must be a list','unclassified_compose_failure',None,None),
                 ('services.web.security_opt_suffix must be a list','unclassified_compose_failure',None,None),
                 ('services.web.'+self.canary+' must be a list','unclassified_compose_failure',None,None),
                 ('unknown tag !override','compose_override_tag_unsupported',None,None)]
        for raw,classification,service,field in vectors:
            result=p.compose_config_diagnostics(b'',(raw+' '+self.canary).encode(),1,'before-storage')
            self.assertEqual((result['classification'],result['publicService'],result['publicField']),
                             (classification,service,field))
            self.assertNotIn(self.canary,p.canonical(result).decode())
            self.assertLessEqual(len(p.canonical(result)),1024)
            self.assertFalse(result['rawOutputIncluded']); self.assertIsNone(result['jsonValid'])

    def test_stdout_success_and_unknown_errors_never_parse_secret_context(self):
        raw=p.canonical({'services':{'web':{'environment':{'PRIVATE':self.canary}}}})
        result=p.compose_config_diagnostics(raw,self.canary.encode(),0,'after-storage')
        self.assertEqual(result['classification'],'config_command_succeeded')
        self.assertIsNone(result['publicField']); self.assertNotIn(self.canary,p.canonical(result).decode())
        result=p.compose_config_diagnostics(b'services.web.security_opt must be a list',b'',1,'before-storage')
        self.assertEqual(result['publicField'],'security_opt')
        result=p.compose_config_diagnostics(b'',self.canary.encode(),1,'before-storage')
        self.assertEqual(result['classification'],'unclassified_compose_failure')

    def test_diagnostic_caps_termination_and_scan_bound(self):
        with self.assertRaisesRegex(p.Refusal,'^invalid_compose_diagnostic_scope$'):
            p.compose_config_diagnostics(b'x'*(p.COMPOSE_CAPTURE_CAP+1),b'',1,'before-storage')
        for phase,termination in ((self.canary,None),('before-storage',self.canary)):
            with self.assertRaises(p.Refusal): p.compose_config_diagnostics(b'',b'',1,phase,termination)
        result=p.compose_config_diagnostics(b'',b'x'*p.COMPOSE_DIAGNOSTIC_SCAN_BYTES+
                    b' services.web.security_opt must be a list',1,'before-storage')
        self.assertTrue(result['truncated']); self.assertEqual(result['classification'],'unclassified_compose_failure')
        for termination in ('command_timeout','command_output_bound','protocol_deadline'):
            result=p.compose_config_diagnostics(b'',b'services.web.security_opt must be a list',-9,'before-storage',termination)
            self.assertEqual(result['classification'],termination); self.assertIsNone(result['publicField'])

    def test_failed_real_runner_capture_is_fake_bounded_and_preserves_primary(self):
        capture=RunnerCaptureTests()
        for phase in p.COMPOSE_PHASES:
            error,result,process=capture.capture(self.canary.encode(),
                 b'services.web.security_opt array items[0,1] must be unique',compose_phase=phase)
            self.assertEqual(error,'isolated_command_failed')
            self.assertEqual(result['classification'],'compose_security_opt_duplicate')
            self.assertEqual(result['phase'],phase); self.assertNotIn(self.canary,json.dumps(result))
            self.assertEqual(process.stdout.close.call_count,2)
        error,result,_=capture.capture(b'',self.canary.encode(),timeout=True,compose_phase='before-storage')
        self.assertEqual((error,result['classification']),('command_timeout','command_timeout'))

    def test_compose_diagnostic_scope_refuses_other_commands_or_private_reads(self):
        runner=p.Runner('desktop-linux',0)
        with mock.patch.object(p.subprocess,'Popen',side_effect=AssertionError('Docker forbidden')), \
             mock.patch.object(p.os,'open',side_effect=AssertionError('private reads forbidden')):
            vectors=[self.argv()[:-3]+['up','-d','web'],self.argv()+['--extra']]
            foreign=self.argv(); foreign[2]='foreign-project'; vectors.append(foreign)
            foreign=self.argv(); foreign[6]='/different-base.yaml'; vectors.append(foreign)
            foreign=self.argv(); foreign[4]='/pure-own-scratch/private.env'; vectors.append(foreign)
            for args in vectors:
                with self.assertRaisesRegex(p.Refusal,'^unsafe_compose_diagnostic_scope$'):
                    runner.run(args,compose_phase='before-storage')
            for options in ({'seconds':16},{'cap':32768},{'check':False},{'cleanup':True},{'data':b'private'},
                            {'env':{'SECRET':self.canary}},{'compose_phase':self.canary}):
                with self.assertRaisesRegex(p.Refusal,'^unsafe_compose_diagnostic_scope$'):
                    runner.run(self.argv(),**{'compose_phase':'before-storage',**options})
        self.assertEqual(runner.calls,0)

    def test_compose_json_failure_and_success_are_not_topology_acceptance(self):
        runner=p.Runner('desktop-linux',0)
        runner.last_compose_diagnostics=p.compose_config_diagnostics(b'{bad',b'',0,'before-storage')
        with mock.patch.object(runner,'run',return_value=(b'{bad',0)):
            with self.assertRaisesRegex(p.Refusal,'^invalid_private_command_json$'):
                runner.json(self.argv(),compose_phase='before-storage')
        self.assertFalse(runner.last_compose_diagnostics['jsonValid'])
        runner.last_compose_diagnostics=p.compose_config_diagnostics(b'{}',b'',0,'after-storage')
        with mock.patch.object(runner,'run',return_value=(b'{}',0)):
            self.assertEqual(runner.json(self.argv(),compose_phase='after-storage'),{})
        self.assertTrue(runner.last_compose_diagnostics['jsonValid'])
        self.assertEqual(runner.last_compose_diagnostics['classification'],'config_command_succeeded')

    def test_compose_markers_and_capture_before_storage_no_extra_commands(self):
        source=inspect.getsource(p.execute)
        self.assertLess(source.index("evidence['phase'] = 'own-compose-config-before-storage'"),
                        source.index("topology = cj(['config'"))
        self.assertLess(source.index('verify_ingress_topology('),source.index("cmd(['up'"))
        self.assertIn("compose_phase='after-storage'",source)
        self.assertIn("evidence['composeConfigDiagnostics'] = runner.last_compose_diagnostics",source)
        self.assertEqual((p.TOTAL_SECONDS,p.WORK_SECONDS),(600,535))
        plan=p.plan({},'a'*64)
        self.assertEqual(plan['composeDiagnostic']['captureBytes'],2*1024**2)
        self.assertEqual(plan['composeDiagnostic']['outputBytes'],1024)
        self.assertEqual(plan['runtimeFlags'],p.OFF)
        self.assertEqual(p.RESOURCE_LIMITS,{'containers':6,'networks':4,'volumes':2})


class EmptyBindRepresentationTests(unittest.TestCase):
    fixture = IngressRepairTests()
    path = fixture.config_path
    canary = 'PRIVATE_EMPTY_BIND_CANARY'

    def generated(self):
        return p.overlay('sha256:'+'c'*64,'sha256:'+'d'*64,[],ingress_config=self.path)

    def mount(self,bind=None):
        return {'type':'bind','source':str(self.path),'target':p.INGRESS_DEST,
                'read_only':True,'bind':{} if bind is None else bind}

    def verify(self,mount,generated=None,mode=None):
        raw=self.generated() if generated is None else generated
        with mock.patch.object(p,'plain_absolute',return_value=self.path), \
             mock.patch.object(Path,'lstat',return_value=argparse.Namespace(st_mode=p.stat.S_IFREG|0o444 if mode is None else mode)), \
             mock.patch.object(p.os,'open',side_effect=AssertionError('no content/private reads')), \
             mock.patch.object(p.subprocess,'Popen',side_effect=AssertionError('no Docker')):
            return p.verify_ingress_compose_bind([mount],self.path,raw)

    def test_exact_two_representations_require_same_explicit_source_input(self):
        self.assertEqual(self.verify(self.mount()),'empty-bind-map')
        self.assertEqual(self.verify(self.mount({'create_host_path':False})),'explicit-false')
        generated=json.loads(self.generated())['services']['web']['volumes'][0]
        self.assertIs(generated['bind']['create_host_path'],False)
        self.assertEqual(generated['source'],str(self.path)); self.assertIs(generated['read_only'],True)

    def test_absent_true_numeric_null_string_extra_bind_keys_refused(self):
        for bind in (None,True,[],self.canary,{'create_host_path':True},{'create_host_path':0},{'create_host_path':1},
                     {'create_host_path':None},{'create_host_path':self.canary},
                     {'create_host_path':False,'unknown':False},{'unknown':False}):
            mount=self.mount(); mount['bind']=bind
            with self.subTest(bind=bind),self.assertRaisesRegex(p.Refusal,'^ingress_compose_bind$'):
                self.verify(mount)
        mount=self.mount(); del mount['bind']
        with self.assertRaisesRegex(p.Refusal,'^ingress_compose_bind$'): self.verify(mount)

    def test_no_generated_input_or_implicit_false_input_can_opt_in(self):
        for bind in ({},{'create_host_path':False}):
            mount=self.mount(bind)
            for raw in (None,b'',b'null',b'{bad',b'[]',b'x'*32769):
                with self.subTest(rawType=type(raw).__name__),self.assertRaisesRegex(p.Refusal,'^ingress_compose_input$'):
                    p.verify_ingress_compose_bind([mount],self.path,raw)
        for value in ({},None,{'create_host_path':True},{'create_host_path':0},
                      {'create_host_path':False,'extra':self.canary}):
            generated=json.loads(self.generated()); generated['services']['web']['volumes'][0]['bind']=value
            with self.assertRaisesRegex(p.Refusal,'^ingress_compose_input$'):
                self.verify(self.mount(),p.canonical(generated))
        generated=json.loads(self.generated()); del generated['services']['web']['volumes'][0]['bind']
        with self.assertRaisesRegex(p.Refusal,'^ingress_compose_input$'):
            self.verify(self.mount(),p.canonical(generated))

    def test_wrong_source_target_rw_type_and_any_extra_mount_key_refused(self):
        for field,value in (('source','/host_mnt'+str(self.path)),('source',str(self.path)+'/suffix'),
                            ('source',self.canary),('target',p.INGRESS_DEST+'/suffix'),('read_only',False),
                            ('read_only',1),('type','volume'),('extra',self.canary)):
            mount=self.mount(); mount[field]=value
            with self.subTest(field=field),self.assertRaisesRegex(p.Refusal,'^ingress_compose_bind$'):
                self.verify(mount)
        with mock.patch.object(p,'plain_absolute',side_effect=AssertionError('no metadata for bad volume set')):
            for volumes in (None,{},[],[self.mount(),self.mount()],[self.canary]):
                with self.assertRaisesRegex(p.Refusal,'^ingress_compose_bind$'):
                    p.verify_ingress_compose_bind(volumes,self.path,self.generated())

    def test_generated_wrong_source_readonly_type_or_noncanonical_bytes_refused(self):
        for field,value in (('source',self.canary),('target',self.canary),('read_only',False),
                            ('read_only',1),('type','volume'),('extra',self.canary)):
            generated=json.loads(self.generated()); generated['services']['web']['volumes'][0][field]=value
            with self.assertRaisesRegex(p.Refusal,'^ingress_compose_input$'):
                self.verify(self.mount(),p.canonical(generated))
        with self.assertRaisesRegex(p.Refusal,'^ingress_compose_input$'):
            self.verify(self.mount(),self.generated()+b'\n')

    def test_preexisting_regular_readonly_nonlinked_public_copy_required(self):
        for mode in (0,p.stat.S_IFREG|0o644,p.stat.S_IFREG|0o4444,p.stat.S_IFDIR|0o444,
                     p.stat.S_IFLNK|0o444,p.stat.S_IFIFO|0o444):
            for bind in ({},{'create_host_path':False}):
                with self.assertRaisesRegex(p.Refusal,'^ingress_public_copy_shape$'):
                    self.verify(self.mount(bind),mode=mode)
        with mock.patch.object(p,'plain_absolute',side_effect=p.Refusal('linked_absolute_path')):
            with self.assertRaisesRegex(p.Refusal,'^linked_absolute_path$'):
                p.verify_ingress_compose_bind([self.mount()],self.path,self.generated())
        wrong=self.path.with_name('unknown.conf'); mount=self.mount(); mount['source']=str(wrong)
        generated=json.loads(self.generated()); generated['services']['web']['volumes'][0]['source']=str(wrong)
        with mock.patch.object(p,'plain_absolute',side_effect=AssertionError('unknown copy must not qualify')):
            with self.assertRaisesRegex(p.Refusal,'^ingress_public_copy_shape$'):
                p.verify_ingress_compose_bind([mount],wrong,p.canonical(generated))
        with mock.patch.object(p,'plain_absolute',return_value=self.path), \
             mock.patch.object(Path,'lstat',side_effect=FileNotFoundError(self.canary)):
            with self.assertRaises(FileNotFoundError):
                p.verify_ingress_compose_bind([self.mount()],self.path,self.generated())

    def test_entire_resolved_topology_still_rejects_other_security_changes(self):
        topology,image,gateway=self.fixture.topology()
        topology['services']['web']['volumes'][0]['bind']={}
        self.assertEqual(self.fixture.verify_topology(topology,image,gateway),'empty-bind-map')
        for field,value in (('security_opt',[]),('cap_add',['NET_ADMIN']),('read_only',False),
                            ('user','0:0'),('environment',{'PRIVATE':self.canary}),('memswap_limit',536870912)):
            bad=json.loads(json.dumps(topology)); bad['services']['web'][field]=value
            with self.assertRaises(p.Refusal): self.fixture.verify_topology(bad,image,gateway)

    def test_execution_uses_same_generated_bytes_before_both_model_gates(self):
        source=inspect.getsource(p.execute)
        self.assertLess(source.index('ingress_config = ingress_public_copy'),source.index('overlay_bytes = overlay'))
        self.assertEqual(source.count('generated_overlay=overlay_bytes'),2)
        self.assertIn('write_new(overlay_path,overlay_bytes)',source)
        self.assertIn('overlay_path.write_bytes(overlay_bytes)',source)
        self.assertIn("evidence['ingressComposeBindBeforeStorage']",source)
        self.assertIn("evidence['ingressComposeBindAfterStorage']",source)
        self.assertLess(source.index('verify_web_container('),source.index('proxy_host_ready(http)'))
        plan=p.plan({},'a'*64)['ingress']
        self.assertEqual(plan['composeBindRepresentations'],['explicit-false','empty-bind-map'])
        self.assertTrue(plan['composeBindRequiresGeneratedFalseAndQualifiedCopy'])
        self.assertTrue(plan['composeBindIsNotMountedIdentity'])


class IngressComposeMemoryTests(unittest.TestCase):
    fixture = IngressRepairTests()
    canary = 'PRIVATE_MEMORY_REPAIR_CANARY'

    def verify(self,topology,image,gateway):
        with mock.patch.object(p.subprocess,'Popen',side_effect=AssertionError('no Docker')), \
             mock.patch.object(p.socket,'socket',side_effect=AssertionError('no socket')):
            return self.fixture.verify_topology(topology,image,gateway)

    def test_all_exact_memory_pairs_and_known_bind_forms_pass_together(self):
        for memory in (268435456,'268435456'):
            for swap in (268435456,'268435456'):
                for bind in ({},{'create_host_path':False}):
                    topology,image,gateway=self.fixture.topology()
                    topology['services']['web'].update(mem_limit=memory,memswap_limit=swap)
                    topology['services']['web']['volumes'][0]['bind']=bind
                    self.assertEqual(self.verify(topology,image,gateway),
                                     'empty-bind-map' if bind == {} else 'explicit-false')

    def test_float_bool_units_whitespace_noncanonical_and_other_values_refused(self):
        bad_values=(268435456.0,True,False,None,0,268435455,268435457,[],{},
                    '256m','256M','268435456.0','2.68435456e8','0268435456','+268435456',
                    ' 268435456','268435456 ','268435456\n','268435456\t',self.canary)
        for field in ('mem_limit','memswap_limit'):
            for bad in bad_values:
                topology,image,gateway=self.fixture.topology()
                topology['services']['web'].update(mem_limit='268435456',memswap_limit='268435456')
                topology['services']['web'][field]=bad
                with self.subTest(field=field,type=type(bad).__name__), \
                     self.assertRaisesRegex(p.Refusal,'^ingress_compose_boundary$'):
                    self.verify(topology,image,gateway)

    def test_exact_types_no_subclasses_or_arbitrary_conversion(self):
        class IntegerSubclass(int): pass
        class StringSubclass(str): pass
        class NoConversion:
            def __int__(self): raise AssertionError('no coercion')
            def __str__(self): raise AssertionError('no string conversion')
            def __eq__(self,other): raise AssertionError('no arbitrary equality')
        for value in (IntegerSubclass(268435456),StringSubclass('268435456'),NoConversion()):
            self.assertIs(p.ingress_compose_memory(value),False)
        self.assertIs(p.ingress_compose_memory(268435456),True)
        self.assertIs(p.ingress_compose_memory('268435456'),True)

    def test_only_two_fields_changed_no_alias_keys_or_other_boundary_bypass(self):
        for field in ('mem_limit','memswap_limit'):
            topology,image,gateway=self.fixture.topology()
            topology['services']['web'][field+'_alias']='268435456'
            del topology['services']['web'][field]
            with self.assertRaises(KeyError): self.verify(topology,image,gateway)
        for field,value in (('security_opt',[]),('cap_drop',['ALL','ALL']),('cap_add',['NET_ADMIN']),
                            ('read_only',False),('user','0:0'),('tmpfs',['/tmp']),('cpus',2),
                            ('pids_limit','128'),('environment',{'PRIVATE':self.canary})):
            topology,image,gateway=self.fixture.topology()
            topology['services']['web'].update(mem_limit='268435456',memswap_limit='268435456')
            topology['services']['web'][field]=value
            with self.assertRaises(p.Refusal): self.verify(topology,image,gateway)
        topology,image,gateway=self.fixture.topology()
        topology['services']['web'].update(mem_limit='268435456',memswap_limit='268435456')
        topology['services']['api']['ports']=[{'target':3001}]
        with self.assertRaisesRegex(p.Refusal,'^unexpected_published_port$'):
            self.verify(topology,image,gateway)

    def test_actual_runtime_memory_and_swap_still_require_same_numeric_bounds(self):
        for field in ('Memory','MemorySwap'):
            for bad in ('268435456',268435455,268435457,536870912,0):
                runner,info=self.fixture.fixture()
                info['HostConfig'][field]=bad
                with self.assertRaisesRegex(p.Refusal,'^ingress_resource_boundary$'):
                    self.fixture.verify(runner)
        runner,_=self.fixture.fixture()
        self.assertTrue(self.fixture.verify(runner)['mountedPublicConfigVerified'])

    def test_model_representations_plan_does_not_claim_runtime_or_widen_worker(self):
        plan=p.plan({},'a'*64)
        self.assertEqual(plan['ingress']['composeMemoryRepresentations'],['exact-integer','exact-decimal-string'])
        self.assertTrue(plan['ingress']['composeMemoryRepresentationIsNotRuntimeQualification'])
        self.assertEqual(plan['workerResources'],{'memory':1073741824,'swap':0,'cpu':1,'pids':128})
        self.assertEqual((p.TOTAL_SECONDS,p.WORK_SECONDS),(600,535))
        self.assertEqual(plan['runtimeFlags'],p.OFF)
        source=inspect.getsource(p.verify_ingress_topology)
        self.assertEqual(source.count('ingress_compose_memory('),2)
        self.assertIn("ingress_compose_memory(web['mem_limit'])",source)
        self.assertIn("ingress_compose_memory(web['memswap_limit'])",source)
        self.assertNotIn('ingress_compose_memory(',inspect.getsource(p.verify_web_container))
        self.assertNotIn('ingress_compose_memory(',inspect.getsource(p.verify_container))


NODE_INITIALIZER_TESTS = r"""
const assert=require('node:assert/strict'),vm=require('node:vm');
const code=INITIALIZER_CODE;
let checks=0;
const fresh=()=>({uid:0,gid:0,mode:0o755,kind:'directory',entries:[]});
function run(state,options={}){
 const calls=[],messages=[];let exit=0;const stop={};
 const stat=()=>({...state,isDirectory:()=>state.kind==='directory',isSymbolicLink:()=>state.kind==='symlink'});
 const error=(syscall,path='/data')=>Object.assign(new Error('PRIVATE_SENTINEL'),{code:'EPERM',syscall,path});
 const fs={
  lstatSync(path){assert.equal(path,'/data');calls.push('lstat');if(options.statError)throw error('lstat','/PRIVATE_SENTINEL');return stat()},
  readdirSync(path){assert.equal(path,'/data');calls.push('readdir');return state.entries},
  chmodSync(path,mode){assert.equal(path,'/data');calls.push('chmod');
   if(options.fail==='chmod'||state.uid!==0)throw error('chmod',options.errorPath);
   if(options.ignore!=='chmod')state.mode=mode},
  chownSync(path,uid,gid){assert.equal(path,'/data');calls.push('chown');
   if(options.fail==='chown')throw error('chown',options.errorPath);
   if(options.ignore!=='chown'){state.uid=uid;state.gid=gid}}
 };
 try{vm.runInNewContext(code,{require:name=>{assert.equal(name,'node:fs');return fs},
  process:{getuid:()=>options.uid??0,getgid:()=>options.gid??0,exit:n=>{exit=n;throw stop}},
  console:{error:text=>messages.push(text)}},{timeout:1000})}catch(e){if(e!==stop)throw e}
 assert(!JSON.stringify(messages).includes('PRIVATE_SENTINEL'));
 return {calls,messages,exit};
}
function refused(state,expected,options={}){
 const result=run(state,options);assert.equal(result.exit,1);
 assert.deepEqual(result.messages,['OWN_INIT_FAILURE:'+expected]);checks++;return result;
}
for(const mode of [0o755,0o700]){
 const state={...fresh(),mode};const first=run(state);
 assert.equal(first.exit,0);assert.deepEqual(first.messages,[]);
 assert.deepEqual(first.calls,['lstat','readdir','chmod','chown','lstat']);
 assert.equal(state.uid,65532);assert.equal(state.gid,65532);assert.equal(state.mode,0o700);
 state.entries=['OWN_PROVISIONED_FIXTURE'];
 const second=run(state);assert.equal(second.exit,0);assert.deepEqual(second.messages,[]);
 assert.deepEqual(second.calls,['lstat']);checks++;
}
for(const kind of ['file','symlink']){
 const result=refused({...fresh(),kind},'own_init_shape_refused');
 assert.deepEqual(result.calls,['lstat']);
}
for(const state of [
 {...fresh(),uid:42},{...fresh(),gid:42},{...fresh(),mode:0o777},{...fresh(),mode:0o1700},
 {...fresh(),uid:65532,gid:65532,mode:0o755},{...fresh(),uid:65532,gid:65531,mode:0o700},
 {...fresh(),uid:65532,gid:65532,mode:0o2700}
]){
 const result=refused(state,'own_init_state_refused');assert.deepEqual(result.calls,['lstat']);
}
for(const options of [{uid:65532},{gid:65532}]){
 const result=refused(fresh(),'own_init_state_refused',options);assert.deepEqual(result.calls,['lstat']);
}
const occupied=refused({...fresh(),entries:['OWN_EXISTING_FIXTURE']},'own_init_fresh_not_empty');
assert.deepEqual(occupied.calls,['lstat','readdir']);
for(const syscall of ['chmod','chown'])refused(fresh(),'own_init_'+syscall+'_eperm',{fail:syscall});
refused(fresh(),'own_init_io_failed',{fail:'chmod',errorPath:'/PRIVATE_SENTINEL'});
refused(fresh(),'own_init_io_failed',{statError:true});
for(const ignore of ['chmod','chown'])refused(fresh(),'own_init_postcondition_failed',{ignore});
console.log(JSON.stringify({kind:'pure-emitted-initializer-vm-tests',passed:true,checks,realFsCalls:0,dockerCalled:false}));
"""


if __name__ == '__main__':
    if sys.argv[1:]==['--emit-initializer-tests']:
        print(NODE_INITIALIZER_TESTS.replace('INITIALIZER_CODE',json.dumps(p.INITIALIZER_JS),1))
    else:
        unittest.main()
