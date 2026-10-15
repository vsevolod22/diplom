"""Pure public-parser candidate tests. No Docker/plugin, socket or temp writes."""
from contextlib import ExitStack
import ast
import copy
import io
import json
import os
from pathlib import Path
import signal
import stat
import types
import unittest
from unittest.mock import Mock, patch

PATH = Path(__file__).with_name('cve14-compose-public-diagnostic.py')
diag = types.ModuleType('public_compose_diagnostic_test_subject')
diag.__file__ = str(PATH)
exec(compile(PATH.read_bytes(),str(PATH),'exec'),diag.__dict__)
CANARY = 'PRIVATE_CANARY_DO_NOT_EMIT_91827'


def metadata(mode=stat.S_IFREG|0o755, inode=4, size=3):
    return types.SimpleNamespace(st_mode=mode,st_dev=1,st_ino=inode,st_size=size,
                                 st_mtime_ns=1,st_ctime_ns=1)


def proof_stub():
    return types.SimpleNamespace(BASES=('compose.stand.yaml','compose.stand.vuln.local.yaml',
                                        'compose.stand.nginx.local.yaml'),
                                 ORIGIN='http://127.0.0.1:18083',
                                 DB={'manifestDigest':'sha256:'+'a'*64,'artifactSha256':'b'*64},
                                 INGRESS_CONFIG='server/deploy/stand.nginx.conf',INGRESS_DEST='/etc/nginx/nginx.conf',
                                                                  INGRESS='sha256:'+'c'*64,INGRESS_TMPFS='rw,noexec,nosuid,uid=101,gid=101,size=16m',
                                 Refusal=diag.Refusal,verify_ingress_topology=Mock())


class FakeStream:
    def __init__(self, fd): self.fd,self.closed = fd,False
    def fileno(self): return self.fd
    def close(self): self.closed = True


class FakeProcess:
    pid = 7654321
    def __init__(self):
        self.stdin,self.stdout,self.stderr = FakeStream(10),FakeStream(11),FakeStream(12)
        self.wait = Mock(return_value=0)


class FakeSelector:
    def __init__(self): self.entries = {}
    def __enter__(self): return self
    def __exit__(self,*args): pass
    def register(self,stream,event,data):
        self.entries[stream.fd] = types.SimpleNamespace(fileobj=stream,data=data)
    def unregister(self,stream): del self.entries[stream.fd]
    def get_map(self): return self.entries
    def select(self,timeout): return [(key,0) for key in list(self.entries.values())]


class CandidateTests(unittest.TestCase):
    def assertRedacted(self, value):
        raw = diag.canonical(value)
        self.assertNotIn(CANARY.encode(),raw)
        self.assertLessEqual(len(raw)+1,diag.RESULT_CAP)

    def main_result(self, argv, **patches):
        output = io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(patch.object(diag.sys,'stdout',output))
            for key,value in patches.items(): stack.enter_context(patch.object(diag,key,value))
            code = diag.main(argv)
        self.assertLessEqual(len(output.getvalue().encode()),1024)
        self.assertNotIn(CANARY,output.getvalue())
        return code,json.loads(output.getvalue())

    def test_cli_invalid_and_abbreviation_never_echo_arguments(self):
        for argv in (['--unknown',CANARY],['--exec'],['--plan','--execute'],['--public-plugin-dir',CANARY]):
            with self.subTest(argv=argv):
                code,result = self.main_result(argv)
                self.assertEqual(code,1)
                self.assertIn(result['classification'],('public_arguments_refused','execute_arguments_without_execute'))

    def test_default_plan_never_enters_execute(self):
        sentinel = Mock(side_effect=AssertionError('must not execute'))
        code,value = self.main_result([],plan=Mock(return_value={'executed':False}),execute=sentinel)
        self.assertEqual((code,value),(0,{'executed':False})); sentinel.assert_not_called()

    def test_setup_error_and_unknown_refusal_redacted(self):
        for error in (OSError(CANARY),diag.Refusal(CANARY)):
            code,result = self.main_result([],plan=Mock(side_effect=error))
            self.assertEqual((code,result['classification']),(1,'public_setup_refused'))
        _,result = self.main_result([],plan=Mock(side_effect=diag.Refusal('public_plugin_unavailable')))
        self.assertEqual(result['classification'],'public_plugin_unavailable')

    def test_result_cap_fails_closed_including_newline(self):
        code,result = self.main_result([],plan=Mock(return_value={'executed':False,'public':'a'*1024}))
        self.assertEqual((code,result['classification']),(1,'public_result_bound'))

    def test_hash_approval_precedes_tool_temp_and_process(self):
        args = types.SimpleNamespace(reviewed_helper_sha256='wrong',reviewed_proof_sha256=diag.PROOF_SHA,
                                     reviewed_source_sha256=diag.SOURCE_SHA,public_plugin_dir=str(diag.PLUGIN_DIR))
        with (patch.object(diag,'public_read',return_value=b'candidate'),patch.object(diag,'qualify_tools') as tools,
              patch.object(diag,'own_public_directory') as temp,patch.object(diag.subprocess,'Popen') as popen):
            with self.assertRaisesRegex(diag.Refusal,'helper_not_approved'): diag.execute(args)
            args.reviewed_helper_sha256 = diag.sha(b'candidate'); args.reviewed_source_sha256 = 'wrong'
            with self.assertRaisesRegex(diag.Refusal,'frozen_inputs_not_approved'): diag.execute(args)
            tools.assert_not_called(); temp.assert_not_called(); popen.assert_not_called()

    def test_public_read_refuses_nonallowlisted_before_open(self):
        with patch.object(diag.os,'open') as opened:
            with self.assertRaisesRegex(diag.Refusal,'unapproved_public_read'):
                diag.public_read(diag.ROOT/'never-read.env',10)
            opened.assert_not_called()

    def test_public_read_nofollow_bound_drift_and_close(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(diag,'directories_plain'))
            opened = stack.enter_context(patch.object(diag.os,'open',return_value=77))
            closed = stack.enter_context(patch.object(diag.os,'close'))
            read = stack.enter_context(patch.object(diag.os,'read',side_effect=[b'abc',b'']))
            info = stack.enter_context(patch.object(diag.os,'fstat',return_value=metadata()))
            self.assertEqual(diag.public_read(diag.SELF,4),b'abc')
            self.assertEqual(opened.call_args.args[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            closed.assert_called_with(77)
            info.return_value = metadata(size=5)
            with self.assertRaisesRegex(diag.Refusal,'public_file_shape'): diag.public_read(diag.SELF,4)
            info.side_effect = [metadata(),metadata(inode=9)]
            read.side_effect = [b'abc',b'']
            with self.assertRaisesRegex(diag.Refusal,'public_source_drift'): diag.public_read(diag.SELF,4)

    def test_directory_symlink_refused(self):
        with patch.object(Path,'lstat',return_value=metadata(stat.S_IFLNK|0o777)):
            with self.assertRaisesRegex(diag.Refusal,'linked_or_missing_public_directory'):
                diag.directories_plain(diag.SELF)

    def test_frozen_proof_drift_stops_before_compile_inventory(self):
        with patch.object(diag,'public_read',return_value=CANARY.encode()) as read:
            with self.assertRaisesRegex(diag.Refusal,'frozen_proof_changed'): diag.frozen_inputs()
            self.assertEqual(read.call_count,1)

    def test_tool_directory_is_exact_and_missing_plugin_stops(self):
        with patch.object(diag,'public_tool') as tool:
            with self.assertRaisesRegex(diag.Refusal,'public_plugin_directory_refused'):
                diag.qualify_tools(str(diag.PLUGIN_DIR)+'/')
            tool.assert_not_called()
            tool.side_effect = [None,FileNotFoundError(CANARY)]
            with self.assertRaisesRegex(diag.Refusal,'public_plugin_unavailable'):
                diag.qualify_tools(str(diag.PLUGIN_DIR))
            self.assertEqual(tool.call_count,2)

    def test_tool_regular_and_exact_public_links_only(self):
        with (patch.object(diag,'directories_plain'),patch.object(Path,'lstat',return_value=metadata()) as ls,
              patch.object(diag.os,'readlink') as readlink):
            permitted = ('../Cellar/docker/28.1.1/bin/docker',)
            diag.public_tool(diag.DOCKER,diag.CLI_TARGET,permitted)
            readlink.assert_not_called()
            ls.side_effect = [metadata(stat.S_IFLNK|0o777),metadata()]; readlink.return_value = permitted[0]
            diag.public_tool(diag.DOCKER,diag.CLI_TARGET,permitted)
            ls.side_effect = None; ls.return_value = metadata(stat.S_IFLNK|0o777)
            for link in (CANARY,str(diag.CLI_TARGET),'../Cellar/docker/28.1.2/bin/docker',
                         '../Cellar/docker/28.1.1/bin/docker/extra','/Volumes/Docker/bin/docker',
                         '../../../Applications/Docker.app/Contents/Resources/bin/docker'):
                readlink.return_value = link
                with self.assertRaisesRegex(diag.Refusal,'public_tool_link_refused'):
                    diag.public_tool(diag.DOCKER,diag.CLI_TARGET,permitted)
            for mode in (stat.S_IFREG|0o777,stat.S_IFREG|0o644,stat.S_IFDIR|0o755):
                ls.return_value = metadata(mode)
                with self.assertRaisesRegex(diag.Refusal,'public_tool_metadata_refused'):
                    diag.public_tool(diag.DOCKER,diag.CLI_TARGET,permitted)

    def test_fixed_homebrew_qualification_no_fallback(self):
        self.assertEqual(diag.DOCKER,Path('/opt/homebrew/bin/docker'))
        self.assertEqual(diag.CLI_TARGET,Path('/opt/homebrew/Cellar/docker/28.1.1/bin/docker'))
        with patch.object(diag,'public_tool') as tool:
            diag.qualify_tools(str(diag.PLUGIN_DIR))
            self.assertEqual(tool.call_args_list[0].args,
                             (diag.DOCKER,diag.CLI_TARGET,('../Cellar/docker/28.1.1/bin/docker',)))
            self.assertEqual(tool.call_args_list[1].args,
                             (diag.PLUGIN_DIR/'docker-compose',diag.PLUGIN_TARGET,
                              (str(diag.PLUGIN_TARGET),'../bin/docker-compose')))
            tool.reset_mock(); tool.side_effect = FileNotFoundError(CANARY)
            with self.assertRaisesRegex(diag.Refusal,'public_docker_unavailable'):
                diag.qualify_tools(str(diag.PLUGIN_DIR))
            self.assertEqual(tool.call_count,1)

    def test_homebrew_exact_target_metadata_and_plain_ancestor_guard(self):
        def info(path):
            self.assertIn(path,(diag.DOCKER,diag.CLI_TARGET))
            return metadata(stat.S_IFLNK|0o777) if path == diag.DOCKER else metadata()
        with (patch.object(diag,'directories_plain') as plain,
              patch.object(Path,'lstat',autospec=True,side_effect=info) as ls,
              patch.object(diag.os,'readlink',return_value='../Cellar/docker/28.1.1/bin/docker'),
              patch.object(Path,'resolve',side_effect=AssertionError('no generic resolution')),
              patch.object(diag.subprocess,'Popen',side_effect=AssertionError('no execution'))):
            diag.public_tool(diag.DOCKER,diag.CLI_TARGET,('../Cellar/docker/28.1.1/bin/docker',))
            self.assertEqual([call.args[0] for call in ls.call_args_list],[diag.DOCKER,diag.CLI_TARGET])
            self.assertEqual([call.args[0] for call in plain.call_args_list],[diag.DOCKER,diag.CLI_TARGET])
            ls.side_effect = [metadata(stat.S_IFLNK|0o777),metadata(stat.S_IFLNK|0o777)]
            with self.assertRaisesRegex(diag.Refusal,'public_tool_metadata_refused'):
                diag.public_tool(diag.DOCKER,diag.CLI_TARGET,('../Cellar/docker/28.1.1/bin/docker',))
            plain.side_effect = [None,diag.Refusal('linked_or_missing_public_directory')]
            ls.side_effect = [metadata(stat.S_IFLNK|0o777)]
            with self.assertRaisesRegex(diag.Refusal,'linked_or_missing_public_directory'):
                diag.public_tool(diag.DOCKER,diag.CLI_TARGET,('../Cellar/docker/28.1.1/bin/docker',))

    def test_clean_environment_and_config_only_argv(self):
        proof = proof_stub(); home = diag.WORKSPACES/'public-test'/'home'; config = home.parent/'docker-config'
        with patch.dict(os.environ,{'DOCKER_HOST':CANARY,'COMPOSE_FILE':CANARY,'SCAN_JWT_SECRET':CANARY}):
            env = diag.public_environment(home,config,proof)
        self.assertNotIn(CANARY,str(env)); self.assertNotIn('DOCKER_HOST',env); self.assertNotIn('COMPOSE_FILE',env)
        self.assertEqual(env['COMPOSE_DISABLE_ENV_FILE'],'true')
        self.assertTrue(env['SCAN_JWT_SECRET'].startswith('PUBLIC_DIAGNOSTIC_NOT_A_SECRET_'))
        args = diag.compose_argv(config,proof)
        self.assertEqual(args[:8],[str(diag.DOCKER),'--config',str(config),'--host','unix:///dev/null',
                                  'compose','--env-file','/dev/null'])
        self.assertEqual(args[-7:],['-f','-','-f',str(diag.PORTS),'config','--format','json'])
        self.assertEqual(args.count('config'),1)
        for name in proof.BASES: self.assertIn(str(diag.ROOT/'server/deploy'/name),args)
        self.assertFalse(set(args)&{'up','build','pull','exec','inspect','version'})
        self.assertEqual(diag.canonical({'cliPluginsExtraDirs':[str(diag.PLUGIN_DIR)]}),
                         b'{"cliPluginsExtraDirs":["/Applications/Docker.app/Contents/Resources/cli-plugins"]}')

    def captured(self, stdout=(b'{}',b''), stderr=(b'',), write_error=None, kill_error=None, clock=None):
        process = FakeProcess(); reads = {11:list(stdout),12:list(stderr)}
        home = diag.WORKSPACES/'public-test'/'home'
        with ExitStack() as stack:
            popen = stack.enter_context(patch.object(diag.subprocess,'Popen',return_value=process))
            stack.enter_context(patch.object(diag.selectors,'DefaultSelector',FakeSelector))
            stack.enter_context(patch.object(diag.os,'set_blocking'))
            stack.enter_context(patch.object(diag.os,'read',side_effect=lambda fd,n: reads[fd].pop(0)))
            written = stack.enter_context(patch.object(diag.os,'write',side_effect=write_error or (lambda fd,b:len(b))))
            kill = stack.enter_context(patch.object(diag.os,'killpg',side_effect=kill_error))
            stack.enter_context(patch.object(diag.time,'monotonic',side_effect=clock or (lambda:0)))
            result = diag.capture(home.parent/'docker-config',home,proof_stub(),b'PUBLIC_OVERLAY')
        self.assertEqual(popen.call_count,1)
        self.assertTrue(popen.call_args.kwargs['start_new_session'])
        self.assertNotIn(CANARY,str(popen.call_args.kwargs['env']))
        kill.assert_called_once_with(process.pid,signal.SIGKILL)
        self.assertTrue(all(s.closed for s in (process.stdin,process.stdout,process.stderr)))
        return result,process,written

    def test_capture_mixed_streams_one_spawn_and_group_cleanup_after_exit(self):
        result,process,written = self.captured(stdout=(b'abc',b''),stderr=(b'def',b''))
        self.assertEqual(result,(b'abc',b'def',0,None)); self.assertEqual(written.call_count,1)
        self.assertEqual(process.wait.call_count,2); self.assertEqual(process.wait.call_args.kwargs['timeout'],0.25)

    def test_capture_eagain_no_resend_and_broken_pipe_redacted(self):
        calls = iter([BlockingIOError(CANARY),len(b'PUBLIC_OVERLAY')])
        def write(fd,b):
            value = next(calls)
            if isinstance(value,Exception): raise value
            return value
        result,_,written = self.captured(stdout=(b'',),stderr=(b'',),write_error=write)
        self.assertIsNone(result[3]); self.assertEqual(written.call_count,2)
        result,_,_ = self.captured(write_error=BrokenPipeError(CANARY))
        self.assertEqual(result[3],'command_io_failed'); self.assertRedacted(diag.reduce_capture(*result,proof_stub()))

    def test_capture_timeout_and_combined_output_cap(self):
        clock = iter(range(100)).__next__
        result,_,_ = self.captured(clock=clock)
        self.assertEqual(result[3],'command_timeout')
        result,_,_ = self.captured(stdout=(b'A'*4096,)*8+(b'',),stderr=(b'B',b''))
        self.assertEqual(result[3],'command_output_bound'); self.assertLessEqual(len(result[0])+len(result[1]),32768)
        with patch.object(diag.subprocess,'Popen') as popen:
            with self.assertRaisesRegex(diag.Refusal,'public_stdin_bound'):
                diag.capture(Path('/public/config'),Path('/public/home'),proof_stub(),b'A'*32769)
            popen.assert_not_called()

    def test_capture_primary_failure_not_masked_by_cleanup(self):
        result,_,_ = self.captured(write_error=BrokenPipeError(CANARY),kill_error=PermissionError(CANARY))
        self.assertEqual(result[3],'command_io_failed')
        result,_,_ = self.captured(clock=iter(range(100)).__next__,kill_error=PermissionError(CANARY))
        self.assertEqual(result[3],'command_timeout')

    def test_finite_classifier_vectors_redact_canary_and_unknown_fields(self):
        vectors = [
            ('could not determine a constructor for tag !override','compose_override_tag_unsupported',None),
            ('unknown flag: --format','compose_format_flag_unsupported',None),
            ("'compose' is not a docker command",'compose_plugin_unavailable',None),
            ('cannot connect to the Docker daemon at unix:///dev/null','compose_daemon_contact_refused',None),
            ('required variable SCAN_JWT_SECRET is missing a value','compose_public_interpolation_missing',None),
            ('services.web.ports must be a list','compose_ports_schema_refused','ports'),
            ('services.worker.tmpfs must be a list','compose_tmpfs_schema_refused','tmpfs'),
            ('services.web Additional property memswap_limit is not allowed','compose_resources_schema_refused','memswap_limit'),
            ('services.worker.mem_limit invalid type','compose_resources_schema_refused','mem_limit'),
            ('services.web.platform must be a string','compose_public_schema_field_refused','platform'),
            ('yaml: mapping values are not allowed here','compose_yaml_syntax_refused',None),
            ('services.web.'+CANARY+' must be a list','unclassified_compose_failure',None),
            ('services.unknown.ports must be a list','unclassified_compose_failure',None),
            ('services.web.portsSuffix must be a list','unclassified_compose_failure',None),
        ]
        for raw,classification,field in vectors:
            with self.subTest(classification=classification,field=field):
                result = diag.reduce_capture(b'',(raw+' '+CANARY).encode(),1,None,proof_stub())
                self.assertEqual((result['classification'],result['publicField']),(classification,field))
                self.assertRedacted(result)

    def test_json_shape_topology_refusal_and_success_no_raw_bytes(self):
        for raw in (b'{bad',b'\xff'):
            result = diag.reduce_capture(raw,CANARY.encode(),0,None,proof_stub())
            self.assertEqual(result['classification'],'compose_stdout_json_invalid'); self.assertRedacted(result)
        proof = proof_stub(); proof.verify_ingress_topology.side_effect = diag.Refusal(CANARY)
        result = diag.reduce_capture(b'{}',b'',0,None,proof)
        self.assertEqual(result['classification'],'compose_topology_contract_refused'); self.assertRedacted(result)
        proof.verify_ingress_topology.side_effect = None
        result = diag.reduce_capture(b'{}',CANARY.encode(),0,None,proof)
        self.assertEqual(result['classification'],'compose_topology_contract_refused')
        self.assertFalse(result['runtimeProofExecuted']); proof.verify_ingress_topology.assert_not_called()
        self.assertRedacted(result)

    def test_own_cleanup_checks_inode_and_never_deletes_replacement(self):
        path = diag.WORKSPACES/'cve14-compose-public-diag-test'
        safe = metadata(stat.S_IFDIR|0o700)
        with (patch.object(diag,'directories_plain'),patch.object(diag.tempfile,'mkdtemp',return_value=str(path)) as temp,
              patch.object(Path,'lstat',side_effect=[safe,safe,safe,safe]),patch.object(diag.shutil,'rmtree') as remove):
            remove.avoids_symlink_attacks = True
            with diag.own_public_directory() as actual: self.assertEqual(actual,path)
            remove.assert_called_once_with(path)
            temp.assert_called_once_with(prefix='cve14-compose-public-diag-',dir=diag.WORKSPACES)
        for primary in (False,True):
            with (patch.object(diag,'directories_plain'),patch.object(diag.tempfile,'mkdtemp',return_value=str(path)),
                  patch.object(Path,'lstat',side_effect=[safe,safe,safe,metadata(stat.S_IFDIR|0o700,inode=9)]),
                  patch.object(diag.shutil,'rmtree') as remove):
                with self.assertRaisesRegex(diag.Refusal,'primary' if primary else 'public_cleanup_refused'):
                    with diag.own_public_directory():
                        if primary: raise diag.Refusal('primary')
                remove.assert_not_called()


    def test_stdout_only_failure_is_classified_without_raw_output(self):
        result = diag.reduce_capture(('services.web.ports must be a list '+CANARY).encode(),b'',1,None,proof_stub())
        self.assertEqual(result['classification'],'compose_ports_schema_refused'); self.assertRedacted(result)

    def test_plugin_exact_links_and_unknown_tool_refused(self):
        with (patch.object(diag,'directories_plain'),patch.object(Path,'lstat') as ls,
              patch.object(diag.os,'readlink') as link):
            for literal in (str(diag.PLUGIN_TARGET),'../bin/docker-compose'):
                ls.side_effect = [metadata(stat.S_IFLNK|0o777),metadata()]; link.return_value = literal
                diag.public_tool(diag.PLUGIN_DIR/'docker-compose',diag.PLUGIN_TARGET,
                                 (str(diag.PLUGIN_TARGET),'../bin/docker-compose'))
            ls.reset_mock()
            with self.assertRaisesRegex(diag.Refusal,'unapproved_public_tool'):
                diag.public_tool(Path('/unapproved/docker'),diag.CLI_TARGET,())
            ls.assert_not_called()

    def test_execute_public_config_and_single_capture_only_fakes(self):
        from contextlib import contextmanager
        proof = proof_stub(); proof.INGRESS = 'sha256:'+'c'*64
        proof.overlay = Mock(return_value=b'PUBLIC_STDIN')
        path = diag.WORKSPACES/'cve14-compose-public-diag-test'
        @contextmanager
        def temp(): yield path
        args = types.SimpleNamespace(reviewed_helper_sha256=diag.sha(b'candidate'),
                                     reviewed_proof_sha256=diag.PROOF_SHA,reviewed_source_sha256=diag.SOURCE_SHA,
                                     public_plugin_dir=str(diag.PLUGIN_DIR))
        output = io.BytesIO()
        class Stream:
            def __enter__(self): return output
            def __exit__(self,*args): pass
        with (patch.object(diag,'public_read',return_value=b'candidate'),patch.object(diag,'qualify_tools') as tools,
              patch.object(diag,'frozen_inputs',return_value=(proof,{})),patch.object(diag,'own_public_directory',temp),
              patch.object(Path,'mkdir') as mkdir,patch.object(diag.os,'open',return_value=77) as opened,
              patch.object(diag.os,'fdopen',return_value=Stream()),
              patch.object(diag,'capture',return_value=(b'{}',b'',0,None)) as capture):
            result = diag.execute(args)
        self.assertEqual(result['classification'],'compose_topology_contract_refused')
        self.assertEqual(result['topologyFailed'],list(PublicBoundaryDiagnosticsTests.topology_labels))
        tools.assert_called_once_with(str(diag.PLUGIN_DIR)); self.assertEqual(mkdir.call_count,2)
        self.assertEqual(opened.call_args.args,(path/'docker-config'/'config.json',
                         os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600))
        self.assertEqual(json.loads(output.getvalue()),{'cliPluginsExtraDirs':[str(diag.PLUGIN_DIR)]})
        capture.assert_called_once_with(path/'docker-config',path/'home',proof,b'PUBLIC_STDIN')
        self.assertEqual(proof.overlay.call_args.args[2],[])
        self.assertEqual(proof.overlay.call_args.args[6],diag.ROOT/proof.INGRESS_CONFIG)


class WebVolumeShapeTests(unittest.TestCase):
    def mount(self):
        return {'type':'bind','source':str(diag.ROOT/proof_stub().INGRESS_CONFIG),
                'target':'/etc/nginx/nginx.conf','read_only':True,'bind':{'create_host_path':False}}

    def result(self, volumes):
        proof = proof_stub(); proof.verify_ingress_topology.side_effect = diag.Refusal(CANARY)
        value = {'services':{'web':{'volumes':volumes}},'privateUnrelatedField':CANARY}
        result = diag.reduce_capture(diag.canonical(value),CANARY.encode(),0,None,proof)
        self.assertEqual(result['classification'],'compose_topology_contract_refused')
        self.assertTrue(result['jsonValid']); self.assertNotIn('webVolumeShape',result)
        self.assertEqual(len(result['webBoundary']),16)
        self.assertNotIn(CANARY,diag.canonical(result).decode())
        self.assertLessEqual(len(diag.canonical(result))+1,1024)
        return {'webVolumeShape':diag.web_volume_shape(value,proof)}

    def test_r9_pins_and_public_ports_only_no_retained_private_reads(self):
        self.assertEqual(diag.PROOF_SHA,'2ce06c6ddc7ee86abb1c0e2755bb38993ff83e43384c134d76ce3b47a928c33b')
        self.assertEqual(diag.R9.name,'run-20261010-proof-r9')
        self.assertEqual(diag.PORTS,diag.R9/'ports.override.yaml')
        self.assertEqual(diag.IMAGE,'sha256:edc9f4875438b5caba2722a67ccf1508fa001db4199b0ef3362bf1b767ce1260')
        args = diag.compose_argv(Path('/public/config'),proof_stub())
        self.assertEqual(args[args.index('--project-directory')+1],str(diag.R9))
        with patch.object(diag.os,'open',side_effect=AssertionError('private read forbidden')):
            for name in ('own.env','isolation.json','own-recovery.json'):
                with self.assertRaisesRegex(diag.Refusal,'unapproved_public_read'):
                    diag.public_read(diag.R9/name,4096)

    def test_exact_single_volume_reports_boolean_keys_and_counts_only(self):
        shape = self.result([self.mount()])['webVolumeShape']
        for key in ('count','objects','binds','sourceMatches','targetMatches','readonlyMatches','tripleMatches'):
            self.assertEqual(shape[key],1)
        self.assertTrue(shape['exactShape']); self.assertTrue(shape['singleObject'])
        self.assertEqual(shape['keys'],dict.fromkeys(('type','source','target','read_only','bind'),True))
        self.assertFalse(shape['extraKeys']); self.assertFalse(shape['bindExtraKeys'])
        self.assertEqual(shape['createHostPath'],'false')

    def test_create_host_path_absent_false_true_invalid_without_normalization(self):
        cases = [(False,'false'),(True,'true'),(0,'invalid'),(1,'invalid'),(None,'invalid'),
                 (CANARY,'invalid'),([], 'invalid')]
        for value,state in cases:
            mount = self.mount(); mount['bind']['create_host_path'] = value
            shape = self.result([mount])['webVolumeShape']
            self.assertEqual(shape['createHostPath'],state)
            self.assertEqual(shape['exactShape'],value is False)
        for bind in ({},None,CANARY,[]):
            mount = self.mount(); mount['bind'] = bind
            shape = self.result([mount])['webVolumeShape']
            self.assertEqual(shape['createHostPath'],'absent' if type(bind) is dict else 'invalid')
            self.assertEqual(shape['bindObject'],type(bind) is dict)
            self.assertFalse(shape['exactShape'])
        mount = self.mount(); del mount['bind']
        shape = self.result([mount])['webVolumeShape']
        self.assertEqual(shape['createHostPath'],'absent'); self.assertFalse(shape['keys']['bind'])
        self.assertIsNone(shape['bindObject']); self.assertFalse(shape['exactShape'])

    def test_invalid_and_bounded_multi_volume_counts_never_echo_values(self):
        for value in (None,CANARY,False,{}):
            shape = self.result(value)['webVolumeShape']
            self.assertFalse(shape['volumesList']); self.assertIsNone(shape['count'])
        shape = self.result([])['webVolumeShape']
        self.assertTrue(shape['countBounded']); self.assertEqual(shape['count'],0)
        self.assertFalse(shape['singleObject'])
        shape = self.result([self.mount()]*8)['webVolumeShape']
        self.assertEqual(shape['count'],8); self.assertEqual(shape['tripleMatches'],8)
        self.assertFalse(shape['exactShape']); self.assertFalse(shape['singleObject'])
        shape = self.result([self.mount()]*9)['webVolumeShape']
        self.assertTrue(shape['volumesList']); self.assertFalse(shape['countBounded'])
        self.assertIsNone(shape['count']); self.assertIsNone(shape['objects'])
        shape = self.result([self.mount(),CANARY])['webVolumeShape']
        self.assertEqual((shape['count'],shape['objects']),(2,1)); self.assertFalse(shape['singleObject'])

    def test_wrong_alias_target_rw_and_unknown_keys_cannot_be_equivalence(self):
        for field,value,count in (('source','/host_mnt'+self.mount()['source'],'sourceMatches'),
                                  ('source',self.mount()['source']+'/suffix','sourceMatches'),
                                  ('source',CANARY,'sourceMatches'),('target',CANARY,'targetMatches'),
                                  ('read_only',False,'readonlyMatches'),('read_only',1,'readonlyMatches'),
                                  ('read_only',CANARY,'readonlyMatches'),('type','volume','binds')):
            mount = self.mount(); mount[field] = value
            shape = self.result([mount])['webVolumeShape']
            self.assertEqual(shape[count],0); self.assertFalse(shape['exactShape'])
        mount = self.mount(); mount[CANARY] = CANARY; mount['bind'][CANARY] = CANARY
        shape = self.result([mount])['webVolumeShape']
        self.assertTrue(shape['extraKeys']); self.assertTrue(shape['bindExtraKeys']); self.assertFalse(shape['exactShape'])
        for key in ('type','source','target','read_only'):
            mount = self.mount(); del mount[key]
            shape = self.result([mount])['webVolumeShape']
            self.assertFalse(shape['keys'][key]); self.assertFalse(shape['exactShape'])

    def test_root_shape_and_failed_capture_have_no_raw_volume_snapshot(self):
        proof = proof_stub(); proof.verify_ingress_topology.side_effect = TypeError(CANARY)
        for value in (None,[],{}, {'services':[]},{'services':{'web':CANARY}}):
            result = diag.reduce_capture(diag.canonical(value),b'',0,None,proof)
            shape = diag.web_volume_shape(value,proof)
            self.assertFalse(shape['volumesList']); self.assertIsNone(shape['count'])
            self.assertEqual(result['webBoundary'],dict.fromkeys(result['webBoundary'],False))
            self.assertNotIn(CANARY,diag.canonical(result).decode())
        for code,termination in ((1,None),(None,'command_timeout'),(None,'command_output_bound')):
            result = diag.reduce_capture(CANARY.encode(),CANARY.encode(),code,termination,proof)
            self.assertIsNone(result['webBoundary']); self.assertIsNone(result['topologyFailed'])
            self.assertFalse(result['jsonValid'])
            self.assertNotIn(CANARY,diag.canonical(result).decode())

    def test_finite_main_result_under_one_kib_with_shape(self):
        result = diag.reduce_capture(diag.canonical({'services':{'web':{'volumes':[self.mount()]}}}),
                                     b'',0,None,proof_stub())
        output = io.StringIO()
        with patch.object(diag,'execute',return_value=result),patch.object(diag.sys,'stdout',output):
            self.assertEqual(diag.main(['--execute']),1)
        self.assertLessEqual(len(output.getvalue().encode()),1024)
        self.assertEqual(len(json.loads(output.getvalue())['webBoundary']),16)
        self.assertNotIn('webVolumeShape',json.loads(output.getvalue()))
        self.assertNotIn(CANARY,output.getvalue())


class FrozenPublicContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Public pinned inventory only; forbid process/temp/network creation.
        with (patch.object(diag.subprocess,'Popen',side_effect=AssertionError('no process')),
              patch.object(diag.tempfile,'mkdtemp',side_effect=AssertionError('no writes'))):
            cls.proof,cls.hashes = diag.frozen_inputs()

    def test_actual_frozen_overlay_public_config_and_empty_accounts(self):
        proof = self.proof
        value = json.loads(proof.overlay(diag.IMAGE,diag.GATEWAY,[],'linux/arm64','linux/arm64',
                                        proof.INGRESS,diag.ROOT/proof.INGRESS_CONFIG,'linux/arm64'))
        self.assertEqual(value['services']['api']['environment']['SCAN_BROWSER_ALLOWED_USER_IDS'],'')
        self.assertEqual(value['services']['web']['volumes'][0]['source'],str(diag.ROOT/proof.INGRESS_CONFIG))
        self.assertFalse(any('env_file' in s for s in value['services'].values()))
        self.assertEqual(len(self.hashes),244)

    def topology(self):
        proof = self.proof
        services = json.loads(proof.overlay(diag.IMAGE,diag.GATEWAY,[],'linux/arm64','linux/arm64',
                                            proof.INGRESS,diag.ROOT/proof.INGRESS_CONFIG,'linux/arm64'))['services']
        for role,names in {'api':['auth_internal','scan_internal'],'worker':['scan_internal'],
                           'egress':['scan_internal','registry_uplink'],'web':['auth_internal','web_edge']}.items():
            services[role]['networks'] = {name:None for name in names}
        services['web'].update(ports=[{'host_ip':'127.0.0.1','target':8080,'published':'18083','protocol':'tcp','mode':'ingress'}],
                               tmpfs=['/tmp:'+proof.INGRESS_TMPFS],mem_limit=268435456,memswap_limit=268435456,
                               security_opt=['no-new-privileges:true'])
        return {'name':diag.PROJECT,'services':services,
                'networks':{n:{'name':diag.PROJECT+'_'+n,'internal':n in ('auth_internal','scan_internal')}
                            for n in ('auth_internal','scan_internal','registry_uplink','web_edge')},
                'volumes':{n:{'name':diag.PROJECT+'_'+n} for n in ('auth_accounts','scan_ledger')}}

    def generated(self):
        return self.proof.overlay(diag.IMAGE,diag.GATEWAY,[],'linux/arm64','linux/arm64',
                                  self.proof.INGRESS,diag.ROOT/self.proof.INGRESS_CONFIG,'linux/arm64')

    def test_real_r9_synthetic_bind_model_refuses_unknown_forms(self):
        for bind in (None,{'create_host_path':True},{'create_host_path':CANARY}):
            value = self.topology(); value['services']['web']['volumes'][0]['bind'] = bind
            result = diag.reduce_capture(diag.canonical(value),b'',0,None,self.proof,self.generated())
            self.assertEqual(result['classification'],'compose_topology_contract_refused')
            self.assertIn('ingress_compose_bind',result['topologyFailed'])
            shape = diag.web_volume_shape(value,self.proof)
            self.assertFalse(shape['exactShape'])
            self.assertEqual(shape['sourceMatches'],1)
            self.assertEqual(shape['targetMatches'],1)
            self.assertEqual(shape['readonlyMatches'],1)
            self.assertNotIn(CANARY,diag.canonical(result).decode())
        value = self.topology(); del value['services']['web']['volumes'][0]['bind']
        result = diag.reduce_capture(diag.canonical(value),b'',0,None,self.proof,self.generated())
        self.assertEqual(result['classification'],'compose_topology_contract_refused')
        self.assertIn('ingress_compose_bind',result['topologyFailed'])

    def test_real_validator_positive_and_mutated_boundaries(self):
        value = self.topology()
        self.assertEqual(diag.reduce_capture(diag.canonical(value),b'',0,None,self.proof,self.generated())['classification'],
                         'compose_public_model_matches')
        for field,bad in (('ports',[]),('cap_add',['NET_ADMIN']),('memswap_limit',536870912),
                          ('environment',{'CANARY':CANARY}),('volumes',[])):
            broken = copy.deepcopy(value); broken['services']['web'][field] = bad
            result = diag.reduce_capture(diag.canonical(broken),b'',0,None,self.proof,self.generated())
            self.assertEqual(result['classification'],'compose_topology_contract_refused')
            self.assertNotIn(CANARY,diag.canonical(result).decode())


class PublicBoundaryDiagnosticsTests(unittest.TestCase):
    topology_labels = ('foreign_compose_topology','composition_image_or_env_mismatch',
                       'unexpected_published_port','compose_network_mismatch','compose_network_not_isolated',
                       'ingress_port_override_required','ingress_compose_bind')
    mutations = (
        ('envAbsent','environment',{'PRIVATE':CANARY}),('entrypoint','entrypoint',[CANARY]),
        ('command','command',[CANARY]),('user','user',CANARY),('readonly','read_only',False),
        ('capDrop','cap_drop',['ALL','ALL']),('capAddAbsent','cap_add',[CANARY]),
        ('nnp','security_opt',['no-new-privileges:true','no-new-privileges:true']),
        ('unprivileged','privileged',True),('pidAbsent','pid',CANARY),('netModeAbsent','network_mode',CANARY),
        ('tmpfs','tmpfs',[CANARY]),('memory','mem_limit',CANARY),('memswap','memswap_limit',CANARY),
        ('cpu','cpus',CANARY),('pids','pids_limit',CANARY),
    )

    @classmethod
    def setUpClass(cls):
        with (patch.object(diag.subprocess,'Popen',side_effect=AssertionError('no process')),
              patch.object(diag.tempfile,'mkdtemp',side_effect=AssertionError('no writes'))):
            cls.proof,cls.hashes = diag.frozen_inputs()

    topology = FrozenPublicContractTests.topology
    generated = FrozenPublicContractTests.generated

    def result(self,value,generated=None):
        with (patch.object(diag.subprocess,'Popen',side_effect=AssertionError('no process')),
              patch.object(diag.tempfile,'mkdtemp',side_effect=AssertionError('no writes')),
              patch.object(self.proof,'verify_ingress_topology',side_effect=AssertionError('no runtime qualification'))):
            result = diag.reduce_capture(diag.canonical(value),CANARY.encode(),0,None,self.proof,
                                         self.generated() if generated is None else generated)
        raw = diag.canonical(result)
        self.assertNotIn(CANARY.encode(),raw); self.assertLessEqual(len(raw)+1,1024)
        self.assertFalse(result['rawOutputIncluded']); self.assertFalse(result['runtimeProofExecuted'])
        self.assertTrue(all(type(v) is bool for v in result['webBoundary'].values()))
        self.assertTrue(set(result['topologyFailed']) <= set(self.topology_labels))
        return result

    def test_every_conjunct_reported_together_and_each_independently_false(self):
        value = self.topology(); result = self.result(value)
        self.assertEqual(result['classification'],'compose_public_model_matches')
        self.assertEqual(result['topologyFailed'],[])
        self.assertEqual(set(result['webBoundary']),{v[0] for v in self.mutations})
        self.assertTrue(all(result['webBoundary'].values()))
        for label,field,bad in self.mutations:
            value = self.topology(); value['services']['web'][field] = bad
            result = self.result(value)
            self.assertEqual([k for k,v in result['webBoundary'].items() if not v],[label])
            self.assertEqual(result['classification'],'compose_topology_contract_refused')
            self.assertEqual(result['topologyFailed'],[])

    def test_all_failures_simultaneous_stay_under_one_kib_and_emit_no_observed_values(self):
        value = self.topology(); value.update(name=CANARY,volumes={},networks={CANARY:CANARY})
        for role in value['services']:
            value['services'][role].update(image=CANARY,env_file=[CANARY],ports=[CANARY],networks=[CANARY])
        for _,field,bad in self.mutations: value['services']['web'][field] = bad
        value['services']['web']['volumes'] = [CANARY]
        result = self.result(value)
        self.assertEqual(result['topologyFailed'],list(self.topology_labels))
        self.assertFalse(any(result['webBoundary'].values()))
        output = io.StringIO()
        with patch.object(diag,'execute',return_value=result),patch.object(diag.sys,'stdout',output):
            self.assertEqual(diag.main(['--execute']),1)
        self.assertLessEqual(len(output.getvalue().encode()),1024)
        self.assertEqual(json.loads(output.getvalue()),result)
        self.assertNotIn(CANARY,output.getvalue())

    def test_individual_topology_failure_labels_and_no_early_shortcircuit(self):
        vectors = (
            ('foreign_compose_topology',lambda v:v.update(name=CANARY)),
            ('composition_image_or_env_mismatch',lambda v:v['services']['worker'].update(image=CANARY)),
            ('composition_image_or_env_mismatch',lambda v:v['services']['api'].update(env_file=[CANARY])),
            ('unexpected_published_port',lambda v:v['services']['api'].update(ports=[CANARY])),
            ('compose_network_mismatch',lambda v:v['services']['worker'].update(networks=[CANARY])),
            ('compose_network_not_isolated',lambda v:v['networks']['auth_internal'].update(internal=False)),
            ('ingress_port_override_required',lambda v:v['services']['web'].update(ports=[CANARY])),
            ('ingress_compose_bind',lambda v:v['services']['web'].update(volumes=[])),
        )
        for label,mutate in vectors:
            value = self.topology(); mutate(value)
            result = self.result(value)
            self.assertEqual(result['topologyFailed'],[label])
            self.assertTrue(all(result['webBoundary'].values()))

    def test_exact_r9_false_or_empty_map_is_model_only_and_requires_explicit_input(self):
        for bind in ({},{'create_host_path':False}):
            value = self.topology(); value['services']['web']['volumes'][0]['bind'] = bind
            self.assertEqual(self.result(value)['classification'],'compose_public_model_matches')
        for bind in (None,True,[],{'create_host_path':True},{'create_host_path':0},
                     {'create_host_path':False,CANARY:CANARY}):
            value = self.topology(); value['services']['web']['volumes'][0]['bind'] = bind
            self.assertIn('ingress_compose_bind',self.result(value)['topologyFailed'])
        for raw in (b'',b'null',b'{bad',b'[]',b'x'*32769,self.generated()+b'\n'):
            self.assertIn('ingress_compose_bind',self.result(self.topology(),raw)['topologyFailed'])
        for bind in ({},{'create_host_path':True},{'create_host_path':0}):
            raw = json.loads(self.generated()); raw['services']['web']['volumes'][0]['bind'] = bind
            self.assertIn('ingress_compose_bind',self.result(self.topology(),diag.canonical(raw))['topologyFailed'])
        result = diag.reduce_capture(diag.canonical(self.topology()),b'',0,None,self.proof)
        self.assertIn('ingress_compose_bind',result['topologyFailed'])

    def test_malformed_and_missing_required_boundary_fields_fail_without_error_echo(self):
        for value in (None,[],{}, {'services':[]},{'services':{'web':CANARY}}):
            result = self.result(value)
            self.assertFalse(any(result['webBoundary'].values()))
            self.assertEqual(len(result['topologyFailed']),7)
        for label,field,_ in self.mutations:
            if label in ('envAbsent','capAddAbsent','unprivileged','pidAbsent','netModeAbsent'): continue
            value = self.topology(); del value['services']['web'][field]
            self.assertFalse(self.result(value)['webBoundary'][label])
        value = self.topology(); value['services']['web']['read_only'] = 1
        self.assertFalse(self.result(value)['webBoundary']['readonly'])
        value['services']['web']['cpus'] = 'nan'
        self.assertFalse(self.result(value)['webBoundary']['cpu'])

    def test_boolean_boundary_conjunction_matches_frozen_proof_expression(self):
        tree = ast.parse(diag.public_read(diag.PROOF,512*1024))
        topology = next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name == 'verify_ingress_topology')
        call = next(n.value for n in topology.body if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and
                    n.value.args and isinstance(n.value.args[-1],ast.Constant) and
                    n.value.args[-1].value == 'ingress_compose_boundary')
        self.assertIsInstance(call.args[0],ast.BoolOp); self.assertEqual(len(call.args[0].values),16)
        expression = compile(ast.Expression(call.args[0]),'<public-boundary-expression>','eval')
        for mutation in (None,*self.mutations):
            value = self.topology()
            if mutation: value['services']['web'][mutation[1]] = mutation[2]
            try:
                actual = bool(eval(expression,{'__builtins__':{},'float':float},
                                   {'web':value['services']['web'],'INGRESS_TMPFS':self.proof.INGRESS_TMPFS}))
            except (KeyError,TypeError,ValueError): actual = False
            self.assertEqual(all(self.result(value)['webBoundary'].values()),actual)

    def test_failure_capture_and_invalid_json_do_not_attempt_comparison_or_leak(self):
        with patch.object(diag,'web_boundary',side_effect=AssertionError('no parsed model')):
            for code,term,raw in ((1,None,CANARY.encode()),(None,'command_timeout',b'{}'),
                                  (None,'command_output_bound',b'{}'),(0,None,b'{bad')):
                result = diag.reduce_capture(raw,CANARY.encode(),code,term,self.proof)
                self.assertIsNone(result['webBoundary']); self.assertIsNone(result['topologyFailed'])
                self.assertNotIn(CANARY,diag.canonical(result).decode())

    def test_fixed_plan_and_single_capture_have_no_proof_or_resource_execution(self):
        import inspect
        source = inspect.getsource(diag.execute)
        self.assertEqual(source.count('*capture('),1)
        self.assertIn('),proof,stdin)',source)
        self.assertNotIn('verify_ingress_topology(',inspect.getsource(diag.reduce_capture))
        with patch.object(diag.subprocess,'Popen',side_effect=AssertionError('no process')):
            plan = diag.plan()
        self.assertEqual((plan['commandSeconds'],plan['captureBytes'],plan['resultBytes'],plan['configCalls']),
                         (5,32768,1024,1))
        self.assertEqual(plan['engineEndpoint'],'unix:///dev/null')
        self.assertEqual(plan['webBoundaryConjuncts'],16)
        self.assertTrue(plan['comparisonIsSyntheticNotRuntimeIdentity'])
        self.assertLessEqual(len(diag.canonical(plan))+1,1024)


class MemoryRepresentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with (patch.object(diag.subprocess,'Popen',side_effect=AssertionError('no process')),
              patch.object(diag.tempfile,'mkdtemp',side_effect=AssertionError('no writes'))):
            cls.proof,cls.hashes = diag.frozen_inputs()

    topology = FrozenPublicContractTests.topology
    generated = FrozenPublicContractTests.generated

    def result(self,value):
        with patch.object(diag.subprocess,'Popen',side_effect=AssertionError('no process')):
            result = diag.reduce_capture(diag.canonical(value),CANARY.encode(),0,None,self.proof,self.generated())
        self.assertLessEqual(len(diag.canonical(result))+1,1024)
        self.assertNotIn(CANARY.encode(),diag.canonical(result))
        self.assertFalse(result['rawOutputIncluded']); self.assertFalse(result['runtimeProofExecuted'])
        self.assertEqual(len(result['webBoundary']),16)
        return result

    def test_exact_integer_and_exact_decimal_string_are_distinct_without_gate_repair(self):
        for observed,representation in ((268435456,'exact-integer'),('268435456','exact-decimal-string')):
            value = self.topology()
            value['services']['web'].update(mem_limit=observed,memswap_limit=observed)
            result = self.result(value)
            self.assertEqual(result['memoryRepresentation'],dict.fromkeys(('memory','memswap'),representation))
            self.assertEqual(result['webBoundary']['memory'],type(observed) is int)
            self.assertEqual(result['webBoundary']['memswap'],type(observed) is int)
            self.assertEqual(result['topologyFailed'],[])
            self.assertEqual(result['classification'],'compose_public_model_matches' if type(observed) is int
                             else 'compose_topology_contract_refused')

    def test_each_field_independent_and_entire_boundary_unchanged(self):
        value = self.topology(); value['services']['web']['mem_limit'] = '268435456'
        result = self.result(value)
        self.assertEqual(result['memoryRepresentation'],{'memory':'exact-decimal-string','memswap':'exact-integer'})
        self.assertEqual([k for k,v in result['webBoundary'].items() if not v],['memory'])
        value['services']['web'].update(mem_limit=268435456,memswap_limit='268435456')
        result = self.result(value)
        self.assertEqual(result['memoryRepresentation'],{'memory':'exact-integer','memswap':'exact-decimal-string'})
        self.assertEqual([k for k,v in result['webBoundary'].items() if not v],['memswap'])

    def test_noncanonical_strings_other_values_and_types_never_echo_or_coerce(self):
        vectors = ('0268435456','+268435456','268435456 ',' 268435456','268435456\n',
                   '268435456.0','2.68435456e8','256m',CANARY,268435455,268435457,
                   268435456.0,True,False,None,[],{}, {'PRIVATE':CANARY})
        for observed in vectors:
            value = self.topology(); value['services']['web'].update(mem_limit=observed,memswap_limit=observed)
            result = self.result(value)
            self.assertEqual(result['memoryRepresentation'],dict.fromkeys(('memory','memswap'),'other-or-type-invalid'))
        class IntegerSubclass(int): pass
        self.assertEqual(diag.memory_representation({'services':{'web':{'mem_limit':IntegerSubclass(268435456)}}}),
                         dict.fromkeys(('memory','memswap'),'other-or-type-invalid'))

    def test_missing_and_malformed_json_shapes_have_only_finite_invalid_enum(self):
        for value in (None,[],{}, {'services':CANARY},{'services':{'web':CANARY}},
                      {'services':{'web':{}}}):
            result = self.result(value)
            self.assertEqual(result['memoryRepresentation'],dict.fromkeys(('memory','memswap'),'other-or-type-invalid'))
        for field,label in (('mem_limit','memory'),('memswap_limit','memswap')):
            value = self.topology(); del value['services']['web'][field]
            self.assertEqual(self.result(value)['memoryRepresentation'][label],'other-or-type-invalid')

    def test_failed_capture_and_bad_json_have_no_representation_or_raw_messages(self):
        with patch.object(diag,'memory_representation',side_effect=AssertionError('not parsed')):
            for code,term,raw in ((1,None,CANARY.encode()),(None,'command_timeout',b'{}'),
                                  (None,'command_output_bound',b'{}'),(0,None,b'{bad')):
                result = diag.reduce_capture(raw,CANARY.encode(),code,term,self.proof)
                self.assertIsNone(result['memoryRepresentation'])
                self.assertNotIn(CANARY.encode(),diag.canonical(result))

    def test_plan_enums_fit_existing_result_cap_without_execution(self):
        with patch.object(diag.subprocess,'Popen',side_effect=AssertionError('no process')):
            plan = diag.plan()
        self.assertEqual(plan['memoryEnums'],['exact-integer','exact-decimal-string','other-or-type-invalid'])
        self.assertLessEqual(len(diag.canonical(plan))+1,1024)
        self.assertEqual((plan['commandSeconds'],plan['captureBytes'],plan['resultBytes'],plan['configCalls']),
                         (5,32768,1024,1))
        self.assertEqual(diag.sha(diag.PROOF.read_bytes()),diag.PROOF_SHA)


if __name__ == '__main__':
    unittest.main()
