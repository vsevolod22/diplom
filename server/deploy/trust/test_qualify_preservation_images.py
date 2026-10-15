"""Small source/envelope tests ONLY. No Docker, native DB or app execution."""
import importlib.util
import json
import os
import re
import stat
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('qualification',Path(__file__).with_name('qualify_preservation_images.py'))
q = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(q)


def record(packet,role,label,ident,argv,state='created'):
    return [ident,q.IMAGES[role],'/dip-preservation-qual-'+role+'-'+label[:16],
            {'Status':state,'Running':False,'Paused':False,'Restarting':False,'OOMKilled':False,'ExitCode':0,'Error':''},
            {q.LABEL:label}, {'ReadonlyRootfs':True,'NetworkMode':'none','CapDrop':['ALL'],'CapAdd':None,
            'Privileged':False,'SecurityOpt':['no-new-privileges:true'],'Memory':2*q.GIB,'MemorySwap':2*q.GIB,
            'NanoCpus':10**9,'PidsLimit':64,'Tmpfs':q.TMPFS,'AutoRemove':False,'PortBindings':None,'Binds':None,
            'Devices':[],'DeviceRequests':None,'RestartPolicy':{'Name':'no'}},
            [{'Type':'bind','RW':False,'Source':str(packet/n),'Destination':'/'+n} for n in q.FILES],
            ['/usr/bin/env'],argv[argv.index(q.IMAGES[role])+1:],'65532:65532','/app/server/api']


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.no_process = mock.patch.object(q.subprocess,'Popen',side_effect=AssertionError('REAL_PROCESS_FORBIDDEN'))
        self.no_process.start()
        self.addCleanup(self.no_process.stop)
        self.packet=Path('/private/tmp/dip-preservation-images-synthetic-test')
        self.label='a'*64
        self.ident='b'*64

    def test_fixed_pins_and_no_real_volume_cli(self):
        self.assertEqual(len(q.IMAGES),3)
        for role in q.ROLES:
            cmd=q.command(self.packet,role,self.label,45000)
            self.assertEqual(cmd[0],'create')
            self.assertIn(q.IMAGES[role],cmd)
            self.assertEqual(cmd[cmd.index('--user')+1],'65532:65532')
            self.assertEqual(cmd[cmd.index('--memory')+1],'2147483648')
            self.assertEqual(cmd[cmd.index('--memory-swap')+1],'2147483648')
            self.assertNotIn('--volume',cmd)
            self.assertNotIn('--env-file',cmd)
            self.assertNotIn('--env',cmd)
            self.assertNotIn('run',cmd)
            self.assertIn('-i',cmd)
            self.assertEqual(sum(v=='--mount' for v in cmd),3)
            self.assertEqual(sum(v=='--tmpfs' for v in cmd),4)
            self.assertNotIn('dip-auth-stand',str(cmd))
        self.assertIn('--experimental-import-meta-resolve',q.command(self.packet,'api',self.label,45000))
        self.assertNotIn('--import',q.command(self.packet,'old',self.label,120000))

    def test_invalid_role_time_label_refuse(self):
        for role,label,duration in [('web',self.label,1),('old','short',1),('old',self.label,0),('old',self.label,240001)]:
            with self.assertRaises(ValueError):q.command(self.packet,role,label,duration)

    def test_endpoint_no_context_credentials_or_network_fallback(self):
        for endpoint in ['tcp://localhost:2375','unix:///tmp/../engine.sock','ssh://host']:
            with self.assertRaises(ValueError):q.Docker(self.packet,endpoint,100)
        d=q.Docker(self.packet,'unix:///synthetic/engine.sock',100)
        self.assertEqual(d.prefix,['docker','--config',str(self.packet/'client'),'--host','unix:///synthetic/engine.sock'])
        self.assertEqual(set(d.env),{'PATH','HOME'})

    def test_guards_accept_only_own_exact_created_or_exited(self):
        argv=q.command(self.packet,'old',self.label,120000)
        for state in ['created','exited']:
            q.guard(record(self.packet,'old',self.label,self.ident,argv,state),self.ident,self.packet,'old',self.label,argv,state)

    def test_ownership_rejects_foreign_id_image_name_label(self):
        argv=q.command(self.packet,'old',self.label,120000)
        for idx,value in [(0,'c'*64),(1,q.API),(2,'/foreign'),(4,{q.LABEL:'c'*64}),(4,{q.LABEL:self.label,'com.docker.compose.project':'stand'})]:
            r=record(self.packet,'old',self.label,self.ident,argv);r[idx]=value
            with self.assertRaises(ValueError):q.guard(r,self.ident,self.packet,'old',self.label,argv,'created')

    def test_resource_mount_entrypoint_drift_refused(self):
        argv=q.command(self.packet,'old',self.label,120000)
        for key,value in [('Memory',q.GIB),('Privileged',True),('NetworkMode','bridge'),('CapAdd',['CHOWN']),('AutoRemove',True),('Tmpfs',{})]:
            r=record(self.packet,'old',self.label,self.ident,argv);r[5][key]=value
            with self.assertRaises(ValueError):q.guard(r,self.ident,self.packet,'old',self.label,argv,'created')
        for mutate in [lambda r:r[6][0].update(RW=True),lambda r:r[6][0].update(Source='/real/auth'),lambda r:r.__setitem__(7,['node'])]:
            r=record(self.packet,'old',self.label,self.ident,argv);mutate(r)
            with self.assertRaises(ValueError):q.guard(r,self.ident,self.packet,'old',self.label,argv,'created')

    def test_oom_nonzero_running_refuse_cleanup(self):
        argv=q.command(self.packet,'old',self.label,120000)
        for key,value in [('OOMKilled',True),('ExitCode',1),('Running',True),('Paused',True),('Status','running')]:
            r=record(self.packet,'old',self.label,self.ident,argv,'exited');r[3][key]=value
            with self.assertRaises(ValueError):q.guard(r,self.ident,self.packet,'old',self.label,argv,'exited')

    def test_path_scope_freshness_and_single_link_reads(self):
        for p in ['/private/tmp/unowned','/Users/example/dip-preservation-images-test','/private/tmp/dip-preservation-images-../escape']:
            with self.assertRaises(ValueError):q.packet_name(Path(p))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();p=root/'public';q.write_new(p,b'synthetic')
            self.assertEqual(q.read_file(p),b'synthetic')
            with self.assertRaises(FileExistsError):q.write_new(p,b'overwrite')
            os.link(p,root/'alias')
            with self.assertRaises(ValueError):q.read_file(p)

    def test_embedded_program_is_not_old_suite_or_application_startup(self):
        self.assertIn('assert.equal(blocks.length,13)',q.QUALIFICATION_JS)
        self.assertIn("old('/app/server/api/src/auth/auth.store.ts'",q.QUALIFICATION_JS)
        self.assertIn("await import('/snapshot.mjs')",q.QUALIFICATION_JS)
        self.assertIn('import.meta.resolve(spec,pathToFileURL(p).href)',q.QUALIFICATION_JS)
        self.assertIn("assert(!fs.existsSync(expected.slice(0,-3)+'.js'))",q.QUALIFICATION_JS)
        self.assertNotIn('NestFactory.create',q.QUALIFICATION_JS)
        self.assertNotIn('runWorker(',q.QUALIFICATION_JS)
        self.assertNotIn('sqlite_state_snapshot.test.mjs',q.QUALIFICATION_JS)
        self.assertNotIn('fetch(',q.QUALIFICATION_JS)
        self.assertNotIn('import(entry)',q.QUALIFICATION_JS)

    def test_image_volume_or_failure_never_cleanup_or_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            packet=Path(directory).resolve()
            calls=[]
            class Inert:
                def __init__(self,*args):pass
                def call(self,args,*more):
                    calls.append(args)
                    if args[:2]==['image','inspect']:
                        return b'\n'.join(q.canonical(v).strip() for v in [q.OLD,'linux','arm64','/app/server/api',{'/real':{}},['docker-entrypoint.sh'],['node']])
                    raise AssertionError('NO_CREATE_ALLOWED')
            with mock.patch.object(q,'load_packet'),mock.patch.object(q,'Docker',Inert):
                with self.assertRaises(ValueError):q.run(packet,self.label,'DIP-ARTF-999','unix:///synthetic/engine.sock')
            self.assertTrue((packet/'attempt.json').exists())
            self.assertEqual(len(calls),1)
            self.assertFalse((packet/'result.json').exists())

    def test_existing_attempt_refuses_before_engine(self):
        with tempfile.TemporaryDirectory() as directory:
            packet=Path(directory).resolve();q.write_new(packet/'attempt.json',b'{}')
            with mock.patch.object(q,'load_packet'),mock.patch.object(q,'Docker',side_effect=AssertionError('NO_ENGINE')):
                with self.assertRaises(FileExistsError):q.run(packet,self.label,'DIP-ARTF-999','unix:///synthetic/engine.sock')

    def mock_run(self, failure=None, cleanup_drift=False, directory_failure=None):
        directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup);packet=Path(directory.name).resolve()
        pins={n:q.sha(n.encode()) for n in q.FILES}
        for n in q.FILES:q.write_new(packet/n,n.encode(),0o444)
        plan=q.canonical({'files':pins});q.write_new(packet/'plan.json',plan);label=q.sha(plan)
        calls=[];states={};commands={};started=[];durable=set();pending=[None]
        real_write=q.write_new;real_sync=q.sync_directory
        def receipt(p,raw,mode=0o600):
            pending[0]=p.name
            try:real_write(p,raw,mode)
            finally:pending[0]=None
        def sync(p):
            if pending[0]==directory_failure and directory_failure is not None:raise OSError('SYNTHETIC_DIR_FSYNC_FAILURE')
            real_sync(p)
            if pending[0] is not None:durable.add(pending[0])
        native={'node':'v24.0.0','abi':'137','sqlite':'3.synthetic','betterSqlite':'12.11.1','nativeSha256':'c'*64,'nodeSha256':'d'*64}
        class Inert:
            def __init__(self,*args):pass
            def call(self,args,*more):
                calls.append(args)
                if args[:2]==['image','inspect']:
                    assert 'attempt.json' in durable
                    return b'\n'.join(q.canonical(v).strip() for v in [args[-1],'linux','arm64','/app/server/api',None,['docker-entrypoint.sh'],['npm','start']])
                if args[0]=='create':
                    role=next(r for r in q.ROLES if q.IMAGES[r] in args);ident=str(q.ROLES.index(role)+1)*64
                    assert 'attempt.json' in durable and role+'-image.json' in durable
                    commands[ident]=(role,args);states[ident]='created';return ident.encode()+b'\n'
                if args[:2]==['start','--attach']:
                    ident=args[-1];role=commands[ident][0];started.append(role)
                    assert role+'-id.json' in durable
                    if role==failure:raise ValueError('MOCK_FAILURE')
                    states[ident]='exited'
                    if role=='old':proof={'sixCliOperations':True,'committedWalRetained':True,'quotaBytesUnchanged':True,'partialCommitHold':True}
                    else:
                        entry='src/oci/nginx-local.main.ts' if role=='api' else 'src/worker/nginx-local-worker.main.ts'
                        proof={'entry':'/app/server/api/'+entry,'launchCommand':['node','--import','tsx',entry],
                               'appBodiesEvaluated':False,'externalPackageBodiesQualified':False,'sourceFiles':1,'edges':[],
                               'entrypoint':{'path':'/usr/local/bin/docker-entrypoint.sh','sha256':'e'*64}}
                    return q.canonical({'code':'SYNTHETIC_QUALIFIED','ok':True,'role':role,'native':native,'proof':proof})
                if args[0]=='rm':return args[-1].encode()+b'\n'
                raise AssertionError('UNREVIEWED_COMMAND')
            def inspect(self,ident):
                role,argv=commands[ident];r=record(packet,role,label,ident,argv,states[ident])
                if cleanup_drift and len(started)==3 and role=='old':r[1]=q.API
                return r
        with mock.patch.object(q,'load_packet'),mock.patch.object(q,'Docker',Inert),mock.patch.object(q,'write_new',side_effect=receipt),mock.patch.object(q,'sync_directory',side_effect=sync):
            if directory_failure:
                with self.assertRaises(OSError):q.run(packet,label,'DIP-ARTF-999','unix:///synthetic/engine.sock')
            elif failure or cleanup_drift:
                with self.assertRaises(ValueError):q.run(packet,label,'DIP-ARTF-999','unix:///synthetic/engine.sock')
            else:q.run(packet,label,'DIP-ARTF-999','unix:///synthetic/engine.sock')
        return calls,packet

    def test_joint_success_cleanup_exact_three_exited_ids_no_force(self):
        calls,packet=self.mock_run()
        removed=[a for a in calls if a[0]=='rm']
        self.assertEqual(removed,[['rm',str(i)*64] for i in (1,2,3)])
        self.assertTrue((packet/'result.json').exists())
        self.assertFalse(json.loads((packet/'result.json').read_text())['applicationStartupProven'])

    def test_phase_failure_retains_created_ids_no_cleanup_or_retry(self):
        calls,packet=self.mock_run(failure='api')
        self.assertFalse(any(a[0]=='rm' for a in calls))
        self.assertEqual(sum(a[:2]==['start','--attach'] for a in calls),2)
        self.assertTrue((packet/'old-id.json').exists());self.assertTrue((packet/'api-id.json').exists())
        self.assertFalse((packet/'worker-id.json').exists());self.assertFalse((packet/'result.json').exists())

    def test_cleanup_image_drift_retains_all_ids(self):
        calls,packet=self.mock_run(cleanup_drift=True)
        self.assertFalse(any(a[0]=='rm' for a in calls));self.assertFalse((packet/'result.json').exists())
        self.assertTrue(all((packet/(r+'-id.json')).exists() for r in q.ROLES))

    def test_partial_backup_uses_existing_2g_not_tmp128m(self):
        self.assertEqual(re.findall(r"const backup='([^']+)'",q.QUALIFICATION_JS),['/backup/partial-backup'])
        self.assertNotIn('/tmp/partial-backup',q.QUALIFICATION_JS)
        self.assertIn("sourceRoots:{auth:'/tmp/partial/auth',data:'/tmp/partial/data'},backupRoot:backup",q.QUALIFICATION_JS)
        self.assertEqual(q.QUALIFICATION_JS.count('backupRoot:'),1)
        self.assertIn('size=2147483648',q.TMPFS['/backup'])
        self.assertIn('size=134217728',q.TMPFS['/tmp'])
        self.assertGreater(2*q.GIB,800*q.MIB)
        self.assertEqual(re.findall(r"'/backup/(pre|post)'",q.QUALIFICATION_JS),['pre','pre','pre','post','pre','post','post'])

    def test_exclusive_receipt_file_closed_then_parent_fsync_before_return(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory).resolve()/'receipt.json';events=[]
            real_fsync=q.os.fsync;real_close=q.os.close
            def fsync(fd):
                events.append('directory_fsync' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file_fsync')
                real_fsync(fd)
            def close(fd):
                events.append('directory_close' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file_close')
                real_close(fd)
            with mock.patch.object(q.os,'fsync',side_effect=fsync),mock.patch.object(q.os,'close',side_effect=close):
                q.write_new(p,b'{}');events.append('returned')
            self.assertEqual(events,['file_fsync','file_close','directory_fsync','directory_close','returned'])

    def test_prepare_packet_parent_is_durable_before_success(self):
        with tempfile.TemporaryDirectory() as directory:
            packet=Path(directory).resolve()/'packet';events=[];real_sync=q.sync_directory
            def sync(p):events.append(p);real_sync(p)
            with mock.patch.object(q,'build_packet',return_value=({'qualification.mjs':b'public'}, {'synthetic':True})),mock.patch.object(q,'sync_directory',side_effect=sync):
                self.assertEqual(q.prepare(packet),q.sha(q.canonical({'synthetic':True})))
            self.assertEqual(events[0],packet.parent)
            self.assertEqual(events[1:],[packet,packet,packet])

    def test_prepare_parent_fsync_failure_retains_partial_no_engine(self):
        with tempfile.TemporaryDirectory() as directory:
            packet=Path(directory).resolve()/'packet'
            with mock.patch.object(q,'build_packet',return_value=({},{})),mock.patch.object(q,'sync_directory',side_effect=OSError('SYNTHETIC_PARENT_FSYNC_FAILURE')),mock.patch.object(q,'Docker',side_effect=AssertionError('NO_ENGINE')):
                with self.assertRaises(OSError):q.prepare(packet)
                with self.assertRaises(FileExistsError):q.prepare(packet)
            self.assertTrue(packet.is_dir());self.assertFalse((packet/'client').exists())

    def test_attempt_directory_fsync_failure_before_any_engine_call_retains_hold(self):
        calls,packet=self.mock_run(directory_failure='attempt.json')
        self.assertEqual(calls,[]);self.assertTrue((packet/'attempt.json').exists())
        self.assertFalse((packet/'old-id.json').exists());self.assertFalse((packet/'result.json').exists())
        with mock.patch.object(q,'load_packet'),mock.patch.object(q,'Docker',side_effect=AssertionError('NO_ENGINE')):
            with self.assertRaises(FileExistsError):q.run(packet,self.label,'DIP-ARTF-999','unix:///synthetic/engine.sock')

    def test_id_directory_fsync_failure_retains_created_id_no_start_no_retry(self):
        calls,packet=self.mock_run(directory_failure='old-id.json')
        self.assertEqual(sum(a[0]=='create' for a in calls),1)
        self.assertFalse(any(a[0] in ('start','rm') for a in calls))
        self.assertTrue((packet/'attempt.json').exists());self.assertTrue((packet/'old-id.json').exists())
        self.assertFalse((packet/'result.json').exists())
        with mock.patch.object(q,'load_packet'),mock.patch.object(q,'Docker',side_effect=AssertionError('NO_ENGINE')):
            with self.assertRaises(FileExistsError):q.run(packet,self.label,'DIP-ARTF-999','unix:///synthetic/engine.sock')

    def test_stage_and_snapshot_pins_mandatory_before_packet_create(self):
        with mock.patch.object(q,'read_file',return_value=b'{"wrong":"public"}'):
            with self.assertRaises(ValueError):q.prepare(self.packet)


class DiagnosticTests(unittest.TestCase):
    """Only NEW diagnostic mocks; never invoke legacy OLD/worker qualification."""
    def setUp(self):
        self.no_process=mock.patch.object(q.subprocess,'Popen',side_effect=AssertionError('REAL_PROCESS_FORBIDDEN'))
        self.no_process.start();self.addCleanup(self.no_process.stop)
        self.packet=Path('/private/tmp/dip-preservation-images-api-diagnostic-20261013-r1')
        self.label='a'*64;self.ident='b'*64

    def envelope(self,packet=None,label=None,argv=None,state='created',rc=0):
        packet=packet or self.packet;label=label or self.label
        argv=argv or q.diagnostic_command(self.packet,label)
        r=record(packet,'api',label,self.ident,argv,state)
        r[2]='/dip-preservation-api-diagnostic-'+label[:16]
        r[4]={q.DIAG_LABEL:label};r[5]['Tmpfs']=dict(q.DIAG_TMPFS)
        r[6]=[{'Type':'bind','RW':False,'Source':str(packet/n),'Destination':'/'+n} for n in q.DIAG_FILES]
        r[3]['ExitCode']=rc
        return r

    def test_frozen_consumed_payload_and_all_original_checks_retained(self):
        self.assertEqual(q.sha(q.QUALIFICATION_JS.encode()),q.FROZEN_R2['programSha256'])
        self.assertEqual(q.FROZEN_R2['packetSha256'],'63e05982518de8ca7c24bf7610f5381bd208dae30ad060f42e76a602079b7f3e')
        for fragment in ["assert.equal(process.getuid(),65532)","assert.equal(process.getgid(),65532)",
            "assert.equal(process.platform,'linux')","assert.equal(process.arch,'arm64')",
            "['HOME','PATH','TMPDIR','TSX_DISABLE_CACHE']","assert.equal(binaries.length,1)",
            'assert.equal(ast.parseDiagnostics.length,0)','assert.equal(actual,expected)',
            "assert(!fs.existsSync(expected.slice(0,-3)+'.js'))",'assert(seen.size<=108)',
            'assert(edges.length+deps.size<=1024)','import.meta.resolve(spec,pathToFileURL(p).href)',
            "real.startsWith('/app/node_modules/')||real.startsWith('/app/server/api/node_modules/')",
            'assert.equal(manifest.files.length,108)','assert.equal(b.length,f.bytes)','assert.equal(sha(b),f.sha256)',
            'fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW',"ensure(s.nlink===1,'MULTILINK')",
            "ensure(s.isFile(),'NOT_REGULAR')","ensure(s.size<=cap,'OVERSIZE')",
            "assert.equal(info.betterSqlite,'12.11.1')",'assert.equal(fs.lstatSync(p).ino,s.ino)']:
            self.assertIn(fragment,q.DIAGNOSTIC_JS)
        for forbidden in ['async function storage','/snapshot.mjs','/source/auth','/source/data','quota_attempt',
                          'spawnSync','await import(','import(entry)','NestFactory','runWorker(','fetch(']:
            self.assertNotIn(forbidden,q.DIAGNOSTIC_JS)
        self.assertIn("const p='/tmp/native.sqlite'",q.DIAGNOSTIC_JS)
        self.assertIn('e?.[failureReason]??reason',q.DIAGNOSTIC_JS)
        self.assertNotIn('e.message',q.DIAGNOSTIC_JS)
        self.assertNotIn('console.',q.DIAGNOSTIC_JS)

    def test_closed_instrumentation_vocabulary(self):
        for c,r in re.findall(r"(?:mark|at)\('([A-Z_]+)','([A-Z_]+)'",q.DIAGNOSTIC_JS):
            self.assertIn(c,q.CHECKPOINTS);self.assertIn(r,q.REASONS)
        for r in re.findall(r"ensure\([^;]+?'([A-Z_]+)'\)",q.DIAGNOSTIC_JS):self.assertIn(r,q.REASONS)
        self.assertIn("emit(false,checkpoint,'TIME_LIMIT')",q.DIAGNOSTIC_JS)

    def test_exact_new_api_envelope_and_namespace(self):
        argv=q.diagnostic_command(self.packet,self.label)
        self.assertIn(q.API,argv);self.assertNotIn(q.OLD,argv);self.assertNotIn(q.WORKER,argv)
        self.assertEqual(argv[-3:],['/qualification.mjs','api','45000'])
        self.assertEqual(argv.count('--mount'),2);self.assertEqual(argv.count('--tmpfs'),2)
        for flag,value in [('--user','65532:65532'),('--memory','2147483648'),('--memory-swap','2147483648'),
                           ('--cpus','1'),('--pids-limit','64'),('--network','none'),('--pull','never')]:
            self.assertEqual(argv[argv.index(flag)+1],value)
        self.assertNotIn('/source/',str(argv));self.assertNotIn('snapshot.mjs',str(argv))
        self.assertNotIn('--env-file',argv);self.assertNotIn('--env',argv)
        self.assertIn('--import',argv);self.assertIn('--experimental-import-meta-resolve',argv)
        for state in ('created','exited'):
            q.diagnostic_guard(self.envelope(state=state),self.ident,self.packet,self.label,argv,state)
        q.diagnostic_guard(self.envelope(state='exited',rc=1),self.ident,self.packet,self.label,argv,'exited')
        for p in ['/private/tmp/dip-preservation-images-20261012-r1','/private/tmp/dip-preservation-images-api-diagnostic-../escape']:
            with self.assertRaises(ValueError):q.diagnostic_name(Path(p))

    def test_guard_identity_resources_mounts_and_state_failclosed(self):
        argv=q.diagnostic_command(self.packet,self.label)
        changes=[lambda r:r.__setitem__(0,'c'*64),lambda r:r.__setitem__(1,q.OLD),lambda r:r.__setitem__(2,'/old'),
                 lambda r:r.__setitem__(4,{q.LABEL:self.label}),lambda r:r[4].update({'com.docker.compose.project':'stand'}),
                 lambda r:r[5].update(Memory=q.GIB),lambda r:r[5].update(Tmpfs=q.TMPFS),
                 lambda r:r[5].update(CapAdd=['CHOWN']),lambda r:r[5].update(NetworkMode='bridge'),
                 lambda r:r[6][0].update(RW=True),lambda r:r[6][0].update(Source='/original/auth'),
                 lambda r:r[3].update(OOMKilled=True),lambda r:r[3].update(Running=True),
                 lambda r:r[3].update(Paused=True),lambda r:r[3].update(Error='private-canary')]
        for change in changes:
            r=self.envelope(state='exited');change(r)
            with self.assertRaises(ValueError):q.diagnostic_guard(r,self.ident,self.packet,self.label,argv,'exited')

    def test_exact_closed_receipt_no_duplicate_extra_or_canary(self):
        good=q.diagnostic_report(False,'GRAPH_RESOLVE','RESOLVE_MISMATCH')
        self.assertEqual(q.parse_diagnostic(q.canonical(good)),good)
        bad=[b'{"code":"API_PROBE_CLASSIFIED","ok":false,"ok":true,"checkpoint":"COMPLETE","reason":"PASS"}',
             q.canonical({**good,'private':'private-canary'}),q.canonical({**good,'reason':'private-canary'}),
             q.canonical({**good,'checkpoint':'private-canary'}),q.canonical({**good,'ok':1}),
             q.canonical({**good,'ok':True}),q.canonical({**good,'reason':'PASS'}),b'x'*2049]
        for raw in bad:
            with self.assertRaises((ValueError,TypeError)):q.parse_diagnostic(raw)

    def simulated(self, *, ok=False, empty=False, stderr=False, rc_drift=False, fsync_failure=None):
        directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup)
        packet=Path(directory.name).resolve();calls=[];events=[];pending=[None]
        payloads={'qualification.mjs':b'public-synthetic-program','sources.json':b'public-synthetic-manifest'}
        plan={'files':{n:q.sha(b) for n,b in payloads.items()}}
        for n,b in payloads.items():q.write_new(packet/n,b,0o444)
        rawplan=q.canonical(plan);q.write_new(packet/'plan.json',rawplan);label=q.sha(rawplan)
        real_write=q.write_new;real_sync=q.sync_directory
        def write(p,raw,mode=0o600):
            pending[0]=p.name
            try:real_write(p,raw,mode)
            finally:pending[0]=None
        def sync(p):
            if pending[0]==fsync_failure and fsync_failure is not None:raise OSError('private-fsync-canary')
            real_sync(p)
            if pending[0]:events.append(pending[0])
        report=q.diagnostic_report(ok,'COMPLETE' if ok else 'GRAPH_RESOLVE','PASS' if ok else 'RESOLVE_MISMATCH')
        case=self
        class Inert:
            def __init__(self,p,e,deadline):self.deadline=deadline;self.argv=None;self.state='created'
            def call(self,args,timeout=20):
                calls.append(args)
                if args[:2]==['image','inspect']:
                    assert 'attempt.json' in events
                    return b'\n'.join(q.canonical(v).strip() for v in [q.API,'linux','arm64','/app/server/api',None])
                if args[0]=='create':
                    assert 'attempt.json' in events and 'image.json' in events
                    self.argv=args;return case.ident.encode()+b'\n'
                raise AssertionError('UNREVIEWED_ENGINE_CALL')
            def inspect(self,ident):
                calls.append(['inspect',ident]);assert 'api-id.json' in events
                return case.envelope(packet,label,self.argv,self.state,0 if self.state=='created' or ok else 1)
            def attach_probe(self,ident):
                calls.append(['start','--attach',ident]);assert 'api-id.json' in events
                self.state='exited'
                return (2 if rc_drift else 0 if ok else 1),b'' if empty else q.canonical(report),stderr
        with mock.patch.object(q,'load_diagnostic',return_value=plan),mock.patch.object(q,'diagnostic_name'),\
             mock.patch.object(q,'DiagnosticDocker',Inert),mock.patch.object(q,'write_new',side_effect=write),\
             mock.patch.object(q,'sync_directory',side_effect=sync):
            result=q.run_diagnostic(packet,label,'DIP-ARTF-999','unix:///synthetic/engine.sock')
        with mock.patch.object(q,'load_diagnostic',return_value=plan),mock.patch.object(q,'DiagnosticDocker',side_effect=AssertionError('NO_RETRY')):
            repeat=q.run_diagnostic(packet,label,'DIP-ARTF-999','unix:///synthetic/engine.sock')
        self.assertEqual(repeat,q.diagnostic_report(False,'HOST_ATTEMPT','GUARD_REFUSED'))
        return result,calls,packet,events

    def test_one_fresh_api_failure_is_classified_not_retried_or_cleaned(self):
        result,calls,packet,events=self.simulated()
        self.assertEqual(result,q.diagnostic_report(False,'GRAPH_RESOLVE','RESOLVE_MISMATCH'))
        self.assertEqual(sum(a[0]=='create' for a in calls),1)
        self.assertEqual(sum(a[0]=='start' for a in calls),1)
        self.assertFalse(any(a[0] in ('rm','logs','exec','stop','kill','restart') for a in calls))
        self.assertNotIn(q.OLD,str(calls));self.assertNotIn(q.WORKER,str(calls))
        self.assertEqual(events,['attempt.json','image.json','api-id.json','result.json'])
        self.assertEqual(json.loads((packet/'result.json').read_bytes()),result)

    def test_pass_is_diagnostic_only_retained_no_qualification(self):
        result,calls,packet,_=self.simulated(ok=True)
        self.assertEqual(result,q.diagnostic_report(True,'COMPLETE','PASS'))
        self.assertEqual(set(result),{'code','ok','checkpoint','reason'})
        self.assertFalse(any(a[0]=='rm' for a in calls));self.assertTrue((packet/'api-id.json').exists())

    def test_preload_boundary_suppresses_private_stderr_without_guessing(self):
        result,_,packet,_=self.simulated(empty=True,stderr=True)
        self.assertEqual(result,q.diagnostic_report(False,'BOOTSTRAP','PRELOAD_OR_PROTOCOL'))
        self.assertNotIn(b'private', (packet/'result.json').read_bytes())

    def test_protocol_stderr_and_exit_disagreement_remain_hold(self):
        for kwargs in ({'stderr':True},{'rc_drift':True}):
            result,_,packet,_=self.simulated(**kwargs)
            self.assertFalse(result['ok']);self.assertEqual(result['reason'],'GUARD_REFUSED')
            self.assertFalse((packet/'result.json').exists())

    def test_attempt_fsync_failure_prevents_engine_and_is_not_adopted(self):
        result,calls,packet,_=self.simulated(fsync_failure='attempt.json')
        self.assertEqual(calls,[]);self.assertEqual(result['checkpoint'],'HOST_ATTEMPT')
        self.assertTrue((packet/'attempt.json').exists());self.assertFalse((packet/'api-id.json').exists())

    def test_id_fsync_failure_prevents_start_retains_own_id(self):
        result,calls,packet,_=self.simulated(fsync_failure='api-id.json')
        self.assertEqual(sum(a[0]=='create' for a in calls),1)
        self.assertFalse(any(a[0] in ('start','rm') for a in calls))
        self.assertEqual(result['checkpoint'],'HOST_CREATE');self.assertTrue((packet/'api-id.json').exists())

    def test_prepare_parent_fsync_failure_retains_exclusive_packet_no_retry(self):
        with tempfile.TemporaryDirectory() as d:
            packet=Path(d).resolve()/'packet'
            with mock.patch.object(q,'build_diagnostic',return_value=({},{})),\
                 mock.patch.object(q,'sync_directory',side_effect=OSError('private-canary')):
                with self.assertRaises(OSError):q.prepare_diagnostic(packet)
                with self.assertRaises(FileExistsError):q.prepare_diagnostic(packet)
            self.assertTrue(packet.is_dir());self.assertFalse((packet/'client').exists())

    def test_new_packet_loader_binds_exact_path_pin_and_client_not_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            packet=Path(d).resolve()/'packet'
            with mock.patch.object(q,'diagnostic_name'),mock.patch.object(q,'build_packet',return_value=({'sources.json':b'public-synthetic'},{})):
                _,plan=q.build_diagnostic(packet)
                with mock.patch.object(q,'build_diagnostic',return_value=({'qualification.mjs':q.DIAGNOSTIC_JS.encode(),'sources.json':b'public-synthetic'},plan)):
                    pin=q.prepare_diagnostic(packet)
                self.assertEqual(q.load_diagnostic(packet,pin),plan)
                self.assertEqual(plan['packet'],str(packet))
                with self.assertRaises(ValueError):q.load_diagnostic(packet,'c'*64)
                (packet/'client').rmdir();alias=packet/'synthetic-empty';alias.mkdir(mode=0o700)
                os.symlink(alias,packet/'client')
                with self.assertRaises(ValueError):q.load_diagnostic(packet,pin)

    def test_directory_vocabulary_is_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve()
            for i in range(9):q.write_new(root/str(i),b'public-synthetic')
            with self.assertRaises(ValueError):q.diagnostic_entries(root)

    def test_diagnostic_cli_requires_separate_authority_no_error_echo(self):
        import io
        cases=[['run-diagnostic','--packet',str(self.packet)],
               ['run-diagnostic','--packet',str(self.packet),'--authorize-synthetic-docker-once'],
               ['run-diagnostic','--packet','private-canary','--packet',str(self.packet)],
               ['prepare-diagnostic','--packet',str(self.packet),'--docker-host','private-canary']]
        for argv in cases:
            out=io.StringIO()
            with mock.patch.object(q.sys,'argv',['probe',*argv]),mock.patch.object(q.sys,'stdout',out),\
                 mock.patch.object(q.sys,'stderr',io.StringIO()),mock.patch.object(q,'run_diagnostic',side_effect=AssertionError('NO_RUN')):
                self.assertEqual(q.diagnostic_main(),1)
            report=q.parse_diagnostic(out.getvalue().encode());self.assertFalse(report['ok'])
            self.assertNotIn('private-canary',out.getvalue())


def native_fact():
    return {'node':'v24.0.0','abi':'137','sqlite':'3.synthetic','betterSqlite':'12.11.1',
            'nativeSha256':'c'*64,'nodeSha256':'d'*64}


def phase_fact(role,ok=True):
    if not ok:return {'code':'NEW_SOURCE_PHASE','ok':False,'role':role,'checkpoint':'GRAPH_RESOLVE','reason':'RESOLVE_MISMATCH'}
    entry='src/oci/nginx-local.main.ts' if role=='api' else 'src/worker/nginx-local-worker.main.ts'
    return {'code':'NEW_SOURCE_PHASE','ok':True,'role':role,'native':native_fact(),
            'proof':{'entry':'/app/server/api/'+entry,'launchCommand':['node','--import','tsx',entry],
                     'entrypoint':{'path':'/usr/local/bin/docker-entrypoint.sh','sha256':'e'*64},
                     'sourceFiles':1,'edges':[],'dependencies':{},'tsx':'4.synthetic',
                     'typescript':'5.synthetic','appBodiesEvaluated':False,'externalPackageBodiesQualified':False}}


class ContinuationTests(unittest.TestCase):
    def setUp(self):
        no_process=mock.patch.object(q.subprocess,'Popen',side_effect=AssertionError('REAL_PROCESS_FORBIDDEN'))
        no_process.start();self.addCleanup(no_process.stop)
        self.packet=Path('/private/tmp/dip-preservation-images-new-closure-20261013-r2');self.label='a'*64

    def envelope(self,packet,role,label,ident,argv,state='created',rc=0):
        r=record(packet,role,label,ident,argv,state)
        r[2]='/dip-preservation-new-closure-'+role+'-'+label[:16];r[4]={q.NEW_LABEL:label}
        r[5]['Tmpfs']=dict(q.DIAG_TMPFS)
        r[6]=[{'Type':'bind','RW':False,'Source':str(packet/n),'Destination':'/'+n} for n in q.DIAG_FILES]
        r[3]['ExitCode']=rc;return r

    def test_consumed_diagnostic_and_r2_frozen_narrow_reader_only(self):
        self.assertEqual(q.sha(q.DIAGNOSTIC_JS.encode()),q.FROZEN_DIAGNOSTIC['programSha256'])
        self.assertEqual(q.sha(q.QUALIFICATION_JS.encode()),q.FROZEN_R2['programSha256'])
        self.assertEqual(q.CONTINUATION_JS.count('sha(readPackageEntry(real,8*1024**2))'),1)
        self.assertIn("ensure(s.nlink===1,'MULTILINK')",q.CONTINUATION_JS)
        self.assertIn('ensure(s.nlink>=1n',q.PUBLIC_ENTRY_READ_JS)
        self.assertIn('x.dev,x.ino,x.nlink,x.mode,x.size,x.mtimeNs,x.ctimeNs',q.PUBLIC_ENTRY_READ_JS)
        self.assertIn('fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK',q.PUBLIC_ENTRY_READ_JS)
        for assertion in ['assert.equal(actual,expected)',"assert(!fs.existsSync(expected.slice(0,-3)+'.js'))",
                          'assert.equal(manifest.files.length,108)','assert.equal(sha(b),f.sha256)',
                          'import.meta.resolve(spec,pathToFileURL(p).href)','assert.equal(binaries.length,1)']:
            self.assertIn(assertion,q.CONTINUATION_JS)
        for forbidden in ['async function storage','/snapshot.mjs','/source/auth','spawnSync','await import(',"closure('old')"]:
            self.assertNotIn(forbidden,q.CONTINUATION_JS)

    def test_two_selected_images_exact_2g_45s_envelope(self):
        self.assertEqual(q.NEW_ROLES,('api','worker'));self.assertNotIn(q.OLD,q.NEW_IMAGES.values())
        for role in q.NEW_ROLES:
            argv=q.continuation_command(self.packet,role,self.label)
            self.assertEqual(argv.count('--mount'),2);self.assertEqual(argv.count('--tmpfs'),2)
            self.assertEqual(argv[-2:],[role,'45000']);self.assertIn(q.NEW_IMAGES[role],argv)
            self.assertEqual(argv[argv.index('--memory')+1],'2147483648')
            self.assertEqual(argv[argv.index('--user')+1],'65532:65532')
            self.assertNotIn('/app/node_modules/',str(argv));self.assertNotIn('snapshot.mjs',str(argv))
            ident='b'*64;r=self.envelope(self.packet,role,self.label,ident,argv)
            q.continuation_guard(r,ident,self.packet,role,self.label,argv,'created')
        with self.assertRaises(ValueError):q.continuation_command(self.packet,'old',self.label)
        with self.assertRaises(ValueError):q.continuation_name(Path('/private/tmp/dip-preservation-images-api-diagnostic-20261013-r1'))

    def test_dependency_image_mount_alias_and_writable_root_refuse(self):
        for role in q.NEW_ROLES:
            argv=q.continuation_command(self.packet,role,self.label);ident='b'*64
            for mutate in [lambda r:r[5].update(ReadonlyRootfs=False),
                           lambda r:r[6].append({'Type':'bind','RW':False,'Source':'/synthetic','Destination':'/app/node_modules'}),
                           lambda r:r[6].append({'Type':'tmpfs','RW':True,'Destination':'/app/server/api/node_modules'}),
                           lambda r:r.__setitem__(1,q.OLD),lambda r:r[3].update(Running=True),lambda r:r[3].update(OOMKilled=True)]:
                r=self.envelope(self.packet,role,self.label,ident,argv);mutate(r)
                with self.assertRaises(ValueError):q.continuation_guard(r,ident,self.packet,role,self.label,argv,'created')

    def test_phase_protocol_private_fields_and_wrong_role_refuse(self):
        for role in q.NEW_ROLES:
            self.assertEqual(q.continuation_phase(q.canonical(phase_fact(role)),role),phase_fact(role))
            self.assertEqual(q.continuation_phase(q.canonical(phase_fact(role,False)),role),phase_fact(role,False))
        bad=phase_fact('api');bad['native']['private']='canary'
        with self.assertRaises(ValueError):q.continuation_phase(q.canonical(bad),'api')
        with self.assertRaises(ValueError):q.continuation_phase(q.canonical(phase_fact('worker')),'api')
        with self.assertRaises(ValueError):q.continuation_phase(b'x'*65537,'api')
        with self.assertRaises(ValueError):q.continuation_phase(b'{"code":"NEW_SOURCE_PHASE","code":"canary"}','api')

    def simulate(self,failure=None,fsync_failure=None,expiry=False,image_entrypoint='docker-entrypoint.sh',missing_wrapper=False):
        directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup);packet=Path(directory.name).resolve()
        payloads={'qualification.mjs':b'public-only','sources.json':b'public-synthetic'}
        plan={'files':{n:q.sha(b) for n,b in payloads.items()}}
        for n,b in payloads.items():q.write_new(packet/n,b,0o444)
        raw=q.canonical(plan);q.write_new(packet/'plan.json',raw);label=q.sha(raw)
        calls=[];events=[];pending=[None];real_write=q.write_new;real_sync=q.sync_directory;case=self
        def write(p,b,mode=0o600):
            pending[0]=p.name
            try:real_write(p,b,mode)
            finally:pending[0]=None
        def sync(p):
            if pending[0]==fsync_failure and fsync_failure is not None:raise OSError('synthetic-fsync')
            real_sync(p)
            if pending[0]:events.append(pending[0])
        class Inert:
            def __init__(self,p,e,deadline):self.deadline=deadline;self.states={};self.commands={}
            def call(self,args):
                calls.append(args);assert 'attempt.json' in events
                if args[:2]==['image','inspect']:
                    return b'\n'.join(q.canonical(v).strip() for v in [args[-1],'linux','arm64','/app/server/api',None,
                                    None if image_entrypoint is None else [image_entrypoint]])
                if args[0]=='create':
                    role=next(r for r in q.NEW_ROLES if q.NEW_IMAGES[r] in args);ident=str(q.NEW_ROLES.index(role)+1)*64
                    assert role+'-image.json' in events
                    self.states[ident]='created';self.commands[ident]=(role,args);return ident.encode()+b'\n'
                raise AssertionError('UNREVIEWED_COMMAND')
            def inspect(self,ident):
                calls.append(['inspect',ident]);role,argv=self.commands[ident];assert role+'-id.json' in events
                state=self.states[ident]
                return case.envelope(packet,role,label,ident,argv,state,1 if state=='exited' and role==failure else 0)
            def attach_probe(self,ident):
                calls.append(['start','--attach',ident]);role=self.commands[ident][0];assert role+'-id.json' in events
                self.states[ident]='exited';phase=phase_fact(role,role!=failure)
                if missing_wrapper and phase['ok']:phase['proof']['entrypoint']=None
                return (1 if role==failure else 0),q.canonical(phase),False
        with mock.patch.object(q,'continuation_load',return_value=plan),mock.patch.object(q,'continuation_name'),\
             mock.patch.object(q,'ContinuationDocker',Inert),mock.patch.object(q,'write_new',side_effect=write),\
             mock.patch.object(q.time,'monotonic',side_effect=[0,200] if expiry else None,wraps=q.time.monotonic),\
             mock.patch.object(q,'sync_directory',side_effect=sync):
            result=q.continuation_run(packet,label,'DIP-ARTF-999','unix:///synthetic/engine.sock')
        with mock.patch.object(q,'continuation_load',return_value=plan),mock.patch.object(q,'ContinuationDocker',side_effect=AssertionError('NO_RETRY')):
            repeat=q.continuation_run(packet,label,'DIP-ARTF-999','unix:///synthetic/engine.sock')
        self.assertFalse(repeat['ok']);self.assertEqual(repeat['checkpoint'],'HOST_ATTEMPT')
        return result,calls,packet,events

    def test_joint_new_only_success_native_facts_private_no_old_equal_claim(self):
        result,calls,packet,events=self.simulate()
        self.assertEqual(result,q.continuation_report(True,'both','COMPLETE','PASS'))
        self.assertEqual(sum(a[0]=='create' for a in calls),2);self.assertEqual(sum(a[0]=='start' for a in calls),2)
        self.assertNotIn(q.OLD,str(calls));self.assertFalse(any(a[0] in ('rm','logs','exec','stop','kill') for a in calls))
        self.assertEqual(set(result),{'code','ok','role','checkpoint','reason'})
        for role in q.NEW_ROLES:self.assertEqual(json.loads((packet/(role+'-result.json')).read_bytes())['native'],native_fact())
        self.assertEqual(events,['attempt.json','api-image.json','api-id.json','api-result.json','worker-image.json','worker-id.json','worker-result.json','result.json'])

    def test_api_failure_stops_before_worker_and_never_retries(self):
        result,calls,packet,_=self.simulate(failure='api')
        self.assertFalse(result['ok']);self.assertEqual(result['role'],'api')
        self.assertEqual(sum(a[0]=='create' for a in calls),1);self.assertNotIn(q.WORKER,str(calls))
        self.assertFalse((packet/'worker-id.json').exists());self.assertTrue((packet/'api-result.json').exists())

    def test_worker_failure_retains_both_and_no_joint_pass(self):
        result,calls,packet,_=self.simulate(failure='worker')
        self.assertFalse(result['ok']);self.assertEqual(result['role'],'worker')
        self.assertEqual(sum(a[0]=='create' for a in calls),2)
        self.assertTrue((packet/'api-result.json').exists());self.assertTrue((packet/'worker-id.json').exists())
        self.assertFalse(any(a[0]=='rm' for a in calls))

    def test_durable_attempt_and_id_failures_before_engine_or_start(self):
        for point in ('attempt.json','api-id.json'):
            result,calls,packet,_=self.simulate(fsync_failure=point)
            self.assertFalse(result['ok']);self.assertFalse(any(a[0]=='start' for a in calls))
            if point=='attempt.json':self.assertEqual(calls,[])
            else:self.assertEqual(sum(a[0]=='create' for a in calls),1);self.assertTrue((packet/'api-id.json').exists())

    def test_shared_budget_and_per_call_bounds_no_widening(self):
        self.assertIn('deadline=time.monotonic()+150',__import__('inspect').getsource(q.continuation_run))
        self.assertIn('future+55',__import__('inspect').getsource(q.continuation_run))
        d=q.ContinuationDocker(self.packet,'unix:///synthetic/engine.sock',150)
        with mock.patch.object(q.Docker,'call',return_value=b'public') as call:
            d.call(['synthetic'],20);self.assertEqual(call.call_args.args[1],5)
        result,calls,_,_=self.simulate(expiry=True);self.assertFalse(result['ok'])
        self.assertEqual(calls,[])

    def test_prepare_loader_exact_new_plan_and_frozen_no_old_adoption(self):
        with tempfile.TemporaryDirectory() as d:
            packet=Path(d).resolve()/'packet';payloads={'qualification.mjs':q.CONTINUATION_JS.encode(),'sources.json':b'public-only'}
            plan={'format':'new-source-closure-v2','packet':str(packet),'images':q.NEW_IMAGES,'aggregate':q.AGGREGATE,
                  'stageSha256':q.STAGE_SHA,'files':{n:q.sha(b) for n,b in payloads.items()},
                  'authorSha256':q.sha(q.read_file(Path(q.__file__).resolve())),'frozenR2':q.FROZEN_R2,
                  'frozenDiagnostic':q.FROZEN_DIAGNOSTIC,'frozenContinuationR1':q.FROZEN_CONTINUATION_R1,
                  'actorSeconds':150,'programMs':45000,
                  'oldNativeEqualityProven':False,'appStartup':False}
            with mock.patch.object(q,'continuation_build',return_value=(payloads,plan)),mock.patch.object(q,'continuation_name'):
                pin=q.continuation_prepare(packet);self.assertEqual(q.continuation_load(packet,pin),plan)
                with self.assertRaises(FileExistsError):q.continuation_prepare(packet)
                with self.assertRaises(ValueError):q.continuation_load(packet,'c'*64)

    def test_cli_separate_permission_and_closed_no_canary(self):
        import io
        for argv in [['run-new-closure','--packet',str(self.packet)],
                     ['run-new-closure','--packet',str(self.packet),'--authorize-new-api-diagnostic-once'],
                     ['prepare-new-closure','--packet','canary','--packet',str(self.packet)]]:
            out=io.StringIO()
            with mock.patch.object(q.sys,'argv',['probe',*argv]),mock.patch.object(q.sys,'stdout',out),mock.patch.object(q.sys,'stderr',io.StringIO()):
                self.assertEqual(q.continuation_main(),1)
            r=json.loads(out.getvalue());self.assertFalse(r['ok']);self.assertNotIn('canary',out.getvalue())


def package_policy_fixture():
    strict=next(line for line in q.DIAGNOSTIC_JS.splitlines() if line.startswith('function read(p,'))
    return r'''import rawAssert from 'node:assert/strict';import path from 'node:path';
const assert=rawAssert;let checkpoint='GRAPH_DEPENDENCY',reason='DEPENDENCY_ESCAPE';const failureReason=Symbol('closed');
function mark(c,r){reason=r;}function reject(r){const e=new Error('SYNTHETIC');e[failureReason]=r;throw e;}function ensure(v,r){if(!v)reject(r);}
const body=Buffer.from('public-synthetic-only');let config={},reads=0,opened=0,closed=0,offset=0;
const base={dev:1n,ino:2n,nlink:2n,mode:33188n,size:BigInt(body.length),mtimeNs:3n,ctimeNs:4n,uid:65532n,gid:65532n};
function stat(big,drift={}){const s={...base,...config.initial,...drift};if(!big){for(const k of Object.keys(s))s[k]=Number(s[k]);s.mtimeMs=3;s.ctimeMs=4;}s.isFile=()=>!config.nonregular;return s;}
const fs={constants:{O_RDONLY:0,O_NOFOLLOW:1,O_NONBLOCK:2},
 realpathSync:p=>config.alias??p,
 openSync(p,flags){assert(flags&1);opened++;offset=0;return 7;},
 fstatSync(fd,options){reads++;return stat(options?.bigint,reads>1?config.fdDrift:undefined);},
 lstatSync(p,options){return stat(options?.bigint,config.pathDrift);},
 readSync(fd,b,start,length){const n=Math.min(length,body.length-offset);body.copy(b,start,offset,offset+n);offset+=n;return n;},
 readFileSync:()=>Buffer.from(body),closeSync(){closed++;}};
function reset(c={}){config=c;reads=0;opened=0;closed=0;offset=0;}
''' + strict+'\n'+q.PUBLIC_ENTRY_READ_JS+r'''
for(const p of ['/app/node_modules/.pnpm/example/node_modules/example/index.js','/app/server/api/node_modules/example/index.js']){
 for(const nlink of [1n,2n,12n]){reset({initial:{nlink}});assert.deepEqual(readPackageEntry(p,1024),body);assert.equal(opened,1);assert.equal(closed,1);}
}
for(const p of ['/qualification.mjs','/sources.json','/backup/pre/manifest.json','/source/auth/auth.sqlite','/app/server/api/src/source.ts','/app/node_modules-evil/a','/app/server/api/node_modules-evil/a','/app/node_modules/a/../b']){
 reset();assert.throws(()=>readPackageEntry(p,1024));assert.equal(opened,0);
}
for(const p of ['/qualification.mjs','/app/server/api/src/source.ts','/backup/private.json']){reset();assert.throws(()=>read(p));assert.equal(closed,1);}
for(const field of ['dev','ino','nlink','mode','size','mtimeNs','ctimeNs','uid','gid']){
 for(const location of ['fdDrift','pathDrift']){reset({[location]:{[field]:base[field]+1n}});assert.throws(()=>readPackageEntry('/app/node_modules/example/index.js',1024));assert.equal(closed,1);}
}
for(const config of [{initial:{nlink:0n}},{initial:{size:1025n}},{nonregular:true},{alias:'/outside/private'}]){
 reset(config);assert.throws(()=>readPackageEntry('/app/node_modules/example/index.js',1024));assert.equal(closed,opened);
}
reset();assert.throws(()=>readPackageEntry('/app/node_modules/example/index.js',8*1024**2+1));assert.equal(opened,0);
process.stdout.write('{"code":"SYNTHETIC_PACKAGE_POLICY_CHECKED","ok":true}\n');
'''


class PackagePolicyTests(unittest.TestCase):
    def test_actual_js_policy_with_fake_fs_hardlinks_and_stat_drift(self):
        # Executes only stdlib JS and the reader with an entirely fake filesystem.
        # No SQLite/tsx/application import, actual /app read or Docker subprocess.
        result=q.subprocess.run(['node','--input-type=module'],input=package_policy_fixture().encode(),
                                capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0);self.assertEqual(result.stderr,b'')
        self.assertEqual(result.stdout,b'{"code":"SYNTHETIC_PACKAGE_POLICY_CHECKED","ok":true}\n')


class LoaderContinuationTests(unittest.TestCase):
    envelope=ContinuationTests.envelope
    simulate=ContinuationTests.simulate

    def setUp(self):
        no_process=mock.patch.object(q.subprocess,'Popen',side_effect=AssertionError('REAL_PROCESS_FORBIDDEN'))
        no_process.start();self.addCleanup(no_process.stop)
        self.packet=Path('/private/tmp/dip-preservation-images-new-closure-20261013-r2');self.label='a'*64

    def test_r1_frozen_and_only_two_loader_reads_changed(self):
        self.assertEqual(q.sha(q.CONTINUATION_R1_JS.encode()),q.FROZEN_CONTINUATION_R1['programSha256'])
        self.assertEqual(q.sha(q.DIAGNOSTIC_JS.encode()),q.FROZEN_DIAGNOSTIC['programSha256'])
        self.assertEqual(q.sha(q.QUALIFICATION_JS.encode()),q.FROZEN_R2['programSha256'])
        self.assertEqual(q.CONTINUATION_JS.count("readLoaderMetadata('entrypoint',wrapper)"),1)
        self.assertEqual(q.CONTINUATION_JS.count("readLoaderMetadata('tsx',fs.realpathSync(req.resolve('tsx/package.json')))"),1)
        self.assertIn("ensure(s.nlink===1,'MULTILINK')",q.CONTINUATION_JS)
        for unchanged in ["read(req.resolve('better-sqlite3/package.json'))",'read(binaries[0],32*1024**2)',
                          'read(process.execPath,128*1024**2)','read(p);assert.equal(b.length,f.bytes)',
                          'assert.equal(actual,expected)',"assert(!fs.existsSync(expected.slice(0,-3)+'.js'))",
                          'sha(readPackageEntry(real,8*1024**2))','assert(fs.existsSync(wrapper))']:
            self.assertIn(unchanged,q.CONTINUATION_JS)

    def test_consumed_r1_namespace_refuses_before_any_state_read(self):
        old=Path('/private/tmp/dip-preservation-images-new-closure-20261013-r1')
        with mock.patch.object(q.os,'lstat',side_effect=AssertionError('NO_PACKET_READ')),\
             mock.patch.object(q,'read_file',side_effect=AssertionError('NO_PACKET_READ')):
            r=q.continuation_run(old,q.FROZEN_CONTINUATION_R1['packetSha256'],'DIP-ARTF-999','unix:///synthetic/engine.sock')
        self.assertEqual(r['checkpoint'],'HOST_PACKET');self.assertFalse(r['ok'])
        q.continuation_name(self.packet)

    def test_loader_image_contract_required_before_create(self):
        for entry in (None,'unreviewed-wrapper'):
            r,calls,packet,_=self.simulate(image_entrypoint=entry)
            self.assertFalse(r['ok']);self.assertEqual(r['checkpoint'],'HOST_IMAGE')
            self.assertFalse(any(a[0] in ('create','start') for a in calls))
            self.assertFalse((packet/'api-id.json').exists())

    def test_missing_wrapper_proof_refuses_before_worker(self):
        r,calls,packet,_=self.simulate(missing_wrapper=True)
        self.assertFalse(r['ok']);self.assertEqual(r['checkpoint'],'HOST_RECEIPT')
        self.assertEqual(sum(a[0]=='create' for a in calls),1)
        self.assertTrue((packet/'api-id.json').exists());self.assertFalse((packet/'worker-id.json').exists())
        self.assertFalse((packet/'api-result.json').exists())

    def test_r2_success_still_native_private_no_old_pass_or_cleanup(self):
        r,calls,packet,_=self.simulate()
        self.assertEqual(r,q.continuation_report(True,'both','COMPLETE','PASS'))
        self.assertNotIn(q.OLD,str(calls));self.assertFalse(any(a[0] in ('rm','logs','exec','stop','kill') for a in calls))
        self.assertEqual(sum(a[0]=='create' for a in calls),2)
        for role in q.NEW_ROLES:self.assertTrue((packet/(role+'-result.json')).exists())

    def test_new_envelope_denies_wrapper_or_metadata_mounts(self):
        for destination in ('/usr/local/bin/docker-entrypoint.sh','/usr/local/bin','/app/node_modules/tsx/package.json'):
            argv=q.continuation_command(self.packet,'api',self.label);ident='b'*64
            r=self.envelope(self.packet,'api',self.label,ident,argv)
            r[6].append({'Type':'bind','RW':False,'Source':'/synthetic-public','Destination':destination})
            with self.assertRaises(ValueError):q.continuation_guard(r,ident,self.packet,'api',self.label,argv,'created')
        self.assertEqual(argv[-1],'45000');self.assertEqual(argv[argv.index('--memory')+1],'2147483648')


def loader_policy_fixture():
    header=package_policy_fixture().split("for(const p of ['/app/node_modules/.pnpm/example/",1)[0]
    return header+r'''
const req={resolve:spec=>{assert.equal(spec,'tsx/package.json');return config.tsxResolved??'/app/node_modules/.pnpm/tsx@4.synthetic/node_modules/tsx/package.json';}};
''' + q.PUBLIC_LOADER_READ_JS+r'''
for(const p of ['/app/node_modules/.pnpm/tsx@4.synthetic/node_modules/tsx/package.json','/app/server/api/node_modules/tsx/package.json']){
 for(const nlink of [1n,2n,12n]){reset({initial:{nlink},tsxResolved:p});assert.deepEqual(readLoaderMetadata('tsx',p),body);assert.equal(closed,1);}
}
const wrapper='/usr/local/bin/docker-entrypoint.sh';
for(const nlink of [1n,2n,12n]){reset({initial:{nlink}});assert.deepEqual(readLoaderMetadata('entrypoint',wrapper),body);assert.equal(closed,1);}
for(const p of ['/usr/local/bin/other.sh','/usr/local/bin/../bin/docker-entrypoint.sh','/app/node_modules/tsx/package.json','/backup/pre/manifest.json','/qualification.mjs','/source/auth/auth.sqlite']){
 reset();assert.throws(()=>readLoaderMetadata('entrypoint',p));assert.equal(opened,0);
}
for(const p of ['/app/node_modules/other/package.json','/app/node_modules/tsx/index.js','/app/server/api/src/tsx/package.json','/app/node_modules-evil/tsx/package.json','/private/tsx/package.json']){
 reset({tsxResolved:p});assert.throws(()=>readLoaderMetadata('tsx',p));assert.equal(opened,0);
}
reset();assert.throws(()=>readLoaderMetadata('tsx','/app/node_modules/tsx/package.json'));assert.equal(opened,0);
reset();assert.throws(()=>readLoaderMetadata('arbitrary',wrapper));assert.equal(opened,0);
for(const kind of ['tsx','entrypoint']){
 const p=kind==='tsx'?'/app/node_modules/.pnpm/tsx@4.synthetic/node_modules/tsx/package.json':wrapper;
 for(const field of ['dev','ino','nlink','mode','size','mtimeNs','ctimeNs','uid','gid']){
  for(const location of ['fdDrift','pathDrift']){reset({[location]:{[field]:base[field]+1n}});assert.throws(()=>readLoaderMetadata(kind,p));assert.equal(closed,1);}
 }
 for(const cfg of [{initial:{nlink:0n}},{initial:{size:BigInt(kind==='tsx'?4*1024**2+1:65537)}},{nonregular:true},{alias:'/outside/private'}]){
  reset(cfg);assert.throws(()=>readLoaderMetadata(kind,p));assert.equal(closed,opened);
 }
}
for(const p of ['/qualification.mjs','/app/server/api/src/source.ts','/backup/private.json']){reset();assert.throws(()=>read(p));assert.equal(closed,1);}
process.stdout.write('{"code":"SYNTHETIC_LOADER_POLICY_CHECKED","ok":true}\n');
'''


class LoaderPolicyTests(unittest.TestCase):
    def test_actual_loader_reader_hardlinks_whitelist_caps_and_stat_drift_fake_fs(self):
        result=q.subprocess.run(['node','--input-type=module'],input=loader_policy_fixture().encode(),capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0);self.assertEqual(result.stderr,b'')
        self.assertEqual(result.stdout,b'{"code":"SYNTHETIC_LOADER_POLICY_CHECKED","ok":true}\n')


class WorkerOnlyTests(unittest.TestCase):
    def setUp(self):
        patch=mock.patch.object(q.subprocess,'Popen',side_effect=AssertionError('REAL_PROCESS_FORBIDDEN'))
        patch.start();self.addCleanup(patch.stop)
        self.packet=Path('/private/tmp/dip-preservation-images-worker-closure-20261013-r1')
        self.pin='a'*64;self.ident='b'*64
        self.base={'com.docker.compose.project':'synthetic-image-baseline','public-test':'baseline-only'}

    def envelope(self,packet=None,pin=None,argv=None,state='created'):
        packet=packet or self.packet;pin=pin or self.pin;argv=argv or q.worker_command(self.packet,pin)
        r=record(packet,'worker',pin,self.ident,argv,state)
        r[2]='/dip-preservation-worker-closure-'+pin[:16];r[4]={**self.base,q.WORKER_LABEL:pin}
        r[5]['Tmpfs']=dict(q.DIAG_TMPFS)
        r[6]=[{'Type':'bind','RW':False,'Source':str(packet/n),'Destination':'/'+n} for n in q.DIAG_FILES]
        return r

    def test_exact_inherited_labels_pass_but_no_name_or_label_authority(self):
        baseline=q.frozen_image_labels(self.base);argv=q.worker_command(self.packet,self.pin)
        for state in ('created','exited'):
            q.worker_guard(self.envelope(state=state),self.ident,self.packet,self.pin,argv,baseline,state)
        for index,value in [(0,'c'*64),(1,q.API),(2,'/foreign-name'),(9,'0:0')]:
            r=self.envelope();r[index]=value
            with self.assertRaises(ValueError):q.worker_guard(r,self.ident,self.packet,self.pin,argv,baseline,'created')

    def test_added_removed_changed_labels_and_forged_own_refuse(self):
        baseline=q.frozen_image_labels(self.base);argv=q.worker_command(self.packet,self.pin)
        for mutate in [lambda d:d.update({'extra':'canary'}),lambda d:d.pop('public-test'),
                       lambda d:d.update({'com.docker.compose.project':'different'}),lambda d:d.update({'public-test':'drift'}),
                       lambda d:d.update({q.WORKER_LABEL:'c'*64}),lambda d:d.pop(q.WORKER_LABEL),
                       lambda d:d.update({q.NEW_LABEL:self.pin})]:
            r=self.envelope();mutate(r[4])
            with self.assertRaises(ValueError):q.worker_guard(r,self.ident,self.packet,self.pin,argv,baseline,'created')

    def test_reserved_owner_baseline_and_mutability_refuse(self):
        for key in (q.LABEL,q.DIAG_LABEL,q.NEW_LABEL,q.WORKER_LABEL,'io.diplom.synthetic-forged'):
            with self.assertRaises(ValueError):q.frozen_image_labels({key:self.pin})
        mutable=dict(self.base);baseline=q.frozen_image_labels(mutable);mutable['public-test']='changed'
        self.assertEqual(baseline['public-test'],'baseline-only')
        with self.assertRaises(TypeError):baseline['public-test']='changed'
        with self.assertRaises(ValueError):q.worker_guard(self.envelope(),self.ident,self.packet,self.pin,q.worker_command(self.packet,self.pin),dict(self.base),'created')

    def test_all_resource_mount_and_state_constraints_remain(self):
        baseline=q.frozen_image_labels(self.base);argv=q.worker_command(self.packet,self.pin)
        for mutate in [lambda r:r[5].update(Memory=q.GIB),lambda r:r[5].update(NetworkMode='bridge'),
                       lambda r:r[5].update(ReadonlyRootfs=False),lambda r:r[5].update(CapAdd=['CHOWN']),
                       lambda r:r[6][0].update(RW=True),lambda r:r[6][0].update(Source='/foreign'),
                       lambda r:r[6].append({'Type':'bind','RW':False,'Source':'/x','Destination':'/app'}),
                       lambda r:r[3].update(Running=True),lambda r:r[3].update(OOMKilled=True),lambda r:r[3].update(ExitCode=1)]:
            r=self.envelope();mutate(r)
            with self.assertRaises(ValueError):q.worker_guard(r,self.ident,self.packet,self.pin,argv,baseline,'created')

    def test_worker_program_frozen_parent_and_no_api_or_retained_actor_command(self):
        self.assertEqual(q.sha(q.CONTINUATION_JS.encode()),q.ACCEPTED_R2['programSha256'])
        self.assertEqual(q.WORKER_JS,q.CONTINUATION_JS.replace("assert(['api','worker'].includes(role));","assert.equal(role,'worker');"))
        argv=q.worker_command(self.packet,self.pin)
        self.assertIn(q.WORKER,argv);self.assertNotIn(q.API,argv);self.assertNotIn(q.OLD,argv)
        self.assertEqual(argv[-2:],['worker','45000']);self.assertEqual(argv.count('--mount'),2)
        self.assertNotIn('api-accepted-result.json',str(argv));self.assertNotIn('snapshot.mjs',str(argv))
        self.assertEqual(argv[argv.index('--memory')+1],'2147483648')
        self.assertNotIn('07dccf25778d563c7f685b6e420f2da8344e9d34103c138f0420001b7ba13d66',str(argv))
        with self.assertRaises(ValueError):q.worker_name(q.ACCEPTED_API_ROOT)

    def test_api_receipt_binding_readonly_exact_digest_and_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();p=root/'api-result.json';raw=q.canonical(phase_fact('api'));q.write_new(p,raw)
            with mock.patch.object(q,'ACCEPTED_API_ROOT',root),mock.patch.dict(q.ACCEPTED_R2,{'apiReceiptSha256':q.sha(raw)}):
                self.assertEqual(q.accepted_api(),raw)
                with mock.patch.dict(q.ACCEPTED_R2,{'apiReceiptSha256':'c'*64}):
                    with self.assertRaises(ValueError):q.accepted_api()
            self.assertEqual(p.read_bytes(),raw)

    def simulate(self,fsync_failure=None,drift=False,expiry=False):
        directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup);packet=Path(directory.name).resolve()
        payloads={'qualification.mjs':b'public-only','sources.json':b'public-synthetic','api-accepted-result.json':b'public-synthetic-accepted'}
        plan={'files':{n:q.sha(b) for n,b in payloads.items()}}
        for n,b in payloads.items():q.write_new(packet/n,b,0o444 if n in q.DIAG_FILES else 0o600)
        raw=q.canonical(plan);q.write_new(packet/'plan.json',raw);pin=q.sha(raw)
        calls=[];events=[];pending=[None];real_write=q.write_new;real_sync=q.sync_directory;case=self
        def write(p,b,mode=0o600):
            pending[0]=p.name
            try:real_write(p,b,mode)
            finally:pending[0]=None
        def sync(p):
            if pending[0]==fsync_failure and fsync_failure is not None:raise OSError('private-canary')
            real_sync(p)
            if pending[0]:events.append(pending[0])
        class Inert:
            def __init__(self,p,e,deadline):self.deadline=deadline;self.argv=None;self.state='created'
            def call(self,args):
                calls.append(args);assert 'attempt.json' in events
                if args[:2]==['image','inspect']:
                    assert args[-1]==q.WORKER
                    return q.canonical([q.WORKER,'linux','arm64','/app/server/api',None,['docker-entrypoint.sh'],case.base])
                if args[0]=='create':
                    assert 'worker-image.json' in events
                    freeze=json.loads((packet/'worker-image.json').read_bytes())
                    assert freeze['image']==q.WORKER and freeze['labels']==case.base and freeze['packetSha256']==pin
                    self.argv=args;return case.ident.encode()+b'\n'
                raise AssertionError('UNREVIEWED_COMMAND')
            def inspect(self,ident):
                calls.append(['inspect',ident]);assert 'worker-id.json' in events
                r=case.envelope(packet,pin,self.argv,self.state)
                if drift:r[4]['public-test']='drift'
                return r
            def attach_probe(self,ident):
                calls.append(['start','--attach',ident]);self.state='exited'
                return 0,q.canonical(phase_fact('worker')),False
        with mock.patch.object(q,'worker_load',return_value=plan),mock.patch.object(q,'worker_name'),\
             mock.patch.object(q,'ContinuationDocker',Inert),mock.patch.object(q,'write_new',side_effect=write),\
             mock.patch.object(q.time,'monotonic',side_effect=[0,200] if expiry else None,wraps=q.time.monotonic),\
             mock.patch.object(q,'sync_directory',side_effect=sync):
            result=q.worker_run(packet,pin,'DIP-ARTF-999','unix:///synthetic/engine.sock')
        with mock.patch.object(q,'worker_load',return_value=plan),mock.patch.object(q,'ContinuationDocker',side_effect=AssertionError('NO_RETRY')):
            repeat=q.worker_run(packet,pin,'DIP-ARTF-999','unix:///synthetic/engine.sock')
        self.assertFalse(repeat['ok']);self.assertEqual(repeat['checkpoint'],'HOST_ATTEMPT')
        return result,calls,packet,events

    def test_one_worker_exact_baseline_frozen_before_create_no_api_repeat_cleanup(self):
        r,calls,packet,events=self.simulate();self.assertEqual(r,q.worker_report(True,'COMPLETE','PASS'))
        self.assertEqual(sum(a[0]=='create' for a in calls),1);self.assertEqual(sum(a[0]=='start' for a in calls),1)
        self.assertNotIn(q.API,str(calls));self.assertNotIn(q.OLD,str(calls));self.assertFalse(any(a[0] in ('rm','exec','logs','stop','kill') for a in calls))
        self.assertEqual(events,['attempt.json','worker-image.json','worker-id.json','worker-result.json','result.json'])
        self.assertNotIn('labels',r);self.assertTrue((packet/'worker-result.json').exists())

    def test_drift_before_start_and_durable_baseline_id_failures_no_retry(self):
        r,calls,_,_=self.simulate(drift=True);self.assertFalse(r['ok']);self.assertFalse(any(a[0]=='start' for a in calls))
        for point in ('attempt.json','worker-image.json','worker-id.json'):
            r,calls,packet,_=self.simulate(fsync_failure=point)
            self.assertFalse(r['ok']);self.assertFalse(any(a[0]=='start' for a in calls));self.assertTrue((packet/point).exists())
            if point!='worker-id.json':self.assertFalse(any(a[0]=='create' for a in calls))

    def test_empty_baseline_and_missing_key_safe_image_template(self):
        argv=q.worker_command(self.packet,self.pin);r=self.envelope();r[4]={q.WORKER_LABEL:self.pin}
        q.worker_guard(r,self.ident,self.packet,self.pin,argv,q.frozen_image_labels(None),'created')
        source=__import__('inspect').getsource(q.worker_run)
        for key in ('WorkingDir','Volumes','Entrypoint','Labels'):
            self.assertIn('index .Config "'+key+'"',source)

    def test_shared90_deadline_before_image_and_closed_cli(self):
        r,calls,_,_=self.simulate(expiry=True);self.assertFalse(r['ok']);self.assertEqual(calls,[])
        self.assertIn('deadline=time.monotonic()+90',__import__('inspect').getsource(q.worker_run))
        import io
        out=io.StringIO()
        with mock.patch.object(q.sys,'argv',['probe','run-worker-closure','--packet',str(self.packet),'--authorize-new-source-continuation-once']),\
             mock.patch.object(q.sys,'stdout',out),mock.patch.object(q.sys,'stderr',io.StringIO()):self.assertEqual(q.worker_main(),1)
        self.assertEqual(set(json.loads(out.getvalue())),{'code','ok','checkpoint','reason'})


if __name__=='__main__':
    unittest.main()
