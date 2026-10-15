#!/usr/bin/env python3
"""Focused INERT fixtures only: header-shaped byte files are NOT SQLite databases.

No old tests/application/helper imports, native/SQL opens, Docker or retained data.
The real pinned controller validators run against new disposable public-tree files.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location('retained_pre_subject',HERE/'diagnose_retained_pre.py')
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


def public_module(relative):
    raw = (d.REPO/relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != d.PINS[relative]:
        raise AssertionError('Public definition pin mismatch')
    return d.load_module(relative,raw)


with patch.object(subprocess,'Popen',side_effect=AssertionError('NO runtime')):
    c,p,t = [public_module(relative) for relative in (d.CONTROLLER,d.PROFILE,d.TRANSPORT)]

IDENTITY = 'a'*64
LABEL = 'key-preservation-abcdefgh'
CANARY = 'SYNTHETIC_PRIVATE_CANARY_DO_NOT_EXPORT'
ARGV = ['--diagnose-retained-pre-once','--source-sha256','a'*64,'--test-sha256','b'*64]


def metadata(status='paused'):
    image = {'Id':p.IMAGE,'Config':{'Env':['FIXTURE='+CANARY],
        'Labels':{'com.docker.compose.project':'synthetic-image'},'WorkingDir':'/app/server/api'}}
    baseline = {name:'/synthetic/'+slot.lower() for slot,name in p.VOLUMES.items()}
    helper = '/host_mnt'+p.HELPER_SOURCE
    declared = [{'Type':'volume','Source':name,'Target':'/source/'+slot.lower()}
                for slot,name in p.VOLUMES.items()]
    declared.append({'Type':'bind','Source':helper,'Target':p.HELPER,'ReadOnly':True,
                     'BindOptions':{'CreateMountpoint':False}})
    mounts = [{'Type':'volume','Name':name,'Source':baseline[name],
               'Destination':'/source/'+slot.lower(),'RW':True} for slot,name in p.VOLUMES.items()]
    mounts.append({'Type':'bind','Source':helper,'Destination':p.HELPER,'RW':False})
    mounts += [{'Type':'tmpfs','Destination':target,'RW':True} for target in p.TMPFS]
    record = {'Id':IDENTITY,'Name':'/dip-key-snapshot-'+'c'*32,'Image':p.IMAGE,'Path':'node',
        'Args':['-e',p.CODE],'Mounts':mounts,'NetworkNone':True,
        'Config':{'Image':p.IMAGE,'Env':copy.deepcopy(image['Config']['Env']),
            'Labels':dict(image['Config']['Labels'],**{p.LABEL:LABEL}),'WorkingDir':'/app/server/api',
            'User':'65532:65532','Entrypoint':['node'],'Cmd':['-e',p.CODE],
            'Healthcheck':{'Test':['NONE']},'Volumes':None,'StopTimeout':5},
        'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],'CapAdd':None,
            'Privileged':False,'SecurityOpt':['no-new-privileges:true'],'Devices':[],
            'DeviceRequests':None,'Binds':None,'PortBindings':{},'CgroupnsMode':'private',
            'Memory':2*1024**3,'MemorySwap':2*1024**3,'NanoCpus':10**9,'PidsLimit':64,
            'Tmpfs':copy.deepcopy(p.TMPFS),'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'Mounts':declared},
        'State':{'Status':status,'Running':status=='paused','Paused':status=='paused',
                 'Restarting':False,'OOMKilled':False,'Dead':False,'ExitCode':0}}
    volumes = [{'Name':name,'Mountpoint':point,'Driver':'local','Scope':'local','Options':{},
        'Labels':{'com.docker.compose.project':'dip-auth-stand'}} for name,point in baseline.items()]
    return record,image,baseline,volumes


def snapshot():
    """Public-validator-shaped INERT bytes only, never valid/native SQLite proof."""
    files,entries,stores = {},[],[]
    for slot in ('auth','data'):
        entries.append({'path':slot,'kind':'directory','mode':0o700,'uid':65532,'gid':65532})
    versions = {'auth/auth.sqlite':(0,0),'auth/llm-usage.sqlite':(1145655601,1),'data/ledger.sqlite':(0,13)}
    for index,relative in enumerate(sorted(c.REQUIRED_STORES)):
        raw = bytearray(4096)
        raw[:16],raw[16:18],raw[18:20] = b'SQLite format 3\0',b'\x10\x00',b'\x01\x01'
        raw[100:100+len(CANARY)] = CANARY.encode()
        raw = bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        entries.append({'path':relative,'kind':'file','mode':0o600,'uid':65532,'gid':65532,
                        'bytes':len(raw),'sha256':digest,'sqlite':True})
        files['raw/'+relative] = files['working/'+relative] = raw
        files['sealed/'+str(index)+'.sqlite'] = raw
        stores.append({'path':relative,'sealed':str(index)+'.sqlite','bytes':len(raw),'sha256':digest,
            'recovery':{'format':'checked-recovery-v1','kind':'main','pageSize':4096,'pages':1},
            'logical':{'format':'sqlite-all-state-v1','schema':{
                'applicationId':str(versions[relative][0]),'userVersion':str(versions[relative][1]),
                'encoding':'UTF-8','objects':[]},'tables':[{'name':CANARY,'columns':[{'hidden':'0'}],
                'rows':1,'rowHashes':['1'*64]}]}})
    manifest = {'format':'stand-state-snapshot-v2','profile':c.MIGRATION_PROFILE,
                'limits':c.SNAPSHOT_LIMITS,'entries':sorted(entries,key=lambda e:e['path']),'stores':stores}
    files['manifest.json'] = t.canonical(manifest)
    return files,manifest


class InertTests(unittest.TestCase):
    def setUp(self):
        for target in (patch.object(subprocess,'Popen',side_effect=AssertionError('NO runtime')),
                       patch.object(os,'fsync',side_effect=AssertionError('NO fsync'))):
            target.start()
            self.addCleanup(target.stop)

    def private_receipt(self,result):
        raw = t.canonical(result)
        self.assertLessEqual(len(raw)+1,4096)
        self.assertEqual(result['historicalDurability'],'NOT_OBSERVED')
        self.assertEqual(result['inHolderInventory'],'NOT_OBSERVED')
        self.assertEqual(result['ownership'],'NOT_ADOPTED')
        self.assertEqual(result['fullQualification'],'NOT_CLAIMED')
        self.assertFalse(result['mutation'])
        for value in (CANARY,LABEL,p.HELPER_SOURCE,p.IMAGE,hashlib.sha256(CANARY.encode()).hexdigest(),
                      'synthetic-image','/synthetic/','dip-key-snapshot-'):
            self.assertNotIn(value.encode(),raw)


class SourceTests(InertTests):
    def test_frozen_pins_and_actual_source_load_only(self):
        for relative,pin in d.PINS.items():
            self.assertEqual(hashlib.sha256((d.REPO/relative).read_bytes()).hexdigest(),pin)
        argv = ARGV.copy()
        argv[2] = hashlib.sha256((d.REPO/d.SELF).read_bytes()).hexdigest()
        argv[4] = hashlib.sha256((d.REPO/d.TEST).read_bytes()).hexdigest()
        controller,profile,transport,pins = d.source_gate(argv,time.monotonic()+10)
        self.assertEqual(controller.backup_inventory.__kwdefaults__,
                         {'durable':True,'byte_limit':controller.EXPORT_BYTES,'deadline':None})
        self.assertEqual(profile.IMAGE,p.IMAGE)
        self.assertEqual(transport.SOCKET,t.SOCKET)
        self.assertEqual(set(pins),set(d.PINS)|{d.SELF,d.TEST})

    def test_arguments_and_pin_mismatch_never_reach_clients(self):
        with patch.object(d,'source_gate') as gate:
            result,status = d.run(ARGV+['--root','elsewhere'])
        self.assertEqual((status,result['checkpoint']),(1,'ARGUMENTS'))
        gate.assert_not_called()
        with patch.object(d,'read_sealed',return_value=(b'wrong',None)), \
                patch.object(d,'load_module') as load:
            result,status = d.run(ARGV)
        self.assertEqual((status,result['checkpoint']),(1,'PUBLIC_SOURCES'))
        load.assert_not_called()

    def test_discovery_exclusions_ambiguity_overflow_and_no_duplicates(self):
        self.assertEqual(d.candidates(('\n'.join(sorted(d.EXCLUDED)+[IDENTITY])+'\n').encode()),[IDENTITY])
        self.assertEqual(d.candidates(('\n'.join(sorted(d.EXCLUDED))+'\n').encode()),[])
        for ids in ([IDENTITY,IDENTITY],['not-an-id'],['a'*64,'b'*64,'c'*64],
                    sorted(d.EXCLUDED)+['a'*64,'b'*64,'c'*64]):
            with self.assertRaises(d.Refused):
                d.candidates(('\n'.join(ids)+'\n').encode())

    def test_full_profile_states_and_default_env_internal_no_preloads(self):
        for status in ('paused','created','exited'):
            record,image,baseline,_ = metadata(status)
            self.assertEqual(d.qualify(p,record,image,baseline,IDENTITY),LABEL)
        changes = (lambda r:r['State'].update(Paused=False),lambda r:r['Config'].update(User='0'),
                   lambda r:r['HostConfig'].update(CapAdd=['SYS_ADMIN']),
                   lambda r:r['Mounts'][0].update(RW=False),lambda r:r['Config'].update(Env=['OTHER=1']))
        for change in changes:
            record,image,baseline,_ = metadata()
            change(record)
            with self.assertRaises(d.Refused):
                d.qualify(p,record,image,baseline,IDENTITY)
        for key in ('NODE_OPTIONS','NODE_PATH'):
            record,image,baseline,_ = metadata()
            record['Config']['Env'] = image['Config']['Env'] = [key+'=']
            with self.assertRaises(d.Refused):
                d.qualify(p,record,image,baseline,IDENTITY)


class HostTests(InertTests):
    def setUp(self):
        super().setUp()
        self.temp = tempfile.TemporaryDirectory(prefix='retained-pre-inert-',dir=HERE)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)/'synthetic-root'
        self.root.mkdir(mode=0o755)
        self.folder = self.root/LABEL
        self.folder.mkdir(mode=0o700)
        self.record,self.image,self.baseline,self.volumes = metadata()
        common = {'version':1,'name':self.record['Name'][1:],'image':p.IMAGE,'backup':LABEL}
        self.intent = dict(common,source=d.HELPER,sourceSha256=d.HELPER_SHA256,preservationMigration=True)
        self.bound = dict(common,id=IDENTITY)
        self.write_journals()
        self.files,self.manifest = snapshot()
        self.stages = []

    def write_journals(self):
        for name,value in (('holder-intent.json',self.intent),('holder-id.json',self.bound)):
            path = self.folder/name
            path.write_bytes(t.canonical(value))
            path.chmod(0o600)

    def create_pre(self):
        pre = self.folder/'pre'
        pre.mkdir(mode=0o700)
        for relative,raw in self.files.items():
            path = pre/relative
            parent = pre
            for part in Path(relative).parts[:-1]:
                parent = parent/part
                parent.mkdir(exist_ok=True,mode=0o700)
            path.write_bytes(raw)
            path.chmod(0o600)
        return pre

    def inspect_host(self):
        return d.host_pre(c,self.folder,time.monotonic()+90,self.stages.append)

    def write_manifest(self):
        self.files['manifest.json'] = t.canonical(self.manifest)

    def execute(self,*,listing=None,final_change=None,final_journal_change=False,fail=None):
        calls=[]
        targets=0
        def client(args,cap):
            nonlocal targets
            calls.append((args,cap))
            if fail is not None and len(calls) == fail:
                raise t.Refused('CLIENT_TIMEOUT')
            if args == p.LIST_ARGS:
                return listing if listing is not None else (next(iter(d.EXCLUDED))+'\n'+IDENTITY+'\n').encode()
            if args[:2] == ('image','inspect'):
                return t.canonical(self.image)
            if args[:2] == ('volume','inspect'):
                return b'\n'.join(t.canonical(v) for v in self.volumes)
            self.assertEqual(args,('container','inspect','--format',p.CANDIDATE_FORMAT,IDENTITY))
            targets+=1
            record=copy.deepcopy(self.record)
            if targets==2:
                if final_change:
                    final_change(record)
                if final_journal_change:
                    (self.folder/'holder-id.json').write_bytes(t.canonical(self.bound)+b' ')
            return t.canonical(record)
        with patch.object(d,'ROOT',self.root),patch.object(d,'source_gate',return_value=(c,p,t,{})), \
                patch.object(t,'Client',return_value=client), \
                patch.object(c.Controller,'__init__',side_effect=AssertionError('NO Controller instance')):
            result,status=d.run(ARGV)
        self.private_receipt(result)
        self.assertNotIn(str(self.root).encode(),t.canonical(result))
        return result,status,calls

    def test_absent_pre_is_observed_absence_not_failed_export_guess(self):
        with patch.object(c,'backup_inventory',side_effect=AssertionError('ABSENT must not inventory')):
            result,status,calls=self.execute()
        self.assertEqual((status,result['hostPre'],result['state']),(0,'ABSENT','PAUSED'))
        self.assertEqual(len(calls),5)
        self.assertEqual(result['candidateIds'],[IDENTITY])

    def test_actual_host_validators_no_fsync_no_sql_and_exact_inventory_bounds(self):
        pre=self.create_pre()
        before={r:str((pre/r).stat().st_mtime_ns) for r in self.files}
        with patch.object(c,'backup_inventory',wraps=c.backup_inventory) as inventory, \
                patch.object(c,'sync_directory',wraps=c.sync_directory) as sync:
            result,status,calls=self.execute(final_change=lambda r:r['Mounts'].reverse())
        self.assertEqual((status,result['hostPre']),(0,'VALIDATED_READ_ONLY'))
        self.assertEqual(len(calls),5)
        self.assertEqual(inventory.call_args.args,(pre,))
        self.assertEqual(inventory.call_args.kwargs['durable'],False)
        self.assertEqual(inventory.call_args.kwargs['byte_limit'],256*c.MIB)
        self.assertGreater(inventory.call_args.kwargs['deadline'],time.monotonic())
        self.assertTrue(sync.call_count)
        self.assertTrue(all(call.kwargs=={'durable':False} for call in sync.call_args_list))
        self.assertEqual(before,{r:str((pre/r).stat().st_mtime_ns) for r in self.files})

    def test_host_first_gate_manifest_hash_version_small_and_header(self):
        cases=('hash','version','small','header')
        for case in cases:
            with self.subTest(case=case):
                # Each case is a fresh synthetic tree, never an operational retry.
                child=HostTests('test_absent_pre_is_observed_absence_not_failed_export_guess')
                child.setUp()
                try:
                    if case=='hash':
                        child.files['raw/auth/auth.sqlite']=b'X'+child.files['raw/auth/auth.sqlite'][1:]
                    elif case=='version':
                        child.manifest['stores'][-1]['logical']['schema']['userVersion']='12'
                        child.write_manifest()
                    elif case=='small':
                        child.manifest['stores'][0]['logical']['tables'][0]['columns'][0]['hidden']='1'
                        child.write_manifest()
                    else:
                        relative='auth/llm-usage.sqlite'
                        raw=bytearray(child.files['raw/'+relative]); raw[18:20]=b'\x02\x02'
                        child.files['raw/'+relative]=bytes(raw)
                        for entry in child.manifest['entries']:
                            if entry['path']==relative:
                                entry['sha256']=hashlib.sha256(raw).hexdigest()
                        child.write_manifest()
                    child.create_pre()
                    result,status,calls=child.execute()
                    expected={'hash':'PRE_MANIFEST','version':'PRE_MANIFEST','small':'PRE_SMALL','header':'PRE_HEADERS'}[case]
                    self.assertEqual((status,result['checkpoint'],result['category']),(1,expected,'PREDICATE_REFUSED'))
                    self.assertEqual(len(calls),4)
                finally:
                    child.doCleanups()

    def test_inventory_symlink_hardlink_and_unsafe_mode_refuse(self):
        pre=self.create_pre()
        path=pre/'working/auth/auth.sqlite'
        alias=pre/'synthetic-alias'
        os.link(path,alias)
        with self.assertRaises(c.Refusal):
            self.inspect_host()
        self.assertEqual(self.stages[-1],'PRE_INVENTORY')
        alias.unlink()
        path.chmod(0o644)
        with self.assertRaises(c.Refusal):
            self.inspect_host()
        path.chmod(0o600)
        path.unlink(); path.symlink_to(pre/'raw/auth/auth.sqlite')
        with self.assertRaises(c.Refusal):
            self.inspect_host()

    def test_journal_binding_and_final_changes_refuse_without_adoption(self):
        self.bound['id']='b'*64
        self.write_journals()
        result,status,calls=self.execute()
        self.assertEqual((status,result['checkpoint']),(1,'JOURNAL_BINDING'))
        self.assertEqual(len(calls),4)
        self.bound['id']=IDENTITY
        self.write_journals()
        result,status,calls=self.execute(final_journal_change=True)
        self.assertEqual((status,result['checkpoint']),(1,'JOURNALS_FINAL'))
        self.assertEqual(len(calls),5)

    def test_final_candidate_declared_change_refuses(self):
        result,status,calls=self.execute(final_change=lambda r:r['HostConfig']['Mounts'].reverse())
        self.assertEqual((status,result['checkpoint']),(1,'CANDIDATE_FINAL'))
        self.assertEqual(len(calls),5)

    def test_final_manifest_drift_caught_after_readonly_headers(self):
        pre=self.create_pre()
        original=c.Controller.small_headers
        def changed(*args):
            value=original(*args)
            path=pre/'manifest.json'
            path.write_bytes(path.read_bytes()+b' ')
            return value
        with patch.object(c.Controller,'small_headers',side_effect=changed),self.assertRaises(d.Refused):
            self.inspect_host()
        self.assertEqual(self.stages[-1],'PRE_FINAL_SEAL')

    def test_discovery_empty_or_ambiguous_never_reads_journals(self):
        with patch.object(d,'read_sealed',side_effect=AssertionError('NO private reads')):
            result,status,calls=self.execute(listing=(next(iter(d.EXCLUDED))+'\n').encode())
            self.assertEqual((status,result['candidateIds'],result['hostPre']),(0,[],'NOT_OBSERVED'))
            self.assertEqual(len(calls),1)
            result,status,calls=self.execute(listing=(IDENTITY+'\n'+'b'*64+'\n').encode())
            self.assertEqual((status,result['category']),(1,'AMBIGUOUS'))
            self.assertEqual(len(calls),1)
            self.assertEqual(result['candidateIds'],[IDENTITY,'b'*64])

    def test_first_client_failure_stays_fixed_and_no_retry(self):
        for fail,point in ((1,'DISCOVERY'),(2,'IMAGE_DEFAULTS'),(3,'VOLUMES'),(4,'CANDIDATE'),(5,'CANDIDATE_FINAL')):
            result,status,calls=self.execute(fail=fail)
            self.assertEqual((status,result['checkpoint'],result['category']),(1,point,'CLIENT_TIMEOUT'))
            self.assertEqual(len(calls),fail)

    def test_expired_deadline_refuses_before_host_reads(self):
        with self.assertRaises(d.Refused) as error:
            d.host_pre(c,self.folder,time.monotonic()-1,self.stages.append)
        self.assertEqual(error.exception.category,'CLIENT_TIMEOUT')
        self.assertEqual(self.stages,['PRE_METADATA'])

    def test_client_allowlist_no_exec_cp_mutation_or_sixth_call(self):
        fake=Mock(return_value=b'public')
        with patch.object(t,'Client',return_value=fake):
            client=d.ReadClient(p,t,time.monotonic()+90)
            for args in (('exec',IDENTITY,'true'),('cp',IDENTITY+':/backup/pre','elsewhere'),
                         ('unpause',IDENTITY),('rm','--force',IDENTITY),('stop',IDENTITY),('start',IDENTITY)):
                with self.assertRaises(d.Refused):
                    client(args)
            fake.assert_not_called()
            client.select(IDENTITY)
            for args in (client.list,client.image,client.volumes,client.target,client.target):
                client(args)
            with self.assertRaises(d.Refused):
                client(client.target)
            self.assertEqual(fake.call_count,5)


class MetadataOnlyTests(InertTests):
    def setUp(self):
        super().setUp()
        self.temp=tempfile.TemporaryDirectory(prefix='pre-metadata-inert-',dir=HERE)
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'synthetic-root'
        self.root.mkdir(mode=0o755)
        self.folder=self.root/LABEL
        self.folder.mkdir(mode=0o700)
        self.pre=self.folder/'pre'
        self.pre.mkdir(mode=0o700)
        self.record={'id':d.CURRENT_ID,'image':p.IMAGE,'configImage':p.IMAGE,
            'name':'/dip-key-snapshot-'+'c'*32,'backup':LABEL,'status':'paused',
            'running':True,'paused':True,'dead':False,'restarting':False,'oom':False}

    def manifest(self,raw=CANARY.encode()):
        path=self.pre/'manifest.json'
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def execute(self):
        client=Mock(return_value=t.canonical(self.record))
        argv=[d.METADATA_MODE,*ARGV[1:]]
        real_open=os.open
        def directories_only(path,flags,*args,**kwargs):
            self.assertTrue(flags & os.O_DIRECTORY,'Metadata mode must NEVER open a leaf')
            return real_open(path,flags,*args,**kwargs)
        with (patch.object(d,'ROOT',self.root),patch.object(d,'source_gate',return_value=(c,p,t,{})),
                patch.object(t,'Client',return_value=client),
                patch.object(d,'ReadClient',side_effect=AssertionError('NO old discovery/client')),
                patch.object(c,'backup_inventory',side_effect=AssertionError('NO inventory/hash')),
                patch.object(c,'validate_manifest',side_effect=AssertionError('NO manifest read')),
                patch.object(d,'read_sealed',side_effect=AssertionError('NO journal/PRE content')),
                patch.object(os,'read',side_effect=AssertionError('NO content read')),
                patch.object(os,'open',side_effect=directories_only)):
            result,status=d.run(argv)
        client.assert_called_once_with(d.METADATA_ARGS,cap=4096)
        self.private_receipt(result)
        self.assertEqual(result['candidateId'],d.CURRENT_ID)
        self.assertEqual(result['manifestContents'],'NOT_OBSERVED')
        self.assertEqual(result['journalContents'],'NOT_OBSERVED')
        self.assertEqual(result['fullProfile'],'NOT_REVALIDATED')
        self.assertEqual(result['priorHashEquality'],'NOT_OBSERVED')
        self.assertNotIn(str(self.root).encode(),t.canonical(result))
        def closed_values(value):
            if type(value) is dict:
                for item in value.values(): closed_values(item)
            else:
                self.assertIn(type(value),(str,bool,type(None)))
        closed_values(result)
        return result,status

    def test_empty_pre_is_classified_without_any_leaf_open(self):
        result,status=self.execute()
        self.assertEqual((status,result['checkpoint']),(0,'M_COMPLETE'))
        flags=result['flags']
        self.assertTrue(flags['preEmpty'])
        self.assertFalse(flags['manifest']['present'])
        self.assertEqual(flags['manifest']['kind'],'ABSENT')
        self.assertTrue(flags['manifest']['followStable']['stable'])

    def test_expected_names_and_metadata_flags_no_content_or_hash(self):
        self.manifest()
        for name in ('raw','working','sealed'):
            (self.pre/name).mkdir(mode=0o700)
        result,status=self.execute()
        self.assertEqual(status,0)
        flags=result['flags']
        self.assertFalse(flags['preEmpty'])
        self.assertTrue(flags['layoutNamesExact'])
        self.assertFalse(flags['unexpectedNames'])
        self.assertEqual(flags['manifest'],{'present':True,'kind':'REGULAR','sizeCap':True,
            'mode600':True,'owner':{'uidMatch':True,'gidMatch':True},
            'followStable':{'noSymlink':True,'singleLink':True,'stable':True}})

    def test_gid_is_independent_flag_not_a_reader_policy_relaxation(self):
        self.manifest()
        real_stat=os.stat
        def different_gid(path,*args,**kwargs):
            value=real_stat(path,*args,**kwargs)
            if path=='manifest.json' and kwargs.get('follow_symlinks') is False:
                fields={name:getattr(value,name) for name in ('st_dev','st_ino','st_mode','st_nlink',
                    'st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')}
                fields['st_gid']=os.getegid()+1
                return d.types.SimpleNamespace(**fields)
            return value
        with patch.object(os,'stat',side_effect=different_gid):
            result,status=self.execute()
        self.assertEqual(status,0)
        self.assertEqual(result['flags']['manifest']['owner'],{'uidMatch':True,'gidMatch':False})
        self.assertTrue(result['flags']['manifest']['followStable']['stable'])

    def test_zero_size_bad_mode_and_symlink_are_information_not_content_reads(self):
        path=self.manifest(b'')
        path.chmod(0o640)
        result,status=self.execute()
        self.assertEqual(status,0)
        self.assertFalse(result['flags']['manifest']['sizeCap'])
        self.assertFalse(result['flags']['manifest']['mode600'])
        path.unlink()
        target=self.folder/'unread-synthetic-canary'
        target.write_bytes(CANARY.encode())
        target.chmod(0o600)
        path.symlink_to(target)
        result,status=self.execute()
        self.assertEqual(status,0)
        self.assertEqual(result['flags']['manifest']['kind'],'SYMLINK')
        self.assertFalse(result['flags']['manifest']['followStable']['noSymlink'])

    def test_fixed_nested_pre_metadata_does_not_enumerate_or_read_inner_tree(self):
        nested=self.pre/'pre'
        nested.mkdir(mode=0o700)
        (nested/'manifest.json').write_bytes(CANARY.encode())
        (nested/'manifest.json').chmod(0o600)
        result,status=self.execute()
        self.assertEqual(status,0)
        flags=result['flags']
        self.assertFalse(flags['manifest']['present'])
        self.assertTrue(flags['nestedPrePresent'])
        self.assertTrue(flags['nestedPreSafe'])
        self.assertTrue(flags['nestedManifestPresent'])
        self.assertFalse(flags['layoutNamesExact'])

    def test_scandir_expected_plus_one_bound_no_unknown_names_output(self):
        for index in range(9):
            (self.pre/(CANARY+str(index))).write_bytes(b'')
        real_scan=os.scandir
        observed=[]
        class Scan:
            def __init__(self,fd): self.inner=real_scan(fd)
            def __enter__(self): return self
            def __exit__(self,*args): self.inner.close()
            def __iter__(self): return self
            def __next__(self):
                item=next(self.inner)
                observed.append(item.name)
                return item
        with patch.object(os,'scandir',side_effect=Scan):
            result,status=self.execute()
        self.assertEqual(status,0)
        self.assertEqual(len(observed),5)
        self.assertFalse(result['flags']['topNamesBounded'])
        self.assertTrue(result['flags']['unexpectedNames'])
        self.assertFalse(result['flags']['preEmpty'])

    def test_exact_id_drift_refuses_before_host_observation(self):
        self.record['id']='b'*64
        with patch.object(d,'host_metadata',side_effect=AssertionError('NO host reads')):
            result,status=self.execute()
        self.assertEqual((status,result['checkpoint']),(1,'M_IDENTITY'))


if __name__=='__main__':
    unittest.main()
