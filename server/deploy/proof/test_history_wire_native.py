"""Candidate test SOURCE, not an authorized inert validation entry.

Module loading imports the runner; existing cases include inventory and host Node.
The new mocked controller regressions have NOT been executed under source-only scope.
"""
import argparse
import ast
import copy
from contextlib import ExitStack
import importlib.util
import json
import re
import subprocess
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('history_wire_candidate', Path(__file__).with_name('history-wire-native.py'))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
PROJECT = 'dip-history-wire-1234567890abcdef'
SCRATCH = m.ROOT.parent / 'cve14-proof-workspaces/run-20261010-history-wire-r1'
STATE = {'owner':'a'*32,'foreign':'b'*32,'scanId':'12345678-abcd-4000-8000-123456789abc',
         'epoch':'12345678-abcd-4000-8000-123456789abd','turnId':'12345678-abcd-4000-8000-123456789abe',
         'mutationId':'12345678-abcd-4000-8000-123456789abf','decisionId':'12345678-abcd-4000-8000-123456789ac0',
         'digest':'sha256:'+'a'*64,'platform':'linux/amd64','reportVersion':'b'*64,'consentPolicyVersion':'c'*64,
         'incarnation':'12345678-abcd-4000-8000-123456789ac1','fingerprintDigest':'d'*64,'reportDigest':'e'*64,
         'accessIncarnation':'c'*32,'historyInode':1,'historyDevice':2}


def model(d, name, mixed=False):
    nets = ['none'] if d['network']=='none' else [PROJECT+'-'+d['network']]
    if d['role']=='web': nets.append(PROJECT+'-probe')
    mounts=[]
    for i,e in enumerate(d['mounts']):
        row={'Destination':e['target'],'Type':e['type'],'RW':e['rw']}
        if e['type']=='volume':row['Name']=e['source']
        else:row['Source']=('/host_mnt' if mixed and i%2==0 else '')+e['source']
        mounts.append(row)
    return {'id':'f'*64,'name':'/'+name,'image':d['image'],'labels':{m.LABEL:PROJECT,m.RUN_LABEL:PROJECT},
            'user':f"{d['uid']}:{d['uid']}",'entrypoint':[d['entry']],'cmd':d['command'],'cwd':d['cwd'],
            'mounts':mounts,'networks':dict.fromkeys(nets,{}),'state':{'Status':'created','OOMKilled':False},
            'host':{'ReadonlyRootfs':True,'Privileged':False,'SecurityOpt':['no-new-privileges=true'],
                    'CapDrop':['ALL'],'CapAdd':['CHOWN'] if d['role']=='volume-init' else None,
                    'Memory':d['memory'],'MemorySwap':d['memory'],'NanoCpus':d['cpu'],'PidsLimit':d['pids'],'CgroupnsMode':'private',
                    'Tmpfs':{'/tmp':d['tmpfs']},'LogConfig':{'Type':'json-file','Config':{'max-size':'1m','max-file':'1'}},
                    'PortBindings':{},'PublishAllPorts':False,'ExtraHosts':None,'Devices':[],'DeviceRequests':None,
                    'Links':None,'VolumesFrom':None,'PidMode':'','IpcMode':'private','UTSMode':'',
                    'NetworkMode':'none' if d['network']=='none' else PROJECT+'-'+d['network'],
                    'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'AutoRemove':False,
                    'Sysctls':None,'DeviceCgroupRules':None,'Init':None}}


class PureContractTests(unittest.TestCase):
    def check(self,v,d,policy=m.POLICY,context='desktop-linux'):
        return m.qualify_container(v,d,PROJECT,PROJECT+'-fixture',policy,context)
    def test_default_and_selftest_no_engine_or_writes(self):
        with patch.object(m.subprocess,'Popen',side_effect=AssertionError('process forbidden')), patch.object(m.os,'mkdir',side_effect=AssertionError('write forbidden')):
            self.assertTrue(m.self_test()['passed'])
            p=m.plan();self.assertFalse(p['executed']);self.assertFalse(p['executionApproved'])
            self.assertEqual(len(p['sourceFiles']),244);self.assertEqual(len(p['embeddedFiles']),238)
            self.assertEqual(p['sourceSnapshotSha256'],m.SNAPSHOT)
    def test_all_five_topologies(self):
        for role in m.SLOTS:
            with self.subTest(role=role):
                d=m.descriptor(role,'disabled' if role=='api' else 'setup',SCRATCH,PROJECT,STATE if role=='api' else None)
                v=model(d,PROJECT+'-fixture',True)
                self.assertTrue(self.check(v,d)['qualified'])
                a=m.create_argv(d,PROJECT+'-fixture',PROJECT)
                self.assertNotIn('--publish',a);self.assertNotIn('--privileged',a)
                self.assertEqual(a[a.index('--pull')+1],'never')
                self.assertEqual(a.count('--cap-add'),1 if role=='volume-init' else 0)
                self.assertEqual(a.count('--mount'),len(d['mounts']))
    def test_manifest_exact_budgets(self):
        p=m.manifest();self.assertEqual(len(p['services']),5);self.assertEqual(len(p['networks']),2)
        self.assertEqual(p['volumes'],['auth','scan']);self.assertEqual(p['bounds']['totalSeconds'],300)
        self.assertEqual(p['bounds']['workSeconds'],240);self.assertEqual(p['bounds']['cleanupSeconds'],60)
        self.assertEqual(p['bounds']['dockerCalls'],80);self.assertEqual(p['bounds']['httpCalls'],128)
        self.assertFalse(p['wholeAcceptance']);self.assertFalse(p['productionClientAcceptance'])
    def test_exact_enabled_nginx_one_change(self):
        raw=m.public_read(m.CONFIG);enabled=m.enabled_config(raw)
        self.assertNotEqual(m.sha(enabled),m.CONFIG_SHA)
        self.assertEqual(enabled.replace(b'set $history_ingress_enabled 1;',b'set $history_ingress_enabled 0;'),raw)
        self.assertIn(b'set $runtime_ingress_enabled 0;',enabled)
        with self.assertRaises(m.Refusal):m.enabled_config(raw+b'\n')
    def test_role_mount_write_set(self):
        for role,leaves in [('seed',[m.SEED]),('api',[m.SEED,m.API]),('probe',[m.CLIENT])]:
            d=m.descriptor(role,'replay',SCRATCH,PROJECT)
            self.assertEqual([v['source'] for v in d['mounts'] if v['type']=='bind'],[str(m.ROOT/p) for p in leaves])
        self.assertFalse(any(x['type']=='volume' for x in m.mounts('probe',SCRATCH,PROJECT)))
        self.assertEqual(len(m.mounts('web',SCRATCH,PROJECT)),1)
    def test_bind_mixed_exact_representations(self):
        d=m.descriptor('api','replay',SCRATCH,PROJECT,STATE)
        v=model(d,PROJECT+'-fixture',True);result=self.check(v,d)
        self.assertEqual(set(result['representations'].values()),{'literal','desktop_host_mnt'})
        with self.assertRaises(m.Refusal):self.check(v,d,'literal')
    def test_bind_negative_suffix_wrong_source_rw_missing_extra(self):
        d=m.descriptor('web','serve',SCRATCH,PROJECT);good=model(d,PROJECT+'-fixture')
        variations=[]
        for source in ['/other/conf','/host_mnt'+str(SCRATCH/'nginx.enabled.conf')+'/suffix','/host_mnt'+str(SCRATCH/'other.conf'),
                       '/unknown'+str(SCRATCH/'nginx.enabled.conf')]:
            v=copy.deepcopy(good);v['mounts'][0]['Source']=source;variations.append(v)
        v=copy.deepcopy(good);v['mounts'][0]['RW']=True;variations.append(v)
        v=copy.deepcopy(good);v['mounts']=[];variations.append(v)
        v=copy.deepcopy(good);v['mounts']*=2;variations.append(v)
        for v in variations:
            with self.assertRaises(m.Refusal):self.check(v,d)
    def test_initializer_cap_chown_exact_singletons(self):
        d=m.descriptor('volume-init','initialize',SCRATCH,PROJECT)
        for caps in (['CHOWN'],['CAP_CHOWN']):
            v=model(d,PROJECT+'-fixture');v['host']['CapAdd']=caps
            self.assertTrue(self.check(v,d)['qualified'])
        argv=m.create_argv(d,PROJECT+'-fixture',PROJECT)
        self.assertEqual(argv.count('--cap-add'),1)
        self.assertEqual(argv[argv.index('--cap-add')+1],'CHOWN')
        self.assertEqual(m.manifest()['services']['volume-init']['add'],['CHOWN'])
    def test_initializer_cap_chown_negative_representations(self):
        d=m.descriptor('volume-init','initialize',SCRATCH,PROJECT)
        invalid=(None,[],False,0,'CHOWN','CAP_CHOWN',{},('CHOWN',),['chown'],['cap_chown'],
                 ['CAP_CHOWN '],['CAP_CAP_CHOWN'],['FOWNER'],['CAP_FOWNER'],['ALL'],
                 ['CHOWN','CAP_CHOWN'],['CHOWN','CHOWN'],['CAP_CHOWN','CAP_CHOWN'],['CAP_CHOWN','FOWNER'])
        for caps in invalid:
            with self.subTest(caps=caps):
                v=model(d,PROJECT+'-fixture');v['host']['CapAdd']=caps
                with self.assertRaises(m.RuntimeQualifierRefusal) as error:self.check(v,d)
                self.assertEqual(str(error.exception),'caps_boundary')
                self.assertEqual(error.exception.diagnostics['failed'],['cap_add'])
        for drop in (None,[],['CAP_ALL'],['ALL','ALL'],['ALL','CHOWN']):
            v=model(d,PROJECT+'-fixture');v['host']['CapDrop']=drop;v['host']['CapAdd']=['CAP_CHOWN']
            with self.assertRaises(m.RuntimeQualifierRefusal) as error:self.check(v,d)
            self.assertEqual(error.exception.diagnostics['failed'],['cap_drop'])
    def test_noninitializer_no_capability_additions(self):
        for role in ('seed','api','web','probe'):
            d=m.descriptor(role,'replay',SCRATCH,PROJECT,STATE if role=='api' else None)
            for caps in (None,[]):
                v=model(d,PROJECT+'-fixture');v['host']['CapAdd']=caps
                self.assertTrue(self.check(v,d)['qualified'])
            for caps in (['CHOWN'],['CAP_CHOWN'],['FOWNER'],['ALL'],['CHOWN','CAP_CHOWN'],False,0,'',{}):
                v=model(d,PROJECT+'-fixture');v['host']['CapAdd']=caps
                with self.assertRaises(m.RuntimeQualifierRefusal) as error:self.check(v,d)
                self.assertEqual(error.exception.diagnostics['failed'],['cap_add'])
            self.assertNotIn('--cap-add',m.create_argv(d,PROJECT+'-fixture',PROJECT))
    def test_runtime_qualifier_all_failed_labels_bounded_redacted(self):
        d=m.descriptor('volume-init','initialize',SCRATCH,PROJECT);v=model(d,PROJECT+'-fixture')
        canary='CANARY-private-env-raw-inspect-value'
        for key in ('id','name','image','user','entrypoint','cmd','cwd'):v[key]=canary
        v['labels']={m.LABEL:canary,m.RUN_LABEL:canary}
        v['host']={key:canary for key in v['host']}
        v['host']['Config.Env']=[canary];v['Config.Env']=[canary]
        v['networks']={canary:{}}
        v['mounts']=[{'Destination':canary,'Type':canary,'RW':canary,'Name':canary,'Source':canary}]
        v['state']={'Status':canary,'OOMKilled':True}
        labels={'id','name','project_label','run_label','image','user','entrypoint','cmd','cwd','readonly','privileged',
                'nnp','cap_drop','cap_add','memory','memory_swap','cpu','pids','tmpfs','log','ports','publish_all',
                'extra_hosts','devices','device_requests','links','volumes_from','pid','ipc','uts','network_mode',
                'autoremove','restart','sysctls','device_rules','init','network_set','mount_count','mount_dest',
                'mount_type','mount_rw','volume_name','bind_source','mount_missing','state','oom'}
        with self.assertRaises(m.RuntimeQualifierRefusal) as error:self.check(v,d)
        diagnostic=error.exception.diagnostics
        self.assertEqual(str(error.exception),'container_identity')
        self.assertEqual(set(diagnostic),{'failed','checked','rawValuesIncluded'})
        self.assertEqual(set(diagnostic['failed']),labels);self.assertEqual(diagnostic['checked'],len(labels))
        self.assertEqual(len(diagnostic['failed']),len(labels));self.assertFalse(diagnostic['rawValuesIncluded'])
        self.assertLessEqual(len(m.canonical(diagnostic)),1024);self.assertNotIn(canary,m.canonical(diagnostic).decode())
        raw=m.public_read(m.NEW[0]).decode()
        self.assertIn("evidence['runtimeQualifierDiagnostics']=error.diagnostics",raw)
        self.assertIn("evidence.setdefault('runtimeQualifierDiagnostics',error.diagnostics)",raw)
    def test_runtime_qualifier_multiple_and_missing_fail_closed(self):
        d=m.descriptor('api','replay',SCRATCH,PROJECT,STATE);v=model(d,PROJECT+'-fixture')
        v['host']['Memory']+=1;v['host']['MemorySwap']+=1;v['host']['CapAdd']=['CAP_CHOWN']
        with self.assertRaises(m.RuntimeQualifierRefusal) as error:self.check(v,d)
        self.assertEqual(str(error.exception),'caps_boundary')
        self.assertEqual(error.exception.diagnostics['failed'],['cap_add','memory','memory_swap'])
        for key in ('host','mounts','state','labels','networks'):
            v=model(d,PROJECT+'-fixture');v.pop(key)
            with self.assertRaises(m.RuntimeQualifierRefusal):self.check(v,d)
        for value in (None,[], 'CANARY-private'):
            with self.assertRaises(m.RuntimeQualifierRefusal) as error:self.check(value,d)
            self.assertNotIn('CANARY',m.canonical(error.exception.diagnostics).decode())
    def test_runtime_resource_no_float_boolean_string_coercion(self):
        d=m.descriptor('web','serve',SCRATCH,PROJECT);good=model(d,PROJECT+'-fixture')
        for key in ('Memory','MemorySwap','NanoCpus','PidsLimit'):
            for value in (float(good['host'][key]),str(good['host'][key]),True):
                v=copy.deepcopy(good);v['host'][key]=value
                with self.assertRaises(m.Refusal):self.check(v,d)
    def test_unknown_context_cannot_opt_in(self):
        for context in ('default','remote','desktop-windows',''):
            with self.assertRaises(m.Refusal):m.bind_candidates(str(SCRATCH/'nginx.enabled.conf'),m.POLICY,context)
        for policy in ('automatic','strip','/host_mnt'):
            with self.assertRaises(m.Refusal):m.bind_candidates(str(SCRATCH/'nginx.enabled.conf'),policy,'desktop-linux')
    def test_all_isolation_conjuncts_fail_closed(self):
        d=m.descriptor('api','disabled',SCRATCH,PROJECT,STATE);good=model(d,PROJECT+'-fixture')
        wrong={'ReadonlyRootfs':False,'Privileged':True,'SecurityOpt':[],'CapDrop':[], 'CapAdd':['FOWNER'],
               'Memory':d['memory']+1,'MemorySwap':d['memory']+1,'NanoCpus':d['cpu']+1,'PidsLimit':129,
               'Tmpfs':{},'LogConfig':{},'PortBindings':{'3001/tcp':[{'HostPort':'18083'}]},'PublishAllPorts':True,
               'ExtraHosts':['host-gateway'],'Devices':[{}],'DeviceRequests':[{}],'Links':['other'],
               'VolumesFrom':['other'],'PidMode':'host','IpcMode':'host','UTSMode':'host',
               'NetworkMode':'host','RestartPolicy':{'Name':'always','MaximumRetryCount':0},'AutoRemove':True,
               'Sysctls':{'net.test':'1'},'DeviceCgroupRules':['a *:* rwm'],'Init':True}
        for key,value in wrong.items():
            with self.subTest(key=key):
                v=copy.deepcopy(good);v['host'][key]=value
                with self.assertRaises(m.Refusal):self.check(v,d)
    def test_namespace_mount_network_and_cleanup_identity(self):
        d=m.descriptor('api','replay',SCRATCH,PROJECT,STATE);good=model(d,PROJECT+'-fixture')
        for key,value in [('id','not-id'),('name','/foreign'),('image',m.NGINX),('user','0:0'),('entrypoint',['sh']),('cmd',['anything']),('cwd','/')]:
            v=copy.deepcopy(good);v[key]=value
            with self.assertRaises(m.Refusal):self.check(v,d)
        for label in (m.LABEL,m.RUN_LABEL):
            v=copy.deepcopy(good);v['labels'][label]='foreign'
            with self.assertRaises(m.Refusal):self.check(v,d)
        v=copy.deepcopy(good);v['networks']['uplink']={}
        with self.assertRaises(m.Refusal):self.check(v,d)
        v=copy.deepcopy(good);v['mounts'][-1]['Name']='live-scan'
        with self.assertRaises(m.Refusal):self.check(v,d)
    def test_real_environment_off_no_private_keys(self):
        d=m.descriptor('api','replay',SCRATCH,PROJECT,STATE)
        self.assertEqual(d['env']['LLM_ENABLED'],'false');self.assertEqual(d['env']['LLM_ROUTING_APPROVED'],'false')
        self.assertEqual(d['env']['LLM_QUOTA_ENABLED'],'false');self.assertEqual(d['env']['LLM_HISTORY_ENABLED'],'true')
        for key in ('OPENROUTER_API_KEY','RUNTIME_DB_PATH','NODE_OPTIONS','HTTP_PROXY'):self.assertNotIn(key,d['env'])
        self.assertEqual(d['env']['SCAN_BROWSER_ALLOWED_USER_IDS'],STATE['owner']+','+STATE['foreign'])
    def test_sticky_final_receipt_failures_never_zero_usage_claim(self):
        final={'kind':'history-wire-api-final','phase':'replay','closed':True,'providerLookups':0,'providerFault':False,'quotaAbsent':True}
        self.assertEqual(m.receipt(m.canonical(final),final['kind'],'replay'),final)
        for key,value in [('providerLookups',1),('providerLookups',False),('providerFault',True),('closed',False),('quotaAbsent',False)]:
            wrong={**final,key:value}
            with self.assertRaises(m.Refusal):m.receipt(m.canonical(wrong),final['kind'],'replay')
        for raw in (b'',b'{"error":"CANARY-private"}',m.canonical({**final,'rawError':'CANARY-private'})):
            with self.assertRaises(m.Refusal):m.receipt(raw,final['kind'],'replay')
    def test_duplicate_json_nonfinite_and_caps(self):
        for raw in (b'{"a":1,"a":2}',b'{"a":NaN}',b'\xff',b'x'*(m.CAP+1)):
            with self.assertRaises(m.Refusal):m.closed_json(raw)
    def test_log_reflection_closed_boolean_only(self):
        for raw in (b'CANARY-history-wire-public',b'demo_session=never-publish',b'history-wire-public-password-a-123',b'Bearer fixture-denied'):
            result=m.privacy(raw);self.assertFalse(result['reflectionAbsent']);self.assertNotIn(raw.decode(),json.dumps(result))
        self.assertFalse(m.privacy(b'x'*(m.CAP+1))['bounded'])
        self.assertTrue(m.privacy(b'nginx public syntax passed')['reflectionAbsent'])
    def test_five_file_freeze_review_gate_before_tool_or_engine(self):
        p=m.plan();args=argparse.Namespace(execute=True,parent_execution_authorized=False)
        with patch.object(m,'validate_tool',side_effect=AssertionError('tool probe forbidden')),patch.object(m,'Runner',side_effect=AssertionError('engine forbidden')):
            with self.assertRaisesRegex(m.Refusal,'new_parent_authority_required'):m.execute(args,p)
        args.parent_execution_authorized=True;args.reviewed_fixture_sha256='0'*64
        with self.assertRaisesRegex(m.Refusal,'fixture_not_reviewed'):m.approve(args,p)
        self.assertEqual(set(p['fixtureSha256']),set(m.NEW))
    def test_initializer_has_exact_minimal_idempotent_authority(self):
        raw=m.INIT_JS
        self.assertIn('s.uid===65532&&s.gid===65532&&(s.mode&4095)===448)continue',raw)
        self.assertIn('a.deepEqual(f.readdirSync(p),[])',raw)
        self.assertLess(raw.index('f.chmodSync(p,448)'),raw.index('f.chownSync(p,65532,65532)'))
        self.assertNotIn('recursive',raw);self.assertNotIn('FOWNER',raw)
    def test_fixture_source_exact_actual_graph_and_no_real_provider(self):
        api=m.public_read(m.API).decode();seed=m.public_read(m.SEED).decode();client=m.public_read(m.CLIENT).decode()
        self.assertIn('NestFactory.create<NestExpressApplication>(NginxLocalModule',api)
        self.assertLess(api.index('configureParentIngress(app)'),api.index('await app.listen('))
        self.assertLess(api.index("Object.defineProperty(runtime, 'provider'"),api.index('await app.listen('))
        self.assertIn('providerLookups++; providerFault = true;',api)
        for forbidden in ('AppModule','new OpenRouterProvider','productionProvider(','fakeKey','quota-init','rotate-restored-lineage'):
            self.assertNotIn(forbidden,api+seed)
        self.assertIn("src/llm/history-init.ts', '--initialize'",seed)
        self.assertIn('const ledgerStore = new LedgerStore()',seed)
        self.assertIn('new NginxLocalScansService(store, new OciResolver())',seed)
        self.assertNotIn('{ ledger } as LedgerStore',seed);self.assertNotIn('{} as OciResolver',seed)
        self.assertIn("revision: 0, mutationId",seed);self.assertIn('readSync(0',seed)
        self.assertIn('revision: 0, mutationId',client);self.assertIn('socket',client)
        self.assertNotIn('fetch(',client);self.assertNotIn('new URL(path)',client)
        self.assertIn('clientSha256',client);self.assertIn('mountedFixtureBytesQualified',api+seed+client)
    def test_independent_logins_cannot_revoke_owner_cookie(self):
        raw=m.public_read(m.CLIENT).decode()
        self.assertIn("exchange('POST','/api/v1/auth/login',accounts[i],{variant:'anonymous'})",raw)
        self.assertIn("if (variant === 'anonymous' || !cookies.length) return null;",raw)
        self.assertIn("cookieHeader('anonymous', cookies), null",raw)
    def test_cache_control_contract_all_positive_paths(self):
        raw=m.public_read(m.CLIENT).decode()
        self.assertIn("validateCacheControl(r.headers['cache-control'], 'json'); return strictJSON(r.body)",raw)
        self.assertIn("validateCacheControl(r.headers['cache-control'], 'ndjson');",raw)
        self.assertNotIn("assert.equal(r.headers['cache-control'],'no-store')",raw)
        self.assertIn("representation === 'ndjson' ? ['no-store', 'no-transform'] : ['no-store']",raw)
        self.assertIn('value.length <= 128 && Buffer.byteLength(value) <= 128',raw)
        self.assertIn('directives.length <= 4',raw)
        self.assertIn('for (const directive of required) assert(parsed.includes(directive))',raw)
        self.assertIn("merged(['no-store, no-transform', 'no-store'])",raw)
        self.assertIn('cacheControlSelfTest();',raw)
        self.assertIn('maxHeaderSize:16384',raw)
    def test_process_budget_deadline_and_stdin_caps_before_process(self):
        with patch.object(m.subprocess,'Popen',side_effect=AssertionError('process forbidden')):
            r=m.Runner(None,SCRATCH);r.calls=65
            with self.assertRaisesRegex(m.Refusal,'docker_budget'):r.start(['container','inspect','known'])
            r=m.Runner(None,SCRATCH)
            with patch.object(r,'remaining',return_value=0):
                with self.assertRaisesRegex(m.Refusal,'work_deadline'):r.start(['info'])
            r=m.Runner(None,SCRATCH)
            with self.assertRaisesRegex(m.Refusal,'stdin_bound'):r.start(['info'],b'x'*(m.CAP+1))
            r=m.Runner(None,SCRATCH)
            with self.assertRaisesRegex(m.Refusal,'docker_command_family'):r.start(['build'])
    def test_raw_canary_capture_error_has_only_finite_classification(self):
        c=m.Capture.__new__(m.Capture)
        c.proc=argparse.Namespace(poll=lambda:1,returncode=1)
        c.selector=argparse.Namespace(get_map=lambda:{})
        c.raw=b'CANARY-private-exception-message'
        with self.assertRaisesRegex(m.Refusal,'^isolated_command_failed$'):c.wait()
        c.proc=argparse.Namespace(poll=lambda:None,returncode=None);c.deadline=0
        with self.assertRaisesRegex(m.Refusal,'^command_deadline$'):c.wait()
    def test_container_name_and_labels_stop_authority_not_full_safety_bypass(self):
        d=m.descriptor('api','disabled',SCRATCH,PROJECT,STATE);v=model(d,PROJECT+'-fixture')
        v['host']['ReadonlyRootfs']=False
        m.own_identity(v,PROJECT,PROJECT+'-fixture')
        with self.assertRaises(m.Refusal):self.check(v,d)
        v['labels'][m.LABEL]='foreign'
        with self.assertRaises(m.Refusal):m.own_identity(v,PROJECT,PROJECT+'-fixture')
    def test_pinned_tool_wrong_link_refused_without_resolve_or_execution(self):
        with patch.object(Path,'is_symlink',return_value=True),patch.object(m.os,'readlink',return_value='../wrong/docker'),\
             patch.object(m.subprocess,'Popen',side_effect=AssertionError('process forbidden')):
            with self.assertRaisesRegex(m.Refusal,'docker_link'):m.validate_tool()
        self.assertEqual(str(m.DOCKER),'/opt/homebrew/bin/docker')
        self.assertEqual(str(m.CLI_TARGET),'/opt/homebrew/Cellar/docker/28.1.1/bin/docker')
    def test_counters_and_topology_fixed_no_broad_operations(self):
        raw=m.public_read(m.NEW[0]).decode()
        for forbidden in ("['system','prune'", "['image','pull'", "['build'", "['compose'", 'env_file', 'docker.sock,target'):
            self.assertNotIn(forbidden,raw)
        self.assertEqual(len(m.MATRIX_IDS),72);self.assertLessEqual(len(m.VECTOR_IDS),128)
        self.assertIn('CALLS-15',raw);self.assertIn('http_calls<=HTTP',raw)
        self.assertIn("qualify_networks(r,project,netids);qualify_volumes(r,project)",raw)
        self.assertIn('set(c)<=set(active)',raw)


class ControllerFailureMetadataTests(unittest.TestCase):
    """Regression SOURCE ONLY; this module's loader/other tests still need separate T consent."""
    def setUp(self):
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        forbidden=AssertionError('unmocked side effect forbidden')
        for target,name in ((m.subprocess,'Popen'),(m.subprocess,'run'),(m.selectors,'DefaultSelector'),
                            (m.os,'open'),(m.os,'close'),(m.os,'fchmod'),(m.os,'set_blocking'),
                            (m.os,'read'),(m.os,'write'),(m.os,'killpg'),(m.os,'mkdir'),
                            (m.signal,'signal'),(Path,'read_bytes'),(Path,'write_bytes'),
                            (m,'public_read'),(m,'inventory'),(m,'plan'),(m,'write_operand')):
            self.stack.enter_context(patch.object(target,name,side_effect=forbidden))
        self.stack.enter_context(patch.object(m.time,'monotonic',return_value=1))
    def envelope(self,d):
        raw=d.encode();self.assertLessEqual(len(raw),2048)
        self.assertNotIn(b'CANARY',raw)
        value=json.loads(raw);m.FailureMetadata.validate(value);return value
    def capture(self,r,exit_code=1,capture_class=None):
        cls=m.Capture if capture_class is None else capture_class
        c=cls.__new__(cls);c.budget=r;c.raw=bytearray(b'CANARY-private-merged-output')
        c.observed_exit=None;c.complete=False;c.deadline=0
        c.proc=argparse.Namespace(poll=lambda:exit_code,returncode=exit_code)
        c.selector=argparse.Namespace(get_map=lambda:{},close=lambda:None)
        r.diagnostic.state['spawned']=True
        r.diagnostic.local.update(childCreated=True,captureRegistered=True,captureSetupComplete=True)
        r.diagnostic.stdin='closed_normally'
        c.context={key:getattr(r.diagnostic,key) for key in ('operation','mutating','ordinal','ordinal_state','state','local','stdin')}
        return c
    def test_static_operations_and_rejected_ordinals_never_spawn(self):
        for calls,cleanup,ordinal in ((65,False,66),(80,True,81),(81,True,None)):
            r=m.Runner(None,SCRATCH,started=1);r.calls=calls;r.cleanup=cleanup
            with self.assertRaisesRegex(m.Refusal,'^docker_budget$'):
                r.start(['info'],operation='inspect_two_images')
            v=self.envelope(r.diagnostic);p=v['primary']
            self.assertEqual(p['operation'],'inspect_two_images');self.assertEqual(p['attemptOrdinal'],ordinal)
            self.assertEqual(p['ordinalState'],'unavailable' if ordinal is None else 'rejected_budget')
            self.assertIs(p['spawned'],False);self.assertIsNone(p['exitValue'])
            self.assertIsNone(p['captureComplete']);self.assertEqual(p['boundary'],'before_spawn')
    def test_spawn_and_partial_capture_setup_are_distinct(self):
        r=m.Runner(None,SCRATCH,started=1)
        with patch.object(m.subprocess,'Popen',side_effect=PermissionError(m.errno.EPERM,'CANARY-private')):
            with self.assertRaises(PermissionError):r.start(['info'],operation='desktop_info')
        v=self.envelope(r.diagnostic);self.assertEqual(v['primary']['errno'],'operation_not_permitted')
        self.assertIsNone(v['primary']['spawned']);self.assertTrue(v['recordsPartial'])
        r=m.Runner(None,SCRATCH,started=1)
        with patch.object(m.subprocess,'Popen',return_value=object()),patch.object(m,'Capture',side_effect=ValueError('CANARY-private')):
            with self.assertRaises(ValueError):r.start(['volume','create'],operation='create_volume_auth',mutating=True)
        v=self.envelope(r.diagnostic);self.assertEqual(v['primary']['boundary'],'capture_setup')
        self.assertTrue(v['primary']['spawned']);self.assertTrue(v['localSupervision']['childCreated'])
        self.assertFalse(v['localSupervision']['captureRegistered'])
        self.assertEqual(v['operationState']['mutationDisposition'],'possible')
        self.assertIsNone(v['localSupervision']['processGroupAbsent'])
    def test_wait_failure_frozen_before_kill_failure_and_more_events(self):
        r=m.Runner(None,SCRATCH,started=1);r.diagnostic.begin('inspect_two_volumes',False,9)
        r.diagnostic.state['spawned']=True;r.diagnostic.local['childCreated']=True
        c=self.capture(r)
        with patch.object(r,'start',return_value=c),patch.object(c,'kill',side_effect=PermissionError(m.errno.EPERM,'CANARY')):
            with self.assertRaises(PermissionError):r.run(['info'])
        first=r.diagnostic.primary
        r.diagnostic.record('supervision','supervision_error',ValueError('CANARY'),operation='local_supervision')
        v=self.envelope(r.diagnostic);self.assertEqual(first,r.diagnostic.primary)
        self.assertEqual(v['primary']['operation'],'inspect_two_volumes')
        self.assertEqual(v['primary']['reason'],'cli_nonzero');self.assertEqual(v['primary']['exitValue'],1)
        self.assertEqual(v['secondary']['operation'],'local_supervision');self.assertEqual(v['secondaryState'],'more_observed')
    def test_stdin_failure_frozen_before_kill_failure(self):
        r=m.Runner(None,SCRATCH,started=1)
        stdin=argparse.Namespace(fileno=lambda:17,close=lambda:None)
        proc=argparse.Namespace(stdin=stdin)
        c=self.capture(r);c.context={'stdin':'not_started'}
        with patch.object(m.subprocess,'Popen',return_value=proc),patch.object(m,'Capture',return_value=c),\
             patch.object(m.os,'set_blocking',return_value=None),\
             patch.object(m.os,'write',side_effect=BrokenPipeError(m.errno.EPIPE,'CANARY')),\
             patch.object(c,'kill',side_effect=PermissionError(m.errno.EPERM,'CANARY')):
            with self.assertRaises(PermissionError):r.start(['info'],b'public',operation='desktop_info')
        v=self.envelope(r.diagnostic)
        self.assertEqual(v['primary']['boundary'],'stdin');self.assertEqual(v['primary']['stdinState'],'closed_error')
        self.assertEqual(v['primary']['exceptionClass'],'broken_pipe')
        self.assertEqual(v['secondary']['reason'],'supervision_error')
    def test_child_exit_without_eof_is_not_complete_and_late_exit_cannot_rewrite(self):
        r=m.Runner(None,SCRATCH,started=1);r.diagnostic.begin('inspect_two_images',False,1)
        r.diagnostic.state['spawned']=True;r.diagnostic.local['childCreated']=True
        c=self.capture(r,0);c.selector=argparse.Namespace(get_map=lambda:{17:True})
        with self.assertRaisesRegex(m.Refusal,'^command_deadline$'):c.wait_exit()
        v=self.envelope(r.diagnostic);first=r.diagnostic.primary
        self.assertEqual(v['primary']['exitValue'],0);self.assertFalse(v['primary']['captureComplete'])
        c.complete=True;c.observed_exit=-9;r.diagnostic.observe_capture(c)
        self.assertEqual(r.diagnostic.primary,first)
    def test_exact_overflow_accounting_no_clamping_or_raw_capture(self):
        for size,aggregate,reason in ((m.CAP+4096,m.CAP+4096,'capture_per_call_bound'),
                                      (4096,m.AGGREGATE+4096,'capture_aggregate_bound')):
            r=m.Runner(None,SCRATCH,started=1);r.aggregate=aggregate-4096
            r.diagnostic.begin('create_network_backend',True,12)
            r.diagnostic.state.update(spawned=True,mutationDisposition='possible');r.diagnostic.local['childCreated']=True
            c=self.capture(r);c.raw=bytearray(b'x'*(size-4096))
            c.selector=argparse.Namespace(select=lambda _: [(argparse.Namespace(fileobj=argparse.Namespace(fileno=lambda:17)),None)])
            with patch.object(m.os,'read',return_value=b'x'*4096):
                with self.assertRaisesRegex(m.Refusal,'^capture_bound$'):c.pump()
            v=self.envelope(r.diagnostic);p=v['primary'];self.assertEqual(p['reason'],reason)
            self.assertEqual(r.aggregate,aggregate);self.assertEqual(len(c.raw),size)
            self.assertEqual(p['mergedBytes'],None if size>m.CAP else size)
            self.assertEqual(p['mergedBytesState'],'exceeded' if size>m.CAP else 'exact')
            self.assertEqual(p['perCallBoundHit'],size>m.CAP);self.assertEqual(p['aggregateBoundHit'],aggregate>m.AGGREGATE)
            self.assertEqual(v['operationState']['mutationDisposition'],'possible')
    def test_signed_exit_unknowns_and_qualified_mutation_record(self):
        for status,kind,value in ((0,'zero',0),(1,'nonzero',1),(-9,'signaled',-9),(256,'other',None),(None,'unavailable',None),(True,'other',None)):
            d=m.FailureMetadata();d.begin('create_volume_scan',True,10);d.exit=status
            d.state.update(spawned=True,cliCompleted=True if type(status) is int else None,mutationDisposition='possible')
            d.local.update(childCreated=True,directChildReaped=True if type(status) is int else None)
            d.record('qualifier','qualifier_refusal')
            v=self.envelope(d);self.assertEqual((v['primary']['exitKind'],v['primary']['exitValue']),(kind,value))
            self.assertIsNone(v['primary']['mergedBytes']);self.assertTrue(v['recordsPartial'])
        d=m.FailureMetadata();d.begin('create_volume_scan',True,10)
        d.state.update(spawned=True,cliCompleted=True);d.local.update(childCreated=True,directChildReaped=True);d.qualified()
        d.record('qualifier','qualifier_refusal');v=self.envelope(d)
        self.assertEqual(v['operationState']['mutationDisposition'],'qualified_record')
        self.assertTrue(v['recordsPartial'])
    def test_zero_exit_decode_failure_and_literal_schema_fail_closed(self):
        r=m.Runner(None,SCRATCH,started=1);r.diagnostic.begin('inspect_two_volumes',False,11)
        r.diagnostic.exit=0;r.diagnostic.state.update(spawned=True,cliCompleted=True)
        r.diagnostic.local.update(childCreated=True,directChildReaped=True)
        with patch.object(r,'run',return_value=b'{"x":1,"x":2}'):
            with self.assertRaisesRegex(m.Refusal,'^duplicate_json_key$'):r.json(['info'],operation='inspect_two_volumes')
        v=self.envelope(r.diagnostic);self.assertEqual(v['primary']['boundary'],'public_decode')
        self.assertEqual(v['primary']['exitValue'],0);self.assertFalse(v['operationState']['responseQualified'])
        for key,value in (('attemptOrdinal',True),('exitValue',True),('mergedBytes',True),('captureComplete',1),
                          ('operation','CANARY-private'),('errno','CANARY-private')):
            bad=copy.deepcopy(v);bad['primary'][key]=value
            with self.assertRaises(m.Refusal):m.FailureMetadata.validate(bad)
        bad=copy.deepcopy(v);bad['primary']['extra']='CANARY'
        with self.assertRaises(m.Refusal):m.FailureMetadata.validate(bad)
    def test_exception_accessors_and_reporting_fallback_never_replace_primary(self):
        class Untrusted(OSError):
            def __getattribute__(self,name):raise AssertionError('arbitrary accessor forbidden')
            def __str__(self):raise AssertionError('formatter forbidden')
        d=m.FailureMetadata();d.begin('inspect_two_images',False,1)
        d.record('spawn','spawn_error',Untrusted())
        v=self.envelope(d);self.assertEqual(v['primary']['exceptionClass'],'other')
        self.assertEqual(v['primary']['errno'],'unavailable');first=d.primary
        d.begin('unknown',False,None);d.record('unknown','reporting_refusal',ValueError('CANARY'))
        self.assertEqual(d.primary,first);self.envelope(d)
        with patch.object(m.FailureMetadata,'validate',side_effect=m.Refusal('diagnostic_bound')):
            self.assertEqual(d.encode(),m.DIAGNOSTIC_FALLBACK)
        self.assertEqual(d.primary,first)
        fallback=json.loads(m.DIAGNOSTIC_FALLBACK)
        self.assertEqual(set(fallback),{'v','primaryUnavailable','rawValuesIncluded','recordsPartial','reportingRefused','rootCauseEstablished'})
        self.assertTrue(fallback['primaryUnavailable']);self.assertTrue(fallback['recordsPartial'])
        self.assertFalse(fallback['rawValuesIncluded']);self.assertFalse(fallback['rootCauseEstablished'])

    def test_r2_keyerror_is_frozen_before_kill_for_both_wait_wrappers(self):
        for seed in (False,True):
            for earlier in (False,True):
                for kill_error in (False,True):
                    r=m.Runner(None,SCRATCH,started=1)
                    if earlier:
                        r.diagnostic.begin('unknown',False,1);r.diagnostic.record('qualifier','qualifier_refusal')
                    original=r.diagnostic.primary
                    def started(*args,**kwargs):
                        r.diagnostic.begin('cleanup_discovery' if earlier else 'unknown',False,2)
                        c=self.capture(r,None)
                        def failed_wait():raise KeyError('CANARY-private-wait')
                        def killed():
                            c.activate_metadata();c.observed_exit=-9;r.diagnostic.observe_capture(c)
                            r.diagnostic.local['selectorClosed']=True
                            if kill_error:raise PermissionError(m.errno.EPERM,'CANARY-private-kill')
                        c.wait=failed_wait;c.wait_exit=failed_wait;c.kill=killed
                        return c
                    with patch.object(r,'start',side_effect=started):
                        with self.assertRaises(PermissionError if kill_error else KeyError):
                            r.seed_run('f'*64,b'') if seed else r.run(['info'])
                    v=self.envelope(r.diagnostic)
                    row=v['secondary'] if earlier else v['primary']
                    self.assertEqual(row['boundary'],'drain');self.assertEqual(row['exceptionClass'],'key_error')
                    self.assertEqual(row['attemptOrdinal'],2);self.assertIsNone(row['exitValue'])
                    self.assertFalse(row['captureComplete'])
                    if earlier:
                        self.assertEqual(r.diagnostic.primary,original)
                        self.assertEqual(v['secondaryState'],'more_observed' if kill_error else 'one_observed')
                    else:
                        self.assertIsNone(v['localSupervision']['directChildReaped'])
                        self.assertIsNone(v['localSupervision']['selectorClosed'])
                        self.assertEqual(v['secondaryState'],'one_observed' if kill_error else 'none')
    def test_r2_existing_primary_retains_first_cleanup_oserror_before_kill(self):
        for seed in (False,True):
            for kill_error in (False,True):
                r=m.Runner(None,SCRATCH,started=1)
                r.diagnostic.begin('unknown',False,1);r.diagnostic.record('qualifier','qualifier_refusal')
                original=r.diagnostic.primary
                def started(*args,**kwargs):
                    r.diagnostic.begin('cleanup_qualification',False,2);c=self.capture(r,None)
                    def failed_wait():raise PermissionError(m.errno.EACCES,'CANARY-drain')
                    def killed():
                        c.observed_exit=-9;r.diagnostic.observe_capture(c)
                        if kill_error:raise OSError(m.errno.ENOBUFS,'CANARY-kill')
                    c.wait=failed_wait;c.wait_exit=failed_wait;c.kill=killed
                    return c
                with patch.object(r,'start',side_effect=started):
                    with self.assertRaises(OSError):
                        r.seed_run('f'*64,b'') if seed else r.run(['info'])
                v=self.envelope(r.diagnostic)
                self.assertEqual(r.diagnostic.primary,original)
                self.assertEqual(v['secondary']['operation'],'cleanup_qualification')
                self.assertEqual(v['secondary']['boundary'],'drain')
                self.assertEqual(v['secondary']['errno'],'permission_denied')
                self.assertIsNone(v['secondary']['exitValue'])
                self.assertEqual(v['secondaryState'],'more_observed' if kill_error else 'one_observed')
    def test_r2_already_recorded_wait_event_is_not_counted_again(self):
        for seed in (False,True):
            r=m.Runner(None,SCRATCH,started=1)
            r.diagnostic.begin('unknown',False,1);r.diagnostic.record('qualifier','qualifier_refusal')
            def started(*args,**kwargs):
                r.diagnostic.begin('cleanup_discovery',False,2);c=self.capture(r,None)
                def failed_wait():
                    r.diagnostic.observe_capture(c);r.diagnostic.deadline=True
                    r.diagnostic.record('drain','command_deadline');raise m.Refusal('command_deadline')
                c.wait=failed_wait;c.wait_exit=failed_wait;c.kill=lambda:None
                return c
            with patch.object(r,'start',side_effect=started):
                with self.assertRaises(m.Refusal):r.seed_run('f'*64,b'') if seed else r.run(['info'])
            v=self.envelope(r.diagnostic)
            self.assertEqual(v['secondary']['reason'],'command_deadline')
            self.assertEqual(v['secondaryState'],'one_observed')
    def test_r2_stdin_refusal_with_primary_and_recorded_pump_control(self):
        capture_class=m.Capture
        for recorded in (False,True):
            r=m.Runner(None,SCRATCH,started=1);r.calls=1
            r.diagnostic.begin('unknown',False,1);r.diagnostic.record('qualifier','qualifier_refusal')
            original=r.diagnostic.primary
            proc=argparse.Namespace(stdin=argparse.Namespace(fileno=lambda:17,close=lambda:None))
            def captured(*args):
                c=self.capture(r,None,capture_class);c.kill=lambda:None
                def failed_pump(seconds):
                    r.diagnostic.observe_capture(c);r.diagnostic.deadline=True
                    r.diagnostic.record('drain','command_deadline');raise m.Refusal('command_deadline')
                c.pump=failed_pump;return c
            with patch.object(m.subprocess,'Popen',return_value=proc),patch.object(m,'Capture',side_effect=captured),\
                 patch.object(m.os,'set_blocking',return_value=None,side_effect=None if recorded else m.Refusal('stdin_closed')),\
                 patch.object(m.os,'write',side_effect=BlockingIOError(m.errno.EAGAIN,'CANARY')):
                with self.assertRaisesRegex(m.Refusal,'^stdin_closed$'):r.start(['info'],b'public')
            v=self.envelope(r.diagnostic);self.assertEqual(r.diagnostic.primary,original)
            self.assertEqual(v['secondaryState'],'one_observed')
            self.assertEqual(v['secondary']['boundary'],'drain' if recorded else 'stdin')
            self.assertEqual(v['secondary']['reason'],'command_deadline' if recorded else 'unknown')
    def test_r2_seed_context_restore_uses_attach_not_later_inspect(self):
        for status,raw in ((1,m.canonical(seed_failure())),(1,b'{'),(256,b'{'),(0,b'{')):
            r=m.Runner(None,SCRATCH,started=1)
            def started(*args,**kwargs):
                r.diagnostic.begin('unknown',False,7);c=self.capture(r,status);c.raw=bytearray(raw)
                def killed():
                    c.observed_exit=-9;r.diagnostic.observe_capture(c);r.diagnostic.local['selectorClosed']=True
                c.kill=killed;return c
            with patch.object(r,'start',side_effect=started):
                self.assertEqual(r.seed_run('f'*64,b''),(raw,status))
            first=r.diagnostic.primary
            r.diagnostic.begin('unknown',False,8)
            r.diagnostic.state.update(spawned=True,cliCompleted=True,responseQualified=True)
            r.diagnostic.local.update(childCreated=True,directChildReaped=True,captureRegistered=True,captureSetupComplete=True)
            r.diagnostic.exit=0;r.diagnostic.size=2;r.diagnostic.complete=True
            r.diagnostic.per_call=False;r.diagnostic.aggregate=False
            r.diagnostic.restore_context(r.seed_context)
            with self.assertRaises(m.Refusal):
                m.seed_outcome(raw,status,{'Status':'exited','ExitCode':1 if status else 0},'setup',diagnostic=r.diagnostic)
            v=self.envelope(r.diagnostic);p=v['primary']
            self.assertEqual(p['attemptOrdinal'],7);self.assertEqual(p['mergedBytes'],len(raw))
            self.assertEqual(p['exitKind'],'other' if status==256 else 'nonzero' if status else 'zero')
            self.assertEqual(p['exitValue'],None if status==256 else status)
            self.assertIsNone(v['localSupervision']['selectorClosed'])
            if status:
                self.assertEqual(r.diagnostic.primary,first)
                self.assertEqual(v['secondary']['attemptOrdinal'],7)
                self.assertEqual(v['secondary']['exitKind'],p['exitKind'])
                self.assertEqual(v['secondary']['boundary'],'public_decode' if raw==b'{' and status==1 else 'qualifier')
            else:self.assertEqual(p['boundary'],'public_decode')
    def test_r2_seed_nonzero_precedes_kill_error(self):
        r=m.Runner(None,SCRATCH,started=1)
        def started(*args,**kwargs):
            r.diagnostic.begin('unknown',False,7);c=self.capture(r,1)
            def killed():raise PermissionError(m.errno.EPERM,'CANARY-kill')
            c.kill=killed;return c
        with patch.object(r,'start',side_effect=started):
            with self.assertRaises(PermissionError):r.seed_run('f'*64,b'')
        v=self.envelope(r.diagnostic)
        self.assertEqual(v['primary']['reason'],'cli_nonzero');self.assertEqual(v['primary']['exitValue'],1)
        self.assertEqual(v['secondary']['reason'],'supervision_error')
        self.assertEqual(json.loads(r.seed_context)['exit'],1)
    def test_r2_crossfield_contradictions_refused_but_nulls_remain_unknown(self):
        r=m.Runner(None,SCRATCH,started=1);r.calls=65
        with self.assertRaises(m.Refusal):r.start(['info'])
        base=self.envelope(r.diagnostic)
        for section,key in (('operationState','cliCompleted'),('operationState','responseQualified'),
                            ('localSupervision','directChildReaped'),('localSupervision','captureSetupComplete'),
                            ('localSupervision','captureRegistered')):
            bad=copy.deepcopy(base);bad[section][key]=True
            with self.assertRaises(m.Refusal):m.FailureMetadata.validate(bad)
        bad=copy.deepcopy(base);bad['primary'].update(reason='cli_nonzero',boundary='cli_exit')
        with self.assertRaises(m.Refusal):m.FailureMetadata.validate(bad)
        r=m.Runner(None,SCRATCH,started=1);r.diagnostic.begin('unknown',False,3)
        c=self.capture(r,0);c.observed_exit=0;c.complete=True;r.diagnostic.observe_capture(c)
        r.diagnostic.record('qualifier','qualifier_refusal');completed=self.envelope(r.diagnostic)
        for section,key,value in (('localSupervision','captureRegistered',False),
                                  ('localSupervision','captureSetupComplete',False),
                                  ('localSupervision','directChildReaped',False),
                                  ('localSupervision','childCreated',False),
                                  ('operationState','cliCompleted',False)):
            bad=copy.deepcopy(completed);bad[section][key]=value
            with self.assertRaises(m.Refusal):m.FailureMetadata.validate(bad)
        for changes in ({'reason':'cli_nonzero'},{'reason':'cli_nonzero','boundary':'cli_exit'},
                        {'reason':'call_budget','boundary':'before_spawn'}):
            bad=copy.deepcopy(completed);bad['primary'].update(changes)
            with self.assertRaises(m.Refusal):m.FailureMetadata.validate(bad)
        d=m.FailureMetadata();d.begin('unknown',False,None)
        d.state.update(attempted=None,spawned=None);d.local=dict.fromkeys(m.DIAGNOSTIC_LOCAL_KEYS)
        d.record('unknown','unknown');v=self.envelope(d)
        self.assertIsNone(v['primary']['exitValue']);self.assertIsNone(v['operationState']['cliCompleted'])
        self.assertTrue(all(value is None for value in v['localSupervision'].values()))


def seed_failure(phase='setup', step='initialize_status', children=None):
    return {'kind':'history-wire-seed-refusal','passed':False,'phase':phase,'step':step,
            'errorClass':'AssertionError','errorCode':'ERR_ASSERTION','initializers':[] if children is None else children,
            'initializerPids':None,'cleanupFailed':False,'rawValuesIncluded':False}


def child_result(kind='initialize'):
    return {'kind':kind,'exit':'zero' if kind=='initialize' else 'one','signal':'none','error':'none',
            'stdoutExpectedMatch':True,'stderrExpectedMatch':True,'stdoutEmpty':kind!='initialize',
            'stderrEmpty':kind=='initialize','stdoutBounded':True,'stderrBounded':True,
                        'node':m.empty_node_diagnostic()}


class SeedCheckpointTests(unittest.TestCase):
    def validate(self,v,phase='setup'):
        return m.receipt(m.canonical(v), 'history-wire-seed-refusal',phase)
    def test_finite_phase_step_class_code_and_bound(self):
        for phase, steps in [('entry',m.SEED_ENTRY_STEPS),('setup',m.SEED_COMMON_STEPS+m.SEED_SETUP_STEPS),
                             ('audit',m.SEED_COMMON_STEPS+m.SEED_AUDIT_STEPS)]:
            for step in steps:
                v=seed_failure(phase,step);self.assertEqual(self.validate(v,'audit' if phase=='audit' else 'setup'),v)
        for error_class in m.SEED_ERROR_CLASSES:
            for code in m.SEED_ERROR_CODES:
                self.validate({**seed_failure(),'errorClass':error_class,'errorCode':code})
        children=[child_result(),child_result('existing_refusal')]
        largest={**seed_failure(step=max(m.SEED_COMMON_STEPS+m.SEED_SETUP_STEPS,key=len)),
                 'errorClass':max(m.SEED_ERROR_CLASSES,key=len),'errorCode':max(m.SEED_ERROR_CODES,key=len),'initializers':children}
        self.assertLessEqual(len(m.canonical(largest)),m.SEED_DIAGNOSTIC_BYTES);self.validate(largest)
    def test_closed_schema_strict_flags_and_unknown_enums(self):
        base=seed_failure();canary='CANARY-private-message-path-cookie'
        variants=[{**base,'extra':canary}, {k:v for k,v in base.items() if k!='step'}]
        for key in ('phase','step','errorClass','errorCode','kind'):
            for value in (canary,None,False,[],{}):variants.append({**base,key:value})
        for key in ('passed','rawValuesIncluded'):
            for value in (True,0,1,'false',None):variants.append({**base,key:value})
        for value in (0,1,'false',None):variants.append({**base,'cleanupFailed':value})
        variants.extend([seed_failure('audit','initialize_status'),seed_failure('setup','audit_head'),
                         seed_failure('entry','environment_uid')])
        for v in variants:
            with self.assertRaises(m.Refusal) as error:self.validate(v)
            self.assertNotIn(canary,str(error.exception))
        for raw in (b'{"kind":"history-wire-seed-refusal","kind":"history-wire-seed-refusal"}',
                    b'{"error":NaN}',b'\xff',b' '+m.canonical(base)+b' '*m.SEED_DIAGNOSTIC_BYTES):
            with self.assertRaises(m.Refusal):m.receipt(raw,base['kind'],'setup')
    def test_initializer_order_flags_enums_and_consistency(self):
        self.validate(seed_failure(children=[child_result(),child_result('existing_refusal')]))
        variations=[{},[],{'raw':'CANARY-private'}, {**child_result(),'extra':False}]
        for key,values in {'kind':['existing_refusal','unknown'], 'exit':[0,False,'unknown'],
                           'signal':['SIGTERM',None], 'error':['ERR_ASSERTION',None]}.items():
            variations.extend({**child_result(),key:value} for value in values)
        for key in ('stdoutExpectedMatch','stderrExpectedMatch','stdoutEmpty','stderrEmpty','stdoutBounded','stderrBounded'):
            variations.append({**child_result(),key:1})
        variations.extend([{**child_result(),'stdoutBounded':False},{**child_result(),'stdoutEmpty':True},
                           {**child_result(),'stderrBounded':False},{**child_result(),'stderrEmpty':False}])
        for row in variations:
            with self.assertRaises(m.Refusal):self.validate(seed_failure(children=[row]))
        for children in (None,{},'unknown',[child_result()]*3,[child_result(),child_result()]):
            v={**seed_failure(),'initializers':children}
            with self.assertRaises(m.Refusal):self.validate(v)
        for phase in ('entry','audit'):
            with self.assertRaises(m.Refusal):self.validate(seed_failure(phase,'entry_read' if phase=='entry' else 'audit_head',[child_result()]),phase if phase=='audit' else 'setup')
        for exit_code in ('zero','one','other','none','invalid'):
            for signal in ('none','sigterm','sigkill','other'):
                for error in ('none','ETIMEDOUT','ENOBUFS','EPERM','EACCES','ENOENT','EAGAIN','ENOMEM','other'):
                    row={**child_result(),'exit':exit_code,'signal':signal,'error':error}
                    self.validate(seed_failure(children=[row]))
    def test_failure_never_becomes_setup_or_audit_success(self):
        state={'Status':'exited','ExitCode':1}
        for phase in ('setup','audit'):
            failure=seed_failure(phase,'initialize_status' if phase=='setup' else 'audit_head')
            with self.assertRaises(m.SeedDiagnosticRefusal) as error:m.seed_outcome(m.canonical(failure),1,state,phase)
            self.assertEqual(str(error.exception),'seed_checkpoint_refused');self.assertEqual(error.exception.diagnostics,failure)
            with self.assertRaises(m.Refusal):m.seed_outcome(m.canonical(failure),0,{'Status':'exited','ExitCode':0},phase)
        for command,container,status in ((True,1,'exited'),(1,True,'exited'),(0,1,'exited'),(1,0,'exited'),
                                         (2,1,'exited'),(-9,1,'exited'),(1,1,'running'),(1,None,'exited')):
            with self.assertRaises(m.Refusal):m.seed_outcome(m.canonical(seed_failure()),command,{'Status':status,'ExitCode':container},'setup')
        for raw in (b'',b'CANARY-history-wire-public',b'private unknown stack',m.canonical({**seed_failure(),'message':'CANARY-private'})):
            with self.assertRaises(m.Refusal) as error:m.seed_outcome(raw,1,state,'setup')
            self.assertNotIn('CANARY',str(error.exception));self.assertNotIn('private',str(error.exception))
        success={'kind':'history-wire-setup','state':STATE,'revisions':[0,1,2],**dict.fromkeys(
            ('missingHistoryRefused','initializerSucceeded','existingInitializerRefusedUnchanged','embeddedSourceQualified',
             'syntheticTerminalReport','syntheticFailedTurn','quotaAbsent','mountedFixtureBytesQualified','fullSynchronous'),True)}
        self.assertEqual(m.seed_outcome(m.canonical(success),0,{'Status':'exited','ExitCode':0},'setup'),success)
        with self.assertRaises(m.Refusal):m.seed_outcome(m.canonical(success),1,state,'setup')
    def test_nonzero_capture_only_seed_transport_and_exact_one_call(self):
        c=m.Capture.__new__(m.Capture);c.proc=argparse.Namespace(poll=lambda:1,returncode=1)
        c.selector=argparse.Namespace(get_map=lambda:{});c.raw=b'CANARY-private-not-for-publication'
        self.assertEqual(c.wait_exit(),(bytes(c.raw),1))
        with self.assertRaisesRegex(m.Refusal,'^isolated_command_failed$'):c.wait()
        r=m.Runner(None,SCRATCH);r.diagnostic.begin('unknown',False,1)
        r.diagnostic.state['spawned']=True
        r.diagnostic.local.update(childCreated=True,captureRegistered=True,captureSetupComplete=True)
        capture=argparse.Namespace(wait_exit=lambda:(b'bounded',1),kill=lambda:None,raw=b'bounded',
                                 observed_exit=1,complete=True,budget=r)
        with patch.object(r,'start',return_value=capture) as start:
            self.assertEqual(r.seed_run('f'*64,b'public-input'),(b'bounded',1))
            start.assert_called_once_with(['container','start','--attach','--interactive','f'*64],b'public-input')
        with patch.object(r,'start',side_effect=AssertionError('process forbidden')):
            for cid in ('unknown','f'*63,'f'*65,'F'*64,None):
                with self.assertRaises(m.Refusal):r.seed_run(cid,b'')
    def test_oneshot_failure_receipt_stops_before_remove_or_startup(self):
        # Execute the actual nested coordinator with fake transport/inspect only.
        tree=ast.parse(m.public_read(m.NEW[0]).decode())
        execute_node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='execute')
        oneshot=next(n for n in execute_node.body if isinstance(n,ast.FunctionDef) and n.name=='oneshot')
        cid='f'*64;events=[];packet=seed_failure(children=[child_result()])
        d=m.descriptor('seed','setup',SCRATCH,PROJECT);observed=model(d,PROJECT+'-seed')
        observed['state']={'Status':'exited','ExitCode':1,'OOMKilled':False}
        def checked_create(role,phase,state):events.append('created');return cid
        runner=m.Runner(None,SCRATCH)
        def transport(target,stdin):
            self.assertEqual(target,cid);self.assertEqual(stdin,b'{"files":{}}');events.append('attached')
            runner.diagnostic.begin('unknown',False,9)
            runner.diagnostic.state.update(spawned=True,cliCompleted=True)
            runner.diagnostic.local.update(childCreated=True,directChildReaped=True,captureRegistered=True,captureSetupComplete=True)
            runner.diagnostic.exit=1;runner.diagnostic.size=len(m.canonical(packet));runner.diagnostic.complete=True
            runner.diagnostic.per_call=False;runner.diagnostic.aggregate=False
            runner.diagnostic.record('cli_exit','cli_nonzero');runner.seed_context=runner.diagnostic.freeze_context()
            return m.canonical(packet),1
        def inspected(argv):
            self.assertEqual(argv,['container','inspect','--format',m.INSPECT,cid]);events.append('inspected')
            runner.diagnostic.begin('unknown',False,10)
            runner.diagnostic.state.update(spawned=True,cliCompleted=True)
            runner.diagnostic.local.update(childCreated=True,directChildReaped=True,captureRegistered=True,captureSetupComplete=True)
            runner.diagnostic.exit=0;runner.diagnostic.size=2;runner.diagnostic.complete=True
            runner.diagnostic.per_call=False;runner.diagnostic.aggregate=False
            return [observed]
        def qualified(*args):
            m.qualify_container(*args);events.append('qualified')
        args=argparse.Namespace(daemon_bind_source_policy=m.POLICY,docker_context='desktop-linux')
        runner.seed_run=transport;runner.rows=inspected
        namespace={**vars(m),'checked_create':checked_create,'r':runner,
                   'active':{cid:(d,PROJECT+'-seed')},'project':PROJECT,'args':args,'qualify_container':qualified,
                   'remove':lambda _:events.append('removed')}
        exec(compile(ast.Module(body=[oneshot],type_ignores=[]),'<public-oneshot-pure>','exec'),namespace)
        with patch.object(m.subprocess,'Popen',side_effect=AssertionError('process forbidden')):
            with self.assertRaises(m.SeedDiagnosticRefusal):namespace['oneshot']('seed','setup',{'files':{}})
        self.assertEqual(events,['created','attached','inspected','qualified'])
        packet['rawMessage']='CANARY-private';events.clear()
        with self.assertRaisesRegex(m.Refusal,'^seed_refusal_receipt_refused$'):namespace['oneshot']('seed','setup',{'files':{}})
        self.assertEqual(events,['created','attached','inspected','qualified'])
    def test_r2_actual_oneshot_preserves_seed_context_after_required_inspect(self):
        # SOURCE ONLY: this existing AST/coordinator pattern is not an approved T entry.
        tree=ast.parse(m.public_read(m.NEW[0]).decode())
        execute_node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='execute')
        oneshot=next(n for n in execute_node.body if isinstance(n,ast.FunctionDef) and n.name=='oneshot')
        cases=((1,m.canonical(seed_failure()),True),(1,b'{',True),(256,b'{',True),
               (0,b'{',True),(0,b'{',False))
        for status,raw,own in cases:
            with self.subTest(status=status,raw=raw,own=own),ExitStack() as stack:
                for target,name in ((m.subprocess,'Popen'),(m.subprocess,'run'),(m.selectors,'DefaultSelector'),
                                    (m.os,'read'),(m.os,'write'),(m.os,'killpg')):
                    stack.enter_context(patch.object(target,name,side_effect=AssertionError('process or IO forbidden')))
                stack.enter_context(patch.object(m.time,'monotonic',return_value=1))
                cid='f'*64;events=[];runner=m.Runner(None,SCRATCH,started=1)
                d=m.descriptor('seed','setup',SCRATCH,PROJECT);observed=model(d,PROJECT+'-seed')
                observed['state']={'Status':'exited','ExitCode':1 if status else 0,'OOMKilled':False}
                if not own:observed['labels'][m.LABEL]='foreign'
                def checked_create(role,phase,state):
                    self.assertEqual((role,phase),('seed','setup'));events.append('created');return cid
                def started(argv,stdin):
                    self.assertEqual(argv,['container','start','--attach','--interactive',cid])
                    self.assertEqual(stdin,b'{"files":{}}');events.append('attached')
                    runner.diagnostic.begin('unknown',False,9)
                    runner.diagnostic.state['spawned']=True
                    runner.diagnostic.local.update(childCreated=True,captureRegistered=True,captureSetupComplete=True)
                    runner.diagnostic.stdin='closed_normally'
                    c=m.Capture.__new__(m.Capture);c.budget=runner;c.raw=bytearray(raw)
                    c.observed_exit=None;c.complete=False;c.deadline=20
                    c.proc=argparse.Namespace(poll=lambda:status,returncode=status)
                    c.selector=argparse.Namespace(get_map=lambda:{})
                    c.context={key:getattr(runner.diagnostic,key) for key in
                               ('operation','mutating','ordinal','ordinal_state','state','local','stdin')}
                    def killed():
                        events.append('local_kill');c.observed_exit=-9;runner.diagnostic.observe_capture(c)
                        runner.diagnostic.local['selectorClosed']=True
                    c.kill=killed;return c
                def inspected(argv):
                    self.assertEqual(argv,['container','inspect','--format',m.INSPECT,cid]);events.append('inspected')
                    runner.diagnostic.begin('unknown',False,10)
                    runner.diagnostic.state.update(spawned=True,cliCompleted=True,responseQualified=True)
                    runner.diagnostic.local.update(childCreated=True,directChildReaped=True,captureRegistered=True,captureSetupComplete=True)
                    runner.diagnostic.exit=0;runner.diagnostic.size=2;runner.diagnostic.complete=True
                    runner.diagnostic.per_call=False;runner.diagnostic.aggregate=False
                    return [observed]
                def qualified(*args):
                    events.append('qualifying');value=m.qualify_container(*args);events.append('qualified');return value
                runner.rows=inspected
                args=argparse.Namespace(daemon_bind_source_policy=m.POLICY,docker_context='desktop-linux')
                namespace={**vars(m),'checked_create':checked_create,'r':runner,
                           'active':{cid:(d,PROJECT+'-seed')},'project':PROJECT,'args':args,'qualify_container':qualified,
                           'remove':lambda _:events.append('removed')}
                exec(compile(ast.Module(body=[oneshot],type_ignores=[]),'<public-oneshot-r2-source-only>','exec'),namespace)
                stack.enter_context(patch.object(runner,'start',side_effect=started))
                with self.assertRaises(m.Refusal) as error:namespace['oneshot']('seed','setup',{'files':{}})
                self.assertEqual(events,['created','attached','local_kill','inspected','qualifying']+(['qualified'] if own else []))
                value=json.loads(runner.diagnostic.encode());m.FailureMetadata.validate(value);p=value['primary']
                self.assertEqual(p['attemptOrdinal'],9 if own else 10)
                self.assertEqual(p['mergedBytes'],len(raw) if own else 2)
                self.assertEqual(p['exitKind'],('other' if status==256 else 'nonzero' if status else 'zero') if own else 'zero')
                self.assertEqual(p['exitValue'],(None if status==256 else status) if own else 0)
                if own:
                    self.assertIsNone(value['localSupervision']['selectorClosed'])
                    self.assertEqual(p['reason'],'cli_nonzero' if status else 'decode_refusal')
                    if status:
                        self.assertEqual(value['secondaryState'],'one_observed')
                        self.assertEqual(value['secondary']['attemptOrdinal'],9)
                        self.assertEqual(value['secondary']['mergedBytes'],len(raw))
                        self.assertEqual(value['secondary']['exitKind'],p['exitKind'])
                    else:self.assertEqual(value['secondaryState'],'none')
                    if raw!=b'{':self.assertIsInstance(error.exception,m.SeedDiagnosticRefusal)
                    else:self.assertNotIsInstance(error.exception,m.SeedDiagnosticRefusal)
                else:
                    self.assertIsInstance(error.exception,m.RuntimeQualifierRefusal)
                    self.assertEqual((p['boundary'],p['reason']),('qualifier','qualifier_refusal'))
                    self.assertEqual(value['secondaryState'],'none')
    def test_source_failure_checkpoint_before_startup_and_no_raw_child_reflection(self):
        seed=m.public_read(m.SEED).decode();runner=m.public_read(m.NEW[0]).decode()
        checkpoints=set(re.findall(r"checkpoint\('([a-z_]+)'\)",seed))
        cleanups=set(re.findall(r"diagnosticCleanup\('([a-z_]+)'",seed))
        allowed=set(m.SEED_ENTRY_STEPS+m.SEED_COMMON_STEPS+m.SEED_SETUP_STEPS+m.SEED_AUDIT_STEPS)
        self.assertEqual(checkpoints|cleanups,allowed)
        self.assertIn('timeout: 10000, maxBuffer: INITIALIZER_CAPTURE_BYTES',seed)
        self.assertEqual(m.INITIALIZER_CAPTURE_BYTES,32768)
        self.assertIn("process.exitCode = 1",seed)
        block=seed.split('// BEGIN PURE SEED DIAGNOSTICS',1)[1].split('// END PURE SEED DIAGNOSTICS',1)[0]
        for forbidden in ('.message','.stack','process.','console.','readFile','JSON.stringify(error)'):
            self.assertNotIn(forbidden,block)
        self.assertLess(runner.index('value=seed_outcome('),runner.index("web=checked_create('web'"))
        self.assertLess(runner.index("qualify_container(observed,d,"),runner.index('value=seed_outcome('))
        self.assertIn("evidence['seedDiagnostics']=error.diagnostics",runner)
        self.assertIn("if role=='seed': raw,command_exit=r.seed_run(cid,stdin)",runner)
        self.assertIn("else: raw=r.run(['container','start','--attach','--interactive',cid],stdin)",runner)
    def test_node_receipt_allowlists_frames_pinned_source_and_negatives(self):
        row={**child_result(),'stderrEmpty':False,'stderrExpectedMatch':False}
        for name in m.SEED_NODE_CLASSES+('none','ambiguous'):
            for code in m.SEED_NODE_CODES+('none','ambiguous'):
                node={**m.empty_node_diagnostic(),'class':name,'code':code}
                self.validate(seed_failure(children=[{**row,'node':node}]))
        for file_id,path in m.SEED_NODE_FRAME_PATHS.items():
            lines=len(m.public_read(path).decode().splitlines())
            for line in (1,lines):
                self.validate(seed_failure(children=[{**row,'node':{**m.empty_node_diagnostic(),'class':'TypeError','frame':[file_id,line]}}]))
            for line in (True,0,-1,lines+1,4097,'1',1.0,None):
                with self.assertRaises(m.Refusal):self.validate(seed_failure(children=[{**row,'node':{**m.empty_node_diagnostic(),'frame':[file_id,line]}}]))
        canary='CANARY-private-raw-output-env-message'
        for node in ({},None,[],{'class':canary,'code':'none','frame':None},
                     {'class':'none','code':canary,'frame':None},
                     {'class':'none','code':'none','frame':['/arbitrary/private/path',1]},
                     {'class':'none','code':'none','frame':['history_init',1,2]},
                     {'class':'none','code':'none','frame':'history_init'},
                     {'class':'none','code':'none','frame':None,'message':canary}):
            with self.assertRaises(m.Refusal) as error:self.validate(seed_failure(children=[{**row,'node':node}]))
            self.assertNotIn(canary,str(error.exception))
        nonempty={**m.empty_node_diagnostic(),'class':'TypeError','code':'ERR_MODULE_NOT_FOUND','frame':['history_init',1]}
        for flags in ({'stderrBounded':False},{'stderrEmpty':True},{'stderrExpectedMatch':True}):
            with self.assertRaises(m.Refusal):self.validate(seed_failure(children=[{**row,**flags,'node':nonempty}]))
    def test_node_receipt_maximum_two_children_still_bounded(self):
        path=max(m.SEED_NODE_FRAME_PATHS,key=len);line=len(m.public_read(m.SEED_NODE_FRAME_PATHS[path]).decode().splitlines())
        node={**m.empty_node_diagnostic(),'class':max(m.SEED_NODE_CLASSES,key=len),'code':max(m.SEED_NODE_CODES,key=len),
              'frame':[path,line],'flags':dict.fromkeys(m.SEED_NODE_FLAGS,False)}
        children=[{**child_result(kind),'stderrEmpty':False,'stderrExpectedMatch':False,'node':node}
                  for kind in ('initialize','existing_refusal')]
        v={**seed_failure(step=max(m.SEED_COMMON_STEPS+m.SEED_SETUP_STEPS,key=len)),
           'errorClass':max(m.SEED_ERROR_CLASSES,key=len),'errorCode':max(m.SEED_ERROR_CODES,key=len),'initializers':children}
        sample={key:[True,True,m.OWN_PIDS_COUNTER_MAX] for key in m.OWN_PIDS_FILES}
        v['step']='existing_error_signal';v['initializerPids']={'kind':'existing_refusal','before':sample,'after':sample}
        self.assertLessEqual(len(m.canonical(v)),m.SEED_DIAGNOSTIC_BYTES);self.validate(v)
    def test_initializer_transport_only_capture_limit_changed(self):
        raw=m.public_read(m.SEED).decode()
        self.assertIn("timeout: 10000, maxBuffer: INITIALIZER_CAPTURE_BYTES, stdio: ['ignore', 'pipe', 'pipe']",raw)
        for assertion in ("assert.equal(initialized.status, 0)","assert(!initialized.error && !initialized.signal)",
                          "assert.equal(initialized.stderr.toString(), '')","assert.equal(negative.status, 1)",
                          "assert(!negative.error && !negative.signal)","assert.equal(negative.stdout.toString(), '')"):
            self.assertIn(assertion,raw)
        self.assertIn("History operator action complete. No provider call or runtime activation performed.\\n",raw)
        self.assertIn("History operator action refused; no quota reset or automatic repair.\\n",raw)
        self.assertEqual(m.SLOTS['seed'],(65532,128,500000000,32,'none'))
        self.assertEqual(m.INITIALIZER_CAPTURE_BYTES,32768)
    def test_pids_closed_schema_values_presence_and_phase(self):
        sample={key:[True,True,32 if key=='max' else 0] for key in m.OWN_PIDS_FILES}
        probe={'kind':'initialize','before':sample,'after':sample}
        v={**seed_failure(children=[child_result()]),'initializerPids':probe};self.validate(v)
        for key in m.OWN_PIDS_FILES:
            for counter in ([False,False,None],[True,False,None],[True,True,0],[True,True,m.OWN_PIDS_COUNTER_MAX]):
                changed=copy.deepcopy(v);changed['initializerPids']['after'][key]=counter;self.validate(changed)
            for counter in ([False,True,0],[False,False,0],[True,False,32],[True,True,True],
                            [True,True,-1],[True,True,m.OWN_PIDS_COUNTER_MAX+1],[True,True,'32'],
                            [1,True,32],[True,1,32],[True,True,32,0],None,{}):
                changed=copy.deepcopy(v);changed['initializerPids']['after'][key]=counter
                with self.assertRaises(m.Refusal):self.validate(changed)
        for key in m.OWN_PIDS_FILES:
            changed=copy.deepcopy(v);changed['initializerPids']['after'][key]=[True,True,'max']
            if key=='max':self.validate(changed)
            else:
                with self.assertRaises(m.Refusal):self.validate(changed)
        for invalid in ([],{}, {'kind':'unknown','before':sample,'after':sample},
                        {**probe,'private':'CANARY-private'}, {**probe,'before':{**sample,'other':0}}):
            with self.assertRaises(m.Refusal) as error:self.validate({**v,'initializerPids':invalid})
            self.assertNotIn('CANARY',str(error.exception))
        for phase,step in (('entry','entry_parse'),('audit','audit_head'),('setup','auth_register_owner')):
            with self.assertRaises(m.Refusal):self.validate({**v,'phase':phase,'step':step},'audit' if phase=='audit' else 'setup')
    def test_node_fixed_flags_closed_boolean_only(self):
        row={**child_result(),'stderrEmpty':False,'stderrExpectedMatch':False}
        for key in m.SEED_NODE_FLAGS:
            node=m.empty_node_diagnostic();node['flags'][key]=True
            self.validate(seed_failure(children=[{**row,'node':node}]))
            for value in (1,0,'true',None):
                node=m.empty_node_diagnostic();node['flags'][key]=value
                with self.assertRaises(m.Refusal):self.validate(seed_failure(children=[{**row,'node':node}]))
        for flags in (None,[],{},dict.fromkeys(m.SEED_NODE_FLAGS,False)|{'unknown':True}):
            node={**m.empty_node_diagnostic(),'flags':flags}
            with self.assertRaises(m.Refusal):self.validate(seed_failure(children=[{**row,'node':node}]))
    def test_private_cgroup_required_before_seed_and_no_resource_or_argv_change(self):
        d=m.descriptor('seed','setup',SCRATCH,PROJECT);name=PROJECT+'-seed';v=model(d,name)
        self.assertTrue(m.qualify_container(v,d,PROJECT,name,m.POLICY,'desktop-linux')['qualified'])
        for namespace in ('host','',None,True,0,[],{}):
            wrong=copy.deepcopy(v);wrong['host']['CgroupnsMode']=namespace
            with self.assertRaises(m.RuntimeQualifierRefusal) as error:m.qualify_container(wrong,d,PROJECT,name,m.POLICY,'desktop-linux')
            self.assertEqual(str(error.exception),'seed_cgroup_namespace');self.assertEqual(error.exception.diagnostics['failed'],['cgroup_namespace'])
        wrong=copy.deepcopy(v);wrong['host'].pop('CgroupnsMode')
        with self.assertRaises(m.RuntimeQualifierRefusal):m.qualify_container(wrong,d,PROJECT,name,m.POLICY,'desktop-linux')
        argv=m.create_argv(d,name,PROJECT)
        self.assertNotIn('--cgroupns',argv);self.assertNotIn('--cap-add',argv)
        self.assertEqual(d['pids'],32);self.assertEqual(d['memory'],128*m.MIB);self.assertEqual(d['cpu'],500000000);self.assertEqual(d['network'],'none')
        source=m.public_read(m.SEED).decode();reader=source.split('function ownPidsSnapshot():',1)[1].split('export const accounts',1)[0]
        for forbidden in ('/proc/','/sys/fs/cgroup/pids/','readFileSync','readdirSync','process.env','.message','.stack'):
            self.assertNotIn(forbidden,reader)
        self.assertIn("root = '/sys/fs/cgroup'",reader);self.assertIn("'/pids.' + kind",reader)
        self.assertIn('Buffer.alloc(257)',reader);self.assertIn('constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK',reader)
        self.assertIn("if (process.platform !== 'linux') return result",reader)
    def test_typescript_extracted_pure_diagnostics_and_first_failure(self):
        # Execute only the marked dependency-free helpers, never seed imports or CLI.
        seed=m.public_read(m.SEED).decode()
        block=seed.split('// BEGIN PURE SEED DIAGNOSTICS',1)[1].split('\n',1)[1].split('// END PURE SEED DIAGNOSTICS',1)[0]
        enums={name:list(getattr(m,name)) for name in ('SEED_ENTRY_STEPS','SEED_COMMON_STEPS','SEED_SETUP_STEPS',
                                                     'SEED_AUDIT_STEPS','SEED_ERROR_CLASSES','SEED_ERROR_CODES',
                                                     'SEED_NODE_CLASSES','SEED_NODE_CODES','SEED_NODE_FLAGS','OWN_PIDS_FILES')}
        enums['SEED_NODE_FRAME_PATHS']=m.SEED_NODE_FRAME_PATHS
        own_reader='function ownPidsSnapshot():'+seed.split('function ownPidsSnapshot():',1)[1].split('export const accounts',1)[0]
        initialize='const initialize = (kind: InitializerKind) => {'+seed.split('const initialize = (kind: InitializerKind) => {',1)[1].split("\n  checkpoint('initialize_spawn')",1)[0]
        js=r'''
const ts=require('typescript'), vm=require('node:vm'), assert=require('node:assert/strict'), crypto=require('node:crypto');
let raw='';process.stdin.setEncoding('utf8');process.stdin.on('data',p=>{raw+=p;assert(Buffer.byteLength(raw)<=65536)});
process.stdin.on('end',()=>{try{
 const input=JSON.parse(raw), compiled=ts.transpileModule(input.block+'\n'+input.reader+'\n'+input.initialize,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS},reportDiagnostics:true});
 assert.equal((compiled.diagnostics||[]).length,0);
 const sandbox={exports:{},Buffer,Error,TypeError,RangeError,SyntaxError,TextDecoder,assert};vm.createContext(sandbox);vm.runInContext(compiled.outputText,sandbox,{timeout:1000});
 const e=sandbox.exports;const actual={};for(const k of Object.keys(input.enums)){actual[k]=Array.isArray(input.enums[k])?Array.from(e[k]):{...e[k]};assert.deepEqual(actual[k],input.enums[k])}
 vm.runInContext(`
 const canary='CANARY-private-credentials-cookie-body-path';
 for (const name of exports.SEED_ERROR_CLASSES.filter(n=>!['other_error','non_error'].includes(n))) {
   const C=class extends Error {};Object.defineProperty(C,'name',{value:name});
   for (const code of exports.SEED_ERROR_CODES) {
     const error=new C(canary);error.code=code;error.stack=canary;
     assert.equal(exports.seedError(error).errorClass,name);assert.equal(exports.seedError(error).errorCode,code);
   }
 }
 const error=new Error(canary);let getters=0;
 for(const k of ['message','stack','name','code'])Object.defineProperty(error,k,{get(){getters++;throw new Error(canary)}});
 assert.equal(exports.seedError(error).errorCode,'other');assert.equal(getters,0);
 assert.equal(exports.seedError({message:canary}).errorClass,'non_error');
 const Unknown=class extends Error {};assert.equal(exports.seedError(new Unknown(canary)).errorClass,'other_error');
 const unknown=new Error(canary);unknown.code=canary;assert.equal(exports.seedError(unknown).errorCode,'other');
 const okOut=Buffer.from('History operator action complete. No provider call or runtime activation performed.\\n');
 const refusalErr=Buffer.from('History operator action refused; no quota reset or automatic repair.\\n');
 const good=exports.initializerDiagnostic('initialize',{status:0,signal:null,stdout:okOut,stderr:Buffer.alloc(0)});
 assert.equal(good.exit,'zero');assert(good.stdoutExpectedMatch&&good.stderrExpectedMatch&&good.stderrEmpty&&good.stdoutBounded);
 const negative=exports.initializerDiagnostic('existing_refusal',{status:1,signal:null,stdout:Buffer.alloc(0),stderr:refusalErr});
 assert.equal(negative.exit,'one');assert(negative.stdoutExpectedMatch&&negative.stderrExpectedMatch&&negative.stdoutEmpty);
 for(const code of ['ETIMEDOUT','ENOBUFS','EPERM','EACCES','ENOENT','EAGAIN','ENOMEM',canary]){
   const error=new Error(canary);error.code=code;
   const result=exports.initializerDiagnostic('initialize',{status:null,signal:'SIGTERM',error,stdout:Buffer.from(canary),stderr:Buffer.alloc(32769,120)});
   assert.equal(result.error,code===canary?'other':code);assert.equal(result.signal,'sigterm');assert.equal(result.exit,'none');
   assert(!result.stdoutExpectedMatch&&!result.stderrExpectedMatch&&!result.stderrBounded);assert(!JSON.stringify(result).includes(canary));
 }
 for(const status of [true,'0',undefined,NaN,Infinity])assert.equal(exports.initializerDiagnostic('initialize',{status,signal:null,stdout:null,stderr:null}).exit,'invalid');
 for(const status of [-9,2])assert.equal(exports.initializerDiagnostic('initialize',{status,signal:'SIGKILL',stdout:null,stderr:null}).exit,'other');
 seedPhase='setup';checkpoint('initialize_status');initializerResults.push(good,negative);
 const primary=new Error(canary);primary.code='EPERM';rememberSeedFailure(primary);
 const before=JSON.stringify(firstSeedFailure);
 diagnosticCleanup('setup_close_history',()=>{});assert.equal(JSON.stringify(firstSeedFailure),before);
 try{diagnosticCleanup('setup_close_ledger',()=>{throw new TypeError(canary)})}catch{}
 rememberSeedFailure(new RangeError(canary));assert.equal(firstSeedFailure.step,'initialize_status');assert.equal(firstSeedFailure.errorCode,'EPERM');
 assert(firstSeedFailure.cleanupFailed);assert(!JSON.stringify(firstSeedFailure).includes(canary));assert(Buffer.byteLength(JSON.stringify(firstSeedFailure))<=2048);
 assert.equal(exports.INITIALIZER_CAPTURE_BYTES,32768);assert.equal(exports.SEED_DIAGNOSTIC_BYTES,2048);
 const signatures={loader:'Error [ERR_MODULE_NOT_FOUND]: '+canary,transform:'Error [TransformError]: '+canary,
   spawn_eagain:'Error: spawn '+canary+' EAGAIN',worker_init:'Error [ERR_WORKER_INIT_FAILED]: '+canary,
   uv_thread:'node[12]: pthread_create: Resource temporarily unavailable',go_thread:'fatal error: newosproc',
   esbuild_stopped:'Error: The service was stopped: '+canary,
   esbuild_binary:'You installed esbuild for another platform than the one you'+String.fromCharCode(39)+'re currently using.'};
 for(const [key,line] of Object.entries(signatures)){
   const classified=exports.initializerNodeDiagnostic(Buffer.from(line));assert(classified.flags[key]);
   for(const value of Object.values(classified.flags))assert.equal(typeof value,'boolean');assert(!JSON.stringify(classified).includes(canary));
 }
 assert(exports.initializerNodeDiagnostic(Buffer.from('node: Assertion (0)==(uv_thread_create(t)) failed')).flags.uv_thread);
 assert(exports.initializerNodeDiagnostic(Buffer.from('runtime: failed to create new OS thread (have 32 already; errno=11)')).flags.go_thread);
 assert(exports.initializerNodeDiagnostic(Buffer.from("Error: The package "+String.fromCharCode(34)+"@esbuild/linux-x64"+String.fromCharCode(34)+" could not be found, and is needed by esbuild.")).flags.esbuild_binary);
 for(const malformed of ['unknown '+signatures.spawn_eagain,'Error [CANARY-private]: text','code: '+canary]){
   const classified=exports.initializerNodeDiagnostic(Buffer.from(malformed));assert(Object.values(classified.flags).every(v=>v===false));
 }
 for(const kind of exports.OWN_PIDS_FILES){
   const valid=exports.pidsCounter(kind,Buffer.from(kind==='events'?'max 32\\n':'32\\n'),true);assert.equal(valid[2],32);assert(valid[0]&&valid[1]);
   for(const raw of [Buffer.from(canary),Buffer.alloc(257,120),Buffer.from([255]),Buffer.from('01\\n'),Buffer.from('-1\\n'),Buffer.from('1000001\\n'),Buffer.from('32\\n\\n'),null]){
     const invalid=exports.pidsCounter(kind,raw,true);assert(invalid[0]&&!invalid[1]&&invalid[2]===null);assert(!JSON.stringify(invalid).includes(canary));
   }
   assert.equal(exports.pidsCounter(kind,null,false)[0],false);
 }
 assert.equal(exports.pidsCounter('max',Buffer.from('max\\n'),true)[2],'max');
 assert.equal(exports.pidsCounter('current',Buffer.from('max\\n'),true)[2],null);
 assert.equal(exports.pidsCounter('events',Buffer.from('max 0\\nother 1\\n'),true)[2],null);
 // Runtime reader and actual initialize arrow execute only against inert fake IO.
 let io=[],childRan=false,childCalls=0,mode='failure';
 globalThis.process={platform:'linux',execPath:'/fixed/public/node'};
 globalThis.constants={O_RDONLY:0,O_NOFOLLOW:1,O_NONBLOCK:2};
 globalThis.lstatSync=path=>{io.push(['stat',path]);return {isDirectory:()=>path==='/sys/fs/cgroup',isSymbolicLink:()=>false,isFile:()=>path!=='/sys/fs/cgroup'}};
 globalThis.realpathSync=path=>path;
 const fds=new Map();let nextFd=1;
 globalThis.openSync=(path,flags)=>{assert.equal(flags,3);assert(exports.OWN_PIDS_FILES.some(k=>path==='/sys/fs/cgroup/pids.'+k));const fd=nextFd++;fds.set(fd,path);io.push(['open',path]);return fd};
 globalThis.fstatSync=()=>({isFile:()=>true});
 globalThis.readSync=(fd,buf)=>{assert.equal(buf.length,257);const path=fds.get(fd);const text=path.endsWith('.events')?'max '+(childRan?'1':'0')+'\\n':path.endsWith('.peak')?(childRan?'32\\n':'24\\n'):path.endsWith('.max')?'32\\n':'16\\n';const raw=Buffer.from(text);raw.copy(buf);return raw.length};
 globalThis.closeSync=fd=>{assert(fds.has(fd));fds.delete(fd);io.push(['closed'])};
 globalThis.spawnSync=(bin,args,opts)=>{
   childCalls++;assert.equal(bin,'/fixed/public/node');assert.equal(args.join('|'),'--import|tsx|src/llm/history-init.ts|--initialize');
   assert.equal(opts.timeout,10000);assert.equal(opts.maxBuffer,32768);childRan=true;
   if(mode==='throw'){const error=new Error(canary);error.code='EAGAIN';throw error}
   return mode==='success'?{status:0,signal:null,stdout:okOut,stderr:Buffer.alloc(0)}:
     mode==='negative'?{status:1,signal:null,stdout:Buffer.alloc(0),stderr:refusalErr}:
     {status:1,signal:null,stdout:Buffer.alloc(0),stderr:Buffer.from(signatures.spawn_eagain)};
 };
 initializerResults.length=0;initializerPids=null;firstSeedFailure=undefined;seedPhase='setup';checkpoint('initialize_spawn');
 initialize('initialize');assert.equal(childCalls,1);assert.equal(fds.size,0);
 assert.equal(initializerPids.before.events[2],0);assert.equal(initializerPids.after.events[2],1);assert.equal(initializerPids.after.peak[2],32);
 assert.equal(io.filter(x=>x[0]==='open').length,8);assert(initializerResults[0].node.flags.spawn_eagain);
 const observed=exports.seedDiagnostic(new Error(canary));assert.equal(observed.initializerPids.kind,'initialize');assert(Buffer.byteLength(JSON.stringify(observed))<=2048);
 for(const testMode of ['success','negative']){
   mode=testMode;io=[];childRan=false;initializerResults.length=0;initializerPids=null;
   initialize(testMode==='success'?'initialize':'existing_refusal');assert.equal(initializerPids,null);assert.equal(io.filter(x=>x[0]==='open').length,4);
 }
 mode='throw';io=[];childRan=false;initializerResults.length=0;initializerPids=null;
 try{initialize('initialize')}catch(error){assert.equal(error.code,'EAGAIN');rememberSeedFailure(error)}
 assert.equal(initializerPids.after.events[2],1);assert.equal(firstSeedFailure.errorCode,'EAGAIN');assert(!JSON.stringify(firstSeedFailure).includes(canary));
 const normalLstat=lstatSync;globalThis.lstatSync=()=>{throw new Error(canary)};io=[];
 assert(Object.values(ownPidsSnapshot()).every(v=>!v[0]&&!v[1]&&v[2]===null));assert.equal(io.length,0);globalThis.lstatSync=normalLstat;
 globalThis.process.platform='darwin';io=[];assert(Object.values(ownPidsSnapshot()).every(v=>!v[0]));assert.equal(io.length,0);globalThis.process.platform='linux';
 globalThis.closeSync=()=>{throw new Error(canary)};const closedBad=ownPidsSnapshot();assert(Object.values(closedBad).every(v=>v[0]&&!v[1]&&v[2]===null));
 const unchanged=exports.initializerNodeDiagnostic(Buffer.from(refusalErr));
 assert.equal(unchanged.class,'none');assert.equal(unchanged.code,'none');assert.equal(unchanged.frame,null);
 for(const name of exports.SEED_NODE_CLASSES)for(const code of exports.SEED_NODE_CODES){
   const packet=exports.initializerNodeDiagnostic(Buffer.from(name+' ['+code+']: '+canary));
   assert.equal(packet.class,name);assert.equal(packet.code,code);assert(!JSON.stringify(packet).includes(canary));
 }
 for(const [id,path] of Object.entries(exports.SEED_NODE_FRAME_PATHS)){
   for(const prefix of ['/app/','file:///app/'])for(const form of [prefix+path+':8:9','    at '+prefix+path+':8:9','    at fixed ('+prefix+path+':8:9)']){
     const packet=exports.initializerNodeDiagnostic(Buffer.from('TypeError: '+canary+'\\n'+form+"\\n  code: 'ERR_MODULE_NOT_FOUND',"));
     assert.equal(packet.class,'TypeError');assert.equal(packet.code,'ERR_MODULE_NOT_FOUND');
     assert.equal(packet.frame[0],id);assert.equal(packet.frame[1],8);assert(!JSON.stringify(packet).includes(canary));assert(!JSON.stringify(packet).includes(path));
   }
 }
 const init='/app/server/api/src/llm/history-init.ts';
 for(const line of ['    at /evil'+init+':8:9','    at '+init+'/suffix:8:9','    at '+init+':0:9',
   '    at '+init+':08:9','    at '+init+':4097:9','    at '+init+':8:0','    at '+init+':8:9)',
   '    at fixed ('+init+':8:9','    at /app/server/api/src/llm/unknown.ts:8:9','    at file://unknown'+init+':8:9']){
   assert.equal(exports.initializerNodeDiagnostic(Buffer.from(line)).frame,null);
 }
 for(const raw of [Buffer.alloc(32769,120),Buffer.from([255]),null]){
   const packet=exports.initializerNodeDiagnostic(raw);assert.equal(packet.class,'none');assert.equal(packet.code,'none');assert.equal(packet.frame,null);
 }
 const ambiguous=exports.initializerNodeDiagnostic(Buffer.from('TypeError: '+canary+'\\nSyntaxError: '+canary+"\\n  code: 'ERR_ASSERTION',\\n  code: 'ENOENT',"));
 assert.equal(ambiguous.class,'ambiguous');assert.equal(ambiguous.code,'ambiguous');
 assert.equal(exports.initializerNodeDiagnostic(Buffer.from('Error [TransformError]: '+canary)).class,'TransformError');
 assert.equal(exports.initializerNodeDiagnostic(Buffer.from(canary+' TypeError: arbitrary')).class,'none');
 assert.equal(exports.initializerNodeDiagnostic(Buffer.from('\\n'.repeat(256)+'TypeError: '+canary)).class,'none');
 assert.equal(exports.initializerNodeDiagnostic(Buffer.from('TypeError: '+'x'.repeat(2049))).class,'none');
 const within=exports.initializerDiagnostic('initialize',{status:1,signal:null,stdout:Buffer.alloc(0),stderr:Buffer.alloc(32768,120)});
 assert(within.stderrBounded);assert(!within.stderrExpectedMatch);assert(within.stdoutEmpty);assert(!within.stdoutExpectedMatch);
 firstSeedFailure=undefined;initializerResults.length=0;initializerPids=null;checkpoint('audit_head');seedPhase='audit';
 try{diagnosticCleanup('audit_close_history',()=>{throw new TypeError(canary)})}catch{}
 assert.equal(firstSeedFailure.step,'audit_close_history');assert.equal(firstSeedFailure.errorClass,'TypeError');assert(firstSeedFailure.cleanupFailed);
 `,sandbox,{timeout:1000});
 console.log(JSON.stringify({passed:true,enumSha256:crypto.createHash('sha256').update(JSON.stringify(input.enums)).digest('hex'),rawValuesIncluded:false}));
 }catch{console.log('{"passed":false,"rawValuesIncluded":false}');process.exitCode=1;}});
'''
        node='/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node'
        result=subprocess.run([node,'-e',js],input=m.canonical({'block':block,'enums':enums,'reader':own_reader,'initialize':initialize}),stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,timeout=10,cwd=m.ROOT/'server/api',
                              env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
        self.assertEqual(result.returncode,0,'extracted pure helper assertion failed; raw child output withheld')
        self.assertEqual(result.stderr,b'','pure helper stderr must be empty')
        self.assertLessEqual(len(result.stdout),256)
        self.assertEqual(json.loads(result.stdout),{'passed':True,'enumSha256':m.sha(m.canonical(enums)), 'rawValuesIncluded':False})


if __name__=='__main__':
    unittest.main()
