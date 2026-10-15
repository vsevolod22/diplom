"""Disposable fixtures and a fake Docker daemon ONLY; never execute activation CLI."""
import ast
import copy
from dataclasses import replace
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('key_recreation_candidate', HERE / 'recreate_openrouter_key.py')
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)

SYNTHETIC_KEY = 'SYNTHETIC_ONLY_${NOT_AN_ENV_READ}_$literal'


def unescape(value):
    if type(value) is str:
        return value.replace('$$', '$')
    if type(value) is list:
        return [unescape(x) for x in value]
    if type(value) is dict:
        return {k: unescape(v) for k, v in value.items()}
    return value


def compose_json(raw):
    """Inert normalized output oracle: false bind flag omits, bind object stays."""
    normalized = copy.deepcopy(raw)
    for service in normalized.get('services', {}).values():
        for mount in service.get('volumes', []):
            bind = mount.get('bind')
            if type(bind) is dict and bind.get('create_host_path') is False:
                bind.pop('create_host_path')
    return m.encoded(normalized).replace(b'$', b'$$')


def good_receipt(operation):
    # Real SQL CLI protocol: no fabricated preservation/startup flags.
    return m.encoded({'code': {'capture': 'CAPTURED', 'compare': 'MATCH', 'compatibility': 'COMPATIBLE'}[operation],
                      'ok': True})


def synthetic_snapshot(versions, *, migration=False):
    """Only inert bytes and an R2-shaped manifest; never create/open a database."""
    files, entries, stores = {}, [], []
    for label in ('auth', 'data'):
        entries.append({'path': label, 'kind': 'directory', 'mode': 0o700,
                        'uid': 65532, 'gid': 65532, 'sourceIdentity': [1, 2]})
    for index, relative in enumerate(sorted(m.REQUIRED_STORES)):
        data = b'SYNTHETIC_NOT_A_DATABASE_' + relative.encode()
        if migration:
            # Header-shaped inert bytes only; no valid SQLite/native invocation.
            header = bytearray(4096)
            header[:16], header[16:18], header[18:20] = b'SQLite format 3\0', b'\x10\x00', b'\x01\x01'
            marker = b'SYNTHETIC_NOT_A_DATABASE_'
            header[100:100 + len(marker)] = marker
            data = bytes(header)
        sha = hashlib.sha256(data).hexdigest()
        entries.append({'path': relative, 'kind': 'file', 'mode': 0o600, 'uid': 65532,
                        'gid': 65532, 'sourceIdentity': [1, index + 3], 'bytes': len(data),
                        'sha256': sha, 'sqlite': True})
        files['raw/' + relative] = files['working/' + relative] = data
        files['sealed/' + str(index) + '.sqlite'] = data
        stores.append({'path': relative, 'sealed': str(index) + '.sqlite', 'bytes': len(data),
                       'sha256': sha, 'sqlite': True, 'recovery': {'format': 'SYNTHETIC'},
                       'logical': {'format': 'sqlite-all-state-v1', 'tables': [],
                                   'schema': dict(zip(('applicationId', 'userVersion'),
                                                      map(str, versions[relative])))}})
    if migration:
        for store in stores:
            store['recovery'] = {'format': 'checked-recovery-v1', 'kind': 'main', 'pageSize': 4096, 'pages': 1}
            store['logical']['schema'].update(encoding='UTF-8', objects=[], objectBytes=[])
            store['logical']['tables'] = [{'name': 'synthetic_inert_table', 'columns': [{'hidden': '0'}],
                                          'rows': 1, 'rowHashes': ['1' * 64]}]
    files['manifest.json'] = m.encoded({'format': 'stand-state-snapshot-v2', 'limits': m.SNAPSHOT_LIMITS,
                                     'entries': sorted(entries, key=lambda e: e['path']), 'stores': stores,
                                     **({'profile': 'preservation-migration-v1'} if migration else {})})
    return files


def synthetic_inventory(files):
    directories = {''}
    for relative in files:
        parts = relative.split('/')
        directories.update('/'.join(parts[:i]) for i in range(1, len(parts)))
    result = [{'path': p, 'kind': 'directory'} for p in directories]
    result.extend({'path': p, 'kind': 'file', 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                  for p, data in files.items())
    return sorted(result, key=lambda e: e['path'])


class FakeDocker:
    def __init__(self, repo, plan):
        self.repo, self.plan = repo, plan
        self.calls = []
        self.fail_on = None
        self.failure = RuntimeError('SYNTHETIC_PRIVATE_DIAGNOSTIC_' + SYNTHETIC_KEY)
        self.receipt_override = {}
        self.new_mutation = None
        self.roundtrip_mutation = None
        self.daemon = 'SYNTHETIC_DAEMON'
        self.memory_total = 4 * m.GIB
        self.snapshot_files = {stage: synthetic_snapshot(plan.expected_versions) for stage in ('pre', 'post')}
        self.private_inputs = []  # Synthetic test bytes only; never part of command/evidence output.
        self.compatibility_after = None
        self.captured = set()
        self.copy_mutation = None
        self.helper_mutation = None
        self.records, self.images = {}, {}
        self.networks = {
            '1' * 64: {'Id': '1' * 64, 'Name': m.PROJECT + '_internal', 'Internal': True, 'Containers': {}},
            '2' * 64: {'Id': '2' * 64, 'Name': m.PROJECT + '_uplink', 'Internal': False, 'Containers': {}},
        }
        self.volumes = {name: {'Name': name, 'Driver': 'local', 'Scope': 'local', 'Options': None,
                              'Labels': {'com.docker.compose.project': m.PROJECT},
                              'Mountpoint': '/synthetic/volumes/' + name, 'CreatedAt': 'SYNTHETIC'}
                        for name in m.VOLUMES.values()}
        self.model = {'name': m.PROJECT, 'services': {},
                      'volumes': {k: {'name': name} for k, name in
                                  zip(('auth_accounts', 'scan_ledger'), m.VOLUMES.values())},
                      'networks': {'internal': {'name': m.PROJECT + '_internal', 'internal': True},
                                   'uplink': {'name': m.PROJECT + '_uplink'}}}
        for role, binding in plan.bindings.items():
            image_config = {'Env': ['PATH=/synthetic/bin'], 'User': '65532:65532',
                            'WorkingDir': '/app/server/api', 'Cmd': ['synthetic-default'], 'Entrypoint': None,
                            'OnBuild': None}
            self.images[binding.image] = {'Id': binding.image, 'Architecture': 'arm64', 'Os': 'linux',
                                         'Config': image_config}
            environment = dict(m.FREE, SCAN_JWT_SECRET='SYNTHETIC_' + 'j' * 40,
                               AUTH_ORIGIN='http://127.0.0.1:8080', LLM_HISTORY_ENABLED='false',
                               OPENROUTER_API_KEY=SYNTHETIC_KEY) if role == 'api' else {}
            command = ['node', '--import', 'tsx', 'src/oci/nginx-local.main.ts'] if role == 'api' else ['synthetic-' + role]
            mounts = []
            service_volumes = []
            if role in ('api', 'worker'):
                pairs = [('scan_ledger', m.VOLUMES['data'], '/data')]
                if role == 'api':
                    pairs.append(('auth_accounts', m.VOLUMES['auth'], '/auth'))
                for logical, name, target in pairs:
                    service_volumes.append({'type': 'volume', 'source': logical, 'target': target})
                    mounts.append({'Type': 'volume', 'Name': name, 'Source': self.volumes[name]['Mountpoint'],
                                   'Destination': target, 'RW': True, 'Propagation': ''})
                service_volumes.append({'type': 'bind', 'source': '/synthetic/release', 'target': '/opt/release',
                                        'read_only': True, 'bind': {'create_host_path': False}})
                mounts.append({'Type': 'bind', 'Source': '/synthetic/release', 'Destination': '/opt/release',
                               'RW': False, 'Propagation': ''})
            selected_networks = {'internal': {}}
            if role in ('egress', 'llm-egress'):
                selected_networks['uplink'] = {}
            service = {'build': {'context': str(repo), 'dockerfile': 'SYNTHETIC_ONLY'}, 'environment': environment,
                       'command': command, 'user': '65532:65532', 'read_only': True,
                       'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
                       'mem_limit': '256m', 'cpus': 1, 'pids_limit': 128,
                       'volumes': service_volumes, 'networks': selected_networks}
            if role == 'web':
                service['ports'] = [{'host_ip': '127.0.0.1', 'published': '8080', 'target': 8080,
                                     'protocol': 'tcp', 'mode': 'ingress'}]
            self.model['services'][role] = service
            runtime_env = dict({'PATH': '/synthetic/bin'}, **environment)
            if role == 'api':
                runtime_env[m.KEY] = 'SYNTHETIC_OLD_KEY'
            config = {'Image': m.PROJECT + '-' + role + ':latest',
                      'Env': [k + '=' + v for k, v in runtime_env.items()],
                      'Hostname': binding.container[:12], 'User': '65532:65532',
                      'WorkingDir': '/app/server/api', 'Cmd': command, 'Entrypoint': None, 'Volumes': None,
                      'Labels': {'com.docker.compose.project': m.PROJECT, 'com.docker.compose.service': role,
                                 'com.docker.compose.config-hash': 'SYNTHETIC_OLD',
                                 'com.docker.compose.project.config_files': 'SYNTHETIC_OLD_FILES',
                                 'com.docker.compose.project.working_dir': str(repo)}}
            host = {'ReadonlyRootfs': True, 'CapDrop': ['ALL'], 'CapAdd': None,
                    'SecurityOpt': ['no-new-privileges:true'], 'Privileged': False,
                    'Memory': 256 * m.MIB, 'MemorySwap': 512 * m.MIB,
                    'NanoCpus': 1_000_000_000, 'PidsLimit': 128, 'RestartPolicy': {'Name': 'no'},
                    'PortBindings': {'8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '8080'}]} if role == 'web' else None}
            self.records[binding.container] = {'Id': binding.container, 'Image': binding.image,
                'Name': '/' + m.PROJECT + '-' + role + '-1', 'Config': config, 'HostConfig': host,
                'Mounts': mounts, 'Path': 'node', 'Args': command[1:],
                'State': {'Running': True, 'Paused': False, 'Restarting': False, 'ExitCode': 0, 'OOMKilled': False,
                          'Health': {'Status': 'healthy'}},
                'NetworkSettings': {'Networks': {self.model['networks'][n]['name']:
                    {'NetworkID': next(i for i, v in self.networks.items() if v['Name'] == self.model['networks'][n]['name'])}
                    for n in selected_networks}}}
        self.model['services']['auth-volume-init'] = {'image': 'SYNTHETIC_INIT_NEVER_RUN'}
        self.model['services']['scan-volume-init'] = {'image': 'SYNTHETIC_INIT_NEVER_RUN'}

    def __call__(self, args, **kwargs):
        args = tuple(args)
        self.calls.append(args)
        if self.fail_on and self.fail_on(args):
            raise self.failure
        if args[:3] == ('docker', 'compose', 'version'):
            return b'2.34.0\n'
        if args[:3] == ('docker', 'image', 'inspect'):
            return m.encoded([copy.deepcopy(self.images[args[-1]])])
        if args[:3] == ('docker', 'volume', 'inspect'):
            return m.encoded([copy.deepcopy(self.volumes[i]) for i in args[3:]])
        if args[:3] == ('docker', 'network', 'inspect'):
            return m.encoded([copy.deepcopy(self.networks[i]) for i in args[3:]])
        if args[:2] == ('docker', 'info'):
            return m.encoded(self.memory_total if args[-1] == '{{json .MemTotal}}' else self.daemon)
        if args[:2] == ('docker', 'ps'):
            if any(a.startswith('name=^/') for a in args):
                name = next(a[6:-1] for a in args if a.startswith('name=^/'))
                ids = [r['Id'] for r in self.records.values() if r['Name'] == name]
            elif any('label=dip.key-preservation=' in a for a in args):
                marker = next(a.split('=', 2)[2] for a in args if a.startswith('label=dip.key-preservation='))
                ids = [r['Id'] for r in self.records.values() if r['Config']['Labels'].get('dip.key-preservation') == marker]
            elif '--filter' in args:
                ids = [r['Id'] for r in self.records.values() if r['Config']['Labels'].get('com.docker.compose.service') == 'api']
            else:
                ids = list(self.records)
            return ('\n'.join(ids) + '\n').encode()
        if args[:2] == ('docker', 'inspect'):
            ids = args[6:] if '--format' in args else args[4:]
            if '--format' in args:
                return b''.join(m.encoded({'id': i, 'running': self.records[i]['State']['Running'],
                                          'mounts': self.records[i]['Mounts']}) for i in ids)
            return m.encoded([copy.deepcopy(self.records[i]) for i in ids])
        if args[:2] == ('docker', 'stop'):
            self.records[args[-1]]['State']['Running'] = False
            return (args[-1] + '\n').encode()
        if args[:2] == ('docker', 'create'):
            identity = ('c' if 'c' * 64 not in self.records else 'd') * 64
            mounts = []
            for i, item in enumerate(args):
                if item == '--mount':
                    fields = dict(pair.split('=', 1) for pair in args[i + 1].split(',') if '=' in pair)
                    source = fields['source']
                    mounts.append({'Type': fields['type'], 'Source': self.volumes[source]['Mountpoint'] if fields['type'] == 'volume' else source,
                                   'Destination': fields['target'], 'RW': 'readonly' not in args[i + 1].split(','),
                                   **({'Name': source} if fields['type'] == 'volume' else {})})
            name = args[args.index('--name') + 1]
            label = args[args.index('--label') + 1].split('=', 1)
            old_image = self.plan.bindings['api'].image
            self.records[identity] = {'Id': identity, 'Image': old_image, 'Name': '/' + name,
                'Config': {'Image': old_image, 'Env': self.images[old_image]['Config']['Env'],
                           'User': args[args.index('--user') + 1], 'Labels': {label[0]: label[1]},
                           'WorkingDir': '/app/server/api', 'Entrypoint': ['node'], 'Cmd': ['-e', m.HOLDER_CODE],
                           'Healthcheck': {'Test': ['NONE']}, 'StopTimeout': 5, 'Volumes': None},
                'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'CapDrop': ['ALL'], 'CapAdd': None,
                               'Privileged': False, 'SecurityOpt': ['no-new-privileges:true'],
                               'Memory': m.memory(args[args.index('--memory') + 1]),
                               'MemorySwap': m.memory(args[args.index('--memory-swap') + 1]),
                               'CgroupnsMode': args[args.index('--cgroupns') + 1] if '--cgroupns' in args else '',
                               'NanoCpus': 1_000_000_000, 'PidsLimit': 64,
                               'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
                               'Tmpfs': dict(args[i + 1].split(':', 1) for i, v in enumerate(args) if v == '--tmpfs')},
                'Mounts': mounts, 'Path': 'node', 'Args': ['-e', m.HOLDER_CODE],
                'NetworkSettings': {'Networks': {'none': {'NetworkID': '9' * 64}}},
                'State': {'Running': False, 'Paused': False, 'ExitCode': 0, 'OOMKilled': False}}
            if self.helper_mutation:
                self.helper_mutation(self.records[identity])
            return (identity + '\n').encode()

        if args[:2] == ('docker', 'start'):
            self.records[args[-1]]['State']['Running'] = True
            return (args[-1] + '\n').encode()
        if args[:2] == ('docker', 'exec'):
            if args[2] == '-i':
                assert args[4:] == ('node', m.SCRIPT_TARGET, 'compatibility', '/backup/pre')
                assert self.captured == {'pre'}
                holder = self.records[args[3]]
                assert holder['State']['Running'] and not holder['State']['Paused']
                m.authority_input(kwargs['input_data'])
                self.private_inputs.append(kwargs['input_data'])
                if self.compatibility_after:
                    self.compatibility_after()
                return self.receipt_override.get('compatibility', good_receipt('compatibility'))
            if args[4] == m.SCRIPT_TARGET:
                identity, operation = args[2], args[5]
                assert self.records[identity]['State']['Running'] and not self.records[identity]['State']['Paused']
                assert args[6] == '/backup/pre'
                if operation == 'compare':
                    assert self.captured == {'pre'} and args[7] == '/backup/post'
                self.captured.add('pre' if operation == 'capture' else 'post')
                return self.receipt_override.get(operation, good_receipt(operation))
            if m.INVENTORY_CODE in args:
                stage = args[-1].split('/')[-1]
                assert stage in self.captured
                return m.encoded(synthetic_inventory(self.snapshot_files[stage]))
            return m.encoded({'ok': True})
        if args[:2] == ('docker', 'cp'):
            identity, source = args[2].split(':', 1)
            stage = source.split('/')[2]
            assert self.records[identity]['State']['Running'] and not self.records[identity]['State']['Paused']
            assert stage in self.captured and source == '/backup/' + stage + '/.'
            destination = Path(args[3])
            assert destination.is_dir() and not list(destination.iterdir())
            for record in synthetic_inventory(self.snapshot_files[stage]):
                path = destination / record['path']
                if record['kind'] == 'directory':
                    if record['path']:
                        path.mkdir(mode=0o700)
                else:
                    fd = os.open(path, os.O_WRONLY | os.O_EXCL | os.O_CREAT, 0o600)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(self.snapshot_files[stage][record['path']])
            if self.copy_mutation:
                self.copy_mutation(destination)
            return b''
        if args[:2] == ('docker', 'pause'):
            self.records[args[2]]['State']['Paused'] = True
            return b''
        if args[:2] == ('docker', 'rm'):
            assert args[2] == '--force'
            self.records.pop(args[3])
            return b''
        if args[:2] == ('docker', 'compose'):
            if 'config' in args:
                if '--quiet' in args:
                    return b''
                if args.count('-f') == 4:
                    # config.go escapes raw JSON dollars, including command/Env values.
                    return compose_json(self.model)
                candidate = unescape(json.loads(Path(args[args.index('-f') + 1]).read_text()))
                if self.roundtrip_mutation:
                    self.roundtrip_mutation(candidate)
                return compose_json(candidate)
            if 'up' in args:
                old = self.records.pop(self.plan.bindings['api'].container)
                candidate = unescape(json.loads(Path(args[args.index('-f') + 1]).read_text()))
                identity = 'b' * 64
                old['Id'] = identity
                old['Config']['Hostname'] = identity[:12]
                old['Image'] = candidate['services']['api']['image']
                old['Config']['Image'] = candidate['services']['api']['image']
                if 'com.docker.compose.image' in old['Config']['Labels']:
                    old['Config']['Labels']['com.docker.compose.image'] = old['Image']
                env = dict({'PATH': '/synthetic/bin'}, **candidate['services']['api']['environment'])
                old['Config']['Env'] = [k + '=' + v for k, v in env.items()]
                old['Config']['Labels']['com.docker.compose.config-hash'] = 'SYNTHETIC_NEW'
                old['Config']['Labels']['com.docker.compose.project.config_files'] = args[args.index('-f') + 1]
                old['Config']['Labels']['com.docker.compose.project.working_dir'] = str(self.repo / 'server/deploy')
                old['State']['Running'] = True
                if self.new_mutation:
                    self.new_mutation(old)
                self.records[identity] = old
                return b''
        raise AssertionError('Unexpected mocked command category; no command/secret echo')


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='key-controller-synthetic-')
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.repo.chmod(0o755)  # OWN synthetic public fixture, never existing stand root.
        root = self.repo / '.local-auth'
        root.mkdir(mode=0o755)
        helper = m.HELPER_PATH
        sources = {}
        for relative in (*m.PUBLIC, helper, m.HELPER_TEST):
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('SYNTHETIC_PUBLIC_NOT_EXECUTABLE\n')
            path.chmod(0o644 if relative == helper else 0o600)
            sources[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        for relative in ('server/.env.local', 'server/.env.openrouter.local', '.local-auth/stand.env'):
            path = self.repo / relative
            path.write_text('SYNTHETIC_ONLY=not_loaded_by_controller\n')
            path.chmod(0o600)
        (root / 'stand-composition.json').write_text(json.dumps({'profile': 'nginx-local', 'llm': 'openrouter-free'}))
        (root / 'stand-composition.json').chmod(0o600)
        bindings = {role: m.Binding(format(i + 3, 'x') * 64, 'sha256:' + format(i + 3, 'x') * 64)
                    for i, role in enumerate(m.ROLES)}
        versions = {'auth/auth.sqlite': (0, 0), 'data/ledger.sqlite': (0, 12),
                    'auth/llm-usage.sqlite': (1145655601, 1)}  # SYNTHETIC reviewed versions, NOT stand facts
        self.plan = m.Plan(bindings, sources, helper, startup_evidence='DIP-ARTF-999999',
                           store_versions=versions, backup_sandbox_reviewed=True, old_db_reads_reviewed=True)
        self.fake = FakeDocker(self.repo, self.plan)
        self.sleeps = []
        # Only synthetic /tmp ancestry is mocked. Real fixture file modes/link counts
        # and the actual existing selector/lock are exercised, with no private env read.
        original_lstat = Path.lstat
        def synthetic_ancestors(path, *a, **kw):
            value = original_lstat(path, *a, **kw)
            if path in self.repo.parents:
                fields = list(value)
                fields[0] = stat.S_IFDIR | 0o755
                return os.stat_result(fields)
            return value
        self.addCleanup(patch.stopall)
        patch.object(Path, 'lstat', synthetic_ancestors).start()
        patch.object(m.shutil, 'disk_usage', return_value=type('SyntheticSpace', (), {'free': 8 * m.GIB})()).start()
        self.controller = m.Controller(self.repo, self.plan, self.fake, sleeper=self.sleeps.append,
                                       env={'SYNTHETIC_AMBIENT': 'kept'})

    def result(self):
        return self.controller.activate()

    def assert_no_daemon_write(self):
        self.assertFalse(any(c[:2] in (('docker', 'stop'), ('docker', 'start'), ('docker', 'create')) or 'up' in c
                             for c in self.fake.calls))

    def test_complete_mocked_sequence_key_only_and_no_initializer_build_pull_retag(self):
        result = self.result()
        self.assertTrue(result['ok'])
        self.assertFalse(result['providerOperabilityProven'])
        self.assertFalse(result['postResumeStateCompared'])
        self.assertEqual(self.sleeps[0], 35)
        ups = [c for c in self.fake.calls if 'up' in c]
        self.assertEqual(len(ups), 1)
        self.assertEqual(ups[0][-11:], ('up', '-d', '--no-build', '--pull', 'never', '--no-deps',
                                      '--force-recreate', '--wait', '--wait-timeout', '45', 'api'))
        self.assertEqual(ups[0].count('-f'), 1)
        selected = [c for c in self.fake.calls if c.count('-f') == 4]
        self.assertEqual(len(selected), 1)
        self.assertEqual([selected[0][i + 1] for i, v in enumerate(selected[0]) if v == '-f'],
                         [str(self.repo / relative) for relative in m.FILES])
        for c in self.fake.calls:
            self.assertFalse(any(v in c for v in ('build', 'pull', 'tag', 'down', 'prune', '--volumes', 'initialize')))
            self.assertNotIn(SYNTHETIC_KEY, ' '.join(c))
            if c[:2] == ('docker', 'start') and '--attach' not in c:
                self.assertIn(c[-1], ('c' * 64, 'b' * 64, self.plan.bindings['worker'].container, self.plan.bindings['web'].container))
        self.assertFalse((self.repo / '.local-auth/.trivy-refresh.lock').exists())
        self.assertEqual((self.repo / '.local-auth').stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.controller.backup.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.controller.compiled.stat().st_mode & 0o777, 0o600)
        self.assertIn('$$', self.controller.compiled.read_text())
        self.assertNotIn(SYNTHETIC_KEY, json.dumps(result))
        self.assertEqual(len(self.controller.helper_ids), 1)
        self.assertTrue(self.controller.helper_removed)
        self.assertEqual(self.controller.exports, {'pre', 'post'})
        self.assertTrue(all(i not in self.fake.records for i in self.controller.helper_ids))
        self.assertEqual([self.fake.records[self.plan.bindings[r].container]['Image'] for r in m.ROLES if r != 'api'],
                         [self.plan.bindings[r].image for r in m.ROLES if r != 'api'])

    def test_foreign_lock_never_removed_or_reused(self):
        lock = self.repo / '.local-auth/.trivy-refresh.lock'
        lock.mkdir(mode=0o700)
        before = lock.stat().st_ino
        self.assertFalse(self.result()['ok'])
        self.assertEqual(lock.stat().st_ino, before)
        self.assertEqual(self.fake.calls, [])

    def test_source_drift_refuses_before_engine_or_daemon_write(self):
        (self.repo / m.FILES[0]).write_text('SYNTHETIC_DRIFT')
        self.assertFalse(self.result()['ok'])
        self.assertEqual(self.fake.calls, [])

    def test_required_new_key_metadata_no_contents_no_repair(self):
        for mode in (0o644, 0o640):
            path = self.repo / 'server/.env.openrouter.local'
            path.chmod(mode)
            self.assertFalse(self.result()['ok'])
            self.assertEqual(path.stat().st_mode & 0o777, mode)
            self.assert_no_daemon_write()

    def test_secret_hardlink_symlink_and_missing_refused(self):
        path = self.repo / 'server/.env.openrouter.local'
        alias = self.repo / 'synthetic-alias'
        os.link(path, alias)
        self.assertFalse(self.result()['ok'])
        alias.unlink()
        path.unlink()
        path.symlink_to(self.repo / 'server/.env.local')
        self.assertFalse(self.result()['ok'])
        path.unlink()
        self.assertFalse(self.result()['ok'])
        self.assert_no_daemon_write()

    def test_secret_contents_are_not_read_by_python_preflight(self):
        original_open = os.open
        def guarded(path, flags, *args, **kw):
            self.assertFalse(str(path).endswith(('.env.local', '.env.openrouter.local', 'stand.env')))
            return original_open(path, flags, *args, **kw)
        with patch.object(m.os, 'open', side_effect=guarded):
            self.assertTrue(self.result()['ok'])

    def test_lost_flags_and_nonkey_env_change_refuse_before_stopping_web(self):
        for key, value in (('LLM_ENABLED', 'false'), ('LLM_QUOTA_USER_INPUT', '1'), ('SCAN_JWT_SECRET', 'different' * 8)):
            original = self.fake.model['services']['api']['environment'][key]
            self.fake.model['services']['api']['environment'][key] = value
            self.assertFalse(self.result()['ok'])
            self.assert_no_daemon_write()
            self.fake.model['services']['api']['environment'][key] = original

    def test_history_enabled_refused_no_history_execution(self):
        self.fake.model['services']['api']['environment']['LLM_HISTORY_ENABLED'] = 'true'
        self.assertFalse(self.result()['ok'])
        self.assert_no_daemon_write()

    def test_runtime_image_or_id_drift_stops_before_writes(self):
        self.fake.records[self.plan.bindings['api'].container]['Image'] = 'sha256:' + 'f' * 64
        self.assertFalse(self.result()['ok'])
        self.assert_no_daemon_write()

    def test_roundtrip_semantic_drift_refuses_without_daemon_write(self):
        self.fake.roundtrip_mutation = lambda model: model['services']['api']['environment'].update(LLM_ENABLED='false')
        self.assertFalse(self.result()['ok'])
        self.assert_no_daemon_write()

    def test_foreign_volume_writer_and_bind_alias_refused(self):
        foreign = copy.deepcopy(self.fake.records[self.plan.bindings['worker'].container])
        foreign['Id'] = 'f' * 64
        foreign['Mounts'] = [{'Type': 'bind', 'Source': self.fake.volumes[m.VOLUMES['auth']]['Mountpoint'] + '/child',
                              'Destination': '/foreign', 'RW': True}]
        self.fake.records[foreign['Id']] = foreign
        self.assertFalse(self.result()['ok'])
        self.assert_no_daemon_write()
        foreign_reads = [c for c in self.fake.calls if foreign['Id'] in c]
        self.assertTrue(foreign_reads)
        self.assertTrue(all('--format' in c for c in foreign_reads))

    def test_pending_receipt_failstop_no_resume_no_restore_and_hold_lock(self):
        self.fake.receipt_override['capture'] = m.encoded({'code': 'INFLIGHT', 'ok': False})
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertTrue(result['manualReconciliationRequired'])
        lock = self.repo / '.local-auth/.trivy-refresh.lock'
        self.assertTrue(lock.is_dir())
        marker = lock / 'KEY_ACTIVATION_HOLD.json'
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(SYNTHETIC_KEY, json.dumps(result))
        self.assertTrue(all(not r['State']['Running'] for r in self.fake.records.values()
                            if r['Config']['Labels'].get('com.docker.compose.service') in ('api', 'worker', 'web')))
        self.assertFalse(any(c[:2] == ('docker', 'start') and c[-1] != self.controller.helper_id for c in self.fake.calls))

    def test_compare_failure_after_recreation_retains_hold_and_stopped_new_api(self):
        self.fake.receipt_override['compare'] = m.encoded({'code': 'MISMATCH', 'ok': False})
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'compare')
        self.assertTrue((self.repo / '.local-auth/.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json').exists())
        self.assertFalse(self.fake.records['b' * 64]['State']['Running'])
        self.assertEqual(sum('up' in c for c in self.fake.calls), 1)

    def test_failed_up_client_is_uncertain_not_rolled_back(self):
        self.fake.fail_on = lambda c: 'up' in c
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'recreate')
        self.assertTrue(result['uncertain'])
        self.assertTrue((self.repo / '.local-auth/.trivy-refresh.lock').exists())
        self.assertEqual(sum('up' in c for c in self.fake.calls), 1)
        self.assertNotIn('SYNTHETIC_PRIVATE_DIAGNOSTIC', json.dumps(result))

    def test_new_api_config_change_refused_no_resume(self):
        self.fake.new_mutation = lambda record: record['HostConfig'].update(ReadonlyRootfs=False)
        self.assertFalse(self.result()['ok'])
        self.assertFalse(self.fake.records['b' * 64]['State']['Running'])
        self.assertFalse(any(c[:2] == ('docker', 'start') and c[-1] != self.controller.helper_id for c in self.fake.calls))

    def test_mount_or_gateway_metadata_drift_during_drain_retains_hold(self):
        def drift(seconds):
            self.fake.records[self.plan.bindings['egress'].container]['HostConfig']['Memory'] = 1
        self.controller.sleep = drift
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'drain')
        self.assertFalse(any(c[:2] == ('docker', 'create') for c in self.fake.calls))
        self.assertTrue((self.repo / '.local-auth/.trivy-refresh.lock').exists())

    def test_hold_exists_before_first_stop_and_remains_on_stop_failure(self):
        def refuse_stop(command):
            if command[:2] == ('docker', 'stop'):
                marker = self.repo / '.local-auth/.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json'
                self.assertTrue(marker.exists())
                self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
                return True
            return False
        self.fake.fail_on = refuse_stop
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertTrue(result['manualReconciliationRequired'])
        self.assertTrue((self.repo / '.local-auth/.trivy-refresh.lock').exists())

    def test_foreign_parent_bind_also_counts_as_volume_access(self):
        foreign = copy.deepcopy(self.fake.records[self.plan.bindings['worker'].container])
        foreign['Id'] = 'f' * 64
        foreign['Mounts'] = [{'Type': 'bind', 'Source': '/synthetic/volumes', 'Destination': '/foreign', 'RW': True}]
        self.fake.records[foreign['Id']] = foreign
        self.assertFalse(self.result()['ok'])
        self.assert_no_daemon_write()

    def test_health_tmpfs_and_web_port_drift_fail_before_writes(self):
        mutations = [lambda: self.fake.model['services']['api'].update(tmpfs=['/unexpected']),
                     lambda: self.fake.model['services']['api'].update(healthcheck={'test': ['CMD', 'different']}),
                     lambda: self.fake.model['services']['web']['ports'][0].update(host_ip='0.0.0.0')]
        original = copy.deepcopy(self.fake.model)
        for mutate in mutations:
            mutate()
            self.assertFalse(self.result()['ok'])
            self.assert_no_daemon_write()
            self.fake.model = copy.deepcopy(original)

    def test_readiness_failure_after_resume_closes_known_ingress_and_retains_lock(self):
        self.fake.fail_on = lambda c: c[:2] == ('docker', 'exec') and 'chainReady' in c[-1]
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'resume')
        self.assertTrue((self.repo / '.local-auth/.trivy-refresh.lock').exists())
        self.assertFalse(self.fake.records[self.plan.bindings['web'].container]['State']['Running'])
        self.assertFalse(self.fake.records['b' * 64]['State']['Running'])

    def test_timed_out_snapshot_client_freezes_only_exact_running_own_holder(self):
        self.fake.fail_on = lambda c: c[:2] == ('docker', 'exec') and m.SCRIPT_TARGET in c
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'capture')
        identity = self.controller.helper_id
        self.assertTrue(self.fake.records[identity]['State']['Running'])
        self.assertTrue(self.fake.records[identity]['State']['Paused'])
        self.assertIn(('docker', 'pause', identity), self.fake.calls)
        self.assertFalse(any(c[:2] in (('docker', 'stop'), ('docker', 'rm')) and c[-1] == identity for c in self.fake.calls))
        self.assertTrue((self.repo / '.local-auth/.trivy-refresh.lock').exists())
        self.assertFalse(any('up' in c for c in self.fake.calls))

    def test_daemon_change_refuses_capture_with_preservation_hold(self):
        self.controller.sleep = lambda _: setattr(self.fake, 'daemon', 'SYNTHETIC_OTHER_DAEMON')
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertTrue(result['manualReconciliationRequired'])
        self.assertFalse(any(c[:2] == ('docker', 'create') for c in self.fake.calls))

    def test_unsafe_root_fails_before_lock_creation_and_no_chmod(self):
        root = self.repo / '.local-auth'
        root.chmod(0o777)
        self.assertFalse(self.result()['ok'])
        self.assertEqual(root.stat().st_mode & 0o777, 0o777)
        self.assertFalse((root / '.trivy-refresh.lock').exists())
        self.assertEqual(self.fake.calls, [])

    def test_no_persistent_root_permission_change_or_extra_composition_input(self):
        self.controller.env['COMPOSE_FILE'] = '/synthetic/unapproved.yaml'
        self.assertFalse(self.result()['ok'])
        self.assert_no_daemon_write()
        self.assertEqual((self.repo / '.local-auth').stat().st_mode & 0o777, 0o755)


    def test_real_receipts_one_uid_holder_and_durable_exports_before_resume(self):
        self.assertTrue(self.result()['ok'])
        calls = self.fake.calls
        creates = [c for c in calls if c[:2] == ('docker', 'create')]
        self.assertEqual(len(creates), 1)
        create = creates[0]
        self.assertEqual(create[-3:], (self.plan.bindings['api'].image, '-e', m.HOLDER_CODE))
        for flag, value in (('--user', '65532:65532'), ('--memory', '2g'), ('--memory-swap', '2g'),
                            ('--cpus', '1'), ('--pids-limit', '64'), ('--network', 'none')):
            self.assertEqual(create[create.index(flag) + 1], value)
        self.assertEqual(dict(create[i + 1].split(':', 1) for i, v in enumerate(create) if v == '--tmpfs'), m.HOLDER_TMPFS)
        mounts = [create[i + 1] for i, v in enumerate(create) if v == '--mount']
        self.assertEqual(len(mounts), 3)
        self.assertTrue(all(value.endswith(',readonly') for value in mounts))
        self.assertFalse(any('target=/backup' in value for value in mounts))
        snapshots = [c for c in calls if c[:2] == ('docker', 'exec') and m.SCRIPT_TARGET in c]
        self.assertEqual(snapshots, [
            ('docker', 'exec', 'c' * 64, 'node', m.SCRIPT_TARGET, 'capture', '/backup/pre'),
            ('docker', 'exec', 'c' * 64, 'node', m.SCRIPT_TARGET, 'compare', '/backup/pre', '/backup/post')])
        copies = [c for c in calls if c[:2] == ('docker', 'cp')]
        self.assertEqual(len(copies), 2)
        pre, post = map(calls.index, copies)
        up = next(i for i, c in enumerate(calls) if 'up' in c)
        remove = calls.index(('docker', 'rm', '--force', 'c' * 64))
        ready = next(i for i, c in enumerate(calls) if c[:2] == ('docker', 'exec') and 'chainReady' in c[-1])
        reopen = calls.index(('docker', 'start', self.plan.bindings['web'].container))
        self.assertLess(pre, up)
        self.assertLess(up, post)
        self.assertLess(post, remove)
        self.assertLess(remove, ready)
        self.assertLess(ready, reopen)
        for stage in ('pre', 'post'):
            inventory = m.backup_inventory(self.controller.backup / stage)
            self.assertEqual(inventory, synthetic_inventory(self.fake.snapshot_files[stage]))
            m.validate_manifest(self.controller.backup / stage, inventory, self.plan.store_versions)

    def test_ambiguous_pre_copy_pauses_not_removes_same_baseline(self):
        self.fake.fail_on = lambda c: c[:2] == ('docker', 'cp')
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'export_pre')
        self.assertTrue(result['uncertain'])
        holder = self.controller.helper_id
        self.assertTrue(self.fake.records[holder]['State']['Paused'])
        self.assertFalse(any('up' in c or c[:2] == ('docker', 'rm') for c in self.fake.calls))
        self.assertFalse(any(c[:2] == ('docker', 'stop') and c[-1] == holder for c in self.fake.calls))
        self.assertEqual(self.controller.exports, set())
        self.assertTrue((self.controller.backup / 'pre').is_dir())

    def test_ambiguous_post_copy_keeps_baseline_and_closed_ingress(self):
        self.fake.fail_on = lambda c: c[:2] == ('docker', 'cp') and ':/backup/post/.' in c[2]
        result = self.result()
        self.assertEqual(result['phase'], 'export_post')
        self.assertEqual(self.controller.exports, {'pre'})
        self.assertTrue(self.fake.records[self.controller.helper_id]['State']['Paused'])
        self.assertFalse(self.fake.records['b' * 64]['State']['Running'])
        self.assertFalse(self.fake.records[self.plan.bindings['web'].container]['State']['Running'])
        self.assertFalse(any(c[:2] == ('docker', 'rm') for c in self.fake.calls))

    def test_incomplete_or_tampered_working_copy_refuses_before_recreate(self):
        self.fake.copy_mutation = lambda destination: (destination / 'working/auth/auth.sqlite').write_bytes(b'SYNTHETIC_DRIFT')
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'export_pre')
        self.assertFalse(any('up' in c for c in self.fake.calls))
        self.assertTrue(self.fake.records[self.controller.helper_id]['State']['Paused'])

    def test_symlink_export_refuses_without_repair(self):
        def mutate(destination):
            target = destination / 'working/auth/auth.sqlite'
            target.unlink()
            target.symlink_to(destination / 'raw/auth/auth.sqlite')
        self.fake.copy_mutation = mutate
        self.assertFalse(self.result()['ok'])
        self.assertTrue((self.controller.backup / 'pre/working/auth/auth.sqlite').is_symlink())
        self.assertFalse(any('up' in c for c in self.fake.calls))

    def test_unsafe_export_mode_refuses_without_chmod(self):
        self.fake.copy_mutation = lambda destination: (destination / 'manifest.json').chmod(0o644)
        self.assertFalse(self.result()['ok'])
        self.assertEqual((self.controller.backup / 'pre/manifest.json').stat().st_mode & 0o777, 0o644)
        self.assertFalse(any('up' in c for c in self.fake.calls))

    def test_reviewed_version_mismatch_fences_startup_before_compose_up(self):
        manifest = json.loads(self.fake.snapshot_files['pre']['manifest.json'])
        next(s for s in manifest['stores'] if s['path'] == 'data/ledger.sqlite')['logical']['schema']['userVersion'] = '14'
        self.fake.snapshot_files['pre']['manifest.json'] = m.encoded(manifest)
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'export_pre')
        self.assertFalse(any('up' in c for c in self.fake.calls))

    def test_unsupported_schema_helper_refusal_does_not_recreate(self):
        self.fake.receipt_override['capture'] = m.encoded({'code': 'INVALID_STORE', 'ok': False})
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'capture')
        self.assertFalse(any('up' in c for c in self.fake.calls))

    def test_manifest_raw_or_sealed_hash_mismatch_not_an_allstate_flag(self):
        manifest = json.loads(self.fake.snapshot_files['pre']['manifest.json'])
        manifest['stores'][0]['sha256'] = 'f' * 64
        self.fake.snapshot_files['pre']['manifest.json'] = m.encoded(manifest)
        self.assertFalse(self.result()['ok'])
        self.assertFalse(any('up' in c for c in self.fake.calls))

    def test_holder_qualification_rejects_each_spoofed_security_field(self):
        self.fake.fail_on = lambda c: c[:2] == ('docker', 'cp')
        self.assertFalse(self.result()['ok'])
        identity = self.controller.helper_id
        self.fake.records[identity]['State']['Paused'] = False  # In-memory fake only.
        original = copy.deepcopy(self.fake.records[identity])
        changes = [lambda r: r.update(Name='/FOREIGN'), lambda r: r.update(Image='sha256:' + 'f' * 64),
                   lambda r: r['Config'].update(User='0:0'), lambda r: r['Config'].update(Cmd=['SPOOF']),
                   lambda r: r['Config'].update(Env=['SYNTHETIC_EXTRA=x']),
                   lambda r: r['Config']['Labels'].update({'dip.key-preservation': 'FOREIGN'}),
                   lambda r: r['HostConfig'].update(CapAdd=['DAC_OVERRIDE']),
                   lambda r: r['HostConfig'].update(CapDrop=[]), lambda r: r['HostConfig'].update(Privileged=True),
                   lambda r: r['HostConfig'].update(SecurityOpt=[]), lambda r: r['HostConfig'].update(NetworkMode='bridge'),
                   lambda r: r['HostConfig'].update(Memory=m.GIB), lambda r: r['HostConfig'].update(MemorySwap=4 * m.GIB),
                   lambda r: r['HostConfig'].update(PidsLimit=128), lambda r: r['HostConfig'].update(NanoCpus=2_000_000_000),
                   lambda r: r['HostConfig']['Tmpfs'].update({'/backup': 'size=4g'}),
                   lambda r: r['Mounts'][0].update(RW=True),
                   lambda r: r['Mounts'].append({'Type': 'bind', 'Source': '/synthetic/volumes', 'Destination': '/alias', 'RW': False}),
                   lambda r: r['State'].update(Running=False)]
        for index, mutate in enumerate(changes):
            self.fake.records[identity] = copy.deepcopy(original)
            mutate(self.fake.records[identity])
            with self.subTest(field_case=index), self.assertRaises(m.Refusal):
                self.controller.writers(set())
        self.fake.records[identity] = original
        self.controller.writers(set())  # ONLY the exact fully qualified RO holder is exempt.

    def test_same_label_foreign_ro_reader_never_exempt_or_paused(self):
        self.fake.fail_on = lambda c: c[:2] == ('docker', 'cp')
        self.assertFalse(self.result()['ok'])
        self.fake.records[self.controller.helper_id]['State']['Paused'] = False
        foreign = copy.deepcopy(self.fake.records[self.controller.helper_id])
        foreign.update(Id='f' * 64, Name='/FOREIGN_SAME_LABEL')
        self.fake.records[foreign['Id']] = foreign
        with self.assertRaises(m.Refusal):
            self.controller.writers(set())
        self.controller.fail_stop()
        pauses = [c for c in self.fake.calls if c[:2] == ('docker', 'pause')]
        self.assertTrue(all(c[-1] == self.controller.helper_id for c in pauses))
        self.assertTrue(foreign['State']['Running'])
        self.assertFalse(foreign['State']['Paused'])

    def test_spoofed_own_holder_not_paused_or_deleted_on_failure(self):
        self.fake.helper_mutation = lambda r: r['Config'].update(User='0:0')
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'holder')
        self.assertFalse(any(c[:2] in (('docker', 'pause'), ('docker', 'rm')) for c in self.fake.calls))

    def test_hold_file_lock_and_root_fsync_complete_before_first_stop(self):
        events = []
        fsync = m.os.fsync
        def record_sync(fd):
            st = os.fstat(fd)
            events.append((st.st_dev, st.st_ino))
            return fsync(fd)
        def at_stop(command):
            if command[:2] == ('docker', 'stop'):
                lock = self.repo / '.local-auth/.trivy-refresh.lock'
                paths = (lock / 'KEY_ACTIVATION_HOLD.json', lock, lock.parent)
                identities = [(p.stat().st_dev, p.stat().st_ino) for p in paths]
                offsets = [max(i for i, e in enumerate(events) if e == identity) for identity in identities]
                self.assertLess(offsets[0], offsets[1])
                self.assertLess(offsets[1], offsets[2])
                return True
            return False
        self.fake.fail_on = at_stop
        with patch.object(m.os, 'fsync', side_effect=record_sync):
            self.assertFalse(self.result()['ok'])
        self.assertTrue(self.controller.hold_requested)

    def test_hold_directory_fsync_failure_refuses_all_daemon_writes(self):
        original = m.sync_directory
        def refuse_lock(path):
            if Path(path).name == '.trivy-refresh.lock':
                raise OSError('SYNTHETIC_FSYNC_FAILURE')
            return original(path)
        with patch.object(m, 'sync_directory', side_effect=refuse_lock):
            result = self.result()
        self.assertFalse(result['ok'])
        self.assertFalse(result['uncertain'])
        self.assertTrue(result['manualReconciliationRequired'])
        self.assert_no_daemon_write()
        self.assertTrue((self.repo / '.local-auth/.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json').exists())

    def test_export_files_and_directories_synced_before_first_recreation(self):
        synced = set()
        original = m.os.fsync
        def record(fd):
            st = os.fstat(fd)
            synced.add((st.st_dev, st.st_ino))
            return original(fd)
        def at_up(command):
            if 'up' in command:
                pre = self.controller.backup / 'pre'
                for path in (pre, *pre.rglob('*'), self.controller.backup, self.controller.root):
                    st = path.stat()
                    self.assertIn((st.st_dev, st.st_ino), synced)
                self.assertEqual(self.controller.exports, {'pre'})
            return False
        self.fake.fail_on = at_up
        with patch.object(m.os, 'fsync', side_effect=record):
            self.assertTrue(self.result()['ok'])

    def test_host_capacity_and_engine_memory_fail_before_first_stop(self):
        self.fake.memory_total = 2 * m.GIB
        self.assertFalse(self.result()['ok'])
        self.assert_no_daemon_write()
        self.fake.memory_total = '4294967296'
        self.assertFalse(self.result()['ok'])
        self.assert_no_daemon_write()
        self.fake.memory_total = 4 * m.GIB
        with patch.object(m.shutil, 'disk_usage', return_value=type('NoSpace', (), {'free': m.GIB})()):
            self.assertFalse(self.result()['ok'])
        self.assert_no_daemon_write()

    def test_missing_review_assertions_or_known_rejected_helper_refuse_before_engine(self):
        candidates = [replace(self.plan, startup_evidence=''), replace(self.plan, old_db_reads_reviewed=False),
                      replace(self.plan, backup_sandbox_reviewed=False), replace(self.plan, store_versions={}),
                      replace(self.plan, sources=dict(self.plan.sources, **{m.HELPER_PATH: m.REJECTED_HELPER}))]
        for candidate in candidates:
            self.controller.plan = candidate
            self.assertFalse(self.result()['ok'])
            self.assertEqual(self.fake.calls, [])

    def test_unhealthy_original_api_or_wrong_existing_quota_refuses_pre_stop(self):
        api = self.fake.records[self.plan.bindings['api'].container]
        api['State']['Health']['Status'] = 'unhealthy'
        self.assertFalse(self.result()['ok'])
        self.assert_no_daemon_write()
        api['State']['Health']['Status'] = 'healthy'
        env = m.env_map(api['Config']['Env'])
        env['LLM_QUOTA_USER_INPUT'] = '1'
        api['Config']['Env'] = [k + '=' + v for k, v in env.items()]
        self.assertFalse(self.result()['ok'])
        self.assert_no_daemon_write()

    def test_holder_walltime_not_extended_and_expiry_refuses_recreate(self):
        self.fake.fail_on = lambda c: c[:2] == ('docker', 'cp')
        self.assertFalse(self.result()['ok'])
        self.controller.holder_started = m.time.monotonic() - 235
        with self.assertRaises(m.Refusal):
            self.controller.holder_budget(1)
        self.assertFalse(any('up' in c for c in self.fake.calls))

    def test_final_lock_removal_fsync_failure_failstops_and_retains_new_own_hold(self):
        original = m.sync_directory
        def refuse_final_root(path):
            if Path(path) == self.controller.root and self.controller.touched and not self.controller.hold_requested:
                raise OSError('SYNTHETIC_FINAL_ROOT_FSYNC_FAILURE')
            return original(path)
        with patch.object(m, 'sync_directory', side_effect=refuse_final_root):
            result = self.result()
        self.assertFalse(result['ok'])
        self.assertTrue(result['uncertain'])
        self.assertTrue(result['manualReconciliationRequired'])
        self.assertTrue((self.controller.root / '.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json').exists())
        self.assertFalse(self.fake.records[self.plan.bindings['web'].container]['State']['Running'])
        self.assertFalse(self.fake.records['b' * 64]['State']['Running'])

    def test_failed_holder_start_client_is_uncertain_and_exact_holder_frozen(self):
        def failed_start(command):
            if command[:2] == ('docker', 'start') and command[-1] == self.controller.helper_id:
                self.fake.records[command[-1]]['State']['Running'] = True
                return True
            return False
        self.fake.fail_on = failed_start
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'holder')
        self.assertTrue(self.fake.records[self.controller.helper_id]['State']['Paused'])
        self.assertFalse(any('up' in c for c in self.fake.calls))

    def test_copy_completed_but_client_failed_retains_material_without_certifying_it(self):
        original = self.controller.run
        def ambiguous_copy(command, **kwargs):
            output = original(command, **kwargs)
            if command[:2] == ('docker', 'cp'):
                raise m.Refusal()
            return output
        self.controller.run = ambiguous_copy
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(self.controller.exports, set())
        self.assertTrue((self.controller.backup / 'pre/manifest.json').is_file())
        self.assertTrue(self.fake.records[self.controller.helper_id]['State']['Paused'])
        self.assertFalse(any('up' in c or c[:2] == ('docker', 'rm') for c in self.fake.calls))

    def test_pause_failure_remains_uncertain_never_deletes_baseline(self):
        self.fake.fail_on = lambda c: c[:2] in (('docker', 'cp'), ('docker', 'pause'))
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertTrue(result['uncertain'])
        self.assertTrue(result['manualReconciliationRequired'])
        self.assertFalse(self.controller.helper_removed)
        self.assertTrue((self.controller.root / '.trivy-refresh.lock').exists())
        self.assertFalse(any(c[:2] == ('docker', 'rm') or 'up' in c for c in self.fake.calls))

    def test_export_hardlink_refuses_without_unlink_or_repair(self):
        def mutate(destination):
            os.link(destination / 'raw/auth/auth.sqlite', destination / 'SYNTHETIC_ALIAS')
        self.fake.copy_mutation = mutate
        self.assertFalse(self.result()['ok'])
        self.assertEqual((self.controller.backup / 'pre/raw/auth/auth.sqlite').stat().st_nlink, 2)
        self.assertFalse(any('up' in c for c in self.fake.calls))

    def test_cli_accepts_only_complete_reviewed_synthetic_nonsecret_plan(self):
        argv = ['--activate-existing-api', '--authorize-preservation-window',
                '--sqlite-helper-relative', m.HELPER_PATH, '--startup-review-evidence', self.plan.startup_evidence,
                '--confirm-old-api-db-reads-reviewed', '--authorize-new-backup-sandbox-2g-240s']
        for role, binding in self.plan.bindings.items():
            argv.extend(('--' + role + '-container', binding.container, '--' + role + '-image', binding.image))
        for path, digest in self.plan.sources.items():
            argv.extend(('--source-sha256', path + '=' + digest))
        for path, version in self.plan.store_versions.items():
            argv.extend(('--store-version', path + '=' + ':'.join(map(str, version))))
        self.assertEqual(m.arguments(argv), self.plan)
        with self.assertRaises(m.Refusal):
            m.arguments([arg for arg in argv if arg != '--confirm-old-api-db-reads-reviewed'])
        self.assertEqual(self.fake.calls, [])

    def test_no_ambient_llm_flags_required_or_injected(self):
        self.assertFalse(any(k.startswith('LLM_') for k in self.controller.env))
        self.assertTrue(self.result()['ok'])
        self.assertEqual(self.controller.env, {'SYNTHETIC_AMBIENT': 'kept'})
        self.assertEqual(m.env_map(self.controller.old['api']['Config']['Env'])['SCAN_JWT_SECRET'],
                         m.env_map(self.fake.records['b' * 64]['Config']['Env'])['SCAN_JWT_SECRET'])


# Independently spelled actual public peer protocol; state/image/evidence fixtures
# below remain synthetic. This test does NOT execute or approve native migration.
MOCK_MIGRATION_PROTOCOL = {
    'capture': ('CAPTURED', ('capture', '--preservation-migration', '/backup/pre'), False),
    'capture-post': ('CAPTURED', ('capture', '--preservation-migration', '/backup/post'), False),
    'plan-migration': ('PLANNED', ('plan-migration', '--preservation-migration', '/backup/pre'), True),
    'apply-migration': ('MIGRATED', ('apply-migration', '--preservation-migration', '/backup/pre'), False),
    'compare-migrated': ('MIGRATION_MATCH', ('compare-migrated', '--preservation-migration', '/backup/pre', '/backup/post'), False),
    'compatibility': ('COMPATIBLE', ('compatibility', '--preservation-migration', '/backup/post'), True),
}


class MigrationDocker(FakeDocker):
    """Only simulated daemon and inert backup bytes. Never invokes the MJS CLI."""
    def __init__(self, existing):
        self.__dict__.update(existing.__dict__)
        self.operation_after = {}
        self.accounting = {'memoryCurrent': 128 * m.MIB, 'memoryMax': 2 * m.GIB, 'swapMax': 0,
                           'vmAvailable': 4 * m.GIB, 'authFree': m.GIB, 'dataFree': m.GIB,
                           'backupAllocated': m.MIB}

    def __call__(self, args, **kwargs):
        args = tuple(args)
        if args[:2] == ('docker', 'exec') and m.SMALL_ACCOUNTING_CODE in args:
            self.calls.append(args)
            assert args == ('docker', 'exec', 'c' * 64, 'node', '-e', m.SMALL_ACCOUNTING_CODE)
            assert kwargs == {'timeout': 5, 'cap': 1024}
            if self.fail_on and self.fail_on(args):
                raise self.failure
            return m.encoded(self.accounting)
        migration_exec = args[:2] == ('docker', 'exec') and m.SCRIPT_TARGET in args
        role_query = args[:2] == ('docker', 'ps') and any('label=com.docker.compose.service=' in a for a in args)
        up = args[:2] == ('docker', 'compose') and 'up' in args
        if not (migration_exec or role_query or up):
            return super().__call__(args, **kwargs)
        self.calls.append(args)
        if self.fail_on and self.fail_on(args):
            raise self.failure
        if role_query:
            role = next(a.split('=', 2)[2] for a in args if a.startswith('label=com.docker.compose.service='))
            return ('\n'.join(r['Id'] for r in self.records.values()
                             if r['Config']['Labels'].get('com.docker.compose.service') == role) + '\n').encode()
        if migration_exec:
            private = args[2] == '-i'
            identity = args[3] if private else args[2]
            index = args.index(m.SCRIPT_TARGET)
            operation = args[index + 1]
            if operation == 'capture' and args[-1] == '/backup/post':
                operation = 'capture-post'
            code, arguments, wants_input = MOCK_MIGRATION_PROTOCOL[operation]
            assert args[index + 1:] == arguments and private is wants_input
            holder = self.records[identity]
            assert holder['State']['Running'] and not holder['State']['Paused']
            if private:
                m.authority_input(kwargs['input_data'])
                self.private_inputs.append(kwargs['input_data'])
            if operation == 'capture':
                assert not self.captured
                self.captured.add('pre')
            elif operation == 'plan-migration':
                assert self.captured == {'pre'}
                self.captured.add('migration')
                plan = {'format': 'preservation-migration-plan-v1',
                        'profile': {'name': m.MIGRATION_PROFILE, 'current': m.CURRENT_SOURCE_AGGREGATE,
                                    'oldAuthSource': 'b39f54808f63e07959ead476bf61a574cd3a4d288d96cbb5035b1bfecb24d4f0',
                                    'oldLedgerSource': '9b0b3cce477da38aa91aeba2946a9b1ab334615f9b3f3a5d8273a45b36c14626'},
                        'baseline': hashlib.sha256(self.snapshot_files['pre']['manifest.json']).hexdigest(),
                        'fingerprint': '1' * 64,
                        'auth': {'createTrusted': True, 'createBrowser': True, 'mappings': [], 'browser': None},
                        'ledger': {'version': 13, 'policies': []},
                        'dryrun': {'auth/auth.sqlite': '2' * 64, 'data/ledger.sqlite': '3' * 64}}
                stores = json.loads(self.snapshot_files['pre']['manifest.json'])['stores']
                sizes = {s['path']: s['bytes'] for s in stores}
                self.snapshot_files['migration'] = {'plan.json': m.encoded(plan),
                                                    'auth.sqlite': b'SYNTHETIC_INERT'.ljust(sizes['auth/auth.sqlite'], b'\0'),
                                                    'ledger.sqlite': b'SYNTHETIC_INERT'.ljust(sizes['data/ledger.sqlite'], b'\0')}
            elif operation == 'apply-migration':
                assert self.captured == {'pre', 'migration'}
                self.snapshot_files['migration'].update({'apply-attempt.json': b'SYNTHETIC_ATTEMPT',
                                                        'applied.json': b'SYNTHETIC_APPLIED'})
            elif operation == 'capture-post':
                assert self.captured == {'pre', 'migration'}
                self.captured.add('post')
            else:
                assert self.captured == {'pre', 'post', 'migration'}
            if operation in self.operation_after:
                self.operation_after[operation]()
            return self.receipt_override.get(operation, m.encoded({'code': code, 'ok': True}))
        candidate = unescape(json.loads(Path(args[args.index('-f') + 1]).read_text()))
        roles = ('web',) if args[-1] == 'web' else ('api', 'worker')
        for role in roles:
            old = self.records.pop(self.plan.bindings[role].container)
            identity = {'api': 'b', 'worker': 'a', 'web': '9'}[role] * 64
            old['Id'] = identity
            old['Config']['Hostname'] = identity[:12]
            old['Image'] = old['Config']['Image'] = candidate['services'][role]['image']
            if 'com.docker.compose.image' in old['Config']['Labels']:
                old['Config']['Labels']['com.docker.compose.image'] = old['Image']
            env = dict({'PATH': '/synthetic/bin'}, **candidate['services'][role]['environment'])
            old['Config']['Env'] = [k + '=' + v for k, v in env.items()]
            old['Config']['Labels']['com.docker.compose.config-hash'] = 'SYNTHETIC_NEW'
            old['Config']['Labels']['com.docker.compose.project.config_files'] = args[args.index('-f') + 1]
            old['Config']['Labels']['com.docker.compose.project.working_dir'] = str(self.repo / 'server/deploy')
            old['State']['Running'] = True
            self.records[identity] = old
            if self.new_mutation:
                self.new_mutation(old)
        return b''


class MigrationTests(unittest.TestCase):
    def setUp(self):
        ControllerTests.setUp(self)
        self.alarm = {'handler': m.signal.SIG_DFL, 'timer': (0.0, 0.0), 'armed': [], 'armedAt': None}
        def install(signum, handler):
            old, self.alarm['handler'] = self.alarm['handler'], handler
            return old
        def arm(which, seconds, interval=0):
            old, self.alarm['timer'] = self.alarm['timer'], (float(seconds), float(interval))
            self.alarm['armed'].append(seconds)
            self.alarm['armedAt'] = m.time.monotonic()
            return old
        def live(which):
            remaining, interval = self.alarm['timer']
            if self.alarm['armedAt'] is not None:
                remaining = max(0.0, remaining - (m.time.monotonic() - self.alarm['armedAt']))
            return (remaining, interval)
        patch.object(m.signal, 'getsignal', side_effect=lambda _: self.alarm['handler']).start()
        patch.object(m.signal, 'getitimer', side_effect=live).start()
        patch.object(m.signal, 'signal', side_effect=install).start()
        patch.object(m.signal, 'setitimer', side_effect=arm).start()
        self.plan = replace(self.plan, store_versions=None, backup_sandbox_reviewed=False,
                            preservation_migration=True, additive_migration_authorized=True,
                            migration_rw_sandbox_authorized=True,
                            candidate_api_image='sha256:' + '8' * 64,
                            candidate_worker_image='sha256:' + 'a' * 64,
                            candidate_web_image='sha256:' + '9' * 64,
                            candidate_source_aggregate=m.CURRENT_SOURCE_AGGREGATE,
                            candidate_source_evidence='DIP-ARTF-999998',
                            migration_review_evidence='DIP-ARTF-999997',
                            web_source_review_evidence='DIP-ARTF-999996')
        self.fake = MigrationDocker(self.fake)
        self.controller.plan = self.fake.plan = self.plan
        self.controller.run = self.fake
        for role in self.plan.replaced_roles:
            candidate = copy.deepcopy(self.fake.images[self.plan.bindings[role].image])
            candidate['Id'] = self.plan.selected_image(role)
            self.fake.images[candidate['Id']] = candidate
            self.fake.records[self.plan.bindings[role].container]['Config']['Labels']['com.docker.compose.image'] = self.plan.bindings[role].image
        pre = dict(m.CURRENT_SOURCE_VERSIONS, **{'data/ledger.sqlite': (0, 13)})
        self.fake.snapshot_files = {'pre': synthetic_snapshot(pre, migration=True),
                                    'post': synthetic_snapshot(m.CURRENT_SOURCE_VERSIONS, migration=True)}

    def result(self):
        return self.controller.activate()

    def no_up(self):
        self.assertFalse(any('up' in c for c in self.fake.calls))

    def cli(self):
        args = ['--activate-existing-api', '--authorize-preservation-window', '--preservation-migration',
                '--authorize-scan-auth-additive-migration', '--authorize-migration-rw-sandbox-2g-240s',
                '--candidate-api-image', self.plan.api_image,
                '--candidate-worker-image', self.plan.candidate_worker_image,
                '--candidate-web-image', self.plan.candidate_web_image,
                '--candidate-source-aggregate', self.plan.candidate_source_aggregate,
                '--candidate-source-review-evidence', self.plan.candidate_source_evidence,
                '--migration-review-evidence', self.plan.migration_review_evidence,
                '--web-source-review-evidence', self.plan.web_source_review_evidence,
                '--sqlite-helper-relative', m.HELPER_PATH, '--startup-review-evidence', self.plan.startup_evidence,
                '--confirm-old-api-db-reads-reviewed']
        for role, binding in self.plan.bindings.items():
            args.extend(('--' + role + '-container', binding.container, '--' + role + '-image', binding.image))
        for path, sha in self.plan.sources.items():
            args.extend(('--source-sha256', path + '=' + sha))
        return args

    def test_migration_order_durable_pre_before_apply_all_gates_before_pair_web_after_ready(self):
        syncs = []
        real_sync = m.sync_directory
        def synced(path):
            real_sync(path)
            syncs.append(Path(path))
        def applying():
            self.assertEqual(self.controller.exports, {'pre'})
            self.assertIn(self.controller.backup / 'pre', syncs)
            self.assertIn(self.controller.root, syncs)
            self.assertTrue(self.controller.migration_planned)
            self.no_up()
        self.fake.operation_after['apply-migration'] = applying
        with patch.object(m, 'sync_directory', side_effect=synced):
            result = self.result()
        self.assertTrue(result['ok'])
        self.assertEqual(result['comparisonMode'], 'additive-scan-auth')
        self.assertFalse(result['providerOperabilityProven'])
        self.assertFalse(result['postResumeStateCompared'])
        calls = self.fake.calls
        def operation(name):
            return next(i for i, c in enumerate(calls) if m.SCRIPT_TARGET in c and name in c)
        pre = next(i for i, c in enumerate(calls) if c[:2] == ('docker', 'cp') and '/backup/pre/.' in c[2])
        post = next(i for i, c in enumerate(calls) if c[:2] == ('docker', 'cp') and '/backup/post/.' in c[2])
        ups = [i for i, c in enumerate(calls) if 'up' in c]
        remove = next(i for i, c in enumerate(calls) if c[:2] == ('docker', 'rm'))
        ordering = [operation('capture'), pre, operation('plan-migration'), operation('apply-migration'),
                    operation('compare-migrated'), operation('compatibility'), post, remove, *ups]
        self.assertEqual(ordering, sorted(ordering))
        self.assertEqual(len(ups), 2)
        self.assertEqual(calls[ups[0]][-2:], ('api', 'worker'))
        self.assertEqual(calls[ups[1]][-1], 'web')
        self.assertTrue(any(c[:2] == ('docker', 'exec') and 'chainReady' in ' '.join(c)
                            for c in calls[ups[0] + 1:ups[1]]))
        self.assertFalse(any(c[:2] == ('docker', 'start') and c[-1] in
                             [b.container for b in self.plan.bindings.values()] for c in calls))
        self.assertEqual(len(self.controller.helper_ids), 1)
        self.assertEqual(self.controller.exports, {'pre', 'post'})
        self.assertEqual(self.controller.material_exports, {'plan', 'migration'})
        self.assertFalse((self.controller.root / '.trivy-refresh.lock').exists())
        for role in ('egress', 'llm-egress'):
            self.assertEqual(self.fake.records[self.plan.bindings[role].container], self.controller.old[role])

    def test_missing_peer_contract_refuses_before_engine_no_guessed_apply_receipt(self):
        with patch.object(m, 'MIGRATION_PROTOCOL', None):
            self.assertFalse(self.result()['ok'])
        self.assertEqual(self.fake.calls, [])
        self.assertFalse((self.controller.root / '.trivy-refresh.lock').exists())

    def test_cli_separate_consent_all_candidates_no_old_worker_assertion_no_ro_grant(self):
        self.assertEqual(m.arguments(self.cli()), self.plan)
        for flag in ('--authorize-scan-auth-additive-migration', '--authorize-migration-rw-sandbox-2g-240s'):
            with self.assertRaises(m.Refusal):
                m.arguments([a for a in self.cli() if a != flag])
        for extra in (['--current-source-profile'], ['--store-version', 'data/ledger.sqlite=0:13'],
                      ['--confirm-original-worker-profile-reviewed'], ['--authorize-new-backup-sandbox-2g-240s']):
            with self.assertRaises(m.Refusal):
                m.arguments(self.cli() + extra)
        for bad in (replace(self.plan, candidate_web_image=None), replace(self.plan, candidate_worker_image=None),
                    replace(self.plan, migration_review_evidence='DIP-ARTF-455'),
                    replace(self.plan, startup_evidence='DIP-ARTF-456')):
            with self.assertRaises(m.Refusal):
                bad.validate()

    def test_same_bounded_uid_holder_rw_exception_exact_only_no_second_actor(self):
        self.assertTrue(self.result()['ok'])
        create = next(c for c in self.fake.calls if c[:2] == ('docker', 'create'))
        mounts = [create[i + 1] for i, c in enumerate(create) if c == '--mount']
        volumes = [item for item in mounts if item.startswith('type=volume,')]
        self.assertEqual(len(volumes), 2)
        self.assertTrue(all('readonly' not in item for item in volumes))
        self.assertTrue(all('readonly' in item for item in mounts if item.startswith('type=bind,')))
        self.assertEqual(create[-3:], (self.plan.bindings['api'].image, '-e', m.HOLDER_CODE))
        self.assertEqual(create[create.index('--user') + 1], '65532:65532')
        self.assertEqual(create[create.index('--memory') + 1], '2g')
        self.assertEqual(create[create.index('--memory-swap') + 1], '2g')
        self.assertEqual(create[create.index('--pids-limit') + 1], '64')
        self.assertEqual(len([c for c in self.fake.calls if c[:2] == ('docker', 'create')]), 1)

    def test_spoofed_holder_not_exempt_paused_deleted_or_used_for_original_apply(self):
        self.fake.helper_mutation = lambda r: r['HostConfig'].update(CapAdd=['DAC_OVERRIDE'])
        self.assertFalse(self.result()['ok'])
        self.no_up()
        self.assertFalse(any('apply-migration' in c or c[:2] in (('docker', 'pause'), ('docker', 'rm')) for c in self.fake.calls))

    def test_nonkey_env_jwt_and_worker_resources_retained(self):
        result = self.result()
        self.assertTrue(result['ok'])
        for role, identity in self.controller.new_roles.items():
            new, old = self.fake.records[identity], self.controller.old[role]
            current, previous = m.env_map(new['Config']['Env']), m.env_map(old['Config']['Env'])
            self.assertEqual({k: v for k, v in current.items() if k != m.KEY},
                             {k: v for k, v in previous.items() if k != m.KEY})
            self.assertEqual(new['HostConfig'], old['HostConfig'])
            self.assertEqual(m.mount_identity(new), m.mount_identity(old))
            self.assertEqual(m.network_identity(new), m.network_identity(old))
        self.assertEqual(len(self.fake.private_inputs), 2)
        expected = {key: m.env_map(self.controller.old['api']['Config']['Env']).get(key) for key in m.AUTH_SETTINGS}
        self.assertTrue(all(m.authority_input(data) == expected for data in self.fake.private_inputs))
        self.assertNotIn(SYNTHETIC_KEY, json.dumps(result))
        self.assertFalse(any('initialize' in c or 'build' in c or 'tag' in c for c in self.fake.calls))

    def test_unknown_pre_version_or_missing_quota_refuses_before_plan_apply_up(self):
        manifest = json.loads(self.fake.snapshot_files['pre']['manifest.json'])
        next(s for s in manifest['stores'] if s['path'] == 'data/ledger.sqlite')['logical']['schema']['userVersion'] = '12'
        self.fake.snapshot_files['pre']['manifest.json'] = m.encoded(manifest)
        self.assertFalse(self.result()['ok'])
        self.no_up()
        self.assertFalse(any('plan-migration' in c or 'apply-migration' in c for c in self.fake.calls))
        self.assertTrue(self.fake.records[self.controller.helper_id]['State']['Paused'])

    def test_missing_quota_refuses_without_initializer_or_original_writes(self):
        files = self.fake.snapshot_files['pre']
        manifest = json.loads(files['manifest.json'])
        manifest['entries'] = [e for e in manifest['entries'] if e['path'] != 'auth/llm-usage.sqlite']
        manifest['stores'] = [s for s in manifest['stores'] if s['path'] != 'auth/llm-usage.sqlite']
        files['manifest.json'] = m.encoded(manifest)
        self.assertFalse(self.result()['ok'])
        self.no_up()
        self.assertFalse(any('apply-migration' in c or 'initialize' in c for c in self.fake.calls))

    def test_partial_apply_failure_retains_pre_holder_hold_no_app_start_or_old_resume(self):
        self.fake.fail_on = lambda c: 'apply-migration' in c
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'apply_migration')
        self.assertEqual(self.controller.exports, {'pre'})
        self.no_up()
        self.assertTrue((self.controller.backup / 'pre/manifest.json').exists())
        self.assertTrue((self.controller.root / '.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json').exists())
        self.assertTrue(self.fake.records[self.controller.helper_id]['State']['Paused'])
        self.assertFalse(any(c[:2] == ('docker', 'rm') for c in self.fake.calls))
        self.assertFalse(any(c[:2] == ('docker', 'start') and c[-1] == self.plan.bindings['worker'].container for c in self.fake.calls))

    def test_failed_additive_match_prevents_all_candidate_starts(self):
        self.fake.receipt_override['compare-migrated'] = m.encoded({'code': 'MISMATCH', 'ok': False})
        self.assertFalse(self.result()['ok'])
        self.no_up()
        self.assertFalse(self.controller.migration_matched)
        self.assertTrue(self.fake.records[self.controller.helper_id]['State']['Paused'])

    def test_current_post_compatibility_failure_does_not_treat_migration_match_as_startup_proof(self):
        self.fake.receipt_override['compatibility'] = m.encoded({'code': 'INCOMPATIBLE', 'ok': False})
        self.assertFalse(self.result()['ok'])
        self.assertTrue(self.controller.migration_matched)
        self.assertFalse(self.controller.migration_compatible)
        self.no_up()

    def test_pre_export_copy_ambiguity_freezes_baseline_before_original_apply(self):
        self.fake.fail_on = lambda c: c[:2] == ('docker', 'cp')
        self.assertFalse(self.result()['ok'])
        self.assertFalse(any('apply-migration' in c for c in self.fake.calls))
        self.no_up()
        self.assertTrue(self.fake.records[self.controller.helper_id]['State']['Paused'])
        self.assertFalse(any(c[:2] == ('docker', 'rm') for c in self.fake.calls))

    def test_post_export_ambiguity_retains_both_tmpfs_sets_never_starts_apps(self):
        self.fake.fail_on = lambda c: c[:2] == ('docker', 'cp') and '/backup/post/.' in c[2]
        self.assertFalse(self.result()['ok'])
        self.no_up()
        self.assertEqual(self.fake.captured, {'pre', 'post', 'migration'})
        self.assertTrue(self.fake.records[self.controller.helper_id]['State']['Paused'])
        self.assertFalse(any(c[:2] == ('docker', 'rm') for c in self.fake.calls))

    def test_image_drift_after_planning_fails_before_original_apply(self):
        self.fake.operation_after['plan-migration'] = lambda: self.fake.images[self.plan.candidate_worker_image]['Config'].update(User='0:0')
        self.assertFalse(self.result()['ok'])
        self.assertFalse(any('apply-migration' in c for c in self.fake.calls))
        self.no_up()

    def test_post_quota_drift_rejects_success_receipts_before_any_start(self):
        manifest = json.loads(self.fake.snapshot_files['post']['manifest.json'])
        next(s for s in manifest['stores'] if s['path'] == 'auth/llm-usage.sqlite')['logical']['schema']['userVersion'] = '2'
        self.fake.snapshot_files['post']['manifest.json'] = m.encoded(manifest)
        self.assertFalse(self.result()['ok'])
        self.no_up()
        self.assertFalse(any(c[:2] == ('docker', 'rm') for c in self.fake.calls))

    def test_pair_up_client_uncertainty_attributes_and_stops_new_api_worker_never_old_resume(self):
        original_run = self.controller.run
        def ambiguous(args, **kwargs):
            value = original_run(args, **kwargs)
            if 'up' in args:
                raise m.Refusal()
            return value
        self.controller.run = ambiguous
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(set(self.controller.new_roles), {'api', 'worker'})
        self.assertTrue(all(not self.fake.records[i]['State']['Running'] for i in self.controller.new_roles.values()))
        self.assertFalse(any(c[:2] == ('docker', 'start') and c[-1] in [b.container for b in self.plan.bindings.values()] for c in self.fake.calls))
        self.assertTrue((self.controller.root / '.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json').exists())

    def test_worker_config_drift_prevents_new_web_and_stops_pair(self):
        self.fake.new_mutation = lambda r: r['HostConfig'].update(PidsLimit=65) if r['Config']['Labels'].get('com.docker.compose.service') == 'worker' else None
        self.assertFalse(self.result()['ok'])
        ups = [c for c in self.fake.calls if 'up' in c]
        self.assertEqual(len(ups), 1)
        self.assertEqual(ups[0][-2:], ('api', 'worker'))
        self.assertFalse(self.fake.records[self.plan.bindings['web'].container]['State']['Running'])
        self.assertFalse(self.fake.records['a' * 64]['State']['Running'])


    def test_wrong_apply_receipt_never_substitutes_capture_for_migration_success(self):
        self.fake.receipt_override['apply-migration'] = m.encoded({'code': 'CAPTURED', 'ok': True})
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'apply_migration')
        self.no_up()
        self.assertTrue(self.fake.records[self.controller.helper_id]['State']['Paused'])

    def test_worker_candidate_defaults_refuse_preflight_before_first_stop(self):
        self.fake.images[self.plan.candidate_worker_image]['Config']['Env'] = ['PATH=/SYNTHETIC_CHANGED']
        self.assertFalse(self.result()['ok'])
        self.assertFalse(any(c[:2] in (('docker', 'stop'), ('docker', 'create')) for c in self.fake.calls))
        self.no_up()

    def test_web_candidate_config_not_inherited_exactly_refuses_before_first_stop(self):
        self.fake.images[self.plan.candidate_web_image]['Config']['OnBuild'] = ['SYNTHETIC_NEVER_EXECUTED']
        self.assertFalse(self.result()['ok'])
        self.assertFalse(any(c[:2] in (('docker', 'stop'), ('docker', 'create')) for c in self.fake.calls))
        self.no_up()

    def test_durable_pre_tamper_in_apply_guard_refuses_before_original_rw_exec(self):
        real_guard = self.controller.migration_guard
        def tamper():
            if self.controller.phase == 'apply_migration':
                path = self.controller.backup / 'pre/raw/auth/auth.sqlite'
                path.write_bytes(b'SYNTHETIC_TAMPERED')
            return real_guard()
        self.controller.migration_guard = tamper
        self.assertFalse(self.result()['ok'])
        self.assertFalse(any('apply-migration' in c for c in self.fake.calls))
        self.no_up()
        self.assertTrue((self.controller.root / '.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json').exists())

    def test_public_peer_exact_cli_receipts_profile_and_separate_post_capture_static_only(self):
        source = (HERE / 'sqlite_state_snapshot.mjs').read_text()
        self.assertEqual(m.MIGRATION_PROTOCOL, MOCK_MIGRATION_PROTOCOL)
        for code, arguments, private in MOCK_MIGRATION_PROTOCOL.values():
            self.assertIn('[' + ', '.join(repr(a) for a in arguments) + ']', source)
            self.assertIn("receipt(true, '" + code + "')", source)
        self.assertIn("name: 'preservation-migration-v1'", source)
        self.assertIn("...(profile ? { profile } : {})", source)
        self.assertIn('preservationMigration: migration', source)
        self.assertIn('const needsInput = compatibility || planMigration || migrationCompatibility', source)

    def test_missing_migration_manifest_profile_is_not_accepted_as_legacy_capture(self):
        manifest = json.loads(self.fake.snapshot_files['pre']['manifest.json'])
        manifest.pop('profile')
        self.fake.snapshot_files['pre']['manifest.json'] = m.encoded(manifest)
        self.assertFalse(self.result()['ok'])
        self.no_up()
        self.assertFalse(any('apply-migration' in c for c in self.fake.calls))

    def test_post_capture_required_closed_receipt_and_no_fabricated_allstate_flag(self):
        self.fake.receipt_override['capture-post'] = m.encoded({'code': 'CAPTURED', 'ok': True, 'allState': True})
        self.assertFalse(self.result()['ok'])
        self.no_up()
        self.assertFalse(any('compare-migrated' in c for c in self.fake.calls))
        self.assertTrue(self.fake.records[self.controller.helper_id]['State']['Paused'])

    def test_private_plan_and_applied_material_exported_before_original_write_and_removal(self):
        def applying():
            self.assertEqual(self.controller.material_exports, {'plan'})
            self.assertTrue((self.controller.backup / 'plan/plan.json').is_file())
        self.fake.operation_after['apply-migration'] = applying
        self.assertTrue(self.result()['ok'])
        calls = self.fake.calls
        material_copies = [i for i, c in enumerate(calls) if c[:2] == ('docker', 'cp') and '/backup/migration/.' in c[2]]
        apply = next(i for i, c in enumerate(calls) if 'apply-migration' in c)
        rm = next(i for i, c in enumerate(calls) if c[:2] == ('docker', 'rm'))
        self.assertEqual(len(material_copies), 2)
        self.assertLess(material_copies[0], apply)
        self.assertLess(apply, material_copies[1])
        self.assertLess(material_copies[1], rm)
        self.assertTrue((self.controller.backup / 'migration/applied.json').is_file())
        self.assertTrue((self.controller.backup / 'migration/apply-attempt.json').is_file())

    def test_foreign_rw_actor_cannot_borrow_migration_holder_label_or_writer_exception(self):
        def foreign():
            record = copy.deepcopy(self.fake.records[self.controller.helper_id])
            record['Id'] = 'f' * 64
            record['Name'] = '/SYNTHETIC_FOREIGN'
            self.fake.records[record['Id']] = record
        self.fake.operation_after['plan-migration'] = foreign
        self.assertFalse(self.result()['ok'])
        self.assertFalse(any('apply-migration' in c for c in self.fake.calls))
        self.no_up()
        self.assertFalse(any(c[:2] in (('docker', 'pause'), ('docker', 'stop'), ('docker', 'rm')) and 'f' * 64 in c for c in self.fake.calls))

    def test_worker_and_web_no_healthcheck_do_not_require_fabricated_docker_health(self):
        for role in ('worker', 'web'):
            self.fake.records[self.plan.bindings[role].container]['State'].pop('Health')
        self.assertTrue(self.result()['ok'])
        self.assertTrue(any('chainReady' in ' '.join(c) for c in self.fake.calls))

    def test_ledger14_pre_is_allowed_without_self_certifying_unknown_versions(self):
        self.fake.snapshot_files['pre'] = synthetic_snapshot(m.CURRENT_SOURCE_VERSIONS, migration=True)
        self.assertTrue(self.result()['ok'])
        self.assertEqual(self.controller.observed_versions, m.CURRENT_SOURCE_VERSIONS)
        self.assertEqual(self.plan.expected_versions['data/ledger.sqlite'], {(0, 13), (0, 14)})

    def test_web_up_client_uncertainty_stops_exact_new_web_pair_and_holds(self):
        original_run = self.controller.run
        def ambiguous(args, **kwargs):
            value = original_run(args, **kwargs)
            if 'up' in args and args[-1] == 'web':
                raise m.Refusal()
            return value
        self.controller.run = ambiguous
        self.assertFalse(self.result()['ok'])
        self.assertEqual(set(self.controller.new_roles), {'api', 'worker', 'web'})
        self.assertTrue(all(not self.fake.records[i]['State']['Running'] for i in self.controller.new_roles.values()))
        self.assertTrue((self.controller.root / '.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json').exists())

    def test_private_stdin_fixed_migration_argv_only_no_apply_capture_or_wrong_profile_input(self):
        runner = m.Runner('/SYNTHETIC', {})
        data = m.encoded({key: None for key in m.AUTH_SETTINGS})
        invalid = [('docker', 'exec', '-i', 'c' * 64, 'node', m.SCRIPT_TARGET, operation,
                    '--preservation-migration', '/backup/pre') for operation in ('capture', 'apply-migration')]
        invalid.append(('docker', 'exec', '-i', 'c' * 64, 'node', m.SCRIPT_TARGET, 'plan-migration', '/backup/pre'))
        invalid.append(('docker', 'exec', '-i', 'c' * 64, 'node', m.SCRIPT_TARGET, 'compatibility', '--preservation-migration', '/backup/pre'))
        for command in invalid:
            with patch.object(m.subprocess, 'Popen') as launch, self.assertRaises(m.Refusal):
                runner(command, input_data=data, cap=4096)
            launch.assert_not_called()
        command = ('docker', 'exec', '-i', 'c' * 64, 'node', m.SCRIPT_TARGET, 'plan-migration', '--preservation-migration', '/backup/pre')
        with patch.object(m.subprocess, 'Popen') as launch, self.assertRaises(m.Refusal):
            runner(command, cap=4096)
        launch.assert_not_called()


class SelectorBootstrapTests(unittest.TestCase):
    def test_captured_source_verified_before_exec_without_path_resolution(self):
        events = []
        digest = hashlib.sha256
        execute = exec
        original_path = list(sys.path)
        def hashed(data):
            value = digest(data)
            self.assertEqual(value.hexdigest(), m.SELECTOR_SHA256)
            events.append('verified')
            return value
        def executing(code, namespace):
            self.assertEqual(events, ['verified'])
            self.assertEqual(code.co_filename, str(HERE / 'stand_composition.py'))
            self.assertNotIn('stand_composition', sys.modules)
            events.append('execute')
            return execute(code, namespace)
        with patch.object(m.hashlib, 'sha256', side_effect=hashed), \
             patch.object(m, 'exec', side_effect=executing, create=True):
            module = m.load_stand_composition()
        self.assertEqual(events, ['verified', 'execute'])
        self.assertEqual(module.BASES, m.BASES)
        self.assertEqual(sys.path, original_path)
        self.assertNotIn(m.SELECTOR_MODULE, sys.modules)
        self.assertNotIn('stand_composition', sys.modules)

    def test_preloaded_selector_or_bootstrap_module_refused_before_open(self):
        for name in ('stand_composition', m.SELECTOR_MODULE):
            foreign = SimpleNamespace(private=SYNTHETIC_KEY)
            with self.subTest(name=name), patch.dict(sys.modules, {name: foreign}), \
                 patch.object(m.os, 'open', side_effect=AssertionError('NO_SOURCE_OPEN')) as opened, \
                 patch.object(m, 'exec', side_effect=AssertionError('NO_EXEC'), create=True) as execute:
                with self.assertRaises(m.BootstrapRefusal):
                    m.load_stand_composition()
                self.assertIs(sys.modules[name], foreign)
                opened.assert_not_called()
                execute.assert_not_called()

    def test_tampered_capture_never_executes(self):
        source = (HERE / 'stand_composition.py').read_bytes()
        tampered = bytes([source[0] ^ 1]) + source[1:]
        with patch.object(m.os, 'read', side_effect=(tampered, b'')), \
             patch.object(m, 'exec', side_effect=AssertionError('NO_UNVERIFIED_EXEC'), create=True) as execute:
            with self.assertRaises(m.BootstrapRefusal):
                m.load_stand_composition()
            execute.assert_not_called()
        self.assertNotIn(m.SELECTOR_MODULE, sys.modules)

    def test_exec_failure_removes_only_owned_temporary_module(self):
        with patch.object(m, 'exec', side_effect=RuntimeError(SYNTHETIC_KEY), create=True):
            with self.assertRaises(RuntimeError):
                m.load_stand_composition()
        self.assertNotIn(m.SELECTOR_MODULE, sys.modules)

    def test_direct_bootstrap_failures_are_closed_without_main_or_traceback(self):
        tree = ast.parse((HERE / 'recreate_openrouter_key.py').read_bytes())
        block = next(node for node in tree.body if isinstance(node, ast.Try) and
                     isinstance(node.body[0], ast.Assign) and
                     any(isinstance(target, ast.Name) and target.id == '_stand' for target in node.body[0].targets))
        code = compile(ast.Module(body=[block], type_ignores=[]), str(HERE / 'recreate_openrouter_key.py'), 'exec')
        for failure in (m.BootstrapRefusal(), OSError(SYNTHETIC_KEY), RuntimeError(SYNTHETIC_KEY)):
            output = io.BytesIO()
            loader = unittest.mock.Mock(side_effect=failure)
            namespace = {'__name__': '__main__', 'load_stand_composition': loader,
                         'BootstrapRefusal': m.BootstrapRefusal, 'BOOTSTRAP_OBSERVATION': None,
                         'json': json, 'sys': SimpleNamespace(stdout=SimpleNamespace(buffer=output))}
            with self.subTest(error=type(failure).__name__), self.assertRaises(SystemExit) as stopped:
                exec(code, namespace)
            self.assertEqual(stopped.exception.code, 1)
            self.assertEqual(json.loads(output.getvalue()), {'ok': False, 'phase': 'preflight',
                             'uncertain': False, 'manualReconciliationRequired': False})
            self.assertNotIn(SYNTHETIC_KEY.encode(), output.getvalue())
            self.assertNotIn('_held_locks', namespace)
            loader.assert_called_once_with(None)


class ReleaseAlignmentTests(unittest.TestCase):
    result = MigrationTests.result
    cli = MigrationTests.cli

    def setUp(self):
        MigrationTests.setUp(self)
        verifier = 'server/deploy/trust/verify_preservation_release.py'
        verifier_test = 'server/deploy/trust/test_verify_preservation_release.py'
        sources = dict(self.plan.sources)
        for relative in (verifier, verifier_test):
            path = self.repo / relative
            path.write_bytes((m.REPO / relative).read_bytes())  # Public pinned bytes; NOT executed.
            sources[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.plan = replace(self.plan, align_api_cve_release=True, release_verifier=verifier,
                            release_verifier_test=verifier_test, sources=sources)
        self.controller.plan = self.fake.plan = self.plan
        pins = {'SCAN_VULN_ENABLED': 'true', 'SCAN_VULN_RELEASE_DIR': '/opt/release',
                'SCAN_VULN_MANIFEST_DIGEST': 'sha256:' + '1' * 64,
                'SCAN_VULN_ARTIFACT_SHA256': '2' * 64}
        for role in ('api', 'worker'):
            service = self.fake.model['services'][role]
            service['environment'].update(pins)
            record = self.fake.records[self.plan.bindings[role].container]
            record['Config']['Env'] += [k + '=' + v for k, v in pins.items()]
            if role == 'worker':
                service['volumes'].append({'type': 'bind', 'source': '/synthetic/release/db',
                                          'target': '/tmp/trivy/db', 'read_only': True, 'bind': {}})
                record['Mounts'].append({'Type': 'bind', 'Source': '/synthetic/release/db',
                                        'Destination': '/tmp/trivy/db', 'RW': False, 'Propagation': ''})
            else:
                next(v for v in record['Mounts'] if v['Destination'] == '/opt/release')['Source'] = '/synthetic/old-release'
            record['HostConfig']['Mounts'] = [
                {'Type': 'bind', 'Source': v['Source'], 'Target': v['Destination'], 'ReadOnly': True,
                 'BindOptions': {'Propagation': 'rprivate'}} for v in record['Mounts'] if v['Type'] == 'bind']
        self.events = []
        test = self
        class Gate:
            sources = {p: sources[p] for p in (verifier, verifier_test)}
            def verify(self, request):
                test.events.append(('verify', len(test.fake.calls)))
                test.assertFalse(any('up' in c or c[:2] == ('docker', 'stop') for c in test.fake.calls))
                test.assertEqual(request['source'], '/synthetic/release')
                test.assertNotIn(SYNTHETIC_KEY, repr(request))
                return b'S' * 32
            def recheck(self, request, seal):
                test.assertEqual(seal, b'S' * 32)
                test.events.append(('recheck', len(test.fake.calls)))
        self.gate = Gate()
        self.controller.release_gate = self.gate
        def align_new(record):
            if record['Config']['Labels']['com.docker.compose.service'] == 'api':
                actual, configured = m.release_mount(record)
                actual['Source'] = configured['Source'] = '/synthetic/release'
        self.fake.new_mutation = align_new

    def captured(self):
        self.controller.old = {r: copy.deepcopy(self.fake.records[b.container]) for r, b in self.plan.bindings.items()}
        self.controller.images = {r: self.fake.images[b.image] for r, b in self.plan.bindings.items()}
        return m.decode(compose_json(self.fake.model))

    def test_profile_pins_cli_migration_only_and_no_implicit_extra_sources(self):
        args = self.cli() + ['--align-api-cve-release', '--release-verifier-relative', self.plan.release_verifier,
                             '--release-verifier-test-relative', self.plan.release_verifier_test]
        self.assertEqual(m.arguments(args), self.plan)
        for plan in (replace(self.plan, align_api_cve_release=False),
                     replace(self.plan, sources={k: v for k, v in self.plan.sources.items() if k != self.plan.release_verifier}),
                     replace(self.plan, release_verifier='server/deploy/trust/../unsafe.py'),
                     replace(self.plan, release_verifier_test=m.HELPER_TEST),
                     replace(self.plan, preservation_migration=False, current_source_profile=True)):
            with self.assertRaises(m.Refusal):
                plan.validate()

    def test_default_missing_gate_refuses_before_engine_or_live_stop(self):
        self.controller.release_gate = None
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(self.fake.calls, [])
        self.assertFalse(self.controller.touched)
        self.assertFalse(self.events)

    def test_shape_only_is_not_activation_admission_and_originals_are_not_mutated(self):
        model = self.captured()
        before = copy.deepcopy((model, self.controller.old))
        self.controller.original_model_matches('api', model, self.controller.old['api'], shape_only=True)
        with self.assertRaises(m.Refusal):
            self.controller.original_model_matches('api', model, self.controller.old['api'])
        with self.assertRaises(m.Refusal):
            self.controller.model_matches('api', model, self.controller.old['api'])
        self.assertEqual((model, self.controller.old), before)
        self.assertEqual(self.events, [])
        self.assertEqual(self.fake.calls, [])

    def test_worker_cache_source_ro_env_and_unrelated_api_drift_still_refuse(self):
        model = self.captured()
        baseline = copy.deepcopy(self.controller.old)
        for field, value in (('Source', '/synthetic/other'), ('RW', True)):
            self.controller.old = copy.deepcopy(baseline)
            cache = next(v for v in self.controller.old['worker']['Mounts'] if v['Destination'] == '/tmp/trivy/db')
            cache[field] = value
            with self.assertRaises(m.Refusal):
                m.release_alignment(model, self.controller.old)
        self.controller.old = copy.deepcopy(baseline)
        self.controller.old['worker']['Config']['Env'].append('SCAN_VULN_MANIFEST_DIGEST=sha256:' + '3' * 64)
        with self.assertRaises(m.Refusal):
            m.release_alignment(model, self.controller.old)
        self.controller.old = copy.deepcopy(baseline)
        self.controller.old['api']['Mounts'][0]['RW'] = False
        with self.assertRaises(m.Refusal):
            self.controller.original_model_matches('api', model, self.controller.old['api'], shape_only=True)

    def test_identity_exception_masks_only_two_exact_sources(self):
        self.captured()
        old = self.controller.old['api']
        new = copy.deepcopy(old)
        actual, configured = m.release_mount(new)
        actual['Source'] = configured['Source'] = '/synthetic/release'
        identity = lambda r, source: m.aligned_config_identity(r, compose_image=self.plan.bindings['api'].image, source=source)
        baseline = identity(old, '/synthetic/old-release')
        self.assertEqual(identity(new, '/synthetic/release'), baseline)
        for mutate in (lambda r: r['HostConfig'].__setitem__('Memory', 1),
                       lambda r: m.release_mount(r)[1]['BindOptions'].__setitem__('Propagation', 'shared'),
                       lambda r: r['Mounts'][0].__setitem__('RW', False),
                       lambda r: m.release_mount(r)[0].__setitem__('Propagation', 'shared')):
            changed = copy.deepcopy(new)
            mutate(changed)
            self.assertNotEqual(identity(changed, '/synthetic/release'), baseline)
        for mutate in (lambda r: m.release_mount(r)[1].__setitem__('Source', '/synthetic/other'),
                       lambda r: r['HostConfig'].__setitem__('Binds', ['UNSUPPORTED']),
                       lambda r: r['Mounts'].append(copy.deepcopy(m.release_mount(r)[0]))):
            changed = copy.deepcopy(new)
            mutate(changed)
            with self.assertRaises(m.Refusal):
                identity(changed, '/synthetic/release')

    def test_verified_before_admission_stops_and_each_pair_web_replacement(self):
        result = self.result()
        self.assertTrue(result['ok'])
        self.assertEqual([event for event, _ in self.events], ['verify', 'recheck', 'recheck', 'recheck'])
        first_stop = next(i for i, c in enumerate(self.fake.calls) if c[:2] == ('docker', 'stop'))
        ups = [i for i, c in enumerate(self.fake.calls) if 'up' in c]
        self.assertEqual(len(ups), 2)
        self.assertLess(self.events[0][1], first_stop)
        self.assertLessEqual(self.events[1][1], first_stop)
        for (_, at), up in zip(self.events[2:], ups):
            self.assertEqual(at, up)
        self.assertFalse(any(c[:2] == ('docker', 'start') and self.plan.bindings['worker'].container in c
                             for c in self.fake.calls))
        self.assertEqual(self.controller.model['services']['api']['volumes'],
                         m.decode(compose_json(self.fake.model))['services']['api']['volumes'])
        recovery = self.controller.backup / 'release-alignment.json'
        self.assertEqual(stat.S_IMODE(recovery.stat().st_mode), 0o600)
        original = m.decode(recovery.read_bytes())['originals']['api']
        self.assertEqual(next(v for v in original['mounts'] if v['Destination'] == '/opt/release')['Source'],
                         '/synthetic/old-release')
        self.assertNotIn(SYNTHETIC_KEY, recovery.read_text())

    def test_verifier_failure_before_stop_and_recheck_failure_never_up_or_old_resume(self):
        with patch.object(self.gate, 'verify', side_effect=m.Refusal):
            self.assertFalse(self.result()['ok'])
        self.assertFalse(any('up' in c or c[:2] == ('docker', 'stop') for c in self.fake.calls))
        self.assertTrue(self.controller.backup.is_dir())
        self.assertEqual(list(self.controller.backup.iterdir()), [])

    def test_missing_seal_and_unbound_verifier_sources_fail_closed(self):
        model = self.captured()
        for value in (None, True, b'', b'x' * 31, b'x' * 33, b'x' * 16385):
            with patch.object(self.gate, 'verify', return_value=value):
                with self.assertRaises(m.Refusal):
                    self.controller.verify_release(model)
        with patch.object(self.gate, 'sources', {}):
            with self.assertRaises(m.Refusal):
                self.controller.verify_release(model)
        self.assertEqual(self.fake.calls, [])
        self.assertIsNone(self.controller.release_seal)

    def test_loader_verifies_all_sources_before_executing_captured_module_and_factory(self):
        runner = SimpleNamespace(deadline=m.time.monotonic() + 600)
        attempt = 'd' * 32
        events, factory_calls = [], []
        read = m.public_source_bytes
        gate = SimpleNamespace(sources=dict(m.RELEASE_VERIFIER_PINS), retained=None, last_recheck_stage=None,
                               verify=lambda q: b'S' * 32, recheck=lambda q, s: None)
        def capture(path):
            events.append(('read', str(path.relative_to(self.repo))))
            return read(path)
        def factory(repo, supplied_runner, **kwargs):
            factory_calls.append((repo, supplied_runner, kwargs))
            return gate
        def execute(code, namespace):
            self.assertEqual({p for event, p in events if event == 'read'}, set(self.plan.sources))
            self.assertEqual(code.co_filename, str(self.repo / m.RELEASE_VERIFIER))
            events.append(('execute', code.co_filename))
            namespace['make_release_gate'] = factory
            namespace['ReleaseRefused'] = type('ReleaseRefused', (Exception,), {'__module__': namespace['__name__']})
            namespace['RECHECK_STAGES'] = m.RELEASE_RECHECK_STAGES
            namespace['RECHECK_CATEGORIES'] = m.RELEASE_RECHECK_CATEGORIES
        with patch.object(m, 'public_source_bytes', side_effect=capture), \
             patch.object(m, 'exec', side_effect=execute, create=True), \
             patch.object(m.os, 'mkdir', side_effect=AssertionError('NO_LOADER_PRIVATE_WRITE')):
            adapter = m.load_release_gate(self.repo, self.plan, runner,
                                          deadline=runner.deadline, attempt_id=attempt)
            self.assertIsInstance(adapter, m.PinnedReleaseGate)
            self.assertIs(adapter._gate, gate)
            self.assertEqual(adapter._refusal_type.__module__, '_dip_pinned_preservation_release')
        self.assertEqual(factory_calls, [(self.repo, runner, {'deadline': runner.deadline, 'attempt_id': attempt})])
        self.assertEqual(events[-1][0], 'execute')
        self.assertNotIn('_dip_pinned_preservation_release', sys.modules)
        self.assertEqual(self.fake.calls, [])

    def test_loader_tampered_module_or_test_never_executes_or_calls_engine(self):
        runner = SimpleNamespace(deadline=m.time.monotonic() + 600)
        for relative in m.RELEASE_VERIFIER_PINS:
            path = self.repo / relative
            before = path.read_bytes()
            path.write_bytes(before + b'\n# INERT_TAMPER\n')
            with patch.object(m, 'exec', side_effect=AssertionError('NO_UNVERIFIED_EXEC'), create=True) as execute:
                with self.assertRaises(m.Refusal):
                    m.load_release_gate(self.repo, self.plan, runner, deadline=runner.deadline, attempt_id='d' * 32)
                execute.assert_not_called()
            path.write_bytes(before)
        with self.assertRaises(m.Refusal):
            m.load_release_gate(self.repo, self.plan, runner, deadline=runner.deadline + 1, attempt_id='d' * 32)
        self.assertEqual(self.fake.calls, [])

    def test_main_factory_is_explicit_same_deadline_attempt_and_no_missing_gate_fallback(self):
        out = SimpleNamespace(buffer=io.BytesIO())
        fake_runner = SimpleNamespace(deadline=m.time.monotonic() + 600)
        with patch.object(m, 'arguments', return_value=self.plan), \
             patch.object(m, 'Runner', return_value=fake_runner), \
             patch.object(m.uuid, 'uuid4', return_value=SimpleNamespace(hex='d' * 32)), \
             patch.object(m, 'load_release_gate', return_value=self.gate) as load, \
             patch.object(m, 'Controller') as controller, patch.object(m.sys, 'stdout', out):
            controller.return_value.activate.return_value = {'ok': True}
            self.assertEqual(m.main([]), 0)
        load.assert_called_once_with(m.REPO, self.plan, fake_runner, deadline=fake_runner.deadline, attempt_id='d' * 32)
        self.assertIs(controller.call_args.kwargs['release_gate'], self.gate)
        self.assertEqual(controller.call_args.kwargs['release_attempt_id'], 'd' * 32)
        self.assertNotIn('release_gate', out.buffer.getvalue().decode())
        out = SimpleNamespace(buffer=io.BytesIO())
        with patch.object(m, 'arguments', return_value=self.plan), \
             patch.object(m, 'load_release_gate', side_effect=RuntimeError(SYNTHETIC_KEY)), \
             patch.object(m, 'Controller') as controller, patch.object(m.sys, 'stdout', out):
            self.assertEqual(m.main([]), 1)
        controller.assert_not_called()
        self.assertNotIn(SYNTHETIC_KEY.encode(), out.buffer.getvalue())

    def test_retained_verifier_identity_is_private_hold_not_stand_failstop_or_output(self):
        attempt, actor = 'd' * 32, 'f' * 64
        self.controller.release_attempt_id = attempt
        self.gate.retained = {'name': 'dip-preservation-release-' + attempt, 'id': actor}
        with patch.object(self.gate, 'verify', side_effect=RuntimeError(SYNTHETIC_KEY)), \
             patch.object(self.controller, 'fail_stop', side_effect=AssertionError('NO_STAND_STOP')):
            result = self.result()
        self.assertEqual(result, {'ok': False, 'phase': 'preflight', 'uncertain': True,
                                  'manualReconciliationRequired': True})
        self.assertFalse(self.controller.touched)
        self.assertTrue((self.controller.root / '.trivy-refresh.lock' / 'KEY_ACTIVATION_HOLD.json').is_file())
        retained = self.controller.backup / 'release-verifier-retained.json'
        self.assertEqual(m.decode(retained.read_bytes()), self.gate.retained)
        self.assertEqual(stat.S_IMODE(retained.stat().st_mode), 0o600)
        for private in (actor, attempt, SYNTHETIC_KEY, str(self.controller.backup)):
            self.assertNotIn(private, json.dumps(result))
        self.assertFalse(any(c[:2] in (('docker', 'stop'), ('docker', 'start'), ('docker', 'create')) or 'up' in c
                             for c in self.fake.calls))

    def retained_persistence_failure(self, failure):
        # Qualification has no precreated scratch directory: exercise retention's
        # fallback mkdir, while rollout now creates its OWN directory before seal.
        self.plan = replace(self.plan, qualify_release_only=True)
        self.controller.plan = self.fake.plan = self.plan
        attempt, actor = 'd' * 32, 'f' * 64
        self.controller.release_attempt_id = attempt
        self.gate.retained = {'name': 'dip-preservation-release-' + attempt, 'id': actor}
        marker = self.controller.root / '.trivy-refresh.lock' / 'KEY_ACTIVATION_HOLD.json'
        write, sync = m.private_write, m.sync_directory
        failures = []
        def refuse():
            self.assertTrue(marker.is_file())
            self.assertTrue(self.controller.release_retained)
            failures.append(failure)
            raise OSError(SYNTHETIC_KEY)
        def write_detail(path, data):
            if path.name == 'release-verifier-retained.json':
                refuse()
            return write(path, data)
        def sync_selected(path):
            if (failure == 'backup-fsync' and path == self.controller.backup or
                    failure == 'hold-fsync' and path == marker.parent):
                refuse()
            return sync(path)
        with patch.object(self.gate, 'verify', side_effect=RuntimeError(SYNTHETIC_KEY)), \
             patch.object(self.controller, 'fail_stop', side_effect=AssertionError('NO_STAND_STOP')), \
             patch.object(m.tempfile, 'mkdtemp', side_effect=lambda **kwargs: refuse()) if failure == 'mkdir' else \
                 patch.object(m, 'private_write', side_effect=write_detail) if failure == 'write' else \
                 patch.object(m, 'sync_directory', side_effect=sync_selected):
            result = self.result()
        self.assertEqual(failures, [failure])
        self.assertEqual(result, {'ok': False, 'phase': 'preflight', 'uncertain': True,
                                  'manualReconciliationRequired': True})
        self.assertFalse(self.controller.touched)
        self.assertTrue(self.controller.hold_requested)
        self.assertTrue(marker.is_file())
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
        self.assertTrue(all(self.fake.records[b.container]['State']['Running']
                            for b in self.plan.bindings.values()))
        self.assertFalse(any(c[:2] in (('docker', 'stop'), ('docker', 'start'), ('docker', 'create')) or 'up' in c
                             for c in self.fake.calls))
        if failure in ('mkdir', 'hold-fsync'):
            self.assertIsNone(self.controller.backup)
        for private in (actor, attempt, SYNTHETIC_KEY, str(self.controller.backup)):
            self.assertNotIn(private, json.dumps(result))

    def test_retained_failure_hold_precedes_backup_mkdir(self):
        self.retained_persistence_failure('mkdir')

    def test_retained_failure_hold_precedes_detail_write(self):
        self.retained_persistence_failure('write')

    def test_retained_failure_hold_precedes_backup_fsync(self):
        self.retained_persistence_failure('backup-fsync')

    def test_retained_failure_hold_marker_survives_its_directory_fsync_failure(self):
        self.retained_persistence_failure('hold-fsync')

    def test_qualification_only_cli_one_verification_no_store_holder_or_live_stops(self):
        self.plan = replace(self.plan, qualify_release_only=True)
        self.controller.plan = self.fake.plan = self.plan
        args = self.cli()
        args[args.index('--activate-existing-api')] = '--qualify-release-only'
        args += ['--align-api-cve-release', '--release-verifier-relative', self.plan.release_verifier,
                 '--release-verifier-test-relative', self.plan.release_verifier_test]
        self.assertEqual(m.arguments(args), self.plan)
        with self.assertRaises(m.Refusal):
            m.arguments(args + ['--activate-existing-api'])
        with patch.object(self.controller, 'preflight', side_effect=AssertionError('NO_WHOLE_PREFLIGHT')), \
             patch.object(self.controller, 'operate_migration', side_effect=AssertionError('NO_MIGRATION')):
            result = self.result()
        self.assertEqual(result, {'ok': True, 'mode': 'release-qualification-only-v1',
                                  'releaseAuthenticated': True, 'standServicesRecreated': False,
                                  'migrationApplied': False, 'providerCalled': False})
        self.assertEqual([event for event, _ in self.events], ['verify'])
        self.assertIsNone(self.controller.backup)
        self.assertFalse(self.controller.touched)
        self.assertFalse((self.controller.root / '.trivy-refresh.lock').exists())
        self.assertFalse(any(c[:2] in (('docker', 'stop'), ('docker', 'start'), ('docker', 'create'), ('docker', 'cp')) or
                             'up' in c or m.SCRIPT_TARGET in c for c in self.fake.calls))

    def test_recheck_failure_before_replacements_keeps_hold_and_never_resumes_old_worker(self):
        checks = []
        def fail_later(request, seal):
            checks.append(None)
            if len(checks) == 2:
                raise m.Refusal()
        with patch.object(self.gate, 'recheck', side_effect=fail_later):
            result = self.result()
        self.assertFalse(result['ok'])
        self.assertTrue(result['manualReconciliationRequired'])
        self.assertFalse(any('up' in c or c[:2] == ('docker', 'start') and
                             self.plan.bindings['worker'].container in c for c in self.fake.calls))


class ReleaseLifecycleTests(unittest.TestCase):
    setUp = ReleaseAlignmentTests.setUp

    def supported_layout_gate(self):
        release = self.controller.root / 'trivy-db-releases' / ('a' * 64)
        (release / 'db').mkdir(parents=True)
        for relative in ('descriptor.json', 'descriptor.sig', 'bundle.bin', 'db/metadata.json', 'db/trivy.db'):
            (release / relative).write_bytes(b'INERT_PUBLIC_RELEASE_NOT_NATIVE')
        source = str(release)
        for role in ('api', 'worker'):
            service = self.fake.model['services'][role]
            for mount in service['volumes']:
                if mount['type'] == 'bind':
                    mount['source'] = source + ('/db' if mount['target'] == '/tmp/trivy/db' else '')
            if role == 'worker':
                record = self.fake.records[self.plan.bindings[role].container]
                for mount in record['Mounts']:
                    if mount['Type'] == 'bind':
                        mount['Source'] = source + ('/db' if mount['Destination'] == '/tmp/trivy/db' else '')
                for mount in record['HostConfig']['Mounts']:
                    mount['Source'] = source + ('/db' if mount['Target'] == '/tmp/trivy/db' else '')
        def align_new(record):
            if record['Config']['Labels']['com.docker.compose.service'] == 'api':
                actual, configured = m.release_mount(record)
                actual['Source'] = configured['Source'] = source
        self.fake.new_mutation = align_new
        stamp = lambda st: (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_uid, st.st_gid,
                            st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        def inventory():
            # Same full fields/ancestor chain as the strict seal, on OWN inert
            # files only; never execute the verifier, crypto, SQLite or app.
            return {'ancestors': tuple((str(p), stamp(p.lstat())) for p in reversed((release, *release.parents))),
                    'db': stamp((release / 'db').lstat()),
                    'files': {p: (stamp((release / p).lstat()), hashlib.sha256((release / p).read_bytes()).hexdigest())
                              for p in ('descriptor.json', 'descriptor.sig', 'bundle.bin', 'db/metadata.json', 'db/trivy.db')}}
        baseline, checks = {}, []
        def verify(request):
            self.assertEqual(request['source'], source)
            self.assertIsNotNone(self.controller.backup)
            self.assertEqual(list(self.controller.backup.iterdir()), [])
            self.assertEqual(stat.S_IMODE(self.controller.backup.stat().st_mode), 0o700)
            baseline['inventory'] = inventory()
            baseline['rootEntries'] = {p.name for p in self.controller.root.iterdir()}
            return b'S' * 32
        def recheck(request, seal):
            self.assertEqual(request['source'], source)
            self.assertEqual(seal, b'S' * 32)
            self.assertEqual(inventory(), baseline['inventory'])
            self.assertEqual({p.name for p in self.controller.root.iterdir()}, baseline['rootEntries'])
            checks.append(len(self.fake.calls))
        self.gate.verify, self.gate.recheck = verify, recheck
        return checks

    def test_supported_layout_preparation_first_recheck_keeps_full_ancestor_seal(self):
        checks = self.supported_layout_gate()
        self.plan = replace(self.plan, prepare_rollout_only=True)
        self.controller.plan = self.fake.plan = self.plan
        self.controller.observation = m.PreparationObservation()
        with patch.object(self.controller, 'operate_migration', side_effect=AssertionError('NO_MIGRATION')) as migrate:
            result = self.controller.activate()
        self.assertTrue(result['ok'])
        self.assertEqual(len(checks), 1)
        migrate.assert_not_called()
        self.assertFalse(self.controller.touched)
        self.assertTrue(self.controller.compiled.is_file())

    def test_supported_layout_production_three_rechecks_have_no_new_root_entries(self):
        checks = self.supported_layout_gate()
        result = self.controller.activate()
        self.assertTrue(result['ok'])
        self.assertEqual(len(checks), 3)
        self.assertEqual(sum('up' in command for command in self.fake.calls), 2)
        self.assertTrue(all('--force-recreate' in command for command in self.fake.calls if 'up' in command))

    def test_exact_verified_exception_only_and_private_retention_forwarded(self):
        class Expected(Exception):
            def __init__(self, *args, fixed_stage=None, fixed_category=None):
                self.fixed_stage, self.fixed_category = fixed_stage, fixed_category
                super().__init__(*args)
        class Subclass(Expected):
            pass
        Unrelated = type('Expected', (Exception,), {})
        raw = SimpleNamespace(sources={'INERT': 'PUBLIC'}, retained={'name': 'INERT', 'id': None},
                              verify=unittest.mock.Mock(), recheck=unittest.mock.Mock())
        adapter = m.PinnedReleaseGate(raw, Expected)
        self.assertEqual(adapter.sources, raw.sources)
        self.assertEqual(adapter.retained, raw.retained)
        for operation, args in ((adapter.verify, ({},)), (adapter.recheck, ({}, b'S' * 32))):
            method = raw.verify if len(args) == 1 else raw.recheck
            method.side_effect = Expected(SYNTHETIC_KEY, **({'fixed_stage': 'INVENTORY_EQUALITY',
                                          'fixed_category': 'PREDICATE_REFUSED'} if len(args) == 2 else {}))
            with self.assertRaises(m.PinnedReleaseRefusal) as refusal:
                operation(*args)
            self.assertNotIn(SYNTHETIC_KEY, str(refusal.exception))
            for failure in (Subclass(SYNTHETIC_KEY), Unrelated(SYNTHETIC_KEY), RuntimeError(SYNTHETIC_KEY)):
                method.side_effect = failure
                with self.assertRaises(type(failure)) as propagated:
                    operation(*args)
                self.assertIs(propagated.exception, failure)

    def test_existing_backup_is_never_adopted_or_replaced(self):
        other = self.controller.root / 'INERT_FOREIGN_DIRECTORY'
        other.mkdir(mode=0o700)
        self.controller.backup = other
        with patch.object(self.gate, 'verify', side_effect=AssertionError('NO_VERIFY')) as verify:
            result = self.controller.activate()
        self.assertFalse(result['ok'])
        self.assertIs(self.controller.backup, other)
        self.assertTrue(other.is_dir())
        verify.assert_not_called()


class ReleaseAttributionTests(unittest.TestCase):
    class Expected(Exception):
        def __init__(self, *, fixed_stage=None, fixed_category=None):
            self.fixed_stage, self.fixed_category = fixed_stage, fixed_category
            super().__init__(SYNTHETIC_KEY)  # Must never become public text.

    def observed(self, failure, *, now=None, callback=None):
        now = [0.0] if now is None else now
        observer = m.PreparationObservation(clock=lambda: now[0], callback=callback)
        raw = SimpleNamespace(recheck=unittest.mock.Mock(side_effect=failure), last_recheck_stage='CLOCK_AFTER')
        adapter = m.PinnedReleaseGate(raw, self.Expected)
        return observer, raw, adapter

    def test_all_fixed_exception_stages_categories_not_stale_gate_property(self):
        for stage in m.RELEASE_RECHECK_STAGES:
            for category in m.RELEASE_RECHECK_CATEGORIES:
                with self.subTest(stage=stage, category=category):
                    failure = self.Expected(fixed_stage=stage, fixed_category=category)
                    observer, raw, adapter = self.observed(failure)
                    with self.assertRaises(m.PinnedReleaseRefusal):
                        with m.observed_stage(observer, 'FIRST_RELEASE_RECHECK'):
                            adapter.recheck({}, b'S' * 32)
                    result = observer.receipt({'ok': False})
                    self.assertEqual((result['checkpoint'], result['category']),
                                     ('FIRST_RELEASE_RECHECK__' + stage, category))
                    self.assertIn(result['checkpoint'], m.STAGE_IDS)
                    self.assertNotIn(SYNTHETIC_KEY, json.dumps(result))
                    self.assertLessEqual(len(json.dumps(result)), 4096)
                    raw.recheck.assert_called_once()

    def test_invalid_or_missing_exception_attributes_are_not_normalized(self):
        for stage, category in ((SYNTHETIC_KEY, 'PREDICATE_REFUSED'), ('SOURCE_PINS', SYNTHETIC_KEY),
                                (None, 'PREDICATE_REFUSED'), (b'SOURCE_PINS', 'PREDICATE_REFUSED'),
                                ('SOURCE_PINS', False), ([], 'PREDICATE_REFUSED')):
            failure = self.Expected(fixed_stage=stage, fixed_category=category)
            observer, raw, adapter = self.observed(failure)
            with self.assertRaises(self.Expected) as propagated:
                with m.observed_stage(observer, 'FIRST_RELEASE_RECHECK'):
                    adapter.recheck({}, b'S' * 32)
            self.assertIs(propagated.exception, failure)
            self.assertEqual(observer.first, ('FIRST_RELEASE_RECHECK', 'UNEXPECTED'))
            self.assertNotIn(SYNTHETIC_KEY, json.dumps(observer.receipt({'ok': False})))
        failure = self.Expected()
        del failure.fixed_stage
        del failure.fixed_category
        observer, raw, adapter = self.observed(failure)
        with self.assertRaises(self.Expected):
            adapter.recheck({}, b'S' * 32)
        raw.verify = unittest.mock.Mock(side_effect=failure)
        with self.assertRaises(self.Expected):
            adapter.verify({})

    def test_same_named_and_subclass_exceptions_keep_unexpected(self):
        class Subclass(self.Expected):
            pass
        SameName = type('Expected', (Exception,), {})
        for failure in (Subclass(fixed_stage='SOURCE_PINS', fixed_category='PREDICATE_REFUSED'),
                        SameName(SYNTHETIC_KEY), RuntimeError(SYNTHETIC_KEY)):
            observer, raw, adapter = self.observed(failure)
            with self.assertRaises(type(failure)) as propagated:
                with m.observed_stage(observer, 'FIRST_RELEASE_RECHECK'):
                    adapter.recheck({}, b'S' * 32)
            self.assertIs(propagated.exception, failure)
            self.assertEqual(observer.first, ('FIRST_RELEASE_RECHECK', 'UNEXPECTED'))

    def test_controller_deadline_precedes_verifier_category_and_first_failure_sticks(self):
        now = [0.0]
        failure = self.Expected(fixed_stage='INVENTORY_READ', fixed_category='PREDICATE_REFUSED')
        observer, raw, adapter = self.observed(failure, now=now)
        def expired(*args):
            now[0] = 150.0
            raise failure
        raw.recheck.side_effect = expired
        with self.assertRaises(m.PinnedReleaseRefusal):
            with m.observed_stage(observer, 'FIRST_RELEASE_RECHECK'):
                adapter.recheck({}, b'S' * 32)
        self.assertEqual(observer.first, ('FIRST_RELEASE_RECHECK__INVENTORY_READ', 'CLIENT_TIMEOUT'))
        observer.fail('LOCK_EXIT', OSError(SYNTHETIC_KEY))
        self.assertEqual(observer.first, ('FIRST_RELEASE_RECHECK__INVENTORY_READ', 'CLIENT_TIMEOUT'))
        self.assertEqual(observer.deadline, 150)

    def test_observer_failure_precedes_gate_call_and_cannot_be_overwritten(self):
        def refuse(*args):
            raise RuntimeError(SYNTHETIC_KEY)
        failure = self.Expected(fixed_stage='CLOCK_AFTER', fixed_category='PREDICATE_REFUSED')
        observer, raw, adapter = self.observed(failure, callback=refuse)
        with self.assertRaises(m.StageObserverRefusal):
            with m.observed_stage(observer, 'FIRST_RELEASE_RECHECK'):
                adapter.recheck({}, b'S' * 32)
        raw.recheck.assert_not_called()
        observer.fail('FIRST_RELEASE_RECHECK', m.PinnedReleaseRefusal(
            fixed_stage='CLOCK_AFTER', fixed_category='UNEXPECTED'))
        self.assertEqual(observer.first, ('FIRST_RELEASE_RECHECK', 'OBSERVER_REFUSED'))

    def test_nonrecheck_requires_none_fields_and_never_exports_stale_stage(self):
        raw = SimpleNamespace(verify=unittest.mock.Mock(), last_recheck_stage='INVENTORY_EQUALITY')
        adapter = m.PinnedReleaseGate(raw, self.Expected)
        raw.verify.side_effect = self.Expected()
        with self.assertRaises(m.PinnedReleaseRefusal) as refusal:
            adapter.verify({})
        self.assertIsNone(refusal.exception.fixed_stage)
        self.assertEqual(refusal.exception.fixed_category, 'PREDICATE_REFUSED')
        raw.verify.side_effect = self.Expected(fixed_stage='SOURCE_PINS', fixed_category='UNEXPECTED')
        with self.assertRaises(self.Expected):
            adapter.verify({})


class PreparationTests(unittest.TestCase):
    cli = MigrationTests.cli

    def setUp(self):
        ReleaseAlignmentTests.setUp(self)
        self.plan = replace(self.plan, prepare_rollout_only=True)
        self.controller.plan = self.fake.plan = self.plan
        self.stage_events = []
        self.now = [0.0]
        self.observation = m.PreparationObservation(clock=lambda: self.now[0],
                                                   callback=lambda *event: self.stage_events.append(event))
        self.controller.observation = self.observation

    def result(self):
        with patch.object(self.controller, 'operate_migration', side_effect=AssertionError('NO_MIGRATION')) as migrate, \
             patch.object(self.controller, 'stop', side_effect=AssertionError('NO_STOP')) as stop, \
             patch.object(self.controller, 'create_holder', side_effect=AssertionError('NO_STORE_HOLDER')) as holder:
            result = self.observation.receipt(self.controller.activate())
        migrate.assert_not_called()
        stop.assert_not_called()
        holder.assert_not_called()
        self.assertFalse(self.controller.touched)
        self.assertIsNone(self.controller.holder_started)
        self.assertLessEqual(len(json.dumps(result).encode('ascii')), 4096)
        for private in (SYNTHETIC_KEY, str(self.repo), str(self.controller.backup), 'd' * 32, 'f' * 64):
            self.assertNotIn(private, json.dumps(result))
        self.assertFalse(any('up' in c or c[:2] in (('docker', 'stop'), ('docker', 'start'), ('docker', 'create'),
                                                  ('docker', 'exec'), ('docker', 'cp')) for c in self.fake.calls))
        return result

    def test_prepare_cli_requires_separate_action_alignment_and_complete_grants(self):
        args = self.cli()
        args[args.index('--activate-existing-api')] = '--prepare-rollout-only'
        args += ['--align-api-cve-release', '--release-verifier-relative', self.plan.release_verifier,
                 '--release-verifier-test-relative', self.plan.release_verifier_test]
        self.assertEqual(m.arguments(args), self.plan)
        for extra in ('--activate-existing-api', '--qualify-release-only'):
            with self.assertRaises(m.Refusal):
                m.arguments(args + [extra])
        for plan in (replace(self.plan, align_api_cve_release=False),
                     replace(self.plan, preservation_migration=False),
                     replace(self.plan, qualify_release_only=True),
                     replace(self.plan, additive_migration_authorized=False),
                     replace(self.plan, sources={p: v for p, v in self.plan.sources.items() if p != m.RELEASE_VERIFIER})):
            with self.assertRaises(m.Refusal):
                plan.validate()

    def test_prepare_success_runs_exact_preflight_recheck_private_durability_and_returns(self):
        result = self.result()
        self.assertTrue(result['ok'])
        self.assertEqual(result['checkpoint'], 'COMPLETE')
        self.assertEqual(result['category'], 'NONE')
        self.assertEqual(result['mode'], 'rollout-preparation-only-v1')
        for key in ('standServicesRecreated', 'migrationApplied', 'providerCalled'):
            self.assertIs(result[key], False)
        self.assertTrue(result['preparationOnly'])
        self.assertEqual([event for event, _ in self.events], ['verify', 'recheck'])
        for name in ('compiled.json', 'release-alignment.json'):
            self.assertEqual(stat.S_IMODE((self.controller.backup / name).stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.controller.backup.stat().st_mode), 0o700)
        self.assertFalse(self.controller.hold_requested)
        self.assertFalse((self.controller.root / '.trivy-refresh.lock').exists())
        for gate in ('COMPILED_QUIET', 'COMPILED_RENDER', 'COMPILED_EQUAL', 'AUTH_INPUT', 'NETWORKS', 'VOLUMES',
                     'HOST_CAPACITY', 'ENGINE_MEMORY', 'HELPER_UID_ACCESS', 'WRITER_FENCE', 'STABILITY',
                     'SOURCE_FINAL', 'SECRET_FINAL', 'SELECTOR_FINAL', 'API_SOCKET_GUARD',
                     'FIRST_RELEASE_RECHECK', 'LOCK_EXIT', 'FINAL_ROOT_FSYNC', 'COMPLETE'):
            self.assertIn((gate, 'ENTER'), self.stage_events)
            self.assertIn((gate, 'PASS'), self.stage_events)

    def test_roundtrip_refusal_is_first_closed_gate_no_later_client_or_recheck(self):
        self.fake.roundtrip_mutation = lambda model: model['services']['api']['environment'].update(LLM_ENABLED='false')
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual((result['checkpoint'], result['category']), ('COMPILED_EQUAL', 'PREDICATE_REFUSED'))
        self.assertFalse(result['uncertain'])
        self.assertFalse(result['manualReconciliationRequired'])
        self.assertEqual([event for event, _ in self.events], ['verify'])
        self.assertNotIn(('NETWORKS', 'ENTER'), self.stage_events)
        self.assertTrue(self.controller.compiled.is_file())

    def test_first_recheck_refusal_cannot_fall_through_or_request_activation_hold(self):
        with patch.object(self.gate, 'recheck', side_effect=m.Refusal):
            result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual((result['checkpoint'], result['category']), ('FIRST_RELEASE_RECHECK', 'PREDICATE_REFUSED'))
        self.assertFalse(self.controller.hold_requested)

    def test_verified_recheck_failure_is_fixed_without_fallthrough(self):
        Expected = ReleaseAttributionTests.Expected
        self.gate.recheck = unittest.mock.Mock(side_effect=Expected(
            fixed_stage='INVENTORY_EQUALITY', fixed_category='UNEXPECTED'))
        self.controller.release_gate = m.PinnedReleaseGate(self.gate, Expected)
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual((result['checkpoint'], result['category']),
                         ('FIRST_RELEASE_RECHECK__INVENTORY_EQUALITY', 'UNEXPECTED'))
        self.assertFalse(self.controller.hold_requested)
        self.gate.recheck.assert_called_once()

    def test_deadline_enter_blocks_next_client_without_renewal(self):
        calls_at_failure = []
        def callback(gate, event):
            if (gate, event) == ('NETWORKS', 'ENTER'):
                calls_at_failure.append(len(self.fake.calls))
                self.now[0] = 150.0
        self.observation.callback = callback
        deadline = self.observation.deadline
        result = self.result()
        self.assertEqual((result['checkpoint'], result['category']), ('NETWORKS', 'CLIENT_TIMEOUT'))
        self.assertEqual(calls_at_failure, [len(self.fake.calls)])
        self.assertEqual(self.observation.deadline, deadline)
        self.assertFalse((self.controller.root / '.trivy-refresh.lock').exists())

    def test_callback_pass_failure_closed_and_return_value_has_no_authority(self):
        def callback(gate, event):
            if (gate, event) == ('COMPILED_RENDER', 'PASS'):
                raise RuntimeError(SYNTHETIC_KEY)
            return False
        self.observation.callback = callback
        result = self.result()
        self.assertEqual((result['checkpoint'], result['category']), ('COMPILED_RENDER', 'OBSERVER_REFUSED'))
        self.assertFalse(result['ok'])
        self.assertEqual([event for event, _ in self.events], ['verify'])

    def test_retained_actor_timeout_keeps_existing_own_hold_and_private_record(self):
        self.controller.release_attempt_id = 'd' * 32
        self.gate.retained = {'name': 'dip-preservation-release-' + 'd' * 32, 'id': 'f' * 64}
        def expired(request):
            self.now[0] = 150.0
            raise m.StageTimeout()
        with patch.object(self.gate, 'verify', side_effect=expired):
            result = self.result()
        self.assertEqual((result['checkpoint'], result['category']), ('RELEASE_VERIFY', 'CLIENT_TIMEOUT'))
        self.assertTrue(result['uncertain'])
        self.assertTrue(result['manualReconciliationRequired'])
        self.assertTrue((self.controller.root / '.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json').is_file())
        self.assertTrue((self.controller.backup / 'release-verifier-retained.json').is_file())

    def test_final_root_fsync_refusal_attributed_after_own_lock_exit(self):
        original = m.sync_directory
        def synced(path):
            if path == self.controller.root:
                raise OSError(SYNTHETIC_KEY)
            return original(path)
        with patch.object(m, 'sync_directory', side_effect=synced):
            result = self.result()
        self.assertEqual((result['checkpoint'], result['category']), ('FINAL_ROOT_FSYNC', 'IO_REFUSED'))
        self.assertFalse((self.controller.root / '.trivy-refresh.lock').exists())

    def test_main_uses150_and_shared_observation_not_production600(self):
        runner = SimpleNamespace(deadline=self.observation.deadline)
        output = SimpleNamespace(buffer=io.BytesIO())
        with patch.object(m, 'arguments', return_value=self.plan), patch.object(m, 'Runner', return_value=runner) as factory, \
             patch.object(m, 'load_release_gate', return_value=self.gate), patch.object(m, 'Controller') as controller, \
             patch.object(m.sys, 'stdout', output):
            controller.return_value.activate.return_value = {'ok': True}
            self.assertEqual(m.main([], observation=self.observation), 0)
        factory.assert_called_once_with(m.REPO, unittest.mock.ANY, budget=150, observation=self.observation)
        self.assertIs(controller.call_args.kwargs['observation'], self.observation)
        self.assertEqual(json.loads(output.buffer.getvalue())['mode'], 'rollout-preparation-only-v1')

    def test_prepare_bootstrap_observer_failure_is_fixed_before_source_open(self):
        observation = m.PreparationObservation(callback=lambda *args: (_ for _ in ()).throw(RuntimeError(SYNTHETIC_KEY)))
        with patch.object(m.os, 'open', side_effect=AssertionError('NO_SOURCE_OPEN')) as opened:
            with self.assertRaises(m.StageObserverRefusal):
                m.load_stand_composition(observation)
        opened.assert_not_called()
        receipt = observation.receipt({'ok': False})
        self.assertEqual((receipt['checkpoint'], receipt['category']), ('BOOTSTRAP', 'OBSERVER_REFUSED'))
        self.assertNotIn(SYNTHETIC_KEY, json.dumps(receipt))

    def test_argument_failure_is_closed_before_gate_load_or_client(self):
        output = SimpleNamespace(buffer=io.BytesIO())
        with patch.object(m, 'arguments', side_effect=m.Refusal), \
             patch.object(m, 'load_release_gate', side_effect=AssertionError('NO_GATE')) as gate, \
             patch.object(m, 'Runner', side_effect=AssertionError('NO_CLIENT')) as runner, \
             patch.object(m.sys, 'stdout', output):
            self.assertEqual(m.main([], observation=self.observation), 1)
        receipt = json.loads(output.buffer.getvalue())
        self.assertEqual((receipt['checkpoint'], receipt['category']), ('ARGUMENTS', 'PREDICATE_REFUSED'))
        self.assertFalse(receipt['ok'])
        gate.assert_not_called()
        runner.assert_not_called()

    def test_lock_exit_failure_is_fixed_and_does_not_claim_complete(self):
        original = Path.rmdir
        def remove(path):
            if path == self.controller.root / '.trivy-refresh.lock':
                raise OSError(SYNTHETIC_KEY)
            return original(path)
        with patch.object(Path, 'rmdir', remove):
            result = self.result()
        self.assertEqual((result['checkpoint'], result['category']), ('LOCK_EXIT', 'IO_REFUSED'))
        self.assertFalse(result['ok'])
        self.assertNotIn(('FINAL_ROOT_FSYNC', 'ENTER'), self.stage_events)

    def test_runner_read15_preserves_verifier90_and_shared_deadline(self):
        proc = SimpleNamespace(stdout=io.BytesIO(), stderr=io.BytesIO(), wait=unittest.mock.Mock(return_value=0))
        selector = unittest.mock.MagicMock()
        selector.__enter__.return_value = selector
        selector.get_map.return_value = {}
        observation = m.PreparationObservation(clock=lambda: 0.0)
        with patch.object(m.time, 'monotonic', return_value=0.0), \
             patch.object(m.selectors, 'DefaultSelector', return_value=selector), \
             patch.object(m.subprocess, 'Popen', return_value=proc) as launch:
            runner = m.Runner(self.repo, {}, budget=150, observation=observation)
            runner(('docker', 'inspect', '--type', 'container', 'f' * 64), timeout=90)
            self.assertEqual(proc.wait.call_args.kwargs['timeout'], 15)
            proc.stdout, proc.stderr = io.BytesIO(), io.BytesIO()
            runner(('docker', 'start', '--attach', 'f' * 64), timeout=90)
            self.assertEqual(proc.wait.call_args.kwargs['timeout'], 90)
            self.assertEqual(runner.deadline, 150)
            observation.first = ('COMPILED_EQUAL', 'PREDICATE_REFUSED')
            with self.assertRaises(m.StageObserverRefusal):
                runner(('docker', 'info'))
            self.assertEqual(launch.call_count, 2)


class ReviewBoundaryTests(unittest.TestCase):
    """464 B1 / restrictive staged input / last-boundary margin; inert mocks only."""
    setUp = MigrationTests.setUp
    result = MigrationTests.result
    no_up = MigrationTests.no_up

    def rejected_config_image(self, role):
        def drift(record):
            if record['Config']['Labels'].get('com.docker.compose.service') == role:
                record['Config']['Image'] = 'SYNTHETIC_REJECTED_CONFIG_IMAGE'
        self.fake.new_mutation = drift
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'recreate_web' if role == 'web' else 'recreate_pair')
        identity = self.controller.new_roles[role]
        record = self.fake.records[identity]
        self.assertEqual(record['Image'], self.plan.selected_image(role))
        self.assertEqual(record['Config']['Image'], 'SYNTHETIC_REJECTED_CONFIG_IMAGE')
        self.assertFalse(record['State']['Running'])
        self.assertIn(('docker', 'stop', '--time', '5', identity), self.fake.calls)
        self.assertTrue(result['manualReconciliationRequired'])
        self.assertTrue((self.controller.root / '.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json').exists())
        self.assertFalse(any(c[:2] == ('docker', 'start') and c[-1] in
                             [b.container for b in self.plan.bindings.values()] for c in self.fake.calls))
        self.assertTrue(all(not self.fake.records[i]['State']['Running'] for i in self.controller.new_roles.values()))

    def test_own_rejected_web_config_image_stopped_and_hold_retained(self):
        self.rejected_config_image('web')

    def test_own_rejected_worker_config_image_stopped_no_web_up_and_hold_retained(self):
        self.rejected_config_image('worker')
        self.assertEqual(len([c for c in self.fake.calls if 'up' in c]), 1)

    def wrong_actual_image(self, role):
        def foreign(record):
            if record['Config']['Labels'].get('com.docker.compose.service') == role:
                record['Image'] = 'sha256:' + 'f' * 64
        self.fake.new_mutation = foreign
        result = self.result()
        self.assertFalse(result['ok'])
        identity = {'web': '9', 'worker': 'a'}[role] * 64
        self.assertTrue(self.fake.records[identity]['State']['Running'])
        self.assertFalse(any(c[:2] in (('docker', 'stop'), ('docker', 'pause'), ('docker', 'rm')) and identity in c
                             for c in self.fake.calls))
        self.assertNotIn(role, self.controller.new_roles)
        self.assertTrue((self.controller.root / '.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json').exists())

    def test_wrong_actual_web_image_not_stopped_based_on_config_image_name_or_labels(self):
        self.wrong_actual_image('web')

    def test_wrong_actual_worker_image_not_stopped_based_on_config_image_name_or_labels(self):
        self.wrong_actual_image('worker')

    def test_attributed_id_with_foreign_identity_or_labels_never_stopped(self):
        # Simulate drift AFTER attribution; fail_stop must requalify every field.
        role, identity = 'web', '9' * 64
        original = copy.deepcopy(self.fake.records[self.plan.bindings[role].container])
        original['Id'] = identity
        original['Name'] = '/' + m.PROJECT + '-web-1'
        original['Image'] = self.plan.selected_image(role)
        original['Config']['Image'] = 'SYNTHETIC_REJECTED_CONFIG_IMAGE'
        self.controller.compiled = self.repo / 'SYNTHETIC_OWN_COMPILED.json'
        original['Config']['Labels']['com.docker.compose.project.config_files'] = str(self.controller.compiled)
        self.controller.new_roles[role] = identity
        mutations = [lambda r: r.update(Id='f' * 64), lambda r: r.update(Name='/SYNTHETIC_FOREIGN'),
                     lambda r: r.update(Image='sha256:' + 'f' * 64),
                     lambda r: r['Config']['Labels'].update({'com.docker.compose.project': 'SYNTHETIC_FOREIGN'}),
                     lambda r: r['Config']['Labels'].update({'com.docker.compose.service': 'worker'}),
                     lambda r: r['Config']['Labels'].update({'com.docker.compose.project.config_files': '/SYNTHETIC_FOREIGN.json'})]
        for index, mutate in enumerate(mutations):
            record = copy.deepcopy(original)
            mutate(record)
            self.fake.records[identity] = record
            with self.subTest(field=index), self.assertRaises(m.Refusal):
                self.controller.attributed_role(role, record)
            self.fake.calls.clear()
            self.controller.fail_stop()
            self.assertFalse(any(c[:2] in (('docker', 'stop'), ('docker', 'pause'), ('docker', 'rm')) and identity in c
                                 for c in self.fake.calls))
            self.assertTrue(record['State']['Running'])

    def test_readonly_staged_key_accepted_without_open_or_permission_repair(self):
        key = self.repo / 'server/.env.openrouter.local'
        key.chmod(0o400)  # OWN disposable fixture, never a real staged key.
        protected = {self.repo / p for p in ('server/.env.local', 'server/.env.openrouter.local', '.local-auth/stand.env')}
        original_open, original_path_open, original_chmod = m.os.open, Path.open, m.os.chmod
        def guarded_open(path, *a, **kw):
            self.assertNotIn(Path(path), protected)
            return original_open(path, *a, **kw)
        def guarded_path_open(path, *a, **kw):
            self.assertNotIn(Path(path), protected)
            return original_path_open(path, *a, **kw)
        def guarded_chmod(path, *a, **kw):
            self.assertNotIn(Path(path), protected)
            return original_chmod(path, *a, **kw)
        with (patch.object(m.os, 'open', side_effect=guarded_open),
              patch.object(Path, 'open', guarded_path_open),
              patch.object(m.os, 'chmod', side_effect=guarded_chmod)):
            self.assertTrue(self.result()['ok'])
        self.assertEqual(stat.S_IMODE(key.lstat().st_mode), 0o400)

    def test_recovery_secret_0400_remains_rejected_by_generic_0600_policy(self):
        key = self.repo / 'server/.env.openrouter.local'
        key.chmod(0o400)
        self.assertEqual(stat.S_IMODE(m.staged_key_metadata(key)[2]), 0o400)
        with self.assertRaises(m.Refusal):
            m.path_metadata(key, secret=True)  # Recovery/HOLD policy not relaxed.
        recovery = self.repo / 'SYNTHETIC_HOLD.json'
        m.private_write(recovery, b'{"synthetic":true}')
        self.assertEqual(stat.S_IMODE(m.path_metadata(recovery, secret=True)[2]), 0o600)
        recovery.chmod(0o400)
        with self.assertRaises(m.Refusal):
            m.path_metadata(recovery, secret=True)

    def test_other_existing_env_inputs_still_require_0600_without_repair(self):
        legacy = self.repo / 'server/.env.local'
        legacy.chmod(0o400)
        self.assertFalse(self.result()['ok'])
        self.assertEqual(self.fake.calls, [])
        self.assertEqual(stat.S_IMODE(legacy.lstat().st_mode), 0o400)

    def test_apply_margin_rechecked_after_final_revalidation_before_original_exec(self):
        clock = [0.0]
        original = self.controller.revalidate_export
        def slow_final_check(stage):
            original(stage)
            if self.controller.phase == 'apply_migration' and stage == 'plan':
                clock[0] = 56.0  # Outer180 passed; inner60 would incorrectly pass.
        self.controller.revalidate_export = slow_final_check
        with patch.object(m.time, 'monotonic', side_effect=lambda: clock[0]):
            result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'apply_migration')
        self.assertFalse(any('apply-migration' in c for c in self.fake.calls))
        self.no_up()
        self.assertEqual(self.controller.exports, {'pre'})
        self.assertEqual(self.controller.material_exports, {'plan'})
        self.assertTrue(self.fake.records[self.controller.helper_id]['State']['Paused'])
        self.assertTrue((self.controller.root / '.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json').exists())
        self.assertEqual(m.HOLDER_MS, 240000)

    def test_host_capacity_rechecked_after_apply_guards_before_original_exec(self):
        space = type('SyntheticSpace', (), {})
        def available(path):
            result = space()
            result.free = m.GIB if self.controller.phase == 'apply_migration' else 8 * m.GIB
            return result
        with patch.object(m.shutil, 'disk_usage', side_effect=available):
            result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'apply_migration')
        self.assertFalse(any('apply-migration' in c for c in self.fake.calls))
        self.no_up()
        self.assertTrue((self.controller.root / '.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json').exists())


class SmallAdmissionTests(unittest.TestCase):
    """Rejection-only profile; fake counters, inert bytes, mocked signal APIs."""
    setUp = MigrationTests.setUp
    result = MigrationTests.result
    no_up = MigrationTests.no_up

    def refused_before_apply(self):
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertFalse(any('apply-migration' in c for c in self.fake.calls))
        self.no_up()
        self.assertTrue((self.controller.root / '.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json').exists())
        if self.controller.helper_id:
            self.assertTrue(self.fake.records[self.controller.helper_id]['State']['Paused'])
        return result

    def fixture(self):
        files = self.fake.snapshot_files['pre']
        return json.loads(files['manifest.json']), synthetic_inventory(files)

    def test_closed_accounting_single_private_cgroup_and_timer_order(self):
        self.assertTrue(self.result()['ok'])
        calls = self.fake.calls
        accounting = next(i for i, c in enumerate(calls) if m.SMALL_ACCOUNTING_CODE in c)
        apply = next(i for i, c in enumerate(calls) if 'apply-migration' in c)
        export = next(i for i, c in enumerate(calls) if c[:2] == ('docker', 'cp') and '/backup/migration/.' in c[2])
        self.assertLess(export, accounting)
        self.assertLess(accounting, apply)
        create = next(c for c in calls if c[:2] == ('docker', 'create'))
        self.assertEqual(create[create.index('--cgroupns') + 1], 'private')
        self.assertEqual(create[create.index('--memory') + 1], '2g')
        self.assertEqual(m.HOLDER_MS, 240000)
        self.assertEqual(self.alarm['armed'], [160, 0])
        self.assertEqual(self.alarm['handler'], m.signal.SIG_DFL)
        self.assertIsNone(self.controller.pending_deadline)

    def add_ordinary_file(self):
        data = b'SYNTHETIC_ORDINARY_ONLY'.ljust(m.MIB, b'\0')
        for stage in ('pre', 'post'):
            files = self.fake.snapshot_files[stage]
            relative = 'auth/ordinary.marker'
            files['raw/' + relative] = files['working/' + relative] = data
            manifest = json.loads(files['manifest.json'])
            manifest['entries'].append({'path': relative, 'kind': 'file', 'mode': 0o600,
                                        'uid': 65532, 'gid': 65532, 'sourceIdentity': [1, 15],
                                        'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'sqlite': False})
            manifest['entries'].sort(key=lambda r: r['path'])
            files['manifest.json'] = m.encoded(manifest)

    def test_ordinary_file_over_growth_reserve_in_raw_and_working_not_sealed(self):
        self.add_ordinary_file()
        self.assertTrue(self.result()['ok'])
        projection = self.controller.small_projection
        self.assertEqual(projection['projectedWorking'], projection['projectedRaw'])
        self.assertEqual(projection['projectedWorking'] - projection['projectedImage'], m.MIB)
        manifest = json.loads((self.controller.backup / 'post/manifest.json').read_bytes())
        summary = m.small_snapshot(manifest, self.controller.export_inventories['post'], post=True)
        self.assertGreater(summary['working'], projection['projectedImage'])
        self.assertLessEqual(summary['working'], projection['projectedWorking'])
        self.assertEqual(summary['sealed'], 3 * 4096)

    def test_excess_working_growth_still_holds_before_removal_or_apps(self):
        self.add_ordinary_file()
        self.fake.snapshot_files['post']['working/auth/ordinary.marker'] += b'X' * (m.SMALL_GROWTH + 1)
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'export_post')
        self.no_up()
        self.assertFalse(any(c[:2] == ('docker', 'rm') for c in self.fake.calls))
        self.assertTrue(self.fake.records[self.controller.helper_id]['State']['Paused'])

    def test_same_callback_timer_replacements_refuse_pending_cleanup_and_restore(self):
        # Three distinct disposable attempts, not retries of real state.
        for live in ((77.0, 4.0), (77.0, 0.0), (0.0, 0.0)):
            case = SmallAdmissionTests()
            try:
                case.setUp()
                def replace_timer():
                    case.alarm['timer'] = live
                    case.alarm['armedAt'] = None
                case.fake.operation_after['apply-migration'] = replace_timer
                with self.subTest(timer=live):
                    result = case.result()
                    self.assertFalse(result['ok'])
                    case.no_up()
                    self.assertTrue(case.controller.timer_ownership_lost)
                    self.assertIs(case.alarm['handler'], case.controller.pending_alarm_handler)
                    self.assertEqual(case.alarm['timer'], live)
                    self.assertEqual(case.alarm['armed'], [160])
                    self.assertIsNone(case.controller.cleanup_deadline)
                    self.assertFalse(any(c[:2] == ('docker', 'rm') for c in case.fake.calls))
                    self.assertTrue((case.controller.root / '.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json').exists())
            finally:
                case.doCleanups()

    def test_restoration_checks_live_timer_even_without_a_pending_checkpoint(self):
        clock = [0.0]
        with patch.object(m.time, 'monotonic', side_effect=lambda: clock[0]):
            self.controller.holder_started = 0.0
            self.controller.start_pending_window()
            self.alarm['timer'], self.alarm['armedAt'] = (77.0, 4.0), None
            with self.assertRaises(m.Refusal):
                self.controller.end_pending_window()
        self.assertEqual(self.alarm['armed'], [160])
        self.assertEqual(self.alarm['timer'], (77.0, 4.0))
        self.assertIs(self.alarm['handler'], self.controller.pending_alarm_handler)

    def test_replacement_during_cleanup_cannot_be_cancelled_by_finally(self):
        original = self.controller.fail_stop
        def failed_cleanup():
            self.alarm['timer'], self.alarm['armedAt'] = (8.0, 2.0), None
            original()
        self.controller.fail_stop = failed_cleanup
        self.fake.receipt_override['apply-migration'] = m.encoded({'code': 'IO_FAILURE', 'ok': False})
        self.assertFalse(self.result()['ok'])
        self.no_up()
        self.assertEqual(len(self.alarm['armed']), 2)
        self.assertEqual(self.alarm['armed'][0], 160)
        self.assertLessEqual(self.alarm['armed'][1], 20)
        self.assertEqual(self.alarm['timer'], (8.0, 2.0))
        self.assertIs(self.alarm['handler'], self.controller.pending_alarm_handler)
        self.assertTrue(self.controller.timer_ownership_lost)

    def test_early_callback_is_not_genuine_owned_expiry(self):
        clock = [0.0]
        with patch.object(m.time, 'monotonic', side_effect=lambda: clock[0]):
            self.controller.holder_started = 0.0
            self.controller.start_pending_window()
            with self.assertRaises(m.Refusal):
                self.alarm['handler'](m.signal.SIGALRM, None)
            with self.assertRaises(m.Refusal):
                self.controller.end_pending_window()
        self.assertFalse(self.controller.owned_timer_expired)
        self.assertTrue(self.controller.timer_ownership_lost)
        self.assertEqual(self.alarm['armed'], [160])

    def test_aggregate_raw_working_sealed_manifest_file_directory_caps(self):
        manifest, inventory = self.fixture()
        for prefix, limit in (('raw/', m.SMALL_RAW), ('working/', m.SMALL_IMAGE), ('sealed/', m.SMALL_IMAGE)):
            records = copy.deepcopy(inventory)
            next(r for r in records if r['kind'] == 'file' and r['path'].startswith(prefix))['bytes'] = limit + 1
            with self.subTest(root=prefix), self.assertRaises(m.Refusal):
                m.small_snapshot(manifest, records)
        records = copy.deepcopy(inventory)
        next(r for r in records if r['path'] == 'manifest.json')['bytes'] = m.SMALL_MANIFEST + 1
        with self.assertRaises(m.Refusal):
            m.small_snapshot(manifest, records)
        for kind, count in (('file', 129), ('directory', 34)):
            records = inventory + [{'path': 'raw/SYNTHETIC_' + str(i), 'kind': kind, 'bytes': 0} for i in range(count)]
            with self.subTest(kind=kind), self.assertRaises(m.Refusal):
                m.small_snapshot(manifest, records)

    def test_small_raw_does_not_admit_high_recovered_extent_or_unknown_modes(self):
        manifest, inventory = self.fixture()
        for kind in ('wal', 'empty-wal', 'journal', 'empty-journal', 'unknown'):
            bad = copy.deepcopy(manifest)
            bad['stores'][0]['recovery']['kind'] = kind
            with self.subTest(kind=kind), self.assertRaises(m.Refusal):
                m.small_snapshot(bad, inventory)
        bad = copy.deepcopy(manifest)
        bad['stores'][0]['recovery'].update(kind='wal', pages=8193)
        with self.assertRaises(m.Refusal):
            m.small_snapshot(bad, inventory)
        bad = copy.deepcopy(manifest)
        bad['stores'][0]['recovery']['pages'] = 2
        with self.assertRaises(m.Refusal):
            m.small_snapshot(bad, inventory)

    def test_all_rows_schema_generated_columns_and_encoded_work_caps(self):
        manifest, inventory = self.fixture()
        bad = copy.deepcopy(manifest)
        table = bad['stores'][0]['logical']['tables'][0]
        table.update(rows=10001, rowHashes=['1' * 64] * 10001)
        with self.assertRaises(m.Refusal):
            m.small_snapshot(bad, inventory)
        bad = copy.deepcopy(manifest)
        bad['stores'][0]['logical']['schema']['objects'] = ['x' * (256 * 1024)]
        with self.assertRaises(m.Refusal):
            m.small_snapshot(bad, inventory)
        bad = copy.deepcopy(manifest)
        bad['stores'][0]['logical']['tables'][0]['columns'][0]['hidden'] = '2'
        with self.assertRaises(m.Refusal):
            m.small_snapshot(bad, inventory)
        bad = copy.deepcopy(manifest)
        table = bad['stores'][0]['logical']['tables'][0]
        table.update(rows=2000, rowHashes=['1' * 64] * 2000, columns=[{'hidden': '0'}] * 256)
        with self.assertRaises(m.Refusal):
            m.small_snapshot(bad, inventory)

    def test_plan_clone_planbytes_projection_and_closed_profile_rejections(self):
        self.assertTrue(self.result()['ok'])
        manifest = json.loads((self.controller.backup / 'pre/manifest.json').read_bytes())
        inventory = self.controller.export_inventories['plan']
        plan = json.loads((self.controller.backup / 'plan/plan.json').read_bytes())
        pre = m.small_snapshot(manifest, self.controller.export_inventories['pre'])
        pre['modes'] = self.controller.small_modes
        projection = m.small_plan(plan, inventory, manifest, pre)
        self.assertLessEqual(projection['finalRetained'], 256 * m.MIB)
        self.assertLessEqual(projection['journalReserve'], 128 * m.MIB)
        for name, size in (('auth.sqlite', m.SMALL_IMAGE + 1), ('plan.json', m.SMALL_PLAN + 1),
                           ('auth.sqlite', 3 * m.MIB)):
            bad = copy.deepcopy(inventory)
            next(r for r in bad if r['path'] == name)['bytes'] = size
            with self.subTest(file=name, size=size), self.assertRaises(m.Refusal):
                m.small_plan(plan, bad, manifest, pre)
        bad = copy.deepcopy(plan)
        bad['profile']['oldAuthSource'] = 'f' * 64
        with self.assertRaises(m.Refusal):
            m.small_plan(bad, inventory, manifest, pre)
        bad = copy.deepcopy(plan)
        bad['ledger']['policies'] = ['synthetic'] * 10000
        with self.assertRaises(m.Refusal):
            m.small_plan(bad, inventory, manifest, pre)
        with self.assertRaises(m.Refusal):
            m.small_plan(plan, inventory, manifest, dict(pre, allocated=257 * m.MIB))

    def test_malformed_accounting_and_snapshot_pressure_have_no_rw_authority(self):
        self.fake.accounting['memoryCurrent'] = True
        self.refused_before_apply()

    def test_measured_charge_can_pass_768_cap_but_fail_projected_1536_cap(self):
        self.fake.accounting['memoryCurrent'] = 700 * m.MIB
        self.refused_before_apply()
        self.assertEqual(self.alarm['armed'], [])

    def test_hostile_cgroup_namespace_never_qualifies_holder_or_exemption(self):
        self.fake.helper_mutation = lambda r: r['HostConfig'].update(CgroupnsMode='host')
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertFalse(any('apply-migration' in c for c in self.fake.calls))
        self.no_up()
        self.assertFalse(any(c[:2] in (('docker', 'pause'), ('docker', 'rm')) for c in self.fake.calls))

    def test_runner_shares_160_deadline_and_restores_only_after_holder_removal(self):
        fake = self.fake
        class InertRunner(m.Runner):
            def __call__(runner, args, **kwargs):
                return fake(args, **kwargs)
        runner = InertRunner(self.repo, {}, budget=600)
        original = runner.deadline
        self.controller.run = runner
        def applying():
            self.assertEqual(runner.deadline, self.controller.pending_deadline)
            self.assertLess(runner.deadline, original)
        self.fake.operation_after['apply-migration'] = applying
        self.assertTrue(self.result()['ok'])
        self.assertEqual(runner.deadline, original)
        self.assertTrue(self.controller.helper_removed)

    def test_lost_timer_ownership_never_overwrites_foreign_handler_or_timer(self):
        foreign = lambda *_: None
        def lost():
            self.alarm['handler'] = foreign
            self.alarm['timer'] = (9.0, 0.0)
        self.fake.operation_after['apply-migration'] = lost
        self.assertFalse(self.result()['ok'])
        self.no_up()
        self.assertIs(self.alarm['handler'], foreign)
        self.assertEqual(self.alarm['timer'], (9.0, 0.0))
        self.assertEqual(self.alarm['armed'], [160])
        self.assertTrue((self.controller.root / '.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json').exists())

    def test_alarm_install_failure_refuses_before_apply_and_preserves_hold(self):
        with patch.object(m.signal, 'setitimer', side_effect=ValueError('SYNTHETIC_TIMER_FAILURE')):
            result = self.result()
        self.assertFalse(result['ok'])
        self.assertFalse(any('apply-migration' in c for c in self.fake.calls))
        self.no_up()
        self.assertTrue((self.controller.root / '.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json').exists())

    def test_missing_or_pressure_accounting_never_applies_originals(self):
        self.fake.accounting.pop('memoryMax')
        self.refused_before_apply()
        self.assertEqual(self.alarm['armed'], [])

    def test_each_pressure_counter_is_rejection_only(self):
        # Fresh disposable fixture per subcase, no reuse/retry of an attempt.
        values = {'memoryCurrent': 769 * m.MIB, 'memoryMax': 3 * m.GIB, 'swapMax': 1,
                  'vmAvailable': 2 * m.GIB, 'authFree': 128 * m.MIB - 1,
                  'dataFree': 128 * m.MIB - 1, 'backupAllocated': 257 * m.MIB}
        for key, value in values.items():
            case = SmallAdmissionTests()
            try:
                case.setUp()
                case.fake.accounting[key] = value
                with self.subTest(key=key):
                    case.refused_before_apply()
            finally:
                case.doCleanups()

    def test_private_header_mixed_modes_refuse_without_mode_repair(self):
        files = self.fake.snapshot_files['pre']
        data = bytearray(files['raw/auth/auth.sqlite'])
        data[18:20] = b'\x02\x01'
        files['raw/auth/auth.sqlite'] = bytes(data)
        manifest = json.loads(files['manifest.json'])
        next(e for e in manifest['entries'] if e['path'] == 'auth/auth.sqlite')['sha256'] = hashlib.sha256(data).hexdigest()
        files['manifest.json'] = m.encoded(manifest)
        self.refused_before_apply()
        self.assertEqual(files['raw/auth/auth.sqlite'][18:20], b'\x02\x01')

    def test_foreign_timer_and_handler_refuse_before_daemon_access(self):
        self.alarm['timer'] = (10.0, 0.0)
        self.assertFalse(self.result()['ok'])
        self.assertEqual(self.fake.calls, [])
        self.assertEqual(self.alarm['armed'], [])
        self.alarm['timer'] = (0.0, 0.0)
        self.alarm['handler'] = lambda *_: None
        self.assertFalse(self.result()['ok'])
        self.assertEqual(self.fake.calls, [])
        self.assertEqual(self.alarm['armed'], [])

    def test_elapsed_45s_final_admission_not_old_55s_rule(self):
        clock = [0.0]
        original = self.controller.revalidate_export
        def slow(stage):
            original(stage)
            if self.controller.phase == 'apply_migration' and stage == 'plan':
                clock[0] = 45.001
        self.controller.revalidate_export = slow
        with patch.object(m.time, 'monotonic', side_effect=lambda: clock[0]):
            self.refused_before_apply()
        self.assertEqual(self.alarm['armed'], [])

    def test_pending_expiration_during_host_work_retains_hold_no_apps(self):
        original = self.controller.revalidate_export
        clock = [0.0]
        def interrupt(stage):
            if self.controller.pending_deadline is not None:
                clock[0] = self.controller.owned_timer_expiry + 0.001
                self.alarm['handler'](m.signal.SIGALRM, None)
            original(stage)
        self.controller.revalidate_export = interrupt
        with patch.object(m.time, 'monotonic', side_effect=lambda: clock[0]):
            result = self.result()
        self.assertFalse(result['ok'])
        self.assertTrue(any('apply-migration' in c for c in self.fake.calls))
        self.no_up()
        self.assertTrue(self.fake.records[self.controller.helper_id]['State']['Paused'])
        self.assertEqual(self.alarm['armed'][0], 160)
        self.assertLessEqual(self.alarm['armed'][1], 20)
        self.assertEqual(self.alarm['armed'][-1], 0)
        self.assertTrue((self.controller.root / '.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json').exists())

    def test_post_size_or_row_forecast_failure_never_removes_baseline_or_starts_apps(self):
        files = self.fake.snapshot_files['post']
        manifest = json.loads(files['manifest.json'])
        table = manifest['stores'][0]['logical']['tables'][0]
        table.update(rows=2, rowHashes=['1' * 64] * 2)
        files['manifest.json'] = m.encoded(manifest)
        self.assertFalse(self.result()['ok'])
        self.no_up()
        self.assertFalse(any(c[:2] == ('docker', 'rm') for c in self.fake.calls))
        self.assertTrue(self.fake.records[self.controller.helper_id]['State']['Paused'])


class WALAdmissionTests(unittest.TestCase):
    """Inert trusted-receipt models only; no real WAL checksum/SQLite execution."""
    setUp = MigrationTests.setUp
    result = MigrationTests.result
    no_up = MigrationTests.no_up
    add_ordinary_file = SmallAdmissionTests.add_ordinary_file

    def wal_fixture(self, relative='auth/auth.sqlite', *, kind='wal', frames=1, commits=1,
                    last=1, main_pages=1, recovered_pages=2, shm=32768):
        for stage in ('pre', 'post'):
            files = self.fake.snapshot_files[stage]
            manifest = json.loads(files['manifest.json'])
            store = next(s for s in manifest['stores'] if s['path'] == relative)
            header = bytearray(files['raw/' + relative][:4096])
            header[18:20] = b'\x02\x02'
            main = bytes(header).ljust(main_pages * 4096, b'\0')
            sealed = bytes(header).ljust(recovered_pages * 4096, b'\0')
            files['raw/' + relative] = main
            files['working/' + relative] = sealed
            files['sealed/' + store['sealed']] = sealed
            raw = next(e for e in manifest['entries'] if e['path'] == relative)
            raw.update(bytes=len(main), sha256=hashlib.sha256(main).hexdigest())
            store.update(bytes=len(sealed), sha256=hashlib.sha256(sealed).hexdigest())
            store['recovery'] = {'format': 'checked-recovery-v1', 'kind': kind,
                                 'pageSize': 4096, 'pages': recovered_pages}
            if kind != 'main':
                store['recovery'].update(frames=frames, commits=commits, lastCommit=last)
                wal = b'' if kind == 'empty-wal' else b'SYNTHETIC_WAL_NOT_CHECKSUM_VALID'.ljust(32 + frames * 4120, b'\0')
                sides = {'-wal': wal}
                if shm is not None:
                    sides['-shm'] = b'SYNTHETIC_SHM'.ljust(shm, b'\0')
                for suffix, data in sides.items():
                    path = relative + suffix
                    files['raw/' + path] = files['working/' + path] = data
                    manifest['entries'].append({'path': path, 'kind': 'file', 'mode': 0o600,
                                                'uid': 65532, 'gid': 65532, 'sourceIdentity': [1, 16],
                                                'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'sqlite': False})
            # Model an old committed row residing only in WAL/recovered output.
            if commits:
                table = store['logical']['tables'][0]
                table.update(rows=2, rowHashes=['1' * 64, '2' * 64])
            manifest['entries'].sort(key=lambda e: e['path'])
            files['manifest.json'] = m.encoded(manifest)

    def no_original_apply(self):
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertFalse(any('apply-migration' in c for c in self.fake.calls))
        self.no_up()
        self.assertTrue((self.controller.root / '.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json').exists())

    def test_committed_wal_only_row_extended_extent_and_ordinary_partition(self):
        self.wal_fixture()
        self.add_ordinary_file()
        self.assertTrue(self.result()['ok'])
        manifest = json.loads((self.controller.backup / 'pre/manifest.json').read_bytes())
        pre = m.small_snapshot(manifest, self.controller.export_inventories['pre'])
        auth = pre['physical']['auth/auth.sqlite']
        self.assertEqual(auth['main'], 4096)
        self.assertEqual(auth['recovered'], 8192)
        self.assertEqual(auth['wal'], 32 + 4120)
        self.assertEqual(pre['ordinary'], m.MIB)
        self.assertEqual(pre['raw'], pre['ordinary'] + sum(p[k] for p in pre['physical'].values() for k in ('main', 'wal', 'shm')))
        self.assertEqual(pre['rows'], 4)
        projection = self.controller.small_projection
        bound = projection['physicalBounds']['auth/auth.sqlite']
        self.assertEqual(bound['main'], 8192 + 256 * 1024)
        self.assertEqual(bound['wal'], auth['wal'] + 32 + 2 * (bound['main'] // 4096) * 4120)
        self.assertEqual(bound['shm'], 128 * 1024)
        self.assertEqual(projection['projectedWorking'], projection['projectedRaw'])
        self.assertGreater(projection['projectedRaw'], projection['projectedImage'] + m.MIB)
        self.assertEqual((self.controller.backup / 'pre/raw/auth/auth.sqlite').read_bytes()[18:20], b'\x02\x02')

    def test_2_2_main_without_sidecars_is_admitted_without_mode_conversion(self):
        self.wal_fixture(kind='main', frames=0, commits=0, last=0, recovered_pages=1, shm=None)
        self.wal_fixture(relative='data/ledger.sqlite', kind='main', frames=0, commits=0, last=0, recovered_pages=1, shm=None)
        self.assertTrue(self.result()['ok'])
        self.assertEqual(self.controller.small_modes, {'auth/auth.sqlite': 2, 'data/ledger.sqlite': 2, 'auth/llm-usage.sqlite': 1})

    def test_empty_wal_and_shm_are_retained_as_presence_not_ordinary(self):
        self.wal_fixture(kind='empty-wal', frames=0, commits=0, last=0, recovered_pages=1)
        self.assertTrue(self.result()['ok'])
        manifest = json.loads((self.controller.backup / 'pre/manifest.json').read_bytes())
        summary = m.small_snapshot(manifest, self.controller.export_inventories['pre'])
        auth = summary['physical']['auth/auth.sqlite']
        self.assertTrue(auth['walPresent'])
        self.assertEqual(auth['wal'], 0)
        self.assertTrue(auth['shmPresent'])
        self.assertEqual(summary['ordinary'], 0)

    def test_header_only_checked_wal_generation_is_admitted(self):
        self.wal_fixture(frames=0, commits=0, last=0, recovered_pages=1, shm=None)
        self.assertTrue(self.result()['ok'])

    def test_complete_uncommitted_tail_and_smaller_committed_extent_are_admitted(self):
        self.wal_fixture(frames=2, commits=1, last=1, main_pages=3, recovered_pages=2)
        self.assertTrue(self.result()['ok'])
        self.assertEqual(self.controller.small_projection['physicalBounds']['auth/auth.sqlite']['main'], 3 * 4096 + 256 * 1024)

    def test_normal_post_close_can_remove_sidecars_but_not_change_2_2_mode(self):
        self.wal_fixture()
        files = self.fake.snapshot_files['post']
        manifest = json.loads(files['manifest.json'])
        store = next(s for s in manifest['stores'] if s['path'] == 'auth/auth.sqlite')
        files['raw/auth/auth.sqlite'] = files['working/auth/auth.sqlite']
        raw = next(e for e in manifest['entries'] if e['path'] == store['path'])
        raw.update(bytes=store['bytes'], sha256=store['sha256'])
        for suffix in ('-wal', '-shm'):
            files.pop('raw/auth/auth.sqlite' + suffix)
            files.pop('working/auth/auth.sqlite' + suffix)
        manifest['entries'] = [e for e in manifest['entries'] if not e['path'].startswith('auth/auth.sqlite-')]
        store['recovery'] = {'format': 'checked-recovery-v1', 'kind': 'main', 'pageSize': 4096, 'pages': 2}
        files['manifest.json'] = m.encoded(manifest)
        self.assertTrue(self.result()['ok'])

    def test_quota_wal_remains_excluded_before_original_apply(self):
        self.wal_fixture(relative='auth/llm-usage.sqlite')
        self.no_original_apply()

    def test_oversized_shm_refuses_before_original_apply(self):
        self.wal_fixture(shm=128 * 1024 + 1)
        self.no_original_apply()

    def test_summary_frame_count_mismatch_refuses_before_original_apply(self):
        self.wal_fixture()
        files = self.fake.snapshot_files['pre']
        manifest = json.loads(files['manifest.json'])
        next(s for s in manifest['stores'] if s['path'] == 'auth/auth.sqlite')['recovery']['frames'] = 2
        files['manifest.json'] = m.encoded(manifest)
        self.no_original_apply()

    def test_mixed_journal_unknown_or_orphan_sidecars_are_not_ordinary(self):
        self.wal_fixture()
        manifest = json.loads(self.fake.snapshot_files['pre']['manifest.json'])
        inventory = synthetic_inventory(self.fake.snapshot_files['pre'])
        for path in ('raw/auth/auth.sqlite-journal', 'raw/auth/auth.sqlite-other', 'raw/auth/orphan-shm'):
            records = inventory + [{'path': path, 'kind': 'file', 'bytes': 1, 'sha256': '1' * 64}]
            with self.subTest(path=path), self.assertRaises(m.Refusal):
                m.small_snapshot(manifest, records)
        records = [r for r in inventory if r['path'] != 'raw/auth/auth.sqlite-wal']
        with self.assertRaises(m.Refusal):
            m.small_snapshot(manifest, records)

    def test_exported_wal_drift_cannot_pass_inventory_binding(self):
        self.wal_fixture()
        def drift(destination):
            if destination.name == 'pre':
                path = destination / 'raw/auth/auth.sqlite-wal'
                data = bytearray(path.read_bytes())
                data[-1] ^= 1
                path.write_bytes(data)
        self.fake.copy_mutation = drift
        self.no_original_apply()

    def test_post_raw_main_wal_and_shm_exceeding_individual_bounds_hold(self):
        for member in ('main', 'wal', 'shm'):
            case = WALAdmissionTests()
            try:
                case.setUp()
                case.wal_fixture()
                def excess():
                    bound = case.controller.small_projection['physicalBounds']['auth/auth.sqlite']
                    files = case.fake.snapshot_files['post']
                    manifest = json.loads(files['manifest.json'])
                    store = next(s for s in manifest['stores'] if s['path'] == 'auth/auth.sqlite')
                    relative = 'auth/auth.sqlite' + ('' if member == 'main' else '-' + member)
                    if member == 'wal':
                        frames = (bound['wal'] - 32) // 4120 + 1
                        size = 32 + frames * 4120
                        store['recovery']['frames'] = frames
                    else:
                        size = (bound['main'] // 4096 + 1) * 4096 if member == 'main' else bound['shm'] + 1
                    data = files['raw/' + relative].ljust(size, b'X')
                    files['raw/' + relative] = files['working/' + relative] = data
                    next(e for e in manifest['entries'] if e['path'] == relative).update(
                        bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                    files['manifest.json'] = m.encoded(manifest)
                case.fake.operation_after['apply-migration'] = excess
                with self.subTest(member=member):
                    result = case.result()
                    self.assertFalse(result['ok'])
                    self.assertEqual(result['phase'], 'export_post')
                    case.no_up()
                    self.assertFalse(any(c[:2] == ('docker', 'rm') for c in case.fake.calls))
                    self.assertTrue(case.fake.records[case.controller.helper_id]['State']['Paused'])
                    self.assertTrue((case.controller.root / '.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json').exists())
            finally:
                case.doCleanups()

    def test_advisory_shm_changes_do_not_require_cross_snapshot_hash_equality(self):
        self.wal_fixture()
        files = self.fake.snapshot_files['post']
        relative = 'auth/auth.sqlite-shm'
        data = b'POST_ADVISORY_ONLY'.ljust(32768, b'\0')
        files['raw/' + relative] = files['working/' + relative] = data
        manifest = json.loads(files['manifest.json'])
        next(e for e in manifest['entries'] if e['path'] == relative)['sha256'] = hashlib.sha256(data).hexdigest()
        files['manifest.json'] = m.encoded(manifest)
        self.assertTrue(self.result()['ok'])
        self.assertNotEqual((self.controller.backup / 'pre/raw' / relative).read_bytes(),
                            (self.controller.backup / 'post/raw' / relative).read_bytes())

    def test_tiny_raw_wal_cannot_bypass_recovered_extent_cap(self):
        self.wal_fixture()
        manifest = json.loads(self.fake.snapshot_files['pre']['manifest.json'])
        records = synthetic_inventory(self.fake.snapshot_files['pre'])
        store = next(s for s in manifest['stores'] if s['path'] == 'auth/auth.sqlite')
        store['recovery']['pages'] = 8193
        store['bytes'] = 8193 * 4096
        with self.assertRaises(m.Refusal):
            m.small_snapshot(manifest, records)

    def test_peer_checksum_or_provenance_failure_is_not_replaced_by_metadata_admission(self):
        self.wal_fixture()
        self.fake.receipt_override['capture'] = m.encoded({'code': 'INVALID_STORE', 'ok': False})
        self.no_original_apply()
        self.assertFalse(any('plan-migration' in c for c in self.fake.calls))

    def test_post_mode_drift_holds_without_conversion_or_start(self):
        self.wal_fixture(kind='main', frames=0, commits=0, last=0, recovered_pages=1, shm=None)
        files = self.fake.snapshot_files['post']
        manifest = json.loads(files['manifest.json'])
        data = bytearray(files['raw/auth/auth.sqlite'])
        data[18:20] = b'\x01\x01'
        files['raw/auth/auth.sqlite'] = bytes(data)
        next(e for e in manifest['entries'] if e['path'] == 'auth/auth.sqlite')['sha256'] = hashlib.sha256(data).hexdigest()
        files['manifest.json'] = m.encoded(manifest)
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'export_post')
        self.no_up()
        self.assertFalse(any(c[:2] == ('docker', 'rm') for c in self.fake.calls))


class CurrentSourceTests(unittest.TestCase):
    """One synthetic current-profile window; no app/native/Docker execution."""
    def setUp(self):
        ControllerTests.setUp(self)
        self.plan = replace(self.plan, store_versions=None, current_source_profile=True,
                            candidate_api_image='sha256:' + '8' * 64,
                            candidate_source_aggregate=m.CURRENT_SOURCE_AGGREGATE,
                            candidate_source_evidence='DIP-ARTF-999998', original_worker_profile_reviewed=True)
        self.controller.plan = self.fake.plan = self.plan
        candidate = copy.deepcopy(self.fake.images[self.plan.bindings['api'].image])
        candidate['Id'] = self.plan.api_image
        self.fake.images[self.plan.api_image] = candidate
        self.fake.snapshot_files = {stage: synthetic_snapshot(m.CURRENT_SOURCE_VERSIONS) for stage in ('pre', 'post')}
        self.fake.records[self.plan.bindings['api'].container]['Config']['Labels']['com.docker.compose.image'] = self.plan.bindings['api'].image

    def result(self):
        return self.controller.activate()

    def no_up(self):
        self.assertFalse(any('up' in c for c in self.fake.calls))

    def cli(self):
        args = ['--activate-existing-api', '--authorize-preservation-window', '--current-source-profile',
                '--candidate-api-image', self.plan.api_image,
                '--candidate-source-aggregate', self.plan.candidate_source_aggregate,
                '--candidate-source-review-evidence', self.plan.candidate_source_evidence,
                '--confirm-original-worker-profile-reviewed', '--sqlite-helper-relative', m.HELPER_PATH,
                '--startup-review-evidence', self.plan.startup_evidence,
                '--confirm-old-api-db-reads-reviewed', '--authorize-new-backup-sandbox-2g-240s']
        for role, binding in self.plan.bindings.items():
            args.extend(('--' + role + '-container', binding.container, '--' + role + '-image', binding.image))
        for path, sha in self.plan.sources.items():
            args.extend(('--source-sha256', path + '=' + sha))
        return args

    def test_candidate_only_up_after_compatibility_and_pre_export_original_holder_worker(self):
        worker_before = copy.deepcopy(self.fake.records[self.plan.bindings['worker'].container])
        self.assertTrue(self.result()['ok'])
        self.assertEqual(self.controller.observed_versions, m.CURRENT_SOURCE_VERSIONS)
        calls = self.fake.calls
        capture = next(i for i, c in enumerate(calls) if m.SCRIPT_TARGET in c and 'capture' in c)
        compatibility = calls.index(('docker', 'exec', '-i', self.controller.helper_id, 'node',
                                     m.SCRIPT_TARGET, 'compatibility', '/backup/pre'))
        pre = next(i for i, c in enumerate(calls) if c[:2] == ('docker', 'cp') and ':/backup/pre/.' in c[2])
        up = next(i for i, c in enumerate(calls) if 'up' in c)
        compare = next(i for i, c in enumerate(calls) if m.SCRIPT_TARGET in c and 'compare' in c)
        post = next(i for i, c in enumerate(calls) if c[:2] == ('docker', 'cp') and ':/backup/post/.' in c[2])
        self.assertEqual(sorted((capture, compatibility, pre, up, compare, post)),
                         [capture, compatibility, pre, up, compare, post])
        create = next(c for c in calls if c[:2] == ('docker', 'create'))
        self.assertEqual(create[-3], self.plan.bindings['api'].image)
        self.assertEqual(self.fake.records['b' * 64]['Image'], self.plan.api_image)
        self.assertEqual(self.fake.records[self.plan.bindings['worker'].container], worker_before)
        self.assertEqual(self.controller.model['services']['api']['image'], self.plan.api_image)
        self.assertTrue(all(c[-1] == 'api' for c in calls if 'up' in c))
        self.assertFalse(any(c[:2] == ('docker', 'tag') or 'build' in c or 'pull' in c for c in calls))

    def test_raw_four_field_input_comes_only_from_old_env_and_preserves_null_empty_unicode(self):
        raw = {'AUTH_ALLOW_INSECURE_LOCAL_HTTP': '', 'SCAN_BROWSER_ALLOWED_USER_IDS': 'SYNTHETIC_ю$"\\\n'}
        old = self.fake.records[self.plan.bindings['api'].container]
        env = m.env_map(old['Config']['Env'])
        env.update(raw)
        old['Config']['Env'] = [k + '=' + v for k, v in env.items()]
        self.fake.model['services']['api']['environment'].update(raw)
        self.controller.env.update({key: 'SYNTHETIC_WRONG_AMBIENT' for key in m.AUTH_SETTINGS})
        self.assertTrue(self.result()['ok'])
        self.assertEqual(len(self.fake.private_inputs), 1)
        data = self.fake.private_inputs[0]
        value = m.authority_input(data)
        self.assertEqual(set(value), set(m.AUTH_SETTINGS))
        self.assertEqual(value, {key: env.get(key) for key in m.AUTH_SETTINGS})
        self.assertIsNone(value['SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS'])
        self.assertNotIn(m.KEY, value)
        self.assertNotIn('SCAN_JWT_SECRET', value)
        self.assertNotIn(SYNTHETIC_KEY.encode(), data)
        for command in self.fake.calls:
            self.assertNotIn(data.decode(), ' '.join(command))
        self.assertFalse(any(p.name.endswith('settings.json') for p in self.controller.backup.rglob('*')))

    def test_current_source_expectation_is_independent_not_actual_tuple_self_equality(self):
        self.assertEqual(self.plan.expected_versions, {'auth/auth.sqlite': (0, 0), 'data/ledger.sqlite': (0, 14),
                                                     'auth/llm-usage.sqlite': (1145655601, 1)})
        manifest = json.loads(self.fake.snapshot_files['pre']['manifest.json'])
        next(s for s in manifest['stores'] if s['path'] == 'data/ledger.sqlite')['logical']['schema']['userVersion'] = '12'
        self.fake.snapshot_files['pre']['manifest.json'] = m.encoded(manifest)
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'export_pre')
        self.no_up()
        self.assertTrue(self.fake.records[self.controller.helper_id]['State']['Paused'])
        self.assertIsNone(self.controller.observed_versions)

    def test_unknown_or_conflicting_profile_and_unbound_evidence_refuse_before_engine(self):
        cases = [replace(self.plan, current_source_profile='other'),
                 replace(self.plan, store_versions=dict(m.CURRENT_SOURCE_VERSIONS)),
                 replace(self.plan, candidate_api_image=None),
                 replace(self.plan, candidate_api_image=self.plan.bindings['api'].image),
                 replace(self.plan, candidate_source_aggregate='29c3...'),
                 replace(self.plan, candidate_source_aggregate='9' * 64),
                 replace(self.plan, candidate_source_evidence=''),
                 replace(self.plan, original_worker_profile_reviewed=False),
                 replace(self.plan, sources={p: s for p, s in self.plan.sources.items() if p != m.HELPER_PATH})]
        for case in cases:
            self.controller.plan = case
            self.assertFalse(self.result()['ok'])
            self.assertEqual(self.fake.calls, [])

    def test_cli_profile_is_mutually_exclusive_and_full_candidate_pins_required(self):
        self.assertEqual(m.arguments(self.cli()), self.plan)
        for extra in (['--store-version', 'data/ledger.sqlite=0:14'], ['--current-source-profile=unknown']):
            with self.assertRaises(m.Refusal):
                m.arguments(self.cli() + extra)
        missing_worker = [a for a in self.cli() if a != '--confirm-original-worker-profile-reviewed']
        with self.assertRaises(m.Refusal):
            m.arguments(missing_worker)
        self.assertEqual(self.fake.calls, [])

    def test_candidate_image_defaults_platform_config_onbuild_changes_refuse_before_stops(self):
        baseline = copy.deepcopy(self.fake.images[self.plan.api_image])
        changes = [lambda r: r['Config'].update(User='0:0'), lambda r: r['Config'].update(WorkingDir='/other'),
                   lambda r: r['Config'].update(Cmd=['initialize']), lambda r: r['Config'].update(Entrypoint=['other']),
                   lambda r: r['Config'].update(OnBuild=['RUN initialize']),
                   lambda r: r['Config'].update(Env=['PATH=/changed']),
                   lambda r: r['Config'].update(Labels={'UNREVIEWED': 'source'}),
                   lambda r: r.update(Architecture='amd64'), lambda r: r.update(Os='other')]
        for index, mutate in enumerate(changes):
            self.fake.images[self.plan.api_image] = copy.deepcopy(baseline)
            mutate(self.fake.images[self.plan.api_image])
            self.assertFalse(self.result()['ok'], str(index))
            self.assertFalse(any(c[:2] in (('docker', 'stop'), ('docker', 'create')) for c in self.fake.calls))
            self.no_up()

    def test_compatibility_false_is_not_capture_or_match_and_retains_hold(self):
        self.fake.receipt_override['compatibility'] = m.encoded({'code': 'INCOMPATIBLE', 'ok': False})
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'compatibility')
        self.assertTrue(result['manualReconciliationRequired'])
        self.assertTrue(self.fake.records[self.controller.helper_id]['State']['Paused'])
        self.no_up()

    def test_ambiguous_private_stdin_exec_does_not_recreate_or_restart_old_api(self):
        self.fake.fail_on = lambda c: c[:3] == ('docker', 'exec', '-i')
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'compatibility')
        self.no_up()
        self.assertTrue(self.fake.records[self.controller.helper_id]['State']['Paused'])
        self.assertFalse(any(c[:2] == ('docker', 'start') and c[-1] == self.plan.bindings['api'].container for c in self.fake.calls))

    def test_source_drift_after_compatibility_refuses_before_first_up(self):
        self.fake.compatibility_after = lambda: (self.repo / m.HELPER_PATH).write_text('SYNTHETIC_SOURCE_DRIFT')
        self.assertFalse(self.result()['ok'])
        self.no_up()
        self.assertTrue((self.controller.root / '.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json').exists())

    def test_old_auth_env_drift_after_compatibility_refuses_before_first_up(self):
        def drift():
            config = self.fake.records[self.plan.bindings['api'].container]['Config']
            config['Env'] = config['Env'] + ['SCAN_BROWSER_ALLOWED_USER_IDS=SYNTHETIC_DRIFT']
        self.fake.compatibility_after = drift
        self.assertFalse(self.result()['ok'])
        self.no_up()

    def test_container_identity_drift_after_compatibility_prevents_first_up(self):
        def drift():
            self.fake.records[self.plan.bindings['worker'].container]['Image'] = 'sha256:' + 'f' * 64
        self.fake.compatibility_after = drift
        self.assertFalse(self.result()['ok'])
        self.no_up()

    def test_extra_compatibility_receipt_flag_never_reaches_first_up(self):
        self.fake.receipt_override['compatibility'] = m.encoded({'code': 'COMPATIBLE', 'ok': True, 'allState': True})
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'compatibility')
        self.no_up()

    def test_candidate_config_drift_after_gate_prevents_first_up(self):
        self.fake.compatibility_after = lambda: self.fake.images[self.plan.api_image]['Config'].update(User='0:0')
        self.assertFalse(self.result()['ok'])
        self.no_up()

    def test_nonkey_candidate_auth_settings_change_refuses_before_first_stop(self):
        self.fake.model['services']['api']['environment']['SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS'] = 'true'
        self.assertFalse(self.result()['ok'])
        self.assertFalse(any(c[:2] == ('docker', 'stop') for c in self.fake.calls))
        self.no_up()

    def test_post_version_drift_refuses_even_a_mocked_match_no_resume_or_removal(self):
        manifest = json.loads(self.fake.snapshot_files['post']['manifest.json'])
        next(s for s in manifest['stores'] if s['path'] == 'auth/llm-usage.sqlite')['logical']['schema']['userVersion'] = '2'
        self.fake.snapshot_files['post']['manifest.json'] = m.encoded(manifest)
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'export_post')
        self.assertEqual(self.controller.exports, {'pre'})
        self.assertFalse(self.fake.records['b' * 64]['State']['Running'])
        self.assertFalse(any(c[:2] == ('docker', 'rm') for c in self.fake.calls))

    def test_current_profile_post_match_and_post_versions_remain_strict(self):
        self.fake.receipt_override['compare'] = m.encoded({'code': 'MISMATCH', 'ok': False})
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'compare')
        self.assertFalse(self.fake.records['b' * 64]['State']['Running'])
        self.assertEqual(self.controller.exports, {'pre'})
        self.assertFalse(any(c[:2] == ('docker', 'rm') for c in self.fake.calls))


class PrivateInputTests(unittest.TestCase):
    command = ('docker', 'exec', '-i', 'c' * 64, 'node', m.SCRIPT_TARGET, 'compatibility', '/backup/pre')

    def test_closed_compatibility_receipts_no_fabricated_private_flags(self):
        m.receipt(b'{"code":"COMPATIBLE","ok":true}', 'compatibility')
        for data in (good_receipt('capture'), good_receipt('compare'), b'{"code":"COMPATIBLE","ok":false}',
                     b'{"code":"COMPATIBLE","ok":1}', b'{"code":"COMPATIBLE","ok":"true"}',
                     b'{"code":"COMPATIBLE","ok":true,"startupCompatible":true}',
                     b'{"code":"COMPATIBLE","code":"COMPATIBLE","ok":true}', b'{"ok":true}'):
            with self.subTest(data_length=len(data)), self.assertRaises(m.Refusal):
                m.receipt(data, 'compatibility')

    def test_peer_public_current_profile_and_private_protocol_constants_match_without_execution(self):
        source = (HERE / 'sqlite_state_snapshot.mjs').read_text()
        self.assertIn("sourceAggregate: '" + m.CURRENT_SOURCE_AGGREGATE + "'", source)
        self.assertIn("auth: '0/0', ledger: '0/14', quota: '1145655601/1'", source)
        self.assertIn("['AUTH_ORIGIN', 'AUTH_ALLOW_INSECURE_LOCAL_HTTP',", source)
        self.assertIn("'SCAN_BROWSER_ALLOWED_USER_IDS', 'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS']", source)
        self.assertIn('AUTH_INPUT_BYTES = 16384, AUTH_VALUE_BYTES = 4096', source)
        self.assertIn("receipt(true, 'COMPATIBLE')", source)
        self.assertIn("['compatibility', '/backup/pre']", source)

    def test_private_input_closed_fields_type_duplicate_cap_and_missing_stdin_refuse_prelaunch(self):
        valid = {key: None for key in m.AUTH_SETTINGS}
        runner = m.Runner('/synthetic', {})
        for data in (m.encoded(dict(valid, OPENROUTER_API_KEY='SYNTHETIC')), m.encoded(dict(valid, AUTH_ORIGIN=True)),
                     m.encoded({}), m.encoded(dict(valid, AUTH_ORIGIN='x' * m.AUTH_INPUT_BYTES)),
                     m.encoded(dict(valid, AUTH_ORIGIN='x' * (m.AUTH_VALUE_BYTES + 1))),
                     m.encoded(dict(valid, AUTH_ORIGIN='\0')), m.encoded(dict(valid, AUTH_ORIGIN='\ud800')),
                     b'{"AUTH_ORIGIN":null,"AUTH_ORIGIN":null}', None):
            with patch.object(m.subprocess, 'Popen') as launch, self.assertRaises(m.Refusal):
                runner(self.command, input_data=data, cap=4096)
            launch.assert_not_called()
        with patch.object(m.subprocess, 'Popen') as launch, self.assertRaises(m.Refusal):
            runner(('docker', 'UNAPPROVED'), input_data=m.encoded(valid), cap=4096)
        launch.assert_not_called()

    def fake_process(self, stderr=b'SYNTHETIC_PRIVATE_STDERR', broken=False):
        from types import SimpleNamespace
        outputs = []
        for data in (good_receipt('compatibility'), stderr):
            read_fd, write_fd = os.pipe()
            os.write(write_fd, data)
            os.close(write_fd)
            outputs.append(os.fdopen(read_fd, 'rb'))
        read_fd, write_fd = os.pipe()
        if broken:
            os.close(read_fd)
        else:
            self.addCleanup(os.close, read_fd)
        proc = SimpleNamespace(stdout=outputs[0], stderr=outputs[1], stdin=os.fdopen(write_fd, 'wb'),
                               pid=123456, wait=lambda **_: 0)
        return proc, read_fd

    def test_runner_partial_private_writes_eof_and_stderr_drain_without_process_execution(self):
        proc, read_fd = self.fake_process()
        data = m.encoded({key: '' if index == 1 else None for index, key in enumerate(m.AUTH_SETTINGS)})
        actual_write = os.write
        with (patch.object(m.subprocess, 'Popen', return_value=proc) as launch,
              patch.object(m.os, 'killpg') as kill,
              patch.object(m.os, 'write', side_effect=lambda fd, block: actual_write(fd, block[:7]))):
            output = m.Runner('/synthetic', {})(self.command, input_data=data, cap=4096, timeout=60)
        self.assertEqual(os.read(read_fd, m.AUTH_INPUT_BYTES), data)
        self.assertEqual(output, good_receipt('compatibility'))
        self.assertIs(launch.call_args.kwargs['stdin'], m.subprocess.PIPE)
        self.assertNotIn(data, launch.call_args.args[0])
        self.assertNotIn('AUTH_ORIGIN', launch.call_args.kwargs['env'])
        self.assertTrue(all(stream.closed for stream in (proc.stdin, proc.stdout, proc.stderr)))
        kill.assert_not_called()

    def test_broken_private_pipe_and_stderr_cap_fail_closed_and_kill_only_mock_client(self):
        for broken, stderr in ((True, b'SYNTHETIC'), (False, b'SYNTHETIC' * 1000)):
            proc, _ = self.fake_process(stderr=stderr, broken=broken)
            with (patch.object(m.subprocess, 'Popen', return_value=proc),
                  patch.object(m.os, 'killpg') as kill, self.assertRaises(m.Refusal)):
                m.Runner('/synthetic', {})(self.command, input_data=m.encoded({key: None for key in m.AUTH_SETTINGS}), cap=4096)
            kill.assert_called_once()
            self.assertTrue(all(stream.closed for stream in (proc.stdin, proc.stdout, proc.stderr)))


class ComposeVersionPolicyTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(m.subprocess, 'Popen', side_effect=AssertionError('NO_REAL_SUBPROCESS')))
        for name in ('getitimer', 'getsignal', 'setitimer', 'signal'):
            self.enterContext(patch.object(m.signal, name, side_effect=AssertionError('NO_REAL_SIGNAL')))

    def test_exact_two_reports_and_near_miss_refusals(self):
        self.assertEqual(m.SUPPORTED_COMPOSE_VERSIONS, frozenset((b'2.34.0', b'2.34.0-desktop.1')))
        for report in m.SUPPORTED_COMPOSE_VERSIONS:
            m.need(report.strip() in m.SUPPORTED_COMPOSE_VERSIONS)
            m.need((b' \t' + report + b'\r\n').strip() in m.SUPPORTED_COMPOSE_VERSIONS)
        for report in (b'2.34.0-desktop.2', b'2.34.0-desktop.10', b'2.34.1', b'2.35.0',
                       b'v2.34.0', b'2.34.0+build', b'2.34.0 extra', b'2.34.0\nextra',
                       b'', b'\xff', b'2.34.0\0'):
            with self.subTest(report=report), self.assertRaises(m.Refusal):
                m.need(report.strip() in m.SUPPORTED_COMPOSE_VERSIONS)

    def test_version_support_preserves_exact_image_defaults_and_labels(self):
        old = {'Id': 'sha256:' + 'a' * 64, 'Os': 'linux', 'Architecture': 'arm64',
               'Config': {'Env': ['PATH=/inert'], 'User': '65532:65532', 'OnBuild': None,
                          'Labels': {'com.docker.compose.version': '2.34.0'}}}
        candidate = copy.deepcopy(old)
        candidate['Id'] = 'sha256:' + 'b' * 64
        m.candidate_image_matches(old, candidate, candidate['Id'], 'arm64')
        for field, value in (('User', '0'), ('Env', ['PATH=/different']),
                             ('Labels', {'com.docker.compose.version': '2.34.0-desktop.1'})):
            changed = copy.deepcopy(candidate)
            changed['Config'][field] = value
            with self.subTest(field=field), self.assertRaises(m.Refusal):
                m.candidate_image_matches(old, changed, candidate['Id'], 'arm64')

    def test_runtime_version_label_and_nonkey_env_not_normalized(self):
        record = {'Id': 'a' * 64, 'Config': {'Hostname': '', 'Env': ['PATH=/inert'],
                  'Labels': {'com.docker.compose.version': '2.34.0'}}, 'HostConfig': {'ReadonlyRootfs': True},
                  'Mounts': [], 'NetworkSettings': {'Networks': {}}, 'Path': 'node', 'Args': []}
        changed = copy.deepcopy(record)
        changed['Config']['Labels']['com.docker.compose.version'] = '2.34.0-desktop.1'
        with self.assertRaises(m.Refusal):
            m.need(m.config_identity(record) == m.config_identity(changed))
        env = dict(m.FREE, SCAN_JWT_SECRET='INERT_' + 'j' * 40, AUTH_ORIGIN='http://127.0.0.1:8080',
                   OPENROUTER_API_KEY='INERT_KEY')
        changed_env = dict(env, INERT_UNRELATED_NONKEY='different')
        with self.assertRaises(m.Refusal):
            m.key_only(env, changed_env)

    def test_public_source_pins(self):
        for name in ('recreate_openrouter_key.py', 'test_recreate_openrouter_key.py'):
            data = (HERE / name).read_bytes()
            self.assertTrue(data and len(data) <= 2 * m.MIB)
            print('OWN_PUBLIC_SOURCE_SHA256 server/deploy/trust/' + name + ' ' + hashlib.sha256(data).hexdigest())


class ComposeRuntimeTests(unittest.TestCase):
    """New representation regressions: public sources, inert temporary fixtures ONLY."""
    def setUp(self):
        ControllerTests.setUp(self)
        for name in ('getsignal', 'getitimer', 'signal', 'setitimer', 'alarm'):
            self.enterContext(patch.object(m.signal, name, side_effect=AssertionError('NO_REAL_SIGNAL')))
        self.enterContext(patch.object(m.subprocess, 'Popen', side_effect=AssertionError('NO_REAL_PROCESS')))

    assert_no_daemon_write = ControllerTests.assert_no_daemon_write

    def serialized(self, raw):
        # Independent byte-level config.go output oracle, not production encoder.
        return m.decode(m.encoded(raw).replace(b'$', b'$$'))

    def test_typed_runtime_view_matches_raw_json_escape_contract_once(self):
        raw = {'services': {'probe': {'command': ['$', '$$', '${NAME}', '$x$$y'],
                'environment': {'KEY': SYNTHETIC_KEY, 'UNICODE': 'caf\u00e9$'},
                'entrypoint': None, 'labels': {'literal': '${NAME}'},
                'volumes': [{'source': '/public/$path', 'read_only': True}]}},
               'numbers': [0, 1.5, False, None]}
        serialized = self.serialized(raw)
        before = copy.deepcopy(serialized)
        self.assertEqual(serialized['services']['probe']['command'], ['$$', '$$$$', '$${NAME}', '$$x$$$$y'])
        self.assertEqual(m.compose_runtime_model(serialized), raw)
        self.assertEqual(serialized, before)
        self.assertEqual(m.dollar_escape(m.compose_runtime_model(serialized)), serialized)
        # This is an inverse for serialized output ONLY: decoding raw values refuses.
        with self.assertRaises(m.Refusal):
            m.compose_runtime_model(raw)

    def test_unsafe_runs_keys_types_and_bounds_refuse(self):
        bad = [{'value': value} for value in ('$', '$$$', '$${NAME}$', '\ud800', b'bytes', float('nan'))]
        bad += [{key: 'value'} for key in ('$KEY', '$$KEY', 1)]
        nested = None
        for _ in range(66):
            nested = [nested]
        bad += [{'nested': nested}, {'nodes': [None] * 65536}, {'value': 'x' * (2 * m.MIB)}]
        for item in bad:
            with self.subTest(case=bad.index(item)), self.assertRaises(m.Refusal):
                m.compose_runtime_model(item)

    def test_compiled_serialized_model_is_written_directly_and_roundtrip_stable(self):
        self.controller.preflight()
        compiled = m.decode(self.controller.compiled.read_bytes())
        self.assertEqual(compiled, self.controller.model)
        self.assertEqual(m.compose_runtime_model(compiled)['services']['api']['environment'][m.KEY], SYNTHETIC_KEY)
        self.assertEqual(m.decode(self.fake((*self.controller.command, 'config', '--format', 'json'))), compiled)
        self.assertNotEqual(m.dollar_escape(compiled), compiled)
        self.assert_no_daemon_write()

    def test_old_double_escape_bug_refuses_with_output_escaping_mock(self):
        write = m.private_write
        def old_bug(path, data):
            if Path(path).name == 'compiled.json':
                data = m.encoded(m.dollar_escape(m.decode(data)))
            return write(path, data)
        with patch.object(m, 'private_write', side_effect=old_bug), self.assertRaises(m.Refusal):
            self.controller.preflight()
        self.assert_no_daemon_write()

    def test_raw_defaults_jwt_auth_and_new_role_checks_are_not_double_decoded(self):
        raw_defaults = '$$raw-default-${NO_INTERPOLATION}'
        settings = {m.AUTH_SETTINGS[0]: 'http://127.0.0.1:8080/$raw',
                    m.AUTH_SETTINGS[1]: 'false', m.AUTH_SETTINGS[2]: '$one,$$two,${three}',
                    m.AUTH_SETTINGS[3]: None}
        env = self.fake.model['services']['api']['environment']
        env.update({k: v for k, v in settings.items() if v is not None})
        env['SCAN_JWT_SECRET'] = '$$JWT_${literal}_' + 'j' * 40
        for role, binding in self.plan.bindings.items():
            image = self.fake.images[binding.image]['Config']
            image['Env'].append('RAW_DEFAULT=' + raw_defaults)
            record = self.fake.records[binding.container]
            actual = dict(m.env_map(image['Env']), **self.fake.model['services'][role]['environment'])
            if role == 'api':
                actual[m.KEY] = 'OLD_$$_${key}'
            record['Config']['Env'] = [k + '=' + v for k, v in actual.items()]
        self.controller.preflight()
        c = self.controller
        old = copy.deepcopy(c.old)
        # Unit-test the private input predicate, not mode validation or activation.
        c.plan = replace(c.plan, current_source_profile=True)
        c.candidate_image = c.images['api']
        self.assertEqual(m.decode(c.compatibility_input()), settings)
        c.plan = self.plan
        for index, role in enumerate(('api', 'worker', 'web')):
            record = copy.deepcopy(c.old[role])
            identity = format(index + 10, 'x') * 64
            record.update(Id=identity, Image=self.plan.selected_image(role))
            record['Config'].update(Hostname=identity[:12], Image=self.plan.selected_image(role))
            record['Config']['Labels']['com.docker.compose.project.config_files'] = str(c.compiled)
            if role == 'api':
                actual = m.env_map(record['Config']['Env'])
                actual[m.KEY] = SYNTHETIC_KEY
                record['Config']['Env'] = [k + '=' + v for k, v in actual.items()]
                c.new_api = identity
            self.fake.records[identity] = record
            c.new_roles[role] = identity
            c.candidate_images[role] = c.images[role]
            c.check_new_role(role, True)
            if role == 'api':
                c.check_new_api(True)
            record['Config']['Env'].append('UNAPPROVED_NONKEY=$literal')
            with self.assertRaises(m.Refusal):
                c.check_new_role(role, True)
            record['Config']['Env'].pop()
            record['Config']['Labels']['com.docker.compose.version'] = 'CHANGED'
            with self.assertRaises(m.Refusal):
                c.check_new_role(role, True)
        self.assertEqual(c.old, old)
        self.assertEqual(m.env_map(c.images['api']['Config']['Env'])['RAW_DEFAULT'], raw_defaults)
        c.plan = replace(c.plan, current_source_profile=True)
        for name in ('SCAN_JWT_SECRET', *m.AUTH_SETTINGS[:3]):
            original = c.model['services']['api']['environment'][name]
            c.model['services']['api']['environment'][name] = original + 'changed'
            with self.assertRaises(m.Refusal):
                c.compatibility_input()
            c.model['services']['api']['environment'][name] = original
        self.assert_no_daemon_write()

    def test_null_and_absent_inherit_but_explicit_empty_clears(self):
        self.controller.preflight()
        role = 'worker'
        c, service = self.controller, self.fake.model['services'][role]
        image, record = c.images[role]['Config'], copy.deepcopy(c.old[role])
        image.update(Cmd=['default', '$$raw'], Entrypoint=['/inert/$entrypoint'])
        for absent, command, entrypoint in ((True, None, None), (False, None, None),
                                            (False, [], []), (False, ['$command'], ['$entrypoint'])):
            if absent:
                service.pop('command', None)
                service.pop('entrypoint', None)
            else:
                service.update(command=command, entrypoint=entrypoint)
            record['Config'].update(Cmd=image['Cmd'] if command is None else command,
                                    Entrypoint=image['Entrypoint'] if entrypoint is None else entrypoint)
            c.model_matches(role, self.serialized(self.fake.model), record)
            changed = copy.deepcopy(record)
            changed['Config']['Cmd'] = ['WRONG']
            with self.assertRaises(m.Refusal):
                c.model_matches(role, self.serialized(self.fake.model), changed)
            changed = copy.deepcopy(record)
            changed['Config']['Entrypoint'] = ['WRONG']
            with self.assertRaises(m.Refusal):
                c.model_matches(role, self.serialized(self.fake.model), changed)
        self.assert_no_daemon_write()


class PredicateObserverTests(unittest.TestCase):
    """Fixed-ID observation only; no new acceptance paths or real clients/signals."""
    setUp = ComposeRuntimeTests.setUp
    serialized = ComposeRuntimeTests.serialized
    assert_no_daemon_write = ControllerTests.assert_no_daemon_write

    def test_enter_precedes_evaluation_pass_follows_and_returns_are_ignored(self):
        events = []
        def observer(gate, event):
            self.assertIn(gate, m.PREDICATE_IDS)
            events.append((gate, event))
            return False
        def operation():
            self.assertEqual(events, [('MODEL_USER', 'ENTER')])
            events.append('EVALUATED')
            return 'unchanged'
        self.assertEqual(m.predicate(observer, 'MODEL_USER', operation), 'unchanged')
        self.assertEqual(events, [('MODEL_USER', 'ENTER'), 'EVALUATED', ('MODEL_USER', 'PASS')])
        events.clear()
        with self.assertRaises(m.Refusal):
            m.predicate(observer, 'MODEL_USER', lambda: m.need(False))
        self.assertEqual(events, [('MODEL_USER', 'ENTER')])
        with self.assertRaises(m.Refusal):
            m.predicate(observer, 'PRIVATE_OR_UNKNOWN', lambda: self.fail('MUST_NOT_EVALUATE'))
        self.assertEqual(events, [('MODEL_USER', 'ENTER')])

    def test_callback_errors_enter_and_pass_fail_closed_without_payload(self):
        for phase in ('ENTER', 'PASS'):
            evaluated = []
            def observer(gate, event):
                if event == phase:
                    raise RuntimeError(SYNTHETIC_KEY)
            with self.assertRaises(m.Refusal) as error:
                m.predicate(observer, 'MODEL_USER', lambda: evaluated.append(True))
            self.assertEqual(str(error.exception), '')
            self.assertEqual(evaluated, [] if phase == 'ENTER' else [True])
        sentinel = RuntimeError('INERT_OPERATION_ERROR')
        for observer in (None, lambda *args: None):
            with self.assertRaises(RuntimeError) as error:
                m.predicate(observer, 'MODEL_USER', lambda: (_ for _ in ()).throw(sentinel))
            self.assertIs(error.exception, sentinel)

    def test_decoder_and_env_first_failure_inventory(self):
        cases = [({}, None), ({'value': '$odd'}, 'RUNTIME_DOLLAR_PAIRS'),
                 ({'$key': ''}, 'RUNTIME_KEYS'), ({'value': '\ud800'}, 'RUNTIME_STRING_UNICODE'),
                 ({'value': float('nan')}, 'RUNTIME_SCALAR'), ([], 'RUNTIME_ROOT')]
        for model, failed in cases:
            events = []
            observer = lambda gate, event: events.append((gate, event))
            if failed:
                with self.assertRaises(m.Refusal):
                    m.compose_runtime_model(model, observer)
                self.assertEqual(events[-1], (failed, 'ENTER'))
            else:
                self.assertEqual(m.compose_runtime_model(model, observer), m.compose_runtime_model(model))
                self.assertEqual(events[-1], ('RUNTIME_INVERSE', 'PASS'))
            self.assertTrue(all(g in m.PREDICATE_IDS and e in ('ENTER', 'PASS') for g, e in events))
        for value, failed in ((None, 'LIST_TYPE'), (['MISSING_EQUALS'], 'ENTRY_FORMAT'),
                              (['A=one', 'A=two'], 'ENTRY_UNIQUE'), ({'A': None}, 'DICT_STRINGS')):
            events = []
            with self.assertRaises(m.Refusal):
                m.env_map(value, lambda g, e: events.append((g, e)), 'API_OLD_ENV')
            self.assertEqual(events[-1], ('API_OLD_ENV_' + failed, 'ENTER'))

    def test_model_predicate_observed_and_default_results_identical(self):
        c = self.controller
        c.images = {role: self.fake.images[b.image] for role, b in self.plan.bindings.items()}
        original = self.fake.records[self.plan.bindings['api'].container]
        c.model_matches('api', self.serialized(self.fake.model), copy.deepcopy(original))
        events = []
        c.model_matches('api', self.serialized(self.fake.model), copy.deepcopy(original),
                        observer=lambda g, e: events.append((g, e)))
        self.assertEqual(events[-1], ('MODEL_API_VOLUMES', 'PASS'))
        self.assertTrue(all(g in m.PREDICATE_IDS and e in ('ENTER', 'PASS') for g, e in events))
        self.assertNotIn(SYNTHETIC_KEY, json.dumps(events))
        cases = [
            ('MODEL_USER', lambda s, r: r['Config'].update(User='0')),
            ('MODEL_WORKDIR', lambda s, r: r['Config'].update(WorkingDir='/wrong')),
            ('MODEL_COMMAND', lambda s, r: r['Config'].update(Cmd=['wrong'])),
            ('MODEL_ENTRYPOINT', lambda s, r: r['Config'].update(Entrypoint=[])),
            ('MODEL_ROOTFS', lambda s, r: r['HostConfig'].update(ReadonlyRootfs=False)),
            ('MODEL_CAP_DROP', lambda s, r: r['HostConfig'].update(CapDrop=[])),
            ('MODEL_CAP_ADD', lambda s, r: r['HostConfig'].update(CapAdd=['SYS_ADMIN'])),
            ('MODEL_SECURITY_OPTIONS', lambda s, r: r['HostConfig'].update(SecurityOpt=[])),
            ('MODEL_PRIVILEGE_DEVICES', lambda s, r: r['HostConfig'].update(Privileged=True)),
            ('MODEL_HEALTH_EQUAL', lambda s, r: r['Config'].update(Healthcheck={'Test': ['NONE']})),
            ('HEALTH_DURATION_FORMAT', lambda s, r: s.update(healthcheck={'interval': 'invalid'})),
            ('MODEL_TMPFS_ITEM', lambda s, r: s.update(tmpfs=[None])),
            ('MODEL_TMPFS_TARGET', lambda s, r: s.update(tmpfs=['relative'])),
            ('MODEL_TMPFS_EQUAL', lambda s, r: r['HostConfig'].update(Tmpfs={'/extra': ''})),
            ('MODEL_RESTART_NAME', lambda s, r: s.update(restart='always')),
            ('MODEL_RESTART_RETRIES', lambda s, r: r['HostConfig']['RestartPolicy'].update(MaximumRetryCount=1)),
            ('MODEL_MEMORY', lambda s, r: r['HostConfig'].update(Memory=1)),
            ('MEMORY_FORMAT', lambda s, r: s.update(mem_limit='invalid')),
            ('MODEL_SWAP', lambda s, r: s.update(memswap_limit=1)),
            ('MODEL_CPU', lambda s, r: r['HostConfig'].update(NanoCpus=1)),
            ('MODEL_PIDS', lambda s, r: r['HostConfig'].update(PidsLimit=1)),
            ('MODEL_IMAGE_VOLUMES', lambda s, r: r['Config'].update(Volumes={'/implicit': {}})),
            ('MODEL_MOUNT_TYPE', lambda s, r: s['volumes'][0].update(type='tmpfs')),
            ('MODEL_BIND_OPTIONS', lambda s, r: s['volumes'][-1].update(bind={'create_host_path': True})),
            ('MODEL_MOUNTS', lambda s, r: r['Mounts'][0].update(RW=False)),
            ('MODEL_NETWORKS', lambda s, r: r['NetworkSettings'].update(Networks={})),
            ('MODEL_PORT_SHAPE', lambda s, r: s.update(ports=[{'host_ip': '0.0.0.0'}])),
            ('MODEL_PORT_BINDINGS', lambda s, r: r['HostConfig'].update(PortBindings={'1/tcp': []})),
            ('MODEL_PORT_ENTRY', lambda s, r: s.update(ports=[{'host_ip': '127.0.0.1'}])),
            ('MODEL_PORT_UNIQUE', lambda s, r: s.update(ports=[{'host_ip': '127.0.0.1', 'target': 1, 'published': '1'}] * 2)),
            ('MODEL_PORT_SCOPE', lambda s, r: (
                s.update(ports=[{'host_ip': '127.0.0.1', 'target': 1, 'published': '1'}]),
                r['HostConfig'].update(PortBindings={'1/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '1'}]}))),
            ('MODEL_API_VOLUMES', lambda s, r: (s['volumes'].pop(1), r['Mounts'].pop(1))),
            ('MODEL_API_COMMAND', lambda s, r: (s.update(command=['wrong']), r['Config'].update(Cmd=['wrong']))),
        ]
        for failed, mutate in cases:
            with self.subTest(gate=failed):
                raw, record = copy.deepcopy(self.fake.model), copy.deepcopy(original)
                mutate(raw['services']['api'], record)
                serialized = self.serialized(raw)
                expected_error = KeyError if failed == 'MODEL_PORT_ENTRY' else m.Refusal
                with self.assertRaises(expected_error):
                    c.model_matches('api', serialized, record)
                events = []
                with self.assertRaises(expected_error):
                    c.model_matches('api', serialized, record, lambda g, e: events.append((g, e)))
                active = []
                for gate, event in events:
                    if event == 'ENTER':
                        active.append(gate)
                    else:
                        self.assertEqual(active.pop(), gate)
                self.assertEqual(active[-1], failed)
                self.assertNotIn(SYNTHETIC_KEY, json.dumps(events))
        self.assert_no_daemon_write()


class BindRepresentationTests(unittest.TestCase):
    """Only the two reviewed non-nil long-form bind representations are admitted."""
    setUp = ComposeRuntimeTests.setUp
    serialized = ComposeRuntimeTests.serialized
    assert_no_daemon_write = ControllerTests.assert_no_daemon_write

    def model(self, role='api', options=None, absent=False):
        raw = copy.deepcopy(self.fake.model)
        mount = raw['services'][role]['volumes'][-1]
        if absent:
            mount.pop('bind')
        else:
            mount['bind'] = copy.deepcopy(options)
        c = self.controller
        c.images = {r: self.fake.images[b.image] for r, b in self.plan.bindings.items()}
        return self.serialized(raw), copy.deepcopy(self.fake.records[self.plan.bindings[role].container])

    def test_exact_present_empty_and_false_pass_without_model_mutation(self):
        for role in ('api', 'worker'):
            for options in ({}, {'create_host_path': False}):
                with self.subTest(role=role, options=options):
                    model, record = self.model(role, options)
                    before = copy.deepcopy(model)
                    self.controller.model_matches(role, model, record)
                    events = []
                    self.controller.model_matches(role, model, record, lambda g, e: events.append((g, e)))
                    self.assertIn(('MODEL_BIND_OPTIONS', 'PASS'), events)
                    self.assertEqual(model, before)
        self.assert_no_daemon_write()

    def test_absent_invalid_true_numeric_null_and_extra_options_refuse(self):
        cases = [(True, None)] + [(False, value) for value in (
            None, False, True, [], 'INERT', {'create_host_path': True}, {'create_host_path': 0},
            {'create_host_path': 1}, {'create_host_path': None}, {'create_host_path': 'false'},
            {'create_host_path': []}, {'create_host_path': False, 'extra': False}, {'extra': False})]
        for absent, options in cases:
            with self.subTest(absent=absent, options=options):
                model, record = self.model(options=options, absent=absent)
                for observed in (False, True):
                    events = []
                    with self.assertRaises(m.Refusal):
                        self.controller.model_matches('api', model, record,
                            (lambda g, e: events.append((g, e))) if observed else None)
                    if observed:
                        self.assertEqual(events[-1], ('MODEL_BIND_OPTIONS', 'ENTER'))
        self.assert_no_daemon_write()

    def test_source_target_and_readonly_drift_still_refuse_both_forms(self):
        for options in ({}, {'create_host_path': False}):
            for field, value in (('source', '/inert/wrong'), ('target', '/wrong'), ('read_only', False)):
                with self.subTest(options=options, field=field):
                    model, record = self.model(options=options)
                    model['services']['api']['volumes'][-1][field] = value
                    events = []
                    with self.assertRaises(m.Refusal):
                        self.controller.model_matches('api', model, record, lambda g, e: events.append((g, e)))
                    self.assertIn(('MODEL_BIND_OPTIONS', 'PASS'), events)
                    self.assertEqual(events[-1], ('MODEL_MOUNTS', 'ENTER'))
        self.assert_no_daemon_write()

    def test_normalized_empty_bind_is_compiled_unchanged_and_roundtrips(self):
        before = copy.deepcopy(self.fake.model)
        self.controller.preflight()
        compiled = m.decode(self.controller.compiled.read_bytes())
        self.assertEqual(compiled, self.controller.model)
        self.assertEqual(compiled['services']['api']['volumes'][-1]['bind'], {})
        self.assertEqual(m.decode(self.fake((*self.controller.command, 'config', '--format', 'json'))), compiled)
        self.assertEqual(self.fake.model, before)
        self.assertIs(before['services']['api']['volumes'][-1]['bind']['create_host_path'], False)
        self.assert_no_daemon_write()


class PureTests(unittest.TestCase):
    def test_full_pins_and_closed_source_allowlist(self):
        with self.assertRaises(m.Refusal):
            m.Binding('b84d83...', 'sha256:487c3909...').validate()
        with self.assertRaises(m.Refusal):
            m.Binding('a' * 64, 'dip-auth-stand-api:latest').validate()

    def test_duplicate_json_and_nonfinite_or_oversized_data_refused(self):
        for value in (b'{"ok":true,"ok":true}', b'{"x":NaN}', b'\xff', b'x' * 4097):
            with self.subTest(value_length=len(value)), self.assertRaises(m.Refusal):
                m.decode(value, 4096)

    def test_receipt_closed_keys_types_and_no_false_or_string_booleans(self):
        for operation in ('capture', 'compare'):
            m.receipt(good_receipt(operation), operation)
            for change in ({'ok': 'true'}, {'ok': 1}, {'version': True}, {'privateRows': []}, {'startupCompatible': True}, {'allState': True}):
                with self.subTest(operation=operation, change_keys=list(change)), self.assertRaises(m.Refusal):
                    m.receipt(m.encoded(dict(json.loads(good_receipt(operation)), **change)), operation)

    def test_actual_public_mjs_receipt_contract_static_not_native_execution(self):
        # Reading public source is inert: no Node/import/SQLite/native/helper run.
        source = (HERE / 'sqlite_state_snapshot.mjs').read_text()
        self.assertIn('Object.freeze({ code, ok })', source)
        self.assertIn("receipt(true, 'CAPTURED')", source)
        self.assertIn("receipt(equal, equal ? 'MATCH' : 'MISMATCH')", source)
        for operation, code in (('capture', 'CAPTURED'), ('compare', 'MATCH')):
            m.receipt(m.encoded({'code': code, 'ok': True}), operation)
            other = 'MATCH' if operation == 'capture' else 'CAPTURED'
            for value in ({'code': other, 'ok': True}, {'code': code, 'ok': False},
                          {'code': code}, {'ok': True}, {'code': 1, 'ok': True}):
                with self.assertRaises(m.Refusal):
                    m.receipt(m.encoded(value), operation)

    def test_dollar_escape_preserves_nested_literals_on_semantic_roundtrip(self):
        model = {'services': {'api': {'environment': {'KEY': SYNTHETIC_KEY, 'PATH': '$$literal'}}},
                 'labels': ['literal${x}', '$']}
        self.assertEqual(m.compose_runtime_model(m.dollar_escape(model)), model)
        self.assertEqual(model['services']['api']['environment']['KEY'], SYNTHETIC_KEY)

    def test_env_duplicates_and_null_values_fail_closed(self):
        for value in (['A=x', 'A=y'], ['EMPTY'], {'A': None}, {'A': True}):
            with self.assertRaises(m.Refusal):
                m.env_map(value)

    def test_cli_default_and_invalid_arguments_emit_no_untrusted_diagnostics(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with patch.object(sys, 'stdout', stdout), patch.object(sys, 'stderr', stderr), self.assertRaises(m.Refusal):
            m.arguments(['--unapproved-secret-argument', SYNTHETIC_KEY])
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(stderr.getvalue(), '')

    def test_closed_http_booleans_do_not_accept_integer_or_extra_fields(self):
        m.closed_ok(b'{"ok":true}')
        for value in (b'{"ok":1}', b'{"ok":"true"}', b'{"ok":false}', b'{"ok":true,"data":[]}'):
            with self.assertRaises(m.Refusal):
                m.closed_ok(value)

    def test_health_duration_and_inherited_defaults(self):
        self.assertEqual(m.duration('5s'), 5000000000)
        self.assertEqual(m.duration('3ms'), 3000000)
        self.assertEqual(m.effective_health({'healthcheck': {'test': ['CMD', 'synthetic'], 'interval': '5s',
                                          'timeout': '3s', 'retries': 12}}, {}),
                         {'Test': ['CMD', 'synthetic'], 'Interval': 5000000000, 'Timeout': 3000000000, 'Retries': 12})
        with self.assertRaises(m.Refusal):
            m.duration('infinite')

    def test_runner_caps_combined_output_with_only_mock_process_and_inert_pipes(self):
        from types import SimpleNamespace
        for cap, expected_success in ((4096, True), (8, False)):
            outputs = []
            for data in (b'SYNTHETIC_STDOUT', b'SYNTHETIC_PRIVATE_STDERR'):
                read_fd, write_fd = os.pipe()
                os.write(write_fd, data)
                os.close(write_fd)
                outputs.append(os.fdopen(read_fd, 'rb'))
            proc = SimpleNamespace(stdout=outputs[0], stderr=outputs[1], pid=123456,
                                   wait=lambda **_: 0)
            with patch.object(m.subprocess, 'Popen', return_value=proc) as launch, patch.object(m.os, 'killpg') as kill:
                runner = m.Runner('/synthetic', {'LLM_ENABLED': 'true'})
                if expected_success:
                    self.assertEqual(runner(('docker', 'MOCK_ONLY'), cap=cap), b'SYNTHETIC_STDOUT')
                    kill.assert_not_called()
                else:
                    with self.assertRaises(m.Refusal):
                        runner(('docker', 'MOCK_ONLY'), cap=cap)
                    kill.assert_called_once()
                self.assertIs(launch.call_args.kwargs['stdin'], m.subprocess.DEVNULL)
                self.assertTrue(launch.call_args.kwargs['start_new_session'])
                self.assertEqual(launch.call_args.kwargs['env']['LLM_ENABLED'], 'true')
            self.assertTrue(all(stream.closed for stream in outputs))

    def test_runner_preserves_ambient_env_without_launching_process(self):
        runner = m.Runner('/synthetic', {'LLM_ENABLED': 'true', 'LLM_QUOTA_ENABLED': 'true'})
        self.assertEqual(runner.env['LLM_ENABLED'], 'true')
        self.assertEqual(runner.env['LLM_QUOTA_ENABLED'], 'true')
        runner.deadline = 0
        with patch.object(m.subprocess, 'Popen') as launch, self.assertRaises(m.Refusal):
            runner(('docker', 'never-run'))
        launch.assert_not_called()


class StoppedReconciliationTests(unittest.TestCase):
    """NEW incident route: disposable inert stores, fake clients and fake alarms ONLY."""
    def setUp(self):
        ReleaseAlignmentTests.setUp(self)
        self.enterContext(patch.object(m.subprocess, 'Popen', side_effect=AssertionError('NO_REAL_CLIENT')))
        self.enterContext(patch.object(m.os, 'killpg', side_effect=AssertionError('NO_REAL_SIGNAL')))
        self.enterContext(patch.object(m.sys, 'platform', 'darwin'))
        self.enterContext(patch.object(m, 'RECONCILIATION_REPO', self.repo))
        self.incident_originals = {r: (b.container, b.image) for r, b in self.plan.bindings.items()}
        self.incident_candidates = {r: self.plan.selected_image(r) for r in self.plan.replaced_roles}
        self.enterContext(patch.object(m, 'RECONCILIATION_ORIGINALS', self.incident_originals))
        self.enterContext(patch.object(m, 'RECONCILIATION_CANDIDATES', self.incident_candidates))
        self.plan = replace(self.plan, reconcile_stopped_stand=True,
                            held_lock_reconciliation_authorized=True, darwin_host_mnt_helper=True)
        self.controller.plan = self.fake.plan = self.plan
        self.prior = self.controller.root / '.trivy-refresh.lock'
        self.prior.mkdir(mode=0o700)
        m.private_write(self.prior / 'KEY_ACTIVATION_HOLD.json', b'{"INERT_PRIOR_HOLD":true}\n')
        self.prior_before = (m.path_metadata(self.prior, directory=True),
                             m.path_metadata(self.prior / 'KEY_ACTIVATION_HOLD.json', secret=True))
        for role, binding in self.plan.bindings.items():
            state = self.fake.records[binding.container]['State']
            state.update(Running=role in ('egress', 'llm-egress'),
                         Status='running' if role in ('egress', 'llm-egress') else 'exited', Dead=False)
        image = self.plan.bindings['api'].image
        self.retained = {'id': m.RETAINED_CREATED_ID, 'image': image, 'configImage': image,
            'name': '/dip-key-snapshot-' + 'e' * 32, 'status': 'created', 'running': False,
            'paused': False, 'restarting': False, 'oom': False, 'dead': False, 'exit': 0, 'restarts': 0,
            'started': '0001-01-01T00:00:00Z', 'finished': '0001-01-01T00:00:00Z',
            'entry': ['node'], 'cmd': ['-e', m.HOLDER_CODE], 'path': 'node', 'args': ['-e', m.HOLDER_CODE],
            'labels': {'dip.key-preservation': 'key-preservation-inert123'}, 'declared': [], 'mounts': []}
        self.retained_before = copy.deepcopy(self.retained)
        self.fake.records[m.RETAINED_CREATED_ID] = {
            'Id': m.RETAINED_CREATED_ID, 'Name': self.retained['name'], 'Image': image,
            'Config': {'Labels': self.retained['labels']}, 'State': {'Running': False}, 'Mounts': []}
        self.alias_mutation = None
        def helper(record):
            declared = []
            for mount in record['Mounts']:
                if mount['Type'] == 'bind':
                    mount['Source'] = '/host_mnt' + mount['Source']
                    declared.append({'Type': 'bind', 'Source': mount['Source'], 'Target': mount['Destination'],
                                     'ReadOnly': True, 'BindOptions': {'Propagation': 'rprivate'}})
                elif mount['Type'] == 'volume':
                    declared.append({'Type': 'volume', 'Source': mount['Name'], 'Target': mount['Destination']})
            record['HostConfig']['Mounts'] = declared
            if self.alias_mutation:
                self.alias_mutation(record)
        self.fake.helper_mutation = helper
        def run(args, **kwargs):
            if m.RETAINED_FORMAT in args:
                self.fake.calls.append(tuple(args))
                return m.encoded(self.retained)
            return self.fake(args, **kwargs)
        self.controller.run = run

    result = MigrationTests.result

    def assert_prior_untouched(self):
        self.assertEqual(self.prior_before, (m.path_metadata(self.prior, directory=True),
                         m.path_metadata(self.prior / 'KEY_ACTIVATION_HOLD.json', secret=True)))
        self.assertEqual(self.retained, self.retained_before)
        for call in self.fake.calls:
            if call[:2] in (('docker', 'stop'), ('docker', 'start'), ('docker', 'pause'), ('docker', 'rm')):
                self.assertNotIn(m.RETAINED_CREATED_ID, call)

    def test_full_fresh_route_preserves_prior_hold_retained_and_env_no_old_start(self):
        events = []
        sync = m.sync_directory
        def synced(path):
            sync(path)
            events.append(('sync', Path(path)))
        run = self.controller.run
        def observed(args, **kwargs):
            if args[:2] == ('docker', 'create'):
                self.assertTrue((self.controller.backup / 'holder-intent.json').is_file())
                self.assertIn(('sync', self.controller.backup), events)
                self.assertTrue(self.controller.hold_requested)
            if args[:2] == ('docker', 'start'):
                self.assertEqual(args[-1], 'c' * 64)  # ONLY fresh inert holder; apps use pinned compose up.
                self.assertTrue((self.controller.backup / 'holder-id.json').is_file())
                self.assertIsNotNone(self.controller.holder_journal_metadata)
            return run(args, **kwargs)
        self.controller.run = observed
        with patch.object(m, 'sync_directory', side_effect=synced):
            result = self.result()
        self.assertTrue(result['ok'], result)
        self.assertTrue(result['priorHoldPreserved'] and result['manualReconciliationRequired'])
        self.assertEqual(self.controller.exports, {'pre', 'post'})
        self.assertEqual(self.controller.material_exports, {'plan', 'migration'})
        self.assertTrue(self.controller.migration_matched and self.controller.migration_compatible)
        self.assertEqual(len([e for e in self.events if e[0] == 'recheck']), 3)
        self.assertFalse(self.sleeps)
        self.assertFalse(any(c[:2] == ('docker', 'stop') for c in self.fake.calls))
        old = m.env_map(self.controller.old['api']['Config']['Env'])
        new = m.env_map(self.fake.records[self.controller.new_roles['api']]['Config']['Env'])
        self.assertEqual({k: v for k, v in old.items() if k != m.KEY},
                         {k: v for k, v in new.items() if k != m.KEY})
        self.assertFalse(self.controller.coordination_path.exists())
        self.assert_prior_untouched()

    def test_alias_exact_both_views_and_readonly_safety_refusals(self):
        # Separate fixtures per variant avoid attempting a second held operation.
        self.controller.old = {r: copy.deepcopy(self.fake.records[b.container]) for r, b in self.plan.bindings.items()}
        self.controller.images = {r: self.fake.images[b.image] for r, b in self.plan.bindings.items()}
        self.controller.backup = self.controller.root / 'key-preservation-own12345'
        self.controller.backup.mkdir(mode=0o700)
        self.controller.volumes = self.fake.volumes
        with patch.object(self.controller, 'writers'), patch.object(self.controller, 'resources'):
            self.controller.create_holder()
        original = copy.deepcopy(self.fake.records[self.controller.helper_id])
        self.controller.qualify_holder(True)
        for mutate in (
            lambda r: r['Mounts'][-1].update(Source='/host_mnt/foreign/helper.mjs'),
            lambda r: r['HostConfig']['Mounts'][-1].update(Source=str(self.repo / m.HELPER_PATH)),
            lambda r: r['HostConfig']['Mounts'][-1].update(ReadOnly=False),
            lambda r: r['Mounts'][-1].update(RW=True),
            lambda r: r['HostConfig']['Mounts'][0].update(ReadOnly=0),
            lambda r: r['HostConfig']['Mounts'][-1].update(BindOptions={'CreateMountpoint': True}),
        ):
            changed = copy.deepcopy(original)
            mutate(changed)
            self.fake.records[self.controller.helper_id] = changed
            with self.assertRaises(m.Refusal):
                self.controller.qualify_holder(True)
        self.fake.records[self.controller.helper_id] = original
        self.controller.plan = replace(self.plan, darwin_host_mnt_helper=False)
        with self.assertRaises(m.Refusal):
            self.controller.qualify_holder(True)

    def test_existing_new_lock_never_adopted_and_no_client(self):
        self.controller.coordination_path.mkdir(mode=0o700)
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertFalse(self.fake.calls)
        self.assert_prior_untouched()

    def test_running_original_refuses_before_verifier_or_holder(self):
        self.fake.records[self.plan.bindings['worker'].container]['State'].update(Running=True, Status='running')
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertFalse(self.events)
        self.assertFalse(any(c[:2] == ('docker', 'create') for c in self.fake.calls))
        self.assertTrue(self.controller.coordination_path.is_dir())
        self.assert_prior_untouched()

    def test_unknown_active_writer_refuses_without_touching_it(self):
        self.fake.records['f' * 64] = {'Id': 'f' * 64, 'State': {'Running': True},
            'Config': {'Labels': {}}, 'Mounts': [{'Type': 'bind', 'Source': self.fake.volumes[m.VOLUMES['auth']]['Mountpoint'],
                                                 'Destination': '/foreign', 'RW': True}]}
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertFalse(any(c[:2] in (('docker', 'create'), ('docker', 'stop')) for c in self.fake.calls))
        self.assertTrue(self.fake.records['f' * 64]['State']['Running'])
        self.assert_prior_untouched()

    def test_retained_drift_refuses_before_capture_no_adoption(self):
        self.retained['started'] = '2026-10-15T00:00:00Z'
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertFalse(self.fake.captured)
        self.assertFalse(any(c[:2] == ('docker', 'create') for c in self.fake.calls))

    def test_id_journal_durable_before_failed_qualification_and_no_capture(self):
        self.alias_mutation = lambda r: r['Mounts'][-1].update(Source='/foreign')
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual(result['phase'], 'holder')
        self.assertTrue(result['manualReconciliationRequired'])
        self.assertFalse(self.fake.captured)
        journal = m.private_json(self.controller.backup / 'holder-id.json', 4096)
        self.assertEqual(journal['id'], self.controller.helper_id)
        self.assertEqual(journal['name'], self.controller.helper_name)
        self.assertTrue((self.controller.coordination_path / 'KEY_ACTIVATION_HOLD.json').is_file())
        self.assert_prior_untouched()

    def test_journal_fsync_failure_prevents_start_capture_and_preserves_both_holds(self):
        sync = m.sync_directory
        def failed(path):
            if self.controller.backup and (self.controller.backup / 'holder-id.json').exists() and Path(path) == self.controller.backup:
                raise OSError('INERT_PRIVATE_FAILURE')
            return sync(path)
        with patch.object(m, 'sync_directory', side_effect=failed):
            result = self.result()
        self.assertFalse(result['ok'])
        self.assertFalse(any(c[:2] == ('docker', 'start') for c in self.fake.calls))
        self.assertFalse(self.fake.captured)
        self.assertNotIn('INERT_PRIVATE_FAILURE', json.dumps(result))
        self.assertTrue((self.controller.coordination_path / 'KEY_ACTIVATION_HOLD.json').is_file())
        self.assert_prior_untouched()

    def test_unknown_pre_version_refuses_before_plan_apply_or_old_start(self):
        manifest = json.loads(self.fake.snapshot_files['pre']['manifest.json'])
        for store in manifest['stores']:
            if store['path'] == 'data/ledger.sqlite':
                store['logical']['schema']['userVersion'] = '15'
        self.fake.snapshot_files['pre']['manifest.json'] = m.encoded(manifest)
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertFalse(any('plan-migration' in c or 'apply-migration' in c or 'up' in c for c in self.fake.calls))
        self.assertFalse(any(c[:2] == ('docker', 'start') and c[-1] != self.controller.helper_id for c in self.fake.calls))
        self.assert_prior_untouched()

    def test_prior_hold_change_blocks_next_client_without_repair(self):
        with self.assertRaises(m.Refusal):  # Context exit must refuse the changed prior state too.
            with self.controller.coordination():
                calls = len(self.fake.calls)
                marker = self.prior / 'KEY_ACTIVATION_HOLD.json'
                marker.write_bytes(b'INERT_FOREIGN_CHANGE')
                with self.assertRaises(m.Refusal):
                    self.controller.retained_created_unchanged()
                self.assertEqual(len(self.fake.calls), calls)
                self.assertTrue(self.controller.coordination_path.is_dir())
        self.assertEqual(marker.read_bytes(), b'INERT_FOREIGN_CHANGE')
        self.assertTrue(self.controller.coordination_path.is_dir())

    def test_plan_requires_exact_incident_and_explicit_coupled_grants(self):
        self.plan.validate()
        for plan in (replace(self.plan, held_lock_reconciliation_authorized=False),
                     replace(self.plan, darwin_host_mnt_helper=False),
                     replace(self.plan, align_api_cve_release=False),
                     replace(self.plan, prepare_rollout_only=True),
                     replace(self.plan, candidate_worker_image='sha256:' + 'e' * 64),
                     replace(self.plan, bindings=dict(self.plan.bindings, api=m.Binding('e' * 64, self.plan.bindings['api'].image)))):
            with self.assertRaises(m.Refusal):
                plan.validate()
        args = MigrationTests.cli(self)
        args[0] = '--reconcile-stopped-stand'
        args += ['--authorize-held-lock-reconciliation', '--darwin-host-mnt-helper', '--align-api-cve-release',
                 '--release-verifier-relative', self.plan.release_verifier,
                 '--release-verifier-test-relative', self.plan.release_verifier_test]
        self.assertEqual(m.arguments(args), self.plan)
        with self.assertRaises(m.Refusal):
            m.arguments(args + ['--activate-existing-api'])


class ReconciliationStageReceiptTests(unittest.TestCase):
    """Sticky production receipts, inert fixtures/clients/alarms; no held-state action."""
    def setUp(self):
        StoppedReconciliationTests.setUp(self)
        self.now, self.stage_events = [0.0], []
        self.observer = m.ReconciliationObservation(clock=lambda: self.now[0],
                                                    callback=lambda *e: self.stage_events.append(e))
        self.controller.observation = self.observer

    def result(self):
        result = self.observer.receipt(self.controller.activate())
        encoded = json.dumps(result)
        self.assertLessEqual(len(encoded.encode('ascii')), 4096)
        self.assertNotIn(SYNTHETIC_KEY, encoded)
        self.assertNotIn(str(self.repo), encoded)
        self.assertNotIn(m.RETAINED_CREATED_ID, encoded)
        self.assertEqual(result['mode'], 'stopped-stand-preservation-v1')
        self.assertTrue(result['manualReconciliationRequired'])
        self.assertNotIn('preparationOnly', result)
        return result

    assert_prior_untouched = StoppedReconciliationTests.assert_prior_untouched

    def test_existing_lock_failure_is_tagged_before_client_or_new_lock(self):
        self.controller.coordination_path.mkdir(mode=0o700)
        result = self.result()
        self.assertEqual((result['checkpoint'], result['category']),
                         ('RECONCILIATION_LOCK_CREATE', 'IO_REFUSED'))
        self.assertFalse(self.fake.calls)
        self.assert_prior_untouched()

    def test_prior_hold_mode_has_distinct_checkpoint(self):
        marker = self.prior / 'KEY_ACTIVATION_HOLD.json'
        marker.chmod(0o644)  # Synthetic fixture only.
        result = self.result()
        self.assertEqual((result['checkpoint'], result['category']),
                         ('PRIOR_HOLD_METADATA', 'PREDICATE_REFUSED'))
        self.assertFalse(self.controller.coordination_path.exists())
        self.assertFalse(self.fake.calls)

    def test_entry_root_failure_is_tagged_before_coordination(self):
        self.controller.root.chmod(0o777)  # Disposable fixture, never the real root.
        result = self.result()
        self.assertEqual((result['checkpoint'], result['category']), ('ENTRY_ROOT_METADATA', 'PREDICATE_REFUSED'))
        self.assertFalse(self.fake.calls)
        self.assertFalse(self.controller.coordination_path.exists())

    def test_hold_directory_fsync_failure_is_tagged_before_client(self):
        sync = m.sync_directory
        def failed(path):
            if Path(path) == self.controller.coordination_path:
                raise OSError(SYNTHETIC_KEY)
            return sync(path)
        with patch.object(m, 'sync_directory', side_effect=failed):
            result = self.result()
        self.assertEqual((result['checkpoint'], result['category']), ('HOLD_DIRECTORY_FSYNC', 'IO_REFUSED'))
        self.assertFalse(self.fake.calls)
        self.assertTrue((self.controller.coordination_path / 'KEY_ACTIVATION_HOLD.json').is_file())
        self.assert_prior_untouched()

    def test_observed_full_route_has_complete_receipt_and_same_bounds(self):
        result = self.result()
        self.assertTrue(result['ok'], result)
        self.assertEqual((result['checkpoint'], result['category']), ('COMPLETE', 'NONE'))
        self.assertTrue(self.controller.migration_matched and self.controller.migration_compatible)
        self.assertEqual(self.controller.exports, {'pre', 'post'})
        self.assertEqual(self.observer.deadline, 600)
        self.assertEqual(m.HOLDER_MS, 240000)
        self.assertEqual(m.SMALL_PENDING_SECONDS, 160)
        self.assertEqual(len([e for e in self.events if e[0] == 'recheck']), 3)
        self.assertFalse(any(c[:2] == ('docker', 'stop') for c in self.fake.calls))
        self.assert_prior_untouched()

    def test_source_failure_survives_different_coordination_teardown_error(self):
        original = self.controller.owned_lock
        teardown = []
        def owned():
            if self.observer.first is not None:
                teardown.append(True)
                raise OSError(SYNTHETIC_KEY)
            return original()
        with patch.object(self.controller, 'verify_sources', side_effect=m.Refusal(SYNTHETIC_KEY)), \
             patch.object(self.controller, 'owned_lock', side_effect=owned):
            result = self.result()
        self.assertTrue(teardown)  # Teardown ran; its exception did not replace the primary receipt.
        self.assertEqual((result['checkpoint'], result['category']), ('SOURCE_PINS', 'PREDICATE_REFUSED'))
        self.assertFalse(self.fake.calls)
        self.assert_prior_untouched()

    def test_teardown_only_error_is_tagged_without_changing_teardown(self):
        original = self.controller.owned_lock
        def owned():
            if self.observer.stack and self.observer.stack[-1] == 'LOCK_EXIT':
                raise OSError(SYNTHETIC_KEY)
            return original()
        with patch.object(self.controller, 'preflight'), \
             patch.object(self.controller, 'operate_migration', return_value={'ok': True}), \
             patch.object(self.controller, 'owned_lock', side_effect=owned):
            result = self.result()
        self.assertEqual((result['checkpoint'], result['category']), ('LOCK_EXIT', 'IO_REFUSED'))
        self.assertFalse(self.fake.calls)
        self.assertTrue((self.controller.coordination_path / 'KEY_ACTIVATION_HOLD.json').is_file())

    def test_capture_failure_and_retained_admission_have_fixed_stage(self):
        self.retained['status'] = 'running'
        result = self.result()
        self.assertEqual((result['checkpoint'], result['category']), ('RETAINED_CREATED', 'PREDICATE_REFUSED'))
        self.assertFalse(any(c[:2] == ('docker', 'create') for c in self.fake.calls))

    def test_first_release_recheck_exports_exact_verified_substage(self):
        failure = m.PinnedReleaseRefusal(fixed_stage='INVENTORY_EQUALITY', fixed_category='PREDICATE_REFUSED')
        with patch.object(self.controller, 'recheck_release', side_effect=failure):
            result = self.result()
        self.assertEqual((result['checkpoint'], result['category']),
                         ('FIRST_RELEASE_RECHECK__INVENTORY_EQUALITY', 'PREDICATE_REFUSED'))
        self.assertFalse(any(c[:2] == ('docker', 'create') for c in self.fake.calls))
        self.assert_prior_untouched()

    def test_deadline_is600_never_renewed_and_primary_stays_sticky(self):
        self.assertEqual(self.observer.deadline, 600)
        self.observer('SOURCE_PINS', 'ENTER')
        self.now[0] = 600
        with self.assertRaises(m.StageTimeout):
            self.observer.check()
        self.observer.fail('LOCK_EXIT', OSError(SYNTHETIC_KEY))
        result = self.observer.receipt({'ok': False})
        self.assertEqual((result['checkpoint'], result['category']), ('SOURCE_PINS', 'CLIENT_TIMEOUT'))
        self.assertEqual(self.observer.deadline, 600)
        self.assertEqual(m.PreparationObservation(clock=lambda: 0).deadline, 150)

    def test_callback_failure_is_closed_and_no_following_client(self):
        def callback(gate, event):
            if gate == 'ROOT_METADATA' and event == 'ENTER':
                raise RuntimeError(SYNTHETIC_KEY)
        self.observer.callback = callback
        result = self.result()
        self.assertEqual((result['checkpoint'], result['category']), ('ROOT_METADATA', 'OBSERVER_REFUSED'))
        self.assertFalse(self.fake.calls)
        self.assert_prior_untouched()

    def test_teardown_runs_even_when_exit_observer_throws(self):
        self.observer.callback = lambda *e: (_ for _ in ()).throw(RuntimeError(SYNTHETIC_KEY))
        ran = []
        with self.assertRaises(m.StageObserverRefusal):
            with m.observed_teardown_stage(self.observer, 'LOCK_EXIT'):
                ran.append(True)
        self.assertEqual(ran, [True])
        self.assertEqual(self.observer.first, ('LOCK_EXIT', 'OBSERVER_REFUSED'))

    def test_arguments_gate_load_and_bootstrap_failures_closed_in_main(self):
        # No source loader, factory, real runner or controller is executed here.
        output = io.BytesIO()
        with patch.object(m, 'arguments', side_effect=m.Refusal(SYNTHETIC_KEY)), \
             patch.object(m, 'BOOTSTRAP_OBSERVATION', None), \
             patch.object(m.sys, 'stdout', SimpleNamespace(buffer=output)):
            code = m.main(['--reconcile-stopped-stand'])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual((result['checkpoint'], result['category']), ('ARGUMENTS', 'PREDICATE_REFUSED'))
        self.assertNotIn(SYNTHETIC_KEY, output.getvalue().decode())
        output = io.BytesIO()
        with patch.object(m, 'arguments', return_value=self.plan), \
             patch.object(m, 'load_release_gate', side_effect=OSError(SYNTHETIC_KEY)), \
             patch.object(m, 'Controller') as controller, \
             patch.object(m, 'BOOTSTRAP_OBSERVATION', None), \
             patch.object(m.sys, 'stdout', SimpleNamespace(buffer=output)):
            code = m.main(['--reconcile-stopped-stand'])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual((result['checkpoint'], result['category']), ('SOURCE_GATE_LOAD', 'IO_REFUSED'))
        controller.assert_not_called()
        with patch.object(m, '_load_stand_composition', side_effect=m.BootstrapRefusal(SYNTHETIC_KEY)):
            observer = m.command_observation(['--reconcile-stopped-stand'])
            with self.assertRaises(m.BootstrapRefusal):
                m.load_stand_composition(observer)
        self.assertEqual(observer.receipt({'ok': False})['checkpoint'], 'BOOTSTRAP')

    def test_direct_bootstrap_exception_receipt_has_no_traceback_or_private_text(self):
        parsed = ast.parse((HERE / 'recreate_openrouter_key.py').read_text())
        block = next(n for n in parsed.body if isinstance(n, ast.Try) and
                     any(isinstance(a, ast.Assign) and any(isinstance(t, ast.Name) and t.id == '_stand'
                         for t in a.targets) for a in n.body))
        code = compile(ast.Module(body=[block], type_ignores=[]), '<INERT_BOOTSTRAP_EXCEPTION>', 'exec')
        output = io.BytesIO()
        observer = m.command_observation(['--reconcile-stopped-stand'])
        def refused(observation):
            with m.observed_stage(observation, 'BOOTSTRAP'):
                raise m.BootstrapRefusal(SYNTHETIC_KEY)
        namespace = {'__name__': '__main__', 'load_stand_composition': refused,
                     'BootstrapRefusal': m.BootstrapRefusal, 'BOOTSTRAP_OBSERVATION': observer,
                     'json': json, 'sys': SimpleNamespace(stdout=SimpleNamespace(buffer=output))}
        with self.assertRaises(SystemExit) as stopped:
            exec(code, namespace)
        self.assertEqual(stopped.exception.code, 1)
        result = json.loads(output.getvalue())
        self.assertEqual((result['checkpoint'], result['category']), ('BOOTSTRAP', 'PREDICATE_REFUSED'))
        self.assertTrue(result['manualReconciliationRequired'])
        self.assertNotIn(SYNTHETIC_KEY, output.getvalue().decode())
        self.assertNotIn('Traceback', output.getvalue().decode())

    def test_production_observation_does_not_inherit_preparation_client15_cap(self):
        # A sentinel Popen raises before any process. Its selected timeout is
        # checked by the typed policy expression, without running a client.
        source = ast.parse((HERE / 'recreate_openrouter_key.py').read_text())
        runner = next(n for n in source.body if isinstance(n, ast.ClassDef) and n.name == 'Runner')
        call = next(n for n in runner.body if isinstance(n, ast.FunctionDef) and n.name == '__call__')
        conditional = next(n for n in ast.walk(call) if isinstance(n, ast.If) and
                           'not isinstance(self.observation, ReconciliationObservation)' in ast.unparse(n.test))
        expr = compile(ast.Expression(conditional.test), '<INERT_PUBLIC_TIMEOUT_POLICY>', 'eval')
        args = ('docker', 'inspect', '--type', 'container', 'a' * 64)
        for observer, cap_expected in ((self.observer, False), (m.PreparationObservation(), True)):
            self.assertIs(eval(expr, {'isinstance': isinstance, 'tuple': tuple,
                                     'ReconciliationObservation': m.ReconciliationObservation,
                                     'self': SimpleNamespace(observation=observer), 'args': args}), cap_expected)


class SuccessorR2Tests(unittest.TestCase):
    """Fixed successor authority; both historical pairs are metadata-only barriers."""
    def setUp(self):
        ReconciliationStageReceiptTests.setUp(self)
        self.plan = replace(self.plan, successor_r2=True)
        self.controller.plan = self.fake.plan = self.plan
        self.previous_reconciliation = self.controller.root / '.key-preservation-reconcile.lock'
        self.previous_reconciliation.mkdir(mode=0o700)
        m.private_write(self.previous_reconciliation / 'KEY_ACTIVATION_HOLD.json', b'INERT_NOT_PARSED\n')
        self.previous_before = (m.path_metadata(self.previous_reconciliation, directory=True),
                                m.path_metadata(self.previous_reconciliation / 'KEY_ACTIVATION_HOLD.json', secret=True))

    result = ReconciliationStageReceiptTests.result

    def assert_prior_untouched(self):
        StoppedReconciliationTests.assert_prior_untouched(self)
        self.assertEqual(self.previous_before,
                         (m.path_metadata(self.previous_reconciliation, directory=True),
                          m.path_metadata(self.previous_reconciliation / 'KEY_ACTIVATION_HOLD.json', secret=True)))

    def test_explicit_cli_requires_complete_existing_incident_profile(self):
        args = MigrationTests.cli(self)
        args[0] = '--reconcile-stopped-stand'
        args += ['--authorize-held-lock-reconciliation', '--darwin-host-mnt-helper', '--align-api-cve-release',
                 '--release-verifier-relative', self.plan.release_verifier,
                 '--release-verifier-test-relative', self.plan.release_verifier_test, '--successor-r2']
        self.assertEqual(m.arguments(args), self.plan)
        for invalid in (replace(self.plan, reconcile_stopped_stand=False),
                        replace(self.plan, successor_r2=1),
                        replace(self.plan, held_lock_reconciliation_authorized=False),
                        replace(self.plan, darwin_host_mnt_helper=False),
                        replace(self.plan, align_api_cve_release=False)):
            with self.assertRaises(m.Refusal):
                invalid.validate()
        args[0] = '--activate-existing-api'
        with self.assertRaises(m.Refusal):
            m.arguments(args)
        self.assertFalse(self.fake.calls)

    def test_fixed_path_and_old_route_selection_are_unchanged(self):
        self.assertEqual(self.controller.coordination_path,
                         self.controller.root / '.key-preservation-reconcile-r2.lock')
        self.controller.plan = replace(self.plan, successor_r2=False)
        self.assertEqual(self.controller.coordination_path, self.previous_reconciliation)
        self.controller.plan = replace(self.plan, successor_r2=False, reconcile_stopped_stand=False)
        self.assertEqual(self.controller.coordination_path, self.prior)
        self.assertFalse(self.fake.calls)

    def test_full_fresh_sequence_preserves_both_pairs_no_historical_content_reads_or_old_starts(self):
        opened = m.os.open
        historical = {path for lock in (self.prior, self.previous_reconciliation)
                      for path in (lock, lock / 'KEY_ACTIVATION_HOLD.json')}
        def own_only(path, *args, **kwargs):
            if Path(path) in historical:
                raise AssertionError('NO_HISTORICAL_CONTENT_OPEN')
            return opened(path, *args, **kwargs)
        with patch.object(m.os, 'open', side_effect=own_only):
            StoppedReconciliationTests.test_full_fresh_route_preserves_prior_hold_retained_and_env_no_old_start(self)
        calls = self.fake.calls
        def operation(name):
            return next(i for i, c in enumerate(calls) if m.SCRIPT_TARGET in c and name in c)
        pre = next(i for i, c in enumerate(calls) if c[:2] == ('docker', 'cp') and '/backup/pre/.' in c[2])
        post = next(i for i, c in enumerate(calls) if c[:2] == ('docker', 'cp') and '/backup/post/.' in c[2])
        ups = [i for i, c in enumerate(calls) if 'up' in c]
        capture_post = next(i for i, c in enumerate(calls)
                            if m.SCRIPT_TARGET in c and 'capture' in c and c[-1] == '/backup/post')
        order = [operation('capture'), pre, operation('plan-migration'), operation('apply-migration'),
                 capture_post, operation('compare-migrated'), operation('compatibility'), post, *ups]
        self.assertEqual(order, sorted(order))
        self.assertEqual(len(ups), 2)
        self.assertEqual(calls[ups[0]][-2:], ('api', 'worker'))
        self.assertEqual(calls[ups[1]][-1], 'web')
        old_ids = {b.container for b in self.plan.bindings.values()}
        self.assertFalse(any(c[:2] == ('docker', 'start') and c[-1] in old_ids for c in calls))
        self.assertEqual(self.observer.deadline, 600)
        self.assertEqual((m.HOLDER_MS, m.SMALL_PENDING_SECONDS), (240000, 160))
        self.assertIn(('PRIOR_RECONCILIATION_HOLD_STABILITY', 'PASS'), self.stage_events)
        self.assert_prior_untouched()

    def test_existing_r2_refuses_before_client_no_fallback_or_adoption(self):
        r2 = self.controller.coordination_path
        r2.mkdir(mode=0o700)
        m.private_write(r2 / 'KEY_ACTIVATION_HOLD.json', b'INERT_FOREIGN_R2\n')
        identity = (m.path_metadata(r2, directory=True),
                    m.path_metadata(r2 / 'KEY_ACTIVATION_HOLD.json', secret=True))
        entries = set(self.controller.root.iterdir())
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual((result['checkpoint'], result['category']), ('RECONCILIATION_LOCK_CREATE', 'IO_REFUSED'))
        self.assertFalse(self.fake.calls)
        self.assertIsNone(self.controller.reconciliation_capability)
        self.assertEqual(set(self.controller.root.iterdir()), entries)
        self.assertEqual(identity, (m.path_metadata(r2, directory=True),
                                   m.path_metadata(r2 / 'KEY_ACTIVATION_HOLD.json', secret=True)))
        self.assert_prior_untouched()

    def test_missing_previous_hold_refuses_before_r2_creation(self):
        (self.previous_reconciliation / 'KEY_ACTIVATION_HOLD.json').unlink()  # Disposable fixture only.
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual((result['checkpoint'], result['category']),
                         ('PRIOR_RECONCILIATION_HOLD_METADATA', 'IO_REFUSED'))
        self.assertFalse(self.controller.coordination_path.exists())
        self.assertFalse(self.fake.calls)
        StoppedReconciliationTests.assert_prior_untouched(self)

    def test_previous_lock_mode_refuses_without_chmod_or_new_lock(self):
        self.previous_reconciliation.chmod(0o755)  # Disposable fixture only.
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual((result['checkpoint'], result['category']),
                         ('PRIOR_RECONCILIATION_LOCK_MODE', 'PREDICATE_REFUSED'))
        self.assertEqual(stat.S_IMODE(self.previous_reconciliation.stat().st_mode), 0o755)
        self.assertFalse(self.controller.coordination_path.exists())
        self.assertFalse(self.fake.calls)
        StoppedReconciliationTests.assert_prior_untouched(self)

    def test_previous_hold_drift_blocks_ownership_and_next_retained_client(self):
        marker = self.previous_reconciliation / 'KEY_ACTIVATION_HOLD.json'
        with self.assertRaises(m.Refusal):  # Teardown independently checks both historical pairs.
            with self.controller.coordination():
                marker.write_bytes(b'INERT_EXTERNAL_DRIFT')
                for boundary in (self.controller.owned_lock, self.controller.retained_created_unchanged):
                    with self.assertRaises(m.Refusal):
                        boundary()
                self.assertFalse(self.fake.calls)
        self.assertEqual(self.observer.first,
                         ('PRIOR_RECONCILIATION_HOLD_STABILITY', 'PREDICATE_REFUSED'))
        self.assertEqual(marker.read_bytes(), b'INERT_EXTERNAL_DRIFT')
        self.assertTrue((self.controller.coordination_path / 'KEY_ACTIVATION_HOLD.json').is_file())
        StoppedReconciliationTests.assert_prior_untouched(self)

    def test_first_prior_drift_is_still_rejected_without_repair(self):
        StoppedReconciliationTests.test_prior_hold_change_blocks_next_client_without_repair(self)
        self.assertEqual(self.previous_before,
                         (m.path_metadata(self.previous_reconciliation, directory=True),
                          m.path_metadata(self.previous_reconciliation / 'KEY_ACTIVATION_HOLD.json', secret=True)))

    def test_capture_refusal_retains_own_and_both_historical_holds_no_old_resume(self):
        self.fake.receipt_override['capture'] = m.encoded({'code': 'INFLIGHT', 'ok': False})
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertTrue(result['manualReconciliationRequired'])
        self.assertTrue((self.controller.coordination_path / 'KEY_ACTIVATION_HOLD.json').is_file())
        self.assertFalse(any('plan-migration' in c or 'apply-migration' in c or 'up' in c for c in self.fake.calls))
        old_ids = {b.container for b in self.plan.bindings.values()}
        self.assertFalse(any(c[:2] in (('docker', 'stop'), ('docker', 'start')) and c[-1] in old_ids
                             for c in self.fake.calls))
        self.assert_prior_untouched()

    def test_primary_failure_survives_coordination_teardown(self):
        ReconciliationStageReceiptTests.test_source_failure_survives_different_coordination_teardown_error(self)


class HolderStageTests(unittest.TestCase):
    """Holder attribution only; fake inspect/create/start, no real clients or alarms."""
    def setUp(self):
        ReconciliationStageReceiptTests.setUp(self)

    result = ReconciliationStageReceiptTests.result
    assert_prior_untouched = StoppedReconciliationTests.assert_prior_untouched

    def prepare(self):
        self.controller.old = {r: copy.deepcopy(self.fake.records[b.container]) for r, b in self.plan.bindings.items()}
        self.controller.images = {r: self.fake.images[b.image] for r, b in self.plan.bindings.items()}
        self.controller.volumes = self.fake.volumes
        self.controller.backup = self.controller.root / 'key-preservation-inert123'
        self.controller.backup.mkdir(mode=0o700)
        self.controller.phase = 'holder'

    def create(self):
        self.prepare()
        with patch.object(self.controller, 'resources'), patch.object(self.controller, 'writers'):
            self.controller.create_holder()

    def reset_observer(self):
        self.stage_events.clear()
        self.observer = m.ReconciliationObservation(clock=lambda: self.now[0],
                                                    callback=lambda *e: self.stage_events.append(e))
        self.controller.observation = self.observer

    def assert_closed(self, gate, category='PREDICATE_REFUSED'):
        result = self.observer.receipt({'ok': False, 'phase': 'holder', 'uncertain': True})
        self.assertEqual((result['checkpoint'], result['category']), (gate, category))
        public = json.dumps(result)
        for private in (SYNTHETIC_KEY, str(self.repo), self.controller.helper_id or 'INERT_PRIVATE_ID',
                        self.controller.helper_name or 'INERT_PRIVATE_NAME'):
            self.assertNotIn(private, public)
        self.assertLessEqual(len(public.encode('ascii')), 4096)

    def test_full_route_stages_are_balanced_and_do_not_change_migration_sequence(self):
        result = self.result()
        self.assertTrue(result['ok'], result)
        self.assertEqual((result['checkpoint'], result['category']), ('COMPLETE', 'NONE'))
        gates = ['HOLDER_SOURCE_PINS', 'HOLDER_RESOURCES_PRE', 'HOLDER_WRITERS_PRE', 'HOLDER_CAPACITY_PRE',
                 'HOLDER_INTENT_JOURNAL', 'HOLDER_CREATE_ARGS', 'HOLDER_CREATE', 'HOLDER_CREATE_ID',
                 'HOLDER_ID_JOURNAL', 'HOLDER_START', 'HOLDER_WRITERS_POST', 'HOLDER_JOURNAL_BINDING',
                 'HOLDER_INSPECT', 'HOLDER_DEFAULTS_PREP', 'HOLDER_IDENTITY', 'HOLDER_CONFIG_DEFAULTS',
                 'HOLDER_ENV_EQUAL', 'HOLDER_COMMAND', 'HOLDER_HEALTH_VOLUMES', 'HOLDER_SECURITY',
                 'HOLDER_RESOURCES', 'HOLDER_TMPFS_OPTIONS', 'HOLDER_RESTART_STOP', 'HOLDER_STATE',
                 'HOLDER_NETWORKS', 'HOLDER_MOUNTS_PREP', 'HOLDER_DECLARED_MOUNTS',
                 'HOLDER_ACTUAL_MOUNTS', 'HOLDER_ACTUAL_TMPFS']
        for gate in gates:
            self.assertIn((gate, 'PASS'), self.stage_events)
            self.assertEqual(self.stage_events.count((gate, 'ENTER')), self.stage_events.count((gate, 'PASS')))
        self.assertFalse(self.observer.stack)
        self.assertEqual(self.controller.exports, {'pre', 'post'})
        self.assertTrue(self.controller.migration_matched and self.controller.migration_compatible)
        self.assertFalse(any(c[:2] == ('docker', 'stop') for c in self.fake.calls))
        self.assertFalse(any(c[:2] == ('docker', 'start') and c[-1] in
                             {b.container for b in self.plan.bindings.values()} for c in self.fake.calls))
        self.assert_prior_untouched()

    def test_qualification_refusals_keep_default_semantics_and_exact_private_group(self):
        self.create()
        identity = self.controller.helper_id
        baseline = copy.deepcopy(self.fake.records[identity])
        variants = (
            ('HOLDER_IDENTITY', lambda r: r.update(Name='/INERT_FOREIGN_NAME')),
            ('HOLDER_CONFIG_DEFAULTS', lambda r: r['Config'].update(User='0:0')),
            ('HOLDER_CONFIG_DEFAULTS', lambda r: r['Config'].update(WorkingDir='/INERT_FOREIGN')),
            ('HOLDER_ENV_EQUAL', lambda r: r['Config'].update(Env=r['Config']['Env'] + ['INERT=' + SYNTHETIC_KEY])),
            ('HOLDER_COMMAND', lambda r: r['Config'].update(Cmd=['INERT_DIFFERENT_COMMAND'])),
            ('HOLDER_HEALTH_VOLUMES', lambda r: r['Config'].update(Healthcheck=None)),
            ('HOLDER_SECURITY', lambda r: r['HostConfig'].update(ReadonlyRootfs=False)),
            ('HOLDER_SECURITY', lambda r: r['HostConfig'].update(CgroupnsMode='host')),
            ('HOLDER_RESOURCES', lambda r: r['HostConfig'].update(MemorySwap=m.GIB)),
            ('HOLDER_TMPFS_OPTIONS', lambda r: r['HostConfig'].update(Tmpfs={})),
            ('HOLDER_RESTART_STOP', lambda r: r['Config'].update(StopTimeout=6)),
            ('HOLDER_STATE', lambda r: r['State'].update(Running=False)),
            ('HOLDER_NETWORKS', lambda r: r['NetworkSettings'].update(Networks={})),
            ('HOLDER_DECLARED_MOUNTS', lambda r: r['HostConfig']['Mounts'][-1].update(Source='/INERT_FOREIGN')),
            ('HOLDER_ACTUAL_MOUNTS', lambda r: r['Mounts'][-1].update(Source='/INERT_FOREIGN')),
            ('HOLDER_ACTUAL_TMPFS', lambda r: r['Mounts'].append(
                {'Type': 'tmpfs', 'Destination': '/INERT_FOREIGN', 'RW': True})),
        )
        for gate, mutate in variants:
            with self.subTest(gate=gate):
                changed = copy.deepcopy(baseline)
                mutate(changed)
                self.fake.records[identity] = changed
                self.controller.observation = None
                with self.assertRaises(m.Refusal):
                    self.controller.qualify_holder(True)
                self.reset_observer()
                first = len(self.fake.calls)
                with self.assertRaises(m.Refusal):
                    self.controller.qualify_holder(True)
                self.assert_closed(gate)
                # The classifier path uses one existing-holder inspect only: no exec/start/create/cp.
                self.assertEqual(len(self.fake.calls[first:]), 1)
                self.assertEqual(self.fake.calls[first][:2], ('docker', 'inspect'))
        self.fake.records[identity] = baseline
        self.controller.observation = None
        self.assertEqual(self.controller.qualify_holder(True), baseline)
        self.reset_observer()
        self.assertEqual(self.controller.qualify_holder(True), baseline)

    def test_qualification_journal_inspect_and_defaults_failures_are_distinct(self):
        self.create()
        self.reset_observer()
        metadata = self.controller.holder_journal_metadata
        self.controller.holder_journal_metadata = None
        before = len(self.fake.calls)
        with self.assertRaises(m.Refusal):
            self.controller.qualify_holder(True)
        self.assert_closed('HOLDER_JOURNAL_BINDING')
        self.assertEqual(len(self.fake.calls), before)
        self.controller.holder_journal_metadata = metadata
        self.reset_observer()
        with patch.object(self.controller, 'inspect', side_effect=m.Refusal(SYNTHETIC_KEY)), self.assertRaises(m.Refusal):
            self.controller.qualify_holder(True)
        self.assert_closed('HOLDER_INSPECT')
        self.reset_observer()
        with patch.dict(self.controller.images, {'api': {}}), self.assertRaises(KeyError):
            self.controller.qualify_holder(True)
        self.assert_closed('HOLDER_DEFAULTS_PREP', 'UNEXPECTED')
        self.reset_observer()
        with patch.dict(self.controller.volumes, {}, clear=True), self.assertRaises(KeyError):
            self.controller.qualify_holder(True)
        self.assert_closed('HOLDER_MOUNTS_PREP', 'UNEXPECTED')

    def test_precreate_guards_fail_before_journals_or_clients(self):
        self.prepare()
        with patch.object(self.controller, 'verify_sources') as sources, \
             patch.object(self.controller, 'resources') as resources, \
             patch.object(self.controller, 'writers') as writers, \
             patch.object(self.controller, 'capacity') as capacity:
            for operation, gate in ((sources, 'HOLDER_SOURCE_PINS'), (resources, 'HOLDER_RESOURCES_PRE'),
                                    (writers, 'HOLDER_WRITERS_PRE'), (capacity, 'HOLDER_CAPACITY_PRE')):
                self.reset_observer()
                operation.side_effect = m.Refusal(SYNTHETIC_KEY)
                with self.assertRaises(m.Refusal):
                    self.controller.create_holder()
                self.assert_closed(gate)
                self.assertFalse(list(self.controller.backup.iterdir()))
                self.assertFalse(self.fake.calls)
                operation.side_effect = None

    def test_intent_fsync_failure_has_fixed_stage_and_no_create(self):
        self.prepare()
        with patch.object(self.controller, 'resources'), patch.object(self.controller, 'writers'), \
             patch.object(m, 'sync_directory', side_effect=OSError(SYNTHETIC_KEY)), self.assertRaises(OSError):
            self.controller.create_holder()
        self.assert_closed('HOLDER_INTENT_JOURNAL', 'IO_REFUSED')
        self.assertFalse(self.fake.calls)

    def test_create_refusal_does_not_claim_id_or_start(self):
        self.prepare()
        self.fake.fail_on = lambda c: c[:2] == ('docker', 'create')
        self.fake.failure = m.Refusal(SYNTHETIC_KEY)
        with patch.object(self.controller, 'resources'), patch.object(self.controller, 'writers'), self.assertRaises(m.Refusal):
            self.controller.create_holder()
        self.assert_closed('HOLDER_CREATE')
        self.assertIsNone(self.controller.helper_id)
        self.assertFalse(any(c[:2] == ('docker', 'start') for c in self.fake.calls))

    def test_id_journal_failure_keeps_created_holder_unstarted(self):
        self.prepare()
        sync = m.sync_directory
        def refuse_id(path):
            if (self.controller.backup / 'holder-id.json').exists():
                raise OSError(SYNTHETIC_KEY)
            return sync(path)
        with patch.object(self.controller, 'resources'), patch.object(self.controller, 'writers'), \
             patch.object(m, 'sync_directory', side_effect=refuse_id), self.assertRaises(OSError):
            self.controller.create_holder()
        self.assert_closed('HOLDER_ID_JOURNAL', 'IO_REFUSED')
        self.assertFalse(self.fake.records[self.controller.helper_id]['State']['Running'])
        self.assertFalse(any(c[:2] == ('docker', 'start') for c in self.fake.calls))

    def test_first_qualification_refusal_is_not_collapsed_to_migration_or_started(self):
        self.prepare()
        self.alias_mutation = lambda r: r['Config'].update(Env=['INERT=' + SYNTHETIC_KEY])
        with patch.object(self.controller, 'resources'), patch.object(self.controller, 'writers'), self.assertRaises(m.Refusal):
            with self.controller.stage('MIGRATION'):
                self.controller.create_holder()
        self.assert_closed('HOLDER_ENV_EQUAL')
        self.observer.fail('LOCK_EXIT', OSError(SYNTHETIC_KEY))
        self.assert_closed('HOLDER_ENV_EQUAL')
        self.assertIsNotNone(self.controller.holder_journal_metadata)
        self.assertFalse(any(c[:2] == ('docker', 'start') for c in self.fake.calls))
        self.assertFalse(self.fake.captured)

    def test_start_failure_has_fixed_stage_and_no_capture(self):
        self.prepare()
        self.fake.fail_on = lambda c: c[:2] == ('docker', 'start')
        self.fake.failure = m.Refusal(SYNTHETIC_KEY)
        with patch.object(self.controller, 'resources'), patch.object(self.controller, 'writers'), self.assertRaises(m.Refusal):
            self.controller.create_holder()
        self.assert_closed('HOLDER_START')
        self.assertFalse(self.fake.captured)

    def test_postwriter_fence_refuses_after_qualified_start_without_capture(self):
        self.prepare()
        with patch.object(self.controller, 'resources'), \
             patch.object(self.controller, 'writers', side_effect=[None, m.Refusal(SYNTHETIC_KEY)]), \
             self.assertRaises(m.Refusal):
            self.controller.create_holder()
        self.assert_closed('HOLDER_WRITERS_POST')
        self.assertTrue(self.fake.records[self.controller.helper_id]['State']['Running'])
        self.assertFalse(self.fake.captured)

    def test_malformed_create_response_is_tagged_before_id_journal_or_start(self):
        self.prepare()
        run = self.controller.run
        def malformed(args, **kwargs):
            result = run(args, **kwargs)
            return b'INERT_INVALID_ID' if tuple(args[:2]) == ('docker', 'create') else result
        self.controller.run = malformed
        with patch.object(self.controller, 'resources'), patch.object(self.controller, 'writers'), self.assertRaises(m.Refusal):
            self.controller.create_holder()
        self.assert_closed('HOLDER_CREATE_ID')
        self.assertIsNone(self.controller.helper_id)
        self.assertFalse((self.controller.backup / 'holder-id.json').exists())
        self.assertFalse(any(c[:2] == ('docker', 'start') for c in self.fake.calls))

    def test_observer_failure_during_readonly_qualification_is_closed(self):
        self.create()
        self.reset_observer()
        first = len(self.fake.calls)
        def fail(gate, event):
            if (gate, event) == ('HOLDER_SECURITY', 'ENTER'):
                raise RuntimeError(SYNTHETIC_KEY)
        self.observer.callback = fail
        with self.assertRaises(m.StageObserverRefusal):
            self.controller.qualify_holder(True)
        self.assert_closed('HOLDER_SECURITY', 'OBSERVER_REFUSED')
        self.assertEqual(len(self.fake.calls[first:]), 1)
        self.assertEqual(self.fake.calls[first][:2], ('docker', 'inspect'))
        self.assertNotIn(('HOLDER_RESOURCES', 'ENTER'), self.stage_events)

    def test_stage_deadline_prevents_next_create_client(self):
        self.prepare()
        def expire(gate, event):
            if (gate, event) == ('HOLDER_CREATE', 'ENTER'):
                self.now[0] = 600
        self.observer.callback = expire
        with patch.object(self.controller, 'resources'), patch.object(self.controller, 'writers'), self.assertRaises(m.StageTimeout):
            self.controller.create_holder()
        self.assert_closed('HOLDER_CREATE', 'CLIENT_TIMEOUT')
        self.assertFalse(self.fake.calls)
        self.assertEqual(self.observer.deadline, 600)


class WriterMountOrderTests(unittest.TestCase):
    """Independent inspect order only; no real holder, clients, stores or signals."""
    def setUp(self):
        HolderStageTests.setUp(self)
        HolderStageTests.create(self)
        self.controller.prior_hold_metadata = self.prior_before
        for mount in self.fake.records[self.controller.helper_id]['Mounts']:
            mount.update(Mode='rw' if mount['RW'] else 'ro', Propagation='rprivate')
            if mount['Type'] == 'volume':
                mount['Driver'] = 'local'
        self.project = lambda mounts: list(reversed(mounts))
        run = self.controller.run
        def reordered(args, **kwargs):
            data = run(args, **kwargs)
            if tuple(args[:2]) == ('docker', 'inspect') and '--format' in args and m.RETAINED_FORMAT not in args:
                rows = [m.decode(row) for row in data.splitlines()]
                for row in rows:
                    if row['id'] == self.controller.helper_id:
                        row['mounts'] = self.project(row['mounts'])
                return b''.join(m.encoded(row) for row in rows)
            return data
        self.controller.run = reordered

    prepare = HolderStageTests.prepare

    def test_reordered_independent_projection_passes_without_any_write_client(self):
        qualified = self.controller.qualify_holder(True)['Mounts']
        self.assertNotEqual(qualified, list(reversed(qualified)))  # Old list equality would refuse.
        before = len(self.fake.calls)
        self.controller.writers(set())
        calls = self.fake.calls[before:]
        self.assertTrue(any('--format' in call and m.RETAINED_FORMAT not in call for call in calls))
        self.assertTrue(all(call[:2] in (('docker', 'inspect'), ('docker', 'info'), ('docker', 'ps')) for call in calls))
        self.assertFalse(self.fake.captured)

    def test_changed_missing_extra_or_duplicate_full_entry_refuses_after_reordering(self):
        def remove_mode(mounts):
            mounts[0].pop('Mode')
        mutations = (
            lambda mounts: mounts[0].update(Source=mounts[0]['Source'] + '/'),
            lambda mounts: mounts[0].update(Destination=mounts[0]['Destination'] + '/'),
            lambda mounts: mounts[0].update(RW=False),
            lambda mounts: mounts[0].update(Type='bind'),
            lambda mounts: mounts[0].update(Name='INERT_OTHER_VOLUME'),
            lambda mounts: mounts[0].update(Propagation='shared'),
            lambda mounts: mounts[0].update(Driver='INERT_OTHER_DRIVER'),
            lambda mounts: mounts[0].update(INERT_EXTRA_FIELD=None),
            remove_mode,
            lambda mounts: mounts.append(copy.deepcopy(mounts[0])),
            lambda mounts: mounts.pop(),
        )
        for index, mutate in enumerate(mutations):
            def changed(mounts, mutate=mutate):
                mutate(mounts)
                return list(reversed(mounts))
            self.project = changed
            before = len(self.fake.calls)
            with self.subTest(case=index), self.assertRaises(m.Refusal):
                self.controller.writers(set())
            self.assertTrue(all(c[:2] in (('docker', 'inspect'), ('docker', 'info'), ('docker', 'ps'))
                                for c in self.fake.calls[before:]))
        self.assertFalse(self.fake.captured)

    def test_full_entry_canonicalization_retains_duplicates_types_and_nested_order(self):
        mount = {'Type': 'bind', 'Source': '/INERT/a/../b', 'Destination': '/INERT/target',
                 'RW': False, 'INERT_nested': {'sequence': ['a', 'b']}}
        reordered_keys = dict(reversed(list(mount.items())))
        self.assertEqual(m.full_mount_entries([mount]), m.full_mount_entries([reordered_keys]))
        self.assertNotEqual(m.full_mount_entries([mount, mount]), m.full_mount_entries([mount]))
        for changed in (dict(mount, Source='/INERT/b'), dict(mount, RW=0),
                        dict(mount, INERT_nested={'sequence': ['b', 'a']}), dict(mount, INERT_extra=None)):
            self.assertNotEqual(m.full_mount_entries([mount]), m.full_mount_entries([changed]))
        for malformed in (None, {}, [None], ['INERT_NOT_A_MOUNT']):
            with self.assertRaises(m.Refusal):
                m.full_mount_entries(malformed)


class SuccessorR3Tests(unittest.TestCase):
    """One fixed R3 continuation; three immutable historical pairs, no retirement action."""
    def setUp(self):
        SuccessorR2Tests.setUp(self)
        self.plan = replace(self.plan, successor_r2=False, successor_r3=True)
        self.controller.plan = self.fake.plan = self.plan
        self.previous_r2 = self.controller.root / '.key-preservation-reconcile-r2.lock'
        self.previous_r2.mkdir(mode=0o700)
        m.private_write(self.previous_r2 / 'KEY_ACTIVATION_HOLD.json', b'INERT_R2_NOT_PARSED\n')
        self.r2_before = (m.path_metadata(self.previous_r2, directory=True),
                          m.path_metadata(self.previous_r2 / 'KEY_ACTIVATION_HOLD.json', secret=True))

    result = ReconciliationStageReceiptTests.result

    def assert_prior_untouched(self):
        SuccessorR2Tests.assert_prior_untouched(self)
        self.assertEqual(self.r2_before, (m.path_metadata(self.previous_r2, directory=True),
                                        m.path_metadata(self.previous_r2 / 'KEY_ACTIVATION_HOLD.json', secret=True)))

    def retired_record(self):
        # State is deliberately irrelevant to absence; any occurrence must refuse.
        self.fake.records[m.RETIRED_R2_HOLDER_ID] = {'Id': m.RETIRED_R2_HOLDER_ID,
            'State': {'Running': False, 'Paused': True}, 'Config': {'Labels': {}}, 'Mounts': []}

    def test_cli_requires_complete_incident_profile_and_excludes_r2(self):
        args = MigrationTests.cli(self)
        args[0] = '--reconcile-stopped-stand'
        args += ['--authorize-held-lock-reconciliation', '--darwin-host-mnt-helper', '--align-api-cve-release',
                 '--release-verifier-relative', self.plan.release_verifier,
                 '--release-verifier-test-relative', self.plan.release_verifier_test, '--successor-r3']
        self.assertEqual(m.arguments(args), self.plan)
        for invalid in (replace(self.plan, reconcile_stopped_stand=False),
                        replace(self.plan, successor_r2=True), replace(self.plan, successor_r3=1),
                        replace(self.plan, held_lock_reconciliation_authorized=False),
                        replace(self.plan, preservation_migration=False),
                        replace(self.plan, align_api_cve_release=False)):
            with self.assertRaises(m.Refusal):
                invalid.validate()
        with self.assertRaises(m.Refusal):
            m.arguments(args + ['--successor-r2'])
        args[0] = '--activate-existing-api'
        with self.assertRaises(m.Refusal):
            m.arguments(args)
        self.assertFalse(self.fake.calls)

    def test_fixed_path_and_existing_routes_are_unchanged(self):
        self.assertEqual(self.controller.coordination_path,
                         self.controller.root / '.key-preservation-reconcile-r3.lock')
        self.controller.plan = replace(self.plan, successor_r3=False, successor_r2=True)
        self.assertEqual(self.controller.coordination_path, self.previous_r2)
        self.controller.plan = replace(self.plan, successor_r3=False)
        self.assertEqual(self.controller.coordination_path, self.previous_reconciliation)
        self.controller.plan = replace(self.plan, successor_r3=False, reconcile_stopped_stand=False)
        self.assertEqual(self.controller.coordination_path, self.prior)
        self.assertFalse(self.fake.calls)

    def test_full_fresh_pipeline_preserves_three_pairs_and_checks_absence_before_verifier(self):
        opened, verify = m.os.open, self.gate.verify
        historical = {p for lock in (self.prior, self.previous_reconciliation, self.previous_r2)
                      for p in (lock, lock / 'KEY_ACTIVATION_HOLD.json')}
        def no_historical_open(path, *args, **kwargs):
            if Path(path) in historical:
                raise AssertionError('NO_HISTORICAL_CONTENT_OPEN')
            return opened(path, *args, **kwargs)
        def verified(request):
            self.assertIn(('RETIRED_R2_CENSUS', 'PASS'), self.stage_events)
            self.assertIn(('RETIRED_R2_ABSENCE', 'PASS'), self.stage_events)
            self.assertIsNotNone(self.controller.prior_r2_hold_metadata)
            self.assertTrue((self.controller.coordination_path / 'KEY_ACTIVATION_HOLD.json').is_file())
            return verify(request)
        with patch.object(m.os, 'open', side_effect=no_historical_open), \
             patch.object(self.gate, 'verify', side_effect=verified):
            SuccessorR2Tests.test_full_fresh_sequence_preserves_both_pairs_no_historical_content_reads_or_old_starts(self)
        self.assertIn(('PRIOR_R2_HOLD_STABILITY', 'PASS'), self.stage_events)
        self.assertLess(self.stage_events.index(('RETIRED_R2_ABSENCE', 'PASS')),
                        self.stage_events.index(('PRIVATE_DIRECTORY', 'ENTER')))
        self.assertGreater(self.stage_events.count(('RETIRED_R2_ABSENCE', 'PASS')), 1)
        self.assertFalse(any(m.RETIRED_R2_HOLDER_ID in call for call in self.fake.calls))
        self.assert_prior_untouched()

    def test_existing_r3_refuses_no_fallback_adoption_or_client(self):
        SuccessorR2Tests.test_existing_r2_refuses_before_client_no_fallback_or_adoption(self)

    def test_missing_r2_hold_refuses_before_r3_create(self):
        (self.previous_r2 / 'KEY_ACTIVATION_HOLD.json').unlink()  # OWN disposable fixture only.
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual((result['checkpoint'], result['category']), ('PRIOR_R2_HOLD_METADATA', 'IO_REFUSED'))
        self.assertFalse(self.controller.coordination_path.exists())
        self.assertFalse(self.fake.calls)
        SuccessorR2Tests.assert_prior_untouched(self)

    def test_unsafe_r2_lock_refuses_without_permissions_repair(self):
        self.previous_r2.chmod(0o755)  # OWN disposable fixture only.
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual((result['checkpoint'], result['category']), ('PRIOR_R2_LOCK_MODE', 'PREDICATE_REFUSED'))
        self.assertEqual(stat.S_IMODE(self.previous_r2.stat().st_mode), 0o755)
        self.assertFalse(self.controller.coordination_path.exists())
        self.assertFalse(self.fake.calls)
        SuccessorR2Tests.assert_prior_untouched(self)

    def test_r2_hold_drift_blocks_ownership_and_client_without_repair(self):
        marker = self.previous_r2 / 'KEY_ACTIVATION_HOLD.json'
        with self.assertRaises(m.Refusal):
            with self.controller.coordination():
                marker.write_bytes(b'INERT_EXTERNAL_R2_DRIFT')
                for boundary in (self.controller.owned_lock, self.controller.retained_created_unchanged):
                    with self.assertRaises(m.Refusal):
                        boundary()
                self.assertFalse(self.fake.calls)
        self.assertEqual(self.observer.first, ('PRIOR_R2_HOLD_STABILITY', 'PREDICATE_REFUSED'))
        self.assertEqual(marker.read_bytes(), b'INERT_EXTERNAL_R2_DRIFT')
        self.assertTrue((self.controller.coordination_path / 'KEY_ACTIVATION_HOLD.json').is_file())
        SuccessorR2Tests.assert_prior_untouched(self)

    def test_original_hold_drift_remains_rejected_with_both_later_pairs_unchanged(self):
        StoppedReconciliationTests.test_prior_hold_change_blocks_next_client_without_repair(self)
        self.assertEqual(self.previous_before,
                         (m.path_metadata(self.previous_reconciliation, directory=True),
                          m.path_metadata(self.previous_reconciliation / 'KEY_ACTIVATION_HOLD.json', secret=True)))
        self.assertEqual(self.r2_before, (m.path_metadata(self.previous_r2, directory=True),
                                        m.path_metadata(self.previous_r2 / 'KEY_ACTIVATION_HOLD.json', secret=True)))

    def test_earlier_historical_drift_guards_remain_active(self):
        SuccessorR2Tests.test_previous_hold_drift_blocks_ownership_and_next_retained_client(self)
        self.assertEqual(self.r2_before, (m.path_metadata(self.previous_r2, directory=True),
                                        m.path_metadata(self.previous_r2 / 'KEY_ACTIVATION_HOLD.json', secret=True)))

    def test_retired_presence_refuses_before_scratch_verifier_or_holder(self):
        self.retired_record()
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual((result['checkpoint'], result['category']), ('RETIRED_R2_ABSENCE', 'PREDICATE_REFUSED'))
        self.assertIsNone(self.controller.backup)
        self.assertFalse(self.events)
        self.assertFalse(any(c[:2] in (('docker', 'create'), ('docker', 'start'), ('docker', 'stop'), ('docker', 'rm'))
                             or 'up' in c for c in self.fake.calls))
        self.assertIn(m.RETIRED_R2_HOLDER_ID, self.fake.records)
        self.assert_prior_untouched()

    def test_retired_reappearance_after_recheck_refuses_before_holder_create(self):
        recheck = self.gate.recheck
        def reappeared(request, seal):
            recheck(request, seal)
            self.retired_record()
        with patch.object(self.gate, 'recheck', side_effect=reappeared):
            result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual((result['checkpoint'], result['category']), ('RETIRED_R2_ABSENCE', 'PREDICATE_REFUSED'))
        self.assertFalse(any(c[:2] in (('docker', 'create'), ('docker', 'start'), ('docker', 'stop'), ('docker', 'rm'))
                             or 'up' in c for c in self.fake.calls))
        self.assertFalse(self.fake.captured)
        self.assert_prior_untouched()

    def test_census_timeout_is_not_absence_or_retry(self):
        run = self.controller.run
        census = ('docker', 'ps', '-a', '--no-trunc', '--format', '{{.ID}}')
        def ambiguous(args, **kwargs):
            if tuple(args) == census:
                self.fake.calls.append(tuple(args))
                raise m.StageTimeout()
            return run(args, **kwargs)
        self.controller.run = ambiguous
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual((result['checkpoint'], result['category']), ('RETIRED_R2_CENSUS', 'CLIENT_TIMEOUT'))
        self.assertEqual(self.fake.calls.count(census), 1)
        self.assertIsNone(self.controller.backup)
        self.assertFalse(self.events)
        self.assertEqual(self.observer.deadline, 600)
        self.assert_prior_untouched()

    def test_census_duplicate_malformed_and_over32_refuse(self):
        valid = self.plan.bindings['api'].container
        values = ((valid + '\n' + valid + '\n').encode(), b'INERT_INVALID_ID\n',
                  ('\n'.join(format(i + 1, '064x') for i in range(33)) + '\n').encode())
        for data in values:
            self.controller.observation = m.ReconciliationObservation(clock=lambda: 0)
            with patch.object(self.controller, 'run', return_value=data) as client, self.assertRaises(m.Refusal):
                self.controller.require_retired_r2_absent()
            client.assert_called_once_with(('docker', 'ps', '-a', '--no-trunc', '--format', '{{.ID}}'), cap=m.MIB)
            self.assertEqual(self.controller.observation.first, ('RETIRED_R2_CENSUS', 'PREDICATE_REFUSED'))
        self.assertFalse(self.fake.calls)

    def test_old_routes_do_not_add_absence_census(self):
        self.controller.plan = replace(self.plan, successor_r3=False, successor_r2=True)
        with patch.object(self.controller, 'run', side_effect=AssertionError('NO_EXTRA_OLD_ROUTE_CLIENT')):
            self.controller.require_retired_r2_absent()
        self.assertFalse(self.fake.calls)


class WriterStageTests(unittest.TestCase):
    """Pre-holder fence attribution: metadata-only fake clients, no new actor or lock."""
    def setUp(self):
        SuccessorR3Tests.setUp(self)
        self.controller.prior_hold_metadata = self.prior_before
        self.controller.prior_reconciliation_hold_metadata = self.previous_before
        self.controller.prior_r2_hold_metadata = self.r2_before
        self.controller.images = {r: self.fake.images[b.image] for r, b in self.plan.bindings.items()}
        self.controller.volumes = self.fake.volumes
        self.controller.daemon = self.fake.daemon  # A prior observation, not a same-read stability assertion.
        self.controller.phase = 'holder'
        self.rewrite = lambda args, data: data
        run = self.controller.run
        def projected(args, **kwargs):
            return self.rewrite(tuple(args), run(args, **kwargs))
        self.controller.run = projected

    prepare = HolderStageTests.prepare

    def reset_observer(self):
        self.stage_events.clear()
        self.observer = m.ReconciliationObservation(clock=lambda: self.now[0],
                                                    callback=lambda *e: self.stage_events.append(e))
        self.controller.observation = self.observer

    def fence(self):
        with self.controller.stage('HOLDER_WRITERS_PRE'):
            self.controller.writers(set())

    def assert_closed(self, gate, category='PREDICATE_REFUSED'):
        result = self.observer.receipt({'ok': False, 'phase': 'holder', 'uncertain': True})
        self.assertEqual((result['checkpoint'], result['category']), (gate, category))
        public = json.dumps(result)
        self.assertLessEqual(len(public.encode('ascii')), 4096)
        for private in (SYNTHETIC_KEY, str(self.repo), m.RETAINED_CREATED_ID, m.RETIRED_R2_HOLDER_ID, self.fake.daemon):
            self.assertNotIn(private, public)

    def assert_reads_only(self):
        self.assertTrue(all(c[:2] in (('docker', 'inspect'), ('docker', 'info'), ('docker', 'ps'))
                            for c in self.fake.calls))
        self.assertFalse(self.fake.captured)
        self.assertIsNone(self.controller.helper_id)

    def test_preholder_success_is_readonly_and_observed_default_equivalent(self):
        self.controller.observation = None
        self.fence()
        self.reset_observer()
        self.fence()
        for gate in ('RETAINED_CREATED', 'WRITER_DAEMON_READ', 'WRITER_DAEMON_SHAPE',
                     'WRITER_DAEMON_STABILITY', 'WRITER_CENSUS', 'WRITER_HOLDER_PRESENCE',
                     'WRITER_BATCH_READ', 'WRITER_BATCH_ROWCOUNT', 'WRITER_ROW_PARSE',
                     'WRITER_ROW_SCHEMA', 'WRITER_ROW_ID_UNIQUE', 'WRITER_TOUCH_CLASSIFY'):
            self.assertIn((gate, 'PASS'), self.stage_events)
            self.assertEqual(self.stage_events.count((gate, 'ENTER')), self.stage_events.count((gate, 'PASS')))
        self.assertNotIn(('WRITER_HOLDER_QUALIFY', 'ENTER'), self.stage_events)
        self.assertFalse(self.observer.stack)
        self.assert_reads_only()

    def test_retained_raw_stability_refusal_has_existing_fixed_stage_before_next_client(self):
        self.controller.retained_created_unchanged()
        self.retained['declared'] = [{'INERT_current': True}]
        self.fake.calls.clear()  # Only the synthetic client trace, never runtime logs.
        with self.assertRaises(m.Refusal):
            self.fence()
        self.assert_closed('RETAINED_CREATED')
        self.assertNotIn(('WRITER_DAEMON_READ', 'ENTER'), self.stage_events)
        self.assertEqual(len(self.fake.calls), 1)
        self.assert_reads_only()

    def test_daemon_census_and_row_failures_preserve_default_refusal_and_attribution(self):
        daemon = ('docker', 'info', '--format', '{{json .ID}}')
        census = ('docker', 'ps', '-a', '--no-trunc', '--format', '{{.ID}}')
        def daemon_value(value):
            return lambda args, data: value if args == daemon else data
        def census_value(value):
            return lambda args, data: value if args == census else data
        def rows_changed(change):
            def rewrite(args, data):
                if args[:2] == ('docker', 'inspect') and '--format' in args and m.RETAINED_FORMAT not in args:
                    rows = [m.decode(row) for row in data.splitlines()]
                    return change(rows)
                return data
            return rewrite
        def schema(rows):
            rows[0].pop('mounts')
            return b''.join(m.encoded(row) for row in rows)
        def duplicate(rows):
            rows[1]['id'] = rows[0]['id']
            return b''.join(m.encoded(row) for row in rows)
        def classification(rows):
            rows[0]['mounts'] = [{'Source': 1}]
            return b''.join(m.encoded(row) for row in rows)
        def active(rows):
            next(row for row in rows if row['id'] == self.plan.bindings['api'].container)['running'] = True
            return b''.join(m.encoded(row) for row in rows)
        cases = (
            ('WRITER_DAEMON_READ', 'PREDICATE_REFUSED', m.Refusal, daemon_value(b'{')),
            ('WRITER_DAEMON_SHAPE', 'PREDICATE_REFUSED', m.Refusal, daemon_value(m.encoded(''))),
            ('WRITER_DAEMON_STABILITY', 'PREDICATE_REFUSED', m.Refusal, daemon_value(m.encoded('INERT_OTHER_DAEMON'))),
            ('WRITER_CENSUS', 'PREDICATE_REFUSED', m.Refusal, census_value(b'INERT_INVALID_ID\n')),
            ('WRITER_BATCH_ROWCOUNT', 'PREDICATE_REFUSED', m.Refusal,
             rows_changed(lambda rows: b''.join(m.encoded(row) for row in rows[:-1]))),
            ('WRITER_ROW_PARSE', 'PREDICATE_REFUSED', m.Refusal,
             rows_changed(lambda rows: b'{\n' + b''.join(m.encoded(row) for row in rows[1:]))),
            ('WRITER_ROW_SCHEMA', 'PREDICATE_REFUSED', m.Refusal, rows_changed(schema)),
            ('WRITER_ROW_ID_UNIQUE', 'PREDICATE_REFUSED', m.Refusal, rows_changed(duplicate)),
            ('WRITER_TOUCH_CLASSIFY', 'UNEXPECTED', AttributeError, rows_changed(classification)),
            ('WRITER_ACTIVE_OTHER_ACCESS', 'PREDICATE_REFUSED', m.Refusal, rows_changed(active)),
        )
        for gate, category, exception, rewrite in cases:
            with self.subTest(gate=gate):
                self.rewrite = rewrite
                self.controller.observation = None
                with self.assertRaises(exception):
                    self.fence()
                self.reset_observer()
                with self.assertRaises(exception):
                    self.fence()
                self.assert_closed(gate, category)
                self.observer.fail('LOCK_EXIT', OSError(SYNTHETIC_KEY))
                self.assert_closed(gate, category)
        self.assert_reads_only()

    def test_batch_transport_failure_is_not_row_or_access_refusal(self):
        run = self.controller.run
        def timeout(args, **kwargs):
            if tuple(args[:2]) == ('docker', 'inspect') and '--format' in args and m.RETAINED_FORMAT not in args:
                raise m.StageTimeout()
            return run(args, **kwargs)
        self.controller.run = timeout
        with self.assertRaises(m.StageTimeout):
            self.fence()
        self.assert_closed('WRITER_BATCH_READ', 'CLIENT_TIMEOUT')
        self.assertNotIn(('WRITER_ROW_PARSE', 'ENTER'), self.stage_events)
        self.assert_reads_only()

    def test_holder_presence_and_full_mount_checks_have_separate_stages(self):
        # Fake holder only; never Docker or SQL. Both cases replay read-only observations.
        HolderStageTests.create(self)
        identity = self.controller.helper_id
        self.reset_observer()
        census = ('docker', 'ps', '-a', '--no-trunc', '--format', '{{.ID}}')
        def missing(args, data):
            if args == census:
                return ('\n'.join(i for i in data.decode('ascii').splitlines() if i != identity) + '\n').encode()
            return data
        self.rewrite = missing
        with self.assertRaises(m.Refusal):
            self.fence()
        self.assert_closed('WRITER_HOLDER_PRESENCE')
        self.reset_observer()
        def drift(args, data):
            if args[:2] == ('docker', 'inspect') and '--format' in args and m.RETAINED_FORMAT not in args:
                rows = [m.decode(row) for row in data.splitlines()]
                next(row for row in rows if row['id'] == identity)['mounts'][0]['INERT_extra'] = True
                return b''.join(m.encoded(row) for row in rows)
            return data
        self.rewrite = drift
        before = len(self.fake.calls)
        with self.assertRaises(m.Refusal):
            self.fence()
        self.assert_closed('WRITER_HOLDER_MOUNTS')
        self.assertTrue(all(c[:2] in (('docker', 'inspect'), ('docker', 'info'), ('docker', 'ps'))
                            for c in self.fake.calls[before:]))
        self.assertFalse(self.fake.captured)

    def test_preflight_pass_does_not_mask_later_active_writer_without_any_create(self):
        self.fence()
        self.fake.records[self.plan.bindings['api'].container]['State']['Running'] = True
        self.reset_observer()
        with self.assertRaises(m.Refusal):
            self.fence()
        self.assert_closed('WRITER_ACTIVE_OTHER_ACCESS')
        self.assert_reads_only()

    def test_callback_failure_prevents_next_metadata_client(self):
        def refused(gate, event):
            if (gate, event) == ('WRITER_CENSUS', 'ENTER'):
                raise RuntimeError(SYNTHETIC_KEY)
        self.observer.callback = refused
        with self.assertRaises(m.StageObserverRefusal):
            self.fence()
        self.assert_closed('WRITER_CENSUS', 'OBSERVER_REFUSED')
        self.assertFalse(any(c[:2] == ('docker', 'ps') for c in self.fake.calls))
        self.assert_reads_only()


class ProtectedStoreTouchTests(unittest.TestCase):
    """Shared pure overlap predicate; synthetic literals only, never an admission grant."""
    def setUp(self):
        self.enterContext(patch.object(m.subprocess, 'Popen', side_effect=AssertionError('NO_REAL_CLIENT')))
        self.enterContext(patch.object(m.os, 'killpg', side_effect=AssertionError('NO_REAL_SIGNAL')))
        self.enterContext(patch.object(m.signal, 'signal', side_effect=AssertionError('NO_REAL_SIGNAL')))
        self.enterContext(patch.object(m.signal, 'setitimer', side_effect=AssertionError('NO_REAL_SIGNAL')))
        self.volumes = {m.VOLUMES['auth']: {'Mountpoint': '/INERT/auth'},
                        m.VOLUMES['data']: {'Mountpoint': '/INERT/data'}}

    def test_named_direct_ancestor_descendant_and_unrelated_exact_literals(self):
        cases = (
            ({'Name': m.VOLUMES['auth']}, True),
            ({'Name': m.VOLUMES['data'], 'Source': '/UNRELATED'}, True),
            ({'Source': '/INERT/auth'}, True),
            ({'Source': '/INERT/data'}, True),
            ({'Source': '/INERT/auth/child'}, True),
            ({'Source': '/INERT'}, True),
            ({'Source': '/'}, True),
            ({'Source': '/UNRELATED'}, False),
            ({'Source': '/INERT/auth-sibling'}, False),
            ({'Source': '/INERT/not/../auth'}, False),
            ({'Source': '/INERT/auth/../other'}, True),
            ({}, False),
        )
        for mount, expected in cases:
            before = copy.deepcopy((mount, self.volumes))
            with self.subTest(case=mount):
                self.assertIs(m.protected_store_touch(mount, self.volumes), expected)
            self.assertEqual((mount, self.volumes), before)

    def test_rw_and_type_are_not_part_of_overlap_classification(self):
        for source, expected in (('/INERT/auth', True), ('/UNRELATED', False)):
            for rw in (True, False, None, 0):
                for kind in ('bind', 'volume', None):
                    self.assertIs(m.protected_store_touch({'Source': source, 'RW': rw, 'Type': kind}, self.volumes), expected)
            self.assertIs(m.protected_store_touch({'Source': source}, self.volumes), expected)

    def test_original_short_circuit_and_malformed_behavior_are_not_replaced_by_new_guards(self):
        self.assertTrue(m.protected_store_touch({'Name': m.VOLUMES['auth'], 'Source': 1}, {}))
        with self.assertRaises(AttributeError):
            m.protected_store_touch({'Source': 1}, self.volumes)
        with self.assertRaises(KeyError):
            m.protected_store_touch({'Source': '/INERT'}, {'INERT': {}})

    def test_formula_ast_is_original_and_writer_calls_shared_function_exactly_once(self):
        source = ast.parse((HERE / 'recreate_openrouter_key.py').read_text())
        function = next(n for n in source.body if isinstance(n, ast.FunctionDef) and n.name == 'protected_store_touch')
        self.assertEqual(len(function.body), 3)  # Docstring, unchanged source assignment, original expression.
        expected_source = ast.parse("source = mount.get('Source', '')").body[0]
        expected_formula = ast.parse("mount.get('Name') in VOLUMES.values() or any("
            "source == v['Mountpoint'] or source.startswith(v['Mountpoint'].rstrip('/') + '/') or "
            "bool(source.startswith('/') and v['Mountpoint'].startswith(source.rstrip('/') + '/')) "
            "for v in volumes.values())", mode='eval').body
        self.assertEqual(ast.dump(function.body[1]), ast.dump(expected_source))
        self.assertEqual(ast.dump(function.body[2].value), ast.dump(expected_formula))
        controller = next(n for n in source.body if isinstance(n, ast.ClassDef) and n.name == 'Controller')
        writer = next(n for n in controller.body if isinstance(n, ast.FunctionDef) and n.name == 'writers')
        calls = [n for n in ast.walk(writer) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                 and n.func.id == 'protected_store_touch']
        self.assertEqual(len(calls), 1)
        self.assertEqual(ast.dump(calls[0]), ast.dump(ast.parse('protected_store_touch(mount, self.volumes)', mode='eval').body))


class RetainedMountOrderTests(unittest.TestCase):
    """Repeated inert retained inspections: only actual outer-mount order may vary."""
    def setUp(self):
        WriterStageTests.setUp(self)
        self.retained['mounts'] = [
            {'Type': 'volume', 'Name': m.VOLUMES['auth'], 'Source': '/INERT/auth',
             'Destination': '/source/auth', 'RW': True, 'Mode': 'rw', 'Driver': 'local', 'Propagation': ''},
            {'Type': 'bind', 'Source': '/INERT/helper.mjs', 'Destination': m.SCRIPT_TARGET,
             'RW': False, 'Mode': 'ro', 'Propagation': 'rprivate'},
        ]
        self.retained['declared'] = [
            {'Type': 'volume', 'Source': m.VOLUMES['auth'], 'Target': '/source/auth', 'ReadOnly': False},
            {'Type': 'bind', 'Source': '/INERT/helper.mjs', 'Target': m.SCRIPT_TARGET, 'ReadOnly': True},
        ]
        self.retained['INERT_extra'] = False
        self.baseline = copy.deepcopy(self.retained)
        self.controller.retained_created_unchanged()
        self.cached = copy.deepcopy(self.controller.retained_created_metadata)

    reset_observer = WriterStageTests.reset_observer
    assert_closed = WriterStageTests.assert_closed

    def check(self):
        with self.controller.stage('RETAINED_CREATED'):
            self.controller.retained_created_unchanged()

    def test_repeated_actual_mount_reorders_and_object_key_order_pass_without_mutating_baseline(self):
        for _ in range(4):
            self.retained['mounts'] = [dict(reversed(list(mount.items()))) for mount in reversed(self.retained['mounts'])]
            self.check()
        self.assertEqual(self.controller.retained_created_metadata, self.cached)
        self.assertTrue(all(m.RETAINED_FORMAT in call for call in self.fake.calls))
        self.assertFalse(self.fake.captured)

    def test_actual_complete_fields_multiplicity_and_types_remain_exact(self):
        variants = (
            lambda v: v['mounts'][0].update(Source='/INERT/auth/'),
            lambda v: v['mounts'][0].update(Destination='/INERT/different'),
            lambda v: v['mounts'][0].update(Name='INERT_OTHER_VOLUME'),
            lambda v: v['mounts'][0].update(Type='bind'),
            lambda v: v['mounts'][0].update(RW=1),
            lambda v: v['mounts'][0].update(Mode='ro'),
            lambda v: v['mounts'][0].update(Driver='INERT_OTHER_DRIVER'),
            lambda v: v['mounts'][0].update(Propagation='shared'),
            lambda v: v['mounts'][0].update(INERT_extra=None),
            lambda v: v['mounts'][0].pop('Mode'),
            lambda v: v['mounts'].append(copy.deepcopy(v['mounts'][0])),
            lambda v: v['mounts'].pop(),
        )
        for index, mutate in enumerate(variants):
            self.retained = copy.deepcopy(self.baseline)
            mutate(self.retained)
            self.retained['mounts'].reverse()
            self.reset_observer()
            with self.subTest(case=index), self.assertRaises(m.Refusal):
                self.check()
            self.assert_closed('RETAINED_CREATED')
            self.assertEqual(self.controller.retained_created_metadata, self.cached)

    def test_declared_mount_order_types_and_other_fields_are_not_normalized(self):
        variants = (
            lambda v: v['declared'].reverse(),
            lambda v: v['declared'][0].update(ReadOnly=0),
            lambda v: v['declared'][0].update(Source='INERT_OTHER_VOLUME'),
            lambda v: v.update(INERT_extra=0),
            lambda v: v.update(name='/dip-key-snapshot-' + 'f' * 32),
        )
        for index, mutate in enumerate(variants):
            self.retained = copy.deepcopy(self.baseline)
            self.retained['mounts'].reverse()
            mutate(self.retained)
            self.reset_observer()
            with self.subTest(case=index), self.assertRaises(m.Refusal):
                self.check()
            self.assert_closed('RETAINED_CREATED')
            self.assertEqual(self.controller.retained_created_metadata, self.cached)

    def test_actual_mount_shape_stays_failclosed(self):
        for malformed in (None, {}, [None]):
            self.retained = copy.deepcopy(self.baseline)
            self.retained['mounts'] = malformed
            self.reset_observer()
            with self.assertRaises(m.Refusal):
                self.check()
            self.assert_closed('RETAINED_CREATED')


class BothCachedMountPathsTests(unittest.TestCase):
    setUp = WriterMountOrderTests.setUp
    prepare = HolderStageTests.prepare

    def test_retained_and_fresh_holder_reorder_independently_in_same_readonly_fences(self):
        self.retained['mounts'] = [
            {'Type': 'bind', 'Source': '/INERT/one', 'Destination': '/one', 'RW': False},
            {'Type': 'bind', 'Source': '/INERT/two', 'Destination': '/two', 'RW': False}]
        self.fake.records[m.RETAINED_CREATED_ID]['Mounts'] = self.retained['mounts']
        before = len(self.fake.calls)
        self.controller.writers(set())
        self.retained['mounts'].reverse()
        self.controller.writers(set())  # Fresh-holder projected mounts are reversed by the fixture too.
        self.assertTrue(all(c[:2] in (('docker', 'inspect'), ('docker', 'info'), ('docker', 'ps'))
                            for c in self.fake.calls[before:]))
        self.assertFalse(self.fake.captured)


class SuccessorR4Tests(unittest.TestCase):
    """Fixed R4 only; no generalized successor paths, historical ownership or cleanup."""
    def setUp(self):
        SuccessorR3Tests.setUp(self)
        self.plan = replace(self.plan, successor_r3=False, successor_r4=True)
        self.controller.plan = self.fake.plan = self.plan
        self.previous_r3 = self.controller.root / '.key-preservation-reconcile-r3.lock'
        self.previous_r3.mkdir(mode=0o700)
        m.private_write(self.previous_r3 / 'KEY_ACTIVATION_HOLD.json', b'INERT_R3_NOT_PARSED\n')
        self.r3_before = (m.path_metadata(self.previous_r3, directory=True),
                          m.path_metadata(self.previous_r3 / 'KEY_ACTIVATION_HOLD.json', secret=True))

    result = ReconciliationStageReceiptTests.result
    retired_record = SuccessorR3Tests.retired_record

    def assert_prior_untouched(self):
        SuccessorR3Tests.assert_prior_untouched(self)
        self.assertEqual(self.r3_before, (m.path_metadata(self.previous_r3, directory=True),
                                        m.path_metadata(self.previous_r3 / 'KEY_ACTIVATION_HOLD.json', secret=True)))

    def test_cli_fixed_path_complete_grants_and_no_combined_successors(self):
        args = MigrationTests.cli(self)
        args[0] = '--reconcile-stopped-stand'
        args += ['--authorize-held-lock-reconciliation', '--darwin-host-mnt-helper', '--align-api-cve-release',
                 '--release-verifier-relative', self.plan.release_verifier,
                 '--release-verifier-test-relative', self.plan.release_verifier_test, '--successor-r4']
        self.assertEqual(m.arguments(args), self.plan)
        self.assertEqual(self.controller.coordination_path, self.controller.root / '.key-preservation-reconcile-r4.lock')
        for invalid in (replace(self.plan, reconcile_stopped_stand=False), replace(self.plan, successor_r4=1),
                        replace(self.plan, successor_r2=True), replace(self.plan, successor_r3=True),
                        replace(self.plan, held_lock_reconciliation_authorized=False),
                        replace(self.plan, align_api_cve_release=False)):
            with self.assertRaises(m.Refusal):
                invalid.validate()
        for other in ('--successor-r2', '--successor-r3'):
            with self.assertRaises(m.Refusal):
                m.arguments(args + [other])
        self.assertFalse(self.fake.calls)

    def test_full_fresh_pipeline_preserves_all_four_pairs_and_existing_bounds(self):
        opened, verify = m.os.open, self.gate.verify
        r3 = {self.previous_r3, self.previous_r3 / 'KEY_ACTIVATION_HOLD.json'}
        def no_r3_open(path, *args, **kwargs):
            if Path(path) in r3:
                raise AssertionError('NO_HISTORICAL_R3_CONTENT_OPEN')
            return opened(path, *args, **kwargs)
        def verified(request):
            self.assertIsNotNone(self.controller.prior_r3_hold_metadata)
            return verify(request)
        with patch.object(m.os, 'open', side_effect=no_r3_open), patch.object(self.gate, 'verify', side_effect=verified):
            SuccessorR3Tests.test_full_fresh_pipeline_preserves_three_pairs_and_checks_absence_before_verifier(self)
        self.assertIn(('PRIOR_R3_HOLD_STABILITY', 'PASS'), self.stage_events)
        self.assert_prior_untouched()

    def test_existing_r4_refuses_without_fallback_or_adoption(self):
        SuccessorR2Tests.test_existing_r2_refuses_before_client_no_fallback_or_adoption(self)

    def test_missing_r3_hold_refuses_before_r4_creation(self):
        (self.previous_r3 / 'KEY_ACTIVATION_HOLD.json').unlink()  # OWN disposable fixture only.
        result = self.result()
        self.assertFalse(result['ok'])
        self.assertEqual((result['checkpoint'], result['category']), ('PRIOR_R3_HOLD_METADATA', 'IO_REFUSED'))
        self.assertFalse(self.controller.coordination_path.exists())
        self.assertFalse(self.fake.calls)
        SuccessorR3Tests.assert_prior_untouched(self)

    def test_r3_drift_blocks_next_client_and_retains_own_hold(self):
        marker = self.previous_r3 / 'KEY_ACTIVATION_HOLD.json'
        with self.assertRaises(m.Refusal):
            with self.controller.coordination():
                marker.write_bytes(b'INERT_EXTERNAL_R3_DRIFT')
                for boundary in (self.controller.owned_lock, self.controller.retained_created_unchanged):
                    with self.assertRaises(m.Refusal):
                        boundary()
                self.assertFalse(self.fake.calls)
        self.assertEqual(self.observer.first, ('PRIOR_R3_HOLD_STABILITY', 'PREDICATE_REFUSED'))
        self.assertEqual(marker.read_bytes(), b'INERT_EXTERNAL_R3_DRIFT')
        self.assertTrue((self.controller.coordination_path / 'KEY_ACTIVATION_HOLD.json').is_file())
        SuccessorR3Tests.assert_prior_untouched(self)

    def test_older_pair_drift_guards_remain_active(self):
        SuccessorR3Tests.test_r2_hold_drift_blocks_ownership_and_client_without_repair(self)
        self.assertEqual(self.r3_before, (m.path_metadata(self.previous_r3, directory=True),
                                        m.path_metadata(self.previous_r3 / 'KEY_ACTIVATION_HOLD.json', secret=True)))

    def test_retired_presence_still_refuses_before_verifier_or_scratch(self):
        SuccessorR3Tests.test_retired_presence_refuses_before_scratch_verifier_or_holder(self)

    def test_retired_reappearance_still_refuses_before_fresh_holder_create(self):
        SuccessorR3Tests.test_retired_reappearance_after_recheck_refuses_before_holder_create(self)

    def test_ambiguous_census_is_not_absence_or_retry(self):
        SuccessorR3Tests.test_census_timeout_is_not_absence_or_retry(self)


class ExportStageTests(unittest.TestCase):
    """Only inert exported bytes/fake holder; never inspect incident recovery material."""
    def setUp(self):
        SuccessorR4Tests.setUp(self)

    prepare = HolderStageTests.prepare
    result = ReconciliationStageReceiptTests.result
    assert_prior_untouched = SuccessorR4Tests.assert_prior_untouched
    reset_observer = HolderStageTests.reset_observer

    def captured_fixture(self):
        HolderStageTests.create(self)
        self.fake.captured.add('pre')  # Inert receipt fixture, NOT a real capture/SQL execution.
        self.controller.phase = 'export_pre'
        self.enterContext(patch.object(self.controller, 'writers'))
        self.fake.calls.clear()
        self.reset_observer()

    def assert_closed(self, gate, category='PREDICATE_REFUSED'):
        result = self.observer.receipt({'ok': False, 'phase': 'export_pre', 'uncertain': True})
        self.assertEqual((result['checkpoint'], result['category']), (gate, category))
        public = json.dumps(result)
        self.assertLessEqual(len(public.encode('ascii')), 4096)
        for private in (SYNTHETIC_KEY, str(self.repo), self.controller.helper_id, self.controller.helper_name):
            self.assertNotIn(private, public)
        self.assertNotIn('pre', self.controller.exports)
        self.assertFalse(any('up' in c or c[:2] == ('docker', 'rm') for c in self.fake.calls))
        self.assertIn(self.controller.helper_id, self.fake.records)
        self.observer.fail('LOCK_EXIT', OSError(SYNTHETIC_KEY))
        self.assertEqual(self.observer.first, (gate, category))

    def test_full_r4_export_stages_balance_without_changing_pipeline(self):
        result = self.result()
        self.assertTrue(result['ok'], result)
        self.assertEqual((result['checkpoint'], result['category']), ('COMPLETE', 'NONE'))
        gates = {gate for gate in m.STAGE_IDS if gate.startswith(('EXPORT_', 'INVENTORY_'))}
        for gate in gates:
            self.assertIn((gate, 'PASS'), self.stage_events)
            self.assertEqual(self.stage_events.count((gate, 'ENTER')), self.stage_events.count((gate, 'PASS')))
        self.assertFalse(self.observer.stack)
        self.assertEqual(self.controller.exports, {'pre', 'post'})
        self.assertEqual(self.controller.material_exports, {'plan', 'migration'})
        self.assert_prior_untouched()
        self.assertFalse(any(c[:2] == ('docker', 'stop') for c in self.fake.calls))

    def test_pre_versions_are_independent_nonempty_sets_and_capture_13_is_accepted(self):
        self.captured_fixture()
        self.assertEqual(self.plan.expected_versions['data/ledger.sqlite'], {(0, 13), (0, 14)})
        self.controller.export('pre')
        self.assertEqual(self.controller.observed_versions['data/ledger.sqlite'], (0, 13))
        self.assertEqual(self.controller.exports, {'pre'})
        self.assertIn(('EXPORT_CERTIFY', 'PASS'), self.stage_events)

    def test_pre_copy_budget_refusal_has_no_destination_or_copy(self):
        self.captured_fixture()
        with patch.object(self.controller, 'holder_budget', side_effect=m.Refusal(SYNTHETIC_KEY)):
            with self.assertRaises(m.Refusal):
                self.controller.export('pre')
        self.assert_closed('EXPORT_BUDGET')
        self.assertFalse((self.controller.backup / 'pre').exists())
        self.assertFalse(any(c[:2] == ('docker', 'cp') for c in self.fake.calls))

    def test_inventory_budget_shape_and_decode_have_distinct_fixed_stages(self):
        self.captured_fixture()
        run = self.controller.run
        cases = (('INVENTORY_READ', b'{'), ('INVENTORY_SHAPE', m.encoded({})))
        for gate, output in cases:
            with self.subTest(gate=gate):
                self.reset_observer()
                def changed(args, **kwargs):
                    return output if m.INVENTORY_CODE in args else run(args, **kwargs)
                with patch.object(self.controller, 'run', side_effect=changed):
                    with self.assertRaises(m.Refusal):
                        self.controller.export('pre')
                self.assert_closed(gate)
        self.reset_observer()
        with patch.object(self.controller, 'holder_budget', side_effect=m.Refusal(SYNTHETIC_KEY)):
            with self.assertRaises(m.Refusal):
                self.controller.holder_inventory('pre')
        self.assert_closed('INVENTORY_BUDGET')
        self.assertFalse((self.controller.backup / 'pre').exists())

    def test_completed_but_refused_copy_preserves_material_without_certification(self):
        self.captured_fixture()
        run = self.controller.run
        def ambiguous(args, **kwargs):
            value = run(args, **kwargs)
            if tuple(args[:2]) == ('docker', 'cp'):
                raise m.Refusal(SYNTHETIC_KEY)
            return value
        with patch.object(self.controller, 'run', side_effect=ambiguous):
            with self.assertRaises(m.Refusal):
                self.controller.export('pre')
        self.assert_closed('EXPORT_COPY')
        self.assertTrue((self.controller.backup / 'pre/manifest.json').is_file())
        self.assertNotIn(('EXPORT_HOST_INVENTORY', 'ENTER'), self.stage_events)
        self.assertIn('pre', self.fake.captured)

    def test_host_inventory_mode_refusal_does_not_repair_copy(self):
        self.captured_fixture()
        self.fake.copy_mutation = lambda path: (path / 'manifest.json').chmod(0o644)
        with self.assertRaises(m.Refusal):
            self.controller.export('pre')
        self.assert_closed('EXPORT_HOST_INVENTORY')
        self.assertEqual((self.controller.backup / 'pre/manifest.json').stat().st_mode & 0o777, 0o644)

    def test_host_mismatch_preserves_short_circuit_no_second_holder_inventory(self):
        self.captured_fixture()
        self.fake.copy_mutation = lambda path: (path / 'working/auth/auth.sqlite').write_bytes(b'INERT_DRIFT')
        with self.assertRaises(m.Refusal):
            self.controller.export('pre')
        self.assert_closed('EXPORT_INVENTORY_EQUAL')
        self.assertEqual(sum(m.INVENTORY_CODE in c for c in self.fake.calls), 1)

    def test_second_holder_inventory_drift_is_not_manifest_failure(self):
        self.captured_fixture()
        inventory = self.controller.holder_inventory
        calls = []
        def drift(stage):
            value = inventory(stage)
            calls.append(stage)
            return value if len(calls) == 1 else value[:-1]
        with patch.object(self.controller, 'holder_inventory', side_effect=drift):
            with self.assertRaises(m.Refusal):
                self.controller.export('pre')
        self.assert_closed('EXPORT_INVENTORY_EQUAL')
        self.assertEqual(calls, ['pre', 'pre'])
        self.assertNotIn(('EXPORT_MANIFEST', 'ENTER'), self.stage_events)

    def test_manifest_refusal_uses_real_validator_after_matching_copy(self):
        self.captured_fixture()
        manifest = m.decode(self.fake.snapshot_files['pre']['manifest.json'])
        manifest['stores'][0]['logical']['schema']['userVersion'] = '999'
        self.fake.snapshot_files['pre']['manifest.json'] = m.encoded(manifest)
        with self.assertRaises(m.Refusal):
            self.controller.export('pre')
        self.assert_closed('EXPORT_MANIFEST')
        self.assertIn(('EXPORT_VERSIONS', 'PASS'), self.stage_events)
        self.assertIn(('EXPORT_INVENTORY_EQUAL', 'PASS'), self.stage_events)

    def test_small_admission_and_headers_are_separate_without_operand_output(self):
        self.captured_fixture()
        with patch.object(m, 'small_snapshot', side_effect=m.Refusal(SYNTHETIC_KEY)):
            with self.assertRaises(m.Refusal):
                self.controller.export('pre')
        self.assert_closed('EXPORT_SMALL_ADMISSION')
        self.assertNotIn(('EXPORT_HEADERS', 'ENTER'), self.stage_events)

    def test_header_refusal_keeps_copied_pre_without_certification(self):
        self.captured_fixture()
        with patch.object(self.controller, 'small_headers', side_effect=m.Refusal(SYNTHETIC_KEY)):
            with self.assertRaises(m.Refusal):
                self.controller.export('pre')
        self.assert_closed('EXPORT_HEADERS')
        self.assertIn(('EXPORT_SMALL_ADMISSION', 'PASS'), self.stage_events)

    def test_fsync_failure_after_inventory_record_is_not_durable_certification(self):
        self.captured_fixture()
        sync = m.sync_directory
        def failed(path):
            if (self.observer.stack and self.observer.stack[-1] == 'EXPORT_DESTINATION_FSYNC'):
                raise OSError(SYNTHETIC_KEY)
            return sync(path)
        with patch.object(m, 'sync_directory', side_effect=failed):
            with self.assertRaises(OSError):
                self.controller.export('pre')
        self.assert_closed('EXPORT_DESTINATION_FSYNC', 'IO_REFUSED')
        self.assertIn('pre', self.controller.export_inventories)
        self.assertNotIn(('EXPORT_CERTIFY', 'ENTER'), self.stage_events)

    def test_callback_refusal_before_copy_does_not_invoke_next_client(self):
        self.captured_fixture()
        def refused(gate, event):
            if (gate, event) == ('EXPORT_COPY', 'ENTER'):
                raise RuntimeError(SYNTHETIC_KEY)
        self.observer.callback = refused
        with self.assertRaises(m.StageObserverRefusal):
            self.controller.export('pre')
        self.assert_closed('EXPORT_COPY', 'OBSERVER_REFUSED')
        self.assertFalse(any(c[:2] == ('docker', 'cp') for c in self.fake.calls))

    def test_deadline_before_copy_is_not_renewed_or_mislabeled(self):
        self.captured_fixture()
        def expired(gate, event):
            if (gate, event) == ('EXPORT_COPY', 'ENTER'):
                self.now[0] = self.observer.deadline
        self.observer.callback = expired
        with self.assertRaises(m.StageTimeout):
            self.controller.export('pre')
        self.assert_closed('EXPORT_COPY', 'CLIENT_TIMEOUT')
        self.assertFalse(any(c[:2] == ('docker', 'cp') for c in self.fake.calls))


class ReadonlyBackupInventoryTests(unittest.TestCase):
    """Disposable inert bytes only; no real client, signal, SQLite or recovery input."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='inert-readonly-inventory-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.files = synthetic_snapshot(m.CURRENT_SOURCE_VERSIONS, migration=True)
        self.serial = 0
        for owner, name in ((m.subprocess, 'Popen'), (m.os, 'killpg'),
                            (m.signal, 'signal'), (m.signal, 'setitimer')):
            self.enterContext(patch.object(owner, name, side_effect=AssertionError('NO_RUNTIME_OPERATION')))

    def fixture(self):
        self.serial += 1
        root = self.base / str(self.serial)
        root.mkdir(mode=0o700)
        for entry in synthetic_inventory(self.files):
            path = root / entry['path']
            if entry['kind'] == 'directory':
                if entry['path']:
                    path.mkdir(mode=0o700)
            else:
                path.write_bytes(self.files[entry['path']])
                path.chmod(0o600)
        return root

    def test_readonly_full_output_and_read_validators_equal_durable(self):
        root = self.fixture()
        with patch.object(m.os, 'fsync'):
            durable = m.backup_inventory(root)
        opened = m.os.open
        def readonly(path, flags, *args, **kwargs):
            self.assertEqual(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND), 0)
            self.assertTrue(flags & os.O_NOFOLLOW)
            return opened(path, flags, *args, **kwargs)
        with patch.object(m.os, 'open', side_effect=readonly), \
             patch.object(m.os, 'fsync', side_effect=AssertionError('NO_FSYNC')), \
             patch.object(m.os, 'write', side_effect=AssertionError('NO_WRITE')):
            observed = m.backup_inventory(root, durable=False)
            manifest = m.validate_manifest(root, observed, m.CURRENT_SOURCE_VERSIONS, migration=True)
            summary = m.small_snapshot(manifest, observed)
            modes = m.Controller.small_headers(None, root, manifest, observed)
        self.assertEqual(observed, durable)
        self.assertEqual(observed, synthetic_inventory(self.files))
        self.assertEqual(set(modes), set(m.REQUIRED_STORES))
        self.assertTrue(all(mode == 1 for mode in modes.values()))
        self.assertGreater(summary['raw'], 0)

    def test_default_and_explicit_durable_keep_exact_file_then_reverse_directory_fsync_order(self):
        root = self.fixture()
        paths = [root, *root.rglob('*')]
        identities = {(p.stat().st_dev, p.stat().st_ino): p.relative_to(root).as_posix() for p in paths}
        def sequence(**kwargs):
            events = []
            def synced(fd):
                value = os.fstat(fd)
                events.append(identities[(value.st_dev, value.st_ino)])
            with patch.object(m.os, 'fsync', side_effect=synced):
                result = m.backup_inventory(root, **kwargs)
            return result, events
        default, explicit = sequence(), sequence(durable=True)
        self.assertEqual(default, explicit)
        expected_files = sorted(self.files)
        inventory = synthetic_inventory(self.files)
        # Directory DFS order is lexicographic; the root is fsynced last.
        expected_dirs = list(reversed([e['path'] or '.' for e in inventory if e['kind'] == 'directory']))
        self.assertEqual(default[1], expected_files + expected_dirs)

    def test_unsafe_modes_links_and_symlinks_refuse_in_both_modes_without_repair(self):
        for durable in (False, True):
            for kind in ('file_mode', 'directory_mode', 'hardlink', 'symlink'):
                with self.subTest(durable=durable, kind=kind):
                    root = self.fixture()
                    target = root / 'raw/auth/auth.sqlite'
                    if kind == 'file_mode':
                        target.chmod(0o644)
                    elif kind == 'directory_mode':
                        (root / 'raw').chmod(0o755)
                    elif kind == 'hardlink':
                        os.link(target, root / 'alias')
                    else:
                        target.unlink()
                        target.symlink_to(root / 'sealed/0.sqlite')
                    with patch.object(m.os, 'fsync'):
                        with self.assertRaises(m.Refusal):
                            m.backup_inventory(root, durable=durable)
                    if kind == 'file_mode':
                        self.assertEqual(target.stat().st_mode & 0o777, 0o644)
                    elif kind == 'directory_mode':
                        self.assertEqual((root / 'raw').stat().st_mode & 0o777, 0o755)
                    elif kind == 'hardlink':
                        self.assertEqual(target.stat().st_nlink, 2)
                    else:
                        self.assertTrue(target.is_symlink())

    def test_readonly_retains_total_and_count_bounds(self):
        root = self.fixture()
        for limit in ('EXPORT_BYTES', 'EXPORT_FILES', 'EXPORT_DIRS'):
            with self.subTest(limit=limit), patch.object(m, limit, 0), \
                 patch.object(m.os, 'fsync', side_effect=AssertionError('NO_FSYNC')):
                with self.assertRaises(m.Refusal):
                    m.backup_inventory(root, durable=False)

    def test_readonly_retains_final_directory_descriptor_identity_check(self):
        root = self.fixture()
        fstat = m.os.fstat
        def replaced(fd):
            value = fstat(fd)
            if stat.S_ISDIR(value.st_mode):
                fields = list(value)
                fields[1] += 1
                return os.stat_result(fields)
            return value
        with patch.object(m.os, 'fstat', side_effect=replaced), \
             patch.object(m.os, 'fsync', side_effect=AssertionError('NO_FSYNC')):
            with self.assertRaises(m.Refusal):
                m.backup_inventory(root, durable=False)

    def test_readonly_retains_file_stability_check(self):
        root = self.fixture()
        metadata = m.path_metadata
        calls = {}
        def drift(path, *args, **kwargs):
            value = metadata(path, *args, **kwargs)
            if Path(path).is_file():
                calls[path] = calls.get(path, 0) + 1
                if calls[path] == 2:
                    return (*value[:-1], value[-1] + 1)
            return value
        with patch.object(m, 'path_metadata', side_effect=drift), \
             patch.object(m.os, 'fsync', side_effect=AssertionError('NO_FSYNC')):
            with self.assertRaises(m.Refusal):
                m.backup_inventory(root, durable=False)


    def test_byte_limit_refuses_before_open_or_hash(self):
        root = self.fixture()
        with patch.object(m.os, 'open', side_effect=AssertionError('NO_FILE_OPEN')), \
             patch.object(m.hashlib, 'sha256', side_effect=AssertionError('NO_HASH')), \
             patch.object(m.os, 'fsync', side_effect=AssertionError('NO_FSYNC')):
            with self.assertRaises(m.Refusal):
                m.backup_inventory(root, durable=False, byte_limit=0)

    def test_cumulative_limit_refuses_next_file_before_open(self):
        root = self.base / 'cumulative'
        root.mkdir(mode=0o700)
        for name in ('a', 'b'):
            (root / name).write_bytes(b'123')
            (root / name).chmod(0o600)
        opened, opens = m.os.open, []
        def tracked(path, *args, **kwargs):
            opens.append(Path(path).name)
            return opened(path, *args, **kwargs)
        with patch.object(m.os, 'open', side_effect=tracked), \
             patch.object(m.os, 'fsync', side_effect=AssertionError('NO_FSYNC')):
            with self.assertRaises(m.Refusal):
                m.backup_inventory(root, durable=False, byte_limit=5)
        self.assertEqual(opens, ['a'])

    def test_invalid_limits_and_deadlines_refuse_before_traversal(self):
        root = self.fixture()
        for options in ({'byte_limit': -1}, {'byte_limit': m.EXPORT_BYTES + 1},
                        {'byte_limit': True}, {'byte_limit': 1.0},
                        {'deadline': float('inf')}, {'deadline': float('nan')}, {'deadline': True}):
            with self.subTest(options=options), \
                 patch.object(Path, 'lstat', side_effect=AssertionError('NO_TRAVERSAL')):
                with self.assertRaises(m.Refusal):
                    m.backup_inventory(root, durable=False, **options)

    def test_expired_deadline_refuses_before_traversal_or_fsync(self):
        root = self.fixture()
        with patch.object(m.time, 'monotonic', return_value=10), \
             patch.object(Path, 'lstat', side_effect=AssertionError('NO_TRAVERSAL')), \
             patch.object(m.os, 'fsync', side_effect=AssertionError('NO_FSYNC')):
            with self.assertRaises(m.StageTimeout):
                m.backup_inventory(root, durable=False, deadline=10)

    def test_chunk_deadline_stops_before_next_read_and_before_fsync(self):
        root = self.base / 'chunks'
        root.mkdir(mode=0o700)
        (root / 'a').write_bytes(b'x' * (m.MIB + 1))
        (root / 'a').chmod(0o600)
        now, reads, read = [0], [], m.os.read
        def expires(fd, size):
            reads.append(size)
            value = read(fd, size)
            now[0] = 10
            return value
        with patch.object(m.time, 'monotonic', side_effect=lambda: now[0]), \
             patch.object(m.os, 'read', side_effect=expires), \
             patch.object(m.os, 'fsync', side_effect=AssertionError('NO_FSYNC')):
            with self.assertRaises(m.StageTimeout):
                m.backup_inventory(root, deadline=10)
        self.assertEqual(reads, [m.MIB])

    def test_final_deadline_check_and_none_never_reads_clock(self):
        root = self.fixture()
        now, sync = [0], m.sync_directory
        def expires(path, **kwargs):
            sync(path, **kwargs)
            if path == root:
                now[0] = 10
        with patch.object(m.time, 'monotonic', side_effect=lambda: now[0]), \
             patch.object(m, 'sync_directory', side_effect=expires), \
             patch.object(m.os, 'fsync', side_effect=AssertionError('NO_FSYNC')):
            with self.assertRaises(m.StageTimeout):
                m.backup_inventory(root, durable=False, deadline=10)
        with patch.object(m.time, 'monotonic', side_effect=AssertionError('NO_CLOCK_WITH_NONE')), \
             patch.object(m.os, 'fsync'):
            self.assertEqual(m.backup_inventory(root), m.backup_inventory(root, durable=False))


if __name__ == '__main__':
    unittest.main()
