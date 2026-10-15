"""Source-only safety/contract tests. No Docker, listeners, browser, scans or providers."""
import argparse
import ast
import inspect
import contextlib
import copy
import hashlib
import http.client
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch


SOURCE = Path(__file__).with_name('final-image-stand.py')
spec = importlib.util.spec_from_file_location('final_image_stand', SOURCE)
smoke = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = smoke
spec.loader.exec_module(smoke)
NONCE = 'a' * 32
PROJECT = 'dip-image-stand-' + NONCE
CID = 'b' * 64
NID = 'c' * 64
SCAN_ID = '12345678-1234-4234-8234-123456789abc'


def baseline():
    """Synthetic resolved Compose shape, not a substitute for actual Compose validation."""
    services = {}
    for name, source in [('auth-volume-init', 'auth_accounts'), ('scan-volume-init', 'scan_ledger')]:
        services[name] = {'image': 'busybox:1.37.0', 'command': ['chown', '65532:65532', '/data'],
                          'network_mode': 'none', 'cap_drop': ['ALL'], 'cap_add': ['CHOWN'],
                          'security_opt': ['no-new-privileges:true'],
                          'volumes': [{'type': 'volume', 'source': source, 'target': '/data'}]}
    for name, networks, mounts in [
        ('api', ['auth_internal', 'scan_internal'], [('auth_accounts', '/auth'), ('scan_ledger', '/data')]),
        ('worker', ['scan_internal'], [('scan_ledger', '/data')]),
        ('web', ['auth_internal', 'web_edge'], []),
        ('egress', ['scan_internal', 'registry_uplink'], []),
    ]:
        services[name] = {
            'build': {'context': '../..', 'dockerfile': 'source-only'},
            'networks': {network: None for network in networks},
            'volumes': [{'type': 'volume', 'source': source, 'target': target} for source, target in mounts],
            'user': '101:101' if name == 'web' else '65532:65532',
            'read_only': True, 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
        }
    services['worker']['environment'] = {'SCAN_LEDGER_PATH': '/data/ledger.sqlite',
        'SCAN_WORKER_READY_PATH': '/data/worker.ready', 'TRIVY_CACHE_DIR': '/tmp/trivy'}
    services['worker']['restart'] = 'on-failure'
    services['api']['healthcheck'] = {'test': ['CMD', 'node', '-e', 'public-auth-health']}
    services['api']['depends_on'] = {'worker': {'condition': 'service_started'},
        'egress': {'condition': 'service_started'},
        'auth-volume-init': {'condition': 'service_completed_successfully'},
        'scan-volume-init': {'condition': 'service_completed_successfully'}}
    return {'name': 'dip-auth-stand', 'services': services,
            'networks': {name: {} for name in smoke.NETWORKS},
            'volumes': {name: {} for name in smoke.VOLUMES}}


def image_map():
    return {**smoke.IMAGES, 'web': 'sha256:' + '1' * 64,
            'egress': 'sha256:' + '2' * 64, 'init': 'sha256:' + '3' * 64}


def compiled():
    return smoke.build_spec(baseline(), PROJECT, NONCE, image_map(), ['4' * 32, '5' * 32], '6' * 64)


def container(identity=CID, nonce=NONCE, project=PROJECT, service='api'):
    return {'Id': identity, 'Name': '/' + project + '-' + service + '-1',
            'State': {'Status': 'exited' if service.endswith('-init') else 'running', 'ExitCode': 0},
            'Config': {'Labels': {smoke.LABEL: nonce,
        'com.docker.compose.project': project, 'com.docker.compose.service': service}}}


def resource(kind, identity, created='2026-10-15T12:00:00Z', nonce=NONCE):
    return {'Id' if kind == 'network' else 'Name': identity,
            'Created' if kind == 'network' else 'CreatedAt': created,
            'Labels': {smoke.LABEL: nonce, 'com.docker.compose.project': PROJECT}}


class FakeRunner:
    def __init__(self, resources=None):
        self.work = Path('/source-only/fake-work')
        self.resources = resources or {}
        self.commands = []
        self.options = []
        self.on_create = None

    def container_id(self, name, cleanup=False):
        return next((identity for (kind, identity), obj in self.resources.items()
                     if kind == 'container' and obj.get('Name', '').lstrip('/') == name), None)

    def inspect(self, kind, identity, cleanup=False):
        return copy.deepcopy(self.resources.get((kind, identity)))

    def checked(self, *args, **kwargs):
        self.commands.append(args)
        self.options.append(kwargs)
        if args[0] == 'compose' and 'create' in args:
            if self.on_create:
                self.on_create(args)
            return b''
        if args[1] == 'ls':
            # Discovery is label-filtered. A foreign resource must never be adopted.
            ids = []
            for (kind, identity), obj in self.resources.items():
                if kind != args[0]:
                    continue
                labels = obj.get('Config', {}).get('Labels', obj.get('Labels', {}))
                if labels.get('com.docker.compose.project') != PROJECT:
                    continue
                if any(arg == 'label=' + smoke.LABEL + '=' + NONCE for arg in args):
                    if labels.get(smoke.LABEL) != NONCE:
                        continue
                ids.append(identity)
            return '\n'.join(ids).encode()
        if args[1] == 'rm':
            self.resources.pop((args[0], args[-1]))
            return b''
        raise AssertionError('Unexpected mock command')


class InertEntryTests(unittest.TestCase):
    def test_import_and_default_plan_have_no_side_effects(self):
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('subprocess forbidden')), \
                patch.object(smoke.socket, 'socket', side_effect=AssertionError('network forbidden')), \
                patch.object(Path, 'mkdir', side_effect=AssertionError('write forbidden')):
            fresh_spec = importlib.util.spec_from_file_location('final_image_stand_inert_import', SOURCE)
            fresh = importlib.util.module_from_spec(fresh_spec)
            sys.modules[fresh_spec.name] = fresh
            self.addCleanup(sys.modules.pop, fresh_spec.name)
            fresh_spec.loader.exec_module(fresh)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(fresh.main([]), 0)
                self.assertEqual(fresh.main(['--plan']), 0)
            self.assertIn('SOURCE_ONLY_NOT_EXECUTED', out.getvalue())
            self.assertEqual(smoke.plan()['checks'], ['secret', 'sbom'])

    def test_wrong_review_hash_cannot_reach_execute(self):
        with patch.object(smoke, 'execute', side_effect=AssertionError('actual forbidden')), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(smoke.main(['--execute-reviewed', '--reviewed-sha256', '0' * 64]), 1)

    def test_tag_only_or_foreign_init_image_is_rejected(self):
        digest = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
        for image in ('busybox:1.37.0', 'private.example/busybox@sha256:' + '0' * 64,
                      'busybox:latest@sha256:' + '0' * 64, 'busybox:1.37.0@sha256:' + 'g' * 64):
            with self.subTest(image=image), self.assertRaisesRegex(smoke.Failure, 'INIT_PUBLIC_DIGEST_REQUIRED'):
                smoke.authorize(argparse.Namespace(execute_reviewed=True, reviewed_sha256=digest,
                                init_image=image, chromium_executable='/not-used'))

    def test_review_hash_and_explicit_public_inputs_authorize_only_not_execute(self):
        with tempfile.TemporaryDirectory() as tmp:
            browser = Path(tmp) / 'public-browser-stub'
            browser.write_text('source-only fixture, never executed')
            browser.chmod(0o700)
            args = argparse.Namespace(execute_reviewed=True,
                reviewed_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                init_image='busybox:1.37.0@sha256:' + '0' * 64, chromium_executable=str(browser),
                                web_image=image_map()['web'], gateway_image=image_map()['egress'],
                prebuilt_metadata='test-results/own/prebuilt-images.json', prebuilt_sha256='0' * 64)
            self.assertEqual(smoke.authorize(args), browser)

    def test_cli_env_discards_ambient_secrets_context_and_proxies(self):
        with patch.dict(smoke.os.environ, {'DOCKER_AUTH_CONFIG': 'private', 'OPENROUTER_API_KEY': 'private',
                        'HTTPS_PROXY': 'private', 'COMPOSE_FILE': 'old-stack', 'DOCKER_CONTEXT': 'old'}):
            env = smoke.clean_env(Path('/own/work'))
        self.assertEqual(set(env), {'PATH', 'HOME', 'DOCKER_CONFIG', 'DOCKER_BUILDKIT', 'LANG'})
        self.assertEqual(env['HOME'], '/own/work')
        self.assertEqual(env['DOCKER_CONFIG'], '/own/work/docker-config')


class BudgetRunnerTests(unittest.TestCase):
    def test_whole_budget_is_not_renewed_and_reserves_cleanup(self):
        now = [0.0]
        budget = smoke.Budget(lambda: now[0])
        self.assertEqual(budget.seconds(600), 600)
        now[0] = 775
        self.assertEqual(budget.seconds(600), 5)
        now[0] = 780
        with self.assertRaisesRegex(smoke.Failure, 'WHOLE_DEADLINE'):
            budget.seconds(1)
        self.assertEqual(budget.seconds(600, cleanup=True), 120)
        now[0] = 900
        with self.assertRaises(smoke.Failure):
            budget.seconds(1, cleanup=True)

    def test_cli_timeout_kills_only_own_process_group(self):
        process = Mock(pid=12345)
        process.communicate.side_effect = [subprocess.TimeoutExpired('mock', 2), (b'', b'')]
        runner = smoke.Runner(Path('/own'), smoke.Budget(lambda: 0))
        with patch.object(smoke.subprocess, 'Popen', return_value=process) as popen, \
                patch.object(smoke.os, 'killpg') as kill:
            with self.assertRaises(subprocess.TimeoutExpired):
                runner.call(['source-only-command'], cap=2)
        kill.assert_called_once_with(12345, smoke.signal.SIGKILL)
        self.assertTrue(popen.call_args.kwargs['start_new_session'])
        self.assertNotIn('shell', popen.call_args.kwargs)
        self.assertEqual(process.communicate.call_args_list[0].kwargs['timeout'], 2)

    def test_cookie_uses_pipe_not_argv_env_or_file(self):
        process = Mock(returncode=0)
        process.communicate.return_value = (b'{}', b'')
        runner = smoke.Runner(Path('/own'), smoke.Budget(lambda: 0))
        with patch.object(smoke.subprocess, 'Popen', return_value=process) as popen:
            runner.call(['node', 'public-source'], input_data=b'COOKIE-CANARY')
        self.assertEqual(popen.call_args.kwargs['stdin'], subprocess.PIPE)
        self.assertEqual(process.communicate.call_args.kwargs['input'], b'COOKIE-CANARY')
        self.assertNotIn('COOKIE-CANARY', repr(popen.call_args))

    def test_public_build_progress_and_errors_are_merged_into_own_log(self):
        process = Mock(returncode=0)
        process.communicate.return_value = (None, None)
        runner = smoke.Runner(Path('/own'), smoke.Budget(lambda: 0))
        public_log = Mock()
        with patch.object(smoke.subprocess, 'Popen', return_value=process) as popen:
            self.assertEqual(runner.call(['public-build'], output=public_log), (0, b'', b''))
        self.assertEqual(popen.call_args.kwargs['stdout'], public_log)
        self.assertEqual(popen.call_args.kwargs['stderr'], subprocess.STDOUT)

    def test_lowercase_no_such_volume_is_absence_not_daemon_failure(self):
        runner = smoke.Runner(Path('/own'), smoke.Budget(lambda: 0))
        with patch.object(runner, 'docker', return_value=(1, b'[]', b'get new: no such volume')):
            self.assertIsNone(runner.inspect('volume', 'new'))
        with patch.object(runner, 'docker', return_value=(1, b'', b'daemon unavailable')):
            with self.assertRaisesRegex(smoke.Failure, 'INSPECT_FAILED'):
                runner.inspect('volume', 'new')

    def test_actual_runner_rejects_build_pull_and_history_before_subprocess(self):
        runner = smoke.Runner(Path('/own'), smoke.Budget(lambda: 0))
        for args in [('buildx', 'build'), ('buildx', 'history', 'ls'), ('pull', 'busybox'),
                     ('build', '.'), ('image', 'pull', 'busybox')]:
            with self.subTest(args=args), patch.object(runner, 'call') as call:
                with self.assertRaisesRegex(smoke.Failure, 'RUNTIME_BUILD_PULL_HISTORY_FORBIDDEN'):
                    runner.docker(*args)
                call.assert_not_called()


def prebuilt_fixture():
    args = argparse.Namespace(web_image=image_map()['web'], gateway_image=image_map()['egress'],
        init_image='busybox:1.37.0@sha256:' + '3' * 64, chromium_executable='/public/chromium')
    images = {}
    for role in ('web', 'egress'):
        images[role] = {'id': image_map()[role], 'exit_code': 0, 'timed_out': False,
            'os': 'linux', 'architecture': 'arm64', 'user': '101:101' if role == 'web' else '65532:65532',
            'labels': {smoke.LABEL + '.source': smoke.BASE, smoke.LABEL + '.role': role,
                       smoke.LABEL + '.context': smoke.CONTEXT_SHA256}}
    metadata = {'version': 1, 'base': smoke.BASE, 'context_sha256': smoke.CONTEXT_SHA256,
        'images': images, 'init': {'id': image_map()['init'], 'reference': args.init_image,
            'repo_digest': 'busybox@sha256:' + '3' * 64, 'os': 'linux', 'architecture': 'arm64'},
        'chromium': {'executable': args.chromium_executable, 'exists': True,
                     'executable_access': True, 'playwright': '1.59.1'}}
    return metadata, args


class PrebuiltOnlyTests(unittest.TestCase):
    def test_metadata_binds_source_ids_success_public_init_and_browser(self):
        metadata, args = prebuilt_fixture()
        smoke.validate_prebuilt(metadata, args)
        mutations = [lambda m: m.update(base='unreviewed'),
            lambda m: m.update(context_sha256='0' * 64),
            lambda m: m['images']['web'].update(id='nginx:latest'),
            lambda m: m['images']['egress'].update(exit_code=1),
            lambda m: m['images']['web']['labels'].update({smoke.LABEL + '.source': 'wrong'}),
            lambda m: m['init'].update(repo_digest='private.example/busybox@sha256:' + '3' * 64),
            lambda m: m['chromium'].update(playwright='unreviewed')]
        for mutate in mutations:
            value = copy.deepcopy(metadata)
            mutate(value)
            with self.assertRaises(smoke.Failure):
                smoke.validate_prebuilt(value, args)

    def test_selected_actual_image_labels_and_init_repodigest_are_verified(self):
        metadata, args = prebuilt_fixture()
        objects = {}
        for role, identity in image_map().items():
            objects[identity] = {'Id': identity, 'Os': 'linux', 'Architecture': 'arm64',
                'Config': {'Labels': metadata['images'].get(role, {}).get('labels', {}),
                    'User': metadata['images'].get(role, {}).get('user', '')},
                'RepoDigests': [metadata['init']['repo_digest']] if role == 'init' else []}
        runner = Mock()
        runner.inspect.side_effect = lambda kind, identity: copy.deepcopy(objects.get(identity))
        self.assertEqual(smoke.verify_prebuilt_images(runner, metadata, args), image_map())
        objects[args.web_image]['Config']['Labels'] = {}
        with self.assertRaisesRegex(smoke.Failure, 'ACTUAL_PREBUILT_METADATA_MISMATCH'):
            smoke.verify_prebuilt_images(runner, metadata, args)
        runner.checked.assert_not_called()  # no pull/build/history, including absent images
        runner.inspect.return_value = None
        runner.inspect.side_effect = lambda *_: None
        with self.assertRaisesRegex(smoke.Failure, 'PREBUILT_IMAGE_MISSING_OR_CHANGED'):
            smoke.verify_prebuilt_images(runner, metadata, args)
        runner.checked.assert_not_called()

    def test_receipt_hash_is_required_before_json_is_trusted(self):
        metadata, args = prebuilt_fixture()
        with tempfile.TemporaryDirectory() as tmp, patch.object(smoke, 'ROOT', Path(tmp)):
            directory = Path(tmp) / 'test-results' / 'own-public-build'
            directory.mkdir(parents=True)
            path = directory / 'prebuilt-images.json'
            path.write_text(json.dumps(metadata))
            args.prebuilt_metadata = str(path)
            args.prebuilt_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(smoke.load_prebuilt(args), metadata)
            path.write_text(json.dumps({**metadata, 'base': 'tampered'}))
            with self.assertRaisesRegex(smoke.Failure, 'PREBUILT_METADATA_HASH'):
                smoke.load_prebuilt(args)

    def test_actual_prepare_has_no_archive_build_pull_or_history_calls(self):
        text = inspect.getsource(smoke.prepare)
        values = {n.value for n in ast.walk(ast.parse(text)) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        self.assertTrue({'build', 'buildx', 'pull', 'archive', 'history'}.isdisjoint(values))
        self.assertNotIn('docker-buildx', inspect.getsource(smoke.execute))
        self.assertNotIn('buildx', inspect.getsource(smoke.verify_prebuilt_images))


class SpecSafetyTests(unittest.TestCase):
    def test_baseline_derived_spec_keeps_guards_and_never_mutates_input(self):
        original = baseline()
        before = copy.deepcopy(original)
        value = smoke.build_spec(original, PROJECT, NONCE, image_map(), [], '6' * 64)
        self.assertEqual(original, before)
        self.assertEqual(value['services']['api']['environment']['SCAN_BROWSER_ALLOWED_USER_IDS'], '')
        self.assertEqual(value['services']['api']['environment']['SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS'], 'false')
        self.assertEqual(value['services']['worker']['restart'], 'on-failure')
        self.assertNotIn('command', value['services']['worker'])
        for kind in ('networks', 'volumes'):
            for name, resource in value[kind].items():
                self.assertEqual(resource, {'external': True, 'name': PROJECT + '-' + name})

    def test_compose_null_defaults_inherit_but_empty_overrides_are_refused(self):
        model = baseline()
        for name, service in model['services'].items():
            service['entrypoint'] = None
            if not name.endswith('-init'):
                service['command'] = None
        value = smoke.build_spec(model, PROJECT, NONCE, image_map(), [], '6' * 64)
        self.assertTrue(all('entrypoint' not in service for service in value['services'].values()))
        self.assertTrue(all(service['entrypoint'] is None for service in model['services'].values()))
        for field, code in [('entrypoint', 'SERVICE_UNSAFE_OVERRIDE'), ('command', 'DEFAULT_ENTRYPOINT_TOPOLOGY')]:
            for override in ([], ['node', 'bypass.js']):
                changed = copy.deepcopy(model)
                changed['services']['api'][field] = override
                with self.assertRaisesRegex(smoke.Failure, code):
                    smoke.build_spec(changed, PROJECT, NONCE, image_map(), [], '6' * 64)

    def test_enrollment_never_email_wildcard_or_old_project(self):
        for enrolled in (['user@example.invalid'], ['*'], [''], ['g' * 32]):
            with self.subTest(enrolled=enrolled), self.assertRaises(smoke.Failure):
                smoke.build_spec(baseline(), PROJECT, NONCE, image_map(), enrolled, '6' * 64)
        with self.assertRaises(smoke.Failure):
            smoke.build_spec(baseline(), 'dip-auth-stand', NONCE, image_map(), [], '6' * 64)

    def test_known_api_worker_ids_cannot_be_replaced(self):
        images = image_map()
        images['api'] = 'sha256:' + '9' * 64
        with self.assertRaisesRegex(smoke.Failure, 'BASE_IMAGE_PIN'):
            smoke.build_spec(baseline(), PROJECT, NONCE, images, [], '6' * 64)

    def test_unsafe_mutations_fail_closed(self):
        mutations = [
            lambda v: v['services']['api'].update(privileged=True),
            lambda v: v['services']['worker'].update(networks={'registry_uplink': None}),
            lambda v: v['services']['worker'].update(entrypoint=['node', 'proof.js']),
            lambda v: v['services']['worker']['environment'].update(SSL_CERT_FILE='/proof/ca.pem'),
            lambda v: v['services']['api']['environment'].update(SCAN_VULN_ENABLED='true'),
            lambda v: v['services']['api']['environment'].update(SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS='true'),
            lambda v: v['services']['api']['environment'].update(AUTH_ORIGIN='http://127.0.0.1:8080'),
            lambda v: v['services']['api']['environment'].update(SCAN_BROWSER_ALLOWED_USER_IDS='*'),
            lambda v: v['services']['api'].update(ports=['3001:3001']),
            lambda v: v['services']['web'].update(ports=['0.0.0.0:18080:8080']),
            lambda v: v['services']['web'].update(image='nginx:latest'),
            lambda v: v['services']['api'].update(mem_limit='0'),
            lambda v: v['services']['worker'].update(cpus=0),
            lambda v: v['services']['worker'].update(cap_add=['SYS_ADMIN']),
            lambda v: v['services']['api'].update(extra_hosts=['registry-1.docker.io:127.0.0.1']),
            lambda v: v['services']['egress'].update(dns=['127.0.0.1']),
            lambda v: v['services']['api']['volumes'].append({'type': 'bind', 'source': '/var/run/docker.sock', 'target': '/sock'}),
            lambda v: v['volumes']['scan_ledger'].update(name='old_ledger'),
            lambda v: v['networks']['scan_internal'].update(name='old_network'),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                value = compiled()
                mutate(value)
                with self.assertRaises(smoke.Failure):
                    smoke.validate_spec(value, PROJECT, NONCE)

    def test_current_source_contracts_without_running_them(self):
        root = SOURCE.parents[3]
        compose = (root / 'server/deploy/compose.stand.yaml').read_text()
        gateway = (root / 'server/deploy/gateway/proxy.py').read_text()
        nginx = (root / 'server/deploy/stand.nginx.conf').read_text()
        readiness = (root / 'server/api/src/scans/scan-readiness.ts').read_text()
        worker = (root / 'server/api/src/worker/outbox-consumer.ts').read_text()
        for text in ('auth_accounts', 'scan_ledger', 'scan_internal', 'registry_uplink', 'auth_internal', 'web_edge'):
            self.assertIn(text, compose)
        self.assertIn('set $runtime_ingress_enabled 0;', nginx)
        self.assertIn('set $history_ingress_enabled 0;', nginx)
        self.assertIn('return gateway && !bypass;', readiness)

        self.assertIn('production.cloudfront.docker.com', gateway)
        self.assertIn('MAX_BYTES = 64 * 1024 * 1024', gateway)
        self.assertIn('ledger.claim(', worker)
        self.assertIn('ledger.finishCombined(', worker)


class ActualTopologyShapeTests(unittest.TestCase):
    def stand(self, state='running'):
        spec = compiled()
        runner = FakeRunner()
        stand = smoke.Stand(runner, PROJECT, NONCE)
        stand.spec = spec
        stand.network_ids = {name: str(index + 1) * 64 for index, name in enumerate(sorted(smoke.NETWORKS))}
        for index, service in enumerate(sorted(smoke.SERVICES)):
            identity = str(index + 1) * 64
            stand.containers[service] = identity
            expected = spec['services'][service]
            obj = container(identity, service=service)
            obj['Config'].update(Image=expected['image'], User=expected.get('user', ''))
            memory = {'worker': 1073741824, 'api': 536870912}.get(service, 268435456)
            obj.update(State={'Status': state}, HostConfig={
                'Privileged': False, 'ReadonlyRootfs': True, 'CapDrop': ['ALL'],
                'SecurityOpt': ['no-new-privileges:true'], 'Memory': memory,
                'MemorySwap': memory, 'NanoCpus': 1_000_000_000, 'PidsLimit': 128,
                'NetworkMode': 'none' if service.endswith('-init') else PROJECT + '-scan_internal',
                'PortBindings': {},
            }, Mounts=[{'Name': PROJECT + '-' + m['source'], 'Destination': m['target'], 'Type': 'volume'}
                       for m in expected.get('volumes', [])],
                NetworkSettings={'Networks': {PROJECT + '-' + name: {'NetworkID':
                    '' if state == 'created' else stand.network_ids[name]}
                    for name in expected.get('networks', {})}})
            runner.resources[('container', identity)] = obj
        return stand

    def test_created_network_ids_may_be_empty_only_before_start(self):
        stand = self.stand('created')
        stand.verify(allow_created=True)
        with self.assertRaisesRegex(smoke.Failure, 'ACTUAL_NETWORKS'):
            stand.verify()
        for obj in stand.r.resources.values():
            obj['State']['Status'] = 'running'
        with self.assertRaisesRegex(smoke.Failure, 'ACTUAL_NETWORKS'):
            stand.verify(allow_created=True)

    def test_running_exact_topology_passes_and_direct_worker_network_fails(self):
        stand = self.stand()
        stand.verify()
        obj = stand.r.resources[('container', stand.containers['worker'])]
        obj['NetworkSettings']['Networks'][PROJECT + '-registry_uplink'] = {'NetworkID': stand.network_ids['registry_uplink']}
        with self.assertRaisesRegex(smoke.Failure, 'ACTUAL_NETWORK_NAMES'):
            stand.verify()

    def test_actual_bind_mount_or_unbounded_cpu_is_refused(self):
        for mutate in (lambda obj: obj['Mounts'].append({'Type': 'bind', 'Destination': '/sock'}),
                       lambda obj: obj['HostConfig'].update(NanoCpus=0)):
            stand = self.stand()
            mutate(stand.r.resources[('container', stand.containers['api'])])
            with self.assertRaises(smoke.Failure):
                stand.verify()


class ArchiveTests(unittest.TestCase):
    def check_members(self, members):
        fake = Mock()
        fake.getmembers.return_value = members
        smoke.public_tar_ok(fake)

    def test_public_sources_only(self):
        ancestor = tarfile.TarInfo('server/')
        ancestor.type = tarfile.DIRTYPE
        self.check_members([ancestor, tarfile.TarInfo('src/app/main.tsx'),
                            tarfile.TarInfo('server/api/src/scans/report-page.ts')])
        with self.assertRaises(smoke.Failure):
            self.check_members([tarfile.TarInfo('server')])

    def test_no_escape_private_files_or_links(self):
        for name in ('/src/file', 'src/../secret', '.local-auth/token', '.env',
                     'src/.env.local', 'src/keys/file', 'public/private.pem',
                     'src/state.db', 'server/deploy/proof/history-wire-native.py'):
            with self.subTest(name=name), self.assertRaises(smoke.Failure):
                self.check_members([tarfile.TarInfo(name)])
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE):
            member = tarfile.TarInfo('src/link')
            member.type = kind
            member.linkname = '/private/secret'
            with self.subTest(kind=kind), self.assertRaises(smoke.Failure):
                self.check_members([member])


class ComposeCreateSafetyTests(unittest.TestCase):
    def stand(self, existing=()):
        runner = FakeRunner()
        stand = smoke.Stand(runner, PROJECT, NONCE)
        stand.spec = compiled()
        for index, name in enumerate(sorted(smoke.NETWORKS)):
            identity = f'{index + 1:064x}'
            stand.network_ids[name] = identity
            runner.resources[('network', identity)] = resource('network', identity, 'now')
            stand.owned.append(smoke.Owned('network', identity, 'now'))
        for name in smoke.VOLUMES:
            identity = PROJECT + '-' + name
            runner.resources[('volume', identity)] = resource('volume', identity, 'now')
            stand.owned.append(smoke.Owned('volume', identity, 'now'))
        self.populate(stand, existing)
        return stand

    def populate(self, stand, services):
        for index, service in enumerate(sorted(services)):
            identity = f'{index + 100:064x}'
            stand.r.resources[('container', identity)] = container(identity, service=service)
            stand.containers[service] = identity
            stand.owned.append(smoke.Owned('container', identity))

    def test_fresh_create_explicit_exact_six_services_no_recreate(self):
        stand = self.stand()
        stand.r.on_create = lambda _args: self.populate(stand, smoke.SERVICES)
        stand.create()
        command = next(args for args in stand.r.commands if args[0] == 'compose')
        self.assertIn('--no-recreate', command)
        self.assertNotIn('--force-recreate', command)
        self.assertIn('--no-build', command)
        self.assertEqual(command[command.index('--pull') + 1], 'never')
        self.assertEqual(set(command[command.index('--no-recreate') + 1:]), smoke.SERVICES)

    def test_api_recreation_never_targets_or_recreates_dependencies(self):
        stand = self.stand(smoke.SERVICES - {'api'})
        previous = dict(stand.containers)
        def create(_args):
            stand.r.resources[('container', CID)] = container(CID)
        stand.r.on_create = create
        stand.create('api')
        command = next(args for args in stand.r.commands if args[0] == 'compose')
        self.assertEqual(command[command.index('--no-recreate') + 1:], ('api',))
        self.assertNotIn('--no-deps', command)  # unsupported by installed create; structural isolation instead
        self.assertEqual(command[command.index('--file') + 1], '-')
        index = stand.r.commands.index(command)
        reduced = json.loads(stand.r.options[index]['input_data'])
        self.assertEqual(set(reduced['services']), {'api'})
        self.assertNotIn('depends_on', reduced['services']['api'])
        expected_api = copy.deepcopy(stand.spec['services']['api'])
        expected_api.pop('depends_on')
        self.assertEqual(reduced['services']['api'], expected_api)  # all guards unchanged
        self.assertEqual({key: stand.containers[key] for key in previous}, previous)

    def test_api_structural_no_deps_requires_other_own_services_already_ready(self):
        stand = self.stand(smoke.SERVICES - {'api'})
        obj = stand.r.resources[('container', stand.containers['worker'])]
        obj['State']['Status'] = 'restarting'
        with self.assertRaisesRegex(smoke.Failure, 'PRECREATE_DEPENDENCY_STATE'):
            stand.create('api')
        self.assertFalse(any(args[0] == 'compose' for args in stand.r.commands))

    def test_late_foreign_name_collision_refuses_before_compose_or_full_inspect(self):
        stand = self.stand()
        foreign = container(CID, nonce='f' * 32, project='foreign')
        foreign['Name'] = '/' + PROJECT + '-api-1'
        stand.r.resources[('container', CID)] = foreign
        with patch.object(stand.r, 'inspect', wraps=stand.r.inspect) as inspected:
            with self.assertRaisesRegex(smoke.Failure, 'PRECREATE_NAME_COLLISION'):
                stand.create()
        self.assertFalse(any(args[0] == 'compose' for args in stand.r.commands))
        self.assertFalse(any(call.args[:2] == ('container', CID) for call in inspected.call_args_list))
        self.assertEqual(stand.owned, [record for record in stand.owned if record.kind != 'container'])

    def test_foreign_collision_between_preflight_and_create_is_not_adopted_or_cleaned(self):
        stand = self.stand()
        foreign_id = 'e' * 64
        def collide(_args):
            self.populate(stand, smoke.SERVICES - {'api'})
            stand.r.resources[('container', foreign_id)] = container(foreign_id, nonce='f' * 32)
        stand.r.on_create = collide
        with self.assertRaisesRegex(smoke.Failure, 'POSTCREATE_EXACT_SERVICE_SET'):
            stand.create()
        stand.cleanup()
        self.assertIn(('container', foreign_id), stand.r.resources)
        self.assertFalse(any(foreign_id in args and args[1] in {'rm', 'start'} for args in stand.r.commands))
        self.assertNotIn(smoke.Owned('container', foreign_id), stand.owned)

    def test_exact_existing_project_set_prevents_orphan_adoption(self):
        stand = self.stand(smoke.SERVICES - {'api'})
        foreign_id = 'e' * 64
        stand.r.resources[('container', foreign_id)] = container(foreign_id, nonce='f' * 32)
        with self.assertRaisesRegex(smoke.Failure, 'PRECREATE_PROJECT_COLLISION'):
            stand.create('api')
        self.assertFalse(any(args[0] == 'compose' for args in stand.r.commands))


class CleanupTests(unittest.TestCase):
    def test_cleanup_only_recorded_owned_exact_ids_and_volume_identity(self):
        volume = PROJECT + '-scan_ledger'
        records = [smoke.Owned('network', NID, 'now'), smoke.Owned('volume', volume, 'now'), smoke.Owned('container', CID)]
        foreign_id = 'd' * 64
        runner = FakeRunner({('network', NID): resource('network', NID, 'now'),
            ('volume', volume): resource('volume', volume, 'now'), ('container', CID): container(),
            ('container', foreign_id): container(foreign_id, nonce='e' * 32, project='old-stand')})
        stand = smoke.Stand(runner, PROJECT, NONCE)
        stand.owned = records
        value = stand.cleanup()
        self.assertEqual(value['status'], 'PASS')
        removals = [args for args in runner.commands if args[1] == 'rm']
        self.assertEqual(removals, [('container', 'rm', '--force', CID),
                                    ('volume', 'rm', volume), ('network', 'rm', NID)])
        self.assertIn(('container', foreign_id), runner.resources)
        self.assertTrue(all('down' not in args and 'prune' not in args for args in runner.commands))

    def test_label_mismatch_refuses_lifecycle(self):
        runner = FakeRunner({('container', CID): container(nonce='e' * 32)})
        stand = smoke.Stand(runner, PROJECT, NONCE)
        stand.owned = [smoke.Owned('container', CID)]
        self.assertEqual(stand.cleanup()['status'], 'INCOMPLETE')
        self.assertFalse(any(args[1] == 'rm' for args in runner.commands))

    def test_reused_volume_name_with_different_created_at_is_not_removed(self):
        name = PROJECT + '-scan_ledger'
        runner = FakeRunner({('volume', name): resource('volume', name, 'new')})
        stand = smoke.Stand(runner, PROJECT, NONCE)
        stand.owned = [smoke.Owned('volume', name, 'old')]
        self.assertEqual(stand.cleanup()['status'], 'INCOMPLETE')
        self.assertFalse(any(args[1] == 'rm' for args in runner.commands))

    def test_partial_create_discovers_only_own_container_ids(self):
        runner = FakeRunner({('container', CID): container()})
        stand = smoke.Stand(runner, PROJECT, NONCE)
        stand.create_uncertain = True
        result = stand.cleanup()
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertIn('COMPOSE_CREATE_UNCONFIRMED', result['errors'])
        self.assertIn(('container', 'rm', '--force', CID), runner.commands)

    def test_pending_storage_not_found_is_not_false_cleanup_pass(self):
        stand = smoke.Stand(FakeRunner(), PROJECT, NONCE)
        stand.pending_storage = [('volume', PROJECT + '-scan_ledger')]
        self.assertEqual(stand.cleanup()['status'], 'INCOMPLETE')

    def test_lifecycle_rechecks_ownership_before_start_or_recreate(self):
        runner = FakeRunner({('container', CID): container(project='old')})
        stand = smoke.Stand(runner, PROJECT, NONCE)
        stand.containers['api'] = CID
        for action in (stand.start, stand.remove_container):
            with self.assertRaises(smoke.Failure):
                action('api')
        self.assertEqual(runner.commands, [])


class JournalTests(unittest.TestCase):
    def test_journal_persists_only_resource_authority_not_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeRunner()
            runner.work = Path(tmp)
            stand = smoke.Stand(runner, PROJECT, NONCE, persist=True)
            stand.spec = {'environment': {'SECRET': 'SECRET-CANARY'}}
            stand.owned = [smoke.Owned('container', CID)]
            stand.pending_storage = [('volume', PROJECT + '-scan_ledger')]
            stand.journal()
            raw = (Path(tmp) / 'owned-resources.json').read_text()
            value = json.loads(raw)
            self.assertEqual(value['resources'][0]['identity'], CID)
            self.assertNotIn('CANARY', raw)
            self.assertFalse((Path(tmp) / 'owned-resources.tmp').exists())


class HttpContractTests(unittest.TestCase):
    def event(self, seq, state='completed', scan_id=SCAN_ID):
        return f'id: {seq}\nevent: scan\ndata: ' + json.dumps({'scanId': scan_id, 'state': state, 'percent': None}) + '\n\n'

    def test_sse_replay_parser_strict_owner_id_and_order(self):
        value = smoke.parse_events('retry: 2000\n\n' + self.event(2, 'queued') + self.event(4), SCAN_ID)
        self.assertEqual(value, [{'id': 2, 'state': 'queued'}, {'id': 4, 'state': 'completed'}])
        self.assertEqual(smoke.parse_events('retry: 2000\n\n', SCAN_ID), [])
        for raw in (self.event(2) + self.event(2), self.event('01'), self.event(2, scan_id='foreign'),
                    'event: error\ndata: {}\n\n'):
            with self.subTest(raw=raw), self.assertRaises(smoke.Failure):
                smoke.parse_events(raw, SCAN_ID)

    def test_http_has_fixed_loopback_origin_and_no_redirect_following(self):
        budget = smoke.Budget(lambda: 0)
        client = smoke.Http(budget, 'demo_session=CANARY')
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 302
        response.getheaders.return_value = [('Location', 'https://forbidden.invalid/')]
        response.read1.side_effect = [b'{}', b'']
        with patch.object(smoke.http.client, 'HTTPConnection', return_value=connection) as factory:
            status, _, _ = client.request_raw('POST', smoke.SCAN, {})
        self.assertEqual(status, 302)
        factory.assert_called_once_with('127.0.0.1', 18080, timeout=15)
        headers = connection.request.call_args.kwargs['headers']
        self.assertEqual(headers['Origin'], smoke.ORIGIN)
        self.assertEqual(headers['Cookie'], 'demo_session=CANARY')
        connection.close.assert_called_once()

    def test_nginx_html404_status_check_does_not_attempt_json(self):
        client = smoke.Http(smoke.Budget(lambda: 0))
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 404
        response.getheaders.return_value = [('Content-Type', 'text/html')]
        response.read1.side_effect = [b'<html>404 Not Found</html>', b'']
        with patch.object(smoke.http.client, 'HTTPConnection', return_value=connection), \
                patch.object(smoke.json, 'loads', side_effect=AssertionError('not an app response')):
            _, raw = smoke.expect_status(client, 'GET', '/api/v1/scans', 404)
        self.assertIn(b'404 Not Found', raw)
        connection.close.assert_called_once()

    def test_app_json_does_not_fall_back_to_raw_or_accept_malformed_payloads(self):
        client = smoke.Http(smoke.Budget(lambda: 0))
        cases = [({'Content-Type': 'text/html'}, b'<html>404</html>', 'APP_JSON_CONTENT_TYPE'),
            ({'Content-Type': 'application/json'}, b'not-json', 'APP_JSON_INVALID'),
            ({'Content-Type': 'application/json'}, b'{"enabled":false,"enabled":true}', 'APP_JSON_DUPLICATE_KEYS'),
            ({'Content-Type': 'application/json'}, b'{"value":NaN}', 'APP_JSON_INVALID')]
        for headers, raw, code in cases:
            with self.subTest(code=code), patch.object(client, 'request_raw', return_value=(404, headers, raw)):
                with self.assertRaisesRegex(smoke.Failure, code):
                    client.request('GET', smoke.SCAN)
        with patch.object(client, 'request_raw', return_value=(401, {'content-type': 'application/json; charset=utf-8'}, b'{"errorCode":"UNAUTHORIZED"}')):
            self.assertEqual(client.request('GET', smoke.SCAN)[2], {'errorCode': 'UNAUTHORIZED'})

    def test_http_bounds_slow_body_and_maximum_bytes(self):
        clock = [0]
        client = smoke.Http(smoke.Budget(lambda: clock[0]))
        response, sock = Mock(), Mock()
        response.read1.side_effect = [b'1234', b'5']
        with self.assertRaisesRegex(smoke.Failure, 'HTTP_BODY_LIMIT'):
            client.read_body(response, sock, 15, 4)
        clock[0] = 16
        with self.assertRaisesRegex(smoke.Failure, 'HTTP_ABSOLUTE_TIMEOUT'):
            client.read_body(response, sock, 15, 4)

    def test_report_pagination_accumulates_exact_real_rows(self):
        client = Mock()
        rows = [{'ecosystem': 'apk', 'name': 'a', 'version': '1'}, {'ecosystem': 'apk', 'name': 'b', 'version': '1'}]
        def page(offset, items, cursor):
            return {'page': {'version': 1, 'limit': 25, 'offset': offset, 'returnedCount': len(items),
                            'totalCount': 2, 'matchedCount': 2}, 'components': items, 'nextCursor': cursor}
        client.request.side_effect = [(200, {}, page(0, rows[:1], 'opaque')), (200, {}, page(1, rows[1:], None))]
        _, actual = smoke.collect_report(client, SCAN_ID, 'sbom')
        self.assertEqual(actual, rows)
        self.assertIn('cursor=opaque', client.request.call_args_list[1].args[1])

    def test_report_truncation_is_not_pass(self):
        client = Mock()
        client.request.return_value = (200, {}, {'page': {'version': 1, 'limit': 25, 'offset': 0,
            'returnedCount': 0, 'totalCount': 3, 'matchedCount': 3}, 'components': [], 'nextCursor': None})
        with self.assertRaisesRegex(smoke.Failure, 'REPORT_TRUNCATED'):
            smoke.collect_report(client, SCAN_ID, 'sbom')

    def test_browser_exact_context_policy_and_disabled_contract_in_pure_node(self):
        script = "import assert from 'node:assert/strict';\n" + smoke.BROWSER_POLICY + r'''
const base = '/api/v1/browser/scans/12345678-1234-4234-8234-123456789abc';
const origin = 'http://127.0.0.1:18080';
assert.equal(browserRequestAllowed(origin + base + '/llm/context', 'GET', base), true);
assert.equal(browserRequestAllowed(origin + base + '/results?view=report-v1', 'GET', base), true);
for (const suffix of ['/llm/summary', '/llm/chat', '/llm/chat/context', '/llm/history',
  '/llm/usage', '/llm/context/', '/llm/context?x=1', 'evil/llm/context']) {
  assert.equal(browserRequestAllowed(origin + base + suffix, 'GET', base), false, suffix);
}
assert.equal(browserRequestAllowed(origin + base + '/llm/context', 'POST', base), false);
assert.equal(browserRequestAllowed('https://provider.invalid' + base + '/llm/context', 'GET', base), false);
assert.equal(browserRequestAllowed(origin + base.replace('12345678', '87654321') + '/llm/context', 'GET', base), false);
const sbom = { image: 'registry-1.docker.io/library/alpine@sha256:' + 'b'.repeat(64), platform: 'linux/amd64' };
const value = { scanId: base.split('/').at(-1), digest: 'sha256:' + 'b'.repeat(64), platform: 'linux/amd64',
 reportVersion: 'a'.repeat(64), enabled: false, policyVersion: null, disclosure: null };
assertDisabledContext(value, value.scanId, sbom);
for (const patch of [{ enabled: true }, { policyVersion: 'enabled' }, { disclosure: {} },
 { scanId: 'foreign' }, { digest: 'sha256:' + 'c'.repeat(64) }]) {
 assert.throws(() => assertDisabledContext({ ...value, ...patch }, value.scanId, sbom));
}
console.log('PURE_BROWSER_POLICY_PASS');
'''
        result = subprocess.run(['node', '--input-type=module'], input=script.encode(), capture_output=True,
            env={'PATH': smoke.PATH, 'HOME': '/nonexistent'}, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout.strip(), b'PURE_BROWSER_POLICY_PASS')

    def test_browser_source_requires_actual_origin_get_only_and_reload(self):
        self.assertIn("method !== 'GET'", smoke.BROWSER_POLICY)
        self.assertIn("url.origin !== 'http://127.0.0.1:18080'", smoke.BROWSER_POLICY)
        self.assertIn('assertDisabledContext', smoke.BROWSER)
        self.assertIn('await page.reload(', smoke.BROWSER)
        self.assertIn('route.continue()', smoke.BROWSER)
        self.assertNotIn('route.fulfill', smoke.BROWSER)
        self.assertNotIn('ignoreHTTPSErrors', smoke.BROWSER)


if __name__ == '__main__':
    unittest.main()
