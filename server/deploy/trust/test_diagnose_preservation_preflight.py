"""Focused inert mocks ONLY. No real child process, signal, Engine, private input or DB."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import selectors
from types import SimpleNamespace
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('owned_read_diagnostic', HERE / 'diagnose_preservation_preflight.py')
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)
SECRET = 'INERT_PRIVATE_SENTINEL_DO_NOT_EXPORT'


def argv():
    result = ['--diagnose-preflight-only', '--authorize-preservation-window', '--preservation-migration',
              '--authorize-scan-auth-additive-migration', '--authorize-migration-rw-sandbox-2g-240s',
              '--confirm-old-api-db-reads-reviewed', '--diagnostic-sha256', '0' * 64,
              '--diagnostic-test-sha256', '1' * 64,
              '--candidate-source-aggregate', d.AGGREGATE,
              '--sqlite-helper-relative', 'server/deploy/trust/sqlite_state_snapshot.mjs']
    for role, (container, image) in d.ORIGINALS.items():
        result += ['--' + role + '-container', container, '--' + role + '-image', 'sha256:' + image]
    for role, image in d.CANDIDATES.items():
        result += ['--candidate-' + role + '-image', 'sha256:' + image]
    for name, evidence in d.EVIDENCES.items():
        result += ['--' + name + '-review-evidence', evidence]
    for relative, pin in d.PINS.items():
        result += ['--source-sha256', relative + '=' + pin]
    return result


class DependencyBootstrapTests(unittest.TestCase):
    def sources(self):
        return {relative: (d.REPO / relative).read_bytes() for relative in (d.SELECTOR, d.CONTROLLER)}

    def test_verified_controller_loads_own_selector_without_injection_or_path_change(self):
        path = list(sys.path)
        execute = exec
        calls = []
        def executing(code, namespace):
            self.assertNotIn('stand_composition', sys.modules)
            self.assertNotIn('_dip_pinned_stand_composition_bootstrap', sys.modules)
            calls.append(code.co_filename)
            return execute(code, namespace)
        with patch.object(d, 'exec', side_effect=executing, create=True):
            module = d.load_dependencies(d.REPO, self.sources())
        self.assertEqual(calls, [str(d.REPO / d.CONTROLLER)])
        self.assertEqual(module.SELECTOR_SHA256, d.PINS[d.SELECTOR])
        self.assertEqual(sys.path, path)
        for name in ('stand_composition', '_dip_pinned_stand_composition_bootstrap',
                     '_dip_pinned_preservation_predicates'):
            self.assertNotIn(name, sys.modules)

    def test_preloaded_modules_refused_without_adoption_or_exec(self):
        for name in ('stand_composition', '_dip_pinned_stand_composition_bootstrap',
                     '_dip_pinned_preservation_predicates'):
            foreign = SimpleNamespace(private=SECRET)
            with self.subTest(name=name), patch.dict(sys.modules, {name: foreign}), \
                 patch.object(d, 'exec', side_effect=AssertionError('NO_EXEC'), create=True) as execute:
                with self.assertRaises(d.ClosedFailure):
                    d.load_dependencies(d.REPO, self.sources())
                self.assertIs(sys.modules[name], foreign)
                execute.assert_not_called()

    def test_final_verifier_pins_match_controller_and_public_sources(self):
        module = d.load_dependencies(d.REPO, self.sources())
        self.assertEqual(d.RELEASE_VERIFIER_PINS, module.RELEASE_VERIFIER_PINS)
        for relative, pin in d.RELEASE_VERIFIER_PINS.items():
            self.assertEqual(hashlib.sha256((d.REPO / relative).read_bytes()).hexdigest(), pin)

    def test_readonly_action_cannot_select_or_convert_to_preparation(self):
        with self.assertRaises(d.ClosedFailure):
            d.arguments(argv() + ['--prepare-rollout-only'])
        module = d.load_dependencies(d.REPO, self.sources())
        plan = d.plan_for(module, d.arguments(argv()))
        self.assertFalse(plan.prepare_rollout_only)
        self.assertFalse(plan.qualify_release_only)

    def test_both_captured_pins_checked_before_any_exec(self):
        for relative in (d.SELECTOR, d.CONTROLLER):
            sources = self.sources()
            sources[relative] += b'\n# INERT_TAMPER\n'
            with self.subTest(relative=relative), \
                 patch.object(d, 'exec', side_effect=AssertionError('NO_UNVERIFIED_EXEC'), create=True) as execute:
                with self.assertRaises(d.ClosedFailure):
                    d.load_dependencies(d.REPO, sources)
                execute.assert_not_called()
        self.assertNotIn('_dip_pinned_preservation_predicates', sys.modules)

    def test_bootstrap_exception_is_closed_by_diagnostic_before_any_client(self):
        with patch.object(d, 'load_dependencies', side_effect=RuntimeError(SECRET)), \
             patch.object(d, 'ReadRunner', side_effect=AssertionError('NO_CLIENT')) as runner:
            diagnostic = d.Diagnostic(d.REPO, {}, reader=lambda *args: b'INERT',
                                      loader=d.load_dependencies, runner_factory=d.ReadRunner)
            with patch.object(d, 'metadata'), patch.object(d, 'lock_absent'):
                result = diagnostic.result(argv())
        self.assertEqual(result['outcome'], 'REFUSED')
        self.assertEqual(result['checkpoint'], 'D_IMPORT')
        self.assertEqual(result['boundary'], 'NO_ACTIVATION')
        self.assertNotIn(SECRET, json.dumps(result))
        runner.assert_not_called()


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # PUBLIC captured sources only. Hash verified before execution; no DB/app imports.
        cls.m = d.load_dependencies(d.REPO, {
            relative: (d.REPO / relative).read_bytes() for relative in (d.SELECTOR, d.CONTROLLER)})

    def setUp(self):
        self.m = type(self).m
        self.tmp = tempfile.TemporaryDirectory(prefix='inert-read-diagnostic-')
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.repo.chmod(0o755)
        helper = self.repo / 'server/deploy/trust/sqlite_state_snapshot.mjs'
        helper.parent.mkdir(parents=True)
        helper.write_bytes(b'INERT_PUBLIC_HELPER_NOT_EXECUTED')
        helper.chmod(0o644)
        self.calls, self.reads = [], []
        self.fail = None
        self.version = b'2.34.0\n'
        self.staged_mode = 0o400
        self.images, self.records = {}, {}
        self.network_id = 'a' * 64
        self.model = {'name': d.PROJECT, 'services': {},
                      'networks': {'internal': {'name': d.PROJECT + '_internal', 'internal': True}},
                      'volumes': {'auth_accounts': {'name': d.PROJECT + '_auth_accounts'},
                                  'scan_ledger': {'name': d.PROJECT + '_scan_ledger'}}}
        for role, (identity, image) in d.ORIGINALS.items():
            env = dict(self.m.FREE, SCAN_JWT_SECRET=SECRET + 'j' * 40,
                       AUTH_ORIGIN='http://127.0.0.1:8080', OPENROUTER_API_KEY=SECRET + '_NEW') if role == 'api' else {}
            command = ['node', '--import', 'tsx', 'src/oci/nginx-local.main.ts'] if role == 'api' else ['inert-' + role]
            defaults = {'Env': ['PATH=/inert'], 'User': '65532:65532', 'WorkingDir': '/app/server/api',
                        'Cmd': ['inert-default'], 'Entrypoint': None, 'OnBuild': None}
            self.images['sha256:' + image] = {'Id': 'sha256:' + image, 'Os': 'linux', 'Architecture': 'arm64',
                                              'Config': defaults}
            mounts, volumes = [], []
            for logical in (('auth_accounts', 'scan_ledger') if role == 'api' else
                            ('scan_ledger',) if role == 'worker' else ()):
                name = d.PROJECT + '_' + logical
                target = '/auth' if logical == 'auth_accounts' else '/data'
                volumes.append({'type': 'volume', 'source': logical, 'target': target})
                mounts.append({'Type': 'volume', 'Name': name, 'Source': '/inert/volumes/' + name,
                               'Destination': target, 'RW': True, 'Propagation': ''})
            service = {'environment': env, 'command': command, 'user': '65532:65532',
                       'read_only': True, 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
                       'volumes': volumes, 'networks': {'internal': {}}, 'mem_limit': '256m', 'cpus': 1,
                       'pids_limit': 128}
            if role == 'web':
                service['ports'] = [{'host_ip': '127.0.0.1', 'published': '8080', 'target': 8080}]
            self.model['services'][role] = service
            runtime_env = dict(PATH='/inert', **env)
            if role == 'api':
                runtime_env['OPENROUTER_API_KEY'] = SECRET + '_OLD'
            self.records[identity] = {
                'Id': identity, 'Image': 'sha256:' + image, 'Name': '/' + d.PROJECT + '-' + role + '-1',
                'Config': {'Env': [k + '=' + v for k, v in runtime_env.items()], 'User': '65532:65532',
                           'WorkingDir': '/app/server/api', 'Cmd': command, 'Entrypoint': None, 'Volumes': None,
                           'Labels': {'com.docker.compose.project': d.PROJECT, 'com.docker.compose.service': role}},
                'HostConfig': {'ReadonlyRootfs': True, 'CapDrop': ['ALL'], 'CapAdd': None,
                               'SecurityOpt': ['no-new-privileges:true'], 'Privileged': False,
                               'RestartPolicy': {'Name': 'no'}, 'Memory': 256 * d.MIB,
                               'NanoCpus': 1000000000, 'PidsLimit': 128,
                               'PortBindings': {'8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '8080'}]} if role == 'web' else None},
                'Mounts': mounts, 'NetworkSettings': {'Networks': {d.PROJECT + '_internal': {'NetworkID': self.network_id}}},
                'Path': 'node', 'Args': command[1:],
                'State': {'Running': True, 'Health': {'Status': 'healthy'}, 'Paused': False, 'Restarting': False},
            }
        self.model['services'].update({'auth-volume-init': {}, 'scan-volume-init': {}})
        for role, image in d.CANDIDATES.items():
            self.images['sha256:' + image] = copy.deepcopy(self.images['sha256:' + d.ORIGINALS[role][1]])
            self.images['sha256:' + image]['Id'] = 'sha256:' + image
        self.volumes = [{'Name': d.PROJECT + '_' + n, 'Driver': 'local', 'Scope': 'local', 'Options': None,
                         'Labels': {'com.docker.compose.project': d.PROJECT}, 'Mountpoint': '/inert/volumes/' + d.PROJECT + '_' + n}
                        for n in ('auth_accounts', 'scan_ledger')]
        self.network = {'Id': self.network_id, 'Name': d.PROJECT + '_internal', 'Internal': True, 'Containers': {}}
        self.env = {'DOCKER_HOST': d.SOCKET, 'DOCKER_CONTEXT': ''}
        self.selected = SimpleNamespace(profile='nginx-local', llm='openrouter-free', files=d.FILES,
                                        command=d.ReadRunner(self.repo, self.env).render[:-7])
        for name in ('activate', 'operate', 'operate_migration', 'preflight', 'fail_stop', 'hold', 'stop',
                     'compatibility', 'snapshot', 'export', 'migration_exec', 'create_holder'):
            self.enterContext(patch.object(self.m.Controller, name, side_effect=AssertionError('FORBIDDEN_LIFECYCLE')))
        self.enterContext(patch.object(d, 'metadata', return_value=(1, 1, stat.S_IFDIR | 0o755, 1, 1, 1, 1)))
        self.lock = self.enterContext(patch.object(d, 'lock_absent'))
        self.enterContext(patch.object(self.m, 'alarm_available'))  # NO real signal/timer calls.
        self.enterContext(patch.object(self.m, 'path_metadata', side_effect=self.secret_metadata))
        self.enterContext(patch.object(self.m, 'select', return_value=self.selected))
        self.enterContext(patch.object(self.m.shutil, 'disk_usage', return_value=SimpleNamespace(free=4 * self.m.GIB)))
        self.enterContext(patch.object(subprocess, 'Popen', side_effect=AssertionError('NO_REAL_SUBPROCESS')))
        self.diag = d.Diagnostic(self.repo, self.env, reader=self.reader, loader=lambda *args: self.m,
                                 runner_factory=lambda *args, **kw: d.ReadRunner(*args, transport=self.transport, **kw))

    def secret_metadata(self, path, **kwargs):
        # No filesystem access: even private metadata uses synthetic tuples ONLY.
        mode = self.staged_mode if str(path).endswith('.env.openrouter.local') else 0o600
        return (1, 1, stat.S_IFREG | mode, 1, 1, 64, 1)

    def reader(self, path, expected):
        self.reads.append(str(path))
        if self.fail and self.fail('source', str(path)):
            raise d.ClosedFailure('PREDICATE_REFUSED')
        return b'INERT_PINNED_SOURCE_TOKEN'

    def transport(self, args, repo, env, timeout, cap):
        self.calls.append(args)
        self.assertLessEqual(timeout, 15)
        if self.fail and self.fail('command', args):
            raise RuntimeError(SECRET)
        if args == ('docker', 'compose', 'version', '--short'):
            return self.version
        if args[1:3] == ('image', 'inspect'):
            value = [self.images[args[3]]]
        elif args[1:3] == ('network', 'inspect'):
            value = [self.network]
        elif args[1:3] == ('volume', 'inspect'):
            value = self.volumes
        elif args[1] == 'info':
            value = 4 * self.m.GIB if 'MemTotal' in args[-1] else 'INERT_DAEMON'
        elif args[1] == 'ps':
            return ('\n'.join(self.records) + '\n').encode()
        elif args[1] == 'inspect' and '--format' in args:
            return b'\n'.join(self.m.encoded({'id': i, 'running': self.records[i]['State']['Running'],
                                            'mounts': self.records[i]['Mounts']}).rstrip() for i in args[6:]) + b'\n'
        elif args[1] == 'inspect':
            value = [self.records[i] for i in args[4:]]
        elif args[1] == 'compose':
            # Independent raw-JSON config.go output contract, not production encoder.
            return self.m.encoded(self.model).replace(b'$', b'$$')
        else:
            self.fail('Unexpected argv')
        return self.m.encoded(value)

    def result(self):
        result = self.diag.result(argv())
        self.assertLess(len(json.dumps(result)), 4096)
        self.assertNotIn(SECRET, json.dumps(result))
        if result['checkpoint'] not in d.CHECKPOINTS:
            identifiers = result['checkpoint'].split('__')
            self.assertIn(identifiers[0], {'D_P_' + r.upper().replace('-', '_') for r in d.ROLES})
            self.assertIn(len(identifiers), (2, 3))
            self.assertTrue(all(gate in self.m.PREDICATE_IDS for gate in identifiers[1:]))
        self.assertIn(result['category'], d.CATEGORIES)
        return result

    def test_read_subset_pass_real_pinned_predicates_no_lifecycle_or_signal(self):
        result = self.result()
        self.assertEqual(result['outcome'], 'READ_SUBSET_PASS')
        self.assertEqual(result['checkpoint'], 'D_COMPLETE')
        self.assertEqual(result['category'], 'NONE')
        self.assertEqual(self.lock.call_count, 2)
        self.assertFalse(any(a[1] in ('up', 'stop', 'exec', 'create', 'run', 'cp') for a in self.calls))

    def test_finite_compose_versions_and_near_misses(self):
        self.assertEqual(self.m.SUPPORTED_COMPOSE_VERSIONS, frozenset((b'2.34.0', b'2.34.0-desktop.1')))
        for report in (b'2.34.0', b' \t2.34.0\r\n', b'2.34.0-desktop.1', b' \t2.34.0-desktop.1\r\n'):
            self.calls.clear()
            self.version = report
            self.assertEqual(self.result()['outcome'], 'READ_SUBSET_PASS')
            self.assertEqual(self.calls.count(('docker', 'compose', 'version', '--short')), 1)
        for report in (b'2.34.0-desktop.2', b'2.34.0-desktop.10', b'2.34.1', b'2.35.0',
                       b'v2.34.0', b'2.34.0+build', b'2.34.0 extra', b'2.34.0\nextra',
                       b'', b'\xff', b'2.34.0\0'):
            self.calls.clear()
            self.version = report
            result = self.result()
            self.assertEqual((result['checkpoint'], result['outcome'], result['category']),
                             ('D_COMPOSE_VERSION', 'REFUSED', 'PREDICATE_REFUSED'))
            self.assertEqual(self.calls, [('docker', 'compose', 'version', '--short')])

    def test_version_clients_fail_closed_without_fallback(self):
        for category in ('CLIENT_NONZERO', 'CLIENT_TIMEOUT', 'OUTPUT_CAP', 'DECODE_REFUSED', 'UNEXPECTED'):
            self.calls.clear()
            def refused(args, *rest):
                self.calls.append(args)
                raise d.ClosedFailure(category)
            self.transport = refused
            result = self.result()
            self.assertEqual((result['checkpoint'], result['outcome'], result['category']),
                             ('D_COMPOSE_VERSION', 'REFUSED', category))
            self.assertEqual(self.calls, [('docker', 'compose', 'version', '--short')])

    def test_desktop_preserves_candidate_labels_and_model_config(self):
        self.version = b'2.34.0-desktop.1\n'
        config = self.images['sha256:' + d.CANDIDATES['web']]['Config']
        config['Labels'] = {'com.docker.compose.version': '2.34.0-desktop.1'}
        self.assertEqual(self.result()['checkpoint'], 'D_CANDIDATE_WEB')
        config.pop('Labels')
        self.model['services']['worker']['read_only'] = False
        self.assertEqual(self.result()['checkpoint'], 'D_P_WORKER__MODEL_ROOTFS')

    def test_serialized_dollars_preserve_raw_env_defaults_jwt_auth(self):
        api = self.records[d.ORIGINALS['api'][0]]['Config']
        env = self.model['services']['api']['environment']
        env.update(OPENROUTER_API_KEY=SECRET + '_$new$${literal}',
                   SCAN_JWT_SECRET=SECRET + '_$$JWT_${literal}' + 'j' * 40,
                   SCAN_BROWSER_ALLOWED_USER_IDS='$one,$$two,${three}')
        for role in d.ROLES:
            defaults = self.images['sha256:' + d.ORIGINALS[role][1]]['Config']['Env']
            defaults.append('RAW_DEFAULT=$$raw${default}')
            if role in d.CANDIDATES:
                self.images['sha256:' + d.CANDIDATES[role]]['Config']['Env'] = list(defaults)
            actual = dict(self.m.env_map(defaults), **self.model['services'][role]['environment'])
            if role == 'api':
                actual[self.m.KEY] = SECRET + '_$old'
            self.records[d.ORIGINALS[role][0]]['Config']['Env'] = [k + '=' + v for k, v in actual.items()]
        before = copy.deepcopy(api)
        captured = []
        predicate = self.m.Controller.compatibility_input
        def private_input(c):
            data = predicate(c)
            captured.append(self.m.decode(data))
            return data
        with patch.object(self.m.Controller, 'compatibility_input', private_input):
            self.assertEqual(self.result()['outcome'], 'READ_SUBSET_PASS')
        self.assertEqual(captured, [{k: env.get(k) for k in self.m.AUTH_SETTINGS}])
        self.assertEqual(api, before)
        env['SCAN_BROWSER_ALLOWED_USER_IDS'] += 'changed'
        self.assertEqual(self.result()['checkpoint'], 'D_API_NONKEY_ENV')

    def test_unsafe_serialized_dollar_refuses_at_wrapped_model_api(self):
        transport = self.transport
        def unsafe(*args):
            output = transport(*args)
            if args[0][1] == 'compose' and 'config' in args[0]:
                model = self.m.decode(output)
                model['services']['api']['environment']['INERT_ODD'] = '$unsafe'
                return self.m.encoded(model)
            return output
        self.transport = unsafe
        result = self.result()
        self.assertEqual((result['checkpoint'], result['category']), ('D_P_API__API_PREP_RUNTIME__RUNTIME_DOLLAR_PAIRS', 'PREDICATE_REFUSED'))
        self.assertEqual(self.calls[-1], d.ReadRunner(self.repo, self.env).render)

    def test_null_command_entrypoint_inherit_and_empty_override_stays_exact(self):
        role = 'worker'
        default = self.images['sha256:' + d.ORIGINALS[role][1]]['Config']
        default.update(Cmd=['default', '$$literal'], Entrypoint=['/inert/$entrypoint'])
        self.images['sha256:' + d.CANDIDATES[role]]['Config'] = copy.deepcopy(default)
        service = self.model['services'][role]
        record = self.records[d.ORIGINALS[role][0]]['Config']
        service.update(command=None, entrypoint=None)
        record.update(Cmd=default['Cmd'], Entrypoint=default['Entrypoint'])
        self.assertEqual(self.result()['outcome'], 'READ_SUBSET_PASS')
        service.update(command=[], entrypoint=[])
        self.assertEqual(self.result()['checkpoint'], 'D_P_WORKER__MODEL_COMMAND')
        record.update(Cmd=[], Entrypoint=[])
        self.assertEqual(self.result()['outcome'], 'READ_SUBSET_PASS')

    def test_same_old_checkpoint_now_separates_prep_and_config_without_private_output(self):
        env = self.records[d.ORIGINALS['api'][0]]['Config']['Env']
        env.append('PATH=INERT_DUPLICATE_' + SECRET)
        result = self.result()
        self.assertEqual(result['checkpoint'], 'D_P_API__API_PREP_ACTUAL_ENV__API_OLD_ENV_ENTRY_UNIQUE')
        self.assertEqual(result['boundary'], 'NO_ACTIVATION')
        self.assertEqual(self.calls[-1], d.ReadRunner(self.repo, self.env).render)
        env.pop()
        self.diag.predicate_stack.clear()  # New inert observation object state, not a runtime retry.
        self.records[d.ORIGINALS['api'][0]]['Config']['User'] = '0'
        result = self.result()
        self.assertEqual(result['checkpoint'], 'D_P_API__MODEL_USER')
        self.assertEqual(set(result), {'mode', 'checkpoint', 'outcome', 'category', 'boundary'})
        self.assertEqual(self.calls[-1], d.ReadRunner(self.repo, self.env).render)
        self.assertFalse(any('up' in a or 'exec' in a or 'stop' in a for a in self.calls))

    def test_nested_pass_restores_parent_failure_and_subgate_is_precise(self):
        record = self.records[d.ORIGINALS['api'][0]]
        record['HostConfig']['Memory'] = 1
        self.assertEqual(self.result()['checkpoint'], 'D_P_API__MODEL_MEMORY')
        record['HostConfig']['Memory'] = 256 * self.m.MIB
        self.diag.predicate_stack.clear()
        self.model['services']['api']['healthcheck'] = {'interval': 'INERT_INVALID_' + SECRET}
        self.assertEqual(self.result()['checkpoint'], 'D_P_API__MODEL_HEALTH_BUILD__HEALTH_DURATION_FORMAT')
        self.assertEqual(self.calls[-1], d.ReadRunner(self.repo, self.env).render)

    def test_observer_errors_fail_closed_no_child_operation_and_no_secret_output(self):
        original = self.diag.predicate_event
        for phase in ('ENTER', 'PASS'):
            self.diag.predicate_stack.clear()
            def fail(gate, event):
                if gate == 'MODEL_USER' and event == phase:
                    raise RuntimeError(SECRET)
                return original(gate, event)
            with patch.object(self.diag, 'predicate_event', side_effect=fail):
                result = self.result()
            self.assertEqual((result['category'], result['outcome']), ('PREDICATE_REFUSED', 'REFUSED'))
            self.assertEqual(self.calls[-1], d.ReadRunner(self.repo, self.env).render)
        self.diag.predicate_stack.clear()
        for gate, phase in (('UNAPPROVED_' + SECRET, 'ENTER'), ('MODEL_USER', 'UNKNOWN')):
            with self.assertRaises(d.ClosedFailure):
                self.diag.predicate_event(gate, phase)

    def test_observer_deadline_enter_and_pass_remain_timeout_and_no_next_client(self):
        now = [0.0]
        self.diag.clock = lambda: now[0]
        self.diag.deadline = 120.0
        original = self.diag.predicate_event
        for phase in ('ENTER', 'PASS'):
            now[0] = 0.0
            self.calls.clear()
            def expire(gate, event):
                if gate == 'MODEL_USER' and event == phase:
                    now[0] = 120.0
                return original(gate, event)
            with patch.object(self.diag, 'predicate_event', side_effect=expire):
                result = self.result()
            self.assertEqual(result, {'mode': 'preflight-readonly-v1', 'checkpoint': 'D_P_API__MODEL_USER',
                                      'category': 'CLIENT_TIMEOUT', 'outcome': 'REFUSED',
                                      'boundary': 'NO_ACTIVATION'})
            self.assertTrue(self.diag.deadline_expired)
            self.assertEqual(self.calls[-1], d.ReadRunner(self.repo, self.env).render)
            self.assertFalse(any('network' in a or 'volume' in a or 'exec' in a or 'up' in a or 'stop' in a
                                 for a in self.calls))
            self.lock.assert_called()  # Read-only absence check only, never an acquisition.

    def test_deadline_flag_reset_does_not_reset_shared_budget_or_mask_other_refusal(self):
        self.diag.deadline_expired = True
        deadline = self.diag.deadline
        with patch.object(self.diag, 'observe', side_effect=d.ClosedFailure('PREDICATE_REFUSED')):
            result = self.result()
        self.assertFalse(self.diag.deadline_expired)
        self.assertEqual(self.diag.deadline, deadline)
        self.assertEqual((result['category'], result['outcome'], result['boundary']),
                         ('PREDICATE_REFUSED', 'REFUSED', 'NO_ACTIVATION'))
        self.assertEqual(self.calls, [])

    def bind_fixture(self):
        mount = {'type': 'bind', 'source': '/inert/release', 'target': '/opt/release', 'read_only': True}
        self.model['services']['api']['volumes'].append(mount)
        self.records[d.ORIGINALS['api'][0]]['Mounts'].append(
            {'Type': 'bind', 'Source': '/inert/release', 'Destination': '/opt/release', 'RW': False, 'Propagation': ''})
        return mount

    def test_reviewed_present_bind_forms_pass_full_read_subset_without_model_mutation(self):
        mount = self.bind_fixture()
        for options in ({}, {'create_host_path': False}):
            mount['bind'] = options
            before = copy.deepcopy(self.model)
            self.assertEqual(self.result()['outcome'], 'READ_SUBSET_PASS')
            self.assertEqual(self.model, before)
        self.assertFalse(any('up' in a or 'stop' in a or 'exec' in a for a in self.calls))

    def test_bad_bind_forms_and_source_target_rw_drift_refuse_before_next_client(self):
        mount = self.bind_fixture()
        for absent, options in [(True, None)] + [(False, value) for value in (
                None, True, [], SECRET, {'create_host_path': True}, {'create_host_path': 0},
                {'create_host_path': 1}, {'create_host_path': None}, {'create_host_path': 'false'},
                {'create_host_path': False, 'extra': False}, {'extra': False})]:
            self.calls.clear()
            if absent:
                mount.pop('bind', None)
            else:
                mount['bind'] = options
            result = self.result()
            self.assertEqual((result['checkpoint'], result['category'], result['boundary']),
                             ('D_P_API__MODEL_BIND_OPTIONS', 'PREDICATE_REFUSED', 'NO_ACTIVATION'))
            self.assertEqual(self.calls[-1], d.ReadRunner(self.repo, self.env).render)
        for options in ({}, {'create_host_path': False}):
            mount['bind'] = options
            for field, value in (('source', '/inert/wrong'), ('target', '/wrong'), ('read_only', False)):
                self.calls.clear()
                original = mount[field]
                mount[field] = value
                result = self.result()
                self.assertEqual((result['checkpoint'], result['category'], result['boundary']),
                                 ('D_P_API__MODEL_MOUNTS', 'PREDICATE_REFUSED', 'NO_ACTIVATION'))
                self.assertEqual(self.calls[-1], d.ReadRunner(self.repo, self.env).render)
                mount[field] = original
        self.assertFalse(any('up' in a or 'stop' in a or 'exec' in a for a in self.calls))

    def classification(self):
        result = self.diag.result(argv() + ['--classify-models-only'])
        self.assertEqual(set(result), {'mode', 'checkpoint', 'outcome', 'category', 'boundary',
                                       'firstFailure', 'models', 'mounts'})
        self.assertEqual(result['mode'], 'model-classification-readonly-v1')
        self.assertEqual(result['boundary'], 'NO_ACTIVATION')
        self.assertIn(result['outcome'], ('MODELS_CLASSIFIED', 'REFUSED'))
        self.assertNotEqual(result['checkpoint'], 'D_COMPLETE')
        self.assertIn(result['category'], d.CATEGORIES)
        self.assertEqual(set(result['models']), set(d.ROLES))
        self.assertEqual(set(result['mounts']), set(d.ROLES))
        self.assertTrue(set(result['models'].values()) <= {'PASS', 'FAIL', 'BLOCKED'})
        for flags in result['mounts'].values():
            self.assertEqual(set(flags), set(d.MOUNT_FLAGS))
            self.assertTrue(set(flags.values()) <= {'YES', 'NO', 'BLOCKED'})
        for checkpoint in [result['checkpoint']] + ([result['firstFailure']['checkpoint']]
                                                    if result['firstFailure'] else []):
            if checkpoint not in d.CHECKPOINTS:
                identifiers = checkpoint.split('__')
                self.assertIn(identifiers[0], {'D_P_' + r.upper().replace('-', '_')
                                              for r in (*d.ROLES, 'all')})
                self.assertIn(len(identifiers), (2, 3))
                self.assertTrue(all(gate in self.m.PREDICATE_IDS for gate in identifiers[1:]))
        if result['firstFailure']:
            self.assertEqual(set(result['firstFailure']), {'checkpoint', 'category'})
            self.assertIn(result['firstFailure']['category'], d.CATEGORIES - {'NONE'})
        receipt = json.dumps(result, sort_keys=True, separators=(',', ':'))
        self.assertLessEqual(len(receipt.encode('ascii')), 4096)
        for private in (SECRET, '/inert', '/auth', '/data', 'OPENROUTER_API_KEY',
                        d.AGGREGATE, *d.PINS.values(), *d.ORIGINALS['api']):
            self.assertNotIn(private, receipt)
        self.assertEqual(self.calls[-1], d.ReadRunner(self.repo, self.env).render)
        self.lock.assert_called_once()  # No final checks, acquisition, or later read clients.
        self.assertEqual(sum(a == d.ReadRunner(self.repo, self.env).render for a in self.calls), 1)
        self.assertFalse(any(a[1] in ('network', 'volume', 'info', 'ps', 'up', 'stop', 'exec', 'run', 'cp')
                             for a in self.calls))
        return result

    def test_classification_all_roles_once_and_stops_after_capture(self):
        original = self.m.Controller.model_matches
        seen = []
        def compare(controller, role, *args, **kwargs):
            seen.append(role)
            return original(controller, role, *args, **kwargs)
        with patch.object(self.m.Controller, 'model_matches', new=compare):
            result = self.classification()
        self.assertEqual(seen, list(d.ROLES))
        self.assertEqual(result['models'], dict.fromkeys(d.ROLES, 'PASS'))
        self.assertTrue(all(set(flags.values()) == {'NO'} for flags in result['mounts'].values()))
        self.assertEqual((result['outcome'], result['category'], result['checkpoint'], result['firstFailure']),
                         ('MODELS_CLASSIFIED', 'NONE', 'D_MODELS_CLASSIFIED', None))

    def test_classification_multirole_failures_keep_first_and_reset_observer(self):
        self.records[d.ORIGINALS['api'][0]]['Mounts'][0]['Name'] = SECRET
        self.records[d.ORIGINALS['worker'][0]]['Config']['User'] = SECRET
        original = self.m.Controller.model_matches
        seen = []
        def compare(controller, role, *args, **kwargs):
            self.assertEqual(self.diag.predicate_stack, [])
            seen.append(role)
            return original(controller, role, *args, **kwargs)
        with patch.object(self.m.Controller, 'model_matches', new=compare):
            result = self.classification()
        self.assertEqual(seen, list(d.ROLES))
        self.assertEqual(result['firstFailure'], {'checkpoint': 'D_P_API__MODEL_MOUNTS',
                                                  'category': 'PREDICATE_REFUSED'})
        self.assertEqual((result['checkpoint'], result['category'], result['outcome']),
                         ('D_P_API__MODEL_MOUNTS', 'PREDICATE_REFUSED', 'REFUSED'))
        self.assertEqual(result['models'], dict(api='FAIL', worker='FAIL', web='PASS',
                                                egress='PASS', **{'llm-egress': 'PASS'}))
        self.assertEqual(result['mounts']['api']['NAMED_VOLUME_SOURCE_MISMATCH'], 'YES')
        self.assertEqual(result['mounts']['api']['BIND_SOURCE_MISMATCH'], 'NO')

    def test_classification_api_prep_failure_blocks_only_api_comparator(self):
        self.records[d.ORIGINALS['api'][0]]['Config']['Env'].append('PATH=' + SECRET)
        original = self.m.Controller.model_matches
        seen = []
        def compare(controller, role, *args, **kwargs):
            seen.append(role)
            return original(controller, role, *args, **kwargs)
        with patch.object(self.m.Controller, 'model_matches', new=compare):
            result = self.classification()
        self.assertEqual(seen, list(d.ROLES[1:]))
        self.assertEqual(result['models'], dict.fromkeys(d.ROLES[1:], 'PASS') | {'api': 'BLOCKED'})
        self.assertEqual(result['firstFailure']['checkpoint'],
                         'D_P_API__API_PREP_ACTUAL_ENV__API_OLD_ENV_ENTRY_UNIQUE')
        self.assertTrue(all(set(flags.values()) == {'NO'} for flags in result['mounts'].values()))

    def test_classification_whole_decoder_failure_blocks_all(self):
        self.model['services']['web']['command'] = ['UNSAFE_$' + SECRET]
        transport = self.transport
        def unsafe(args, *rest):
            data = transport(args, *rest)
            return data.replace(b'UNSAFE_$$', b'UNSAFE_$') if args[1] == 'compose' else data
        self.diag.runner_factory = lambda *args, **kw: d.ReadRunner(*args, transport=unsafe, **kw)
        with patch.object(self.m.Controller, 'model_matches', side_effect=AssertionError('NO_COMPARATOR')) as compare:
            result = self.classification()
        compare.assert_not_called()
        self.assertEqual(result['models'], dict.fromkeys(d.ROLES, 'BLOCKED'))
        self.assertTrue(all(set(flags.values()) == {'BLOCKED'} for flags in result['mounts'].values()))
        self.assertEqual(result['category'], 'PREDICATE_REFUSED')
        self.assertTrue(result['firstFailure']['checkpoint'].startswith('D_P_ALL__'))

    def test_classification_later_timeout_preserves_first_and_stops_remaining_roles(self):
        self.records[d.ORIGINALS['api'][0]]['Mounts'][0]['Name'] = SECRET
        now = [0.0]
        self.diag.clock, self.diag.deadline = lambda: now[0], 120.0
        observer = self.diag.predicate_event
        original = self.m.Controller.model_matches
        seen = []
        def expire(gate, event):
            if self.diag.predicate_role == 'worker' and gate == 'MODEL_USER' and event == 'ENTER':
                now[0] = 120.0
            return observer(gate, event)
        def compare(controller, role, *args, **kwargs):
            seen.append(role)
            return original(controller, role, *args, **kwargs)
        with patch.object(self.diag, 'predicate_event', side_effect=expire), \
             patch.object(self.m.Controller, 'model_matches', new=compare):
            result = self.classification()
        self.assertEqual(seen, ['api', 'worker'])
        self.assertEqual(result['firstFailure'], {'checkpoint': 'D_P_API__MODEL_MOUNTS',
                                                  'category': 'PREDICATE_REFUSED'})
        self.assertEqual((result['checkpoint'], result['category'], result['outcome']),
                         ('D_P_WORKER__MODEL_USER', 'CLIENT_TIMEOUT', 'REFUSED'))
        self.assertEqual(result['models'], dict.fromkeys(d.ROLES, 'BLOCKED') | {'api': 'FAIL'})

    def test_classification_step_timeout_blocks_role_without_observer_event(self):
        now = [0.0]
        self.diag.clock, self.diag.deadline = lambda: now[0], 120.0
        def expire(*args, **kwargs):
            now[0] = 120.0
        with patch.object(self.m.Controller, 'model_matches', new=expire):
            result = self.classification()
        self.assertEqual(result['models'], dict.fromkeys(d.ROLES, 'BLOCKED'))
        self.assertEqual(result['category'], 'CLIENT_TIMEOUT')
        self.assertEqual(result['checkpoint'], 'D_API_CONFIG')

    def test_classification_projection_flags_exact_sources_types_rw_and_tmpfs(self):
        mount = self.bind_fixture()
        mount['bind'] = {}
        runtime = self.m.compose_runtime_model(self.model)
        actual = self.records[d.ORIGINALS['api'][0]]
        actual['Mounts'].append({'Type': 'tmpfs', 'Destination': '/inert/tmp'})
        actual['Mounts'].reverse()  # Ordering and named-volume host Source do not affect equality.
        flags = d.classify_mounts(runtime, 'api', actual)
        self.assertEqual(flags, dict.fromkeys(d.MOUNT_FLAGS, 'NO'))
        actual['Mounts'][1]['Source'] = SECRET
        actual['Mounts'][2]['Name'] = SECRET
        actual['Mounts'][2]['RW'] = False
        flags = d.classify_mounts(runtime, 'api', actual)
        self.assertEqual({k for k, v in flags.items() if v == 'YES'},
                         {'BIND_SOURCE_MISMATCH', 'NAMED_VOLUME_SOURCE_MISMATCH', 'RW_MISMATCH'})
        actual['Mounts'][1]['Type'] = 'volume'
        actual['Mounts'][1]['Name'] = SECRET
        flags = d.classify_mounts(runtime, 'api', actual)
        self.assertEqual(flags['TYPE_MISMATCH'], 'YES')
        self.assertEqual(flags['BIND_SOURCE_MISMATCH'], 'BLOCKED')
        self.assertEqual(flags['NAMED_VOLUME_SOURCE_MISMATCH'], 'BLOCKED')
        self.assertEqual(flags['RW_MISMATCH'], 'YES')

    def test_classification_projection_duplicates_unmatched_cardinality_block_dependents(self):
        runtime = self.m.compose_runtime_model(self.model)
        original = self.records[d.ORIGINALS['api'][0]]
        for change, yes in (('duplicate', {'CARDINALITY_MISMATCH', 'DUPLICATE_TARGETS'}),
                            ('target', {'UNMATCHED_TARGETS'}),
                            ('missing', {'CARDINALITY_MISMATCH', 'UNMATCHED_TARGETS'})):
            record = copy.deepcopy(original)
            if change == 'duplicate':
                record['Mounts'].append(copy.deepcopy(record['Mounts'][0]))
            elif change == 'target':
                record['Mounts'][0]['Destination'] = SECRET
            else:
                record['Mounts'].pop()
            flags = d.classify_mounts(runtime, 'api', record)
            self.assertEqual({k for k, v in flags.items() if v == 'YES'}, yes)
            self.assertTrue(all(flags[k] == 'BLOCKED' for k in d.MOUNT_FLAGS[4:]))
        runtime['services']['api']['volumes'].append(copy.deepcopy(runtime['services']['api']['volumes'][0]))
        flags = d.classify_mounts(runtime, 'api', original)
        self.assertEqual(flags['DUPLICATE_TARGETS'], 'YES')
        self.assertTrue(all(flags[k] == 'BLOCKED' for k in d.MOUNT_FLAGS[4:]))

    def test_classification_projection_malformed_and_bounded(self):
        runtime = self.m.compose_runtime_model(self.model)
        for mounts in (None, [None], [{'Type': 'volume', 'Name': SECRET, 'Destination': '/inert', 'RW': 0}],
                       self.records[d.ORIGINALS['api'][0]]['Mounts'] * d.MOUNT_CLASSIFY_LIMIT):
            flags = d.classify_mounts(runtime, 'api', {'Mounts': mounts})
            self.assertEqual(flags, dict.fromkeys(d.MOUNT_FLAGS, 'BLOCKED') | {'MALFORMED': 'YES'})
        self.records[d.ORIGINALS['worker'][0]]['Mounts'] = None
        result = self.classification()
        self.assertEqual(result['models']['worker'], 'FAIL')
        self.assertEqual(result['mounts']['worker']['MALFORMED'], 'YES')
        self.assertEqual(result['models']['web'], 'PASS')

    def test_classification_flag_strict_and_legacy_mode_unchanged(self):
        with self.assertRaises(d.ClosedFailure):
            d.arguments(argv() + ['--classify-models'])
        result = self.result()
        self.assertEqual((result['mode'], result['outcome'], result['checkpoint']),
                         ('preflight-readonly-v1', 'READ_SUBSET_PASS', 'D_COMPLETE'))
        self.assertNotIn('models', result)

    def alignment_fixture(self):
        api_bind = self.bind_fixture()
        api_bind['bind'] = {}
        pins = {'SCAN_VULN_ENABLED': 'true', 'SCAN_VULN_RELEASE_DIR': '/opt/release',
                'SCAN_VULN_MANIFEST_DIGEST': 'sha256:' + '1' * 64,
                'SCAN_VULN_ARTIFACT_SHA256': '2' * 64}
        for role in ('api', 'worker'):
            service = self.model['services'][role]
            service['environment'].update(pins)
            record = self.records[d.ORIGINALS[role][0]]
            record['Config']['Env'] += [k + '=' + v for k, v in pins.items()]
            if role == 'api':
                record['Mounts'][-1]['Source'] = '/inert/old-release'
            else:
                for source, target in (('/inert/release', '/opt/release'), ('/inert/release/db', '/tmp/trivy/db')):
                    service['volumes'].append({'type': 'bind', 'source': source, 'target': target,
                                               'read_only': True, 'bind': {}})
                    record['Mounts'].append({'Type': 'bind', 'Source': source, 'Destination': target,
                                            'RW': False, 'Propagation': ''})
            record['HostConfig']['Mounts'] = [{'Type': 'bind', 'Source': v['Source'],
                'Target': v['Destination'], 'ReadOnly': True} for v in record['Mounts'] if v['Type'] == 'bind']
        verifier = 'server/deploy/trust/verify_preservation_release.py'
        verifier_test = 'server/deploy/trust/test_verify_preservation_release.py'
        return ['--align-api-cve-release', '--release-verifier-relative', verifier,
                '--release-verifier-test-relative', verifier_test,
                '--source-sha256', verifier + '=' + d.RELEASE_VERIFIER_PINS[verifier],
                '--source-sha256', verifier_test + '=' + d.RELEASE_VERIFIER_PINS[verifier_test]]

    def test_alignment_diagnostic_is_shape_only_no_gate_no_later_client(self):
        suffix = self.alignment_fixture()
        with patch.object(self.m.Controller, 'verify_release', side_effect=AssertionError('NO_ACTOR')), \
             patch.object(self.m.Controller, 'recheck_release', side_effect=AssertionError('NO_ACTOR')):
            result = self.diag.result(argv() + ['--classify-models-only'] + suffix)
        self.assertEqual((result['mode'], result['outcome'], result['releaseAuthentication'], result['boundary']),
                         ('model-alignment-shape-readonly-v1', 'SHAPE_ONLY_CLASSIFIED', 'NOT_PERFORMED', 'NO_ACTIVATION'))
        self.assertEqual(result['models'], dict.fromkeys(d.ROLES, 'PASS'))
        self.assertIsNone(result['firstFailure'])
        self.assertEqual(result['mounts']['api']['BIND_SOURCE_MISMATCH'], 'YES')  # Raw observation not rewritten.
        self.assertEqual(self.calls[-1], d.ReadRunner(self.repo, self.env).render)
        self.lock.assert_called_once()
        receipt = json.dumps(result)
        self.assertLessEqual(len(receipt), 4096)
        for value in (SECRET, '/inert', d.AGGREGATE, *d.PINS.values()):
            self.assertNotIn(value, receipt)
        self.assertFalse(any(a[1] in ('network', 'volume', 'info', 'ps', 'up', 'stop', 'exec', 'run', 'cp') for a in self.calls))

    def test_alignment_profile_cannot_claim_full_read_subset_or_accept_unpinned_peer(self):
        suffix = self.alignment_fixture()
        for extra in (suffix, ['--classify-models-only'] + suffix[:-2],
                      ['--classify-models-only'] + suffix + ['--source-sha256', 'server/deploy/trust/stray.py=' + 'c' * 64]):
            result = self.diag.result(argv() + extra)
            self.assertEqual((result['checkpoint'], result['outcome']), ('D_ARGUMENTS', 'REFUSED'))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.reads, [])

    def test_alignment_shape_refuses_worker_cache_drift_without_authentication_claim(self):
        suffix = self.alignment_fixture()
        self.records[d.ORIGINALS['worker'][0]]['Mounts'][-1]['Source'] = '/inert/other-db'
        result = self.diag.result(argv() + ['--classify-models-only'] + suffix)
        self.assertEqual((result['outcome'], result['releaseAuthentication']), ('REFUSED', 'NOT_PERFORMED'))
        self.assertEqual(result['models']['api'], 'FAIL')
        self.assertEqual(result['models']['worker'], 'FAIL')
        self.assertEqual(result['models']['web'], 'PASS')
        self.assertEqual(self.calls[-1], d.ReadRunner(self.repo, self.env).render)

    def test_current_production_pins_match(self):
        for relative, pin in d.PINS.items():
            self.assertEqual(hashlib.sha256((d.REPO / relative).read_bytes()).hexdigest(), pin)

    def test_strict_args_unknown_abbreviation_activation_and_binding_change(self):
        for suffix in (['--activate-existing-api'], ['--diagnose-preflight'], ['--arbitrary'],
                       ['--api-container', 'f' * 64]):
            result = self.diag.result(argv() + suffix)
            self.assertEqual(result['checkpoint'], 'D_ARGUMENTS')
            self.assertEqual(result['outcome'], 'REFUSED')
        self.assertEqual(self.calls, [])

    def test_root_refusal_and_no_python_private_open_or_host_write(self):
        with patch.object(d, 'metadata', side_effect=d.ClosedFailure('PREDICATE_REFUSED')):
            self.assertEqual(self.result()['checkpoint'], 'D_ROOT_ANCESTRY')
        self.assertEqual(self.calls, [])
        self.assertEqual(self.reads, [])
        with patch.object(d.os, 'open', side_effect=AssertionError('NO_PRIVATE_OPEN')), \
             patch.object(d.os, 'mkdir', side_effect=AssertionError('NO_LOCK_OR_BACKUP')), \
             patch.object(d.os, 'chmod', side_effect=AssertionError('NO_PERMISSION_REPAIR')), \
             patch.object(self.m, 'private_write', side_effect=AssertionError('NO_PRIVATE_WRITE')):
            self.assertEqual(self.result()['outcome'], 'READ_SUBSET_PASS')

    def test_owned_public_source_pins(self):
        for relative in (d.SELF, d.TEST):
            data = (d.REPO / relative).read_bytes()
            self.assertTrue(data and len(data) < 2 * d.MIB)
            print('OWN_PUBLIC_SOURCE_SHA256 ' + relative + ' ' + hashlib.sha256(data).hexdigest())

    def test_existing_lock_refuses_before_sources_or_subprocess(self):
        self.lock.side_effect = d.ClosedFailure('PREDICATE_REFUSED')
        self.assertEqual(self.result()['checkpoint'], 'D_LOCK_ABSENT')
        self.assertEqual(self.calls, [])
        self.assertEqual(self.reads, [])

    def test_source_drift_and_final_drift_have_fixed_slots(self):
        self.fail = lambda kind, item: kind == 'source' and item.endswith(d.CONTROLLER)
        self.assertEqual(self.result()['checkpoint'], 'D_PUBLIC_01')
        self.assertEqual(self.calls, [])
        self.fail = lambda kind, item: kind == 'source' and item.endswith(d.CONTROLLER) and self.reads.count(item) > 1
        self.reads.clear()
        self.assertEqual(self.result()['checkpoint'], 'D_PUBLIC_FINAL_01')

    def test_staged0400_admitted_0644_refused_without_permission_write(self):
        self.assertEqual(self.result()['outcome'], 'READ_SUBSET_PASS')
        self.staged_mode = 0o644
        self.assertEqual(self.result()['checkpoint'], 'D_SECRET_STAGED')

    def test_ambient_compose_even_empty_refuses_before_client(self):
        self.diag.env['COMPOSE_FILE'] = ''
        self.assertEqual(self.result()['checkpoint'], 'D_COMPOSE_AMBIENT')
        self.assertEqual(self.calls, [])

    def test_old_policy_candidate_policy_and_nonkey_environment_checkpoints(self):
        self.version = b'2.34.0-desktop.1\n'
        old = self.records[d.ORIGINALS['api'][0]]['Config']['Env']
        old.append('LLM_HISTORY_AUTHORITY=' + SECRET)
        self.assertEqual(self.result()['checkpoint'], 'D_P_API__OLD_POLICY_HISTORY_AUTHORITY')
        old.pop()
        env = self.model['services']['api']['environment']
        env['LLM_ENABLED'] = 'false'
        self.assertEqual(self.result()['checkpoint'], 'D_P_API__CANDIDATE_POLICY_FREE')
        env['LLM_ENABLED'] = 'true'
        env['INERT_UNRELATED_NONKEY'] = SECRET
        self.assertEqual(self.result()['checkpoint'], 'D_API_NONKEY_ENV')

    def test_duplicate_old_api_env_reports_model_api_before_policy(self):
        env = self.records[d.ORIGINALS['api'][0]]['Config']['Env']
        env.extend(['INERT_DUPLICATE=' + SECRET, 'INERT_DUPLICATE=second'])
        stdout = SimpleNamespace(buffer=io.BytesIO())
        with patch.object(d, 'Diagnostic', return_value=self.diag), patch.object(d.sys, 'stdout', stdout):
            self.assertEqual(d.main(argv()), 1)
        output = stdout.buffer.getvalue()
        self.assertNotIn(SECRET.encode(), output)
        self.assertEqual(json.loads(output), {'mode': 'preflight-readonly-v1',
                                             'checkpoint': 'D_P_API__API_PREP_ACTUAL_ENV__API_OLD_ENV_ENTRY_UNIQUE',
                                             'outcome': 'REFUSED', 'category': 'PREDICATE_REFUSED',
                                             'boundary': 'NO_ACTIVATION'})
        self.assertEqual(self.calls[-1], d.ReadRunner(self.repo, self.env).render)
        self.lock.assert_called_once()  # No later observation/acquisition after first refusal.

    def test_null_rendered_api_env_reports_model_api_before_policy(self):
        self.model['services']['api']['environment']['INERT_NULL'] = None
        stdout = SimpleNamespace(buffer=io.BytesIO())
        with patch.object(d, 'Diagnostic', return_value=self.diag), patch.object(d.sys, 'stdout', stdout):
            self.assertEqual(d.main(argv()), 1)
        output = stdout.buffer.getvalue()
        self.assertNotIn(SECRET.encode(), output)
        self.assertEqual(json.loads(output), {'mode': 'preflight-readonly-v1',
                                             'checkpoint': 'D_P_API__API_PREP_SERVICE_ENV__API_SERVICE_ENV_DICT_STRINGS',
                                             'outcome': 'REFUSED', 'category': 'PREDICATE_REFUSED',
                                             'boundary': 'NO_ACTIVATION'})
        self.assertEqual(self.calls[-1], d.ReadRunner(self.repo, self.env).render)
        self.lock.assert_called_once()  # No later observation/acquisition after first refusal.

    def test_candidate_default_config_mismatch_is_not_repaired(self):
        self.version = b'2.34.0-desktop.1\n'
        self.images['sha256:' + d.CANDIDATES['worker']]['Config']['User'] = '0'
        self.assertEqual(self.result()['checkpoint'], 'D_CANDIDATE_WORKER')

    def test_final_original_drift_refuses(self):
        original = self.transport
        full_inspections = 0
        def drift(*args):
            nonlocal full_inspections
            if args[0][1] == 'inspect' and '--format' not in args[0]:
                full_inspections += 1
                if full_inspections == 2:
                    self.records[d.ORIGINALS['worker'][0]]['State']['Running'] = False
            return original(*args)
        self.transport = drift
        self.assertEqual(self.result()['checkpoint'], 'D_STABLE_FINAL')

    def test_untrusted_exception_never_exported_and_no_followup(self):
        self.fail = lambda kind, item: kind == 'command' and item == ('docker', 'compose', 'version', '--short')
        result = self.result()
        self.assertEqual(result['category'], 'UNEXPECTED')
        self.assertEqual(result['checkpoint'], 'D_COMPOSE_VERSION')
        self.assertEqual(len(self.calls), 1)

    def test_main_output_closed_and_no_traceback(self):
        stdout = SimpleNamespace(buffer=io.BytesIO())
        with patch.object(d, 'Diagnostic', side_effect=RuntimeError(SECRET)), patch.object(d.sys, 'stdout', stdout):
            self.assertEqual(d.main([]), 1)
        text = stdout.buffer.getvalue()
        self.assertNotIn(SECRET.encode(), text)
        self.assertEqual(set(json.loads(text)), {'mode', 'checkpoint', 'outcome', 'category', 'boundary'})


class RunnerTests(unittest.TestCase):
    def runner(self, transport):
        return d.ReadRunner(Path('/inert'), {'DOCKER_HOST': d.SOCKET, 'DOCKER_CONTEXT': ''},
                            clock=lambda: 10, transport=transport, deadline=130)

    def test_allowlist_rejects_mutation_helper_logs_foreign_fullinspect_and_unknown_network(self):
        calls = []
        run = self.runner(lambda *args: calls.append(args))
        for args in (('docker', 'stop', d.ORIGINALS['api'][0]), ('docker', 'exec', d.ORIGINALS['api'][0], 'node'),
                     ('docker', 'logs', d.ORIGINALS['api'][0]), ('docker', 'compose', 'up'),
                     ('docker', 'inspect', '--type', 'container', 'f' * 64),
                     ('docker', 'network', 'inspect', 'f' * 64), ('sh', '-c', SECRET)):
            with self.assertRaises(d.ClosedFailure):
                run(args)
        self.assertEqual(calls, [])

    def test_decode_cap_timeout_nonzero_categories_without_private_output(self):
        for data, category in ((b'{"a":1,"a":2}', 'DECODE_REFUSED'),
                               (SECRET.encode() * 400, 'OUTPUT_CAP')):
            run = self.runner(lambda *args: data)
            with self.assertRaises(d.ClosedFailure) as caught:
                run(('docker', 'info', '--format', '{{json .ID}}'), cap=4096)
            self.assertEqual(caught.exception.category, category)
            self.assertNotIn(SECRET, str(caught.exception))
        for category in ('CLIENT_NONZERO', 'CLIENT_TIMEOUT'):
            def refused(*args):
                raise d.ClosedFailure(category)
            with self.assertRaises(d.ClosedFailure) as caught:
                self.runner(refused)(('docker', 'compose', 'version', '--short'), cap=4096)
            self.assertEqual(caught.exception.category, category)
        run = self.runner(lambda *args: self.fail('Must not spawn'))
        run.deadline = 10
        with self.assertRaises(d.ClosedFailure) as caught:
            run(('docker', 'compose', 'version', '--short'), cap=4096)
        self.assertEqual(caught.exception.category, 'CLIENT_TIMEOUT')

    def test_foreign_mount_projection_requires_validated_enumeration_no_env(self):
        foreign = 'f' * 64
        calls = []
        def transport(args, *rest):
            calls.append(args)
            if args[1] == 'ps':
                return (foreign + '\n').encode()
            return b'{"id":"' + foreign.encode() + b'","running":true,"mounts":[]}\n'
        run = self.runner(transport)
        projection = ('docker', 'inspect', '--type', 'container', '--format', d.MOUNT_FORMAT, foreign)
        with self.assertRaises(d.ClosedFailure):
            run(projection)
        run(('docker', 'ps', '-a', '--no-trunc', '--format', '{{.ID}}'), cap=d.MIB)
        run(projection)
        self.assertTrue(all('Env' not in str(a) for a in calls))

    def test_transport_both_stream_cap_nonzero_timeout_and_reap_mocked(self):
        class Pipe:
            def __init__(self, fd):
                self.fd, self.closed = fd, False
            def fileno(self):
                return self.fd
            def close(self):
                self.closed = True
        class Streams:
            def __init__(self):
                self.entries = {}
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def register(self, pipe, event, data):
                self.entries[pipe.fd] = SimpleNamespace(fileobj=pipe, data=data)
            def unregister(self, pipe):
                del self.entries[pipe.fd]
            def get_map(self):
                return self.entries
            def select(self, timeout):
                return [(e, selectors.EVENT_READ) for e in list(self.entries.values())]
        for scenario in ('stderr_cap', 'nonzero', 'wait_timeout', 'success'):
            with self.subTest(scenario=scenario):
                stdout, stderr = Pipe(10), Pipe(11)
                proc = SimpleNamespace(stdout=stdout, stderr=stderr, pid=12345)
                def wait(timeout):
                    if scenario == 'wait_timeout' and timeout != 5:
                        raise subprocess.TimeoutExpired('INERT', timeout, stderr=SECRET)
                    return 1 if scenario == 'nonzero' else 0
                proc.wait = unittest.mock.Mock(side_effect=wait)
                outputs = {10: [b'{}', b''], 11: [SECRET.encode() if scenario == 'stderr_cap' else b'', b'']}
                with patch.object(d.selectors, 'DefaultSelector', Streams), \
                     patch.object(d.os, 'set_blocking'), patch.object(d.os, 'read', side_effect=lambda fd, n: outputs[fd].pop(0)), \
                     patch.object(d.os, 'killpg') as kill:
                    if scenario == 'success':
                        self.assertEqual(d.capture(('INERT',), Path('/inert'), {}, 15, 4,
                                                   clock=lambda: 10, spawn=lambda *a, **k: proc), b'{}')
                        kill.assert_not_called()
                    else:
                        with self.assertRaises(d.ClosedFailure) as caught:
                            d.capture(('INERT',), Path('/inert'), {}, 15, 4,
                                      clock=lambda: 10, spawn=lambda *a, **k: proc)
                        self.assertEqual(caught.exception.category, {'stderr_cap': 'OUTPUT_CAP',
                                         'nonzero': 'CLIENT_NONZERO', 'wait_timeout': 'CLIENT_TIMEOUT'}[scenario])
                        kill.assert_called_once()
                        self.assertEqual(proc.wait.call_args.kwargs['timeout'], 5)
                self.assertTrue(stdout.closed and stderr.closed)


if __name__ == '__main__':
    unittest.main()
