#!/usr/bin/env python3
"""Focused INERT tests: public pinned definitions, synthetic metadata/read outputs.
No Engine child, private host metadata/configuration, environment file or DB read.
"""
from contextlib import ExitStack
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location('held_diagnostic_test_subject', HERE / 'diagnose_held_preflight.py')
d = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = d
spec.loader.exec_module(d)
CANARY = 'PRIVATE_CANARY_MUST_NOT_ESCAPE'


def captured_public():
    result = {}
    for relative, pin in d.PINS.items():
        data = (d.REPO / relative).read_bytes()  # Public source only; tests are not executed.
        if hashlib.sha256(data).hexdigest() != pin:
            raise AssertionError('PUBLIC_SOURCE_PIN_CHANGED')
        if relative == d.CONTROLLER:
            result[relative] = data
    return result


def namespace_stat(mode, *, owner=None, nlink=1, size=1, ino=1):
    return types.SimpleNamespace(st_dev=1, st_ino=ino, st_mode=mode, st_nlink=nlink,
        st_uid=os.geteuid() if owner is None else owner, st_gid=1, st_size=size,
        st_mtime_ns=1, st_ctime_ns=1)


class MetadataTests(unittest.TestCase):
    def classify(self, st, kind='hold', second=None):
        path = Path('/synthetic/root/marker')
        safe_dir = namespace_stat(stat.S_IFDIR | 0o755)
        with patch.object(Path, 'lstat', return_value=safe_dir), \
             patch.object(d, 'directories') as chain, patch.object(d.os, 'stat', side_effect=[st, second or st]):
            chain.return_value.__enter__.return_value = 9
            with patch.object(d.os, 'open', side_effect=AssertionError('NO_FILE_OPEN')), \
                 patch.object(d.os, 'read', side_effect=AssertionError('NO_CONTENT')):
                return d.classify_metadata(path, kind, lambda: None)

    def test_closed_metadata_classes(self):
        cases = [
            (namespace_stat(stat.S_IFREG | 0o600), 'hold', 'PRESENT_SAFE'),
            (namespace_stat(stat.S_IFLNK | 0o777), 'hold', 'SYMLINK'),
            (namespace_stat(stat.S_IFDIR | 0o600), 'hold', 'WRONG_TYPE'),
            (namespace_stat(stat.S_IFREG | 0o600, owner=os.geteuid() + 1), 'hold', 'WRONG_OWNER'),
            (namespace_stat(stat.S_IFREG | 0o644), 'hold', 'WRONG_MODE'),
            (namespace_stat(stat.S_IFREG | 0o600, nlink=2), 'hold', 'MULTILINK'),
            (namespace_stat(stat.S_IFREG | 0o600, size=8193), 'hold', 'SIZE_REFUSED'),
            (namespace_stat(stat.S_IFDIR | 0o755), 'root', 'PRESENT_SAFE'),
            (namespace_stat(stat.S_IFDIR | 0o755), 'lock', 'WRONG_MODE'),
            (namespace_stat(stat.S_IFDIR | 0o700), 'lock', 'PRESENT_SAFE'),
        ]
        for st, kind, expected in cases:
            with self.subTest(expected=expected, kind=kind):
                self.assertEqual(self.classify(st, kind), expected)

    def test_missing_and_changed(self):
        with patch.object(Path, 'lstat', side_effect=FileNotFoundError(CANARY)):
            self.assertEqual(d.classify_metadata(Path('/synthetic/marker'), 'hold', lambda: None), 'MISSING')
        st = namespace_stat(stat.S_IFREG | 0o600)
        other = namespace_stat(stat.S_IFREG | 0o600, ino=2)
        self.assertEqual(self.classify(st, second=other), 'CHANGED')

    def test_unsafe_parent_not_followed(self):
        st = namespace_stat(stat.S_IFLNK | 0o777)
        with patch.object(Path, 'lstat', return_value=st), patch.object(d.os, 'open') as opening:
            self.assertEqual(d.classify_metadata(Path('/synthetic/marker'), 'hold', lambda: None), 'UNSAFE_ANCESTRY')
            opening.assert_not_called()

    def test_exact_five_paths_and_no_unsafe_child(self):
        obs = d.Observation()
        answers = iter(('PRESENT_SAFE', 'PRESENT_SAFE', 'PRESENT_SAFE', 'MISSING'))
        with patch.object(d, 'classify_metadata', side_effect=lambda *a: next(answers)) as classifier:
            paths = d.coordination_metadata(d.REPO, obs)
        self.assertEqual(classifier.call_count, 4)
        self.assertEqual(obs.metadata['RECONCILE_HOLD'], 'PARENT_NOT_SAFE')
        self.assertEqual(len(paths), 5)
        self.assertEqual(paths[2].name, 'KEY_ACTIVATION_HOLD.json')


class ObservationTests(unittest.TestCase):
    def test_sticky_deepest_failure_and_closed_privacy(self):
        obs = d.Observation()
        with self.assertRaises(d.Refused):
            with obs.stage('CONTROLLER_ENTRY'):
                with obs.stage('RETAINED_CREATED'):
                    raise d.Refused('CLIENT_EXEC_DENIED')
        obs.fail('COMPLETE', RuntimeError(CANARY))
        self.assertEqual(obs.first, ('RETAINED_CREATED', 'CLIENT_EXEC_DENIED'))
        raw = json.dumps(obs.receipt(False))
        self.assertNotIn(CANARY, raw)
        self.assertLess(len(raw), 4096)

    def test_deadline_is_shared_and_no_private_directory_stage(self):
        now = [0.0]
        obs = d.Observation(lambda: now[0])
        now[0] = 90
        with self.assertRaises(d.Refused):
            with obs.stage('SOURCE_PINS'):
                self.fail('deadline bypassed')
        self.assertEqual(obs.first, ('SOURCE_PINS', 'CLIENT_TIMEOUT'))
        self.assertNotIn('PRIVATE_DIRECTORY', d.CAPTURE_STAGES | d.OWN_STAGES)
        with self.assertRaises(d.Refused):
            d.Observation()('PRIVATE_DIRECTORY', 'ENTER')

    def test_unexpected_exception_text_not_exported(self):
        obs = d.Observation()
        with self.assertRaises(KeyboardInterrupt):
            with obs.stage('SELECTOR'):
                raise KeyboardInterrupt(CANARY)
        self.assertEqual(obs.first, ('SELECTOR', 'UNEXPECTED'))
        self.assertNotIn(CANARY, json.dumps(obs.receipt(False)))


class RunnerUnitTests(unittest.TestCase):
    def runner(self, clock=lambda: 1):
        bindings = {str(i): types.SimpleNamespace(container=str(i) * 64, image='sha256:' + str(i) * 64)
                    for i in range(1, 6)}
        plan = types.SimpleNamespace(bindings=bindings, replaced_roles=('api', 'worker', 'web'),
            selected_image=lambda role: 'sha256:' + {'api': '6', 'worker': '7', 'web': '8'}[role] * 64)
        module = types.SimpleNamespace(RETAINED_FORMAT='FIXED_PUBLIC_PROJECTION', RETAINED_CREATED_ID='9' * 64)
        return d.ReadRunner(d.REPO, {'DOCKER_HOST': d.SOCKET, 'DOCKER_CONTEXT': ''}, module, plan,
                            d.Observation(clock))

    def test_allowlist_consumes_failure_and_never_retries(self):
        runner = self.runner()
        self.assertEqual(len(runner.allowed), 12)
        with patch.object(d, 'verify_executable'), patch.object(d, 'capture', side_effect=d.Refused('CLIENT_NONZERO')) as transport:
            command = ('docker', 'compose', 'version', '--short')
            with self.assertRaises(d.Refused):
                runner(command, cap=4096)
            with self.assertRaises(d.Refused) as caught:
                runner(command, cap=4096)
            self.assertEqual(caught.exception.category, 'COMMAND_REFUSED')
            self.assertEqual(transport.call_count, 1)

    def test_only_fixed_reads_and_no_stdin(self):
        runner = self.runner()
        forbidden = [('docker', 'create'), ('docker', 'stop', '1' * 64),
                     ('docker', 'exec', '9' * 64, 'node'), ('docker', 'logs', '9' * 64),
                     ('docker', 'inspect', '--type', 'container', '0' * 64),
                     ('docker', 'compose', 'config'), ('docker', 'info')]
        with patch.object(d, 'capture') as transport:
            for command in forbidden:
                with self.subTest(command=command), self.assertRaises(d.Refused):
                    runner(command)
            with self.assertRaises(d.Refused):
                runner(('docker', 'compose', 'version', '--short'), cap=4096, input_data=b'X')
            transport.assert_not_called()

    def test_source_gate_failure_never_imports_or_observes_private_paths(self):
        with patch.object(d, 'verified_sources', side_effect=d.Refused()), \
             patch.object(d, 'load_controller') as load, patch.object(d, 'coordination_metadata') as metadata:
            receipt, status = d.run([], env={})
        self.assertEqual(status, 1)
        self.assertFalse(receipt['ok'])
        self.assertEqual(set(receipt['coordinationMetadata'].values()), {'NOT_OBSERVED'})
        load.assert_not_called()
        metadata.assert_not_called()


class PinnedIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.captured = captured_public()
        cls.m = d.load_controller(d.REPO, cls.captured)

    def test_plan_matches_incident_and_has_no_ownership(self):
        plan = d.incident_plan(self.m)
        self.assertEqual(plan.sources, d.PINS)
        self.assertTrue(plan.reconcile_stopped_stand and plan.darwin_host_mnt_helper)
        self.assertTrue(plan.align_api_cve_release and plan.preservation_migration)
        self.assertIsNone(plan.store_versions)
        self.assertFalse(plan.prepare_rollout_only or plan.qualify_release_only)

    def runner(self):
        return d.ReadRunner(d.REPO, {'DOCKER_HOST': d.SOCKET, 'DOCKER_CONTEXT': ''}, self.m,
                            d.incident_plan(self.m), d.Observation())

    def test_exact_twelve_allowlist_and_mutations_rejected(self):
        runner = self.runner()
        self.assertEqual(len(runner.allowed), 12)
        for args in [('docker', 'create'), ('docker', 'start', self.m.RETAINED_CREATED_ID),
                     ('docker', 'exec', 'id', 'node'), ('docker', 'logs', 'id'),
                     ('docker', 'info'), ('docker', 'ps'), ('docker', 'volume', 'inspect', 'x'),
                     ('docker', 'inspect', '--type', 'container', '0' * 64)]:
            with self.subTest(args=args), self.assertRaises(d.Refused):
                runner(args)
        with patch.object(d, 'capture') as capture, patch.object(d, 'verify_executable') as exe:
            capture.return_value = b'2.34.0-desktop.1\n'
            command = ('docker', 'compose', 'version', '--short')
            self.assertEqual(runner(command, cap=4096), capture.return_value)
            launched = capture.call_args.args
            self.assertEqual(launched[0][:3], (str(d.DOCKER), '--host', d.SOCKET))
            self.assertLessEqual(launched[3] - runner.obs.clock(), 15)
            self.assertEqual(exe.call_count, 1)
            with self.assertRaises(d.Refused):
                runner(command, cap=4096)
            self.assertEqual(capture.call_count, 1)

    def test_factory_real_load_only_and_capture_returns_before_private_directory(self):
        m, obs = self.m, d.Observation()
        root = d.REPO / '.local-auth'
        paths = (root, root / '.trivy-refresh.lock', root / '.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json',
                 root / '.key-preservation-reconcile.lock', root / '.key-preservation-reconcile.lock/KEY_ACTIVATION_HOLD.json')
        metadata = (1, 2, stat.S_IFDIR | 0o700, os.geteuid(), 1, 1, 1)
        file_metadata = (1, 3, stat.S_IFREG | 0o600, os.geteuid(), 1, 1, 1)
        original_metadata = m.path_metadata
        def private_metadata(path, **kw):
            path = Path(path)
            if path == root or root in path.parents or path.name in ('.env.local', '.env.openrouter.local'):
                return metadata if kw.get('directory') else file_metadata
            return original_metadata(path, **kw)
        def classify(repo, observation):
            observation.metadata = dict.fromkeys(d.PATH_IDS, 'PRESENT_SAFE')
            return paths
        def image(identity):
            return {'Id': identity, 'Os': 'linux', 'Architecture': 'arm64',
                    'Config': {'Env': ['PUBLIC_FIXTURE=fixture'], 'Labels': {}, 'Volumes': None, 'OnBuild': None}}
        def old(role, binding):
            running = role in ('egress', 'llm-egress')
            return {'Id': binding.container, 'Image': binding.image, 'Name': '/' + d.PROJECT + '-' + role + '-1',
                'State': {'Running': running, 'Status': 'running' if running else 'exited'},
                'Config': {'Labels': {'com.docker.compose.project': d.PROJECT, 'com.docker.compose.service': role},
                           'Env': ['PRIVATE_FIXTURE=' + CANARY]},
                'HostConfig': {'RestartPolicy': {'Name': 'no'}}}
        plan = d.incident_plan(m)
        selected_command = ('docker', 'compose', '--env-file', str(root / 'stand.env'))
        for relative in d.FILES:
            selected_command += ('-f', str(d.REPO / relative))
        selected = types.SimpleNamespace(profile='nginx-local', llm='openrouter-free', files=d.FILES,
                                         command=selected_command)
        calls, gates = [], []
        original_factory = m.load_release_gate
        def real_factory(*args, **kw):
            gate = original_factory(*args, **kw)  # Actual pinned verifier, source hashes ONLY.
            gate.verify = unittest.mock.Mock(side_effect=AssertionError('NO_VERIFY'))
            gate.recheck = unittest.mock.Mock(side_effect=AssertionError('NO_RECHECK'))
            gates.append(gate)
            return gate
        def transport(argv, repo, env, until, cap, **kw):
            calls.append(argv)
            args = argv[3:]
            if args == ('compose', 'version', '--short'):
                return b'2.34.0-desktop.1\n'
            if args[:2] == ('image', 'inspect'):
                result = [image(args[2])]
            elif args[:4] == ('inspect', '--type', 'container', '--format'):
                result = dict(id=m.RETAINED_CREATED_ID, image=plan.bindings['api'].image,
                    configImage=plan.bindings['api'].image, status='created', running=False, paused=False,
                    restarting=False, oom=False, dead=False, exit=0, restarts=0,
                    started='0001-01-01T00:00:00Z', finished='0001-01-01T00:00:00Z',
                    entry=['node'], cmd=['-e', m.HOLDER_CODE], args=['-e', m.HOLDER_CODE], path='node',
                    name='/dip-key-snapshot-' + 'a' * 32, labels={'dip.key-preservation': 'key-preservation-aaaaaaaa'})
            elif args[:3] == ('inspect', '--type', 'container'):
                result = [old(r, b) for r, b in plan.bindings.items()]
            elif args[-3:] == ('config', '--format', 'json'):
                result = {'name': d.PROJECT, 'services': dict.fromkeys((*m.ROLES, 'auth-volume-init', 'scan-volume-init'), {})}
            else:
                raise AssertionError('UNEXPECTED_CLIENT')
            return json.dumps(result).encode()
        forbidden = ('preflight', 'coordination', 'activate', 'qualify_release')
        with patch.object(d, 'load_controller', return_value=m), \
             patch.object(d, 'coordination_metadata', side_effect=classify), \
             patch.object(m, 'path_metadata', side_effect=private_metadata), \
             patch.object(m, 'select', return_value=selected), \
             patch.object(m, 'load_release_gate', side_effect=real_factory), \
             patch.object(d, 'verify_executable'), patch.object(d, 'capture', side_effect=transport):
            with ExitStack() as stack:
                for name in forbidden:
                    stack.enter_context(patch.object(m.Controller, name, side_effect=AssertionError('NO_MUTATION')))
                d.diagnose(d.REPO, {'DOCKER_HOST': d.SOCKET, 'DOCKER_CONTEXT': ''}, self.captured, obs)
        self.assertEqual(len(calls), 12)
        self.assertEqual(set(calls), {(str(d.DOCKER), '--host', d.SOCKET, *args[1:])
                                     for args in self.runner().allowed})
        self.assertEqual(len(gates), 1)
        gates[0].verify.assert_not_called()
        gates[0].recheck.assert_not_called()
        self.assertIsNone(gates[0].retained)
        self.assertIsNone(gates[0]._gate._sealed)
        self.assertIsNone(gates[0]._gate.id)
        self.assertNotIn(CANARY, json.dumps(obs.receipt(True)))

    def test_frozen_factory_stages_are_sticky_without_actor_invocation(self):
        m = self.m
        for failing_gate in ('GATE_ROOT_METADATA', 'GATE_SOURCE_PINS'):
            with self.subTest(gate=failing_gate):
                runner = self.runner()
                obs = runner.obs
                obs.module = m
                self.assertIs(runner.observation, obs)
                root_failure = m.Refusal() if failing_gate == 'GATE_ROOT_METADATA' else None
                with patch.object(m, 'path_metadata', side_effect=root_failure, return_value=(1,)), \
                     patch.object(m, 'public_source_bytes', side_effect=m.Refusal()), \
                     patch.object(d, 'capture') as transport:
                    with self.assertRaises(m.Refusal):
                        with obs.stage('RELEASE_FACTORY_LOAD'):
                            m.load_release_gate(d.REPO, d.incident_plan(m), runner,
                                                deadline=obs.deadline, attempt_id='a' * 32)
                self.assertEqual(obs.first, (failing_gate, 'PREDICATE_REFUSED'))
                transport.assert_not_called()

    def test_source_gate_stops_before_import(self):
        obs = d.Observation()
        with patch.object(d, 'verified_sources', side_effect=d.Refused()), patch.object(d, 'load_controller') as load:
            receipt, status = d.run([], env={})
        self.assertEqual(status, 1)
        self.assertFalse(receipt['ok'])
        load.assert_not_called()
        with self.assertRaises(d.Refused):
            d.load_controller(d.REPO, {d.CONTROLLER: b'raise RuntimeError("' + CANARY.encode() + b'")'})


class PreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.captured = captured_public()
        cls.m = d.load_controller(d.REPO, cls.captured)

    def observer(self, guard=lambda: None):
        return d.preparation_observer(self.m, d.Observation(preparation=True), guard)

    def test_real_preparation_observer_deadline_and_first_recheck_substage(self):
        bootstrap = d.Observation(preparation=True)
        obs = d.preparation_observer(self.m, bootstrap, lambda: None)
        self.assertIsInstance(obs, self.m.PreparationObservation)
        self.assertEqual(obs.deadline, bootstrap.deadline)
        with self.assertRaises(self.m.PinnedReleaseRefusal):
            with self.m.observed_stage(obs, 'FIRST_RELEASE_RECHECK'):
                raise self.m.PinnedReleaseRefusal(fixed_stage='INVENTORY_EQUALITY')
        obs.fail('COMPLETE', RuntimeError(CANARY))
        self.assertEqual(obs.first, ('FIRST_RELEASE_RECHECK__INVENTORY_EQUALITY', 'PREDICATE_REFUSED'))

    def test_preparation_cannot_enter_coordination_or_migration_stage(self):
        for gate in ('LOCK_ENTER', 'MIGRATION', 'RECONCILIATION_LOCK_CREATE'):
            obs = self.observer()
            with self.subTest(gate=gate), self.assertRaises(self.m.StageObserverRefusal):
                obs(gate, 'ENTER')

    def test_preparation_bootstrap_refusal_is_not_labeled_readonly(self):
        with patch.object(d, 'verified_sources', side_effect=d.Refused()), patch.object(d, 'prepare_held') as prepare:
            receipt, status = d.run(['--prepare-held-preflight'], env={})
        self.assertEqual(status, 1)
        self.assertTrue(receipt['preparationOnly'])
        self.assertFalse(receipt['readOnly'] or receipt['capturePrefixOnly'])
        prepare.assert_not_called()

    def test_existing_pair_change_is_detected_without_content_read(self):
        m = self.m
        root = Path('/synthetic/root')
        paths = (root, root / 'prior', root / 'prior/HOLD', root / 'reconcile', root / 'reconcile/HOLD')
        st = namespace_stat(stat.S_IFDIR | 0o700)
        file_st = namespace_stat(stat.S_IFREG | 0o600)
        def lstat(path):
            return file_st if path.name == 'HOLD' else st
        with patch.object(m, 'path_metadata', return_value=(1, 1, st.st_mode, os.geteuid())), \
             patch.object(Path, 'lstat', autospec=True, side_effect=lstat), patch.object(d.os, 'read') as read:
            guard = d.HeldMetadataGuard(m, paths)
            guard()
            file_st.st_ctime_ns += 1
            with self.assertRaises(d.Refused):
                guard()
            self.assertTrue(guard.changed)
            read.assert_not_called()

    def actor_runner(self):
        m, obs = self.m, self.observer()
        runner = d.PrepareRunner(d.REPO, {'DOCKER_HOST': d.SOCKET, 'DOCKER_CONTEXT': ''}, m,
                                 d.incident_plan(m), obs, lambda: None)
        actual_meta = m.path_metadata
        def public_or_mock(path, **kw):
            if Path(path) == d.REPO / '.local-auth':
                return (1, 1, stat.S_IFDIR | 0o755, os.geteuid(), 1, 1, 1)
            return actual_meta(path, **kw)
        with patch.object(m, 'path_metadata', side_effect=public_or_mock):
            gate = m.load_release_gate(d.REPO, runner.plan, runner, deadline=obs.deadline, attempt_id='a' * 32)
        runner.bind_gate(gate)
        return runner

    def test_actor_exact_command_binding_rejects_edits_and_unqualified_start(self):
        runner = self.actor_runner()
        actor = runner.actor
        request = {'source': '/synthetic/release', 'manifest': 'sha256:' + 'b' * 64, 'artifact': 'c' * 64}
        command = actor._command(request, {'files': {'bundle.bin': {'sha256': 'c' * 64}}})
        self.assertEqual(runner.intent, command)
        self.assertIn('--no-healthcheck', command)
        self.assertIn('--read-only', command)
        runner.scratch = Path('/synthetic/scratch')
        with patch.object(runner, 'private_record') as record:
            self.assertEqual(runner.actor_command(command), (4096, 1, 'create'))
            record.assert_called_once()
            with self.assertRaises(d.Refused):
                runner.actor_command(command)
        changed = list(command)
        changed[changed.index('none')] = 'host'
        runner.controller = types.SimpleNamespace(old={}, networks={}, compiled=runner.scratch / 'compiled.json')
        with patch.object(d, 'capture') as transport:
            with self.assertRaises(d.Refused):
                runner(tuple(changed), cap=4096)
            transport.assert_not_called()
        runner.actor_id = actor.id = 'd' * 64
        with self.assertRaises(d.Refused):
            runner.actor_command(('docker', 'start', '--attach', actor.id))
        with self.assertRaises(d.Refused):
            runner.actor_command(('docker', 'rm', actor.id))
        self.assertIsNone(runner.actor_command(('docker', 'start', 'e' * 64)))

    def test_actor_start90_read15_and_no_store_holder_or_sql_commands(self):
        runner = self.actor_runner()
        runner.actor_id = runner.actor.id = 'd' * 64
        runner.checked_state = (runner.actor_id, 'created')
        runner.controller = types.SimpleNamespace(old={}, networks={}, compiled=None)
        with patch.object(d, 'verify_executable'), patch.object(d, 'capture', return_value=b'{}') as transport:
            runner(('docker', 'start', '--attach', runner.actor_id), timeout=120, cap=16384)
            self.assertLessEqual(transport.call_args.args[3] - runner.obs.clock(), 90)
            runner(('docker', 'info', '--format', '{{json .MemTotal}}'), timeout=120, cap=4096)
            self.assertLessEqual(transport.call_args.args[3] - runner.obs.clock(), 15)
            for command in (('docker', 'exec', '-i', runner.actor_id, 'node', 'apply-migration'),
                            ('docker', 'create', '--name', 'store-holder'),
                            ('docker', 'stop', '--time', '15', 'e' * 64),
                            ('docker', 'logs', runner.actor_id), ('docker', 'compose', 'up')):
                with self.subTest(command=command), self.assertRaises((d.Refused, self.m.StageObserverRefusal)):
                    runner(command)
            self.assertEqual(transport.call_count, 2)

    def test_first_client_failure_survives_only_exact_actor_failure_stop(self):
        runner = self.actor_runner()
        runner.actor_id = runner.actor.id = 'd' * 64
        runner.checked_state = (runner.actor_id, 'created')
        with patch.object(d, 'verify_executable'), patch.object(d, 'capture', side_effect=d.Refused('CLIENT_NONZERO')):
            with self.assertRaises(d.Refused):
                with self.m.observed_stage(runner.obs, 'RELEASE_VERIFY'):
                    runner(('docker', 'start', '--attach', runner.actor_id), cap=16384)
        self.assertEqual(runner.obs.first, ('RELEASE_VERIFY', 'CLIENT_NONZERO'))
        runner.actor._failed = True
        runner.checked_state = (runner.actor_id, 'running')
        with patch.object(d, 'verify_executable'), patch.object(d, 'capture', return_value=runner.actor_id.encode()) as transport:
            runner(('docker', 'stop', '--time', '1', runner.actor_id), cap=16384)
            with self.assertRaises(self.m.StageObserverRefusal):
                runner(('docker', 'start', '--attach', runner.actor_id), cap=16384)
            self.assertEqual(transport.call_count, 1)
        self.assertEqual(runner.obs.first, ('RELEASE_VERIFY', 'CLIENT_NONZERO'))

    def test_retention_without_owned_scratch_refuses_without_private_write(self):
        runner = self.actor_runner()
        runner.actor._may_exist = True
        with patch.object(self.m, 'private_write') as write:
            with self.assertRaises(d.Refused):
                runner.retain_failure()
            write.assert_not_called()

    def test_retention_uses_only_owned_scratch_and_never_controller_lock_method(self):
        runner = self.actor_runner()
        actor = runner.actor
        actor._may_exist, actor.id = True, 'd' * 64
        with patch.object(runner, 'private_record') as record, \
             patch.object(self.m.Controller, 'retain_release_failure', side_effect=AssertionError('NO_LOCK')):
            runner.retain_failure()
        self.assertEqual(record.call_args.args, ('release-verifier-retained.json',
                         {'name': actor.name, 'id': actor.id}))
        self.assertTrue(runner.retained_recorded)

    def test_full_authoritative_suffix_controlflow_and_recheck_stop_boundary(self):
        # Real preflight control flow; synthetic model/actor predicates only. No
        # cryptographic/native/production qualification is claimed by this test.
        m, bootstrap = self.m, d.Observation(preparation=True)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / '.local-auth'
            root.mkdir(mode=0o700)
            for name in ('.trivy-refresh.lock', '.key-preservation-reconcile.lock'):
                (root / name).mkdir(mode=0o700)
                hold = root / name / 'KEY_ACTIVATION_HOLD.json'
                hold.write_bytes(b'SYNTHETIC')
                hold.chmod(0o600)
            paths = (root, root / '.trivy-refresh.lock', root / '.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json',
                     root / '.key-preservation-reconcile.lock', root / '.key-preservation-reconcile.lock/KEY_ACTIVATION_HOLD.json')
            before = [d.stamp(p.lstat()) for p in paths[1:]]
            plan = d.incident_plan(m)
            net = 'e' * 64
            network = {'Id': net, 'Name': 'synthetic_network', 'Internal': True, 'Containers': {}}
            model = {'name': d.PROJECT, 'services': {r: {'image': plan.bindings[r].image} for r in m.ROLES},
                     'networks': {'synthetic': {'name': 'synthetic_network', 'internal': True}}}
            old = {r: {'Id': b.container, 'Image': b.image, 'Name': '/' + d.PROJECT + '-' + r + '-1',
                'Path': 'synthetic', 'Args': [], 'Mounts': [],
                'State': {'Running': r in ('egress', 'llm-egress')},
                'Config': {'Labels': {'com.docker.compose.project': d.PROJECT, 'com.docker.compose.service': r}},
                'HostConfig': {'Mounts': [], 'RestartPolicy': {'Name': 'no'}},
                'NetworkSettings': {'Networks': {'synthetic': {'NetworkID': net}}}}
                for r, b in plan.bindings.items()}
            selected = types.SimpleNamespace(files=d.FILES)
            actual_controller, actual_metadata, actual_factory = m.Controller, m.path_metadata, m.load_release_gate
            gates, controllers, calls = [], [], []
            def metadata(path, **kw):
                path = Path(path)
                if path == d.REPO / '.local-auth':
                    return (1, 1, stat.S_IFDIR | 0o755, os.geteuid(), 1, 1, 1)
                if Path(temporary) == path or Path(temporary) in path.parents:
                    st = path.lstat()
                    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_nlink, st.st_size, st.st_mtime_ns)
                return actual_metadata(path, **kw)
            class SyntheticController(actual_controller):
                def __init__(self, *args, **kw):
                    super().__init__(*args, **kw)
                    self.root = root
                    controllers.append(self)
                def capture_preflight_model(self):
                    self.old, self.selected = copy.deepcopy(old), selected
                    return copy.deepcopy(model)
                def original_model_matches(self, *args, **kw):
                    pass
                def release_verification_request(self, model):
                    return {'verifier_sources': {p: d.PINS[p] for p in (d.VERIFIER, d.VERIFIER_TEST)}}
                def compatibility_input(self):
                    return b'SYNTHETIC'
                def secrets_metadata(self):
                    pass
                def capacity(self, before_stops=False):
                    with self.stage('HOST_CAPACITY'):
                        self.assert_unused = before_stops
                def writers(self, permitted):
                    if permitted:
                        raise AssertionError('STOPPED_PROFILE_REQUIRED')
            def factory(*args, **kw):
                gate = actual_factory(*args, **kw)
                gate.verify = unittest.mock.Mock(return_value=b'x' * 32)
                gate.recheck = unittest.mock.Mock(return_value=None)
                gates.append(gate)
                return gate
            def coordinates(repo, obs):
                obs.metadata = dict.fromkeys(d.PATH_IDS, 'PRESENT_SAFE')
                return paths
            def transport(argv, repo, env, until, cap, **kw):
                args = argv[3:]
                calls.append(args)
                if args[:3] == ('network', 'inspect', net):
                    result = [network]
                elif args[:2] == ('volume', 'inspect'):
                    result = [{'Name': name, 'Driver': 'local', 'Scope': 'local', 'Options': None,
                               'Labels': {'com.docker.compose.project': d.PROJECT}, 'Mountpoint': '/synthetic/' + key}
                              for key, name in m.VOLUMES.items()]
                elif args[:3] == ('inspect', '--type', 'container'):
                    result = list(old.values())
                elif args[-2:] == ('config', '--quiet'):
                    return b''
                elif args[-3:] == ('config', '--format', 'json'):
                    result = json.loads(controllers[0].compiled.read_bytes())
                else:
                    raise AssertionError('UNREVIEWED_SYNTHETIC_COMMAND')
                return json.dumps(result).encode()
            with patch.object(d, 'load_controller', return_value=m), \
                 patch.object(d, 'coordination_metadata', side_effect=coordinates), \
                 patch.object(m, 'Controller', SyntheticController), patch.object(m, 'path_metadata', side_effect=metadata), \
                 patch.object(m, 'load_release_gate', side_effect=factory), patch.object(m, 'select', return_value=selected), \
                 patch.object(d, 'verify_executable'), patch.object(d, 'capture', side_effect=transport), ExitStack() as stack:
                for name in ('activate', 'coordination', 'operate', 'operate_migration', 'retain_release_failure', 'hold'):
                    stack.enter_context(patch.object(SyntheticController, name, side_effect=AssertionError('NO_ROLLOUT')))
                receipt, status = d.prepare_held(d.REPO, {'DOCKER_HOST': d.SOCKET, 'DOCKER_CONTEXT': ''}, self.captured, bootstrap)
            self.assertEqual((status, receipt['code']), (0, 'HELD_PREPARATION_PASS'), receipt)
            self.assertTrue(receipt['preparationOnly'] and receipt['heldMetadataUnchanged'])
            self.assertFalse(receipt['readOnly'] or receipt['migrationApplied'] or receipt['standServicesRecreated'])
            gates[0].verify.assert_called_once()
            gates[0].recheck.assert_called_once()
            self.assertEqual([d.stamp(p.lstat()) for p in paths[1:]], before)
            self.assertTrue((controllers[0].backup / 'compiled.json').is_file())
            self.assertTrue((controllers[0].backup / 'release-alignment.json').is_file())
            self.assertIsNone(controllers[0].helper_id)
            self.assertLess(len(json.dumps(receipt)), 4096)
            self.assertNotIn(CANARY, json.dumps(receipt))


class TransportTests(unittest.TestCase):
    def test_start_errors_closed(self):
        for exc, category in ((FileNotFoundError(CANARY), 'CLIENT_EXEC_NOT_FOUND'),
                              (PermissionError(CANARY), 'CLIENT_EXEC_DENIED'),
                              (OSError(CANARY), 'CLIENT_EXEC_OS_REFUSED')):
            with self.subTest(category=category), patch.object(d.subprocess, 'Popen', side_effect=exc):
                with self.assertRaises(d.Refused) as caught:
                    d.capture(('NEVER_EXECUTE',), Path('/'), {}, 1, 1)
                self.assertEqual(caught.exception.category, category)
                self.assertNotIn(CANARY, str(caught.exception))

    def test_timeout_no_negative_wait_and_cleanup_does_not_replace_first(self):
        process = unittest.mock.Mock(pid=999999)
        process.wait.side_effect = RuntimeError(CANARY)
        selector = unittest.mock.MagicMock()
        selector.get_map.return_value = {1: True}
        with patch.object(d.subprocess, 'Popen', return_value=process), \
             patch.object(d.selectors, 'DefaultSelector') as factory, \
             patch.object(d.os, 'set_blocking'), patch.object(d.os, 'killpg', side_effect=PermissionError(CANARY)):
            factory.return_value.__enter__.return_value = selector
            with self.assertRaises(d.Refused) as caught:
                d.capture(('NEVER_EXECUTE',), Path('/'), {}, 1, 1, clock=lambda: 2)
        self.assertEqual(caught.exception.category, 'CLIENT_TIMEOUT')
        selector.select.assert_not_called()
        process.wait.assert_called_once_with(timeout=0.2)

    def test_output_cap_and_nonzero_do_not_export_streams(self):
        for data, cap, exit_code, category in ((CANARY.encode(), 1, 0, 'OUTPUT_CAP'),
                                               (b'', 100, 1, 'CLIENT_NONZERO')):
            with self.subTest(category=category):
                process = unittest.mock.Mock(pid=999999)
                process.wait.return_value = exit_code
                selector = unittest.mock.MagicMock()
                selector.get_map.side_effect = [True, False]
                event = types.SimpleNamespace(fileobj=process.stdout, data=True)
                selector.select.return_value = [(event, 1)]
                with patch.object(d.subprocess, 'Popen', return_value=process), \
                     patch.object(d.selectors, 'DefaultSelector') as factory, \
                     patch.object(d.os, 'set_blocking'), patch.object(d.os, 'read', return_value=data), \
                     patch.object(d.os, 'killpg'):
                    factory.return_value.__enter__.return_value = selector
                    with self.assertRaises(d.Refused) as caught:
                        d.capture(('NEVER_EXECUTE',), Path('/'), {}, 10, cap, clock=lambda: 1)
                self.assertEqual(caught.exception.category, category)
                self.assertNotIn(CANARY, str(caught.exception))


if __name__ == '__main__':
    unittest.main()
