"""NEW focused inert tests. No real transport, signing, SQLite, app or image imports.

Release bytes below are disposable FAKE public files, NOT a cryptographic fixture.
A mocked actor receipt tests gate plumbing only; real production-crypto execution
in the pinned image remains a separate independently reviewed qualification.
"""
import contextlib
import copy
import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).absolute()
spec = importlib.util.spec_from_file_location('own_release_gate', HERE.with_name('verify_preservation_release.py'))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class FakeRunner:
    def __init__(self, receipt):
        self.deadline = time.monotonic() + 600
        self.receipt = receipt
        self.calls = []
        self.gate = None
        self.state = 'created'
        self.labels = {'com.docker.compose.project': 'immutable-image-inherited'}
        self.preexisting = False
        self.break_guard = None
        self.on_start = None
        self.fail_create = False
        self.fail_start = False
        self.removed = False
        self.health = {'Test': ['NONE']}
        self.cid = 'a' * 64

    def info(self):
        g = self.gate
        host = {'ReadonlyRootfs': True, 'NetworkMode': 'none', 'CapDrop': ['ALL'],
                'CapAdd': None, 'Privileged': False, 'SecurityOpt': ['no-new-privileges:true'],
                'Memory': 2 * 1024**3, 'MemorySwap': 2 * 1024**3, 'NanoCpus': 10**9,
                'PidsLimit': 64, 'Tmpfs': v.TMPFS, 'AutoRemove': False,
                'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
                'LogConfig': {'Type': 'none', 'Config': {}}, 'IpcMode': 'none',
                'Mounts': [{'Type': 'bind', 'Source': g._request['source'], 'Target': '/opt/release',
                            'ReadOnly': True, 'BindOptions': {'Propagation': 'rprivate'}}]}
        info = {'id': self.cid, 'image': v.API, 'name': '/' + g.name,
                'labels': dict(self.labels, **{v.LABEL: g.attempt_id}),
                'state': {'Status': self.state, 'Running': self.state == 'running', 'Paused': False,
                          'Restarting': False, 'Dead': False, 'OOMKilled': False, 'Error': '', 'ExitCode': 0},
                'host': host, 'mounts': [{'Type': 'bind', 'Source': g._request['source'],
                                         'Destination': '/opt/release', 'RW': False, 'Propagation': 'rprivate'}],
                'entry': ['/usr/bin/env'], 'cmd': g._cmd, 'user': '65532:65532',
                'cwd': '/app/server/api', 'stop': 1,
                'health_disabled': v.canonical(self.health) == v.canonical({'Test': ['NONE']})}
        if self.break_guard:
            self.break_guard(info)
        return info

    def __call__(self, args, *, timeout, cap):
        self.calls.append((args, timeout, cap))
        assert args[0] == 'docker' and 0 < timeout <= 90
        if args[1:3] == ('image', 'inspect'):
            assert args[-1] == v.API and args[3:5] == ('--format', v.IMAGE_FORMAT)
            return v.canonical({'id': v.API, 'os': 'linux', 'arch': 'arm64',
                                'labels': self.labels, 'volumes': None})
        if args[1] == 'ps':
            return b'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n' if self.preexisting else b''
        if args[1] == 'create':
            if self.fail_create:
                raise OSError('PRIVATE_CANARY')
            return (self.cid + '\n').encode()
        if args[1:3] == ('container', 'inspect'):
            assert args[3:5] == ('--format', v.INSPECT_FORMAT) and args[-1] == self.cid
            return v.canonical(self.info())
        if args[1:3] == ('start', '--attach'):
            self.state = 'running'
            if self.on_start:
                self.on_start()
            if self.fail_start:
                raise OSError('PRIVATE_CANARY')
            self.state = 'exited'
            return self.receipt
        if args[1] == 'stop':
            assert args == ('docker', 'stop', '--time', '1', self.cid)
            self.state = 'exited'
            return self.cid.encode()
        if args[1] == 'rm':
            assert args == ('docker', 'rm', self.cid) and self.state == 'exited'
            self.removed = True
            return self.cid.encode()
        raise AssertionError('UNEXPECTED_INERT_CALL')


class ReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.no_process = mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('NO_REAL_CHILD')).start()
        self.addCleanup(mock.patch.stopall)
        self.temp = tempfile.TemporaryDirectory(prefix='own-release-gate-inert-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / 'repo'
        directory = self.repo / 'server/deploy/trust'
        directory.mkdir(parents=True)
        for name in (v.MODULE, v.TEST):
            shutil.copyfile(HERE.parent / Path(name).name, self.repo / name)
        mock.patch.object(v, '__file__', str(self.repo / v.MODULE)).start()
        self.release = self.base / 'public-release'
        (self.release / 'db').mkdir(parents=True)
        self.addCleanup(self.writable)
        now = datetime.datetime.now(datetime.timezone.utc)
        fmt = lambda value: value.strftime('%Y-%m-%dT%H:%M:%S') + '.000000000Z'
        self.expiry = fmt(now + datetime.timedelta(days=13))
        bundle, db = b'FAKE_PUBLIC_BUNDLE', b'FAKE_PUBLIC_DB_NOT_SQLITE'
        metadata = b'{"synthetic":true}'
        self.identity = {'envelopeVersion': 1, 'signer': 'local-db-operator-v1',
                         'source': 'ghcr.io/aquasecurity/trivy-db@sha256:' + 'b' * 64,
                         'schemaVersion': 2, 'artifactSha256': sha(bundle),
                         'metadataSha256': sha(metadata), 'dbSha256': sha(db),
                         'manifestDigest': 'sha256:' + 'b' * 64,
                         'updatedAt': fmt(now - datetime.timedelta(days=1)),
                         'downloadedAt': fmt(now), 'nextUpdate': fmt(now + datetime.timedelta(days=1))}
        # Preserve JS descriptor field order; no fixture key/signature is created.
        descriptor = json.dumps(self.identity, separators=(',', ':')).encode()
        for name, raw in {'descriptor.json': descriptor, 'descriptor.sig': b'x' * 64,
                          'bundle.bin': bundle, 'db/metadata.json': metadata, 'db/trivy.db': db}.items():
            path = self.release / name
            path.write_bytes(raw)
            path.chmod(0o444)
        for path in (self.release / 'db', self.release):
            path.chmod(0o555)
        result = {'code': 'RELEASE_AUTHENTICATED', 'ok': True, 'identity': self.identity,
                  'policy': v.POLICY, 'evaluatedAt': time.time_ns() // 10**6, 'usableUntil': self.expiry}
        self.runner = FakeRunner(v.canonical(result))
        self.gate = self.make_gate()
        self.runner.gate = self.gate
        self.request = {'version': 1, 'actor_image': v.API, 'candidate_worker_image': v.WORKER,
                        'source': str(self.release), 'manifest': self.identity['manifestDigest'],
                        'artifact': self.identity['artifactSha256'], 'policy': v.POLICY,
                        'trusted_spki_sha256': v.TRUST, 'source_aggregate': v.AGGREGATE,
                        'verifier_sources': self.gate.sources}

    def writable(self):
        # Only this new disposable fixture; never a recursive deployment cleanup.
        for path in (self.release, self.release / 'db'):
            if path.exists():
                path.chmod(0o755)

    def make_gate(self):
        return v.make_release_gate(self.repo, self.runner,
                                   deadline=time.monotonic() + 600, attempt_id='c' * 32)

    def refuse(self, operation):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with self.assertRaises(v.ReleaseRefused) as caught:
                operation()
        self.assertEqual(str(caught.exception), 'RELEASE_REFUSED')
        self.assertEqual((out.getvalue(), err.getvalue()), ('', ''))
        self.no_process.assert_not_called()
        return caught.exception

    def test_full_factory_protocol_one_actor_three_rechecks_no_extra_engine_calls(self):
        self.assertEqual(set(self.gate.sources), {v.MODULE, v.TEST})
        self.assertIsNone(self.gate.last_recheck_stage)
        external = self.gate.sources
        external[v.MODULE] = '0' * 64
        self.assertNotEqual(external, self.gate.sources)
        seal = self.gate.verify(copy.deepcopy(self.request))
        self.assertEqual((type(seal), len(seal)), (bytes, 32))
        self.assertTrue(self.runner.removed)
        self.assertIsNone(self.gate.retained)
        before = len(self.runner.calls)
        for _ in range(3):
            self.assertIsNone(self.gate.recheck(copy.deepcopy(self.request), seal))
            self.assertEqual(self.gate.last_recheck_stage, 'CLOCK_AFTER')
        self.assertEqual(len(self.runner.calls), before)
        self.refuse(lambda: self.gate.recheck(self.request, seal))
        self.assertEqual(sum(a[1] == 'create' for a, _, _ in self.runner.calls), 1)
        self.no_process.assert_not_called()

    def test_actor_exact_envelope_imports_source_pins_and_no_unsealed_cli(self):
        self.gate.verify(self.request)
        command = next(a for a, _, _ in self.runner.calls if a[1] == 'create')
        for option, value in (('--user', '65532:65532'), ('--network', 'none'), ('--cap-drop', 'ALL'),
                              ('--memory', '2147483648'), ('--memory-swap', '2147483648'), ('--cpus', '1'),
                              ('--pids-limit', '64'), ('--log-driver', 'none'), ('--pull', 'never'),
                              ('--entrypoint', '/usr/bin/env'), ('--ipc', 'none')):
            self.assertEqual(command[command.index(option) + 1], value)
        self.assertIn('--read-only', command)
        self.assertEqual(command.count('--no-healthcheck'), 1)
        self.assertIn('(json .Config.Healthcheck)', v.INSPECT_FORMAT)
        self.assertIn('"{\\"Test\\":[\\"NONE\\"]}"', v.INSPECT_FORMAT)
        self.assertEqual(command.count('--mount'), 1)
        self.assertEqual(command[command.index('--mount') + 1],
                         'type=bind,src=' + str(self.release) + ',dst=/opt/release,readonly,bind-propagation=rprivate')
        self.assertNotIn('--env-file', command)
        self.assertNotIn('--env', command)
        self.assertEqual(command[command.index(v.API) + 1:command.index(v.API) + 6], ('-i', *v.ENV))
        self.assertIn('await preflightVulnDbBundle(', v.PROGRAM)
        self.assertIn('policy:CURRENT_DB_POLICY', v.PROGRAM)
        self.assertIn('operatorUsableUntil(id)', v.PROGRAM)
        for path, digest in v.SOURCE_PINS.items():
            self.assertIn(path, v.PROGRAM)
            self.assertIn(digest, v.PROGRAM)
        for forbidden in ('verify-vuln-db-release.ts', 'process.env.SCAN_', 'runWorker(', 'now:', 'better-sqlite3'):
            self.assertNotIn(forbidden, v.PROGRAM)
        self.assertNotIn('.Config.Env', v.INSPECT_FORMAT + v.IMAGE_FORMAT)
        self.assertNotIn('logs', [a[1] for a, _, _ in self.runner.calls])
        payload = json.loads(command[-1])
        self.assertLessEqual(payload['ms'], 80000)
        self.assertEqual(set(payload['files']), set(v.BOUNDS))

    def test_exact_request_pins_extra_field_and_public_source_drift_refuse_before_engine(self):
        for key, value in (('version', True), ('actor_image', v.WORKER), ('candidate_worker_image', v.API),
                           ('source_aggregate', '0' * 64), ('policy', 'legacy-db-freshness-v1'),
                           ('trusted_spki_sha256', '0' * 64), ('manifest', 'latest'), ('artifact', 'A' * 64),
                           ('source', str(self.release) + '/../public-release'), ('unknown', 'PRIVATE_CANARY')):
            with self.subTest(key=key):
                gate = self.make_gate()
                req = dict(self.request, **{key: value})
                self.refuse(lambda: gate.verify(req))
        self.assertEqual(self.runner.calls, [])
        (self.repo / v.MODULE).write_bytes(b'PRIVATE_CANARY')
        self.refuse(lambda: self.gate.verify(self.request))
        self.assertEqual(self.runner.calls, [])

    def test_layout_symlink_hardlink_writable_and_extra_file_refuse_before_engine(self):
        for kind in ('symlink', 'hardlink', 'writable', 'extra', 'short-signature'):
            with self.subTest(kind=kind):
                self.writable()
                path = self.release / 'descriptor.sig'
                original = path.read_bytes()
                if kind == 'symlink':
                    path.unlink(); path.symlink_to('bundle.bin')
                elif kind == 'hardlink':
                    os.link(path, self.base / 'signature-alias')
                elif kind == 'writable':
                    path.chmod(0o644)
                elif kind == 'extra':
                    (self.release / 'PRIVATE_CANARY').write_bytes(b'PUBLIC_EXTRA')
                else:
                    path.chmod(0o644); path.write_bytes(b'x'); path.chmod(0o444)
                self.release.chmod(0o555); (self.release / 'db').chmod(0o555)
                gate = self.make_gate()
                self.refuse(lambda: gate.verify(self.request))
                self.assertEqual(self.runner.calls, [])
                self.writable()
                if kind == 'hardlink':
                    (self.base / 'signature-alias').unlink()
                if kind == 'extra':
                    (self.release / 'PRIVATE_CANARY').unlink()
                path.unlink(); path.write_bytes(original); path.chmod(0o444)

    def test_preexisting_namespace_and_inherited_reserved_label_never_adopt(self):
        self.runner.preexisting = True
        self.refuse(lambda: self.gate.verify(self.request))
        self.assertFalse(any(a[1] == 'create' for a, _, _ in self.runner.calls))
        self.assertIsNone(self.gate.retained)
        self.runner.preexisting = False
        self.runner.labels[v.LABEL] = 'forged'
        gate = self.make_gate()
        self.refuse(lambda: gate.verify(self.request))
        self.assertFalse(any(a[1] == 'create' for a, _, _ in self.runner.calls))

    def test_guard_inherited_labels_pass_but_drift_forgery_mount_create_or_rw_refuse(self):
        mutations = [lambda i: i['labels'].update(forged='PRIVATE_CANARY'),
                     lambda i: i['labels'].update({v.LABEL: 'forged'}),
                     lambda i: i['host']['Mounts'][0]['BindOptions'].update(CreateMountpoint=True),
                     lambda i: i['host']['Mounts'][0]['BindOptions'].update(CreateMountpoint=0),
                     lambda i: i['host']['Mounts'][0].update(ReadOnly=1),
                     lambda i: i['host']['Mounts'][0]['BindOptions'].update(Unknown=False),
                     lambda i: i.update(stop=True),
                     lambda i: i.update(health_disabled=1),
                     lambda i: i['mounts'][0].update(Source='/host_mnt' + str(self.release)),
                     lambda i: i['mounts'][0].update(RW=True),
                     lambda i: i['host'].update(Privileged=True),
                     lambda i: i.update(image=v.WORKER)]
        for change in mutations:
            gate = self.make_gate(); self.runner.gate = gate
            self.runner.break_guard = change
            before = len(self.runner.calls)
            self.refuse(lambda: gate.verify(self.request))
            new = [a for a, _, _ in self.runner.calls[before:]]
            self.assertFalse(any(a[1] in ('start', 'stop', 'rm') for a in new))
            self.assertEqual(gate.retained, {'name': gate.name, 'id': self.runner.cid})

    def test_healthcheck_enabled_inherited_missing_or_nonexact_refuse_before_start(self):
        for health in (None, {}, {'Test': []}, {'Test': ['CMD', 'PRIVATE_CANARY']},
                       {'Test': ['CMD-SHELL', 'PRIVATE_CANARY']}, {'Test': ['NONE', 'extra']},
                       {'Test': ['NONE'], 'Interval': 1}, {'Test': ['NONE'], 'Unknown': False}):
            with self.subTest(health=health):
                gate = self.make_gate(); self.runner.gate = gate; self.runner.health = health
                before = len(self.runner.calls)
                self.refuse(lambda: gate.verify(self.request))
                self.assertFalse(any(a[1] in ('start', 'stop', 'rm')
                                     for a, _, _ in self.runner.calls[before:]))
        self.runner.health = {'Test': ['NONE']}
        gate = self.make_gate(); self.runner.gate = gate
        self.assertEqual(len(gate.verify(self.request)), 32)

    def test_directory_iterator_exact_sets_expected_plus_one_and_always_close(self):
        expected = {'a', 'b'}
        for names, passes in ((('a', 'b'), True), (('b', 'a'), True), (('a',), False),
                              (('a', 'b', 'extra', 'never-read'), False),
                              (('a', 'a'), False), (('unknown', 'never-read'), False)):
            with self.subTest(names=names):
                scan = mock.MagicMock()
                scan.__enter__.return_value = scan
                scan.__next__.side_effect = iter(type('Entry', (), {'name': n})() for n in names)
                ticks = []
                with mock.patch.object(v.os, 'scandir', return_value=scan) as opened:
                    operation = lambda: v.exact_entries(123, expected, lambda: ticks.append(1))
                    if passes:
                        self.assertIsNone(operation())
                    else:
                        self.refuse(operation)
                opened.assert_called_once_with(123)
                scan.__exit__.assert_called_once()
                self.assertLessEqual(scan.__next__.call_count, len(expected) + 1)
                self.assertEqual(len(ticks), scan.__next__.call_count + 1)

    def test_directory_deadline_closes_and_inventory_uses_four_bounded_scans(self):
        scan = mock.MagicMock()
        scan.__enter__.return_value = scan
        scan.__next__.return_value = type('Entry', (), {'name': 'a'})()
        tick = mock.Mock(side_effect=(None, None, v.ReleaseRefused()))
        with mock.patch.object(v.os, 'scandir', return_value=scan):
            self.refuse(lambda: v.exact_entries(123, {'a', 'b'}, tick))
        scan.__exit__.assert_called_once()
        self.assertEqual(scan.__next__.call_count, 1)
        with mock.patch.object(v.os, 'listdir', side_effect=AssertionError('NO_UNBOUNDED_LISTDIR')), \
             mock.patch.object(v, 'exact_entries', wraps=v.exact_entries) as bounded:
            v.inventory(str(self.release), lambda: None)
        self.assertEqual([len(call.args[1]) for call in bounded.call_args_list], [4, 2, 4, 2])
        self.assertIn('fs.opendirSync(path,{bufferSize:1})', v.PROGRAM)
        self.assertIn('i<=expected.length', v.PROGRAM)
        self.assertIn('finally{dir.closeSync();}', v.PROGRAM)
        self.assertNotIn('readdirSync', v.PROGRAM)

    def test_moby_omitted_false_defaults_and_explicit_boolean_false_are_equivalent(self):
        self.runner.break_guard = lambda i: i['host']['Mounts'][0]['BindOptions'].update(v.BIND_OPTIONS)
        seal = self.gate.verify(self.request)
        self.assertEqual(len(seal), 32)
        self.assertTrue(self.runner.removed)

    def test_start_failure_stops_only_guarded_id_retains_and_no_retry(self):
        self.runner.fail_start = True
        self.refuse(lambda: self.gate.verify(self.request))
        commands = [a for a, _, _ in self.runner.calls]
        self.assertIn(('docker', 'stop', '--time', '1', self.runner.cid), commands)
        self.assertNotIn('rm', [a[1] for a in commands])
        self.assertEqual(self.gate.retained['id'], self.runner.cid)
        count = len(self.runner.calls)
        self.refuse(lambda: self.gate.verify(self.request))
        self.assertEqual(len(self.runner.calls), count)

    def test_uncertain_create_retains_name_without_query_or_adoption(self):
        self.runner.fail_create = True
        self.refuse(lambda: self.gate.verify(self.request))
        self.assertEqual(self.gate.retained, {'name': self.gate.name, 'id': None})
        self.assertFalse(any(a[1] in ('container', 'start', 'stop', 'rm') for a, _, _ in self.runner.calls))

    def test_tamper_during_actor_and_bad_receipt_never_issue_seal_or_cleanup(self):
        path = self.release / 'bundle.bin'
        def mutate():
            path.chmod(0o644); path.write_bytes(b'TAMPER_PUBLIC_BYTES'); path.chmod(0o444)
        self.runner.on_start = mutate
        self.refuse(lambda: self.gate.verify(self.request))
        self.assertIsNone(self.gate._sealed)
        self.assertFalse(self.runner.removed)
        self.refuse(lambda: self.gate.recheck(self.request, b'forged'))

    def test_wrong_private_receipt_refuses_and_does_not_leak(self):
        for raw in (b'{"code":"RELEASE_REFUSED","ok":false}\n',
                    b'{"PRIVATE_CANARY":true}', b'{"code":1,"code":2}',
                    self.runner.receipt.replace(b'RELEASE_AUTHENTICATED', b'PRIVATE_CANARY'),
                    b'x' * 16385):
            gate = self.make_gate(); self.runner.gate = gate; self.runner.state = 'created'
            self.runner.receipt = raw
            self.refuse(lambda: gate.verify(self.request))
            self.assertIsNone(gate._sealed)
            self.assertFalse(self.runner.removed)

    def test_recheck_same_bytes_inode_metadata_and_expiry_no_second_actor(self):
        seal = self.gate.verify(self.request)
        count = len(self.runner.calls)
        path = self.release / 'db/trivy.db'
        path.chmod(0o644); path.write_bytes(b'CHANGED_PUBLIC_DB'); path.chmod(0o444)
        self.refuse(lambda: self.gate.recheck(self.request, seal))
        self.assertEqual(len(self.runner.calls), count)
        self.refuse(lambda: self.gate.recheck(self.request, seal))

    def test_recheck_opaque_capability_request_expiry_and_clock_rollback(self):
        for kind in ('capability', 'request', 'expiry', 'clock'):
            gate = self.make_gate(); self.runner.gate = gate; self.runner.state = 'created'
            seal = gate.verify(self.request)
            request = copy.deepcopy(self.request)
            if kind == 'capability':
                seal = b'0' * 32
            elif kind == 'request':
                request['artifact'] = 'd' * 64
            elif kind == 'expiry':
                gate.wall_ns = lambda: v.until_ns(self.expiry) + 1
            else:
                gate.wall_ns = lambda: gate._wall_start - 1
            count = len(self.runner.calls)
            self.refuse(lambda: gate.recheck(request, seal))
            self.assertEqual(len(self.runner.calls), count)

    def test_clock_rollback_between_successful_rechecks_and_same_byte_inode_replacement(self):
        seal = self.gate.verify(self.request)
        future = self.gate._last_wall + 10**9
        self.gate.wall_ns = lambda: future
        self.assertIsNone(self.gate.recheck(self.request, seal))
        self.gate.wall_ns = lambda: future - 1
        self.refuse(lambda: self.gate.recheck(self.request, seal))
        gate = self.make_gate(); self.runner.gate = gate; self.runner.state = 'created'
        seal = gate.verify(self.request)
        self.writable()
        path = self.release / 'db/trivy.db'
        raw = path.read_bytes()
        path.unlink(); path.write_bytes(raw); path.chmod(0o444)
        self.release.chmod(0o555); (self.release / 'db').chmod(0o555)
        count = len(self.runner.calls)
        self.refuse(lambda: gate.recheck(self.request, seal))
        self.assertEqual(len(self.runner.calls), count)

    def test_recheck_closed_stage_boundaries_exact_exception_and_failstop(self):
        self.assertEqual(v.RECHECK_STAGES, frozenset(('CAPABILITY_REQUEST', 'SOURCE_PINS',
                         'CLOCK_BEFORE', 'INVENTORY_READ', 'INVENTORY_EQUALITY', 'CLOCK_AFTER')))
        for stage in sorted(v.RECHECK_STAGES):
            with self.subTest(stage=stage), contextlib.ExitStack() as patches:
                gate = self.make_gate(); self.runner.gate = gate; self.runner.state = 'created'
                seal = gate.verify(self.request)
                sealed = gate._sealed
                if stage == 'CAPABILITY_REQUEST':
                    seal = b'0' * 32
                elif stage == 'SOURCE_PINS':
                    patches.enter_context(mock.patch.object(gate, '_validate', side_effect=v.ReleaseRefused()))
                elif stage == 'CLOCK_BEFORE':
                    gate.wall_ns = lambda: gate._last_wall - 1
                elif stage == 'INVENTORY_READ':
                    patches.enter_context(mock.patch.object(v, 'inventory', side_effect=v.ReleaseRefused()))
                elif stage == 'INVENTORY_EQUALITY':
                    changed = copy.deepcopy(sealed[0])
                    changed['files']['bundle.bin']['sha256'] = '0' * 64
                    patches.enter_context(mock.patch.object(v, 'inventory', return_value=changed))
                else:
                    gate.wall_ns = mock.Mock(side_effect=(gate._last_wall, gate._last_wall - 1))
                calls = len(self.runner.calls)
                error = self.refuse(lambda: gate.recheck(self.request, seal))
                self.assertIs(type(error), v.ReleaseRefused)
                self.assertEqual((error.fixed_stage, gate.last_recheck_stage), (stage, stage))
                self.assertEqual(error.fixed_category, 'PREDICATE_REFUSED')
                self.assertEqual(error.args, ('RELEASE_REFUSED',))
                self.assertIs(gate._sealed, sealed)
                self.assertTrue(gate._failed)
                repeated = self.refuse(lambda: gate.recheck(self.request, seal))
                self.assertEqual(repeated.fixed_stage, 'CAPABILITY_REQUEST')
                self.assertEqual(len(self.runner.calls), calls)

    def test_recheck_unexpected_errors_closed_without_private_type_or_message(self):
        class ForeignRefusal(v.ReleaseRefused):
            pass
        for error in (OSError('PRIVATE_CANARY'), ValueError('PRIVATE_CANARY'), ForeignRefusal()):
            gate = self.make_gate(); self.runner.gate = gate; self.runner.state = 'created'
            seal = gate.verify(self.request)
            calls = len(self.runner.calls)
            with mock.patch.object(v, 'inventory', side_effect=error):
                refused = self.refuse(lambda: gate.recheck(self.request, seal))
            self.assertIs(type(refused), v.ReleaseRefused)
            self.assertEqual((refused.fixed_stage, refused.fixed_category), ('INVENTORY_READ', 'UNEXPECTED'))
            self.assertEqual(set(vars(refused)), {'fixed_stage', 'fixed_category'})
            self.assertNotIn('PRIVATE_CANARY', str(refused) + repr(refused) + repr(vars(refused)))
            self.assertTrue(refused.__suppress_context__)
            self.assertEqual(gate.last_recheck_stage, 'INVENTORY_READ')
            self.assertEqual(len(self.runner.calls), calls)

    def test_sibling_creation_invalidates_strict_ancestor_seal_but_preseal_scratch_passes(self):
        seal = self.gate.verify(self.request)
        captured = self.gate._sealed[0]
        (self.base / 'fresh-own-scratch').mkdir(mode=0o700)
        current = v.inventory(str(self.release), lambda: None)
        self.assertEqual(current['files'], captured['files'])
        self.assertEqual(current['db'], captured['db'])
        self.assertNotEqual(current['ancestors'], captured['ancestors'])
        calls = len(self.runner.calls)
        refused = self.refuse(lambda: self.gate.recheck(self.request, seal))
        self.assertEqual((refused.fixed_stage, refused.fixed_category),
                         ('INVENTORY_EQUALITY', 'PREDICATE_REFUSED'))
        self.assertEqual(len(self.runner.calls), calls)
        gate = self.make_gate(); self.runner.gate = gate; self.runner.state = 'created'
        seal = gate.verify(self.request)  # Same scratch already exists BEFORE this seal.
        sealed = gate._sealed
        calls = len(self.runner.calls)
        self.assertIsNone(gate.recheck(self.request, seal))
        self.assertIs(gate._sealed, sealed)
        self.assertEqual(gate.last_recheck_stage, 'CLOCK_AFTER')
        self.assertEqual(len(self.runner.calls), calls)

    def test_streaming_caps_shared_deadline_and_no_source_init(self):
        ticks = []
        captured = v.inventory(str(self.release), lambda: ticks.append(1))
        self.assertEqual(set(captured['files']), set(v.BOUNDS))
        self.assertGreater(len(ticks), 5)
        with mock.patch.dict(v.BOUNDS, {'bundle.bin': 1}):
            self.refuse(lambda: self.gate.verify(self.request))
        self.assertEqual(self.runner.calls, [])
        self.runner.deadline = time.monotonic() - 1
        gate = self.gate
        self.refuse(lambda: v.make_release_gate(self.repo, self.runner,
                    deadline=time.monotonic() + 600, attempt_id='d' * 32))
        self.assertIsNone(gate.retained)
        self.assertFalse((self.release / 'new-file').exists())


if __name__ == '__main__':
    unittest.main()
