"""OWN inert tests only: no real subprocess, Docker/plugin/app or private input.

Plugin content tests use disposable PUBLIC byte files, never real executables.
Both operations and output fault tests use mocks. No authority for runtime queries.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).with_name('qualify_compose_render.py')
spec = importlib.util.spec_from_file_location('own_public_compose_qualifier', SOURCE)
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)


class InertCase(unittest.TestCase):
    def setUp(self):
        patch = mock.patch.object(q.subprocess, 'Popen',
                                  side_effect=AssertionError('NO_REAL_CHILD'))
        self.forbidden_process = patch.start()
        self.addCleanup(patch.stop)
        temp = tempfile.TemporaryDirectory(prefix='own-compose-render-mock-')
        self.addCleanup(temp.cleanup)
        self.parent = Path(temp.name).resolve()
        self.root = self.parent / 'fresh'
        self.source_pin = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
        self.test_pin = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        self.identity = {'path': str(q.PLUGIN), 'stat': [0] * 9, 'sha256': 'b' * 64}
        self.metadata = {'SchemaVersion': '0.1.0', 'Vendor': 'Docker Inc.',
                         'Version': q.SEMANTIC_VERSION, 'ShortDescription': 'Docker Compose',
                         'URL': 'https://github.com/docker/compose'}
        self.proof = {'code': 'PLUGIN_PROVENANCE', 'source_sha256': self.source_pin,
                      'test_sha256': self.test_pin, 'plugin': self.identity,
                      'metadata': self.metadata, 'semantic_version': q.SEMANTIC_VERSION,
                      'historical514_binary_identity': 'NOT_ESTABLISHED'}
        self.proof_pin = hashlib.sha256(q.canonical(self.proof)).hexdigest()

    def render(self, responses=None):
        calls = []
        values = responses if responses is not None else [q.canonical(q.expected_model())] * 2

        def runner(argv, env, cwd, deadline):
            calls.append((argv, env, cwd, deadline))
            self.assertTrue((self.root / 'attempt.json').is_file())
            self.assertTrue((self.root / 'test_qualify_compose_render.py').is_file())
            self.assertEqual((self.root / 'client/config.json').read_bytes(), b'{}\n')
            return values[len(calls) - 1]

        with mock.patch.object(q, 'read_provenance', return_value=self.proof), \
                mock.patch.object(q, 'plugin_identity', return_value=self.identity), \
                mock.patch.object(q, 'bounded_client', side_effect=runner):
            result = q.execute(self.root, self.source_pin, self.test_pin, self.proof_pin)
        return result, calls

    def render_args(self):
        return ['--execute-public-two-renders', '--source-sha256', self.source_pin,
                '--test-sha256', self.test_pin, '--provenance-sha256', self.proof_pin]


class ComposeRenderTests(InertCase):
    def test_two_direct_config_commands_full_equal_roundtrip(self):
        result, calls = self.render()
        self.assertEqual(result, 'PASS')
        self.assertEqual(len(calls), 2)
        for index, (argv, env, cwd, _) in enumerate(calls):
            self.assertEqual(argv, q.compose_argv(str(q.PLUGIN), self.root, bool(index)))
            self.assertEqual(argv[0], str(q.PLUGIN))
            self.assertEqual(argv[-3:], ['config', '--format', 'json'])
            self.assertEqual(env, q.child_env(self.root))
            self.assertEqual(cwd, str(self.root))
            self.assertIn('/dev/null', argv)
            for prohibited in ('compose', 'version', 'docker-cli-plugin-metadata',
                               'inspect', 'create', 'build', 'exec', 'up', 'pull'):
                self.assertNotIn(prohibited, argv[1:])
        self.assertFalse((self.root / 'missing-optional.env').exists())
        self.assertFalse((self.root / '.env').exists())
        self.assertEqual((self.root / 'receipt.json').read_bytes(), b'{"code":"PASS"}\n')
        first = q.parse_model((self.root / 'first.json').read_bytes())
        self.assertEqual((self.root / 'second.json').read_bytes(), q.canonical(first))
        self.assertEqual((self.root / 'normalized.json').read_bytes(), q.canonical(first))
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        attempt = json.loads((self.root / 'attempt.json').read_bytes())
        self.assertEqual(attempt['plugin'], self.identity)
        self.assertEqual(attempt['metadata'], self.metadata)
        self.assertEqual(attempt['provenance_sha256'], self.proof_pin)
        self.assertEqual(attempt['plugin_identity_against_prior_measurement'], 'NOT_ESTABLISHED')

    def test_no_ambient_environment_or_default_config(self):
        with mock.patch.dict(os.environ, {'PRIVATE_CANARY': 'secret', 'DOCKER_CONTEXT': 'stand',
                                          'COMPOSE_FILE': '/private/stand.yml',
                                          'INERT_PUBLIC': 'wrong', 'HTTP_PROXY': 'secret'}):
            env = q.child_env(self.root)
        self.assertEqual(env['INERT_PUBLIC'], 'public-marker')
        self.assertEqual(env['INERT_LITERAL'], 'ambient-poison')
        self.assertEqual(env['DOCKER_CONTEXT'], '')
        for name in ('COMPOSE_FILE', 'PRIVATE_CANARY', 'HTTP_PROXY'):
            self.assertNotIn(name, env)
        self.assertEqual(env['DOCKER_HOST'], 'unix://' + str(self.root / 'no-engine.sock'))

    def test_dollar_escape_all_strings_and_key_refusal(self):
        value = {'nested': ['$', '$$', '${INERT_LITERAL}', {'x': '$here'}], 'bool': True}
        self.assertEqual(q.dollar_escape(value), {
            'nested': ['$$', '$$$$', '$${INERT_LITERAL}', {'x': '$$here'}], 'bool': True})
        with self.assertRaises(q.Refused):
            q.dollar_escape({'$unsafe': 'public'})

    def test_typed_oracle_order_override_and_unknown_fields(self):
        changes = [lambda s: s['environment'].update(ORDER='first'),
                   lambda s: s['tmpfs'].append('/tmp/base-a:rw'),
                   lambda s: s['environment'].update(NUMERIC=7),
                   lambda s: s['environment'].update(BOOLEAN=False),
                   lambda s: s['ports'][0].update(target='8080'),
                   lambda s: s['ports'][0].update(published=18080),
                   lambda s: s.update(read_only=1),
                   lambda s: s.update(env_file=['unexpected']),
                   lambda s: s.update(build={'context': '/private'}),
                   lambda s: s['environment'].update(BRACED='ambient-poison'),
                   lambda s: s.pop('entrypoint'), lambda s: s.update(entrypoint=[]),
                   *[lambda s,v=v: s['environment'].update(DOLLAR=v)
                     for v in ('$literal', '$$$$literal')]]
        for change in changes:
            model = q.expected_model()
            change(model['services']['probe'])
            with self.assertRaises(q.Refused):
                q.assert_oracle(model)

    def test_first_refusal_no_second_child_no_raw_evidence(self):
        calls = []
        with mock.patch.object(q, 'read_provenance', return_value=self.proof), \
                mock.patch.object(q, 'plugin_identity', return_value=self.identity), \
                mock.patch.object(q, 'bounded_client', side_effect=lambda *a:
                                  calls.append(a) or b'{"PRIVATE_CANARY":"secret"}'):
            with self.assertRaises(q.Refused):
                q.execute(self.root, self.source_pin, self.test_pin, self.proof_pin)
        self.assertEqual(len(calls), 1)
        self.assertFalse((self.root / 'first.json').exists())
        self.assertFalse((self.root / 'normalized.json').exists())
        for path in self.root.rglob('*.json'):
            self.assertNotIn(b'PRIVATE_CANARY', path.read_bytes())

    def test_second_requires_full_equality(self):
        changed = q.expected_model()
        changed['services']['probe']['labels']['public.literal'] = 'ambient-poison'
        with self.assertRaises(q.Refused):
            self.render([q.canonical(q.expected_model()), q.canonical(changed)])
        self.assertTrue((self.root / 'first.json').is_file())
        self.assertFalse((self.root / 'second.json').exists())
        self.assertEqual((self.root / 'receipt.json').read_bytes(), b'{"code":"REFUSED"}\n')

    def test_strict_json_and_data_caps(self):
        samples = [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1.0}',
                   b'{"x":"\xff"}', b'{"x":"\\ud800"}', b'{"$x":1}', b'[]',
                   b'{}' + b' ' * q.FILE_CAP,
                   b'{"x":' + b'[' * 34 + b'0' + b']' * 34 + b'}',
                   b'{"x":[' + b'0,' * 4096 + b'0]}']
        for raw in samples:
            with self.assertRaises(Exception):
                q.parse_model(raw)

    def test_existing_packet_symlink_never_adopt(self):
        self.root.mkdir()
        marker = self.root / 'retained'
        marker.write_text('keep')
        with self.assertRaises(FileExistsError):
            q.Packet(self.root)
        link = self.parent / 'link'
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            q.Packet(link)
        self.assertEqual(marker.read_text(), 'keep')

    def test_pin_mismatch_before_root_or_client(self):
        with self.assertRaises(q.Refused):
            q.execute(self.root, '0' * 64, self.test_pin, self.proof_pin)
        self.assertFalse(self.root.exists())
        self.forbidden_process.assert_not_called()

    def test_durability_failure_before_client(self):
        with mock.patch.object(q, 'read_provenance', return_value=self.proof), \
                mock.patch.object(q, 'plugin_identity', return_value=self.identity), \
                mock.patch.object(q, 'fsync_dir', side_effect=OSError('PRIVATE_CANARY')), \
                mock.patch.object(q, 'bounded_client') as runner:
            with self.assertRaises(OSError):
                q.execute(self.root, self.source_pin, self.test_pin, self.proof_pin)
        runner.assert_not_called()
        self.assertTrue(self.root.exists())

    def test_source_hardlinks_symlinks_and_file_caps(self):
        packet = q.Packet(self.root)
        with self.assertRaises(q.Refused):
            packet.write('first.json', b'x' * (q.FILE_CAP + 1))
        packet.write('first.json', b'{}')
        os.link(self.root / 'first.json', self.root / 'alias')
        with self.assertRaises(q.Refused):
            q.read_own(self.root / 'first.json')
        (self.root / 'linked').symlink_to(self.root / 'first.json')
        with self.assertRaises(q.Refused):
            q.read_own(self.root / 'linked')

    def test_plugin_drift_before_second_stops_no_retry(self):
        drift = dict(self.identity, sha256='c' * 64)
        with mock.patch.object(q, 'read_provenance', return_value=self.proof), \
                mock.patch.object(q, 'plugin_identity',
                                  side_effect=[self.identity, self.identity, drift]), \
                mock.patch.object(q, 'bounded_client',
                                  return_value=q.canonical(q.expected_model())) as runner:
            with self.assertRaises(q.Refused):
                q.execute(self.root, self.source_pin, self.test_pin, self.proof_pin)
        self.assertEqual(runner.call_count, 1)
        self.assertTrue((self.root / 'first.json').exists())
        self.assertFalse((self.root / 'second.json').exists())


class ClosedFailureTests(InertCase):
    def test_operation_baseexceptions_closed_no_query_or_raw_stderr(self):
        for error in (KeyboardInterrupt('PRIVATE_CANARY'), SystemExit('PRIVATE_CANARY'),
                      OSError('PRIVATE_CANARY')):
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.object(q, 'execute', side_effect=error) as operation, \
                    mock.patch.object(q, 'observe_plugin') as observe, \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = q.main(self.render_args())
            self.assertEqual(status, 1)
            self.assertEqual(stdout.getvalue(), '{"code":"REFUSED"}\n')
            self.assertEqual(stderr.getvalue(), '')
            operation.assert_called_once()
            observe.assert_not_called()
            self.forbidden_process.assert_not_called()

    def test_observation_baseexception_and_invalid_shape_closed(self):
        for args in ([], ['--help'], ['--observe-public-plugin', '--source-sha256',
                                     self.source_pin, '--test-sha256', self.test_pin]):
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.object(q, 'observe_plugin', side_effect=KeyboardInterrupt('sentinel')), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(q.main(args), 1)
            self.assertEqual(stdout.getvalue(), '{"code":"REFUSED"}\n')
            self.assertEqual(stderr.getvalue(), '')

    def test_output_write_flush_short_write_failure_nonzero_no_second_write(self):
        for failure in ('write', 'flush', 'short'):
            class Writer:
                writes = 0
                flushes = 0

                def write(self, text):
                    self.writes += 1
                    if failure == 'write':
                        raise KeyboardInterrupt('PRIVATE_CANARY')
                    return len(text) - 1 if failure == 'short' else len(text)

                def flush(self):
                    self.flushes += 1
                    raise OSError('PRIVATE_CANARY')
            writer, stderr = Writer(), io.StringIO()
            with mock.patch.object(q, 'execute', return_value='PASS') as operation, \
                    contextlib.redirect_stdout(writer), contextlib.redirect_stderr(stderr):
                status = q.main(self.render_args())
                self.assertIsInstance(q.sys.stdout, q.QuietOutput)
                q.sys.stdout.flush()  # Shutdown cannot reflush the failed writer.
            self.assertEqual(status, 1)
            self.assertEqual(writer.writes, 1)
            self.assertEqual(writer.flushes, 1 if failure == 'flush' else 0)
            self.assertEqual(stderr.getvalue(), '')
            operation.assert_called_once()

    def test_internal_result_enum_not_arbitrary_output(self):
        stdout = io.StringIO()
        with mock.patch.object(q, 'execute', return_value='PRIVATE_CANARY'), \
                contextlib.redirect_stdout(stdout):
            self.assertEqual(q.main(self.render_args()), 1)
        self.assertEqual(stdout.getvalue(), '{"code":"REFUSED"}\n')


class PublicPluginTests(InertCase):
    def test_one_mock_metadata_query_distinct_from_render(self):
        with mock.patch.object(q, 'plugin_identity', return_value=self.identity) as measure, \
                mock.patch.object(q, 'bounded_client',
                                  return_value=q.canonical(self.metadata)) as runner:
            code = q.observe_plugin(self.root, self.source_pin, self.test_pin)
        self.assertEqual(code, 'PROVENANCE')
        runner.assert_called_once()
        args, kwargs = runner.call_args
        self.assertEqual(args[0], [str(q.PLUGIN), 'docker-cli-plugin-metadata'])
        self.assertEqual(args[1], q.child_env(self.root))
        self.assertEqual(kwargs, {'output_cap': 4096})
        self.assertEqual(measure.call_count, 3)
        proof = q.parse_model((self.root / 'provenance.json').read_bytes())
        self.assertEqual(proof, self.proof)
        self.assertEqual((self.root / 'receipt.json').read_bytes(), b'{"code":"PROVENANCE"}\n')
        self.assertFalse((self.root / 'base.yaml').exists())

    def test_metadata_exact_finite_spelling_schema_and_rejections(self):
        self.assertEqual(q.METADATA_VERSIONS,
                         frozenset(('2.34.0-desktop.1', 'v2.34.0-desktop.1')))
        for version in q.METADATA_VERSIONS:
            self.assertEqual(q.metadata_model(q.canonical(dict(self.metadata, Version=version)))
                             ['Version'], version)
        for version in ('2.34.0', '2.34.0-desktop.2', '2.34.0-desktop.10',
                        '2.34.1', ' vv2.34.0-desktop.1', '2.34.0-desktop.1\n'):
            with self.assertRaises(q.Refused):
                q.metadata_model(q.canonical(dict(self.metadata, Version=version)))
        for value in (dict(self.metadata, extra='PRIVATE_CANARY'),
                      dict(self.metadata, Vendor='other'), dict(self.metadata, URL='other')):
            with self.assertRaises(q.Refused):
                q.metadata_model(q.canonical(value))
        with self.assertRaises(q.Refused):
            q.metadata_model(b' ' * 4097)

    def test_wrong_version_and_changed_content_retained_no_fallback(self):
        for phase in ('version', 'after-query'):
            root = self.parent / phase
            wrong = dict(self.identity, sha256='c' * 64)
            identities = [self.identity, self.identity,
                          wrong if phase == 'after-query' else self.identity]
            with mock.patch.object(q, 'plugin_identity', side_effect=identities), \
                    mock.patch.object(q, 'bounded_client', return_value=q.canonical(
                        dict(self.metadata, Version='other') if phase == 'version'
                        else self.metadata)) as runner:
                with self.assertRaises(q.Refused):
                    q.observe_plugin(root, self.source_pin, self.test_pin)
            self.assertEqual(runner.call_count, 1)
            self.assertTrue(root.exists())
            self.assertFalse((root / 'provenance.json').exists())
            self.assertEqual((root / 'receipt.json').read_bytes(), b'{"code":"REFUSED"}\n')

    def test_public_content_measurement_own_synthetic_regular_file_only(self):
        path = self.parent / 'public-plugin-bytes'
        path.write_bytes(b'PUBLIC SYNTHETIC, NEVER EXECUTED')
        path.chmod(0o700)
        with mock.patch.object(q, 'PLUGIN', path):
            measured = q.plugin_identity(q.time.monotonic() + 1)
            self.assertEqual(measured['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(measured['path'], str(path))
            self.assertEqual(measured['stat'], list(q.stamp(path.stat())))
            path.chmod(0o722)
            with self.assertRaises(q.Refused):
                q.plugin_identity(q.time.monotonic() + 1)
            path.chmod(0o700)
            with mock.patch.object(q, 'BINARY_CAP', 1), self.assertRaises(q.Refused):
                q.plugin_identity(q.time.monotonic() + 1)
        link = self.parent / 'symlink-plugin'
        link.symlink_to(path)
        with mock.patch.object(q, 'PLUGIN', link), self.assertRaises(q.Refused):
            q.plugin_identity(q.time.monotonic() + 1)
        with mock.patch.object(q, 'PLUGIN', self.parent / 'missing'), self.assertRaises(FileNotFoundError):
            q.plugin_identity(q.time.monotonic() + 1)
        self.forbidden_process.assert_not_called()

    def test_public_proof_digest_source_binding_and_failed_receipt(self):
        self.root.mkdir()
        proof = dict(self.proof, producer_mode=q.DIAGNOSTIC_MODE, producer_root=str(self.root))
        raw = q.canonical(proof)
        pin = hashlib.sha256(raw).hexdigest()
        (self.root / 'provenance.json').write_bytes(raw)
        (self.root / 'receipt.json').write_bytes(q.canonical(q.Diagnostic().receipt(success=True)))
        with mock.patch.object(q, 'DIAGNOSTIC_PACKET', self.root):
            self.assertEqual(q.read_provenance(pin, self.source_pin, self.test_pin), proof)
            with self.assertRaises(q.Refused):
                q.read_provenance('0' * 64, self.source_pin, self.test_pin)
            with self.assertRaises(q.Refused):
                q.read_provenance(pin, '0' * 64, self.test_pin)
            (self.root / 'receipt.json').write_bytes(b'{"code":"REFUSED"}\n')
            with self.assertRaises(q.Refused):
                q.read_provenance(pin, self.source_pin, self.test_pin)

    def test_other_plugin_path_not_allowed_no_discovery_or_shadow(self):
        with self.assertRaises(q.Refused):
            q.compose_argv('/usr/local/lib/docker/cli-plugins/docker-compose', self.root, False)
        self.assertEqual(q.compose_argv(str(q.PLUGIN), self.root, False)[0], str(q.PLUGIN))
        self.assertNotIn('shutil', q.__dict__)


class BoundedTransportTests(InertCase):
    def pipe_child(self, stdout=b'public', stderr=b'', status=0):
        class Child:
            pid = 99999999

            def __init__(self):
                self.stdout, self.stderr = self.pipe(stdout), self.pipe(stderr)

            def pipe(self, raw):
                reader, writer = os.pipe()
                if raw:
                    os.write(writer, raw)
                os.close(writer)
                return os.fdopen(reader, 'rb')

            def wait(self, timeout):
                return status
        return Child()

    def test_transport_success_and_explicit_env(self):
        child = self.pipe_child()
        with mock.patch.object(q.subprocess, 'Popen', return_value=child) as popen:
            self.assertEqual(q.bounded_client(['public'], {'PUBLIC': 'only'}, str(self.parent),
                                               q.time.monotonic() + 1), b'public')
        self.assertEqual(popen.call_args.kwargs['stdin'], q.subprocess.DEVNULL)
        self.assertTrue(popen.call_args.kwargs['start_new_session'])
        self.assertTrue(popen.call_args.kwargs['close_fds'])
        self.assertEqual(popen.call_args.kwargs['env'], {'PUBLIC': 'only'})

    def test_nonzero_stderr_cap_timeout_one_client(self):
        for failure in ('nonzero', 'stderr', 'cap', 'timeout'):
            child = self.pipe_child(stderr=b'PRIVATE_CANARY' if failure == 'stderr' else b'',
                                    status=1 if failure == 'nonzero' else 0)
            with mock.patch.object(q.subprocess, 'Popen', return_value=child) as popen, \
                    mock.patch.object(q.os, 'killpg') as kill, \
                    mock.patch.object(q.time, 'monotonic',
                        side_effect=[0, 0, 11] if failure == 'timeout' else None, return_value=0):
                with self.assertRaises(q.Refused):
                    q.bounded_client(['public'], {}, str(self.parent), 30,
                                     output_cap=2 if failure == 'cap' else 4096)
            popen.assert_called_once()
            kill.assert_called_once_with(child.pid, q.signal.SIGKILL)
            self.assertTrue(child.stdout.closed and child.stderr.closed)


class CheckpointedProvenanceTests(InertCase):
    """NEW focused class; run this class ONLY, not prior qualification tests."""
    def args(self):
        return ['--diagnose-public-plugin', '--source-sha256', self.source_pin,
                '--test-sha256', self.test_pin]

    def run_diagnostic(self, root, raw=None, fail_gate=None, fault=None):
        launches = []
        raw = q.canonical(self.metadata) if raw is None else raw
        original_check = q.Diagnostic.check

        def check(state, gate, operation, predicate_category='PREDICATE_REFUSED'):
            def injected():
                if gate == fail_gate:
                    raise fault if fault is not None else OSError('PRIVATE_CANARY')
                return operation()
            return original_check(state, gate, injected, predicate_category)

        def identity(deadline, diagnostic=None):
            if diagnostic:
                for gate in ('PLUGIN_CANONICAL', 'PLUGIN_STAT', 'PLUGIN_TYPE',
                             'PLUGIN_OWNER_MODE', 'PLUGIN_SIZE', 'PLUGIN_OPEN',
                             'PLUGIN_FD_IDENTITY', 'PLUGIN_HASH', 'PLUGIN_STABILITY'):
                    diagnostic.check(gate, lambda: None)
            return self.identity

        def client(argv, env, cwd, deadline, output_cap=None, diagnostic=None):
            def launch():
                launches.append(argv)
                self.assertTrue((root / 'attempt.json').is_file())
                self.assertEqual(argv, [str(q.PLUGIN), 'docker-cli-plugin-metadata'])
                self.assertEqual(output_cap, 4096)
                self.assertEqual(env, q.child_env(root))
                self.assertEqual(cwd, str(root))
            diagnostic.check('CLIENT_LAUNCH', launch)
            diagnostic.check('CLIENT_READ', lambda: None)
            diagnostic.check('CLIENT_EXIT', lambda: None)
            return raw

        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(q, 'DIAGNOSTIC_PACKET', root), \
                mock.patch.object(q.Diagnostic, 'check', check), \
                mock.patch.object(q, 'plugin_identity', side_effect=identity), \
                mock.patch.object(q, 'bounded_client', side_effect=client), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = q.main(self.args())
        self.assertEqual(stderr.getvalue(), '')
        self.assertNotIn('PRIVATE_CANARY', stdout.getvalue())
        return status, json.loads(stdout.getvalue()), launches

    def test_first_checkpoint_lazy_before_every_key_group(self):
        gates = q.DIAGNOSTIC_GATES - {'OUTPUT', 'COMPLETE'}
        before_launch = {
            'ARGUMENTS', 'SOURCE_PINS', 'ROOT_PREPARE', 'SOURCE_DURABILITY',
            'CLIENT_CONFIG_DURABILITY', 'PLUGIN_CANONICAL', 'PLUGIN_STAT', 'PLUGIN_TYPE',
            'PLUGIN_OWNER_MODE', 'PLUGIN_SIZE', 'PLUGIN_OPEN', 'PLUGIN_FD_IDENTITY',
            'PLUGIN_HASH', 'PLUGIN_STABILITY', 'ATTEMPT_DURABILITY', 'PRE_CHILD_IDENTITY',
            'SOCKET_GUARD', 'CLIENT_LAUNCH'}
        for index, gate in enumerate(sorted(gates)):
            with self.subTest(gate=gate):
                root = self.parent / ('gate-' + str(index))
                status, receipt, launches = self.run_diagnostic(root, fail_gate=gate)
                self.assertEqual(status, 1)
                self.assertEqual(receipt, {'mode': q.DIAGNOSTIC_MODE,
                    'boundary': 'NO_ACTIVATION', 'outcome': 'REFUSED',
                    'checkpoint': gate, 'category': 'IO_FAILED'})
                self.assertEqual(len(launches), 0 if gate in before_launch else 1)
                self.assertLessEqual(len(launches), 1)

    def test_success_genuine_new_root_proof_consumer_no_old_reads(self):
        read = q.read_own
        paths = []

        def tracked(path):
            paths.append(path)
            self.assertFalse(path.is_relative_to(q.PROVENANCE_PACKET))
            return read(path)

        with mock.patch.object(q, 'read_own', side_effect=tracked):
            status, receipt, launches = self.run_diagnostic(self.root)
            self.assertEqual(status, 0)
            self.assertEqual(receipt, q.Diagnostic().receipt(success=True))
            self.assertEqual(len(launches), 1)
            raw = (self.root / 'provenance.json').read_bytes()
            pin = hashlib.sha256(raw).hexdigest()
            with mock.patch.object(q, 'DIAGNOSTIC_PACKET', self.root):
                proof = q.read_provenance(pin, self.source_pin, self.test_pin)
        self.assertEqual(proof['producer_mode'], q.DIAGNOSTIC_MODE)
        self.assertEqual(proof['producer_root'], str(self.root))
        self.assertEqual(proof['source_sha256'], self.source_pin)
        self.assertEqual(proof['test_sha256'], self.test_pin)
        self.assertEqual(proof['plugin'], self.identity)
        self.assertEqual(proof['metadata'], self.metadata)
        self.assertEqual(proof['historical514_binary_identity'], 'NOT_ESTABLISHED')
        self.assertEqual((self.root / 'receipt.json').read_bytes(), q.canonical(receipt))
        self.assertTrue(self.root.exists())
        self.forbidden_process.assert_not_called()

    def test_metadata_json_schema_and_fixed_fields_distinct(self):
        cases = [(b'\xff', 'METADATA_JSON', 'DECODE_REFUSED'),
                 (b'{"x":1,"x":2}', 'METADATA_JSON', 'DECODE_REFUSED'),
                 (b'{"x":NaN}', 'METADATA_JSON', 'DECODE_REFUSED'),
                 (b'{"x":1}', 'METADATA_SCHEMA', 'PREDICATE_REFUSED')]
        for key, gate in (('SchemaVersion', 'METADATA_SCHEMA_VERSION'),
                          ('Vendor', 'METADATA_VENDOR'), ('Version', 'METADATA_VERSION'),
                          ('ShortDescription', 'METADATA_DESCRIPTION'), ('URL', 'METADATA_URL')):
            cases.append((q.canonical(dict(self.metadata, **{key: 'PRIVATE_CANARY'})),
                          gate, 'PREDICATE_REFUSED'))
        for index, (raw, gate, category) in enumerate(cases):
            status, receipt, launches = self.run_diagnostic(self.parent / ('metadata-' + str(index)), raw)
            self.assertEqual(status, 1)
            self.assertEqual(receipt['checkpoint'], gate)
            self.assertEqual(receipt['category'], category)
            self.assertEqual(len(launches), 1)

    def test_transport_distinct_faults_pipe_mocks_only(self):
        for failure, gate, category in (
                ('nonzero', 'CLIENT_EXIT', 'CLIENT_NONZERO'),
                ('stderr', 'CLIENT_EXIT', 'STDERR_PRESENT'),
                ('cap', 'CLIENT_READ', 'OUTPUT_CAP'),
                ('timeout', 'CLIENT_READ', 'CLIENT_TIMEOUT')):
            diagnostic = q.Diagnostic()
            child = BoundedTransportTests.pipe_child(self,
                stderr=b'PRIVATE_CANARY' if failure == 'stderr' else b'',
                status=1 if failure == 'nonzero' else 0)
            with mock.patch.object(q.subprocess, 'Popen', return_value=child) as popen, \
                    mock.patch.object(q.os, 'killpg') as kill, \
                    mock.patch.object(q.time, 'monotonic',
                        side_effect=[0, 0, 11] if failure == 'timeout' else None, return_value=0):
                with self.assertRaises(q.Refused):
                    q.bounded_client([str(q.PLUGIN), 'docker-cli-plugin-metadata'], {},
                        str(self.parent), 12, output_cap=2 if failure == 'cap' else 4096,
                        diagnostic=diagnostic)
            self.assertEqual(diagnostic.receipt()['checkpoint'], gate)
            self.assertEqual(diagnostic.receipt()['category'], category)
            popen.assert_called_once()
            kill.assert_called_once_with(child.pid, q.signal.SIGKILL)
            self.assertTrue(child.stdout.closed and child.stderr.closed)

    def test_partial_proof_does_not_pass_new_consumer(self):
        status, receipt, launches = self.run_diagnostic(self.root, fail_gate='RECEIPT_DURABILITY')
        self.assertEqual(status, 1)
        self.assertEqual(len(launches), 1)
        self.assertEqual(receipt['checkpoint'], 'RECEIPT_DURABILITY')
        raw = (self.root / 'provenance.json').read_bytes()
        with mock.patch.object(q, 'DIAGNOSTIC_PACKET', self.root), self.assertRaises(q.Refused):
            q.read_provenance(hashlib.sha256(raw).hexdigest(), self.source_pin, self.test_pin)
        self.assertTrue((self.root / 'provenance.json').exists())

    def test_existing_new_root_refuses_no_adoption_or_child(self):
        self.root.mkdir()
        marker = self.root / 'retain'
        marker.write_bytes(b'PUBLIC RETAINED')
        status, receipt, launches = self.run_diagnostic(self.root)
        self.assertEqual(status, 1)
        self.assertEqual(receipt['checkpoint'], 'ROOT_PREPARE')
        self.assertEqual(receipt['category'], 'IO_FAILED')
        self.assertEqual(launches, [])
        self.assertEqual(marker.read_bytes(), b'PUBLIC RETAINED')
        self.assertFalse((self.root / 'receipt.json').exists())

    def test_argument_and_pin_admission_no_child(self):
        for args, gate in ((self.args()[:-1], 'ARGUMENTS'),
                           (['--diagnose-public-plugin', '--source-sha256', '0' * 64,
                             '--test-sha256', self.test_pin], 'SOURCE_PINS')):
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.object(q, 'Packet') as packet, \
                    mock.patch.object(q, 'bounded_client') as client, \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(q.main(args), 1)
            receipt = json.loads(stdout.getvalue())
            self.assertEqual(receipt['checkpoint'], gate)
            self.assertEqual(receipt['category'], 'PREDICATE_REFUSED')
            self.assertEqual(stderr.getvalue(), '')
            packet.assert_not_called()
            client.assert_not_called()

    def test_consumer_rejects_old_producer_root_and_pins_without_old_read(self):
        status, _, _ = self.run_diagnostic(self.root)
        self.assertEqual(status, 0)
        original = q.parse_model((self.root / 'provenance.json').read_bytes())
        for change in (
                {'producer_root': str(q.PROVENANCE_PACKET)},
                {'producer_mode': 'public-compose-plugin-observation-v1'},
                {'source_sha256': '65e45f997eb072e146db07f632424468f1dfaeddca9a0ce5fd2a77a154f2b75d'}):
            raw = q.canonical(dict(original, **change))
            (self.root / 'provenance.json').write_bytes(raw)
            with mock.patch.object(q, 'DIAGNOSTIC_PACKET', self.root), self.assertRaises(q.Refused):
                q.read_provenance(hashlib.sha256(raw).hexdigest(), self.source_pin, self.test_pin)
        self.forbidden_process.assert_not_called()

    def test_interrupt_and_output_failure_remain_closed(self):
        status, receipt, launches = self.run_diagnostic(self.root,
            fail_gate='SOURCE_PINS', fault=KeyboardInterrupt('PRIVATE_CANARY'))
        self.assertEqual(status, 1)
        self.assertEqual(receipt['checkpoint'], 'SOURCE_PINS')
        self.assertEqual(receipt['category'], 'UNEXPECTED')
        self.assertEqual(launches, [])
        for failure in ('write', 'flush'):
            class Writer:
                writes = 0
                flushes = 0

                def write(self, text):
                    self.writes += 1
                    if failure == 'write':
                        raise KeyboardInterrupt('PRIVATE_CANARY')
                    return len(text)

                def flush(self):
                    self.flushes += 1
                    raise OSError('PRIVATE_CANARY')
            writer, stderr = Writer(), io.StringIO()
            with mock.patch.object(q, 'diagnose_plugin',
                                   return_value=q.Diagnostic().receipt(success=True)) as operation, \
                    contextlib.redirect_stdout(writer), contextlib.redirect_stderr(stderr):
                self.assertEqual(q.main(self.args()), 1)
                self.assertIsInstance(q.sys.stdout, q.QuietOutput)
                q.sys.stdout.flush()
            self.assertEqual(writer.writes, 1)
            self.assertEqual(writer.flushes, 1 if failure == 'flush' else 0)
            self.assertEqual(stderr.getvalue(), '')
            operation.assert_called_once()


class SchemaObservationTests(InertCase):
    """529 only: finite public mapping, unknown-name suppression, no provenance."""
    def args(self):
        return ['--observe-public-schema', '--source-sha256', self.source_pin,
                '--test-sha256', self.test_pin]

    def observe(self, raw, fault=None, fail_gate='CLIENT_EXIT'):
        launches = []

        def identity(deadline, diagnostic=None):
            if diagnostic:
                diagnostic.check('PLUGIN_CANONICAL', lambda: None)
            return self.identity

        def client(argv, env, cwd, deadline, output_cap=None, diagnostic=None):
            diagnostic.check('CLIENT_LAUNCH', lambda: launches.append(argv))
            self.assertEqual(argv, [str(q.PLUGIN), 'docker-cli-plugin-metadata'])
            self.assertEqual(env, q.child_env(self.root))
            self.assertEqual(cwd, str(self.root))
            self.assertEqual(output_cap, 4096)

            def read():
                if len(raw) > output_cap:
                    raise q.Classified('OUTPUT_CAP')
            diagnostic.check('CLIENT_READ', read)
            if fault:
                def fail():
                    raise fault
                diagnostic.check(fail_gate, fail)
            diagnostic.check('CLIENT_EXIT', lambda: None)
            return raw

        actual_read = q.read_own
        def own_source_only(path):
            self.assertIn(path, (SOURCE.absolute(), Path(__file__).absolute()))
            return actual_read(path)

        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(q, 'SCHEMA_PACKET', self.root), \
                mock.patch.object(q, 'plugin_identity', side_effect=identity), \
                mock.patch.object(q, 'bounded_client', side_effect=client), \
                mock.patch.object(q, 'read_own', side_effect=own_source_only), \
                mock.patch.object(q, 'observe_plugin', side_effect=AssertionError('NO_PROVENANCE')), \
                mock.patch.object(q, 'diagnose_plugin', side_effect=AssertionError('NO_PROVENANCE')), \
                mock.patch.object(q, 'execute', side_effect=AssertionError('NO_RENDER')), \
                mock.patch.object(q, 'read_provenance', side_effect=AssertionError('NO_PROOF_READ')), \
                mock.patch.object(q, 'metadata_model', side_effect=AssertionError('NO_ADMISSION')), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = q.main(self.args())
        self.assertEqual(stderr.getvalue(), '')
        self.assertLessEqual(len(stdout.getvalue().encode()), 2048)
        return status, json.loads(stdout.getvalue()), launches

    def test_unknown_names_and_all_raw_values_suppressed_no_proof(self):
        metadata = dict(self.metadata, UnknownPublicCanary='PRIVATE_VALUE_CANARY')
        status, receipt, launches = self.observe(q.canonical(metadata))
        self.assertEqual(status, 0)
        self.assertEqual(len(launches), 1)
        self.assertEqual(set(receipt), {'code', 'mode', 'outcome', 'boundary',
                                        'fields', 'unknown_key_count'})
        self.assertEqual(receipt['code'], 'SCHEMA')
        self.assertEqual(receipt['mode'], q.SCHEMA_MODE)
        self.assertEqual(receipt['outcome'], 'SCHEMA')
        self.assertEqual(receipt['boundary'], 'NO_ACTIVATION')
        self.assertEqual(receipt['unknown_key_count'], 1)
        identifiers = [item['field'] for item in receipt['fields']]
        self.assertEqual(identifiers, sorted(identifiers))
        self.assertEqual(set(identifiers), {'SCHEMA_VERSION', 'VENDOR', 'VERSION',
                                           'SHORT_DESCRIPTION', 'URL'})
        forbidden = [b'UnknownPublicCanary', b'PRIVATE_VALUE_CANARY',
                     hashlib.sha256(b'UnknownPublicCanary').hexdigest().encode(),
                     hashlib.sha256(q.canonical(metadata)).hexdigest().encode()]
        for raw in [q.canonical(receipt)] + [p.read_bytes() for p in self.root.rglob('*.json')]:
            for canary in forbidden:
                self.assertNotIn(canary, raw)
        attempt = json.loads((self.root / 'attempt.json').read_bytes())
        self.assertNotIn('environment', attempt)
        self.assertEqual((self.root / 'receipt.json').read_bytes(), q.canonical(receipt))
        self.assertFalse((self.root / 'provenance.json').exists())
        self.forbidden_process.assert_not_called()

    def test_six_exact_type_enums_bool_not_integer_no_nested_names(self):
        for value, name in (('PRIVATE_VALUE_CANARY', 'STRING'), (True, 'BOOLEAN'),
                            (987654321, 'INTEGER'), (None, 'NULL'),
                            ({'NestedSecretName': 'value'}, 'OBJECT'), (['value'], 'ARRAY')):
            receipt = q.public_schema({'Vendor': value})
            self.assertEqual(receipt['fields'], [{'field': 'VENDOR', 'type': name}])
            self.assertEqual(receipt['unknown_key_count'], 0)
            self.assertNotIn('PRIVATE_VALUE_CANARY', str(receipt))
            self.assertNotIn('NestedSecretName', str(receipt))
            self.assertNotIn('987654321', str(receipt))
        self.assertEqual(dict(q.PUBLIC_SCHEMA_FIELDS), {
            'SchemaVersion': 'SCHEMA_VERSION', 'Vendor': 'VENDOR', 'Version': 'VERSION',
            'ShortDescription': 'SHORT_DESCRIPTION', 'URL': 'URL'})
        self.assertEqual(q.public_schema({})['fields'], [])

    def test_unknown_bound_and_known_missing_are_information_not_admission(self):
        metadata = {'PublicField' + str(index): None for index in range(16)}
        receipt = q.public_schema(metadata)
        self.assertEqual(receipt['fields'], [])
        self.assertEqual(receipt['unknown_key_count'], 16)
        subset = dict(self.metadata)
        subset.pop('URL')
        receipt = q.public_schema(subset)
        self.assertNotIn('URL', [item['field'] for item in receipt['fields']])
        self.assertEqual(q.metadata_model(q.canonical(subset)), subset)  #531: URL alone is optional.
        with self.assertRaises(q.Refused):
            q.parse_model(b'{"Vendor":1.5}')  # No relaxed float parser.

    def test_invalid_keys_count_json_and_bytes_refuse_without_text(self):
        cases = [(b'\xff', 'METADATA_JSON'), (b'{"Vendor":1,"Vendor":2}', 'METADATA_JSON'),
                 (b'{"Vendor":NaN}', 'METADATA_JSON'), (b'{"Vendor":1.5}', 'METADATA_JSON'),
                 (b'{"Vendor":"\\ud800"}', 'METADATA_JSON'), (b'[]', 'METADATA_JSON'),
                 (q.canonical({'BadKey' + str(i): 0 for i in range(17)}), 'SCHEMA_KEYS')]
        for key in ('', '_invalid', 'not-valid', 'NonAsciié', 'A' * 65):
            cases.append((q.canonical({key: 'PRIVATE_VALUE_CANARY'}), 'SCHEMA_KEYS'))
        cases.append((b' ' * 4097, 'CLIENT_READ'))
        for index, (raw, gate) in enumerate(cases):
            self.root = self.parent / ('invalid-' + str(index))
            status, receipt, launches = self.observe(raw)
            self.assertEqual(status, 1)
            self.assertEqual(receipt['code'], 'REFUSED')
            self.assertEqual(receipt['mode'], q.SCHEMA_MODE)
            self.assertEqual(receipt['checkpoint'], gate)
            self.assertEqual(len(launches), 1)
            self.assertNotIn('PRIVATE_VALUE_CANARY', q.canonical(receipt).decode())
            self.assertFalse((self.root / 'provenance.json').exists())

    def test_source_and_existing_root_refuse_before_child_no_adoption(self):
        stdout = io.StringIO()
        with mock.patch.object(q, 'Packet') as packet, \
                mock.patch.object(q, 'bounded_client') as client, \
                contextlib.redirect_stdout(stdout):
            args = self.args()
            args[2] = '0' * 64
            self.assertEqual(q.main(args), 1)
        self.assertEqual(json.loads(stdout.getvalue())['checkpoint'], 'SOURCE_PINS')
        packet.assert_not_called()
        client.assert_not_called()
        self.root.mkdir()
        (self.root / 'retain').write_bytes(b'PUBLIC KEEP')
        status, receipt, launches = self.observe(q.canonical(self.metadata))
        self.assertEqual(status, 1)
        self.assertEqual(receipt['checkpoint'], 'ROOT_PREPARE')
        self.assertEqual(launches, [])
        self.assertEqual((self.root / 'retain').read_bytes(), b'PUBLIC KEEP')
        self.assertFalse((self.root / 'receipt.json').exists())

    def test_client_categories_closed_one_child_no_fallback(self):
        for category in ('CLIENT_NONZERO', 'CLIENT_TIMEOUT', 'OUTPUT_CAP', 'STDERR_PRESENT'):
            self.root = self.parent / category
            status, receipt, launches = self.observe(b'PRIVATE_VALUE_CANARY',
                                                    fault=q.Classified(category))
            self.assertEqual(status, 1)
            self.assertEqual(receipt['category'], category)
            self.assertEqual(receipt['checkpoint'], 'CLIENT_EXIT')
            self.assertEqual(len(launches), 1)
            self.assertNotIn('PRIVATE_VALUE_CANARY', str(receipt))

    def test_output_faults_no_second_write_no_query_or_raw_stderr(self):
        for failure in ('write', 'flush'):
            class Writer:
                writes = 0
                flushes = 0
                def write(self, text):
                    self.writes += 1
                    if failure == 'write':
                        raise KeyboardInterrupt('PRIVATE_VALUE_CANARY')
                    return len(text)
                def flush(self):
                    self.flushes += 1
                    raise OSError('PRIVATE_VALUE_CANARY')
            writer, stderr = Writer(), io.StringIO()
            with mock.patch.object(q, 'observe_public_schema',
                                   return_value=q.public_schema(self.metadata)) as operation, \
                    contextlib.redirect_stdout(writer), contextlib.redirect_stderr(stderr):
                self.assertEqual(q.main(self.args()), 1)
                self.assertIsInstance(q.sys.stdout, q.QuietOutput)
                q.sys.stdout.flush()
            self.assertEqual(writer.writes, 1)
            self.assertEqual(writer.flushes, 1 if failure == 'flush' else 0)
            self.assertEqual(stderr.getvalue(), '')
            operation.assert_called_once()
            self.forbidden_process.assert_not_called()


class OptionalMetadataURLTests(InertCase):
    """Determined531 repair only; no actual metadata subprocess or old packet."""
    def test_absent_and_exact_present_url_preserve_metadata(self):
        absent = dict(self.metadata)
        absent.pop('URL')
        self.assertEqual(q.metadata_model(q.canonical(absent)), absent)
        self.assertEqual(q.metadata_model(q.canonical(self.metadata)), self.metadata)
        self.assertNotIn('URL', q.metadata_model(q.canonical(absent)))
        self.assertEqual(q.METADATA_REQUIRED_KEYS,
                         frozenset(('SchemaVersion', 'Vendor', 'Version', 'ShortDescription')))

    def test_present_invalid_url_never_treated_as_absent(self):
        for value in (None, '', False, 0, [], {}, 'http://github.com/docker/compose',
                      'https://github.com/docker/compose/',
                      ' https://github.com/docker/compose', 'PRIVATE_CANARY'):
            with self.subTest(value=value), self.assertRaises(q.Refused):
                q.metadata_model(q.canonical(dict(self.metadata, URL=value)))

    def test_missing_required_extra_keys_and_known_value_rules_stay_closed(self):
        absent = dict(self.metadata)
        absent.pop('URL')
        for missing in q.METADATA_REQUIRED_KEYS:
            value = dict(absent)
            value.pop(missing)
            with self.assertRaises(q.Refused):
                q.metadata_model(q.canonical(value))
        for base in (self.metadata, absent):
            with self.assertRaises(q.Refused):
                q.metadata_model(q.canonical(dict(base, Extra='PRIVATE_CANARY')))
            for key in q.METADATA_REQUIRED_KEYS:
                with self.assertRaises(q.Refused):
                    q.metadata_model(q.canonical(dict(base, **{key: 'PRIVATE_CANARY'})))
        for version in ('2.34.0', '2.34.0-desktop.2', '2.34.1',
                        '2.34.0-desktop.1+build', '2.34.0-desktop.1\n', None, True, []):
            with self.assertRaises(q.Refused):
                q.metadata_model(q.canonical(dict(absent, Version=version)))

    def diagnostic(self, metadata):
        def identity(deadline, diagnostic=None):
            if diagnostic:
                diagnostic.check('PLUGIN_CANONICAL', lambda: None)
            return self.identity

        def client(argv, env, cwd, deadline, output_cap=None, diagnostic=None):
            self.assertEqual(argv, [str(q.PLUGIN), 'docker-cli-plugin-metadata'])
            self.assertEqual(output_cap, 4096)
            diagnostic.check('CLIENT_LAUNCH', lambda: None)
            diagnostic.check('CLIENT_READ', lambda: None)
            diagnostic.check('CLIENT_EXIT', lambda: None)
            return q.canonical(metadata)

        actual_read = q.read_own
        def allowed_read(path):
            self.assertTrue(path in (SOURCE.absolute(), Path(__file__).absolute())
                            or path.is_relative_to(self.root))
            return actual_read(path)

        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(q, 'DIAGNOSTIC_PACKET', self.root), \
                mock.patch.object(q, 'plugin_identity', side_effect=identity), \
                mock.patch.object(q, 'bounded_client', side_effect=client) as query, \
                mock.patch.object(q, 'read_own', side_effect=allowed_read), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = q.main(['--diagnose-public-plugin', '--source-sha256', self.source_pin,
                             '--test-sha256', self.test_pin])
        self.assertEqual(query.call_count, 1)
        self.assertEqual(stderr.getvalue(), '')
        return status, json.loads(stdout.getvalue())

    def test_new_r2_producer_and_consumer_accept_genuine_mock_proof(self):
        self.assertEqual(str(q.DIAGNOSTIC_PACKET),
                         '/private/tmp/dip-compose-plugin-provenance-20261013-diag-r2')
        absent = dict(self.metadata)
        absent.pop('URL')
        for index, metadata in enumerate((absent, self.metadata)):
            self.root = self.parent / ('new-r2-' + str(index))
            status, receipt = self.diagnostic(metadata)
            self.assertEqual(status, 0)
            self.assertEqual(receipt, q.Diagnostic().receipt(success=True))
            raw = (self.root / 'provenance.json').read_bytes()
            pin = hashlib.sha256(raw).hexdigest()
            with mock.patch.object(q, 'DIAGNOSTIC_PACKET', self.root):
                proof = q.read_provenance(pin, self.source_pin, self.test_pin)
            self.assertEqual(proof['producer_root'], str(self.root))
            self.assertEqual(proof['producer_mode'], q.DIAGNOSTIC_MODE)
            self.assertEqual(proof['source_sha256'], self.source_pin)
            self.assertEqual(proof['test_sha256'], self.test_pin)
            self.assertEqual(proof['metadata'], metadata)
            self.assertEqual(proof['historical514_binary_identity'], 'NOT_ESTABLISHED')
        self.forbidden_process.assert_not_called()

    def test_diagnostic_rejects_invalid_url_and_extras_at_exact_gate(self):
        for index, (metadata, gate) in enumerate((
                (dict(self.metadata, URL=None), 'METADATA_URL'),
                (dict(self.metadata, URL='PRIVATE_CANARY'), 'METADATA_URL'),
                (dict(self.metadata, Extra='PRIVATE_CANARY'), 'METADATA_SCHEMA'),
                (dict(self.metadata, Version='2.34.0-desktop.2'), 'METADATA_VERSION'))):
            self.root = self.parent / ('invalid-r2-' + str(index))
            status, receipt = self.diagnostic(metadata)
            self.assertEqual(status, 1)
            self.assertEqual(receipt['checkpoint'], gate)
            self.assertEqual(receipt['category'], 'PREDICATE_REFUSED')
            self.assertFalse((self.root / 'provenance.json').exists())
            self.assertNotIn('PRIVATE_CANARY', q.canonical(receipt).decode())

    def test_consumer_rejects_old_producer_root_even_with_new_pins(self):
        status, _ = self.diagnostic(self.metadata)
        self.assertEqual(status, 0)
        raw = (self.root / 'provenance.json').read_bytes()
        proof = q.parse_model(raw)
        proof['producer_root'] = '/private/tmp/dip-compose-plugin-provenance-20261013-diag-r1'
        raw = q.canonical(proof)
        (self.root / 'provenance.json').write_bytes(raw)
        with mock.patch.object(q, 'DIAGNOSTIC_PACKET', self.root), self.assertRaises(q.Refused):
            q.read_provenance(hashlib.sha256(raw).hexdigest(), self.source_pin, self.test_pin)
        self.forbidden_process.assert_not_called()


class RenderDiagnosticTests(InertCase):
    """NEW selected mocks only; accepted proof is simulated, never reread here."""
    def run_render(self, first=None, second=None, fail_gate=None, fault=None):
        first = q.expected_model() if first is None else first
        second = q.expected_model() if second is None else second
        proof = dict(self.proof, source_sha256=q.ACCEPTED_PRODUCER_SOURCE,
                     test_sha256=q.ACCEPTED_PRODUCER_TEST, producer_mode=q.DIAGNOSTIC_MODE,
                     producer_root=str(q.ACCEPTED_PRODUCER_ROOT))
        calls = []
        original = q.RenderDiagnostic.check
        def check(state, gate, operation, predicate_category='PREDICATE_REFUSED'):
            def thunk():
                if gate == fail_gate:
                    raise fault if fault is not None else OSError('PRIVATE_CANARY')
                return operation()
            return original(state, gate, thunk, predicate_category)
        def client(argv, env, cwd, deadline, output_cap=None, diagnostic=None):
            diagnostic.check('CLIENT_LAUNCH', lambda: calls.append(argv))
            self.assertEqual(argv[-3:], ['config', '--format', 'json'])
            self.assertEqual(env, q.child_env(self.root))
            self.assertEqual(cwd, str(self.root))
            diagnostic.check('CLIENT_READ', lambda: None)
            diagnostic.check('CLIENT_EXIT', lambda: None)
            value = first if len(calls) == 1 else second
            return value if type(value) is bytes else q.canonical(value)
        real_read = q.read_own
        def sources_only(path):
            self.assertIn(path, (SOURCE.absolute(), Path(__file__).absolute()))
            return real_read(path)
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(q, 'RENDER_PACKET', self.root), \
                mock.patch.object(q, 'read_provenance', return_value=proof) as accepted, \
                mock.patch.object(q, 'plugin_identity', return_value=self.identity), \
                mock.patch.object(q.RenderDiagnostic, 'check', check), \
                mock.patch.object(q, 'bounded_client', side_effect=client), \
                mock.patch.object(q, 'read_own', side_effect=sources_only), \
                mock.patch.object(q, 'observe_plugin', side_effect=AssertionError('NO_QUERY')), \
                mock.patch.object(q, 'diagnose_plugin', side_effect=AssertionError('NO_QUERY')), \
                mock.patch.object(q, 'observe_public_schema', side_effect=AssertionError('NO_QUERY')), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = q.main(['--diagnose-public-renders', '--source-sha256', self.source_pin,
                             '--test-sha256', self.test_pin,
                             '--provenance-sha256', q.ACCEPTED_PROOF_SHA256])
        self.assertEqual(stderr.getvalue(), '')
        self.assertNotIn('PRIVATE_CANARY', stdout.getvalue())
        self.assertLessEqual(len(stdout.getvalue().encode()), 2048)
        return status, json.loads(stdout.getvalue()), calls, accepted

    def test_frozen_producer_separate_consumer_two_children_no_metadata(self):
        status, receipt, calls, accepted = self.run_render()
        self.assertEqual(status, 0)
        self.assertEqual(receipt, q.RenderDiagnostic().receipt(success=True))
        self.assertEqual(len(calls), 2)
        accepted.assert_called_once_with(q.ACCEPTED_PROOF_SHA256,
                                        q.ACCEPTED_PRODUCER_SOURCE, q.ACCEPTED_PRODUCER_TEST)
        self.assertEqual(q.ACCEPTED_PRODUCER_SOURCE,
                         '38ad3c71a48284a6d26ef7b9d4c83d9fac630aeaa6f35de11c8f13accab85478')
        self.assertNotEqual(self.source_pin, q.ACCEPTED_PRODUCER_SOURCE)
        attempt = q.parse_model((self.root / 'attempt.json').read_bytes())
        self.assertEqual(attempt['consumer_source_sha256'], self.source_pin)
        self.assertEqual(attempt['consumer_test_sha256'], self.test_pin)
        self.assertEqual(attempt['producer_source_sha256'], q.ACCEPTED_PRODUCER_SOURCE)
        copied = q.parse_model((self.root / 'provenance.json').read_bytes())
        self.assertEqual(copied['source_sha256'], q.ACCEPTED_PRODUCER_SOURCE)
        self.assertEqual(copied['producer_root'], str(q.ACCEPTED_PRODUCER_ROOT))
        for name in ('normalized.json', 'second.json'):
            self.assertEqual((self.root / name).read_bytes(), q.canonical(q.expected_model()))
        self.forbidden_process.assert_not_called()

    def test_oracle_notes_only_fixed_paths_types_and_extra_count(self):
        def paths(value, prefix=''):
            result = {prefix}
            if type(value) is dict:
                for key, item in value.items():
                    result |= paths(item, prefix + '/' + key)
            if type(value) is list:
                for index, item in enumerate(value):
                    result |= paths(item, prefix + '/' + str(index))
            return result
        allowed = paths(q.expected_model())
        cases = []
        value = q.expected_model(); value['services']['probe']['environment']['DOLLAR'] = 'PRIVATE_CANARY'
        cases.append((value, 'VALUE'))
        value = q.expected_model(); value['services']['probe']['read_only'] = 1
        cases.append((value, 'TYPE'))
        value = q.expected_model(); value['services']['probe'].pop('command')
        cases.append((value, 'MISSING'))
        value = q.expected_model()
        value['services']['probe'].update(attach=False, PRIVATE_CANARY='PRIVATE_CANARY')
        cases.append((value, 'EXTRAS'))
        value = q.expected_model(); value['services']['probe']['command'].append('PRIVATE_CANARY')
        cases.append((value, 'LENGTH'))
        for model, kind in cases:
            note = q.oracle_difference(model)
            self.assertIn(note['path'], allowed)
            self.assertEqual(note['kind'], kind)
            self.assertNotIn('PRIVATE_CANARY', q.canonical(note).decode())
            if kind == 'EXTRAS':
                self.assertEqual(note.pop('service_extras'), {'known': [
                    {'field': 'ATTACH', 'type': 'BOOLEAN'}],
                    'known_omitted_count': 0, 'unknown_count': 1})
                with self.assertRaises(q.Refused):
                    q.assert_oracle(model)
            self.assertEqual(set(note), {'path', 'kind', 'expected_type', 'actual_type', 'extra_count'})
        self.assertIsNone(q.oracle_difference(q.expected_model()))

    def test_ipam_struct_exact_and_network_extras_closed(self):
        self.assertEqual(q.expected_model()['networks']['probe_net']['ipam'], {})
        for replacement in (None, {'PRIVATE_CANARY': 'PRIVATE_CANARY'}):
            model = q.expected_model()
            model['networks']['probe_net']['ipam'] = replacement
            with self.assertRaises(q.Refused):
                q.assert_oracle(model)
            self.assertNotIn('PRIVATE_CANARY', q.canonical(q.oracle_difference(model)).decode())
        model = q.expected_model(); del model['networks']['probe_net']['ipam']
        with self.assertRaises(q.Refused):
            q.assert_oracle(model)
        self.assertEqual(q.oracle_difference(model)['kind'], 'MISSING')
        model = q.expected_model()
        model['networks']['probe_net'].update(enable_ipv4=True, labels={}, PRIVATE_CANARY='PRIVATE_CANARY')
        status, receipt, calls, _ = self.run_render(first=model)
        self.assertEqual((status, len(calls)), (1, 1))
        self.assertEqual(receipt['checkpoint'], 'FIRST_ORACLE')
        note = receipt['oracle']
        self.assertEqual((note['path'], note['extra_count']), ('/networks/probe_net', 3))
        self.assertEqual(note['network_extras'], {'known': [
            {'field': 'ENABLE_IPV4', 'type': 'BOOLEAN'},
            {'field': 'LABELS', 'type': 'OBJECT'}], 'unknown_count': 1})
        self.assertNotIn('PRIVATE_CANARY', q.canonical(note).decode())
        self.forbidden_process.assert_not_called()

    def test_first_oracle_and_json_failure_stop_before_second(self):
        changed = q.expected_model()
        changed['services']['probe']['environment']['DOLLAR'] = 'PRIVATE_CANARY'
        status, receipt, calls, _ = self.run_render(first=changed)
        self.assertEqual(status, 1)
        self.assertEqual(receipt['checkpoint'], 'FIRST_ORACLE')
        self.assertEqual(receipt['oracle']['path'], '/services/probe/environment/DOLLAR')
        self.assertEqual(receipt['oracle']['kind'], 'VALUE')
        self.assertEqual(len(calls), 1)
        self.assertFalse((self.root / 'first.json').exists())
        self.assertFalse((self.root / 'normalized.json').exists())
        self.root = self.parent / 'invalid-json'
        status, receipt, calls, _ = self.run_render(first=b'\xffPRIVATE_CANARY')
        self.assertEqual(receipt['checkpoint'], 'FIRST_JSON')
        self.assertEqual(receipt['category'], 'DECODE_REFUSED')
        self.assertIsNone(receipt['oracle'])
        self.assertEqual(len(calls), 1)

    def test_second_equality_failure_has_note_but_no_second_output_file(self):
        changed = q.expected_model()
        changed['services']['probe']['labels']['public.literal'] = 'PRIVATE_CANARY'
        status, receipt, calls, _ = self.run_render(second=changed)
        self.assertEqual(status, 1)
        self.assertEqual(receipt['checkpoint'], 'SECOND_EQUALITY')
        self.assertEqual(receipt['oracle']['path'], '/services/probe/labels/public.literal')
        self.assertEqual(receipt['oracle']['actual_type'], 'STRING')
        self.assertEqual(len(calls), 2)
        self.assertTrue((self.root / 'first.json').exists())
        self.assertFalse((self.root / 'second.json').exists())

    def test_selected_lazy_gates_and_client_categories_first_failure(self):
        cases = [('SOURCE_PINS', 0), ('ACCEPTED_PROOF_PIN', 0), ('ACCEPTED_PROOF_READ', 0),
                 ('INITIAL_IDENTITY', 0), ('ROOT_PREPARE', 0), ('FIXTURE_DURABILITY', 0),
                 ('ATTEMPT_DURABILITY', 0), ('FIRST_CLIENT_LAUNCH', 0),
                 ('FIRST_CLIENT_READ', 1), ('FIRST_DURABILITY', 1),
                 ('NORMALIZED_DURABILITY', 1), ('SECOND_CLIENT_LAUNCH', 1),
                 ('SECOND_CLIENT_EXIT', 2), ('FINAL_IDENTITY', 2), ('RECEIPT_DURABILITY', 2)]
        for index, (gate, count) in enumerate(cases):
            self.root = self.parent / ('gate-' + str(index))
            status, receipt, calls, _ = self.run_render(fail_gate=gate)
            self.assertEqual(status, 1)
            self.assertEqual(receipt['checkpoint'], gate)
            self.assertEqual(receipt['category'], 'IO_FAILED')
            self.assertEqual(len(calls), count)
        for index, category in enumerate(('CLIENT_NONZERO', 'CLIENT_TIMEOUT', 'OUTPUT_CAP', 'STDERR_PRESENT')):
            self.root = self.parent / ('category-' + str(index))
            _, receipt, calls, _ = self.run_render(fail_gate='SECOND_CLIENT_READ',
                                                  fault=q.Classified(category))
            self.assertEqual(receipt['checkpoint'], 'SECOND_CLIENT_READ')
            self.assertEqual(receipt['category'], category)
            self.assertEqual(len(calls), 2)

    def test_existing_root_and_output_failure_stay_closed(self):
        self.root.mkdir()
        (self.root / 'retain').write_bytes(b'KEEP')
        status, receipt, calls, _ = self.run_render()
        self.assertEqual(status, 1)
        self.assertEqual(receipt['checkpoint'], 'ROOT_PREPARE')
        self.assertEqual(calls, [])
        self.assertEqual((self.root / 'retain').read_bytes(), b'KEEP')
        self.assertFalse((self.root / 'receipt.json').exists())
        class Writer:
            writes = 0
            def write(self, text):
                self.writes += 1
                raise KeyboardInterrupt('PRIVATE_CANARY')
            def flush(self):
                raise OSError('PRIVATE_CANARY')
        writer, stderr = Writer(), io.StringIO()
        with mock.patch.object(q, 'diagnose_renders',
                               return_value=q.RenderDiagnostic().receipt(success=True)), \
                contextlib.redirect_stdout(writer), contextlib.redirect_stderr(stderr):
            self.assertEqual(q.main(['--diagnose-public-renders', '--source-sha256', self.source_pin,
                '--test-sha256', self.test_pin, '--provenance-sha256', q.ACCEPTED_PROOF_SHA256]), 1)
            self.assertIsInstance(q.sys.stdout, q.QuietOutput)
            q.sys.stdout.flush()
        self.assertEqual(writer.writes, 1)
        self.assertEqual(stderr.getvalue(), '')

    def test_wrong_frozen_pin_and_root_refuse_without_read_or_query(self):
        with mock.patch.object(q, 'read_provenance') as read:
            with self.assertRaises(q.Refused):
                q.read_accepted_render_proof('0' * 64)
            with mock.patch.object(q, 'DIAGNOSTIC_PACKET', self.parent / 'not-accepted'), self.assertRaises(q.Refused):
                q.read_accepted_render_proof(q.ACCEPTED_PROOF_SHA256)
        read.assert_not_called()
        self.assertEqual(str(q.RENDER_PACKET), '/private/tmp/dip-compose-render-20261013-diag-r5')
        self.forbidden_process.assert_not_called()


if __name__ == '__main__':
    unittest.main()
