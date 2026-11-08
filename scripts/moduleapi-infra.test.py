"""Synthetic secret-bridge qualification: no Docker, real credential, DNS or listeners."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bridge = load('moduleapi_infra_bridge', ROOT / 'scripts/moduleapi-secret-provision.py')
initializer = load('moduleapi_infra_init', ROOT / 'server/deploy/moduleapi-secret-init.py')
IMAGE = 'sha256:' + 'a' * 64
KEY = b'synthetic_moduleapi_not_real_key_1234'
PAYLOAD = b'MODULEAPI_ENABLED=false\nMODULE_API_KEY=' + KEY + b'\n'


def descriptor(image=IMAGE):
    return json.dumps([image, 'linux', bridge.IMAGE_ENTRYPOINT, bridge.IMAGE_COMMAND, '0:0', '/', None, None, 'v1']).encode()


class Fixture:
    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='moduleapi-infra-synthetic-')
        self.home = Path(self.temp.name)
        os.chmod(self.home, 0o700)
        self.directory = self.home / '.diplom-moduleapi'
        self.directory.mkdir(mode=0o700)
        self.file = self.directory / 'server.env'
        self.file.write_bytes(PAYLOAD)
        os.chmod(self.file, 0o600)
        self.account = patch.object(bridge.pwd, 'getpwuid', return_value=types.SimpleNamespace(pw_dir=str(self.home)))
        self.account.start()
        return self

    def __exit__(self, *args):
        self.account.stop()
        self.temp.cleanup()


class FakeEngine:
    def __init__(self, test, collision=False, timeout=False, invalid_image=False, invalid_volume=False):
        self.test = test
        self.calls = []
        self.claim = None
        self.collision = collision
        self.timeout = timeout
        self.invalid_image = invalid_image
        self.invalid_volume = invalid_volume

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        self.test.assertEqual(argv[:3], bridge.DOCKER)
        self.test.assertEqual(set(kwargs['env']), {'HOME', 'PATH'})
        self.test.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
        self.test.assertTrue(kwargs['close_fds'])
        self.test.assertGreater(kwargs['timeout'], 0)
        command = argv[3:]
        output = b''
        if command[:2] == ['image', 'inspect']:
            self.test.assertNotIn('Config.Env', ' '.join(command))
            output = descriptor('sha256:' + 'f' * 64 if self.invalid_image else IMAGE)
        elif command[0] == 'create':
            for flag in ['--pull=never', '--network=none', '--read-only', '--log-driver=none', '--ulimit=core=0:0']:
                self.test.assertIn(flag, command)
            self.test.assertNotIn('type=bind', ' '.join(command))
            self.test.assertNotIn('MODULE_API_KEY', ' '.join(command))
            self.test.assertIn(IMAGE, command)
            if command[2] == bridge.LOCK_NAME:
                self.claim = command[4].split('=')[1]
                output = b'1' * 64
            else:
                self.test.assertEqual(command[2], bridge.INIT_NAME)
                self.test.assertIn('type=volume,src=moduleapi-secrets,dst=/run/moduleapi-secrets,volume-nocopy', command)
                output = b'2' * 64
        elif command[:2] == ['volume', 'ls']:
            output = b'moduleapi-secrets' if self.collision else b''
        elif command[:2] == ['volume', 'inspect']:
            output = json.dumps([{bridge.LABEL: 'v1', bridge.CLAIM_LABEL: self.claim}, 'local',
                                 {} if self.invalid_volume else None]).encode()
        elif command[0] == 'start':
            self.test.assertEqual(command, ['start', '--attach', '--interactive', '2' * 64])
            fd = kwargs['stdin']
            self.test.assertIsInstance(fd, int)
            self.test.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 0)  # Host never read payload.
            if self.timeout:
                raise subprocess.TimeoutExpired('synthetic', 25)
        return subprocess.CompletedProcess(argv, 0, stdout=output)


class SecretBridgeTests(unittest.TestCase):
    def setUp(self):
        # Even an accidentally uninjected run() must never invoke a real engine.
        guard = patch.object(subprocess, 'Popen', side_effect=AssertionError('real subprocess forbidden'))
        guard.start()
        self.addCleanup(guard.stop)

    def test_image_and_command_contract(self):
        bridge.validate_image_descriptor(IMAGE, descriptor())
        for item in [b'{}', b'x' * 4097, descriptor('sha256:' + 'b' * 64)]:
            with self.assertRaises(bridge.Refusal):
                bridge.validate_image_descriptor(IMAGE, item)
        for image in ['python:latest', 'sha256:short', IMAGE.upper()]:
            with self.assertRaises(bridge.Refusal):
                bridge.commands(image, 'b' * 32)
        plan = bridge.commands(IMAGE, 'b' * 32)
        self.assertNotIn('env_file', str(plan))
        self.assertNotIn('openai', str(plan).lower())

    def test_protected_host_fd_no_content_read(self):
        with Fixture() as fixture, patch.object(bridge.os, 'read', side_effect=AssertionError('host read forbidden')):
            directory, fd = bridge.open_source(fixture.home, os.getuid())
            try:
                self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 0)
                self.assertEqual(os.fstat(fd).st_size, len(PAYLOAD))
            finally:
                os.close(fd)
                os.close(directory)

    def test_host_metadata_links_and_fifo_refuse(self):
        for kind in ['mode', 'hardlink', 'symlink', 'fifo', 'directory-mode']:
            with self.subTest(kind=kind), Fixture() as fixture:
                if kind == 'mode':
                    os.chmod(fixture.file, 0o644)
                elif kind == 'hardlink':
                    os.link(fixture.file, fixture.directory / 'second')
                elif kind == 'symlink':
                    fixture.file.rename(fixture.directory / 'other')
                    fixture.file.symlink_to('other')
                elif kind == 'fifo':
                    fixture.file.unlink()
                    os.mkfifo(fixture.file, 0o600)
                else:
                    os.chmod(fixture.directory, 0o755)
                with self.assertRaises(bridge.Refusal):
                    bridge.open_source(fixture.home, os.getuid())

    def test_fake_engine_success_uses_fd_and_immutable_packaged_image(self):
        with Fixture() as fixture, patch.object(bridge.os, 'read', side_effect=AssertionError('host read forbidden')):
            fake = FakeEngine(self)
            bridge.provision(IMAGE, run=fake, source_opener=lambda _home, uid: bridge.open_source(fixture.home, uid))
            commands = [argv[3:] for argv, _ in fake.calls]
            self.assertEqual(commands[-2:], [['rm', '2' * 64], ['rm', '1' * 64]])
            self.assertEqual(sum(command[0] == 'start' for command in commands), 1)
            self.assertEqual(fixture.file.read_bytes(), PAYLOAD)

    def test_replaced_host_source_is_detected_after_fd_transfer_without_payload_read(self):
        with Fixture() as fixture:
            fake = FakeEngine(self)

            def replace_after_start(argv, **kwargs):
                result = fake(argv, **kwargs)
                if argv[3] == 'start':
                    fixture.file.rename(fixture.directory / 'old')
                    fixture.file.write_bytes(PAYLOAD)
                    os.chmod(fixture.file, 0o600)
                return result

            with self.assertRaises(bridge.Refusal) as caught:
                bridge.provision(IMAGE, run=replace_after_start)
            self.assertEqual(caught.exception.code, 77)
            self.assertNotIn(['rm', '1' * 64], [argv[3:] for argv, _ in fake.calls])

    def test_bad_image_refuses_before_opening_host_source(self):
        fake = FakeEngine(self, invalid_image=True)
        with self.assertRaises(bridge.Refusal) as caught:
            bridge.provision(IMAGE, run=fake, source_opener=lambda *_: self.fail('credential open before image check'))
        self.assertEqual(caught.exception.code, 78)
        self.assertEqual(len(fake.calls), 1)

    def test_collisions_volume_identity_and_timeout_hold_without_store_operations(self):
        for kwargs in [{'collision': True}, {'invalid_volume': True}, {'timeout': True}]:
            with self.subTest(kwargs=kwargs), Fixture() as fixture:
                fake = FakeEngine(self, **kwargs)
                with self.assertRaises(bridge.Refusal):
                    bridge.provision(IMAGE, run=fake, source_opener=lambda _home, uid: bridge.open_source(fixture.home, uid))
                commands = [argv[3:] for argv, _ in fake.calls]
                self.assertNotIn(['rm', '1' * 64], commands)  # Lock and volume retained on failure.
                self.assertFalse(any(command[:2] == ['volume', 'rm'] for command in commands))
                if kwargs.get('timeout'):
                    self.assertEqual(commands[-1], ['rm', '--force', '2' * 64])

    def test_each_engine_failure_holds_without_retry_or_unrelated_cleanup(self):
        for phase in ['image', 'lock', 'volumes', 'users', 'volume', 'identity', 'init', 'start', 'remove-init', 'remove-lock']:
            with self.subTest(phase=phase), Fixture() as fixture:
                fake = FakeEngine(self)
                failed = []

                def run(argv, **kwargs):
                    command = argv[3:]
                    key = ('image' if command[:2] == ['image', 'inspect'] else
                           'lock' if command[:3] == ['create', '--name', bridge.LOCK_NAME] else
                           'init' if command[:3] == ['create', '--name', bridge.INIT_NAME] else
                           'volumes' if command[:2] == ['volume', 'ls'] else
                           'users' if command[0] == 'ps' else
                           'volume' if command[:2] == ['volume', 'create'] else
                           'identity' if command[:2] == ['volume', 'inspect'] else
                           'start' if command[0] == 'start' else
                           'remove-init' if command == ['rm', '2' * 64] else
                           'remove-lock' if command == ['rm', '1' * 64] else 'cleanup')
                    if key == phase:
                        failed.append(key)
                        return subprocess.CompletedProcess(argv, 1, stdout=KEY)
                    return fake(argv, **kwargs)

                with self.assertRaises(bridge.Refusal) as caught:
                    bridge.provision(IMAGE, run=run)
                self.assertEqual(caught.exception.code, 74)
                self.assertEqual(failed, [phase])
                commands = [argv[3:] for argv, _ in fake.calls]
                self.assertFalse(any(command[:2] == ['volume', 'rm'] for command in commands))
                self.assertFalse(any(command[0] in ['stop', 'restart', 'build', 'pull', 'exec'] for command in commands))
                if phase != 'remove-lock':
                    self.assertNotIn(['rm', '1' * 64], commands)
                if phase in ['start', 'remove-init']:
                    self.assertEqual(commands[-1], ['rm', '--force', '2' * 64])

    def test_directory_path_replacement_refuses_before_initializer_start(self):
        with Fixture() as fixture:
            fake = FakeEngine(self)

            def replace_directory(argv, **kwargs):
                result = fake(argv, **kwargs)
                if argv[3:6] == ['create', '--name', bridge.INIT_NAME]:
                    fixture.directory.rename(fixture.home / 'retained-original')
                    fixture.directory.mkdir(mode=0o700)
                return result

            with self.assertRaises(bridge.Refusal) as caught:
                bridge.provision(IMAGE, run=replace_directory)
            self.assertEqual(caught.exception.code, 77)
            self.assertFalse(any(argv[3] == 'start' for argv, _ in fake.calls))
            self.assertEqual(fake.calls[-1][0][3:], ['rm', '--force', '2' * 64])

    def test_initializer_partial_write_failure_is_quarantined_and_not_overwritten(self):
        with tempfile.TemporaryDirectory(prefix='moduleapi-infra-partial-') as volume:
            os.chmod(volume, 0o700)
            write = initializer.os.write
            count = 0
            retained = None

            def partial(fd, buffer):
                nonlocal count, retained
                retained = buffer.obj
                count += 1
                if count == 1:
                    return write(fd, buffer[:7])
                raise OSError('synthetic sensitive failure')

            with patch.object(initializer.os, 'write', side_effect=partial), self.assertRaises(OSError):
                initializer.initialize(volume, io.BytesIO(PAYLOAD), owner=(os.getuid(), os.getgid()))
            self.assertTrue(retained and all(byte == 0 for byte in retained))
            target = Path(volume) / 'server.env'
            self.assertEqual(target.read_bytes(), PAYLOAD[:7])
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            with self.assertRaises(initializer.Refusal):
                initializer.initialize(volume, io.BytesIO(PAYLOAD), owner=(os.getuid(), os.getgid()))
            self.assertEqual(target.read_bytes(), PAYLOAD[:7])

    def test_initializer_alarm_and_identity_are_fixed_without_real_signals_or_processes(self):
        for arguments, uid, expected in [([], 0, 64), (['--initialize'], 65532, 77)]:
            with patch.object(initializer.resource, 'setrlimit'), patch.object(initializer.os, 'umask'), \
                    patch.object(initializer.signal, 'signal'), patch.object(initializer.signal, 'alarm') as alarm, \
                    patch.object(initializer.os, 'geteuid', return_value=uid), \
                    patch.object(initializer.os, 'getegid', return_value=uid), \
                    patch.object(initializer, 'initialize') as initialize:
                self.assertEqual(initializer.main(arguments), expected)
                self.assertEqual([call.args[0] for call in alarm.call_args_list], [15, 0])
                initialize.assert_not_called()
        with self.assertRaises(initializer.Refusal) as caught:
            initializer.timeout(None, None)
        self.assertEqual(caught.exception.code, 75)

    def test_plan_is_inert_and_not_activation(self):
        with patch.object(bridge, 'provision', side_effect=AssertionError('must not provision')), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(bridge.main(['--plan', '--image', IMAGE]), 0)
        plan = json.loads(output.getvalue())
        self.assertEqual(plan['activation'], False)
        self.assertEqual(plan['executed'], False)

    def test_initializer_exact_payload_bounds_and_other_provider_refusal(self):
        for length in [16, 512]:
            initializer.validate_payload(b'MODULEAPI_ENABLED=false\nMODULE_API_KEY=' + b'x' * length + b'\n')
        for payload in [PAYLOAD.replace(b'false', b'true'), PAYLOAD + b'EXTRA=1\n', PAYLOAD.replace(b'\n', b'\r\n'),
                        b'OPENAI_ENABLED=false\nOPENAI_API_KEY=' + KEY + b'\n',
                        *[b'MODULEAPI_ENABLED=false\nMODULE_API_KEY=' + b'x' * n + b'\n' for n in [15, 513]]]:
            with self.assertRaises(initializer.Refusal):
                initializer.validate_payload(payload)

    def test_initializer_nonoverwrite_ownership_and_modes_synthetic_only(self):
        with tempfile.TemporaryDirectory(prefix='moduleapi-infra-volume-') as volume:
            os.chmod(volume, 0o700)
            initializer.initialize(volume, io.BytesIO(PAYLOAD), owner=(os.getuid(), os.getgid()))
            path = Path(volume) / 'server.env'
            self.assertEqual(path.read_bytes(), PAYLOAD)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
            self.assertEqual(stat.S_IMODE(Path(volume).stat().st_mode), 0o700)
            with self.assertRaises(initializer.Refusal):
                initializer.initialize(volume, io.BytesIO(PAYLOAD), owner=(os.getuid(), os.getgid()))


if __name__ == '__main__':
    unittest.main()
