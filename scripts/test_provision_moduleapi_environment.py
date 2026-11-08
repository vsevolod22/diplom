"""Synthetic temp-home tests only; never inspect/provision an operator credential.

Run from diplom:
  python3 -I -B scripts/test_provision_moduleapi_environment.py
"""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import patch
import warnings


SOURCE = Path(__file__).with_name('provision-moduleapi-environment.py')


def load_provisioner():
    spec = importlib.util.spec_from_file_location('moduleapi_provision_test', SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


provisioner = load_provisioner()
KEY = 'synthetic_not_a_real_key_12345'


class ProvisionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.home.chmod(0o700)
        self.destination = self.home / '.diplom-moduleapi'
        self.target = self.destination / 'server.env'
        patches = [
            patch.object(provisioner.pwd, 'getpwuid', return_value=types.SimpleNamespace(pw_dir=str(self.home))),
            patch.object(provisioner.sys.stdin, 'isatty', return_value=True),
            patch.object(provisioner.sys, 'gettrace', return_value=None),
            patch.object(provisioner.sys, 'getprofile', return_value=None),

            patch.object(provisioner.resource, 'setrlimit'),
            patch.object(provisioner.resource, 'getrlimit', return_value=(0, 0)),
            patch.object(provisioner.os, 'umask'),
            patch.object(provisioner.getpass, 'getpass', return_value=KEY),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def run_main(self, argv=None, stderr_tty=True):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                patch.object(err, 'isatty', return_value=stderr_tty):
            result = provisioner.main(['--create'] if argv is None else argv)
        self.output = out.getvalue() + err.getvalue()
        self.assertNotIn(KEY, self.output)
        return result

    def test_exact_disabled_payload_permissions_and_single_prompt(self):
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(self.target.read_bytes(),
                         b'MODULEAPI_ENABLED=false\nMODULE_API_KEY=' + KEY.encode('ascii') + b'\n')
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o700)
        info = self.target.stat()
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(info.st_uid, os.getuid())
        self.assertEqual(info.st_nlink, 1)
        provisioner.getpass.getpass.assert_called_once()
        provisioner.resource.setrlimit.assert_called_once_with(provisioner.resource.RLIMIT_CORE, (0, 0))
        provisioner.os.umask.assert_called_once_with(0o077)
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(provisioner.getpass.getpass.call_count, 1)

    def test_key_length_boundaries(self):
        for length in (16, 512):
            with self.subTest(length=length), patch.object(provisioner.getpass, 'getpass', return_value='z' * length):
                self.assertEqual(self.run_main(), 0)
                self.assertEqual(self.target.stat().st_size, len(provisioner.PREFIX) + length + 1)
                self.target.unlink()

    def test_invalid_input_never_creates_file_or_echoes_input(self):
        for key in ('', 'x' * 15, 'x' * 513, KEY + '\n', KEY + '\r', KEY + '\x00',
                    KEY + ' ', KEY + '=', KEY + '$', KEY + 'é', KEY + '"', KEY + '\\'):
            with self.subTest(length=len(key)), patch.object(provisioner.getpass, 'getpass', return_value=key):
                self.assertEqual(self.run_main(), 1)
                if key:
                    self.assertNotIn(key, self.output)
                self.assertFalse(self.target.exists())

    def test_noninteractive_stdin_or_stderr_refused_before_prompt_or_files(self):
        with patch.object(provisioner.sys.stdin, 'isatty', return_value=False):
            self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.run_main(stderr_tty=False), 1)
        self.assertFalse(self.destination.exists())
        provisioner.getpass.getpass.assert_not_called()

    def test_debug_trace_profile_and_inspect_refused(self):
        for name in ('gettrace', 'getprofile'):
            with patch.object(provisioner.sys, name, return_value=object()):
                self.assertEqual(self.run_main(), 1)
        for name in ('debug', 'inspect'):
            flags = types.SimpleNamespace(**{field: getattr(provisioner.sys.flags, field)
                                             for field in dir(provisioner.sys.flags)
                                             if not field.startswith('_')})
            setattr(flags, name, 1)
            with patch.object(provisioner.sys, 'flags', flags):
                self.assertEqual(self.run_main(), 1)
        provisioner.getpass.getpass.assert_not_called()
        self.assertFalse(self.destination.exists())

    def test_core_dump_disable_failure_or_verification_failure_refused(self):
        with patch.object(provisioner.resource, 'setrlimit', side_effect=OSError(KEY)):
            self.assertEqual(self.run_main(), 1)
        with patch.object(provisioner.resource, 'getrlimit', return_value=(1, 1)):
            self.assertEqual(self.run_main(), 1)
        provisioner.getpass.getpass.assert_not_called()
        self.assertFalse(self.destination.exists())

    def test_getpass_warning_refuses_instead_of_falling_back_to_echo(self):
        def warn(*args):
            warnings.warn(KEY, provisioner.getpass.GetPassWarning)
            return KEY
        with patch.object(provisioner.getpass, 'getpass', side_effect=warn):
            self.assertEqual(self.run_main(), 1)
        self.assertFalse(self.target.exists())

    def test_prompt_interrupt_and_errors_are_sanitized(self):
        for error in (KeyboardInterrupt(), EOFError(KEY), RuntimeError(KEY)):
            with patch.object(provisioner.getpass, 'getpass', side_effect=error):
                self.assertEqual(self.run_main(), 1)
                self.assertFalse(self.target.exists())

    def test_unsafe_home_modes_refused_before_prompt(self):
        for mode in (0o777, 0o770, 0o702):
            self.home.chmod(mode)
            self.assertEqual(self.run_main(), 1)
        provisioner.getpass.getpass.assert_not_called()

    def test_wrong_owner_on_home_or_destination_refused(self):
        self.destination.mkdir(mode=0o700)
        original = os.fstat
        for bad_call in (1, 2):
            calls = 0
            def wrong_owner(fd):
                nonlocal calls
                calls += 1
                value = original(fd)
                if calls == bad_call:
                    return types.SimpleNamespace(st_uid=os.getuid() + 1, st_mode=value.st_mode)
                return value
            with patch.object(provisioner.os, 'fstat', side_effect=wrong_owner):
                self.assertEqual(self.run_main(), 1)
        provisioner.getpass.getpass.assert_not_called()

    def test_directory_symlink_file_and_unsafe_mode_refused(self):
        other = self.home / 'other'
        other.mkdir(mode=0o700)
        self.destination.symlink_to(other, target_is_directory=True)
        self.assertEqual(self.run_main(), 1)
        self.destination.unlink()
        self.destination.write_text('synthetic non-directory')
        self.assertEqual(self.run_main(), 1)
        self.destination.unlink()
        self.destination.mkdir(mode=0o755)
        self.assertEqual(self.run_main(), 1)
        provisioner.getpass.getpass.assert_not_called()

    def test_repository_destination_relative_home_and_home_symlink_refused(self):
        fake_script = self.home / 'scripts' / 'provision.py'
        with patch.object(provisioner, '__file__', str(fake_script)):
            self.assertEqual(self.run_main(), 1)
        linked_home = self.home / 'linked-home'
        linked_home.symlink_to(self.home, target_is_directory=True)
        for home in (str(linked_home), 'relative-account-home'):
            with patch.object(provisioner.pwd, 'getpwuid', return_value=types.SimpleNamespace(pw_dir=home)):
                self.assertEqual(self.run_main(), 1)
        provisioner.getpass.getpass.assert_not_called()

    def test_home_environment_and_credential_environment_are_not_used(self):
        with patch.dict(os.environ, {'HOME': '/unused-synthetic-home', 'MODULE_API_KEY': 'unused_synthetic_value'}):
            self.assertEqual(self.run_main(), 0)
        self.assertEqual(self.target.read_text(), provisioner.PREFIX + KEY + '\n')
        provisioner.getpass.getpass.assert_called_once()

    def test_existing_file_symlinks_hardlinks_and_fifo_are_never_opened(self):
        self.destination.mkdir(mode=0o700)
        existing = self.home / 'synthetic-existing'
        existing.write_text('existing synthetic content')
        factories = (
            lambda: self.target.write_text('existing synthetic content'),
            lambda: self.target.symlink_to(self.home / 'missing'),
            lambda: self.target.symlink_to(existing),
            lambda: os.link(existing, self.target),
            lambda: os.mkfifo(self.target, 0o600),
        )
        original_open = os.open
        def no_target_open(path, *args, **kwargs):
            if path == 'server.env':
                self.fail('existing credential must not be opened')
            return original_open(path, *args, **kwargs)
        for factory in factories:
            factory()
            with patch.object(provisioner.os, 'open', side_effect=no_target_open):
                self.assertEqual(self.run_main(), 1)
            self.target.unlink()
        self.assertEqual(existing.read_text(), 'existing synthetic content')
        provisioner.getpass.getpass.assert_not_called()

    def test_creation_race_cannot_overwrite_or_follow_symlink(self):
        other = self.home / 'synthetic-race-target'
        other.write_text('synthetic unchanged')
        def race(*args):
            self.target.symlink_to(other)
            return KEY
        with patch.object(provisioner.getpass, 'getpass', side_effect=race):
            self.assertEqual(self.run_main(), 1)
        self.assertTrue(self.target.is_symlink())
        self.assertEqual(other.read_text(), 'synthetic unchanged')

    def test_partial_writes_are_completed_and_payload_is_cleared(self):
        original_write = os.write
        buffers = []
        def short_write(fd, data):
            buffers.append(data.obj)
            return original_write(fd, data[:3])
        with patch.object(provisioner.os, 'write', side_effect=short_write):
            self.assertEqual(self.run_main(), 0)
        self.assertEqual(self.target.read_text(), provisioner.PREFIX + KEY + '\n')
        self.assertTrue(buffers)
        self.assertTrue(all(buffer == bytes(len(buffer)) for buffer in buffers))

    def test_write_failure_zero_progress_and_fsync_failure_remove_partial_file(self):
        for error in (OSError(KEY), KeyboardInterrupt()):
            with patch.object(provisioner.os, 'write', side_effect=error):
                self.assertEqual(self.run_main(), 1)
            self.assertFalse(self.target.exists())
        with patch.object(provisioner.os, 'write', return_value=0):
            self.assertEqual(self.run_main(), 1)
        self.assertFalse(self.target.exists())
        for bad_call in (1, 2):
            calls = 0
            def fail_sync(fd):
                nonlocal calls
                calls += 1
                if calls == bad_call:
                    raise OSError(KEY)
            with patch.object(provisioner.os, 'fsync', side_effect=fail_sync):
                self.assertEqual(self.run_main(), 1)
            self.assertFalse(self.target.exists())

    def test_cli_default_help_and_invalid_arguments_are_inert_and_sanitized(self):
        with patch.object(provisioner, 'provision', side_effect=AssertionError('must stay inert')):
            for args in ([], ['--help'], ['-h']):
                self.assertEqual(self.run_main(args), 0)
            for args in ([KEY], ['--key', KEY], ['--create', KEY], ['--cre'],
                         ['--create', '--create'], ['--destination', str(self.home)]):
                self.assertEqual(self.run_main(args), 2)
        self.assertFalse(self.destination.exists())

    def test_import_is_inert(self):
        with patch.object(provisioner.os, 'open', side_effect=AssertionError('no filesystem provisioning')), \
                patch.object(provisioner.pwd, 'getpwuid', side_effect=AssertionError('no account lookup')), \
                patch.object(provisioner.resource, 'setrlimit', side_effect=AssertionError('no process mutation')):
            module = load_provisioner()
        module.getpass.getpass.assert_not_called()
        self.assertFalse(self.destination.exists())


if __name__ == '__main__':
    unittest.main()
