"""Inert local tests: only the new utility and synthetic temporary directories."""

from contextlib import contextmanager
import getpass
import importlib.util
import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "local_key_setter", Path(__file__).with_name("set-openrouter-key.py")
)
setter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setter)
FAKE_KEY = "SYNTHETIC_ONLY_NOT_A_REAL_KEY_12345"


@contextmanager
def sandbox():
    with tempfile.TemporaryDirectory(prefix="openrouter-setter-test-") as directory:
        # macOS /var can itself be a symlink; canonicalize only this controlled sandbox.
        root = Path(directory).resolve()
        fd = setter.open_directory(root)
        try:
            yield root, fd
        finally:
            os.close(fd)


class SetterTests(unittest.TestCase):
    def test_exclusive_creation_only_new_file_and_0600(self):
        with sandbox() as (root, fd):
            previous_umask = os.umask(0o777)
            try:
                setter.install_key(fd, FAKE_KEY)
            finally:
                os.umask(previous_umask)
            target = root / setter.ENV_NAME
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(target.read_bytes(), setter.EMPTY_FILE + f"OPENROUTER_API_KEY={FAKE_KEY}\n".encode())
            self.assertEqual([item.name for item in root.iterdir()], [setter.ENV_NAME])

    def test_canonical_comment_only_file_can_be_filled_once(self):
        with sandbox() as (root, fd):
            target = root / setter.ENV_NAME
            target.write_bytes(setter.EMPTY_FILE)
            target.chmod(0o600)
            original_inode = target.stat().st_ino
            setter.install_key(fd, FAKE_KEY)
            self.assertEqual(target.stat().st_ino, original_inode)
            before = target.read_bytes()
            with self.assertRaises(setter.Refusal):
                setter.install_key(fd, "SYNTHETIC_DIFFERENT_KEY_12345")
            self.assertEqual(target.read_bytes(), before)

    def test_other_content_is_never_overwritten_or_printed(self):
        samples = [b"", b"# another comment\n", b"OPENROUTER_API_KEY=\n",
                   b"OPENROUTER_API_KEY=SYNTHETIC_EXISTING_12345\n",
                   b"X" * len(setter.EMPTY_FILE), setter.EMPTY_FILE + b"\n"]
        for content in samples:
            with self.subTest(size=len(content)), sandbox() as (root, fd):
                target = root / setter.ENV_NAME
                target.write_bytes(content)
                target.chmod(0o600)
                output = io.StringIO()
                with patch("sys.stdout", output), patch("sys.stderr", output):
                    with self.assertRaises(setter.Refusal):
                        setter.install_key(fd, FAKE_KEY)
                self.assertEqual(output.getvalue(), "")
                self.assertEqual(target.read_bytes(), content)

    def test_success_syncs_file_then_parent_directory(self):
        for precreated in (False, True):
            with self.subTest(precreated=precreated), sandbox() as (root, fd):
                if precreated:
                    target = root / setter.ENV_NAME
                    target.write_bytes(setter.EMPTY_FILE)
                    target.chmod(0o600)
                observed = []
                fsync = os.fsync

                def sync(target_fd):
                    observed.append('directory' if stat.S_ISDIR(os.fstat(target_fd).st_mode) else 'file')
                    return fsync(target_fd)

                with patch.object(setter.os, 'fsync', side_effect=sync):
                    setter.install_key(fd, FAKE_KEY)
                self.assertEqual(observed, ['file', 'directory'])

    def test_directory_sync_failure_does_not_report_success_or_print_key(self):
        with sandbox() as (root, fd):
            terminal = io.StringIO()
            terminal.isatty = lambda: True
            fsync = os.fsync

            def sync(target_fd):
                if stat.S_ISDIR(os.fstat(target_fd).st_mode):
                    raise OSError('SYNTHETIC_PRIVATE_DIAGNOSTIC_' + FAKE_KEY)
                return fsync(target_fd)

            with patch('sys.argv', ['setter']), patch('sys.stdin', terminal), \
                    patch('sys.stderr', terminal), patch('sys.stdout', terminal), \
                    patch.object(setter.getpass, 'getpass', side_effect=[FAKE_KEY, FAKE_KEY]), \
                    patch.object(setter, 'open_directory', return_value=os.dup(fd)), \
                    patch.object(setter.os, 'fsync', side_effect=sync):
                self.assertEqual(setter.main(), 1)
            self.assertNotIn(FAKE_KEY, terminal.getvalue())
            self.assertNotIn('Replacement saved', terminal.getvalue())
            self.assertEqual(stat.S_IMODE((root / setter.ENV_NAME).stat().st_mode), 0o600)
            with self.assertRaises(setter.Refusal):
                setter.install_key(fd, FAKE_KEY)

    def test_legacy_envs_untouched(self):
        with sandbox() as (root, fd):
            for name in [".env.local", "stand.env"]:
                (root / name).write_bytes(b"SYNTHETIC_LEGACY_SENTINEL\n")
            setter.install_key(fd, FAKE_KEY)
            for name in [".env.local", "stand.env"]:
                self.assertEqual((root / name).read_bytes(), b"SYNTHETIC_LEGACY_SENTINEL\n")

    def test_invalid_key_does_not_create_anything(self):
        for key in ["", "short", "X" * 513, "X" * 16 + "\n", "X" * 16 + "=", "X" * 16 + "$", "К" * 16]:
            with self.subTest(length=len(key)), sandbox() as (root, fd):
                with self.assertRaises(setter.Refusal):
                    setter.install_key(fd, key)
                self.assertEqual(list(root.iterdir()), [])

    def test_target_symlink_and_dangling_symlink_refused(self):
        for dangling in [False, True]:
            with self.subTest(dangling=dangling), sandbox() as (root, fd):
                other = root / "synthetic-target"
                if not dangling:
                    other.write_bytes(setter.EMPTY_FILE)
                    other.chmod(0o600)
                (root / setter.ENV_NAME).symlink_to(other)
                with self.assertRaises(OSError):
                    setter.install_key(fd, FAKE_KEY)
                if not dangling:
                    self.assertEqual(other.read_bytes(), setter.EMPTY_FILE)
                else:
                    self.assertFalse(other.exists())

    def test_hardlink_refused(self):
        with sandbox() as (root, fd):
            other = root / "synthetic-target"
            other.write_bytes(setter.EMPTY_FILE)
            other.chmod(0o600)
            os.link(other, root / setter.ENV_NAME)
            with self.assertRaises(setter.Refusal):
                setter.install_key(fd, FAKE_KEY)
            self.assertEqual(other.read_bytes(), setter.EMPTY_FILE)

    def test_unsafe_file_permissions_refused(self):
        with sandbox() as (root, fd):
            target = root / setter.ENV_NAME
            target.write_bytes(setter.EMPTY_FILE)
            target.chmod(0o644)
            with self.assertRaises(setter.Refusal):
                setter.install_key(fd, FAKE_KEY)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)
            self.assertEqual(target.read_bytes(), setter.EMPTY_FILE)

    def test_unsafe_directory_refused(self):
        with sandbox() as (root, fd):
            root.chmod(0o777)
            with self.assertRaises(setter.Refusal):
                setter.install_key(fd, FAKE_KEY)
            self.assertEqual(list(root.iterdir()), [])

    def test_directory_and_fifo_targets_refused_without_blocking(self):
        for fifo in [False, True]:
            with self.subTest(fifo=fifo), sandbox() as (root, fd):
                target = root / setter.ENV_NAME
                if fifo:
                    os.mkfifo(target, 0o600)
                else:
                    target.mkdir()
                with self.assertRaises((OSError, setter.Refusal)):
                    setter.install_key(fd, FAKE_KEY)

    def test_directory_components_must_not_be_symlinks(self):
        with sandbox() as (root, _):
            (root / "real").mkdir()
            (root / "link").symlink_to(root / "real", target_is_directory=True)
            for path in [root / "link", root / "link" / "child"]:
                with self.assertRaises(OSError):
                    setter.open_directory(path)

    def test_competing_setter_lock_refused(self):
        with sandbox() as (root, fd):
            target = root / setter.ENV_NAME
            target.write_bytes(setter.EMPTY_FILE)
            target.chmod(0o600)
            held_fd = os.open(target, os.O_RDWR)
            try:
                setter.fcntl.flock(held_fd, setter.fcntl.LOCK_EX | setter.fcntl.LOCK_NB)
                with self.assertRaises(OSError):
                    setter.install_key(fd, FAKE_KEY)
                self.assertEqual(target.read_bytes(), setter.EMPTY_FILE)
            finally:
                os.close(held_fd)

    def test_changed_inode_refused_before_write(self):
        with sandbox() as (root, fd):
            target = root / setter.ENV_NAME
            target.write_bytes(setter.EMPTY_FILE)
            target.chmod(0o600)
            real_stat = os.stat

            def replace_then_stat(*args, **kwargs):
                target.unlink()
                target.write_bytes(b"SYNTHETIC_CONCURRENT_CONTENT\n")
                target.chmod(0o600)
                return real_stat(*args, **kwargs)

            with patch.object(setter.os, "stat", side_effect=replace_then_stat):
                with self.assertRaises(setter.Refusal):
                    setter.install_key(fd, FAKE_KEY)
            self.assertEqual(target.read_bytes(), b"SYNTHETIC_CONCURRENT_CONTENT\n")

    def test_main_refuses_argv_and_noninteractive_input_without_prompt(self):
        for argv in [["setter", "SYNTHETIC_ARGV"], ["setter"]]:
            output = io.StringIO()
            with patch("sys.argv", argv), patch("sys.stdin", io.StringIO()), patch("sys.stderr", output), \
                    patch.object(setter.getpass, "getpass", side_effect=AssertionError("prompt forbidden")):
                self.assertEqual(setter.main(), 1)
            self.assertNotIn("SYNTHETIC_ARGV", output.getvalue())

    def test_getpass_echo_fallback_refused_before_filesystem_access(self):
        terminal = io.StringIO()
        terminal.isatty = lambda: True
        with patch("sys.argv", ["setter"]), patch("sys.stdin", terminal), patch("sys.stderr", terminal), \
                patch.object(setter.getpass, "getpass", side_effect=getpass.GetPassWarning()), \
                patch.object(setter, "open_directory", side_effect=AssertionError("filesystem forbidden")):
            self.assertEqual(setter.main(), 1)

    def test_confirmation_mismatch_refused_before_filesystem_access(self):
        terminal = io.StringIO()
        terminal.isatty = lambda: True
        with patch("sys.argv", ["setter"]), patch("sys.stdin", terminal), patch("sys.stderr", terminal), \
                patch.object(setter.getpass, "getpass", side_effect=[FAKE_KEY, "SYNTHETIC_OTHER_12345"]), \
                patch.object(setter, "open_directory", side_effect=AssertionError("filesystem forbidden")):
            self.assertEqual(setter.main(), 1)
        self.assertNotIn(FAKE_KEY, terminal.getvalue())


if __name__ == "__main__":
    unittest.main()
