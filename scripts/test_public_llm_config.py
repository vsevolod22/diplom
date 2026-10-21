import contextlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("public_llm_config", Path(__file__).with_name("public-llm-config.py"))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
KEY = "sk-or-disposable-synthetic-public-test-123456"


class PublicLlmConfigTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.state = self.root / "public" / "llm"
        self.fd = helper.open_state(self.state, create=True)

    def tearDown(self):
        os.close(self.fd)
        self.temporary.cleanup()

    def run_main(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(helper, "state_path", return_value=self.state), mock.patch.object(helper.sys, "argv", ["public-llm-config.py", *args]), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = helper.main()
        output = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn(KEY, output)
        return code, output

    def test_fixed_nonsecret_config_and_private_exclusive_files(self):
        code, output = self.run_main(["--prepare"])
        self.assertEqual(code, 0)
        self.assertIn("No activation", output)
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        config = self.state / helper.CONFIG_NAME
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
        self.assertEqual(config.read_text(), helper.CONFIG)
        self.assertNotIn("OPENROUTER_API_KEY=", helper.CONFIG)
        self.assertNotIn(".local-stand", helper.CONFIG)
        self.assertNotIn(".local-auth", helper.CONFIG)
        self.assertIn("LLM_MODEL=xingchen-agi/xing4.0-29b-a4b:free", helper.CONFIG)
        self.assertIn("LLM_PROVIDER_ALLOWLIST=phala", helper.CONFIG)
        self.assertEqual(self.run_main(["--prepare"])[0], 1)
        helper.install_key(self.fd, KEY)
        key = self.state / helper.KEY_NAME
        self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
        self.assertEqual(key.read_bytes(), (KEY + "\n").encode())
        with self.assertRaises(FileExistsError):
            helper.install_key(self.fd, KEY + "changed")
        self.assertEqual(key.read_bytes(), (KEY + "\n").encode())

    def test_status_is_boolean_metadata_only(self):
        helper.install_key(self.fd, KEY)
        with mock.patch.object(helper.os, "open", side_effect=AssertionError("status must not open existing key")):
            self.assertTrue(helper.present(self.fd, helper.KEY_NAME))
            self.assertFalse(helper.present(self.fd, helper.CONFIG_NAME))
        code, output = self.run_main(["--status"])
        self.assertEqual(code, 0)
        self.assertIn("public key present: true", output)

    def test_no_argv_or_piped_credentials(self):
        for args in (["--set-key", KEY], [KEY], ["--key=" + KEY], []):
            self.assertEqual(self.run_main(args)[0], 1)
        self.assertEqual(self.run_main(["--set-key"])[0], 1)
        self.assertFalse(helper.present(self.fd, helper.KEY_NAME))

    def test_unsafe_format_and_file_aliases_refused_without_overwrite(self):
        for key in ("short", KEY + "\n", KEY + "=x", KEY + "\nOTHER=value", "п" * 32):
            with self.assertRaises(helper.Refusal):
                helper.install_key(self.fd, key)
        target = self.root / "existing"
        target.write_text("untouched")
        os.symlink(target, self.state / helper.KEY_NAME)
        with self.assertRaises(OSError):
            helper.install_key(self.fd, KEY)
        with self.assertRaises(helper.Refusal):
            helper.present(self.fd, helper.KEY_NAME)
        self.assertEqual(target.read_text(), "untouched")
        (self.state / helper.KEY_NAME).unlink()
        os.link(target, self.state / helper.KEY_NAME)
        with self.assertRaises(helper.Refusal):
            helper.present(self.fd, helper.KEY_NAME)
        with self.assertRaises(OSError):
            helper.install_key(self.fd, KEY)

    def test_symlinked_or_nonprivate_state_refused(self):
        alias = self.root / "alias"
        alias.symlink_to(self.state, target_is_directory=True)
        with self.assertRaises(OSError):
            helper.open_state(alias)
        self.state.chmod(0o755)
        with self.assertRaises(helper.Refusal):
            helper.open_state(self.state)

    def test_hidden_confirmation_and_getpass_fallback(self):
        for values, expected in (([KEY, KEY], 0), ([KEY, KEY + "different"], 1)):
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.object(helper, "state_path", return_value=self.state), mock.patch.object(helper.sys, "argv", ["helper", "--set-key"]), mock.patch.object(helper.sys.stdin, "isatty", return_value=True), mock.patch.object(stderr, "isatty", return_value=True), mock.patch.object(helper.getpass, "getpass", side_effect=values), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(helper.main(), expected)
            self.assertNotIn(KEY, stdout.getvalue() + stderr.getvalue())
        (self.state / helper.KEY_NAME).unlink()
        with mock.patch.object(helper, "state_path", return_value=self.state), mock.patch.object(helper.sys, "argv", ["helper", "--set-key"]), mock.patch.object(helper.sys.stdin, "isatty", return_value=True), mock.patch.object(helper.sys.stderr, "isatty", return_value=True), mock.patch.object(helper.getpass, "getpass", side_effect=helper.getpass.GetPassWarning()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(helper.main(), 1)
        self.assertFalse(helper.present(self.fd, helper.KEY_NAME))


if __name__ == "__main__":
    unittest.main()
