import contextlib
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


helper = load("public_llm_provision", "public-llm-provision.py")
initializer = load("public_llm_key_init", "public-llm-key-init.py")
KEY = b"sk-or-disposable-synthetic-volume-test-123456\n"
IMAGE = "sha256:" + "a" * 64


class PublicLlmProvisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.state = self.root / "llm"
        self.directory = helper.config.open_state(self.state, create=True)
        self.volume = self.root / "volume"
        self.volume.mkdir(mode=0o700)

    def tearDown(self):
        self.volume.chmod(0o700)
        os.close(self.directory)
        self.temp.cleanup()

    def install_source(self):
        helper.config.install_key(self.directory, KEY.decode().strip())
        # The real --set-key process closes its pinned directory before provisioning.
        fcntl.flock(self.directory, fcntl.LOCK_UN)

    def test_initializer_exclusive_durable_single_key_no_alias_or_replacement(self):
        initializer.initialize(self.volume, io.BytesIO(KEY), (os.geteuid(), os.getegid()))
        target = self.volume / initializer.KEY_NAME
        self.assertEqual(target.read_bytes(), KEY)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(self.volume.stat().st_mode), 0o500)
        source = mock.Mock()
        with self.assertRaises(ValueError):
            initializer.initialize(self.volume, source, (os.geteuid(), os.getegid()))
        source.read.assert_not_called()
        self.assertEqual(target.read_bytes(), KEY)
        alias = self.root / "alias"
        alias.symlink_to(self.volume, target_is_directory=True)
        with self.assertRaises(OSError):
            initializer.initialize(alias, io.BytesIO(KEY))

    def test_initializer_default_actual_uid_gid_and_failed_chown_never_succeeds(self):
        self.assertEqual((initializer.UID, initializer.GID), (65532, 65532))
        with mock.patch.object(initializer.os, "fchown", side_effect=OSError("private diagnostic")) as chown:
            with self.assertRaises(OSError):
                initializer.initialize(self.volume, io.BytesIO(KEY))
        self.assertEqual(chown.call_args.args[1:], (65532, 65532))
        with self.assertRaises(ValueError):
            initializer.initialize(self.volume, io.BytesIO(KEY))

    def test_initializer_rejects_malformed_unbounded_input_and_nonempty_destination(self):
        for content in (KEY[:-1], KEY + b"\n", KEY + b"EXTRA", b"OPENROUTER_API_KEY=" + KEY,
                        KEY[:-1] + b"\r\n", b"x" * 514, b"a" * 16 + b"\x00\n"):
            with self.assertRaises(ValueError):
                initializer.initialize(self.volume, io.BytesIO(content))
            self.assertEqual(list(self.volume.iterdir()), [])
        outside = self.root / "outside"
        outside.write_bytes(b"untouched")
        (self.volume / initializer.KEY_NAME).symlink_to(outside)
        with self.assertRaises(ValueError):
            initializer.initialize(self.volume, io.BytesIO(KEY))
        self.assertEqual(outside.read_bytes(), b"untouched")

    def test_command_plan_is_local_pinned_network_none_minimal_and_secret_free(self):
        volume = helper.PREFIX + "b" * 32
        plan = helper.commands(IMAGE, volume, Path("/reviewed/public-llm-key-init.py"))
        wire = json.dumps(plan)
        self.assertNotIn(KEY.decode().strip(), wire)
        self.assertNotIn("openrouter.key", wire)
        self.assertNotIn("--env", wire)
        self.assertNotIn("--tty", wire)
        self.assertNotIn("--privileged", wire)
        self.assertNotIn("--volumes-from", wire)
        for command in plan:
            self.assertEqual(command[:3], ["docker", "--context", "desktop-linux"])
        for flag in ("--network=none", "--pull=never", "--read-only", "--user=0:0", "--cap-drop=ALL",
                     "--cap-add=CHOWN", "--log-driver=none", "--interactive", "--ulimit=core=0:0"):
            self.assertIn(flag, plan[2])
        self.assertEqual(plan[2][-6:], [IMAGE, "-I", "-S", "-B", "/public-llm-key-init.py", "--initialize"])
        for image in ("python:latest", IMAGE + "extra", "--privileged", KEY.decode().strip()):
            with self.assertRaises(helper.config.Refusal):
                helper.commands(image, volume, Path("/reviewed/init.py"))
        with self.assertRaises(helper.config.Refusal):
            helper.commands(IMAGE, "old-holder", Path("/reviewed/init.py"))

    def test_private_fd_stdin_child_output_discarded_nonsecret_receipt_no_second_run(self):
        self.install_source()
        calls = []

        def fake_run(command, **kwargs):
            calls.append(command)
            self.assertNotIn(KEY.decode().strip(), json.dumps(command))
            self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
            self.assertNotIn("OPENROUTER_API_KEY", kwargs["env"])
            self.assertNotIn("DOCKER_HOST", kwargs["env"])
            self.assertEqual(kwargs["timeout"], 45)
            if "run" in command:
                self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
                # Only the private synthetic fake child sees bytes, never tool output.
                with os.fdopen(os.dup(kwargs["stdin"]), "rb") as source:
                    self.assertEqual(source.read(), KEY)
            return subprocess.CompletedProcess(command, 0, stdout=b"")

        with mock.patch.object(helper.config, "state_path", return_value=self.state), mock.patch.object(helper.resource, "setrlimit"):
            volume = helper.provision(IMAGE, run=fake_run)
            receipt = json.loads((self.state / helper.RECEIPT).read_text())
            self.assertEqual(receipt["volume"], volume)
            self.assertEqual(receipt["uid"], 65532)
            self.assertEqual(receipt["gid"], 65532)
            self.assertNotIn(KEY.decode().strip(), json.dumps(receipt))
            self.assertEqual(stat.S_IMODE((self.state / helper.RECEIPT).stat().st_mode), 0o600)
            with self.assertRaises(helper.config.Refusal):
                helper.provision(IMAGE, run=fake_run)
        self.assertEqual(len(calls), 3)
        self.assertEqual((self.state / helper.config.KEY_NAME).read_bytes(), KEY)

    def test_missing_unsafe_or_aliased_source_refuses_before_docker(self):
        fake = mock.Mock()
        with mock.patch.object(helper.config, "state_path", return_value=self.state), mock.patch.object(helper.resource, "setrlimit"):
            with self.assertRaises(helper.config.Refusal):
                helper.provision(IMAGE, run=fake)
            self.install_source()
            source = self.state / helper.config.KEY_NAME
            source.chmod(0o644)
            with self.assertRaises(helper.config.Refusal):
                helper.provision(IMAGE, run=fake)
            source.chmod(0o600)
            os.link(source, self.root / "alias")
            with self.assertRaises(helper.config.Refusal):
                helper.provision(IMAGE, run=fake)
        fake.assert_not_called()

    def test_collision_or_failed_init_never_publishes_receipt_or_retries(self):
        self.install_source()
        for failure in ("collision", "init"):
            calls = []

            def fake_run(command, **kwargs):
                calls.append(command)
                if "run" in command:
                    raise subprocess.CalledProcessError(1, command, output=KEY, stderr=KEY)
                return subprocess.CompletedProcess(command, 0, stdout=KEY if failure == "collision" else b"")

            with mock.patch.object(helper.config, "state_path", return_value=self.state), mock.patch.object(helper.resource, "setrlimit"):
                with self.assertRaises(Exception):
                    helper.provision(IMAGE, run=fake_run)
            self.assertFalse((self.state / helper.RECEIPT).exists())
            self.assertEqual(len(calls), 1 if failure == "collision" else 3)

    def test_plan_and_argument_errors_never_read_key_spawn_docker_or_echo_credentials(self):
        for args, expected in ((["--plan", "--image", IMAGE], 0), (["--provision", "--image", KEY.decode().strip()], 1),
                               (["--plan", "--image", IMAGE, "--key", KEY.decode().strip()], 1)):
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.object(helper.sys, "argv", ["helper", *args]), mock.patch.object(helper.config, "open_state", side_effect=AssertionError()), mock.patch.object(helper.subprocess, "run", side_effect=AssertionError()), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(helper.main(), expected)
            self.assertNotIn(KEY.decode().strip(), stdout.getvalue() + stderr.getvalue())
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(helper.sys, "argv", ["helper", "--provision", "--image", IMAGE]), mock.patch.object(helper, "provision", side_effect=subprocess.CalledProcessError(1, "private", output=KEY, stderr=KEY)), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(helper.main(), 1)
        self.assertNotIn(KEY.decode().strip(), stdout.getvalue() + stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
