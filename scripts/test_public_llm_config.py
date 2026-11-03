import contextlib
import importlib.util
import io
import json
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
        self.assertIn("LLM_MODEL=dots-studio/dots-3-note-preview:free", helper.CONFIG)
        self.assertIn("LLM_PROVIDER_ALLOWLIST=atlas-cloud/fp8", helper.CONFIG)
        self.assertIn("LLM_RETENTION=no-training", helper.CONFIG)
        self.assertIn("LLM_POLICY_REVISION=public-8081-remediation-4k-v1", helper.CONFIG)
        self.assertIn("LLM_OUTPUT_TOKENS=4096\n", helper.CONFIG)
        self.assertIn("LLM_TIMEOUT_MS=90000", helper.CONFIG)
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

    def upgrade(self, verify=lambda: None):
        with mock.patch.object(helper, 'state_path', return_value=self.state):
            helper.upgrade_timeout(self.fd, verify)

    def legacy_config(self, payload=None):
        helper.create_file(self.fd, helper.CONFIG_NAME, payload or helper.LEGACY_CONFIG.encode('ascii'))

    def test_timeout_exact_upgrade_private_original_backup_no_key_access_and_no_retry(self):
        self.legacy_config()
        # A forbidden sentinel; the config upgrade must not even stat the key.
        (self.state / helper.KEY_NAME).symlink_to('/forbidden-public-key')
        opened, stated = helper.os.open, helper.os.stat

        def guarded_open(path, *args, **kwargs):
            self.assertNotIn('openrouter.key', str(path))
            self.assertNotIn('sqlite', str(path))
            self.assertNotIn('scan-jwt', str(path))
            return opened(path, *args, **kwargs)

        def guarded_stat(path, *args, **kwargs):
            self.assertNotIn('openrouter.key', str(path))
            return stated(path, *args, **kwargs)

        with mock.patch.object(helper.os, 'open', side_effect=guarded_open), mock.patch.object(helper.os, 'stat', side_effect=guarded_stat):
            self.upgrade()
        self.assertEqual((self.state / helper.CONFIG_NAME).read_bytes(), helper.XING_CONFIG.encode('ascii'))
        backup = self.state / helper.TIMEOUT_BACKUP
        self.assertEqual(backup.read_bytes(), helper.LEGACY_CONFIG.encode('ascii'))
        self.assertEqual(backup.stat().st_nlink, 1)
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.state / helper.CONFIG_NAME).stat().st_mode), 0o600)
        self.assertFalse((self.state / helper.TIMEOUT_PENDING).exists())
        with self.assertRaises(helper.Refusal):
            self.upgrade()
        self.assertEqual(backup.read_bytes(), helper.LEGACY_CONFIG.encode('ascii'))

    def test_timeout_only_exact_original_source_is_eligible(self):
        for payload in (helper.CONFIG, helper.LEGACY_CONFIG + '# drift\n',
                        helper.LEGACY_CONFIG.replace('phala', 'novita'),
                        helper.LEGACY_CONFIG.replace('LLM_TIMEOUT_MS=30000', 'LLM_TIMEOUT_MS=60000'),
                        helper.LEGACY_CONFIG.replace('LLM_REQUEST_PRICE_USD=0', 'LLM_REQUEST_PRICE_USD=1'),
                        helper.LEGACY_CONFIG.replace('no-storage', 'unknown'),
                        helper.LEGACY_CONFIG + 'OPENROUTER_API_KEY=forbidden\n'):
            with self.subTest(payload=payload):
                self.legacy_config(payload.encode('ascii'))
                with self.assertRaises(helper.Refusal):
                    self.upgrade()
                self.assertFalse((self.state / helper.TIMEOUT_BACKUP).exists())
                self.assertEqual((self.state / helper.CONFIG_NAME).read_text(), payload)
                (self.state / helper.CONFIG_NAME).unlink()

    def test_timeout_file_aliases_nonprivate_and_backup_or_pending_refuse(self):
        self.legacy_config()
        config = self.state / helper.CONFIG_NAME
        config.rename(self.state / 'other')
        config.symlink_to(self.state / 'other')
        with self.assertRaises(helper.Refusal):
            self.upgrade()
        config.unlink()
        os.link(self.state / 'other', config)
        with self.assertRaises(helper.Refusal):
            self.upgrade()
        config.unlink()
        (self.state / 'other').rename(config)
        config.chmod(0o644)
        with self.assertRaises(helper.Refusal):
            self.upgrade()
        config.chmod(0o600)
        for name in (helper.TIMEOUT_BACKUP, helper.TIMEOUT_PENDING):
            (self.state / name).symlink_to('/forbidden-backup')
            with self.assertRaises(helper.Refusal):
                self.upgrade()
            (self.state / name).unlink()
        self.assertEqual(config.read_text(), helper.LEGACY_CONFIG)

    def test_timeout_source_or_lock_fence_failure_does_not_commit(self):
        self.legacy_config()
        calls = 0

        def changed():
            nonlocal calls
            calls += 1
            if calls == 4:  # durable original and pending already exist
                raise helper.Refusal('Synthetic source/lock drift')

        with self.assertRaises(helper.Refusal):
            self.upgrade(changed)
        self.assertEqual((self.state / helper.CONFIG_NAME).read_text(), helper.LEGACY_CONFIG)
        self.assertEqual((self.state / helper.TIMEOUT_BACKUP).read_text(), helper.LEGACY_CONFIG)
        self.assertTrue((self.state / helper.TIMEOUT_PENDING).exists())
        with self.assertRaises(helper.Refusal):
            self.upgrade()

    def test_timeout_exclusive_write_failure_keeps_original_and_partial_backup_for_review(self):
        self.legacy_config()
        with mock.patch.object(helper.os, 'write', return_value=0):
            with self.assertRaises(helper.Refusal):
                self.upgrade()
        self.assertEqual((self.state / helper.CONFIG_NAME).read_text(), helper.LEGACY_CONFIG)
        self.assertTrue((self.state / helper.TIMEOUT_BACKUP).exists())
        with self.assertRaises(helper.Refusal):
            self.upgrade()

    def test_timeout_coordinator_capability_and_source_manifest_are_required(self):
        self.legacy_config()
        helper.fcntl.flock(self.fd, helper.fcntl.LOCK_UN)  # preparation process has finished
        scripts = self.root / 'scripts'
        scripts.mkdir(mode=0o700)
        names = ('public-llm-stand.mjs', 'public-llm-config.py')
        for name in names:
            (scripts / name).write_text('# synthetic reviewed source\n')
        lock_path = self.root / '.local-public-images' / '.operation.lock'
        lock = helper.open_state(lock_path, create=True)
        expected = {name: helper.hashlib.sha256((scripts / name).read_bytes()).hexdigest() for name in names}

        def run(manifest, fd=lock, *, receipt=None, intent=None):
            payload = {'sources': manifest, **({'eligibility': receipt} if receipt is not None else {})}
            stdin = io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode('ascii')))
            with mock.patch.object(helper, '__file__', str(scripts / names[1])), mock.patch.object(helper, 'state_path', return_value=self.state), mock.patch.object(helper.sys, 'stdin', stdin):
                return helper.coordinator_upgrade(fd, intent if intent is not None else self.fd, check_only=receipt is None)

        intent = None
        try:
            with self.assertRaises(helper.Refusal):
                run(expected, self.fd)  # private directory, but not the public lock
            with self.assertRaises(helper.Refusal):
                run({**expected, names[0]: '0' * 64})
            self.assertFalse((self.state / helper.TIMEOUT_BACKUP).exists())
            receipt = run(expected)
            self.assertEqual((self.state / helper.CONFIG_NAME).read_text(), helper.LEGACY_CONFIG)
            self.assertEqual(list(lock_path.iterdir()), [])
            for body in (None, b'{}', helper.MIGRATION_INTENT.replace(b'false', b'true'),
                         helper.MIGRATION_INTENT[:-1] + b',"extra":1}'):
                with self.subTest(body=body):
                    if body is not None:
                        (lock_path / 'mutation.json').write_bytes(body)
                        (lock_path / 'mutation.json').chmod(0o600)
                        intent = os.open(lock_path / 'mutation.json', os.O_RDONLY)
                    with self.assertRaises((helper.Refusal, OSError)):
                        run(expected, receipt=receipt, intent=intent)
                    if intent is not None:
                        os.close(intent)
                        intent = None
                        (lock_path / 'mutation.json').unlink()
                    self.assertFalse((self.state / helper.TIMEOUT_BACKUP).exists())
            (lock_path / 'mutation.json').write_bytes(helper.MIGRATION_INTENT)
            (lock_path / 'mutation.json').chmod(0o600)
            intent = os.open(lock_path / 'mutation.json', os.O_RDONLY)
            (lock_path / 'unexpected').write_text('unrelated HOLD')
            with self.assertRaises(helper.Refusal):
                run(expected, receipt=receipt, intent=intent)
            (lock_path / 'unexpected').unlink()
            real_upgrade = helper.upgrade_timeout

            def drift_before_commit(fd, verify, **kwargs):
                calls = 0

                def changed():
                    nonlocal calls
                    calls += 1
                    if calls == 4:
                        # Even identical intent bytes at a new inode cannot retain authority.
                        replacement = lock_path / 'replacement'
                        replacement.write_bytes(helper.MIGRATION_INTENT)
                        replacement.chmod(0o600)
                        replacement.replace(lock_path / 'mutation.json')
                    verify()

                return real_upgrade(fd, changed, **kwargs)

            with mock.patch.object(helper, 'upgrade_timeout', side_effect=drift_before_commit):
                with self.assertRaises(helper.Refusal):
                    run(expected, receipt=receipt, intent=intent)
            self.assertEqual((self.state / helper.CONFIG_NAME).read_text(), helper.LEGACY_CONFIG)
            self.assertEqual((self.state / helper.TIMEOUT_BACKUP).read_text(), helper.LEGACY_CONFIG)
            self.assertTrue((self.state / helper.TIMEOUT_PENDING).exists())
        finally:
            if intent is not None:
                os.close(intent)
            os.close(lock)

    def test_timeout_postcommit_fsync_failure_retains_original_without_rollback(self):
        self.legacy_config()
        rename = helper.os.rename
        committed = False

        def commit(*args, **kwargs):
            nonlocal committed
            rename(*args, **kwargs)
            committed = True

        sync = helper.os.fsync

        def failed_sync(fd):
            if committed:
                raise OSError('Synthetic durable outcome unknown')
            sync(fd)

        with mock.patch.object(helper.os, 'rename', side_effect=commit), mock.patch.object(helper.os, 'fsync', side_effect=failed_sync):
            with self.assertRaises(OSError):
                self.upgrade()
        self.assertEqual((self.state / helper.CONFIG_NAME).read_text(), helper.XING_CONFIG)
        self.assertEqual((self.state / helper.TIMEOUT_BACKUP).read_text(), helper.LEGACY_CONFIG)
        with self.assertRaises(helper.Refusal):
            self.upgrade()

    def test_timeout_rejects_directory_replacement_and_cooperating_writer(self):
        self.legacy_config()
        self.state.rename(self.state.with_name('original'))
        self.state.mkdir(mode=0o700)
        with self.assertRaises(helper.Refusal):
            self.upgrade()
        original = self.state.with_name('original')
        self.assertEqual((original / helper.CONFIG_NAME).read_text(), helper.LEGACY_CONFIG)
        self.state.rmdir()
        original.rename(self.state)
        helper.fcntl.flock(self.fd, helper.fcntl.LOCK_UN)
        other = os.open(self.state, os.O_RDONLY | os.O_DIRECTORY)
        try:
            helper.fcntl.flock(other, helper.fcntl.LOCK_EX | helper.fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                self.upgrade()
        finally:
            os.close(other)

    def nvidia(self, verify=lambda: None, **kwargs):
        with mock.patch.object(helper, 'state_path', return_value=self.state):
            return helper.migrate_nvidia(self.fd, verify, **kwargs)

    def test_nvidia_exact_xing90_private_backup_and_no_protected_access(self):
        self.legacy_config(helper.XING_CONFIG.encode('ascii'))
        # Existing timeout evidence is unrelated and must survive the new migration.
        evidence = self.state / helper.TIMEOUT_BACKUP
        evidence.write_text(helper.LEGACY_CONFIG)
        for name in (helper.KEY_NAME, 'key-volume.json', 'scan-jwt', 'llm-history.sqlite', 'llm-usage.sqlite'):
            (self.state / name).symlink_to('/forbidden-protected-state')
        opened, stated = helper.os.open, helper.os.stat

        def guarded(operation, path, *args, **kwargs):
            self.assertFalse(any(name in str(path) for name in ('openrouter.key', 'key-volume.json', 'scan-jwt', 'sqlite')))
            return operation(path, *args, **kwargs)

        before = sorted(p.name for p in self.state.iterdir())
        with mock.patch.object(helper.os, 'open', side_effect=lambda p, *a, **k: guarded(opened, p, *a, **k)), \
                mock.patch.object(helper.os, 'stat', side_effect=lambda p, *a, **k: guarded(stated, p, *a, **k)):
            receipt = self.nvidia(check_only=True)
            self.assertEqual(sorted(p.name for p in self.state.iterdir()), before)
            self.nvidia(expected=receipt)
        self.assertEqual((self.state / helper.CONFIG_NAME).read_text(), helper.NVIDIA_CONFIG)
        backup = self.state / helper.NVIDIA_BACKUP
        self.assertEqual(backup.read_text(), helper.XING_CONFIG)
        self.assertLess(backup.stat().st_size, 16384)
        self.assertEqual(backup.stat().st_nlink, 1)
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.state / helper.CONFIG_NAME).stat().st_mode), 0o600)
        self.assertFalse((self.state / helper.NVIDIA_PENDING).exists())
        self.assertEqual(evidence.read_text(), helper.LEGACY_CONFIG)
        with self.assertRaises(helper.Refusal):
            self.nvidia()

    def test_nvidia_refuses_nonexact_prior_and_existing_evidence_before_writes(self):
        for payload in (helper.LEGACY_CONFIG, helper.CONFIG, helper.XING_CONFIG + '# drift\n',
                        helper.XING_CONFIG.replace('phala', 'nvidia'),
                        helper.XING_CONFIG.replace('no-storage', 'no-training'),
                        helper.XING_CONFIG.replace('90000', '90001'),
                        helper.XING_CONFIG + 'OPENROUTER_API_KEY=forbidden\n'):
            self.legacy_config(payload.encode('ascii'))
            with self.assertRaises(helper.Refusal):
                self.nvidia(check_only=True)
            self.assertEqual((self.state / helper.CONFIG_NAME).read_text(), payload)
            self.assertFalse((self.state / helper.NVIDIA_BACKUP).exists())
            (self.state / helper.CONFIG_NAME).unlink()
        self.legacy_config(helper.XING_CONFIG.encode('ascii'))
        for name in (helper.NVIDIA_BACKUP, helper.NVIDIA_PENDING):
            (self.state / name).symlink_to('/forbidden-evidence')
            with self.assertRaises(helper.Refusal):
                self.nvidia()
            (self.state / name).unlink()

    def test_nvidia_source_fence_and_receipt_drift_never_commit_or_retry(self):
        self.legacy_config(helper.XING_CONFIG.encode('ascii'))
        receipt = self.nvidia(check_only=True)
        config = self.state / helper.CONFIG_NAME
        config.rename(self.state / 'old-inode')
        helper.create_file(self.fd, helper.CONFIG_NAME, helper.XING_CONFIG.encode('ascii'))
        with self.assertRaises(helper.Refusal):
            self.nvidia(expected=receipt)
        self.assertFalse((self.state / helper.NVIDIA_BACKUP).exists())
        calls = 0

        def drift():
            nonlocal calls
            calls += 1
            if calls == 4:
                raise helper.Refusal('Synthetic source/lock drift')

        with self.assertRaises(helper.Refusal):
            self.nvidia(drift)
        self.assertEqual(config.read_text(), helper.XING_CONFIG)
        self.assertEqual((self.state / helper.NVIDIA_BACKUP).read_text(), helper.XING_CONFIG)
        self.assertTrue((self.state / helper.NVIDIA_PENDING).exists())
        with self.assertRaises(helper.Refusal):
            self.nvidia()

    def test_nvidia_cli_has_no_direct_migration_or_profile_bypass(self):
        self.legacy_config(helper.XING_CONFIG.encode('ascii'))
        for args in (['--migrate-nvidia'], ['--coordinator-commit-nvidia'],
                     ['--coordinator-check-nvidia'], ['--prepare', '--force']):
            self.assertEqual(self.run_main(args)[0], 1)
        self.assertEqual((self.state / helper.CONFIG_NAME).read_text(), helper.XING_CONFIG)
        self.assertFalse((self.state / helper.NVIDIA_BACKUP).exists())

    def dots(self, verify=lambda: None, **kwargs):
        with mock.patch.object(helper, 'state_path', return_value=self.state):
            return helper.migrate_dots(self.fd, verify, **kwargs)

    def test_dots_exact_nvidia90_private_original_and_no_protected_access(self):
        self.legacy_config(helper.NVIDIA_CONFIG.encode('ascii'))
        for name, text in ((helper.TIMEOUT_BACKUP, helper.LEGACY_CONFIG),
                           (helper.NVIDIA_BACKUP, helper.XING_CONFIG)):
            (self.state / name).write_text(text)
        for name in (helper.KEY_NAME, 'key-volume.json', 'scan-jwt', 'auth.sqlite',
                     'ledger.sqlite', 'llm-history.sqlite', 'llm-usage.sqlite'):
            (self.state / name).symlink_to('/forbidden-protected-state')
        opened, stated = helper.os.open, helper.os.stat

        def guarded(operation, path, *args, **kwargs):
            self.assertFalse(any(name in str(path) for name in ('openrouter.key', 'key-volume.json', 'scan-jwt', 'sqlite')))
            return operation(path, *args, **kwargs)

        before = sorted(p.name for p in self.state.iterdir())
        with mock.patch.object(helper.os, 'open', side_effect=lambda p, *a, **k: guarded(opened, p, *a, **k)), \
                mock.patch.object(helper.os, 'stat', side_effect=lambda p, *a, **k: guarded(stated, p, *a, **k)):
            receipt = self.dots(check_only=True)
            self.assertEqual(sorted(p.name for p in self.state.iterdir()), before)
            self.dots(expected=receipt)
        self.assertEqual((self.state / helper.CONFIG_NAME).read_bytes(), helper.DOTS_CONFIG.encode('ascii'))
        backup = self.state / helper.DOTS_BACKUP
        self.assertEqual(backup.read_bytes(), helper.NVIDIA_CONFIG.encode('ascii'))
        for path in (backup, self.state / helper.CONFIG_NAME):
            self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertFalse((self.state / helper.DOTS_PENDING).exists())
        self.assertEqual((self.state / helper.TIMEOUT_BACKUP).read_text(), helper.LEGACY_CONFIG)
        self.assertEqual((self.state / helper.NVIDIA_BACKUP).read_text(), helper.XING_CONFIG)
        with self.assertRaises(helper.Refusal):
            self.dots()

    def test_dots_refuses_nonexact_prior_and_existing_evidence_before_writes(self):
        for payload in (helper.LEGACY_CONFIG, helper.XING_CONFIG, helper.CONFIG,
                        helper.NVIDIA_CONFIG + '# drift\n', helper.NVIDIA_CONFIG.replace('90000', '30000'),
                        helper.NVIDIA_CONFIG.replace('nvidia\n', 'atlas-cloud/fp8\n'),
                        helper.NVIDIA_CONFIG.replace('no-training', 'no-storage'),
                        helper.NVIDIA_CONFIG + 'OPENROUTER_API_KEY=forbidden\n'):
            self.legacy_config(payload.encode('ascii'))
            with self.assertRaises(helper.Refusal):
                self.dots(check_only=True)
            self.assertEqual((self.state / helper.CONFIG_NAME).read_text(), payload)
            self.assertFalse((self.state / helper.DOTS_BACKUP).exists())
            (self.state / helper.CONFIG_NAME).unlink()
        self.legacy_config(helper.NVIDIA_CONFIG.encode('ascii'))
        for name in (helper.DOTS_BACKUP, helper.DOTS_PENDING):
            (self.state / name).symlink_to('/forbidden-evidence')
            with self.assertRaises(helper.Refusal):
                self.dots()
            (self.state / name).unlink()

    def test_dots_cli_has_no_direct_migration_or_profile_bypass(self):
        self.legacy_config(helper.NVIDIA_CONFIG.encode('ascii'))
        for args in (['--migrate-dots'], ['--coordinator-commit-dots'],
                     ['--coordinator-check-dots'], ['--prepare', '--force']):
            self.assertEqual(self.run_main(args)[0], 1)
        self.assertEqual((self.state / helper.CONFIG_NAME).read_text(), helper.NVIDIA_CONFIG)
        self.assertFalse((self.state / helper.DOTS_BACKUP).exists())

    def report4k(self, verify=lambda: None, **kwargs):
        with mock.patch.object(helper, 'state_path', return_value=self.state):
            return helper.migrate_report4k(self.fd, verify, **kwargs)

    def test_report4k_exact_dots2048_private_original_no_protected_access_or_retry(self):
        self.assertEqual(helper.CONFIG, helper.DOTS_CONFIG.replace(
            'LLM_OUTPUT_TOKENS=2048\n', 'LLM_OUTPUT_TOKENS=4096\n').replace(
            'public-8081-dots-v1', 'public-8081-remediation-4k-v1'))
        for config in (helper.LEGACY_CONFIG, helper.XING_CONFIG, helper.NVIDIA_CONFIG, helper.DOTS_CONFIG):
            self.assertIn('LLM_OUTPUT_TOKENS=2048\n', config)
        self.legacy_config(helper.DOTS_CONFIG.encode('ascii'))
        evidence = {helper.TIMEOUT_BACKUP: helper.LEGACY_CONFIG, helper.NVIDIA_BACKUP: helper.XING_CONFIG,
                    helper.DOTS_BACKUP: helper.NVIDIA_CONFIG}
        for name, text in evidence.items():
            (self.state / name).write_text(text)
        for name in (helper.KEY_NAME, 'key-volume.json', 'scan-jwt', 'auth.sqlite', 'ledger.sqlite',
                     'llm-history.sqlite', 'llm-usage.sqlite'):
            (self.state / name).symlink_to('/forbidden-protected-state')
        opened, stated = helper.os.open, helper.os.stat

        def guarded(operation, path, *args, **kwargs):
            self.assertFalse(any(name in str(path) for name in ('openrouter.key', 'key-volume.json', 'scan-jwt', 'sqlite')))
            return operation(path, *args, **kwargs)

        before = sorted(p.name for p in self.state.iterdir())
        with mock.patch.object(helper.os, 'open', side_effect=lambda p, *a, **k: guarded(opened, p, *a, **k)), \
                mock.patch.object(helper.os, 'stat', side_effect=lambda p, *a, **k: guarded(stated, p, *a, **k)):
            receipt = self.report4k(check_only=True)
            self.assertEqual(sorted(p.name for p in self.state.iterdir()), before)
            self.report4k(expected=receipt)
        self.assertEqual((self.state / helper.CONFIG_NAME).read_text(), helper.CONFIG)
        backup = self.state / helper.REPORT4K_BACKUP
        self.assertEqual(backup.read_text(), helper.DOTS_CONFIG)
        for path in (backup, self.state / helper.CONFIG_NAME):
            self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertFalse((self.state / helper.REPORT4K_PENDING).exists())
        for name, text in evidence.items():
            self.assertEqual((self.state / name).read_text(), text)
        with self.assertRaises(helper.Refusal):
            self.report4k()

    def test_report4k_only_exact_v4_all_fields_and_exclusive_evidence(self):
        payloads = [helper.LEGACY_CONFIG, helper.XING_CONFIG, helper.NVIDIA_CONFIG, helper.CONFIG,
                    helper.DOTS_CONFIG + '# drift\n', helper.DOTS_CONFIG + 'OPENROUTER_API_KEY=forbidden\n']
        payloads.extend(helper.DOTS_CONFIG.replace(line, line + 'changed')
                        for line in helper.DOTS_CONFIG.splitlines() if line and not line.startswith('#'))
        for payload in payloads:
            self.legacy_config(payload.encode('ascii'))
            with self.assertRaises(helper.Refusal):
                self.report4k(check_only=True)
            self.assertEqual((self.state / helper.CONFIG_NAME).read_text(), payload)
            self.assertFalse((self.state / helper.REPORT4K_BACKUP).exists())
            (self.state / helper.CONFIG_NAME).unlink()
        self.legacy_config(helper.DOTS_CONFIG.encode('ascii'))
        for name in (helper.REPORT4K_BACKUP, helper.REPORT4K_PENDING):
            (self.state / name).symlink_to('/forbidden-evidence')
            with self.assertRaises(helper.Refusal):
                self.report4k()
            (self.state / name).unlink()

    def test_report4k_cli_has_no_direct_migration_or_profile_bypass(self):
        self.legacy_config(helper.DOTS_CONFIG.encode('ascii'))
        for args in (['--migrate-report4k'], ['--coordinator-commit-report4k'],
                     ['--coordinator-check-report4k'], ['--prepare', '--force']):
            self.assertEqual(self.run_main(args)[0], 1)
        self.assertEqual((self.state / helper.CONFIG_NAME).read_text(), helper.DOTS_CONFIG)
        self.assertFalse((self.state / helper.REPORT4K_BACKUP).exists())

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
