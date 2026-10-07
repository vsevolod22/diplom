import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
from stand_composition import BASES, OVERLAY, refresh_lock, select, write_descriptor_locked
spec = importlib.util.spec_from_file_location('composition_refresh', Path(__file__).with_name('refresh-local-stand.py'))
refresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(refresh)


class CompositionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.root = self.repo / '.local-auth'
        self.root.mkdir(mode=0o700)
        self.path = self.root / 'stand-composition.json'
        self.env = self.root / 'stand.env'
        self.env.write_text('SCAN_JWT_SECRET=unchanged\nSCAN_VULN_RELEASE_HOST_DIR=/old\nSCAN_VULN_MANIFEST_DIGEST=sha256:' + 'a'*64 + '\nSCAN_VULN_ARTIFACT_SHA256=' + 'b'*64 + '\n')
        self.env.chmod(0o600)
        for relative in (*BASES, OVERLAY):
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('services: {}\n')
            path.chmod(0o600)

    def test_default_fixed_local_and_atomic_capability(self):
        before = self.env.read_bytes()
        self.assertEqual(select(self.repo).files, BASES)
        with refresh_lock(self.root) as capability:
            self.assertIsNone(write_descriptor_locked(self.repo, 'nginx-local', capability))
            selected = select(self.repo)
            self.assertEqual(selected.files, (*BASES, OVERLAY))
            self.assertEqual(selected.command.count('-f'), 3)
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
            previous = write_descriptor_locked(self.repo, 'default', capability)
            self.assertEqual(json.loads(previous)['profile'], 'nginx-local')
            self.assertEqual(selected.files, (*BASES, OVERLAY))  # frozen snapshot
        with self.assertRaises(ValueError):
            write_descriptor_locked(self.repo, 'nginx-local', capability)
        self.assertEqual(self.env.read_bytes(), before)

    def test_foreign_lock_and_forged_capability_cannot_write(self):
        with refresh_lock(self.root):
            with self.assertRaises(FileExistsError):
                with refresh_lock(self.root):
                    self.fail('lock reused')
            with self.assertRaises(ValueError):
                write_descriptor_locked(self.repo, 'nginx-local', object())
            self.assertFalse(self.path.exists())
        self.assertFalse((self.root / '.trivy-refresh.lock').exists())

    def test_malformed_unknown_duplicate_writable_symlink_fail_closed(self):
        for text in ('null', '[]', '{}', '{"profile":"evil"}', '{"profile":"default","command":"x"}',
                     '{"profile":"nginx-local","overlay":"/tmp/evil"}', '{"profile":"default","overlay":"x"}',
                     '{"profile":"default","profile":"nginx-local"}', 'x'*1025):
            self.path.write_text(text)
            self.path.chmod(0o600)
            with self.subTest(text=text[:70]), self.assertRaises(ValueError):
                select(self.repo)
        self.path.write_text('{"profile":"default"}')
        self.path.chmod(0o666)
        with self.assertRaises(ValueError): select(self.repo)
        self.path.unlink()
        self.path.symlink_to(self.root / 'absent')
        with self.assertRaises((ValueError, OSError)): select(self.repo)
        self.path.unlink()
        self.path.symlink_to(self.env)
        with self.assertRaises(OSError): select(self.repo)

    def test_overlay_symlink_and_group_writable_are_not_accepted(self):
        with refresh_lock(self.root) as capability:
            write_descriptor_locked(self.repo, 'nginx-local', capability)
        overlay = self.repo / OVERLAY
        overlay.chmod(0o666)
        with self.assertRaises(ValueError): select(self.repo)
        overlay.unlink()
        overlay.symlink_to(self.repo / BASES[0])
        with self.assertRaises(ValueError): select(self.repo)

    def test_refresh_freezes_selected_composition_through_failed_switch_and_rollback(self):
        with refresh_lock(self.root) as capability:
            write_descriptor_locked(self.repo, 'nginx-local', capability)
        original = self.env.read_text()
        updated = refresh.replace_pins(original, self.repo / 'new', 'sha256:' + 'c'*64, 'd'*64)
        calls = []
        def selected_refresh():
            self.assertEqual(refresh.COMPOSE.count('-f'), 3)
            # Even if another operator overwrites the file outside our lock, the
            # in-flight switch/verification/rollback never re-selects entrypoints.
            self.path.write_text('{"profile":"default"}')
            refresh.switch(original, updated, 'sha256:' + 'c'*64, 'd'*64)
        def run(*args, **kwargs):
            calls.append(args)
            return ''
        previous = refresh.COMPOSE
        with patch.object(refresh, 'REPO', self.repo), patch.object(refresh, 'ROOT', self.root), patch.object(refresh, 'ENV', self.env), \
             patch.object(refresh, 'refresh_selected', side_effect=selected_refresh), patch.object(refresh, 'run', side_effect=run), \
             patch.object(refresh, 'healthy', return_value=True), patch.object(refresh, 'container_preflight', side_effect=ValueError('candidate invalid')):
            with self.assertRaises(ValueError): refresh.refresh()
        self.assertIs(refresh.COMPOSE, previous)
        self.assertEqual(self.env.read_text(), original)
        recreate = [args for args in calls if 'up' in args]
        self.assertEqual(len(recreate), 2)
        self.assertTrue(all(str(self.repo / OVERLAY) in args and args.count('-f') == 3 for args in recreate))
        self.assertFalse((self.root / '.trivy-refresh.lock').exists())

    def test_readiness_requires_local_marker_only_for_selected_overlay(self):
        for profile in ('default', 'nginx-local'):
            with refresh_lock(self.root) as capability:
                write_descriptor_locked(self.repo, profile, capability)
            with patch.object(refresh, 'REPO', self.repo), patch.object(refresh, 'COMPOSE', list(select(self.repo).command)), patch.object(refresh, 'run') as run:
                refresh.scan_chain_ready()
                program = run.call_args.args[-1]
                self.assertEqual('localWorkerReady()' in program, profile == 'nginx-local')
                self.assertIn('chainReady()', program)


if __name__ == '__main__':
    unittest.main()
