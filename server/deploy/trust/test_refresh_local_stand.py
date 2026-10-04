import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('refresh_local_stand', Path(__file__).with_name('refresh-local-stand.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = Path(self.tmp.name) / 'stand.env'
        self.env.write_text('SCAN_JWT_SECRET=unchanged\nSCAN_VULN_RELEASE_HOST_DIR=/old\n'
                            'SCAN_VULN_MANIFEST_DIGEST=sha256:' + 'a' * 64 + '\n'
                            'SCAN_VULN_ARTIFACT_SHA256=' + 'b' * 64 + '\n')
        self.env.chmod(0o600)
        self.original = self.env.read_text()
        self.pin = 'sha256:' + 'c' * 64
        self.updated = module.replace_pins(self.original, Path(self.tmp.name) / 'new', self.pin, 'd' * 64)

    def test_env_keeps_auth_secret_and_rejects_duplicate_or_invalid_pin(self):
        self.assertIn('SCAN_JWT_SECRET=unchanged\n', self.updated)
        self.assertEqual(module.env_values(self.updated)['SCAN_VULN_MANIFEST_DIGEST'], self.pin)
        with self.assertRaises(ValueError):
            module.env_values(self.original + 'SCAN_JWT_SECRET=other\n')
        with self.assertRaises(ValueError):
            module.replace_pins(self.original, Path('relative'), self.pin, 'd' * 64)

    def test_switch_rolls_back_pins_and_recreates_previous_services_on_failed_health(self):
        with patch.object(module, 'ENV', self.env), patch.object(module, 'ROOT', self.env.parent), \
             patch.object(module, 'run', return_value='') as run, \
             patch.object(module, 'healthy', return_value=False), \
             patch.object(module.time, 'sleep'):
            with self.assertRaises(ValueError):
                module.switch(self.original, self.updated, self.pin, 'd' * 64)
        self.assertEqual(self.env.read_text(), self.original)
        self.assertEqual(self.env.stat().st_mode & 0o777, 0o600)
        self.assertEqual(sum('up' in call.args for call in run.call_args_list), 2)

    def test_switch_success_preserves_pins(self):
        with patch.object(module, 'ENV', self.env), patch.object(module, 'ROOT', self.env.parent), \
             patch.object(module, 'run', return_value=''), patch.object(module, 'healthy', return_value=True), \
             patch.object(module, 'container_preflight'), patch.object(module, 'scan_chain_ready'):
            module.switch(self.original, self.updated, self.pin, 'd' * 64)
        self.assertEqual(self.env.read_text(), self.updated)

    def test_container_preflight_failure_restores_pins(self):
        with patch.object(module, 'ENV', self.env), patch.object(module, 'ROOT', self.env.parent), \
             patch.object(module, 'run', return_value='') as run, \
             patch.object(module, 'healthy', return_value=True), \
             patch.object(module, 'container_preflight', side_effect=ValueError('failed')):
            with self.assertRaises(ValueError):
                module.switch(self.original, self.updated, self.pin, 'd' * 64)
        self.assertEqual(self.env.read_text(), self.original)
        self.assertEqual(sum('up' in call.args for call in run.call_args_list), 2)

    def test_scan_chain_failure_rolls_back(self):
        with patch.object(module, 'ENV', self.env), patch.object(module, 'ROOT', self.env.parent), \
             patch.object(module, 'run', return_value='') as run, \
             patch.object(module, 'healthy', return_value=True), \
             patch.object(module, 'container_preflight'), \
             patch.object(module, 'scan_chain_ready', side_effect=ValueError('egress unavailable')):
            with self.assertRaises(ValueError):
                module.switch(self.original, self.updated, self.pin, 'd' * 64)
        self.assertEqual(self.env.read_text(), self.original)
        self.assertEqual(sum('up' in call.args for call in run.call_args_list), 2)

    def test_new_manifest_traverses_pinned_layer_signer_proof_and_switch(self):
        root = Path(self.tmp.name)
        (root / 'trust').mkdir()
        (root / 'trust/db-signing-key.pem').write_text('test private key')
        (root / 'trust/db-signing-key.pem').chmod(0o600)
        (root / 'trivy-db-candidates').mkdir()
        (root / 'trivy-db-releases').mkdir()
        layer = b'compressed fixture'
        layer_hash = 'sha256:' + hashlib.sha256(layer).hexdigest()
        manifest_bytes = json.dumps({'layers': [{'mediaType': 'application/vnd.aquasec.trivy.db.layer.v1.tar+gzip',
                                                  'size': len(layer), 'digest': layer_hash}]}).encode()
        manifest = 'sha256:' + hashlib.sha256(manifest_bytes).hexdigest()
        candidate = root / 'trivy-db-candidates' / manifest
        candidate.mkdir()
        (candidate / 'manifest.json').write_bytes(manifest_bytes)
        (candidate / 'layer.tar.gz').write_bytes(layer)
        calls = []

        def fake_run(*args, **_kwargs):
            calls.append(args)
            if args[-1] == 'discover':
                return 'Review upstream tag :2, then download by digest: ' + manifest + '\n'
            if 'prepare-db-release.py' in ' '.join(map(str, args)):
                release = root / 'trivy-db-releases' / manifest[7:]
                (release / 'db').mkdir(parents=True)
                for name in ('bundle.bin', 'descriptor.json', 'descriptor.sig', 'db/trivy.db', 'db/metadata.json'):
                    (release / name).write_bytes(b'fixture')
                return json.dumps({'manifest': manifest, 'layer': layer_hash,
                                   'bundle': 'd' * 64, 'db': 'e' * 64}) + '\n'
            return ''

        with patch.object(module, 'ROOT', root), patch.object(module, 'ENV', self.env), \
             patch.object(module, 'TRUST', root / 'trust'), patch.object(module, 'run', side_effect=fake_run), \
             patch.object(module, 'switch') as switch:
            module.refresh()
        self.assertEqual(switch.call_args.args[2:], (manifest, 'd' * 64))
        self.assertIn('SCAN_JWT_SECRET=unchanged', switch.call_args.args[1])
        self.assertTrue(any('sign-offline-db.mjs' in ' '.join(map(str, args)) for args in calls))
        self.assertTrue(any('offline_vuln_db_proof.py' in ' '.join(map(str, args)) for args in calls))
        self.assertFalse((root / '.trivy-refresh.lock').exists())

    def test_env_symlink_and_wrong_permissions_are_rejected(self):
        with patch.object(module, 'ENV', self.env), patch.object(module, 'ROOT', self.env.parent):
            self.env.chmod(0o644)
            with self.assertRaises(ValueError):
                module.atomic_env(self.updated)
            self.env.chmod(0o600)
            self.env.unlink()
            self.env.symlink_to(Path(self.tmp.name) / 'other')
            with self.assertRaises(ValueError):
                module.atomic_env(self.updated)


if __name__ == '__main__':
    unittest.main()
