import hashlib
import io
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

    def test_healthy_accepts_running_services_and_ignores_blank_lines(self):
        records = [
            {'Service': 'worker', 'State': 'running'},
            {'Service': 'egress', 'State': 'running'},
            {'Service': 'api', 'State': 'running', 'Health': 'healthy'},
        ]
        output = '\n \t\n' + '\n\n'.join(map(json.dumps, records)) + '\n \n'
        with patch.object(module, 'run', return_value=output) as run:
            self.assertTrue(module.healthy())
        run.assert_called_once_with(*module.COMPOSE, 'ps', '--format', 'json', timeout=45)

    def test_healthy_rejects_missing_or_unready_services(self):
        api = {'Service': 'api', 'State': 'running', 'Health': 'healthy'}
        worker = {'Service': 'worker', 'State': 'running'}
        cases = [[], [api], [worker],
                 [dict(api, Health='unhealthy'), worker],
                 [dict(api, Health='starting'), worker],
                 [dict(api, State='exited'), worker],
                 [api, dict(worker, State='exited')],
                 [api, dict(worker, State='restarting')]]
        for records in cases:
            with self.subTest(records=records), patch.object(
                    module, 'run', return_value='\n'.join(map(json.dumps, records))):
                self.assertFalse(module.healthy())

    def test_healthy_invalid_records_fail_closed(self):
        for output in ('not json', 'null', '[]', '{}'):
            with self.subTest(output=output), patch.object(module, 'run', return_value=output):
                with self.assertRaises((ValueError, TypeError, KeyError)):
                    module.healthy()

    def test_switch_with_real_health_verifies_candidate(self):
        output = '\n'.join(map(json.dumps, [
            {'Service': 'api', 'State': 'running', 'Health': 'healthy'},
            {'Service': 'worker', 'State': 'running'},
        ]))
        with patch.object(module, 'ENV', self.env), patch.object(module, 'ROOT', self.env.parent), \
             patch.object(module, 'run', return_value=output) as run, \
             patch.object(module, 'container_preflight') as preflight, \
             patch.object(module, 'scan_chain_ready') as ready:
            module.switch(self.original, self.updated, self.pin, 'd' * 64)
        self.assertEqual(self.env.read_text(), self.updated)
        self.assertEqual(self.env.stat().st_mode & 0o777, 0o600)
        self.assertEqual(module.env_values(self.env.read_text())['SCAN_JWT_SECRET'], 'unchanged')
        preflight.assert_called_once_with(self.pin, 'd' * 64)
        ready.assert_called_once_with()
        self.assertEqual(sum('up' in call.args for call in run.call_args_list), 1)

    def test_switch_with_real_invalid_health_rolls_back(self):
        with patch.object(module, 'ENV', self.env), patch.object(module, 'ROOT', self.env.parent), \
             patch.object(module, 'run', return_value='not json') as run, \
             patch.object(module, 'container_preflight') as preflight, \
             patch.object(module, 'scan_chain_ready') as ready:
            with self.assertRaises(ValueError):
                module.switch(self.original, self.updated, self.pin, 'd' * 64)
        self.assertEqual(self.env.read_text(), self.original)
        self.assertEqual(self.env.stat().st_mode & 0o777, 0o600)
        preflight.assert_not_called()
        ready.assert_not_called()
        recreate = (*module.COMPOSE, 'up', '-d', '--no-build', '--no-deps',
                    '--force-recreate', 'worker', 'api')
        self.assertEqual(sum(call.args == recreate for call in run.call_args_list), 2)

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

    def test_new_manifest_traverses_pinned_layer_signer_proof_and_switch(self, switch_error=None):
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
             patch.object(module, 'switch', side_effect=switch_error) as switch:
            module.refresh()
        self.assertEqual(switch.call_args.args[2:], (manifest, 'd' * 64))
        self.assertIn('SCAN_JWT_SECRET=unchanged', switch.call_args.args[1])
        self.assertTrue(any('sign-offline-db.mjs' in ' '.join(map(str, args)) for args in calls))
        self.assertTrue(any('offline_vuln_db_proof.py' in ' '.join(map(str, args)) for args in calls))
        self.assertFalse((root / '.trivy-refresh.lock').exists())

    def test_discovery_outage_keeps_verified_active_usable_but_update_error_visible(self):
        root = Path(self.tmp.name)
        (root / 'trivy-db-candidates').mkdir()
        (root / 'trivy-db-releases').mkdir()
        with patch.object(module, 'ROOT', root), patch.object(module, 'ENV', self.env), \
             patch.object(module, 'run', side_effect=ValueError('test registry outage')) as run, \
             patch.object(module, 'verify_active') as active, patch.object(module, 'switch') as switch:
            with self.assertRaisesRegex(ValueError, 'test registry outage'):
                module.refresh_selected()
        active.assert_called_once_with(module.env_values(self.original))
        switch.assert_not_called()
        self.assertEqual(self.env.read_text(), self.original)
        self.assertEqual(len(run.call_args_list), 1)  # no download/sign/proof/recreate

    def test_discovery_outage_does_not_rescue_invalid_active_release(self):
        root = Path(self.tmp.name)
        (root / 'trivy-db-candidates').mkdir()
        (root / 'trivy-db-releases').mkdir()
        with patch.object(module, 'ROOT', root), patch.object(module, 'ENV', self.env), \
             patch.object(module, 'run', side_effect=ValueError('registry outage')), \
             patch.object(module, 'verify_active', side_effect=ValueError('active invalid')):
            with self.assertRaisesRegex(ValueError, 'registry outage'):
                module.refresh_selected()
        self.assertEqual(self.env.read_text(), self.original)

    def test_unchanged_upstream_does_not_require_key_or_re_sign(self):
        root = Path(self.tmp.name)
        (root / 'trivy-db-candidates').mkdir()
        (root / 'trivy-db-releases').mkdir()
        manifest = module.env_values(self.original)['SCAN_VULN_MANIFEST_DIGEST']
        with patch.object(module, 'ROOT', root), patch.object(module, 'ENV', self.env), \
             patch.object(module, 'run', return_value='Review upstream tag :2, then download by digest: ' + manifest + '\n') as run, \
             patch.object(module, 'verify_active') as active, patch.object(module, 'switch') as switch:
            module.refresh_selected()
        active.assert_called_once()
        switch.assert_not_called()
        self.assertEqual(len(run.call_args_list), 1)
        self.assertEqual(self.env.read_text(), self.original)

    def test_R4_every_pre_switch_failure_independently_reports_unchanged_active(self):
        for stage in ('download', 'hash', 'metadata', 'prepare', 'sign', 'verify', 'proof', 'permissions'):
            for active_state in ('usable', 'invalid', 'unready'):
                with self.subTest(stage=stage, active=active_state), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'trust').mkdir()
                    key = root / 'trust/db-signing-key.pem'
                    key.write_bytes(b'SYNTHETIC NON-KEY; subprocess is mocked')
                    key.chmod(0o600)
                    candidates = root / 'trivy-db-candidates'; candidates.mkdir()
                    releases = root / 'trivy-db-releases'; releases.mkdir()
                    active = releases / 'active'; active.mkdir()
                    (active / 'unchanged').write_bytes(b'unchanged active bytes')
                    env = root / 'stand.env'
                    original = module.replace_pins(self.original, active, 'sha256:' + 'a' * 64, 'b' * 64)
                    env.write_text(original)
                    layer = b'compressed fixture'
                    layer_hash = 'sha256:' + hashlib.sha256(layer).hexdigest()
                    data = {'layers': [{'mediaType': 'application/vnd.aquasec.trivy.db.layer.v1.tar+gzip',
                                       'size': len(layer), 'digest': layer_hash}]}
                    if stage == 'metadata': data = {'layers': []}
                    manifest_bytes = json.dumps(data).encode()
                    manifest = 'sha256:' + hashlib.sha256(manifest_bytes).hexdigest()
                    candidate = candidates / manifest
                    if stage != 'download':
                        candidate.mkdir()
                        (candidate / 'manifest.json').write_bytes(manifest_bytes)
                        (candidate / 'layer.tar.gz').write_bytes(b'wrong bytes' if stage == 'hash' else layer)
                    release = releases / manifest[7:]
                    calls = []
                    update_error = ValueError('synthetic candidate failure')
                    receipt = json.dumps({'identity': {'updatedAt': '2026-10-01T12:00:00.000Z'},
                                          'warnings': ['DB_PUBLICATION_OVERDUE']})

                    def fake_run(*args, **kwargs):
                        calls.append(args)
                        self.assertGreater(kwargs.get('timeout', 0), 0)
                        if args[-1] == 'discover':
                            return 'Review upstream tag :2, then download by digest: ' + manifest + '\n'
                        if str(active) in args:
                            if active_state == 'invalid': raise ValueError('synthetic active invalid')
                            return receipt
                        if args[0] == 'node' and args[2] == manifest: raise update_error
                        command = ' '.join(map(str, args))
                        if 'prepare-db-release.py' in command:
                            if stage == 'prepare': raise update_error
                            (release / 'db').mkdir(parents=True)
                            for name in ('bundle.bin', 'descriptor.json', 'descriptor.sig', 'db/trivy.db', 'db/metadata.json'):
                                (release / name).write_bytes(b'synthetic candidate')
                            return json.dumps({'manifest': manifest, 'layer': layer_hash, 'bundle': 'd' * 64, 'db': 'e' * 64}) + '\n'
                        if ((stage == 'sign' and 'sign-offline-db.mjs' in command) or
                            (stage == 'verify' and 'verify-vuln-db-release.ts' in command) or
                            (stage == 'proof' and 'offline_vuln_db_proof.py' in command)):
                            raise update_error
                        if stage == 'permissions' and 'offline_vuln_db_proof.py' in command:
                            (release / 'descriptor.sig').unlink()  # chmod validation fails before switch
                        return ''

                    stdout, stderr = io.StringIO(), io.StringIO()
                    with patch.object(module, 'ROOT', root), patch.object(module, 'ENV', env), \
                         patch.object(module, 'TRUST', root / 'trust'), patch.object(module, 'run', side_effect=fake_run), \
                         patch.object(module, 'container_preflight') as preflight, \
                         patch.object(module, 'scan_chain_ready', side_effect=ValueError('synthetic unready') if active_state == 'unready' else None) as ready, \
                         patch.object(module, 'switch') as switch, patch.object(module.sys, 'stdout', stdout), patch.object(module.sys, 'stderr', stderr):
                        with self.assertRaises((OSError, ValueError, KeyError, IndexError, TypeError)) as raised:
                            module.refresh_selected()
                    if stage in ('download', 'prepare', 'sign', 'verify', 'proof'):
                        self.assertIs(raised.exception, update_error)  # active failure never masks update error
                    self.assertEqual(sum(str(active) in args for args in calls), 1)
                    switch.assert_not_called()
                    self.assertEqual(env.read_text(), original)
                    self.assertEqual((active / 'unchanged').read_bytes(), b'unchanged active bytes')
                    if active_state == 'usable':
                        self.assertIn(receipt, stdout.getvalue())
                        self.assertIn('remains usable', stderr.getvalue())
                        preflight.assert_called_once_with('sha256:' + 'a' * 64, 'b' * 64)
                        ready.assert_called_once()
                    else:
                        self.assertNotIn('remains usable', stderr.getvalue())
                        self.assertIn('usability/readiness not verified', stderr.getvalue())
                        if active_state == 'invalid': preflight.assert_not_called(); ready.assert_not_called()

    def test_R4_switch_failure_is_not_reported_as_unchanged_active(self):
        # The success fixture covers every candidate stage. A failure from switch
        # must remain outside the pre-switch active-usability handler.
        with patch.object(module, 'verify_active') as active:
            with self.assertRaisesRegex(ValueError, 'synthetic switch failed'):
                self.test_new_manifest_traverses_pinned_layer_signer_proof_and_switch(ValueError('synthetic switch failed'))
        active.assert_not_called()

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
