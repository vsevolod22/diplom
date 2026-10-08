import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import test_stand_composition as fixtures
from stand_composition import select, refresh_lock, write_descriptor_locked, LLM_OVERLAY

spec = importlib.util.spec_from_file_location('free_deploy', Path(__file__).with_name('deploy-openrouter-free.py'))
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


class FreeDeploymentTests(unittest.TestCase):
    # Reuse the disposable composition setup, not LIVE env/volumes/keys.
    setUp = fixtures.CompositionTests.setUp
    def test_secret_metadata_no_symlink_or_group_read_and_no_descriptor_change(self):
        secret = self.repo / 'server/.env.local'
        with refresh_lock(self.root) as capability:
            write_descriptor_locked(self.repo, 'nginx-local', capability)
            before = self.path.read_bytes()
            for mode in (0o644, 0o640, 0o660):
                secret.chmod(mode)
                with self.assertRaises(ValueError): write_descriptor_locked(self.repo, 'nginx-local', capability, llm='openrouter-free')
                self.assertEqual(self.path.read_bytes(), before)
            secret.unlink(); secret.symlink_to(self.env)
            with self.assertRaises(ValueError): write_descriptor_locked(self.repo, 'nginx-local', capability, llm='openrouter-free')
            self.assertEqual(self.path.read_bytes(), before)

    def test_deploy_uses_four_frozen_files_only_selected_services_and_no_model_call(self):
        with refresh_lock(self.root) as capability: write_descriptor_locked(self.repo, 'nginx-local', capability)
        before = self.env.read_bytes()
        calls = []
        def run(command, *args, **kwargs):
            calls.append((command, args))
        with patch.object(deploy, 'run', side_effect=run): deploy.deploy(self.repo)
        self.assertEqual(select(self.repo).llm, 'openrouter-free')
        self.assertEqual(self.env.read_bytes(), before)
        commands = [c for c, _ in calls]
        self.assertTrue(all(c == commands[0] and c.count('-f') == 4 and str(self.repo / LLM_OVERLAY) in c for c in commands))
        self.assertEqual(calls[0][1], ('config', '--quiet'))
        self.assertEqual(calls[1][1], ('build', 'api', 'web', 'llm-egress'))
        self.assertEqual(calls[2][1], ('up', '-d', '--no-build', '--no-deps', '--wait', '--wait-timeout', '90', 'llm-egress', 'api', 'web'))
        self.assertFalse(any('summary' in str(args) or 'down' in args or '--volumes' in args or 'config' in args and '--quiet' not in args for _, args in calls))

    def test_pre_up_failure_restores_descriptor_and_post_up_failure_is_not_fake_rollback(self):
        for fail_stage in ('build', 'up'):
            with refresh_lock(self.root) as capability: write_descriptor_locked(self.repo, 'nginx-local', capability, llm=None)
            def run(command, *args, **kwargs):
                if args[0] == fail_stage: raise ValueError('SYNTHETIC_FAILURE')
            with patch.object(deploy, 'run', side_effect=run), self.assertRaises(ValueError): deploy.deploy(self.repo)
            self.assertEqual(select(self.repo).llm, None if fail_stage == 'build' else 'openrouter-free')
            self.assertFalse((self.root / '.trivy-refresh.lock').exists())


class SourceFenceTests(unittest.TestCase):
    def test_fixed_apodex_profile_revision_and_default_off_approvals(self):
        root = Path(__file__).resolve().parents[1]
        overlay = (root / 'compose.stand.openrouter.free.yaml').read_text()
        for line in ('LLM_MODEL: apodex/apodex-1.1-mini:free',
                     'LLM_PROVIDER_ALLOWLIST: novita/bf16',
                     'LLM_POLICY_REVISION: openrouter-free-apodex-v2',
                     'LLM_RETENTION: ${LLM_RETENTION:-undecided}',
                     'LLM_ENABLED: ${LLM_ENABLED:-false}',
                     'LLM_ROUTING_APPROVED: ${LLM_ROUTING_APPROVED:-false}',
                     'LLM_FREE_ONLY: "true"'):
            self.assertIn(line, overlay)
        for field in ('LLM_REQUEST_BUDGET_USD', 'LLM_INPUT_PRICE_PER_MILLION_USD',
                      'LLM_OUTPUT_PRICE_PER_MILLION_USD', 'LLM_REQUEST_PRICE_USD'):
            self.assertIn(f'{field}: "0"', overlay)
        self.assertNotIn('liquid', overlay)

    def test_key_only_api_and_isolated_llm_egress_and_exact_ingress(self):
        root = Path(__file__).resolve().parents[1]
        overlay = (root / 'compose.stand.openrouter.free.yaml').read_text()
        api = overlay.split('  api:\n', 1)[1].split('networks:\n', 1)[0]
        self.assertIn('env_file:', api); self.assertIn('path: ../.env.local', api)
        self.assertNotIn('env_file:', overlay.split('  api:\n', 1)[0])
        self.assertNotIn('  worker:', overlay); self.assertNotIn('OPENROUTER_API_KEY:', overlay)
        self.assertIn('networks: [llm_internal, llm_uplink]', overlay)
        self.assertIn('llm_internal:\n    internal: true', overlay)
        self.assertNotIn('ports:', overlay); self.assertNotIn('scan_internal', overlay)
        nginx = (root / 'stand.nginx.conf').read_text()
        summary = nginx.split('/llm/summary$" {', 1)[1].split('\n        }', 1)[0]
        self.assertIn('limit_except POST', summary); self.assertIn('client_max_body_size 1k', summary)
        self.assertIn('proxy_read_timeout 35s', summary); self.assertIn('no-store', summary)
        self.assertIn('proxy_set_header Authorization ""', summary)
        self.assertIn('location ^~ /api/ { return 404; }', nginx)


if __name__ == '__main__':
    unittest.main()
