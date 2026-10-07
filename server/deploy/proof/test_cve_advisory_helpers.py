"""Focused proof-helper tests; synthetic data, no Docker or LIVE access."""
import ast
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from server.deploy.proof import test_cve_advisory_path as proof
from server.deploy.proof.test_cve_advisory_path import cleanup, core, digest


class ProofHelpers(unittest.TestCase):
    def test_actual_overlay_replaces_values_not_environment_variable_names(self):
        tree = ast.parse(Path(proof.__file__).read_text())
        assignment = next(n for n in ast.walk(tree) if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'template' for t in n.targets))
        code = compile(ast.fix_missing_locations(ast.Module(body=[assignment], type_ignores=[])), proof.__file__, 'exec')
        context = {'json': json, 'PROOF': Path('/synthetic/proof'), 'origin': 'http://127.0.0.1:23456', 'port': 23456}
        exec(code, context)
        overlay = context['template'].replace('{{IDS}}', json.dumps('synthetic-a,synthetic-b'))
        self.assertIn('AUTH_ORIGIN: "http://127.0.0.1:23456"', overlay)
        self.assertIn('SCAN_BROWSER_ALLOWED_USER_IDS: "synthetic-a,synthetic-b"', overlay)
        self.assertIn('127.0.0.1:23456:8080', overlay)
        self.assertNotIn('{{', overlay)

    def test_core_keeps_ids_and_compatibility_but_excludes_optional(self):
        findings = [{'findingId': 'b', 'severity': 'LOW', 'advisory': {'title': 'optional'}}, {'findingId': 'a', 'severity': 'HIGH'}]
        self.assertEqual(core(findings), [{'findingId': 'a', 'severity': 'HIGH'}, {'findingId': 'b', 'severity': 'LOW'}])
        self.assertEqual(core(findings), core([{**f, 'advisory': None} for f in findings]))

    def test_digest_is_mapping_order_independent_not_array_order_independent(self):
        self.assertEqual(digest({'a': 1, 'b': 2}), digest({'b': 2, 'a': 1}))
        self.assertNotEqual(digest(['a', 'b']), digest(['b', 'a']))

    def test_cleanup_targets_exact_composition_only(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / 'own'; directory.mkdir()
            foreign = Path(root) / 'foreign'; foreign.mkdir()
            runner = Mock(return_value=SimpleNamespace(returncode=0))
            result = cleanup(['docker', 'compose', '-p', 'own', '-f', 'own.yaml'], directory, runner=runner)
            runner.assert_called_once_with(['docker', 'compose', '-p', 'own', '-f', 'own.yaml', 'down', '--volumes', '--remove-orphans'], 120)
            self.assertEqual(result, {'exactProjectDown': True, 'fixturesRemoved': True, 'failures': []})
            self.assertTrue(foreign.exists())

    def test_failed_down_retains_mounted_fixtures_and_primary_failure(self):
        for failure in [SimpleNamespace(returncode=1), subprocess.TimeoutExpired('PRIVATE_CANARY', 120)]:
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as root:
                directory = Path(root) / 'own'; directory.mkdir()
                runner = Mock(side_effect=failure) if isinstance(failure, Exception) else Mock(return_value=failure)
                primary = RuntimeError('original scenario failure')
                result = cleanup(['docker', 'compose', '-p', 'own'], directory, primary, runner)
                self.assertTrue(directory.exists()); self.assertFalse(result['exactProjectDown'])
                self.assertNotIn('PRIVATE_CANARY', primary.__notes__[0])
                self.assertIn('mounted fixtures retained', primary.__notes__[0])

    def test_teardown_failure_without_primary_is_safe_and_visible(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / 'own'; directory.mkdir()
            with self.assertRaisesRegex(RuntimeError, 'compose-down') as caught:
                cleanup(['docker', 'compose', '-p', 'own'], directory, runner=Mock(side_effect=OSError('PRIVATE_CANARY')))
            self.assertNotIn('PRIVATE_CANARY', str(caught.exception)); self.assertTrue(directory.exists())


if __name__ == '__main__':
    unittest.main()
