"""Synthetic protected nonsecret config preparation. Never opens operator state."""
import contextlib
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

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('moduleapi_source_config', ROOT / 'scripts/public-llm-config.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def fixture():
    # Import only a pure synthetic fixture, not installed descriptor/private ENV.
    result = subprocess.run(['node', '--input-type=module', '-e',
                             "import {syntheticModuleApiDeployment} from './scripts/moduleapi-source.fixture.mjs';"
                             "process.stdout.write(JSON.stringify(syntheticModuleApiDeployment()));"],
                            cwd=ROOT, capture_output=True, timeout=10, check=True,
                            env={'PATH': '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin'})
    return result.stdout


class ModuleApiConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = fixture()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='moduleapi-config-')
        self.home = Path(self.temp.name).resolve()
        self.state = self.home / 'state' / 'llm'
        fd = helper.open_state(self.state, create=True)
        os.close(fd)

    def tearDown(self):
        self.temp.cleanup()

    def prepare(self, payload=None, args=None):
        output, error = io.StringIO(), io.StringIO()
        stdin = io.TextIOWrapper(io.BytesIO(self.payload if payload is None else payload), encoding='utf8')
        with mock.patch.object(helper, 'state_path', return_value=self.state), \
                mock.patch.object(helper.sys, 'stdin', stdin), \
                mock.patch.object(helper.sys, 'argv', ['public-llm-config.py', *(args or ['--prepare-moduleapi'])]), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            code = helper.main()
        text = output.getvalue() + error.getvalue()
        self.assertNotIn('synthetic-moduleapi-policy', text)
        self.assertNotIn(str(self.home), text)
        return code, text

    def test_actual_validator_produces_exclusive_private_descriptor(self):
        code, text = self.prepare()
        self.assertEqual(code, 0, text)
        self.assertIn('nonsecret v7 descriptor prepared', text)
        destination = self.state / helper.MODULEAPI_CONFIG_NAME
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        self.assertEqual(json.loads(destination.read_bytes()), json.loads(self.payload))
        original = destination.read_bytes()
        self.assertEqual(self.prepare()[0], 1)
        self.assertEqual(destination.read_bytes(), original)
        self.assertEqual(sorted(p.name for p in self.state.iterdir()), ['moduleapi-deployment.json'])

    def test_bad_descriptors_never_create_or_print_values(self):
        missing_rate = json.loads(self.payload)
        del missing_rate['environment']['MODULEAPI_INPUT_PRICE_MICROS_PER_MILLION']
        secret = json.loads(self.payload)
        secret['environment']['MODULE_API_KEY'] = 'synthetic-value-never-installed'
        wrong_quota = json.loads(self.payload)
        wrong_quota['environment']['LLM_QUOTA_LIFETIME_USER_COST_MICROS'] = '1'
        for payload in [b'', b'{', b'x' * 16385, json.dumps(missing_rate).encode(),
                        json.dumps(secret).encode(), json.dumps(wrong_quota).encode()]:
            with self.subTest(size=len(payload)):
                code, text = self.prepare(payload)
                self.assertEqual(code, 1)
                self.assertNotIn('synthetic-value-never-installed', text)
                self.assertFalse((self.state / helper.MODULEAPI_CONFIG_NAME).exists())

    def test_existing_descriptor_and_other_operator_files_not_opened_or_overwritten(self):
        destination = self.state / helper.MODULEAPI_CONFIG_NAME
        destination.write_bytes(b'existing-nonsecret-descriptor')
        destination.chmod(0o600)
        other = self.state / 'openai-deployment.json'
        other.write_bytes(b'untouched-old-config')
        other.chmod(0o600)
        self.assertEqual(self.prepare()[0], 1)
        self.assertEqual(destination.read_bytes(), b'existing-nonsecret-descriptor')
        self.assertEqual(other.read_bytes(), b'untouched-old-config')

    def test_symlink_destination_refuses_and_preserves_target(self):
        target = self.home / 'target'
        target.write_bytes(b'untouched')
        (self.state / helper.MODULEAPI_CONFIG_NAME).symlink_to(target)
        self.assertEqual(self.prepare()[0], 1)
        self.assertEqual(target.read_bytes(), b'untouched')

    def test_symlink_ancestor_and_unsafe_directory_refuse(self):
        original = self.state
        alias = self.home / 'alias'
        alias.symlink_to(original, target_is_directory=True)
        self.state = alias
        self.assertEqual(self.prepare()[0], 1)
        self.state = original
        original.chmod(0o755)
        self.assertEqual(self.prepare()[0], 1)
        self.assertFalse((original / helper.MODULEAPI_CONFIG_NAME).exists())

    def test_source_tree_destination_refuses_before_validator_or_write(self):
        self.state = ROOT / 'must-not-be-created-moduleapi'
        with mock.patch.object(helper.subprocess, 'run', side_effect=AssertionError('validator must not run')):
            self.assertEqual(self.prepare()[0], 1)
        self.assertFalse(self.state.exists())

    def test_validator_failure_and_deadline_are_sanitized(self):
        for failure in [OSError('synthetic-private-error'), subprocess.TimeoutExpired('node', 10)]:
            with mock.patch.object(helper.subprocess, 'run', side_effect=failure):
                code, text = self.prepare()
            self.assertEqual(code, 1)
            self.assertNotIn('synthetic-private-error', text)
        self.assertFalse((self.state / helper.MODULEAPI_CONFIG_NAME).exists())

    def test_no_path_or_provider_options(self):
        for args in [['--prepare-moduleapi', '/tmp/elsewhere'], ['--prepare-moduleapi=enabled']]:
            self.assertEqual(self.prepare(args=args)[0], 1)
        self.assertFalse((self.state / helper.MODULEAPI_CONFIG_NAME).exists())

    def test_default_descriptor_entry_is_inert_and_bad_options_are_sanitized(self):
        for args, code in [([], 0), (['--unknown'], 1)]:
            result = subprocess.run(['node', 'scripts/moduleapi-deployment-descriptor.mjs', *args], cwd=ROOT,
                                    input=self.payload, capture_output=True, timeout=10,
                                    env={'PATH': '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin'})
            self.assertEqual(result.returncode, code)
            self.assertEqual(result.stdout, b'')
            self.assertNotIn(b'synthetic', result.stderr)


if __name__ == '__main__':
    unittest.main()
