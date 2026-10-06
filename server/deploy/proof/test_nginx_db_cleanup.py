"""Deterministic teardown regressions: synthetic fixtures/processes, no Docker."""
import ast
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from server.deploy.proof import test_nginx_db_path as proof


class NginxDbCleanup(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.case = self.root / 'case'
        self.case.mkdir()
        self.env = self.root / 'synthetic.env'
        self.env.write_bytes(b'synthetic unchanged env')
        self.subject = proof.NginxDbPath()
        self.subject.env_file = self.env
        self.subject.env_before = self.env.read_bytes()
        self.compose = ['docker', 'compose', '-p', 'dip-nginx-db-synthetic',
                        '--env-file', str(self.env), '-f', 'base.yaml',
                        '-f', 'vuln.yaml', '-f', str(self.case / 'compose.yaml')]
        self.client = Mock()
        self.client.poll.return_value = None
        self.stage = {'pid': 42, 'start': '123'}
        self.subject.invoke = Mock(return_value=SimpleNamespace(returncode=0))
        self.subject.resume = Mock()
        # Execute the actual scenario finally body, not a copied cleanup algorithm.
        tree = ast.parse(Path(proof.__file__).read_text())
        scenario = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'scenario')
        final = next(n for n in scenario.body if isinstance(n, ast.Try) and n.finalbody)
        self.finalbody = compile(ast.fix_missing_locations(ast.Module(body=final.finalbody, type_ignores=[])), proof.__file__, 'exec')
        self.addCleanup(setattr, proof.NginxDbPath, 'preserve_fixtures', False)

    def cleanup(self):
        exec(self.finalbody, {'self': self.subject, 'compose': self.compose,
                             'stopped_pid': self.stage, 'client': self.client,
                             'case': self.case})

    def assert_teardown(self):
        self.subject.invoke.assert_called_once_with(
            self.compose + ['down', '--volumes', '--remove-orphans'], 120)
        self.client.kill.assert_called_once_with()
        self.client.wait.assert_called_once_with(timeout=10)
        self.client.stdout.close.assert_called_once_with()
        self.assertEqual(self.env.read_bytes(), self.subject.env_before)

    def test_resume_failures_cannot_skip_cleanup_and_are_redacted(self):
        for error in [AssertionError('PRIVATE_DB_CANARY'),
                      OSError('PRIVATE_DB_CANARY'),
                      subprocess.TimeoutExpired(['PRIVATE_DB_CANARY'], 60,
                                                output=b'PRIVATE_DB_CANARY')]:
            with self.subTest(error=type(error).__name__):
                if not self.case.exists(): self.case.mkdir()
                self.subject.resume.side_effect = error
                with self.assertRaises(AssertionError) as caught: self.cleanup()
                self.assertIn('resume', str(caught.exception))
                self.assertNotIn('PRIVATE_DB_CANARY', str(caught.exception))
                self.assert_teardown()
                self.assertFalse(self.case.exists())
                self.subject.invoke.reset_mock()
                self.client.reset_mock()

    def test_primary_error_is_preserved_with_safe_secondary_note(self):
        primary = RuntimeError('original scenario failure')
        self.subject.resume.side_effect = AssertionError('PRIVATE_DB_CANARY')
        with self.assertRaises(RuntimeError) as caught:
            try:
                raise primary
            finally:
                self.cleanup()
        self.assertIs(caught.exception, primary)
        self.assertEqual(primary.__notes__, ['Disposable cleanup failed: resume; diagnostics suppressed'])
        self.assert_teardown()
        self.assertFalse(self.case.exists())

    def test_client_failures_are_independent_and_do_not_skip_down(self):
        self.client.kill.side_effect = OSError('PRIVATE_DB_CANARY')
        self.client.wait.side_effect = subprocess.TimeoutExpired('PRIVATE_DB_CANARY', 10)
        self.client.stdout.close.side_effect = OSError('PRIVATE_DB_CANARY')
        with self.assertRaisesRegex(AssertionError, 'client-kill, client-wait, client-stream'):
            self.cleanup()
        self.assert_teardown()
        self.assertFalse(self.case.exists())

    def test_failed_or_timed_out_down_retains_fixtures_through_class_teardown(self):
        for timeout in [False, True]:
            with self.subTest(timeout=timeout):
                self.subject.invoke.side_effect = subprocess.TimeoutExpired('PRIVATE_DB_CANARY', 120) if timeout else None
                self.subject.invoke.return_value = SimpleNamespace(returncode=1)
                with self.assertRaisesRegex(AssertionError, 'compose-down'): self.cleanup()
                self.assert_teardown()
                self.assertTrue(self.case.exists())
                with patch.object(proof.NginxDbPath, 'directory', self.root, create=True), \
                     patch.object(proof.NginxDbPath, 'env_file', self.env, create=True), \
                     patch.object(proof.NginxDbPath, 'env_before', self.env.read_bytes(), create=True):
                    proof.NginxDbPath.tearDownClass()
                self.assertTrue(self.case.exists())
                self.subject.invoke.reset_mock()
                self.client.reset_mock()

    def test_env_check_failure_still_disposes_confirmed_down_case(self):
        self.env.write_bytes(b'changed synthetic env')
        with self.assertRaisesRegex(AssertionError, 'env-check'): self.cleanup()
        self.subject.invoke.assert_called_once()
        self.assertFalse(self.case.exists())
        self.assertEqual(self.env.read_bytes(), b'changed synthetic env')

    def test_failed_setup_removes_only_unmounted_own_directory(self):
        auth = self.root / '.local-auth'
        auth.mkdir()
        (auth / 'stand.env').write_bytes(b'synthetic setup env')
        for mode in ['build-timeout', 'build-failure', 'fixture-failure']:
            with self.subTest(mode=mode):
                with patch.object(proof, 'ROOT', self.root), \
                     patch.object(proof.NginxDbPath, 'invoke', return_value=SimpleNamespace(returncode=1 if mode == 'build-failure' else 0)) as invoke, \
                     patch.object(proof.NginxDbPath, 'fixture', side_effect=AssertionError('synthetic fixture failure')):
                    if mode == 'build-timeout': invoke.side_effect = subprocess.TimeoutExpired('synthetic build', 600)
                    with self.assertRaises((AssertionError, subprocess.TimeoutExpired)):
                        proof.NginxDbPath.setUpClass()
                    self.assertFalse(proof.NginxDbPath.directory.exists())
                    self.assertEqual(list(auth.iterdir()), [auth / 'stand.env'])

    def test_success_and_no_client_or_stopped_scanner(self):
        self.stage = None
        self.client = None
        self.cleanup()
        self.subject.resume.assert_not_called()
        self.subject.invoke.assert_called_once()
        self.assertFalse(self.case.exists())

    def test_actual_resume_fences_gone_reused_and_wrong_binary_pid(self):
        # Execute the actual generated Node probe in a VM with controlled /proc and
        # signal operations; never send a signal to a host/container process.
        real_resume = proof.NginxDbPath.resume.__get__(self.subject)
        for mode in ['gone', 'reused', 'wrong-binary', 'valid', 'exec-error', 'exec-timeout']:
            with self.subTest(mode=mode):
                signals = []
                def invoke(args, timeout=60):
                    self.assertEqual(args[:-1], self.compose + ['exec', '-T', 'worker', 'node', '-e'])
                    if mode == 'exec-error': return SimpleNamespace(returncode=1)
                    if mode == 'exec-timeout': raise subprocess.TimeoutExpired('PRIVATE_DB_CANARY', timeout)
                    harness = """const vm=require('node:vm');const input=JSON.parse(require('node:fs').readFileSync(0,'utf8'));
const signals=[];let exit=0;const fs={readFileSync(path){if(input.mode==='gone')throw Error('gone');
if(path.endsWith('/stat'))return '42 (trivy) '+Array(19).fill('0').concat(input.mode==='reused'?'999':'123').join(' ');
return (input.mode==='wrong-binary'?'/unrelated':'/usr/local/bin/trivy')+'\\0';}};
try{vm.runInNewContext(input.code,{require(){return fs;},process:{exit(n){exit=n;throw Error('exit');},kill(p,s){signals.push([p,s]);}}});}catch{exit=exit||1;}
console.log(JSON.stringify({exit,signals}));"""
                    result = subprocess.run(['node', '-e', harness], input=json.dumps({'mode': mode, 'code': args[-1]}),
                                            capture_output=True, text=True, timeout=10, check=True)
                    outcome = json.loads(result.stdout)
                    signals.extend(outcome['signals'])
                    return SimpleNamespace(returncode=outcome['exit'])
                self.subject.invoke = invoke
                if mode == 'valid':
                    real_resume(self.compose, self.stage)
                    self.assertEqual(signals, [[42, 'SIGCONT']])
                else:
                    with self.assertRaises((AssertionError, subprocess.TimeoutExpired)):
                        real_resume(self.compose, self.stage)
                    self.assertEqual(signals, [])


if __name__ == '__main__':
    unittest.main()
