"""Disposable real-worker archive proof; exact EOL candidate stays unqualified.

Uses the existing local stand gateway and signed read-only DB, but never opens its
ledger/auth volumes, reads the private signing key, recreates services or toggles
admission. This exercises actual consumer/ledger/cookie HTTP routes for negative
EOL/DB cases, not positive qualification. Chromium proves closed admission.
"""
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ['docker', 'compose', '--env-file', '.local-auth/stand.env',
           '-f', 'server/deploy/compose.stand.yaml',
           '-f', 'server/deploy/compose.stand.vuln.local.yaml']


class NginxArchivePath(unittest.TestCase):
    def test_actual_consumer_independent_eol_db_failure_cleanup_and_scoped_results(self):
        env_file = ROOT / '.local-auth/stand.env'
        before = env_file.read_bytes()  # Compared privately; never printed.
        command = COMPOSE + ['run', '--rm', '-T', '--no-deps', '-v',
                             f'{ROOT}/server/api/src:/app/server/api/src:ro',
                             'worker', 'node', '--import', 'tsx', 'src/oci/archive-qualification.ts']
        result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=600, check=False)
        self.assertEqual(env_file.read_bytes(), before)
        self.assertEqual(result.returncode, 0, 'Bounded archive qualification runner failed; raw diagnostics suppressed')
        summaries = [json.loads(line) for line in result.stdout.decode('utf-8').splitlines() if line.startswith('{')]
        self.assertEqual(len(summaries), 6)
        for summary in summaries:
            self.assertFalse(summary['qualified'])
            self.assertTrue(summary['cleanup'])
            self.assertTrue(summary['ownership'])
            self.assertTrue(summary['replay'])
            self.assertTrue(summary['cookieHttp'])
        for summary in summaries[:2]:
            self.assertEqual(summary['terminal'], 'completed')
            self.assertEqual(summary['vuln'], 'checked')
            self.assertGreater(summary['findings'], 0)
            self.assertEqual(summary['metrics']['compressedBytes'], 25950947)
            self.assertEqual(summary['metrics']['expandedBytes'], 63492096)
        self.assertEqual(summaries[1]['components'], 72)
        summaries = summaries[2:]
        for summary in summaries:
            self.assertEqual(summary['metrics']['compressedBytes'], 20580925)
            self.assertEqual(summary['metrics']['expandedBytes'], 48599040)
        self.assertEqual(summaries[0]['terminal'], 'failed')
        self.assertEqual(summaries[0]['reason'], 'OS_EOL')
        for summary in summaries[1:]:
            self.assertEqual(summary['terminal'], 'partial')
            self.assertEqual(summary['secret'], 'checked')
            self.assertEqual(summary['sbom'], 'checked')
            self.assertEqual(summary['components'], 67)
        self.assertEqual(summaries[1]['vuln'], 'unsupported')
        self.assertEqual(summaries[2]['vuln'], 'failed')
        self.assertEqual(summaries[3]['vuln'], 'failed')

    def test_actual_chromium_closed_public_admission_and_server_eligibility(self):
        result = subprocess.run(['node', 'server/deploy/proof/nginx-browser-negative.mjs'], cwd=ROOT,
                                capture_output=True, timeout=60, check=False)
        self.assertEqual(result.returncode, 0, 'Browser negative proof failed; transient credentials suppressed')
        summary = json.loads(result.stdout)
        self.assertTrue(summary['actualChromium'])
        self.assertTrue(summary['serverDerivedSuggestionDisabled'])
        self.assertFalse(summary['positiveQualification'])


if __name__ == '__main__':
    unittest.main()
