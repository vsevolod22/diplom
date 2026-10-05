"""Bounded isolated real DOM proof. Production remains default-off and untouched."""
import json

from pathlib import Path
import secrets
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class NginxDomPath(unittest.TestCase):
    def test_real_dom_exact_candidate_with_fresh_isolated_volumes(self):
        env_file = ROOT / '.local-auth/stand.env'
        before = env_file.read_bytes()  # Only byte comparison; no secret output.
        project = 'dip-nginx-proof-' + secrets.token_hex(6)
        with tempfile.TemporaryDirectory(prefix='nginx-dom-', dir=ROOT / '.local-auth') as temporary:
            directory = Path(temporary)
            credentials = directory / 'credentials.json'
            credentials.write_text(json.dumps([{'email': 'proof-' + secrets.token_hex(12) + '@qualification.invalid',
                                                'password': secrets.token_hex(24)} for _ in range(2)]))
            credentials.chmod(0o444)  # RO container file; containing host directory remains 0700.
            overlay = directory / 'compose.yaml'
            overlay.write_text('''services:
  api:
    command: [node, --import, tsx, src/oci/nginx-proof.main.ts]
    environment:
      AUTH_ORIGIN: http://127.0.0.1:18080
      AUTH_ALLOW_INSECURE_LOCAL_HTTP: "true"
      SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: "false"
      SCAN_BROWSER_ALLOWED_USER_IDS: ""
      SCAN_JWT_SECRET: "''' + secrets.token_hex(32) + '''"
      SCAN_JWT_ISSUER: dip-nginx-disposable-proof
      SCAN_JWT_AUDIENCE: dip-nginx-disposable-proof
    volumes:
      - type: bind
        source: ''' + str(credentials) + '''
        target: /proof/credentials.json
        read_only: true
        bind: { create_host_path: false }
  web:
    ports: !override ["127.0.0.1:18080:8080"]
''')
            overlay.chmod(0o600)
            compose = ['docker', 'compose', '-p', project, '--env-file', str(env_file),
                       '-f', str(ROOT / 'server/deploy/compose.stand.yaml'),
                       '-f', str(ROOT / 'server/deploy/compose.stand.vuln.local.yaml'), '-f', str(overlay)]
            def run(arguments, timeout=60):
                return subprocess.run(arguments, cwd=ROOT, capture_output=True, timeout=timeout, check=False)
            try:
                configured = run(compose + ['config', '--quiet'])
                self.assertEqual(configured.returncode, 0, 'Isolated compose config failed; secrets suppressed')
                started = run(compose + ['up', '-d', '--build', '--wait', '--wait-timeout', '120'], 600)
                self.assertEqual(started.returncode, 0, 'Isolated build/start failed; credentials suppressed')
                # Inspect only isolation fields, never Config.Env or container logs.
                for service in ['api', 'worker']:
                    container = run(compose + ['ps', '-q', service]).stdout.decode().strip()
                    inspection = run(['docker', 'inspect', '--format', '{{json .Mounts}}', container])
                    mounts = json.loads(inspection.stdout)
                    for mount in mounts:
                        if mount['Type'] == 'volume':
                            self.assertTrue(mount['Name'].startswith(project + '_'))
                        if mount['Type'] == 'bind':
                            self.assertFalse(mount['RW'])
                            self.assertNotIn('db-signing-key.pem', mount['Source'])
                        self.assertNotEqual(mount['Destination'], '/var/run/docker.sock')
                    network = run(['docker', 'inspect', '--format', '{{json .NetworkSettings.Networks}}', container])
                    networks = json.loads(network.stdout)
                    self.assertTrue(all(name.startswith(project + '_') for name in networks))
                    for name in networks:
                        internal = run(['docker', 'network', 'inspect', '--format', '{{json .Internal}}', name])
                        self.assertEqual(json.loads(internal.stdout), True)
                    constraints = run(['docker', 'inspect', '--format',
                        '{{json .HostConfig.ReadonlyRootfs}} {{json .HostConfig.CapDrop}} {{json .HostConfig.SecurityOpt}}', container])
                    self.assertEqual(constraints.stdout.decode().strip(), 'true ["ALL"] ["no-new-privileges:true"]')
                worker = run(compose + ['ps', '-q', 'worker']).stdout.decode().strip()
                resource = run(['docker', 'inspect', '--format',
                    '{{json .HostConfig.Memory}} {{json .HostConfig.NanoCpus}} {{json .HostConfig.PidsLimit}}', worker])
                self.assertEqual(resource.stdout.decode().strip(), '2147483648 1000000000 128',
                                 'This local proof uses the existing 2-GiB overlay, not a 1-GiB qualification')
                result = run(['node', 'server/deploy/proof/nginx-browser-positive.mjs', str(credentials)], 700)
                summary = json.loads(result.stdout)
                self.assertEqual(result.returncode, 0, 'Real DOM proof failed at ' + str(summary.get('failedPhase')) +
                                 '; status=' + str(summary.get('actualStatus')) + '; snapshot=' + json.dumps(summary.get('snapshot')) +
                                 '; transient credentials suppressed')
                self.assertTrue(summary['domLoginSearchSelectionCreateReportReload'])
                self.assertTrue(summary['noSeededScan'])
                self.assertFalse(summary['archiveQualified'])
                self.assertGreater(summary['findings'], 0)
                self.assertEqual(summary['components'], 72)
                # Real private scratch cleanup and continued worker liveness.
                cleaned = run(compose + ['exec', '-T', 'worker', 'node', '-e',
                    "const fs=require('node:fs'); if(fs.readdirSync('/tmp/trivy/jobs').length) process.exit(1)"])
                self.assertEqual(cleaned.returncode, 0, 'Archive scratch not cleaned')
                print(json.dumps(summary))
            finally:
                # Only this unique project can be removed; never the live project.
                stopped = run(compose + ['down', '--volumes', '--remove-orphans'], 120)
                self.assertEqual(stopped.returncode, 0, 'Disposable project cleanup failed')
                self.assertEqual(env_file.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
