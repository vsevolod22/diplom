"""Real compiled LOCAL composition, ordinary pre-existing isolated accounts; LIVE untouched."""
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[3]


class NginxLocalPath(unittest.TestCase):
    def test_current_local_http_chromium_and_recreation(self):
        env_file = ROOT / '.local-auth/stand.env'
        before = env_file.read_bytes()  # Never output auth values.
        values = dict(line.split('=', 1) for line in before.decode().splitlines() if line and not line.startswith('#'))
        manifest, bundle = values['SCAN_VULN_MANIFEST_DIGEST'], values['SCAN_VULN_ARTIFACT_SHA256']
        self.assertRegex(manifest, r'^sha256:[a-f0-9]{64}$')
        self.assertRegex(bundle, r'^[a-f0-9]{64}$')
        release = Path(values['SCAN_VULN_RELEASE_HOST_DIR'])
        def run(args, timeout=60):
            return subprocess.run(args, cwd=ROOT, capture_output=True, timeout=timeout, check=False)
        checked = subprocess.run(
            ['node', '--import', 'tsx', 'src/worker/verify-vuln-db-release.ts', str(release), manifest, bundle], cwd=ROOT / 'server/api', capture_output=True, timeout=180)
        self.assertEqual(checked.returncode, 0, 'Current production-anchor signed RO DB must be fresh; no fallback')
        metadata = json.loads((release / 'db/metadata.json').read_text())
        project = 'dip-nginx-local-' + secrets.token_hex(6)
        with tempfile.TemporaryDirectory(prefix='nginx-local-', dir=ROOT / '.local-auth') as temporary:
            directory = Path(temporary)
            credentials = directory / 'credentials.json'
            credentials.write_text(json.dumps([{'email': 'proof-' + secrets.token_hex(12) + '@qualification.invalid', 'password': secrets.token_hex(24)} for _ in range(3)]))
            credentials.chmod(0o444)
            overlay = directory / 'compose.yaml'
            common = '''services:
  api:
    environment:
      AUTH_ORIGIN: http://127.0.0.1:18080
      AUTH_ALLOW_INSECURE_LOCAL_HTTP: "true"
      SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: "false"
      SCAN_BROWSER_ALLOWED_USER_IDS: "IDS"
      SCAN_JWT_SECRET: "JWT"
      SCAN_JWT_ISSUER: dip-nginx-local-isolated
      SCAN_JWT_AUDIENCE: dip-nginx-local-isolated
  web:
    ports: !override ["127.0.0.1:18080:8080"]
'''.replace('"JWT"', json.dumps(secrets.token_hex(32)))
            # LOCAL startup never manufactures users. A separate, one-shot
            # ordinary AuthStore provisioning command creates OWN volume users.
            provision = common.replace('"IDS"', '""').replace('  web:', '''    volumes:
      - type: bind
        source: ''' + str(credentials) + '''
        target: /proof/credentials.json
        read_only: true
        bind: { create_host_path: false }
  web:''')
            overlay.write_text(provision); overlay.chmod(0o600)
            compose = ['docker', 'compose', '-p', project, '--env-file', str(env_file),
                       '-f', str(ROOT / 'server/deploy/compose.stand.yaml'),
                       '-f', str(ROOT / 'server/deploy/compose.stand.vuln.local.yaml'),
                       '-f', str(ROOT / 'server/deploy/compose.stand.nginx.local.yaml'), '-f', str(overlay)]
            def must(args, timeout=60, message='Isolated command failed; private output suppressed'):
                result = run(args, timeout); self.assertEqual(result.returncode, 0, message); return result.stdout
            try:
                must(compose + ['config', '--quiet'])
                merged = json.loads(must(compose + ['config', '--format', 'json']))['services']
                self.assertEqual(merged['api']['command'][-1], 'src/oci/nginx-local.main.ts')
                self.assertEqual(merged['worker']['command'][-1], 'src/worker/nginx-local-worker.main.ts')
                must(compose + ['build', 'api', 'worker', 'web', 'egress'], 600, 'LOCAL build failed; output suppressed')
                must(compose + ['up', '-d', 'auth-volume-init', 'scan-volume-init'], 90)
                script = "import {AuthStore} from './src/auth/auth.store.ts'; import {readFileSync} from 'node:fs'; const store=new AuthStore(); const ids=[]; for(const u of JSON.parse(readFileSync('/proof/credentials.json','utf8'))) {const user=await store.register(u.email,u.password); if(!user) throw Error('not fresh'); ids.push(user.id);} store.onModuleDestroy(); console.log(JSON.stringify(ids));"
                ids = json.loads(must(compose + ['run', '--rm', '--no-deps', '-T', 'api', 'node', '--import', 'tsx', '--input-type=module', '-e', script], 90))
                self.assertEqual(len(ids), 3)
                # Unlisted third account exercises 403; first two are ordinary
                # explicitly listed existing accounts, not allow-all/startup stubs.
                overlay.write_text(common.replace('"IDS"', json.dumps(','.join(ids[:2]))))
                must(compose + ['up', '-d', '--no-build', '--wait', '--wait-timeout', '120'], 180, 'LOCAL startup failed')
                worker = must(compose + ['ps', '-q', 'worker']).decode().strip()
                for service in ('api', 'worker'):
                    container = must(compose + ['ps', '-q', service]).decode().strip()
                    mounts = json.loads(must(['docker', 'inspect', '--format', '{{json .Mounts}}', container]))
                    for mount in mounts:
                        if mount['Type'] == 'volume': self.assertTrue(mount['Name'].startswith(project + '_'))
                        if mount['Type'] == 'bind':
                            self.assertFalse(mount['RW']); self.assertNotIn('db-signing-key.pem', mount['Source'])
                        self.assertNotEqual(mount['Destination'], '/var/run/docker.sock')
                    constraints = must(['docker', 'inspect', '--format', '{{json .HostConfig.ReadonlyRootfs}} {{json .HostConfig.CapDrop}} {{json .HostConfig.SecurityOpt}}', container]).decode().strip()
                    self.assertEqual(constraints, 'true ["ALL"] ["no-new-privileges:true"]')
                    networks = json.loads(must(['docker', 'inspect', '--format', '{{json .NetworkSettings.Networks}}', container]))
                    for name in networks:
                        self.assertTrue(name.startswith(project + '_'))
                        self.assertEqual(json.loads(must(['docker', 'network', 'inspect', '--format', '{{json .Internal}}', name])), True)
                    must(compose + ['exec', '-T', service, 'node', '--import', 'tsx', 'src/worker/verify-vuln-db-release.ts', '/opt/release', manifest, bundle], 180, 'Actual container fresh DB preflight failed')
                resource = must(['docker', 'inspect', '--format', '{{json .HostConfig.Memory}} {{json .HostConfig.MemorySwap}} {{json .HostConfig.NanoCpus}} {{json .HostConfig.PidsLimit}}', worker]).decode().strip()
                self.assertEqual(resource, '1073741824 1073741824 1000000000 128')
                self.assertEqual(json.loads(must(['docker', 'inspect', '--format', '{{json .HostConfig.Tmpfs}}', worker])), {'/tmp': 'rw,noexec,nosuid,size=16m', '/tmp/trivy': 'rw,noexec,nosuid,uid=65532,gid=65532,size=512m'})
                def cgroup():
                    return json.loads(must(compose + ['exec', '-T', 'worker', 'node', '-e', "const fs=require('node:fs'); console.log(JSON.stringify(Object.fromEntries(['memory.max','memory.swap.max','memory.current','memory.peak','memory.events','cpu.max','pids.max'].map(n=>[n,fs.readFileSync('/sys/fs/cgroup/'+n,'utf8').trim()]))))"]))
                initial = cgroup()
                self.assertEqual([initial[k] for k in ('memory.max','memory.swap.max','cpu.max','pids.max')], ['1073741824','0','100000 100000','128'])
                samples, errors, stop = [], [], threading.Event()
                def sample():
                    while not stop.is_set():
                        try: samples.append(cgroup())
                        except Exception: errors.append('measurement failed'); return
                        stop.wait(1)
                monitor = threading.Thread(target=sample, daemon=True); monitor.start()
                try: result = run(['node', 'server/deploy/proof/nginx-local-browser.mjs', str(credentials)], 1000)
                finally: stop.set(); monitor.join(timeout=65)
                final = cgroup()
                self.assertFalse(errors); self.assertTrue(samples)
                summary = json.loads(result.stdout)
                self.assertEqual(result.returncode, 0, 'LOCAL browser proof failed: ' + json.dumps(summary))
                self.assertTrue(summary['archiveQualified']); self.assertTrue(summary['savedCardReload'])
                self.assertGreater(summary['findings'], 0); self.assertEqual(summary['dbManifest'], manifest)
                for event in ('oom', 'oom_kill', 'oom_group_kill'):
                    self.assertEqual(dict(line.split() for line in initial['memory.events'].splitlines())[event], dict(line.split() for line in final['memory.events'].splitlines())[event])
                must(compose + ['exec', '-T', 'worker', 'node', '-e', "const fs=require('node:fs'); if(fs.readdirSync('/tmp/trivy/jobs').length) process.exit(1)"])
                # Durable SQLite binding/report and ordinary accounts survive
                # recreation under the SAME exact LOCAL entrypoints/JWT/volumes.
                query = "import Database from 'better-sqlite3'; const db=new Database('/data/ledger.sqlite',{readonly:true}); const rows=db.prepare('SELECT s.state,p.binding,a.report FROM scans s JOIN scan_execution_profiles p ON p.scan_id=s.id JOIN scan_archive_results a ON a.scan_id=s.id').all(); if(rows.length!==2||rows.some(r=>r.state!=='completed'||JSON.parse(r.binding).qualificationId!=='nginx-local-0dcc-v1')) process.exit(1); console.log(JSON.stringify({rows:rows.length,version:db.pragma('user_version',{simple:true})})); db.close();"
                ledger = json.loads(must(compose + ['exec', '-T', 'api', 'node', '--input-type=module', '-e', query]))
                must(compose + ['up', '-d', '--no-build', '--no-deps', '--force-recreate', 'worker', 'api'], 180)
                ready = "import {chainReady} from './src/scans/scan-readiness.ts'; import {localWorkerReady} from './src/oci/nginx-local-profile.ts'; for(let i=0;i<60;i++){if(await chainReady()&&await localWorkerReady()) process.exit(0); await new Promise(r=>setTimeout(r,1000));} process.exit(1);"
                must(compose + ['exec', '-T', 'api', 'node', '--import', 'tsx', '--input-type=module', '-e', ready], 90, 'LOCAL recreation lost qualification readiness')
                self.assertEqual(json.loads(must(compose + ['exec', '-T', 'api', 'node', '--input-type=module', '-e', query])), ledger)
                print(json.dumps({'scope':'fresh compiled LOCAL, ordinary existing isolated accounts, no LIVE activation', 'metadata':metadata, 'ledger':ledger, 'before':initial, 'after':final, 'samples':len(samples), 'sampledPeakBytes':max(int(s['memory.current']) for s in samples), 'recreation':True, 'proof':summary}))
            finally:
                must(compose + ['down', '--volumes', '--remove-orphans'], 120, 'Unique LOCAL project cleanup failed')
                self.assertEqual(env_file.read_bytes(), before)
                live = run(['curl', '--silent', '--output', '/dev/null', '--write-out', '%{http_code}', 'http://127.0.0.1:8080/api/v1/auth/me'])
                self.assertEqual(live.stdout.decode(), '401', 'LIVE8080 must remain healthy')


if __name__ == '__main__': unittest.main()
