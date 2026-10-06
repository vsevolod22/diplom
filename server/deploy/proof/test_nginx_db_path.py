"""Real disposable test-key HTTP/Chromium qualification; no production trust/clock override.

Fresh same-key baselines precede mutations. Every expiry uses naturally elapsed wall
clock, real HTTP202, real worker/Trivy and real attempt-fenced SQLite. Private fixture
keys remain host-only. Docker/DOM errors are suppressed instead of dumping secrets.
"""
import hashlib
import json
from pathlib import Path
import queue
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[3]
API = ROOT / 'server/api'


class NginxDbPath(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env_file = ROOT / '.local-auth/stand.env'
        cls.env_before = cls.env_file.read_bytes()
        # Explicit lifetime: failed teardown must retain still-mounted fixtures,
        # including when the test class is torn down or garbage-collected.
        cls.directory = Path(tempfile.mkdtemp(prefix='nginx-db-proof-', dir=ROOT / '.local-auth'))
        cls.preserve_fixtures = False
        cls.build_project = 'dip-db-build-' + secrets.token_hex(6)
        cls.bases = ['--env-file', str(cls.env_file), '-f', str(ROOT / 'server/deploy/compose.stand.yaml'),
                     '-f', str(ROOT / 'server/deploy/compose.stand.vuln.local.yaml')]
        try:
            built = cls.invoke(['docker', 'compose', '-p', cls.build_project] + cls.bases + ['build', 'api', 'worker', 'web', 'egress'], 600)
            if built.returncode != 0:
                raise AssertionError('Disposable images build failed; diagnostics suppressed')
            initialized = cls.fixture('init', str(cls.directory))
        except BaseException:
            # Setup has not started scenario containers or mounted these fixtures.
            shutil.rmtree(cls.directory, ignore_errors=True)
            raise
        cls.source = initialized
        print(json.dumps({'fixtureSource': initialized}), flush=True)

    @classmethod
    def tearDownClass(cls):
        if not cls.preserve_fixtures:
            shutil.rmtree(cls.directory)
        if cls.env_file.read_bytes() != cls.env_before:
            raise AssertionError('Live stand env changed during proof')

    @staticmethod
    def invoke(arguments, timeout=60, cwd=ROOT):
        return subprocess.run(arguments, cwd=cwd, capture_output=True, timeout=timeout, check=False)

    @classmethod
    def fixture(cls, *args):
        result = cls.invoke(['node', '--import', 'tsx', '../deploy/proof/nginx-db-fixtures.mjs', *args], 180, API)
        if result.returncode != 0:
            failure = json.loads(result.stdout)
            diagnostic = {key: failure[key] for key in ['fixtureFailure', 'stage', 'ioCode'] if key in failure}
            raise AssertionError('Host-only fixture failed: ' + json.dumps(diagnostic))
        return json.loads(result.stdout)

    def scenario(self, kind, mode, phase='normal', check_set='combined', ttl=600):
        name = kind + '-' + phase + '-' + check_set + '-' + secrets.token_hex(4)
        try:
            info = self.fixture('mint', str(self.directory), name, kind, phase, str(ttl))
        except Exception:
            # A rejected mint has not started Compose. Remove only its own partial clone.
            import shutil
            shutil.rmtree(self.directory / name, ignore_errors=True)
            raise
        self.assertLess(info['baselineVerifiedAt'], int(time.time() * 1000))
        case = self.directory / name
        proof, release = case / 'proof', case / 'release'
        credentials = proof / 'credentials.json'
        credentials.write_text(json.dumps([{'email': 'proof-' + secrets.token_hex(12) + '@qualification.invalid',
                                            'password': secrets.token_hex(24)} for _ in range(2)]))
        credentials.chmod(0o444)
        project = 'dip-nginx-db-' + secrets.token_hex(6)
        overlay = case / 'compose.yaml'
        bind = lambda source, target: '\n      - type: bind\n        source: ' + str(source) + '\n        target: ' + target + '\n        read_only: true\n        bind: { create_host_path: false }'
        overlay.write_text('''services:
  egress:
    image: ''' + self.build_project + '''-egress
  api:
    image: ''' + self.build_project + '''-api
    command: [node, --import, tsx, src/oci/nginx-db-proof.main.ts]
    environment:
      AUTH_ORIGIN: http://127.0.0.1:18080
      AUTH_ALLOW_INSECURE_LOCAL_HTTP: "true"
      SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: "false"
      SCAN_BROWSER_ALLOWED_USER_IDS: ""
      SCAN_JWT_SECRET: "''' + secrets.token_hex(32) + '''"
      SCAN_JWT_ISSUER: dip-nginx-db-disposable-proof
      SCAN_JWT_AUDIENCE: dip-nginx-db-disposable-proof
    volumes:''' + bind(release, '/opt/release') + bind(proof, '/proof') + '''
  worker:
    image: ''' + self.build_project + '''-worker
    command: [node, --import, tsx, src/worker/nginx-db-proof-worker.main.ts]
    environment:
      SCAN_JWT_ISSUER: dip-nginx-db-disposable-proof
    volumes:''' + bind(release, '/opt/release') + bind(release / 'db', '/tmp/trivy/db') + bind(proof, '/proof') + '''
  web:
    image: ''' + self.build_project + '''-web
    ports: !override ["127.0.0.1:18080:8080"]
''')
        overlay.chmod(0o600)
        compose = ['docker', 'compose', '-p', project] + self.bases + ['-f', str(overlay)]
        client = None
        stopped_pid = None
        fixture_before = {str(p.relative_to(release)): (p.stat().st_size, p.stat().st_mtime_ns, p.stat().st_ino)
                          for p in release.rglob('*') if p.is_file()}
        next_update = int(__import__('datetime').datetime.fromisoformat(info['nextUpdate'].replace('Z', '+00:00')).timestamp() * 1000)
        try:
            merged = self.invoke(compose + ['config', '--format', 'json'])
            self.assertEqual(merged.returncode, 0, 'Compose merge failed; secrets suppressed')
            config = json.loads(merged.stdout)['services']
            for service in ['api', 'worker']:
                mounts = {m['target']: m for m in config[service]['volumes']}
                self.assertEqual(mounts['/opt/release']['source'], str(release))
                self.assertTrue(mounts['/opt/release']['read_only'])
                self.assertEqual(mounts['/proof']['source'], str(proof))
            self.assertEqual(config['worker']['volumes'][0].get('type'), 'volume')
            self.assertEqual({m['target']: m for m in config['worker']['volumes']}['/tmp/trivy/db']['source'], str(release / 'db'))
            started = self.invoke(compose + ['up', '-d', '--no-build', '--wait', '--wait-timeout', '90'], 180)
            self.assertEqual(started.returncode, 0, 'Disposable startup failed; secret diagnostics suppressed')
            worker = self.invoke(compose + ['ps', '-q', 'worker']).stdout.decode().strip()
            for service in ['api', 'worker']:
                cid = self.invoke(compose + ['ps', '-q', service]).stdout.decode().strip()
                mounts = json.loads(self.invoke(['docker', 'inspect', '--format', '{{json .Mounts}}', cid]).stdout)
                for mount in mounts:
                    if mount['Type'] == 'volume': self.assertTrue(mount['Name'].startswith(project + '_'))
                    if mount['Type'] == 'bind':
                        self.assertFalse(mount['RW'])
                        self.assertNotIn('private', mount['Source'])
                        self.assertNotIn('db-signing-key.pem', mount['Source'])
                    self.assertNotEqual(mount['Destination'], '/var/run/docker.sock')
                boundary = self.invoke(['docker', 'inspect', '--format', '{{json .HostConfig.ReadonlyRootfs}} {{json .HostConfig.CapDrop}} {{json .HostConfig.SecurityOpt}}', cid])
                self.assertEqual(boundary.stdout.decode().strip(), 'true ["ALL"] ["no-new-privileges:true"]')
                networks = json.loads(self.invoke(['docker', 'inspect', '--format', '{{json .NetworkSettings.Networks}}', cid]).stdout)
                for network in networks:
                    self.assertTrue(network.startswith(project + '_'))
                    self.assertEqual(self.invoke(['docker', 'network', 'inspect', '--format', '{{json .Internal}}', network]).stdout.decode().strip(), 'true')
            resources = self.invoke(['docker', 'inspect', '--format', '{{json .HostConfig.Memory}} {{json .HostConfig.MemorySwap}} {{json .HostConfig.NanoCpus}} {{json .HostConfig.PidsLimit}}', worker])
            self.assertEqual(resources.stdout.decode().strip(), '1073741824 1073741824 1000000000 128')
            tmpfs = json.loads(self.invoke(['docker', 'inspect', '--format', '{{json .HostConfig.Tmpfs}}', worker]).stdout)
            self.assertEqual(tmpfs, {'/tmp': 'rw,noexec,nosuid,size=16m', '/tmp/trivy': 'rw,noexec,nosuid,uid=65532,gid=65532,size=512m'})
            cgroup = self.exec_json(compose, "const fs=require('node:fs'); console.log(JSON.stringify(Object.fromEntries(['memory.max','memory.swap.max','cpu.max','pids.max'].map(n=>[n,fs.readFileSync('/sys/fs/cgroup/'+n,'utf8').trim()]))))")
            self.assertEqual(cgroup, {'memory.max': '1073741824', 'memory.swap.max': '0', 'cpu.max': '100000 100000', 'pids.max': '128'})
            mount_identity = self.exec_json(compose, "const fs=require('node:fs'); console.log(JSON.stringify(['metadata.json','trivy.db'].filter(n=>fs.existsSync('/tmp/trivy/db/'+n)).map(n=>{const a=fs.statSync('/tmp/trivy/db/'+n),b=fs.statSync('/opt/release/db/'+n);if(a.ino!==b.ino||a.dev!==b.dev)process.exit(1);return [n,a.dev,a.ino,a.size]})))")
            if kind == 'stale': self.wait_expiry(next_update)
            before = self.durable(compose)
            command = ['node', '--import', './server/api/node_modules/tsx/dist/loader.mjs',
                       'server/deploy/proof/nginx-db-browser.mjs', str(credentials), mode, check_set]
            client = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            lines = queue.Queue()
            def read_lines():
                for line in client.stdout: lines.put(line)
            reader = threading.Thread(target=read_lines, daemon=True); reader.start()
            created = []
            ordering = None
            if phase in ['queued', 'during', 'precommit']:
                first = json.loads(lines.get(timeout=120))
                self.assertIn('created', first, 'HTTP202 was not observed while fresh')
                created.append(first)
                self.assertLess(first['admittedAt'], next_update, 'Admission happened after expiry')
                if phase == 'queued':
                    state = self.durable(compose)
                    self.assertEqual(state['scans'], before['scans'] + 1)
                    self.assertEqual(state['states'], [{'state': 'queued', 'n': 1}])
                    self.assertEqual(state['attempts'], [0])
                    observed = int(time.time() * 1000)
                elif phase == 'during':
                    # Observe PID, fixed argv and process start identity, then STOP
                    # atomically in the same exec. No scanner replacement/output stub.
                    observed_stage = self.exec_json(compose, r"""const fs=require('node:fs');
(async()=>{const deadline=Date.now()+90000;while(Date.now()<deadline){
for(const pid of fs.readdirSync('/proc').filter(p=>/^\d+$/.test(p))){try{
 const args=fs.readFileSync('/proc/'+pid+'/cmdline','utf8').split('\0');
 if(args[0]==='/usr/local/bin/trivy'&&args.includes('--input')&&args.includes('vuln')){
 const stat=fs.readFileSync('/proc/'+pid+'/stat','utf8');process.kill(Number(pid),'SIGSTOP');
 console.log(JSON.stringify({pid:Number(pid),observedAt:Date.now(),start:stat.slice(stat.lastIndexOf(')')+2).split(' ')[19],fixedInput:true}));return;}
}catch{}}await new Promise(r=>setTimeout(r,5));}process.exitCode=1;})();""", 100)
                    stopped_pid = observed_stage
                    observed = observed_stage['observedAt']
                else:
                    deadline = time.monotonic() + 100
                    while time.monotonic() < deadline:
                        stage = self.exec_json(compose, "const fs=require('node:fs'); console.log(fs.existsSync('/data/db-proof.stage.json')?fs.readFileSync('/data/db-proof.stage.json','utf8'):'null')")
                        if stage: break
                        time.sleep(0.1)
                    self.assertIsNotNone(stage, 'Actual checked report did not reach precommit barrier')
                    self.assertLess(stage['checkedAt'], next_update)
                    observed = stage['observedAt']
                self.assertLess(observed, next_update, 'Required actual phase was not reached while fresh')
                self.wait_expiry(next_update)
                resumed = int(time.time() * 1000)
                if phase == 'during':
                    self.assertLess(resumed - observed, 110_000, 'Expiry hold cannot masquerade as scanner timeout')
                    self.resume(compose, stopped_pid); stopped_pid = None
                else:
                    released = self.invoke(compose + ['exec', '-T', 'worker', 'node', '-e', "require('node:fs').writeFileSync('/data/db-proof.go','release',{mode:0o600})"])
                    self.assertEqual(released.returncode, 0)
                ordering = {'admittedAt': first['admittedAt'], 'observedAt': observed, 'nextUpdateMs': next_update,
                            'releasedAt': resumed, 'realWallClock': True, 'phase': phase}
            client.wait(timeout=700); reader.join(timeout=10)
            output = []
            while not lines.empty(): output.append(json.loads(lines.get_nowait()))
            summaries = [line for line in output if 'created' not in line]
            self.assertEqual(client.returncode, 0, 'Real browser proof failed: ' + json.dumps(summaries))
            self.assertTrue(summaries)
            summary = summaries[-1]
            after = self.durable(compose)
            if mode == 'admission':
                self.assertEqual(after['scans'], before['scans'])
                self.assertEqual(after['outbox'], before['outbox'])
                self.assertEqual(after['reports'], before['reports'])
                self.assertTrue(summary['domRejected'])
            else:
                self.assertEqual(after['scans'] - before['scans'], len(summary['accepted']))
                self.assertEqual(after['reports'], after['scans'])
                self.assertEqual(after['outbox'], after['scans'])
                self.assertEqual(after['delivered'], after['scans'])
                self.assertEqual(after['terminal'], after['scans'])
                self.assertTrue(all(attempt == 1 for attempt in after['attempts']))
                for scan_id in summary['accepted']:
                    fence = self.invoke(compose + ['exec', '-T', 'worker', 'node', '--import', 'tsx', '--input-type=module', '-e',
                        "import {ScanLedger} from './src/ledger/ledger.ts';const l=new ScanLedger('/data/ledger.sqlite');if(l.finish('" + scan_id + "',0,'failed')||l.attemptActive('" + scan_id + "',0))process.exit(1);l.close()"])
                    self.assertEqual(fence.returncode, 0)
            # Inspect only disposable persisted sinks/logs. Return booleans, never
            # rows, raw scanner output, passwords or error text on a failed check.
            redacted = self.exec_json(compose, "const fs=require('node:fs');const Database=require('better-sqlite3');const d=new Database('/data/ledger.sqlite',{readonly:true});const canaries=JSON.parse(fs.readFileSync('/proof/credentials.json','utf8')).map(u=>u.password).concat(['MALFORMED_DB_SECRET_CANARY','NOT_A_BOLT_DB_SECRET_CANARY','PRIVATE_DB_CANARY']);let clean=true;for(const table of ['scans','outbox','scan_archive_results','scan_events','scan_audit']){const rows=d.prepare('SELECT * FROM '+table+' LIMIT 257').all();if(rows.length>256)process.exit(1);for(const row of rows){const text=JSON.stringify(row);if(canaries.some(c=>text.includes(c)))clean=false;}}d.close();console.log(JSON.stringify({ledgerRedacted:clean}))")
            self.assertTrue(redacted['ledgerRedacted'], 'Disposable ledger canary leak; values suppressed')
            logs = self.invoke(compose + ['logs', '--no-color', '--tail', '200', 'api', 'worker', 'web', 'egress'])
            self.assertEqual(logs.returncode, 0, 'Disposable log probe failed; diagnostics suppressed')
            self.assertLessEqual(len(logs.stdout) + len(logs.stderr), 1024 * 1024, 'Disposable logs exceed proof bound')
            canaries = [u['password'].encode() for u in json.loads(credentials.read_text())] + [
                b'MALFORMED_DB_SECRET_CANARY', b'NOT_A_BOLT_DB_SECRET_CANARY', b'PRIVATE_DB_CANARY']
            self.assertFalse(any(c in logs.stdout or c in logs.stderr for c in canaries), 'Disposable log canary leak; values suppressed')
            clean = self.invoke(compose + ['exec', '-T', 'worker', 'node', '-e', "const fs=require('node:fs');if(fs.existsSync('/tmp/trivy/jobs')&&fs.readdirSync('/tmp/trivy/jobs').length)process.exit(1)"])
            self.assertEqual(clean.returncode, 0, 'Private scanner scratch remains')
            self.assertEqual(mount_identity, self.exec_json(compose, "const fs=require('node:fs');console.log(JSON.stringify(['metadata.json','trivy.db'].filter(n=>fs.existsSync('/tmp/trivy/db/'+n)).map(n=>{const s=fs.statSync('/tmp/trivy/db/'+n);return [n,s.dev,s.ino,s.size]})))"))
            self.assertEqual(fixture_before, {str(p.relative_to(release)): (p.stat().st_size, p.stat().st_mtime_ns, p.stat().st_ino)
                             for p in release.rglob('*') if p.is_file()})
            print(json.dumps({'case': info, 'ordering': ordering, 'httpBrowser': summary, 'ledgerBefore': before,
                              'ledgerAfter': after, 'cleanup': True, 'mountUnchanged': True,
                              'ledgerAndBoundedLogsRedacted': True, 'resources': cgroup}), flush=True)
        finally:
            self.cleanup_scenario(compose, stopped_pid, client, case)

    def cleanup_scenario(self, compose, stopped_pid, client, case):
        primary = sys.exc_info()[1]
        failures = []

        def attempt(stage, action):
            try:
                action()
                return True
            except BaseException:
                # Never expose subprocess argv/output, credentials or raw errors.
                failures.append(stage)
                return False

        try:
            if stopped_pid:
                attempt('resume', lambda: self.resume(compose, stopped_pid))
        finally:
            try:
                if client:
                    running = True
                    try:
                        running = client.poll() is None
                    except BaseException:
                        failures.append('client-poll')
                    if running:
                        attempt('client-kill', client.kill)
                        attempt('client-wait', lambda: client.wait(timeout=10))
                    if client.stdout:
                        attempt('client-stream', client.stdout.close)
            finally:
                def down_project():
                    down = self.invoke(compose + ['down', '--volumes', '--remove-orphans'], 120)
                    self.assertEqual(down.returncode, 0, 'Only disposable project cleanup failed')

                down_ok = attempt('compose-down', down_project)
                if not down_ok:
                    type(self).preserve_fixtures = True
                attempt('env-check', lambda: self.assertEqual(self.env_file.read_bytes(), self.env_before,
                                                            'Live stand env changed during proof'))
                # Only a confirmed exact-project teardown permits fixture deletion.
                if down_ok:
                    attempt('fixture-remove', lambda: shutil.rmtree(case))

        if failures:
            message = 'Disposable cleanup failed: ' + ', '.join(failures) + '; diagnostics suppressed'
            if primary is not None:
                primary.add_note(message)
            else:
                raise AssertionError(message) from None

    def exec_json(self, compose, code, timeout=60):
        result = self.invoke(compose + ['exec', '-T', 'worker', 'node', '-e', code], timeout)
        self.assertEqual(result.returncode, 0, 'Operator-only bounded probe failed')
        return json.loads(result.stdout)

    def durable(self, compose):
        return self.exec_json(compose, "const Database=require('better-sqlite3');const d=new Database('/data/ledger.sqlite',{readonly:true});const n=t=>d.prepare('SELECT count(*) n FROM '+t).get().n;console.log(JSON.stringify({scans:n('scans'),outbox:n('outbox'),reports:n('scan_archive_results'),delivered:d.prepare('SELECT count(*) n FROM outbox WHERE delivered_at IS NOT NULL').get().n,terminal:d.prepare(\"SELECT count(*) n FROM scan_events WHERE state IN ('completed','partial','failed','cancelled')\").get().n,states:d.prepare('SELECT state,count(*) n FROM scans GROUP BY state').all(),attempts:d.prepare('SELECT attempts FROM outbox').all().map(r=>r.attempts)}));d.close()")

    def resume(self, compose, stage):
        # PID reuse cannot signal an unrelated process. Start identity and fixed
        # binary must still agree with the atomically observed scanner.
        result = self.invoke(compose + ['exec', '-T', 'worker', 'node', '-e',
            "const fs=require('node:fs');const p=" + str(stage['pid']) + ";const s=fs.readFileSync('/proc/'+p+'/stat','utf8');if(s.slice(s.lastIndexOf(')')+2).split(' ')[19]!==" + json.dumps(stage['start']) + "||fs.readFileSync('/proc/'+p+'/cmdline','utf8').split('\\0')[0]!=='/usr/local/bin/trivy')process.exit(1);process.kill(p,'SIGCONT')"])
        self.assertEqual(result.returncode, 0, 'Stopped real scanner identity/resume failed')

    @staticmethod
    def wait_expiry(next_update):
        remaining = next_update / 1000 - time.time() + 0.15
        if remaining > 0: time.sleep(remaining)
        if int(time.time() * 1000) < next_update: raise AssertionError('Real clock did not cross expiry')

    def test_01_real_standalone_and_baseline(self):
        self.scenario('valid', 'positive', ttl=3600)

    def test_02_admission_matrix(self):
        for kind in ['stale', 'missing-db', 'db-tamper', 'bundle-tamper', 'metadata-tamper', 'bad-signature',
                     'schema', 'malformed-metadata', 'noncanonical-descriptor']:
            with self.subTest(kind=kind): self.scenario(kind, 'admission', ttl=30 if kind == 'stale' else 600)
        # Expired signed release still allows independent real Secrets/SBOM.
        self.scenario('stale', 'independent', ttl=30)
        for check_set in ['vuln', 'combined']:
            with self.subTest(content=check_set): self.scenario('malformed-content', 'malformed-content', check_set=check_set)

    def test_03_real_expiry_matrix(self):
        for phase in ['queued', 'during', 'precommit']:
            for check_set in ['vuln', 'combined']:
                with self.subTest(phase=phase, checks=check_set):
                    self.scenario('valid', 'expired', phase=phase, check_set=check_set, ttl=90)


if __name__ == '__main__':
    unittest.main()
