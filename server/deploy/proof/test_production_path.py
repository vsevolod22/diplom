"""Opt-in proof against actual API, worker, Trivy and production CONNECT handler.

Run: python3 -m unittest server/deploy/proof/test_production_path.py -v
No skips or expected failures; only safe fixed labels leave this test process.
"""
import json
import os
import pathlib
import secrets
import subprocess
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = ('docker', 'compose', '-p', 'dip-proof-' + secrets.token_hex(4), '-f', str(ROOT / 'compose.yaml'),
        '-f', str(pathlib.Path(__file__).with_name('compose.yaml')), '--profile', 'api')
ENV = {**os.environ, 'SCAN_JWT_SECRET': secrets.token_hex(32),
       'SCAN_JWT_ISSUER': 'proof-issuer', 'SCAN_JWT_AUDIENCE': 'proof-api'}
# Fixed script only returns safe status, receipt IDs and persisted digests; never HTTP bodies/errors.
JS = '''const crypto=require('node:crypto'),Database=require('better-sqlite3');
const now=Math.floor(Date.now()/1000),head=Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT'})).toString('base64url');
const claims=Buffer.from(JSON.stringify({iss:process.env.SCAN_JWT_ISSUER,aud:process.env.SCAN_JWT_AUDIENCE,
 sub:'proof-'+(process.argv[3]||'alice'),scope:'scan:create',iat:now-1,exp:now+300})).toString('base64url');
const signed=head+'.'+claims;
const token=signed+'.'+crypto.createHmac('sha256',process.env.SCAN_JWT_SECRET).update(signed).digest('base64url');
const url='http://127.0.0.1:3001/api/v1/scans', headers={authorization:'Bearer '+token,'content-type':'application/json'};
(async()=>{const op=process.argv[1],key=process.argv[2]||'proof-key-0001';
 let response;
 if(op==='post') response=await fetch(url,{method:'POST',headers,body:JSON.stringify({imageReference:process.argv[4]||'registry-1.docker.io/library/alpine:stable',
 checks:['secret'],scope:'image',idempotencyKey:key})});
 else response=await fetch(url+'/'+key,{headers});
 const text=await response.text();
 let scanId=null,state=null;
 if(response.ok){const body=JSON.parse(text);scanId=body.scanId||null;state=body.state||null;}
 const db=new Database(process.env.SCAN_LEDGER_PATH,{readonly:true});
 const rows=db.prepare('SELECT scans.id, scans.digest, scans.platform, scans.state, outbox.attempts, scan_results.error_code AS errorCode FROM scans JOIN outbox ON outbox.scan_id=scans.id LEFT JOIN scan_results ON scan_results.scan_id=scans.id ORDER BY scans.created_at, scans.id').all();
 db.close(); console.log(JSON.stringify({status:response.status,scanId,state,rows,leak:text.includes('CANARY_SIGNED')||text.includes('fixture-token')}));
})().catch(()=>{console.log(JSON.stringify({error:'request failed'}));process.exitCode=1});'''


def run(*args, timeout=120):
    return subprocess.run(args, env=ENV, capture_output=True, text=True, timeout=timeout)


def compose(*args, timeout=120):
    return run(*BASE, *args, timeout=timeout)


class ProductionPathProof(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if run('docker', 'info', timeout=15).returncode:
            raise AssertionError('Docker Engine required; proof must not skip')
        if compose('config', '--quiet').returncode:
            raise AssertionError('proof Compose invalid')
        build = compose('up', '-d', '--build', timeout=420)
        if build.returncode:
            raise AssertionError(f'proof build/start failed (exit {build.returncode}); no acceptance claimed')
        time.sleep(4)

    @classmethod
    def tearDownClass(cls):
        compose('down', '-v', '--remove-orphans', timeout=120)

    def control(self, service, name, value=None):
        self.assertIn(service, ('registry', 'egress'))
        self.assertIn(name, ('mode', 'tag', 'pause', 'release', 'arrived', 'hits', 'leak', 'proof-dns', 'proof-dials'))
        path = '/tmp/' + name
        script = "from pathlib import Path; p=Path('" + path + "'); p.write_text(" + repr(value) + ")" if value is not None else "from pathlib import Path; Path('" + path + "').unlink(missing_ok=True)"
        result = compose('exec', '-T', service, 'python', '-c', script)
        self.assertEqual(result.returncode, 0, f'control {service}/{name} failed')

    def lines(self, service, name):
        self.assertIn((service, name), (('registry', 'hits'), ('registry', 'leak'), ('sink', 'hits'), ('egress', 'proof-dials')))
        result = compose('exec', '-T', service, 'python', '-c',
                         "from pathlib import Path; p=Path('/tmp/" + name + "'); print(p.read_text() if p.exists() else '',end='')")
        self.assertEqual(result.returncode, 0, f'{service} counter unavailable')
        return result.stdout.splitlines()

    def request(self, op='post', key='proof-key-0001', subject='alice', reference='registry-1.docker.io/library/alpine:stable'):
        result = compose('exec', '-T', 'api', 'node', '-e', JS, op, key, subject, reference, timeout=35)
        self.assertEqual(result.returncode, 0, 'API command failed (safe diagnostics only)')
        try:
            value = json.loads(result.stdout.strip())
        except ValueError:
            self.fail('API did not return safe JSON')
        self.assertNotIn('error', value)
        self.assertFalse(value['leak'], 'canary/token in API response')
        return value

    def wait_ready(self):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            result = compose('exec', '-T', 'api', 'node', '--import', 'tsx', '-e',
                             "import('./src/scans/scan-readiness.ts').then(m=>m.chainReady()).then(x=>console.log(x?'ready':'waiting')).catch(()=>console.log('waiting'))", timeout=10)
            if result.returncode == 0 and result.stdout.strip() == 'ready':
                return
            time.sleep(.5)
        self.fail('actual API worker/gateway readiness unavailable')

    def assert_no_canary_in_service_logs_or_ledger(self):
        for service in ('api', 'worker', 'egress', 'registry'):
            raw = compose('logs', '--no-color', service, timeout=20)
            self.assertEqual(raw.returncode, 0, f'{service} logs unavailable')
            self.assertNotIn('CANARY_SIGNED', raw.stdout + raw.stderr, f'{service} logged signed canary')
            self.assertNotIn('fixture-token', raw.stdout + raw.stderr, f'{service} logged bearer token')
        script = "const fs=require('node:fs');for(const p of ['/data/ledger.sqlite','/data/ledger.sqlite-wal']){if(fs.existsSync(p)){const b=fs.readFileSync(p).toString('utf8');if(b.includes('CANARY_SIGNED')||b.includes('fixture-token'))process.exit(2)}}console.log('clean')"
        result = compose('exec', '-T', 'api', 'node', '-e', script, timeout=15)
        self.assertEqual((result.returncode, result.stdout.strip()), (0, 'clean'), 'ledger has signed canary or token')

    def reset(self):
        for name in ('mode', 'tag', 'pause', 'release', 'arrived', 'hits', 'leak'):
            self.control('registry', name)
        for name in ('proof-dns', 'proof-dials'):
            self.control('egress', name)

    def scanner(self, reference='registry-1.docker.io/library/alpine:stable'):
        result = compose('exec', '-T', '-e', 'HTTPS_PROXY=http://egress:8080', '-e', 'HTTP_PROXY=http://egress:8080',
                         '-e', 'NO_PROXY=', 'worker', 'trivy', 'image', '--image-src', 'remote', '--scanners', 'secret',
                         '--skip-db-update', '--skip-java-db-update', '--offline-scan', '--platform', 'linux/amd64', '--format', 'json',
                         '--cache-dir', '/tmp/proof-trivy-' + secrets.token_hex(4),
                         '--timeout', '12s', reference, timeout=30)
        # raw stdout/stderr can contain signed URLs and must not escape this process.
        self._scanner_error_flags = {label: label in result.stderr.lower() for label in (
            'certificate', 'x509', 'permission', 'cache', 'connection', 'denied', 'forbidden',
            'unauthorized', 'timeout', 'manifest', 'blob', 'no space', 'registry', 'error')}
        return result.returncode, result.stdout

    def test_01_pinned_tag_changes_while_live_worker_is_in_flight(self):
        self.reset()
        self.control('registry', 'tag', 'A')
        self.control('registry', 'pause', 'yes')
        first = self.request(key='mutation-proof-1')
        self.assertEqual(first['status'], 202, f"safe fixture paths: {self.lines('registry', 'hits')}, dials: {self.lines('egress', 'proof-dials')}")
        self.assertEqual(len(first['rows']), 1)
        self.assertEqual(first['rows'][0]['platform'], 'linux/amd64')
        tag_hits_before_swap = sum('/manifests/stable' in hit for hit in self.lines('registry', 'hits'))
        deadline = time.monotonic() + 23
        while time.monotonic() < deadline:
            result = compose('exec', '-T', 'registry', 'python', '-c', "from pathlib import Path; print(Path('/tmp/arrived').exists())")
            if result.stdout.strip() == 'True':
                break
            time.sleep(.3)
        else:
            self.control('registry', 'pause')
            code, raw = self.scanner('registry-1.docker.io/library/alpine@' + first['rows'][0]['digest'])
            labels = {label: label in raw.lower() for label in ('not found', 'unauthorized', 'denied', 'timeout', 'blob', 'config', 'manifest', 'json', 'tls', 'certificate', 'platform', 'error', 'invalid')}
            self.fail(f"live Trivy did not reach digest layer barrier; safe state={self.request('status', first['scanId'])['state']}, scanner_code={code}, labels={labels}, paths={self.lines('registry','hits')}")
        self.control('registry', 'tag', 'B')
        self.control('registry', 'release', 'yes')
        deadline = time.monotonic() + 55
        while time.monotonic() < deadline:
            last = self.request('status', first['scanId'])
            if last['state'] in ('completed', 'failed'):
                break
            time.sleep(.6)
        if last['state'] != 'completed':
            code, raw = self.scanner('registry-1.docker.io/library/alpine@' + first['rows'][0]['digest'])
            try:
                decoded = json.loads(raw)
                keys = list(decoded) if isinstance(decoded, dict) else ['non-object']
                if isinstance(decoded, dict):
                    keys.append('Results-type:' + type(decoded.get('Results')).__name__)
                    keys.append('ArtifactType:' + str(decoded.get('ArtifactType')))
                    keys.append('Metadata-keys:' + ','.join(decoded.get('Metadata', {}).keys()))
            except ValueError:
                keys = ['non-json']
            self.fail(f"pinned worker did not complete; safe result={last['rows']}, scanner_code={code}, schema_keys={keys}, paths={self.lines('registry', 'hits')}")
        self.assertEqual(last['rows'][0]['digest'], first['rows'][0]['digest'])
        self.assertEqual(last['rows'][0]['attempts'], 1)
        hits = self.lines('registry', 'hits')
        self.assertTrue(any(first['rows'][0]['digest'] in hit for hit in hits), 'Trivy never requested pinned digest')
        self.assertEqual(sum('/manifests/stable' in hit for hit in hits), tag_hits_before_swap, 'worker resolved mutable tag')
        self.assertEqual(self.lines('registry', 'leak'), [])
        self.assert_no_canary_in_service_logs_or_ledger()
        self.assertEqual(compose('restart', 'api', 'worker', timeout=90).returncode, 0)
        time.sleep(3)
        replay = self.request(key='mutation-proof-1')
        self.assertEqual(replay['status'], 202)
        self.assertEqual(replay['scanId'], first['scanId'])
        self.assertEqual(replay['rows'], last['rows'])
        self.assertEqual(self.request(key='mutation-proof-1', reference='registry-1.docker.io/library/alpine:other')['status'], 409)
        self.assertEqual(len(self.request(key='mutation-proof-1')['rows']), 1)
        conflict = self.request(key='mutation-proof-2', subject='bob')
        self.assertEqual(conflict['status'], 202)
        self.assertNotEqual(conflict['rows'][-1]['digest'], first['rows'][0]['digest'])
        self.assertEqual(compose('stop', 'egress', timeout=30).returncode, 0)
        try:
            self.assertEqual(self.request(key='mutation-proof-1')['scanId'], first['scanId'])
            self.assertEqual(self.request(key='mutation-proof-3', subject='bob')['status'], 503)
        finally:
            self.assertEqual(compose('start', 'egress', timeout=30).returncode, 0)

    def test_02_api_and_trivy_reject_redirects_and_hostile_token(self):
        self.wait_ready()
        for mode, marker in (('manifest-redirect', '/manifests/'), ('manifest-sink', '/manifests/'),
                             ('manifest-host', '/manifests/'), ('blob-redirect', '/blobs/'),
                             ('blob-metadata', '/blobs/'), ('token-metadata', '/v2/'),
                             ('token-sink', '/v2/'), ('token-service', '/v2/'), ('token-scope', '/v2/')):
            with self.subTest(mode=mode):
                self.reset()
                self.control('registry', 'tag', 'A')
                self.control('registry', 'mode', mode)
                self.assertEqual(self.request(key='negative-' + mode, subject=mode.replace('-', ''))['status'], 503)
                hits = self.lines('registry', 'hits')
                self.assertTrue(any(marker in hit for hit in hits), f'API did not exercise malicious response; safe hits={hits}')
                source_before = len(hits)
                code, raw = self.scanner()
                self.assertNotEqual(code, 0, 'real Trivy accepted hostile fixture')
                self.assertGreater(len(self.lines('registry', 'hits')), source_before,
                                   'real Trivy did not receive adversarial source response')
                self.assertTrue(any(marker in hit for hit in self.lines('registry', 'hits')))
                self.assertEqual(self.lines('sink', 'hits'), [], 'forbidden upstream was reached')
                self.assertTrue(all(line.endswith(' 172.30.92.10') for line in self.lines('egress', 'proof-dials')),
                                'gateway dialed outside exact fixture pair')
                self.assertEqual(self.lines('registry', 'leak'), [], 'credential forwarded to CDN')
                self.assertEqual(self.request(key='negative-' + mode, subject=mode.replace('-', ''))['status'], 503)
                self.assert_no_canary_in_service_logs_or_ledger()
                # Raw Trivy diagnostics stay only inside the test process; never emit them.
                del raw

    def test_03_real_connect_rebind_and_mixed_answers_have_no_dial(self):
        self.reset()
        self.control('registry', 'tag', 'A')
        code, raw = self.scanner()
        self.assertEqual(code, 0, f"positive real Trivy control did not run: {self._scanner_error_flags}, hits={self.lines('registry', 'hits')}, dials={self.lines('egress', 'proof-dials')}")
        del raw
        before = len(self.lines('egress', 'proof-dials'))
        for mode in ('mixed', 'rebind'):
            with self.subTest(mode=mode):
                self.control('egress', 'proof-dns', mode)
                self.assertEqual(self.request(key='dns-' + mode, subject='dns' + mode)['status'], 503)
                code, raw = self.scanner()
                self.assertNotEqual(code, 0)
                self.assertEqual(len(self.lines('egress', 'proof-dials')), before, 'forbidden numeric dial')
                self.assertEqual(self.lines('sink', 'hits'), [])
                del raw
        self.control('egress', 'proof-dns', 'fixture')

    def test_04_rebind_during_one_real_trivy_run_and_no_direct_bypass(self):
        from server.deploy.test_api_docker import NETWORK_PROBE
        for service in ('api', 'worker'):
            with self.subTest(service=service):
                result = compose('exec', '-T', '-e', 'HTTP_PROXY=', '-e', 'HTTPS_PROXY=', '-e',
                                 'NO_PROXY=*', service, 'node', '-e', NETWORK_PROBE, timeout=30)
                self.assertEqual(result.returncode, 0, f'{service} direct TCP/daemon probe failed')
        for mode in ('rebind-after-one', 'mixed-after-one'):
            with self.subTest(mode=mode):
                self.reset()
                self.control('egress', 'proof-dns', mode)
                code, raw = self.scanner()
                self.assertNotEqual(code, 0, 'scanner bypassed per-CONNECT DNS validation')
                self.assertEqual(len(self.lines('egress', 'proof-dials')), 1, 'second CONNECT dialed after rebind')
                self.assertTrue(self.lines('registry', 'hits'), 'scanner did not reach first allowed CONNECT')
                self.assertEqual(self.lines('sink', 'hits'), [])
                del raw
        self.control('egress', 'proof-dns', 'fixture')
        result = compose('exec', '-T', '-e', 'HTTP_PROXY=', '-e', 'HTTPS_PROXY=', '-e', 'NO_PROXY=*',
                         'worker', 'trivy', 'image', '--image-src', 'remote', '--scanners', 'secret',
                         '--skip-db-update', '--skip-java-db-update', '--offline-scan', '--timeout', '8s',
                         'registry-1.docker.io/library/alpine:stable', timeout=25)
        self.assertNotEqual(result.returncode, 0, 'Trivy bypassed network isolation without gateway')

    def test_05_real_tls_ca_and_hostname_verification(self):
        self.reset()
        script = '''const http=require('node:http'),tls=require('node:tls');
const sni=process.argv[1];let done=false;
const end=x=>{if(!done){done=true;console.log(x?'verified':'rejected');process.exitCode=x?0:3}};
const req=http.request({host:'egress',port:8080,method:'CONNECT',path:'registry-1.docker.io:443',headers:{host:'registry-1.docker.io:443'},timeout:4000});
req.on('connect',(r,s)=>{if(r.statusCode!==200)return end(false);
const secure=tls.connect({socket:s,servername:sni,rejectUnauthorized:true});
secure.on('secureConnect',()=>{secure.destroy();end(true)});
secure.on('error',()=>end(false));secure.setTimeout(5000,()=>{secure.destroy();end(false)});});
req.on('error',()=>end(false));req.on('timeout',()=>{req.destroy();end(false)});req.end();'''
        good = compose('exec', '-T', 'api', 'node', '-e', script, 'registry-1.docker.io', timeout=15)
        self.assertEqual((good.returncode, good.stdout.strip()), (0, 'verified'), f"safe dial count: {len(self.lines('egress', 'proof-dials'))}")
        for env, sni in (('NODE_EXTRA_CA_CERTS=', 'registry-1.docker.io'),
                         ('NODE_EXTRA_CA_CERTS=/trust/cert.pem', 'evil.example.org')):
            with self.subTest(env=env, sni=sni):
                bad = compose('exec', '-T', '-e', env, 'api', 'node', '-e', script, sni, timeout=15)
                self.assertEqual((bad.returncode, bad.stdout.strip()), (3, 'rejected'))
        self.assertEqual(self.lines('sink', 'hits'), [])

if __name__ == '__main__':
    unittest.main()
