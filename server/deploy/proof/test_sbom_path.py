"""Opt-in public-policy Docker SBOM proof; never uses the fixture Compose override.

Run: python3 -m unittest server/deploy/proof/test_sbom_path.py -v
No skips. Outputs only fixed labels/counts, never response bodies, tokens or Trivy output.
"""
import json
import os
import secrets
import subprocess
import time
import unittest
from pathlib import Path

COMPOSE = Path(__file__).resolve().parents[1] / 'compose.yaml'
PROJECT = 'dip-sbom-proof-' + secrets.token_hex(4)
BASE = ('docker', 'compose', '-p', PROJECT, '-f', str(COMPOSE), '--profile', 'api')
ENV = {**os.environ, 'SCAN_JWT_SECRET': secrets.token_hex(32),
       'SCAN_JWT_ISSUER': 'sbom-proof', 'SCAN_JWT_AUDIENCE': 'sbom-proof-api'}
DIGEST = 'sha256:d56c381f961d307a21b3ca004cf1e3910f106644aefb1f43e654c8a56c4fd395'
CANARY = 'CANARY_SIGNED_SBOM_PROOF_' + secrets.token_hex(12)

# Execute inside the real API image; only small safe, deliberately selected fields leave it.
SCRIPT = r'''const crypto=require('node:crypto'), Database=require('better-sqlite3'), fs=require('node:fs');
const image='registry-1.docker.io/library/alpine@sha256:d56c381f961d307a21b3ca004cf1e3910f106644aefb1f43e654c8a56c4fd395';
const canary=process.argv[1], now=Math.floor(Date.now()/1000);
const url='http://127.0.0.1:3001/api/v1/scans';
function auth(subject){
 const h=Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT'})).toString('base64url');
 const p=Buffer.from(JSON.stringify({iss:process.env.SCAN_JWT_ISSUER,aud:process.env.SCAN_JWT_AUDIENCE,sub:subject,scope:'scan:create',iat:now-1,exp:now+300})).toString('base64url');
 const signed=h+'.'+p;
 return signed+'.'+crypto.createHmac('sha256',process.env.SCAN_JWT_SECRET).update(signed).digest('base64url');
}
const bearer=auth('sbom-alice'), headers={authorization:'Bearer '+bearer,'content-type':'application/json'};
const body=(checks,key,ref=image)=>({imageReference:ref,checks,scope:'image',idempotencyKey:key});
const post=(payload,h=headers)=>fetch(url,{method:'POST',headers:h,body:JSON.stringify(payload)});
const get=(path,h=headers)=>fetch(url+path,{headers:h});
function check(ok,label){if(!ok)throw Error(label)}
function database(){return new Database(process.env.SCAN_LEDGER_PATH,{readonly:true,fileMustExist:true})}
function counts(){const db=database();try{
 return {scans:db.prepare('SELECT count(*) n FROM scans').get().n,
  checked:db.prepare("SELECT count(*) n FROM scan_sbom_results WHERE outcome='checked'").get().n,
  components:db.prepare('SELECT count(*) n FROM scan_sbom_components').get().n,
  vuln:db.prepare("SELECT count(*) n FROM scans WHERE checks LIKE '%vuln%'").get().n};
}finally{db.close()}}
function digest(components){return crypto.createHash('sha256').update(JSON.stringify(components.map(c=>[c.ecosystem,c.name,c.version]).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b))))).digest('hex')}
(async()=>{
 let phase='negative';
 try{
  const start=counts();check(start.scans===0&&start.checked===0,'not-empty');
  for(const checks of [['vuln'],['sbom','vuln']]){
   phase='negative-vuln';const r=await post(body(checks,'bad-vuln-00001'));check(r.status===400,'vuln-admitted');
  }
  phase='negative-canary';check((await post({...body(['sbom'],'bad-canary-00001'),canary})).status===400,'canary-admitted');
  phase='negative-image';check((await post(body(['sbom'],'bad-image-00001','registry-1.docker.io/other/alpine:3.20'))).status===400,'bad-image-admitted');
  phase='negative-auth';check((await get('/00000000-0000-0000-0000-000000000000/sbom',{authorization:'Bearer '+canary})).status===401,'canary-authorized');
  phase='negative-missing-image';
  const missing=await post(body(['sbom'],'bad-digest-00001','registry-1.docker.io/library/alpine@sha256:'+ '0'.repeat(64)));
  check(missing.status===503,'missing-image-status-'+missing.status);
  check(counts().scans===0&&counts().vuln===0&&counts().checked===0,'negative-enqueued');
  phase='create';
  const created=await post(body(['sbom'],'real-sbom-00001'));
  check(created.status===202,'post-status-'+created.status);
  const receipt=await created.json();check(/^[a-f0-9-]{36}$/.test(receipt.scanId),'receipt');
  const id=receipt.scanId;
  check((await get('/'+id+'/sbom',{authorization:'Bearer '+auth('sbom-bob')})).status===404,'cross-subject');
  check((await get('/'+id+'/sbom',{authorization:'Bearer '+canary})).status===401,'unauthorized');
  phase='worker';
  let status, state;
  for(let i=0;i<110;i++){
   const r=await get('/'+id);check(r.status===200,'status-http');status=await r.json();state=status.state;
   if(state==='completed'||state==='failed')break;
   await new Promise(resolve=>setTimeout(resolve,1000));
  }
  check(state==='completed','terminal-'+(state||'timeout'));
  check(status.check==='sbom'&&status.digest===image.split('@')[1]&&status.platform==='linux/amd64','wrong-target');
  check(status.result?.check==='sbom'&&status.result?.coverage==='image'&&status.result?.outcome==='checked'&&status.result?.scannerVersion==='0.69.3'&&status.result?.componentCount===16,'not-checked-16');
  phase='sbom';
  let cursor=0, pageCount=0, components=[];
  do{
   const response=await get('/'+id+'/sbom?limit=5&cursor='+cursor);
   check(response.status===200,'sbom-http');const page=await response.json();
   check(page.outcome==='checked'&&page.coverage==='image'&&page.scannerVersion==='0.69.3'&&page.image===image&&page.platform==='linux/amd64'&&page.os?.name==='alpine'&&page.componentCount===16,'sbom-metadata');
   check(Object.keys(page).sort().join(',')==='checkedAt,componentCount,components,coverage,image,nextCursor,os,outcome,platform,scannerVersion','sbom-raw-fields');
   check(page.components.length>0&&page.components.length<=5&&page.components.every(c=>c.ecosystem==='apk'&&typeof c.name==='string'&&typeof c.version==='string'&&Object.keys(c).sort().join(',')==='ecosystem,name,version'),'sbom-components');
   components.push(...page.components);pageCount++;
   if(page.nextCursor===null)break;
   check(page.nextCursor===components.length&&pageCount<=4,'sbom-cursor');cursor=page.nextCursor;
  }while(true);
  check(components.length===16&&new Set(components.map(c=>JSON.stringify(c))).size===16,'sbom-count');
  const db=database();let persisted;
  try{
   const row=db.prepare('SELECT s.digest,s.platform,s.checks,s.state,o.attempts,r.coverage,r.outcome,r.scanner_version version,r.component_count n,r.image,r.os_name os,r.error_code error FROM scans s JOIN outbox o ON o.scan_id=s.id JOIN scan_sbom_results r ON r.scan_id=s.id WHERE s.id=? AND s.subject=?').get(id,'sbom-alice');
   check(row&&row.digest===image.split('@')[1]&&row.platform==='linux/amd64'&&row.checks==='["sbom"]'&&row.state==='completed'&&row.attempts===1&&row.coverage==='image'&&row.outcome==='checked'&&row.version==='0.69.3'&&row.n===16&&row.image===image&&row.os==='alpine'&&row.error===null,'ledger-coverage');
   persisted=db.prepare('SELECT ecosystem,name,version FROM scan_sbom_components WHERE scan_id=? ORDER BY ordinal').all(id);
  }finally{db.close()}
  check(persisted.length===16&&digest(persisted)===digest(components),'ledger-api-mismatch');
  check((await get('/'+id+'/sbom',{authorization:'Bearer '+auth('sbom-bob')})).status===404,'leaked-report');
  check((await post(body(['sbom'],'real-sbom-00001'))).status===202,'replay-status');
  check((await post(body(['vuln'],'bad-vuln-00002'))).status===400,'vuln-after-sbom');
  check(counts().scans===1&&counts().checked===1&&counts().components===16&&counts().vuln===0,'false-coverage');
  const bytes=['/data/ledger.sqlite','/data/ledger.sqlite-wal'].filter(fs.existsSync).map(p=>fs.readFileSync(p));
  check(bytes.every(b=>!b.includes(canary)&&!b.includes(bearer)),'persisted-canary-or-token');
  console.log(JSON.stringify({ok:true,apk:components.length,pages:pageCount,attempts:1,negative:true,ledger:true,scoped:true,clean:true}));
 }catch(e){const reason=typeof e.message==='string'&&/^[a-z0-9-]{1,48}$/.test(e.message)?e.message:'unsafe-runtime-error';console.log(JSON.stringify({ok:false,phase,reason}));process.exitCode=1}
})().catch(()=>{console.log(JSON.stringify({ok:false,phase:'runtime'}));process.exitCode=1});'''


def command(*args, timeout=120):
    return subprocess.run(args, env=ENV, capture_output=True, text=True, timeout=timeout, check=False)


def compose(*args, timeout=120):
    return command(*BASE, *args, timeout=timeout)


class SbomPathProof(unittest.TestCase):
    def test_real_public_policy_sbom_and_negative_paths(self):
        self.assertEqual(command('docker', 'info', timeout=15).returncode, 0, 'Docker Engine required')
        config = compose('config', '--format', 'json', timeout=20)
        self.assertEqual(config.returncode, 0, 'Compose config unavailable')
        topology = json.loads(config.stdout)
        self.assertTrue(topology['networks']['scan_internal']['internal'])
        self.assertEqual(set(topology['services']['worker']['networks']), {'scan_internal'})
        self.assertEqual(set(topology['services']['api']['networks']), {'scan_internal'})
        self.assertEqual(set(topology['services']['egress']['networks']), {'scan_internal', 'registry_uplink'})
        self.assertNotIn('ports', topology['services']['api'])
        self.assertNotIn('ports', topology['services']['worker'])
        try:
            result = compose('up', '-d', '--build', timeout=480)
            self.assertEqual(result.returncode, 0, f'isolated build/start failed (exit {result.returncode}; raw diagnostics suppressed)')
            ready = False
            for _ in range(35):
                probe = compose('exec', '-T', 'api', 'node', '--import', 'tsx', '-e',
                                "import('./src/scans/scan-readiness.ts').then(m=>m.chainReady()).then(x=>console.log(x?'ready':'waiting')).catch(()=>console.log('waiting'))", timeout=15)
                if probe.returncode == 0 and probe.stdout.strip() == 'ready':
                    ready = True
                    break
                time.sleep(1)
            self.assertTrue(ready, 'isolated public-policy API/worker/gateway not ready')
            version = compose('exec', '-T', 'worker', 'trivy', '--version', timeout=20)
            self.assertEqual(version.returncode, 0, 'worker Trivy version unavailable')
            self.assertTrue(version.stdout.strip().startswith('Version: 0.69.3'), 'worker Trivy is not 0.69.3')
            cache = compose('exec', '-T', 'worker', 'node', '-e',
                            "const f=require('node:fs');console.log(f.existsSync('/tmp/trivy/db/trivy.db')?'db-present':'db-absent')", timeout=15)
            self.assertEqual((cache.returncode, cache.stdout.strip()), (0, 'db-absent'), 'vulnerability DB present in fresh isolated worker')
            for _ in range(25):
                http = compose('exec', '-T', 'api', 'node', '-e',
                               "fetch('http://127.0.0.1:3001/api/v1/scans').then(r=>console.log(r.status)).catch(()=>console.log('waiting'))", timeout=12)
                if http.returncode == 0 and http.stdout.strip() == '401':
                    break
                time.sleep(1)
            else:
                self.fail('isolated API HTTP listener unavailable (readiness alone is insufficient)')
            proof = compose('exec', '-T', 'api', 'node', '-e', SCRIPT, CANARY, timeout=170)
            try:
                outcome = json.loads(proof.stdout.strip())
            except ValueError:
                self.fail('API proof did not produce safe JSON; raw output suppressed')
            self.assertEqual(proof.returncode, 0, f'SBOM E2E blocked: {outcome}')
            self.assertEqual(outcome, {'ok': True, 'apk': 16, 'pages': 4, 'attempts': 1,
                                       'negative': True, 'ledger': True, 'scoped': True, 'clean': True})
            for service in ('api', 'worker', 'egress'):
                logs = compose('logs', '--no-color', service, timeout=20)
                self.assertEqual(logs.returncode, 0, f'{service} logs unavailable')
                self.assertNotIn(CANARY, logs.stdout + logs.stderr, f'{service} logged raw canary')
            print('public-policy Trivy 0.69.3: HTTP 202, checked SQLite/APK 16, scoped GET, negatives and canary clean')
        finally:
            stopped = compose('down', '-v', '--remove-orphans', timeout=120)
            self.assertEqual(stopped.returncode, 0, 'isolated Compose cleanup failed; inspect proof project only')


if __name__ == '__main__':
    unittest.main()
