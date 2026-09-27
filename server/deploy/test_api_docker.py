"""Production-compose API/worker smoke with ephemeral JWT secret and disposable volume."""
import os
import pathlib
import secrets
import subprocess
import time
import unittest

COMPOSE = pathlib.Path(__file__).with_name("compose.yaml")
PROJECT = "dip-e2e-" + secrets.token_hex(4)
BASE = ("docker", "compose", "-p", PROJECT, "-f", str(COMPOSE), "--profile", "api")
ENV = {**os.environ, "SCAN_JWT_SECRET": secrets.token_hex(32),
       "SCAN_JWT_ISSUER": "test-issuer", "SCAN_JWT_AUDIENCE": "test-scan-api"}

# Only emit status codes and safe result metadata, never bearer tokens or raw HTTP errors.
SCRIPT = '''const crypto = require('node:crypto');
const now = Math.floor(Date.now()/1000);
const header = Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT'})).toString('base64url');
const claim = Buffer.from(JSON.stringify({iss:process.env.SCAN_JWT_ISSUER,aud:process.env.SCAN_JWT_AUDIENCE,
 sub:'alice',scope:'scan:create',iat:now-1,exp:now+120})).toString('base64url');
const unsigned = header + '.' + claim;
const token = unsigned + '.' + crypto.createHmac('sha256',process.env.SCAN_JWT_SECRET).update(unsigned).digest('base64url');
const url='http://127.0.0.1:3001/api/v1/scans';
const body={imageReference:'registry-1.docker.io/library/alpine:3.20',checks:['secret'],scope:'image',idempotencyKey:'public-test-key-001'};
const headers={authorization:'Bearer '+token,'content-type':'application/json'};
(async()=>{
 const result=await fetch(url,{method:'POST',headers,body:JSON.stringify(body)});
 if(result.status!==202){console.log('POST '+result.status);process.exitCode=1;return;}
 const receipt=await result.json();
 if(!receipt.scanId||!receipt.statusUrl||!receipt.eventsUrl){process.exitCode=2;return;}
 const again=await fetch(url,{method:'POST',headers,body:JSON.stringify(body)});
 const replay=await again.json();
 if(again.status!==202||receipt.scanId!==replay.scanId){console.log('replay failed');process.exitCode=3;return;}
 const conflict=await fetch(url,{method:'POST',headers,body:JSON.stringify({...body,imageReference:'registry-1.docker.io/library/alpine:latest'})});
 if(conflict.status!==409){console.log('conflict '+conflict.status);process.exitCode=4;return;}
 for(let i=0;i<45;i++){
   const status=await fetch(url+'/'+receipt.scanId,{headers});
   if(status.status!==200){process.exitCode=5;return;}
   const snapshot=await status.json();
   if(snapshot.state==='completed'){
     if(snapshot.result?.check!=='secret'||snapshot.result?.coverage!=='image'){
       process.exitCode=6;return;
     }
     const events=await fetch(url+'/'+receipt.scanId+'/events',{headers});
     const stream=await events.text();
     const ids=[...stream.matchAll(/^id: (\\d+)$/gm)].map(m=>Number(m[1]));
     if(events.status!==200||ids.length<3||ids.some((id,i)=>i>0&&id<=ids[i-1])){process.exitCode=7;return;}
     const reconnect=await fetch(url+'/'+receipt.scanId+'/events',{headers:{...headers,'last-event-id':String(ids[0])}});
     const replayStream=await reconnect.text();
     if(reconnect.status!==200||!replayStream.includes('id: '+ids[1])){process.exitCode=11;return;}
     const findings=await fetch(url+'/'+receipt.scanId+'/results?limit=1',{headers});
     const page=await findings.json();
     if(findings.status!==200||page.coverage?.outcome!=='checked'||!Array.isArray(page.findings)){process.exitCode=12;return;}
     const other=Buffer.from(JSON.stringify({iss:process.env.SCAN_JWT_ISSUER,aud:process.env.SCAN_JWT_AUDIENCE,
       sub:'bob',scope:'scan:create',iat:now-1,exp:now+120})).toString('base64url');
     const otherToken=header+'.'+other+'.'+crypto.createHmac('sha256',process.env.SCAN_JWT_SECRET).update(header+'.'+other).digest('base64url');
     for(const path of ['', '/events', '/results']){
       const denied=await fetch(url+'/'+receipt.scanId+path,{headers:{authorization:'Bearer '+otherToken}});
       if(denied.status!==404){process.exitCode=13;return;}
     }
     console.log('202 replay conflict terminal scoped results and ordered events OK');return;
   }
   if(snapshot.state==='failed'){console.log('worker failed');process.exitCode=8;return;}
   await new Promise(r=>setTimeout(r,1000));
 }
 console.log('worker timeout');process.exitCode=9;
})().catch(()=>{console.log('API unavailable');process.exitCode=10});
'''


def command(*args, timeout=240):
    return subprocess.run(args, env=ENV, capture_output=True, text=True, timeout=timeout)


# Run inside the actual API and Trivy worker images, not a lookalike probe container.
# No proxy env and no DNS assumptions: the network must deny direct TCP even if
# a process overrides NO_PROXY. Never print environment values or scanner output.
NETWORK_PROBE = '''const net = require('node:net'),tls=require('node:tls'),fs = require('node:fs');
if(process.env.DOCKER_HOST || fs.existsSync('/var/run/docker.sock')) process.exit(2);
const destinations=[['1.1.1.1',443],['169.254.169.254',80],['host.docker.internal',2375]];
(async()=>{
 for(const [host,port] of destinations){
  const connected=await new Promise(resolve=>{
   const socket=net.connect({host,port,timeout:1500});
   socket.once('connect',()=>{socket.destroy();resolve(true)});
   socket.once('error',()=>resolve(false));
   socket.once('timeout',()=>{socket.destroy();resolve(false)});
  });
  if(connected){console.log('direct TCP permitted');process.exitCode=3;return}
 }
 for(const target of ['169.254.169.254','evil.example.org']){
  const denied=await new Promise(resolve=>{
   const s=net.connect({host:'egress',port:8080,timeout:2000});let text='';
   s.once('connect',()=>s.write(`CONNECT ${target}:443 HTTP/1.1\\r\\nHost: ${target}:443\\r\\nProxy-Authorization: Basic CANARY\\r\\n\\r\\n`));
   s.on('data',chunk=>text+=chunk.toString('ascii'));
   s.once('close',()=>resolve(text.startsWith('HTTP/1.1 403')));
   s.once('error',()=>resolve(false));s.once('timeout',()=>{s.destroy();resolve(false)});
  });
  if(!denied){process.exitCode=5;return}
 }
 const tlsDenied=await new Promise(resolve=>{
  const s=net.connect({host:'egress',port:8080,timeout:3000});let text='';
  s.once('connect',()=>s.write('CONNECT registry-1.docker.io:443 HTTP/1.1\\r\\nHost: registry-1.docker.io:443\\r\\n\\r\\n'));
  s.on('data',chunk=>{
   text+=chunk.toString('ascii');
   if(text.startsWith('HTTP/1.1 200')){
    s.removeAllListeners('data');
    const secure=tls.connect({socket:s,servername:'evil.example.org',rejectUnauthorized:true});
    secure.once('secureConnect',()=>{secure.destroy();resolve(false)});
    secure.once('error',()=>resolve(true));
    secure.setTimeout(4000,()=>{secure.destroy();resolve(false)});
   }
  });
  s.once('error',()=>resolve(false));s.once('timeout',()=>{s.destroy();resolve(false)});
 });
 if(!tlsDenied){process.exitCode=6;return}
 console.log('direct TCP, forbidden CONNECT, invalid TLS and daemon denied');
})().catch(()=>{process.exitCode=4});
'''

FAIL_CLOSED = SCRIPT.replace("if(result.status!==202){console.log('POST '+result.status);process.exitCode=1;return;}",
  "if(result.status===503){console.log('new scan refused pending production egress proof');return;}process.exitCode=1;return;")

OUTAGE = '''const crypto=require('node:crypto');
const now=Math.floor(Date.now()/1000),h=Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT'})).toString('base64url');
const p=Buffer.from(JSON.stringify({iss:process.env.SCAN_JWT_ISSUER,aud:process.env.SCAN_JWT_AUDIENCE,sub:'alice',scope:'scan:create',iat:now-1,exp:now+120})).toString('base64url');
const t=h+'.'+p+'.'+crypto.createHmac('sha256',process.env.SCAN_JWT_SECRET).update(h+'.'+p).digest('base64url');
const url='http://127.0.0.1:3001/api/v1/scans';
const body={imageReference:'registry-1.docker.io/library/alpine:3.20',checks:['secret'],scope:'image',idempotencyKey:'public-test-key-001'};
(async()=>{
 const headers={authorization:'Bearer '+t,'content-type':'application/json'};
 const replay=await fetch(url,{method:'POST',headers,body:JSON.stringify(body)});
 const fresh=await fetch(url,{method:'POST',headers,body:JSON.stringify({...body,idempotencyKey:'outage-new-key-01'})});
 if(replay.status!==202||fresh.status!==503)process.exitCode=1;
 else console.log('outage replay 202 / new 503');
})().catch(()=>{process.exitCode=2});
'''

class PublicScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if command("docker", "info", timeout=15).returncode:
            raise AssertionError("Docker Engine required (no skips)")
        result = command(*BASE, "up", "-d", "--build", timeout=240)
        if result.returncode:
            raise AssertionError(f"compose build/start failed (exit {result.returncode})")
        time.sleep(3)

    @classmethod
    def tearDownClass(cls):
        command(*BASE, "down", "-v", timeout=90)

    def test_00_new_scan_fails_closed_without_accepted_production_proof(self):
        result = command(*BASE, 'exec', '-T', 'api', 'node', '-e', FAIL_CLOSED, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout[:100])

    # These two criteria intentionally remain red until the controlled redirect,
    # DNS rebind and same-tag mutation production evidence is available.
    @unittest.expectedFailure
    def test_01_public_pinned_secret_scan_and_idempotency(self):
        result = command(*BASE, "exec", "-T", "api", "node", "-e", SCRIPT, timeout=100)
        # The script prints only fixed labels and status codes; never print raw service stderr.
        self.assertEqual(result.returncode, 0, result.stdout[:200])

    def test_02_direct_bypass_and_daemon_denied_in_both_service_containers(self):
        for service in ('api', 'worker'):
            with self.subTest(service=service):
                result = command(*BASE, 'exec', '-T', '-e', 'NO_PROXY=*', service,
                                 'node', '-e', NETWORK_PROBE, timeout=30)
                self.assertEqual(result.returncode, 0, f'{service}: {result.stdout[:100]}')

    def test_03_trivy_cannot_bypass_gateway(self):
        result = command(*BASE, 'exec', '-T', '-e', 'HTTP_PROXY=', '-e', 'HTTPS_PROXY=',
                         '-e', 'NO_PROXY=*', 'worker', 'trivy', 'image', '--image-src', 'remote',
                         '--scanners', 'secret', '--skip-db-update', '--skip-java-db-update',
                         '--offline-scan', '--timeout', '8s',
                         'registry-1.docker.io/library/alpine:3.20', timeout=35)
        # Never print raw Trivy stderr/stdout; signed blob URLs may be present.
        self.assertNotEqual(result.returncode, 0, 'Trivy bypassed network isolation')

    @unittest.expectedFailure
    def test_04_committed_replay_survives_gateway_outage(self):
        try:
            self.assertEqual(command(*BASE, 'stop', 'egress', timeout=35).returncode, 0)
            result = command(*BASE, 'exec', '-T', 'api', 'node', '-e', OUTAGE, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout[:100])
        finally:
            self.assertEqual(command(*BASE, 'start', 'egress', timeout=35).returncode, 0)


if __name__ == "__main__":
    unittest.main()
