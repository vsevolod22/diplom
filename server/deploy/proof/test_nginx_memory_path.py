"""Actual cgroup pressure, scanner kill and unchanged 627s lease recovery.

Only disposable resources. OOM injector death is not whole-worker OOM proof;
parent SIGKILL/restart is separately measured and never preserves in-memory checks.
"""
import json
import subprocess
import queue
import threading
import time
import uuid

from . import test_nginx_dom_path as dom
ROOT = dom.ROOT


def memory_scenarios(test, compose, run, credentials, cgroup):
    worker = run(compose + ['ps', '-q', 'worker']).stdout.decode().strip()
    recovery = run(compose + ['exec', '-T', 'worker', 'node', '--import', 'tsx', '--input-type=module', '-e',
        "import fs from 'node:fs/promises'; import {randomUUID} from 'node:crypto'; "
        "import {recoverArchiveScratch} from './src/oci/bounded-image-archive.ts'; "
        "const db=await fs.stat('/tmp/trivy/db/trivy.db'); const root='/tmp/trivy/jobs'; "
        "if((await fs.readdir(root)).length) process.exit(1); const own=root+'/'+randomUUID(); "
        "await fs.mkdir(own,{mode:0o700}); await fs.writeFile(own+'/abandoned','proof'); "
        "await recoverArchiveScratch(); const after=await fs.stat('/tmp/trivy/db/trivy.db'); "
        "if((await fs.readdir(root)).length||db.ino!==after.ino||db.dev!==after.dev) process.exit(1)"])
    test.assertEqual(recovery.returncode, 0, 'Real recovery must remove only generated abandoned scratch and retain RO DB')
    before = cgroup()
    # Raising only this disposable injector's OOM score makes its own allocation
    # the preferred victim. No swap, resource override, production flag or request seam.
    pressure = run(compose + ['exec', '-T', 'worker', 'node', '-e',
        "const fs=require('node:fs'); fs.writeFileSync('/proc/self/oom_score_adj','1000'); "
        "const held=[]; for(let i=0;i<192;i++){held.push(Buffer.alloc(8*1024*1024,0x51)); "
        "console.log((i+1)*8*1024*1024)}"], 90)
    after = cgroup()
    events = lambda value: {key: int(number) for key, number in (line.split() for line in value['memory.events'].splitlines())}
    test.assertNotEqual(pressure.returncode, 0, 'Pressure must actually fail allocation or incur OOM')
    test.assertGreater(events(after)['oom_kill'], events(before)['oom_kill'], 'No actual cgroup OOM kill measured')
    test.assertEqual(run(['docker', 'inspect', '--format', '{{.State.Running}}', worker]).stdout.strip(), b'true')
    print(json.dumps({'pressureInjectorExit': pressure.returncode, 'before': before, 'after': after,
                      'workerSurvived': True, 'scope': 'injector OOM, not parent OOM'}))

    def durable_state(scan_id):
        test.assertEqual(str(uuid.UUID(scan_id)), scan_id)
        state = run(compose + ['exec', '-T', 'worker', 'node', '--input-type=module', '-e',
            "import Database from 'better-sqlite3'; const db=new Database(process.env.SCAN_LEDGER_PATH,{readonly:true}); "
            "const id='" + scan_id + "'; console.log(JSON.stringify({outbox:db.prepare('SELECT attempts,lease_until,delivered_at FROM outbox WHERE scan_id=?').get(id), "
            "events:db.prepare('SELECT state,count(*) AS count FROM scan_events WHERE scan_id=? GROUP BY state').all(id), "
            "report:db.prepare('SELECT attempt FROM scan_archive_results WHERE scan_id=?').get(id)??null, now:Date.now()})); db.close()"])
        test.assertEqual(state.returncode, 0, 'Disposable durable attempt read failed')
        return json.loads(state.stdout)

    find_scanner = r"""const fs=require('node:fs');
(async()=>{ const deadline=Date.now()+180000; while(Date.now()<deadline){
for(const pid of fs.readdirSync('/proc').filter(p=>/^\d+$/.test(p))){
 try { const args=fs.readFileSync('/proc/'+pid+'/cmdline','utf8').split('\0');
 if(args[0]==='/usr/local/bin/trivy' && args.includes('--input') && args.includes('vuln')) {
 process.kill(Number(pid), SIGNAL); console.log(pid); return; } } catch {} }
await new Promise(resolve=>setTimeout(resolve,10)); } process.exitCode=1; })();
"""
    for mode in ['kill', 'restart']:
        client = subprocess.Popen(['node', 'server/deploy/proof/nginx-memory-client.mjs', str(credentials), mode],
                                  cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        try:
            # A stuck browser/login must not hold the disposable project forever.
            # A daemon reader also bounds partial/missing newline output.
            lines = queue.Queue(maxsize=1)
            reader = threading.Thread(target=lambda: lines.put(client.stdout.readline()), daemon=True)
            reader.start()
            created = json.loads(lines.get(timeout=120))
            test.assertIn('created', created, 'Actual cookie HTTP job creation failed')
            scan_id = created['created']
            # Detect and signal in the same exec process: a second Docker exec
            # can race completion of a short scanner stage. STOP holds restart's
            # observed real stage only until the whole container is killed.
            probe = run(compose + ['exec', '-T', 'worker', 'node', '-e',
                find_scanner.replace('SIGNAL', json.dumps('SIGKILL' if mode == 'kill' else 'SIGSTOP'))], 190)
            test.assertEqual(probe.returncode, 0, 'Actual vuln scanner stage was not observed/signalled')
            test.assertTrue(probe.stdout.decode().strip().isdigit())
            # Prior checks are in memory only. They persist only if the parent survives.
            if mode == 'restart':
                original = durable_state(scan_id)
                test.assertEqual(original['outbox']['attempts'], 1)
                test.assertIsNone(original['report'], 'No in-memory partial checks may be called durable before parent death')
                remaining = original['outbox']['lease_until'] - original['now']
                test.assertGreater(remaining, 550_000)
                test.assertLessEqual(remaining, 627_000)
                killed_at = time.monotonic()
                test.assertEqual(run(['docker', 'kill', '--signal', 'KILL', worker]).returncode, 0)
                test.assertEqual(run(compose + ['start', 'worker']).returncode, 0)
                # Container restart resets tmpfs: absence of jobs is valid, not a
                # claim that recovery deleted files retained across a container stop.
                time.sleep(3)
                clean = run(compose + ['exec', '-T', 'worker', 'node', '-e',
                    "const fs=require('node:fs'); if((fs.existsSync('/tmp/trivy/jobs') && fs.readdirSync('/tmp/trivy/jobs').length) || !fs.statSync('/tmp/trivy/db/trivy.db').isFile()) process.exit(1)"])
                test.assertEqual(clean.returncode, 0, 'Boot recovery did not clean only abandoned scratch')
            output, _ = client.communicate(timeout=900 if mode == 'restart' else 180)
            test.assertEqual(client.returncode, 0, 'Actual failure/recovery HTTP+DOM proof: ' + output)
            summary = json.loads(output.strip())
            test.assertTrue(summary['independentOutcomes'])
            test.assertTrue(summary['domReload'])
            if mode == 'restart':
                elapsed = time.monotonic() - killed_at
                test.assertGreaterEqual(elapsed * 1000, remaining - 2000, 'Recovery must wait for the unchanged lease deadline')
                summary['restartRecoverySeconds'] = elapsed
                summary['remainingLeaseAtKillMs'] = remaining
                recovered = durable_state(scan_id)
                test.assertEqual(recovered['outbox']['attempts'], 2)
                test.assertIsNotNone(recovered['outbox']['delivered_at'])
                test.assertIsNone(recovered['outbox']['lease_until'])
                test.assertEqual(recovered['report'], {'attempt': 2})
                test.assertEqual({item['state']: item['count'] for item in recovered['events']},
                                 {'queued': 1, 'running': 2, 'completed': 1})
                summary['durableAttempt'] = 2
                summary['terminalEvents'] = 1
                # Attempt to write via the real fence; it must return false with no mutation.
                fence = run(compose + ['exec', '-T', 'worker', 'node', '--import', 'tsx', '--input-type=module', '-e',
                    "import {ScanLedger} from './src/ledger/ledger.ts'; const l=new ScanLedger(process.env.SCAN_LEDGER_PATH); "
                    "if(l.attemptActive('" + scan_id + "',1)||l.finish('" + scan_id + "',1,'failed')) process.exit(1); l.close()"])
                test.assertEqual(fence.returncode, 0, 'Old attempt was not fenced after real restart recovery')
            clean = run(compose + ['exec', '-T', 'worker', 'node', '-e',
                "const fs=require('node:fs'); if(fs.readdirSync('/tmp/trivy/jobs').length) process.exit(1)"])
            test.assertEqual(clean.returncode, 0)
            print(json.dumps(summary))
        finally:
            if client.poll() is None:
                client.kill(); client.communicate(timeout=20)


class NginxMemoryPath(dom.NginxDomPath):
    RUN_MEMORY = True
