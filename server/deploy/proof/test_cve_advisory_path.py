"""Real Stage2 proof on ordinary isolated LOCAL accounts; never deploys LIVE.

Run explicitly, not as an unbounded unittest discovery side effect. Private command
output is captured; only vetted metrics and normalized advisory evidence are emitted.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import traceback
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[3]
PROOF = Path(__file__).resolve().parent


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def core(findings):
    return sorted([{k: v for k, v in f.items() if k != 'advisory'} for f in findings], key=lambda f: f['findingId'])


def invoke(args, timeout=60, cwd=ROOT, data=None):
    return subprocess.run(args, cwd=cwd, input=data, capture_output=True, timeout=timeout, check=False)


def must(args, timeout=60, cwd=ROOT, data=None):
    result = invoke(args, timeout, cwd, data)
    if result.returncode:
        raise RuntimeError('Command failed; private diagnostics suppressed')
    return result.stdout


def cleanup(compose, directory, primary=None, runner=invoke):
    failures = []
    try:
        result = runner(compose + ['down', '--volumes', '--remove-orphans'], 120)
        down = result.returncode == 0
    except Exception:
        down = False
    if not down:
        failures.append('compose-down; mounted fixtures retained')
    if down:
        try:
            shutil.rmtree(directory)
        except Exception:
            failures.append('fixture-removal')
    if failures:
        note = 'Proof cleanup failed: ' + ', '.join(failures) + '; diagnostics suppressed'
        if primary is not None:
            primary.add_note(note)
        else:
            raise RuntimeError(note)
    return {'exactProjectDown': down, 'fixturesRemoved': down and not directory.exists(), 'failures': failures}


LIVE_SQL = """import Database from 'better-sqlite3'; import {createHash} from 'node:crypto';
const out={}; for(const [name,path] of [['auth','/auth/auth.sqlite'],['ledger','/data/ledger.sqlite']]){
 const db=new Database(path,{readonly:true}); db.pragma('query_only=ON');
 const tables=name==='auth'?['users']:db.prepare(\"SELECT name FROM sqlite_master WHERE type='table' AND (name='scans' OR name LIKE 'scan_%') ORDER BY name\").all().map(r=>r.name);
 const hashes={}; for(const table of tables){const rows=db.prepare('SELECT * FROM '+table).all().map(r=>JSON.stringify(r)).sort(); hashes[table]={count:rows.length,sha256:createHash('sha256').update(JSON.stringify(rows)).digest('hex')};}
 out[name]={version:db.pragma('user_version',{simple:true}),tables:hashes};db.close();
}console.log(JSON.stringify(out));"""

SQL = """import Database from 'better-sqlite3'; const db=new Database('/data/ledger.sqlite',{readonly:true});db.pragma('query_only=ON');
const rows=db.prepare('SELECT id,state,registry,repository,digest,platform,checks FROM scans ORDER BY id').all();
for(const r of rows){const a=db.prepare('SELECT report FROM scan_archive_results WHERE scan_id=?').get(r.id);
 if(a){r.archive=JSON.parse(a.report);r.binding=JSON.parse(db.prepare('SELECT binding FROM scan_execution_profiles WHERE scan_id=?').get(r.id).binding);}
 else {r.vuln=db.prepare('SELECT * FROM scan_vuln_results WHERE scan_id=?').get(r.id);r.findings=db.prepare('SELECT finding_id AS findingId,cve_id AS cveId,ecosystem,package_name AS packageName,installed_version AS installedVersion,severity,severity_sources AS severitySources,provenance_ref AS provenanceRef,fixed_version AS fixedVersion,advisory FROM scan_vuln_findings WHERE scan_id=? ORDER BY ordinal').all(r.id).map(({advisory,...f})=>({...f,severitySources:JSON.parse(f.severitySources),...(advisory===null?{}:{advisory:JSON.parse(advisory)})}));}}
console.log(JSON.stringify({version:db.pragma('user_version',{simple:true}),rows}));db.close();"""


def live_snapshot():
    web = must(['docker', 'ps', '-q', '--filter', 'publish=8080']).decode().split()
    assert len(web) == 1, 'Cannot uniquely identify LIVE8080'
    info = json.loads(must(['docker', 'inspect', web[0]]))[0]
    project = info['Config']['Labels']['com.docker.compose.project']
    ids = must(['docker', 'ps', '-q', '--filter', 'label=com.docker.compose.project=' + project]).decode().split()
    containers = json.loads(must(['docker', 'inspect', *ids]))
    api = next(c['Id'] for c in containers if c['Config']['Labels'].get('com.docker.compose.service') == 'api')
    result = {'project': project, 'containers': digest(sorted([{'id': c['Id'], 'image': c['Image'], 'config': c['Config'], 'mounts': sorted(c['Mounts'], key=lambda m: m['Destination']), 'host': c['HostConfig']} for c in containers], key=lambda c: c['id'])),
              'sql': json.loads(must(['docker', 'exec', api, 'node', '--input-type=module', '-e', LIVE_SQL])), 'files': {}}
    for relative in ['.local-auth/stand.env', '.local-auth/stand-composition.json', 'server/deploy/trust/db-signing-key.pub.pem',
                     'docs/notices/shadcn-21st-LICENSE.txt', 'docs/notices/shadcn-21st.md', 'public/notices/shadcn-21st-LICENSE.txt', 'public/notices/shadcn-21st.md']:
        result['files'][relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    return result


def scenario(evidence_path):
    evidence = {'scope': 'Stage2 isolated proof only', 'startedAt': datetime.now(timezone.utc).isoformat(), 'liveDeployment': False, 'wholeTaskAccepted': False, 'reports': [], 'failures': []}
    phase, directory, compose, primary = 'LIVE-readonly-baseline', None, None, None
    baseline = live_snapshot()
    evidence['liveBefore'] = baseline
    backend_paths = sorted(str(p.relative_to(ROOT)) for p in (ROOT / 'server/api/src').rglob('*.ts') if '.test.' not in p.name)
    source_paths = backend_paths + ['src/shared/api/scans/scanTransport.ts', 'src/shared/api/scans/vulnAdvisory.ts', 'src/pages/scans/VulnAdvisoryCard.tsx', 'src/pages/scans/ScanDetailPage.tsx', 'src/pages/scans/ScanCreatePage.tsx', 'server/deploy/compose.stand.yaml', 'server/deploy/compose.stand.vuln.local.yaml', 'server/deploy/compose.stand.nginx.local.yaml', 'server/deploy/proof/test_cve_advisory_path.py', 'server/deploy/proof/cve-advisory-browser.mjs', 'server/deploy/proof/cve-scanner-baseline.mjs']
    def source_hashes():
        return {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in source_paths}
    evidence['sourceHashes'] = source_hashes()
    evidence['reviewedCommit'] = must(['git', '--no-pager', 'rev-parse', 'HEAD']).decode().strip()
    try:
        phase = 'host-current-signed-DB'
        values = dict(line.split('=', 1) for line in (ROOT / '.local-auth/stand.env').read_text().splitlines() if line and not line.startswith('#'))
        manifest, bundle = values['SCAN_VULN_MANIFEST_DIGEST'], values['SCAN_VULN_ARTIFACT_SHA256']
        release = Path(values['SCAN_VULN_RELEASE_HOST_DIR'])
        verify = ['node', '--import', 'tsx', 'src/worker/verify-vuln-db-release.ts', str(release), manifest, bundle]
        must(verify, 180, ROOT / 'server/api')
        metadata = json.loads((release / 'db/metadata.json').read_text())
        evidence['db'] = {'manifest': manifest, 'bundleSha256': bundle, 'metadata': metadata, 'hostFreshVerified': True}
        print(json.dumps({'phase': phase, 'verified': True, 'manifest': manifest, 'nextUpdate': metadata['NextUpdate']}), flush=True)
        project = 'dip-cve-proof-' + secrets.token_hex(6)
        directory = Path(tempfile.mkdtemp(prefix='cve-proof-', dir=ROOT / '.local-auth')); directory.chmod(0o700)
        env = directory / 'frozen.env'
        # No LIVE JWT/auth allowlist is copied into the proof composition.
        frozen = {k: values[k] for k in ['SCAN_VULN_RELEASE_HOST_DIR', 'SCAN_VULN_MANIFEST_DIGEST', 'SCAN_VULN_ARTIFACT_SHA256']}
        frozen.update(SCAN_JWT_SECRET=secrets.token_hex(32), AUTH_ORIGIN='http://127.0.0.1:1')
        env.write_text('\n'.join(k + '=' + v for k, v in frozen.items()) + '\n'); env.chmod(0o600)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        origin = 'http://127.0.0.1:' + str(port)
        credentials = directory / 'credentials.json'
        credentials.write_text(json.dumps([{'email': 'proof-' + secrets.token_hex(12) + '@qualification.invalid', 'password': secrets.token_hex(24)} for _ in range(3)])); credentials.chmod(0o600)
        overlay = directory / 'compose.yaml'
        template = '''services:
  api:
    environment:
      AUTH_ORIGIN: {{ORIGIN}}
      AUTH_ALLOW_INSECURE_LOCAL_HTTP: "true"
      SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: "false"
      SCAN_BROWSER_ALLOWED_USER_IDS: {{IDS}}
      SCAN_JWT_ISSUER: dip-cve-isolated
      SCAN_JWT_AUDIENCE: dip-cve-isolated
  worker:
    volumes:
      - type: bind
        source: {{BASELINE}}
        target: /proof/cve-scanner-baseline.mjs
        read_only: true
        bind: { create_host_path: false }
  web:
    ports: !override ["127.0.0.1:{{PORT}}:8080"]
'''.replace('{{ORIGIN}}', json.dumps(origin)).replace('{{BASELINE}}', json.dumps(str(PROOF / 'cve-scanner-baseline.mjs'))).replace('{{PORT}}', str(port))
        overlay.write_text(template.replace('{{IDS}}', '""')); overlay.chmod(0o600)
        compose = ['docker', 'compose', '-p', project, '--env-file', str(env)]
        for name in ['compose.stand.yaml', 'compose.stand.vuln.local.yaml', 'compose.stand.nginx.local.yaml']:
            compose += ['-f', str(ROOT / 'server/deploy' / name)]
        compose += ['-f', str(overlay)]
        evidence.update(project=project, origin=origin)
        def cmd(args, timeout=60, data=None):
            return must(compose + args, timeout, data=data)
        phase = 'isolated-build'
        cmd(['config', '--quiet'])
        cmd(['build', 'api', 'worker', 'web', 'egress'], 600)
        cmd(['up', '-d', 'auth-volume-init', 'scan-volume-init'], 90)
        phase = 'ordinary-own-account-provision'
        script = "import {AuthStore} from './src/auth/auth.store.ts';import{readFileSync}from'node:fs';const store=new AuthStore();const ids=[];for(const u of JSON.parse(readFileSync(0,'utf8'))){const user=await store.register(u.email,u.password);if(!user)throw Error('not fresh');ids.push(user.id);}store.onModuleDestroy();console.log(JSON.stringify(ids));"
        ids = json.loads(cmd(['run', '--rm', '--no-deps', '-T', 'api', 'node', '--import', 'tsx', '--input-type=module', '-e', script], 90, credentials.read_bytes()))
        assert len(ids) == 3
        overlay.write_text(template.replace('{{IDS}}', json.dumps(','.join(ids[:2]))))
        phase = 'isolated-startup'
        cmd(['up', '-d', '--no-build', '--wait', '--wait-timeout', '120'], 180)
        ready = "import{chainReady}from'./src/scans/scan-readiness.ts';import{localWorkerReady}from'./src/oci/nginx-local-profile.ts';for(let i=0;i<60;i++){if(await chainReady()&&await localWorkerReady())process.exit(0);await new Promise(r=>setTimeout(r,1000));}process.exit(1);"
        cmd(['exec', '-T', 'api', 'node', '--import', 'tsx', '--input-type=module', '-e', ready], 90)
        phase = 'isolation-resource-DB-verification'
        evidence['deployedBackendSourceHashes'] = {}
        for service in ['api', 'worker']:
            container = cmd(['ps', '-q', service]).decode().strip()
            info = json.loads(must(['docker', 'inspect', container]))[0]
            assert info['Config']['User'] == '65532:65532'
            assert info['HostConfig']['ReadonlyRootfs'] and info['HostConfig']['CapDrop'] == ['ALL']
            assert info['HostConfig']['SecurityOpt'] == ['no-new-privileges:true']
            for mount in info['Mounts']:
                if mount['Type'] == 'volume': assert mount['Name'].startswith(project + '_')
                if mount['Type'] == 'bind': assert not mount['RW'] and 'db-signing-key.pem' not in mount['Source']
                assert mount['Destination'] != '/var/run/docker.sock'
            for network in info['NetworkSettings']['Networks']:
                assert network.startswith(project + '_')
                assert json.loads(must(['docker', 'network', 'inspect', '--format', '{{json .Internal}}', network]))
            pins = dict(v.split('=', 1) for v in info['Config']['Env'])
            assert pins['SCAN_VULN_MANIFEST_DIGEST'] == manifest and pins['SCAN_VULN_ARTIFACT_SHA256'] == bundle
            cmd(['exec', '-T', service, 'node', '--import', 'tsx', 'src/worker/verify-vuln-db-release.ts', '/opt/release', manifest, bundle], 180)
            hash_script = "const fs=require('node:fs'),crypto=require('node:crypto');const paths=" + json.dumps(backend_paths) + ";console.log(JSON.stringify(Object.fromEntries(paths.map(p=>[p,crypto.createHash('sha256').update(fs.readFileSync('/app/'+p)).digest('hex')]))));"
            deployed = json.loads(cmd(['exec', '-T', service, 'node', '-e', hash_script]))
            assert deployed == {path: evidence['sourceHashes'][path] for path in backend_paths}
            evidence['deployedBackendSourceHashes'][service] = deployed
            if service == 'worker':
                h = info['HostConfig']
                assert [h[k] for k in ['Memory', 'MemorySwap', 'NanoCpus', 'PidsLimit']] == [1073741824, 1073741824, 1000000000, 128]
                assert h['Tmpfs'] == {'/tmp': 'rw,noexec,nosuid,size=16m', '/tmp/trivy': 'rw,noexec,nosuid,uid=65532,gid=65532,size=512m'}
        def cgroup():
            js = "const fs=require('node:fs');console.log(JSON.stringify(Object.fromEntries(['memory.max','memory.swap.max','memory.current','memory.peak','memory.events','cpu.max','pids.max'].map(n=>[n,fs.readFileSync('/sys/fs/cgroup/'+n,'utf8').trim()]))))"
            return json.loads(cmd(['exec', '-T', 'worker', 'node', '-e', js]))
        initial = cgroup(); assert [initial[k] for k in ['memory.max', 'memory.swap.max', 'cpu.max', 'pids.max']] == ['1073741824', '0', '100000 100000', '128']
        evidence['resourcesBefore'] = initial
        cohort_file = directory / 'cohort.json'
        def browser(mode):
            result = invoke(['node', '--import', 'tsx', str(PROOF / 'cve-advisory-browser.mjs'), str(credentials), origin, str(cohort_file), mode], 1800, ROOT / 'server/api')
            try:
                summary = json.loads(result.stdout)
            except Exception:
                summary = {'failedPhase': 'client-no-safe-summary'}
            evidence['browser-' + mode] = summary
            print(json.dumps(summary), flush=True)
            assert result.returncode == 0, 'Browser proof failed; safe summary recorded'
        phase = 'real-HTTP-Trivy-strict-parser-Chromium'
        # Read-only process observation, not subprocess interception or scanner
        # output. The pathname remains private and belongs to this OWN worker.
        observed = directory / 'observed-paths.jsonl'
        observer_script = "const fs=require('node:fs');const marker='/tmp/cve-proof-observer';fs.writeFileSync(marker,'own');const seen=new Set();const timer=setInterval(()=>{if(!fs.existsSync(marker)){clearInterval(timer);process.exit(0);}for(const pid of fs.readdirSync('/proc').filter(x=>/^[0-9]+$/.test(x))){try{const argv=fs.readFileSync('/proc/'+pid+'/cmdline','utf8').split('\\0');if(argv[0]!=='/usr/local/bin/trivy')continue;const i=argv.indexOf('--input');const path=i<0?null:argv[i+1];if(path&&/^\\/tmp\\/trivy\\/jobs\\/[a-f0-9-]{36}\\/image\\.tar$/.test(path)&&!seen.has(path)){if(seen.size>=4)process.exit(1);seen.add(path);console.log(JSON.stringify({path}));}}catch{}}},250);setTimeout(()=>process.exit(1),1200000).unref();"
        observed.touch(mode=0o600)
        with observed.open('wb') as stream:
            observer = subprocess.Popen(compose + ['exec', '-T', 'worker', 'node', '-e', observer_script], cwd=ROOT, stdout=stream, stderr=subprocess.DEVNULL)
            try:
                browser('create')
            finally:
                try:
                    cmd(['exec', '-T', 'worker', 'node', '-e', "require('node:fs').rmSync('/tmp/cve-proof-observer',{force:true})"])
                finally:
                    try:
                        observer.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        observer.kill(); observer.wait(timeout=10)
        cohort = json.loads(cohort_file.read_text())['records']
        archive_paths = [json.loads(line)['path'] for line in observed.read_text().splitlines()]
        assert observer.returncode == 0 and len(archive_paths) == 2
        phase = 'same-frozen-companion-scanners'
        companions = {'alpine': json.loads(cmd(['exec', '-T', 'worker', 'node', '--import', 'tsx', '/proof/cve-scanner-baseline.mjs', 'alpine'], 360))}
        for r, path in zip([r for r in cohort if r['name'].startswith('archive-')], archive_paths):
            companions[r['name']] = json.loads(cmd(['exec', '-T', 'worker', 'node', '--import', 'tsx', '/proof/cve-scanner-baseline.mjs', 'archive', path], 360))
        for mode, companion in companions.items():
            print(json.dumps({'phase': 'actual-companion-' + mode, 'uniqueCount': companion['uniqueCount'], 'independentIds': companion['independentIds'], 'observedOwnJobPathReused': companion['observedOwnJobPathReused']}), flush=True)
        sql = json.loads(cmd(['exec', '-T', 'api', 'node', '--input-type=module', '-e', SQL]))
        assert sql['version'] == 13 and len(sql['rows']) == 4
        phase = 'BOTH-SQLite-all-pages-core-advisory-equality'
        for r in cohort:
            row = next(row for row in sql['rows'] if row['id'] == r['scanId'])
            archive = 'archive' in row
            stored = row['archive']['vuln']['findings'] if archive else row['findings']
            api = r['snapshot']['vuln']['findings']
            companion = companions[r['name'] if archive else 'alpine']
            assert len(api) > 0
            comparisons = {'name': r['name'], 'count': len(api), 'SQLAPIEqual': sorted(stored, key=lambda f: f['findingId']) == sorted(api, key=lambda f: f['findingId']), 'companionCoreEqual': core(api) == core(companion['findings']), 'companionAdvisoryEqual': sorted(api, key=lambda f: f['findingId']) == sorted(companion['findings'], key=lambda f: f['findingId'])}
            print(json.dumps(comparisons), flush=True)
            evidence.setdefault('comparisons', []).append(comparisons)
            assert comparisons['SQLAPIEqual']
            assert core(api) == core(companion['findings'])
            assert sorted(api, key=lambda f: f['findingId']) == sorted(companion['findings'], key=lambda f: f['findingId'])
            assert row['state'] == 'completed' and row['platform'] == 'linux/amd64'
            assert r['image'] == companion['image']
            head = r['snapshot']['vuln']['rawPages'][0]
            if archive:
                assert head['db'] == companion['db'] and row['archive']['vuln']['db'] == companion['db']
                assert row['archive']['receipt'] == companion['receipt']
                if 'sbom' in r['checks']:
                    inventory = sorted([{k: component[k] for k in ['ecosystem', 'name', 'version']} for component in r['snapshot']['sbom']['findings']], key=lambda c: json.dumps(c, sort_keys=True))
                    assert inventory == sorted(companion['packageInventory'], key=lambda c: json.dumps(c, sort_keys=True))
            else:
                assert 'db' not in head  # Ordinary durable history has no DB identity.
                assert row['vuln']['image'] == r['image'] and row['vuln']['finding_count'] == len(api)
                assert row['vuln']['checked_at'] == head['checkedAt']
            evidence['reports'].append({'name': r['name'], 'scanId': r['scanId'], 'url': origin + '/scans/' + r['scanId'], 'checks': r['checks'], 'image': r['image'], 'count': len(api), 'pages': len(r['snapshot']['vuln']['rawPages']), 'fullIdsHash': digest(sorted(f['findingId'] for f in api)), 'coreHash': digest(core(api)), 'fullFindingHash': digest(sorted(api, key=lambda f: f['findingId'])), 'scannerSQLAPIBrowserEqual': True, 'companionNotJobStdout': True, 'dbStored': head.get('db'), 'scannerVersion': head['scannerVersion'], 'checkedAt': head['checkedAt'], 'dom': r['dom'], 'perCheck': r['snapshot']['status']['perCheck'], 'sbom': {'count': r['snapshot']['sbom']['total'], 'pages': len(r['snapshot']['sbom']['rawPages']), 'fullComponentHash': digest(r['snapshot']['sbom']['findings']), 'os': r['snapshot']['sbom']['rawPages'][0]['os']} if 'sbom' in r['checks'] else None, 'config': {'supportedRuleIds': r['snapshot']['status']['config']['supportedRuleIds'], 'completedRuleIds': r['snapshot']['status']['config']['completedRuleIds'], 'findingRuleIds': [f['ruleId'] for f in r['snapshot']['status']['config']['findings']], 'coverage': r['snapshot']['status']['config']['config']} if 'config' in r['checks'] else None})
        evidence['companions'] = {k: {key: value for key, value in v.items() if key not in ['findings', 'packageInventory']} for k, v in companions.items()}
        final = cgroup(); evidence['resourcesAfter'] = final
        for event in ['oom', 'oom_kill', 'oom_group_kill']:
            assert dict(line.split() for line in initial['memory.events'].splitlines())[event] == dict(line.split() for line in final['memory.events'].splitlines())[event]
        cmd(['exec', '-T', 'worker', 'node', '-e', "const fs=require('node:fs');if(fs.readdirSync('/tmp/trivy/jobs').length)process.exit(1)"])
        phase = 'own-API-worker-recreation-same-volumes-JWT'
        cmd(['up', '-d', '--no-build', '--no-deps', '--force-recreate', 'worker', 'api'], 180)
        cmd(['exec', '-T', 'api', 'node', '--import', 'tsx', '--input-type=module', '-e', ready], 90)
        assert json.loads(cmd(['exec', '-T', 'api', 'node', '--input-type=module', '-e', SQL])) == sql
        browser('verify')
        recreated = json.loads(cohort_file.read_text())['records']
        for report in evidence['reports']:
            record = next(r for r in recreated if r['scanId'] == report['scanId'])
            assert record['recreatedDom']['fullIdsHash'] == report['dom']['fullIdsHash']
            assert record['recreatedDom']['coreHash'] == report['dom']['coreHash']
            report['recreatedDom'] = record['recreatedDom']
        evidence['sameReportsRecreated'] = True
        phase = 'fresh-DB-end-verification'
        must(verify, 180, ROOT / 'server/api')
        for service in ['api', 'worker']:
            cmd(['exec', '-T', service, 'node', '--import', 'tsx', 'src/worker/verify-vuln-db-release.ts', '/opt/release', manifest, bundle], 180)
        assert json.loads((release / 'db/metadata.json').read_text()) == metadata
        evidence['db']['endFreshVerified'] = True
        assert source_hashes() == evidence['sourceHashes']
        evidence['sourcesUnchangedDuringProof'] = True
    except Exception as error:
        primary = error
        location = next((f.lineno for f in reversed(traceback.extract_tb(error.__traceback__)) if f.filename == __file__), None)
        evidence['failures'].append({'phase': phase, 'type': type(error).__name__, 'proofLine': location, 'diagnosticsSuppressed': True})
        print(json.dumps({'failedPhase': phase, 'errorType': type(error).__name__, 'proofLine': location, 'diagnosticsSuppressed': True}), flush=True)
    finally:
        if compose:
            try:
                evidence['cleanup'] = cleanup(compose, directory, primary)
            except Exception as error:
                primary = primary or error
                evidence['cleanup'] = {'exactProjectDown': False, 'diagnosticsSuppressed': True}
        try:
            after = live_snapshot()
            evidence['livePreserved'] = after == baseline
            evidence['liveAfter'] = after
            assert after == baseline
        except Exception as error:
            evidence['failures'].append({'phase': 'LIVE-preservation', 'type': type(error).__name__})
            primary = primary or error
        evidence['finishedAt'] = datetime.now(timezone.utc).isoformat()
        evidence['passed'] = primary is None
        evidence_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps({'passed': evidence['passed'], 'livePreserved': evidence.get('livePreserved'), 'cleanup': evidence.get('cleanup'), 'evidence': str(evidence_path.relative_to(ROOT)), 'reportCounts': [r['count'] for r in evidence['reports']]}), flush=True)
    return 1 if primary else 0


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: python test_cve_advisory_path.py <sanitized-evidence-path>')
    raise SystemExit(scenario(Path(sys.argv[1]).resolve()))
