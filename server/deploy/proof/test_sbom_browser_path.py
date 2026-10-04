"""Isolated browser-API (not DOM/Playwright) SBOM proof through published nginx.

Run: python3 -m unittest server/deploy/proof/test_sbom_browser_path.py -v
Requires Docker and public Docker Hub access. No skips; never prints secrets, IDs or raw responses.
"""
import json
import os
import re
import secrets
import socket
import subprocess
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

COMPOSE = Path(__file__).resolve().parents[1] / 'compose.stand.yaml'
PROJECT = 'dip-browser-sbom-proof-' + secrets.token_hex(8)
BASE = ('docker', 'compose', '-p', PROJECT, '-f', str(COMPOSE))
ORIGIN = 'http://127.0.0.1:8080'
IMAGE = 'registry-1.docker.io/library/alpine@sha256:d56c381f961d307a21b3ca004cf1e3910f106644aefb1f43e654c8a56c4fd395'
CANARY = 'CANARY_BROWSER_SBOM_' + secrets.token_hex(12)
# Do not inherit stale Compose overrides or account enrollment from the user's shell.
ENV = {key: value for key, value in os.environ.items()
       if key not in {'COMPOSE_PROJECT_NAME', 'COMPOSE_FILE', 'COMPOSE_PROFILES', 'COMPOSE_ENV_FILES',
                      'SCAN_JWT_SECRET', 'SCAN_BROWSER_ALLOWED_USER_IDS'}}
ENV.update(SCAN_JWT_SECRET=secrets.token_hex(32), AUTH_ORIGIN=ORIGIN,
           AUTH_ALLOW_INSECURE_LOCAL_HTTP='true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS='true',
           SCAN_BROWSER_ALLOWED_USER_IDS='')

# Only fixed labels/counts leave the container. Never print the ledger or its rows.
LEDGER_CHECK = r'''const fs=require('node:fs'), Database=require('better-sqlite3');
const canary=process.argv[1];
try {
 const db=new Database(process.env.SCAN_LEDGER_PATH,{readonly:true,fileMustExist:true});
 let scans,components,vuln,checked;
 try {
  scans=db.prepare('SELECT count(*) n FROM scans').get().n;
  components=db.prepare('SELECT count(*) n FROM scan_sbom_components').get().n;
  vuln=db.prepare("SELECT count(*) n FROM scans WHERE checks LIKE '%vuln%'").get().n;
  checked=db.prepare("SELECT count(*) n FROM scan_sbom_results WHERE outcome='checked'").get().n;
 } finally {db.close()}
 const clean=['/data/ledger.sqlite','/data/ledger.sqlite-wal','/data/ledger.sqlite-shm']
  .filter(fs.existsSync).every(p=>!fs.readFileSync(p).includes(canary));
 console.log(JSON.stringify({scans,components,vuln,checked,clean}));
} catch {console.log(JSON.stringify({error:'ledger-check-failed'}));process.exitCode=1}'''


def run(*args, timeout=30):
    try:
        return subprocess.run(args, env=ENV, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise AssertionError('required Docker command unavailable or timed out') from None


def compose(*args, timeout=30):
    return run(*BASE, *args, timeout=timeout)


def require(ok, label):
    if not ok:
        raise AssertionError(label)


def request(path, method='GET', cookie=None, payload=None):
    headers = {}
    if cookie:
        headers['Cookie'] = cookie
    data = None
    if payload is not None:
        data = json.dumps(payload).encode('utf-8')
        headers.update({'Origin': ORIGIN, 'Content-Type': 'application/json'})
    try:
        with urlopen(Request(ORIGIN + path, data=data, headers=headers, method=method), timeout=12) as response:
            return response.status, dict(response.headers), response.read(65536)
    except HTTPError as error:
        error.close()  # Never include raw response or URL in an exception.
        return error.code, {}, b''
    except (OSError, URLError):
        raise AssertionError('loopback HTTP request unavailable') from None


def json_body(data, label):
    try:
        return json.loads(data)
    except (ValueError, UnicodeDecodeError):
        raise AssertionError(label + ': invalid JSON (body suppressed)') from None


class BrowserSbomProof(unittest.TestCase):
    def test_cookie_bound_sbom_over_published_nginx(self):
        require(run('docker', 'info', timeout=12).returncode == 0, 'Docker Engine required')
        config = compose('config', '--format', 'json', timeout=20)
        require(config.returncode == 0, 'stand Compose config unavailable')
        topology = json_body(config.stdout, 'Compose config')
        require(topology['networks']['scan_internal']['internal'], 'scan network must be internal')
        require(set(topology['services']['worker']['networks']) == {'scan_internal'}, 'worker network changed')
        require(set(topology['services']['egress']['networks']) == {'scan_internal', 'registry_uplink'}, 'egress networks changed')
        require(set(topology['services']['api']['networks']) == {'auth_internal', 'scan_internal'}, 'API networks changed')
        require('ports' not in topology['services']['api'] and 'ports' not in topology['services']['worker'], 'internal ports exposed')
        ports = topology['services']['web']['ports']
        require(len(ports) == 1 and ports[0]['host_ip'] == '127.0.0.1' and
                ports[0]['published'] == '8080' and ports[0]['target'] == 8080, 'web port differs from loopback 8080')
        # Bind before starting Docker: an occupied port is a hard failure, never shut down its owner.
        try:
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 8080))
        except OSError:
            raise AssertionError('loopback port 8080 occupied; no Compose project started') from None

        started = False
        try:
            started = True  # Even a partially successful up owns resources to tear down.
            up = compose('up', '-d', '--build', timeout=400)
            require(up.returncode == 0, 'isolated stand build/start failed (raw diagnostics suppressed)')
            for _ in range(25):
                try:
                    status, _, _ = request('/api/v1/auth/me')
                    if status == 401:
                        break
                except AssertionError:
                    pass
                time.sleep(1)
            else:
                self.fail('published nginx/auth not ready')
            require(request('/api/v1/scans')[0] == 404, 'private JWT API exposed by nginx')
            require(request('/api/v1/browser/scans')[0] == 401, 'anonymous browser list not denied')
            key = secrets.token_hex(10)
            accounts = []
            for number in (1, 2):
                credentials = {'email': 'sbom-proof-' + key + '-' + str(number) + '@example.invalid',
                               'password': secrets.token_urlsafe(24)}
                code, headers, _ = request('/api/v1/auth/register', 'POST', payload=credentials)
                require(code == 201, 'register failed')
                cookie = headers.get('Set-Cookie', '').split(';', 1)[0]
                require(re.fullmatch(r'demo_session=[A-Za-z0-9_-]{43}', cookie) is not None, 'register cookie missing')
                code, _, _ = request('/api/v1/auth/logout', 'POST', cookie=cookie, payload={})
                require(code == 204, 'logout failed')
                require(request('/api/v1/browser/scans', cookie=cookie)[0] == 401, 'revoked cookie accepted')
                code, headers, _ = request('/api/v1/auth/login', 'POST', payload=credentials)
                require(code == 200, 'login failed')
                cookie = headers.get('Set-Cookie', '').split(';', 1)[0]
                require(re.fullmatch(r'demo_session=[A-Za-z0-9_-]{43}', cookie) is not None, 'login cookie missing')
                accounts.append(cookie)
            alice, bob = accounts
            path = '/api/v1/browser/scans'
            body = lambda checks, key: {'imageReference': IMAGE, 'checks': checks, 'scope': 'image', 'idempotencyKey': key}
            require(request(path, 'POST', payload=body(['sbom'], 'anonymous-test'))[0] == 401, 'anonymous create accepted')
            for checks in (['vuln'], ['sbom', 'vuln']):
                require(request(path, 'POST', alice, body(checks, 'vuln-' + secrets.token_hex(5)))[0] == 400,
                        'vulnerability check admitted')
            require(request(path, 'POST', alice, {**body(['sbom'], 'canary-' + secrets.token_hex(5)),
                                                   'canary': CANARY})[0] == 400, 'canary request admitted')
            ledger = compose('exec', '-T', 'api', 'node', '-e', LEDGER_CHECK, CANARY, timeout=15)
            require(ledger.returncode == 0, 'pre-scan ledger inspection failed')
            pre = json_body(ledger.stdout, 'pre-scan ledger')
            require(pre == {'scans': 0, 'components': 0, 'vuln': 0, 'checked': 0, 'clean': True},
                    'negative requests enqueued or persisted canary')
            code, _, data = request(path, 'POST', alice, body(['sbom'], 'sbom-' + secrets.token_hex(5)))
            require(code == 202, 'SBOM create did not return 202')
            receipt = json_body(data, 'SBOM receipt')
            scan_id = receipt.get('scanId') if isinstance(receipt, dict) else None
            require(isinstance(scan_id, str) and re.fullmatch(r'[a-f0-9-]{36}', scan_id) is not None,
                    'invalid SBOM receipt')
            item = path + '/' + scan_id
            require(request(item, cookie=bob)[0] == 404 and request(item + '/sbom', cookie=bob)[0] == 404,
                    'cross-account read accepted')
            require(request(item)[0] == 401 and request(item + '/sbom')[0] == 401, 'anonymous read accepted')
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                code, _, data = request(item, cookie=alice)
                require(code == 200, 'owner status unavailable')
                status = json_body(data, 'status')
                require(isinstance(status, dict), 'invalid status shape')
                if status.get('state') in ('completed', 'failed', 'cancelled'):
                    break
                time.sleep(2)
            else:
                self.fail('SBOM worker did not reach terminal state')
            require(status.get('state') == 'completed', 'SBOM worker did not complete')
            require(status.get('check') == 'sbom' and status.get('digest') == IMAGE.split('@')[1] and
                    status.get('platform') == 'linux/amd64', 'status target mismatch')
            result = status.get('result')
            require(isinstance(result, dict) and result.get('coverage') == 'image' and
                    result.get('outcome') == 'checked' and result.get('componentCount') == 16,
                    'SBOM result not checked with 16 components')
            components = []
            cursor = 0
            for page_number in range(1, 6):
                code, _, data = request(item + '/sbom?limit=5&cursor=' + str(cursor), cookie=alice)
                require(code == 200, 'SBOM page unavailable')
                page = json_body(data, 'SBOM page')
                require(isinstance(page, dict) and page.get('outcome') == 'checked' and
                        page.get('coverage') == 'image' and page.get('image') == IMAGE and
                        page.get('platform') == 'linux/amd64' and page.get('componentCount') == 16 and
                        isinstance(page.get('os'), dict) and page['os'].get('name') == 'alpine',
                        'SBOM page metadata mismatch')
                entries = page.get('components')
                require(isinstance(entries, list) and 0 < len(entries) <= 5 and
                        all(isinstance(c, dict) and set(c) == {'ecosystem', 'name', 'version'} and
                            c['ecosystem'] == 'apk' and isinstance(c['name'], str) and
                            isinstance(c['version'], str) for c in entries), 'non-APK or invalid SBOM page')
                components.extend(entries)
                if page.get('nextCursor') is None:
                    break
                require(page['nextCursor'] == len(components), 'SBOM pagination cursor mismatch')
                cursor = page['nextCursor']
            else:
                self.fail('SBOM pagination did not terminate')
            require(page_number == 4 and len(components) == 16 and
                    len({(c['ecosystem'], c['name'], c['version']) for c in components}) == 16,
                    'SBOM does not contain 16 distinct APKs across 4 pages')
            require(request(item + '/sbom', cookie=bob)[0] == 404, 'cross-account SBOM leaked')
            ledger = compose('exec', '-T', 'api', 'node', '-e', LEDGER_CHECK, CANARY, timeout=15)
            require(ledger.returncode == 0, 'post-scan ledger inspection failed')
            require(json_body(ledger.stdout, 'post-scan ledger') ==
                    {'scans': 1, 'components': 16, 'vuln': 0, 'checked': 1, 'clean': True},
                    'ledger coverage or canary mismatch')
            for service in ('api', 'worker', 'egress', 'web'):
                logs = compose('logs', '--no-color', service, timeout=15)
                require(logs.returncode == 0, 'isolated service logs unavailable')
                require(CANARY not in logs.stdout + logs.stderr, 'canary present in isolated service logs')
            print('browser HTTP/API proof: cookie auth, scoped SBOM 16 APKs, negatives, ledger/log canary clean; DOM not tested')
        finally:
            if started:
                down = compose('down', '-v', '--remove-orphans', timeout=75)
                require(down.returncode == 0, 'isolated Compose cleanup failed (raw diagnostics suppressed)')


if __name__ == '__main__':
    unittest.main()
