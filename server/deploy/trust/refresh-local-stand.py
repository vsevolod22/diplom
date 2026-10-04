#!/usr/bin/env python3
"""Operator-host-only, opt-in unattended local stand DB publisher.

Trust policy: verified HTTPS transport and OCI hashes, NOT publisher signature.
Never run inside the worker, CI or a container. No keys or scanner output in logs.
"""
import hashlib
import json
import os
from pathlib import Path
import re

import subprocess
import sys
import tempfile
import time

SHA = re.compile(r'sha256:[a-f0-9]{64}\Z')
HEX = re.compile(r'[a-f0-9]{64}\Z')
REPO = Path(__file__).resolve().parents[3]
TRUST = REPO / 'server/deploy/trust'
ROOT = REPO / '.local-auth'
ENV = ROOT / 'stand.env'
COMPOSE = ['docker', 'compose', '--env-file', str(ENV), '-f', str(REPO / 'server/deploy/compose.stand.yaml'),
           '-f', str(REPO / 'server/deploy/compose.stand.vuln.local.yaml')]


def check(ok):
    if not ok:
        raise ValueError('local DB refresh validation failed')


def run(*args, timeout=900):
    # Never print subprocess stderr: registry errors and Docker diagnostics can carry URLs.
    completed = subprocess.run(args, cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=timeout, check=False)
    check(completed.returncode == 0)
    return completed.stdout.decode('utf-8', errors='strict')


def regular(path, cap):
    st = path.lstat()
    check(path.is_file() and not path.is_symlink() and 0 < st.st_size <= cap)
    return st


def digest(path, cap):
    regular(path, cap)
    h = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def env_values(text):
    values = {}
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition('=')
        check(sep and re.fullmatch(r'[A-Z][A-Z0-9_]*', key) and key not in values)
        values[key] = value
    check(all(k in values for k in ('SCAN_JWT_SECRET', 'SCAN_VULN_RELEASE_HOST_DIR',
                                    'SCAN_VULN_MANIFEST_DIGEST', 'SCAN_VULN_ARTIFACT_SHA256')))
    return values


def replace_pins(text, release, manifest, bundle):
    check(release.is_absolute() and SHA.fullmatch(manifest) and HEX.fullmatch(bundle))
    values = env_values(text)
    pins = {'SCAN_VULN_RELEASE_HOST_DIR': str(release), 'SCAN_VULN_MANIFEST_DIGEST': manifest,
            'SCAN_VULN_ARTIFACT_SHA256': bundle}
    check(all('\n' not in v and '\r' not in v for v in pins.values()))
    return '\n'.join(line.partition('=')[0] + '=' + pins[line.partition('=')[0]]
                     if line.partition('=')[0] in pins else line for line in text.splitlines()) + '\n'


def atomic_env(text):
    check(ENV.lstat().st_mode & 0o777 == 0o600 and not ENV.is_symlink())
    fd, name = tempfile.mkstemp(prefix='.stand.env-', dir=ROOT)
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, ENV)
        directory = os.open(ROOT, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def healthy():
    lines = run(*COMPOSE, 'ps', '--format', 'json', timeout=45).splitlines()
    services = {record['Service']: record for record in (json.loads(line) for line in lines if line.strip())}
    return (services.get('api', {}).get('State') == 'running' and
            services['api'].get('Health') == 'healthy' and
            services.get('worker', {}).get('State') == 'running')


def container_preflight(manifest, bundle):
    for service in ('api', 'worker'):
        run(*COMPOSE, 'exec', '-T', service, 'node', '--import', 'tsx',
            'src/worker/verify-vuln-db-release.ts', '/opt/release', manifest, bundle, timeout=180)


def scan_chain_ready():
    run(*COMPOSE, 'exec', '-T', 'api', 'node', '--import', 'tsx', '--input-type=module', '-e',
        "import {chainReady} from './src/scans/scan-readiness.ts'; process.exit((await chainReady()) ? 0 : 1)",
        timeout=30)


def switch(text, updated, manifest, bundle):
    """Switch pins, recreate two services, verify readiness; restore old pins on failure."""
    atomic_env(updated)
    try:
        run(*COMPOSE, 'config', '--quiet', timeout=30)
        run(*COMPOSE, 'up', '-d', '--no-build', '--no-deps', '--force-recreate', 'worker', 'api', timeout=180)
        for _ in range(30):
            if healthy():
                container_preflight(manifest, bundle)
                scan_chain_ready()
                return
            time.sleep(2)
        raise ValueError('services did not become healthy')
    except BaseException:
        atomic_env(text)
        try:
            run(*COMPOSE, 'up', '-d', '--no-build', '--no-deps', '--force-recreate', 'worker', 'api', timeout=180)
        except Exception:
            pass  # Retain previous env; operator alert is still required.
        raise


def refresh():
    check(ROOT.is_dir() and not ROOT.is_symlink())
    lock = ROOT / '.trivy-refresh.lock'
    lock.mkdir(mode=0o700)  # exclusive across timer/manual runs
    try:
        current = ENV.read_text()
        values = env_values(current)
        key = ROOT / 'trust/db-signing-key.pem'
        check(regular(key, 8192).st_mode & 0o077 == 0)
        candidates = ROOT / 'trivy-db-candidates'
        releases = ROOT / 'trivy-db-releases'
        check(all(p.is_dir() and not p.is_symlink() for p in (candidates, releases)))
        discovery = run('node', str(TRUST / 'fetch-db-layer.mjs'), 'discover', timeout=90)
        match = re.fullmatch(r'Review upstream tag :2, then download by digest: (sha256:[a-f0-9]{64})\n', discovery)
        check(match is not None)
        manifest = match[1]
        if values['SCAN_VULN_MANIFEST_DIGEST'] == manifest:
            # An unchanged upstream tag does not imply a still-fresh local DB.
            active = Path(values['SCAN_VULN_RELEASE_HOST_DIR'])
            check(active.is_absolute() and active.is_dir() and not active.is_symlink() and
                  SHA.fullmatch(values['SCAN_VULN_MANIFEST_DIGEST']) and
                  HEX.fullmatch(values['SCAN_VULN_ARTIFACT_SHA256']))
            run('pnpm', '--filter', '@diplom/scan-api', 'exec', 'tsx', 'src/worker/verify-vuln-db-release.ts',
                str(active), manifest, values['SCAN_VULN_ARTIFACT_SHA256'], timeout=180)
            container_preflight(manifest, values['SCAN_VULN_ARTIFACT_SHA256'])
            scan_chain_ready()
            print('DB still fresh and current; no change')
            return
        candidate = candidates / manifest
        if candidate.exists():
            check(candidate.is_dir() and not candidate.is_symlink())
        else:
            run('node', str(TRUST / 'fetch-db-layer.mjs'), manifest, str(candidate), timeout=600)
        manifest_bytes = (candidate / 'manifest.json').read_bytes()
        check(len(manifest_bytes) <= 65536 and 'sha256:' + hashlib.sha256(manifest_bytes).hexdigest() == manifest)
        descriptor = json.loads(manifest_bytes)
        layer = descriptor['layers'][0]
        check(isinstance(descriptor['layers'], list) and len(descriptor['layers']) == 1 and
              layer['mediaType'] == 'application/vnd.aquasec.trivy.db.layer.v1.tar+gzip' and
              SHA.fullmatch(layer['digest']) and type(layer['size']) is int and
              layer['size'] == regular(candidate / 'layer.tar.gz', 512 * 1024 ** 2).st_size and
              'sha256:' + digest(candidate / 'layer.tar.gz', 512 * 1024 ** 2) == layer['digest'])
        release = releases / manifest[7:]
        check(not release.exists())  # a failed partial release is investigated, never reused
        output = run('python3', str(TRUST / 'prepare-db-release.py'), str(candidate), str(release),
                     manifest, layer['digest'], timeout=900)
        hashes = json.loads(output.splitlines()[0])
        check(hashes['manifest'] == manifest and hashes['layer'] == layer['digest'] and
              HEX.fullmatch(hashes['bundle']) and HEX.fullmatch(hashes['db']))
        run('node', str(TRUST / 'sign-offline-db.mjs'), str(release), str(key),
            str(TRUST / 'db-signing-key.pub.pem'), manifest, hashes['bundle'], hashes['db'], timeout=180)
        run('pnpm', '--filter', '@diplom/scan-api', 'exec', 'tsx', 'src/worker/verify-vuln-db-release.ts',
            str(release), manifest, hashes['bundle'], timeout=180)
        run('python3', str(REPO / 'server/deploy/proof/offline_vuln_db_proof.py'),
            str(release), hashes['db'], hashes['bundle'], timeout=300)
        for folder in (release / 'db', release):
            folder.chmod(0o555)
        for name in ('bundle.bin', 'descriptor.json', 'descriptor.sig', 'db/trivy.db', 'db/metadata.json'):
            (release / name).chmod(0o444)
        switch(current, replace_pins(current, release, manifest, hashes['bundle']), manifest, hashes['bundle'])
        print('DB release activated; TLS/OCI/local signature verified (NOT publisher identity)')
    finally:
        lock.rmdir()


if __name__ == '__main__':
    try:
        check(len(sys.argv) == 1)
        refresh()
    except (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.TimeoutExpired, UnicodeError) as error:
        print('Local DB refresh failed; inspect operator logs and active pins; no scanner DB fallback', file=sys.stderr)
        sys.exit(1)
