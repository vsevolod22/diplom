"""Explicit, local-only Trivy 0.69.3 compatibility proof; NOT DB publisher attestation.

Run with pinned hashes from independently reviewed provisioning records:
 python3 server/deploy/proof/offline_vuln_db_proof.py DB_DIRECTORY DB_SHA256 BUNDLE_SHA256
Does not change the running stand, grant admission, fetch DB, or print raw scanner output.
"""
import gzip
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

TRIVY = 'aquasec/trivy:0.69.3'
MAX_DB = 2 * 1024 ** 3
MAX_BUNDLE = 512 * 1024 ** 2
DOCKERFILE = 'FROM scratch\nCOPY etc/alpine-release /etc/alpine-release\nCOPY lib/apk/db/installed /lib/apk/db/installed\nCOPY package-lock.json /app/package-lock.json\nCOPY package.json /app/package.json\nCOPY node_modules/lodash/package.json /app/node_modules/lodash/package.json\n'
APK = 'P:openssl\nV:3.3.2-r0\nA:x86_64\nS:10000\nI:10000\nT:OpenSSL\nU:https://www.openssl.org/\nL:Apache-2.0\n\n'
LOCK = {'name': 'offline-vuln-proof', 'version': '1.0.0', 'lockfileVersion': 2,
        'requires': True,
        'packages': {'': {'name': 'offline-vuln-proof', 'version': '1.0.0',
                         'dependencies': {'lodash': '4.17.20'}},
                     'node_modules/lodash': {'version': '4.17.20',
                                             'resolved': 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz',
                                             'integrity': 'sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='}},
        'dependencies': {'lodash': {'version': '4.17.20',
                                    'resolved': 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz',
                                    'integrity': 'sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='}}}


def digest(stream, limit):
    h = hashlib.sha256()
    total = 0
    while chunk := stream.read(1024 * 1024):
        total += len(chunk)
        if total > limit:
            raise AssertionError('DB artifact exceeds proof limit')
        h.update(chunk)
    return h.hexdigest(), total


def run(*args, timeout=120):
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, check=False)


def assert_fresh(metadata):
    assert metadata['Version'] == 2, 'incompatible DB schema'
    def stamp(name):
        text = metadata[name]
        assert isinstance(text, str) and text.endswith('Z')
        return datetime.fromisoformat(text.replace('Z', '+00:00'))
    now = datetime.now(timezone.utc)
    updated, downloaded, next_update = (stamp(k) for k in ('UpdatedAt', 'DownloadedAt', 'NextUpdate'))
    assert updated <= downloaded <= now + timedelta(minutes=5)
    assert updated <= now + timedelta(minutes=5)
    assert now - updated < timedelta(hours=48)
    assert now - downloaded < timedelta(hours=24)
    assert now < next_update <= updated + timedelta(days=7), 'DB stale or invalid NextUpdate'


def scanner(db, image, cache, *, with_db=True):
    command = ['docker', 'run', '--rm', '--network', 'none', '--read-only',
               '--security-opt', 'no-new-privileges', '--cap-drop', 'ALL',
               '--memory', '2g', '--pids-limit', '100',
               '--tmpfs', '/tmp:rw,noexec,nosuid,size=512m',
               '--mount', f'type=bind,src={image},dst=/image.tar,readonly']
    if with_db:
        command += ['--mount', f'type=bind,src={db},dst=/tmp/cache/db,readonly']
    command += [TRIVY, 'image', '--quiet', '--scanners', 'vuln',
                '--skip-db-update', '--skip-java-db-update', '--offline-scan',
                '--cache-dir', cache, '--format', 'json', '--input', '/image.tar']
    return run(*command, timeout=120)


def main():
    if len(sys.argv) != 4 or any(len(x) != 64 or any(c not in '0123456789abcdef' for c in x)
                                 for x in sys.argv[2:]):
        raise SystemExit('usage: offline_vuln_db_proof.py DB_DIRECTORY DB_SHA256 BUNDLE_SHA256')
    root = pathlib.Path(sys.argv[1]).resolve(strict=True)
    db = root / 'db'
    metadata = json.loads((db / 'metadata.json').read_text())
    assert_fresh(metadata)
    for broken in ({**metadata, 'NextUpdate': '2020-01-01T00:00:00Z'},
                   {**metadata, 'UpdatedAt': '2020-01-01T00:00:00Z'},
                   {**metadata, 'Version': 3}):
        try:
            assert_fresh(broken)
        except (AssertionError, KeyError, ValueError):
            pass
        else:
            raise AssertionError('stale or incompatible DB metadata was accepted')
    assert (db / 'trivy.db').stat().st_size <= MAX_DB
    assert (root / 'bundle.bin').stat().st_size <= MAX_BUNDLE
    with (db / 'trivy.db').open('rb') as f:
        assert digest(f, MAX_DB)[0] == sys.argv[2], 'pinned DB digest mismatch'
    with (root / 'bundle.bin').open('rb') as f:
        assert digest(f, MAX_BUNDLE)[0] == sys.argv[3], 'pinned bundle digest mismatch'
    with gzip.open(root / 'bundle.bin', 'rb') as f:
        assert digest(f, MAX_DB)[0] == sys.argv[2], 'bundle does not unpack to pinned DB'
    with tempfile.TemporaryDirectory(prefix='dip-offline-vuln-') as temp:
        base = pathlib.Path(temp)
        context = base / 'context'
        (context / 'etc').mkdir(parents=True)
        (context / 'lib/apk/db').mkdir(parents=True)
        (context / 'node_modules/lodash').mkdir(parents=True)
        (context / 'Dockerfile').write_text(DOCKERFILE)
        (context / 'etc/alpine-release').write_text('3.21.0\n')
        (context / 'lib/apk/db/installed').write_text(APK)
        (context / 'package-lock.json').write_text(json.dumps(LOCK))
        (context / 'package.json').write_text(json.dumps({'name': 'offline-vuln-proof', 'version': '1.0.0', 'dependencies': {'lodash': '4.17.20'}}))
        (context / 'node_modules/lodash/package.json').write_text(json.dumps({'name': 'lodash', 'version': '4.17.20'}))
        name = 'dip-offline-vuln-proof:local'
        try:
            build = run('docker', 'build', '--network', 'none', '--platform', 'linux/amd64',
                        '-t', name, str(context), timeout=120)
            assert build.returncode == 0, 'local scratch image build failed'
            image = base / 'image.tar'
            saved = run('docker', 'save', '-o', str(image), name)
            assert saved.returncode == 0, 'local fixture image save failed'
            ok = scanner(db, image, '/tmp/cache')
            assert ok.returncode == 0, 'offline Trivy scan failed'
            report = json.loads(ok.stdout)
            results = report.get('Results')
            assert isinstance(results, list), 'invalid Trivy Results'
            def found(kind, ecosystem, package, version, cve):
                return any(r.get('Class') == kind and r.get('Type') == ecosystem and
                           any(v.get('PkgName') == package and
                               v.get('InstalledVersion') == version and
                               v.get('VulnerabilityID') == cve
                               for v in r.get('Vulnerabilities') or []) for r in results)
            assert found('os-pkgs', 'alpine', 'openssl', '3.3.2-r0', 'CVE-2021-3711'), 'OS CVE missing'
            assert found('lang-pkgs', 'node-pkg', 'lodash', '4.17.20', 'CVE-2021-23337'), 'Node CVE missing'
            missing = scanner(db, image, '/tmp/empty-cache', with_db=False)
            assert missing.returncode != 0 and not missing.stdout.strip(), 'missing DB falsely reported success'
            print('PASS: pinned archive matches DB; fresh metadata; offline image has OS+Node CVEs; missing DB and stale metadata rejected')
        finally:
            run('docker', 'image', 'rm', '-f', name, timeout=30)


if __name__ == '__main__':
    main()
