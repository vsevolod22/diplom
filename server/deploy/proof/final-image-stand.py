#!/usr/bin/env python3
"""Finite, opt-in default-image stand smoke. Import/--plan never touch Docker.

No historical proof imports, recovery, external volumes, provider calls or guard
subclasses. Actual execution requires a separately reviewed source hash. Evidence
contains summaries, never cookies, passwords, JWT material or raw container logs.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import signal
import socket
import subprocess

import time
from dataclasses import dataclass
from urllib.parse import urlencode
import uuid

ROOT = Path(__file__).resolve().parents[3]
BASE = '636b834fa7d3c4d8114ecb4cf4fcc9357ca075e7'
IMAGES = {
    'api': 'sha256:70d11c11167a1bd8ecbc68901b5cd4b99efb99a2a472c69a32d769df05673878',
    'worker': 'sha256:79d8cdcdf65f8d85a93390255e457f434b6cfceac6147da019fecd499d7a7844',
}
ORIGIN = 'http://127.0.0.1:18080'
SCAN = '/api/v1/browser/scans'
TARGET = 'registry-1.docker.io/library/alpine:3.21.3'
LABEL = 'org.diplom.final-image-stand'
SERVICES = {'auth-volume-init', 'scan-volume-init', 'egress', 'worker', 'api', 'web'}
NETWORKS = {'auth_internal', 'scan_internal', 'registry_uplink', 'web_edge'}
VOLUMES = {'auth_accounts', 'scan_ledger'}
PUBLIC_PATHS = (
    '.dockerignore', 'package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml',
    'index.html', 'admin.html', 'tsconfig.json', 'vite.config.ts',
    'vite.admin.config.ts', 'vitest.config.ts', 'src', 'public', 'tests-vite',
    'server/api/package.json', 'server/api/tsconfig.json', 'server/api/src',
    'server/runtime/src', 'server/deploy/stand.Dockerfile',
    'server/deploy/stand.nginx.conf', 'server/deploy/gateway/Dockerfile',
    'server/deploy/gateway/proxy.py',
)
CONTEXT_SHA256 = 'ba69af8fead84d3e8ebe0b2a4316399608a900b918405330f5a014f4fc56bf8c'
ID = re.compile(r'[a-f0-9]{64}')
IMAGE_ID = re.compile(r'sha256:[a-f0-9]{64}')
ACCOUNT = re.compile(r'[a-f0-9]{32}')
SCAN_ID = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}')
MAX_REPLY = 2_100_000
WHOLE_SECONDS = 900
CLEANUP_RESERVE = 120
PATH = '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'


class Failure(Exception):
    """Only stable, non-sensitive codes may cross the evidence boundary."""


def require(condition, code):
    if not condition:
        raise Failure(code)


def plan():
    return {
        'mode': 'SOURCE_ONLY_NOT_EXECUTED', 'base': BASE, 'images': IMAGES,
        'origin': ORIGIN, 'target': TARGET, 'checks': ['secret', 'sbom'],
        'whole_seconds': WHOLE_SECONDS, 'cleanup_reserve_seconds': CLEANUP_RESERVE,
        'job_seconds_max': 600, 'actual_requires': [
            'explicit followup after independent review', '--execute-reviewed',
            '--reviewed-sha256 matching this file',
            '--web-image and --gateway-image prebuilt immutable IDs',
            '--prebuilt-metadata and --prebuilt-sha256 reviewed public build receipt',
            '--init-image existing busybox:1.37.0@sha256:<reviewed-public-digest>; no pull',
            '--chromium-executable absolute public browser binary',
        ],
        'builds': 'FORBIDDEN_IN_ACTUAL_PREBUILT_ONLY_NO_PULL_NO_HISTORY',
        'cve': 'UNSUPPORTED_NOT_ENABLED_NO_DB_RELEASE',
        'resolver': 'default Docker DNS only; no resolver workaround/fallback',
        'cleanup': 'own recorded container/network IDs; volume name+CreatedAt+labels',
    }


def authorize(args):
    require(args.execute_reviewed, 'EXECUTION_NOT_AUTHORIZED')
    actual = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    require(args.reviewed_sha256 == actual, 'REVIEW_HASH_MISMATCH')
    require(bool(re.fullmatch(r'(?:docker\.io/library/)?busybox:1\.37\.0@sha256:[a-f0-9]{64}',
                              args.init_image or '')), 'INIT_PUBLIC_DIGEST_REQUIRED')
    require(all(IMAGE_ID.fullmatch(getattr(args, field, '') or '')
                for field in ('web_image', 'gateway_image')), 'PREBUILT_IDS_REQUIRED')
    require(bool(getattr(args, 'prebuilt_metadata', None)) and
            ID.fullmatch(getattr(args, 'prebuilt_sha256', '') or ''), 'PREBUILT_RECEIPT_REQUIRED')
    browser = Path(args.chromium_executable or '')
    require(browser.is_absolute() and browser.is_file() and os.access(browser, os.X_OK),
            'EXPLICIT_BROWSER_BINARY_REQUIRED')
    return browser


def clean_env(work):
    return {'PATH': PATH, 'HOME': str(work), 'DOCKER_CONFIG': str(work / 'docker-config'),
            'DOCKER_BUILDKIT': '1', 'LANG': 'C.UTF-8'}


class Budget:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.end = clock() + WHOLE_SECONDS

    def seconds(self, cap, cleanup=False):
        remaining = self.end - self.clock() - (0 if cleanup else CLEANUP_RESERVE)
        require(remaining > 0, 'WHOLE_DEADLINE')
        return min(cap, remaining)


class Runner:
    def __init__(self, work, budget):
        self.work, self.budget = work, budget
        self.env = clean_env(work)
        self.base = ['docker', '--config', str(work / 'docker-config'),
                     '--host', 'unix:///var/run/docker.sock']

    def call(self, argv, *, cap=20, stdin=None, input_data=None, output=None, cleanup=False, env=None):
        timeout = self.budget.seconds(cap, cleanup)
        require(stdin is None or input_data is None, 'STDIN_CONFLICT')
        proc = subprocess.Popen(argv, cwd=self.work, env=env or self.env,
                                stdin=subprocess.PIPE if input_data is not None else stdin,
                                stdout=output if output is not None else subprocess.PIPE,
                                stderr=subprocess.STDOUT if output is not None else subprocess.PIPE,
                                start_new_session=True)
        try:
            stdout, stderr = proc.communicate(input=input_data, timeout=timeout)
        except BaseException:
            # Only our CLI process group. Killing it does not certify daemon completion.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.communicate(timeout=2)
            raise
        require(output is not None or len(stdout) <= MAX_REPLY, 'CLI_REPLY_TOO_LARGE')
        # Do not expose stderr/argv: config output and HTTP cookies may be sensitive.
        return proc.returncode, stdout or b'', stderr or b''

    def docker(self, *args, **kwargs):
        # Actual is a prebuilt-only consumer, not a build/pull/history orchestrator.
        verbs = {'image': {'inspect'}, 'container': {'inspect', 'ls', 'start', 'rm', 'wait', 'exec'},
                 'network': {'inspect', 'ls', 'create', 'rm'}, 'volume': {'inspect', 'ls', 'create', 'rm'}}
        if args and args[0] == 'compose':
            require(any(verb in args for verb in ('config', 'create')) and
                    not any(verb in args for verb in ('up', 'down', 'build', 'pull', 'run', 'restart')),
                    'RUNTIME_COMPOSE_VERB_FORBIDDEN')
        else:
            require(len(args) >= 2 and args[1] in verbs.get(args[0], set()),
                    'RUNTIME_BUILD_PULL_HISTORY_FORBIDDEN')
        return self.call(self.base + list(args), **kwargs)

    def checked(self, *args, **kwargs):
        code, out, _ = self.docker(*args, **kwargs)
        require(code == 0, 'DOCKER_COMMAND_FAILED')
        return out

    def inspect(self, kind, identity, cleanup=False):
        code, out, err = self.docker(kind, 'inspect', identity, cleanup=cleanup, cap=5)
        if code and (b'no such' in err.lower() or b'not found' in err.lower()):
            return None
        require(code == 0, 'INSPECT_FAILED')
        value = json.loads(out)
        require(isinstance(value, list) and len(value) == 1, 'INSPECT_SHAPE')
        return value[0]


    def container_id(self, name, cleanup=False):
        # A name collision may be foreign: inspect ONLY its ID, never its Env/mounts.
        code, out, err = self.docker('container', 'inspect', '--format', '{{.Id}}', name,
                                    cleanup=cleanup, cap=5)
        if code and (b'no such' in err.lower() or b'not found' in err.lower()):
            return None
        require(code == 0 and ID.fullmatch(out.decode().strip()), 'CONTAINER_ID_LOOKUP')
        return out.decode().strip()


def public_tar_ok(archive):
    """Validate archive metadata before sending it; never traverse workspace secrets."""
    for member in archive.getmembers():
        path = PurePosixPath(member.name)
        require(not path.is_absolute() and '..' not in path.parts, 'CONTEXT_PATH_ESCAPE')
        require(member.isfile() or member.isdir(), 'CONTEXT_LINK_OR_SPECIAL')
        name = path.as_posix()
        require(any(name == root or name.startswith(root + '/') or
                    member.isdir() and root.startswith(name + '/')
                    for root in PUBLIC_PATHS), 'CONTEXT_NOT_ALLOWLISTED')
        require(not any(part.startswith('.env') or part in {'.local-auth', '.git', 'keys'}
                        for part in path.parts), 'CONTEXT_PRIVATE_PATH')
        require(path.suffix.lower() not in {'.pem', '.key', '.sqlite', '.db'},
                'CONTEXT_PRIVATE_FILE')


def build_spec(baseline, project, nonce, images, enrolled, jwt):
    """Transform resolved compose.stand baseline, not a proof/gate-bypass stack."""
    require(re.fullmatch(r'dip-image-stand-[a-f0-9]{32}', project) is not None,
            'PROJECT_NAMESPACE')
    require(ACCOUNT.fullmatch(nonce) is not None, 'NONCE')
    require(set(baseline['services']) == SERVICES and set(baseline['networks']) == NETWORKS
            and set(baseline['volumes']) == VOLUMES, 'BASELINE_TOPOLOGY_CHANGED')
    require(all(ACCOUNT.fullmatch(item) for item in enrolled), 'ENROLLMENT_IDS_ONLY')
    require(set(images) == {'api', 'worker', 'web', 'egress', 'init'}
            and all(IMAGE_ID.fullmatch(value) for value in images.values()), 'IMMUTABLE_IMAGES_ONLY')
    require(all(images[role] == IMAGES[role] for role in IMAGES), 'BASE_IMAGE_PIN')
    spec = copy.deepcopy(baseline)
    spec['name'] = project
    for name, service in spec['services'].items():
        for field in ('build', 'container_name', 'profiles'):
            service.pop(field, None)
        # Compose emits null command/entrypoint for inherited image defaults.
        # Drop only null; empty/non-null overrides remain subject to refusal.
        for field in ('entrypoint', 'command'):
            if service.get(field, False) is None:
                service.pop(field)
        service['container_name'] = project + '-' + name + '-1'
        service['image'] = images['init' if name.endswith('-init') else name]
        service['pull_policy'] = 'never'
        service.setdefault('labels', {}).update({LABEL: nonce})
        service.update(read_only=True, security_opt=['no-new-privileges:true'],
                       cap_drop=['ALL'], pids_limit=128, cpus=1)
        service['mem_limit'] = {'worker': '1g', 'api': '512m'}.get(name, '256m')
        service['memswap_limit'] = service['mem_limit']
        if name in {'api', 'web', 'worker'}:
            service['tmpfs'] = ['/tmp:size=' + ('512m' if name == 'worker' else '64m')]
    api = spec['services']['api']
    api['environment'] = {
        'SCAN_BIND_ADDRESS': '0.0.0.0', 'PORT': '3001', 'SCAN_JWT_SECRET': jwt,
        'SCAN_JWT_ISSUER': project, 'SCAN_JWT_AUDIENCE': project,
        'AUTH_DB_PATH': '/auth/auth.sqlite', 'SCAN_LEDGER_PATH': '/data/ledger.sqlite',
        'SCAN_WORKER_READY_PATH': '/data/worker.ready',
        'SCAN_BROWSER_ALLOWED_USER_IDS': ','.join(enrolled),
        'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS': 'false', 'AUTH_ORIGIN': ORIGIN,
        'AUTH_ALLOW_INSECURE_LOCAL_HTTP': 'true',
    }
    spec['services']['web']['ports'] = [
        {'target': 8080, 'published': '18080', 'host_ip': '127.0.0.1', 'protocol': 'tcp'}]
    for name in NETWORKS:
        spec['networks'][name] = {'external': True, 'name': project + '-' + name}
    for name in VOLUMES:
        spec['volumes'][name] = {'external': True, 'name': project + '-' + name}
    validate_spec(spec, project, nonce)
    return spec


def validate_spec(spec, project, nonce):
    require(set(spec['services']) == SERVICES and spec['name'] == project
            and set(spec['networks']) == NETWORKS and set(spec['volumes']) == VOLUMES,
            'SERVICES_CHANGED')
    expected_nets = {'api': {'auth_internal', 'scan_internal'}, 'worker': {'scan_internal'},
                     'egress': {'scan_internal', 'registry_uplink'},
                     'web': {'auth_internal', 'web_edge'}}
    expected_mounts = {'api': {'auth_accounts': '/auth', 'scan_ledger': '/data'},
                       'worker': {'scan_ledger': '/data'},
                       'auth-volume-init': {'auth_accounts': '/data'},
                       'scan-volume-init': {'scan_ledger': '/data'}, 'web': {}, 'egress': {}}
    for name, service in spec['services'].items():
        require(not any(key in service for key in ('build', 'privileged', 'devices',
                    'env_file', 'extra_hosts', 'dns', 'pid', 'ipc', 'entrypoint')),
                'SERVICE_UNSAFE_OVERRIDE')
        require(service.get('container_name') == project + '-' + name + '-1', 'EXACT_CONTAINER_NAMES')
        require(service['labels'][LABEL] == nonce and service['read_only'] is True
                and service['cap_drop'] == ['ALL']
                and service['security_opt'] == ['no-new-privileges:true'], 'SERVICE_GUARDS')
        require(service['image'].startswith('sha256:') and IMAGE_ID.fullmatch(service['image']),
                'MUTABLE_IMAGE')
        require(service['mem_limit'] == {'worker': '1g', 'api': '512m'}.get(name, '256m')
                and service['memswap_limit'] == service['mem_limit'] and service['cpus'] == 1
                and service['pids_limit'] == 128, 'RESOURCE_LIMITS')
        require(service.get('user') == ('101:101' if name == 'web' else '65532:65532')
                if not name.endswith('-init') else not service.get('user'), 'SERVICE_USER')
        if name in IMAGES:
            require(service['image'] == IMAGES[name], 'BASE_IMAGE_PIN')
        if name.endswith('-init'):
            require(service['network_mode'] == 'none' and service['cap_add'] == ['CHOWN']
                    and service['command'] == ['chown', '65532:65532', '/data'], 'INIT_SCOPE')
        else:
            require(set(service['networks']) == expected_nets[name]
                    and not service.get('cap_add') and 'command' not in service, 'DEFAULT_ENTRYPOINT_TOPOLOGY')
        require({m['source']: m['target'] for m in service.get('volumes', [])}
                == expected_mounts[name]
                and all(m['type'] == 'volume' for m in service.get('volumes', [])), 'MOUNTS_CHANGED')
        require(not service.get('ports') or name == 'web', 'PORT_SCOPE')
    require(spec['services']['worker']['environment'] == {
        'SCAN_LEDGER_PATH': '/data/ledger.sqlite', 'SCAN_WORKER_READY_PATH': '/data/worker.ready',
        'TRIVY_CACHE_DIR': '/tmp/trivy'}, 'WORKER_ENV')
    require(spec['services']['web']['ports'] == [
        {'target': 8080, 'published': '18080', 'host_ip': '127.0.0.1', 'protocol': 'tcp'}], 'WEB_ORIGIN_PORT')
    env = spec['services']['api']['environment']
    require(set(env) == {'SCAN_BIND_ADDRESS', 'PORT', 'SCAN_JWT_SECRET', 'SCAN_JWT_ISSUER',
        'SCAN_JWT_AUDIENCE', 'AUTH_DB_PATH', 'SCAN_LEDGER_PATH', 'SCAN_WORKER_READY_PATH',
        'SCAN_BROWSER_ALLOWED_USER_IDS', 'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS', 'AUTH_ORIGIN',
        'AUTH_ALLOW_INSECURE_LOCAL_HTTP'}, 'API_ENV_ALLOWLIST')
    require(not env['SCAN_BROWSER_ALLOWED_USER_IDS'] or all(ACCOUNT.fullmatch(item)
        for item in env['SCAN_BROWSER_ALLOWED_USER_IDS'].split(',')), 'ENROLLMENT_IDS_ONLY')
    require(env['AUTH_ORIGIN'] == ORIGIN and env['SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS'] == 'false'
            and all(not key.startswith(('SCAN_VULN_', 'LLM_', 'OPENROUTER_', 'RUNTIME_', 'HOST_'))
                    for key in env), 'DEFAULT_GATES')
    for kind in ('networks', 'volumes'):
        for name, resource in spec[kind].items():
            require(resource == {'external': True, 'name': project + '-' + name}, 'RESOURCE_NAMESPACE')


def api_recreate_spec(spec):
    # Compose 2.34 create has no --no-deps flag. A single-service spec has no
    # dependency graph to traverse; all other own IDs/states are preflighted.
    reduced = copy.deepcopy(spec)
    reduced['services'] = {'api': copy.deepcopy(spec['services']['api'])}
    reduced['services']['api'].pop('depends_on', None)
    return reduced


@dataclass(frozen=True)
class Owned:
    kind: str
    identity: str
    created: str = ''


def owns(resource, record, project, nonce):
    if record.kind == 'container':
        labels = resource.get('Config', {}).get('Labels', {}) or {}
        return (resource.get('Id') == record.identity and labels.get(LABEL) == nonce
                and labels.get('com.docker.compose.project') == project
                and labels.get('com.docker.compose.service') in SERVICES)
    labels = resource.get('Labels', {}) or {}
    identity = resource.get('Id') if record.kind == 'network' else resource.get('Name')
    created = resource.get('Created') if record.kind == 'network' else resource.get('CreatedAt')
    return (identity == record.identity and created == record.created
            and labels.get(LABEL) == nonce and labels.get('com.docker.compose.project') == project)


class Stand:
    def __init__(self, runner, project, nonce, persist=False):
        self.r, self.project, self.nonce = runner, project, nonce
        self.persist = persist
        self.owned = []
        self.pending_storage = []
        self.create_uncertain = False
        self.containers = {}
        self.network_ids = {}
        self.spec = None
        self.file = runner.work / 'compose.json'

    def journal(self):
        if not self.persist:
            return
        path = self.r.work / 'owned-resources.json'
        temporary = path.with_suffix('.tmp')
        value = {'project': self.project, 'nonce': self.nonce,
                 'resources': [record.__dict__ for record in self.owned],
                 'pending_storage': self.pending_storage, 'create_uncertain': self.create_uncertain}
        with temporary.open('w') as output:
            json.dump(value, output, indent=2)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)

    def save(self, spec):
        self.spec = spec
        # Synthetic JWT only; never write a resolved config to stdout/evidence.
        fd = os.open(self.file, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as output:
            json.dump(spec, output)

    def project_ids(self, cleanup=False):
        out = self.r.checked('container', 'ls', '--all', '--no-trunc', '--filter',
                             'label=com.docker.compose.project=' + self.project,
                             '--format', '{{.ID}}', cleanup=cleanup, cap=5)
        ids = out.decode().splitlines()
        require(all(ID.fullmatch(identity) for identity in ids) and len(ids) == len(set(ids)),
                'PROJECT_ID_SET')
        return set(ids)

    def preflight_create(self, service):
        # Re-evaluate immediately before create, not just at initial prepare.
        validate_spec(self.spec, self.project, self.nonce)
        expected = set() if service is None else SERVICES - {'api'}
        require(service is None or service == 'api', 'ONLY_OWN_API_RECREATE')
        require(set(self.containers) == expected, 'PRECREATE_EXPECTED_SERVICE_SET')
        require(not self.pending_storage and set(self.network_ids) == NETWORKS
                and {r.identity for r in self.owned if r.kind == 'network'} == set(self.network_ids.values())
                and {r.identity for r in self.owned if r.kind == 'volume'} ==
                    {self.project + '-' + name for name in VOLUMES}, 'PRECREATE_EXACT_STORAGE_SET')
        require(self.project_ids() == set(self.containers.values()), 'PRECREATE_PROJECT_COLLISION')
        for name in sorted(SERVICES):
            identity = self.r.container_id(self.project + '-' + name + '-1')
            require(identity == self.containers.get(name), 'PRECREATE_NAME_COLLISION')
            if identity is not None:
                _, obj = self.container(name)  # full inspect only for an already recorded owned ID
                if service == 'api':
                    state = obj['State']
                    require(state['Status'] == 'exited' and state['ExitCode'] == 0
                            if name.endswith('-init') else state['Status'] == 'running',
                            'PRECREATE_DEPENDENCY_STATE')
        for record in self.owned:
            if record.kind != 'container':
                obj = self.r.inspect(record.kind, record.identity)
                require(obj is not None and owns(obj, record, self.project, self.nonce),
                        'PRECREATE_STORAGE_OWNERSHIP')

    def discover(self, cleanup=False):
        ids = self.r.checked('container', 'ls', '--all', '--filter',
                             'label=' + LABEL + '=' + self.nonce, '--filter',
                             'label=com.docker.compose.project=' + self.project,
                             '--format', '{{.ID}}', cleanup=cleanup, cap=5).decode().splitlines()
        seen = {}
        for short_id in ids:
            obj = self.r.inspect('container', short_id, cleanup)
            require(obj is not None and ID.fullmatch(obj['Id']), 'DISCOVERY_ID')
            record = Owned('container', obj['Id'])
            require(owns(obj, record, self.project, self.nonce), 'DISCOVERY_OWNERSHIP')
            service = obj['Config']['Labels']['com.docker.compose.service']
            require(service not in seen and obj.get('Name', '').lstrip('/') ==
                    self.project + '-' + service + '-1', 'DISCOVERY_EXACT_SERVICE_SET')
            if record not in self.owned:
                self.owned.append(record)
            seen[service] = obj['Id']
        self.containers = seen
        self.journal()

    def create(self, service=None):
        self.preflight_create(service)
        previous = dict(self.containers)
        targets = sorted(SERVICES) if service is None else ['api']
        self.create_uncertain = True
        self.journal()
        create_file = str(self.file) if service is None else '-'
        input_data = None if service is None else json.dumps(api_recreate_spec(self.spec)).encode()
        try:
            self.r.checked('compose', '--env-file', '/dev/null', '--project-directory', str(self.r.work),
                           '--project-name', self.project, '--file', create_file, 'create',
                           '--no-build', '--pull', 'never', '--no-recreate', *targets,
                           input_data=input_data, cap=40)
            self.create_uncertain = False
        finally:
            # Capture exact owned IDs even when compose create partially failed.
            self.discover()
        require(set(self.containers) == SERVICES and self.project_ids() == set(self.containers.values()),
                'POSTCREATE_EXACT_SERVICE_SET')
        require(all(self.containers.get(name) == identity for name, identity in previous.items()),
                'POSTCREATE_EXISTING_ID_CHANGED')
        for name, identity in self.containers.items():
            require(self.r.container_id(self.project + '-' + name + '-1') == identity,
                    'POSTCREATE_NAME_COLLISION')

    def new_storage(self):
        for kind, names in [('network', NETWORKS), ('volume', VOLUMES)]:
            for name in sorted(names):
                full = self.project + '-' + name
                require(self.r.inspect(kind, full) is None, 'RESOURCE_ALREADY_EXISTS')
                args = [kind, 'create', '--label', LABEL + '=' + self.nonce,
                        '--label', 'com.docker.compose.project=' + self.project]
                if kind == 'network' and name.endswith('_internal'):
                    args += ['--internal']
                self.pending_storage.append((kind, full))
                self.journal()
                out = self.r.checked(*args, full).decode().strip()
                obj = self.r.inspect(kind, out)
                require(obj is not None, 'CREATED_RESOURCE_MISSING')
                record = Owned(kind, obj['Id'] if kind == 'network' else obj['Name'],
                               obj['Created'] if kind == 'network' else obj['CreatedAt'])
                require(owns(obj, record, self.project, self.nonce), 'CREATED_RESOURCE_OWNERSHIP')
                self.owned.append(record)
                self.pending_storage.remove((kind, full))
                self.journal()
                if kind == 'network':
                    require(bool(obj['Internal']) == name.endswith('_internal'), 'NETWORK_INTERNAL')
                    self.network_ids[name] = obj['Id']

    def container(self, service, cleanup=False):
        identity = self.containers[service]
        record = Owned('container', identity)
        obj = self.r.inspect('container', identity, cleanup)
        require(obj is not None and owns(obj, record, self.project, self.nonce), 'CONTAINER_OWNERSHIP')
        return identity, obj

    def verify(self, allow_created=False):
        require(set(self.containers) == SERVICES, 'MISSING_SERVICE')
        for service in SERVICES:
            _, obj = self.container(service)
            expected = self.spec['services'][service]
            host = obj['HostConfig']
            require(obj['Config']['Image'] == expected['image'] and not host['Privileged']
                    and host['ReadonlyRootfs'] and host['CapDrop'] == ['ALL']
                    and host['SecurityOpt'] == ['no-new-privileges:true']
                    and obj['Config'].get('User', '') == expected.get('user', ''), 'ACTUAL_CONTAINER_GUARDS')
            expected_memory = {'worker': 1073741824, 'api': 536870912}.get(service, 268435456)
            require(host['Memory'] == host['MemorySwap'] == expected_memory
                    and host['NanoCpus'] == 1_000_000_000
                    and host['PidsLimit'] == 128, 'ACTUAL_RESOURCE_LIMITS')
            if service.endswith('-init'):
                require(host['NetworkMode'] == 'none', 'ACTUAL_INIT_NETWORK')
            else:
                networks = obj['NetworkSettings']['Networks']
                require(set(networks) == {self.project + '-' + name for name in expected['networks']},
                        'ACTUAL_NETWORK_NAMES')
                for name in expected['networks']:
                    actual = networks[self.project + '-' + name]['NetworkID']
                    require(actual == self.network_ids[name] or
                            allow_created and obj['State']['Status'] == 'created' and not actual,
                            'ACTUAL_NETWORKS')
            require({m['Name']: m['Destination'] for m in obj['Mounts'] if m['Type'] == 'volume'} ==
                    {self.project + '-' + m['source']: m['target'] for m in expected.get('volumes', [])}
                    and all(m['Type'] == 'volume' or
                            m['Type'] == 'tmpfs' and m['Destination'] == '/tmp'
                            for m in obj['Mounts']), 'ACTUAL_MOUNTS')
            require(not host['PortBindings'] or service == 'web', 'ACTUAL_PORTS')

    def start(self, service):
        identity, _ = self.container(service)
        self.r.checked('container', 'start', identity)

    def remove_container(self, service):
        identity, _ = self.container(service)
        self.r.checked('container', 'rm', '--force', identity)
        self.containers.pop(service)

    def cleanup(self):
        failures = ['COMPOSE_CREATE_UNCONFIRMED'] if self.create_uncertain else []
        for kind, name in self.pending_storage:
            try:
                obj = self.r.inspect(kind, name, cleanup=True)
                require(obj is not None, 'STORAGE_CREATE_UNCONFIRMED')
                record = Owned(kind, obj['Id'] if kind == 'network' else obj['Name'],
                               obj['Created'] if kind == 'network' else obj['CreatedAt'])
                require(owns(obj, record, self.project, self.nonce), 'PENDING_STORAGE_OWNERSHIP')
                if record not in self.owned:
                    self.owned.append(record)
            except Exception:
                failures.append('STORAGE_CREATE_UNCONFIRMED')
        try:
            self.discover(cleanup=True)
        except Exception:
            failures.append('DISCOVERY_FAILED')
        for record in reversed(self.owned):
            try:
                obj = self.r.inspect(record.kind, record.identity, cleanup=True)
                if obj is None:
                    continue
                require(owns(obj, record, self.project, self.nonce), 'CLEANUP_OWNERSHIP_REFUSED')
                args = [record.kind, 'rm'] + (['--force'] if record.kind == 'container' else [])
                self.r.checked(*args, record.identity, cleanup=True, cap=5)
                require(self.r.inspect(record.kind, record.identity, cleanup=True) is None,
                        'CLEANUP_RESOURCE_REMAINS')
            except Exception:
                failures.append('REMOVE_' + record.kind.upper() + '_FAILED_OR_REFUSED')
        try:
            for kind in ('container', 'network', 'volume'):
                args = [kind, 'ls', '--filter', 'label=com.docker.compose.project=' + self.project,
                        '--format', '{{.Name}}' if kind == 'volume' else '{{.ID}}']
                if kind == 'container':
                    args.insert(2, '--all')
                require(not self.r.checked(*args, cleanup=True, cap=5).strip(), 'CLEANUP_NAMESPACE_REMAINS')
        except Exception:
            failures.append('NAMESPACE_NOT_EMPTY_OR_UNCONFIRMED')
        return {'status': 'PASS' if not failures else 'INCOMPLETE', 'errors': failures,
                'recorded_resources': len(self.owned)}


class Http:
    def __init__(self, budget, cookie=''):
        self.budget, self.cookie = budget, cookie

    def read_body(self, response, sock, end, maximum):
        data = bytearray()
        while True:
            left = min(end - self.budget.clock(), self.budget.seconds(20))
            require(left > 0, 'HTTP_ABSOLUTE_TIMEOUT')
            sock.settimeout(left)
            chunk = response.read1(min(16384, maximum + 1 - len(data)))
            if not chunk:
                return bytes(data)
            data.extend(chunk)
            require(len(data) <= maximum, 'HTTP_BODY_LIMIT')

    def request_raw(self, method, path, body=None, extra=None):
        require(path.startswith('/api/v1/') and not any(c in path for c in '\r\n'), 'HTTP_PATH')
        connection = http.client.HTTPConnection('127.0.0.1', 18080,
                                                timeout=self.budget.seconds(15))
        headers = {'Origin': ORIGIN, 'Cache-Control': 'no-store'}
        if self.cookie:
            headers['Cookie'] = self.cookie
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers['Content-Type'] = 'application/json'
        headers.update(extra or {})
        end = self.budget.clock() + self.budget.seconds(15)
        try:
            connection.request(method, path, body=data, headers=headers)
            sock = connection.sock
            response = connection.getresponse()
            raw = self.read_body(response, sock, end, MAX_REPLY)
            return response.status, dict(response.getheaders()), raw
        finally:
            connection.close()

    def request(self, method, path, body=None, extra=None):
        status, headers, raw = self.request_raw(method, path, body, extra)
        if not raw and status in {204, 205}:
            return status, headers, None
        content_type = next((value for key, value in headers.items() if key.lower() == 'content-type'), '')
        require(content_type.split(';', 1)[0].strip().lower() == 'application/json', 'APP_JSON_CONTENT_TYPE')
        def unique_object(pairs):
            require(len(dict(pairs)) == len(pairs), 'APP_JSON_DUPLICATE_KEYS')
            return dict(pairs)
        def invalid_constant(_value):
            raise Failure('APP_JSON_INVALID')
        try:
            value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object,
                               parse_constant=invalid_constant)
        except (ValueError, UnicodeError):
            raise Failure('APP_JSON_INVALID') from None
        require(isinstance(value, (dict, list)), 'APP_JSON_SHAPE')
        return status, headers, value

    def sse(self, scan_id, after=None):
        require(SCAN_ID.fullmatch(scan_id), 'SSE_SCAN_ID')
        connection = http.client.HTTPConnection('127.0.0.1', 18080,
                                                timeout=self.budget.seconds(20))
        headers = {'Cookie': self.cookie, 'Accept': 'text/event-stream'}
        if after is not None:
            headers['Last-Event-ID'] = str(after)
        end = self.budget.clock() + self.budget.seconds(20)
        try:
            connection.request('GET', SCAN + '/' + scan_id + '/events', headers=headers)
            sock = connection.sock
            response = connection.getresponse()
            require(response.status == 200 and response.getheader('Content-Type', '').startswith('text/event-stream'), 'SSE_HTTP')
            # Called only after terminal: the current server closes the bounded replay.
            raw = self.read_body(response, sock, end, 65536)
            return parse_events(raw.decode(), scan_id)
        finally:
            connection.close()


def parse_events(text, scan_id):
    events = []
    for block in text.split('\n\n'):
        fields = dict(line.split(': ', 1) for line in block.splitlines() if ': ' in line)
        if fields.get('event') != 'scan':
            require(fields.get('event') is None, 'SSE_ERROR_EVENT')
            continue
        value = json.loads(fields['data'])
        require(re.fullmatch(r'[1-9][0-9]*', fields.get('id', '')) and value.get('scanId') == scan_id
                and value.get('state') in {'queued', 'running', 'completed', 'partial', 'failed', 'cancelled'}
                and value.get('percent') is None, 'SSE_EVENT_CONTRACT')
        event = {'id': int(fields['id']), 'state': value['state']}
        require(not events or event['id'] > events[-1]['id'], 'SSE_ORDER')
        events.append(event)
    return events


def expect_status(client, method, path, status, body=None):
    actual, headers, raw = client.request_raw(method, path, body)
    require(actual == status, 'HTTP_EXPECTED_' + str(status) + '_GOT_' + str(actual))
    return headers, raw


def expect_http(client, method, path, status, body=None):
    actual, headers, value = client.request(method, path, body)
    require(actual == status, 'HTTP_EXPECTED_' + str(status) + '_GOT_' + str(actual))
    return headers, value


def register(budget):
    client = Http(budget)
    headers, user = expect_http(client, 'POST', '/api/v1/auth/register', 201,
                               {'email': 'smoke-' + uuid.uuid4().hex + '@example.invalid',
                                'password': secrets.token_urlsafe(24)})
    require(isinstance(user, dict) and ACCOUNT.fullmatch(user.get('id', '')), 'ACCOUNT_CONTRACT')
    cookie = next((value for key, value in headers.items() if key.lower() == 'set-cookie'), '')
    require(re.fullmatch(r'demo_session=[A-Za-z0-9_-]{43}', cookie.split(';')[0]) is not None
            and 'HttpOnly' in cookie and 'SameSite=Lax' in cookie, 'COOKIE_CONTRACT')
    return user['id'], Http(budget, cookie.split(';')[0])


def terminal(client, scan_id):
    end = client.budget.clock() + client.budget.seconds(300)
    while client.budget.clock() < end:
        _, status = expect_http(client, 'GET', SCAN + '/' + scan_id, 200)
        if status.get('state') in {'completed', 'partial', 'failed', 'cancelled'}:
            return status
        time.sleep(min(1, client.budget.seconds(1)))
    raise Failure('JOB_TIMEOUT_300S')


def collect_report(client, scan_id, kind):
    rows, cursor, first = [], None, None
    for _ in range(41):
        query = {'view': 'report-v1', 'limit': '25'}
        if cursor is not None:
            query['cursor'] = cursor
        _, page = expect_http(client, 'GET', SCAN + '/' + scan_id + '/' + kind + '?' + urlencode(query), 200)
        meta = page.get('page', {})
        require(meta.get('version') == 1 and meta.get('limit') == 25
                and meta.get('offset') == len(rows), 'REPORT_PAGE')
        field = 'components' if kind == 'sbom' else 'findings'
        items = page.get(field)
        require(isinstance(items, list) and len(items) == meta.get('returnedCount')
                and meta.get('totalCount') == meta.get('matchedCount'), 'REPORT_COUNTS')
        first = page if first is None else first
        require(meta.get('totalCount') == first['page']['totalCount'], 'REPORT_SNAPSHOT')
        rows.extend(items)
        next_cursor = page.get('nextCursor')
        if next_cursor is None:
            require(len(rows) == meta['totalCount'], 'REPORT_TRUNCATED')
            return first, rows
        require(items and isinstance(next_cursor, str) and len(next_cursor) <= 512
                and next_cursor != cursor, 'REPORT_CURSOR')
        cursor = next_cursor
    raise Failure('REPORT_PAGE_CAP')


# Pure policy is separately executable in unit tests without Playwright/network.
BROWSER_POLICY = r'''
function browserRequestAllowed(raw, method, base) {
  const url = new URL(raw);
  if (url.origin !== 'http://127.0.0.1:18080' || url.username || url.password || method !== 'GET') return false;
  if (!url.pathname.startsWith('/api/')) return true;
  if (url.pathname === `${base}/llm/context`) return url.search === '';
  return url.pathname === '/api/v1/auth/me' || url.pathname === '/api/v1/browser/scans' ||
    [base, `${base}/results`, `${base}/sbom`, `${base}/events`].includes(url.pathname);
}
function assertDisabledContext(value, scanId, expectedSbom) {
  assert.equal(value.scanId, scanId);
  assert.equal(value.digest, expectedSbom.image.split('@')[1]);
  assert.equal(value.platform, expectedSbom.platform);
  assert.match(value.reportVersion, /^[a-f0-9]{64}$/);
  assert.equal(value.enabled, false);
  assert.equal(value.policyVersion, null);
  assert.equal(value.disclosure, null);
}
'''

# Only actual same-origin GETs; no fixtures/responses/provider calls mocked.
BROWSER = BROWSER_POLICY + r'''
import assert from 'node:assert/strict';
import { chromium, expect } from '@playwright/test';
let input = ''; for await (const chunk of process.stdin) input += chunk;
const { cookie, scanId, executablePath, expected } = JSON.parse(input);
const origin = 'http://127.0.0.1:18080', base = `/api/v1/browser/scans/${scanId}`;
let browser, context; let blocked = 0, errors = 0;
const deadline = setTimeout(() => { process.exitCode = 1; void browser?.close(); }, 75000);
const hardDeadline = setTimeout(() => process.exit(2), 85000);
try {
  browser = await chromium.launch({ headless: true, executablePath, timeout: 15000,
    args: ['--disable-background-networking', '--disable-component-update', '--no-first-run'] });
  context = await browser.newContext({ serviceWorkers: 'block' });
  await context.route('**/*', route => {
    const request = route.request();
    const allowed = browserRequestAllowed(request.url(), request.method(), base);
    if (!allowed) { blocked++; return route.abort(); }
    return route.continue();
  });
  await context.addCookies([{ name: 'demo_session', value: cookie.split('=')[1],
    url: origin, httpOnly: true, sameSite: 'Lax' }]);
  const page = await context.newPage(); page.on('pageerror', () => errors++);
  const contextChecks = []; let contextFailed = false;
  page.on('response', response => {
    if (response.url() !== `${origin}${base}/llm/context`) return;
    contextChecks.push((async () => {
      assert.equal(response.request().method(), 'GET');
      assert.equal(response.status(), 200);
      assert.match(response.headers()['content-type'] || '', /^application\/json(?:;|$)/);
      assertDisabledContext(await response.json(), scanId, expected.sbom);
    })().catch(() => { contextFailed = true; }));
  });
  page.setDefaultTimeout(12000);
  const specs = [
    ['results', 'Результаты Secrets', 'findings'],
    ['sbom', 'Пакеты SBOM', 'components'],
  ];
  for (let pass = 0; pass < 2; pass++) {
    const contextReply = page.waitForResponse(response =>
      response.url() === `${origin}${base}/llm/context` && response.request().method() === 'GET');
    const replies = specs.map(([kind]) => page.waitForResponse(response => {
      const url = new URL(response.url());
      return url.pathname === `${base}/${kind}` && url.searchParams.get('view') === 'report-v1';
    }));
    if (!pass) await page.goto(`${origin}/scans/${scanId}`, { waitUntil: 'domcontentloaded' });
    else await page.reload({ waitUntil: 'domcontentloaded' });
    const disabled = await contextReply;
    assert.equal(disabled.status(), 200);
    assert.match(disabled.headers()['content-type'] || '', /^application\/json(?:;|$)/);
    assertDisabledContext(await disabled.json(), scanId, expected.sbom);
    for (const [index, response] of (await Promise.all(replies)).entries()) {
      assert.equal(response.status(), 200);
      const value = await response.json(), [kind, region, field] = specs[index];
      assert.equal(value.page.offset, 0); assert.equal(value.page.limit, 25);
      assert.deepEqual(value[field], expected[kind][field]);
      assert.equal(value.page.totalCount, expected[kind].page.totalCount);
      const section = page.getByRole('region', { name: region, exact: true });
      await expect(section.locator('[aria-busy]')).toHaveAttribute('aria-busy', 'false');
      await expect(section.getByRole('alert')).toHaveCount(0);
      await expect(section.locator('ul.scan-report-inventory > li')).toHaveCount(value[field].length);
      const text = await section.innerText();
      for (const row of value[field]) assert.ok(text.includes(kind === 'sbom' ? row.name : row.findingId));
    }
  }
  await Promise.all(contextChecks);
  assert.ok(contextChecks.length >= 2); assert.equal(contextFailed, false);
  assert.equal(blocked, 0); assert.equal(errors, 0);
  console.log(JSON.stringify({ status: 'PASS', reload: true, llmContextDisabled: true, blockedRequests: blocked, browserErrors: errors }));
} catch { console.log(JSON.stringify({ status: 'FAIL' })); process.exitCode = 1; }
finally { await context?.close(); await browser?.close(); clearTimeout(deadline); clearTimeout(hardDeadline); }
'''


def run_browser(runner, browser, owner, scan_id, reports):
    payload = json.dumps({'cookie': owner.cookie, 'scanId': scan_id, 'executablePath': str(browser),
                          'expected': reports}).encode()
    # Cookie travels over anonymous pipe, never argv, disk, or evidence.
    code, out, _ = runner.call(['node', '--input-type=module', '-e', BROWSER],
                               cap=90, input_data=payload, env=runner.env)
    require(code == 0, 'BROWSER_RELOAD_FAILED')
    value = json.loads(out)
    require(value == {'status': 'PASS', 'reload': True, 'llmContextDisabled': True, 'blockedRequests': 0, 'browserErrors': 0},
            'BROWSER_EVIDENCE')
    return value


def outbox_receipt(stand, scan_id, subject):
    identity, _ = stand.container('api')
    script = '''const D=require('better-sqlite3'); const d=new D('/data/ledger.sqlite',{readonly:true,fileMustExist:true});
const row=d.prepare(`SELECT s.state,s.digest,s.platform,s.checks,o.attempts,
o.delivered_at IS NOT NULL AS delivered FROM scans s JOIN outbox o ON o.scan_id=s.id
WHERE s.id=? AND s.subject=?`).get(process.argv[1],process.argv[2]);
d.close(); console.log(JSON.stringify(row??null));'''
    out = stand.r.checked('container', 'exec', identity, 'node', '-e', script, scan_id, subject)
    value = json.loads(out)
    require(isinstance(value, dict) and value.get('state') == 'completed'
            and value.get('delivered') == 1 and value.get('attempts', 0) >= 1
            and value.get('checks') == '["secret","sbom"]', 'OUTBOX_NOT_DELIVERED')
    return value


def workflow(stand, browser, budget, result):
    anonymous = Http(budget)
    for service in ('auth-volume-init', 'scan-volume-init'):
        stand.start(service)
        identity, _ = stand.container(service)
        code = stand.r.checked('container', 'wait', identity, cap=15)
        require(code.strip() == b'0', 'NEW_VOLUME_INIT_FAILED')
    for service in ('egress', 'worker', 'api'):
        stand.start(service)
    wait_auth(stand, budget)
    stand.start('web')
    _, web = stand.container('web')
    require(web['NetworkSettings']['Ports'].get('8080/tcp') ==
            [{'HostIp': '127.0.0.1', 'HostPort': '18080'}], 'LOOPBACK_PORT_BINDING')
    wait_http(anonymous)
    stand.verify()
    owner_id, owner = register(budget)
    peer_id, peer = register(budget)
    _, unenrolled = register(budget)
    expect_http(owner, 'GET', SCAN, 403)  # bootstrap denies all; no temporary all-accounts override
    spec = copy.deepcopy(stand.spec)
    spec['services']['api']['environment']['SCAN_BROWSER_ALLOWED_USER_IDS'] = owner_id + ',' + peer_id
    validate_spec(spec, stand.project, stand.nonce)
    stand.remove_container('api')  # only our exact recorded ID; own fresh volumes persist
    stand.save(spec)
    stand.create('api')
    stand.verify(allow_created=True)
    stand.start('api')
    wait_auth(stand, budget)
    wait_http(anonymous)
    stand.verify()
    expect_http(anonymous, 'GET', SCAN, 401)
    expect_http(unenrolled, 'GET', SCAN, 403)
    expect_status(owner, 'GET', '/api/v1/scans', 404)  # nginx HTML denial, not an app JSON contract
    for _ in range(5):
        _, eligible = expect_http(owner, 'POST', SCAN + '/images/eligibility', 200,
                                 {'imageReference': TARGET, 'checks': ['secret', 'sbom']})
        if eligible.get('eligible'):
            break
        time.sleep(min(2, budget.seconds(2)))
    require(eligible.get('eligible') is True and eligible.get('reason') == 'READY', 'DEFAULT_READINESS_OR_REGISTRY_BLOCKED')
    intent = {'imageReference': TARGET, 'scope': 'image', 'checks': ['secret', 'sbom'],
              'idempotencyKey': 'smoke-' + uuid.uuid4().hex}
    _, receipt = expect_http(owner, 'POST', SCAN, 202, intent)
    scan_id = receipt.get('scanId', '')
    require(SCAN_ID.fullmatch(scan_id), 'SCAN_RECEIPT')
    result['scan_id'] = scan_id
    _, replay = expect_http(owner, 'POST', SCAN, 202, intent)
    require(replay == receipt, 'IDEMPOTENCY_REPLAY')
    for suffix in ('', '/results?view=report-v1', '/sbom?view=report-v1', '/events'):
        expect_http(peer, 'GET', SCAN + '/' + scan_id + suffix, 404)
        expect_http(anonymous, 'GET', SCAN + '/' + scan_id + suffix, 401)
    status = terminal(owner, scan_id)
    require(status.get('state') == 'completed' and status.get('checks') == ['secret', 'sbom']
            and all(status.get('perCheck', {}).get(k, {}).get('outcome') == 'checked'
                    for k in ('secret', 'sbom')), 'REAL_SCAN_NOT_CHECKED')
    reports = {}
    for kind in ('results', 'sbom'):
        first, rows = collect_report(owner, scan_id, kind)
        coverage = first.get('coverage') if kind == 'results' else first
        require(isinstance(coverage, dict) and coverage.get('outcome') == 'checked'
                and coverage.get('scannerVersion') == '0.69.3', 'REAL_SCANNER_VERSION')
        reports[kind] = first
        result[kind] = {'count': len(rows), 'pages_checked': True,
                        'dataset_sha256': hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()}
    require(reports['sbom'].get('platform') == 'linux/amd64'
            and reports['sbom'].get('image') == 'registry-1.docker.io/library/alpine@' + status['digest']
            and result['sbom']['count'] > 0, 'SBOM_TARGET_BINDING')
    result['outbox'] = outbox_receipt(stand, scan_id, owner_id)
    require(result['outbox']['digest'] == status['digest'], 'OUTBOX_DIGEST_BINDING')
    result['actual_scan'] = 'SECRETS_SBOM_CHECKED'
    events = owner.sse(scan_id)
    require([e['state'] for e in events] == ['queued', 'running', 'completed'], 'SSE_TRANSITIONS')
    require(owner.sse(scan_id, events[0]['id']) == events[1:]
            and owner.sse(scan_id, events[-1]['id']) == [], 'SSE_EXCLUSIVE_REPLAY')
    result['sse'] = {'status': 'PASS', 'events': events, 'terminal_replay_only': True}
    # No DB release, CVE opt-in or positive CVE coverage claim.
    _, denied = expect_http(owner, 'POST', SCAN, 503, {**intent, 'checks': ['vuln'],
                                                     'idempotencyKey': 'cve-denied-' + uuid.uuid4().hex})
    require(denied.get('errorCode') == 'SCANNER_UNAVAILABLE', 'CVE_DEFAULT_DENIAL')
    result['cve'] = 'UNSUPPORTED_NOT_ENABLED_NO_DB_RELEASE'
    result['browser'] = run_browser(stand.r, browser, owner, scan_id, reports)
    # Eligibility charges unsupported references before returning, without registry dispatch.
    # A fresh enrolled peer has no prior eligibility calls. This is NOT scan admission 429.
    rate_start = budget.clock()
    negative = {'imageReference': 'registry-1.docker.io/library/nginx:latest', 'checks': ['secret']}
    for _ in range(30):
        _, value = expect_http(peer, 'POST', SCAN + '/images/eligibility', 200, negative)
        require(value.get('eligible') is False and value.get('reason') == 'UNSUPPORTED_SCAN', 'UNSUPPORTED_TARGET_GATE')
    headers, limited = expect_http(peer, 'POST', SCAN + '/images/eligibility', 429, negative)
    seconds = limited.get('retryAfterSeconds')
    require(budget.clock() - rate_start < 60 and limited.get('errorCode') == 'IMAGE_SEARCH_RATE_LIMITED'
            and limited.get('limitReason') == 'rate' and type(seconds) is int and 1 <= seconds <= 60
            and next((v for k, v in headers.items() if k.lower() == 'retry-after'), None) == str(seconds), 'ELIGIBILITY_429_CONTRACT')
    result['rate_limit'] = {'status': 'PASS', 'scope': 'eligibility_only', 'retry_after': seconds}
    # No sleeping/pausing worker, readiness marker forging or queue seeding to win a race.
    _, second = expect_http(owner, 'POST', SCAN, 202,
                            {**intent, 'idempotencyKey': 'cancel-' + uuid.uuid4().hex})
    cancel_id = second.get('scanId', '')
    require(SCAN_ID.fullmatch(cancel_id), 'CANCEL_SCAN_RECEIPT')
    code, _, cancelled = owner.request('POST', SCAN + '/' + cancel_id + '/cancel', {})
    if code == 200:
        require(cancelled == {'scanId': cancel_id, 'state': 'cancelled'}, 'CANCEL_RECEIPT')
        require(terminal(owner, cancel_id)['state'] == 'cancelled', 'CANCEL_TERMINAL')
        time.sleep(min(2, budget.seconds(2)))
        _, stable = expect_http(owner, 'GET', SCAN + '/' + cancel_id, 200)
        require(stable['state'] == 'cancelled', 'CANCEL_LATE_RESULT')
        result['cancel'] = {'status': 'PASS', 'scan_id': cancel_id, 'termination': 'best_effort_not_proven'}
    else:
        require(code == 409 and cancelled.get('errorCode') == 'SCAN_TERMINAL', 'CANCEL_UNEXPECTED')
        result['cancel'] = {'status': 'NOT_OBSERVED_TERMINAL_RACE', 'scan_id': cancel_id}
    # Fresh HTTP connection, same owner, same committed dataset after browser reload.
    for kind in ('results', 'sbom'):
        _, rows = collect_report(owner, scan_id, kind)
        require(hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()
                == result[kind]['dataset_sha256'], 'REPORT_RELOAD_CHANGED')


def wait_auth(stand, budget):
    end = budget.clock() + budget.seconds(60)
    while budget.clock() < end:
        _, obj = stand.container('api')
        if obj['State'].get('Health', {}).get('Status') == 'healthy':
            return
        require(obj['State']['Status'] not in {'exited', 'dead'}, 'API_BOOT_FAILED')
        time.sleep(min(1, budget.seconds(1)))
    raise Failure('API_HEALTH_TIMEOUT')


def wait_http(client):
    end = client.budget.clock() + client.budget.seconds(20)
    while client.budget.clock() < end:
        try:
            expect_http(client, 'GET', '/api/v1/auth/me', 401)
            return
        except (ConnectionError, OSError, http.client.HTTPException):
            time.sleep(min(1, client.budget.seconds(1)))
    raise Failure('OWN_WEB_HTTP_TIMEOUT')


def load_prebuilt(args):
    path = Path(args.prebuilt_metadata or '')
    path = path if path.is_absolute() else ROOT / path
    require(path == path.resolve() and path.is_relative_to(ROOT / 'test-results')
            and path.name == 'prebuilt-images.json' and path.is_file(), 'PUBLIC_PREBUILT_METADATA_PATH')
    with path.open('rb') as source:
        raw = source.read(16385)
    require(len(raw) <= 16384 and hashlib.sha256(raw).hexdigest() == args.prebuilt_sha256,
            'PREBUILT_METADATA_HASH')
    metadata = json.loads(raw)
    validate_prebuilt(metadata, args)
    return metadata


def validate_prebuilt(metadata, args):
    require(set(metadata) == {'version', 'base', 'context_sha256', 'images', 'init', 'chromium'}
            and metadata['version'] == 1 and metadata['base'] == BASE
            and metadata['context_sha256'] == CONTEXT_SHA256, 'PREBUILT_SOURCE_BINDING')
    require(set(metadata['images']) == {'web', 'egress'}, 'PREBUILT_ROLE_SET')
    for role, identity in [('web', args.web_image), ('egress', args.gateway_image)]:
        record = metadata['images'][role]
        require(IMAGE_ID.fullmatch(identity) and record['id'] == identity
                and record['exit_code'] == 0 and record['timed_out'] is False
                and record['os'] == 'linux' and record['architecture'] == 'arm64'
                and record['user'] == ('101:101' if role == 'web' else '65532:65532'),
                'PREBUILT_IMAGE_BINDING')
        labels = record['labels']
        require(labels.get(LABEL + '.source') == BASE and labels.get(LABEL + '.role') == role
                and labels.get(LABEL + '.context') == CONTEXT_SHA256, 'PREBUILT_LABEL_BINDING')
    init = metadata['init']
    require(IMAGE_ID.fullmatch(init['id']) and init['reference'] == args.init_image
            and init['repo_digest'].split('@')[0] in {'busybox', 'docker.io/library/busybox'}
            and init['repo_digest'].split('@')[-1] == args.init_image.split('@')[-1]
            and init['os'] == 'linux' and init['architecture'] == 'arm64', 'PREBUILT_INIT_BINDING')
    browser = metadata['chromium']
    require(browser['executable'] == args.chromium_executable and browser['exists'] is True
            and browser['executable_access'] is True and browser['playwright'] == '1.59.1',
            'PREBUILT_BROWSER_TOOLCHAIN_BINDING')


def verify_prebuilt_images(runner, metadata, args):
    images = {**IMAGES, 'web': args.web_image, 'egress': args.gateway_image,
              'init': metadata['init']['id']}
    for role, identity in images.items():
        obj = runner.inspect('image', identity)
        require(obj is not None and obj['Id'] == identity and obj['Os'] == 'linux'
                and obj['Architecture'] == 'arm64', 'PREBUILT_IMAGE_MISSING_OR_CHANGED')
        if role in {'web', 'egress'}:
            labels = obj['Config'].get('Labels') or {}
            require(all(labels.get(LABEL + suffix) == value for suffix, value in
                        [('.source', BASE), ('.role', role), ('.context', CONTEXT_SHA256)])
                    and obj['Config']['User'] == metadata['images'][role]['user'],
                    'ACTUAL_PREBUILT_METADATA_MISMATCH')
        if role == 'init':
            require(metadata['init']['repo_digest'] in obj.get('RepoDigests', []),
                    'ACTUAL_INIT_REPODIGEST_MISMATCH')
    return images


def prepare(runner, project, nonce, args, result):
    metadata = load_prebuilt(args)
    code, raw, _ = runner.call(['git', '--no-pager', '-C', str(ROOT), 'rev-parse', 'HEAD'])
    require(code == 0 and raw.decode().strip() == BASE, 'HEAD_CHANGED_REVIEW_REQUIRED')
    images = verify_prebuilt_images(runner, metadata, args)
    result.update(images=images, prebuilt_metadata_sha256=args.prebuilt_sha256,
                  context_sha256=metadata['context_sha256'])
    for kind in ('container', 'network', 'volume'):
        query = [kind, 'ls', '--filter', 'label=com.docker.compose.project=' + project,
                 '--format', '{{.Name}}' if kind == 'volume' else '{{.ID}}']
        if kind == 'container':
            query.insert(2, '--all')
        require(not runner.checked(*query).strip(), 'PROJECT_ALREADY_EXISTS')
    with socket.socket() as port:
        port.bind(('127.0.0.1', 18080))  # only availability test; not a stand listener
    baseline = runner.work / 'baseline.yaml'
    code, raw, _ = runner.call(['git', '--no-pager', '-C', str(ROOT), 'show',
                                BASE + ':./server/deploy/compose.stand.yaml'])
    require(code == 0, 'BASELINE_READ_FAILED')
    baseline.write_bytes(raw)
    env = {**runner.env, 'SCAN_JWT_SECRET': secrets.token_hex(32), 'AUTH_ORIGIN': ORIGIN,
           'AUTH_ALLOW_INSECURE_LOCAL_HTTP': 'true', 'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS': 'false'}
    code, raw, _ = runner.docker('compose', '--env-file', '/dev/null', '--project-directory', str(runner.work),
                                '--project-name', project, '--file', str(baseline),
                                'config', '--format', 'json', env=env)
    require(code == 0, 'BASELINE_COMPOSE_CONFIG')
    return build_spec(json.loads(raw), project, nonce, images, [], env['SCAN_JWT_SECRET'])


def execute(args, browser):
    budget = Budget()
    nonce = uuid.uuid4().hex
    project = 'dip-image-stand-' + nonce
    parent = ROOT / 'test-results'
    require(parent.is_dir() and not parent.is_symlink(), 'ARTIFACT_ROOT')
    work = parent / project
    work.mkdir(mode=0o700, exist_ok=False)
    config = work / 'docker-config'
    config.mkdir(mode=0o700)
    (config / 'config.json').write_text('{}\n')
    (config / 'config.json').chmod(0o600)
    plugin_dir = Path(args.plugin_dir)
    plugins = config / 'cli-plugins'
    plugins.mkdir()
    for name in ('docker-compose',):
        require((plugin_dir / name).is_file(), 'PUBLIC_CLI_PLUGIN_REQUIRED')
        (plugins / name).symlink_to((plugin_dir / name).resolve())
    runner = Runner(work, budget)
    stand = Stand(runner, project, nonce, persist=True)
    result = {'status': 'FAIL', 'base': BASE, 'project': project, 'images': IMAGES,
              'image_mode': 'PREBUILT_ONLY_NO_BUILD_PULL_HISTORY', 'actual_scan': 'NOT_YET_CHECKED', 'deployment': 'NOT_PRODUCTION',
              'reviewed_source_sha256': args.reviewed_sha256}
    old_handlers = {}
    def interrupted(_signum, _frame):
        raise Failure('INTERRUPTED')
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
        old_handlers[signum] = signal.signal(signum, interrupted)
    # Wall-clock backstop also bounds slow HTTP headers. Normal work must leave
    # two minutes for exact-ID cleanup; no operation may renew the whole budget.
    signal.setitimer(signal.ITIMER_REAL, budget.seconds(WHOLE_SECONDS))
    try:
        result['phase'] = 'prepare'
        spec = prepare(runner, project, nonce, args, result)
        result['phase'] = 'new_storage_and_create'
        stand.save(spec)
        stand.new_storage()
        stand.create()
        stand.verify(allow_created=True)
        result['phase'] = 'http_scan_report_browser_and_cancel'
        workflow(stand, browser, budget, result)
        result['phase'] = 'checks_finished'
        result['status'] = 'PASS' if result['cancel']['status'] == 'PASS' else 'PARTIAL_CANCEL_RACE'
    except Exception as error:
        result['error'] = str(error) if isinstance(error, Failure) else 'UNEXPECTED_' + type(error).__name__
    finally:
        signal.setitimer(signal.ITIMER_REAL, max(0.001, budget.end - budget.clock()))
        result['cleanup'] = stand.cleanup()
        if result['cleanup']['status'] != 'PASS':
            result['status'] = 'FAIL'
        stand.file.unlink(missing_ok=True)  # remove only our synthetic credential file
        signal.setitimer(signal.ITIMER_REAL, 0)
        for signum, previous in old_handlers.items():
            signal.signal(signum, previous)
        result['elapsed_seconds'] = round(WHOLE_SECONDS - (budget.end - budget.clock()), 3)
        (work / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--plan', action='store_true', help='source-only; default, no Docker calls')
    mode.add_argument('--execute-reviewed', action='store_true')
    parser.add_argument('--reviewed-sha256')
    parser.add_argument('--init-image')
    parser.add_argument('--web-image')
    parser.add_argument('--gateway-image')
    parser.add_argument('--prebuilt-metadata')
    parser.add_argument('--prebuilt-sha256')
    parser.add_argument('--chromium-executable')
    parser.add_argument('--plugin-dir', default='/Applications/Docker.app/Contents/Resources/cli-plugins')
    args = parser.parse_args(argv)
    if not args.execute_reviewed:
        print(json.dumps(plan(), indent=2))
        return 0
    try:
        browser = authorize(args)
        return execute(args, browser)
    except Exception as error:
        print(json.dumps({'status': 'FAIL', 'error': str(error) if isinstance(error, Failure)
                          else 'UNEXPECTED_' + type(error).__name__}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
