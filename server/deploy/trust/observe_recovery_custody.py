#!/usr/bin/env python3
"""Repeatable observation, never recovery, resource adoption or PRE certification.

BLOCKED pending separate informed privacy consent and independent review.
Docker CLI --format filters stdout, NOT Engine responses: the trusted local CLI
internally receives full records, including container Env/labels, for known AND
foreign targets. No such sensitive fields are emitted to the agent receipt.
Native entry refuses without distinct --allow-cli-full-metadata acknowledgement;
maintenance/preservation consent is not this consent. No controller imports.
Native entry also requires -I -B and reviewed source/test pins. Eleven read-only
Docker calls maximum, two complete <=32-container sweeps, 90s shared clock,
8s/client, <=3MiB aggregate CLI PIPE transport, <=16KiB closed receipt. These
caps do NOT bound full Engine responses or CLI internal memory. External 110s
supervisor required for blocked filesystem calls. No retries/fallback.
Host private filesystem access is directory metadata for TWO fixed roots ONLY,
no leaves. Output write/flush failure exits 74 without retry or shutdown flush.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

REPO = Path('/Users/vsevolod/Documents/oldstartup/diplom')
SELF = 'server/deploy/trust/observe_recovery_custody.py'
TEST = 'server/deploy/trust/test_observe_recovery_custody.py'
ROOTS = (('checkout', REPO / '.local-auth'),
         ('historical', Path('/Users/vsevolod/Documents/startup/diplom/.local-auth')))
SOCKET = 'unix:///Users/vsevolod/.docker/run/docker.sock'
# Historical public CLI identity, NOT a fresh native observation or fallback path.
DOCKER = Path('/opt/homebrew/Cellar/docker/28.1.1/bin/docker')
DOCKER_SHA256 = '5cfddb229b6278953fdbb5016619e0f786ac8291969183fb28e3717a92f8bd52'
HEX = re.compile(r'[a-f0-9]{64}\Z')
TARGETS = {
    'api': ('5cbe0936a5f09d663a77960749e687fbd41fbef52c8990b063362b9363d3e9ec', 'sha256:487c3909d3eeee08d60840a81c1adeb61c292aee0a31df17b2a8cf92f6dbb58c'),
    'worker': ('016c41e7b3eabcbb08903bbc3c54d657ed92c22813e47fa37d444cb448602b44', 'sha256:8748cbebba753603d79f320c2fb476c46ab676ce12e0aa08bee0021a3e14e57a'),
    'web': ('b84245ef672d172d5513971a57ea91469800846cdf6c59bedceb006b06caa4f4', 'sha256:1659b39c98d5183c91feae78a8d9eb1d4c6ee527d541c1e1d74dfe842adee8c0'),
    'egress': ('2850e2d03d0681482727f7b5d658961ef9ef2aa829b63473f36d8ed3c63f3d35', 'sha256:2b9eff3b381979c82bf42c310fcd7941805d42adeda67c8814143d6503490655'),
    'llm-egress': ('f64639115f21233277ac52db2bd5ceda495203511da87896ff996e8c1ce3a68a', 'sha256:3ccbd5a6c3348b7b1c99e23b29d9bdca485dfd48f690a408a119e06163a59a8d'),
    'holder': ('207709f0f2992532af3331e0e2b38878c08a8d157ad074956f78c895aa5380e4', 'sha256:487c3909d3eeee08d60840a81c1adeb61c292aee0a31df17b2a8cf92f6dbb58c'),
    'created-holder': ('d9433f7ed0fc504a3521574668f15b7b3a0e8d283d61b9aa33d1e97187708a4f', 'sha256:487c3909d3eeee08d60840a81c1adeb61c292aee0a31df17b2a8cf92f6dbb58c'),
}
VOLUMES = {'auth': 'dip-auth-stand_auth_accounts', 'data': 'dip-auth-stand_scan_ledger'}
TMPFS = {'/backup': 'rw,noexec,nosuid,uid=65532,gid=65532,mode=0700,size=2g',
         '/tmp': 'rw,noexec,nosuid,uid=65532,gid=65532,mode=0700,size=128m'}
# CLI stdout projection ONLY: the CLI still receives full Engine records,
# including Env/labels. This is not an API no-read boundary. Nil Mounts becomes
# [] through range, NOT a truncated prefix or parser-side null coercion.
MOUNTS_FORMAT = ('[{{range $i, $m := .Mounts}}{{if $i}},{{end}}'
    '{"type":{{json $m.Type}},"name":{{json $m.Name}},"source":{{json $m.Source}},'
    '"destination":{{json $m.Destination}},"rw":{{json $m.RW}},'
    '"propagation":{{json $m.Propagation}}}{{end}}]')
COMMON_FORMAT = ('{"id":{{json .Id}},"status":{{json .State.Status}},'
    '"running":{{json .State.Running}},"paused":{{json .State.Paused}},'
    '"restarting":{{json .State.Restarting}},"dead":{{json .State.Dead}},'
    '"oom":{{json .State.OOMKilled}},"exit":{{json .State.ExitCode}},'
    '"mounts":' + MOUNTS_FORMAT + '}')
KNOWN_FORMAT = (COMMON_FORMAT[:-1] + ',"image":{{json .Image}},'
    '"tmpfs":{{json .HostConfig.Tmpfs}}}')
VOLUME_FORMAT = ('{"name":{{json .Name}},"driver":{{json .Driver}},'
    '"scope":{{json .Scope}},"optionsPresent":{{if .Options}}true{{else}}false{{end}},'
    '"mountpoint":{{json .Mountpoint}},"created":{{json .CreatedAt}}}')
INFO = ('info', '--format', '{{json .ID}}')
CENSUS = ('container', 'ls', '--all', '--no-trunc', '--format', '{{.ID}}')
VOLUME = ('volume', 'inspect', '--format', VOLUME_FORMAT, *VOLUMES.values())
CONSENT_FLAG = '--allow-cli-full-metadata'
OUTPUT_FAILURE = 74
CHECKPOINTS = frozenset(('ARGUMENTS', 'PRIVACY_CONSENT', 'PUBLIC_SOURCES', 'ROOTS', 'DAEMON_BEFORE',
    'VOLUMES_BEFORE', 'CENSUS_BEFORE', 'KNOWN_BEFORE', 'BATCH_BEFORE', 'CENSUS_AFTER',
    'BATCH_AFTER', 'KNOWN_AFTER', 'VOLUMES_AFTER', 'CENSUS_FINAL', 'DAEMON_AFTER', 'CLASSIFY',
    'SOURCE_FINAL', 'COMPLETE', 'OUTPUT'))
CATEGORIES = frozenset(('NONE', 'ARGUMENT_REFUSED', 'CLI_FULL_METADATA_CONSENT_REQUIRED',
    'SOURCE_REFUSED', 'EXEC_IDENTITY',
    'EXEC_NOT_FOUND', 'EXEC_DENIED', 'EXEC_IO', 'COMMAND_REFUSED', 'CLIENT_TIMEOUT',
    'CLIENT_NONZERO', 'CLIENT_IO', 'OUTPUT_CAP', 'DECODE_REFUSED', 'SHAPE_REFUSED', 'MOUNT_REFUSED',
    'VOLUME_REFUSED', 'CENSUS_REFUSED', 'OBSERVATION_DRIFT', 'HOST_IO', 'UNEXPECTED'))
MAX_CONTAINERS = 32
MAX_MOUNTS = 64
TRANSPORT_CAP = 3 * 1024**2
RECEIPT_CAP = 16384


class Refused(Exception):
    def __init__(self, category):
        self.category = category if category in CATEGORIES else 'UNEXPECTED'
        super().__init__('REFUSED')


def need(value, category='SHAPE_REFUSED'):
    if not value:
        raise Refused(category)


def tick(deadline):
    need(time.monotonic() < deadline, 'CLIENT_TIMEOUT')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def decode(raw, cap):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'DECODE_REFUSED')
            result[key] = value
        return result
    def reject(_):
        raise Refused('DECODE_REFUSED')
    need(type(raw) is bytes and 0 < len(raw) <= cap, 'OUTPUT_CAP')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                          parse_float=reject, parse_constant=reject)
    except (UnicodeError, ValueError, RecursionError):
        raise Refused('DECODE_REFUSED') from None


def string(value, cap=4096, empty=False):
    need(type(value) is str and (empty or bool(value)) and len(value.encode()) <= cap)
    need(not any(ord(c) < 32 or ord(c) == 127 for c in value))
    return value


def absolute(value):
    string(value)
    need(value.startswith('/') and not value.startswith('//') and
         os.path.normpath(value) == value, 'MOUNT_REFUSED')
    return value


def census(raw):
    need(type(raw) is bytes and len(raw) <= 4096, 'OUTPUT_CAP')
    try:
        need(raw == b'' or raw.endswith(b'\n'), 'CENSUS_REFUSED')
        ids = raw.decode('ascii').splitlines()
    except UnicodeError:
        raise Refused('CENSUS_REFUSED') from None
    need(len(ids) <= MAX_CONTAINERS and len(set(ids)) == len(ids) and
         all(HEX.fullmatch(item) for item in ids), 'CENSUS_REFUSED')
    return tuple(sorted(ids))


def inspect_args(ids, known=False):
    return ('container', 'inspect', '--format', KNOWN_FORMAT if known else COMMON_FORMAT, *ids)


def mounts(value):
    need(type(value) is list and len(value) <= MAX_MOUNTS, 'MOUNT_REFUSED')
    destinations = set()
    for m in value:
        need(type(m) is dict and set(m) == {'type', 'name', 'source', 'destination',
             'rw', 'propagation'}, 'MOUNT_REFUSED')
        need(m['type'] in ('volume', 'bind', 'tmpfs'), 'MOUNT_REFUSED')
        string(m['name'], empty=True)
        string(m['propagation'], cap=128, empty=True)
        absolute(m['destination'])
        need(m['destination'] not in destinations and type(m['rw']) is bool, 'MOUNT_REFUSED')
        destinations.add(m['destination'])
        if m['type'] in ('volume', 'bind'):
            absolute(m['source'])
        else:
            string(m['source'], empty=True)
            need(not m['source'] or m['source'].startswith('/'), 'MOUNT_REFUSED')
            if m['source']:
                absolute(m['source'])
        need(bool(m['name']) if m['type'] == 'volume' else not m['name'], 'MOUNT_REFUSED')
    # Only outer order ignored; cardinality/duplicates/all projected fields retained.
    return sorted(value, key=canonical)


def rows(raw, ids, known=False):
    cap = 128 * 1024 if known else 1024**2
    need(type(raw) is bytes and len(raw) <= cap and raw.endswith(b'\n'), 'OUTPUT_CAP')
    lines = raw.splitlines()
    need(len(lines) == len(ids), 'SHAPE_REFUSED')
    result = {}
    fields = {'id', 'status', 'running', 'paused', 'restarting', 'dead', 'oom', 'exit', 'mounts'}
    for line in lines:
        r = decode(line, cap)
        need(type(r) is dict and set(r) == fields | ({'image', 'tmpfs'} if known else set()))
        need(type(r['id']) is str and r['id'] in ids and r['id'] not in result)
        need(r['status'] in ('created', 'running', 'paused', 'restarting', 'exited', 'dead', 'removing'))
        need(all(type(r[k]) is bool for k in ('running', 'paused', 'restarting', 'dead', 'oom')))
        need(type(r['exit']) is int and -2147483648 <= r['exit'] <= 2147483647)
        need(not r['paused'] or r['running'])
        if r['status'] in ('created', 'exited'):
            need(not any(r[k] for k in ('running', 'paused', 'restarting', 'dead')))
        if r['status'] == 'running':
            need(r['running'] and not r['paused'] and not r['restarting'] and not r['dead'])
        if r['status'] == 'paused':
            need(r['paused'] and r['running'] and not r['restarting'] and not r['dead'])
        if r['status'] == 'restarting':
            need(r['restarting'])
        r['mounts'] = mounts(r['mounts'])
        if known:
            need(type(r['image']) is str and re.fullmatch(r'sha256:[a-f0-9]{64}', r['image']))
            need(r['tmpfs'] is None or type(r['tmpfs']) is dict and len(r['tmpfs']) <= 8)
            for key, value in (r['tmpfs'] or {}).items():
                absolute(key)
                string(value, cap=1024)
        result[r['id']] = r
    need(set(result) == set(ids))
    return result


def volumes(raw):
    need(type(raw) is bytes and len(raw) <= 16384 and raw.endswith(b'\n'), 'OUTPUT_CAP')
    lines = raw.splitlines()
    need(len(lines) == 2, 'VOLUME_REFUSED')
    result = {}
    for line in lines:
        v = decode(line, 16384)
        need(type(v) is dict and set(v) == {'name', 'driver', 'scope', 'optionsPresent',
             'mountpoint', 'created'}, 'VOLUME_REFUSED')
        need(type(v['name']) is str and v['name'] in VOLUMES.values() and v['name'] not in result,
             'VOLUME_REFUSED')
        need(v['driver'] == v['scope'] == 'local' and v['optionsPresent'] is False, 'VOLUME_REFUSED')
        absolute(v['mountpoint'])
        string(v['created'], cap=128)
        result[v['name']] = v
    paths = [v['mountpoint'] for v in result.values()]
    need(len(set(paths)) == 2 and not overlap(*paths), 'VOLUME_REFUSED')
    return result


def overlap(a, b):
    return a == b or a.startswith(b.rstrip('/') + '/') or b.startswith(a.rstrip('/') + '/')


def touches(m, v):
    # Reject-only conservative name/path checks, never a resource ownership grant.
    return (m['name'] in VOLUMES.values() or
            any(name in m['source'].split('/') for name in VOLUMES.values()) or
            bool(m['source'].startswith('/') and
                 any(overlap(m['source'], item['mountpoint']) for item in v.values())))


def potentially_active(r):
    # Paused and restarting are never exemptions; dead/removing are uncertain.
    return any(r[k] for k in ('running', 'paused', 'restarting', 'dead')) or r['status'] not in ('created', 'exited')


def binding(r, volume, destination, v):
    if r is None:
        return 'NOT_OBSERVED'
    entries = [m for m in r['mounts'] if m['destination'] == destination]
    if not entries:
        return 'MISSING_TARGET'
    m = entries[0]
    if m['type'] != 'volume' or m['name'] != volume or m['source'] != v[volume]['mountpoint']:
        return 'WRONG_BINDING'
    return 'MATCH_RW' if m['rw'] else 'MATCH_RO'


def classify(v, all_rows, known):
    targets = {}
    for role, (identity, image) in TARGETS.items():
        r = known.get(identity)
        targets[role] = {'present': r is not None, 'state': r['status'].upper() if r else 'ABSENT_IN_CENSUS',
                         'imageMatches': r['image'] == image if r else None,
                         'exit': ('ZERO' if r['exit'] == 0 else 'NONZERO') if r else 'NOT_OBSERVED',
                                                  'flags': {k: r[k] if r else None for k in
                                                            ('running', 'paused', 'restarting', 'dead', 'oom')}}
    bindings = {}
    for role, key, destination in (('api', 'auth', '/auth'), ('api', 'data', '/data'),
                                    ('worker', 'data', '/data'), ('holder', 'auth', '/source/auth'),
                                    ('holder', 'data', '/source/data')):
        bindings[role + '.' + key] = binding(known.get(TARGETS[role][0]), VOLUMES[key], destination, v)
    holder = known.get(TARGETS['holder'][0])
    no_active = not any(potentially_active(r) and any(touches(m, v) for m in r['mounts'])
                        for r in all_rows.values())
    return {'targets': targets, 'volumesPresent': {'auth': True, 'data': True},
            'mountBindings': bindings, 'originalBindingsMatch': all(bindings[k] in ('MATCH_RO', 'MATCH_RW')
                for k in ('api.auth', 'api.data', 'worker.data')),
            'noActiveProtectedAttachments': no_active,
            'completeStableMetadataFence': True,
            'holderTmpfsDeclarationMatches': holder['tmpfs'] == TMPFS if holder else None,
            'holderTmpfs': 'EXITED_NOT_RESTORABLE_BY_START' if holder and holder['status'] == 'exited'
                          else 'NOT_ESTABLISHED',
            'aliasCoverage': 'NAMED_AND_LITERAL_SOURCE_OVERLAP_ONLY'}


def stamp(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid, s.st_gid,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


class MetadataFS:
    """Directory-only adapter. No read/scandir/leaf open API is provided."""
    def root(self):
        return os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def lstat(self, fd, name):
        return os.stat(name, dir_fd=fd, follow_symlinks=False)

    def directory(self, fd, name):
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)

    def fstat(self, fd):
        return os.fstat(fd)

    def close(self, fd):
        os.close(fd)


def root_metadata(path, fs, deadline, uid, gid):
    """755 may be observable; private700 is a SEPARATE false predicate, not waived."""
    result = {'classification': 'NOT_OBSERVED', 'atRoot': None, 'uidMatch': None,
              'gidMatch': None, 'mode700': None, 'mode755': None,
              'noGroupWorldWrite': None, 'ownerAllowed': None,
              'private700Matches': None, 'stable': False}
    fds, edges = [], []
    try:
        fds.append(fs.root())
        for index, part in enumerate(path.parts[1:]):
            tick(deadline)
            final = index == len(path.parts) - 2
            try:
                before = fs.lstat(fds[-1], part)
            except FileNotFoundError:
                result.update(classification='ABSENT', atRoot=final)
                try:
                    fs.lstat(fds[-1], part)
                except FileNotFoundError:
                    break
                raise Refused('OBSERVATION_DRIFT')
            if stat.S_ISLNK(before.st_mode):
                result.update(classification='SYMLINK_REFUSED', atRoot=final)
                edges.append((fds[-1], part, stamp(before)))
                break
            if not stat.S_ISDIR(before.st_mode):
                result.update(classification='NOT_DIRECTORY', atRoot=final)
                edges.append((fds[-1], part, stamp(before)))
                break
            mode = stat.S_IMODE(before.st_mode)
            if final:
                result.update(classification='DIRECTORY_METADATA', atRoot=True,
                    uidMatch=before.st_uid == uid, gidMatch=before.st_gid == gid,
                    mode700=mode == 0o700, mode755=mode == 0o755,
                    noGroupWorldWrite=not bool(mode & 0o022), ownerAllowed=before.st_uid in (0, uid),
                    private700Matches=before.st_uid == uid and before.st_gid == gid and mode == 0o700)
            edges.append((fds[-1], part, stamp(before)))
            # Unsafe final directory is classified, never opened or traversed.
            if before.st_uid not in (0, uid) or mode & 0o022:
                if not final:
                    result.update(classification='UNSAFE_ANCESTOR', atRoot=False)
                break
            child = fs.directory(fds[-1], part)
            fds.append(child)
            need(stamp(fs.fstat(child)) == stamp(before), 'OBSERVATION_DRIFT')
        for parent, name, before in edges:
            tick(deadline)
            need(stamp(fs.lstat(parent, name)) == before, 'OBSERVATION_DRIFT')
        result['stable'] = True
        return result
    except Refused:
        raise
    except OSError:
        raise Refused('HOST_IO') from None
    finally:
        for fd in reversed(fds):
            fs.close(fd)


def public_hash(path, deadline, cap):
    """Only called with the two public source paths or canonical CLI, never roots."""
    fds, edges, fd = [], [], None
    try:
        fds.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        for part in path.parent.parts[1:]:
            tick(deadline)
            s = os.stat(part, dir_fd=fds[-1], follow_symlinks=False)
            need(stat.S_ISDIR(s.st_mode) and not s.st_mode & 0o022 and
                 s.st_uid in (0, os.geteuid()), 'SOURCE_REFUSED')
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1])
            edges.append((fds[-1], part, stamp(s)))
            fds.append(child)
            need(stamp(os.fstat(child)) == stamp(s), 'SOURCE_REFUSED')
        before = os.stat(path.name, dir_fd=fds[-1], follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             before.st_uid in (0, os.geteuid()) and not before.st_mode & 0o022 and
             0 < before.st_size <= cap, 'SOURCE_REFUSED')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fds[-1])
        need(stamp(os.fstat(fd)) == stamp(before), 'SOURCE_REFUSED')
        digest, total = hashlib.sha256(), 0
        while True:
            tick(deadline)
            block = os.read(fd, min(65536, cap + 1 - total))
            if not block:
                break
            total += len(block)
            need(total <= cap, 'SOURCE_REFUSED')
            digest.update(block)
        need(total == before.st_size and stamp(os.fstat(fd)) == stamp(before) and
             stamp(os.stat(path.name, dir_fd=fds[-1], follow_symlinks=False)) == stamp(before), 'SOURCE_REFUSED')
        for parent, name, before_edge in edges:
            need(stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)) == before_edge, 'SOURCE_REFUSED')
        return digest.hexdigest()
    finally:
        if fd is not None:
            os.close(fd)
        for item in reversed(fds):
            os.close(item)


def config_absent():
    try:
        os.stat(REPO / 'server/deploy/trust/config.json', follow_symlinks=False)
    except FileNotFoundError:
        return
    raise Refused('SOURCE_REFUSED')


def verify_cli(deadline):
    try:
        need(public_hash(DOCKER, deadline, 64 * 1024**2) == DOCKER_SHA256, 'EXEC_IDENTITY')
    except FileNotFoundError:
        raise Refused('EXEC_NOT_FOUND') from None
    except PermissionError:
        raise Refused('EXEC_DENIED') from None
    except OSError:
        raise Refused('EXEC_IO') from None
    except Refused as exc:
        if exc.category == 'CLIENT_TIMEOUT':
            raise
        raise Refused('EXEC_IDENTITY') from None


class DockerClient:
    """Trusted local full-record filter, not an Engine field-projection API."""
    def __init__(self, deadline, *, allow_cli_full_metadata=False):
        self.allow_cli_full_metadata = allow_cli_full_metadata
        self.deadline, self.calls, self.total = deadline, 0, 0
        self.used, self.ids = {}, None

    def bind(self, ids):
        need(self.ids is None and type(ids) is tuple and len(ids) <= MAX_CONTAINERS and
             len(set(ids)) == len(ids) and all(HEX.fullmatch(i) for i in ids), 'COMMAND_REFUSED')
        self.ids = ids

    def __call__(self, args):
        need(self.allow_cli_full_metadata is True, 'CLI_FULL_METADATA_CONSENT_REQUIRED')
        tick(self.deadline)
        allowed = {INFO: (2, 4096), VOLUME: (2, 16384), CENSUS: (3, 4096)}
        if self.ids:
            allowed[inspect_args(self.ids)] = (2, 1024**2)
            known = tuple(i for i in self.ids if i in {v[0] for v in TARGETS.values()})
            if known:
                allowed[inspect_args(known, True)] = (2, 128 * 1024)
        need(type(args) is tuple and args in allowed and self.calls < 11, 'COMMAND_REFUSED')
        limit, cap = allowed[args]
        need(self.used.get(args, 0) < limit, 'COMMAND_REFUSED')
        self.used[args] = self.used.get(args, 0) + 1
        self.calls += 1
        verify_cli(self.deadline)
        config_absent()
        until = min(self.deadline, time.monotonic() + 8)
        env = {'PATH': '/usr/bin:/bin', 'HOME': '/var/empty', 'DOCKER_HOST': SOCKET,
               'DOCKER_CONTEXT': '', 'DOCKER_CONFIG': str(REPO / 'server/deploy/trust')}
        proc = None
        try:
            proc = subprocess.Popen((str(DOCKER), '--config', env['DOCKER_CONFIG'], '--host', SOCKET, *args),
                cwd=REPO, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True)
        except FileNotFoundError:
            raise Refused('EXEC_NOT_FOUND') from None
        except PermissionError:
            raise Refused('EXEC_DENIED') from None
        except OSError:
            raise Refused('EXEC_IO') from None
        output, stderr_bytes = bytearray(), 0
        try:
            with selectors.DefaultSelector() as streams:
                streams.register(proc.stdout, selectors.EVENT_READ, True)
                streams.register(proc.stderr, selectors.EVENT_READ, False)
                while streams.get_map():
                    tick(until)
                    for key, _ in streams.select(min(0.05, max(0, until - time.monotonic()))):
                        stream_left = cap - len(output) if key.data else 4096 - stderr_bytes
                        read_cap = min(8192, stream_left + 1, TRANSPORT_CAP - self.total + 1)
                        block = os.read(key.fd, read_cap)
                        if not block:
                            streams.unregister(key.fileobj)
                            continue
                        self.total += len(block)
                        need(self.total <= TRANSPORT_CAP, 'OUTPUT_CAP')
                        if key.data:
                            output.extend(block)
                            need(len(output) <= cap, 'OUTPUT_CAP')
                        else:
                            stderr_bytes += len(block)
                            need(stderr_bytes <= 4096, 'OUTPUT_CAP')
                tick(until)
                need(proc.wait(timeout=max(0.001, until - time.monotonic())) == 0, 'CLIENT_NONZERO')
            tick(self.deadline)
            return bytes(output)
        except BaseException as exc:
            # Kill/reap CLI process group ONLY, never any Docker resource.
            try:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                proc.wait(timeout=0.2)
            except (OSError, subprocess.TimeoutExpired):
                pass
            if isinstance(exc, subprocess.TimeoutExpired):
                raise Refused('CLIENT_TIMEOUT') from None
            if isinstance(exc, OSError):
                raise Refused('CLIENT_IO') from None
            raise
        finally:
            proc.stdout.close()
            proc.stderr.close()


def receipt(ok, checkpoint, category, roots=None, docker=None):
    need(checkpoint in CHECKPOINTS and category in CATEGORIES)
    return {'schema': 'recovery-custody-observation-v1', 'ok': ok,
            'checkpoint': checkpoint, 'category': category, 'roots': roots, 'docker': docker,
            'mutation': False, 'ownership': 'NOT_ADOPTED', 'sourceFilesystemOwnership': 'NOT_OBSERVED',
            'preCustody': 'NOT_PROVEN', 'historicalDurability': 'NOT_OBSERVED',
            'databaseIntegrity': 'NOT_OBSERVED', 'fullQualification': 'NOT_CLAIMED',
            'continuousWriterExclusion': 'NOT_PROVEN', 'recoveryAuthorized': False,
            'lockContents': 'NOT_OBSERVED', 'locksAdoptedOrRemoved': False,
                        'cliMetadataBoundary': 'FULL_RECORDS_TRUSTED_LOCAL_FILTERING',
                        'sensitiveFieldsEmittedToAgentReceipt': False}


def observe(client, fs, deadline, *, uid, gid, final_sources=lambda: None):
    checkpoint, roots = 'ROOTS', None
    try:
        tick(deadline)
        roots = {name: root_metadata(path, fs, deadline, uid, gid) for name, path in ROOTS}
        checkpoint = 'DAEMON_BEFORE'
        before = decode(client(INFO), 4096)
        string(before, cap=256)
        checkpoint = 'VOLUMES_BEFORE'
        v = volumes(client(VOLUME))
        checkpoint = 'CENSUS_BEFORE'
        ids = census(client(CENSUS))
        client.bind(ids)
        known_ids = tuple(i for i in ids if i in {v[0] for v in TARGETS.values()})
        checkpoint = 'KNOWN_BEFORE'
        known = rows(client(inspect_args(known_ids, True)), known_ids, True) if known_ids else {}
        checkpoint = 'BATCH_BEFORE'
        first = rows(client(inspect_args(ids)), ids) if ids else {}
        for identity, record in known.items():
            need({k: v for k, v in record.items() if k not in ('image', 'tmpfs')} == first[identity],
                 'OBSERVATION_DRIFT')
        checkpoint = 'CENSUS_AFTER'
        need(census(client(CENSUS)) == ids, 'OBSERVATION_DRIFT')
        checkpoint = 'BATCH_AFTER'
        second = rows(client(inspect_args(ids)), ids) if ids else {}
        need(first == second, 'OBSERVATION_DRIFT')
        checkpoint = 'KNOWN_AFTER'
        final_known = rows(client(inspect_args(known_ids, True)), known_ids, True) if known_ids else {}
        need(known == final_known, 'OBSERVATION_DRIFT')
        checkpoint = 'VOLUMES_AFTER'
        need(volumes(client(VOLUME)) == v, 'OBSERVATION_DRIFT')
        checkpoint = 'CENSUS_FINAL'
        need(census(client(CENSUS)) == ids, 'OBSERVATION_DRIFT')
        checkpoint = 'DAEMON_AFTER'
        need(decode(client(INFO), 4096) == before, 'OBSERVATION_DRIFT')
        checkpoint = 'CLASSIFY'
        result = classify(v, second, final_known)
        checkpoint = 'SOURCE_FINAL'
        final_sources()
        tick(deadline)
        return receipt(True, 'COMPLETE', 'NONE', roots, result)
    except Refused as exc:
        return receipt(False, checkpoint, exc.category, roots)
    except OSError:
        return receipt(False, checkpoint, 'HOST_IO', roots)
    except BaseException:
        return receipt(False, checkpoint, 'UNEXPECTED', roots)


def arguments(argv):
    need(len(argv) in (5, 6) and argv[0] == '--observe' and argv[1] == '--source-sha256' and
         argv[3] == '--test-sha256' and HEX.fullmatch(argv[2]) and HEX.fullmatch(argv[4]) and
         (len(argv) == 5 or argv[5] == CONSENT_FLAG), 'ARGUMENT_REFUSED')
    return len(argv) == 6


def source_gate(argv, deadline):
    need(arguments(argv), 'CLI_FULL_METADATA_CONSENT_REQUIRED')
    need(sys.flags.isolated and sys.dont_write_bytecode and Path(__file__).absolute() == REPO / SELF,
         'ARGUMENT_REFUSED')
    pins = ((REPO / SELF, argv[2]), (REPO / TEST, argv[4]))
    def verify():
        for path, pin in pins:
            need(public_hash(path, deadline, 512 * 1024) == pin, 'SOURCE_REFUSED')
        config_absent()
    verify()
    return verify


def main(argv):
    deadline, checkpoint = time.monotonic() + 90, 'ARGUMENTS'
    try:
        consent = arguments(argv)
        checkpoint = 'PRIVACY_CONSENT'
        need(consent, 'CLI_FULL_METADATA_CONSENT_REQUIRED')
        checkpoint = 'PUBLIC_SOURCES'
        verify = source_gate(argv, deadline)
        result = observe(DockerClient(deadline, allow_cli_full_metadata=consent), MetadataFS(), deadline,
                         uid=os.geteuid(), gid=os.getegid(), final_sources=verify)
    except Refused as exc:
        result = receipt(False, checkpoint, exc.category)
    except OSError:
        result = receipt(False, checkpoint, 'HOST_IO')
    except BaseException:
        result = receipt(False, checkpoint, 'UNEXPECTED')
    try:
        raw = canonical(result)
        need(len(raw) <= RECEIPT_CAP, 'OUTPUT_CAP')
    except BaseException:
        result = receipt(False, 'OUTPUT', 'OUTPUT_CAP')
        raw = canonical(result)
    try:
        packet = raw + b'\n'
        written = sys.stdout.buffer.write(packet)
        if type(written) is not int or written != len(packet):
            return OUTPUT_FAILURE
        sys.stdout.buffer.flush()
    except BaseException:
        # Never retry output or print an exception/second receipt to stderr.
        return OUTPUT_FAILURE
    return 0 if result['ok'] else 1


def entrypoint(argv):
    code = main(argv)
    if code == OUTPUT_FAILURE:
        # Buffered output may be partly pending after write/flush/BrokenPipeError.
        # Skip Python finalization, which could otherwise flush again and emit an
        # unraisable traceback with source paths. Only this process exits here.
        os._exit(OUTPUT_FAILURE)
    raise SystemExit(code)


if __name__ == '__main__':
    entrypoint(sys.argv[1:])
