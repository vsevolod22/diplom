#!/usr/bin/env python3
"""ONE read-only discovery, NOT qualification/adoption/recovery or retry authority.

Caller: isolated -I -B Python; exact source/test SHA256 arguments; wall fence75s.
Shared60s, each Docker client<=10s, <=8 fixed metadata clients, aggregate transport
cap per client65536 (listing4096), final closed JSON<=4096. No Env, State.Error,
logs, config dump, SQL, helper execution, resource mutation, locks or disk writes.
Only new IDs may be printed; names/labels/paths/commands/digests remain internal.
Public sources are read/hash-only; controller b34dcd63 is NEVER imported/executed.
Private metadata scope: .local-auth and ONE unambiguous label-derived directory;
no enumeration/content reads. Owner0700/no-follow/stable FD/path checks, <=10s.

Core Docker only, exact measured canonical binary/hash/full metadata checked
before EACH child; hashing is charged to shared60s, child execution remains<=10s.
No executable search or fallback. Explicit fixed socket; clean environment/empty context. CLI
config points at the public source directory after refusing an existing config.json
there (metadata only), so ambient ~/.docker/config/contexts are never selected.
No shell, automatic fallback, second listing, adoption or retry. Kernel I/O is not
universally preemptible; external75s supervisor remains necessary. Receipt flags
are observations of one fixed envelope, NOT the full controller qualifier. Env
is deliberately NOT_OBSERVED; materialized volume sources use original API mount
metadata, NOT a guessed Docker Desktop path or host filesystem volume probe.
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

SELF = 'server/deploy/trust/discover_preservation_holder.py'
TEST = 'server/deploy/trust/test_discover_preservation_holder.py'
CONTROLLER = 'server/deploy/trust/recreate_openrouter_key.py'
CONTROLLER_SHA256 = 'b34dcd63a77d06d997b4c6bf61a36bc7fbe67d8129aa12f444d055a1b9f50438'
REPO = Path(__file__).absolute().parents[3]
SOCKET = 'unix:///Users/vsevolod/.docker/run/docker.sock'
# Public host metadata/hash observation only; binary was NOT executed.
DOCKER_PATH = Path('/opt/homebrew/Cellar/docker/28.1.1/bin/docker')
DOCKER_SHA256 = '5cfddb229b6278953fdbb5016619e0f786ac8291969183fb28e3717a92f8bd52'
DOCKER_STAT = (16777233, 1321905, 0o100555, 1, 501, 80, 28011650,
               1744969487000000000, 1746429174027377498)
HEX = re.compile(r'[a-f0-9]{64}\Z')
LABEL = 'dip.key-preservation'
NAME = re.compile(r'/dip-key-snapshot-[0-9a-f]{32}\Z')
BACKUP = re.compile(r'key-preservation-[a-z0-9_]{8}\Z')
ORIGINALS = {
    'api': ('5cbe0936a5f09d663a77960749e687fbd41fbef52c8990b063362b9363d3e9ec', 'sha256:487c3909d3eeee08d60840a81c1adeb61c292aee0a31df17b2a8cf92f6dbb58c'),
    'worker': ('016c41e7b3eabcbb08903bbc3c54d657ed92c22813e47fa37d444cb448602b44', 'sha256:8748cbebba753603d79f320c2fb476c46ab676ce12e0aa08bee0021a3e14e57a'),
    'web': ('b84245ef672d172d5513971a57ea91469800846cdf6c59bedceb006b06caa4f4', 'sha256:1659b39c98d5183c91feae78a8d9eb1d4c6ee527d541c1e1d74dfe842adee8c0'),
    'egress': ('2850e2d03d0681482727f7b5d658961ef9ef2aa829b63473f36d8ed3c63f3d35', 'sha256:2b9eff3b381979c82bf42c310fcd7941805d42adeda67c8814143d6503490655'),
    'llm-egress': ('f64639115f21233277ac52db2bd5ceda495203511da87896ff996e8c1ce3a68a', 'sha256:3ccbd5a6c3348b7b1c99e23b29d9bdca485dfd48f690a408a119e06163a59a8d'),
}
BASELINE = frozenset(pair[0] for pair in ORIGINALS.values()) | frozenset((
    '2181bd8cdfe5861125de4fc1653872374bb4aba4ae0e016a1abe00b07825098b',
    '07dccf25778d563c7f685b6e420f2da8344e9d34103c138f0420001b7ba13d66',
    'a4a1ed5a6a6333ed708d89b2182ae0e8c21c799d6e558937db83f0b049cba27a',
    'b31343ed105e97b362fe82a5c1f76f62633ef2dda615e70efe23d735fe927781',
    'e360c9eba35fd283694ed96aae0ae5fe5419a2b11928bd5d622071952b25716b',
    '74d3605a84feb854d2b75928aa2583cdd8a056e61ba809d92f5e3e800f202472',
    '7e5db263579e35de9634557b55e0119b522a493ec7d5a2a2924b900df0c562fd',
    '0feffefa7d0403c9ebf235008bef00158ef65c555e1b744cdccb663e7bdab92f',
    'de13d3031dd20a9f4e865e9934e16586923340571c60d4141afbfd084b107e4e',
    'ef8f2161152d7d971f436e8fee958be230f99347ad40ca026ec925ce9c4bd943',
    'f9e853aa61ce3a87ff4f51a4a5bdc998f2ba18e226ee39b5cfc094cf2a11eeaa',
    'e1720a2f6ea267ca00a036a9c809b567ac94824ca8611b83fffba8b036bdc401',
))
VOLUMES = {'auth': 'dip-auth-stand_auth_accounts', 'data': 'dip-auth-stand_scan_ledger'}
SCRIPT = 'server/deploy/trust/sqlite_state_snapshot.mjs'
TARGET = '/app/server/api/.key-preservation.mjs'
HOLDER_CODE = 'setTimeout(()=>{},240000)'
TMPFS = {'/backup': 'rw,noexec,nosuid,uid=65532,gid=65532,mode=0700,size=2g',
         '/tmp': 'rw,noexec,nosuid,uid=65532,gid=65532,mode=0700,size=128m'}
STATE_FIELDS = ('"status":{{json .State.Status}},"running":{{json .State.Running}},'
                '"paused":{{json .State.Paused}},"restarting":{{json .State.Restarting}},'
                '"oom":{{json .State.OOMKilled}},"dead":{{json .State.Dead}},'
                '"exit":{{json .State.ExitCode}}')
OLD_FORMAT = '{"id":{{json .Id}},"image":{{json .Image}},' + STATE_FIELDS + '}'
API_FORMAT = OLD_FORMAT[:-1] + ',"mounts":{{json .Mounts}}}'
IMAGE_FORMAT = ('{"id":{{json .Id}},"labels":{{json .Config.Labels}},'
                '"cwd":{{json .Config.WorkingDir}},"volumes":{{json .Config.Volumes}}}')
# Explicit fields only: never .Config, .Config.Env, .State or .State.Error.
CANDIDATE_FORMAT = (
    '{"id":{{json .Id}},"image":{{json .Image}},"name":{{json .Name}},' + STATE_FIELDS +
    ',"configImage":{{json .Config.Image}},"labels":{{json .Config.Labels}},'
    '"user":{{json .Config.User}},"cwd":{{json .Config.WorkingDir}},'
    '"entry":{{json .Config.Entrypoint}},"cmd":{{json .Config.Cmd}},'
    '"health":{{json .Config.Healthcheck}},"volumes":{{json .Config.Volumes}},'
    '"stop":{{json .Config.StopTimeout}},"path":{{json .Path}},"args":{{json .Args}},'
    '"host":{"NetworkMode":{{json .HostConfig.NetworkMode}},'
    '"ReadonlyRootfs":{{json .HostConfig.ReadonlyRootfs}},"CapDrop":{{json .HostConfig.CapDrop}},'
    '"CapAdd":{{json .HostConfig.CapAdd}},"Privileged":{{json .HostConfig.Privileged}},'
    '"SecurityOpt":{{json .HostConfig.SecurityOpt}},"Devices":{{json .HostConfig.Devices}},'
    '"DeviceRequests":{{json .HostConfig.DeviceRequests}},"Binds":{{json .HostConfig.Binds}},'
    '"PortBindings":{{json .HostConfig.PortBindings}},"CgroupnsMode":{{json .HostConfig.CgroupnsMode}},'
    '"Memory":{{json .HostConfig.Memory}},"MemorySwap":{{json .HostConfig.MemorySwap}},'
    '"NanoCpus":{{json .HostConfig.NanoCpus}},"PidsLimit":{{json .HostConfig.PidsLimit}},'
    '"Tmpfs":{{json .HostConfig.Tmpfs}},"RestartPolicy":{{json .HostConfig.RestartPolicy}}},'
    '"declared":{{json .HostConfig.Mounts}},"mounts":{{json .Mounts}},'
    '"networkCount":{{len .NetworkSettings.Networks}},'
    '"networkNone":{{if and (eq (len .NetworkSettings.Networks) 1) '
    '(index .NetworkSettings.Networks "none")}}true{{else}}false{{end}}}')
LIST_ARGS = ('container', 'ls', '--all', '--no-trunc', '--filter', 'label=' + LABEL,
             '--filter', 'name=^/dip-key-snapshot-[0-9a-f]{32}$', '--format', '{{.ID}}')
CHECKPOINTS = frozenset(('ARGUMENTS', 'PUBLIC_SOURCES', 'LIST', 'IMAGE', 'ORIGINALS',
                         'CANDIDATES', 'DIRECTORY_METADATA', 'COMPLETE'))
CATEGORIES = frozenset(('PREDICATE_REFUSED', 'CLIENT_TIMEOUT', 'CLIENT_NONZERO',
                        'CLIENT_EXEC_IDENTITY', 'CLIENT_EXEC_NOT_FOUND', 'CLIENT_EXEC_DENIED',
                        'CLIENT_EXEC_OS_REFUSED', 'OUTPUT_CAP', 'DECODE_REFUSED', 'UNEXPECTED'))


class Refused(Exception):
    def __init__(self, category='PREDICATE_REFUSED'):
        self.category = category if category in CATEGORIES else 'UNEXPECTED'
        super().__init__('REFUSED')


def need(value):
    if not value:
        raise Refused()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result)
            result[key] = value
        return result
    def invalid(_):
        raise Refused('DECODE_REFUSED')
    try:
        need(type(raw) is bytes and 0 < len(raw) <= 65536)
        return json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs,
                          parse_float=invalid, parse_constant=invalid)
    except BaseException:
        raise Refused('DECODE_REFUSED') from None


def stamp(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_uid,
            value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def tick(deadline, clock=time.monotonic):
    if clock() >= deadline:
        raise Refused('CLIENT_TIMEOUT')


def chain(path, deadline, clock=time.monotonic):
    need(path.is_absolute() and '..' not in path.parts and str(path) == os.path.normpath(path))
    fds = []
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fds.append(fd)
        for part in path.parts[1:]:
            tick(deadline, clock)
            before = os.stat(part, dir_fd=fds[-1], follow_symlinks=False)
            need(stat.S_ISDIR(before.st_mode))
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1])
            fds.append(fd)
            need(stamp(before) == stamp(os.fstat(fd)))
        return fds
    except BaseException:
        for fd in reversed(fds):
            os.close(fd)
        raise


def public_hash(path, deadline, cap=65536):
    fds = chain(path.parent, deadline)
    fd = None
    try:
        before = os.stat(path.name, dir_fd=fds[-1], follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= cap)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fds[-1])
        need(stamp(before) == stamp(os.fstat(fd)))
        digest, total = hashlib.sha256(), 0
        while True:
            tick(deadline)
            block = os.read(fd, min(65536, cap + 1 - total))
            if not block:
                break
            total += len(block)
            need(total <= cap)
            digest.update(block)
        need(total == before.st_size and stamp(before) == stamp(os.fstat(fd)) and
             stamp(before) == stamp(os.stat(path.name, dir_fd=fds[-1], follow_symlinks=False)))
        return digest.hexdigest()
    finally:
        if fd is not None:
            os.close(fd)
        for item in reversed(fds):
            os.close(item)


def source_gate(repo, argv, deadline):
    need(len(argv) == 5 and argv[0] == '--discover-once' and argv[1] == '--source-sha256' and
         argv[3] == '--test-sha256' and HEX.fullmatch(argv[2]) and HEX.fullmatch(argv[4]))
    need(sys.flags.isolated and sys.dont_write_bytecode)
    need(Path(__file__).absolute() == repo / SELF)
    need(public_hash(repo / SELF, deadline) == argv[2] and public_hash(repo / TEST, deadline) == argv[4])
    need(public_hash(repo / CONTROLLER, deadline, 512 * 1024) == CONTROLLER_SHA256)
    # Core clients must not read the ambient private Docker CLI config/context.
    try:
        os.stat(repo / 'server/deploy/trust/config.json', follow_symlinks=False)
    except FileNotFoundError:
        return
    raise Refused()


def verify_executable(deadline):
    """Exact canonical public binary; no execution, search or PATH fallback."""
    try:
        tick(deadline)
        need(stamp(DOCKER_PATH.lstat()) == DOCKER_STAT)
        need(public_hash(DOCKER_PATH, deadline, 128 * 1024**2) == DOCKER_SHA256)
        need(stamp(DOCKER_PATH.lstat()) == DOCKER_STAT)
        tick(deadline)
    except FileNotFoundError:
        raise Refused('CLIENT_EXEC_NOT_FOUND') from None
    except PermissionError:
        raise Refused('CLIENT_EXEC_DENIED') from None
    except OSError:
        raise Refused('CLIENT_EXEC_OS_REFUSED') from None
    except Refused as exc:
        if type(exc) is Refused and exc.category == 'CLIENT_TIMEOUT':
            raise
        raise Refused('CLIENT_EXEC_IDENTITY') from None


class Client:
    def __init__(self, repo, deadline):
        self.repo, self.deadline, self.calls = repo, deadline, 0
        self.env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/var/empty',
                    'DOCKER_HOST': SOCKET, 'DOCKER_CONTEXT': '',
                    'DOCKER_CONFIG': str(repo / 'server/deploy/trust')}

    def __call__(self, args, cap=65536):
        tick(self.deadline)
        need(self.calls < 8)
        self.calls += 1
        verify_executable(self.deadline)
        until = min(self.deadline, time.monotonic() + 10)
        try:
            proc = subprocess.Popen((str(DOCKER_PATH), '--host', SOCKET, *args), cwd=self.repo, env=self.env,
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    start_new_session=True)
        except FileNotFoundError:
            raise Refused('CLIENT_EXEC_NOT_FOUND') from None
        except PermissionError:
            raise Refused('CLIENT_EXEC_DENIED') from None
        except OSError:
            raise Refused('CLIENT_EXEC_OS_REFUSED') from None
        output, total, failed = bytearray(), 0, False
        try:
            with selectors.DefaultSelector() as streams:
                streams.register(proc.stdout, selectors.EVENT_READ, True)
                streams.register(proc.stderr, selectors.EVENT_READ, False)
                while streams.get_map():
                    remaining = max(0.0, until - time.monotonic())
                    if remaining == 0:
                        raise Refused('CLIENT_TIMEOUT')
                    for entry, _ in streams.select(min(0.05, remaining)):
                        block = os.read(entry.fileobj.fileno(), 8192)
                        if not block:
                            streams.unregister(entry.fileobj)
                        else:
                            total += len(block)
                            if total > cap:
                                raise Refused('OUTPUT_CAP')
                            if entry.data:
                                output.extend(block)
                remaining = max(0.0, until - time.monotonic())
                if remaining == 0:
                    raise Refused('CLIENT_TIMEOUT')
                if proc.wait(timeout=remaining) != 0:
                    raise Refused('CLIENT_NONZERO')
            return bytes(output)
        except BaseException as exc:
            failed = True
            # Preserve the FIRST failure: cleanup must not replace its category.
            try:
                os.killpg(proc.pid, signal.SIGKILL)  # CLIENT only, never a container operation.
            except BaseException:
                pass
            try:
                proc.wait(timeout=max(0.001, min(0.2, self.deadline - time.monotonic())))
            except BaseException:
                pass
            if isinstance(exc, subprocess.TimeoutExpired):
                raise Refused('CLIENT_TIMEOUT') from None
            raise
        finally:
            close_failed = False
            for stream in (proc.stdout, proc.stderr):
                try:
                    stream.close()
                except BaseException:
                    close_failed = True
            if close_failed and not failed:
                raise Refused('UNEXPECTED') from None


def candidate_ids(raw):
    need(type(raw) is bytes and len(raw) <= 4096)
    need(raw == b'' or raw.endswith(b'\n'))
    try:
        lines = [] if raw == b'' else raw[:-1].decode('ascii', 'strict').split('\n')
    except UnicodeError:
        raise Refused() from None
    need(len(lines) <= 2 and len(set(lines)) == len(lines) and
         all(HEX.fullmatch(item) and item not in BASELINE for item in lines))
    return tuple(sorted(lines))


def state(record):
    status = record.get('status')
    need(type(status) is str and all(type(record.get(k)) is bool for k in
         ('running', 'paused', 'restarting', 'oom', 'dead')) and type(record.get('exit')) is int)
    allowed = {'created', 'running', 'paused', 'restarting', 'removing', 'exited', 'dead'}
    return {'state': status.upper() if status in allowed else 'OTHER',
            'running': record['running'], 'paused': record['paused'],
            'restarting': record['restarting'], 'oom': record['oom'], 'dead': record['dead'],
            'exit': 'ZERO' if record['exit'] == 0 else 'NONZERO'}


def declared_mounts(record, repo):
    mounts = record.get('declared')
    if type(mounts) is not list or len(mounts) != 3 or any(type(m) is not dict for m in mounts):
        return False
    by_target = {m.get('Target'): m for m in mounts if type(m.get('Target')) is str}
    if set(by_target) != {'/source/auth', '/source/data', TARGET}:
        return False
    for key, volume in VOLUMES.items():
        m = by_target['/source/' + key]
        if not (set(m) <= {'Type', 'Source', 'Target', 'ReadOnly', 'VolumeOptions'} and
                m.get('Type') == 'volume' and m.get('Source') == volume and
                ('ReadOnly' not in m or m['ReadOnly'] is False) and
                m.get('VolumeOptions') in (None, {})):
            return False
    m = by_target[TARGET]
    options = m.get('BindOptions')
    return (set(m) <= {'Type', 'Source', 'Target', 'ReadOnly', 'BindOptions'} and
            m.get('Type') == 'bind' and m.get('Source') == str(repo / SCRIPT) and m.get('ReadOnly') is True and
            (options is None or type(options) is dict and
             set(options) <= {'Propagation', 'NonRecursive', 'CreateMountpoint',
                              'ReadOnlyNonRecursive', 'ReadOnlyForceRecursive'} and
             options.get('Propagation', '') in ('', 'rprivate') and
             all(v is False for k, v in options.items() if k != 'Propagation')))


def volume_baseline(api):
    result = {}
    mounts = api.get('mounts')
    if type(mounts) is not list or len(mounts) > 32:
        return result
    for key, volume in VOLUMES.items():
        matches = [m for m in mounts if type(m) is dict and m.get('Type') == 'volume' and
                   m.get('Name') == volume and m.get('Destination') == '/' + key and
                   type(m.get('Source')) is str and m['Source'].startswith('/') and m.get('RW') is True]
        if len(matches) != 1:
            return {}
        result[key] = matches[0]['Source']
    return result


def materialized_mounts(record, repo, sources):
    mounts = record.get('mounts')
    if set(sources) != set(VOLUMES) or type(mounts) is not list or not 3 <= len(mounts) <= 5:
        return False
    if any(type(m) is not dict or type(m.get('Destination')) is not str or type(m.get('RW')) is not bool
           for m in mounts) or len({m['Destination'] for m in mounts}) != len(mounts):
        return False
    actual = [(m.get('Type'), m.get('Name', ''), m.get('Source', ''), m['Destination'], m['RW'])
              for m in mounts if m.get('Type') != 'tmpfs']
    expected = [('volume', name, sources[key], '/source/' + key, True) for key, name in VOLUMES.items()]
    expected.append(('bind', '', str(repo / SCRIPT), TARGET, False))
    return (len(actual) == len(expected) and all(item in actual for item in expected) and
            all(m['Destination'] in TMPFS and m['RW'] is True for m in mounts if m.get('Type') == 'tmpfs'))


def groups(record, image, repo, sources):
    host = record.get('host')
    need(type(host) is dict)
    label = record.get('labels', {}).get(LABEL) if type(record.get('labels')) is dict else None
    valid_label = type(label) is str and BACKUP.fullmatch(label) is not None
    base = image['labels'] if image['labels'] is not None else {}
    labels = (type(base) is dict and LABEL not in base and valid_label and
              canonical(record['labels']) == canonical(dict(base, **{LABEL: label})))
    command = (record.get('image') == ORIGINALS['api'][1] == record.get('configImage') and
               type(record.get('name')) is str and NAME.fullmatch(record['name']) is not None and labels and
               record.get('user') == '65532:65532' and record.get('cwd') == image['cwd'] and
               record.get('entry') == ['node'] and record.get('cmd') == ['-e', HOLDER_CODE] and
               record.get('path') == 'node' and record.get('args') == ['-e', HOLDER_CODE])
    security = (host.get('NetworkMode') == 'none' and host.get('ReadonlyRootfs') is True and
                host.get('CapDrop') == ['ALL'] and not host.get('CapAdd') and host.get('Privileged') is False and
                host.get('SecurityOpt') == ['no-new-privileges:true'] and host.get('CgroupnsMode') == 'private' and
                not any(host.get(k) for k in ('Devices', 'DeviceRequests', 'Binds', 'PortBindings')) and
                canonical(record.get('health')) == canonical({'Test': ['NONE']}) and
                record.get('volumes') in (None, {}))
    resources = (all(type(host.get(k)) is int and host[k] == v for k, v in
                 {'Memory': 2 * 1024**3, 'MemorySwap': 2 * 1024**3, 'NanoCpus': 10**9, 'PidsLimit': 64}.items()) and
                 canonical(host.get('Tmpfs')) == canonical(TMPFS) and
                 canonical(host.get('RestartPolicy')) == canonical({'Name': 'no', 'MaximumRetryCount': 0}) and
                 type(record.get('stop')) is int and record['stop'] == 5)
    return {'identityImageCommand': bool(command), 'labelBaseline': bool(labels),
            'securityHealth': bool(security), 'resources': bool(resources),
            'networkNoneMaterialized': record.get('networkNone') is True and record.get('networkCount') == 1,
            'createdNotMaterialized': record['status'] == 'created' and record['running'] is False and
                                     record.get('networkCount') == 0 and record.get('mounts') == [],
            'mountsHostDeclared': declared_mounts(record, repo),
            'mountsMaterialized': materialized_mounts(record, repo, sources),
            'runtimeStateClean': not any(record[k] for k in ('paused', 'restarting', 'oom', 'dead'))}


def directory_metadata(repo, label, deadline, clock=time.monotonic):
    """Never list/read .local-auth or the selected child. No lock/recovery probe."""
    need(type(label) is str and BACKUP.fullmatch(label))
    until = min(deadline, clock() + 10)
    fds = chain(repo, until, clock)
    opened = []
    try:
        for parent, name in ((fds[-1], '.local-auth'), (None, label)):
            tick(until, clock)
            parent = opened[-1][2] if parent is None else parent
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            need(stat.S_ISDIR(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o700 and
                 before.st_uid == os.getuid())
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            opened.append((parent, name, fd, stamp(before)))
            need(stamp(os.fstat(fd)) == stamp(before))
        for parent, name, fd, saved in opened:
            tick(until, clock)
            need(stamp(os.fstat(fd)) == saved == stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)))
        tick(until, clock)
        return True
    finally:
        for _, _, fd, _ in reversed(opened):
            os.close(fd)
        for fd in reversed(fds):
            os.close(fd)


class Discovery:
    def __init__(self, repo, client, deadline, metadata=directory_metadata):
        self.repo, self.client, self.deadline, self.metadata = repo, client, deadline, metadata
        self.checkpoint = 'LIST'
        self.used = False

    def run(self):
        need(not self.used)
        self.used = True
        tick(self.deadline)
        ids = candidate_ids(self.client(LIST_ARGS, cap=4096))
        self.checkpoint = 'IMAGE'
        image = decode(self.client(('image', 'inspect', '--format', IMAGE_FORMAT, ORIGINALS['api'][1])))
        need(type(image) is dict and set(image) == {'id', 'labels', 'cwd', 'volumes'} and
             image['id'] == ORIGINALS['api'][1] and type(image['cwd']) is str and
             (image['labels'] is None or type(image['labels']) is dict))
        self.checkpoint = 'ORIGINALS'
        roles, api = {}, None
        for role, (cid, expected_image) in ORIGINALS.items():
            fmt = API_FORMAT if role == 'api' else OLD_FORMAT
            record = decode(self.client(('container', 'inspect', '--format', fmt, cid)))
            need(type(record) is dict and record.get('id') == cid)
            roles[role] = dict(state(record), imageMatch=record.get('image') == expected_image)
            if role == 'api' and roles[role]['imageMatch']:
                api = record
        sources = volume_baseline(api or {})
        self.checkpoint = 'CANDIDATES'
        records = []
        if ids:
            raw = self.client(('container', 'inspect', '--format', CANDIDATE_FORMAT, *ids))
            need(type(raw) is bytes and len(raw) <= 65536)
            lines = raw.splitlines()
            need(len(lines) == len(ids))
            records = [decode(line) for line in lines]
            need(all(type(r) is dict for r in records) and
                 sorted(r.get('id', '') for r in records) == list(ids))
        candidates, labels = [], set()
        for record in records:
            flags = groups(record, image, self.repo, sources)
            candidates.append(dict(id=record['id'], **state(record), groups=flags))
            label = record.get('labels', {}).get(LABEL) if type(record.get('labels')) is dict else None
            if type(label) is str and BACKUP.fullmatch(label):
                labels.add(label)
        self.checkpoint = 'DIRECTORY_METADATA'
        metadata = 'NOT_OBSERVED'
        if len(labels) > 1:
            metadata = 'AMBIGUOUS_NOT_OBSERVED'
        elif len(labels) == 1:
            try:
                metadata = 'MATCH' if self.metadata(self.repo, next(iter(labels)), self.deadline) is True else 'REFUSED'
            except BaseException:
                metadata = 'REFUSED'
        tick(self.deadline)
        self.checkpoint = 'COMPLETE'
        return {'code': 'DISCOVERED_NOT_ADOPTED', 'ok': True, 'fullQualification': 'NOT_CLAIMED',
                'Env': 'NOT_OBSERVED', 'roles': roles, 'candidates': candidates,
                'privateDirectoryMetadata': metadata, 'volumeBaselineObserved': bool(sources)}


def receipt(value):
    raw = canonical(value) + b'\n'
    need(len(raw) <= 4096)
    return raw


def main(argv=None):
    deadline = time.monotonic() + 60
    checkpoint, discovery = 'ARGUMENTS', None
    try:
        args = sys.argv[1:] if argv is None else argv
        need(len(args) == 5 and args[0] == '--discover-once' and args[1] == '--source-sha256' and
             args[3] == '--test-sha256' and HEX.fullmatch(args[2]) and HEX.fullmatch(args[4]))
        checkpoint = 'PUBLIC_SOURCES'
        source_gate(REPO, args, deadline)
        discovery = Discovery(REPO, Client(REPO, deadline), deadline)
        result = discovery.run()
        output = receipt(result)
        code = 0
    except BaseException as exc:
        checkpoint = discovery.checkpoint if discovery is not None else checkpoint
        category = exc.category if type(exc) is Refused else 'UNEXPECTED'
        output = receipt({'code': 'REFUSED', 'ok': False, 'checkpoint': checkpoint,
                          'category': category, 'fullQualification': 'NOT_CLAIMED', 'Env': 'NOT_OBSERVED'})
        code = 1
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()
    return code


if __name__ == '__main__':
    try:
        status = main()
    except BaseException:
        os._exit(1)  # Output failure must not produce an exception/operand traceback.
    raise SystemExit(status)
