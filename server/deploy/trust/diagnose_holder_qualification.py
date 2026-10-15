#!/usr/bin/env python3
"""ONE bounded read-only holder metadata packet; NOT qualification or adoption.

New review/authority required. Isolated -I -B; shared60s, clients<=10s, caller75s.
ONE exact namespace listing, <=3 IDs (FOURTH/duplicate/malformed => no more query),
then ONE fixed OLD API image-default projection, ONE two-volume projection, and
<=3 exact-ID projections. <=6 clients, combined streams<=65536/client (list4096),
receipt<=4096. No polling/retry, private host metadata/content, journals, backup
locator, actors, app/helper/SQL, HTTP/provider, logs, mutation or resource cleanup.
Config.Env is privately compared EXACTLY to OLD image Config.Env, including list
order/null. ONLY equality leaves memory: no names, values, lengths or hashes.
Public source/hash and executable metadata are the only host files examined.

Reuse ONLY Client/decode from the captured frozen transport; NEVER its stale
source_gate, discovery/private metadata functions, or any controller execution.
Controller/test digest arguments must be finalized by author397 and bound in the
independently reviewed literal. Both are read/hash-only; no dynamic acceptance or
repinning. The profile below is a static observable projection of qualify_holder
for the stopped reconciliation migration profile, NOT a replacement qualifier.
All groups are evaluated independently: true=MATCH, false=MISMATCH, null=malformed
or missing prerequisite. Existing private journal/intent/name/backup bindings are
explicitly NOT_OBSERVED, never synthesized from a label. They can still refuse a
real qualifier even if every observable group matches. No sole-cause claim.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import types

REPO = Path('/Users/vsevolod/Documents/startup/diplom')
SELF = 'server/deploy/trust/diagnose_holder_qualification.py'
TEST = 'server/deploy/trust/test_diagnose_holder_qualification.py'
LIBRARY = 'server/deploy/trust/discover_preservation_holder.py'
LIBRARY_PINS = {
    LIBRARY: '4afb0bc484d34aca428fee956bd939d7b322727285eef0f721425849bb32a1f4',
    'server/deploy/trust/test_discover_preservation_holder.py':
        'cc1a168804cb9a07f9c53724730bfbbaae7596c44c88743b0dc169f26a1bf312',
}
CONTROLLER = 'server/deploy/trust/recreate_openrouter_key.py'
CONTROLLER_TEST = 'server/deploy/trust/test_recreate_openrouter_key.py'
IMAGE = 'sha256:487c3909d3eeee08d60840a81c1adeb61c292aee0a31df17b2a8cf92f6dbb58c'
INITIAL = 'd9433f7ed0fc504a3521574668f15b7b3a0e8d283d61b9aa33d1e97187708a4f'
LABEL = 'dip.key-preservation'
HELPER = '/app/server/api/.key-preservation.mjs'
HELPER_SOURCE = str(REPO / 'server/deploy/trust/sqlite_state_snapshot.mjs')
CODE = 'setTimeout(()=>{},240000)'
VOLUMES = {'AUTH': 'dip-auth-stand_auth_accounts', 'DATA': 'dip-auth-stand_scan_ledger'}
TMPFS = {'/backup': 'rw,noexec,nosuid,uid=65532,gid=65532,mode=0700,size=2g',
         '/tmp': 'rw,noexec,nosuid,uid=65532,gid=65532,mode=0700,size=128m'}
HEX = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'/dip-key-snapshot-[0-9a-f]{32}\Z')
BACKUP = re.compile(r'key-preservation-[a-z0-9_]{8}\Z')
LIST_ARGS = ('container', 'ls', '--all', '--no-trunc', '--filter', 'label=' + LABEL,
             '--filter', 'name=^/dip-key-snapshot-[0-9a-f]{32}$', '--format', '{{.ID}}')
IMAGE_FORMAT = ('{"Id":{{json .Id}},"Config":{"Env":{{json .Config.Env}},'
                '"Labels":{{json .Config.Labels}},"WorkingDir":{{json .Config.WorkingDir}}}}')
VOLUME_FORMAT = ('{"Name":{{json .Name}},"Mountpoint":{{json .Mountpoint}},'
                 '"Driver":{{json .Driver}},"Scope":{{json .Scope}},'
                 '"Options":{{json .Options}},"Labels":{{json .Labels}}}')
CONFIG_FIELDS = ('Image', 'Labels', 'User', 'Env', 'WorkingDir', 'Entrypoint', 'Cmd',
                 'Healthcheck', 'Volumes', 'StopTimeout')
HOST_FIELDS = ('NetworkMode', 'ReadonlyRootfs', 'CapDrop', 'CapAdd', 'Privileged', 'SecurityOpt',
               'Devices', 'DeviceRequests', 'Binds', 'PortBindings', 'CgroupnsMode',
               'Memory', 'MemorySwap', 'NanoCpus', 'PidsLimit', 'Tmpfs', 'RestartPolicy', 'Mounts')
STATE_FIELDS = ('Status', 'Running', 'Paused', 'Restarting', 'OOMKilled', 'Dead', 'ExitCode')

def projection(fields, prefix):
    return ','.join('"' + field + '":{{json .' + prefix + field + '}}' for field in fields)

# Inspect endpoint objects may be empty; only cardinality and the map KEY matter.
NETWORK_NONE_TEMPLATE = ('{{if eq (len .NetworkSettings.Networks) 1}}'
    '{{range $networkName, $endpoint := .NetworkSettings.Networks}}'
    '{{if eq $networkName "none"}}true{{else}}false{{end}}{{end}}'
    '{{else}}false{{end}}')
CANDIDATE_FORMAT = ('{' + projection(('Id', 'Name', 'Image', 'Path', 'Args', 'Mounts'), '') +
    ',"Config":{' + projection(CONFIG_FIELDS, 'Config.') + '},"HostConfig":{' +
    projection(HOST_FIELDS, 'HostConfig.') + '},"State":{' + projection(STATE_FIELDS, 'State.') + '},'
    '"NetworkNone":' + NETWORK_NONE_TEMPLATE + '}')
GROUPS = ('ID_IMAGE', 'LABELS', 'UID', 'ENV', 'CWD', 'ARGV', 'HEALTH', 'VOLUMES',
    'NETMODE', 'ROOT_RO', 'CAPS', 'PRIVILEGE', 'SECOPT', 'NO_DEVICES', 'NO_BINDS_PORTS', 'CGROUPNS',
    'MEMORY', 'SWAP', 'CPU', 'PIDS', 'TMPFS', 'RESTART_STOP', 'STATE_CLEAR', 'RUN_FALSE', 'RUN_TRUE',
    'UNPAUSED', 'NET_NONE', 'DECL_SET', 'DECL_AUTH', 'DECL_DATA', 'DECL_BIND', 'BIND_OPTIONS',
    'ACTUAL_SET', 'ACTUAL_AUTH', 'ACTUAL_DATA', 'ACTUAL_BIND', 'ACTUAL_TMPFS')
CATEGORIES = frozenset(('PREDICATE_REFUSED', 'CLIENT_TIMEOUT', 'CLIENT_NONZERO', 'CLIENT_EXEC_IDENTITY',
    'CLIENT_EXEC_NOT_FOUND', 'CLIENT_EXEC_DENIED', 'CLIENT_EXEC_OS_REFUSED', 'OUTPUT_CAP',
    'DECODE_REFUSED', 'IO_REFUSED', 'UNEXPECTED'))
CHECKPOINTS = frozenset(('ARGUMENTS', 'PUBLIC_SOURCES', 'LIST', 'IMAGE_DEFAULTS', 'VOLUME_BASELINE',
                        'CANDIDATE_METADATA', 'CLASSIFY', 'SOURCE_FINAL', 'COMPLETE'))

class Refused(Exception):
    def __init__(self, category='PREDICATE_REFUSED'):
        self.category = category if category in CATEGORIES else 'UNEXPECTED'
        super().__init__()

def need(value):
    if not value:
        raise Refused()

def tick(deadline):
    if time.monotonic() >= deadline:
        raise Refused('CLIENT_TIMEOUT')

def stamp(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_uid, st.st_gid,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)

def public_bytes(path, deadline, cap=65536):
    # Source directories/files only. Never resolve/read a private state path.
    import stat
    fds, fd = [], None
    try:
        fds.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        for part in path.parent.parts[1:]:
            tick(deadline)
            before = os.stat(part, dir_fd=fds[-1], follow_symlinks=False)
            need(stat.S_ISDIR(before.st_mode))
            fds.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1]))
            need(stamp(before) == stamp(os.fstat(fds[-1])))
        before = os.stat(path.name, dir_fd=fds[-1], follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid() and
             not before.st_mode & 0o022 and 0 < before.st_size <= cap)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fds[-1])
        need(stamp(before) == stamp(os.fstat(fd)))
        data = bytearray()
        while True:
            tick(deadline)
            block = os.read(fd, min(65536, cap + 1 - len(data)))
            if not block:
                break
            data.extend(block)
            need(len(data) <= cap)
        need(len(data) == before.st_size and stamp(before) == stamp(os.fstat(fd)) and
             stamp(before) == stamp(os.stat(path.name, dir_fd=fds[-1], follow_symlinks=False)))
        return bytes(data)
    finally:
        if fd is not None:
            os.close(fd)
        for item in reversed(fds):
            os.close(item)

def load_transport(repo, argv, deadline):
    need(len(argv) == 9 and argv[0] == '--diagnose-holder-qualification-once' and
         argv[1::2] == ['--source-sha256', '--test-sha256', '--controller-sha256', '--controller-test-sha256'] and
         all(HEX.fullmatch(v) for v in argv[2::2]))
    need(sys.flags.isolated and sys.dont_write_bytecode and repo == REPO and
         Path(__file__).absolute() == repo / SELF)
    pins = {SELF: argv[2], TEST: argv[4], CONTROLLER: argv[6], CONTROLLER_TEST: argv[8], **LIBRARY_PINS}
    captured = None
    for relative, expected in pins.items():
        raw = public_bytes(repo / relative, deadline, 512 * 1024 if relative in (CONTROLLER, CONTROLLER_TEST) else 65536)
        need(hashlib.sha256(raw).hexdigest() == expected)
        if relative == LIBRARY:
            captured = raw
    # Frozen Client uses this OWN public directory as Docker config; refuse presence,
    # including symlinks, without reading config or ambient ~/.docker configuration.
    try:
        os.stat(repo / 'server/deploy/trust/config.json', follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise Refused()
    module = types.ModuleType('_holder_qualification_transport')
    module.__file__ = str(repo / LIBRARY)
    exec(compile(captured, module.__file__, 'exec'), module.__dict__)
    return module, pins

def ids_from_listing(raw):
    need(type(raw) is bytes and len(raw) <= 4096 and (raw == b'' or raw.endswith(b'\n')))
    try:
        ids = raw.decode('ascii').splitlines()
    except UnicodeError:
        raise Refused() from None
    need(len(ids) <= 3 and len(ids) == len(set(ids)) and all(HEX.fullmatch(i) for i in ids))
    return tuple(ids)

def rows(raw, module, maximum):
    need(type(raw) is bytes and len(raw) <= 65536)
    lines = raw.splitlines()
    need(len(lines) <= maximum and all(lines))
    return [module.decode(line) for line in lines]

def volume_baseline(records):
    try:
        need(type(records) is list and len(records) == 2 and all(type(v) is dict for v in records))
        need({v['Name'] for v in records} == set(VOLUMES.values()))
        result = {}
        for v in records:
            need(v['Driver'] == 'local' and v['Scope'] == 'local' and not v['Options'] and
                 type(v['Labels']) is dict and v['Labels'].get('com.docker.compose.project') == 'dip-auth-stand' and
                 type(v['Mountpoint']) is str and v['Mountpoint'].startswith('/') and
                 len(v['Mountpoint'].encode()) <= 4096 and '\0' not in v['Mountpoint'])
            result[v['Name']] = v['Mountpoint']
        need(len(set(result.values())) == 2)
        return result
    except (Refused, KeyError, TypeError, ValueError):
        return None

def env_value(value):
    need(value is None or type(value) is list and len(value) <= 512 and
         all(type(v) is str and len(v.encode('utf-8')) <= 8192 for v in value))
    return value

def compare_groups(record, image, baseline, identity):
    """Observable predicates only; each evaluated independently, no private operands."""
    result = dict.fromkeys(GROUPS)
    def group(name, operation):
        try:
            value = operation()
            need(type(value) is bool)
            result[name] = value
        except (Refused, KeyError, TypeError, ValueError, AttributeError, IndexError):
            result[name] = None
    def config():
        value = record['Config']
        need(type(value) is dict)
        return value
    def host():
        value = record['HostConfig']
        need(type(value) is dict)
        return value
    def state():
        value = record['State']
        need(type(value) is dict)
        return value
    def defaults():
        need(type(image) is dict and image['Id'] == IMAGE and type(image['Config']) is dict)
        return image['Config']
    def labels():
        actual, original = config()['Labels'], defaults()['Labels']
        need(type(actual) is dict and (original is None or type(original) is dict))
        own = actual.get(LABEL)
        return type(own) is str and BACKUP.fullmatch(own) is not None and actual == dict(original or {}, **{LABEL: own})
    def declared():
        value = host()['Mounts']
        need(type(value) is list and len(value) <= 8 and all(type(v) is dict for v in value))
        return value
    def one_decl(target):
        values = [v for v in declared() if v.get('Target') == target]
        need(len(values) == 1)
        return values[0]
    def actual():
        value = record['Mounts']
        need(type(value) is list and len(value) <= 8 and all(type(v) is dict for v in value))
        return value
    def one_actual(target):
        values = [v for v in actual() if v.get('Destination') == target]
        need(len(values) == 1)
        return values[0]
    def volume_decl(slot):
        v = one_decl('/source/' + slot.lower())
        return (set(v) <= {'Type', 'Source', 'Target', 'ReadOnly', 'VolumeOptions'} and
                v['Type'] == 'volume' and v['Source'] == VOLUMES[slot] and
                ('ReadOnly' not in v or v['ReadOnly'] is False) and v.get('VolumeOptions') in (None, {}))
    def bind_decl():
        v = one_decl(HELPER)
        return (set(v) <= {'Type', 'Source', 'Target', 'ReadOnly', 'BindOptions'} and
                v['Type'] == 'bind' and v['ReadOnly'] is True and
                v['Source'] in (HELPER_SOURCE, '/host_mnt' + HELPER_SOURCE))
    def bind_options():
        value = one_decl(HELPER).get('BindOptions')
        return (value is None or type(value) is dict and
                set(value) <= {'Propagation', 'NonRecursive', 'CreateMountpoint', 'ReadOnlyNonRecursive', 'ReadOnlyForceRecursive'} and
                value.get('Propagation', '') in ('', 'rprivate') and
                all(v is False for k, v in value.items() if k != 'Propagation'))
    def volume_actual(slot):
        need(baseline is not None)
        v = one_actual('/source/' + slot.lower())
        return (v['Type'] == 'volume' and v.get('Name', '') == VOLUMES[slot] and
                v['Source'] == baseline[VOLUMES[slot]] and v['RW'] is True)
    def bind_actual():
        v, declaration = one_actual(HELPER), one_decl(HELPER)
        return (v['Type'] == 'bind' and v.get('Name', '') == '' and v['Source'] == declaration['Source'] and
                declaration['Source'] in (HELPER_SOURCE, '/host_mnt' + HELPER_SOURCE) and v['RW'] is False)
    group('ID_IMAGE', lambda: record['Id'] == identity and type(record['Name']) is str and
          NAME.fullmatch(record['Name']) is not None and record['Image'] == IMAGE and config()['Image'] == IMAGE)
    group('LABELS', labels)
    group('UID', lambda: config()['User'] == '65532:65532')
    group('ENV', lambda: env_value(config()['Env']) == env_value(defaults()['Env']))
    group('CWD', lambda: config()['WorkingDir'] == defaults()['WorkingDir'])
    group('ARGV', lambda: config()['Entrypoint'] == ['node'] and config()['Cmd'] == ['-e', CODE] and
          record['Path'] == 'node' and record['Args'] == ['-e', CODE])
    group('HEALTH', lambda: config()['Healthcheck'] == {'Test': ['NONE']})
    group('VOLUMES', lambda: not config()['Volumes'])
    group('NETMODE', lambda: host()['NetworkMode'] == 'none')
    group('ROOT_RO', lambda: host()['ReadonlyRootfs'] is True)
    group('CAPS', lambda: host()['CapDrop'] == ['ALL'] and not host()['CapAdd'])
    group('PRIVILEGE', lambda: host()['Privileged'] is False)
    group('SECOPT', lambda: host()['SecurityOpt'] == ['no-new-privileges:true'])
    group('NO_DEVICES', lambda: not host()['Devices'] and not host()['DeviceRequests'])
    group('NO_BINDS_PORTS', lambda: not host()['Binds'] and not host()['PortBindings'])
    group('CGROUPNS', lambda: host()['CgroupnsMode'] == 'private')
    for name, field, expected in (('MEMORY', 'Memory', 2 * 1024**3), ('SWAP', 'MemorySwap', 2 * 1024**3),
                                  ('CPU', 'NanoCpus', 10**9), ('PIDS', 'PidsLimit', 64)):
        group(name, lambda f=field, e=expected: type(host()[f]) is int and host()[f] == e)
    group('TMPFS', lambda: host()['Tmpfs'] == TMPFS)
    group('RESTART_STOP', lambda: host()['RestartPolicy'] == {'Name': 'no', 'MaximumRetryCount': 0} and
          type(config()['StopTimeout']) is int and config()['StopTimeout'] == 5)
    group('STATE_CLEAR', lambda: not state()['Restarting'] and not state()['OOMKilled'])
    group('RUN_FALSE', lambda: type(state()['Running']) is bool and state()['Running'] is False)
    group('RUN_TRUE', lambda: type(state()['Running']) is bool and state()['Running'] is True)
    group('UNPAUSED', lambda: not state()['Paused'])
    group('NET_NONE', lambda: record['NetworkNone'] is True)
    group('DECL_SET', lambda: len(declared()) == 3 and
          {v.get('Target') for v in declared()} == {'/source/auth', '/source/data', HELPER})
    group('DECL_AUTH', lambda: volume_decl('AUTH'))
    group('DECL_DATA', lambda: volume_decl('DATA'))
    group('DECL_BIND', bind_decl)
    group('BIND_OPTIONS', bind_options)
    group('ACTUAL_SET', lambda: len([v for v in actual() if v['Type'] != 'tmpfs']) == 3 and
          {v['Destination'] for v in actual() if v['Type'] != 'tmpfs'} == {'/source/auth', '/source/data', HELPER})
    group('ACTUAL_AUTH', lambda: volume_actual('AUTH'))
    group('ACTUAL_DATA', lambda: volume_actual('DATA'))
    group('ACTUAL_BIND', bind_actual)
    group('ACTUAL_TMPFS', lambda: len([v for v in actual() if v['Type'] == 'tmpfs']) ==
          len({v['Destination'] for v in actual() if v['Type'] == 'tmpfs'}) and
          all(v['Destination'] in TMPFS and v['RW'] is True for v in actual() if v['Type'] == 'tmpfs'))
    status = record.get('State', {}).get('Status') if type(record.get('State')) is dict else None
    return {'id': identity, 'state': status.upper() if status in
            ('created', 'running', 'paused', 'restarting', 'removing', 'exited', 'dead') else 'OTHER', 'groups': result}

def packet(module, repo, deadline):
    client = module.Client(repo, deadline)
    ids = ids_from_listing(client(LIST_ARGS, cap=4096))
    if not ids:
        return [], None, ids
    image = module.decode(client(('image', 'inspect', '--format', IMAGE_FORMAT, IMAGE)))
    need(type(image) is dict and image.get('Id') == IMAGE)
    volume_rows = rows(client(('volume', 'inspect', '--format', VOLUME_FORMAT, *VOLUMES.values())), module, 2)
    baseline = volume_baseline(volume_rows)
    results = []
    for identity in ids:
        tick(deadline)
        record = module.decode(client(('container', 'inspect', '--format', CANDIDATE_FORMAT, identity)))
        need(type(record) is dict and record.get('Id') == identity)
        results.append(compare_groups(record, image, baseline, identity))
    return results, baseline, ids

def run(argv, repo=REPO):
    deadline, checkpoint, module = time.monotonic() + 60, 'ARGUMENTS', None
    try:
        checkpoint = 'PUBLIC_SOURCES'
        module, pins = load_transport(repo, argv, deadline)
        # Fixed stage hook local to this one Client instance, not a generic executor.
        original_client = module.Client
        outer = {'checkpoint': 'LIST'}
        class StagedClient(original_client):
            def __call__(self, args, cap=65536):
                outer['checkpoint'] = ('LIST' if args == LIST_ARGS else 'IMAGE_DEFAULTS' if args[:2] == ('image', 'inspect')
                    else 'VOLUME_BASELINE' if args[:2] == ('volume', 'inspect') else 'CANDIDATE_METADATA')
                return super().__call__(args, cap=cap)
        module.Client = StagedClient
        try:
            candidates, baseline, ids = packet(module, repo, deadline)
        except BaseException:
            checkpoint = outer['checkpoint']
            raise
        checkpoint = 'SOURCE_FINAL'
        for relative, pin in pins.items():
            need(hashlib.sha256(public_bytes(repo / relative, deadline,
                 512 * 1024 if relative in (CONTROLLER, CONTROLLER_TEST) else 65536)).hexdigest() == pin)
        receipt = {'code': 'HOLDERS_CLASSIFIED_NOT_QUALIFIED', 'ok': True, 'Env': 'EQUALITY_ONLY_PRIVATE',
            'fullQualification': 'NOT_CLAIMED', 'adopted': False, 'privateBindings': 'NOT_OBSERVED',
            'volumeBaseline': 'COMPLETE' if baseline is not None else 'NOT_AVAILABLE',
            'knownInitial': 'PRESENT' if INITIAL in ids else 'ABSENT', 'candidates': candidates}
        need(len(json.dumps(receipt, separators=(',', ':'), ensure_ascii=True).encode('ascii')) <= 4096)
        return receipt, 0
    except BaseException as exc:
        category = (exc.category if type(exc) is Refused or module is not None and type(exc) is module.Refused
                    else 'IO_REFUSED' if isinstance(exc, OSError) else 'UNEXPECTED')
        if category not in CATEGORIES:
            category = 'UNEXPECTED'
        return {'code': 'REFUSED', 'ok': False, 'checkpoint': checkpoint if checkpoint in CHECKPOINTS else 'CLASSIFY',
                'category': category, 'Env': 'EQUALITY_ONLY_PRIVATE', 'fullQualification': 'NOT_CLAIMED',
                'adopted': False, 'privateBindings': 'NOT_OBSERVED'}, 1

def main():
    output = os.dup(1)
    try:
        with open(os.devnull, 'wb', buffering=0) as sink:
            os.dup2(sink.fileno(), 1)
            os.dup2(sink.fileno(), 2)
            receipt, status = run(sys.argv[1:])
        raw = json.dumps(receipt, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
        need(len(raw) <= 4096)
        os.write(output, raw + b'\n')
        return status
    except BaseException:
        os.write(output, b'{"code":"REFUSED","ok":false,"category":"UNEXPECTED"}\n')
        return 1
    finally:
        os.close(output)

if __name__ == '__main__':
    raise SystemExit(main())
