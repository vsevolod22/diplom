#!/usr/bin/env python3
"""ONE exact-ID mount metadata diagnostic; NOT qualification/adoption/recovery.

One container inspect client <=10s, shared30s, caller45s, transport<=65536 bytes,
closed receipt<=4096. Fixed holder+original API only. No ls/image/volume queries,
private filesystem metadata/content, Env, labels, State.Error, logs, helper/SQL,
HTTP, mutation, retry or resource cleanup. Only PUBLIC source files and the pinned
public Docker executable are read on host. No returned paths/names/options escape.

Frozen discovery source/test and controller are SHA-bound before reuse of ONLY
Client/decode; no controller execution or Discovery/directory_metadata call. The
frozen Client checks the measured canonical executable/hash/full stat and clean
endpoint/environment. Source config.json presence is refused before any child.
HOST_MNT_PREFIX is exact string comparison evidence ONLY, never normalization or
permission to relax the authoritative controller. No full qualifier/Env claim.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import types

SELF = 'server/deploy/trust/diagnose_holder_mounts.py'
TEST = 'server/deploy/trust/test_diagnose_holder_mounts.py'
LIBRARY = 'server/deploy/trust/discover_preservation_holder.py'
PINS = {
    LIBRARY: '4afb0bc484d34aca428fee956bd939d7b322727285eef0f721425849bb32a1f4',
    'server/deploy/trust/test_discover_preservation_holder.py':
        'cc1a168804cb9a07f9c53724730bfbbaae7596c44c88743b0dc169f26a1bf312',
    'server/deploy/trust/recreate_openrouter_key.py':
        'b34dcd63a77d06d997b4c6bf61a36bc7fbe67d8129aa12f444d055a1b9f50438',
}
REPO = Path(__file__).absolute().parents[3]
HOLDER = 'd9433f7ed0fc504a3521574668f15b7b3a0e8d283d61b9aa33d1e97187708a4f'
API = '5cbe0936a5f09d663a77960749e687fbd41fbef52c8990b063362b9363d3e9ec'
IMAGE = 'sha256:487c3909d3eeee08d60840a81c1adeb61c292aee0a31df17b2a8cf92f6dbb58c'
SCRIPT = 'server/deploy/trust/sqlite_state_snapshot.mjs'
TARGET = '/app/server/api/.key-preservation.mjs'
SLOTS = {'AUTH': ('/source/auth', 'volume', 'dip-auth-stand_auth_accounts'),
         'DATA': ('/source/data', 'volume', 'dip-auth-stand_scan_ledger'),
         'HELPER': (TARGET, 'bind', '')}
FORMAT = ('{"id":{{json .Id}},"image":{{json .Image}},'
          '"status":{{json .State.Status}},"running":{{json .State.Running}},'
          '"paused":{{json .State.Paused}},"restarting":{{json .State.Restarting}},'
          '"oom":{{json .State.OOMKilled}},"dead":{{json .State.Dead}},'
          '"declared":{{if eq .Id "' + HOLDER + '"}}{{json .HostConfig.Mounts}}{{else}}null{{end}},'
          '"actual":{{json .Mounts}}}')
ARGS = ('container', 'inspect', '--format', FORMAT, API, HOLDER)
HEX = re.compile(r'[0-9a-f]{64}\Z')
BOOL_KEYS = {'NonRecursive': 'NON_RECURSIVE', 'CreateMountpoint': 'CREATE_MOUNTPOINT',
             'ReadOnlyNonRecursive': 'RO_NON_RECURSIVE', 'ReadOnlyForceRecursive': 'RO_FORCE_RECURSIVE'}
EXTRA_KEYS = {'Consistency': 'CONSISTENCY', 'ImageOptions': 'IMAGE_OPTIONS',
              'TmpfsOptions': 'TMPFS_OPTIONS', 'ClusterOptions': 'CLUSTER_OPTIONS'}
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


def tick(deadline):
    if time.monotonic() >= deadline:
        raise Refused('CLIENT_TIMEOUT')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def stamp(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid, s.st_gid,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def public_bytes(path, deadline, cap=65536):
    """Bounded public sources ONLY; no-follow each directory and final file."""
    fds, fd = [], None
    try:
        fds.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        for part in path.parent.parts[1:]:
            tick(deadline)
            before = os.stat(part, dir_fd=fds[-1], follow_symlinks=False)
            need(stat.S_ISDIR(before.st_mode))
            item = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1])
            fds.append(item)
            need(stamp(before) == stamp(os.fstat(item)))
        before = os.stat(path.name, dir_fd=fds[-1], follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= cap)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fds[-1])
        need(stamp(before) == stamp(os.fstat(fd)))
        raw = bytearray()
        while True:
            tick(deadline)
            block = os.read(fd, min(65536, cap + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
            need(len(raw) <= cap)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd)) and
             stamp(before) == stamp(os.stat(path.name, dir_fd=fds[-1], follow_symlinks=False)))
        return bytes(raw)
    finally:
        if fd is not None:
            os.close(fd)
        for item in reversed(fds):
            os.close(item)


def load_library(repo, argv, deadline):
    need(sys.flags.isolated and sys.dont_write_bytecode and Path(__file__).absolute() == repo / SELF)
    need(hashlib.sha256(public_bytes(repo / SELF, deadline)).hexdigest() == argv[2])
    need(hashlib.sha256(public_bytes(repo / TEST, deadline)).hexdigest() == argv[4])
    captured = None
    for relative, expected in PINS.items():
        raw = public_bytes(repo / relative, deadline, 512 * 1024 if relative.endswith('/recreate_openrouter_key.py') else 65536)
        need(hashlib.sha256(raw).hexdigest() == expected)
        if relative == LIBRARY:
            captured = raw
    try:
        os.stat(repo / 'server/deploy/trust/config.json', follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise Refused()
    module = types.ModuleType('_pinned_holder_mount_transport')
    module.__file__ = str(repo / LIBRARY)
    exec(compile(captured, module.__file__, 'exec'), module.__dict__)
    return module


def kind(value):
    if value is None:
        return 'NULL'
    return {bool: 'BOOLEAN', int: 'INTEGER', str: 'STRING', list: 'ARRAY', dict: 'OBJECT'}.get(type(value), 'OTHER')


def boolean_field(obj, key):
    if key not in obj:
        return 'OMITTED'
    return 'TRUE' if obj[key] is True else 'FALSE' if obj[key] is False else 'WRONG_TYPE'


def source_relation(value, expected, *, helper=False):
    if type(value) is not str:
        return 'WRONG_TYPE'
    if value == '':
        return 'EMPTY'
    if expected is None:
        return 'BASELINE_NOT_OBSERVED'
    if value == expected:
        return 'EXACT'
    if helper and value == '/host_mnt' + expected:
        return 'HOST_MNT_PREFIX'
    return 'DIFFERENT'


def option_summary(m):
    result = {}
    # Finite names from Moby v28 Mount/BindOptions/VolumeOptions, not raw keys.
    known = {'Type', 'Source', 'Target', 'ReadOnly', 'BindOptions', 'VolumeOptions', *EXTRA_KEYS}
    result['extraKnown'] = {token: kind(m[key]) for key, token in EXTRA_KEYS.items() if key in m}
    result['unknownKeys'] = len(set(m) - known)
    for key, token in (('BindOptions', 'bind'), ('VolumeOptions', 'volume')):
        if key not in m:
            result[token] = {'kind': 'OMITTED'}
            continue
        value = m[key]
        summary = {'kind': kind(value)}
        if type(value) is dict:
            need(len(value) <= 16)
            summary['empty'] = not value
            if key == 'BindOptions':
                propagation = value.get('Propagation')
                summary['propagation'] = ('OMITTED' if 'Propagation' not in value else 'EMPTY' if propagation == ''
                                          else 'RPRIVATE' if propagation == 'rprivate' else 'OTHER')
                summary['flags'] = {name: boolean_field(value, field) for field, name in BOOL_KEYS.items() if field in value}
                summary['unknownKeys'] = len(set(value) - {'Propagation', *BOOL_KEYS})
            else:
                summary['noCopy'] = boolean_field(value, 'NoCopy')
                known_volume = {'Labels': 'LABELS', 'Subpath': 'SUBPATH', 'DriverConfig': 'DRIVER_CONFIG'}
                summary['extraKnown'] = {name: kind(value[field]) for field, name in known_volume.items() if field in value}
                summary['unknownKeys'] = len(set(value) - {'NoCopy', *known_volume})
        result[token] = summary
    return result


def shape(mounts, target_key, *, actual=False):
    if mounts is None:
        return {'kind': 'NULL'}, []
    need(type(mounts) is list and len(mounts) <= 8 and all(type(m) is dict and len(m) <= 16 for m in mounts))
    targets = [m.get(target_key) for m in mounts]
    need(all(type(t) is str for t in targets))
    expected = {slot[0] for slot in SLOTS.values()}
    return {'kind': 'ARRAY', 'cardinality': 'THREE' if len(mounts) == 3 else 'EMPTY' if not mounts else 'OTHER',
            'duplicateTargets': len(set(targets)) != len(targets),
            'unknownTargets': sum(t not in expected and not (actual and t in ('/backup', '/tmp')) for t in targets),
            'tmpfsTargets': sum(t in ('/backup', '/tmp') for t in targets) if actual else 0}, mounts


def rows(mounts, repo, baseline, *, actual):
    target_key = 'Destination' if actual else 'Target'
    summary, items = shape(mounts, target_key, actual=actual)
    slots = {}
    for name, (target, expected_type, volume) in SLOTS.items():
        found = [m for m in items if m[target_key] == target]
        if len(found) != 1:
            slots[name] = {'presence': 'MISSING' if not found else 'DUPLICATE'}
            continue
        m = found[0]
        expected_source = str(repo / SCRIPT) if name == 'HELPER' else baseline.get(name) if actual else volume
        out = {'presence': 'EXACT', 'typeMatch': m.get('Type') == expected_type,
               'source': source_relation(m.get('Source'), expected_source, helper=name == 'HELPER'),
               ('rw' if actual else 'readOnly'): boolean_field(m, 'RW' if actual else 'ReadOnly')}
        if actual:
            out['nameMatch'] = m.get('Name', '') == volume
        else:
            out['options'] = option_summary(m)
        slots[name] = out
    return {'shape': summary, 'slots': slots}


def classify(records, repo):
    need(type(records) is list and len(records) == 2 and all(type(r) is dict for r in records))
    need({r.get('id') for r in records} == {API, HOLDER})
    indexed = {r['id']: r for r in records}
    for cid, status in ((API, 'exited'), (HOLDER, 'created')):
        r = indexed[cid]
        need(set(r) == {'id', 'image', 'status', 'running', 'paused', 'restarting', 'oom', 'dead', 'declared', 'actual'})
        need(r['image'] == IMAGE and r['status'] == status and
             all(r[k] is False for k in ('running', 'paused', 'restarting', 'oom', 'dead')))
    api, holder = indexed[API], indexed[HOLDER]
    baseline = {}
    need(api['declared'] is None)
    need(type(api['actual']) is list and len(api['actual']) <= 8)
    for name, (_, _, volume) in SLOTS.items():
        if name == 'HELPER':
            continue
        found = [m for m in api['actual'] if type(m) is dict and m.get('Type') == 'volume' and
                 m.get('Name') == volume and m.get('Destination') == '/' + name.lower() and m.get('RW') is True]
        if len(found) == 1 and type(found[0].get('Source')) is str and found[0]['Source'].startswith('/'):
            baseline[name] = found[0]['Source']
    declared = rows(holder['declared'], repo, baseline, actual=False)
    materialized = rows(holder['actual'], repo, baseline, actual=True)
    declaration = holder['declared'] or []
    actual = holder['actual'] or []
    d = [m for m in declaration if m.get('Target') == TARGET]
    a = [m for m in actual if m.get('Destination') == TARGET]
    helper_cross = ('MATCH' if d[0].get('Source') == a[0].get('Source') else 'MISMATCH') if len(d) == len(a) == 1 else 'NOT_OBSERVED'
    return {'code': 'MOUNTS_CLASSIFIED_NOT_QUALIFIED', 'ok': True, 'Env': 'NOT_OBSERVED',
            'fullQualification': 'NOT_CLAIMED', 'volumeBaseline': 'COMPLETE' if len(baseline) == 2 else 'INCOMPLETE',
            'declared': declared, 'materialized': materialized, 'helperSourceAcrossViews': helper_cross}


def diagnose(module, repo, deadline):
    tick(deadline)
    client = module.Client(repo, deadline)
    try:
        raw = client(ARGS, cap=65536)  # ONE client, TWO exact IDs; no discovery/list/follow-up.
    except BaseException as exc:
        if type(exc) is module.Refused:
            raise Refused(exc.category) from None
        raise
    need(client.calls == 1 and type(raw) is bytes and 0 < len(raw) <= 65536)
    lines = raw.splitlines()
    need(len(lines) == 2)
    try:
        records = [module.decode(line) for line in lines]
    except BaseException:
        raise Refused('DECODE_REFUSED') from None
    tick(deadline)
    return classify(records, repo)


def main(argv=None):
    deadline, checkpoint = time.monotonic() + 30, 'ARGUMENTS'
    try:
        argv = sys.argv[1:] if argv is None else argv
        need(len(argv) == 5 and argv[0] == '--diagnose-once' and argv[1] == '--source-sha256' and
             argv[3] == '--test-sha256' and HEX.fullmatch(argv[2]) and HEX.fullmatch(argv[4]))
        checkpoint = 'PUBLIC_SOURCES'
        module = load_library(REPO, argv, deadline)
        checkpoint = 'EXACT_ID_INSPECT'
        result = diagnose(module, REPO, deadline)
        tick(deadline)
        checkpoint = 'RECEIPT'
        code = 0
    except BaseException as exc:
        result = {'code': 'REFUSED', 'ok': False, 'checkpoint': checkpoint,
                  'category': exc.category if type(exc) is Refused else 'UNEXPECTED',
                  'Env': 'NOT_OBSERVED', 'fullQualification': 'NOT_CLAIMED'}
        code = 1
    raw = canonical(result) + b'\n'
    if len(raw) > 4096:
        raw = b'{"Env":"NOT_OBSERVED","code":"REFUSED","fullQualification":"NOT_CLAIMED","ok":false,"checkpoint":"RECEIPT","category":"OUTPUT_CAP"}\n'
        code = 1
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()
    return code


if __name__ == '__main__':
    try:
        status = main()
    except BaseException:
        os._exit(1)
    raise SystemExit(status)
