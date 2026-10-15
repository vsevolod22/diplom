#!/usr/bin/env python3
"""DRAFT ONLY — no runtime authorization. One exact paused-holder retirement.

Future independent source/literal/security review AND separate informed USER consent
are required. The consent flag acknowledges loss of this exact actor's rootfs/logs
and possibly SOLE /backup/tmpfs recovery copy. Existing maintenance/migration grants
are NOT this consent. No fallback preservation/export/migration branch exists.

Fixed target only; no list/newest/adoption. Shared60s, <=5 clients<=10s, caller75s;
transport<=65536/client (rm4096), receipt<=4096. Only ONE mutation argv is possible:
  docker rm --force <fixed full ID>    (NEVER -v)
No unpause/stop/start/exec, retry, automatic cleanup, migration, SQL, provider, HTTP,
logs, Env output, lock changes, private directory enumeration or host file writes.
Named volumes/images/other actors and host journals/HOLDs are not deletion targets.
An exact rm acknowledgement is NOT volume-content preservation or a post-inventory.
Any attempted-removal ambiguity => STOP/manual HOLD, never query/retry/fallback.

Privately projected exact-target metadata supplies a validated backup label, NOT
an ownership capability. Ownership is then constrained by BOTH complete known
holder journals, read ONLY from that single label-derived owned0700 directory.
Only holder-intent.json and holder-id.json are opened privately; <=4096 bytes each,
regular0600, owner, nlink1, no-follow full ancestry, stable FD/path metadata, exact
schema/ID/name/image/backup/helper/hash/profile. No other private files are read.
Records/full ancestry are sealed privately and reread immediately before rm, after
an exact unchanged-target reinspection. No private contents/hash/path is emitted.
Checks are bounded checkpoints, not an atomic daemon/host exclusion guarantee.
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

REPO = Path('/Users/vsevolod/Documents/startup/diplom')
ROOT = REPO / '.local-auth'
SELF = 'server/deploy/trust/retire_failed_holder.py'
TEST = 'server/deploy/trust/test_retire_failed_holder.py'
TARGET = '4dc55f9708f1537fa369ea165aadd050c1f44a6570f0adccb93043d1467d1769'
IMAGE = 'sha256:487c3909d3eeee08d60840a81c1adeb61c292aee0a31df17b2a8cf92f6dbb58c'
PROFILE = 'server/deploy/trust/diagnose_holder_qualification.py'
TRANSPORT = 'server/deploy/trust/discover_preservation_holder.py'
HELPER = 'server/deploy/trust/sqlite_state_snapshot.mjs'
HELPER_SHA256 = '323ca629483f92896634ada79d2c8f098d9ff885464eb24ba9d86bb75e563dee'
CONSENT = '--consent-discard-target-rootfs-logs-and-possibly-sole-tmpfs'
HEX = re.compile(r'[a-f0-9]{64}\Z')
PINS = {
    PROFILE: '8e051eeb3c7a4fa913d93a50e19dc21bf32884780d3102fe3cfe36897dce3eb8',
    'server/deploy/trust/test_diagnose_holder_qualification.py':
        'e25c7a9e1e7ec78c7a91d83c4f0c6e72b5e40fe42400d9f9f9f37b606a4ca8a0',
    TRANSPORT: '4afb0bc484d34aca428fee956bd939d7b322727285eef0f721425849bb32a1f4',
    'server/deploy/trust/test_discover_preservation_holder.py':
        'cc1a168804cb9a07f9c53724730bfbbaae7596c44c88743b0dc169f26a1bf312',
    'server/deploy/trust/recreate_openrouter_key.py':
        '8ed5b4994997437afc5ff6d1bdcaecc19fc593f92940f2a7d7f6aed309ffa86c',
    'server/deploy/trust/test_recreate_openrouter_key.py':
        'f8872067b4003d17e84a8dbb1bc25e4a7a74cc332b0f720cdae213b72f584d17',
    HELPER: HELPER_SHA256,
}
CATEGORIES = frozenset(('PREDICATE_REFUSED', 'CLIENT_TIMEOUT', 'CLIENT_NONZERO', 'CLIENT_EXEC_IDENTITY',
    'CLIENT_EXEC_NOT_FOUND', 'CLIENT_EXEC_DENIED', 'CLIENT_EXEC_OS_REFUSED', 'OUTPUT_CAP',
    'DECODE_REFUSED', 'IO_REFUSED', 'UNEXPECTED'))
STAGES = frozenset(('ARGUMENTS_CONSENT', 'PUBLIC_SOURCES', 'IMAGE_DEFAULTS', 'VOLUME_BASELINE',
    'TARGET_METADATA', 'PAUSED_SANDBOX', 'CUSTODY_JOURNALS', 'SOURCE_FINAL', 'TARGET_FINAL',
    'JOURNALS_FINAL', 'REMOVE', 'COMPLETE'))
INTENT_KEYS = {'version', 'name', 'image', 'backup', 'source', 'sourceSha256', 'preservationMigration'}
ID_KEYS = {'version', 'id', 'name', 'image', 'backup'}

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

def read_sealed(path, deadline, *, private=False, root=None, cap=4096):
    """Stable no-follow ancestry + leaf; contents and seals stay in process memory."""
    need(path.is_absolute() and '..' not in path.parts and str(path) == os.path.normpath(path))
    fds, edges, fd = [], [], None
    try:
        fds.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        for part in path.parent.parts[1:]:
            tick(deadline)
            before = os.stat(part, dir_fd=fds[-1], follow_symlinks=False)
            need(stat.S_ISDIR(before.st_mode) and not before.st_mode & 0o022)
            fds.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1]))
            need(stamp(before) == stamp(os.fstat(fds[-1])))
            edges.append((fds[-2], part, stamp(before)))
        parent = os.fstat(fds[-1])
        need(parent.st_uid == os.geteuid())
        if private:
            need(root is not None and path.parent.parent == root and
                 path.name in ('holder-intent.json', 'holder-id.json') and
                 stat.S_IMODE(parent.st_mode) == 0o700)
            root_st = os.fstat(fds[-2])
            need(root_st.st_uid == os.geteuid() and not root_st.st_mode & 0o022)
        before = os.stat(path.name, dir_fd=fds[-1], follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid() and
             not before.st_mode & 0o022 and 0 < before.st_size <= cap)
        if private:
            need(stat.S_IMODE(before.st_mode) == 0o600)
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
        for parent_fd, name, metadata in edges:
            need(stamp(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) == metadata)
        return bytes(data), (tuple(e[2] for e in edges), stamp(before), hashlib.sha256(data).digest())
    finally:
        if fd is not None:
            os.close(fd)
        for item in reversed(fds):
            os.close(item)

def parse_arguments(argv):
    need(len(argv) == 6 and argv[0] == '--retire-exact-paused-holder' and argv[1] == CONSENT and
         argv[2] == '--source-sha256' and argv[4] == '--test-sha256' and
         HEX.fullmatch(argv[3]) and HEX.fullmatch(argv[5]))

def load_sources(repo, argv, deadline):
    need(sys.flags.isolated and sys.dont_write_bytecode and repo == REPO and Path(__file__).absolute() == repo / SELF)
    pins = {SELF: argv[3], TEST: argv[5], **PINS}
    captured = {}
    for relative, expected in pins.items():
        raw, _ = read_sealed(repo / relative, deadline, cap=512 * 1024)
        need(hashlib.sha256(raw).hexdigest() == expected)
        if relative in (PROFILE, TRANSPORT):
            captured[relative] = raw
    try:
        os.stat(repo / 'server/deploy/trust/config.json', follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise Refused()
    modules = []
    for relative in (PROFILE, TRANSPORT):
        module = types.ModuleType('_retire_pinned_' + ('profile' if relative == PROFILE else 'transport'))
        module.__file__ = str(repo / relative)
        exec(compile(captured[relative], module.__file__, 'exec'), module.__dict__)
        modules.append(module)
    return (*modules, pins)

def environment(value):
    need(value is None or type(value) is list and len(value) <= 512)
    result = {}
    for item in value or []:
        need(type(item) is str and '\0' not in item and len(item.encode()) <= 8192 and '=' in item)
        key, val = item.split('=', 1)
        need(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,255}', key) and key not in result and
             key not in ('NODE_OPTIONS', 'NODE_PATH'))
        result[key] = val
    return result

def qualify(profile, record, image, baseline):
    need(type(record) is dict and record.get('Id') == TARGET and type(image) is dict and image.get('Id') == IMAGE)
    need(baseline is not None)
    environment(record['Config']['Env'])
    environment(image['Config']['Env'])
    result = profile.compare_groups(record, image, baseline, TARGET)
    expected = dict.fromkeys(profile.GROUPS, True)
    expected.update(RUN_FALSE=False, UNPAUSED=False)
    need(result['groups'] == expected)
    state = record['State']
    need(state['Status'] == 'paused' and state['Running'] is True and state['Paused'] is True and
         state['Restarting'] is False and state['OOMKilled'] is False and state['Dead'] is False and
         type(state['ExitCode']) is int and state['ExitCode'] == 0)
    label = record['Config']['Labels'][profile.LABEL]
    need(type(label) is str and profile.BACKUP.fullmatch(label) is not None)
    return label

def custody(profile, transport, label, record, deadline, *, root=ROOT):
    need(type(label) is str and profile.BACKUP.fullmatch(label) is not None)
    folder = root / label
    intent_raw, intent_seal = read_sealed(folder / 'holder-intent.json', deadline, private=True, root=root)
    id_raw, id_seal = read_sealed(folder / 'holder-id.json', deadline, private=True, root=root)
    need(intent_seal[1][:2] != id_seal[1][:2] and intent_seal[0] == id_seal[0])
    intent, bound = transport.decode(intent_raw), transport.decode(id_raw)
    need(type(intent) is dict and set(intent) == INTENT_KEYS and type(bound) is dict and set(bound) == ID_KEYS)
    for value in (intent, bound):
        need(type(value['version']) is int and value['version'] == 1 and value['image'] == IMAGE and
             value['backup'] == label and type(value['name']) is str and
             '/' + value['name'] == record['Name'] and profile.NAME.fullmatch('/' + value['name']) is not None)
    need(bound['id'] == TARGET and intent['name'] == bound['name'] and intent['source'] == HELPER and
         intent['sourceSha256'] == HELPER_SHA256 and intent['preservationMigration'] is True)
    return intent_seal, id_seal

def target_metadata_signature(transport, record):
    """Ignore only actual Mounts outer order; retain full records and multiplicity."""
    need(type(record) is dict and type(record.get('Mounts')) is list and
         len(record['Mounts']) <= 8 and all(type(item) is dict for item in record['Mounts']))
    return (transport.canonical({key: value for key, value in record.items() if key != 'Mounts'}),
            tuple(sorted(transport.canonical(item) for item in record['Mounts'])))


class ExactClient:
    def __init__(self, profile, transport, repo, deadline):
        self.deadline, self.inner, self.removal_attempted = deadline, transport.Client(repo, deadline), False
        self.image = ('image', 'inspect', '--format', profile.IMAGE_FORMAT, IMAGE)
        self.volumes = ('volume', 'inspect', '--format', profile.VOLUME_FORMAT, *profile.VOLUMES.values())
        self.target = ('container', 'inspect', '--format', profile.CANDIDATE_FORMAT, TARGET)
        self.remove = ('rm', '--force', TARGET)
        self.limits, self.used = {self.image: 1, self.volumes: 1, self.target: 2, self.remove: 1}, {}

    def __call__(self, args):
        tick(self.deadline)
        need(args in self.limits and self.used.get(args, 0) < self.limits[args] and not self.removal_attempted)
        self.used[args] = self.used.get(args, 0) + 1  # Consume before launch; no retries.
        if args == self.remove:
            self.removal_attempted = True  # BEFORE an ambiguous daemon request.
        return self.inner(args, cap=4096 if args == self.remove else 65536)

def run(argv, repo=REPO):
    deadline, stage, transport, client = time.monotonic() + 60, 'ARGUMENTS_CONSENT', None, None
    try:
        parse_arguments(argv)  # No consent => no public/private reads or clients.
        stage = 'PUBLIC_SOURCES'
        profile, transport, pins = load_sources(repo, argv, deadline)
        client = ExactClient(profile, transport, repo, deadline)
        stage = 'IMAGE_DEFAULTS'
        image = transport.decode(client(client.image))
        stage = 'VOLUME_BASELINE'
        volumes = profile.rows(client(client.volumes), transport, 2)
        baseline = profile.volume_baseline(volumes)
        stage = 'TARGET_METADATA'
        initial = transport.decode(client(client.target))
        stage = 'PAUSED_SANDBOX'
        label = qualify(profile, initial, image, baseline)
        stage = 'CUSTODY_JOURNALS'
        sealed = custody(profile, transport, label, initial, deadline)
        stage = 'SOURCE_FINAL'
        for relative, pin in pins.items():
            raw, _ = read_sealed(repo / relative, deadline, cap=512 * 1024)
            need(hashlib.sha256(raw).hexdigest() == pin)
        stage = 'TARGET_FINAL'
        final = transport.decode(client(client.target))
        need(target_metadata_signature(transport, final) == target_metadata_signature(transport, initial) and
             qualify(profile, final, image, baseline) == label)
        stage = 'JOURNALS_FINAL'
        need(custody(profile, transport, label, final, deadline) == sealed)
        stage = 'REMOVE'
        need(client(client.remove).strip() == TARGET.encode('ascii'))
        return receipt(True, 'COMPLETE', 'NONE', True, False), 0
    except BaseException as exc:
        category = (exc.category if type(exc) is Refused or transport is not None and type(exc) is transport.Refused
                    else 'IO_REFUSED' if isinstance(exc, OSError) else 'UNEXPECTED')
        return receipt(False, stage, category if category in CATEGORIES else 'UNEXPECTED',
                       client is not None and client.removal_attempted,
                       client is not None and client.removal_attempted), 1

def receipt(ok, stage, category, attempted, uncertain):
    need(stage in STAGES and category in CATEGORIES | {'NONE'})
    return {'code': 'REMOVAL_ACKNOWLEDGED' if ok else 'REFUSED', 'ok': ok, 'checkpoint': stage,
            'category': category, 'removalAttempted': attempted, 'uncertain': uncertain,
            'namedVolumeRemovalRequested': False, 'hostWritesRequested': False, 'migrationApplied': False,
            'preservationVerified': False, 'manualReconciliationRequired': True}

def main():
    output = None
    try:
        output = os.dup(1)
        with open(os.devnull, 'wb', buffering=0) as sink:
            os.dup2(sink.fileno(), 1)
            os.dup2(sink.fileno(), 2)
            result, status = run(sys.argv[1:])
        raw = json.dumps(result, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
        need(len(raw) <= 4096)
        os.write(output, raw + b'\n')
        return status
    except BaseException:
        # A failed output guard must never manufacture certainty after a request.
        try:
            os.write(1 if output is None else output,
                     b'{"code":"REFUSED","ok":false,"category":"UNEXPECTED",'
                     b'"uncertain":true,"manualReconciliationRequired":true,"preservationVerified":false}\n')
        except BaseException:
            pass
        return 1
    finally:
        if output is not None:
            try:
                os.close(output)
            except BaseException:
                pass

if __name__ == '__main__':
    raise SystemExit(main())
