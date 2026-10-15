#!/usr/bin/env python3
"""Review-only ONE metadata packet, not qualification/adoption or incident replay.

-I -B; shared60s / <=6 clients<=10s / caller75000ms / receipt4096 bytes.
Combined stdout+stderr caps: batch2MiB, volumes/retained64KiB, info/census4KiB;
public source files<=512KiB, mounts<=64/container, source strings<=4096 bytes.
Exact sequence: two named volumes; daemon ID; complete census<=32; ONE census
batch {id,running,mounts}; fixed retained-CREATED projection; daemon ID again.
Empty/invalid census => no batch, never truncate/query a subset or arbitrary IDs.
No Env/logs/private files/locks, actors, helpers, SQL, HTTP, mutation or retry.
Paths/labels/defaults/daemon IDs stay internal. Only container full IDs and finite
flags/counts escape. At most32 active rows, ALL observed active IDs, no sampling.
shape=[censusCount,batchLines,decodedRows,duplicateRows,missingIDs,unexpectedIDs,activeCount].
Census/batch overflow counts saturate at33 and explicitly refuse completeness;
uninspected counters/predicates are null, not invented zero/PASS.
Historical daemon / cached retained equality / default labels / historical HOLD
are NOT_OBSERVED. Fresh observations cannot reconstruct those incident operands.
No original controller lifecycle function is called: only protected_store_touch.
Controller import loads its pinned PUBLIC selector definitions, never app code.

Active row [fullID,mask]: 1 named,2 exact source,4 descendant,8 ancestor;
16 volume,32 bind,64 other type,128 RWtrue,256 RWfalse (touching mounts only);
512 malformed mount,1024 active-touch violation,2048 egress,4096 llm-egress.
No writer exemptions: holder=None and permitted=set(), including both egress IDs.
Independent groups continue after predicate mismatches, NOT after client failures.
CLASSIFIED/ok means packet obtained; currentMatch is NOT full qualification and
never grants continuation. No claimed historical cause or continuous exclusion.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

REPO = Path('/Users/vsevolod/Documents/startup/diplom')
SELF = 'server/deploy/trust/diagnose_writer_fence.py'
TEST = 'server/deploy/trust/test_diagnose_writer_fence.py'
CONTROLLER = 'server/deploy/trust/recreate_openrouter_key.py'
TRANSPORT = 'server/deploy/trust/discover_preservation_holder.py'
PINS = {
    CONTROLLER: '9b62bcadcf70f0f42178fda4a3f19040601185eaf325f68ddfe5f9218fbe7b7c',
    'server/deploy/trust/test_recreate_openrouter_key.py':
        'a173bb9cac0514430a6fe26669a39075643f867def1310144968c1d3a11464cd',
    'server/deploy/trust/stand_composition.py':
        '97283889749a4413d5e27f9b0ce828927f56b56ef507cb220a3c607fd3d23f5a',
    TRANSPORT: '4afb0bc484d34aca428fee956bd939d7b322727285eef0f721425849bb32a1f4',
    'server/deploy/trust/test_discover_preservation_holder.py':
        'cc1a168804cb9a07f9c53724730bfbbaae7596c44c88743b0dc169f26a1bf312',
}
HEX = re.compile(r'[0-9a-f]{64}\Z')
INITIAL = 'd9433f7ed0fc504a3521574668f15b7b3a0e8d283d61b9aa33d1e97187708a4f'
OLD_IMAGE = 'sha256:487c3909d3eeee08d60840a81c1adeb61c292aee0a31df17b2a8cf92f6dbb58c'
VOLUMES = ('dip-auth-stand_auth_accounts', 'dip-auth-stand_scan_ledger')
VOLUME_FORMAT = ('{"name":{{json .Name}},"driver":{{json .Driver}},"scope":{{json .Scope}},'
    '"options":{{json .Options}},"project":{{json (index .Labels "com.docker.compose.project")}},'
    '"mountpoint":{{json .Mountpoint}}}')
VOLUME_ARGS = ('volume', 'inspect', '--format', VOLUME_FORMAT, *VOLUMES)
DAEMON_ARGS = ('info', '--format', '{{json .ID}}')
CENSUS_ARGS = ('ps', '-a', '--no-trunc', '--format', '{{.ID}}')
BATCH_FORMAT = '{"id":{{json .Id}},"running":{{json .State.Running}},"mounts":{{json .Mounts}}}'
RETAINED_FORMAT = ('{"id":{{json .Id}},"image":{{json .Image}},"configImage":{{json .Config.Image}},'
    '"name":{{json .Name}},"status":{{json .State.Status}},"running":{{json .State.Running}},'
    '"paused":{{json .State.Paused}},"restarting":{{json .State.Restarting}},'
    '"oom":{{json .State.OOMKilled}},"dead":{{json .State.Dead}},"exit":{{json .State.ExitCode}},'
    '"restarts":{{json .RestartCount}},"started":{{json .State.StartedAt}},'
    '"finished":{{json .State.FinishedAt}},"entry":{{json .Config.Entrypoint}},'
    '"cmd":{{json .Config.Cmd}},"path":{{json .Path}},"args":{{json .Args}}}')
RETAINED_ARGS = ('inspect', '--type', 'container', '--format', RETAINED_FORMAT, INITIAL)
STAGES = frozenset(('ARGUMENTS','PUBLIC_SOURCES','VOLUMES','DAEMON_BEFORE','CENSUS','BATCH',
                    'RETAINED','DAEMON_AFTER','CLASSIFY','SOURCE_FINAL','COMPLETE','OUTPUT_GUARD'))
CATEGORIES = frozenset(('NONE','PREDICATE_REFUSED','COMMAND_REFUSED','CLIENT_TIMEOUT','CLIENT_NONZERO',
    'CLIENT_EXEC_IDENTITY','CLIENT_EXEC_NOT_FOUND','CLIENT_EXEC_DENIED','CLIENT_EXEC_OS_REFUSED',
    'OUTPUT_CAP','DECODE_REFUSED','IO_REFUSED','UNEXPECTED'))
GROUPS = ('VOLUME_SHAPE','VOLUME_IDENTITY','VOLUME_POLICY','VOLUME_PATHS','DAEMON_SHAPE','DAEMON_EQUAL',
    'CENSUS_BOUND','CENSUS_IDS','CENSUS_UNIQUE','RETIRED_ABSENT','INITIAL_PRESENT',
    'BATCH_COUNT','BATCH_DECODE','BATCH_SHAPE','BATCH_IDS','BATCH_UNIQUE','BATCH_COMPLETE','INITIAL_BATCH_STOPPED',
    'MOUNT_SHAPE','TOUCH_REASON_AGREEMENT','NO_ACTIVE_TOUCH',
    'RETAINED_ID_IMAGE','RETAINED_CREATED','RETAINED_FLAGS','RETAINED_COUNTERS',
    'RETAINED_TIMESTAMPS','RETAINED_ARGV','RETAINED_NAME')
NOT_OBSERVED = ('HISTORICAL_DAEMON','RETAINED_CACHE','DEFAULT_LABELS','HISTORICAL_HOLD')

class Refused(Exception):
    def __init__(self, category='PREDICATE_REFUSED'):
        self.category = category if category in CATEGORIES else 'UNEXPECTED'
        super().__init__()

def need(value, category='PREDICATE_REFUSED'):
    if not value:
        raise Refused(category)

def tick(deadline):
    need(time.monotonic() < deadline, 'CLIENT_TIMEOUT')

def stamp(st):
    return (st.st_dev,st.st_ino,st.st_mode,st.st_nlink,st.st_uid,st.st_gid,
            st.st_size,st.st_mtime_ns,st.st_ctime_ns)

def public_bytes(path, deadline):
    need(path in {REPO / name for name in (*PINS,SELF,TEST)})
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
        before = os.stat(path.name, dir_fd=fds[-1], follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid() and
             not before.st_mode & 0o022 and 0 < before.st_size <= 512 * 1024)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fds[-1])
        need(stamp(before) == stamp(os.fstat(fd)))
        raw = bytearray()
        while True:
            tick(deadline)
            block = os.read(fd, min(65536, 512 * 1024 + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
            need(len(raw) <= 512 * 1024)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd)) and
             stamp(before) == stamp(os.stat(path.name, dir_fd=fds[-1], follow_symlinks=False)))
        for parent, name, metadata in edges:
            need(stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)) == metadata)
        return bytes(raw)
    finally:
        if fd is not None:
            os.close(fd)
        for item in reversed(fds):
            os.close(item)

def load_module(relative, raw):
    name = '_writer_fence_' + Path(relative).stem
    need(name not in sys.modules)
    spec = importlib.util.spec_from_file_location(name, REPO / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        exec(compile(raw, str(REPO / relative), 'exec'), module.__dict__)
    finally:
        del sys.modules[name]
    return module

def source_gate(argv, deadline):
    need(sys.flags.isolated and sys.dont_write_bytecode and Path(__file__).absolute() == REPO / SELF)
    pins = {SELF:argv[2], TEST:argv[4], **PINS}
    captured = {}
    for relative, pin in pins.items():
        raw = public_bytes(REPO / relative, deadline)
        need(hashlib.sha256(raw).hexdigest() == pin)
        if relative in (CONTROLLER,TRANSPORT):
            captured[relative] = raw
    try:
        os.stat(REPO / 'server/deploy/trust/config.json', follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise Refused()
    c = load_module(CONTROLLER, captured[CONTROLLER])
    t = load_module(TRANSPORT, captured[TRANSPORT])
    need(tuple(c.VOLUMES.values()) == VOLUMES and c.RETAINED_CREATED_ID == INITIAL and
         c.RECONCILIATION_ORIGINALS['api'][1] == OLD_IMAGE and callable(c.protected_store_touch))
    return c,t,pins

class ReadClient:
    def __init__(self, transport, deadline):
        self.inner, self.deadline = transport.Client(REPO,deadline),deadline
        self.allowed = {VOLUME_ARGS:1, DAEMON_ARGS:2, CENSUS_ARGS:1, RETAINED_ARGS:1}
        self.used, self.batch = {},None
    def set_batch(self, ids):
        need(self.batch is None and type(ids) is list and 0 < len(ids) <= 32 and
             len(set(ids)) == len(ids) and all(type(v) is str and HEX.fullmatch(v) for v in ids))
        self.batch = ('inspect','--type','container','--format',BATCH_FORMAT,*ids)
        self.allowed[self.batch] = 1
    def __call__(self, args):
        tick(self.deadline)
        need(type(args) is tuple and args in self.allowed and sum(self.used.values()) < 6 and
             self.used.get(args,0) < self.allowed[args], 'COMMAND_REFUSED')
        self.used[args] = self.used.get(args,0) + 1
        return self.inner(args, cap=2 * 1024**2 if args == self.batch else
                          65536 if args in (VOLUME_ARGS,RETAINED_ARGS) else 4096)

def census(raw):
    need(type(raw) is bytes and len(raw) <= 4096, 'OUTPUT_CAP')
    try:
        ids = raw.decode('ascii').splitlines()
    except UnicodeError:
        raise Refused('DECODE_REFUSED') from None
    return ids, len(ids) <= 32 and len(set(ids)) == len(ids) and all(HEX.fullmatch(v) for v in ids)

def lines(raw):
    # Detect the 33rd record, rather than silently classify an output prefix.
    need(type(raw) is bytes and len(raw) <= 2 * 1024**2, 'OUTPUT_CAP')
    result = raw.split(b'\n',32)
    if result and result[-1] == b'':
        result.pop()
    return result

def classification(c,t,volumes_raw,before,after,ids,batch,retained):
    g = dict.fromkeys(GROUPS)
    def group(name, operation):
        try:
            value = operation()
            need(type(value) is bool)
            g[name] = value
        except (Refused,KeyError,TypeError,ValueError,AttributeError,IndexError):
            g[name] = False
    volume_lines = lines(volumes_raw)
    volumes = [t.decode(row) for row in volume_lines]
    group('VOLUME_SHAPE', lambda: len(volumes) == 2 and all(type(v) is dict and set(v) ==
          {'name','driver','scope','options','project','mountpoint'} for v in volumes))
    group('VOLUME_IDENTITY', lambda: len(volumes) == 2 and {v['name'] for v in volumes} == set(VOLUMES))
    group('VOLUME_POLICY', lambda: len(volumes) == 2 and all(v['driver'] == v['scope'] == 'local' and
          not v['options'] and v['project'] == 'dip-auth-stand' for v in volumes))
    group('VOLUME_PATHS', lambda: len(volumes) == 2 and all(type(v['mountpoint']) is str and
          0 < len(v['mountpoint'].encode()) <= 4096 and v['mountpoint'].startswith('/') and
          '\0' not in v['mountpoint'] for v in volumes) and len({v['mountpoint'] for v in volumes}) == 2)
    protected = ({v['name']:{'Mountpoint':v['mountpoint']} for v in volumes}
                 if all(g[k] for k in ('VOLUME_SHAPE','VOLUME_IDENTITY','VOLUME_POLICY','VOLUME_PATHS')) else None)
    group('DAEMON_SHAPE', lambda: all(type(v) is str and 0 < len(v.encode()) <= 4096 for v in (before,after)))
    group('DAEMON_EQUAL', lambda: g['DAEMON_SHAPE'] and before == after)
    group('CENSUS_BOUND', lambda: len(ids) <= 32)
    group('CENSUS_IDS', lambda: all(bool(HEX.fullmatch(v)) for v in ids))
    group('CENSUS_UNIQUE', lambda: len(set(ids)) == len(ids))
    group('RETIRED_ABSENT', lambda: c.RETIRED_R2_HOLDER_ID not in ids)
    group('INITIAL_PRESENT', lambda: INITIAL in ids)
    valid_ids = all(g[k] for k in ('CENSUS_BOUND','CENSUS_IDS','CENSUS_UNIQUE'))
    rows = lines(batch) if batch is not None else []
    inspected = batch is not None and len(rows) <= 32
    g['BATCH_COUNT'] = valid_ids and inspected and len(rows) == len(ids)
    g['BATCH_DECODE'] = g['BATCH_SHAPE'] = g['BATCH_IDS'] = g['BATCH_UNIQUE'] = True if inspected else None
    seen, decoded, duplicates, unexpected = set(),0,0,0
    active, initial_running = {},[]
    g['MOUNT_SHAPE'] = True
    g['TOUCH_REASON_AGREEMENT'] = g['NO_ACTIVE_TOUCH'] = True if protected is not None else None
    for row in rows if len(rows) <= 32 else []:
        try:
            item = t.decode(row)
        except t.Refused:
            g['BATCH_DECODE'] = False
            continue
        decoded += 1
        if not (type(item) is dict and set(item) == {'id','running','mounts'} and
                type(item.get('running')) is bool and type(item.get('id')) is str and HEX.fullmatch(item['id'])):
            g['BATCH_SHAPE'] = False
            continue
        identity = item['id']
        if identity not in ids:
            unexpected += 1
            g['BATCH_IDS'] = False
            continue
        if identity in seen:
            duplicates += 1
            g['BATCH_UNIQUE'] = False
        seen.add(identity)
        if identity == INITIAL:
            initial_running.append(item['running'])
        if item['running']:
            active.setdefault(identity, 2048 if identity == c.RECONCILIATION_ORIGINALS['egress'][0] else
                              4096 if identity == c.RECONCILIATION_ORIGINALS['llm-egress'][0] else 0)
        mounts = item['mounts']
        if not (type(mounts) is list and len(mounts) <= 64 and all(type(m) is dict for m in mounts)):
            g['MOUNT_SHAPE'] = False
            if item['running']:
                active[identity] |= 512
            continue
        for mount in mounts:
            source = mount.get('Source','')
            if not (type(source) is str and len(source.encode()) <= 4096 and '\0' not in source and
                    (mount.get('Name') is None or type(mount['Name']) is str) and
                    type(mount.get('Type')) is str and type(mount.get('RW')) is bool):
                g['MOUNT_SHAPE'] = False
                if item['running']:
                    active[identity] |= 512
                continue
            if protected is None:
                continue
            touches = c.protected_store_touch(mount,protected)  # SOLE authoritative touch decision.
            need(type(touches) is bool)
            # Explanation only, cross-checked against the pinned decision. No path normalization.
            reasons = (mount.get('Name') in c.VOLUMES.values(),
                any(source == v['Mountpoint'] for v in protected.values()),
                any(source.startswith(v['Mountpoint'].rstrip('/') + '/') for v in protected.values()),
                any(bool(source.startswith('/') and v['Mountpoint'].startswith(source.rstrip('/') + '/'))
                    for v in protected.values()))
            g['TOUCH_REASON_AGREEMENT'] &= touches == any(reasons)
            if item['running'] and touches:
                g['NO_ACTIVE_TOUCH'] = False  # No holder or permitted writer at this source checkpoint.
                active[identity] |= sum(bit for bit,value in zip((1,2,4,8),reasons) if value)
                active[identity] |= (16 if mount['Type'] == 'volume' else 32 if mount['Type'] == 'bind' else 64)
                active[identity] |= (128 if mount['RW'] else 256) | 1024
    missing = len(set(ids) - seen) if valid_ids else None
    g['BATCH_COMPLETE'] = valid_ids and g['BATCH_COUNT'] and seen == set(ids) and all(g[k] for k in
        ('BATCH_DECODE','BATCH_SHAPE','BATCH_IDS','BATCH_UNIQUE'))
    g['INITIAL_BATCH_STOPPED'] = (len(initial_running) == 1 and initial_running[0] is False
                                  if g['BATCH_COMPLETE'] else None)
    if not g['MOUNT_SHAPE']:
        for name in ('TOUCH_REASON_AGREEMENT','NO_ACTIVE_TOUCH'):
            if g[name] is True:
                g[name] = None
    if not g['BATCH_COMPLETE']:
        for name in ('MOUNT_SHAPE','TOUCH_REASON_AGREEMENT','NO_ACTIVE_TOUCH'):
            if g[name] is True:
                g[name] = None
    group('RETAINED_ID_IMAGE', lambda: type(retained) is dict and retained['id'] == INITIAL and
          retained['image'] == retained['configImage'] == OLD_IMAGE)
    group('RETAINED_CREATED', lambda: retained['status'] == 'created')
    group('RETAINED_FLAGS', lambda: all(type(retained[k]) is bool and retained[k] is False
          for k in ('running','paused','restarting','oom','dead')))
    group('RETAINED_COUNTERS', lambda: all(type(retained[k]) is int and retained[k] == 0 for k in ('exit','restarts')))
    group('RETAINED_TIMESTAMPS', lambda: retained['started'] == retained['finished'] == '0001-01-01T00:00:00Z')
    group('RETAINED_ARGV', lambda: retained['entry'] == ['node'] and retained['cmd'] == retained['args'] ==
          ['-e',c.HOLDER_CODE] and retained['path'] == 'node')
    group('RETAINED_NAME', lambda: type(retained['name']) is str and
          re.fullmatch(r'/dip-key-snapshot-[a-f0-9]{32}',retained['name']) is not None)
    return {'groups':g, 'shape':[min(len(ids),33),min(len(rows),33) if batch is not None else None,
            decoded if inspected else None,duplicates if inspected else None,missing if inspected else None,
            unexpected if inspected else None,len(active) if inspected else None],
            'active':[[identity,mask] for identity,mask in sorted(active.items())]}

def receipt(ok,stage,category,result=None):
    need(stage in STAGES and category in CATEGORIES)
    result = result or {'groups':dict.fromkeys(GROUPS),'shape':[None]*7,'active':[]}
    groups = result['groups']
    return dict(result,code='CLASSIFIED' if ok else 'REFUSED',ok=ok,checkpoint=stage,category=category,
        currentMatch=ok and all(v is True for v in groups.values()),
        firstMismatch=next((k for k in GROUPS if groups[k] is False),'NONE'),
        notObserved=list(NOT_OBSERVED),fullQualification='NOT_CLAIMED',mutation=False)

def run(argv):
    deadline,stage,t,result = time.monotonic()+60,'ARGUMENTS',None,None
    try:
        need(len(argv) == 5 and argv[0] == '--diagnose-writer-fence-once' and
             argv[1::2] == ['--source-sha256','--test-sha256'] and all(HEX.fullmatch(v) for v in argv[2::2]))
        stage = 'PUBLIC_SOURCES'
        c,t,pins = source_gate(argv,deadline)
        client = ReadClient(t,deadline)
        stage = 'VOLUMES'
        volumes = client(VOLUME_ARGS)
        stage = 'DAEMON_BEFORE'
        before = t.decode(client(DAEMON_ARGS))
        stage = 'CENSUS'
        ids,valid = census(client(CENSUS_ARGS))
        stage = 'BATCH'
        batch = None
        if valid and ids:
            client.set_batch(ids)
            batch = client(client.batch)
        elif valid:
            batch = b''
        stage = 'RETAINED'
        retained = t.decode(client(RETAINED_ARGS))
        stage = 'DAEMON_AFTER'
        after = t.decode(client(DAEMON_ARGS))
        stage = 'CLASSIFY'
        tick(deadline)
        result = classification(c,t,volumes,before,after,ids,batch,retained)
        stage = 'SOURCE_FINAL'
        for relative,pin in pins.items():
            need(hashlib.sha256(public_bytes(REPO / relative,deadline)).hexdigest() == pin)
        tick(deadline)
        return receipt(True,'COMPLETE','NONE',result),0
    except BaseException as exc:
        category = (exc.category if type(exc) is Refused or t is not None and type(exc) is t.Refused else
                    'IO_REFUSED' if isinstance(exc,OSError) else 'UNEXPECTED')
        return receipt(False,stage,category if category in CATEGORIES else 'UNEXPECTED',result),1

def main():
    output = None
    try:
        output = os.dup(1)
        with open(os.devnull,'wb',buffering=0) as sink:
            os.dup2(sink.fileno(),1)
            os.dup2(sink.fileno(),2)
            result,status = run(sys.argv[1:])
        raw = json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
        need(len(raw)+1 <= 4096,'OUTPUT_CAP')
        os.write(output,raw+b'\n')
        return status
    except BaseException:
        try:
            raw = json.dumps(receipt(False,'OUTPUT_GUARD','UNEXPECTED'),separators=(',',':')).encode('ascii')
            os.write(1 if output is None else output,raw+b'\n')
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
