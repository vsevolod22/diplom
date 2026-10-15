#!/usr/bin/env python3
"""Review-only ONE retained-host-PRE diagnostic. Never recovery or ownership adoption.

-I -B; shared90s; <=5 Docker clients<=10s (ceiling6); caller110000ms; receipt4KiB.
Namespace listing<=4 full IDs INCLUDING two fixed exclusions, <=2 eligible IDs;
exactly ONE eligible candidate required for any private inspection. No newest,
name-based selection, fallback or retry. Image defaults/Env, volume metadata and
full guarded holder projection stay private; only candidate full ID/state escape.
Host private reads ONLY two genuine custody journals + existing selected host pre/.
Absent pre => ABSENT, not a guessed failed export gate. Inventory hashes files via
pinned backup_inventory(durable=False,byte_limit=256MiB,deadline=shared_deadline).
Then actual validate_manifest(migration=True), small_snapshot and small_headers;
NO SQLite opens. Manifest<=4MiB before manifest parsing. Byte limit bounds inventory
payload, not total repeated manifest/header reads (bounded separately). Traversal
and hash checks charge the shared clock; other bounded validators are bracketed.
Blocked filesystem calls require the caller wall fence. No resource widening.

No fsync, cp/exec/unpause/stop/start/rm, lock, actor, SQL, source-volume host read,
private Env, HTTP/provider, signing material, adoption or writes. No controller
instance/lifecycle is invoked. Its PUBLIC selector definitions load on import.
Final candidate metadata ignores ONLY actual Mounts outer order, preserves full
canonical multiset; declarations/all other fields remain type-sensitive exact.
Journal/manifest/ancestor stability rechecked, no claimed continuous exclusion.
Historical durability and in-holder inventory ALWAYS NOT_OBSERVED. Even host
VALIDATED_READ_ONLY cannot certify an export or prove personal-state preservation.
"""
# Separate --diagnose-retained-pre-metadata-once: exact incident ID, ONE projected
# read client, no discovery/Env/journal/PRE content/inventory/hash/SQL/fsync. Only
# fixed host names plus <=5 top-level scandir entries; never recurse/enumerate raw.
# Same90s/10s/caller110000ms bounds. Existing observation mode is not reauthorized.
from contextlib import contextmanager
import hashlib
import importlib.util
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
SELF = 'server/deploy/trust/diagnose_retained_pre.py'
TEST = 'server/deploy/trust/test_diagnose_retained_pre.py'
CONTROLLER = 'server/deploy/trust/recreate_openrouter_key.py'
PROFILE = 'server/deploy/trust/diagnose_holder_qualification.py'
TRANSPORT = 'server/deploy/trust/discover_preservation_holder.py'
HELPER = 'server/deploy/trust/sqlite_state_snapshot.mjs'
HELPER_SHA256 = '323ca629483f92896634ada79d2c8f098d9ff885464eb24ba9d86bb75e563dee'
PINS = {
    CONTROLLER:'76153d2cd7d0452c14149a367cde4bb934d973380a7e10e22ebb798f95893857',
    'server/deploy/trust/test_recreate_openrouter_key.py':
        '15b0460d1faefa31112f67cbfa86cd1d0db90046ecb2f74b110ba6e90629ac60',
    'server/deploy/trust/stand_composition.py':
        '97283889749a4413d5e27f9b0ce828927f56b56ef507cb220a3c607fd3d23f5a',
    PROFILE:'8e051eeb3c7a4fa913d93a50e19dc21bf32884780d3102fe3cfe36897dce3eb8',
    'server/deploy/trust/test_diagnose_holder_qualification.py':
        'e25c7a9e1e7ec78c7a91d83c4f0c6e72b5e40fe42400d9f9f9f37b606a4ca8a0',
    TRANSPORT:'4afb0bc484d34aca428fee956bd939d7b322727285eef0f721425849bb32a1f4',
    'server/deploy/trust/test_discover_preservation_holder.py':
        'cc1a168804cb9a07f9c53724730bfbbaae7596c44c88743b0dc169f26a1bf312',
    HELPER:HELPER_SHA256,
}
EXCLUDED = frozenset(('d9433f7ed0fc504a3521574668f15b7b3a0e8d283d61b9aa33d1e97187708a4f',
                     '4dc55f9708f1537fa369ea165aadd050c1f44a6570f0adccb93043d1467d1769'))
HEX = re.compile(r'[0-9a-f]{64}\Z')
BACKUP = re.compile(r'key-preservation-[a-z0-9_]{8}\Z')
METADATA_MODE = '--diagnose-retained-pre-metadata-once'
CURRENT_ID = '207709f0f2992532af3331e0e2b38878c08a8d157ad074956f78c895aa5380e4'
METADATA_FORMAT = ('{"id":{{json .Id}},"image":{{json .Image}},"configImage":{{json .Config.Image}},'
    '"name":{{json .Name}},"backup":{{json (index .Config.Labels "dip.key-preservation")}},'
    '"status":{{json .State.Status}},"running":{{json .State.Running}},"paused":{{json .State.Paused}},'
    '"dead":{{json .State.Dead}},"restarting":{{json .State.Restarting}},"oom":{{json .State.OOMKilled}}}')
METADATA_ARGS = ('container','inspect','--format',METADATA_FORMAT,CURRENT_ID)
METADATA_STAGES = frozenset(('M_TARGET','M_IDENTITY','M_BACKUP_METADATA','M_PRE_METADATA','M_TOP_NAMES',
    'M_MANIFEST_METADATA','M_NESTED_PRE_METADATA','M_METADATA_FINAL','M_SOURCE_FINAL','M_COMPLETE'))
INTENT_KEYS = {'version','name','image','backup','source','sourceSha256','preservationMigration'}
ID_KEYS = {'version','id','name','image','backup'}
STAGES = frozenset(('ARGUMENTS','PUBLIC_SOURCES','DISCOVERY','IMAGE_DEFAULTS','VOLUMES',
    'CANDIDATE','HOLDER_PROFILE','JOURNAL_INTENT','JOURNAL_ID','JOURNAL_BINDING',
    'PRE_METADATA','PRE_INVENTORY','PRE_MANIFEST_SEAL','PRE_MANIFEST','PRE_SMALL','PRE_HEADERS',
    'PRE_FINAL_SEAL','CANDIDATE_FINAL','JOURNALS_FINAL','SOURCE_FINAL','COMPLETE','OUTPUT_GUARD'))
CATEGORIES = frozenset(('NONE','PREDICATE_REFUSED','AMBIGUOUS','COMMAND_REFUSED','CLIENT_TIMEOUT',
    'CLIENT_NONZERO','CLIENT_EXEC_IDENTITY','CLIENT_EXEC_NOT_FOUND','CLIENT_EXEC_DENIED',
    'CLIENT_EXEC_OS_REFUSED','OUTPUT_CAP','DECODE_REFUSED','IO_REFUSED','UNEXPECTED'))

class Refused(Exception):
    def __init__(self, category='PREDICATE_REFUSED'):
        self.category = category if category in CATEGORIES else 'UNEXPECTED'
        super().__init__()

def need(value, category='PREDICATE_REFUSED'):
    if not value:
        raise Refused(category)

def tick(deadline):
    need(time.monotonic() < deadline,'CLIENT_TIMEOUT')

def stamp(st):
    return (st.st_dev,st.st_ino,st.st_mode,st.st_nlink,st.st_uid,st.st_gid,
            st.st_size,st.st_mtime_ns,st.st_ctime_ns)

@contextmanager
def checked_directory(path,deadline,*,private=False):
    need(path.is_absolute() and '..' not in path.parts and str(path) == os.path.normpath(path))
    fds,edges = [],[]
    try:
        fds.append(os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW))
        for part in path.parts[1:]:
            tick(deadline)
            before = os.stat(part,dir_fd=fds[-1],follow_symlinks=False)
            need(stat.S_ISDIR(before.st_mode) and not before.st_mode & 0o022)
            fds.append(os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fds[-1]))
            need(stamp(before) == stamp(os.fstat(fds[-1])))
            edges.append((fds[-2],part,stamp(before)))
        last = os.fstat(fds[-1])
        need(last.st_uid == os.geteuid())
        if private:
            need(stat.S_IMODE(last.st_mode) == 0o700 and last.st_gid == os.getegid())
        yield fds[-1],tuple(edge[2] for edge in edges)
        tick(deadline)
        for parent,name,metadata in edges:
            need(stamp(os.stat(name,dir_fd=parent,follow_symlinks=False)) == metadata)
    finally:
        for fd in reversed(fds):
            os.close(fd)

def read_sealed(path,deadline,*,private=False,cap=4096):
    with checked_directory(path.parent,deadline,private=private) as (parent,ancestry):
        before = os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid() and
             not before.st_mode & 0o022 and 0 < before.st_size <= cap)
        if private:
            need(stat.S_IMODE(before.st_mode) == 0o600 and before.st_gid == os.getegid())
        fd = os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            need(stamp(before) == stamp(os.fstat(fd)))
            raw = bytearray()
            while True:
                tick(deadline)
                block = os.read(fd,min(65536,cap+1-len(raw)))
                if not block:
                    break
                raw.extend(block)
                need(len(raw) <= cap)
            need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd)) and
                 stamp(before) == stamp(os.stat(path.name,dir_fd=parent,follow_symlinks=False)))
            return bytes(raw),(ancestry,stamp(before),hashlib.sha256(raw).digest())
        finally:
            os.close(fd)

def load_module(relative,raw):
    name = '_retained_pre_' + Path(relative).stem
    need(name not in sys.modules)
    spec = importlib.util.spec_from_file_location(name,REPO/relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        exec(compile(raw,str(REPO/relative),'exec'),module.__dict__)
    finally:
        del sys.modules[name]
    return module

def source_gate(argv,deadline):
    need(sys.flags.isolated and sys.dont_write_bytecode and Path(__file__).absolute() == REPO/SELF)
    pins = {SELF:argv[2],TEST:argv[4],**PINS}
    captured = {}
    for relative,pin in pins.items():
        raw,_ = read_sealed(REPO/relative,deadline,cap=512*1024)
        need(hashlib.sha256(raw).hexdigest() == pin)
        if relative in (CONTROLLER,PROFILE,TRANSPORT):
            captured[relative] = raw
    try:
        os.stat(REPO/'server/deploy/trust/config.json',follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise Refused()
    c,p,t = [load_module(relative,captured[relative]) for relative in (CONTROLLER,PROFILE,TRANSPORT)]
    need(c.backup_inventory.__kwdefaults__ == {'durable':True,'byte_limit':c.EXPORT_BYTES,'deadline':None})
    need(tuple(c.VOLUMES.values()) == tuple(p.VOLUMES.values()) and
         c.RECONCILIATION_ORIGINALS['api'][1] == p.IMAGE)
    return c,p,t,pins

def candidates(raw):
    need(type(raw) is bytes and len(raw) <= 4096,'OUTPUT_CAP')
    try:
        ids = raw.decode('ascii').splitlines()
    except UnicodeError:
        raise Refused('DECODE_REFUSED') from None
    need(len(ids) <= 4 and len(ids) == len(set(ids)) and all(HEX.fullmatch(v) for v in ids))
    eligible = sorted(set(ids)-EXCLUDED)
    need(len(eligible) <= 2)
    return eligible

class ReadClient:
    def __init__(self,p,t,deadline):
        self.inner,self.deadline = t.Client(REPO,deadline),deadline
        self.list = p.LIST_ARGS
        self.image = ('image','inspect','--format',p.IMAGE_FORMAT,p.IMAGE)
        self.volumes = ('volume','inspect','--format',p.VOLUME_FORMAT,*p.VOLUMES.values())
        self.allowed,self.used,self.target = {self.list:1,self.image:1,self.volumes:1},{},None
        self.profile = p
    def select(self,identity):
        need(self.target is None and type(identity) is str and HEX.fullmatch(identity) and identity not in EXCLUDED)
        self.target = ('container','inspect','--format',self.profile.CANDIDATE_FORMAT,identity)
        self.allowed[self.target] = 2
    def __call__(self,args):
        tick(self.deadline)
        need(type(args) is tuple and args in self.allowed and sum(self.used.values()) < 5 and
             self.used.get(args,0) < self.allowed[args],'COMMAND_REFUSED')
        self.used[args] = self.used.get(args,0)+1
        return self.inner(args,cap=4096 if args == self.list else 65536)

def environment(value):
    need(value is None or type(value) is list and len(value) <= 512)
    seen = set()
    for item in value or []:
        need(type(item) is str and '\0' not in item and len(item.encode()) <= 8192 and '=' in item)
        key = item.split('=',1)[0]
        need(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,255}',key) and key not in seen and
             key not in ('NODE_OPTIONS','NODE_PATH'))
        seen.add(key)

def state_code(record):
    value = record.get('State',{}).get('Status') if type(record) is dict and type(record.get('State')) is dict else None
    return value.upper() if value in ('paused','created','exited') else 'OTHER'

def qualify(p,record,image,baseline,identity):
    need(type(record) is dict and record.get('Id') == identity and baseline is not None and
         type(image) is dict and image.get('Id') == p.IMAGE)
    state = record['State']
    status = state_code(record)
    need(status in ('PAUSED','CREATED','EXITED') and type(state['ExitCode']) is int and state['ExitCode'] == 0 and
         state['Running'] is (status == 'PAUSED') and state['Paused'] is (status == 'PAUSED') and
         all(state[key] is False for key in ('Restarting','OOMKilled','Dead')))
    environment(record['Config']['Env'])
    environment(image['Config']['Env'])
    actual = p.compare_groups(record,image,baseline,identity)['groups']
    expected = dict.fromkeys(p.GROUPS,True)
    expected.update(RUN_FALSE=status != 'PAUSED',RUN_TRUE=status == 'PAUSED',UNPAUSED=status != 'PAUSED')
    need(actual == expected)
    label = record['Config']['Labels'][p.LABEL]
    need(type(label) is str and BACKUP.fullmatch(label))
    return label

def metadata_signature(t,record):
    mounts = record['Mounts']
    need(type(mounts) is list and len(mounts) <= 8 and all(type(m) is dict for m in mounts))
    return t.canonical({k:v for k,v in record.items() if k != 'Mounts'}),tuple(sorted(t.canonical(m) for m in mounts))

def bind_journals(p,t,intent_raw,id_raw,intent_seal,id_seal,record,label,identity):
    need(intent_seal[0] == id_seal[0] and intent_seal[1][:2] != id_seal[1][:2])
    intent,bound = t.decode(intent_raw),t.decode(id_raw)
    need(type(intent) is dict and set(intent) == INTENT_KEYS and type(bound) is dict and set(bound) == ID_KEYS)
    for value in (intent,bound):
        need(type(value['version']) is int and value['version'] == 1 and value['backup'] == label and
             value['image'] == p.IMAGE and type(value['name']) is str and '/' + value['name'] == record['Name'] and
             p.NAME.fullmatch('/'+value['name']))
    need(bound['id'] == identity and intent['name'] == bound['name'] and intent['source'] == HELPER and
         intent['sourceSha256'] == HELPER_SHA256 and intent['preservationMigration'] is True)

def metadata_flags():
    return {'prePresent':None,'preDirectorySafe':None,'preEmpty':None,'topNamesBounded':None,
        'layoutNamesExact':None,'unexpectedNames':None,'nestedPrePresent':None,
        'nestedPreSafe':None,'nestedManifestPresent':None,'parentSafe':None,
        'manifest':{'present':None,'kind':'NOT_OBSERVED','sizeCap':None,'mode600':None,
            'owner':{'uidMatch':None,'gidMatch':None},
            'followStable':{'noSymlink':None,'singleLink':None,'stable':None}}}

def leaf_stat(parent,name):
    try:
        return os.stat(name,dir_fd=parent,follow_symlinks=False)
    except FileNotFoundError:
        return None

def safe_private_directory(st):
    return (st is not None and stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o700 and
            st.st_uid == os.geteuid() and st.st_gid == os.getegid())

def host_metadata(folder,small_cap,deadline,stage,flags):
    """Metadata ONLY; never open a leaf, read content, hash it or infer old inventory."""
    stage('M_BACKUP_METADATA')
    with checked_directory(folder,deadline) as (parent,_):
        flags['parentSafe'] = safe_private_directory(os.fstat(parent))
        need(flags['parentSafe'])
        stage('M_PRE_METADATA')
        before_pre = leaf_stat(parent,'pre')
        flags['prePresent'] = before_pre is not None
        if before_pre is None:
            need(leaf_stat(parent,'pre') is None)
            return
        flags['preDirectorySafe'] = safe_private_directory(before_pre)
        if not flags['preDirectorySafe']:
            return  # No traversal of unsafe pre, and NEVER a content-read fallback.
        with checked_directory(folder/'pre',deadline,private=True) as (pre_fd,_):
            need(stamp(os.fstat(pre_fd)) == stamp(before_pre))
            stage('M_TOP_NAMES')
            expected = {'manifest.json','raw','working','sealed'}
            names = []
            with os.scandir(pre_fd) as scan:
                for entry in scan:
                    tick(deadline)
                    names.append(entry.name)  # Private transient name, never printed/returned.
                    if len(names) > len(expected):
                        break  # Expected+ONE. Context closes iterator; never scan a prefix as complete.
            flags['preEmpty'] = not names
            flags['topNamesBounded'] = len(names) <= len(expected)
            flags['unexpectedNames'] = bool(set(names)-expected)
            flags['layoutNamesExact'] = flags['topNamesBounded'] and set(names) == expected
            stage('M_MANIFEST_METADATA')
            before_manifest = leaf_stat(pre_fd,'manifest.json')
            manifest = flags['manifest']
            manifest['present'] = before_manifest is not None
            if before_manifest is None:
                manifest['kind'] = 'ABSENT'
            else:
                manifest['kind'] = ('REGULAR' if stat.S_ISREG(before_manifest.st_mode) else
                    'DIRECTORY' if stat.S_ISDIR(before_manifest.st_mode) else
                    'SYMLINK' if stat.S_ISLNK(before_manifest.st_mode) else 'OTHER')
                manifest['sizeCap'] = 0 < before_manifest.st_size <= small_cap
                manifest['mode600'] = stat.S_IMODE(before_manifest.st_mode) == 0o600
                manifest['owner'] = {'uidMatch':before_manifest.st_uid == os.geteuid(),
                                     'gidMatch':before_manifest.st_gid == os.getegid()}
                manifest['followStable'].update(noSymlink=not stat.S_ISLNK(before_manifest.st_mode),
                                                 singleLink=before_manifest.st_nlink == 1)
            stage('M_NESTED_PRE_METADATA')
            nested = leaf_stat(pre_fd,'pre')
            flags['nestedPrePresent'] = nested is not None
            if nested is not None:
                flags['nestedPreSafe'] = safe_private_directory(nested)
                if flags['nestedPreSafe']:
                    with checked_directory(folder/'pre'/'pre',deadline,private=True) as (nested_fd,_):
                        need(stamp(os.fstat(nested_fd)) == stamp(nested))
                        flags['nestedManifestPresent'] = leaf_stat(nested_fd,'manifest.json') is not None
                # No symlink/unsafe nested traversal and no nested directory enumeration.
                nested_after = leaf_stat(pre_fd,'pre')
                need(nested_after is not None and stamp(nested_after) == stamp(nested))
            stage('M_METADATA_FINAL')
            after_manifest = leaf_stat(pre_fd,'manifest.json')
            stable = ((before_manifest is None and after_manifest is None) or
                before_manifest is not None and after_manifest is not None and
                stamp(before_manifest) == stamp(after_manifest))
            manifest['followStable']['stable'] = stable
            need(stable)
            after_pre = leaf_stat(parent,'pre')
            need(after_pre is not None and stamp(after_pre) == stamp(before_pre))


def metadata_receipt(ok,point,category,flags,state):
    need(point in METADATA_STAGES and category in CATEGORIES and state in
         ('NOT_OBSERVED','PAUSED','CREATED','EXITED','OTHER'))
    return {'code':'PRE_METADATA_CLASSIFIED' if ok else 'REFUSED','ok':ok,'checkpoint':point,
        'category':category,'candidateId':CURRENT_ID,'state':state,'flags':flags,
        'ownership':'NOT_ADOPTED','fullQualification':'NOT_CLAIMED','mutation':False,
        'manifestContents':'NOT_OBSERVED','journalContents':'NOT_OBSERVED',
        'fullProfile':'NOT_REVALIDATED','priorInventoryRecord':'NOT_OBSERVED',
        'priorHashEquality':'NOT_OBSERVED','historicalDurability':'NOT_OBSERVED',
        'inHolderInventory':'NOT_OBSERVED'}

def metadata_run(c,p,t,pins,deadline):
    point,state,flags = 'M_TARGET','NOT_OBSERVED',metadata_flags()
    def stage(value):
        nonlocal point
        need(value in METADATA_STAGES)
        point = value
        tick(deadline)
    try:
        stage('M_TARGET')
        # The sole literal client. No listing, retargeting, retry or original-mode ReadClient.
        record = t.decode(t.Client(REPO,deadline)(METADATA_ARGS,cap=4096))
        if type(record) is dict:
            state = record.get('status')
            state = state.upper() if state in ('paused','created','exited') else 'OTHER'
        stage('M_IDENTITY')
        need(type(record) is dict and set(record) == {'id','image','configImage','name','backup',
             'status','running','paused','dead','restarting','oom'} and record['id'] == CURRENT_ID and
             record['image'] == record['configImage'] == p.IMAGE and type(record['name']) is str and
             p.NAME.fullmatch(record['name']) and type(record['backup']) is str and
             BACKUP.fullmatch(record['backup']) and record['status'] == 'paused' and
             record['running'] is True and record['paused'] is True and
             all(record[key] is False for key in ('dead','restarting','oom')))
        # This label bounds an observation path, NOT ownership or a rescue capability.
        host_metadata(ROOT/record['backup'],c.SMALL_MANIFEST,deadline,stage,flags)
        stage('M_SOURCE_FINAL')
        for relative,pin in pins.items():
            need(hashlib.sha256(read_sealed(REPO/relative,deadline,cap=512*1024)[0]).hexdigest() == pin)
        stage('M_COMPLETE')
        return metadata_receipt(True,point,'NONE',flags,state),0
    except BaseException as exc:
        category = (exc.category if type(exc) in (Refused,t.Refused) else
                    'IO_REFUSED' if isinstance(exc,OSError) else 'UNEXPECTED')
        return metadata_receipt(False,point,category if category in CATEGORIES else 'UNEXPECTED',flags,state),1


def host_pre(c,folder,deadline,stage,*,reader=read_sealed):
    """Existing host pre only; stage callback never receives private values."""
    stage('PRE_METADATA')
    with checked_directory(folder,deadline,private=True) as (parent,_):
        try:
            pre_stat = os.stat('pre',dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:
            return 'ABSENT'
        need(stat.S_ISDIR(pre_stat.st_mode))
        pre = folder/'pre'
        with checked_directory(pre,deadline,private=True):
            stage('PRE_INVENTORY')
            inventory = c.backup_inventory(pre,durable=False,byte_limit=256*c.MIB,deadline=deadline)
            stage('PRE_MANIFEST_SEAL')
            record = next((r for r in inventory if r['path'] == 'manifest.json'),None)
            need(record is not None and record['kind'] == 'file' and 0 < record['bytes'] <= c.SMALL_MANIFEST)
            raw,seal = reader(pre/'manifest.json',deadline,private=True,cap=c.SMALL_MANIFEST)
            need(len(raw) == record['bytes'] and hashlib.sha256(raw).hexdigest() == record['sha256'])
            stage('PRE_MANIFEST')
            # This pure property supplies PUBLIC expectations, not observed state or a Plan capability.
            versions = c.Plan.expected_versions.fget(types.SimpleNamespace(preservation_migration=True))
            manifest = c.validate_manifest(pre,inventory,versions,migration=True)
            stage('PRE_SMALL')
            c.small_snapshot(manifest,inventory,post=False)
            stage('PRE_HEADERS')
            c.Controller.small_headers(None,pre,manifest,inventory)  # Pinned read-only method; no Controller instance.
            stage('PRE_FINAL_SEAL')
            final_raw,final_seal = reader(pre/'manifest.json',deadline,private=True,cap=c.SMALL_MANIFEST)
            need(final_seal == seal and final_raw == raw)
    return 'VALIDATED_READ_ONLY'

def receipt(ok,stage,category,ids,state,pre):
    need(stage in STAGES and category in CATEGORIES and state in ('NOT_OBSERVED','PAUSED','CREATED','EXITED','OTHER') and
         pre in ('NOT_OBSERVED','ABSENT','VALIDATED_READ_ONLY') and type(ids) is list and len(ids) <= 2 and
         all(type(v) is str and HEX.fullmatch(v) and v not in EXCLUDED for v in ids))
    return {'code':'OBSERVED' if ok else 'REFUSED','ok':ok,'checkpoint':stage,'category':category,
            'candidateIds':ids,'state':state,'hostPre':pre,'ownership':'NOT_ADOPTED',
            'historicalDurability':'NOT_OBSERVED','inHolderInventory':'NOT_OBSERVED',
            'fullQualification':'NOT_CLAIMED','mutation':False}

def run(argv):
    deadline,point = time.monotonic()+90,'ARGUMENTS'
    c=p=t=None
    ids,state,pre = [],'NOT_OBSERVED','NOT_OBSERVED'
    def stage(value):
        nonlocal point
        need(value in STAGES)
        point = value
        tick(deadline)
    try:
        need(len(argv) == 5 and argv[0] in ('--diagnose-retained-pre-once',METADATA_MODE) and
             argv[1::2] == ['--source-sha256','--test-sha256'] and all(HEX.fullmatch(v) for v in argv[2::2]))
        stage('PUBLIC_SOURCES')
        c,p,t,pins = source_gate(argv,deadline)
        if argv[0] == METADATA_MODE:
            return metadata_run(c,p,t,pins,deadline)
        client = ReadClient(p,t,deadline)
        stage('DISCOVERY')
        ids = candidates(client(client.list))
        need(len(ids) <= 1,'AMBIGUOUS')
        if not ids:
            return receipt(True,'COMPLETE','NONE',ids,state,pre),0
        identity = ids[0]
        client.select(identity)
        stage('IMAGE_DEFAULTS')
        image = t.decode(client(client.image))
        stage('VOLUMES')
        baseline = p.volume_baseline(p.rows(client(client.volumes),t,2))
        need(baseline is not None)
        stage('CANDIDATE')
        record = t.decode(client(client.target))
        state = state_code(record)
        stage('HOLDER_PROFILE')
        label = qualify(p,record,image,baseline,identity)
        folder = ROOT/label
        stage('JOURNAL_INTENT')
        intent_raw,intent_seal = read_sealed(folder/'holder-intent.json',deadline,private=True)
        stage('JOURNAL_ID')
        id_raw,id_seal = read_sealed(folder/'holder-id.json',deadline,private=True)
        stage('JOURNAL_BINDING')
        bind_journals(p,t,intent_raw,id_raw,intent_seal,id_seal,record,label,identity)
        pre = host_pre(c,folder,deadline,stage)
        stage('CANDIDATE_FINAL')
        final = t.decode(client(client.target))
        need(metadata_signature(t,final) == metadata_signature(t,record) and
             qualify(p,final,image,baseline,identity) == label)
        stage('JOURNALS_FINAL')
        need(read_sealed(folder/'holder-intent.json',deadline,private=True)[1] == intent_seal and
             read_sealed(folder/'holder-id.json',deadline,private=True)[1] == id_seal)
        stage('SOURCE_FINAL')
        for relative,pin in pins.items():
            need(hashlib.sha256(read_sealed(REPO/relative,deadline,cap=512*1024)[0]).hexdigest() == pin)
        stage('COMPLETE')
        return receipt(True,point,'NONE',ids,state,pre),0
    except BaseException as exc:
        known = [Refused]
        for module,names in ((c,('Refusal','BootstrapRefusal')),(p,('Refused',)),(t,('Refused',))):
            if module is not None:
                known.extend(getattr(module,name) for name in names)
        category = ('CLIENT_TIMEOUT' if time.monotonic() >= deadline or c is not None and type(exc) is c.StageTimeout else
                    exc.category if type(exc) is Refused or t is not None and type(exc) is t.Refused else
                    'PREDICATE_REFUSED' if type(exc) in known else
                    'IO_REFUSED' if isinstance(exc,OSError) else 'UNEXPECTED')
        return receipt(False,point,category if category in CATEGORIES else 'UNEXPECTED',ids,state,pre),1

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
            raw = json.dumps(receipt(False,'OUTPUT_GUARD','UNEXPECTED',[],'NOT_OBSERVED','NOT_OBSERVED'),
                             separators=(',',':')).encode('ascii')
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
