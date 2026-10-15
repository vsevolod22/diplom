#!/usr/bin/env python3
"""Preservation-migration, current-source/API-only and legacy REVIEW CANDIDATE.

Migration is a SEPARATE express-consent route: NEW API/worker/web immutable pins,
exact authorized OWN RW source holder, durable PRE before any original SQL write,
private PLANNED -> explicit apply -> independent MIGRATION_MATCH -> CURRENT POST
COMPATIBLE -> durable POST -> helper removal -> NEW API+worker -> ready/401 ->
NEW web. It never resumes the old worker/web or enables schedules/history.
Its actual peer CLI protocol is statically synchronized and source-pinned.
Fresh joint source/literal-command review is still required before use.
Migration requires local-report-summary-small-v1 admission: checked MAIN/WAL
for auth/ledger, strict MAIN/DELETE quota, bounded private PRE/plan/POST and
same-holder cgroup-v2 aggregates. Unknown/large state refuses; this is NOT a
journal-mode conversion or a general memory/physical-fit proof.
Initial capture/plan retain the peer's existing limits; no small pre-copy gate
is claimed. A host alarm + shared client deadline bounds interruptible pending
work, NOT uninterruptible kernel I/O or daemon cancellation. Independent owner
supervision remains necessary; no automatic retry follows expiration.
Public review IDs are assertions, never approval receipts.

The exact selected four-file LOCAL/free composition is compiled privately. Only
API.image changes in historical modes; migration changes API/worker/web.image
only. Optional align-api-cve-release permits ONLY the API release bind source
already modeled and matched by the worker; a separately pinned verifier gate is
mandatory before admission/stops and before replacements. The source-before-import
loader binds the exact separately reviewed verifier module/test pair.
--qualify-release-only stops after captured-model checks and ONE isolated release
verification: no compiled write, app startup, store access, stop/up or migration.
It cannot be combined with activation and never continues into production.
--prepare-rollout-only is a separate NOT-readonly action: shared authoritative
preflight, fresh verifier, OWN private compiled/durable files, first host-only
release recheck, then RETURN before activation HOLD/touched/stop/store holder.
It emits only fixed first-failure stage/category identifiers, has a shared150s
budget (verifier90s; other read clients15s), and never authorizes a later rollout.
Existing retained-verifier failure HOLD is preserved. Caller wall fence180000ms.
--reconcile-stopped-stand is a NEW express-consent incident route, not a spent
command retry: exact stopped originals/running gateways, prior HOLD metadata
unchanged, separate fresh exclusive reconciliation lock, retained CREATED actor
untouched. It captures a fresh baseline and never starts an OLD application.
Only this Darwin profile admits the exact /host_mnt+literal helper bind, with
matching safe declarations/actual mounts. Fresh holder intent/ID are journaled
before create/qualification respectively. Success preserves the prior HOLD;
manual reconciliation remains required. Existing600/240/160/cleanup bounds apply.
--successor-r2 additionally requires that stopped-stand profile and BOTH historical
lock/HOLD pairs unchanged; it exclusively creates the fixed incident R2 lock,
never adopts a historical lock or selects a fallback path.
--successor-r3 is mutually exclusive with R2, protects all THREE historical pairs,
and requires the exact retired R2 actor absent from a fresh bounded census before
new actors and at writer checkpoints. Only its fixed exclusive R3 lock is used.
--successor-r4 instead protects all FOUR fixed historical pairs and exclusively
creates the fixed R4 lock; the same retired-actor absence and preservation gates apply.
Private env/config/backup data and hashes NEVER reach evidence
or console. No build, pull, retag, initialization, repair or automatic rollback.

ONE old-image holder, UID/GID65532, RO root (sources RO except the separately
consented migration mode's exact RW sources), network-none/cap-dropALL/NNP,
2GiB memory/equal swap, CPU1/PIDs64, /backup2GiB + /tmp128MiB private UID-owned
TMPFS, fixed Node240s holder argv. This NEW sandbox needs its own express review,
not a grant to widen any stopped native-history limits. CLI receipts are ONLY
{code,ok}: capture CAPTURED/true; compare MATCH/true. Neither proves startup
compatibility. Parent review evidence + bound healthy OLD image/LOCAL command/
unchanged mounts/env + exact reviewed captured versions form a separate gate.
Current-source mode instead binds a NEW API image/source aggregate/review and fixed
source expectations (auth0/0, ledger0/14, quota1145655601/1). Its sealed-copy
COMPATIBLE gate receives ONLY four raw auth settings privately through stdin.
The holder and resumed worker remain the ORIGINAL images; no worker rollout.

Capture and compare use SAME in-container pre. Export pre and post while holder
RUNNING into fresh OWN host0700 destinations, validate all files/manifests privately,
fsync files/directories/parent entries before recreation or exact OWN removal.
No host archive is imported into the helper. Failed/ambiguous exec/export freezes
ONLY the fully qualified OWN holder; never stop/delete its sole tmpfs baseline.
Holder pause/expiry and Docker-client timeout remain uncertain daemon outcomes.

File+lock+root fsync completes before first stop. Failure retains OWN HOLD and
private recovery material; manual reconciliation only. Writer checks are bounded
checkpoints, not continuous host/timer exclusion. Resume starts API a second time
and worker writes: equality certifies stopped PRE-RESUME state, not final live DBs.
"""
from __future__ import annotations

import argparse

from contextlib import contextmanager
from dataclasses import dataclass
import copy
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import threading
import uuid

SELECTOR_SHA256 = '97283889749a4413d5e27f9b0ce828927f56b56ef507cb220a3c607fd3d23f5a'
SELECTOR_MODULE = '_dip_pinned_stand_composition_bootstrap'


class BootstrapRefusal(Exception):
    pass


RELEASE_RECHECK_STAGES = frozenset(('CAPABILITY_REQUEST', 'SOURCE_PINS', 'CLOCK_BEFORE',
                                    'INVENTORY_READ', 'INVENTORY_EQUALITY', 'CLOCK_AFTER'))
RELEASE_RECHECK_CATEGORIES = frozenset(('PREDICATE_REFUSED', 'UNEXPECTED'))
STAGE_IDS = frozenset((
    'BOOTSTRAP', 'ARGUMENTS', 'SOURCE_GATE_LOAD', 'CONTROLLER_ENTRY', 'LOCK_ENTER', 'LOCK_OWNERSHIP',
    'LOCK_EXIT', 'FINAL_ROOT_FSYNC', 'CAPTURE_PLAN', 'CAPTURE_PROTOCOL', 'ROOT_METADATA', 'SOURCE_PINS',
    'SECRET_METADATA', 'COMPOSE_AMBIENT', 'COMPOSE_VERSION', 'SELECTOR', 'ORIGINAL_INSPECT',
    'CANDIDATE_IMAGES', 'RENDER', 'MODEL_SHAPE', 'RELEASE_VERIFY', 'MODEL_RESTRICTIONS', 'IMAGE_SUBSTITUTION',
    'PRIVATE_DIRECTORY', 'COMPILED_WRITE', 'ALIGNMENT_WRITE', 'PRIVATE_DIRECTORY_FSYNC', 'COMPILED_METADATA',
    'COMPILED_QUIET', 'COMPILED_RENDER', 'COMPILED_EQUAL', 'AUTH_INPUT', 'NETWORKS', 'VOLUMES',
    'HOST_CAPACITY', 'ENGINE_MEMORY', 'HELPER_UID_ACCESS', 'WRITER_FENCE', 'STABILITY', 'SOURCE_FINAL',
    'SECRET_FINAL', 'SELECTOR_FINAL', 'API_SOCKET_GUARD', 'FIRST_RELEASE_RECHECK', 'COMPLETE',
    'RECONCILIATION_PROFILE', 'PRIOR_LOCK_METADATA', 'PRIOR_HOLD_METADATA', 'PRIOR_LOCK_MODE',
    'PRIOR_RECONCILIATION_LOCK_METADATA', 'PRIOR_RECONCILIATION_HOLD_METADATA',
    'PRIOR_RECONCILIATION_LOCK_MODE', 'PRIOR_RECONCILIATION_HOLD_STABILITY',
    'PRIOR_R2_LOCK_METADATA', 'PRIOR_R2_HOLD_METADATA', 'PRIOR_R2_LOCK_MODE', 'PRIOR_R2_HOLD_STABILITY',
    'PRIOR_R3_LOCK_METADATA', 'PRIOR_R3_HOLD_METADATA', 'PRIOR_R3_LOCK_MODE', 'PRIOR_R3_HOLD_STABILITY',
    'RETIRED_R2_CENSUS', 'RETIRED_R2_ABSENCE',
    'RECONCILIATION_LOCK_CREATE', 'RECONCILIATION_LOCK_MODE', 'RECONCILIATION_LOCK_IDENTITY',
    'RECONCILIATION_CAPABILITY', 'PRIOR_HOLD_STABILITY', 'COORDINATION_BODY', 'RETAINED_CREATED',
    'HOLD_OWNERSHIP', 'HOLD_REUSE', 'HOLD_WRITE', 'HOLD_METADATA', 'HOLD_DIRECTORY_FSYNC',
    'HOLD_ROOT_FSYNC', 'HOLD_FINAL_OWNERSHIP', 'PREFLIGHT', 'MIGRATION',
    'GATE_ROOT_METADATA', 'GATE_SOURCE_PINS', 'ENTRY_ROOT_METADATA',
    'HOLDER_SOURCE_PINS', 'HOLDER_RESOURCES_PRE', 'HOLDER_WRITERS_PRE', 'HOLDER_CAPACITY_PRE',
    'HOLDER_INTENT_JOURNAL', 'HOLDER_CREATE_ARGS', 'HOLDER_CREATE', 'HOLDER_CREATE_ID',
    'HOLDER_ID_JOURNAL', 'HOLDER_START', 'HOLDER_WRITERS_POST',
    'HOLDER_JOURNAL_BINDING', 'HOLDER_INSPECT', 'HOLDER_DEFAULTS_PREP', 'HOLDER_IDENTITY',
    'HOLDER_CONFIG_DEFAULTS', 'HOLDER_ENV_EQUAL', 'HOLDER_COMMAND', 'HOLDER_HEALTH_VOLUMES',
    'HOLDER_SECURITY', 'HOLDER_RESOURCES', 'HOLDER_TMPFS_OPTIONS', 'HOLDER_RESTART_STOP',
    'HOLDER_STATE', 'HOLDER_NETWORKS', 'HOLDER_MOUNTS_PREP', 'HOLDER_DECLARED_MOUNTS',
    'HOLDER_ACTUAL_MOUNTS', 'HOLDER_ACTUAL_TMPFS',
    'WRITER_DAEMON_READ', 'WRITER_DAEMON_SHAPE', 'WRITER_DAEMON_STABILITY',
    'WRITER_HOLDER_QUALIFY', 'WRITER_CENSUS', 'WRITER_HOLDER_PRESENCE',
    'WRITER_BATCH_READ', 'WRITER_BATCH_ROWCOUNT', 'WRITER_ROW_PARSE', 'WRITER_ROW_SCHEMA',
    'WRITER_ROW_ID_UNIQUE', 'WRITER_HOLDER_MOUNTS', 'WRITER_TOUCH_CLASSIFY',
    'WRITER_ACTIVE_ACCESS', 'WRITER_ACTIVE_HOLDER_ACCESS', 'WRITER_ACTIVE_OTHER_ACCESS',
    'INVENTORY_STAGE', 'INVENTORY_BUDGET', 'INVENTORY_QUALIFY', 'INVENTORY_READ', 'INVENTORY_SHAPE',
    'EXPORT_STAGE', 'EXPORT_CAPACITY', 'EXPORT_WRITERS_PRE', 'EXPORT_BUDGET', 'EXPORT_INVENTORY_BEFORE',
    'EXPORT_DESTINATION_CREATE', 'EXPORT_DESTINATION_MODE', 'EXPORT_PARENT_FSYNC', 'EXPORT_COPY',
    'EXPORT_QUALIFY_AFTER_COPY', 'EXPORT_HOST_INVENTORY', 'EXPORT_INVENTORY_EQUAL', 'EXPORT_VERSIONS',
    'EXPORT_MANIFEST', 'EXPORT_SMALL_ADMISSION', 'EXPORT_HEADERS', 'EXPORT_POST_BOUNDS',
    'EXPORT_POST_PHYSICAL', 'EXPORT_MATERIAL_SHAPE', 'EXPORT_MATERIAL_BYTES', 'EXPORT_PLAN_BOUNDS',
    'EXPORT_RETAINED_BOUNDS', 'EXPORT_OBSERVED_VERSIONS', 'EXPORT_INVENTORY_RECORD',
    'EXPORT_DESTINATION_FSYNC', 'EXPORT_BACKUP_FSYNC', 'EXPORT_ROOT_FSYNC', 'EXPORT_QUALIFY_FINAL',
    'EXPORT_WRITERS_FINAL', 'EXPORT_CERTIFY',
    *('OLD_' + r for r in ('API', 'WORKER', 'WEB', 'EGRESS', 'LLM_EGRESS')),
    *('IMAGE_' + r for r in ('API', 'WORKER', 'WEB', 'EGRESS', 'LLM_EGRESS')),
    *('MODEL_' + r for r in ('API', 'WORKER', 'WEB', 'EGRESS', 'LLM_EGRESS')),
    *('FIRST_RELEASE_RECHECK__' + stage for stage in RELEASE_RECHECK_STAGES),
))
STAGE_CATEGORIES = frozenset(('NONE', 'PREDICATE_REFUSED', 'CLIENT_TIMEOUT', 'OBSERVER_REFUSED',
                              'IO_REFUSED', 'UNEXPECTED'))


class StageTimeout(BootstrapRefusal):
    pass


class StageObserverRefusal(BootstrapRefusal):
    pass


class PreparationObservation:
    """Fixed identifiers only; one deadline and first failure, never private operands."""
    budget_seconds = 150

    def __init__(self, *, clock=time.monotonic, callback=None):
        self.clock, self.callback = clock, callback
        self.deadline = clock() + self.budget_seconds
        self.stack, self.first = [], None
        self.deadline_expired = False

    def fail(self, gate, exc):
        if self.first is None:
            self.deadline_expired = self.deadline_expired or self.clock() >= self.deadline
            pinned = type(exc) is globals().get('PinnedReleaseRefusal')
            category = ('CLIENT_TIMEOUT' if self.deadline_expired or isinstance(exc, (StageTimeout, subprocess.TimeoutExpired))
                        else 'OBSERVER_REFUSED' if isinstance(exc, StageObserverRefusal)
                        else exc.fixed_category if pinned
                        else 'PREDICATE_REFUSED' if isinstance(exc, (BootstrapRefusal, globals().get('Refusal', BootstrapRefusal)))
                        else 'IO_REFUSED' if isinstance(exc, OSError) else 'UNEXPECTED')
            checkpoint = self.stack[-1] if self.stack else gate
            if pinned and checkpoint == 'FIRST_RELEASE_RECHECK' and exc.fixed_stage is not None:
                checkpoint += '__' + exc.fixed_stage
            self.first = (checkpoint, category)

    def check(self):
        if self.clock() >= self.deadline:
            self.deadline_expired = True
            failure = StageTimeout()
            self.fail(self.stack[-1] if self.stack else 'CONTROLLER_ENTRY', failure)
            raise failure
        if self.first is not None:
            raise StageObserverRefusal()

    def __call__(self, gate, event):
        allowed = STAGE_IDS | globals().get('PREDICATE_IDS', frozenset())
        if gate not in allowed or event not in ('ENTER', 'PASS'):
            raise StageObserverRefusal()
        if event == 'ENTER':
            self.stack.append(gate)
        try:
            self.check()
            if self.callback is not None:
                try:
                    self.callback(gate, event)  # Return value is deliberately ignored.
                except BaseException:
                    raise StageObserverRefusal() from None
            self.check()
            if event == 'PASS':
                if not self.stack or self.stack[-1] != gate:
                    raise StageObserverRefusal()
                self.stack.pop()
        except BaseException as exc:
            self.fail(gate, exc)
            raise

    def receipt(self, result):
        checkpoint, category = self.first or ('COMPLETE', 'NONE')
        result = dict(result, mode='rollout-preparation-only-v1', checkpoint=checkpoint,
                      category=category, preparationOnly=True, standServicesRecreated=False,
                      migrationApplied=False, providerCalled=False)
        if len(json.dumps(result, separators=(',', ':')).encode('ascii')) > 4096:
            raise StageObserverRefusal()
        return result


class ReconciliationObservation(PreparationObservation):
    """Production600s observation, not preparation or authority to continue/retry."""
    budget_seconds = 600

    def check(self):
        if self.clock() >= self.deadline:
            self.deadline_expired = True
            failure = StageTimeout()
            self.fail(self.stack[-1] if self.stack else 'CONTROLLER_ENTRY', failure)
            raise failure
        # An exception unwinds forward execution. Do not suppress the existing
        # retention/fail-stop clients solely because a PRIMARY failure was recorded.
        # Their existing deadlines still apply; this600s deadline is never renewed.

    def receipt(self, result):
        checkpoint, category = self.first or ('COMPLETE', 'NONE')
        if checkpoint not in STAGE_IDS | globals().get('PREDICATE_IDS', frozenset()) or category not in STAGE_CATEGORIES:
            raise StageObserverRefusal()
        result = dict(result, mode='stopped-stand-preservation-v1', checkpoint=checkpoint,
                      category=category, manualReconciliationRequired=True)
        if len(json.dumps(result, separators=(',', ':')).encode('ascii')) > 4096:
            raise StageObserverRefusal()
        return result


def command_observation(argv):
    if '--reconcile-stopped-stand' in argv:
        return ReconciliationObservation()
    return PreparationObservation() if '--prepare-rollout-only' in argv else None


@contextmanager
def observed_stage(observer, gate):
    if observer is None:
        yield
        return
    observer(gate, 'ENTER')
    try:
        yield
    except BaseException as exc:
        observer.fail(gate, exc)
        raise
    observer(gate, 'PASS')


@contextmanager
def observed_teardown_stage(observer, gate):
    """Observation must not skip existing teardown, or replace its primary receipt."""
    pending = None
    if observer is not None and observer.first is None:
        try:
            observer(gate, 'ENTER')
        except BaseException as failure:
            pending = failure
    try:
        yield
    except BaseException as failure:
        if observer is not None:
            observer.fail(gate, failure)
        raise
    if pending is not None:
        raise pending
    if observer is not None and observer.first is None:
        observer(gate, 'PASS')


@contextmanager
def observed_refresh_lock(root, observer):
    if observer is None:
        with refresh_lock(root) as capability:
            yield capability
        return
    context, entered = refresh_lock(root), False
    def leave(exc):
        pending = None
        if observer.first is None:
            try:
                observer('LOCK_EXIT', 'ENTER')
            except BaseException as failure:
                pending = failure
        try:
            context.__exit__(*exc)  # OWN lock exit must run even if observation/deadline failed.
        except BaseException as failure:
            observer.fail('LOCK_EXIT', failure)
            raise
        if pending is not None:
            raise pending
        if observer.first is None:
            observer('LOCK_EXIT', 'PASS')
    try:
        with observed_stage(observer, 'LOCK_ENTER'):
            capability = context.__enter__()
            entered = True
        yield capability
    except BaseException:
        if entered:
            leave(sys.exc_info())
        raise
    else:
        leave((None, None, None))


def _load_stand_composition():
    """Capture fixed-repo public bytes before execution; never resolve an import."""
    if 'stand_composition' in sys.modules or SELECTOR_MODULE in sys.modules:
        raise BootstrapRefusal()
    path = Path(__file__).absolute().with_name('stand_composition.py')
    for ancestor in (*reversed(path.parents), path):
        st = ancestor.lstat()
        if (stat.S_ISLNK(st.st_mode) or st.st_mode & 0o022 or
                (ancestor != path and not stat.S_ISDIR(st.st_mode))):
            raise BootstrapRefusal()
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
            before.st_nlink != 1 or not 0 < before.st_size <= 65536):
        raise BootstrapRefusal()
    identity = lambda st: (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_nlink,
                           st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if identity(os.fstat(fd)) != identity(before):
            raise BootstrapRefusal()
        data = bytearray()
        while block := os.read(fd, 65536):
            data.extend(block)
            if len(data) > 65536:
                raise BootstrapRefusal()
        if (identity(os.fstat(fd)) != identity(before) or identity(path.lstat()) != identity(before) or
                len(data) != before.st_size or hashlib.sha256(data).hexdigest() != SELECTOR_SHA256):
            raise BootstrapRefusal()
    finally:
        os.close(fd)
    spec = importlib.util.spec_from_file_location(SELECTOR_MODULE, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[SELECTOR_MODULE] = module  # dataclass resolves only this OWN temporary module.
    try:
        exec(compile(bytes(data), str(path), 'exec'), module.__dict__)
        return module
    finally:
        if sys.modules.get(SELECTOR_MODULE) is module:
            del sys.modules[SELECTOR_MODULE]


def load_stand_composition(observer=None):
    with observed_stage(observer, 'BOOTSTRAP'):
        return _load_stand_composition()


BOOTSTRAP_OBSERVATION = command_observation(sys.argv[1:]) if __name__ == '__main__' else None
try:
    _stand = load_stand_composition(BOOTSTRAP_OBSERVATION)
    BASES, OVERLAY, LLM_OVERLAY = _stand.BASES, _stand.OVERLAY, _stand.LLM_OVERLAY
    _held_locks, refresh_lock, select = _stand._held_locks, _stand.refresh_lock, _stand.select
except BaseException:
    if __name__ == '__main__':
        try:
            closed = {'manualReconciliationRequired': False, 'ok': False, 'phase': 'preflight', 'uncertain': False}
            if BOOTSTRAP_OBSERVATION is not None:
                closed = BOOTSTRAP_OBSERVATION.receipt(closed)
            sys.stdout.buffer.write(json.dumps(closed, sort_keys=True, separators=(',', ':')).encode('ascii') + b'\n')
        except BaseException:
            pass
        raise SystemExit(1) from None
    raise BootstrapRefusal() from None

REPO = Path(__file__).resolve().parents[3]
PROJECT = 'dip-auth-stand'
FILES = (*BASES, OVERLAY, LLM_OVERLAY)
ROLES = ('api', 'worker', 'web', 'egress', 'llm-egress')
VOLUMES = {'auth': PROJECT + '_auth_accounts', 'data': PROJECT + '_scan_ledger'}
PUBLIC = (*FILES, 'server/deploy/trust/stand_composition.py',
          'server/deploy/trust/recreate_openrouter_key.py',
          'server/deploy/trust/test_recreate_openrouter_key.py')
IMAGE = re.compile(r'sha256:[a-f0-9]{64}\Z')
HEX = re.compile(r'[a-f0-9]{64}\Z')
HELPER_PATH = 'server/deploy/trust/sqlite_state_snapshot.mjs'
HELPER_TEST = 'server/deploy/trust/sqlite_state_snapshot.test.mjs'
RELEASE_VERIFIER = 'server/deploy/trust/verify_preservation_release.py'
RELEASE_VERIFIER_TEST = 'server/deploy/trust/test_verify_preservation_release.py'
RELEASE_VERIFIER_PINS = {
    RELEASE_VERIFIER: 'c93ced26d68140f2afe3201db16b373ecc5260a9212fd2075d2e978c1d898533',
    RELEASE_VERIFIER_TEST: '04c1748f6f5180225584e0f06e4e80f0e0598f2390a0bbd60296374b504fbd39',
}
REJECTED_HELPER = 'f396746a36860d64b80ce70d40677cceee18f0d22bdb29b4de7cdcec81dc359c'
EVIDENCE = re.compile(r'DIP-ARTF-[1-9][0-9]{0,8}\Z')
SUPPORTED_COMPOSE_VERSIONS = frozenset((b'2.34.0', b'2.34.0-desktop.1'))
MIB = 1024 * 1024
GIB = 1024 * MIB
HOLDER_MS = 240000
HOLDER_CODE = 'setTimeout(()=>{},240000)'
HOLDER_TMPFS = {
    '/backup': 'rw,noexec,nosuid,uid=65532,gid=65532,mode=0700,size=2g',
    '/tmp': 'rw,noexec,nosuid,uid=65532,gid=65532,mode=0700,size=128m',
}
REQUIRED_STORES = ('auth/auth.sqlite', 'data/ledger.sqlite', 'auth/llm-usage.sqlite')
# Independently reviewed CURRENT source expectations, NOT observed stand facts.
# Pin shared CURRENT_PROFILE source identity; parent verifies its actual package/review.
CURRENT_SOURCE_AGGREGATE = '29c3ca5bd186d625cc102e2f7e43b4f1e8e168ba3372cabd7840cc21b6676a37'
CURRENT_SOURCE_VERSIONS = {
    'auth/auth.sqlite': (0, 0), 'data/ledger.sqlite': (0, 14),
    'auth/llm-usage.sqlite': (1145655601, 1),
}
AUTH_SETTINGS = ('AUTH_ORIGIN', 'AUTH_ALLOW_INSECURE_LOCAL_HTTP',
                 'SCAN_BROWSER_ALLOWED_USER_IDS', 'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS')
# Actual peer runCli/createSnapshotter contract, read statically, not executed.
# Every original-RW operation explicitly selects the separate migration profile.
# Capture POST is separate: compare-migrated NEVER silently recaptures it.
MIGRATION_PROFILE = 'preservation-migration-v1'
MIGRATION_PROTOCOL = {
    'capture': ('CAPTURED', ('capture', '--preservation-migration', '/backup/pre'), False),
    'capture-post': ('CAPTURED', ('capture', '--preservation-migration', '/backup/post'), False),
    'plan-migration': ('PLANNED', ('plan-migration', '--preservation-migration', '/backup/pre'), True),
    'apply-migration': ('MIGRATED', ('apply-migration', '--preservation-migration', '/backup/pre'), False),
    'compare-migrated': ('MIGRATION_MATCH', ('compare-migrated', '--preservation-migration', '/backup/pre', '/backup/post'), False),
    'compatibility': ('COMPATIBLE', ('compatibility', '--preservation-migration', '/backup/post'), True),
}
SMALL_PROFILE = 'local-report-summary-small-v1'
SMALL_RAW = 16 * 1024 * 1024
SMALL_IMAGE = 32 * 1024 * 1024
SMALL_MANIFEST = 4 * 1024 * 1024
SMALL_PLAN = 1024 * 1024
SMALL_ROWS = 10000
SMALL_PENDING_SECONDS = 160
# Bracket live timer reads with monotonic time; refuse slow reads/schedule drift.
TIMER_TOLERANCE = 0.05
SMALL_APPLY_ELAPSED = 45
SMALL_GROWTH = 512 * 1024
SMALL_SHM = 128 * 1024
SMALL_CELL_WORK = 8 * MIB
# Private aggregate only. Fixed same-holder command, no Env/DB/app access.
# cgroup-v2 PRIVATE namespace only; unavailable/other layouts refuse.
SMALL_ACCOUNTING_CODE = r'''const fs=require('node:fs');
function read(p,cap){const f=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW),b=Buffer.alloc(cap+1);try{const n=fs.readSync(f,b,0,b.length,0);if(n>cap)throw Error();return b.subarray(0,n).toString('ascii');}finally{fs.closeSync(f);}}
function num(s){if(!/^(0|[1-9][0-9]*)\n?$/.test(s))throw Error();const n=Number(s.trim());if(!Number.isSafeInteger(n))throw Error();return n;}
function free(p){const s=fs.statfsSync(p,{bigint:true}),n=s.bavail*s.bsize;if(n<0n||n>9007199254740991n)throw Error();return Number(n);}
function allocated(){const s=fs.statfsSync('/backup',{bigint:true}),n=(s.blocks-s.bfree)*s.bsize;if(n<0n||n>9007199254740991n)throw Error();return Number(n);}
try{if(read('/proc/self/cgroup',256)!=='0::/\n')throw Error();
 const c=num(read('/sys/fs/cgroup/memory.current',64)),m=num(read('/sys/fs/cgroup/memory.max',64)),sw=num(read('/sys/fs/cgroup/memory.swap.max',64));
 const text=read('/proc/meminfo',65536),a=text.match(/^MemAvailable:\s+([0-9]+) kB$/m),t=text.match(/^MemTotal:\s+([0-9]+) kB$/m);
 if(!a||!t)throw Error();const available=num(a[1])*1024,total=num(t[1])*1024;if(!Number.isSafeInteger(available)||available>total)throw Error();
 process.stdout.write(JSON.stringify({memoryCurrent:c,memoryMax:m,swapMax:sw,vmAvailable:available,authFree:free('/source/auth'),dataFree:free('/source/data'),backupAllocated:allocated()}));
}catch{process.exit(1);}'''
AUTH_INPUT_BYTES = 16384
AUTH_VALUE_BYTES = 4096
EXPORT_BYTES = GIB
EXPORT_FILES = 4113
EXPORT_DIRS = 516
MANIFEST_BYTES = 32 * MIB
SNAPSHOT_LIMITS = {
    'bytes': 256 * MIB, 'files': 2048, 'directories': 256, 'depth': 8,
    'databases': 16, 'objects': 512, 'columns': 256, 'tableRows': 100000,
    'rows': 250000, 'cellBytes': MIB, 'rowBytes': 2 * MIB,
    'exportBytes': 64 * MIB, 'manifestBytes': MANIFEST_BYTES,
    'schemaBytes': 4 * MIB, 'freeBytes': 800 * MIB,
    'backupMs': 30000, 'recoveryMs': 30000,
}
SCRIPT_TARGET = '/app/server/api/.key-preservation.mjs'
# Exact incident/profile bindings, not discovery-derived adoption authority.
RECONCILIATION_REPO = Path('/Users/vsevolod/Documents/startup/diplom')
RETAINED_CREATED_ID = 'd9433f7ed0fc504a3521574668f15b7b3a0e8d283d61b9aa33d1e97187708a4f'
RETIRED_R2_HOLDER_ID = '4dc55f9708f1537fa369ea165aadd050c1f44a6570f0adccb93043d1467d1769'
RECONCILIATION_ORIGINALS = {
    'api': ('5cbe0936a5f09d663a77960749e687fbd41fbef52c8990b063362b9363d3e9ec', 'sha256:487c3909d3eeee08d60840a81c1adeb61c292aee0a31df17b2a8cf92f6dbb58c'),
    'worker': ('016c41e7b3eabcbb08903bbc3c54d657ed92c22813e47fa37d444cb448602b44', 'sha256:8748cbebba753603d79f320c2fb476c46ab676ce12e0aa08bee0021a3e14e57a'),
    'web': ('b84245ef672d172d5513971a57ea91469800846cdf6c59bedceb006b06caa4f4', 'sha256:1659b39c98d5183c91feae78a8d9eb1d4c6ee527d541c1e1d74dfe842adee8c0'),
    'egress': ('2850e2d03d0681482727f7b5d658961ef9ef2aa829b63473f36d8ed3c63f3d35', 'sha256:2b9eff3b381979c82bf42c310fcd7941805d42adeda67c8814143d6503490655'),
    'llm-egress': ('f64639115f21233277ac52db2bd5ceda495203511da87896ff996e8c1ce3a68a', 'sha256:3ccbd5a6c3348b7b1c99e23b29d9bdca485dfd48f690a408a119e06163a59a8d'),
}
RECONCILIATION_CANDIDATES = {
    'api': 'sha256:4b3a3d4b3c2658ec9a36209afcac69eda2b64cef6e055a5e2716e2602e5338d1',
    'worker': 'sha256:891b5adccbe469345cea585e75dc71c6d3bf93405c5a18386795af1b012b314d',
    'web': 'sha256:3d14f3d9e7347a9609fe3ae53b46efd70293aacae64da48c001ed6e826155817',
}
# Never Config/Env, logs or helper execution. This actor is observed, never adopted.
RETAINED_FORMAT = ('{"id":{{json .Id}},"image":{{json .Image}},"name":{{json .Name}},'
    '"status":{{json .State.Status}},"running":{{json .State.Running}},'
    '"paused":{{json .State.Paused}},"restarting":{{json .State.Restarting}},'
    '"oom":{{json .State.OOMKilled}},"dead":{{json .State.Dead}},'
    '"exit":{{json .State.ExitCode}},"restarts":{{json .RestartCount}},'
    '"started":{{json .State.StartedAt}},"finished":{{json .State.FinishedAt}},'
    '"configImage":{{json .Config.Image}},"entry":{{json .Config.Entrypoint}},'
    '"cmd":{{json .Config.Cmd}},"path":{{json .Path}},"args":{{json .Args}},'
    '"labels":{{json .Config.Labels}},"declared":{{json .HostConfig.Mounts}},'
    '"mounts":{{json .Mounts}}}')

# Executed ONLY inside the qualified holder. It hashes private backup files, not
# source DBs; captured stdout remains internal private memory, never agent output.
INVENTORY_CODE = r'''const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const root=process.argv[1];if(!['/backup/pre','/backup/post','/backup/migration'].includes(root))process.exit(1);
let files=0,dirs=0,total=0;const out=[],seen=new Set();
function walk(p,rel,depth){const s=fs.lstatSync(p),id=s.dev+':'+s.ino;
 if(depth>10||seen.has(id)||s.uid!==65532||s.gid!==65532||s.isSymbolicLink())throw Error();seen.add(id);
 if(s.isDirectory()){if((s.mode&4095)!==448||++dirs>516)throw Error();
 out.push({path:rel,kind:'directory'});for(const n of fs.readdirSync(p).sort()){
 if(n==='.'||n==='..'||/[\x00-\x1f\x7f]/.test(n)||Buffer.byteLength(n)>255)throw Error();walk(path.join(p,n),rel?rel+'/'+n:n,depth+1);}}
 else{if(!s.isFile()||s.nlink!==1||(s.mode&4095)!==384||++files>4113||s.size>268435456||(total+=s.size)>1073741824)throw Error();
 const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW),h=crypto.createHash('sha256'),b=Buffer.alloc(1048576);let count=0;
 try{const before=fs.fstatSync(fd);if(before.ino!==s.ino||before.dev!==s.dev)throw Error();let n;
 while((n=fs.readSync(fd,b,0,b.length,null))){count+=n;if(count>s.size)throw Error();h.update(b.subarray(0,n));}
 const after=fs.fstatSync(fd);if(count!==s.size||after.size!==s.size||after.mtimeMs!==s.mtimeMs||after.ctimeMs!==s.ctimeMs)throw Error();}
 finally{fs.closeSync(fd);}out.push({path:rel,kind:'file',bytes:s.size,sha256:h.digest('hex')});}}
try{walk(root,'',0);out.sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);process.stdout.write(JSON.stringify(out));}
catch{process.exit(1);}'''
KEY = 'OPENROUTER_API_KEY'

FREE = {
    'LLM_ENABLED': 'true', 'LLM_ROUTING_APPROVED': 'true',
    'LLM_REGION': 'global', 'LLM_RETENTION': 'no-storage',
    'LLM_POLICY_REVISION': 'openrouter-free-apodex-v2', 'LLM_FREE_ONLY': 'true',
    'LLM_MODEL': 'apodex/apodex-1.1-mini:free', 'LLM_PROVIDER_ALLOWLIST': 'novita/bf16',
    'LLM_REQUEST_BUDGET_USD': '0', 'LLM_INPUT_PRICE_PER_MILLION_USD': '0',
    'LLM_OUTPUT_PRICE_PER_MILLION_USD': '0', 'LLM_REQUEST_PRICE_USD': '0',
    'LLM_TIMEOUT_MS': '30000', 'LLM_REQUEST_BYTES': '262144', 'LLM_RESPONSE_BYTES': '65536',
    'LLM_MAX_FINDINGS': '1000', 'LLM_OUTPUT_TOKENS': '2048',
    'LLM_QUOTA_ENABLED': 'true', 'LLM_QUOTA_REVISION': 'summary-quota-utc-v1',
    'LLM_QUOTA_WINDOW': 'utc-day', 'LLM_QUOTA_USER_INPUT': '262144',
    'LLM_QUOTA_USER_OUTPUT': '16384', 'LLM_QUOTA_USER_COST_USD': '0',
    'LLM_QUOTA_SCAN_INPUT': '65536', 'LLM_QUOTA_SCAN_OUTPUT': '8192',
    'LLM_QUOTA_SCAN_COST_USD': '0', 'LLM_QUOTA_WARNING_PERCENT': '80',
    'LLM_QUOTA_REQUEST_INPUT': '65536', 'LLM_QUOTA_OBSERVATION_TOKENS': '1048576',
    'LLM_QUOTA_OBSERVATION_COST_USD': '1', 'LLM_QUOTA_RECEIPT_MS': '300000',
    'LLM_QUOTA_REPLAY_DAYS': '7', 'LLM_QUOTA_MAX_ROWS': '100000',
    'LLM_QUOTA_DB_BYTES': '67108864', 'LLM_QUOTA_DISK_HEADROOM_BYTES': '134217728',
    'LLM_QUOTA_BUSY_MS': '1000', 'LLM_QUOTA_CLEANUP_BATCH': '256',
    'AUTH_DB_PATH': '/auth/auth.sqlite', 'SCAN_LEDGER_PATH': '/data/ledger.sqlite',
    'SCAN_JWT_ISSUER': PROJECT, 'SCAN_JWT_AUDIENCE': PROJECT,
}
PHASES = {'plan_migration', 'apply_migration', 'migration_match', 'current_compatibility',
          'recreate_pair', 'recreate_web', 'preflight', 'close_ingress', 'drain', 'quiesce', 'holder', 'capture',
          'compatibility', 'export_pre', 'recreate', 'check_api', 'compare', 'export_post', 'cleanup',
          'resume', 'reopen', 'accept'}


class Refusal(Exception):
    """No untrusted text is ever attached to a public exception."""


def need(condition):
    if not condition:
        raise Refusal()


ENV_GATE_SCOPES = ('ENV', 'API_OLD_ENV', 'API_IMAGE_ENV', 'API_SERVICE_ENV',
                   'MODEL_IMAGE_ENV', 'MODEL_SERVICE_ENV', 'MODEL_ACTUAL_ENV')
PREDICATE_IDS = frozenset('''
API_PREP_RUNTIME API_PREP_ACTUAL_ENV API_PREP_IMAGE_ENV API_PREP_SERVICE_ENV API_KEY_ONLY
RUNTIME_ROOT RUNTIME_BUDGET RUNTIME_STRING_UNICODE RUNTIME_DOLLAR_PAIRS
RUNTIME_KEYS RUNTIME_KEY_UNICODE RUNTIME_SCALAR RUNTIME_SIZE RUNTIME_INVERSE
KEY_SHAPE KEY_NONKEY HEALTH_DURATION_TYPE HEALTH_DURATION_FORMAT
MEMORY_NONNEGATIVE MEMORY_TYPE MEMORY_FORMAT
MODEL_RUNTIME MODEL_INPUTS MODEL_CONFIG_INPUTS MODEL_ENV_IMAGE MODEL_ENV_SERVICE MODEL_ENV_ACTUAL MODEL_ENV_MATCH
MODEL_USER MODEL_WORKDIR MODEL_COMMAND MODEL_ENTRYPOINT MODEL_ROOTFS MODEL_CAP_DROP
MODEL_CAP_ADD MODEL_SECURITY_OPTIONS MODEL_PRIVILEGE_DEVICES MODEL_HEALTH_BUILD MODEL_HEALTH_EQUAL
MODEL_TMPFS_BUILD MODEL_TMPFS_ITEM MODEL_TMPFS_TARGET MODEL_TMPFS_EQUAL
MODEL_RESTART_PARSE MODEL_RESTART_NAME MODEL_RESTART_RETRIES
MODEL_MEMORY MODEL_SWAP MODEL_CPU MODEL_PIDS MODEL_IMAGE_VOLUMES MODEL_MOUNT_TYPE
MODEL_MOUNTS_BUILD MODEL_MOUNT_ENTRY MODEL_MOUNTS_ACTUAL MODEL_BIND_OPTIONS MODEL_MOUNTS MODEL_NETWORKS
MODEL_PORTS_BUILD MODEL_PORT_SHAPE MODEL_PORT_ENTRY MODEL_PORT_UNIQUE
MODEL_PORT_BINDINGS MODEL_PORT_SCOPE MODEL_API_COMMAND MODEL_API_VOLUMES
'''.split()) | frozenset(scope + '_' + gate for scope in ENV_GATE_SCOPES
                         for gate in ('DICT_STRINGS', 'LIST_TYPE', 'ENTRY_FORMAT', 'ENTRY_UNIQUE')) | frozenset(
    scope + '_' + gate for scope in ('OLD_POLICY', 'CANDIDATE_POLICY')
    for gate in ('FREE', 'JWT', 'ORIGIN_HISTORY', 'HISTORY_AUTHORITY', 'RUNTIME_LIVE'))


def predicate(observer, gate, operation):
    """Observe fixed IDs only; ENTER precedes evaluation, PASS follows success.

    Return values of the observer are ignored. Observer errors are sanitized and
    fail closed; operation errors retain their existing fail-fast behavior.
    """
    need(gate in PREDICATE_IDS)
    if observer is not None:
        try:
            observer(gate, 'ENTER')
        except BaseException:
            raise Refusal() from None
    result = operation()
    if observer is not None:
        try:
            observer(gate, 'PASS')
        except BaseException:
            raise Refusal() from None
    return result


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result)
        result[key] = value
    return result


def decode(data, cap=2 * MIB):
    need(type(data) is bytes and len(data) <= cap)
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refusal()))
    except (ValueError, UnicodeError, RecursionError):
        raise Refusal() from None


def encoded(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':'), sort_keys=True).encode('ascii') + b'\n'


def env_map(value, observer=None, scope='ENV'):
    need(scope in ENV_GATE_SCOPES)
    if type(value) is dict:
        predicate(observer, scope + '_DICT_STRINGS',
                  lambda: need(all(type(k) is str and type(v) is str for k, v in value.items())))
        return dict(value)
    predicate(observer, scope + '_LIST_TYPE', lambda: need(type(value) is list))
    result = {}
    for item in value:
        predicate(observer, scope + '_ENTRY_FORMAT', lambda: need(type(item) is str and '=' in item))
        key, val = item.split('=', 1)
        predicate(observer, scope + '_ENTRY_UNIQUE', lambda: need(key and key not in result))
        result[key] = val
    return result


def policy(env, observer=None, scope='OLD_POLICY'):
    need(scope in ('OLD_POLICY', 'CANDIDATE_POLICY'))
    predicate(observer, scope + '_FREE', lambda: need(all(env.get(k) == v for k, v in FREE.items())))
    predicate(observer, scope + '_JWT',
              lambda: need(type(env.get('SCAN_JWT_SECRET')) is str and len(env['SCAN_JWT_SECRET'].encode()) >= 32))
    predicate(observer, scope + '_ORIGIN_HISTORY',
              lambda: need(env.get('AUTH_ORIGIN') and env.get('LLM_HISTORY_ENABLED') in (None, 'false')))
    # No new history/runtime authority or live-capture gate may be enabled.
    predicate(observer, scope + '_HISTORY_AUTHORITY',
              lambda: need(not env.get('LLM_HISTORY_AUTHORITY') and not env.get('RUNTIME_DB_PATH')))
    predicate(observer, scope + '_RUNTIME_LIVE', lambda: need(env.get('RUNTIME_LIVE') in (None, 'false')))


def key_only(old, candidate, observer=None):
    policy(old, observer, 'OLD_POLICY')
    policy(candidate, observer, 'CANDIDATE_POLICY')
    predicate(observer, 'KEY_SHAPE',
              lambda: need(type(candidate.get(KEY)) is str and 0 < len(candidate[KEY].encode()) <= 4096))
    predicate(observer, 'KEY_NONKEY', lambda: need({k: v for k, v in old.items() if k != KEY} ==
                                                {k: v for k, v in candidate.items() if k != KEY}))


def dollar_escape(value):
    """Encode a RAW view for comparison; never re-escape Compose config output."""
    if type(value) is str:
        return value.replace('$', '$$')
    if type(value) is list:
        return [dollar_escape(x) for x in value]
    if type(value) is dict:
        need(all('$' not in k for k in value))
        return {k: dollar_escape(v) for k, v in value.items()}
    return value


def compose_runtime_model(serialized, observer=None):
    """Invert ONLY Compose's config-output dollar encoding, once, in memory.

    config.go's raw-JSON dollar replacement also reaches object keys. Our
    supported domain rejects dollar-bearing keys, so typed string traversal is
    equivalent without modifying keys/types or touching inspect/image defaults.
    Serialized output is retained separately for compilation/full roundtrip.
    """
    budget = [65536]

    def unicode_string(value):
        try:
            value.encode('utf-8')
        except UnicodeError:
            raise Refusal() from None

    def walk(value, depth=0):
        budget[0] -= 1
        predicate(observer, 'RUNTIME_BUDGET', lambda: need(depth <= 64 and budget[0] >= 0))
        if type(value) is str:
            predicate(observer, 'RUNTIME_STRING_UNICODE', lambda: unicode_string(value))
            predicate(observer, 'RUNTIME_DOLLAR_PAIRS',
                      lambda: need(all(len(run.group()) % 2 == 0 for run in re.finditer(r'\$+', value))))
            return value.replace('$$', '$')
        if type(value) is list:
            return [walk(item, depth + 1) for item in value]
        if type(value) is dict:
            predicate(observer, 'RUNTIME_KEYS', lambda: need(all(type(key) is str and '$' not in key for key in value)))
            for key in value:
                predicate(observer, 'RUNTIME_KEY_UNICODE', lambda: unicode_string(key))
            return {key: walk(item, depth + 1) for key, item in value.items()}
        predicate(observer, 'RUNTIME_SCALAR', lambda: need(value is None or type(value) in (bool, int) or
                                                        type(value) is float and math.isfinite(value)))
        return value

    predicate(observer, 'RUNTIME_ROOT', lambda: need(type(serialized) is dict))
    runtime = walk(serialized)
    predicate(observer, 'RUNTIME_SIZE', lambda: need(len(encoded(serialized)) <= 2 * MIB))
    predicate(observer, 'RUNTIME_INVERSE', lambda: need(dollar_escape(runtime) == serialized))
    return runtime


def path_metadata(path, *, secret=False, directory=False):
    path = Path(path).absolute()
    # lstat the full ancestry, without reading any private file's contents.
    for ancestor in (*reversed(path.parents), path):
        st = ancestor.lstat()
        need(not stat.S_ISLNK(st.st_mode))
        if ancestor != path:
            need(stat.S_ISDIR(st.st_mode) and not st.st_mode & 0o022)
    st = path.lstat()
    need(st.st_uid == os.geteuid())
    if directory:
        need(stat.S_ISDIR(st.st_mode) and not st.st_mode & 0o022)
    else:
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and not st.st_mode & 0o022)
        if secret:
            need(stat.S_IMODE(st.st_mode) == 0o600 and 0 < st.st_size <= 8192)
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_nlink, st.st_size, st.st_mtime_ns)


def staged_key_metadata(path):
    """Existing input only; recovery/HOLD secrets still require exactly0600."""
    metadata = path_metadata(path)
    need(stat.S_IMODE(metadata[2]) in (0o400, 0o600) and 0 < metadata[5] <= 8192)
    return metadata


def public_source_bytes(path):
    before = path_metadata(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        need((st.st_dev, st.st_ino) == before[:2] and st.st_size <= 2 * MIB)
        data = bytearray()
        while block := os.read(fd, 65536):
            data.extend(block)
            need(len(data) <= 2 * MIB)
        need(path_metadata(path) == before)
        after = os.fstat(fd)
        need((st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns))
        return bytes(data)
    finally:
        os.close(fd)


def public_digest(path):
    return hashlib.sha256(public_source_bytes(path)).hexdigest()


class PinnedReleaseRefusal(Refusal):
    """Only validated attributes from the verified module's exact class map here."""
    def __init__(self, *, fixed_stage=None, fixed_category='PREDICATE_REFUSED'):
        need(fixed_stage is None or type(fixed_stage) is str and fixed_stage in RELEASE_RECHECK_STAGES)
        need(type(fixed_category) is str and fixed_category in RELEASE_RECHECK_CATEGORIES)
        self.fixed_stage, self.fixed_category = fixed_stage, fixed_category
        super().__init__()


class PinnedReleaseGate:
    def __init__(self, gate, refusal_type):
        need(type(refusal_type) is type and issubclass(refusal_type, Exception))
        self._gate, self._refusal_type = gate, refusal_type

    @property
    def sources(self):
        return self._gate.sources

    @property
    def retained(self):
        return self._gate.retained

    def _invoke(self, operation, *args, recheck=False):
        try:
            return operation(*args)
        except BaseException as failure:
            if type(failure) is self._refusal_type:
                stage = getattr(failure, 'fixed_stage', False)
                category = getattr(failure, 'fixed_category', False)
                if recheck:
                    # The gate property can be stale. Export ONLY this failure's
                    # attributes, after exact-type and independent allowlist checks.
                    if (type(stage) is str and stage in RELEASE_RECHECK_STAGES and
                            type(category) is str and category in RELEASE_RECHECK_CATEGORIES):
                        raise PinnedReleaseRefusal(fixed_stage=stage, fixed_category=category) from None
                elif stage is None and category is None:
                    raise PinnedReleaseRefusal() from None
            raise  # Never normalize subclasses, names, text or unrelated/invalid attributes.

    def verify(self, request):
        return self._invoke(self._gate.verify, request)

    def recheck(self, request, seal):
        return self._invoke(self._gate.recheck, request, seal, recheck=True)


def load_release_gate(repo, plan, runner, *, deadline, attempt_id):
    """Execute only captured pinned public module bytes; never import its tests."""
    if not plan.align_api_cve_release:
        return None
    plan.validate()
    need(type(deadline) in (int, float) and math.isfinite(deadline) and
         type(attempt_id) is str and re.fullmatch(r'[a-f0-9]{32}', attempt_id))
    need(deadline <= runner.deadline and deadline > time.monotonic())
    observer = getattr(runner, 'observation', None)
    with observed_stage(observer, 'GATE_ROOT_METADATA'):
        path_metadata(Path(repo) / '.local-auth', directory=True)
    captured = {}
    with observed_stage(observer, 'GATE_SOURCE_PINS'):
        for relative, expected in plan.sources.items():
            data = public_source_bytes(Path(repo) / relative)
            need(hashlib.sha256(data).hexdigest() == expected)
            if relative in RELEASE_VERIFIER_PINS:
                captured[relative] = data
    need(set(captured) == set(RELEASE_VERIFIER_PINS))
    name = '_dip_pinned_preservation_release'
    need(name not in sys.modules)
    spec = importlib.util.spec_from_file_location(name, Path(repo) / RELEASE_VERIFIER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        exec(compile(captured[RELEASE_VERIFIER], str(Path(repo) / RELEASE_VERIFIER), 'exec'), module.__dict__)
        need(callable(module.make_release_gate))
        refusal_type = module.ReleaseRefused
        need(type(refusal_type) is type and issubclass(refusal_type, Exception) and
             refusal_type.__module__ == name)
        need(type(module.RECHECK_STAGES) is frozenset and module.RECHECK_STAGES == RELEASE_RECHECK_STAGES and
             type(module.RECHECK_CATEGORIES) is frozenset and module.RECHECK_CATEGORIES == RELEASE_RECHECK_CATEGORIES)
        try:
            gate = module.make_release_gate(repo, runner, deadline=deadline, attempt_id=attempt_id)
        except BaseException as failure:
            if (type(failure) is refusal_type and getattr(failure, 'fixed_stage', False) is None and
                    getattr(failure, 'fixed_category', False) is None):
                raise PinnedReleaseRefusal() from None
            raise
        need(gate.sources == RELEASE_VERIFIER_PINS and callable(gate.verify) and callable(gate.recheck) and
             gate.retained is None and gate.last_recheck_stage is None)
        return PinnedReleaseGate(gate, refusal_type)
    finally:
        if sys.modules.get(name) is module:
            del sys.modules[name]


def private_write(path, data):
    need(type(data) is bytes)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def sync_directory(path, *, durable=True):
    before = path_metadata(path, directory=True)[:4]
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
    try:
        st = os.fstat(fd)
        need((st.st_dev, st.st_ino, st.st_mode, st.st_uid) == before)
        if durable:
            os.fsync(fd)
        need(path_metadata(path, directory=True)[:4] == before)
    finally:
        os.close(fd)


def backup_inventory(root, *, durable=True, byte_limit=EXPORT_BYTES, deadline=None):
    """Private host copies only; durable=False observes without fsync/certification.

    Never called on source volumes or private env. Both modes retain identical
    metadata, bounds, stability and content checks; neither certifies a PRE export.
    byte_limit only tightens the cumulative pre-hash stat bound. deadline is an
    absolute monotonic deadline, never renewed; None performs no clock reads.
    Checks cannot interrupt a blocked filesystem syscall.
    """
    need(type(byte_limit) is int and 0 <= byte_limit <= EXPORT_BYTES)
    need(deadline is None or (type(deadline) in (int, float) and math.isfinite(deadline)))

    def check_deadline():
        if deadline is not None and time.monotonic() >= deadline:
            raise StageTimeout()

    entries, seen, directories = [], set(), []
    files = total = 0

    def visit(path, relative, depth):
        nonlocal files, total
        check_deadline()
        need(depth <= 10 and len(relative.encode()) <= 4096)
        st = path.lstat()
        identity = (st.st_dev, st.st_ino)
        need(identity not in seen and st.st_uid == os.geteuid() and st.st_gid == os.getegid())
        seen.add(identity)
        if stat.S_ISDIR(st.st_mode):
            need(stat.S_IMODE(st.st_mode) == 0o700 and len(directories) < EXPORT_DIRS)
            directories.append(path)
            entries.append({'path': relative, 'kind': 'directory'})
            with os.scandir(path) as scan:
                names = []
                for item in scan:
                    check_deadline()
                    need(len(names) < EXPORT_FILES + EXPORT_DIRS)
                    names.append(item.name)
            for name in sorted(names):
                need(name not in ('.', '..') and len(name.encode()) <= 255 and
                     not any(ord(c) < 32 or ord(c) == 127 for c in name))
                visit(path / name, relative + '/' + name if relative else name, depth + 1)
            after = path.lstat()
            need((after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_mtime_ns) ==
                 (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_mtime_ns))
        else:
            files += 1
            total += st.st_size
            need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == 0o600)
            need(files <= EXPORT_FILES and st.st_size <= 256 * MIB and total <= byte_limit)
            before = path_metadata(path, secret=False)
            check_deadline()
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                actual = os.fstat(fd)
                need((actual.st_dev, actual.st_ino) == identity)
                sha, size = hashlib.sha256(), 0
                while True:
                    check_deadline()
                    block = os.read(fd, MIB)
                    if not block:
                        break
                    size += len(block)
                    need(size <= st.st_size)
                    sha.update(block)
                need(size == st.st_size and path_metadata(path) == before)
                check_deadline()
                if durable:
                    os.fsync(fd)
                entries.append({'path': relative, 'kind': 'file', 'bytes': size, 'sha256': sha.hexdigest()})
            finally:
                os.close(fd)

    visit(root, '', 0)
    for path in reversed(directories):
        check_deadline()
        if durable:
            sync_directory(path)
        else:
            sync_directory(path, durable=False)
    result = sorted(entries, key=lambda e: e['path'])
    check_deadline()
    return result


def validate_manifest(root, inventory, versions, *, migration=False):
    """Validate the actual R2 manifest, without SQL or public data/hash output."""
    records = {e['path']: e for e in inventory}
    need(len(records) == len(inventory))
    need(records.get('manifest.json', {}).get('kind') == 'file' and
         records['manifest.json']['bytes'] <= MANIFEST_BYTES)
    fd = os.open(root / 'manifest.json', os.O_RDONLY | os.O_NOFOLLOW)
    try:
        data = bytearray()
        while block := os.read(fd, 65536):
            data.extend(block)
            need(len(data) <= MANIFEST_BYTES)
    finally:
        os.close(fd)
    manifest = decode(bytes(data), MANIFEST_BYTES)
    keys = {'format', 'limits', 'entries', 'stores'} | ({'profile'} if migration else set())
    need(type(manifest) is dict and set(manifest) == keys)
    if migration:
        need(manifest['profile'] == MIGRATION_PROFILE)
    need(manifest['format'] == 'stand-state-snapshot-v2' and manifest['limits'] == SNAPSHOT_LIMITS)
    need(type(manifest['entries']) is list and len(manifest['entries']) <= 2304)
    raw_paths = {'raw'}
    database_paths = []
    for entry in manifest['entries']:
        need(type(entry) is dict and type(entry.get('path')) is str)
        relative = entry['path']
        parts = relative.split('/')
        need(parts[0] in ('auth', 'data') and all(p not in ('', '.', '..') for p in parts))
        target = 'raw/' + relative
        need(target not in raw_paths)
        raw_paths.add(target)
        record = records.get(target)
        need(record is not None and record['kind'] == entry.get('kind'))
        need(all(type(entry.get(k)) is int and entry[k] >= 0 for k in ('mode', 'uid', 'gid')))
        need(entry['mode'] <= 0o777 and not entry['mode'] & 0o022)
        if record['kind'] == 'file':
            need(type(entry.get('bytes')) is int and type(entry.get('sha256')) is str and
                 entry['bytes'] == record['bytes'] and entry['sha256'] == record['sha256'])
            need(type(entry.get('sqlite')) is bool)
            if entry['sqlite']:
                database_paths.append(relative)
    need({p for p in records if p == 'raw' or p.startswith('raw/')} == raw_paths)
    need(set(REQUIRED_STORES) <= set(database_paths))
    stores = manifest['stores']
    need(type(stores) is list and 3 <= len(stores) <= 16)
    need([s['path'] for s in stores] == sorted(database_paths))
    for index, store in enumerate(stores):
        need(store['sealed'] == str(index) + '.sqlite')
        sealed = records.get('sealed/' + store['sealed'])
        need(sealed is not None and sealed['kind'] == 'file' and
             sealed['bytes'] == store['bytes'] and sealed['sha256'] == store['sha256'])
        logical = store['logical']
        need(logical['format'] == 'sqlite-all-state-v1' and type(logical['tables']) is list)
        if store['path'] in versions:
            schema = logical['schema']
            expected = versions[store['path']]
            choices = expected if type(expected) is set else {expected}
            need((schema['applicationId'], schema['userVersion']) in
                 {tuple(str(n) for n in pair) for pair in choices})
    need({p for p in records if p == 'sealed' or p.startswith('sealed/')} ==
         {'sealed', *('sealed/' + s['sealed'] for s in stores)})
    need({p.split('/')[0] for p in records if p} == {'manifest.json', 'raw', 'sealed', 'working'})
    # Working files have no manifest hashes: their complete bytes are bound by the
    # separate same-holder inventory, before AND after the host copy.
    return manifest


def private_json(path, cap):
    before = path_metadata(path)
    need(stat.S_IMODE(before[2]) == 0o600 and 0 < before[5] <= cap)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        need((st.st_dev, st.st_ino) == before[:2])
        data = bytearray()
        while block := os.read(fd, min(65536, cap + 1 - len(data))):
            data.extend(block)
            need(len(data) <= cap)
        need(len(data) == before[5] and path_metadata(path) == before)
        return decode(bytes(data), cap)
    finally:
        os.close(fd)


def rounded_inventory(inventory):
    # Conservative per-member allocation allowance, not measured filesystem blocks.
    need(len(inventory) <= 512)
    return sum(((r.get('bytes', 0) + 4095) // 4096 + 1) * 4096 for r in inventory)


def alarm_available():
    need(threading.current_thread() is threading.main_thread() and
         signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0) and
         signal.getsignal(signal.SIGALRM) in (signal.SIG_DFL, signal.SIG_IGN))


def small_physical(manifest, records):
    """Partition bound RAW evidence; peer462 remains checksum/recovery authority."""
    physical, claimed = {}, set()
    for store in manifest['stores']:
        relative, recovery = store['path'], store['recovery']
        base = 'raw/' + relative
        main = records.get(base)
        need(main is not None and main['kind'] == 'file')
        wal, shm = records.get(base + '-wal'), records.get(base + '-shm')
        need(all(r is None or r['kind'] == 'file' for r in (wal, shm)))
        associated = {p for p in records if p.startswith(base + '-')}
        need(associated <= {base + '-wal', base + '-shm'} and (shm is None or wal is not None))
        kind = recovery.get('kind')
        keys = {'format', 'kind', 'pageSize', 'pages'}
        need(kind in ('main', 'empty-wal', 'wal') and
             set(recovery) == keys | ({'frames', 'commits', 'lastCommit'} if kind != 'main' else set()))
        page_size, pages = recovery.get('pageSize'), recovery.get('pages')
        need(type(page_size) is int and page_size in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536) and
             type(pages) is int and pages > 0 and main['bytes'] >= 100 and main['bytes'] % page_size == 0)
        extent = page_size * pages
        need(extent == store['bytes'] and extent <= SMALL_IMAGE)
        if kind == 'main':
            need(wal is None and shm is None and main['bytes'] == extent)
        else:
            need(relative != 'auth/llm-usage.sqlite' and wal is not None)
            frames, commits, last = (recovery[k] for k in ('frames', 'commits', 'lastCommit'))
            need(all(type(n) is int and n >= 0 for n in (frames, commits, last)) and
                 commits <= last <= frames and (commits == 0) is (last == 0))
            if kind == 'empty-wal':
                need(wal['bytes'] == 0 and frames == commits == last == 0)
            else:
                need(wal['bytes'] == 32 + frames * (page_size + 24))
            if commits == 0:
                need(main['bytes'] == extent)
        if relative == 'auth/llm-usage.sqlite':
            need(kind == 'main' and wal is None and shm is None)
        need(shm is None or shm['bytes'] <= SMALL_SHM)
        claimed.add(base)
        claimed.update(associated)
        physical[relative] = {'main': main['bytes'], 'wal': 0 if wal is None else wal['bytes'],
                              'shm': 0 if shm is None else shm['bytes'],
                              'walPresent': wal is not None, 'shmPresent': shm is not None,
                              'pageSize': page_size, 'recovered': extent}
    ordinary = 0
    for path, record in records.items():
        if path.startswith('raw/') and record['kind'] == 'file' and path not in claimed:
            need(not path.endswith(('-wal', '-shm', '-journal')))
            ordinary += record['bytes']
    total = ordinary + sum(p[k] for p in physical.values() for k in ('main', 'wal', 'shm'))
    need(total == sum(r['bytes'] for p, r in records.items() if p.startswith('raw/') and r['kind'] == 'file'))
    return physical, ordinary


def small_snapshot(manifest, inventory, *, post=False):
    """Reject-only aggregate profile; not an alternate SQLite qualifier."""
    need(type(manifest) is dict and manifest.get('profile') == MIGRATION_PROFILE)
    records = {r['path']: r for r in inventory}
    need(len(records) == len(inventory) and records['manifest.json']['bytes'] <= SMALL_MANIFEST)
    sums = {}
    for root, maximum in (('raw', SMALL_IMAGE if post else SMALL_RAW), ('working', SMALL_IMAGE), ('sealed', SMALL_IMAGE)):
        members = [r for r in inventory if r['path'] == root or r['path'].startswith(root + '/')]
        need(sum(r['kind'] == 'file' for r in members) <= 128 and
             sum(r['kind'] == 'directory' for r in members) <= 33)
        need(all(type(r.get('bytes', 0)) is int and r.get('bytes', 0) >= 0 for r in members))
        sums[root] = sum(r.get('bytes', 0) for r in members)
        need(sums[root] <= maximum)
    stores = manifest['stores']
    need(len(stores) == 3 and {s['path'] for s in stores} == set(REQUIRED_STORES))
    physical, ordinary = small_physical(manifest, records)
    extent = rows = row_work = 0
    for store in stores:
        recovery, logical = store['recovery'], store['logical']
        need(recovery.get('format') == 'checked-recovery-v1')
        size, pages = recovery.get('pageSize'), recovery.get('pages')
        need(type(size) is int and size in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536) and
             type(pages) is int and pages > 0)
        extent += size * pages
        need(extent <= SMALL_IMAGE and size * pages == store['bytes'])
        # RAW main/sidecar bytes are distinct from checked recovered/sealed
        # extent. No SQLite opens or substitute WAL checksum verifier here.
        schema = logical['schema']
        need(schema.get('encoding') == 'UTF-8' and len(encoded(schema)) <= 256 * 1024)
        tables = logical['tables']
        need(type(tables) is list and tables and len({t['name'] for t in tables}) == len(tables))
        for table in tables:
            count, columns, hashes = table['rows'], table['columns'], table['rowHashes']
            need(type(count) is int and count >= 0 and type(columns) is list and 0 < len(columns) <= 256 and
                 type(hashes) is list and len(hashes) == count and all(type(h) is str and HEX.fullmatch(h) for h in hashes))
            # Virtual/generated columns can repeat values without corresponding
            # physical payload; reject instead of using the page-derived bound.
            need(all(type(c) is dict and c.get('hidden') == '0' for c in columns))
            rows += count
            need(rows <= SMALL_ROWS)
            # Conservative typed-cell work bound, not plaintext/row inspection.
            row_work += count * (32 * (len(columns) + 1) + 64)
    need(3 * sums['sealed'] + row_work <= SMALL_CELL_WORK)
    allocated = rounded_inventory(inventory)
    need(allocated <= 256 * MIB)
    return {'raw': sums['raw'], 'working': sums['working'], 'sealed': sums['sealed'],
            'rows': rows, 'rowWork': row_work, 'extent': extent, 'allocated': allocated,
                        'physical': physical, 'ordinary': ordinary}


def small_plan(plan, inventory, manifest, pre):
    files = {r['path']: r for r in inventory if r['kind'] == 'file'}
    need(type(plan) is dict and set(files) == {'plan.json', 'auth.sqlite', 'ledger.sqlite'} and
         0 < files['plan.json']['bytes'] <= SMALL_PLAN and
         all(type(r['bytes']) is int and r['bytes'] > 0 for r in files.values()))
    dry = files['auth.sqlite']['bytes'] + files['ledger.sqlite']['bytes']
    need(dry <= SMALL_IMAGE and plan.get('format') == 'preservation-migration-plan-v1' and
         plan.get('profile', {}).get('name') == MIGRATION_PROFILE and
         plan['profile'].get('current') == CURRENT_SOURCE_AGGREGATE)
    need(set(plan) == {'format', 'profile', 'baseline', 'fingerprint', 'auth', 'ledger', 'dryrun'} and
         plan['profile'] == {'name': MIGRATION_PROFILE, 'current': CURRENT_SOURCE_AGGREGATE,
                            'oldAuthSource': 'b39f54808f63e07959ead476bf61a574cd3a4d288d96cbb5035b1bfecb24d4f0',
                            'oldLedgerSource': '9b0b3cce477da38aa91aeba2946a9b1ab334615f9b3f3a5d8273a45b36c14626'})
    need(type(plan['fingerprint']) is str and HEX.fullmatch(plan['fingerprint']) and
         type(plan['dryrun']) is dict and set(plan['dryrun']) == {'auth/auth.sqlite', 'data/ledger.sqlite'} and
         all(type(v) is str and HEX.fullmatch(v) for v in plan['dryrun'].values()))
    auth, ledger = plan['auth'], plan['ledger']
    need(type(auth) is dict and set(auth) == {'createTrusted', 'createBrowser', 'mappings', 'browser'} and
         type(auth['createTrusted']) is bool and type(auth['createBrowser']) is bool and
         type(ledger) is dict and set(ledger) == {'version', 'policies'} and
         type(ledger['version']) is int and ledger['version'] in (13, 14) and
         type(auth['mappings']) is list and type(ledger['policies']) is list)
    need(all(type(r) is list and len(r) == 4 and type(r[0]) is str and
             re.fullmatch(r'[1-9][0-9]{0,18}', r[0]) and int(r[0]) <= 9223372036854775807 and
             type(r[1]) is str and HEX.fullmatch(r[1]) and type(r[2]) is str and
             re.fullmatch(r'[a-f0-9]{32}', r[2]) and type(r[3]) is int and r[3] == 1
             for r in auth['mappings']))
    need(auth['browser'] is None or (type(auth['browser']) is list and len(auth['browser']) == 3 and
         type(auth['browser'][0]) is int and auth['browser'][0] == 1 and
         auth['browser'][1] == plan['fingerprint'] and type(auth['browser'][2]) is str and
         re.fullmatch(r'[a-f0-9]{32}', auth['browser'][2])))
    need(all(type(v) is str and 0 < len(v.encode()) <= 200 for v in ledger['policies']))
    need(len(auth['mappings']) <= SMALL_ROWS and len(ledger['policies']) <= SMALL_ROWS)
    additions = len(auth['mappings']) + int(auth['browser'] is not None) + len(ledger['policies'])
    need(pre['rows'] + additions <= SMALL_ROWS)
    quota = next(s for s in manifest['stores'] if s['path'] == 'auth/llm-usage.sqlite')['bytes']
    # Fixed per-DB growth/frame/SHM allowances, not SQLite allocator maxima.
    projected_image = dry + quota + SMALL_GROWTH
    need(set(pre['modes']) == set(REQUIRED_STORES))
    bounds = {}
    for relative, actual in pre['physical'].items():
        mode, size = pre['modes'][relative], actual['pageSize']
        need(type(mode) is int and mode in (1, 2))
        if relative == 'auth/llm-usage.sqlite':
            need(mode == 1)
            main, wal, shm = actual['main'], 0, 0
        else:
            clone = files['auth.sqlite' if relative == 'auth/auth.sqlite' else 'ledger.sqlite']['bytes']
            main = max(actual['main'], clone) + SMALL_GROWTH // 2
            frames = 2 * ((main + size - 1) // size)
            wal = actual['wal'] + 32 + frames * (size + 24) if mode == 2 else 0
            shm = SMALL_SHM if mode == 2 else 0
        bounds[relative] = {'main': main, 'wal': wal, 'shm': shm, 'mode': mode, 'pageSize': size}
    projected_tree = pre['ordinary'] + sum(b[k] for b in bounds.values() for k in ('main', 'wal', 'shm'))
    need(projected_tree <= SMALL_IMAGE and projected_image <= SMALL_IMAGE and
         3 * projected_image + pre['rowWork'] + additions * 1024 <= SMALL_CELL_WORK)
    # Rounded per-file/directory allowances; future file counts use the caps, not
    # raw payload sums. Same holder has one clone set; host keeps two exports.
    current = pre['allocated'] + rounded_inventory(inventory)
    need(current <= 256 * MIB)
    retained_post = 3 * SMALL_IMAGE + SMALL_MANIFEST + 512 * 4096
    final = current + retained_post + SMALL_PLAN + 256 * 4096
    need(final <= 256 * MIB)
    journals = (2 * (pre['extent'] + projected_image) + 2 * MIB +
                sum(b['wal'] + b['shm'] for b in bounds.values()))
    need(journals <= 128 * MIB)
    return {'finalRetained': final, 'increment': retained_post + 2 * MIB,
            'dryBytes': dry, 'projectedRows': pre['rows'] + additions, 'journalReserve': journals,
            'projectedImage': projected_image, 'projectedRaw': projected_tree,
            'projectedWorking': projected_tree, 'currentRetained': current, 'physicalBounds': bounds}


@dataclass(frozen=True)
class Binding:
    container: str
    image: str

    def validate(self):
        need(HEX.fullmatch(self.container) is not None and IMAGE.fullmatch(self.image) is not None)


@dataclass(frozen=True)
class Plan:
    bindings: dict
    sources: dict
    sqlite_helper: str
    architecture: str = 'arm64'
    startup_evidence: str = ''
    store_versions: dict | None = None
    backup_sandbox_reviewed: bool = False
    old_db_reads_reviewed: bool = False
    current_source_profile: bool = False
    candidate_api_image: str | None = None
    candidate_source_aggregate: str = ''
    candidate_source_evidence: str = ''
    original_worker_profile_reviewed: bool = False
    preservation_migration: bool = False
    additive_migration_authorized: bool = False
    migration_rw_sandbox_authorized: bool = False
    candidate_worker_image: str | None = None
    candidate_web_image: str | None = None
    migration_review_evidence: str = ''
    web_source_review_evidence: str = ''
    align_api_cve_release: bool = False
    release_verifier: str = ''
    release_verifier_test: str = ''
    qualify_release_only: bool = False
    prepare_rollout_only: bool = False
    reconcile_stopped_stand: bool = False
    held_lock_reconciliation_authorized: bool = False
    darwin_host_mnt_helper: bool = False
    successor_r2: bool = False
    successor_r3: bool = False
    successor_r4: bool = False

    @property
    def replaced_roles(self):
        return ('api', 'worker', 'web') if self.preservation_migration else ('api',)

    def selected_image(self, role):
        candidate = getattr(self, 'candidate_' + role + '_image', None)
        return candidate if role in self.replaced_roles and (self.current_source_profile or self.preservation_migration) else self.bindings[role].image

    @property
    def api_image(self):
        return self.selected_image('api')

    @property
    def expected_versions(self):
        if self.preservation_migration:
            return {'auth/auth.sqlite': {(0, 0)}, 'data/ledger.sqlite': {(0, 13), (0, 14)},
                    'auth/llm-usage.sqlite': {(1145655601, 1)}}
        return dict(CURRENT_SOURCE_VERSIONS) if self.current_source_profile else dict(self.store_versions)

    def validate(self):
        need(set(self.bindings) == set(ROLES) and self.architecture == 'arm64')
        for binding in self.bindings.values():
            need(type(binding) is Binding)
            binding.validate()
        need(len({b.container for b in self.bindings.values()}) == len(ROLES))
        need(self.sqlite_helper == HELPER_PATH)
        need(type(self.align_api_cve_release) is bool and type(self.qualify_release_only) is bool and
             type(self.prepare_rollout_only) is bool)
        need(type(self.reconcile_stopped_stand) is bool and type(self.successor_r2) is bool and
             type(self.successor_r3) is bool and type(self.successor_r4) is bool and
             type(self.held_lock_reconciliation_authorized) is bool and type(self.darwin_host_mnt_helper) is bool)
        need(sum((self.successor_r2, self.successor_r3, self.successor_r4)) <= 1)
        need(not (self.successor_r2 or self.successor_r3 or self.successor_r4) or self.reconcile_stopped_stand)
        need(sum((self.qualify_release_only, self.prepare_rollout_only, self.reconcile_stopped_stand)) <= 1)
        if self.reconcile_stopped_stand:
            need(self.preservation_migration and self.align_api_cve_release and
                 self.held_lock_reconciliation_authorized and self.darwin_host_mnt_helper)
            need({r: (b.container, b.image) for r, b in self.bindings.items()} == RECONCILIATION_ORIGINALS)
            need({r: self.selected_image(r) for r in self.replaced_roles} == RECONCILIATION_CANDIDATES)
        else:
            need(not self.held_lock_reconciliation_authorized and not self.darwin_host_mnt_helper)
        need(not (self.qualify_release_only or self.prepare_rollout_only) or
             self.align_api_cve_release and self.preservation_migration)
        extra = ()
        if self.align_api_cve_release:
            need(self.preservation_migration is True)
            need(self.release_verifier == RELEASE_VERIFIER and self.release_verifier_test == RELEASE_VERIFIER_TEST)
            extra = (RELEASE_VERIFIER, RELEASE_VERIFIER_TEST)
            need(all(self.sources.get(p) == pin for p, pin in RELEASE_VERIFIER_PINS.items()))
        else:
            need(self.release_verifier == self.release_verifier_test == '')
        need(set(self.sources) == set((*PUBLIC, HELPER_PATH, HELPER_TEST, *extra)))
        need(all(type(v) is str and HEX.fullmatch(v) for v in self.sources.values()))
        need(self.sources[HELPER_PATH] != REJECTED_HELPER)  # Known corrupt-WAL/schema R1 is not consumable.
        need(type(self.startup_evidence) is str and EVIDENCE.fullmatch(self.startup_evidence))
        need(self.old_db_reads_reviewed is True)
        need(self.backup_sandbox_reviewed is (not self.preservation_migration))
        need(type(self.current_source_profile) is bool and type(self.preservation_migration) is bool)
        need(not (self.current_source_profile and self.preservation_migration))
        if self.preservation_migration:
            need(self.store_versions is None and self.original_worker_profile_reviewed is False)
            need(self.additive_migration_authorized is True and self.migration_rw_sandbox_authorized is True)
            for role in self.replaced_roles:
                image = self.selected_image(role)
                need(type(image) is str and IMAGE.fullmatch(image) and image != self.bindings[role].image)
            need(len({self.selected_image(r) for r in self.replaced_roles}) == 3)
            need(self.candidate_source_aggregate == CURRENT_SOURCE_AGGREGATE)
            for evidence in (self.startup_evidence, self.candidate_source_evidence,
                             self.migration_review_evidence, self.web_source_review_evidence):
                need(type(evidence) is str and EVIDENCE.fullmatch(evidence) and
                     evidence not in ('DIP-ARTF-409', 'DIP-ARTF-455', 'DIP-ARTF-456'))
        elif self.current_source_profile:
            need(self.store_versions is None)  # Explicit modes; no observed=expected fallback.
            need(type(self.candidate_api_image) is str and IMAGE.fullmatch(self.candidate_api_image) and
                 self.candidate_api_image != self.bindings['api'].image)
            need(type(self.candidate_source_aggregate) is str and
                 self.candidate_source_aggregate == CURRENT_SOURCE_AGGREGATE)
            need(type(self.candidate_source_evidence) is str and EVIDENCE.fullmatch(self.candidate_source_evidence))
            need(self.original_worker_profile_reviewed is True)
        else:
            need(self.candidate_api_image is None and self.candidate_source_aggregate == '' and
                 self.candidate_source_evidence == '' and self.original_worker_profile_reviewed is False)
            need(type(self.store_versions) is dict and set(self.store_versions) == set(REQUIRED_STORES))
            for value in self.store_versions.values():
                need(type(value) is tuple and len(value) == 2 and
                     all(type(n) is int and 0 <= n <= 2147483647 for n in value))
        if not self.preservation_migration:
            need(self.additive_migration_authorized is False and self.migration_rw_sandbox_authorized is False and
                 self.candidate_worker_image is None and self.candidate_web_image is None and
                 self.migration_review_evidence == '' and self.web_source_review_evidence == '')


def authority_input(data):
    """Closed private input protocol; neither authority nor its hash is public."""
    value = decode(data, AUTH_INPUT_BYTES)
    need(type(value) is dict and set(value) == set(AUTH_SETTINGS) and
         all(v is None or type(v) is str for v in value.values()))
    for setting in value.values():
        if setting is not None:
            try:
                need('\0' not in setting and len(setting.encode('utf-8')) <= AUTH_VALUE_BYTES)
            except UnicodeError:
                raise Refusal() from None
    return value


def candidate_image_matches(old, candidate, identity, architecture):
    """Code/rootfs may change, image defaults/configuration may not."""
    need(candidate['Id'] == identity and candidate['Os'] == old['Os'] == 'linux' and
         candidate['Architecture'] == old['Architecture'] == architecture and
         candidate.get('Variant') == old.get('Variant'))
    previous, current = copy.deepcopy(old['Config']), copy.deepcopy(candidate['Config'])
    need(type(previous) is dict and type(current) is dict and set(previous) == set(current))
    for config in (previous, current):
        need(config.get('OnBuild') is None or (type(config['OnBuild']) is list and not config['OnBuild']))
        need(not config.get('Volumes'))
        # Some Docker builders retain a parent-image ID inside image Config.
        # Only that validated immutable identity field can vary, never labels/env.
        if 'Image' in config:
            need(config['Image'] in (None, '') or
                 (type(config['Image']) is str and IMAGE.fullmatch(config['Image'])))
            config.pop('Image')
        config['Env'] = env_map(config.get('Env') or [])
        need(KEY not in config['Env'] and 'SCAN_JWT_SECRET' not in config['Env'])
    need(current == previous)


class Runner:
    """Bounded in-memory stdout/stderr; no shell, diagnostics, tracebacks or files."""
    def __init__(self, repo, env, budget=600, *, observation=None):
        self.repo = repo
        self.env = dict(env)
        self.observation = observation
        self.deadline = min(time.monotonic() + budget, observation.deadline) if observation is not None else time.monotonic() + budget

    def __call__(self, args, timeout=30, cap=2 * MIB, input_data=None):
        if self.observation is not None:
            self.observation.check()
            # Preparation read clients retain their15s cap; production observation
            # preserves existing client limits, including the verifier's <=90s.
            if not isinstance(self.observation, ReconciliationObservation) and (
                    tuple(args[:2]) in (('docker', 'inspect'), ('docker', 'info'), ('docker', 'ps')) or
                    tuple(args[:3]) in (('docker', 'image', 'inspect'), ('docker', 'network', 'inspect'),
                                        ('docker', 'volume', 'inspect'), ('docker', 'compose', 'version')) or
                    tuple(args[:2]) == ('docker', 'compose') and 'config' in args):
                timeout = min(timeout, 15)
        private_command = (len(args) in (8, 9) and tuple(args[:3]) == ('docker', 'exec', '-i') and
                           HEX.fullmatch(args[3]) is not None and
                           tuple(args[4:]) in (('node', SCRIPT_TARGET, 'compatibility', '/backup/pre'),
                                              ('node', SCRIPT_TARGET, 'plan-migration', '--preservation-migration', '/backup/pre'),
                                              ('node', SCRIPT_TARGET, 'compatibility', '--preservation-migration', '/backup/post')))
        need((input_data is not None) == private_command)
        if input_data is not None:
            authority_input(input_data)
            need(0 < timeout <= 60 and 0 < cap <= 4096)
        timeout = min(timeout, self.deadline - time.monotonic())
        need(timeout > 0)
        proc = subprocess.Popen(tuple(args), cwd=self.repo, env=self.env,
                                stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True)
        output = bytearray()
        size = 0
        until = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as streams:
                streams.register(proc.stdout, selectors.EVENT_READ, True)
                streams.register(proc.stderr, selectors.EVENT_READ, False)
                offset = 0
                if input_data is not None:
                    os.set_blocking(proc.stdin.fileno(), False)
                    streams.register(proc.stdin, selectors.EVENT_WRITE, None)
                while streams.get_map():
                    remaining = until - time.monotonic()
                    need(remaining > 0)
                    for entry, _ in streams.select(min(remaining, 0.1)):
                        if entry.data is None:
                            try:
                                sent = os.write(entry.fileobj.fileno(), input_data[offset:])
                            except BlockingIOError:
                                continue
                            need(sent > 0)
                            offset += sent
                            if offset == len(input_data):
                                streams.unregister(entry.fileobj)
                                entry.fileobj.close()  # EOF is part of the fixed private protocol.
                            continue
                        block = os.read(entry.fileobj.fileno(), 65536)
                        if not block:
                            streams.unregister(entry.fileobj)
                        else:
                            size += len(block)
                            need(size <= cap)
                            if entry.data:
                                output.extend(block)
                need(input_data is None or offset == len(input_data))
                need(proc.wait(timeout=max(0.01, until - time.monotonic())) == 0)
            if self.observation is not None:
                self.observation.check()
            return bytes(output)
        except BaseException as failure:
            if self.observation is not None:
                timed = time.monotonic() >= until or isinstance(failure, subprocess.TimeoutExpired)
                self.observation.fail(self.observation.stack[-1] if self.observation.stack else 'CONTROLLER_ENTRY',
                                      StageTimeout() if timed else failure)
            # Killing the Docker CLIENT does not prove cancellation of daemon work.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            raise Refusal() from None
        finally:
            if input_data is not None:
                proc.stdin.close()
            proc.stdout.close()
            proc.stderr.close()


def receipt(data, operation):
    need(operation in ('capture', 'compare', 'compatibility'))
    value = decode(data, 4096)
    need(type(value) is dict and set(value) == {'code', 'ok'})
    need(value['ok'] is True and type(value['code']) is str and
         value['code'] == {'capture': 'CAPTURED', 'compare': 'MATCH', 'compatibility': 'COMPATIBLE'}[operation])


def closed_ok(data):
    value = decode(data, 4096)
    need(type(value) is dict and set(value) == {'ok'} and value['ok'] is True)


def duration(value, observer=None):
    predicate(observer, 'HEALTH_DURATION_TYPE', lambda: need(type(value) is str))
    match = re.fullmatch(r'([0-9]+)(ns|us|ms|s|m|h)', value)
    predicate(observer, 'HEALTH_DURATION_FORMAT', lambda: need(match is not None))
    return int(match[1]) * {'ns': 1, 'us': 1000, 'ms': 1000000,
                          's': 1000000000, 'm': 60000000000, 'h': 3600000000000}[match[2]]


def effective_health(service, defaults, observer=None):
    result = copy.deepcopy(defaults.get('Healthcheck') or {})
    value = service.get('healthcheck', {})
    if value.get('disable'):
        return {'Test': ['NONE']}
    for name, target in (('test', 'Test'), ('retries', 'Retries'), ('interval', 'Interval'),
                         ('timeout', 'Timeout'), ('start_period', 'StartPeriod'), ('start_interval', 'StartInterval')):
        if name in value:
            result[target] = duration(value[name], observer) if target not in ('Test', 'Retries') else value[name]
    return {k: v for k, v in result.items() if v != 0}


def memory(value, observer=None):
    if type(value) is int:
        predicate(observer, 'MEMORY_NONNEGATIVE', lambda: need(value >= 0))
        return value
    predicate(observer, 'MEMORY_TYPE', lambda: need(type(value) is str))
    match = re.fullmatch(r'([0-9]+)([kmgt]?)(?:b)?', value.lower())
    predicate(observer, 'MEMORY_FORMAT', lambda: need(match is not None))
    return int(match[1]) * 1024 ** ('kmgt'.index(match[2]) + 1 if match[2] else 0)


def config_identity(record, *, compose_image=None):
    """Compare old/new actual API configuration, excluding only bound identities."""
    config = copy.deepcopy(record['Config'])
    need(config.get('Hostname') in ('', record['Id'][:12]))
    config.pop('Hostname', None)
    config.pop('Image', None)
    config['Env'] = env_map(config['Env'])
    config['Env'].pop(KEY, None)
    labels = config.get('Labels', {})
    if compose_image is not None and 'com.docker.compose.image' in labels:
        need(labels['com.docker.compose.image'] == compose_image)
        labels.pop('com.docker.compose.image')  # Only the verified old/new image identity changes.
    for name in ('com.docker.compose.config-hash', 'com.docker.compose.project.config_files',
                 'com.docker.compose.project.working_dir'):
        labels.pop(name, None)
    return {'Config': config, 'HostConfig': record['HostConfig'],
            'mounts': mount_identity(record), 'networks': network_identity(record),
            'Path': record.get('Path'), 'Args': record.get('Args')}


def mount_identity(record):
    return sorted((m['Type'], m.get('Name', ''), m['Source'], m['Destination'],
                   m['RW'], m.get('Propagation', '')) for m in record['Mounts'])


def full_mount_entries(mounts):
    """Ignore only outer order; retain every field, literal value and duplicate."""
    need(type(mounts) is list and all(type(mount) is dict for mount in mounts))
    return sorted(encoded(mount) for mount in mounts)


def protected_store_touch(mount, volumes):
    """Original literal named/direct/ancestor/descendant overlap; not an access grant."""
    source = mount.get('Source', '')
    return mount.get('Name') in VOLUMES.values() or any(
        source == v['Mountpoint'] or source.startswith(v['Mountpoint'].rstrip('/') + '/') or
        bool(source.startswith('/') and v['Mountpoint'].startswith(source.rstrip('/') + '/'))
        for v in volumes.values())


def release_mount(record):
    """Exact long-form API/worker release bind; no path resolution/adoption."""
    mounts, host = record['Mounts'], record['HostConfig']
    need(type(mounts) is list and type(host.get('Mounts')) is list and not host.get('Binds'))
    actual = [v for v in mounts if v.get('Destination') == '/opt/release']
    configured = [v for v in host['Mounts'] if v.get('Target') == '/opt/release']
    need(len(actual) == len(configured) == 1)
    actual, configured = actual[0], configured[0]
    need(actual['Type'] == configured['Type'] == 'bind' and actual['RW'] is False and
         configured.get('ReadOnly') is True and actual['Source'] == configured['Source'])
    source = actual['Source']
    need(type(source) is str and source.startswith('/') and source != '/' and
         str(Path(source)) == source and '..' not in Path(source).parts and
         not any(ord(c) < 32 or ord(c) == 127 for c in source))
    return actual, configured


def release_alignment(model, old):
    """Shape/provenance prerequisites ONLY; this is not release authentication."""
    runtime = compose_runtime_model(model)
    services = runtime['services']
    selected = []
    values = []
    for role in ('api', 'worker'):
        binds = [v for v in services[role]['volumes'] if v['type'] == 'bind']
        release = [v for v in binds if v['target'] == '/opt/release']
        need(len(release) == 1 and len(binds) == (1 if role == 'api' else 2))
        entry = release[0]
        need(entry.get('read_only') is True and type(entry.get('bind')) is dict and
             set(entry['bind']) <= {'create_host_path'} and
             ('create_host_path' not in entry['bind'] or entry['bind']['create_host_path'] is False))
        selected.append(entry['source'])
        actual, _ = release_mount(old[role])
        if role == 'worker':
            need(actual['Source'] == entry['source'])
            cache = [v for v in binds if v['target'] == '/tmp/trivy/db']
            need(len(cache) == 1 and cache[0]['source'] == entry['source'] + '/db' and
                 cache[0].get('read_only') is True)
            actual_cache = [v for v in old[role]['Mounts'] if v['Destination'] == '/tmp/trivy/db']
            need(len(actual_cache) == 1 and actual_cache[0]['Type'] == 'bind' and
                 actual_cache[0]['Source'] == cache[0]['source'] and actual_cache[0]['RW'] is False)
        keys = ('SCAN_VULN_ENABLED', 'SCAN_VULN_RELEASE_DIR', 'SCAN_VULN_MANIFEST_DIGEST',
                'SCAN_VULN_ARTIFACT_SHA256')
        actual_env = env_map(old[role]['Config']['Env'])
        modeled_env = env_map(services[role]['environment'])
        current = {k: actual_env[k] for k in keys}
        need(current == {k: modeled_env[k] for k in keys} and
             current[keys[0]] == 'true' and current[keys[1]] == '/opt/release' and
             IMAGE.fullmatch(current[keys[2]]) and HEX.fullmatch(current[keys[3]]))
        values.append(current)
    need(selected[0] == selected[1] and values[0] == values[1])
    original, _ = release_mount(old['api'])
    need(original['Source'] != selected[0])  # Explicit change, not a general bypass.
    return {'source': selected[0], 'old_source': original['Source'],
            'manifest': values[0]['SCAN_VULN_MANIFEST_DIGEST'],
            'artifact': values[0]['SCAN_VULN_ARTIFACT_SHA256']}


def aligned_config_identity(record, *, compose_image, source):
    # Validate before masking only the two source fields; never all of HostConfig.
    actual, configured = release_mount(record)
    need(actual['Source'] == configured['Source'] == source)
    view = copy.deepcopy(record)
    actual, configured = release_mount(view)
    actual['Source'] = configured['Source'] = '<approved-api-release-source>'
    return config_identity(view, compose_image=compose_image)


def network_identity(record):
    return {name: value['NetworkID'] for name, value in record['NetworkSettings']['Networks'].items()}


class Controller:
    def __init__(self, repo, plan, run, *, sleeper=time.sleep, env=None, release_gate=None, release_attempt_id=None,
                 observation=None):
        self.repo = Path(repo).absolute()
        self.root = self.repo / '.local-auth'
        self.plan = plan
        self.run = run
        self.observation = observation
        self.sleep = sleeper
        self.env = dict(os.environ if env is None else env)
        self.phase = 'preflight'
        self.touched = False
        self.old = {}
        self.images = {}
        self.volumes = {}
        self.networks = {}
        self.new_api = None
        self.helper_ids = set()
        self.helper_names = set()
        self.helper_id = None
        self.helper_name = None
        self.holder_started = None
        self.helper_removed = False
        self.exports = set()
        self.lock_capability = None
        self.lock_identity = None
        self.hold_requested = False
        self.hold_identity = None
        self.backup = None
        self.secret_stats = {}
        self.daemon = None
        self.compiled = None
        self.base_command = None
        self.compiled_metadata = None
        self.selected = None
        self.candidate_image = None
        self.observed_versions = None
        self.compatibility_holder = None
        self.new_roles = {}
        self.candidate_images = {}
        self.export_inventories = {}
        self.material_exports = set()
        self.migration_planned = False
        self.migration_matched = False
        self.migration_compatible = False
        self.replacement_attempted = set()
        self.pending_deadline = None
        self.pending_runner_deadline = None
        self.pending_alarm_handler = None
        self.previous_alarm_handler = None
        self.small_projection = None
        self.small_modes = None
        self.cleanup_deadline = None
        self.owned_timer_expiry = None
        self.owned_timer_expired = False
        self.timer_installation_failed = False
        self.timer_ownership_lost = False
        self.release_gate = release_gate  # main injects ONLY the captured-source pinned factory result.
        self.release_attempt_id = release_attempt_id
        self.release_verification_attempted = False
        self.release_retained = None
        self.release_binding = None
        self.release_seal = None
        self.release_request = None
        self.prior_hold_metadata = None
        self.prior_reconciliation_hold_metadata = None
        self.prior_r2_hold_metadata = None
        self.prior_r3_hold_metadata = None
        self.reconciliation_capability = None
        self.reconciliation_pid = None
        self.retained_created_metadata = None
        self.holder_journal_metadata = None

    @property
    def coordination_path(self):
        if self.plan.successor_r4:
            need(self.plan.reconcile_stopped_stand and not (self.plan.successor_r2 or self.plan.successor_r3))
            return self.root / '.key-preservation-reconcile-r4.lock'
        if self.plan.successor_r3:
            need(self.plan.reconcile_stopped_stand and not self.plan.successor_r2)
            return self.root / '.key-preservation-reconcile-r3.lock'
        if self.plan.successor_r2:
            need(self.plan.reconcile_stopped_stand)
            return self.root / '.key-preservation-reconcile-r2.lock'
        return self.root / ('.key-preservation-reconcile.lock' if self.plan.reconcile_stopped_stand
                            else '.trivy-refresh.lock')

    def prior_hold_unchanged(self):
        need(self.plan.reconcile_stopped_stand and self.prior_hold_metadata is not None)
        lock = self.root / '.trivy-refresh.lock'
        need((path_metadata(lock, directory=True),
              path_metadata(lock / 'KEY_ACTIVATION_HOLD.json', secret=True)) == self.prior_hold_metadata)
        if self.plan.successor_r2 or self.plan.successor_r3 or self.plan.successor_r4:
            with self.stage('PRIOR_RECONCILIATION_HOLD_STABILITY'):
                need(self.prior_reconciliation_hold_metadata is not None)
                prior = self.root / '.key-preservation-reconcile.lock'
                need((path_metadata(prior, directory=True),
                      path_metadata(prior / 'KEY_ACTIVATION_HOLD.json', secret=True)) ==
                     self.prior_reconciliation_hold_metadata)
        if self.plan.successor_r3 or self.plan.successor_r4:
            with self.stage('PRIOR_R2_HOLD_STABILITY'):
                need(self.prior_r2_hold_metadata is not None)
                prior = self.root / '.key-preservation-reconcile-r2.lock'
                need((path_metadata(prior, directory=True),
                      path_metadata(prior / 'KEY_ACTIVATION_HOLD.json', secret=True)) == self.prior_r2_hold_metadata)
        if self.plan.successor_r4:
            with self.stage('PRIOR_R3_HOLD_STABILITY'):
                need(self.prior_r3_hold_metadata is not None)
                prior = self.root / '.key-preservation-reconcile-r3.lock'
                need((path_metadata(prior, directory=True),
                      path_metadata(prior / 'KEY_ACTIVATION_HOLD.json', secret=True)) == self.prior_r3_hold_metadata)

    @contextmanager
    def coordination(self):
        if not self.plan.reconcile_stopped_stand:
            with observed_refresh_lock(self.root, self.observation) as capability:
                yield capability
            return
        # Separate express authority; NEVER register, empty, rename or remove the prior lock.
        with self.stage('LOCK_ENTER'):
            with self.stage('RECONCILIATION_PROFILE'):
                need(self.repo == RECONCILIATION_REPO and sys.platform == 'darwin')
            prior = self.root / '.trivy-refresh.lock'
            with self.stage('PRIOR_LOCK_METADATA'):
                prior_lock = path_metadata(prior, directory=True)
            with self.stage('PRIOR_HOLD_METADATA'):
                prior_marker = path_metadata(prior / 'KEY_ACTIVATION_HOLD.json', secret=True)
            self.prior_hold_metadata = (prior_lock, prior_marker)
            with self.stage('PRIOR_LOCK_MODE'):
                need(stat.S_IMODE(self.prior_hold_metadata[0][2]) == 0o700)
            if self.plan.successor_r2 or self.plan.successor_r3 or self.plan.successor_r4:
                prior_reconciliation = self.root / '.key-preservation-reconcile.lock'
                with self.stage('PRIOR_RECONCILIATION_LOCK_METADATA'):
                    previous_lock = path_metadata(prior_reconciliation, directory=True)
                with self.stage('PRIOR_RECONCILIATION_HOLD_METADATA'):
                    previous_marker = path_metadata(prior_reconciliation / 'KEY_ACTIVATION_HOLD.json', secret=True)
                self.prior_reconciliation_hold_metadata = (previous_lock, previous_marker)
                with self.stage('PRIOR_RECONCILIATION_LOCK_MODE'):
                    need(stat.S_IMODE(previous_lock[2]) == 0o700)
            if self.plan.successor_r3 or self.plan.successor_r4:
                prior_r2 = self.root / '.key-preservation-reconcile-r2.lock'
                with self.stage('PRIOR_R2_LOCK_METADATA'):
                    r2_lock = path_metadata(prior_r2, directory=True)
                with self.stage('PRIOR_R2_HOLD_METADATA'):
                    r2_marker = path_metadata(prior_r2 / 'KEY_ACTIVATION_HOLD.json', secret=True)
                self.prior_r2_hold_metadata = (r2_lock, r2_marker)
                with self.stage('PRIOR_R2_LOCK_MODE'):
                    need(stat.S_IMODE(r2_lock[2]) == 0o700)
            if self.plan.successor_r4:
                prior_r3 = self.root / '.key-preservation-reconcile-r3.lock'
                with self.stage('PRIOR_R3_LOCK_METADATA'):
                    r3_lock = path_metadata(prior_r3, directory=True)
                with self.stage('PRIOR_R3_HOLD_METADATA'):
                    r3_marker = path_metadata(prior_r3 / 'KEY_ACTIVATION_HOLD.json', secret=True)
                self.prior_r3_hold_metadata = (r3_lock, r3_marker)
                with self.stage('PRIOR_R3_LOCK_MODE'):
                    need(stat.S_IMODE(r3_lock[2]) == 0o700)
            with self.stage('RECONCILIATION_LOCK_CREATE'):
                self.coordination_path.mkdir(mode=0o700)  # Exclusive: pre-existing reconciliation refuses.
            with self.stage('RECONCILIATION_LOCK_MODE'):
                os.chmod(self.coordination_path, 0o700)  # Only the freshly created OWN directory.
            with self.stage('RECONCILIATION_LOCK_IDENTITY'):
                self.lock_identity = path_metadata(self.coordination_path, directory=True)[:4]
            with self.stage('RECONCILIATION_CAPABILITY'):
                self.reconciliation_capability = object()
                self.reconciliation_pid = os.getpid()
                self.lock_capability = self.reconciliation_capability
            # Keep failed preparation exclusive too; marker exists before verifier/create clients.
            self.hold()
        try:
            with self.stage('PRIOR_HOLD_STABILITY'):
                self.prior_hold_unchanged()
            yield self.reconciliation_capability
        except BaseException as failure:
            if self.observation is not None:
                self.observation.fail('COORDINATION_BODY', failure)
            raise
        finally:
            with observed_teardown_stage(self.observation, 'LOCK_EXIT'):
                self.owned_lock()
                if not self.hold_requested:
                    self.coordination_path.rmdir()  # Only THIS attempt's empty, unchanged OWN lock.
                    sync_directory(self.root)
                self.reconciliation_capability = None
                self.reconciliation_pid = None

    def retained_created_unchanged(self):
        if not self.plan.reconcile_stopped_stand:
            return
        self.prior_hold_unchanged()
        value = decode(self.run(('docker', 'inspect', '--type', 'container', '--format',
                                 RETAINED_FORMAT, RETAINED_CREATED_ID), cap=65536), 65536)
        need(type(value) is dict and value['id'] == RETAINED_CREATED_ID and
             value['image'] == value['configImage'] == self.plan.bindings['api'].image and
             value['status'] == 'created')
        need(all(type(value[k]) is bool and value[k] is False
                 for k in ('running', 'paused', 'restarting', 'oom', 'dead')))
        need(all(type(value[k]) is int and value[k] == 0 for k in ('exit', 'restarts')) and
             value['started'] == value['finished'] == '0001-01-01T00:00:00Z')
        need(value['entry'] == ['node'] and value['cmd'] == value['args'] == ['-e', HOLDER_CODE] and
             value['path'] == 'node' and type(value['name']) is str and
             re.fullmatch(r'/dip-key-snapshot-[a-f0-9]{32}', value['name']))
        labels = dict(self.images['api']['Config'].get('Labels') or {})
        own_label = value['labels'].get('dip.key-preservation')
        need(type(own_label) is str and re.fullmatch(r'key-preservation-[a-z0-9_]{8}', own_label))
        need(value['labels'] == dict(labels, **{'dip.key-preservation': own_label}))
        # Only the outer actual-mount array is order-independent. Everything else,
        # including declared mounts and their order, remains complete and type-sensitive.
        identity = (full_mount_entries(value['mounts']),
                    encoded({key: entry for key, entry in value.items() if key != 'mounts'}))
        if self.retained_created_metadata is None:
            self.retained_created_metadata = identity
        else:
            need(identity == self.retained_created_metadata)

    def stage(self, gate):
        return observed_stage(self.observation, gate)

    def alignment_shape(self, model):
        need(self.plan.align_api_cve_release and self.plan.preservation_migration)
        binding = release_alignment(model, self.old)
        if self.release_binding is not None:
            need(binding == self.release_binding)
        else:
            self.release_binding = binding
        return binding

    def release_verification_request(self, model):
        binding = self.alignment_shape(model)
        return {'version': 1, 'actor_image': self.plan.api_image,
                'candidate_worker_image': self.plan.candidate_worker_image,
                'source': binding['source'], 'manifest': binding['manifest'], 'artifact': binding['artifact'],
                'policy': 'cve-db-updated-at-14d-v2',
                'trusted_spki_sha256': 'd75c6f6b2384de68978090fc837387ab4f3e878ee004bccf27ea98a84fbee078',
                'source_aggregate': self.plan.candidate_source_aggregate,
                'verifier_sources': {p: self.plan.sources[p] for p in
                                     (self.plan.release_verifier, self.plan.release_verifier_test)}}

    def verify_release(self, model):
        if not self.plan.align_api_cve_release:
            return
        need(self.release_gate is not None and self.release_seal is None)
        self.verify_sources()
        request = self.release_verification_request(model)
        need(self.release_gate.sources == request['verifier_sources'])
        self.release_verification_attempted = True
        seal = self.release_gate.verify(copy.deepcopy(request))
        need(type(seal) is bytes and len(seal) == 32)
        self.release_request, self.release_seal = copy.deepcopy(request), seal

    def retain_release_failure(self):
        if not self.release_verification_attempted or self.release_gate is None:
            return
        retained = getattr(self.release_gate, 'retained', None)
        if retained is None:
            return
        # Set uncertainty before filesystem work; even a failed durable write is
        # not authority to retry or to print/adopt the verifier's private identity.
        self.release_retained = True
        # Keep the OWN coordination lock even if identity validation or later
        # recovery persistence fails; those failures must not enable a retry.
        if not self.hold_requested:
            self.hold()
        need(type(retained) is dict and set(retained) == {'name', 'id'} and
             type(self.release_attempt_id) is str and re.fullmatch(r'[a-f0-9]{32}', self.release_attempt_id) and
             retained['name'] == 'dip-preservation-release-' + self.release_attempt_id and
             (retained['id'] is None or type(retained['id']) is str and HEX.fullmatch(retained['id'])))
        if self.backup is None:
            self.backup = Path(tempfile.mkdtemp(prefix='key-preservation-', dir=self.root))
            os.chmod(self.backup, 0o700)
        private_write(self.backup / 'release-verifier-retained.json', encoded(retained))
        sync_directory(self.backup)

    def recheck_release(self):
        if not self.plan.align_api_cve_release:
            return
        need(self.release_gate is not None and type(self.release_seal) is bytes and self.release_seal)
        self.verify_sources()
        request = self.release_verification_request(self.model)
        need(request == self.release_request and self.release_gate.sources == request['verifier_sources'])
        need(self.release_gate.recheck(copy.deepcopy(request), self.release_seal) is None)

    def original_model_matches(self, role, model, record, observer=None, *, shape_only=False):
        if role == 'api' and self.plan.align_api_cve_release:
            binding = self.alignment_shape(model)
            if not shape_only:
                need(self.release_gate is not None and self.release_seal is not None)
            # Compare every original predicate; substitute ONLY the approved source
            # in a transient actual projection, never compiled output or old capture.
            record = copy.deepcopy(record)
            actual, _ = release_mount(record)
            need(actual['Source'] == binding['old_source'])
            actual['Source'] = binding['source']
        self.model_matches(role, model, record, observer=observer)

    def verify_sources(self):
        for relative, expected in self.plan.sources.items():
            need(public_digest(self.repo / relative) == expected)

    def verify_candidate_image(self, initial=False):
        need(self.plan.current_source_profile or self.plan.preservation_migration)
        for role in self.plan.replaced_roles:
            identity = self.plan.selected_image(role)
            records = decode(self.run(('docker', 'image', 'inspect', identity)))
            need(type(records) is list and len(records) == 1)
            candidate_image_matches(self.images[role], records[0], identity, self.plan.architecture)
            if initial:
                need(role not in self.candidate_images)
                self.candidate_images[role] = records[0]
            else:
                need(records[0] == self.candidate_images[role])
        self.candidate_image = self.candidate_images['api']
        # Image/source-aggregate/review identifiers are mandatory trust bindings.
        # Parent verifies the real proof's contents/authority; no fabricated receipt,
        # Docker label or artifact-shaped string constitutes independent acceptance.

    def compatibility_input(self):
        need(self.plan.current_source_profile or self.plan.preservation_migration)
        old = env_map(self.old['api']['Config']['Env'])
        candidate = env_map(self.candidate_image['Config'].get('Env') or [])
        candidate.update(env_map(compose_runtime_model(self.model)['services']['api']['environment']))
        key_only(old, candidate)
        settings = {key: old.get(key) for key in AUTH_SETTINGS}
        need(settings == {key: candidate.get(key) for key in AUTH_SETTINGS})
        data = encoded(settings)  # Raw null/string semantics; NO Python authority hash.
        authority_input(data)
        return data

    def compatibility(self):
        need(self.plan.current_source_profile and self.compatibility_holder is None)
        self.stable({'egress', 'llm-egress'})
        self.verify_sources()
        self.secrets_metadata()
        self.verify_candidate_image()
        self.writers(set())
        self.holder_budget(60)
        data = self.compatibility_input()
        output = self.run(('docker', 'exec', '-i', self.helper_id, 'node', SCRIPT_TARGET,
                           'compatibility', '/backup/pre'), timeout=60, cap=4096, input_data=data)
        receipt(output, 'compatibility')
        self.qualify_holder(True)
        self.verify_sources()
        self.secrets_metadata()
        self.writers(set())
        self.compatibility_holder = self.helper_id  # THIS fresh holder/pre only, never a cached pass.

    def secrets_metadata(self):
        paths = ('server/.env.local', 'server/.env.openrouter.local', '.local-auth/stand.env')
        current = {p: (staged_key_metadata(self.repo / p) if p == 'server/.env.openrouter.local'
                       else path_metadata(self.repo / p, secret=True)) for p in paths}
        if self.secret_stats:
            need(current == self.secret_stats)
        else:
            self.secret_stats = current

    def inspect(self, ids):
        need(ids and all(HEX.fullmatch(i) for i in ids))
        data = decode(self.run(('docker', 'inspect', '--type', 'container', *ids)))
        need(type(data) is list and len(data) == len(ids))
        need({r['Id'] for r in data} == set(ids))
        return {r['Id']: r for r in data}

    def bound(self, role, record, running):
        binding = self.plan.bindings[role]
        need(record['Id'] == binding.container and record['Image'] == binding.image)
        need(record['Name'] == f'/{PROJECT}-{role}-1')
        labels = record['Config']['Labels']
        need(labels.get('com.docker.compose.project') == PROJECT and
             labels.get('com.docker.compose.service') == role)
        need(type(record['State']['Running']) is bool and record['State']['Running'] is running)
        need(not record['State'].get('Paused') and not record['State'].get('Restarting'))
        if not running:
            need(record['HostConfig']['RestartPolicy']['Name'] in ('no', 'on-failure', ''))

    def stable(self, running):
        records = self.inspect([b.container for role, b in self.plan.bindings.items()
                                if role not in self.new_roles and (role != 'api' or self.new_api is None)])
        for role, binding in self.plan.bindings.items():
            if role in self.new_roles or (role == 'api' and self.new_api is not None):
                continue
            record = records[binding.container]
            self.bound(role, record, role in running)
            if role == 'api' and role in running:
                need(record['State'].get('Health', {}).get('Status') == 'healthy')
            need(record['Path'] == self.old[role]['Path'] and record['Args'] == self.old[role]['Args'])
            need(record['Config'] == self.old[role]['Config'] and
                 record['HostConfig'] == self.old[role]['HostConfig'] and
                 mount_identity(record) == mount_identity(self.old[role]) and
                 network_identity(record) == network_identity(self.old[role]))
        if self.plan.preservation_migration:
            for role in self.new_roles:
                self.check_new_role(role, role in running)
        elif self.new_api is not None:
            self.check_new_api('api' in running)
        self.resources()

    def resources(self):
        names = tuple(VOLUMES.values())
        volumes = decode(self.run(('docker', 'volume', 'inspect', *names)))
        need(type(volumes) is list and len(volumes) == 2)
        current = {v['Name']: v for v in volumes}
        need(set(current) == set(names))
        if self.volumes:
            need(current == self.volumes)
        else:
            for v in volumes:
                need(v.get('Driver') == 'local' and v.get('Scope') == 'local' and not v.get('Options'))
                need(v.get('Labels', {}).get('com.docker.compose.project') == PROJECT)
            self.volumes = current
        if self.networks:
            networks = decode(self.run(('docker', 'network', 'inspect', *self.networks)))
            need({n['Id']: {k: v for k, v in n.items() if k != 'Containers'} for n in networks} == self.networks)

    def container_census(self):
        raw = self.run(('docker', 'ps', '-a', '--no-trunc', '--format', '{{.ID}}'), cap=MIB)
        ids = raw.decode('ascii').splitlines()
        need(len(ids) <= (32 if self.plan.reconcile_stopped_stand else 512) and
             len(set(ids)) == len(ids) and all(HEX.fullmatch(i) for i in ids))
        return ids

    def require_retired_r2_absent(self, ids=None):
        if not (self.plan.successor_r3 or self.plan.successor_r4):
            return
        with self.stage('RETIRED_R2_ABSENCE'):
            if ids is None:
                with self.stage('RETIRED_R2_CENSUS'):
                    ids = self.container_census()
            need(RETIRED_R2_HOLDER_ID not in ids)

    def writers(self, permitted):
        with self.stage('RETAINED_CREATED'):
            self.retained_created_unchanged()
        # All containers, including foreign ones, get metadata-only projection:
        # never read their Config.Env or full inspect output.
        with self.stage('WRITER_DAEMON_READ'):
            daemon = decode(self.run(('docker', 'info', '--format', '{{json .ID}}'), cap=4096))
        with self.stage('WRITER_DAEMON_SHAPE'):
            need(type(daemon) is str and daemon)
        with self.stage('WRITER_DAEMON_STABILITY'):
            if self.daemon is None:
                self.daemon = daemon
            need(daemon == self.daemon)
        holder = None
        holder_mounts = None
        if self.helper_id is not None and not self.helper_removed:
            with self.stage('WRITER_HOLDER_QUALIFY'):
                qualified = self.qualify_holder(running=True)
                holder, holder_mounts = qualified['Id'], full_mount_entries(qualified['Mounts'])
        with self.stage('WRITER_CENSUS'):
            ids = self.container_census()
        self.require_retired_r2_absent(ids)
        with self.stage('WRITER_HOLDER_PRESENCE'):
            need(holder is None or holder in ids)
        fmt = ('{"id":{{json .Id}},"running":{{json .State.Running}},'
               '"mounts":{{json .Mounts}}}')
        for start in range(0, len(ids), 32):
            with self.stage('WRITER_BATCH_READ'):
                rows = self.run(('docker', 'inspect', '--type', 'container', '--format', fmt,
                                 *ids[start:start + 32]), cap=2 * MIB).splitlines()
            with self.stage('WRITER_BATCH_ROWCOUNT'):
                need(len(rows) == len(ids[start:start + 32]))
            seen = set()
            for row in rows:
                with self.stage('WRITER_ROW_PARSE'):
                    item = decode(row)
                with self.stage('WRITER_ROW_SCHEMA'):
                    need(set(item) == {'id', 'running', 'mounts'} and type(item['running']) is bool)
                with self.stage('WRITER_ROW_ID_UNIQUE'):
                    need(item['id'] in ids[start:start + 32] and item['id'] not in seen)
                    seen.add(item['id'])
                if item['id'] == holder:
                    with self.stage('WRITER_HOLDER_MOUNTS'):
                        need(item['running'] is True and full_mount_entries(item['mounts']) == holder_mounts)
                for mount in item['mounts']:
                    with self.stage('WRITER_TOUCH_CLASSIFY'):
                        touches = protected_store_touch(mount, self.volumes)
                    if touches and item['running']:
                        with self.stage('WRITER_ACTIVE_ACCESS'):
                            if item['id'] == holder:
                                with self.stage('WRITER_ACTIVE_HOLDER_ACCESS'):
                                    need(mount['RW'] is self.plan.preservation_migration and mount['Type'] == 'volume' and
                                         mount.get('Name') in VOLUMES.values())
                            else:
                                with self.stage('WRITER_ACTIVE_OTHER_ACCESS'):
                                    need(item['id'] in permitted and mount['RW'] is True)
        # Instantaneous observation, NOT daemon/host-wide continuous exclusion.

    def model_matches(self, role, model, record, observer=None):
        def check(gate, operation):
            return predicate(observer, gate, operation)

        model = check('MODEL_RUNTIME', lambda: compose_runtime_model(model, observer))
        service, image = check('MODEL_INPUTS', lambda: (model['services'][role], self.images[role]))
        expected_env = check('MODEL_ENV_IMAGE', lambda: env_map(image['Config'].get('Env') or [], observer, 'MODEL_IMAGE_ENV'))
        expected_env.update(check('MODEL_ENV_SERVICE', lambda: env_map(service.get('environment', {}), observer, 'MODEL_SERVICE_ENV')))
        actual = check('MODEL_ENV_ACTUAL', lambda: env_map(record['Config']['Env'], observer, 'MODEL_ACTUAL_ENV'))
        if role == 'api':
            check('MODEL_ENV_MATCH', lambda: key_only(actual, expected_env, observer))
        else:
            check('MODEL_ENV_MATCH', lambda: need(actual == expected_env))
        config, host = check('MODEL_CONFIG_INPUTS', lambda: (record['Config'], record['HostConfig']))
        check('MODEL_USER', lambda: need(config['User'] == service.get('user', image['Config'].get('User', ''))))
        check('MODEL_WORKDIR', lambda: need(config['WorkingDir'] == service.get('working_dir', image['Config'].get('WorkingDir', ''))))
        # Compose null means inherit; explicit [] remains an exact clearing override.
        check('MODEL_COMMAND', lambda: need(config['Cmd'] ==
              (image['Config'].get('Cmd') if service.get('command') is None else service['command'])))
        check('MODEL_ENTRYPOINT', lambda: need(config.get('Entrypoint') ==
              (image['Config'].get('Entrypoint') if service.get('entrypoint') is None else service['entrypoint'])))
        check('MODEL_ROOTFS', lambda: need(host['ReadonlyRootfs'] is service.get('read_only', False)))
        check('MODEL_CAP_DROP', lambda: need(set(host.get('CapDrop') or []) == set(service.get('cap_drop', []))))
        check('MODEL_CAP_ADD', lambda: need(not host.get('CapAdd') and not service.get('cap_add')))
        check('MODEL_SECURITY_OPTIONS', lambda: need(host.get('SecurityOpt') == service.get('security_opt', [])))
        check('MODEL_PRIVILEGE_DEVICES', lambda: need(host['Privileged'] is False and not host.get('Devices') and not service.get('devices')))
        health = check('MODEL_HEALTH_BUILD', lambda: effective_health(service, image['Config'], observer))
        check('MODEL_HEALTH_EQUAL', lambda: need(health ==
              {k: v for k, v in (config.get('Healthcheck') or {}).items() if v != 0}))
        expected_tmpfs = {}
        for item in check('MODEL_TMPFS_BUILD', lambda: iter(service.get('tmpfs', []))):
            check('MODEL_TMPFS_ITEM', lambda: need(type(item) is str))
            target, _, options = item.partition(':')
            check('MODEL_TMPFS_TARGET', lambda: need(target.startswith('/') and target not in expected_tmpfs))
            expected_tmpfs[target] = options
        check('MODEL_TMPFS_EQUAL', lambda: need((host.get('Tmpfs') or {}) == expected_tmpfs))
        restart = check('MODEL_RESTART_PARSE', lambda: service.get('restart', 'no').split(':'))
        check('MODEL_RESTART_NAME', lambda: need(len(restart) <= 2 and host['RestartPolicy']['Name'] == restart[0]))
        check('MODEL_RESTART_RETRIES', lambda: need(host['RestartPolicy'].get('MaximumRetryCount', 0) ==
              (int(restart[1]) if len(restart) == 2 else 0)))
        for field, runtime in (('mem_limit', 'Memory'), ('memswap_limit', 'MemorySwap')):
            if field in service:
                check('MODEL_MEMORY' if field == 'mem_limit' else 'MODEL_SWAP',
                      lambda: need(host[runtime] == memory(service[field], observer)))
        if 'cpus' in service:
            check('MODEL_CPU', lambda: need(host['NanoCpus'] == int(float(service['cpus']) * 1_000_000_000)))
        if 'pids_limit' in service:
            check('MODEL_PIDS', lambda: need(host['PidsLimit'] == service['pids_limit']))
        check('MODEL_IMAGE_VOLUMES', lambda: need(not config.get('Volumes')))
        expected_mounts = []
        for mount in check('MODEL_MOUNTS_BUILD', lambda: iter(service.get('volumes', []))):
            check('MODEL_MOUNT_TYPE', lambda: need(mount['type'] in ('bind', 'volume')))
            source = check('MODEL_MOUNT_ENTRY', lambda: model['volumes'][mount['source']]['name']
                           if mount['type'] == 'volume' else mount['source'])
            expected_mounts.append(check('MODEL_MOUNT_ENTRY', lambda:
                (mount['type'], source, mount['target'], not mount.get('read_only', False))))
            if mount['type'] == 'bind':
                # compose-go v2.4.9 omits false; a present bind object retains the Mount API path.
                check('MODEL_BIND_OPTIONS', lambda: need(type(mount.get('bind')) is dict and
                      set(mount['bind']) <= {'create_host_path'} and
                      ('create_host_path' not in mount['bind'] or mount['bind']['create_host_path'] is False)))
        actual_mounts = check('MODEL_MOUNTS_ACTUAL', lambda:
            [(m['Type'], m.get('Name') if m['Type'] == 'volume' else m['Source'],
              m['Destination'], m['RW']) for m in record['Mounts'] if m['Type'] != 'tmpfs'])
        check('MODEL_MOUNTS', lambda: need(sorted(expected_mounts) == sorted(actual_mounts)))
        check('MODEL_NETWORKS', lambda: need({model['networks'][n]['name'] for n in service.get('networks', {})} ==
              set(record['NetworkSettings']['Networks'])))
        expected_ports = {}
        for port in check('MODEL_PORTS_BUILD', lambda: iter(service.get('ports', []))):
            check('MODEL_PORT_SHAPE', lambda: need(type(port) is dict and port.get('host_ip') == '127.0.0.1' and
                  port.get('protocol', 'tcp') == 'tcp' and port.get('mode', 'ingress') == 'ingress'))
            target = check('MODEL_PORT_ENTRY', lambda: str(port['target']) + '/tcp')
            check('MODEL_PORT_UNIQUE', lambda: need(target not in expected_ports))
            expected_ports[target] = check('MODEL_PORT_ENTRY', lambda:
                [{'HostIp': '127.0.0.1', 'HostPort': str(port['published'])}])
        check('MODEL_PORT_BINDINGS', lambda: need((host.get('PortBindings') or {}) == expected_ports))
        check('MODEL_PORT_SCOPE', lambda: need(not expected_ports if role != 'web' else expected_ports ==
              {'8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '8080'}]}))
        if role == 'api':
            check('MODEL_API_COMMAND', lambda: need(config['Cmd'] == ['node', '--import', 'tsx', 'src/oci/nginx-local.main.ts']))
            check('MODEL_API_VOLUMES', lambda: need({m[1:3] for m in expected_mounts if m[0] == 'volume'} ==
                  {(VOLUMES['auth'], '/auth'), (VOLUMES['data'], '/data')}))

    def capture_preflight_model(self):
        """Existing bounded read prefix only: no compiled files, stores or serving writes."""
        with self.stage('CAPTURE_PLAN'):
            self.plan.validate()
            if self.plan.align_api_cve_release:
                need(self.release_gate is not None)  # Missing adapter refuses BEFORE any Engine client.
        with self.stage('CAPTURE_PROTOCOL'):
            if self.plan.preservation_migration:
                self.migration_protocol()  # Refuse absent/unsynchronized peer BEFORE Engine access.
                alarm_available()  # No foreign timer/non-main-thread before any daemon write.
        with self.stage('ROOT_METADATA'):
            path_metadata(self.root, directory=True)  # 0755 permitted; never chmod an existing root.
        with self.stage('SOURCE_PINS'):
            self.verify_sources()
        with self.stage('SECRET_METADATA'):
            self.secrets_metadata()
        with self.stage('COMPOSE_AMBIENT'):
            need(not any(k in self.env for k in ('COMPOSE_FILE', 'COMPOSE_PROFILES', 'COMPOSE_ENV_FILES')))
            need(self.env.get('COMPOSE_PROJECT_NAME', PROJECT) == PROJECT)
        with self.stage('COMPOSE_VERSION'):
            need(self.run(('docker', 'compose', 'version', '--short'), cap=4096).strip() in SUPPORTED_COMPOSE_VERSIONS)
        with self.stage('SELECTOR'):
            selected = select(self.repo, self.root)
            self.selected = selected
            need(selected.profile == 'nginx-local' and selected.llm == 'openrouter-free' and selected.files == FILES)
            self.base_command = (*selected.command, '--project-name', PROJECT,
                                 '--project-directory', str(self.repo / 'server/deploy'))
        with self.stage('ORIGINAL_INSPECT'):
            records = self.inspect([b.container for b in self.plan.bindings.values()])
        for role, binding in self.plan.bindings.items():
            with self.stage('OLD_' + role.upper().replace('-', '_')):
                record = records[binding.container]
                running = not self.plan.reconcile_stopped_stand or role in ('egress', 'llm-egress')
                self.bound(role, record, running)
                if self.plan.reconcile_stopped_stand:
                    need(record['State']['Status'] == ('running' if running else 'exited') and
                         not record['State'].get('OOMKilled') and not record['State'].get('Dead'))
                elif role == 'api':
                    need(record['State'].get('Health', {}).get('Status') == 'healthy')
                self.old[role] = record
            with self.stage('IMAGE_' + role.upper().replace('-', '_')):
                images = decode(self.run(('docker', 'image', 'inspect', binding.image)))
                need(type(images) is list and len(images) == 1 and images[0]['Id'] == binding.image)
                need(images[0]['Os'] == 'linux')
                if role == 'api':
                    need(images[0]['Architecture'] == self.plan.architecture)
                    defaults = env_map(images[0]['Config'].get('Env') or [])
                    need(KEY not in defaults and 'SCAN_JWT_SECRET' not in defaults)
                self.images[role] = images[0]
        with self.stage('RETAINED_CREATED'):
            self.retained_created_unchanged()
        with self.stage('CANDIDATE_IMAGES'):
            if self.plan.current_source_profile or self.plan.preservation_migration:
                self.verify_candidate_image(initial=True)
        with self.stage('RENDER'):
            model = decode(self.run((*self.base_command, 'config', '--format', 'json')))
        with self.stage('MODEL_SHAPE'):
            need(model['name'] == PROJECT)
            need(set(model['services']) == set((*ROLES, 'auth-volume-init', 'scan-volume-init')))
        return model

    def qualify_release(self):
        need(self.plan.qualify_release_only and self.plan.align_api_cve_release and self.release_gate is not None)
        model = self.capture_preflight_model()
        for role in ROLES:
            self.original_model_matches(role, model, self.old[role], shape_only=True)
        need(all(not any(k in s for k in ('profiles', 'develop', 'provider', 'scale', 'extends', 'include', 'env_file'))
                 for s in model['services'].values()))
        self.model = model
        self.verify_release(model)  # One isolated verifier only; no migration-holder or app startup.
        return {'ok': True, 'mode': 'release-qualification-only-v1', 'releaseAuthenticated': True,
                'standServicesRecreated': False, 'migrationApplied': False, 'providerCalled': False}

    def preflight(self):
        need(not self.plan.qualify_release_only)
        model = self.capture_preflight_model()
        self.require_retired_r2_absent()  # Fresh census BEFORE even the release-verifier actor or scratch entry.
        selected = self.selected
        # The strict release seal includes .local-auth ancestor metadata in the
        # supported layout. Create our root entry BEFORE sealing, never after.
        with self.stage('PRIVATE_DIRECTORY'):
            need(self.backup is None and self.compiled is None)
            self.backup = Path(tempfile.mkdtemp(prefix='key-preservation-', dir=self.root))
            os.chmod(self.backup, 0o700)  # OWN freshly created directory only; never adopt.
            self.compiled = self.backup / 'compiled.json'
        with self.stage('RELEASE_VERIFY'):
            self.verify_release(model)  # Authentication BEFORE admitting the original-source exception.
        for role in ROLES:
            with self.stage('MODEL_' + role.upper().replace('-', '_')):
                self.original_model_matches(role, model, self.old[role], observer=self.observation)
        with self.stage('MODEL_RESTRICTIONS'):
            for field in ('profiles', 'develop', 'provider', 'scale', 'extends', 'include'):
                need(all(field not in s for s in model['services'].values()))
            need(all('env_file' not in s for s in model['services'].values()))
        with self.stage('IMAGE_SUBSTITUTION'):
            original = copy.deepcopy(model)
            for role in self.plan.replaced_roles:
                model['services'][role]['image'] = self.plan.selected_image(role)
            check = copy.deepcopy(model)
            for role in self.plan.replaced_roles:
                if 'image' in original['services'][role]:
                    check['services'][role]['image'] = original['services'][role]['image']
                else:
                    check['services'][role].pop('image')
            need(check == original)  # Only the mode's explicitly bound image fields may change.
        with self.stage('COMPILED_WRITE'):
            private_write(self.compiled, encoded(model))  # Already reloadable dollar-escaped JSON.
        with self.stage('ALIGNMENT_WRITE'):
            if self.plan.align_api_cve_release:
                private_write(self.backup / 'release-alignment.json', encoded({
                    'request': self.release_request, 'seal': self.release_seal.hex(),
                    'originals': {r: {'id': self.old[r]['Id'], 'image': self.old[r]['Image'],
                                     'mounts': self.old[r]['Mounts'],
                                     'hostMounts': self.old[r]['HostConfig']['Mounts']}
                                  for r in ('api', 'worker')}}))  # PRIVATE, never stdout.
        with self.stage('PRIVATE_DIRECTORY_FSYNC'):
            sync_directory(self.backup)
        with self.stage('COMPILED_METADATA'):
            self.compiled_metadata = path_metadata(self.compiled)
            need(stat.S_IMODE(self.compiled_metadata[2]) == 0o600 and self.compiled_metadata[5] <= 2 * MIB)
            self.command = ('docker', 'compose', '--project-name', PROJECT,
                            '--project-directory', str(self.repo / 'server/deploy'),
                            '--env-file', '/dev/null', '-f', str(self.compiled))
        # No secret sources are revisited by this compiled config's execution.
        with self.stage('COMPILED_QUIET'):
            self.run((*self.command, 'config', '--quiet'))
        with self.stage('COMPILED_RENDER'):
            roundtrip = decode(self.run((*self.command, 'config', '--format', 'json')))
        with self.stage('COMPILED_EQUAL'):
            need(roundtrip == model)
            self.model = model
        with self.stage('AUTH_INPUT'):
            if self.plan.current_source_profile or self.plan.preservation_migration:
                self.compatibility_input()  # Input cap/env mismatch refuses BEFORE first stop.
        with self.stage('NETWORKS'):
            ids = sorted({value['NetworkID'] for r in self.old.values()
                          for value in r['NetworkSettings']['Networks'].values()})
            networks = decode(self.run(('docker', 'network', 'inspect', *ids)))
            need(len(networks) == len(ids))
            self.networks = {n['Id']: {k: v for k, v in n.items() if k != 'Containers'} for n in networks}
            runtime = compose_runtime_model(model)
            for n in networks:
                logical = next((key for key, value in runtime['networks'].items() if value['name'] == n['Name']), None)
                need(logical is not None and n['Internal'] is runtime['networks'][logical].get('internal', False))
        with self.stage('VOLUMES'):
            self.resources()
        self.capacity(before_stops=True)
        with self.stage('WRITER_FENCE'):
            self.writers(set() if self.plan.reconcile_stopped_stand else
                         {self.plan.bindings[r].container for r in ('api', 'worker')})
        with self.stage('STABILITY'):
            self.stable({'egress', 'llm-egress'} if self.plan.reconcile_stopped_stand else set(ROLES))
        with self.stage('SOURCE_FINAL'):
            self.verify_sources()
        with self.stage('SECRET_FINAL'):
            self.secrets_metadata()
        # Freeze guards again immediately before the first daemon write.
        with self.stage('SELECTOR_FINAL'):
            need(select(self.repo, self.root) == selected)
        with self.stage('API_SOCKET_GUARD'):
            if self.plan.preservation_migration:
                need(all(not m.get('Source', '').endswith('/docker.sock') and
                         not m.get('Destination', '').endswith('/docker.sock')
                         for m in self.old['api']['Mounts']))

    def stop(self, role, seconds=15):
        identity = self.new_roles.get(role) or (self.new_api if role == 'api' and self.new_api else self.plan.bindings[role].container)
        self.run(('docker', 'stop', '--time', str(seconds), identity), timeout=seconds + 15, cap=4096)

    def capacity(self, before_stops=False):
        with self.stage('HOST_CAPACITY'):
            baseline_capacity = 3 * GIB if self.plan.preservation_migration else 2 * GIB
            required = (baseline_capacity if before_stops else GIB) + 128 * MIB
            need(shutil.disk_usage(self.backup or self.root).free >= required)
        if before_stops:
            with self.stage('ENGINE_MEMORY'):
                total = decode(self.run(('docker', 'info', '--format', '{{json .MemTotal}}'), cap=4096))
                need(type(total) is int and total >= 2 * GIB + 256 * MIB)
            # MemTotal is capacity, not an assertion of unreserved live memory.
            # OOM/refusal is HOLD; these reviewed limits are NEVER widened.
            with self.stage('HELPER_UID_ACCESS'):
                script = self.repo / self.plan.sqlite_helper
                for path in (script, *script.parents):
                    st = path.lstat()
                    permission = 0o400 if path == script else 0o100
                    need(st.st_mode & (permission if st.st_uid == 65532 else permission >> 6))
                    if path == self.repo:
                        break

    def holder_budget(self, seconds):
        self.check_pending()
        need(self.holder_started is not None and
             time.monotonic() + seconds + 5 < self.holder_started + HOLDER_MS / 1000)

    def qualify_holder(self, running, allow_paused=False):
        with self.stage('HOLDER_JOURNAL_BINDING'):
            need(self.helper_id is not None and not self.helper_removed)
            need(self.holder_journal_metadata is not None and
                 path_metadata(self.backup / 'holder-id.json', secret=True) == self.holder_journal_metadata)
        with self.stage('HOLDER_INSPECT'):
            record = self.inspect([self.helper_id])[self.helper_id]
            config, host, state = record['Config'], record['HostConfig'], record['State']
        with self.stage('HOLDER_DEFAULTS_PREP'):
            defaults = self.images['api']['Config']
            labels = dict(defaults.get('Labels') or {})
            labels['dip.key-preservation'] = self.backup.name
        with self.stage('HOLDER_IDENTITY'):
            need(record['Id'] == self.helper_id and record['Name'] == '/' + self.helper_name and
                 record['Image'] == self.plan.bindings['api'].image and config['Image'] == record['Image'])
        with self.stage('HOLDER_CONFIG_DEFAULTS'):
            need(config['Labels'] == labels and config['User'] == '65532:65532')
            with self.stage('HOLDER_ENV_EQUAL'):
                need(config['Env'] == defaults.get('Env'))
            need(config['WorkingDir'] == defaults.get('WorkingDir', ''))
        with self.stage('HOLDER_COMMAND'):
            need(config['Entrypoint'] == ['node'] and config['Cmd'] == ['-e', HOLDER_CODE] and
                 record['Path'] == 'node' and record['Args'] == ['-e', HOLDER_CODE])
        with self.stage('HOLDER_HEALTH_VOLUMES'):
            need(config.get('Healthcheck') == {'Test': ['NONE']} and not config.get('Volumes'))
        with self.stage('HOLDER_SECURITY'):
            need(host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] is True and
                 host['CapDrop'] == ['ALL'] and not host.get('CapAdd') and host['Privileged'] is False)
            need(host.get('SecurityOpt') == ['no-new-privileges:true'] and not host.get('Devices') and
                 not host.get('DeviceRequests') and not host.get('Binds') and not host.get('PortBindings'))
            if self.plan.preservation_migration:
                need(host.get('CgroupnsMode') == 'private')
        with self.stage('HOLDER_RESOURCES'):
            need(host['Memory'] == 2 * GIB and host['MemorySwap'] == 2 * GIB and
                 host['NanoCpus'] == 1_000_000_000 and host['PidsLimit'] == 64)
            with self.stage('HOLDER_TMPFS_OPTIONS'):
                need(host['Tmpfs'] == HOLDER_TMPFS)
        with self.stage('HOLDER_RESTART_STOP'):
            need(host['RestartPolicy'] == {'Name': 'no', 'MaximumRetryCount': 0} and config.get('StopTimeout') == 5)
        with self.stage('HOLDER_STATE'):
            need(not state.get('Restarting') and not state.get('OOMKilled') and
                 type(state['Running']) is bool and state['Running'] is running)
            need(allow_paused or not state.get('Paused'))
        with self.stage('HOLDER_NETWORKS'):
            networks = record['NetworkSettings']['Networks']
            need(set(networks) == {'none'})
        with self.stage('HOLDER_MOUNTS_PREP'):
            expected = [('volume', VOLUMES[k], self.volumes[VOLUMES[k]]['Mountpoint'], '/source/' + k, self.plan.preservation_migration)
                        for k in VOLUMES]
            helper_source = str(self.repo / self.plan.sqlite_helper)
        if self.plan.darwin_host_mnt_helper:
            with self.stage('HOLDER_DECLARED_MOUNTS'):
                need(self.plan.reconcile_stopped_stand and sys.platform == 'darwin' and
                     self.repo == RECONCILIATION_REPO)
                declared = host.get('Mounts')
                need(type(declared) is list and len(declared) == 3 and all(type(v) is dict for v in declared))
                by_target = {v.get('Target'): v for v in declared}
                need(set(by_target) == {'/source/auth', '/source/data', SCRIPT_TARGET})
                for key, volume in VOLUMES.items():
                    entry = by_target['/source/' + key]
                    need(set(entry) <= {'Type', 'Source', 'Target', 'ReadOnly', 'VolumeOptions'} and
                         entry['Type'] == 'volume' and entry['Source'] == volume and
                         ('ReadOnly' not in entry or entry['ReadOnly'] is False) and
                         entry.get('VolumeOptions') in (None, {}))
                entry = by_target[SCRIPT_TARGET]
                need(set(entry) <= {'Type', 'Source', 'Target', 'ReadOnly', 'BindOptions'} and
                     entry['Type'] == 'bind' and entry['ReadOnly'] is True and
                     entry['Source'] in (helper_source, '/host_mnt' + helper_source))
                options = entry.get('BindOptions')
                need(options is None or type(options) is dict and
                     set(options) <= {'Propagation', 'NonRecursive', 'CreateMountpoint',
                                      'ReadOnlyNonRecursive', 'ReadOnlyForceRecursive'} and
                     options.get('Propagation', '') in ('', 'rprivate') and
                     all(v is False for k, v in options.items() if k != 'Propagation'))
                helper_source = entry['Source']  # Actual source must match this EXACT safe declaration.
        with self.stage('HOLDER_ACTUAL_MOUNTS'):
            expected.append(('bind', '', helper_source, SCRIPT_TARGET, False))
            mounts = record['Mounts']
            actual = [(v['Type'], v.get('Name', ''), v.get('Source', ''), v['Destination'], v['RW'])
                      for v in mounts if v['Type'] != 'tmpfs']
            need(sorted(actual) == sorted(expected))
        with self.stage('HOLDER_ACTUAL_TMPFS'):
            tmpfs = [v for v in mounts if v['Type'] == 'tmpfs']
            need(len(tmpfs) == len({v['Destination'] for v in tmpfs}) and
                 all(v['Destination'] in HOLDER_TMPFS and v['RW'] is True for v in tmpfs))
        return record

    def create_holder(self):
        with self.stage('HOLDER_SOURCE_PINS'):
            self.verify_sources()
        with self.stage('HOLDER_RESOURCES_PRE'):
            self.resources()
        with self.stage('HOLDER_WRITERS_PRE'):
            self.writers(set())
        with self.stage('HOLDER_CAPACITY_PRE'):
            self.capacity()
        with self.stage('HOLDER_INTENT_JOURNAL'):
            need(self.helper_name is None)
            self.helper_name = 'dip-key-snapshot-' + uuid.uuid4().hex
            self.helper_names.add(self.helper_name)
            private_write(self.backup / 'holder-intent.json', encoded({
                'version': 1, 'name': self.helper_name, 'image': self.plan.bindings['api'].image,
                'backup': self.backup.name, 'source': self.plan.sqlite_helper,
                'sourceSha256': self.plan.sources[self.plan.sqlite_helper],
                'preservationMigration': self.plan.preservation_migration}))
            sync_directory(self.backup)
            sync_directory(self.root)  # Durable intent BEFORE even an ambiguous create response.
        with self.stage('HOLDER_CREATE_ARGS'):
            argv = ['docker', 'create', '--name', self.helper_name,
                    '--label', 'dip.key-preservation=' + self.backup.name,
                    '--pull', 'never', '--network', 'none', '--read-only', '--user', '65532:65532',
                    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                    '--memory', '2g', '--memory-swap', '2g', '--cpus', '1', '--pids-limit', '64',
                    '--restart', 'no', '--stop-timeout', '5', '--no-healthcheck', '--entrypoint', 'node']
            if self.plan.preservation_migration:
                argv.extend(('--cgroupns', 'private'))
            for target, options in HOLDER_TMPFS.items():
                argv.extend(('--tmpfs', target + ':' + options))
            for key, volume in VOLUMES.items():
                access = '' if self.plan.preservation_migration else ',readonly'
                argv.extend(('--mount', f'type=volume,source={volume},target=/source/{key}{access}'))
            argv.extend(('--mount', f'type=bind,source={self.repo / self.plan.sqlite_helper},target={SCRIPT_TARGET},readonly',
                         self.plan.bindings['api'].image, '-e', HOLDER_CODE))
        with self.stage('HOLDER_CREATE'):
            created = self.run(argv, cap=4096)
        with self.stage('HOLDER_CREATE_ID'):
            identity = created.strip().decode('ascii')
            need(HEX.fullmatch(identity) is not None)
            self.helper_id = identity
            self.helper_ids.add(identity)
        with self.stage('HOLDER_ID_JOURNAL'):
            private_write(self.backup / 'holder-id.json', encoded({
                'version': 1, 'id': identity, 'name': self.helper_name,
                'image': self.plan.bindings['api'].image, 'backup': self.backup.name}))
            sync_directory(self.backup)
            sync_directory(self.root)
            self.holder_journal_metadata = path_metadata(self.backup / 'holder-id.json', secret=True)
        self.qualify_holder(False)
        with self.stage('HOLDER_START'):
            self.holder_started = time.monotonic()  # Conservative: BEFORE start request.
            self.run(('docker', 'start', identity), cap=4096)
        self.qualify_holder(True)
        with self.stage('HOLDER_WRITERS_POST'):
            self.writers(set())

    def snapshot(self, operation):
        self.verify_sources()
        self.resources()
        self.writers(set())
        self.holder_budget(60)
        argv = ['docker', 'exec', self.helper_id, 'node', SCRIPT_TARGET, operation, '/backup/pre']
        if operation == 'compare':
            need('pre' in self.exports)
            argv.append('/backup/post')
        receipt(self.run(argv, timeout=60, cap=4096), operation)
        self.qualify_holder(True)
        self.resources()
        self.writers(set())

    def holder_inventory(self, stage):
        with self.stage('INVENTORY_STAGE'):
            need(stage in ('pre', 'post', 'migration'))
        with self.stage('INVENTORY_BUDGET'):
            self.holder_budget(15)
        with self.stage('INVENTORY_QUALIFY'):
            self.qualify_holder(True)
        with self.stage('INVENTORY_READ'):
            value = decode(self.run(('docker', 'exec', self.helper_id, 'node', '-e', INVENTORY_CODE,
                                     '/backup/' + stage), timeout=15, cap=2 * MIB))
        with self.stage('INVENTORY_SHAPE'):
            need(type(value) is list and len(value) <= EXPORT_FILES + EXPORT_DIRS)
        return value

    def export(self, stage):
        with self.stage('EXPORT_STAGE'):
            need(stage in ('pre', 'post', 'plan', 'migration') and stage not in self.exports | self.material_exports)
            source = 'migration' if stage in ('plan', 'migration') else stage
        with self.stage('EXPORT_CAPACITY'):
            self.capacity()
        with self.stage('EXPORT_WRITERS_PRE'):
            self.writers(set())
        with self.stage('EXPORT_BUDGET'):
            self.holder_budget(50)
        with self.stage('EXPORT_INVENTORY_BEFORE'):
            before = self.holder_inventory(source)
        with self.stage('EXPORT_DESTINATION_CREATE'):
            destination = self.backup / stage
            destination.mkdir(mode=0o700)  # exclusive; never repair a pre-existing copy
        with self.stage('EXPORT_DESTINATION_MODE'):
            need(stat.S_IMODE(destination.lstat().st_mode) == 0o700)
        with self.stage('EXPORT_PARENT_FSYNC'):
            sync_directory(self.backup)
        # Docker cp without -a maps ownership to the invoking user. No -L, import,
        # shell, tar extraction or overwrite of a previous export is permitted.
        with self.stage('EXPORT_COPY'):
            self.run(('docker', 'cp', self.helper_id + ':/backup/' + source + '/.', str(destination)),
                     timeout=30, cap=4096)
        with self.stage('EXPORT_QUALIFY_AFTER_COPY'):
            self.qualify_holder(True)
        with self.stage('EXPORT_HOST_INVENTORY'):
            actual = backup_inventory(destination)
        with self.stage('EXPORT_INVENTORY_EQUAL'):
            need(actual == before and self.holder_inventory(source) == before)
        if stage in ('pre', 'post'):
            with self.stage('EXPORT_VERSIONS'):
                expected = (self.plan.expected_versions if stage == 'pre' else
                            CURRENT_SOURCE_VERSIONS if self.plan.preservation_migration else self.observed_versions)
                need(expected is not None)
            with self.stage('EXPORT_MANIFEST'):
                manifest = validate_manifest(destination, actual, expected, migration=self.plan.preservation_migration)
            if self.plan.preservation_migration:
                with self.stage('EXPORT_SMALL_ADMISSION'):
                    summary = small_snapshot(manifest, actual, post=stage == 'post')
                with self.stage('EXPORT_HEADERS'):
                    summary['modes'] = self.small_headers(destination, manifest, actual)
                if stage == 'pre':
                    self.small_modes = summary['modes']
                if stage == 'post':
                    with self.stage('EXPORT_POST_BOUNDS'):
                        need(self.small_projection is not None and
                             summary['rows'] == self.small_projection['projectedRows'] and
                             summary['raw'] <= self.small_projection['projectedRaw'] and
                             summary['working'] <= self.small_projection['projectedWorking'] and
                             summary['sealed'] <= self.small_projection['projectedImage'])
                    with self.stage('EXPORT_POST_PHYSICAL'):
                        for relative, physical in summary['physical'].items():
                            bound = self.small_projection['physicalBounds'][relative]
                            need(summary['modes'][relative] == bound['mode'] and physical['pageSize'] == bound['pageSize'] and
                                 all(physical[k] <= bound[k] for k in ('main', 'wal', 'shm')))
        else:
            with self.stage('EXPORT_MATERIAL_SHAPE'):
                files = {r['path'] for r in actual if r['kind'] == 'file'}
                expected_files = {'plan.json', 'auth.sqlite', 'ledger.sqlite'} | (
                    {'apply-attempt.json', 'applied.json'} if stage == 'migration' else set())
                need(files == expected_files and all(r['path'] == '' or r['kind'] == 'file' for r in actual))
            with self.stage('EXPORT_MATERIAL_BYTES'):
                need(sum(r.get('bytes', 0) for r in actual) <= 256 * MIB + 3 * MANIFEST_BYTES)
            # Fixed peer files only, no arbitrary bind/config/Env material adoption.
            if self.plan.preservation_migration:
                with self.stage('EXPORT_PLAN_BOUNDS'):
                    need(next(r['bytes'] for r in actual if r['path'] == 'plan.json') <= SMALL_PLAN and
                         sum(r['bytes'] for r in actual if r['path'] in ('auth.sqlite', 'ledger.sqlite')) <= SMALL_IMAGE)
                if stage == 'migration':
                    with self.stage('EXPORT_RETAINED_BOUNDS'):
                        need(sum(r.get('bytes', 0) for r in actual if r['path'].endswith('.json')) <= SMALL_PLAN + 512 and
                             sum(rounded_inventory(self.export_inventories[s]) for s in ('pre', 'post')) +
                             rounded_inventory(actual) <= self.small_projection['finalRetained'])
        if stage == 'pre':
            # Derive actual pairs from the validated PRIVATE manifest, only AFTER
            # checking independent profile/legacy expectations. Never self-certify.
            with self.stage('EXPORT_OBSERVED_VERSIONS'):
                self.observed_versions = {
                    s['path']: tuple(int(s['logical']['schema'][key]) for key in ('applicationId', 'userVersion'))
                    for s in manifest['stores'] if s['path'] in REQUIRED_STORES
                }
                if not self.plan.preservation_migration:
                    need(self.observed_versions == self.plan.expected_versions)
        with self.stage('EXPORT_INVENTORY_RECORD'):
            self.export_inventories[stage] = actual
        with self.stage('EXPORT_DESTINATION_FSYNC'):
            sync_directory(destination)
        with self.stage('EXPORT_BACKUP_FSYNC'):
            sync_directory(self.backup)
        with self.stage('EXPORT_ROOT_FSYNC'):
            sync_directory(self.root)
        with self.stage('EXPORT_QUALIFY_FINAL'):
            self.qualify_holder(True)
        with self.stage('EXPORT_WRITERS_FINAL'):
            self.writers(set())
        with self.stage('EXPORT_CERTIFY'):
            (self.exports if stage in ('pre', 'post') else self.material_exports).add(stage)

    def remove_holder(self):
        need(self.exports == {'pre', 'post'})
        if self.plan.preservation_migration:
            need(self.material_exports == {'plan', 'migration'} and self.migration_matched and self.migration_compatible)
        self.holder_budget(15)
        self.qualify_holder(True)
        self.writers(set())
        self.run(('docker', 'rm', '--force', self.helper_id), timeout=15, cap=4096)
        self.helper_removed = True
        self.writers(set())
        if self.plan.preservation_migration:
            self.check_pending()
            self.end_pending_window()

    def discover_api(self):
        data = self.run(('docker', 'ps', '-a', '--no-trunc', '--filter', 'label=com.docker.compose.project=' + PROJECT,
                         '--filter', 'label=com.docker.compose.service=api', '--format', '{{.ID}}'), cap=4096)
        ids = data.decode('ascii').splitlines()
        need(len(ids) == 1 and HEX.fullmatch(ids[0]) is not None)
        record = self.inspect(ids)[ids[0]]
        need(record['Id'] != self.plan.bindings['api'].container)
        need(record['Name'] == '/' + PROJECT + '-api-1' and record['Image'] == self.plan.api_image)
        need(record['Config']['Labels'].get('com.docker.compose.project.config_files') == str(self.compiled))
        self.new_api = record['Id']

    def check_new_api(self, running):
        record = self.inspect([self.new_api])[self.new_api]
        need(record['Name'] == '/' + PROJECT + '-api-1' and record['Image'] == self.plan.api_image)
        need(record['Config']['Image'] == self.plan.api_image)
        need(record['State']['Running'] is running and not record['State'].get('Restarting') and not record['State'].get('Paused'))
        need(record['Config']['Labels'].get('com.docker.compose.project.config_files') == str(self.compiled))
        expected_env = env_map(self.images['api']['Config'].get('Env') or [])
        expected_env.update(env_map(compose_runtime_model(self.model)['services']['api']['environment']))
        need(env_map(record['Config']['Env']) == expected_env)
        key_only(env_map(self.old['api']['Config']['Env']), expected_env)
        need(config_identity(record, compose_image=self.plan.api_image if self.plan.current_source_profile else None) ==
             config_identity(self.old['api'], compose_image=self.plan.bindings['api'].image
                             if self.plan.current_source_profile else None))
        if running:
            need(record['State'].get('Health', {}).get('Status') == 'healthy')

    def anonymous(self, ingress=False):
        url = 'http://web:8080/api/v1/auth/me' if ingress else 'http://127.0.0.1:3001/api/v1/auth/me'
        program = ("fetch(" + json.dumps(url) + ",{redirect:'error',signal:AbortSignal.timeout(3000)})"
                   ".then(r=>{process.stdout.write(JSON.stringify({ok:r.status===401}));process.exit(r.status===401?0:1)})"
                   ".catch(()=>process.exit(1))")
        closed_ok(self.run(('docker', 'exec', self.new_api, 'node', '-e', program), timeout=6, cap=4096))

    def owned_lock(self):
        if self.plan.reconcile_stopped_stand:
            need(self.reconciliation_capability is not None and
                 self.lock_capability is self.reconciliation_capability and self.reconciliation_pid == os.getpid())
            need(path_metadata(self.coordination_path, directory=True)[:4] == self.lock_identity)
            self.prior_hold_unchanged()
            return
        held = _held_locks.get(self.lock_capability)
        need(held is not None and held[0] == self.root and held[3] == os.getpid())
        current = path_metadata(self.root / '.trivy-refresh.lock', directory=True)
        need(current[:2] == held[1:3] and current[:4] == self.lock_identity and
             stat.S_IMODE(current[2]) == 0o700)

    def hold(self):
        with self.stage('HOLD_OWNERSHIP'):
            need(self.phase in PHASES)
            self.owned_lock()
        self.hold_requested = True
        marker = self.coordination_path / 'KEY_ACTIVATION_HOLD.json'
        if self.plan.reconcile_stopped_stand and self.hold_identity is not None:
            with self.stage('HOLD_REUSE'):
                need(path_metadata(marker, secret=True) == self.hold_identity)
            return  # The OWN preflight marker is retained, not rewritten after release sealing.
        with self.stage('HOLD_WRITE'):
            private_write(marker, encoded({'version': 2, 'phase': self.phase, 'uncertain': True,
                                           'manualReconciliationRequired': True}))
        with self.stage('HOLD_METADATA'):
            self.hold_identity = path_metadata(marker, secret=True)
        with self.stage('HOLD_DIRECTORY_FSYNC'):
            sync_directory(marker.parent)
        with self.stage('HOLD_ROOT_FSYNC'):
            sync_directory(self.root)
        with self.stage('HOLD_FINAL_OWNERSHIP'):
            self.owned_lock()

    def release_hold(self):
        marker = self.coordination_path / 'KEY_ACTIVATION_HOLD.json'
        need(self.hold_identity is not None and path_metadata(marker, secret=True) == self.hold_identity)
        self.owned_lock()
        marker.unlink()  # ONLY our unchanged marker; refresh_lock owns lock removal.
        try:
            sync_directory(marker.parent)
        except BaseException:
            # Recreate a conservative HOLD if removal durability was not established.
            self.hold()
            raise
        self.hold_requested = False

    def ready(self):
        program = ("import {chainReady} from './src/scans/scan-readiness.ts'; "
                   "import {localWorkerReady} from './src/oci/nginx-local-profile.ts'; "
                   "const ok=await chainReady() && await localWorkerReady(); "
                   "process.stdout.write(JSON.stringify({ok}));process.exit(ok?0:1)")
        closed_ok(self.run(('docker', 'exec', self.new_api, 'node', '--import', 'tsx',
                            '--input-type=module', '-e', program), timeout=15, cap=4096))

    def fail_stop(self):
        if self.plan.preservation_migration:
            for role in self.replacement_attempted:
                if role not in self.new_roles:
                    try:
                        self.discover_role(role)
                    except Exception:
                        pass
        # New ingress stays closed; stopping is not rollback or a preservation claim.
        # All targets must be previously bound or attributable to our compiled file.
        if self.phase in ('recreate', 'check_api') and self.new_api is None:
            try:
                self.discover_api()
            except Exception:
                pass
        # Freeze ONLY our exact qualified holder. Never stop/remove on ambiguous
        # exec/cp: stopping would destroy the sole in-container tmpfs baseline.
        if self.backup is not None and self.helper_name and not self.helper_removed:
            try:
                if self.helper_id is None:
                    raw = self.run(('docker', 'ps', '-a', '--no-trunc', '--filter',
                                    'name=^/' + self.helper_name + '$', '--format', '{{.ID}}'), cap=4096)
                    ids = raw.decode('ascii').splitlines()
                    need(len(ids) == 1 and HEX.fullmatch(ids[0]))
                    self.helper_id = ids[0]
                record = self.qualify_holder(True, allow_paused=True)
                if not record['State'].get('Paused'):
                    self.run(('docker', 'pause', self.helper_id), timeout=10, cap=4096)
            except Exception:
                pass  # Expiry/pause/client failure is uncertain, never recovery proof.
        for role in ('web', 'api', 'worker'):
            try:
                identity = self.new_roles.get(role) or (self.new_api if role == 'api' and self.new_api else self.plan.bindings[role].container)
                record = self.inspect([identity])[identity]
                if role in self.new_roles:
                    self.attributed_role(role, record)
                elif role == 'api' and self.new_api:
                    need(record['Name'] == '/' + PROJECT + '-api-1' and
                         record['Image'] == self.plan.api_image and
                         record['Config']['Labels'].get('com.docker.compose.project.config_files') == str(self.compiled))
                else:
                    self.bound(role, record, record['State']['Running'])
                if record['State']['Running']:
                    self.stop(role, 5)
            except Exception:
                pass

    def migration_protocol(self):
        """Exact statically synchronized peer contract, not an acceptance receipt."""
        need(type(MIGRATION_PROTOCOL) is dict and set(MIGRATION_PROTOCOL) ==
             {'capture', 'capture-post', 'plan-migration', 'apply-migration', 'compare-migrated', 'compatibility'})
        codes = {'capture': 'CAPTURED', 'capture-post': 'CAPTURED', 'plan-migration': 'PLANNED',
                 'apply-migration': 'MIGRATED', 'compare-migrated': 'MIGRATION_MATCH', 'compatibility': 'COMPATIBLE'}
        for operation, (code, arguments, private) in MIGRATION_PROTOCOL.items():
            command = 'capture' if operation == 'capture-post' else operation
            paths = ('/backup/pre', '/backup/post') if operation == 'compare-migrated' else (
                '/backup/post' if operation in ('capture-post', 'compatibility') else '/backup/pre',)
            need(code == codes[operation] and arguments == (command, '--preservation-migration', *paths) and
                 private is (operation in ('plan-migration', 'compatibility')))
        return MIGRATION_PROTOCOL

    def revalidate_export(self, stage):
        self.check_pending()
        need(stage in self.exports | self.material_exports and stage in self.export_inventories)
        actual = backup_inventory(self.backup / stage)
        need(actual == self.export_inventories[stage])
        if stage in ('pre', 'post'):
            expected = self.plan.expected_versions if stage == 'pre' else CURRENT_SOURCE_VERSIONS
            validate_manifest(self.backup / stage, actual, expected, migration=True)
        sync_directory(self.backup / stage)
        sync_directory(self.backup)
        sync_directory(self.root)

    def migration_guard(self):
        self.check_pending()
        self.owned_lock()
        marker = self.coordination_path / 'KEY_ACTIVATION_HOLD.json'
        need(self.hold_requested and path_metadata(marker, secret=True) == self.hold_identity)
        self.stable({'egress', 'llm-egress'})
        self.verify_sources()
        self.secrets_metadata()
        self.verify_candidate_image()
        self.compatibility_input()
        self.writers(set())
        need(path_metadata(self.compiled) == self.compiled_metadata)
        need(decode(self.run((*self.command, 'config', '--format', 'json'))) == self.model)
        need(select(self.repo, self.root) == self.selected)
        self.qualify_holder(True)

    def migration_exec(self, operation):
        contract = self.migration_protocol()
        code, arguments, private = contract[operation]
        self.migration_guard()
        if operation == 'apply-migration':
            need(self.migration_planned and self.exports == {'pre'} and self.material_exports == {'plan'})
            self.revalidate_export('pre')
            self.revalidate_export('plan')
            need(self.holder_inventory('migration') == self.export_inventories['plan'])
            self.capacity()
        # Recheck the EXISTING 180s margin after all apply guards/rehashes/fsyncs,
        # immediately before original RW execution. This is not a real-state
        # peak-memory or sum-of-worst-case completion proof; never extend240s.
        self.holder_budget(180 if operation == 'apply-migration' else 60)
        if operation == 'apply-migration':
            self.small_admission()
            self.start_pending_window()
        argv = ('docker', 'exec', *(('-i',) if private else ()), self.helper_id,
                'node', SCRIPT_TARGET, *arguments)
        kwargs = {'input_data': self.compatibility_input()} if private else {}
        value = decode(self.run(argv, timeout=60, cap=4096, **kwargs), 4096)
        need(type(value) is dict and set(value) == {'code', 'ok'} and
             value['ok'] is True and type(value['code']) is str and value['code'] == code)
        self.migration_guard()

    def check_owned_timer(self, *, allow_expired=False):
        need(not self.timer_ownership_lost and not self.timer_installation_failed)
        before = time.monotonic()
        live = signal.getitimer(signal.ITIMER_REAL)
        after = time.monotonic()
        valid = (self.pending_alarm_handler is not None and
                 signal.getsignal(signal.SIGALRM) is self.pending_alarm_handler and
                 self.owned_timer_expiry is not None and type(live) is tuple and len(live) == 2 and
                 all(type(v) in (int, float) and math.isfinite(v) and v >= 0 for v in live) and
                 live[1] == 0 and 0 <= after - before <= TIMER_TOLERANCE)
        if valid:
            remaining = live[0]
            valid = ((remaining > 0 and not self.owned_timer_expired and
                      before + remaining - TIMER_TOLERANCE <= self.owned_timer_expiry <=
                      after + remaining + TIMER_TOLERANCE) or
                     (remaining == 0 and allow_expired and self.owned_timer_expired and
                      before >= self.owned_timer_expiry))
        if not valid:
            self.timer_ownership_lost = True  # Sticky: later convergence is not ownership.
        need(valid)

    def arm_owned_timer(self, seconds, *, deadline=None):
        need(not self.timer_ownership_lost and 0 < seconds <= SMALL_PENDING_SECONDS)
        before = time.monotonic()
        if deadline is not None:
            seconds = min(seconds, deadline - before)
        need(seconds > 0)
        self.timer_installation_failed = True  # Failed syscall outcome is ambiguous.
        signal.setitimer(signal.ITIMER_REAL, seconds)
        self.owned_timer_expiry = before + seconds
        self.owned_timer_expired = False
        self.timer_installation_failed = False
        self.check_owned_timer()

    def check_pending(self):
        if self.pending_deadline is not None:
            self.check_owned_timer()
            need(time.monotonic() < self.pending_deadline)

    def start_pending_window(self):
        need(self.pending_deadline is None and time.monotonic() - self.holder_started <= SMALL_APPLY_ELAPSED)
        alarm_available()
        self.previous_alarm_handler = signal.getsignal(signal.SIGALRM)
        def expired(signum, frame):
            # Only the observed expiry of this installed one-shot permits rearm.
            # An early/disarmed/replaced timer with the same callback is not OWN.
            valid = (signum == signal.SIGALRM and not self.timer_ownership_lost and
                     not self.timer_installation_failed and self.owned_timer_expiry is not None and
                     signal.getsignal(signal.SIGALRM) is self.pending_alarm_handler and
                     time.monotonic() >= self.owned_timer_expiry and
                     signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0))
            self.owned_timer_expired = valid
            self.timer_ownership_lost = not valid
            raise Refusal()
        self.pending_alarm_handler = expired
        signal.signal(signal.SIGALRM, expired)  # Main thread only; failure refuses before apply.
        self.arm_owned_timer(SMALL_PENDING_SECONDS)
        self.pending_deadline = self.owned_timer_expiry
        if isinstance(self.run, Runner):
            self.pending_runner_deadline = self.run.deadline
            self.run.deadline = min(self.run.deadline, self.pending_deadline)
        self.check_pending()

    def end_pending_window(self):
        if self.pending_alarm_handler is not None:
            self.check_owned_timer(allow_expired=True)
            signal.setitimer(signal.ITIMER_REAL, 0)
            self.owned_timer_expiry = None
            need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0) and
                 signal.getsignal(signal.SIGALRM) is self.pending_alarm_handler)
            signal.signal(signal.SIGALRM, self.previous_alarm_handler)
            self.pending_alarm_handler = None
        if isinstance(self.run, Runner) and self.pending_runner_deadline is not None:
            self.run.deadline = self.pending_runner_deadline
        self.pending_runner_deadline = None
        self.pending_deadline = None

    def small_headers(self, root, manifest, inventory):
        records = {r['path']: r for r in inventory}
        physical, _ = small_physical(manifest, records)
        modes = {}
        # PRIVATE exported raw copies only, not originals/Env or SQLite opens.
        for store in manifest['stores']:
            path = root / 'raw' / store['path']
            before = path_metadata(path)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                st = os.fstat(fd)
                need((st.st_dev, st.st_ino) == before[:2])
                header = os.read(fd, 100)
                need(len(header) == 100 and header[:16] == b'SQLite format 3\0' and
                     header[18] in (1, 2) and header[18] == header[19] and path_metadata(path) == before)
                size = int.from_bytes(header[16:18], 'big')
                size = 65536 if size == 1 else size
                actual = physical[store['path']]
                need(size == actual['pageSize'] and actual['main'] % size == 0)
                mode = header[18]
                if store['path'] == 'auth/llm-usage.sqlite':
                    need(mode == 1)
                if mode == 1:
                    need(store['recovery']['kind'] == 'main' and not actual['walPresent'] and not actual['shmPresent'])
                modes[store['path']] = mode
            finally:
                os.close(fd)
        return modes

    def small_admission(self):
        self.check_pending()
        need(self.exports == {'pre'} and self.material_exports == {'plan'})
        pre_inventory, plan_inventory = self.export_inventories['pre'], self.export_inventories['plan']
        manifest = private_json(self.backup / 'pre/manifest.json', SMALL_MANIFEST)
        pre = small_snapshot(manifest, pre_inventory)
        plan = private_json(self.backup / 'plan/plan.json', SMALL_PLAN)
        need(plan.get('baseline') == next(r['sha256'] for r in pre_inventory if r['path'] == 'manifest.json'))
        pre['modes'] = self.small_headers(self.backup / 'pre', manifest, pre_inventory)
        need(pre['modes'] == self.small_modes)
        projection = small_plan(plan, plan_inventory, manifest, pre)
        self.qualify_holder(True)
        value = decode(self.run(('docker', 'exec', self.helper_id, 'node', '-e', SMALL_ACCOUNTING_CODE),
                                timeout=5, cap=1024), 1024)
        need(type(value) is dict and set(value) == {'memoryCurrent', 'memoryMax', 'swapMax', 'vmAvailable', 'authFree', 'dataFree', 'backupAllocated'} and
             all(type(v) is int and 0 <= v <= 9007199254740991 for v in value.values()))
        need(value['memoryMax'] == 2 * GIB and value['swapMax'] == 0 and value['memoryCurrent'] <= 768 * MIB and
             value['vmAvailable'] >= 2 * GIB + 256 * MIB and value['authFree'] >= 128 * MIB and value['dataFree'] >= 128 * MIB)
        need(value['backupAllocated'] <= 256 * MIB and
             max(value['backupAllocated'], projection['currentRetained']) + projection['increment'] <= 256 * MIB)
        self.small_projection = projection
        # Count incremental future copies/work on top of total charge, not the
        # retained PRE/clones a second time. Reserves are not allocator maxima.
        peak = value['memoryCurrent'] + projection['increment'] + (128 + 128 + 512 + 128) * MIB
        need(peak <= 1536 * MIB)
        self.qualify_holder(True)
        self.capacity()
        need(time.monotonic() - self.holder_started <= SMALL_APPLY_ELAPSED)
        self.holder_budget(180)

    def attributed_role(self, role, record):
        """OWN immutable identity only: rejected serving config must not prevent stop."""
        need(HEX.fullmatch(record['Id']) is not None and
             record['Id'] == self.new_roles[role] and record['Id'] != self.plan.bindings[role].container and
             record['Name'] == '/' + PROJECT + '-' + role + '-1' and
             record['Image'] == self.plan.selected_image(role))
        labels = record['Config']['Labels']
        need(labels.get('com.docker.compose.project') == PROJECT and
             labels.get('com.docker.compose.service') == role and
             labels.get('com.docker.compose.project.config_files') == str(self.compiled))

    def discover_role(self, role):
        need(self.plan.preservation_migration and role in self.plan.replaced_roles)
        data = self.run(('docker', 'ps', '-a', '--no-trunc', '--filter', 'label=com.docker.compose.project=' + PROJECT,
                         '--filter', 'label=com.docker.compose.service=' + role, '--format', '{{.ID}}'), cap=4096)
        ids = data.decode('ascii').splitlines()
        need(len(ids) == 1 and HEX.fullmatch(ids[0]) is not None)
        record = self.inspect(ids)[ids[0]]
        # Attribution first; no foreign container may become a fail-stop target.
        need(record['Id'] != self.plan.bindings[role].container and
             record['Name'] == '/' + PROJECT + '-' + role + '-1' and
             record['Image'] == self.plan.selected_image(role) and
             record['Config']['Labels'].get('com.docker.compose.project') == PROJECT and
             record['Config']['Labels'].get('com.docker.compose.service') == role and
             record['Config']['Labels'].get('com.docker.compose.project.config_files') == str(self.compiled))
        self.new_roles[role] = record['Id']
        if role == 'api':
            self.new_api = record['Id']

    def check_new_role(self, role, running):
        record = self.inspect([self.new_roles[role]])[self.new_roles[role]]
        self.attributed_role(role, record)
        need(record['Config']['Image'] == self.plan.selected_image(role))
        need(record['State']['Running'] is running and not record['State'].get('Paused') and
             not record['State'].get('Restarting') and not record['State'].get('OOMKilled'))
        defaults = env_map(self.candidate_images[role]['Config'].get('Env') or [])
        defaults.update(env_map(compose_runtime_model(self.model)['services'][role].get('environment', {})))
        need(env_map(record['Config']['Env']) == defaults)
        if role == 'api':
            key_only(env_map(self.old[role]['Config']['Env']), defaults)
        else:
            need(env_map(self.old[role]['Config']['Env']) == defaults)
        if role == 'api' and self.plan.align_api_cve_release:
            need(self.release_seal is not None and self.release_binding is not None)
            need(aligned_config_identity(record, compose_image=self.plan.selected_image(role),
                                         source=self.release_binding['source']) ==
                 aligned_config_identity(self.old[role], compose_image=self.plan.bindings[role].image,
                                         source=self.release_binding['old_source']))
        else:
            need(config_identity(record, compose_image=self.plan.selected_image(role)) ==
                 config_identity(self.old[role], compose_image=self.plan.bindings[role].image))
        health = record['Config'].get('Healthcheck') or {}
        if running and (role == 'api' or health.get('Test') not in (None, [], ['NONE'])):
            need(record['State'].get('Health', {}).get('Status') == 'healthy')
        # Worker/web without Docker healthchecks are not assigned fabricated
        # health. LOCAL signed-release readiness and anonymous ingress 401 are
        # independent gates below; running alone is not serving acceptance.

    def migration_up(self, roles):
        need(self.migration_matched and self.migration_compatible and
             self.exports == {'pre', 'post'} and self.helper_removed)
        need(tuple(roles) in (('api', 'worker'), ('web',)))
        expected_running = {'egress', 'llm-egress'} | ({'api', 'worker'} if tuple(roles) == ('web',) else set())
        self.stable(expected_running)
        self.writers({self.new_roles[r] for r in ('api', 'worker')} if 'api' in expected_running else set())
        need(select(self.repo, self.root) == self.selected)
        self.verify_sources()
        self.secrets_metadata()
        self.verify_candidate_image()
        self.resources()
        need(path_metadata(self.compiled) == self.compiled_metadata)
        need(decode(self.run((*self.command, 'config', '--format', 'json'))) == self.model)
        self.revalidate_export('pre')
        self.revalidate_export('post')
        self.revalidate_export('plan')
        self.revalidate_export('migration')
        self.recheck_release()  # Same sealed selected release/current usability before EACH replacement group.
        self.replacement_attempted.update(roles)  # BEFORE an ambiguous Compose request.
        self.run((*self.command, 'up', '-d', '--no-build', '--pull', 'never', '--no-deps',
                  '--force-recreate', '--wait', '--wait-timeout', '45', *roles), timeout=60, cap=4096)
        for role in roles:
            self.discover_role(role)
            self.check_new_role(role, True)

    def operate_migration(self):
        # No app constructor is used as a migration trial. Only the separately
        # reviewed original-RW SQL helper may cross the first-write boundary.
        with self.stage('FIRST_RELEASE_RECHECK'):
            self.recheck_release()  # Mandatory sealed/current gate before HOLD or first live stop.
        self.phase = 'close_ingress'
        self.hold()
        if not self.plan.reconcile_stopped_stand:
            self.touched = True
            self.stop('web')
            self.phase = 'drain'
            self.sleep(35)
            self.stable({'api', 'worker', 'egress', 'llm-egress'})
            self.phase = 'quiesce'
            self.stop('api', 35)
            self.stop('worker', 35)
        self.stable({'egress', 'llm-egress'})
        self.writers(set())
        self.phase = 'holder'
        self.touched = True  # Fresh holder create is an uncertain daemon write even with originals stopped.
        self.create_holder()
        self.phase = 'capture'
        self.migration_exec('capture')
        self.phase = 'export_pre'
        self.export('pre')  # Durable RAW/working/sealed PRE BEFORE original SQL writes.
        self.phase = 'plan_migration'
        self.migration_exec('plan-migration')
        self.migration_planned = True
        self.export('plan')  # RAW private plan + dry-run copies, durable BEFORE originals RW.
        self.revalidate_export('pre')
        self.revalidate_export('plan')
        need(self.holder_inventory('migration') == self.export_inventories['plan'])
        self.migration_guard()
        self.capacity()
        self.holder_budget(180)  # Fail closed; not a worst-case completion promise.
        self.phase = 'apply_migration'
        need(self.migration_planned and self.exports == {'pre'})
        self.migration_exec('apply-migration')
        self.revalidate_export('pre')
        self.phase = 'migration_match'
        self.holder_budget(120)
        self.migration_exec('capture-post')  # Separate O_RDONLY raw capture; SAME holder/pre.
        self.migration_exec('compare-migrated')
        self.migration_matched = True
        self.phase = 'current_compatibility'
        self.migration_exec('compatibility')  # CURRENT sealed POST + same OLD auth settings.
        self.migration_compatible = True
        self.phase = 'export_post'
        self.export('post')
        self.export('migration')  # Retain apply-attempt/applied records, not only tmpfs.
        self.revalidate_export('pre')
        self.revalidate_export('post')
        self.revalidate_export('plan')
        self.revalidate_export('migration')
        self.migration_guard()
        self.phase = 'cleanup'
        self.remove_holder()
        self.stable({'egress', 'llm-egress'})
        self.writers(set())
        self.phase = 'recreate_pair'
        self.migration_up(('api', 'worker'))
        self.stable({'api', 'worker', 'egress', 'llm-egress'})
        self.writers({self.new_roles[r] for r in ('api', 'worker')})
        self.ready()
        self.anonymous()
        self.phase = 'recreate_web'
        self.migration_up(('web',))  # NEVER resume the OLD worker or OLD web.
        self.phase = 'accept'
        self.stable(set(ROLES))
        self.writers({self.new_roles[r] for r in ('api', 'worker')})
        self.ready()
        self.anonymous(ingress=True)
        result = {'ok': True, 'preservationCompared': True, 'comparisonMode': 'additive-scan-auth',
                  'keyConfigured': True, 'providerOperabilityProven': False, 'postResumeStateCompared': False}
        private_write(self.backup / 'result.json', encoded(dict(result, version=3, preservationMigration=True,
                      migrationReviewEvidence=self.plan.migration_review_evidence,
                      startupReviewEvidence=self.plan.startup_evidence,
                      candidateSourceReviewEvidence=self.plan.candidate_source_evidence,
                      candidateSourceAggregate=self.plan.candidate_source_aggregate,
                      webSourceReviewEvidence=self.plan.web_source_review_evidence,
                      providerCalled=False, schedulesReenabled=False, admissionProfile=SMALL_PROFILE)))
        sync_directory(self.backup)
        sync_directory(self.root)
        self.release_hold()
        return result

    def operate(self):
        if self.plan.qualify_release_only:
            return self.qualify_release()
        with self.stage('PREFLIGHT'):
            self.preflight()
        if self.plan.prepare_rollout_only:
            with self.stage('FIRST_RELEASE_RECHECK'):
                self.recheck_release()
            return {'ok': True, 'preparationOnly': True, 'standServicesRecreated': False,
                    'migrationApplied': False, 'providerCalled': False}
        if self.plan.preservation_migration:
            with self.stage('MIGRATION'):
                return self.operate_migration()
        self.phase = 'close_ingress'
        self.hold()  # Persist failure exclusion BEFORE attempting a daemon write.
        self.touched = True  # Set BEFORE attempting any daemon mutation.
        self.stop('web')
        self.phase = 'drain'
        self.sleep(35)
        self.stable({'api', 'worker', 'egress', 'llm-egress'})
        self.phase = 'quiesce'
        self.stop('api', 35)
        self.stop('worker', 35)
        self.stable({'egress', 'llm-egress'})
        self.writers(set())
        self.phase = 'holder'
        self.create_holder()
        self.phase = 'capture'
        self.snapshot('capture')
        if self.plan.current_source_profile:
            self.phase = 'compatibility'
            self.compatibility()
        self.phase = 'export_pre'
        self.export('pre')
        self.stable({'egress', 'llm-egress'})
        self.verify_sources()
        self.secrets_metadata()
        self.phase = 'recreate'
        need(self.exports == {'pre'} and self.observed_versions == self.plan.expected_versions)
        if self.plan.current_source_profile:
            need(self.compatibility_holder == self.helper_id and not self.helper_removed)
            self.verify_candidate_image()
            self.compatibility_input()
        self.capacity()
        self.holder_budget(120)  # Reserve time beyond up for stop/compare/export; no timer extension.
        self.writers(set())
        need(path_metadata(self.compiled) == self.compiled_metadata)
        need(decode(self.run((*self.command, 'config', '--format', 'json'))) == self.model)
        self.run((*self.command, 'up', '-d', '--no-build', '--pull', 'never', '--no-deps',
                  '--force-recreate', '--wait', '--wait-timeout', '45', 'api'), timeout=60)
        self.discover_api()
        self.phase = 'check_api'
        self.check_new_api(True)
        self.stable({'api', 'egress', 'llm-egress'})
        self.writers({self.new_api})
        self.anonymous()
        self.stop('api', 35)
        self.stable({'egress', 'llm-egress'})
        self.phase = 'compare'
        self.snapshot('compare')
        self.stable({'egress', 'llm-egress'})
        self.phase = 'export_post'
        self.export('post')
        self.verify_sources()
        self.secrets_metadata()
        self.phase = 'cleanup'
        self.remove_holder()
        self.phase = 'resume'
        # Same stopped worker/web IDs, never compose up/dependency expansion for them.
        for role, identity in (('api', self.new_api), ('worker', self.plan.bindings['worker'].container)):
            self.run(('docker', 'start', identity), cap=4096)
            if role == 'api':
                for _ in range(18):
                    state = self.inspect([self.new_api])[self.new_api]['State']
                    if state.get('Health', {}).get('Status') == 'healthy':
                        break
                    self.sleep(1)
                self.check_new_api(True)
        self.stable({'api', 'worker', 'egress', 'llm-egress'})
        self.writers({self.new_api, self.plan.bindings['worker'].container})
        self.ready()  # Ingress remains CLOSED until all prerequisites above pass.
        self.verify_sources()
        self.secrets_metadata()
        self.phase = 'reopen'
        self.run(('docker', 'start', self.plan.bindings['web'].container), cap=4096)
        self.phase = 'accept'
        self.stable(set(ROLES))
        self.anonymous(ingress=True)
        private_write(self.backup / 'result.json', encoded({'version': 2, 'preservationCompared': True,
                      'startupReviewEvidence': self.plan.startup_evidence,
                      'currentSourceProfile': self.plan.current_source_profile,
                      'candidateSourceReviewEvidence': self.plan.candidate_source_evidence,
                      'candidateSourceAggregate': self.plan.candidate_source_aggregate,
                      'apiImageMatched': True, 'keyConfigured': True, 'anonymous401': True,
                      'providerCalled': False, 'providerOperabilityProven': False,
                      'postResumeStateCompared': False}))
        sync_directory(self.backup)
        sync_directory(self.root)
        self.release_hold()
        return {'ok': True, 'preservationCompared': True, 'keyConfigured': True,
                'providerOperabilityProven': False, 'postResumeStateCompared': False}

    def activate(self):
        # A pre-existing lock fails before any action. A failed operation leaves
        # its marker inside the OWN lock, so refresh_lock's rmdir cannot release it.
        try:
            with self.stage('CONTROLLER_ENTRY'):
                self.plan.validate()
                need(not self.plan.prepare_rollout_only or isinstance(self.observation, PreparationObservation))
                with self.stage('ENTRY_ROOT_METADATA'):
                    path_metadata(self.root, directory=True)
            with self.coordination() as capability:
                with self.stage('LOCK_OWNERSHIP'):
                    self.lock_capability = capability
                    self.lock_identity = path_metadata(self.coordination_path, directory=True)[:4]
                try:
                    result = self.operate()
                except BaseException:
                    try:
                        self.retain_release_failure()
                    except BaseException:
                        pass  # Closed uncertainty remains true if private durability failed.
                    raise
            with self.stage('FINAL_ROOT_FSYNC'):
                sync_directory(self.root)  # Persist refresh_lock's successful OWN rmdir.
            with self.stage('COMPLETE'):
                pass
            if self.plan.reconcile_stopped_stand:
                result = dict(result, mode='stopped-stand-preservation-v1', priorHoldPreserved=True,
                              retainedCreatedHolderUntouched=True, manualReconciliationRequired=True)
            return result
        except BaseException:
            if self.touched:
                try:
                    if self.pending_deadline is not None:
                        # ONE cleanup window, anchored to this attempt/holder.
                        # Never overwrite a foreign alarm or reset the holder240s.
                        self.check_owned_timer(allow_expired=True)
                        need(self.cleanup_deadline is None)
                        self.cleanup_deadline = min(time.monotonic() + 20, self.holder_started + 235)
                        self.arm_owned_timer(20, deadline=self.cleanup_deadline)
                        if isinstance(self.run, Runner):
                            self.run.deadline = min(self.pending_runner_deadline, self.cleanup_deadline)
                    elif isinstance(self.run, Runner):
                        self.run.deadline = time.monotonic() + 45
                    self.fail_stop()
                except BaseException:
                    pass  # Fail-stop itself is best effort, not daemon cancellation proof.
                if not self.hold_requested and not self.plan.reconcile_stopped_stand:
                    # A final rmdir/parent-fsync error is a failure too. Acquire a
                    # NEW exclusive OWN lock if possible, never adopt/repair an
                    # existing lock. Failed fsync remains explicitly uncertain.
                    try:
                        with refresh_lock(self.root) as capability:
                            self.lock_capability = capability
                            self.lock_identity = path_metadata(self.root / '.trivy-refresh.lock', directory=True)[:4]
                            self.hold()
                            raise Refusal()  # Keep this OWN marker/lock for review.
                    except BaseException:
                        pass
            result = {'ok': False, 'phase': self.phase, 'uncertain': self.touched or self.release_retained is not None,
                      'manualReconciliationRequired': (self.plan.reconcile_stopped_stand or self.touched or
                                                       self.hold_requested or self.release_retained is not None)}
            if self.plan.reconcile_stopped_stand:
                result['mode'] = 'stopped-stand-preservation-v1'
            return result
        finally:
            try:
                self.end_pending_window()
            except BaseException:
                pass  # Never mask sanitized failure or overwrite a foreign handler.


class QuietParser(argparse.ArgumentParser):
    def error(self, message):
        raise Refusal()


def arguments(argv):
    parser = QuietParser(add_help=False, description='Review required; separate key-only and additive migration preservation modes.')
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--activate-existing-api', action='store_true')
    action.add_argument('--qualify-release-only', action='store_true')
    action.add_argument('--prepare-rollout-only', action='store_true')
    action.add_argument('--reconcile-stopped-stand', action='store_true')
    parser.add_argument('--authorize-held-lock-reconciliation', action='store_true')
    parser.add_argument('--successor-r2', action='store_true')
    parser.add_argument('--successor-r3', action='store_true')
    parser.add_argument('--successor-r4', action='store_true')
    parser.add_argument('--darwin-host-mnt-helper', action='store_true')
    parser.add_argument('--authorize-preservation-window', action='store_true')
    for role in ROLES:
        parser.add_argument('--' + role + '-container', required=True)
        parser.add_argument('--' + role + '-image', required=True)
    parser.add_argument('--sqlite-helper-relative', required=True)
    parser.add_argument('--startup-review-evidence', required=True)
    parser.add_argument('--confirm-old-api-db-reads-reviewed', action='store_true')
    parser.add_argument('--authorize-new-backup-sandbox-2g-240s', action='store_true')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--store-version', action='append',
                      help='Legacy exact required store path=application_id:user_version; reviewed observations only')
    mode.add_argument('--current-source-profile', action='store_true')
    mode.add_argument('--preservation-migration', action='store_true')
    parser.add_argument('--authorize-scan-auth-additive-migration', action='store_true')
    parser.add_argument('--authorize-migration-rw-sandbox-2g-240s', action='store_true')
    parser.add_argument('--candidate-worker-image')
    parser.add_argument('--candidate-web-image')
    parser.add_argument('--migration-review-evidence', default='')
    parser.add_argument('--web-source-review-evidence', default='')
    parser.add_argument('--align-api-cve-release', action='store_true')
    parser.add_argument('--release-verifier-relative', default='')
    parser.add_argument('--release-verifier-test-relative', default='')
    parser.add_argument('--candidate-api-image')
    parser.add_argument('--candidate-source-aggregate', default='')
    parser.add_argument('--candidate-source-review-evidence', default='')
    parser.add_argument('--confirm-original-worker-profile-reviewed', action='store_true')
    parser.add_argument('--source-sha256', action='append', required=True, help='Public relative-path=full-SHA256 only')
    args = parser.parse_args(argv)
    need((args.activate_existing_api or args.qualify_release_only or args.prepare_rollout_only or
          args.reconcile_stopped_stand) and
         args.authorize_preservation_window)
    sources = {}
    for item in args.source_sha256:
        relative, separator, sha = item.partition('=')
        need(separator and relative not in sources)
        sources[relative] = sha
    versions = {}
    for item in args.store_version or ():
        relative, separator, value = item.partition('=')
        need(separator and relative in REQUIRED_STORES and relative not in versions and
             re.fullmatch(r'(0|[1-9][0-9]{0,9}):(0|[1-9][0-9]{0,9})', value))
        versions[relative] = tuple(int(n) for n in value.split(':'))
    plan = Plan({role: Binding(getattr(args, role.replace('-', '_') + '_container'),
                              getattr(args, role.replace('-', '_') + '_image')) for role in ROLES},
                sources, args.sqlite_helper_relative, startup_evidence=args.startup_review_evidence,
                store_versions=None if args.current_source_profile or args.preservation_migration else versions,
                backup_sandbox_reviewed=args.authorize_new_backup_sandbox_2g_240s,
                old_db_reads_reviewed=args.confirm_old_api_db_reads_reviewed,
                current_source_profile=args.current_source_profile,
                candidate_api_image=args.candidate_api_image,
                candidate_source_aggregate=args.candidate_source_aggregate,
                candidate_source_evidence=args.candidate_source_review_evidence,
                original_worker_profile_reviewed=args.confirm_original_worker_profile_reviewed,
                preservation_migration=args.preservation_migration,
                additive_migration_authorized=args.authorize_scan_auth_additive_migration,
                migration_rw_sandbox_authorized=args.authorize_migration_rw_sandbox_2g_240s,
                candidate_worker_image=args.candidate_worker_image, candidate_web_image=args.candidate_web_image,
                migration_review_evidence=args.migration_review_evidence,
                web_source_review_evidence=args.web_source_review_evidence,
                align_api_cve_release=args.align_api_cve_release,
                release_verifier=args.release_verifier_relative,
                release_verifier_test=args.release_verifier_test_relative,
                qualify_release_only=args.qualify_release_only, prepare_rollout_only=args.prepare_rollout_only,
                reconcile_stopped_stand=args.reconcile_stopped_stand,
                held_lock_reconciliation_authorized=args.authorize_held_lock_reconciliation,
                darwin_host_mnt_helper=args.darwin_host_mnt_helper, successor_r2=args.successor_r2,
                successor_r3=args.successor_r3, successor_r4=args.successor_r4)
    plan.validate()
    return plan


def main(argv=None, *, observation=None):
    argv = sys.argv[1:] if argv is None else argv
    if observation is None:
        observation = BOOTSTRAP_OBSERVATION
    if observation is None:
        observation = command_observation(argv)
    try:
        with observed_stage(observation, 'ARGUMENTS'):
            plan = arguments(argv)
            need(observation is None or plan.prepare_rollout_only or
                 plan.reconcile_stopped_stand and isinstance(observation, ReconciliationObservation))
        with observed_stage(observation, 'SOURCE_GATE_LOAD'):
            env = dict(os.environ)  # Preserve ambient interpolation decisions; never print them.
            options = {'observation': observation} if observation is not None else {}
            runner = Runner(REPO, env, budget=150 if plan.qualify_release_only or plan.prepare_rollout_only else 600,
                            **options)
            attempt_id = uuid.uuid4().hex if plan.align_api_cve_release else None
            gate = load_release_gate(REPO, plan, runner, deadline=runner.deadline, attempt_id=attempt_id)
        result = Controller(REPO, plan, runner, env=env, release_gate=gate,
                            release_attempt_id=attempt_id, **options).activate()
    except BaseException:
        result = {'ok': False, 'phase': 'preflight', 'uncertain': False,
                  'manualReconciliationRequired': '--reconcile-stopped-stand' in argv}
        if '--reconcile-stopped-stand' in argv:
            result['mode'] = 'stopped-stand-preservation-v1'
    if observation is not None:
        if not result['ok'] and observation.first is None:
            observation.fail('CONTROLLER_ENTRY', Refusal())
        result = observation.receipt(result)
    sys.stdout.buffer.write(encoded(result))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
