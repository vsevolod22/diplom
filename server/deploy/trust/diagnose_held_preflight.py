#!/usr/bin/env python3
"""Separate read-only capture and NOT-readonly held preparation; no rollout/retry.

Review this pair and literal before invocation. -I -B; caller wall fence110000ms.
Shared90s; <=12 exact read clients, each<=15s, stdout+stderr<=2MiB (version4KiB,
retained64KiB). Trusted existing Compose configuration/inspect Env is processed
ONLY privately in memory, with the same inherited environment as the incident
shell and explicit fixed endpoint/empty context. No private values are exported.
Five exact coordination paths: metadata ONLY, no enumeration/content read/adoption.
The real pinned release factory is loaded but NEVER verify/recheck/invoked.
Only capture_preflight_model(), followed by unconditional return: no coordination,
full preflight, PRIVATE_DIRECTORY, actor, store, SQL, HTTP, write or cleanup.
Public source reads<=2MiB/file; Docker binary<=128MiB, stable exact measured identity.
Kernel I/O is not universally preemptible; external supervisor remains necessary.
Any refusal is HOLD, never automatic retry. A prefix PASS is NOT full preflight.

--prepare-held-preflight is a SEPARATE NOT-readonly150s preparation, caller180000ms:
real PreparationObservation + full authoritative preflight() + first host recheck,
then RETURN. Both existing lock/HOLD pairs are metadata-guarded at stage/client
boundaries, NEVER acquired/adopted/changed. Root identity/mode stays fixed; its
mtime/link count can change ONLY because authoritative preflight creates fresh
OWN0700 scratch before the release seal. Compiled/alignment/retention files stay
private there. ONE actual pinned release actor<=90s; ordinary read clients<=15s,
<=40 clients total. No store holder, SQL, apps, provider, scanner or coordination.
Actor intent and returned identity are durably recorded before create/start;
failed actors are retained under the original verifier policy, never blindly rm.
Metadata checkpoints are not continuous host exclusion. No automatic cleanup.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid

REPO = Path('/Users/vsevolod/Documents/startup/diplom')
SELF = 'server/deploy/trust/diagnose_held_preflight.py'
TEST = 'server/deploy/trust/test_diagnose_held_preflight.py'
CONTROLLER = 'server/deploy/trust/recreate_openrouter_key.py'
SELECTOR = 'server/deploy/trust/stand_composition.py'
VERIFIER = 'server/deploy/trust/verify_preservation_release.py'
VERIFIER_TEST = 'server/deploy/trust/test_verify_preservation_release.py'
PINS = {
    CONTROLLER: 'e07bc714b8d2aa8f3175f3b07ca51ed7a0154691cebd2992518d4312c140239b',
    'server/deploy/trust/test_recreate_openrouter_key.py': '511906937d4f57208d3c0702bbef79312d5902eb91e103091b6b5400db99e539',
    'server/deploy/trust/sqlite_state_snapshot.mjs': '323ca629483f92896634ada79d2c8f098d9ff885464eb24ba9d86bb75e563dee',
    'server/deploy/trust/sqlite_state_snapshot.test.mjs': 'f9668e4f288a712969bf50199f38464b3d854d28d3dc4d4e58647c9c7d59453e',
    SELECTOR: '97283889749a4413d5e27f9b0ce828927f56b56ef507cb220a3c607fd3d23f5a',
    'server/deploy/compose.stand.yaml': 'da5c96aaa959e10b32868a458e9cc53e7a819596a33e9ac913f8f2966f552509',
    'server/deploy/compose.stand.vuln.local.yaml': '80ec2a655f661cfa5f51fcea0b99e216ae048b356a9c67e830e01d34bcdbe275',
    'server/deploy/compose.stand.nginx.local.yaml': 'f6587a7a355ac1c51610d65f1851223a72b9e0e64e09f548c3e8faca0ab0e3a6',
    'server/deploy/compose.stand.openrouter.free.yaml': '6dcb3afd60363998e98d3ac1629d25c5a166ba00455d1cc735c26d2d686fb326',
    VERIFIER: 'c93ced26d68140f2afe3201db16b373ecc5260a9212fd2075d2e978c1d898533',
    VERIFIER_TEST: '04c1748f6f5180225584e0f06e4e80f0e0598f2390a0bbd60296374b504fbd39',
}
FILES = tuple(p for p in PINS if p.endswith('.yaml'))
SOCKET = 'unix:///Users/vsevolod/.docker/run/docker.sock'
PROJECT = 'dip-auth-stand'
DOCKER = Path('/opt/homebrew/Cellar/docker/28.1.1/bin/docker')
DOCKER_SHA256 = '5cfddb229b6278953fdbb5016619e0f786ac8291969183fb28e3717a92f8bd52'
DOCKER_STAT = (16777233, 1321905, 0o100555, 1, 501, 80, 28011650,
               1744969487000000000, 1746429174027377498)
HEX = re.compile(r'[a-f0-9]{64}\Z')
MIB = 1024 * 1024
PATH_IDS = ('ROOT', 'PRIOR_LOCK', 'PRIOR_HOLD', 'RECONCILE_LOCK', 'RECONCILE_HOLD')
METADATA_CODES = frozenset(('NOT_OBSERVED', 'PARENT_NOT_SAFE', 'PRESENT_SAFE', 'MISSING',
    'SYMLINK', 'WRONG_TYPE', 'WRONG_OWNER', 'WRONG_MODE', 'MULTILINK', 'SIZE_REFUSED',
    'UNSAFE_ANCESTRY', 'CHANGED', 'IO_REFUSED'))
OWN_STAGES = frozenset(('ARGUMENTS', 'SELF_PINS', 'PUBLIC_PINS', 'IMPORT', 'PLAN',
    'COORDINATION_METADATA', 'PRIOR_SNAPSHOT', 'RELEASE_FACTORY_LOAD', 'CONTROLLER_ENTRY',
    'PREFIX_RETURN', 'COMPLETE'))
CAPTURE_STAGES = frozenset(('CAPTURE_PLAN', 'CAPTURE_PROTOCOL', 'ROOT_METADATA', 'SOURCE_PINS',
    'SECRET_METADATA', 'COMPOSE_AMBIENT', 'COMPOSE_VERSION', 'SELECTOR', 'ORIGINAL_INSPECT',
    'RETAINED_CREATED', 'CANDIDATE_IMAGES', 'RENDER', 'MODEL_SHAPE',
        'GATE_ROOT_METADATA', 'GATE_SOURCE_PINS',
    *('OLD_' + r for r in ('API', 'WORKER', 'WEB', 'EGRESS', 'LLM_EGRESS')),
    *('IMAGE_' + r for r in ('API', 'WORKER', 'WEB', 'EGRESS', 'LLM_EGRESS'))))
CATEGORIES = frozenset(('NONE', 'PREDICATE_REFUSED', 'CLIENT_TIMEOUT', 'CLIENT_NONZERO',
    'CLIENT_EXEC_IDENTITY', 'CLIENT_EXEC_NOT_FOUND', 'CLIENT_EXEC_DENIED', 'CLIENT_EXEC_OS_REFUSED',
    'COMMAND_REFUSED', 'OUTPUT_CAP', 'IO_REFUSED', 'UNEXPECTED'))


class Refused(Exception):
    def __init__(self, category='PREDICATE_REFUSED'):
        self.category = category if category in CATEGORIES - {'NONE'} else 'UNEXPECTED'
        super().__init__()


def need(value, category='PREDICATE_REFUSED'):
    if not value:
        raise Refused(category)


def stamp(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_uid, st.st_gid,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


class Observation:
    def __init__(self, clock=time.monotonic, *, preparation=False):
        self.clock, self.deadline = clock, clock() + (150 if preparation else 90)
        self.stack, self.first, self.module = [], None, None
        self.metadata = dict.fromkeys(PATH_IDS, 'NOT_OBSERVED')

    def check(self):
        if self.clock() >= self.deadline:
            raise Refused('CLIENT_TIMEOUT')
        need(self.first is None)

    def fail(self, gate, exc):
        if self.first is not None:
            return
        point = self.stack[-1] if self.stack else gate
        point = point if point in OWN_STAGES | CAPTURE_STAGES else 'CONTROLLER_ENTRY'
        category = ('CLIENT_TIMEOUT' if self.clock() >= self.deadline or isinstance(exc, subprocess.TimeoutExpired)
                    else exc.category if type(exc) is Refused
                    else 'PREDICATE_REFUSED' if self.module is not None and isinstance(
                        exc, (self.module.Refusal, self.module.BootstrapRefusal))
                    else 'PREDICATE_REFUSED' if point == 'SELECTOR' and type(exc) is ValueError
                    else 'IO_REFUSED' if isinstance(exc, OSError) else 'UNEXPECTED')
        self.first = (point, category)

    def __call__(self, gate, event):
        need(gate in OWN_STAGES | CAPTURE_STAGES and event in ('ENTER', 'PASS'))
        if event == 'ENTER':
            self.stack.append(gate)
        self.check()
        if event == 'PASS':
            need(self.stack and self.stack[-1] == gate)
            self.stack.pop()

    @contextmanager
    def stage(self, gate):
        try:
            self(gate, 'ENTER')
            yield
            self(gate, 'PASS')
        except BaseException as exc:
            self.fail(gate, exc)
            raise

    def receipt(self, ok):
        point, category = self.first or ('COMPLETE', 'NONE')
        need(point in OWN_STAGES | CAPTURE_STAGES and category in CATEGORIES)
        need(set(self.metadata) == set(PATH_IDS) and all(v in METADATA_CODES for v in self.metadata.values()))
        return dict(code='CAPTURE_PREFIX_PASS' if ok else 'REFUSED', ok=ok,
                    checkpoint=point, category=category, coordinationMetadata=self.metadata,
                    capturePrefixOnly=True, fullQualification='NOT_CLAIMED',
                    privateValuesExported=False, releaseActorInvoked=False,
                    coordinationAdopted=False, mutationAttempted=False, manualReconciliationRequired=True)


@contextmanager
def directories(path, check, *, safe=True):
    """No-follow descriptors, stable linked ancestry; no listing or contents."""
    need(path.is_absolute() and str(path) == os.path.normpath(path) and '..' not in path.parts)
    fds, edges = [], []
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fds.append(fd)
        for part in path.parts[1:]:
            check()
            before = os.stat(part, dir_fd=fds[-1], follow_symlinks=False)
            need(stat.S_ISDIR(before.st_mode) and (not safe or not before.st_mode & 0o022))
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1])
            fds.append(child)
            need(stamp(before) == stamp(os.fstat(child)))
            edges.append((fds[-2], part, before))
        yield fds[-1]
        check()
        for parent, part, before in edges:
            need(stamp(os.stat(part, dir_fd=parent, follow_symlinks=False)) == stamp(before))
    finally:
        for fd in reversed(fds):
            os.close(fd)


def public_bytes(path, check, cap=2 * MIB, *, binary=False):
    with directories(path.parent, check, safe=not binary) as parent:
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= cap)
        if not binary:
            need(before.st_uid == os.geteuid() and not before.st_mode & 0o022)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            need(stamp(os.fstat(fd)) == stamp(before))
            data = bytearray()
            while True:
                check()
                block = os.read(fd, min(65536, cap + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
                need(len(data) <= cap)
            need(len(data) == before.st_size and stamp(os.fstat(fd)) == stamp(before) and
                 stamp(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == stamp(before))
            return bytes(data)
        finally:
            os.close(fd)


def verified_sources(repo, argv, obs):
    with obs.stage('ARGUMENTS'):
        need(len(argv) == 5 and argv[0] in ('--diagnose-held-preflight', '--prepare-held-preflight') and
             argv[1] == '--source-sha256' and argv[3] == '--test-sha256' and
             HEX.fullmatch(argv[2]) and HEX.fullmatch(argv[4]))
        need(sys.flags.isolated and sys.dont_write_bytecode and
             Path(__file__).absolute() == repo / SELF and repo == REPO)
    with obs.stage('SELF_PINS'):
        for relative, pin in ((SELF, argv[2]), (TEST, argv[4])):
            need(hashlib.sha256(public_bytes(repo / relative, obs.check)).hexdigest() == pin)
    with obs.stage('PUBLIC_PINS'):
        captured = {}
        for relative, pin in PINS.items():
            data = public_bytes(repo / relative, obs.check)
            need(hashlib.sha256(data).hexdigest() == pin)
            if relative == CONTROLLER:
                captured[relative] = data
        return captured


def load_controller(repo, captured):
    name = '_dip_held_preflight_controller'
    need(not any(n in sys.modules for n in (name, 'stand_composition', '_dip_pinned_stand_composition_bootstrap')))
    need(hashlib.sha256(captured[CONTROLLER]).hexdigest() == PINS[CONTROLLER])
    spec = importlib.util.spec_from_file_location(name, repo / CONTROLLER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        exec(compile(captured[CONTROLLER], str(repo / CONTROLLER), 'exec'), module.__dict__)
        need(module.SELECTOR_SHA256 == PINS[SELECTOR] and CAPTURE_STAGES <= module.STAGE_IDS)
        return module
    finally:
        if sys.modules.get(name) is module:
            del sys.modules[name]


def incident_plan(m):
    # Exact incident bindings in the hash-verified controller, not resource discovery.
    plan = m.Plan({r: m.Binding(c, i) for r, (c, i) in m.RECONCILIATION_ORIGINALS.items()},
        dict(PINS), m.HELPER_PATH, startup_evidence='DIP-ARTF-502', old_db_reads_reviewed=True,
        preservation_migration=True, additive_migration_authorized=True,
        migration_rw_sandbox_authorized=True,
        candidate_api_image=m.RECONCILIATION_CANDIDATES['api'],
        candidate_worker_image=m.RECONCILIATION_CANDIDATES['worker'],
        candidate_web_image=m.RECONCILIATION_CANDIDATES['web'],
        candidate_source_aggregate='29c3ca5bd186d625cc102e2f7e43b4f1e8e168ba3372cabd7840cc21b6676a37',
        candidate_source_evidence='DIP-ARTF-502', migration_review_evidence='DIP-ARTF-491',
        web_source_review_evidence='DIP-ARTF-463', align_api_cve_release=True,
        release_verifier=VERIFIER, release_verifier_test=VERIFIER_TEST,
        reconcile_stopped_stand=True, held_lock_reconciliation_authorized=True, darwin_host_mnt_helper=True)
    plan.validate()
    return plan


def classify_metadata(path, kind, check):
    """No opening marker files; exact no-follow metadata predicates only."""
    try:
        # Classify unsafe ancestry separately, never follow a symlink parent.
        for ancestor in reversed(path.parents):
            check()
            st = ancestor.lstat()
            if not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o022:
                return 'UNSAFE_ANCESTRY'
        with directories(path.parent, check) as parent:
            before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                result = 'SYMLINK'
            elif not (stat.S_ISREG(before.st_mode) if kind == 'hold' else stat.S_ISDIR(before.st_mode)):
                result = 'WRONG_TYPE'
            elif before.st_uid != os.geteuid():
                result = 'WRONG_OWNER'
            elif (stat.S_IMODE(before.st_mode) != (0o600 if kind == 'hold' else 0o700)
                  if kind != 'root' else bool(before.st_mode & 0o022)):
                result = 'WRONG_MODE'
            elif kind == 'hold' and before.st_nlink != 1:
                result = 'MULTILINK'
            elif kind == 'hold' and not 0 < before.st_size <= 8192:
                result = 'SIZE_REFUSED'
            else:
                result = 'PRESENT_SAFE'
            check()
            if stamp(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) != stamp(before):
                return 'CHANGED'
        return result
    except FileNotFoundError:
        return 'MISSING'
    except OSError:
        return 'IO_REFUSED'


def coordination_metadata(repo, obs):
    root = repo / '.local-auth'
    paths = (root, root / '.trivy-refresh.lock', root / '.trivy-refresh.lock/KEY_ACTIVATION_HOLD.json',
             root / '.key-preservation-reconcile.lock',
             root / '.key-preservation-reconcile.lock/KEY_ACTIVATION_HOLD.json')
    for key, path, kind, parent in zip(PATH_IDS, paths, ('root', 'lock', 'hold', 'lock', 'hold'),
                                      (None, 'ROOT', 'PRIOR_LOCK', 'ROOT', 'RECONCILE_LOCK')):
        obs.check()
        obs.metadata[key] = ('PARENT_NOT_SAFE' if parent and obs.metadata[parent] != 'PRESENT_SAFE'
                             else classify_metadata(path, kind, obs.check))
    return paths


def verify_executable(check):
    try:
        check()
        need(stamp(DOCKER.lstat()) == DOCKER_STAT, 'CLIENT_EXEC_IDENTITY')
        data = public_bytes(DOCKER, check, 128 * MIB, binary=True)
        need(hashlib.sha256(data).hexdigest() == DOCKER_SHA256 and stamp(DOCKER.lstat()) == DOCKER_STAT,
             'CLIENT_EXEC_IDENTITY')
        check()
    except FileNotFoundError:
        raise Refused('CLIENT_EXEC_NOT_FOUND') from None
    except PermissionError:
        raise Refused('CLIENT_EXEC_DENIED') from None
    except OSError:
        raise Refused('CLIENT_EXEC_OS_REFUSED') from None
    except Refused as exc:
        if exc.category == 'CLIENT_TIMEOUT':
            raise
        raise Refused('CLIENT_EXEC_IDENTITY') from None


def capture(argv, repo, env, until, cap, clock=time.monotonic):
    try:
        proc = subprocess.Popen(argv, cwd=repo, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    except FileNotFoundError:
        raise Refused('CLIENT_EXEC_NOT_FOUND') from None
    except PermissionError:
        raise Refused('CLIENT_EXEC_DENIED') from None
    except OSError:
        raise Refused('CLIENT_EXEC_OS_REFUSED') from None
    output, total = bytearray(), 0
    try:
        with selectors.DefaultSelector() as streams:
            for pipe, keep in ((proc.stdout, True), (proc.stderr, False)):
                os.set_blocking(pipe.fileno(), False)
                streams.register(pipe, selectors.EVENT_READ, keep)
            while streams.get_map():
                remaining = max(0.0, until - clock())
                need(remaining > 0, 'CLIENT_TIMEOUT')
                for event, _ in streams.select(min(0.05, remaining)):
                    try:
                        block = os.read(event.fileobj.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not block:
                        streams.unregister(event.fileobj)
                    else:
                        total += len(block)
                        need(total <= cap, 'OUTPUT_CAP')
                        if event.data:
                            output.extend(block)
            remaining = max(0.0, until - clock())
            need(remaining > 0, 'CLIENT_TIMEOUT')
            need(proc.wait(timeout=remaining) == 0, 'CLIENT_NONZERO')
        return bytes(output)
    except BaseException as exc:
        # Kill/reap only this read-client process group; preserve FIRST failure.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except BaseException:
            pass
        try:
            proc.wait(timeout=0.2)
        except BaseException:
            pass
        if isinstance(exc, subprocess.TimeoutExpired):
            raise Refused('CLIENT_TIMEOUT') from None
        raise
    finally:
        for pipe in (proc.stdout, proc.stderr):
            try:
                pipe.close()
            except BaseException:
                pass


class ReadRunner:
    def __init__(self, repo, env, m, plan, obs):
        self.repo, self.env, self.obs, self.deadline = repo, dict(env), obs, obs.deadline
        self.observation = obs  # Frozen controller's load-only factory stage interface.
        originals = tuple(b.container for b in plan.bindings.values())
        images = tuple(b.image for b in plan.bindings.values()) + tuple(
            plan.selected_image(r) for r in plan.replaced_roles)
        selected = ('docker', 'compose', '--env-file', str(repo / '.local-auth/stand.env'))
        for relative in FILES:
            selected += ('-f', str(repo / relative))
        render = (*selected, '--project-name', PROJECT, '--project-directory',
                  str(repo / 'server/deploy'), 'config', '--format', 'json')
        self.allowed = {('docker', 'compose', 'version', '--short'): 4096,
            ('docker', 'inspect', '--type', 'container', *originals): 2 * MIB,
            ('docker', 'inspect', '--type', 'container', '--format', m.RETAINED_FORMAT,
             m.RETAINED_CREATED_ID): 65536, render: 2 * MIB,
            **{('docker', 'image', 'inspect', image): 2 * MIB for image in images}}
        need(len(self.allowed) == 12)
        self.used = set()

    def __call__(self, args, timeout=15, cap=2 * MIB, input_data=None):
        self.obs.check()
        args = tuple(args)
        need(args in self.allowed and args not in self.used and len(self.used) < 12 and input_data is None,
             'COMMAND_REFUSED')
        need(self.env.get('DOCKER_HOST') == SOCKET and self.env.get('DOCKER_CONTEXT') == '')
        need(type(cap) is int and 0 < cap <= self.allowed[args] and type(timeout) in (int, float) and
             math.isfinite(timeout) and timeout > 0)
        self.used.add(args)  # Consume before launch; no failure retry.
        verify_executable(self.obs.check)
        until = min(self.deadline, self.obs.clock() + min(15, timeout))
        data = capture((str(DOCKER), '--host', SOCKET, *args[1:]), self.repo, self.env, until, cap,
                       clock=self.obs.clock)
        self.obs.check()
        need(type(data) is bytes and len(data) <= cap, 'OUTPUT_CAP')
        return data


class HeldMetadataGuard:
    """Exact existing pairs; no file contents, listing, writes or lock capability."""
    def __init__(self, m, paths):
        self.m, self.paths, self.changed = m, paths, False
        self.baseline = self.snapshot()

    def snapshot(self):
        root = self.m.path_metadata(self.paths[0], directory=True)
        # Root entry creation is expressly allowed; root identity/owner/mode is not.
        values = [(root[:4], self.paths[0].lstat().st_gid)]
        for index, path in enumerate(self.paths[1:]):
            self.m.path_metadata(path, directory=index % 2 == 0, secret=index % 2 == 1)
            st = path.lstat()
            need(stat.S_IMODE(st.st_mode) == (0o700 if index % 2 == 0 else 0o600))
            values.append(stamp(st))
        return tuple(values)

    def __call__(self):
        try:
            need(self.snapshot() == self.baseline)
        except BaseException:
            self.changed = True
            raise


def preparation_observer(m, bootstrap, guard):
    """Actual production150s observer, narrowed to this preparation's stages."""
    allowed = CAPTURE_STAGES | frozenset(('PREFLIGHT', 'PRIVATE_DIRECTORY', 'RELEASE_VERIFY',
        'MODEL_RESTRICTIONS', 'IMAGE_SUBSTITUTION', 'COMPILED_WRITE', 'ALIGNMENT_WRITE',
        'PRIVATE_DIRECTORY_FSYNC', 'COMPILED_METADATA', 'COMPILED_QUIET', 'COMPILED_RENDER',
        'COMPILED_EQUAL', 'AUTH_INPUT', 'NETWORKS', 'VOLUMES', 'HOST_CAPACITY', 'ENGINE_MEMORY',
        'HELPER_UID_ACCESS', 'WRITER_FENCE', 'STABILITY', 'SOURCE_FINAL', 'SECRET_FINAL',
        'SELECTOR_FINAL', 'API_SOCKET_GUARD', 'FIRST_RELEASE_RECHECK', 'COMPLETE',
        'SOURCE_GATE_LOAD', 'CONTROLLER_ENTRY',
        *('MODEL_' + r for r in ('API', 'WORKER', 'WEB', 'EGRESS', 'LLM_EGRESS'))))
    def callback(gate, event):
        need(gate in allowed or gate in m.PREDICATE_IDS)
        if gate in m.STAGE_IDS:
            guard()
    class HeldPreparationObservation(m.PreparationObservation):
        def fail(self, gate, exc):
            if self.first is None and type(exc) is Refused and self.clock() < self.deadline:
                self.first = (self.stack[-1] if self.stack else gate, exc.category)
            else:
                super().fail(gate, exc)
    observer = HeldPreparationObservation(clock=bootstrap.clock, callback=callback)
    observer.deadline = bootstrap.deadline  # Includes source/bootstrap time, never renew.
    return observer


class PrepareRunner(ReadRunner):
    """Exact finite suffix reads plus ONE authoritative verifier instance's lifecycle.

    Record the pinned instance's _command result, _guard success and _result success;
    do not duplicate its sandbox/trust predicates or permit arbitrary create argv.
    """
    def __init__(self, repo, env, m, plan, obs, guard):
        super().__init__(repo, env, m, plan, obs)
        self.m, self.plan, self.guard = m, plan, guard
        self.controller = self.gate = self.actor = None
        self.intent = self.actor_id = self.checked_state = None
        self.actor_result = False
        self.counts, self.calls, self.create_used, self.start_used, self.rm_used, self.stop_used = {}, 0, False, False, False, False
        self.scratch = self.scratch_identity = None
        self.intent_recorded = self.created_recorded = self.retained_recorded = False
        self.actor_attempted = self.mutation_attempted = False
        self.writer_ids = ()

    def bind_gate(self, gate):
        need(self.gate is None and isinstance(gate, self.m.PinnedReleaseGate))
        self.gate, self.actor = gate, gate._gate
        original_command, original_guard, original_result = self.actor._command, self.actor._guard, self.actor._result
        def command(request, captured):
            need(self.intent is None)
            result = original_command(request, captured)
            need(type(result) is tuple and result[:2] == ('docker', 'create'))
            self.intent = result
            return result
        def checked(info, state=None):
            result = original_guard(info, state)
            self.checked_state = (self.actor.id, info['state']['Status'])
            return result
        def authenticated(raw, captured):
            result = original_result(raw, captured)
            self.actor_result = True
            return result
        self.actor._command, self.actor._guard, self.actor._result = command, checked, authenticated

    def bind_scratch(self):
        c = self.controller
        need(c is not None and self.scratch is None and c.backup is not None and
             c.backup.parent == c.root and re.fullmatch(r'key-preservation-[a-z0-9_]{8}', c.backup.name) and
             c.compiled == c.backup / 'compiled.json')
        meta = self.m.path_metadata(c.backup, directory=True)
        need(stat.S_IMODE(meta[2]) == 0o700)
        self.scratch, self.scratch_identity = c.backup, meta[:4]
        self.mutation_attempted = True

    def private_record(self, filename, value):
        need(filename in ('release-verifier-intent.json', 'release-verifier-created.json',
                          'release-verifier-retained.json'))
        need(self.scratch is not None and self.m.path_metadata(self.scratch, directory=True)[:4] ==
             self.scratch_identity)
        need(self.obs.clock() < self.deadline)
        self.m.private_write(self.scratch / filename, self.m.encoded(value))
        self.m.sync_directory(self.scratch)
        self.m.sync_directory(self.scratch.parent)

    def retain_failure(self):
        retained = None if self.gate is None else self.gate.retained
        if retained is None:
            return
        need(type(retained) is dict and set(retained) == {'name', 'id'} and
             retained['name'] == self.actor.name and
             (retained['id'] is None or type(retained['id']) is str and HEX.fullmatch(retained['id'])))
        self.private_record('release-verifier-retained.json', retained)
        self.retained_recorded = True

    def suffix_read(self, args):
        c = self.controller
        need(c is not None, 'COMMAND_REFUSED')
        original = ('docker', 'inspect', '--type', 'container', *(b.container for b in self.plan.bindings.values()))
        retained = ('docker', 'inspect', '--type', 'container', '--format', self.m.RETAINED_FORMAT,
                    self.m.RETAINED_CREATED_ID)
        if args in self.allowed:
            limit = 2 if args in (original, retained) else 1
            return self.allowed[args], limit
        if self.scratch is not None:
            base = ('docker', 'compose', '--project-name', PROJECT, '--project-directory',
                    str(self.repo / 'server/deploy'), '--env-file', '/dev/null', '-f', str(c.compiled))
            if args in ((*base, 'config', '--quiet'), (*base, 'config', '--format', 'json')):
                return 2 * MIB, 1
        if args == ('docker', 'volume', 'inspect', *self.m.VOLUMES.values()):
            return 2 * MIB, 2
        ids = tuple(sorted({v['NetworkID'] for r in c.old.values()
                            for v in r.get('NetworkSettings', {}).get('Networks', {}).values()}))
        need(len(ids) <= 32 and all(type(i) is str and HEX.fullmatch(i) for i in ids), 'COMMAND_REFUSED')
        # Authoritative resources() preserves insertion order of initial network inspect.
        if ids and args in (('docker', 'network', 'inspect', *ids),
                            ('docker', 'network', 'inspect', *c.networks)):
            return 2 * MIB, 3
        if args in (('docker', 'info', '--format', '{{json .MemTotal}}'),
                    ('docker', 'info', '--format', '{{json .ID}}')):
            return 4096, 1
        if args == ('docker', 'ps', '-a', '--no-trunc', '--format', '{{.ID}}'):
            return MIB, 1
        fmt = ('{"id":{{json .Id}},"running":{{json .State.Running}},'
               '"mounts":{{json .Mounts}}}')
        if self.writer_ids and args == ('docker', 'inspect', '--type', 'container', '--format', fmt,
                                        *self.writer_ids):
            return 2 * MIB, 1
        raise Refused('COMMAND_REFUSED')

    def actor_command(self, args):
        a = self.actor
        if a is None:
            return None
        # Constants/formats are obtained from the verified factory's defining module.
        namespace = a._image.__func__.__globals__
        if args == ('docker', 'image', 'inspect', '--format', namespace['IMAGE_FORMAT'], namespace['API']):
            return 16384, 1, 'read'
        if args == ('docker', 'ps', '-aq', '--no-trunc', '--filter', 'name=^/' + a.name + '$'):
            return 16384, 1, 'read'
        if self.intent is not None and args == self.intent:
            need(not self.create_used and self.scratch is not None, 'COMMAND_REFUSED')
            self.create_used = self.actor_attempted = self.mutation_attempted = True
            self.private_record('release-verifier-intent.json', {'name': a.name, 'id': None})
            self.intent_recorded = True
            return 4096, 1, 'create'
        if self.actor_id is None or a.id != self.actor_id:
            return None
        if args == ('docker', 'container', 'inspect', '--format', namespace['INSPECT_FORMAT'], self.actor_id):
            return 16384, 4, 'read'
        if args == ('docker', 'start', '--attach', self.actor_id):
            need(not self.start_used and self.checked_state == (self.actor_id, 'created'), 'COMMAND_REFUSED')
            self.start_used = True
            return 16384, 1, 'start'
        if args == ('docker', 'rm', self.actor_id):
            need(not self.rm_used and self.actor_result and self.checked_state == (self.actor_id, 'exited'),
                 'COMMAND_REFUSED')
            self.rm_used = True
            return 16384, 1, 'remove'
        if args == ('docker', 'stop', '--time', '1', self.actor_id):
            need(not self.stop_used and self.checked_state == (self.actor_id, 'running'), 'COMMAND_REFUSED')
            self.stop_used = True
            return 16384, 1, 'stop'
        return None

    def __call__(self, args, timeout=15, cap=2 * MIB, input_data=None):
        try:
            return self._execute(args, timeout=timeout, cap=cap, input_data=input_data)
        except BaseException as exc:
            # Preserve transport's first category before the gate wraps its failure.
            self.obs.fail('CONTROLLER_ENTRY', exc)
            raise

    def _execute(self, args, timeout=15, cap=2 * MIB, input_data=None):
        args = tuple(args)
        cleanup = (self.obs.first is not None and self.actor is not None and self.actor._failed and
                   self.actor_id is not None and self.actor.id == self.actor_id and
                   (args == ('docker', 'stop', '--time', '1', self.actor_id) or
                    args[:4] == ('docker', 'container', 'inspect', '--format') and
                    len(args) == 6 and args[-1] == self.actor_id))
        def check():
            if cleanup:
                # Only the pinned gate's existing guarded inspect/stop failure path;
                # never restart forward work, renew deadlines or replace first failure.
                need(self.obs.clock() < self.deadline, 'CLIENT_TIMEOUT')
            else:
                self.obs.check()
        check()
        self.guard()
        need(input_data is None and self.calls < 40 and self.env.get('DOCKER_HOST') == SOCKET and
             self.env.get('DOCKER_CONTEXT') == '', 'COMMAND_REFUSED')
        actor = self.actor_command(args)
        ceiling, limit, kind = actor if actor is not None else (*self.suffix_read(args), 'read')
        need(type(cap) is int and 0 < cap <= ceiling and type(timeout) in (int, float) and
             math.isfinite(timeout) and timeout > 0)
        used = self.counts.get(args, 0)
        need(used < limit, 'COMMAND_REFUSED')
        self.counts[args], self.calls = used + 1, self.calls + 1
        verify_executable(check)
        until = min(self.deadline, self.obs.clock() + min(timeout, 90 if kind == 'start' else 15))
        data = capture((str(DOCKER), '--host', SOCKET, *args[1:]), self.repo, self.env, until, cap,
                       clock=self.obs.clock)
        need(type(data) is bytes and len(data) <= cap, 'OUTPUT_CAP')
        if kind == 'create':
            identity = data.strip().decode('ascii')
            need(HEX.fullmatch(identity) is not None)
            self.actor_id = identity
            self.private_record('release-verifier-created.json', {'name': self.actor.name, 'id': identity})
            self.created_recorded = True
        elif args == ('docker', 'ps', '-a', '--no-trunc', '--format', '{{.ID}}'):
            ids = data.decode('ascii').splitlines()
            need(len(ids) <= 32 and len(ids) == len(set(ids)) and all(HEX.fullmatch(i) for i in ids))
            self.writer_ids = tuple(ids)
        self.guard()
        check()
        return data


def prepare_held(repo, env, captured, bootstrap):
    with bootstrap.stage('IMPORT'):
        m = load_controller(repo, captured)
        bootstrap.module = m
    with bootstrap.stage('PLAN'):
        plan = incident_plan(m)  # Incident comparison profile, NOT activation argv.
        need(env.get('DOCKER_HOST') == SOCKET and env.get('DOCKER_CONTEXT') == '')
    with bootstrap.stage('COORDINATION_METADATA'):
        paths = coordination_metadata(repo, bootstrap)
        need(all(v == 'PRESENT_SAFE' for v in bootstrap.metadata.values()))
        guard = HeldMetadataGuard(m, paths)
    observer = preparation_observer(m, bootstrap, guard)
    runner = PrepareRunner(repo, env, m, plan, observer, guard)
    controller = None
    # Extend only the observation callback to bind the authoritative fresh scratch.
    callback = observer.callback
    def stages(gate, event):
        callback(gate, event)
        if gate == 'PRIVATE_DIRECTORY' and event == 'ENTER':
            need(runner.controller is not None and runner.controller.backup is None)
            runner.mutation_attempted = True  # mkdir can partly succeed before failure.
        if gate == 'PRIVATE_DIRECTORY' and event == 'PASS':
            runner.bind_scratch()
    observer.callback = stages
    ok = False
    try:
        with m.observed_stage(observer, 'SOURCE_GATE_LOAD'):
            gate = m.load_release_gate(repo, plan, runner, deadline=observer.deadline, attempt_id=uuid.uuid4().hex)
            runner.bind_gate(gate)
        with m.observed_stage(observer, 'CONTROLLER_ENTRY'):
            controller = m.Controller(repo, plan, runner, env=env, release_gate=gate,
                                      release_attempt_id=runner.actor.attempt_id, observation=observer)
            controller.prior_hold_metadata = (m.path_metadata(paths[1], directory=True),
                                               m.path_metadata(paths[2], secret=True))
            runner.controller = controller
        with m.observed_stage(observer, 'PREFLIGHT'):
            controller.preflight()  # Full authoritative suffix, including compiled writes/fsync.
        with m.observed_stage(observer, 'FIRST_RELEASE_RECHECK'):
            controller.recheck_release()
        with m.observed_stage(observer, 'COMPLETE'):
            guard()
            need(not controller.touched and controller.lock_capability is None and
                 controller.reconciliation_capability is None and controller.helper_id is None and
                 not controller.migration_planned and not controller.replacement_attempted and
                 gate.retained is None)
        ok = True
    except BaseException as exc:
        observer.fail('CONTROLLER_ENTRY', exc)
        # Do NOT call retain_release_failure(): it asserts OWN lock authority.
        try:
            runner.retain_failure()
        except BaseException:
            pass  # Intent/created record remain private; receipt never certifies durability.
    finally:
        try:
            guard()  # Check failure exits too; never replace a prior failure.
        except BaseException as exc:
            ok = False
            observer.fail('COMPLETE', exc)
    point, category = observer.first or ('COMPLETE', 'NONE')
    need(point in m.STAGE_IDS | m.PREDICATE_IDS and category in CATEGORIES | m.STAGE_CATEGORIES)
    retained = runner.gate is not None and runner.gate.retained is not None
    receipt = dict(code='HELD_PREPARATION_PASS' if ok else 'REFUSED', ok=ok,
        checkpoint=point, category=category, preparationOnly=True, readOnly=False,
        capturePrefixOnly=False, fullQualification='NOT_CLAIMED', coordinationMetadata=bootstrap.metadata,
        heldMetadataUnchanged=not guard.changed, coordinationAdopted=False,
        releaseActorAttempted=runner.actor_attempted, mutationAttempted=runner.mutation_attempted,
        retainedActorPossible=retained, retainedIdentityRecorded=runner.retained_recorded,
        actorIntentRecorded=runner.intent_recorded, actorCreatedRecorded=runner.created_recorded,
        privateValuesExported=False, standServicesRecreated=False, migrationApplied=False,
        providerCalled=False, manualReconciliationRequired=True)
    return receipt, 0 if ok else 1  # No coordination/operate/activate/migration continuation.


def diagnose(repo, env, captured, obs):
    with obs.stage('IMPORT'):
        m = load_controller(repo, captured)
        obs.module = m
    with obs.stage('PLAN'):
        plan = incident_plan(m)
        need(env.get('DOCKER_HOST') == SOCKET and env.get('DOCKER_CONTEXT') == '')
        runner = ReadRunner(repo, env, m, plan, obs)
    with obs.stage('COORDINATION_METADATA'):
        paths = coordination_metadata(repo, obs)
    with obs.stage('PRIOR_SNAPSHOT'):
        need(all(obs.metadata[k] == 'PRESENT_SAFE' for k in ('ROOT', 'PRIOR_LOCK', 'PRIOR_HOLD')))
        prior = (m.path_metadata(paths[1], directory=True), m.path_metadata(paths[2], secret=True))
        need(stat.S_IMODE(prior[0][2]) == 0o700)
        # Reconcile lock/HOLD are observation only, never adopted or required absent.
    with obs.stage('RELEASE_FACTORY_LOAD'):
        attempt = uuid.uuid4().hex  # Memory only; never a resource creation request.
        gate = m.load_release_gate(repo, plan, runner, deadline=obs.deadline, attempt_id=attempt)
    with obs.stage('CONTROLLER_ENTRY'):
        controller = m.Controller(repo, plan, runner, env=env, release_gate=gate,
                                  release_attempt_id=attempt, observation=obs)
        controller.prior_hold_metadata = prior  # Actual observations, NOT lock ownership.
    controller.capture_preflight_model()
    with obs.stage('PREFIX_RETURN'):
        need(controller.backup is None and controller.compiled is None and not controller.touched and
             controller.lock_capability is None and controller.reconciliation_capability is None and
             not controller.release_verification_attempted and controller.release_seal is None and
             gate.retained is None)
    return  # Explicit boundary: never call preflight(), coordination(), verify() or lifecycle.


def run(argv, repo=REPO, env=None):
    preparation = bool(argv and argv[0] == '--prepare-held-preflight')
    obs = Observation(preparation=preparation)
    try:
        captured = verified_sources(repo, argv, obs)
        if preparation:
            return prepare_held(repo, dict(os.environ if env is None else env), captured, obs)
        diagnose(repo, dict(os.environ if env is None else env), captured, obs)
        return obs.receipt(True), 0
    except BaseException as exc:
        obs.fail('CONTROLLER_ENTRY', exc)
        receipt = obs.receipt(False)
        if preparation:
            receipt.update(preparationOnly=True, readOnly=False, capturePrefixOnly=False,
                           standServicesRecreated=False, migrationApplied=False, providerCalled=False)
        return receipt, 1


def main():
    # Quarantine incidental import/child diagnostics; no traceback or exception text.
    out = os.dup(1)
    try:
        with open(os.devnull, 'wb', buffering=0) as sink:
            os.dup2(sink.fileno(), 1)
            os.dup2(sink.fileno(), 2)
            receipt, code = run(sys.argv[1:])
        data = json.dumps(receipt, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                          allow_nan=False).encode('ascii')
        need(len(data) <= 4096)
        os.write(out, data + b'\n')
        return code
    except BaseException:
        os.write(out, b'{"category":"UNEXPECTED","checkpoint":"CONTROLLER_ENTRY","code":"REFUSED","ok":false}\n')
        return 1
    finally:
        os.close(out)


if __name__ == '__main__':
    raise SystemExit(main())
