#!/usr/bin/env python3
"""507 review candidate: a bounded observation, NEVER an activation attempt.

Only pinned stdlib-only production predicates/read methods are reused. No lock,
backup, compiled file, helper, DB, HTTP, signal installation or repair operation.
READ_SUBSET_PASS excludes lock acquisition/release, compiled-file writes/fsync,
compiled Compose roundtrip, and every stopped-state/migration/serving gate.
Private child output/Env stays in memory. Parent execution needs fresh independent
source + literal approval; spent504 is not authority to run this program.

--classify-models-only is a separate, narrower observation: after the existing
capture it evaluates at most one authoritative comparator per role, plus eight
fixed mount flags, entirely in memory. It NEVER continues to later read clients
or emits READ_SUBSET_PASS/D_COMPLETE, even when every model comparison passes.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
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

REPO = Path(__file__).resolve().parents[3]
PROJECT = 'dip-auth-stand'
SOCKET = 'unix:///Users/vsevolod/.docker/run/docker.sock'
MIB = 1024 * 1024
HEX = re.compile(r'[a-f0-9]{64}\Z')
ROLES = ('api', 'worker', 'web', 'egress', 'llm-egress')
FILES = ('server/deploy/compose.stand.yaml', 'server/deploy/compose.stand.vuln.local.yaml',
         'server/deploy/compose.stand.nginx.local.yaml', 'server/deploy/compose.stand.openrouter.free.yaml')
CONTROLLER = 'server/deploy/trust/recreate_openrouter_key.py'
SELECTOR = 'server/deploy/trust/stand_composition.py'
SELF = 'server/deploy/trust/diagnose_preservation_preflight.py'
TEST = 'server/deploy/trust/test_diagnose_preservation_preflight.py'
PINS = {
    CONTROLLER: 'b34dcd63a77d06d997b4c6bf61a36bc7fbe67d8129aa12f444d055a1b9f50438',
    'server/deploy/trust/test_recreate_openrouter_key.py': 'b34b1f14483ee7f5a280181042e5eb11bbdc8459e42c247c7c72cd4b0cb914cb',
    'server/deploy/trust/sqlite_state_snapshot.mjs': '323ca629483f92896634ada79d2c8f098d9ff885464eb24ba9d86bb75e563dee',
    'server/deploy/trust/sqlite_state_snapshot.test.mjs': 'f9668e4f288a712969bf50199f38464b3d854d28d3dc4d4e58647c9c7d59453e',
    SELECTOR: '97283889749a4413d5e27f9b0ce828927f56b56ef507cb220a3c607fd3d23f5a',
    FILES[0]: 'da5c96aaa959e10b32868a458e9cc53e7a819596a33e9ac913f8f2966f552509',
    FILES[1]: '80ec2a655f661cfa5f51fcea0b99e216ae048b356a9c67e830e01d34bcdbe275',
    FILES[2]: 'f6587a7a355ac1c51610d65f1851223a72b9e0e64e09f548c3e8faca0ab0e3a6',
    FILES[3]: '6dcb3afd60363998e98d3ac1629d25c5a166ba00455d1cc735c26d2d686fb326',
}
RELEASE_VERIFIER_PINS = {
    'server/deploy/trust/verify_preservation_release.py': 'c93ced26d68140f2afe3201db16b373ecc5260a9212fd2075d2e978c1d898533',
    'server/deploy/trust/test_verify_preservation_release.py': '04c1748f6f5180225584e0f06e4e80f0e0598f2390a0bbd60296374b504fbd39',
}
ORIGINALS = {
    'api': ('5cbe0936a5f09d663a77960749e687fbd41fbef52c8990b063362b9363d3e9ec', '487c3909d3eeee08d60840a81c1adeb61c292aee0a31df17b2a8cf92f6dbb58c'),
    'worker': ('016c41e7b3eabcbb08903bbc3c54d657ed92c22813e47fa37d444cb448602b44', '8748cbebba753603d79f320c2fb476c46ab676ce12e0aa08bee0021a3e14e57a'),
    'web': ('b84245ef672d172d5513971a57ea91469800846cdf6c59bedceb006b06caa4f4', '1659b39c98d5183c91feae78a8d9eb1d4c6ee527d541c1e1d74dfe842adee8c0'),
    'egress': ('2850e2d03d0681482727f7b5d658961ef9ef2aa829b63473f36d8ed3c63f3d35', '2b9eff3b381979c82bf42c310fcd7941805d42adeda67c8814143d6503490655'),
    'llm-egress': ('f64639115f21233277ac52db2bd5ceda495203511da87896ff996e8c1ce3a68a', '3ccbd5a6c3348b7b1c99e23b29d9bdca485dfd48f690a408a119e06163a59a8d'),
}
CANDIDATES = {
    'api': '4b3a3d4b3c2658ec9a36209afcac69eda2b64cef6e055a5e2716e2602e5338d1',
    'worker': '891b5adccbe469345cea585e75dc71c6d3bf93405c5a18386795af1b012b314d',
    'web': '3d14f3d9e7347a9609fe3ae53b46efd70293aacae64da48c001ed6e826155817',
}
AGGREGATE = '29c3ca5bd186d625cc102e2f7e43b4f1e8e168ba3372cabd7840cc21b6676a37'
EVIDENCES = {'startup': 'DIP-ARTF-502', 'candidate-source': 'DIP-ARTF-502',
             'migration': 'DIP-ARTF-491', 'web-source': 'DIP-ARTF-463'}
MOUNT_FORMAT = ('{"id":{{json .Id}},"running":{{json .State.Running}},'
                '"mounts":{{json .Mounts}}}')
CATEGORIES = frozenset(('NONE', 'PREDICATE_REFUSED', 'CLIENT_NONZERO', 'CLIENT_TIMEOUT',
                        'OUTPUT_CAP', 'DECODE_REFUSED', 'UNEXPECTED'))
MOUNT_FLAGS = ('MALFORMED', 'CARDINALITY_MISMATCH', 'DUPLICATE_TARGETS', 'UNMATCHED_TARGETS',
               'TYPE_MISMATCH', 'BIND_SOURCE_MISMATCH', 'NAMED_VOLUME_SOURCE_MISMATCH', 'RW_MISMATCH')
MOUNT_CLASSIFY_LIMIT = 256
CHECKPOINTS = frozenset((
    'D_ARGUMENTS', 'D_ROOT_ANCESTRY', 'D_LOCK_ABSENT', 'D_SELF', 'D_TEST', 'D_IMPORT',
    'D_CLASSIFY_RUNTIME', 'D_CLASSIFY_MOUNTS', 'D_MODELS_CLASSIFIED',
    'D_PLAN', 'D_PROTOCOL', 'D_ALARM_AVAILABLE', 'D_COMPOSE_AMBIENT', 'D_COMPOSE_VERSION',
    'D_SELECTOR', 'D_ORIGINAL_INSPECT', 'D_RENDER', 'D_MODEL_SHAPE', 'D_MODEL_RESTRICTIONS', 'D_API_CONFIG',
    'D_API_OLD_POLICY', 'D_API_CANDIDATE_POLICY', 'D_API_KEY_SHAPE', 'D_API_NONKEY_ENV',
    'D_IMAGE_ONLY', 'D_AUTH_INPUT', 'D_NETWORKS', 'D_VOLUMES', 'D_HOST_DISK',
    'D_ENGINE_MEMORY', 'D_HELPER_UID_ACCESS', 'D_WRITER_FENCE', 'D_STABLE_FINAL',
    'D_SECRET_FINAL', 'D_SELECTOR_FINAL', 'D_API_SOCKET_GUARD', 'D_LOCK_FINAL', 'D_COMPLETE',
    *('D_PUBLIC_%02d' % n for n in range(1, 12)),
    *('D_PUBLIC_FINAL_%02d' % n for n in range(1, 12)),
    'D_SECRET_LEGACY', 'D_SECRET_STAGED', 'D_SECRET_STAND',
    *('D_OLD_' + r.upper().replace('-', '_') for r in ROLES),
    *('D_OLD_IMAGE_' + r.upper().replace('-', '_') for r in ROLES),
    *('D_CANDIDATE_' + r.upper() for r in CANDIDATES),
    *('D_MODEL_' + r.upper().replace('-', '_') for r in ROLES),
))


class ClosedFailure(Exception):
    def __init__(self, category):
        self.category = category if category in CATEGORIES - {'NONE'} else 'UNEXPECTED'
        super().__init__()  # No child diagnostics or private text.


def require(ok):
    if not ok:
        raise ClosedFailure('PREDICATE_REFUSED')


def classify_mounts(runtime, role, record):
    """Read-only structural flags; exactly the production four-tuple projections.

    No aliases, normalization, counts or operands leave this function. Field
    comparisons require identical unique destination sets; otherwise they are
    BLOCKED, not guessed by sorted position or by a non-unique source.
    """
    flags = dict.fromkeys(MOUNT_FLAGS, 'BLOCKED')
    try:
        mounts = runtime['services'][role].get('volumes', [])
        actual = record['Mounts']
        require(type(mounts) is list and type(actual) is list and
                len(mounts) <= MOUNT_CLASSIFY_LIMIT and len(actual) <= MOUNT_CLASSIFY_LIMIT)
        expected = [(m['type'], runtime['volumes'][m['source']]['name'] if m['type'] == 'volume' else m['source'],
                     m['target'], not m.get('read_only', False)) for m in mounts]
        observed = [(m['Type'], m.get('Name') if m['Type'] == 'volume' else m['Source'],
                     m['Destination'], m['RW']) for m in actual if m['Type'] != 'tmpfs']
        require(all(all(type(v) is str for v in row[:3]) and type(row[3]) is bool
                    for row in (*expected, *observed)))
    except (ClosedFailure, KeyError, TypeError, AttributeError, ValueError):
        flags['MALFORMED'] = 'YES'
        return flags
    flag = lambda value: 'YES' if value else 'NO'
    flags['MALFORMED'] = 'NO'
    flags['CARDINALITY_MISMATCH'] = flag(len(expected) != len(observed))
    e_targets, a_targets = [row[2] for row in expected], [row[2] for row in observed]
    duplicate = len(set(e_targets)) != len(e_targets) or len(set(a_targets)) != len(a_targets)
    unmatched = set(e_targets) != set(a_targets)
    flags['DUPLICATE_TARGETS'], flags['UNMATCHED_TARGETS'] = flag(duplicate), flag(unmatched)
    if duplicate or unmatched:
        return flags
    e_map, a_map = {row[2]: row for row in expected}, {row[2]: row for row in observed}
    pairs = [(row, a_map[target]) for target, row in e_map.items()]
    type_mismatch = any(e[0] != a[0] for e, a in pairs)
    flags['TYPE_MISMATCH'] = flag(type_mismatch)
    flags['RW_MISMATCH'] = flag(any(e[3] != a[3] for e, a in pairs))
    if not type_mismatch:
        flags['BIND_SOURCE_MISMATCH'] = flag(any(e[0] == 'bind' and e[1] != a[1] for e, a in pairs))
        flags['NAMED_VOLUME_SOURCE_MISMATCH'] = flag(any(e[0] == 'volume' and e[1] != a[1] for e, a in pairs))
    return flags


def metadata(path, directory=False):
    """Bootstrap public/ancestry check, before trusting the pinned module bodies."""
    path = Path(path).absolute()
    for ancestor in (*reversed(path.parents), path):
        st = ancestor.lstat()
        require(not stat.S_ISLNK(st.st_mode))
        if ancestor != path:
            require(stat.S_ISDIR(st.st_mode) and not st.st_mode & 0o022)
    st = path.lstat()
    require(st.st_uid == os.geteuid() and not st.st_mode & 0o022)
    require(stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode) and st.st_nlink == 1)
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_nlink, st.st_size, st.st_mtime_ns)


def public_bytes(path, expected):
    require(type(expected) is str and HEX.fullmatch(expected))
    before = metadata(path)
    require(before[5] <= 2 * MIB)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        require((st.st_dev, st.st_ino) == before[:2])
        chunks, total = [], 0
        while block := os.read(fd, 65536):
            total += len(block)
            require(total <= 2 * MIB)
            chunks.append(block)
        data = b''.join(chunks)
        require(metadata(path) == before and hashlib.sha256(data).hexdigest() == expected)
        return data
    finally:
        os.close(fd)


def lock_absent(root):
    try:
        (root / '.trivy-refresh.lock').lstat()
    except FileNotFoundError:
        return
    raise ClosedFailure('PREDICATE_REFUSED')  # Including dangling symlinks; never open/remove.


def load_dependencies(repo, verified):
    """Execute exactly the captured, verified PUBLIC bytes, never __main__/app code."""
    name = '_dip_pinned_preservation_predicates'
    require(all(n not in sys.modules for n in
                ('stand_composition', '_dip_pinned_stand_composition_bootstrap', name)))
    for relative in (SELECTOR, CONTROLLER):
        require(hashlib.sha256(verified[relative]).hexdigest() == PINS[relative])
    # No selector injection: the controller separately captures its fixed sibling,
    # verifies the same approved pin, and executes only that captured public source.
    spec = importlib.util.spec_from_file_location(name, repo / CONTROLLER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        exec(compile(verified[CONTROLLER], str(repo / CONTROLLER), 'exec'), module.__dict__)
        require(module.SELECTOR_SHA256 == PINS[SELECTOR])
        return module
    finally:
        if sys.modules.get(name) is module:
            del sys.modules[name]


class QuietParser(argparse.ArgumentParser):
    def error(self, message):
        raise ClosedFailure('PREDICATE_REFUSED')


def arguments(argv):
    parser = QuietParser(add_help=False, allow_abbrev=False)
    parser.add_argument('--classify-models-only', action='store_true')
    parser.add_argument('--align-api-cve-release', action='store_true')
    parser.add_argument('--release-verifier-relative', default='')
    parser.add_argument('--release-verifier-test-relative', default='')
    for flag in ('diagnose-preflight-only', 'authorize-preservation-window', 'preservation-migration',
                 'authorize-scan-auth-additive-migration', 'authorize-migration-rw-sandbox-2g-240s',
                 'confirm-old-api-db-reads-reviewed'):
        parser.add_argument('--' + flag, action='store_true', required=True)
    for role in ROLES:
        parser.add_argument('--' + role + '-container', required=True)
        parser.add_argument('--' + role + '-image', required=True)
    for role in CANDIDATES:
        parser.add_argument('--candidate-' + role + '-image', required=True)
    for name in EVIDENCES:
        parser.add_argument('--' + name + '-review-evidence', required=True)
    for name in ('candidate-source-aggregate', 'sqlite-helper-relative',
                 'diagnostic-sha256', 'diagnostic-test-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--source-sha256', action='append', required=True)
    args = parser.parse_args(argv)
    sources = {}
    for item in args.source_sha256:
        relative, sep, sha = item.partition('=')
        require(sep and relative not in sources)
        sources[relative] = sha
    extra = ()
    if args.align_api_cve_release:
        require(args.classify_models_only and re.fullmatch(
            r'server/deploy/trust/[a-z][a-z0-9_]{0,63}\.py', args.release_verifier_relative))
        require(args.release_verifier_test_relative == str(Path(args.release_verifier_relative).with_name(
            'test_' + Path(args.release_verifier_relative).name)))
        extra = (args.release_verifier_relative, args.release_verifier_test_relative)
        require(extra == tuple(RELEASE_VERIFIER_PINS) and
                all(sources.get(p) == pin for p, pin in RELEASE_VERIFIER_PINS.items()))
    else:
        require(args.release_verifier_relative == args.release_verifier_test_relative == '')
    require(set(sources) == set((*PINS, *extra)) and all(sources[p] == pin for p, pin in PINS.items()) and
            all(HEX.fullmatch(sources[p]) for p in extra))
    args.verified_sources = {**PINS, **{p: sources[p] for p in extra}}
    for role, (container, image) in ORIGINALS.items():
        prefix = role.replace('-', '_')
        require(getattr(args, prefix + '_container') == container and
                getattr(args, prefix + '_image') == 'sha256:' + image)
    for role, image in CANDIDATES.items():
        require(getattr(args, 'candidate_' + role + '_image') == 'sha256:' + image)
    for name, evidence in EVIDENCES.items():
        require(getattr(args, name.replace('-', '_') + '_review_evidence') == evidence)
    require(args.candidate_source_aggregate == AGGREGATE and
            args.sqlite_helper_relative == 'server/deploy/trust/sqlite_state_snapshot.mjs')
    require(HEX.fullmatch(args.diagnostic_sha256) and HEX.fullmatch(args.diagnostic_test_sha256))
    return args


def plan_for(m, args):
    # Comparison-only assertions; do not manufacture an activation argv or call main.
    return m.Plan({r: m.Binding(c, 'sha256:' + i) for r, (c, i) in ORIGINALS.items()},
                  dict(args.verified_sources), args.sqlite_helper_relative,
                  startup_evidence=args.startup_review_evidence, old_db_reads_reviewed=True,
                  preservation_migration=True, additive_migration_authorized=True,
                  migration_rw_sandbox_authorized=True,
                  candidate_api_image='sha256:' + CANDIDATES['api'],
                  candidate_worker_image='sha256:' + CANDIDATES['worker'],
                  candidate_web_image='sha256:' + CANDIDATES['web'],
                  candidate_source_aggregate=AGGREGATE,
                  candidate_source_evidence=args.candidate_source_review_evidence,
                  migration_review_evidence=args.migration_review_evidence,
                  web_source_review_evidence=args.web_source_review_evidence,
                  align_api_cve_release=args.align_api_cve_release,
                  release_verifier=args.release_verifier_relative,
                  release_verifier_test=args.release_verifier_test_relative)


def private_decode(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError()
            result[key] = value
        return result
    def constant(value):
        raise ValueError()
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ClosedFailure('DECODE_REFUSED') from None


def capture(argv, repo, env, timeout, cap, *, clock=time.monotonic, spawn=subprocess.Popen):
    """No shell/stdin. Bound both private streams; reap on EVERY unsuccessful exit."""
    proc = spawn(argv, cwd=repo, env=env, stdin=subprocess.DEVNULL,
                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    output, size = bytearray(), 0
    until = clock() + timeout
    try:
        with selectors.DefaultSelector() as streams:
            for pipe, stdout in ((proc.stdout, True), (proc.stderr, False)):
                os.set_blocking(pipe.fileno(), False)
                streams.register(pipe, selectors.EVENT_READ, stdout)
            while streams.get_map():
                remaining = until - clock()
                if remaining <= 0:
                    raise ClosedFailure('CLIENT_TIMEOUT')
                for event, _ in streams.select(min(remaining, 0.1)):
                    try:
                        block = os.read(event.fileobj.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not block:
                        streams.unregister(event.fileobj)
                    else:
                        size += len(block)
                        if size > cap:
                            raise ClosedFailure('OUTPUT_CAP')
                        if event.data:
                            output.extend(block)
            remaining = until - clock()
            if remaining <= 0:
                raise ClosedFailure('CLIENT_TIMEOUT')
            try:
                code = proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                raise ClosedFailure('CLIENT_TIMEOUT') from None
            if code != 0:
                raise ClosedFailure('CLIENT_NONZERO')
        return bytes(output)
    except BaseException:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        raise
    finally:
        proc.stdout.close()
        proc.stderr.close()


class ReadRunner:
    """Exact read argv only; no production Runner/lifecycle or arbitrary formats."""
    def __init__(self, repo, env, *, clock=time.monotonic, transport=capture, deadline=None):
        self.repo, self.env, self.clock, self.transport = repo, dict(env), clock, transport
        self.deadline = clock() + 120 if deadline is None else deadline
        self.networks, self.enumerated = (), ()
        self.original_ids = tuple(c for c, _ in ORIGINALS.values())
        self.images = frozenset('sha256:' + i for _, i in ORIGINALS.values()) | frozenset(
            'sha256:' + i for i in CANDIDATES.values())
        selected = ('docker', 'compose', '--env-file', str(repo / '.local-auth/stand.env'))
        for relative in FILES:
            selected += ('-f', str(repo / relative))
        self.render = selected + ('--project-name', PROJECT, '--project-directory',
                                  str(repo / 'server/deploy'), 'config', '--format', 'json')

    def remaining(self):
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise ClosedFailure('CLIENT_TIMEOUT')
        return remaining

    def bind_networks(self, records):
        require(set(records) == set(ROLES))
        ids = sorted({v['NetworkID'] for record in records.values()
                      for v in record['NetworkSettings']['Networks'].values()})
        require(0 < len(ids) <= 32 and all(type(i) is str and HEX.fullmatch(i) for i in ids))
        self.networks = tuple(ids)
        return self.networks

    def __call__(self, args, timeout=15, cap=2 * MIB, input_data=None):
        args = tuple(args)
        require(input_data is None and self.env.get('DOCKER_HOST') == SOCKET and
                self.env.get('DOCKER_CONTEXT') == '')
        kind, ceiling = 'json', 2 * MIB
        if args == ('docker', 'compose', 'version', '--short'):
            kind, ceiling = 'text', 4096
        elif args == self.render:
            pass
        elif args[:4] == ('docker', 'inspect', '--type', 'container') and args[4:] == self.original_ids:
            pass
        elif len(args) == 4 and args[:3] == ('docker', 'image', 'inspect') and args[3] in self.images:
            pass
        elif self.networks and args == ('docker', 'network', 'inspect', *self.networks):
            pass
        elif args == ('docker', 'volume', 'inspect', PROJECT + '_auth_accounts', PROJECT + '_scan_ledger'):
            pass
        elif args in (('docker', 'info', '--format', '{{json .ID}}'),
                      ('docker', 'info', '--format', '{{json .MemTotal}}')):
            ceiling = 4096
        elif args == ('docker', 'ps', '-a', '--no-trunc', '--format', '{{.ID}}'):
            kind, ceiling = 'ids', MIB
        elif (args[:6] == ('docker', 'inspect', '--type', 'container', '--format', MOUNT_FORMAT)
              and 0 < len(args[6:]) <= 32 and len(set(args[6:])) == len(args[6:])
              and self.enumerated and all(i in self.enumerated for i in args[6:])):
            kind = 'rows'
        else:
            raise ClosedFailure('PREDICATE_REFUSED')
        require(type(timeout) in (int, float) and timeout > 0 and type(cap) is int and 0 < cap <= ceiling)
        data = self.transport(args, self.repo, self.env, min(timeout, 15, self.remaining()), cap)
        require(type(data) is bytes)
        if len(data) > cap:
            raise ClosedFailure('OUTPUT_CAP')
        self.remaining()
        if kind == 'ids':
            try:
                ids = tuple(data.decode('ascii').splitlines())
            except UnicodeError:
                raise ClosedFailure('DECODE_REFUSED') from None
            require(len(ids) <= 512 and len(set(ids)) == len(ids) and all(HEX.fullmatch(i) for i in ids))
            self.enumerated = ids
        elif kind == 'rows':
            rows = data.splitlines()
            require(len(rows) == len(args[6:]))
            for row in rows:
                private_decode(row)
        elif kind == 'json':
            private_decode(data)
        return data


class Diagnostic:
    def __init__(self, repo, env, *, clock=time.monotonic, reader=public_bytes,
                 loader=load_dependencies, runner_factory=ReadRunner):
        self.repo, self.env, self.clock = Path(repo).absolute(), dict(env), clock
        self.deadline = clock() + 120
        self.reader, self.loader, self.runner_factory = reader, loader, runner_factory
        self.checkpoint, self.m = 'D_ARGUMENTS', None
        self.predicate_stack, self.predicate_role = [], 'api'
        self.deadline_expired = False
        self.classify_models_only = False
        self.first_failure = None
        self.model_status = dict.fromkeys(ROLES, 'BLOCKED')
        self.mount_status = {role: dict.fromkeys(MOUNT_FLAGS, 'BLOCKED') for role in ROLES}
        self.source_pins, self.alignment_shape_only = dict(PINS), False

    def predicate_event(self, gate, event):
        # Only public fixed identifiers, never operands, paths, counts or Env keys.
        require(self.m is not None and gate in self.m.PREDICATE_IDS and event in ('ENTER', 'PASS'))
        require(self.predicate_role in ROLES or self.classify_models_only and self.predicate_role == 'all')
        if event == 'ENTER':
            require(len(self.predicate_stack) < 8)
            self.predicate_stack.append(gate)
        else:
            require(self.predicate_stack and self.predicate_stack[-1] == gate)
            self.predicate_stack.pop()
        active = self.predicate_stack or [gate]
        identifiers = [active[0]] + ([active[-1]] if len(active) > 1 else [])
        self.checkpoint = 'D_P_' + self.predicate_role.upper().replace('-', '_') + '__' + '__'.join(identifiers)
        if self.clock() >= self.deadline:
            self.deadline_expired = True
            raise ClosedFailure('CLIENT_TIMEOUT')

    def step(self, checkpoint, function, *args, **kwargs):
        require(checkpoint in CHECKPOINTS)
        self.checkpoint = checkpoint
        if self.clock() >= self.deadline:
            raise ClosedFailure('CLIENT_TIMEOUT')
        result = function(*args, **kwargs)
        if self.clock() >= self.deadline:
            raise ClosedFailure('CLIENT_TIMEOUT')
        return result

    def sources(self, final=False):
        verified = {}
        for n, (relative, pin) in enumerate(self.source_pins.items(), 1):
            checkpoint = ('D_PUBLIC_FINAL_' if final else 'D_PUBLIC_') + '%02d' % n
            verified[relative] = self.step(checkpoint, self.reader, self.repo / relative, pin)
        return verified

    def api_env(self, c, model):
        m = self.m
        observer = self.predicate_event
        model = m.predicate(observer, 'API_PREP_RUNTIME', lambda: m.compose_runtime_model(model, observer))
        actual = m.predicate(observer, 'API_PREP_ACTUAL_ENV',
                             lambda: m.env_map(c.old['api']['Config']['Env'], observer, 'API_OLD_ENV'))
        expected = m.predicate(observer, 'API_PREP_IMAGE_ENV',
                               lambda: m.env_map(c.images['api']['Config'].get('Env') or [], observer, 'API_IMAGE_ENV'))
        expected.update(m.predicate(observer, 'API_PREP_SERVICE_ENV',
                                   lambda: m.env_map(model['services']['api'].get('environment', {}), observer, 'API_SERVICE_ENV')))
        self.step('D_API_OLD_POLICY', m.policy, actual, observer, 'OLD_POLICY')
        self.step('D_API_CANDIDATE_POLICY', m.policy, expected, observer, 'CANDIDATE_POLICY')
        self.step('D_API_KEY_SHAPE', m.need, type(expected.get(m.KEY)) is str and
                  0 < len(expected[m.KEY].encode()) <= 4096)
        self.step('D_API_NONKEY_ENV', m.need,
                  {k: v for k, v in actual.items() if k != m.KEY} ==
                  {k: v for k, v in expected.items() if k != m.KEY})
        m.predicate(observer, 'API_KEY_ONLY', lambda: m.key_only(actual, expected, observer))  # Full invariant retained.

    def remember_failure(self, exc):
        category = exc.category if isinstance(exc, ClosedFailure) else (
            'PREDICATE_REFUSED' if self.m is not None and isinstance(exc, self.m.Refusal) else 'UNEXPECTED')
        if self.deadline_expired:
            category = 'CLIENT_TIMEOUT'
        if self.first_failure is None:
            self.first_failure = {'checkpoint': self.checkpoint, 'category': category}
        if category == 'CLIENT_TIMEOUT':
            self.deadline_expired = True
            raise ClosedFailure('CLIENT_TIMEOUT') from None

    def classify_captured(self, c, model):
        self.predicate_stack, self.predicate_role = [], 'all'
        try:
            runtime = self.step('D_CLASSIFY_RUNTIME', self.m.compose_runtime_model, model, self.predicate_event)
        except BaseException as exc:
            self.remember_failure(exc)
            return  # A whole-model decoder failure blocks every role and projection.
        finally:
            self.predicate_stack = []
        for role in ROLES:
            self.predicate_stack, self.predicate_role = [], role
            ready = True
            if role == 'api':
                try:
                    self.step('D_MODEL_API', self.api_env, c, model)
                except BaseException as exc:
                    ready = False  # Do not invoke the API comparator after failed Env preparation.
                    self.remember_failure(exc)
                finally:
                    self.predicate_stack = []
            if ready:
                try:
                    self.step('D_API_CONFIG' if role == 'api' else 'D_MODEL_' + role.upper().replace('-', '_'),
                              c.original_model_matches, role, model, c.old[role],
                              observer=self.predicate_event, shape_only=True)
                    require(not self.predicate_stack)
                    self.model_status[role] = 'PASS'
                except BaseException as exc:
                    self.model_status[role] = 'BLOCKED' if (self.deadline_expired or
                                            isinstance(exc, ClosedFailure) and exc.category == 'CLIENT_TIMEOUT') else 'FAIL'
                    self.remember_failure(exc)
                finally:
                    self.predicate_stack = []
            flags = self.step('D_CLASSIFY_MOUNTS', classify_mounts, runtime, role, c.old[role])
            self.mount_status[role] = flags
            if flags['MALFORMED'] == 'YES':
                self.remember_failure(ClosedFailure('PREDICATE_REFUSED'))
        self.step('D_MODELS_CLASSIFIED', lambda: None)

    def observe(self, argv):
        args = self.step('D_ARGUMENTS', arguments, argv)
        self.classify_models_only = args.classify_models_only
        self.alignment_shape_only = args.align_api_cve_release
        self.source_pins = dict(args.verified_sources)
        root = self.repo / '.local-auth'
        self.step('D_ROOT_ANCESTRY', metadata, root, directory=True)
        self.step('D_LOCK_ABSENT', lock_absent, root)
        self.step('D_SELF', self.reader, self.repo / SELF, args.diagnostic_sha256)
        self.step('D_TEST', self.reader, self.repo / TEST, args.diagnostic_test_sha256)
        verified = self.sources()
        m = self.step('D_IMPORT', self.loader, self.repo, verified)
        self.m = m
        plan = self.step('D_PLAN', plan_for, m, args)
        self.step('D_PLAN', plan.validate)
        run = self.runner_factory(self.repo, self.env, clock=self.clock, deadline=self.deadline)
        c = m.Controller(self.repo, plan, run, env=self.env)  # Inert, no lifecycle method.
        self.step('D_PROTOCOL', c.migration_protocol)
        self.step('D_ALARM_AVAILABLE', m.alarm_available)
        for checkpoint, relative in (('D_SECRET_LEGACY', 'server/.env.local'),
                                     ('D_SECRET_STAGED', 'server/.env.openrouter.local'),
                                     ('D_SECRET_STAND', '.local-auth/stand.env')):
            if checkpoint == 'D_SECRET_STAGED':
                self.step(checkpoint, m.staged_key_metadata, self.repo / relative)
            else:
                self.step(checkpoint, m.path_metadata, self.repo / relative, secret=True)
        self.step('D_SECRET_STAND', c.secrets_metadata)
        self.step('D_COMPOSE_AMBIENT', m.need,
                  not any(k in self.env for k in ('COMPOSE_FILE', 'COMPOSE_PROFILES', 'COMPOSE_ENV_FILES')) and
                  self.env.get('COMPOSE_PROJECT_NAME', PROJECT) == PROJECT and
                  self.env.get('DOCKER_HOST') == SOCKET and self.env.get('DOCKER_CONTEXT') == '')
        version = self.step('D_COMPOSE_VERSION', run, ('docker', 'compose', 'version', '--short'), cap=4096)
        self.step('D_COMPOSE_VERSION', m.need, version.strip() in m.SUPPORTED_COMPOSE_VERSIONS)
        selected = self.step('D_SELECTOR', m.select, self.repo, root)
        self.step('D_SELECTOR', m.need, selected.profile == 'nginx-local' and
                  selected.llm == 'openrouter-free' and selected.files == m.FILES == FILES)
        c.selected = selected
        c.base_command = (*selected.command, '--project-name', PROJECT,
                          '--project-directory', str(self.repo / 'server/deploy'))
        self.step('D_SELECTOR', m.need, (*c.base_command, 'config', '--format', 'json') == run.render)
        records = self.step('D_ORIGINAL_INSPECT', c.inspect, list(run.original_ids))
        for role, binding in plan.bindings.items():
            checkpoint = 'D_OLD_' + role.upper().replace('-', '_')
            record = records[binding.container]
            self.step(checkpoint, c.bound, role, record, True)
            if role == 'api':
                self.step(checkpoint, m.need, record['State'].get('Health', {}).get('Status') == 'healthy')
            c.old[role] = record
            checkpoint = 'D_OLD_IMAGE_' + role.upper().replace('-', '_')
            images = m.decode(self.step(checkpoint, run, ('docker', 'image', 'inspect', binding.image)))
            self.step(checkpoint, m.need, type(images) is list and len(images) == 1 and
                      images[0]['Id'] == binding.image and images[0]['Os'] == 'linux')
            if role == 'api':
                defaults = m.env_map(images[0]['Config'].get('Env') or [])
                self.step(checkpoint, m.need, images[0]['Architecture'] == plan.architecture and
                          m.KEY not in defaults and 'SCAN_JWT_SECRET' not in defaults)
            c.images[role] = images[0]
        for role in plan.replaced_roles:
            checkpoint = 'D_CANDIDATE_' + role.upper()
            identity = plan.selected_image(role)
            images = m.decode(self.step(checkpoint, run, ('docker', 'image', 'inspect', identity)))
            self.step(checkpoint, m.need, type(images) is list and len(images) == 1)
            self.step(checkpoint, m.candidate_image_matches, c.images[role], images[0], identity, plan.architecture)
            c.candidate_images[role] = images[0]
        c.candidate_image = c.candidate_images['api']
        model = m.decode(self.step('D_RENDER', run, (*c.base_command, 'config', '--format', 'json')))
        self.step('D_MODEL_SHAPE', m.need, model['name'] == PROJECT and
                  set(model['services']) == set((*ROLES, 'auth-volume-init', 'scan-volume-init')))
        if self.classify_models_only:
            self.classify_captured(c, model)
            return  # No later read client, image substitution, AUTH input or full-preflight result.
        for role in ROLES:
            self.predicate_role = role
            if role == 'api':
                self.step('D_MODEL_API', self.api_env, c, model)
            self.step('D_API_CONFIG' if role == 'api' else 'D_MODEL_' + role.upper().replace('-', '_'),
                      c.model_matches, role, model, c.old[role], observer=self.predicate_event)
            self.step('D_API_CONFIG' if role == 'api' else 'D_MODEL_' + role.upper().replace('-', '_'),
                      require, not self.predicate_stack)
        self.step('D_MODEL_RESTRICTIONS', m.need,
                  all(not any(k in s for k in ('profiles', 'develop', 'provider', 'scale', 'extends', 'include', 'env_file'))
                      for s in model['services'].values()))
        original = copy.deepcopy(model)
        for role in plan.replaced_roles:
            model['services'][role]['image'] = plan.selected_image(role)
        check = copy.deepcopy(model)
        for role in plan.replaced_roles:
            if 'image' in original['services'][role]:
                check['services'][role]['image'] = original['services'][role]['image']
            else:
                check['services'][role].pop('image')
        self.step('D_IMAGE_ONLY', m.need, check == original)
        c.model = model
        self.step('D_AUTH_INPUT', c.compatibility_input)  # Memory construction ONLY, no compatibility().
        ids = self.step('D_NETWORKS', run.bind_networks, c.old)
        networks = m.decode(self.step('D_NETWORKS', run, ('docker', 'network', 'inspect', *ids)))
        self.step('D_NETWORKS', m.need, type(networks) is list and len(networks) == len(ids) and
                  {n['Id'] for n in networks} == set(ids))
        c.networks = {n['Id']: {k: v for k, v in n.items() if k != 'Containers'} for n in networks}
        runtime = self.step('D_NETWORKS', m.compose_runtime_model, model)
        for n in networks:
            logical = next((k for k, v in runtime['networks'].items() if v['name'] == n['Name']), None)
            self.step('D_NETWORKS', m.need, logical is not None and
                      n['Internal'] is runtime['networks'][logical].get('internal', False))
        self.step('D_VOLUMES', c.resources)
        self.step('D_HOST_DISK', lambda: m.need(m.shutil.disk_usage(root).free >= 3 * m.GIB + 128 * MIB))
        total = m.decode(self.step('D_ENGINE_MEMORY', run, ('docker', 'info', '--format', '{{json .MemTotal}}'), cap=4096))
        self.step('D_ENGINE_MEMORY', m.need, type(total) is int and total >= 2 * m.GIB + 256 * MIB)
        script = self.repo / plan.sqlite_helper
        for path in (script, *script.parents):
            st = self.step('D_HELPER_UID_ACCESS', path.lstat)
            permission = 0o400 if path == script else 0o100
            self.step('D_HELPER_UID_ACCESS', m.need, st.st_mode & (permission if st.st_uid == 65532 else permission >> 6))
            if path == self.repo:
                break
        self.step('D_WRITER_FENCE', c.writers, {plan.bindings[r].container for r in ('api', 'worker')})
        self.step('D_STABLE_FINAL', c.stable, set(ROLES))
        self.sources(final=True)
        self.step('D_SECRET_FINAL', c.secrets_metadata)
        self.step('D_SELECTOR_FINAL', lambda: m.need(m.select(self.repo, root) == selected))
        self.step('D_API_SOCKET_GUARD', m.need,
                  all(not v.get('Source', '').endswith('/docker.sock') and
                      not v.get('Destination', '').endswith('/docker.sock') for v in c.old['api']['Mounts']))
        self.step('D_LOCK_FINAL', lock_absent, root)
        self.step('D_COMPLETE', lambda: None)

    def result(self, argv):
        self.predicate_stack, self.predicate_role = [], 'api'
        self.deadline_expired = False
        self.classify_models_only, self.first_failure = False, None
        self.source_pins, self.alignment_shape_only = dict(PINS), False
        self.model_status = dict.fromkeys(ROLES, 'BLOCKED')
        self.mount_status = {role: dict.fromkeys(MOUNT_FLAGS, 'BLOCKED') for role in ROLES}
        category, outcome = 'NONE', 'READ_SUBSET_PASS'
        try:
            self.observe(argv)
        except ClosedFailure as exc:
            category, outcome = exc.category, 'REFUSED'
        except BaseException as exc:
            category, outcome = ('PREDICATE_REFUSED' if self.m is not None and isinstance(exc, self.m.Refusal)
                                 else 'UNEXPECTED'), 'REFUSED'
        # The controller deliberately sanitizes callback exceptions into Refusal.
        # Preserve an observed deadline without weakening that callback boundary.
        if self.deadline_expired:
            category, outcome = 'CLIENT_TIMEOUT', 'REFUSED'
        if self.classify_models_only:
            if outcome == 'REFUSED' and self.first_failure is None:
                self.first_failure = {'checkpoint': self.checkpoint, 'category': category}
            if self.first_failure is not None:
                outcome = 'REFUSED'
                if category != 'CLIENT_TIMEOUT':
                    self.checkpoint, category = self.first_failure['checkpoint'], self.first_failure['category']
            elif outcome != 'REFUSED':
                outcome = 'MODELS_CLASSIFIED'
            result = {'mode': 'model-classification-readonly-v1', 'checkpoint': self.checkpoint,
                      'outcome': outcome, 'category': category, 'boundary': 'NO_ACTIVATION',
                      'firstFailure': self.first_failure, 'models': self.model_status, 'mounts': self.mount_status}
            if self.alignment_shape_only:
                result['mode'] = 'model-alignment-shape-readonly-v1'
                result['releaseAuthentication'] = 'NOT_PERFORMED'
                if result['outcome'] == 'MODELS_CLASSIFIED':
                    result['outcome'] = 'SHAPE_ONLY_CLASSIFIED'
            require(len(json.dumps(result, sort_keys=True, separators=(',', ':')).encode('ascii')) <= 4096)
            return result
        return {'mode': 'preflight-readonly-v1', 'checkpoint': self.checkpoint,
                'outcome': outcome, 'category': category, 'boundary': 'NO_ACTIVATION'}


def main(argv=None):
    try:
        result = Diagnostic(REPO, os.environ).result(sys.argv[1:] if argv is None else argv)
    except BaseException:
        result = {'mode': 'preflight-readonly-v1', 'checkpoint': 'D_ARGUMENTS',
                  'outcome': 'REFUSED', 'category': 'UNEXPECTED', 'boundary': 'NO_ACTIVATION'}
    try:
        sys.stdout.buffer.write(json.dumps(result, sort_keys=True, separators=(',', ':')).encode('ascii') + b'\n')
    except BaseException:
        return 1  # Failed output is not a receipt; never print a traceback.
    return 0 if result['outcome'] in ('READ_SUBSET_PASS', 'MODELS_CLASSIFIED', 'SHAPE_ONLY_CLASSIFIED') else 1


if __name__ == '__main__':
    sys.exit(main())
