#!/usr/bin/env python3
"""Review-only helper; no execution/removal authority is conferred by this file.

Phase 1: two fixed, metadata-only listings; <=80 containers/100 image rows,
<=32768 bytes/client INCLUDING stderr, <=65536 transport/receipt bytes, shared60s,
each client10s, external supervisor75s required. No automatic deletion candidates.
Container ls .Image can be a mutable tag: listedReferences is NOT proof of actual
immutable references or of non-use. Phase 2 requires a separately reviewed literal
canonical exact batch plan (1..7 allowlisted public-build snapshots), fresh image
listing, all-container ID listing and immutable image projection for the ENTIRE
batch before ANY removal. Then one non-force image rm --no-prune per ID, serially.
Removal: <=3 metadata clients16384B + <=7 removal clients2048B, <=63488B aggregate,
shared60s/client10s/external75s. Stop on FIRST failure; no retries/compensation.

Never removes containers (including paused4dc), volumes, build cache, untagged
images, the five original/three candidate images, or retained c09ce4 history base.
No source actors, ownership inference from names/tags, Env/args/labels/mounts,
logs, private files, daemon config, source/controller execution or host writes.
The sole authorization flag explicitly permits discarding the selected exact
images if freshly unreferenced while the stand remains under maintenance HOLD.
It asserts exclusive daemon custody, NOT deployment completion or historical
image provenance. Source dataflow describes rebuildable namespaces, not proof
of individual image custody/content. Parent must exclude concurrent mutations
through the entire preflight/removal boundary; no HOLD/lock read or change.
--no-prune preserves untagged parents; non-force Docker conflict checks remain
mandatory. Failure after removal ATTEMPT means HOLD/manual reconciliation, no
query/retry. Successful acknowledgement is not a post-inventory or integrity proof.
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
SELF = 'server/deploy/trust/cleanup_unused_docker.py'
TEST = 'server/deploy/trust/test_cleanup_unused_docker.py'
TRANSPORT = 'server/deploy/trust/discover_preservation_holder.py'
RUNNER = 'server/deploy/proof/cve14-combined-proof.py'
RUNNER_SHA256 = '945404d04957c86523de0490b5a65f17787010f6733a9a7ead1f76dfcfb4adc0'
# Exact user-supplied inventory bindings, NOT inferred from namespace matches.
# Source inspection establishes namespace/build dataflow, not historical per-ID
# custody. Explicit USER authorization permits discarding selected exact IDs if
# freshly unreferenced, without claiming historical custody or proving contents.
SNAPSHOTS = {
    'sha256:15197100f752c1fe10615a85b1b33633dd35eb716dce1789320791de86693032':
        ('dip-cve14-snapshot-c68e78d102921bfc:local', 'combined-source-build'),
    'sha256:23ffa5aa37f93186a943c5c92b47d2d6eec2df4da37729057c86ab3dd6fb790a':
        ('dip-cve14-snapshot-db0036568330ec7e:local', 'combined-source-build'),
    'sha256:4ca2b8083033b718f490ae08ff614c3f593e35d782130e2e5c7f46acc86dcf40':
        ('dip-cve14-snapshot-d8fdd66d9bf40de5:local', 'combined-source-build'),
    'sha256:4ca80cff07620171413cdd48c7697547f04829089c5937430e970fc20ac64b5d':
        ('dip-cve14-snapshot-50a215ff36203a77:local', 'combined-source-build'),
    'sha256:63602c1f062b998107d827faaadfb9acc486f445d9775a587f5ccfbb65864d25':
        ('dip-cve14-diag-snapshot-7c6ab13aed49881d:local', 'diagnostic-source-build'),
    'sha256:d060e223a5e927c134ffbc5c885eea6a0cd9bdbaf1bf218eefc6478b20c6eb25':
        ('dip-cve14-snapshot-50c9f4bae2cec49b:local', 'combined-source-build'),
    'sha256:edc9f4875438b5caba2722a67ccf1508fa001db4199b0ef3362bf1b767ce1260':
        ('dip-cve14-snapshot-4b5a7fbb46389420:local', 'combined-source-build'),
}
PINS = {
    RUNNER: RUNNER_SHA256,
    TRANSPORT: '4afb0bc484d34aca428fee956bd939d7b322727285eef0f721425849bb32a1f4',
    'server/deploy/trust/test_discover_preservation_holder.py':
        'cc1a168804cb9a07f9c53724730bfbbaae7596c44c88743b0dc169f26a1bf312',
}
PROTECTED = frozenset((
    'sha256:487c3909d3eeee08d60840a81c1adeb61c292aee0a31df17b2a8cf92f6dbb58c',
    'sha256:8748cbebba753603d79f320c2fb476c46ab676ce12e0aa08bee0021a3e14e57a',
    'sha256:1659b39c98d5183c91feae78a8d9eb1d4c6ee527d541c1e1d74dfe842adee8c0',
    'sha256:2b9eff3b381979c82bf42c310fcd7941805d42adeda67c8814143d6503490655',
    'sha256:3ccbd5a6c3348b7b1c99e23b29d9bdca485dfd48f690a408a119e06163a59a8d',
    'sha256:4b3a3d4b3c2658ec9a36209afcac69eda2b64cef6e055a5e2716e2602e5338d1',
    'sha256:891b5adccbe469345cea585e75dc71c6d3bf93405c5a18386795af1b012b314d',
    'sha256:3d14f3d9e7347a9609fe3ae53b46efd70293aacae64da48c001ed6e826155817',
    'sha256:c09ce4c8e6185784fad2c263b462952092fa89058d16363ebd543e0cd4bbd50d',
))
HEX = re.compile(r'[a-f0-9]{64}\Z')
IMAGE_ID = re.compile(r'sha256:[a-f0-9]{64}\Z')
TEXT = re.compile(r'[A-Za-z0-9_./:@+() -]{1,512}\Z')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,255}\Z')
STATES = frozenset(('created', 'restarting', 'running', 'removing', 'paused', 'exited', 'dead'))
AUTHORIZATION = '--authorize-exclusive-held-stand-unused-images'
CONTAINER_FORMAT = ('{"id":{{json .ID}},"image":{{json .Image}},'
                    '"state":{{json .State}},"name":{{json .Names}},"size":{{json .Size}}}')
IMAGE_FORMAT = ('{"id":{{json .ID}},"repository":{{json .Repository}},'
                '"tag":{{json .Tag}},"size":{{json .Size}}}')
REFERENCE_FORMAT = '{"id":{{json .Id}},"image":{{json .Image}}}'
CONTAINERS = ('container', 'ls', '--all', '--no-trunc', '--size', '--format', CONTAINER_FORMAT)
IMAGES = ('image', 'ls', '--all', '--no-trunc', '--format', IMAGE_FORMAT)
CATEGORIES = frozenset(('PREDICATE_REFUSED', 'CLIENT_TIMEOUT', 'CLIENT_NONZERO',
    'CLIENT_EXEC_IDENTITY', 'CLIENT_EXEC_NOT_FOUND', 'CLIENT_EXEC_DENIED',
    'CLIENT_EXEC_OS_REFUSED', 'OUTPUT_CAP', 'DECODE_REFUSED', 'IO_REFUSED', 'UNEXPECTED'))


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
    except Exception:
        raise Refused('DECODE_REFUSED') from None


def stamp(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_uid, st.st_gid,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def public_bytes(path, deadline):
    """Read only exact public source files, with stable no-follow FD/path checks."""
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
        before = os.stat(path.name, dir_fd=fds[-1], follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             before.st_uid == os.geteuid() and not before.st_mode & 0o022 and
             0 < before.st_size <= 512 * 1024)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fds[-1])
        need(stamp(before) == stamp(os.fstat(fd)))
        data = bytearray()
        while True:
            tick(deadline)
            block = os.read(fd, min(65536, 512 * 1024 + 1 - len(data)))
            if not block:
                break
            data.extend(block)
            need(len(data) <= 512 * 1024)
        need(len(data) == before.st_size and stamp(before) == stamp(os.fstat(fd)) and
             stamp(before) == stamp(os.stat(path.name, dir_fd=fds[-1], follow_symlinks=False)))
        for parent, name, metadata in edges:
            need(stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)) == metadata)
        return bytes(data)
    finally:
        if fd is not None:
            os.close(fd)
        for item in reversed(fds):
            os.close(item)


def no_config():
    try:
        os.stat(REPO / 'server/deploy/trust/config.json', follow_symlinks=False)
    except FileNotFoundError:
        return
    raise Refused()


def arguments(argv):
    need(len(argv) in (5, 10) and argv[1] == '--source-sha256' and
         argv[3] == '--test-sha256' and HEX.fullmatch(argv[2]) and HEX.fullmatch(argv[4]))
    if len(argv) == 5:
        need(argv[0] == '--inventory-once')
        return None
    need(argv[0] == '--remove-exact-batch-once' and argv[5] == AUTHORIZATION and
         argv[6] == '--plan-sha256' and HEX.fullmatch(argv[7]) and argv[8] == '--plan-json')
    need(len(argv[9].encode()) <= 4096)
    raw = argv[9].encode('ascii')
    plan = decode(raw)
    need(canonical(plan) == raw and hashlib.sha256(raw).hexdigest() == argv[7])
    return validate_plan(plan)


def validate_plan(plan):
    need(type(plan) is dict and set(plan) ==
         {'version', 'images', 'source'} and
         type(plan['version']) is int and plan['version'] == 3 and
         type(plan['source']) is dict and plan['source'] == {'path': RUNNER, 'sha256': RUNNER_SHA256} and
         type(plan['images']) is list and 1 <= len(plan['images']) <= 7)
    seen = set()
    for entry in plan['images']:
        need(type(entry) is dict and set(entry) == {'image', 'tag', 'namespace'} and
             type(entry['image']) is str and IMAGE_ID.fullmatch(entry['image']) and
             entry['image'] not in seen and entry['image'] not in PROTECTED and
             entry['image'] in SNAPSHOTS and
             (entry['tag'], entry['namespace']) == SNAPSHOTS[entry['image']])
        seen.add(entry['image'])
    return plan


def load_transport(argv, deadline):
    need(sys.flags.isolated and sys.dont_write_bytecode and Path(__file__).absolute() == REPO / SELF)
    captured = None
    for relative, expected in {SELF: argv[2], TEST: argv[4], **PINS}.items():
        raw = public_bytes(REPO / relative, deadline)
        need(hashlib.sha256(raw).hexdigest() == expected)
        if relative == TRANSPORT:
            captured = raw
    no_config()
    # Execute precisely the captured, verified public transport, never a path reload
    # or its main/source_gate/controller. Importing it has no daemon side effects.
    module = types.ModuleType('_cleanup_pinned_transport')
    module.__file__ = str(REPO / TRANSPORT)
    exec(compile(captured, module.__file__, 'exec'), module.__dict__)
    return module


def valid_text(value):
    return type(value) is str and TEXT.fullmatch(value) is not None


def valid_tag(value):
    return (valid_text(value) and '<' not in value and ' ' not in value and ':' in value and
            not value.startswith(('-', 'sha256:')) and '@' not in value)


def lines(raw, maximum):
    need(type(raw) is bytes and len(raw) <= 32768 and (not raw or raw.endswith(b'\n')))
    if not raw:
        return []
    items = raw[:-1].split(b'\n')
    need(len(items) <= maximum and all(items))
    return items


def containers(raw):
    result, ids, names = [], set(), set()
    for line in lines(raw, 80):
        item = decode(line)
        need(type(item) is dict and set(item) == {'id', 'image', 'state', 'name', 'size'})
        need(type(item['id']) is str and HEX.fullmatch(item['id']) and item['id'] not in ids and
             valid_text(item['image']) and item['state'] in STATES and
             type(item['name']) is str and NAME.fullmatch(item['name']) and item['name'] not in names and
             valid_text(item['size']))
        ids.add(item['id'])
        names.add(item['name'])
        result.append(item)
    return sorted(result, key=lambda item: item['id'])


def images(raw):
    result, rows = {}, set()
    for line in lines(raw, 100):
        item = decode(line)
        need(type(item) is dict and set(item) == {'id', 'repository', 'tag', 'size'})
        need(type(item['id']) is str and IMAGE_ID.fullmatch(item['id']) and valid_text(item['size']))
        repo, tag = item['repository'], item['tag']
        if repo == '<none>' and tag == '<none>':
            full_tag = None
        else:
            need(type(repo) is str and type(tag) is str)
            full_tag = repo + ':' + tag
            need(valid_tag(full_tag))
        row = (item['id'], full_tag)
        need(row not in rows)
        rows.add(row)
        entry = result.setdefault(item['id'], {'id': item['id'], 'tags': [], 'size': item['size']})
        need(entry['size'] == item['size'])
        if full_tag is not None:
            need(all(full_tag not in other['tags'] for other in result.values()))
            entry['tags'].append(full_tag)
    for entry in result.values():
        entry['tags'].sort()
    return sorted(result.values(), key=lambda item: item['id'])


def references(raw, expected):
    found = {}
    for line in lines(raw, 80):
        item = decode(line)
        need(type(item) is dict and set(item) == {'id', 'image'} and
             type(item['id']) is str and item['id'] in expected and item['id'] not in found and
             type(item['image']) is str and IMAGE_ID.fullmatch(item['image']))
        found[item['id']] = item['image']
    need(set(found) == set(expected))
    return found


class Cleanup:
    def __init__(self, transport, deadline):
        self.transport, self.deadline = transport, deadline
        self.client = transport.Client(REPO, deadline)
        self.calls, self.removal_attempted, self.stage = 0, False, 'PUBLIC_SOURCES'
        self.used, self.mutator = False, None
        self.metadata_calls, self.mutation_calls, self.allocated_bytes = 0, 0, 0
        self.planned_images, self.attempted_images, self.confirmed_images = [], [], []
        self.current_image, self.plan_sha256 = None, None

    def call(self, args, *, removal=False, mutation=False):
        tick(self.deadline)
        need(self.calls < (10 if removal else 2))
        if mutation:
            need(removal and self.mutator is not None and self.mutation_calls < 7 and
                 args == ('image', 'rm', '--no-prune', self.current_image))
            cap, client = 2048, self.mutator
        else:
            need(self.metadata_calls < (3 if removal else 2))
            cap, client = (16384 if removal else 32768), self.client
        need(self.allocated_bytes + cap <= 65536)
        no_config()
        self.calls += 1
        self.allocated_bytes += cap
        if mutation:
            self.mutation_calls += 1
        else:
            self.metadata_calls += 1
        try:
            return client(args, cap=cap)
        except self.transport.Refused as exc:
            raise Refused(exc.category) from None

    def partial_receipt(self):
        return {'planSha256': self.plan_sha256,
                'attemptedImages': list(self.attempted_images),
                'confirmedRemovedImages': list(self.confirmed_images),
                'uncertainImage': self.current_image,
                'notAttemptedImages': [image for image in self.planned_images
                                       if image not in self.attempted_images],
                'postInventory': False}

    def inventory(self):
        need(not self.used)
        self.used = True
        self.stage = 'CONTAINER_LIST'
        actors = containers(self.call(CONTAINERS))
        self.stage = 'IMAGE_LIST'
        listing = images(self.call(IMAGES))
        for item in listing:
            item['listedReferences'] = [actor['id'] for actor in actors
                if actor['image'] == item['id'] or actor['image'] in item['tags']]
        self.stage = 'COMPLETE'
        return {'ok': True, 'mode': 'inventory-only', 'containers': actors, 'images': listing,
                'referencesAuthoritative': False, 'removalAuthorized': False}

    def remove(self, plan):
        need(not self.used)
        self.used = True
        validate_plan(plan)
        self.planned_images = [entry['image'] for entry in plan['images']]
        self.plan_sha256 = hashlib.sha256(canonical(plan)).hexdigest()
        self.stage = 'IMAGE_RECHECK'
        listing = {item['id']: item for item in images(self.call(IMAGES, removal=True))}
        for entry in plan['images']:
            need(entry['image'] in listing and listing[entry['image']]['tags'] == [entry['tag']])
        self.stage = 'CONTAINER_RECHECK'
        actors = containers(self.call(CONTAINERS, removal=True))
        self.stage = 'IMMUTABLE_REFERENCE_RECHECK'
        if actors:
            ids = tuple(item['id'] for item in actors)
            actual = references(self.call(('container', 'inspect', '--format', REFERENCE_FORMAT, *ids),
                                          removal=True), ids)
            # Validate the WHOLE batch before any mutation; never delete an earlier
            # member when a later member is still referenced (in ANY lifecycle).
            need(not set(self.planned_images).intersection(actual.values()))
        # Two independently bounded transport instances share this one deadline
        # and aggregate call/byte budget: metadata<=3, mutations<=7. Neither needs
        # its captured transport's <=8-call guard changed/reset/bypassed.
        self.mutator = self.transport.Client(REPO, self.deadline)
        for entry in plan['images']:
            tick(self.deadline)
            # Parent serialization excludes concurrent writers for this entire
            # batch. These checkpoints are not an atomic daemon graph snapshot.
            self.stage = 'REMOVE'
            self.current_image = entry['image']
            self.attempted_images.append(entry['image'])
            self.removal_attempted = True
            raw = self.call(('image', 'rm', '--no-prune', entry['image']), removal=True, mutation=True)
            allowed = {'Untagged: ' + entry['tag'], 'Deleted: ' + entry['image']}
            decoded = [line.decode('ascii', 'strict') for line in lines(raw, 2)]
            need(len(decoded) == len(set(decoded)) and set(decoded) == allowed)
            self.confirmed_images.append(entry['image'])
            self.current_image = None
        self.stage = 'COMPLETE'
        return {'ok': True, 'mode': 'exact-image-batch-removal',
                'manualReconciliationRequired': False, **self.partial_receipt()}


def main(argv=None):
    deadline, runner = time.monotonic() + 60, None
    stage = 'ARGUMENTS'
    try:
        argv = sys.argv[1:] if argv is None else argv
        plan = arguments(argv)
        stage = 'PUBLIC_SOURCES'
        transport = load_transport(argv, deadline)
        runner = Cleanup(transport, deadline)
        result = runner.inventory() if plan is None else runner.remove(plan)
        tick(deadline)
        output = canonical(result) + b'\n'
        need(len(output) <= 65536)
        sys.stdout.buffer.write(output)
        return 0
    except BaseException as exc:
        category = exc.category if isinstance(exc, Refused) else 'IO_REFUSED' if isinstance(exc, OSError) else 'UNEXPECTED'
        result = {'ok': False, 'category': category, 'checkpoint': runner.stage if runner else stage,
                  'removalAttempted': bool(runner and runner.removal_attempted),
                  'manualReconciliationRequired': bool(runner and runner.removal_attempted)}
        if runner and runner.plan_sha256 is not None:
            result.update(runner.partial_receipt())
        sys.stdout.buffer.write(canonical(result) + b'\n')
        return 1


if __name__ == '__main__':
    sys.exit(main())
