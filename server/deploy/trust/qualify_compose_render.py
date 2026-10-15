#!/usr/bin/env python3
"""Public-only TWO-render Compose candidate; execution needs independent approval.

No version query, Engine operation, original configuration or application import.
Bounds: 30s shared, 10s/client, <=1s failed-client reap, 128KiB combined
stdout/stderr per client, 64KiB/file, 1MiB packet, JSON depth32/nodes4096.
Caller MUST impose 45000ms. No retry/fallback/cleanup. Only PASS/REFUSED stdout.
Direct bundled-plugin execution avoids CLI discovery and shadowing. The fixed
candidate path is proposed, NOT observed. A SEPARATELY APPROVED one-query public
metadata observation must precede the two renders. Both source pins and the exact
provenance receipt digest are required. Historical514 binary equality is NOT claimed.
"""

import hashlib
import json
import os

import re
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time

PACKET = Path('/private/tmp/dip-compose-render-20261013-r1')
RENDER_PACKET = Path('/private/tmp/dip-compose-render-20261013-diag-r5')
RENDER_MODE = 'public-compose-render-diagnostic-v1'
# Accepted533 producer, verified535 proof. NOT this new consumer's source pins.
ACCEPTED_PRODUCER_ROOT = Path('/private/tmp/dip-compose-plugin-provenance-20261013-diag-r2')
ACCEPTED_PRODUCER_SOURCE = '38ad3c71a48284a6d26ef7b9d4c83d9fac630aeaa6f35de11c8f13accab85478'
ACCEPTED_PRODUCER_TEST = 'b4fca98cb887fab50787b7309918b63691c4407fc911b06741ce50a9b1d54a21'
ACCEPTED_PROOF_SHA256 = 'e382d8e8c7f3dd9ccfa414663f1d089553d05d8189e915b21c4f8cfc6bad6d54'
PROVENANCE_PACKET = Path('/private/tmp/dip-compose-plugin-provenance-20261013-r1')
DIAGNOSTIC_PACKET = Path('/private/tmp/dip-compose-plugin-provenance-20261013-diag-r2')
DIAGNOSTIC_MODE = 'public-plugin-provenance-diagnostic-v1'
SCHEMA_PACKET = Path('/private/tmp/dip-compose-plugin-schema-20261013-r1')
SCHEMA_MODE = 'public-plugin-schema-observation-v1'
# PUBLIC Docker CLI v28.0.1 cli-plugins/manager/metadata.go field names only.
# No discovery-driven names, aliases or unknown-key hashes are exported.
PUBLIC_SCHEMA_FIELDS = (
    ('SchemaVersion', 'SCHEMA_VERSION'), ('Vendor', 'VENDOR'), ('Version', 'VERSION'),
    ('ShortDescription', 'SHORT_DESCRIPTION'), ('URL', 'URL'))
SCHEMA_TYPES = {str: 'STRING', bool: 'BOOLEAN', int: 'INTEGER', type(None): 'NULL',
                dict: 'OBJECT', list: 'ARRAY'}
# compose-go/v2 v2.4.9 types.NetworkConfig JSON fields. Diagnostic recognition
# never admits an extra field; unknown names/values remain unexported.
PUBLIC_NETWORK_FIELDS = (
    ('attachable', 'ATTACHABLE'), ('driver', 'DRIVER'), ('driver_opts', 'DRIVER_OPTS'),
    ('enable_ipv4', 'ENABLE_IPV4'), ('enable_ipv6', 'ENABLE_IPV6'),
    ('external', 'EXTERNAL'), ('internal', 'INTERNAL'), ('ipam', 'IPAM'),
    ('labels', 'LABELS'), ('name', 'NAME'))
# Exact public ServiceConfig JSON tags from the same pinned types.go; exclude
# json:"-" Name/CustomLabels/Extensions. Uppercase ONLY these fixed literals.
PUBLIC_SERVICE_FIELDS = tuple((key, key.upper()) for key in sorted('''
profiles annotations attach build develop blkio_config cap_add cap_drop
cgroup_parent cgroup cpu_count cpu_percent cpu_period cpu_quota cpu_rt_period
cpu_rt_runtime cpus cpuset cpu_shares command configs container_name
credential_spec depends_on deploy device_cgroup_rules devices dns dns_opt
dns_search dockerfile domainname entrypoint environment env_file expose extends
external_links extra_hosts group_add gpus hostname healthcheck image init ipc
isolation labels label_file links logging log_driver log_opt mem_limit
mem_reservation memswap_limit mem_swappiness mac_address net network_mode networks
oom_kill_disable oom_score_adj pid pids_limit platform ports privileged pull_policy
read_only restart runtime scale secrets security_opt shm_size stdin_open
stop_grace_period stop_signal storage_opt sysctls tmpfs tty ulimits user
userns_mode uts volume_driver volumes volumes_from working_dir post_start pre_stop
'''.split()))
DIAGNOSTIC_GATES = frozenset((
    'ARGUMENTS', 'SOURCE_PINS', 'ROOT_PREPARE', 'SOURCE_DURABILITY',
    'CLIENT_CONFIG_DURABILITY', 'PLUGIN_CANONICAL', 'PLUGIN_STAT', 'PLUGIN_TYPE',
    'PLUGIN_OWNER_MODE', 'PLUGIN_SIZE', 'PLUGIN_OPEN', 'PLUGIN_FD_IDENTITY',
    'PLUGIN_HASH', 'PLUGIN_STABILITY', 'ATTEMPT_DURABILITY', 'PRE_CHILD_IDENTITY',
    'SOCKET_GUARD', 'CLIENT_LAUNCH', 'CLIENT_READ', 'CLIENT_EXIT', 'METADATA_JSON',
    'METADATA_SCHEMA', 'METADATA_SCHEMA_VERSION', 'METADATA_VENDOR',
    'METADATA_VERSION', 'METADATA_DESCRIPTION', 'METADATA_URL',
    'POST_CHILD_IDENTITY', 'PROOF_DURABILITY', 'FINAL_DEADLINE',
    'RECEIPT_DURABILITY', 'OUTPUT', 'COMPLETE'))
DIAGNOSTIC_CATEGORIES = frozenset((
    'PREDICATE_REFUSED', 'IO_FAILED', 'CLIENT_NONZERO', 'CLIENT_TIMEOUT',
    'OUTPUT_CAP', 'STDERR_PRESENT', 'DECODE_REFUSED', 'UNEXPECTED'))
PLUGIN = Path('/Applications/Docker.app/Contents/Resources/cli-plugins/docker-compose')
SEMANTIC_VERSION = '2.34.0-desktop.1'
# Finite, explicit metadata spellings; no suffix stripping/SemVer range/fallback.
METADATA_VERSIONS = frozenset((SEMANTIC_VERSION, 'v' + SEMANTIC_VERSION))
METADATA_REQUIRED_KEYS = frozenset(('SchemaVersion', 'Vendor', 'Version', 'ShortDescription'))
BINARY_CAP = 256 * 1024 * 1024
METADATA_CAP = 4096
OBSERVATION_SECONDS = 12
PROJECT = 'dip-compose-public-render-proof'
PUBLIC_PATH = '/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin'
FILE_CAP = 65536
PACKET_CAP = 1048576
OUTPUT_CAP = 131072
SHARED_SECONDS = 30
CLIENT_SECONDS = 10
BASE = b'''services:
  probe:
    image: busybox:1.36.1
    command: ["echo", "$$literal", "$$$$pair", "$${INERT_LITERAL}"]
    read_only: true
    restart: "no"
    tmpfs: ["/tmp/base-a:rw", "/tmp/base-b:rw"]
    env_file:
      - path: ./required.env
        required: true
    environment:
      EMPTY: ""
      NUMERIC: "007"
      BOOLEAN: "false"
      INTERPOLATED: "${INERT_PUBLIC:?required public marker}"
      DOLLAR: "$$literal"
      PAIR: "$$$$pair"
      BRACED: "$${INERT_LITERAL}"
      UNICODE: "public-caf\xc3\xa9"
    labels:
      public.literal: "$${INERT_LITERAL}"
    ports:
      - target: 8080
        published: "18080"
        host_ip: "127.0.0.1"
        protocol: tcp
    volumes:
      - type: volume
        source: probe_data
        target: /public-data
        read_only: true
        volume:
          nocopy: true
    networks: [probe_net]
volumes:
  probe_data: {}
networks:
  probe_net:
    driver: bridge
    internal: true
'''
OVERLAY = b'''services:
  probe:
    tmpfs: !override ["/tmp/replaced:rw,mode=0700"]
    env_file:
      - path: ./override.env
        required: false
      - path: ./missing-optional.env
        required: false
'''
REQUIRED = b'ORDER=first\nKEEP=preserved\nEMPTY_FROM_FILE=\nNUM_FROM_FILE=0042\nBOOL_FROM_FILE=false\n'
OVERRIDE = b'ORDER=second\nEXTRA=override\n'
FIXTURES = {'base.yaml': BASE, 'overlay.yaml': OVERLAY,
            'required.env': REQUIRED, 'override.env': OVERRIDE}


class Refused(Exception):
    """No raw reason/value leaves the process."""


class Classified(Refused):
    def __init__(self, category):
        self.category = category if category in DIAGNOSTIC_CATEGORIES else 'UNEXPECTED'


class Diagnostic:
    gates = DIAGNOSTIC_GATES

    def __init__(self):
        self.checkpoint = 'ARGUMENTS'
        self.category = None

    def check(self, gate, operation, predicate_category='PREDICATE_REFUSED'):
        # Set BEFORE thunk evaluation; latch the first failure through unwinding.
        need(gate in self.gates and self.category is None)
        self.checkpoint = gate
        try:
            return operation()
        except BaseException as error:
            if self.category is not None:
                raise
            if isinstance(error, Classified):
                self.category = error.category
            elif isinstance(error, Refused):
                self.category = predicate_category
            elif isinstance(error, subprocess.TimeoutExpired):
                self.category = 'CLIENT_TIMEOUT'
            elif isinstance(error, (UnicodeError, json.JSONDecodeError, RecursionError)):
                self.category = 'DECODE_REFUSED'
            elif isinstance(error, OSError):
                self.category = 'IO_FAILED'
            else:
                self.category = 'UNEXPECTED'
            raise

    def receipt(self, success=False):
        return {'mode': DIAGNOSTIC_MODE, 'boundary': 'NO_ACTIVATION',
                'outcome': 'PROVENANCE' if success else 'REFUSED',
                'checkpoint': 'COMPLETE' if success else self.checkpoint,
                'category': 'NONE' if success else (self.category or 'UNEXPECTED')}


class SchemaDiagnostic(Diagnostic):
    gates = DIAGNOSTIC_GATES | frozenset(('SCHEMA_KEYS', 'SCHEMA_TYPES'))

    def receipt(self, success=False):
        # Failure only: successful schema receipt is built from bounded public keys.
        need(not success)
        return {'code': 'REFUSED', 'mode': SCHEMA_MODE, 'boundary': 'NO_ACTIVATION',
                'checkpoint': self.checkpoint, 'category': self.category or 'UNEXPECTED'}


class RenderDiagnostic(Diagnostic):
    gates = DIAGNOSTIC_GATES | frozenset((
        'ACCEPTED_PROOF_PIN', 'ACCEPTED_PROOF_READ', 'INITIAL_IDENTITY',
        'FIXTURE_DURABILITY', 'ACCEPTED_PROOF_DURABILITY',
        'FIRST_IDENTITY', 'FIRST_SOCKET', 'FIRST_RENDER',
        'FIRST_CLIENT_LAUNCH', 'FIRST_CLIENT_READ', 'FIRST_CLIENT_EXIT',
        'FIRST_JSON', 'FIRST_ORACLE', 'FIRST_DURABILITY', 'NORMALIZED_DURABILITY',
        'SECOND_IDENTITY', 'SECOND_SOCKET', 'SECOND_RENDER',
        'SECOND_CLIENT_LAUNCH', 'SECOND_CLIENT_READ', 'SECOND_CLIENT_EXIT',
        'SECOND_JSON', 'SECOND_EQUALITY', 'FINAL_IDENTITY', 'SECOND_DURABILITY'))

    def __init__(self):
        super().__init__()
        self.oracle = None

    def receipt(self, success=False):
        return {'mode': RENDER_MODE, 'boundary': 'NO_ACTIVATION',
                'outcome': 'PASS' if success else 'REFUSED',
                'checkpoint': 'COMPLETE' if success else self.checkpoint,
                'category': 'NONE' if success else (self.category or 'UNEXPECTED'),
                'oracle': None if success else self.oracle}


class RenderPhase:
    def __init__(self, diagnostic, prefix):
        need(prefix in ('FIRST_', 'SECOND_'))
        self.diagnostic, self.prefix = diagnostic, prefix

    def check(self, gate, operation, predicate_category='PREDICATE_REFUSED'):
        need(gate in ('CLIENT_LAUNCH', 'CLIENT_READ', 'CLIENT_EXIT'))
        return self.diagnostic.check(self.prefix + gate, operation, predicate_category)


def need(condition):
    if not condition:
        raise Refused()


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')


def dollar_escape(value):
    # Public Compose v2.34.0 config.go escapeDollarSign equivalent for this
    # bounded JSON domain (keys cannot contain dollars). NOT a reinput step.
    if type(value) is str:
        return value.replace('$', '$$')
    if type(value) is list:
        return [dollar_escape(item) for item in value]
    if type(value) is dict:
        need(all(type(key) is str and '$' not in key for key in value))
        return {key: dollar_escape(item) for key, item in value.items()}
    return value


def parse_model(raw):
    need(type(raw) is bytes and len(raw) <= FILE_CAP)

    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result)
            result[key] = value
        return result

    def invalid_constant(_):
        raise Refused()

    value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                       parse_constant=invalid_constant)
    budget = [4096]

    def walk(item, depth):
        budget[0] -= 1
        need(depth <= 32 and budget[0] >= 0)
        if type(item) is dict:
            for key, child in item.items():
                need(type(key) is str and '$' not in key)
                key.encode('utf-8')  # Refuse lone surrogates, including JSON escapes.
                walk(child, depth + 1)
        elif type(item) is list:
            for child in item:
                walk(child, depth + 1)
        elif type(item) is str:
            item.encode('utf-8')
        else:
            need(item is None or type(item) in (bool, int))
    walk(value, 0)
    need(type(value) is dict)
    return value


def expected_model():
    # Independent SERIALIZED JSON fixture oracle, not renderer-derived.
    # config.go runConfig escapes ALL dollars after MarshalJSON (also JSON).
    # A second config parse consumes those pairs and emits the same pairs.
    return {
        'name': PROJECT,
        'services': {'probe': {
            'image': 'busybox:1.36.1',
            'command': ['echo', '$$literal', '$$$$pair', '$${INERT_LITERAL}'],
            'entrypoint': None,  # ServiceConfig JSON tag has no omitempty.
            'read_only': True, 'restart': 'no',
            'tmpfs': ['/tmp/replaced:rw,mode=0700'],
            'environment': {
                'ORDER': 'second', 'KEEP': 'preserved', 'EMPTY_FROM_FILE': '',
                'NUM_FROM_FILE': '0042', 'BOOL_FROM_FILE': 'false',
                'EXTRA': 'override', 'EMPTY': '', 'NUMERIC': '007',
                'BOOLEAN': 'false', 'INTERPOLATED': 'public-marker',
                'DOLLAR': '$$literal', 'PAIR': '$$$$pair',
                'BRACED': '$${INERT_LITERAL}', 'UNICODE': 'public-café'},
            'labels': {'public.literal': '$${INERT_LITERAL}'},
            'ports': [{'target': 8080, 'published': '18080',
                       'host_ip': '127.0.0.1', 'protocol': 'tcp', 'mode': 'ingress'}],
            'volumes': [{'type': 'volume', 'source': 'probe_data',
                         'target': '/public-data', 'read_only': True,
                         'volume': {'nocopy': True}}],
            'networks': {'probe_net': None}}},
        'volumes': {'probe_data': {'name': PROJECT + '_probe_data'}},
        # compose-go v2.4.9 NetworkConfig.Ipam is a non-pointer IPAMConfig.
        # Go1.23.6 encoding/json.isEmptyValue does NOT omit zero structs.
        'networks': {'probe_net': {'name': PROJECT + '_probe_net',
                                  'driver': 'bridge', 'internal': True, 'ipam': {}}}}


def assert_oracle(model):
    need(canonical(model) == canonical(expected_model()))


def oracle_difference(actual):
    # Paths come ONLY from this fixed expected tree. No unknown actual keys,
    # values, response hashes or dynamic indices enter the diagnostic receipt.
    expected = expected_model()

    def type_name(value):
        return SCHEMA_TYPES[type(value)]

    def note(path, kind, left, right, extras=0, missing=False):
        need(0 <= extras <= 4096)
        return {'path': path, 'kind': kind, 'expected_type': type_name(left),
                'actual_type': 'MISSING' if missing else type_name(right),
                'extra_count': extras}

    def walk(left, right, path):
        if type(left) is not type(right):
            return note(path, 'TYPE', left, right)
        if type(left) is dict:
            extra_keys = set(right) - set(left)
            extras = len(extra_keys)
            if extras:
                result = note(path, 'EXTRAS', left, right, extras)
                if path == '/networks/probe_net':
                    known = [{'field': label, 'type': type_name(right[key])}
                             for key, label in PUBLIC_NETWORK_FIELDS if key in extra_keys]
                    result['network_extras'] = {
                        'known': known, 'unknown_count': extras - len(known)}
                elif path == '/services/probe':
                    known = [{'field': label, 'type': type_name(right[key])}
                             for key, label in PUBLIC_SERVICE_FIELDS if key in extra_keys]
                    # Bound receipt even if every public field is unexpectedly present.
                    result['service_extras'] = {'known': known[:8],
                        'known_omitted_count': max(0, len(known) - 8),
                        'unknown_count': extras - len(known)}
                return result
            for key in sorted(left):
                child_path = path + '/' + key
                if key not in right:
                    return note(child_path, 'MISSING', left[key], None, missing=True)
                found = walk(left[key], right[key], child_path)
                if found:
                    return found
        elif type(left) is list:
            if len(left) != len(right):
                return note(path, 'LENGTH', left, right, max(0, len(right) - len(left)))
            for index, item in enumerate(left):
                found = walk(item, right[index], path + '/' + str(index))
                if found:
                    return found
        elif canonical(left) != canonical(right):
            return note(path, 'VALUE', left, right)
        return None
    return walk(expected, actual, '')


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_own(path):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
         and before.st_size <= FILE_CAP and before.st_uid == os.getuid())
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        need(stamp(os.fstat(fd)) == stamp(before))
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            raw = handle.read(FILE_CAP + 1)
        need(len(raw) <= FILE_CAP and stamp(os.fstat(fd)) == stamp(before)
             and stamp(path.lstat()) == stamp(before))
        return raw
    finally:
        os.close(fd)


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Packet:
    def __init__(self, root):
        self.root = root
        self.bytes = 0
        # Existing directory or symlink MUST refuse, never adopt/clean/retry.
        os.mkdir(root, 0o700)
        need(stat.S_IMODE(root.lstat().st_mode) == 0o700)
        fsync_dir(root.parent)
        for name in ('home', 'client', 'xdg'):
            os.mkdir(root / name, 0o700)
        fsync_dir(root)

    def write(self, name, raw):
        need(type(raw) is bytes and len(raw) <= FILE_CAP
             and self.bytes + len(raw) <= PACKET_CAP)
        need(name in {'base.yaml', 'overlay.yaml', 'required.env', 'override.env',
                      'attempt.json', 'normalized.json', 'first.json', 'second.json',
                      'receipt.json', 'qualify_compose_render.py',
                      'test_qualify_compose_render.py', 'client/config.json', 'provenance.json'})
        path = self.root / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as handle:
                handle.write(raw)
                handle.flush()
            os.fsync(fd)
        finally:
            os.close(fd)
        self.bytes += len(raw)
        fsync_dir(path.parent)


def pin_valid(pin):
    return (type(pin) is str and len(pin) == 64
            and all(char in '0123456789abcdef' for char in pin))


def sources(source_pin, test_pin):
    source = Path(__file__).absolute()
    test = source.with_name('test_qualify_compose_render.py')
    raw_source, raw_test = read_own(source), read_own(test)
    for raw, pin in ((raw_source, source_pin), (raw_test, test_pin)):
        need(pin_valid(pin) and hashlib.sha256(raw).hexdigest() == pin)
    return raw_source, raw_test


def plugin_identity(deadline, diagnostic=None):
    # Same fixed candidate and predicates. Optional checkpoints do not loosen them.
    def checked(gate, operation):
        return operation() if diagnostic is None else diagnostic.check(gate, operation)

    checked('PLUGIN_CANONICAL', lambda: need(PLUGIN.resolve(strict=True) == PLUGIN))
    before = checked('PLUGIN_STAT', lambda: PLUGIN.lstat())
    checked('PLUGIN_TYPE', lambda: need(stat.S_ISREG(before.st_mode) and before.st_nlink >= 1))
    checked('PLUGIN_OWNER_MODE', lambda: need(before.st_uid in (0, os.getuid())
            and before.st_mode & 0o111 and not before.st_mode & 0o6022))
    checked('PLUGIN_SIZE', lambda: need(0 < before.st_size <= BINARY_CAP))
    fd = checked('PLUGIN_OPEN', lambda: os.open(PLUGIN, os.O_RDONLY | os.O_NOFOLLOW))
    try:
        checked('PLUGIN_FD_IDENTITY', lambda: need(stamp(os.fstat(fd)) == stamp(before)))

        def hash_file():
            digest = hashlib.sha256()
            size = 0
            while True:
                if time.monotonic() >= deadline:
                    raise Classified('CLIENT_TIMEOUT')
                raw = os.read(fd, 65536)
                if not raw:
                    break
                size += len(raw)
                need(size <= BINARY_CAP)
                digest.update(raw)
            need(size == before.st_size)
            return digest.hexdigest()

        digest = checked('PLUGIN_HASH', hash_file)
        checked('PLUGIN_STABILITY', lambda: need(stamp(os.fstat(fd)) == stamp(before)
                and stamp(PLUGIN.lstat()) == stamp(before)))
        return {'path': str(PLUGIN), 'stat': list(stamp(before)), 'sha256': digest}
    finally:
        os.close(fd)


def metadata_schema(value):
    # Actual531 omitted URL; public CLI metadata.go declares URL omitempty.
    # Exactly four required keys, with ONLY this optional fifth key.
    return set(value) in (METADATA_REQUIRED_KEYS, METADATA_REQUIRED_KEYS | {'URL'})


def metadata_url(value):
    return ('URL' not in value or (type(value['URL']) is str
            and value['URL'] == 'https://github.com/docker/compose'))


def metadata_model(raw):
    need(type(raw) is bytes and len(raw) <= METADATA_CAP)
    value = parse_model(raw)
    need(metadata_schema(value))
    need(value['SchemaVersion'] == '0.1.0' and value['Vendor'] == 'Docker Inc.'
         and type(value['Version']) is str and value['Version'] in METADATA_VERSIONS
         and value['ShortDescription'] == 'Docker Compose'
         and metadata_url(value))
    return value


def observe_plugin(root, source_pin, test_pin):
    # This mode is a distinct ONE-query authority, never part of render mode.
    deadline = time.monotonic() + OBSERVATION_SECONDS
    source_bytes, test_bytes = sources(source_pin, test_pin)
    packet = Packet(root)
    try:
        packet.write('qualify_compose_render.py', source_bytes)
        packet.write('test_qualify_compose_render.py', test_bytes)
        packet.write('client/config.json', b'{}\n')
        identity = plugin_identity(deadline)
        env = child_env(root)
        argv = [str(PLUGIN), 'docker-cli-plugin-metadata']
        packet.write('attempt.json', canonical({
            'kind': 'public-compose-plugin-observation-v1',
            'source_sha256': source_pin, 'test_sha256': test_pin,
            'plugin': identity, 'command': argv, 'environment': env,
            'shared_seconds': OBSERVATION_SECONDS, 'client_seconds': CLIENT_SECONDS,
            'output_cap': METADATA_CAP, 'caller_timeout_ms_required': 15000}))
        need(plugin_identity(deadline) == identity
             and not (root / 'no-engine.sock').exists())
        metadata = metadata_model(bounded_client(argv, env, str(root), deadline,
                                                output_cap=METADATA_CAP))
        need(plugin_identity(deadline) == identity)
        packet.write('provenance.json', canonical({
            'code': 'PLUGIN_PROVENANCE', 'source_sha256': source_pin,
            'test_sha256': test_pin, 'plugin': identity, 'metadata': metadata,
            'semantic_version': SEMANTIC_VERSION,
            'historical514_binary_identity': 'NOT_ESTABLISHED'}))
        need(time.monotonic() < deadline)
        packet.write('receipt.json', b'{"code":"PROVENANCE"}\n')
        return 'PROVENANCE'
    except BaseException:
        try:
            packet.write('receipt.json', b'{"code":"REFUSED"}\n')
        except BaseException:
            pass
        raise Refused() from None


def diagnose_plugin(root, source_pin, test_pin, diagnostic):
    # New producer/root, no reads of spent r1 or its failed proof. At most ONE child.
    deadline = time.monotonic() + OBSERVATION_SECONDS
    source_bytes, test_bytes = diagnostic.check('SOURCE_PINS', lambda: sources(source_pin, test_pin))
    packet = diagnostic.check('ROOT_PREPARE', lambda: Packet(root))
    try:
        def write_sources():
            packet.write('qualify_compose_render.py', source_bytes)
            packet.write('test_qualify_compose_render.py', test_bytes)
        diagnostic.check('SOURCE_DURABILITY', write_sources)
        diagnostic.check('CLIENT_CONFIG_DURABILITY', lambda: packet.write('client/config.json', b'{}\n'))
        identity = diagnostic.check('PLUGIN_CANONICAL', lambda: plugin_identity(deadline, diagnostic))
        env = child_env(root)
        argv = [str(PLUGIN), 'docker-cli-plugin-metadata']
        diagnostic.check('ATTEMPT_DURABILITY', lambda: packet.write('attempt.json', canonical({
            'kind': DIAGNOSTIC_MODE, 'source_sha256': source_pin, 'test_sha256': test_pin,
            'producer_root': str(root), 'plugin': identity, 'command': argv,
            'environment': env, 'shared_seconds': OBSERVATION_SECONDS,
            'client_seconds': CLIENT_SECONDS, 'output_cap': METADATA_CAP,
            'caller_timeout_ms_required': 15000})))
        diagnostic.check('PRE_CHILD_IDENTITY', lambda: need(plugin_identity(deadline) == identity))
        diagnostic.check('SOCKET_GUARD', lambda: need(not (root / 'no-engine.sock').exists()))
        raw = bounded_client(argv, env, str(root), deadline, output_cap=METADATA_CAP,
                             diagnostic=diagnostic)
        metadata = diagnostic.check('METADATA_JSON', lambda: parse_model(raw),
                                    predicate_category='DECODE_REFUSED')
        diagnostic.check('METADATA_SCHEMA', lambda: need(metadata_schema(metadata)))
        diagnostic.check('METADATA_SCHEMA_VERSION', lambda: need(metadata['SchemaVersion'] == '0.1.0'))
        diagnostic.check('METADATA_VENDOR', lambda: need(metadata['Vendor'] == 'Docker Inc.'))
        diagnostic.check('METADATA_VERSION', lambda: need(type(metadata['Version']) is str
                         and metadata['Version'] in METADATA_VERSIONS))
        diagnostic.check('METADATA_DESCRIPTION', lambda: need(metadata['ShortDescription'] == 'Docker Compose'))
        diagnostic.check('METADATA_URL', lambda: need(metadata_url(metadata)))
        diagnostic.check('POST_CHILD_IDENTITY', lambda: need(plugin_identity(deadline) == identity))
        diagnostic.check('PROOF_DURABILITY', lambda: packet.write('provenance.json', canonical({
            'code': 'PLUGIN_PROVENANCE', 'source_sha256': source_pin,
            'test_sha256': test_pin, 'plugin': identity, 'metadata': metadata,
            'semantic_version': SEMANTIC_VERSION,
            'historical514_binary_identity': 'NOT_ESTABLISHED',
            'producer_mode': DIAGNOSTIC_MODE, 'producer_root': str(root)})))
        diagnostic.check('FINAL_DEADLINE', lambda: need(time.monotonic() < deadline))
        diagnostic.check('RECEIPT_DURABILITY', lambda: packet.write(
            'receipt.json', canonical(diagnostic.receipt(success=True))))
        return diagnostic.receipt(success=True)
    except BaseException:
        # Only a successfully created OWN Packet object may receive a failure
        # receipt; never open/adopt an already-existing/failed old root.
        try:
            packet.write('receipt.json', canonical(diagnostic.receipt()))
        except BaseException:
            pass
        raise


def schema_keys(metadata):
    need(type(metadata) is dict and len(metadata) <= 16)
    need(all(type(key) is str and re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,63}', key,
                                             flags=re.ASCII) for key in metadata))


def public_schema(metadata):
    # Finite PUBLIC name mapping ONLY. Unknown names are counted, never emitted,
    # hashed or saved. Missing known names are absence, not a value assertion.
    schema_keys(metadata)
    need(all(type(value) in SCHEMA_TYPES for value in metadata.values()))
    fields = [{'field': identifier, 'type': SCHEMA_TYPES[type(metadata[name])]}
              for name, identifier in sorted(PUBLIC_SCHEMA_FIELDS, key=lambda item: item[1])
              if name in metadata]
    receipt = {'code': 'SCHEMA', 'mode': SCHEMA_MODE, 'outcome': 'SCHEMA',
               'boundary': 'NO_ACTIVATION', 'fields': fields,
               'unknown_key_count': len(metadata) - len(fields)}
    need(len(canonical(receipt)) <= 2048)
    return receipt


def observe_public_schema(root, source_pin, test_pin, diagnostic):
    # NEW independent information-producing action. No provenance or old-root read.
    deadline = time.monotonic() + OBSERVATION_SECONDS
    source_bytes, test_bytes = diagnostic.check('SOURCE_PINS', lambda: sources(source_pin, test_pin))
    packet = diagnostic.check('ROOT_PREPARE', lambda: Packet(root))
    try:
        def write_sources():
            packet.write('qualify_compose_render.py', source_bytes)
            packet.write('test_qualify_compose_render.py', test_bytes)
        diagnostic.check('SOURCE_DURABILITY', write_sources)
        diagnostic.check('CLIENT_CONFIG_DURABILITY', lambda: packet.write('client/config.json', b'{}\n'))
        identity = diagnostic.check('PLUGIN_CANONICAL', lambda: plugin_identity(deadline, diagnostic))
        env = child_env(root)
        argv = [str(PLUGIN), 'docker-cli-plugin-metadata']
        diagnostic.check('ATTEMPT_DURABILITY', lambda: packet.write('attempt.json', canonical({
            'kind': SCHEMA_MODE, 'source_sha256': source_pin, 'test_sha256': test_pin,
            'producer_root': str(root), 'plugin': identity, 'command': argv,
            'shared_seconds': OBSERVATION_SECONDS,
            'client_seconds': CLIENT_SECONDS, 'output_cap': METADATA_CAP,
            'caller_timeout_ms_required': 15000})))
        diagnostic.check('PRE_CHILD_IDENTITY', lambda: need(plugin_identity(deadline) == identity))
        diagnostic.check('SOCKET_GUARD', lambda: need(not (root / 'no-engine.sock').exists()))
        raw = bounded_client(argv, env, str(root), deadline, output_cap=METADATA_CAP,
                             diagnostic=diagnostic)
        metadata = diagnostic.check('METADATA_JSON', lambda: parse_model(raw),
                                    predicate_category='DECODE_REFUSED')
        diagnostic.check('SCHEMA_KEYS', lambda: schema_keys(metadata))
        receipt = diagnostic.check('SCHEMA_TYPES', lambda: public_schema(metadata))
        diagnostic.check('POST_CHILD_IDENTITY', lambda: need(plugin_identity(deadline) == identity))
        diagnostic.check('FINAL_DEADLINE', lambda: need(time.monotonic() < deadline))
        diagnostic.check('RECEIPT_DURABILITY', lambda: packet.write('receipt.json', canonical(receipt)))
        return receipt
    except BaseException:
        try:
            packet.write('receipt.json', canonical(diagnostic.receipt()))
        except BaseException:
            pass
        raise


def read_provenance(pin, source_pin, test_pin):
    # Accept ONLY this new reviewed producer/root; never inspect/adopt r1.
    need(pin_valid(pin))
    need(read_own(DIAGNOSTIC_PACKET / 'receipt.json') == canonical(Diagnostic().receipt(success=True)))
    raw = read_own(DIAGNOSTIC_PACKET / 'provenance.json')
    need(hashlib.sha256(raw).hexdigest() == pin)
    value = parse_model(raw)
    need(set(value) == {'code', 'source_sha256', 'test_sha256', 'plugin', 'metadata',
                       'semantic_version', 'historical514_binary_identity',
                       'producer_mode', 'producer_root'})
    need(value['producer_mode'] == DIAGNOSTIC_MODE
         and value['producer_root'] == str(DIAGNOSTIC_PACKET))
    need(value['code'] == 'PLUGIN_PROVENANCE' and value['source_sha256'] == source_pin
         and value['test_sha256'] == test_pin
         and value['semantic_version'] == SEMANTIC_VERSION
         and value['historical514_binary_identity'] == 'NOT_ESTABLISHED')
    metadata_model(canonical(value['metadata']))
    identity = value['plugin']
    need(type(identity) is dict and set(identity) == {'path', 'stat', 'sha256'}
         and identity['path'] == str(PLUGIN) and pin_valid(identity['sha256'])
         and type(identity['stat']) is list and len(identity['stat']) == 9
         and all(type(item) is int for item in identity['stat']))
    return value


def child_env(root):
    # NEVER copy ambient os.environ, credentials, proxy, context or interpolation.
    return {'PATH': PUBLIC_PATH, 'HOME': str(root / 'home'),
            'XDG_CONFIG_HOME': str(root / 'xdg'),
            'DOCKER_CONFIG': str(root / 'client'),
            'DOCKER_HOST': 'unix://' + str(root / 'no-engine.sock'),
            'DOCKER_CONTEXT': '', 'COMPOSE_DISABLE_ENV_FILE': '1',
            'INERT_PUBLIC': 'public-marker', 'INERT_LITERAL': 'ambient-poison',
            'LC_ALL': 'C', 'LANG': 'C'}


def compose_argv(plugin, root, second):
    # Standalone Compose V2 entrypoint: no docker CLI/plugin search. Docker client
    # config/endpoint isolation comes from the exact child environment below.
    need(plugin == str(PLUGIN))
    argv = [plugin, '--ansi', 'never',
            '--project-name', PROJECT, '--project-directory', str(root),
            '--env-file', '/dev/null']
    files = ('normalized.json',) if second else ('base.yaml', 'overlay.yaml')
    for name in files:
        argv.extend(['-f', str(root / name)])
    return argv + ['config', '--format', 'json']


def bounded_client(argv, env, cwd, deadline, output_cap=None, diagnostic=None):
    """Same bounded transport; optional diagnostic observes lazy phase thunks."""
    def checked(gate, operation):
        return operation() if diagnostic is None else diagnostic.check(gate, operation)

    def launch():
        cap = OUTPUT_CAP if output_cap is None else output_cap
        need(type(cap) is int and 0 < cap <= OUTPUT_CAP)
        remaining = min(CLIENT_SECONDS, deadline - time.monotonic())
        if remaining <= 0:
            raise Classified('CLIENT_TIMEOUT')
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, cwd=cwd, env=env,
                                start_new_session=True, close_fds=True)
        return proc, cap, min(deadline, time.monotonic() + remaining)

    proc, cap, stop = checked('CLIENT_LAUNCH', launch)
    output = {proc.stdout: bytearray(), proc.stderr: bytearray()}

    def drain():
        total = 0
        with selectors.DefaultSelector() as selector:
            for stream in output:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                if time.monotonic() >= stop:
                    raise Classified('CLIENT_TIMEOUT')
                for key, _ in selector.select(min(0.05, max(0, stop - time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), min(8192, cap - total + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > cap:
                        raise Classified('OUTPUT_CAP')
                    output[key.fileobj].extend(chunk)

    def exit_status():
        if time.monotonic() >= stop:
            raise Classified('CLIENT_TIMEOUT')
        status = proc.wait(timeout=max(0.001, stop - time.monotonic()))
        if status != 0:
            raise Classified('CLIENT_NONZERO')
        if output[proc.stderr]:
            raise Classified('STDERR_PRESENT')

    try:
        checked('CLIENT_READ', drain)
        checked('CLIENT_EXIT', exit_status)
        return bytes(output[proc.stdout])
    except BaseException:
        # Only this OWN client process group, not any Docker resource/daemon.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        raise Refused() from None
    finally:
        proc.stdout.close()
        proc.stderr.close()


def execute(root, source_pin, test_pin, provenance_pin):
    deadline = time.monotonic() + SHARED_SECONDS
    source_bytes, test_bytes = sources(source_pin, test_pin)
    provenance = read_provenance(provenance_pin, source_pin, test_pin)
    identity = provenance['plugin']
    need(plugin_identity(deadline) == identity)
    packet = Packet(root)
    try:
        packet.write('qualify_compose_render.py', source_bytes)
        packet.write('test_qualify_compose_render.py', test_bytes)
        for name, raw in FIXTURES.items():
            packet.write(name, raw)
        packet.write('client/config.json', b'{}\n')
        packet.write('provenance.json', canonical(provenance))
        env = child_env(root)
        commands = [compose_argv(str(PLUGIN), root, second) for second in (False, True)]
        packet.write('attempt.json', canonical({
            'kind': 'public-compose-two-render-v2', 'source_sha256': source_pin,
            'test_sha256': test_pin, 'plugin': identity,
            'provenance_sha256': provenance_pin, 'metadata': provenance['metadata'],
            'commands': commands, 'environment': env, 'shared_seconds': SHARED_SECONDS,
            'client_seconds': CLIENT_SECONDS, 'caller_timeout_ms_required': 45000,
            'plugin_identity_against_prior_measurement': 'NOT_ESTABLISHED',
            'fixture_sha256': {name: hashlib.sha256(raw).hexdigest()
                               for name, raw in FIXTURES.items()}}))
        # No subprocess before ALL fixtures/source/provenance are durable.
        need(plugin_identity(deadline) == identity and not (root / 'no-engine.sock').exists())
        first = parse_model(bounded_client(commands[0], env, str(root), deadline))
        assert_oracle(first)
        packet.write('first.json', canonical(first))
        # config --format json is already dollar-escaped for Compose reinput.
        packet.write('normalized.json', canonical(first))
        need(plugin_identity(deadline) == identity and not (root / 'no-engine.sock').exists())
        second = parse_model(bounded_client(commands[1], env, str(root), deadline))
        need(canonical(second) == canonical(first))
        need(plugin_identity(deadline) == identity and time.monotonic() < deadline)
        packet.write('second.json', canonical(second))
        packet.write('receipt.json', b'{"code":"PASS"}\n')
        return 'PASS'
    except BaseException:
        # Never persist unexpected child data, exceptions, paths or error strings.
        try:
            packet.write('receipt.json', b'{"code":"REFUSED"}\n')
        except BaseException:
            pass
        raise Refused() from None


def read_accepted_render_proof(pin):
    need(pin == ACCEPTED_PROOF_SHA256 and DIAGNOSTIC_PACKET == ACCEPTED_PRODUCER_ROOT)
    # Reuse exact receipt/schema/metadata/identity validation, but explicitly bind
    # the accepted producer's pins, NEVER the new consumer's pins or a new query.
    return read_provenance(pin, ACCEPTED_PRODUCER_SOURCE, ACCEPTED_PRODUCER_TEST)


def diagnose_renders(root, source_pin, test_pin, proof_pin, diagnostic):
    deadline = time.monotonic() + SHARED_SECONDS
    source_bytes, test_bytes = diagnostic.check('SOURCE_PINS', lambda: sources(source_pin, test_pin))
    diagnostic.check('ACCEPTED_PROOF_PIN', lambda: need(proof_pin == ACCEPTED_PROOF_SHA256))
    proof = diagnostic.check('ACCEPTED_PROOF_READ', lambda: read_accepted_render_proof(proof_pin))
    identity = proof['plugin']
    diagnostic.check('INITIAL_IDENTITY', lambda: need(plugin_identity(deadline) == identity))
    packet = diagnostic.check('ROOT_PREPARE', lambda: Packet(root))
    try:
        def write_sources():
            packet.write('qualify_compose_render.py', source_bytes)
            packet.write('test_qualify_compose_render.py', test_bytes)
        def write_fixtures():
            for name, raw in FIXTURES.items():
                packet.write(name, raw)
        diagnostic.check('SOURCE_DURABILITY', write_sources)
        diagnostic.check('FIXTURE_DURABILITY', write_fixtures)
        diagnostic.check('CLIENT_CONFIG_DURABILITY', lambda: packet.write('client/config.json', b'{}\n'))
        diagnostic.check('ACCEPTED_PROOF_DURABILITY', lambda: packet.write('provenance.json', canonical(proof)))
        env = child_env(root)
        commands = [compose_argv(str(PLUGIN), root, second) for second in (False, True)]
        diagnostic.check('ATTEMPT_DURABILITY', lambda: packet.write('attempt.json', canonical({
            'kind': RENDER_MODE, 'consumer_source_sha256': source_pin,
            'consumer_test_sha256': test_pin, 'producer_source_sha256': ACCEPTED_PRODUCER_SOURCE,
            'producer_test_sha256': ACCEPTED_PRODUCER_TEST, 'producer_root': str(ACCEPTED_PRODUCER_ROOT),
            'provenance_sha256': proof_pin, 'commands': commands,
            'shared_seconds': SHARED_SECONDS, 'client_seconds': CLIENT_SECONDS,
            'output_cap': OUTPUT_CAP, 'caller_timeout_ms_required': 45000})))
        diagnostic.check('FIRST_IDENTITY', lambda: need(plugin_identity(deadline) == identity))
        diagnostic.check('FIRST_SOCKET', lambda: need(not (root / 'no-engine.sock').exists()))
        raw = diagnostic.check('FIRST_RENDER', lambda: bounded_client(
            commands[0], env, str(root), deadline, diagnostic=RenderPhase(diagnostic, 'FIRST_')))
        first = diagnostic.check('FIRST_JSON', lambda: parse_model(raw), 'DECODE_REFUSED')

        def first_oracle():
            if canonical(first) != canonical(expected_model()):
                diagnostic.oracle = oracle_difference(first)
            assert_oracle(first)  # Keep original complete independent oracle.
        diagnostic.check('FIRST_ORACLE', first_oracle)
        diagnostic.check('FIRST_DURABILITY', lambda: packet.write('first.json', canonical(first)))
        diagnostic.check('NORMALIZED_DURABILITY', lambda: packet.write(
            'normalized.json', canonical(first)))
        diagnostic.check('SECOND_IDENTITY', lambda: need(plugin_identity(deadline) == identity))
        diagnostic.check('SECOND_SOCKET', lambda: need(not (root / 'no-engine.sock').exists()))
        raw = diagnostic.check('SECOND_RENDER', lambda: bounded_client(
            commands[1], env, str(root), deadline, diagnostic=RenderPhase(diagnostic, 'SECOND_')))
        second = diagnostic.check('SECOND_JSON', lambda: parse_model(raw), 'DECODE_REFUSED')

        def second_equality():
            if canonical(second) != canonical(first):
                diagnostic.oracle = oracle_difference(second)
            need(canonical(second) == canonical(first))  # ALL fields, no normalization.
        diagnostic.check('SECOND_EQUALITY', second_equality)
        diagnostic.check('FINAL_IDENTITY', lambda: need(plugin_identity(deadline) == identity))
        diagnostic.check('SECOND_DURABILITY', lambda: packet.write('second.json', canonical(second)))
        diagnostic.check('FINAL_DEADLINE', lambda: need(time.monotonic() < deadline))
        diagnostic.check('RECEIPT_DURABILITY', lambda: packet.write(
            'receipt.json', canonical(diagnostic.receipt(success=True))))
        return diagnostic.receipt(success=True)
    except BaseException:
        try:
            packet.write('receipt.json', canonical(diagnostic.receipt()))
        except BaseException:
            pass
        raise


class QuietOutput:
    # Prevent interpreter-shutdown reflush of a failed stdout from emitting an
    # unraisable exception. No second output attempt; absent/partial != receipt.
    def write(self, value):
        return len(value)

    def flush(self):
        pass


def main(argv=None):
    diagnostic = Diagnostic()
    # If argument retrieval itself fails, emit the fixed ARGUMENTS diagnostic.
    diagnostic_mode = True
    schema_mode = False
    render_mode = False
    success = False
    try:
        args = diagnostic.check('ARGUMENTS', lambda: sys.argv[1:] if argv is None else argv)
        schema_mode = bool(args and args[0] == '--observe-public-schema')
        render_mode = bool(args and args[0] == '--diagnose-public-renders')
        diagnostic_mode = render_mode or schema_mode or bool(args and args[0] == '--diagnose-public-plugin')
        if schema_mode:
            diagnostic = SchemaDiagnostic()
        elif render_mode:
            diagnostic = RenderDiagnostic()

        def arguments():
            need(len(args) in (5, 7) and args[1] == '--source-sha256'
                 and args[3] == '--test-sha256')
            if render_mode:
                need(len(args) == 7 and args[5] == '--provenance-sha256')
            elif diagnostic_mode:
                need(len(args) == 5)
        diagnostic.check('ARGUMENTS', arguments)
        if render_mode:
            payload = diagnose_renders(RENDER_PACKET, args[2], args[4], args[6], diagnostic)
            need(payload == diagnostic.receipt(success=True))
        elif schema_mode:
            payload = observe_public_schema(SCHEMA_PACKET, args[2], args[4], diagnostic)
            need(type(payload) is dict and set(payload) ==
                 {'code', 'mode', 'outcome', 'boundary', 'fields', 'unknown_key_count'}
                 and payload['code'] == 'SCHEMA' and payload['mode'] == SCHEMA_MODE
                 and payload['outcome'] == 'SCHEMA' and payload['boundary'] == 'NO_ACTIVATION')
        elif diagnostic_mode:
            payload = diagnose_plugin(DIAGNOSTIC_PACKET, args[2], args[4], diagnostic)
            need(payload == diagnostic.receipt(success=True))
        elif len(args) == 5 and args[0] == '--observe-public-plugin':
            code = observe_plugin(PROVENANCE_PACKET, args[2], args[4])
            need(code == 'PROVENANCE')
            payload = {'code': code}
        else:
            need(len(args) == 7 and args[0] == '--execute-public-two-renders'
                 and args[5] == '--provenance-sha256')
            code = execute(PACKET, args[2], args[4], args[6])
            need(code == 'PASS')
            payload = {'code': code}
        success = True
    except BaseException:
        payload = diagnostic.receipt() if diagnostic_mode else {'code': 'REFUSED'}

    def write_output():
        receipt = canonical(payload).decode('utf-8')
        need(sys.stdout.write(receipt) == len(receipt))
        sys.stdout.flush()
    try:
        # On a prior failure retain its FIRST checkpoint/category, not OUTPUT.
        if diagnostic_mode and success:
            diagnostic.check('OUTPUT', write_output)
        else:
            write_output()
    except BaseException:
        sys.stdout = QuietOutput()
        return 1
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
