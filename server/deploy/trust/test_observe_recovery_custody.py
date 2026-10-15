#!/usr/bin/env python3
"""Inert tests: fake Docker transport/processes and fake directory metadata only.

Run with isolated Python -I -B. Never invokes observer's native entry, Docker,
private filesystem, SQLite, controller/helper imports or test fixture writes.
"""
import copy
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).with_name('observe_recovery_custody.py')
spec = importlib.util.spec_from_file_location('recovery_observer_under_test', SOURCE)
o = importlib.util.module_from_spec(spec)
spec.loader.exec_module(o)
CANARY = 'PRIVATE_PATH_LABEL_DB_ENV_MUST_NEVER_ESCAPE'
FOREIGN = 'a' * 64


def encoded(value):
    return json.dumps(value, separators=(',', ':')).encode() + b'\n'


def packet(records):
    return b''.join(encoded(r) for r in records)


def metadata(ino, mode=0o40755, uid=501, gid=20):
    return SimpleNamespace(st_dev=1, st_ino=ino, st_mode=mode, st_nlink=2,
        st_uid=uid, st_gid=gid, st_size=0, st_mtime_ns=1, st_ctime_ns=1)


class FakeFS:
    def __init__(self):
        self.nodes, self.opened, self.closed, self.stats = {'/': metadata(1)}, [], [], []
        self.change = None
        for _, path in o.ROOTS:
            for parent in reversed((path, *path.parents)):
                key = str(parent)
                if key not in self.nodes:
                    self.nodes[key] = metadata(len(self.nodes) + 1)
        for _, path in o.ROOTS:
            self.nodes[str(path)].st_mode = 0o40700

    def root(self):
        self.opened.append('/')
        return '/'

    def lstat(self, fd, name):
        path = str(Path(fd) / name)
        self.stats.append(path)
        if self.change:
            self.change(path, self)
        if path not in self.nodes:
            raise FileNotFoundError(CANARY)
        return copy.copy(self.nodes[path])

    def directory(self, fd, name):
        path = str(Path(fd) / name)
        s = self.nodes[path]
        if not stat.S_ISDIR(s.st_mode):
            raise AssertionError('followed non-directory')
        if '.local-auth' in Path(fd).parts:
            raise AssertionError('traversed private leaf')
        self.opened.append(path)
        return path

    def fstat(self, fd):
        return copy.copy(self.nodes[fd])

    def close(self, fd):
        self.closed.append(fd)


def mount(name, source, destination, rw=True, kind='volume'):
    return {'type': kind, 'name': name, 'source': source, 'destination': destination,
            'rw': rw, 'propagation': ''}


def fixture():
    volumes = [{'name': name, 'driver': 'local', 'scope': 'local', 'optionsPresent': False,
                'mountpoint': '/var/lib/docker/volumes/' + name + '/_data',
                'created': '2026-10-01T00:00:00Z'} for name in o.VOLUMES.values()]
    paths = {key: volumes[index]['mountpoint'] for index, key in enumerate(o.VOLUMES)}
    records = []
    for role, (identity, image) in o.TARGETS.items():
        mounts = []
        for key, dest in ({'api': [('auth', '/auth'), ('data', '/data')],
                          'worker': [('data', '/data')],
                          'holder': [('auth', '/source/auth'), ('data', '/source/data')],
                          'created-holder': [('auth', '/source/auth'), ('data', '/source/data')]}.get(role, [])):
            mounts.append(mount(o.VOLUMES[key], paths[key], dest))
        if role == 'holder':
            mounts.append(mount('', '/private/' + CANARY + '/helper.mjs', '/helper.mjs', False, 'bind'))
        records.append({'id': identity, 'status': 'created' if role == 'created-holder' else 'exited',
            'running': False, 'paused': False, 'restarting': False, 'dead': False, 'oom': False,
            'exit': 0, 'mounts': mounts, 'image': image,
            'tmpfs': dict(o.TMPFS) if 'holder' in role else None})
    records.append({'id': FOREIGN, 'status': 'exited', 'running': False, 'paused': False,
                    'restarting': False, 'dead': False, 'oom': False, 'exit': 0, 'mounts': []})
    return volumes, records


def common(r):
    return {k: v for k, v in r.items() if k not in ('image', 'tmpfs')}


class FakeClient:
    def __init__(self, volumes=None, records=None):
        v, r = fixture()
        self.volumes, self.records = volumes if volumes is not None else v, records if records is not None else r
        self.ids = tuple(sorted(item['id'] for item in self.records))
        self.known = tuple(i for i in self.ids if i in {p[0] for p in o.TARGETS.values()})
        rows = {r['id']: r for r in self.records}
        listing = ('\n'.join(self.ids) + '\n').encode() if self.ids else b''
        all_rows = packet([common(rows[i]) for i in self.ids])
        known = packet([rows[i] for i in self.known])
        self.queue = [(o.INFO, encoded(CANARY)), (o.VOLUME, packet(self.volumes)), (o.CENSUS, listing)]
        if self.known:
            self.queue.append((o.inspect_args(self.known, True), known))
        if self.ids:
            self.queue.append((o.inspect_args(self.ids), all_rows))
        self.queue.append((o.CENSUS, listing))
        if self.ids:
            self.queue.append((o.inspect_args(self.ids), all_rows))
        if self.known:
            self.queue.append((o.inspect_args(self.known, True), known))
        self.queue.extend([(o.VOLUME, packet(self.volumes)), (o.CENSUS, listing), (o.INFO, encoded(CANARY))])
        self.calls, self.bound, self.overrides = [], None, {}

    def bind(self, ids):
        if self.bound is not None:
            raise AssertionError('rebind')
        self.bound = ids

    def __call__(self, args):
        index = len(self.calls)
        self.calls.append(args)
        expected, value = self.queue[index]
        if args != expected:
            raise AssertionError('unexpected query sequence')
        value = self.overrides.get(index, value)
        if isinstance(value, BaseException):
            raise value
        return value


class ObservationTests(unittest.TestCase):
    def observe(self, client=None, fs=None, final=None):
        client, fs = client or FakeClient(), fs or FakeFS()
        result = o.observe(client, fs, time.monotonic() + 10, uid=501, gid=20,
                           final_sources=final or (lambda: None))
        self.assertLessEqual(len(o.canonical(result)), o.RECEIPT_CAP)
        self.assertNotIn(CANARY, o.canonical(result).decode())
        self.assertNotIn('/Users/', o.canonical(result).decode())
        self.assertNotIn('/var/lib/', o.canonical(result).decode())
        self.assertEqual(len(fs.opened), len(fs.closed))
        return result, client

    def test_complete_repeatable_observation_no_authority(self):
        first, client = self.observe()
        second, _ = self.observe()
        self.assertEqual(first, second)
        self.assertEqual(len(client.calls), 11)
        self.assertTrue(first['ok'])
        d = first['docker']
        self.assertTrue(d['completeStableMetadataFence'])
        self.assertTrue(d['noActiveProtectedAttachments'])
        self.assertTrue(d['originalBindingsMatch'])
        self.assertEqual(d['holderTmpfs'], 'EXITED_NOT_RESTORABLE_BY_START')
        self.assertEqual(first['ownership'], 'NOT_ADOPTED')
        self.assertEqual(first['sourceFilesystemOwnership'], 'NOT_OBSERVED')
        self.assertEqual(first['preCustody'], 'NOT_PROVEN')
        self.assertFalse(first['recoveryAuthorized'])

    def test_every_client_failure_stops_without_retry_or_partial_docker_pass(self):
        for index in range(11):
            for category in ('CLIENT_NONZERO', 'CLIENT_TIMEOUT', 'OUTPUT_CAP', 'EXEC_IDENTITY'):
                with self.subTest(index=index, category=category):
                    client = FakeClient()
                    client.overrides[index] = o.Refused(category)
                    result, _ = self.observe(client)
                    self.assertFalse(result['ok'])
                    self.assertEqual(result['category'], category)
                    self.assertIsNone(result['docker'])
                    self.assertEqual(len(client.calls), index + 1)

    def test_census_membership_drift_both_brackets(self):
        for index in (5, 9):
            client = FakeClient()
            client.overrides[index] = (''.join(i + '\n' for i in client.ids if i != FOREIGN)).encode()
            result, _ = self.observe(client)
            self.assertEqual(result['category'], 'OBSERVATION_DRIFT')
            self.assertEqual(len(client.calls), index + 1)

    def test_state_mount_image_volume_and_daemon_drift(self):
        for index, mutate in (
            (3, lambda rs: rs[0].update(exit=1)),
            (6, lambda rs: rs[0].update(exit=1)),
            (7, lambda rs: rs[0].update(image='sha256:' + 'f' * 64)),
            (8, lambda rs: rs[0].update(created='2026-10-02T00:00:00Z'))):
            client = FakeClient()
            rs = [json.loads(line) for line in client.queue[index][1].splitlines()]
            mutate(rs)
            client.overrides[index] = packet(rs)
            result, _ = self.observe(client)
            self.assertEqual(result['category'], 'OBSERVATION_DRIFT')
        client = FakeClient()
        client.overrides[10] = encoded('different-daemon')
        self.assertEqual(self.observe(client)[0]['category'], 'OBSERVATION_DRIFT')

    def test_outer_mount_order_only_is_ignored(self):
        client = FakeClient()
        rs = [json.loads(line) for line in client.queue[6][1].splitlines()]
        for r in rs:
            r['mounts'].reverse()
        client.overrides[6] = packet(rs)
        self.assertTrue(self.observe(client)[0]['ok'])
        for key, value in (('rw', False), ('propagation', 'rshared'), ('source', '/different')):
            client = FakeClient()
            rs = [json.loads(line) for line in client.queue[6][1].splitlines()]
            next(r for r in rs if r['mounts'])['mounts'][0][key] = value
            client.overrides[6] = packet(rs)
            self.assertEqual(self.observe(client)[0]['category'], 'OBSERVATION_DRIFT')

    def test_all_foreign_mount_aliases_and_ro_attachments_are_conservative(self):
        for kind, name, source, rw in (
            ('volume', o.VOLUMES['data'], '/unrelated', True),
            ('bind', '', '/var/lib/docker/volumes', True),
            ('bind', '', '/var/lib/docker/volumes/' + o.VOLUMES['data'] + '/_data/file', True),
            ('bind', '', '/host_mnt/var/lib/docker/volumes/' + o.VOLUMES['data'] + '/_data', False)):
            for state in ('running', 'paused', 'restarting', 'dead', 'removing'):
                v, rs = fixture()
                r = rs[-1]
                r.update(status=state, running=state in ('running', 'paused'), paused=state == 'paused',
                         restarting=state == 'restarting', dead=state == 'dead',
                         mounts=[mount(name, source, '/foreign', rw, kind)])
                result, _ = self.observe(FakeClient(v, rs))
                self.assertTrue(result['ok'])
                self.assertFalse(result['docker']['noActiveProtectedAttachments'])

    def test_no_holder_or_egress_exemption(self):
        for role in o.TARGETS:
            v, rs = fixture()
            r = next(r for r in rs if r['id'] == o.TARGETS[role][0])
            r.update(status='running', running=True)
            r['mounts'].append(mount('', '/var/lib/docker', '/wide-bind', False, 'bind'))
            result, _ = self.observe(FakeClient(v, rs))
            self.assertFalse(result['docker']['noActiveProtectedAttachments'])

    def test_unrelated_active_container_not_reported_as_protected_writer(self):
        v, rs = fixture()
        rs[-1].update(status='running', running=True,
                      mounts=[mount('', '/unrelated', '/foreign', True, 'bind')])
        result, _ = self.observe(FakeClient(v, rs))
        self.assertTrue(result['docker']['noActiveProtectedAttachments'])

    def test_bindings_are_observed_not_repaired_or_adopted(self):
        for alteration, expected in (('ro', 'MATCH_RO'), ('missing', 'MISSING_TARGET'), ('wrong', 'WRONG_BINDING')):
            v, rs = fixture()
            api = next(r for r in rs if r['id'] == o.TARGETS['api'][0])
            if alteration == 'ro':
                api['mounts'][0]['rw'] = False
            elif alteration == 'missing':
                api['mounts'].pop(0)
            else:
                api['mounts'][0]['source'] = '/wrong/' + CANARY
            result, _ = self.observe(FakeClient(v, rs))
            self.assertTrue(result['ok'])
            self.assertEqual(result['docker']['mountBindings']['api.auth'], expected)
            self.assertFalse(result['recoveryAuthorized'])

    def test_missing_targets_and_empty_census_are_explicit_not_full_qualification(self):
        for rs in ([], fixture()[1][-1:]):
            result, client = self.observe(FakeClient(records=rs))
            self.assertTrue(result['ok'])
            self.assertFalse(result['docker']['originalBindingsMatch'])
            self.assertEqual(result['docker']['targets']['holder']['state'], 'ABSENT_IN_CENSUS')
            self.assertFalse(result['recoveryAuthorized'])
            self.assertLess(len(client.calls), 11)

    def test_volume_options_driver_identity_and_overlap_refuse(self):
        for field, value in (('optionsPresent', True), ('driver', 'nfs'), ('scope', 'global'),
                             ('name', 'unknown'), ('mountpoint', '/')):
            v, rs = fixture()
            v[0][field] = value
            result, client = self.observe(FakeClient(v, rs))
            self.assertFalse(result['ok'])
            self.assertEqual(result['checkpoint'], 'VOLUMES_BEFORE')
            self.assertEqual(len(client.calls), 2)

    def test_final_source_drift_suppresses_positive_fence(self):
        def refuse():
            raise o.Refused('SOURCE_REFUSED')
        result, _ = self.observe(final=refuse)
        self.assertEqual(result['checkpoint'], 'SOURCE_FINAL')
        self.assertIsNone(result['docker'])

    def test_unexpected_error_is_closed_without_exception_text(self):
        client = FakeClient()
        client.overrides[0] = RuntimeError(CANARY)
        result, _ = self.observe(client)
        self.assertEqual(result['category'], 'UNEXPECTED')

    def test_deadline_expired_before_any_metadata_or_client(self):
        client, fs = FakeClient(), FakeFS()
        result = o.observe(client, fs, 0, uid=501, gid=20)
        self.assertEqual(result['category'], 'CLIENT_TIMEOUT')
        self.assertEqual(client.calls, [])
        self.assertEqual(fs.opened, [])


class RootTests(unittest.TestCase):
    def check(self, fs):
        result = o.root_metadata(o.ROOTS[0][1], fs, time.monotonic() + 5, 501, 20)
        self.assertEqual(len(fs.opened), len(fs.closed))
        return result

    def test_755_parent_and_root_are_metadata_not_private_custody(self):
        fs = FakeFS()
        fs.nodes[str(o.ROOTS[0][1])].st_mode = 0o40755
        r = self.check(fs)
        self.assertEqual(r['classification'], 'DIRECTORY_METADATA')
        self.assertTrue(r['mode755'])
        self.assertTrue(r['noGroupWorldWrite'])
        self.assertFalse(r['private700Matches'])
        self.assertTrue(r['stable'])

    def test_private_predicates_individually_visible_no_weakening(self):
        for key, value, flag in (('st_uid', 123, 'uidMatch'), ('st_gid', 123, 'gidMatch'),
                                ('st_mode', 0o40755, 'mode700'), ('st_mode', 0o40777, 'noGroupWorldWrite')):
            fs = FakeFS()
            setattr(fs.nodes[str(o.ROOTS[0][1])], key, value)
            r = self.check(fs)
            self.assertFalse(r[flag])
            self.assertFalse(r['private700Matches'])
            if key == 'st_uid' or value == 0o40777:
                self.assertNotIn(str(o.ROOTS[0][1]), fs.opened)

    def test_symlink_at_any_component_never_followed(self):
        path = o.ROOTS[0][1]
        for component in (path, path.parent, Path('/Users')):
            fs = FakeFS()
            fs.nodes[str(component)].st_mode = 0o120777
            r = self.check(fs)
            self.assertEqual(r['classification'], 'SYMLINK_REFUSED')
            self.assertNotIn(str(component), fs.opened)
            self.assertFalse(any(p.startswith(str(component) + '/') for p in fs.stats))

    def test_missing_root_vs_ancestor_are_classified_without_search(self):
        for path, at_root in ((o.ROOTS[0][1], True), (o.ROOTS[0][1].parent, False)):
            fs = FakeFS()
            del fs.nodes[str(path)]
            r = self.check(fs)
            self.assertEqual(r['classification'], 'ABSENT')
            self.assertEqual(r['atRoot'], at_root)
            self.assertFalse(any(p.startswith(str(path) + '/') for p in fs.stats))

    def test_non_directory_or_unsafe_ancestor_stops(self):
        for mode, category in ((0o100600, 'NOT_DIRECTORY'), (0o40777, 'UNSAFE_ANCESTOR')):
            fs = FakeFS()
            path = str(o.ROOTS[0][1].parent)
            fs.nodes[path].st_mode = mode
            self.assertEqual(self.check(fs)['classification'], category)
            self.assertNotIn(path, fs.opened)

    def test_fd_and_final_path_drift_close_every_descriptor(self):
        for fd_drift in (True, False):
            fs = FakeFS()
            if fd_drift:
                original = fs.fstat
                def changed(fd):
                    s = original(fd)
                    s.st_ino += 1000
                    return s
                fs.fstat = changed
            else:
                target = str(o.ROOTS[0][1])
                def changed(path, fake):
                    if path == target and fake.stats.count(path) == 2:
                        fake.nodes[path].st_mtime_ns += 1
                fs.change = changed
            with self.assertRaises(o.Refused) as error:
                self.check(fs)
            self.assertEqual(error.exception.category, 'OBSERVATION_DRIFT')
            self.assertEqual(len(fs.opened), len(fs.closed))

    def test_host_io_is_closed(self):
        fs = FakeFS()
        fs.lstat = Mock(side_effect=PermissionError(CANARY))
        with self.assertRaises(o.Refused) as error:
            self.check(fs)
        self.assertEqual(error.exception.category, 'HOST_IO')
        self.assertEqual(len(fs.opened), len(fs.closed))


class ParserTests(unittest.TestCase):
    def test_duplicate_keys_nan_float_utf8_rejected(self):
        for raw in (b'{"id":1,"id":2}', b'NaN', b'1.5', b'\xff'):
            with self.subTest(raw=raw), self.assertRaises(o.Refused):
                o.decode(raw, 4096)

    def test_complete_census_not_prefix_or_duplicate(self):
        for raw in (b'x\n', (FOREIGN + '\n' + FOREIGN + '\n').encode(), FOREIGN.encode(),
                    ''.join(format(i, '064x') + '\n' for i in range(33)).encode()):
            with self.assertRaises(o.Refused):
                o.census(raw)
        self.assertEqual(o.census(b''), ())

    def test_mount_shape_cardinality_types_and_ambiguous_paths(self):
        v, rs = fixture()
        original = next(r for r in rs if r['mounts'])['mounts'][0]
        cases = [None, [original] * 2, [original] * 65]
        for field, value in (('rw', 1), ('source', '/a/../b'), ('source', '//host/a'),
                             ('type', 'unknown'), ('destination', '/a//b'), ('name', None)):
            m = dict(original, **{field: value})
            cases.append([m])
        for case in cases:
            with self.subTest(case=case), self.assertRaises(o.Refused):
                o.mounts(case)
        self.assertEqual(o.mounts([]), [])

    def test_row_coverage_duplicates_and_boolean_integer_confusion(self):
        _, rs = fixture()
        one = common(rs[0])
        for payload in (packet([one, one]), encoded(dict(one, exit=False)), encoded(dict(one, running=1)),
                        encoded(dict(one, status='exited', paused=True))):
            with self.assertRaises(o.Refused):
                o.rows(payload, (one['id'],))

    def test_cli_stdout_template_excludes_sensitive_fields_not_engine_response(self):
        for fmt in (o.COMMON_FORMAT, o.KNOWN_FORMAT, o.VOLUME_FORMAT):
            for forbidden in ('.Config', '.Labels', '.State.Error', '.State.Health',
                              'json .State}', 'json .HostConfig}', 'json .Mounts}'):
                self.assertNotIn(forbidden, fmt)
        self.assertNotIn('Env', o.KNOWN_FORMAT)


class FakeStream:
    def __init__(self, fd):
        self.fd, self.closed = fd, False

    def fileno(self):
        return self.fd

    def close(self):
        self.closed = True


class FakeProcess:
    def __init__(self, code=0):
        self.stdout, self.stderr = FakeStream(10), FakeStream(11)
        self.pid, self.returncode, self.code = 12345, None, code

    def poll(self):
        return self.returncode

    def wait(self, timeout):
        self.returncode = self.code
        return self.code


class FakeSelector:
    def __init__(self):
        self.mapping = {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def register(self, stream, events, data):
        self.mapping[stream.fd] = SimpleNamespace(fd=stream.fd, fileobj=stream, data=data)

    def unregister(self, stream):
        del self.mapping[stream.fd]

    def get_map(self):
        return self.mapping

    def select(self, timeout):
        return [(key, 1) for key in list(self.mapping.values())]


class TransportTests(unittest.TestCase):
    def run_fake(self, stdout=b'{}\n', stderr=b'', code=0, total=0):
        proc, client = FakeProcess(code), o.DockerClient(time.monotonic() + 5, allow_cli_full_metadata=True)
        client.total = total
        chunks = {10: [stdout, b''], 11: [stderr, b'']}
        with patch.object(o, 'verify_cli'), patch.object(o, 'config_absent'), \
             patch.object(o.subprocess, 'Popen', return_value=proc) as popen, \
             patch.object(o.selectors, 'DefaultSelector', FakeSelector), \
             patch.object(o.os, 'read', side_effect=lambda fd, count: chunks[fd].pop(0)), \
             patch.object(o.os, 'killpg') as kill:
            try:
                result = client(o.INFO)
            except o.Refused as exc:
                result = exc.category
        self.assertTrue(proc.stdout.closed and proc.stderr.closed)
        return result, popen, kill

    def test_clean_environment_fixed_socket_no_shell_or_private_config(self):
        result, popen, kill = self.run_fake()
        self.assertEqual(result, b'{}\n')
        args, kwargs = popen.call_args
        self.assertEqual(args[0][:5], (str(o.DOCKER), '--config', str(o.REPO / 'server/deploy/trust'), '--host', o.SOCKET))
        self.assertEqual(kwargs['env']['HOME'], '/var/empty')
        self.assertEqual(set(kwargs['env']), {'PATH', 'HOME', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG'})
        self.assertNotIn('shell', kwargs)
        self.assertIs(kwargs['stdin'], o.subprocess.DEVNULL)
        kill.assert_not_called()

    def test_stdout_stderr_aggregate_caps_and_client_nonzero(self):
        for stdout, stderr, code, total, expected in (
            (b'x' * 4097, b'', 0, 0, 'OUTPUT_CAP'),
            (b'', b'x' * 4097, 0, 0, 'OUTPUT_CAP'),
            (b'x', b'', 0, o.TRANSPORT_CAP, 'OUTPUT_CAP'),
            (b'', CANARY.encode(), 1, 0, 'CLIENT_NONZERO')):
            result, _, kill = self.run_fake(stdout, stderr, code, total)
            self.assertEqual(result, expected)
            if code:
                kill.assert_not_called()  # Never signal a reaped/reused process group.

    def test_timeout_and_pipe_io_kill_only_live_fake_client_and_close_streams(self):
        for failure, category in ((o.Refused('CLIENT_TIMEOUT'), 'CLIENT_TIMEOUT'),
                                  (OSError(CANARY), 'CLIENT_IO')):
            proc = FakeProcess()
            client = o.DockerClient(time.monotonic() + 5, allow_cli_full_metadata=True)
            with patch.object(o, 'verify_cli'), patch.object(o, 'config_absent'), \
                 patch.object(o.subprocess, 'Popen', return_value=proc), \
                 patch.object(o.selectors, 'DefaultSelector', FakeSelector), \
                 patch.object(o.os, 'read', side_effect=failure), \
                 patch.object(o.os, 'killpg') as kill, self.assertRaises(o.Refused) as error:
                client(o.INFO)
            self.assertEqual(error.exception.category, category)
            kill.assert_called_once_with(proc.pid, o.signal.SIGKILL)
            self.assertTrue(proc.stdout.closed and proc.stderr.closed)

    def test_read_size_is_remaining_budget_plus_one_not_unbounded_chunk(self):
        proc = FakeProcess()
        client = o.DockerClient(time.monotonic() + 5, allow_cli_full_metadata=True)
        client.total = o.TRANSPORT_CAP - 2
        chunks = {10: [b'ab', b'x'], 11: [b'']}
        with patch.object(o, 'verify_cli'), patch.object(o, 'config_absent'), \
             patch.object(o.subprocess, 'Popen', return_value=proc), \
             patch.object(o.selectors, 'DefaultSelector', FakeSelector), \
             patch.object(o.os, 'read', side_effect=lambda fd, cap: chunks[fd].pop(0)) as read, \
             patch.object(o.os, 'killpg'), self.assertRaises(o.Refused) as caught:
            client(o.INFO)
        self.assertEqual(caught.exception.category, 'OUTPUT_CAP')
        self.assertEqual([call.args[1] for call in read.call_args_list], [3, 1, 1])
        self.assertEqual(client.total, o.TRANSPORT_CAP + 1)

    def test_stderr_canary_is_never_returned_even_on_success(self):
        result, _, _ = self.run_fake(stderr=CANARY.encode())
        self.assertEqual(result, b'{}\n')

    def test_unknown_mutating_or_unbound_commands_refused_before_native(self):
        client = o.DockerClient(time.monotonic() + 5, allow_cli_full_metadata=True)
        with patch.object(o.subprocess, 'Popen') as popen:
            for args in (('start', FOREIGN), ('exec', FOREIGN, 'true'), ('cp', 'x', 'y'),
                         ('inspect', FOREIGN), o.inspect_args((FOREIGN,))):
                with self.assertRaises(o.Refused) as error:
                    client(args)
                self.assertEqual(error.exception.category, 'COMMAND_REFUSED')
            popen.assert_not_called()

    def test_pinned_binary_failure_does_not_spawn_or_fallback(self):
        client = o.DockerClient(time.monotonic() + 5, allow_cli_full_metadata=True)
        with patch.object(o, 'verify_cli', side_effect=o.Refused('EXEC_IDENTITY')), \
             patch.object(o.subprocess, 'Popen') as popen:
            with self.assertRaises(o.Refused) as error:
                client(o.INFO)
            self.assertEqual(error.exception.category, 'EXEC_IDENTITY')
            popen.assert_not_called()

    def test_call_budget_and_per_command_budget(self):
        for calls, used in ((11, {}), (2, {o.INFO: 2})):
            client = o.DockerClient(time.monotonic() + 5, allow_cli_full_metadata=True)
            client.calls, client.used = calls, used
            with patch.object(o.subprocess, 'Popen') as popen, self.assertRaises(o.Refused):
                client(o.INFO)
            popen.assert_not_called()

    def test_config_presence_and_spawn_errors_are_closed(self):
        with patch.object(o, 'verify_cli'), patch.object(o, 'config_absent', side_effect=o.Refused('SOURCE_REFUSED')), \
             patch.object(o.subprocess, 'Popen') as popen:
            with self.assertRaises(o.Refused):
                o.DockerClient(time.monotonic() + 5, allow_cli_full_metadata=True)(o.INFO)
            popen.assert_not_called()
        for error, category in ((FileNotFoundError(CANARY), 'EXEC_NOT_FOUND'),
                                (PermissionError(CANARY), 'EXEC_DENIED'), (OSError(CANARY), 'EXEC_IO')):
            with patch.object(o, 'verify_cli'), patch.object(o, 'config_absent'), \
                 patch.object(o.subprocess, 'Popen', side_effect=error), self.assertRaises(o.Refused) as caught:
                o.DockerClient(time.monotonic() + 5, allow_cli_full_metadata=True)(o.INFO)
            self.assertEqual(caught.exception.category, category)


class EntryTests(unittest.TestCase):
    def test_default_invocation_refuses_before_source_host_or_native_access(self):
        sink = SimpleNamespace(buffer=io.BytesIO())
        with patch.object(o.sys, 'stdout', sink), \
             patch.object(o, 'source_gate') as gate, patch.object(o, 'public_hash') as hashed, \
             patch.object(o, 'DockerClient') as client, patch.object(o, 'MetadataFS') as fs, \
             patch.object(o.subprocess, 'Popen') as popen:
            code = o.main(['--observe', '--source-sha256', 'b' * 64, '--test-sha256', 'c' * 64])
        result = json.loads(sink.buffer.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(result['checkpoint'], 'PRIVACY_CONSENT')
        self.assertEqual(result['category'], 'CLI_FULL_METADATA_CONSENT_REQUIRED')
        self.assertIsNone(result['roots'])
        self.assertIsNone(result['docker'])
        for dependency in (gate, hashed, client, fs, popen):
            dependency.assert_not_called()

    def test_client_defaults_and_truthy_nonboolean_do_not_grant_consent(self):
        clients = [o.DockerClient(time.monotonic() + 5)]
        clients.extend(o.DockerClient(time.monotonic() + 5, allow_cli_full_metadata=value)
                       for value in (None, 0, 1, 'true'))
        with patch.object(o, 'verify_cli') as verify, patch.object(o, 'config_absent') as config, \
             patch.object(o.subprocess, 'Popen') as popen:
            for client in clients:
                with self.assertRaises(o.Refused) as error:
                    client(o.INFO)
                self.assertEqual(error.exception.category, 'CLI_FULL_METADATA_CONSENT_REQUIRED')
                self.assertEqual(client.calls, 0)
        for dependency in (verify, config, popen):
            dependency.assert_not_called()

    def test_source_gate_itself_requires_consent_before_public_hash(self):
        with patch.object(o, 'public_hash') as hashed, self.assertRaises(o.Refused) as error:
            o.source_gate(['--observe', '--source-sha256', 'b' * 64, '--test-sha256', 'c' * 64],
                          time.monotonic() + 5)
        self.assertEqual(error.exception.category, 'CLI_FULL_METADATA_CONSENT_REQUIRED')
        hashed.assert_not_called()

    def test_consent_requires_exact_distinct_flag_once_in_fixed_position(self):
        base = ['--observe', '--source-sha256', 'b' * 64, '--test-sha256', 'c' * 64]
        self.assertFalse(o.arguments(base))
        self.assertTrue(o.arguments(base + [o.CONSENT_FLAG]))
        for args in (base + ['--allow-cli-full-metadata=true'], base + [o.CONSENT_FLAG] * 2,
                     [o.CONSENT_FLAG] + base, base + ['--anything']):
            with self.assertRaises(o.Refused) as error:
                o.arguments(args)
            self.assertEqual(error.exception.category, 'ARGUMENT_REFUSED')

    def test_output_write_and_flush_are_guarded_in_order(self):
        buffer = Mock()
        buffer.write.side_effect = lambda packet: len(packet)
        with patch.object(o.sys, 'stdout', SimpleNamespace(buffer=buffer)):
            code = o.main(['invalid'])
        self.assertEqual(code, 1)
        self.assertEqual([call[0] for call in buffer.mock_calls], ['write', 'flush'])
        raw = buffer.write.call_args.args[0]
        self.assertTrue(raw.endswith(b'\n'))
        self.assertEqual(json.loads(raw)['category'], 'ARGUMENT_REFUSED')

    def test_output_write_failures_no_retry_flush_or_stderr(self):
        for error in (BrokenPipeError(CANARY), OSError(CANARY), ValueError(CANARY)):
            buffer, stderr = Mock(), io.StringIO()
            buffer.write.side_effect = error
            with patch.object(o.sys, 'stdout', SimpleNamespace(buffer=buffer)), \
                 patch.object(o.sys, 'stderr', stderr):
                code = o.main(['invalid'])
            self.assertEqual(code, o.OUTPUT_FAILURE)
            buffer.write.assert_called_once()
            buffer.flush.assert_not_called()
            self.assertEqual(stderr.getvalue(), '')

    def test_output_flush_failures_no_retry_or_stderr(self):
        for error in (BrokenPipeError(CANARY), OSError(CANARY), ValueError(CANARY)):
            buffer, stderr = Mock(), io.StringIO()
            buffer.write.side_effect = lambda packet: len(packet)
            buffer.flush.side_effect = error
            with patch.object(o.sys, 'stdout', SimpleNamespace(buffer=buffer)), \
                 patch.object(o.sys, 'stderr', stderr):
                code = o.main(['invalid'])
            self.assertEqual(code, o.OUTPUT_FAILURE)
            buffer.write.assert_called_once()
            buffer.flush.assert_called_once()
            self.assertEqual(stderr.getvalue(), '')

    def test_short_write_is_output_failure_without_flush_or_rewrite(self):
        for written in (0, 1, None, True):
            buffer = Mock()
            buffer.write.return_value = written
            with patch.object(o.sys, 'stdout', SimpleNamespace(buffer=buffer)):
                code = o.main(['invalid'])
            self.assertEqual(code, o.OUTPUT_FAILURE)
            buffer.write.assert_called_once()
            buffer.flush.assert_not_called()

    def test_broken_pipe_entry_uses_immediate_exit_to_skip_shutdown_flush(self):
        # Fake _exit only: no subprocess or real interpreter/process shutdown.
        for phase in ('write', 'flush'):
            buffer, stderr = Mock(), io.StringIO()
            buffer.write.side_effect = lambda packet: len(packet)
            getattr(buffer, phase).side_effect = BrokenPipeError(CANARY)
            with patch.object(o.sys, 'stdout', SimpleNamespace(buffer=buffer)), \
                 patch.object(o.sys, 'stderr', stderr), \
                 patch.object(o.os, '_exit', side_effect=SystemExit(o.OUTPUT_FAILURE)) as immediate, \
                 self.assertRaises(SystemExit) as caught:
                o.entrypoint(['invalid'])
            self.assertEqual(caught.exception.code, 74)
            immediate.assert_called_once_with(74)
            self.assertEqual(buffer.write.call_count, 1)
            self.assertEqual(buffer.flush.call_count, 1 if phase == 'flush' else 0)
            self.assertEqual(stderr.getvalue(), '')

    def test_normal_entry_uses_system_exit_not_immediate_exit(self):
        for code in (0, 1):
            with patch.object(o, 'main', return_value=code), patch.object(o.os, '_exit') as immediate, \
                 self.assertRaises(SystemExit) as caught:
                o.entrypoint([])
            self.assertEqual(caught.exception.code, code)
            immediate.assert_not_called()

    def test_argument_failure_has_only_closed_receipt_and_no_native(self):
        sink = SimpleNamespace(buffer=io.BytesIO())
        with patch.object(o.sys, 'stdout', sink), patch.object(o.subprocess, 'Popen') as popen:
            code = o.main(['--not-allowed', CANARY])
        result = json.loads(sink.buffer.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(result['category'], 'ARGUMENT_REFUSED')
        self.assertNotIn(CANARY, sink.buffer.getvalue().decode())
        popen.assert_not_called()

    def test_entry_with_every_external_dependency_fake(self):
        sink, client, fs = SimpleNamespace(buffer=io.BytesIO()), FakeClient(), FakeFS()
        verify = Mock()
        with patch.object(o.sys, 'stdout', sink), patch.object(o, 'source_gate', return_value=verify), \
             patch.object(o, 'DockerClient', return_value=client) as factory, patch.object(o, 'MetadataFS', return_value=fs), \
             patch.object(o.subprocess, 'Popen') as popen:
            code = o.main(['--observe', '--source-sha256', 'b' * 64, '--test-sha256', 'c' * 64, o.CONSENT_FLAG])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(sink.buffer.getvalue())['ok'])
        verify.assert_called_once()
        self.assertIs(factory.call_args.kwargs['allow_cli_full_metadata'], True)
        popen.assert_not_called()

    def test_source_pin_mismatch_has_no_client(self):
        with patch.object(o, 'public_hash', return_value='a' * 64), \
             patch.object(o, '__file__', str(o.REPO / o.SELF)), \
             patch.object(o.sys, 'flags', SimpleNamespace(isolated=True, dont_write_bytecode=True)), \
             patch.object(o.subprocess, 'Popen') as popen, self.assertRaises(o.Refused) as caught:
            o.source_gate(['--observe', '--source-sha256', 'b' * 64, '--test-sha256', 'c' * 64, o.CONSENT_FLAG], time.monotonic() + 5)
        self.assertEqual(caught.exception.category, 'SOURCE_REFUSED')
        popen.assert_not_called()


if __name__ == '__main__':
    unittest.main()
