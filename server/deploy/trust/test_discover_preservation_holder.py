"""Own inert tests ONLY. No Engine, original/private metadata, DB or app imports."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).absolute()
spec = importlib.util.spec_from_file_location('own_holder_discovery', HERE.with_name('discover_preservation_holder.py'))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
REAL_VERIFY_EXECUTABLE = v.verify_executable
CANARY = 'PRIVATE_CANARY'
CID = '2' * 64
LABEL_VALUE = 'key-preservation-abcd1234'


def state(cid, image, status='exited'):
    return {'id': cid, 'image': image, 'status': status, 'running': status == 'running',
            'paused': False, 'restarting': False, 'oom': False, 'dead': False, 'exit': 0}


def sources():
    return {key: '/' + CANARY + '/' + key + '/_data' for key in v.VOLUMES}


def old_mounts():
    return [{'Type': 'volume', 'Name': name, 'Source': sources()[key],
             'Destination': '/' + key, 'RW': True} for key, name in v.VOLUMES.items()]


def candidate(repo, cid=CID):
    r = state(cid, v.ORIGINALS['api'][1], 'created')
    r.update(name='/dip-key-snapshot-' + 'a' * 32, configImage=v.ORIGINALS['api'][1],
             labels={'com.docker.compose.project': 'public-image-inherited', v.LABEL: LABEL_VALUE},
             user='65532:65532', cwd='/app/server/api', entry=['node'], cmd=['-e', v.HOLDER_CODE],
             path='node', args=['-e', v.HOLDER_CODE], health={'Test': ['NONE']}, volumes=None, stop=5,
             host={'NetworkMode': 'none', 'ReadonlyRootfs': True, 'CapDrop': ['ALL'], 'CapAdd': None,
                   'Privileged': False, 'SecurityOpt': ['no-new-privileges:true'], 'Devices': None,
                   'DeviceRequests': None, 'Binds': None, 'PortBindings': None, 'CgroupnsMode': 'private',
                   'Memory': 2 * 1024**3, 'MemorySwap': 2 * 1024**3, 'NanoCpus': 10**9,
                   'PidsLimit': 64, 'Tmpfs': copy.deepcopy(v.TMPFS),
                   'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0}},
             declared=[{'Type': 'volume', 'Source': name, 'Target': '/source/' + key}
                       for key, name in v.VOLUMES.items()] +
                      [{'Type': 'bind', 'Source': str(repo / v.SCRIPT), 'Target': v.TARGET,
                        'ReadOnly': True, 'BindOptions': {}}],
             mounts=[], networkCount=0, networkNone=False)
    return r


class FakeClient:
    def __init__(self, repo, records=None):
        self.repo = repo
        self.records = [candidate(repo)] if records is None else records
        self.listing = b''.join((r['id'] + '\n').encode() for r in self.records)
        self.calls = []
        self.image = {'id': v.ORIGINALS['api'][1], 'labels': {'com.docker.compose.project': 'public-image-inherited'},
                      'cwd': '/app/server/api', 'volumes': None}
        self.originals = {role: state(cid, image) for role, (cid, image) in v.ORIGINALS.items()}
        self.originals['api']['mounts'] = old_mounts()

    def __call__(self, args, cap=65536):
        self.calls.append((args, cap))
        assert len(self.calls) <= 8
        if args == v.LIST_ARGS:
            return self.listing
        if args == ('image', 'inspect', '--format', v.IMAGE_FORMAT, v.ORIGINALS['api'][1]):
            return v.canonical(self.image)
        for role, (cid, _) in v.ORIGINALS.items():
            fmt = v.API_FORMAT if role == 'api' else v.OLD_FORMAT
            if args == ('container', 'inspect', '--format', fmt, cid):
                return v.canonical(self.originals[role])
        if args[:4] == ('container', 'inspect', '--format', v.CANDIDATE_FORMAT):
            assert args[4:] == tuple(sorted(r['id'] for r in self.records))
            return b'\n'.join(v.canonical(r) for r in self.records) + b'\n'
        raise AssertionError('UNREVIEWED_CLIENT')


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.no_child = mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('NO_REAL_CLIENT')).start()
        self.addCleanup(mock.patch.stopall)
        self.binary_check = mock.patch.object(v, 'verify_executable', return_value=None).start()
        self.temp = tempfile.TemporaryDirectory(prefix='own-holder-discovery-inert-')
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name).resolve() / 'repo'
        self.repo.mkdir()
        self.client = FakeClient(self.repo)
        self.meta = mock.Mock(return_value=True)

    def discovery(self, client=None, meta=None, deadline=None):
        return v.Discovery(self.repo, self.client if client is None else client,
                           time.monotonic() + 60 if deadline is None else deadline,
                           self.meta if meta is None else meta)

    def refuse(self, operation):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with self.assertRaises(v.Refused) as caught:
                operation()
        self.assertEqual((out.getvalue(), err.getvalue()), ('', ''))
        self.assertEqual(str(caught.exception), 'REFUSED')
        self.no_child.assert_not_called()
        return caught.exception

    def test_one_pass_eight_calls_closed_created_not_materialized_no_adoption(self):
        d = self.discovery()
        result = d.run()
        self.assertEqual(len(self.client.calls), 8)
        self.assertEqual(result['code'], 'DISCOVERED_NOT_ADOPTED')
        self.assertEqual(result['fullQualification'], 'NOT_CLAIMED')
        self.assertEqual(result['Env'], 'NOT_OBSERVED')
        self.assertEqual(result['privateDirectoryMetadata'], 'MATCH')
        self.assertEqual(set(result['roles']), set(v.ORIGINALS))
        self.assertTrue(all(r['state'] == 'EXITED' and r['imageMatch'] for r in result['roles'].values()))
        flags = result['candidates'][0]['groups']
        self.assertTrue(flags['identityImageCommand'] and flags['mountsHostDeclared'])
        self.assertTrue(flags['createdNotMaterialized'])
        self.assertFalse(flags['mountsMaterialized'] or flags['networkNoneMaterialized'])
        self.meta.assert_called_once()
        self.assertEqual(self.meta.call_args.args[:2], (self.repo, LABEL_VALUE))
        raw = v.receipt(result)
        self.assertLessEqual(len(raw), 4096)
        for private in (CANARY, LABEL_VALUE, '/app/', 'sha256:', 'dip-key-snapshot-', '240000'):
            self.assertNotIn(private.encode(), raw)
        self.assertIn(CID.encode(), raw)
        self.refuse(d.run)
        self.assertEqual(len(self.client.calls), 8)

    def test_bad_listing_third_duplicate_baseline_and_malformed_no_followup(self):
        need_ids = [pair[0] for pair in v.ORIGINALS.values()]
        self.assertEqual(len(v.BASELINE), 17)
        self.assertTrue(all(v.HEX.fullmatch(item) for item in v.BASELINE))
        self.assertTrue(set(need_ids) <= v.BASELINE)
        for raw in (b'\n', CID.encode(), (CID + '\r\n').encode(), (CID + '\v\n').encode(),
                    b'0\n', b'F' * 64 + b'\n', b'\xff\n', b'x' * 4097,
                    ((CID + '\n') * 2).encode(),
                    ('\n'.join((CID, '3' * 64, '4' * 64)) + '\n').encode(),
                    (sorted(v.BASELINE)[0] + '\n').encode()):
            with self.subTest(raw_kind=len(raw)):
                client = FakeClient(self.repo)
                client.listing = raw
                self.refuse(self.discovery(client).run)
                self.assertEqual(len(client.calls), 1)
        self.meta.assert_not_called()

    def test_zero_or_two_candidates_and_only_one_metadata_directory(self):
        empty = FakeClient(self.repo, [])
        result = self.discovery(empty).run()
        self.assertEqual((len(empty.calls), result['candidates']), (7, []))
        self.assertEqual(result['privateDirectoryMetadata'], 'NOT_OBSERVED')
        self.meta.assert_not_called()
        second = candidate(self.repo, '3' * 64)
        two = FakeClient(self.repo, [second, candidate(self.repo)])
        result = self.discovery(two).run()
        self.assertEqual(len(two.calls), 8)
        self.assertEqual(len(result['candidates']), 2)
        self.meta.assert_called_once()
        self.assertLessEqual(len(v.receipt(result)), 4096)
        self.meta.reset_mock()
        second['labels'][v.LABEL] = 'key-preservation-zzzz1234'
        result = self.discovery(FakeClient(self.repo, [second, candidate(self.repo)])).run()
        self.assertEqual(result['privateDirectoryMetadata'], 'AMBIGUOUS_NOT_OBSERVED')
        self.meta.assert_not_called()

    def test_group_failures_are_observations_not_qualification(self):
        for change, expected in (
                (lambda r: r.update(cmd=['-e', CANARY]), 'identityImageCommand'),
                (lambda r: r['labels'].update(forged=CANARY), 'labelBaseline'),
                (lambda r: r['host'].update(CapAdd=['SYS_ADMIN']), 'securityHealth'),
                (lambda r: r.update(health={'Test': ['CMD', CANARY]}), 'securityHealth'),
                (lambda r: r['host'].update(PidsLimit=True), 'resources'),
                (lambda r: r['declared'][2].update(ReadOnly=1), 'mountsHostDeclared'),
                (lambda r: r['declared'][2].update(BindOptions={'CreateMountpoint': True}), 'mountsHostDeclared')):
            r = candidate(self.repo)
            change(r)
            result = self.discovery(FakeClient(self.repo, [r])).run()
            self.assertFalse(result['candidates'][0]['groups'][expected])
            self.assertEqual(result['code'], 'DISCOVERED_NOT_ADOPTED')
            self.assertNotIn(CANARY.encode(), v.receipt(result))

    def test_exact_actual_mounts_no_alias_and_missing_baseline_not_invented(self):
        r = candidate(self.repo)
        r.update(status='running', running=True, networkCount=1, networkNone=True)
        r['mounts'] = [{'Type': 'volume', 'Name': name, 'Source': sources()[key],
                        'Destination': '/source/' + key, 'RW': True} for key, name in v.VOLUMES.items()]
        r['mounts'].append({'Type': 'bind', 'Source': str(self.repo / v.SCRIPT),
                            'Destination': v.TARGET, 'RW': False})
        result = self.discovery(FakeClient(self.repo, [r])).run()
        self.assertTrue(result['candidates'][0]['groups']['mountsMaterialized'])
        self.assertTrue(result['candidates'][0]['groups']['networkNoneMaterialized'])
        r['mounts'][-1]['Source'] = '/host_mnt' + str(self.repo / v.SCRIPT)
        result = self.discovery(FakeClient(self.repo, [r])).run()
        self.assertFalse(result['candidates'][0]['groups']['mountsMaterialized'])
        client = FakeClient(self.repo, [candidate(self.repo)])
        client.originals['api']['mounts'] = []
        result = self.discovery(client).run()
        self.assertFalse(result['volumeBaselineObserved'])

    def test_formats_fixed_endpoint_environment_no_private_fields_or_mutation(self):
        all_formats = v.OLD_FORMAT + v.API_FORMAT + v.IMAGE_FORMAT + v.CANDIDATE_FORMAT
        for forbidden in ('.Config.Env', '.State.Error', '{{json .Config}}', '{{json .State}}'):
            self.assertNotIn(forbidden, all_formats)
        client = v.Client(self.repo, time.monotonic() + 60)
        self.assertEqual(client.env['DOCKER_HOST'], v.SOCKET)
        self.assertEqual(client.env['DOCKER_CONTEXT'], '')
        self.assertEqual(client.env['DOCKER_CONFIG'], str(self.repo / 'server/deploy/trust'))
        self.assertEqual(set(client.env), {'PATH', 'HOME', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG'})
        self.discovery().run()
        for args, _ in self.client.calls:
            self.assertIn(args[:2], (('container', 'ls'), ('image', 'inspect'), ('container', 'inspect')))
            for forbidden in ('exec', 'logs', 'stats', 'cp', 'create', 'start', 'stop', 'pause', 'rm', 'prune'):
                self.assertNotIn(forbidden, args)
        self.assertEqual(self.client.calls[0], (v.LIST_ARGS, 4096))

    def test_transport_fixed_socket_no_shell_stderr_cap_and_client_failure(self):
        def pipe(raw):
            read, write = os.pipe()
            os.write(write, raw)
            os.close(write)
            return os.fdopen(read, 'rb', buffering=0)
        for stdout, stderr, cap, status, category in (
                (b'public\n', b'', 64, 0, None),
                (b'', b'PRIVATE_CANARY', 4, 0, 'OUTPUT_CAP'),
                (b'public\n', b'PRIVATE_CANARY', 64, 1, 'CLIENT_NONZERO')):
            proc = mock.Mock(pid=12345, stdout=pipe(stdout), stderr=pipe(stderr))
            proc.wait.return_value = status
            self.no_child.side_effect = None
            self.no_child.return_value = proc
            client = v.Client(self.repo, time.monotonic() + 60)
            with mock.patch.object(v.os, 'killpg') as kill:
                if category is None:
                    self.assertEqual(client(v.LIST_ARGS, cap), stdout)
                    kill.assert_not_called()
                else:
                    with self.assertRaises(v.Refused) as failure:
                        client(v.LIST_ARGS, cap)
                    self.assertEqual(failure.exception.category, category)
                    self.assertEqual(str(failure.exception), 'REFUSED')
                    kill.assert_called_once_with(proc.pid, v.signal.SIGKILL)
            args, kwargs = self.no_child.call_args
            self.assertEqual(args[0], (str(v.DOCKER_PATH), '--host', v.SOCKET, *v.LIST_ARGS))
            self.assertNotIn('shell', kwargs)
            self.assertEqual(kwargs['env'], client.env)
            self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
            self.assertTrue(proc.stdout.closed and proc.stderr.closed)
            self.no_child.reset_mock()
        client.calls = 8
        with self.assertRaises(v.Refused):
            client(v.LIST_ARGS)
        self.no_child.assert_not_called()

    def test_public_executable_pin_nofollow_stable_hash_and_metadata_only(self):
        path = self.repo / 'public-synthetic-cli-not-executed'
        raw = b'SYNTHETIC_PUBLIC_BINARY_NOT_EXECUTABLE_CODE'
        path.write_bytes(raw)
        path.chmod(0o555)
        with mock.patch.object(v, 'DOCKER_PATH', path), \
             mock.patch.object(v, 'DOCKER_SHA256', hashlib.sha256(raw).hexdigest()), \
             mock.patch.object(v, 'DOCKER_STAT', v.stamp(path.lstat())):
            self.assertIsNone(REAL_VERIFY_EXECUTABLE(time.monotonic() + 10))
            path.chmod(0o755)
            failure = self.refuse(lambda: REAL_VERIFY_EXECUTABLE(time.monotonic() + 10))
            self.assertEqual(failure.category, 'CLIENT_EXEC_IDENTITY')
            path.chmod(0o644)
            path.write_bytes(b'CHANGED_PUBLIC_CONTENT')
            path.chmod(0o555)
            with mock.patch.object(v, 'DOCKER_STAT', v.stamp(path.lstat())):
                failure = self.refuse(lambda: REAL_VERIFY_EXECUTABLE(time.monotonic() + 10))
                self.assertEqual(failure.category, 'CLIENT_EXEC_IDENTITY')
            path.unlink()
            path.symlink_to(self.repo)
            failure = self.refuse(lambda: REAL_VERIFY_EXECUTABLE(time.monotonic() + 10))
            self.assertEqual(failure.category, 'CLIENT_EXEC_IDENTITY')
            path.unlink()
            failure = self.refuse(lambda: REAL_VERIFY_EXECUTABLE(time.monotonic() + 10))
            self.assertEqual(failure.category, 'CLIENT_EXEC_NOT_FOUND')
        self.no_child.assert_not_called()

    def test_popen_os_failures_finite_closed_categories_no_path_or_error_text(self):
        for error, category in ((FileNotFoundError(CANARY), 'CLIENT_EXEC_NOT_FOUND'),
                                (PermissionError(CANARY), 'CLIENT_EXEC_DENIED'),
                                (OSError(CANARY), 'CLIENT_EXEC_OS_REFUSED'),
                                (BlockingIOError(CANARY), 'CLIENT_EXEC_OS_REFUSED')):
            self.no_child.side_effect = error
            client = v.Client(self.repo, time.monotonic() + 60)
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                 mock.patch.object(v.os, 'killpg') as kill:
                with self.assertRaises(v.Refused) as caught:
                    client(v.LIST_ARGS)
            self.assertEqual(caught.exception.category, category)
            self.assertEqual(str(caught.exception), 'REFUSED')
            self.assertEqual((out.getvalue(), err.getvalue()), ('', ''))
            kill.assert_not_called()
            self.assertEqual(client.calls, 1)
        self.assertEqual(self.binary_check.call_count, 4)

    def test_executable_refusal_before_child_no_search_or_fallback(self):
        self.binary_check.side_effect = v.Refused('CLIENT_EXEC_IDENTITY')
        client = v.Client(self.repo, time.monotonic() + 60)
        failure = self.refuse(lambda: client(v.LIST_ARGS))
        self.assertEqual(failure.category, 'CLIENT_EXEC_IDENTITY')
        self.binary_check.assert_called_once_with(client.deadline)
        self.no_child.assert_not_called()

    def test_client_cleanup_errors_preserve_first_output_cap_failure(self):
        class Closing:
            def __init__(self, raw):
                read, write = os.pipe()
                os.write(write, raw); os.close(write)
                self.file = os.fdopen(read, 'rb', buffering=0)
            def fileno(self):
                return self.file.fileno()
            def close(self):
                self.file.close()
                raise OSError(CANARY)
        stdout, stderr = Closing(b'PUBLIC_TOO_LONG'), Closing(b'')
        proc = mock.Mock(pid=12345, stdout=stdout, stderr=stderr)
        proc.wait.side_effect = OSError(CANARY)
        self.no_child.side_effect = None
        self.no_child.return_value = proc
        with mock.patch.object(v.os, 'killpg', side_effect=PermissionError(CANARY)):
            with self.assertRaises(v.Refused) as caught:
                v.Client(self.repo, time.monotonic() + 60)(v.LIST_ARGS, cap=4)
        self.assertEqual(caught.exception.category, 'OUTPUT_CAP')
        self.assertEqual(str(caught.exception), 'REFUSED')
        self.assertTrue(stdout.file.closed and stderr.file.closed)
        # A close-only failure is still a refusal, not silently accepted.
        stdout, stderr = Closing(b'PUBLIC'), Closing(b'')
        proc = mock.Mock(pid=12345, stdout=stdout, stderr=stderr)
        proc.wait.return_value = 0
        self.no_child.return_value = proc
        with mock.patch.object(v.os, 'killpg') as kill:
            with self.assertRaises(v.Refused) as caught:
                v.Client(self.repo, time.monotonic() + 60)(v.LIST_ARGS, cap=64)
        self.assertEqual(caught.exception.category, 'UNEXPECTED')
        kill.assert_not_called()
        self.assertTrue(stdout.file.closed and stderr.file.closed)

    def test_selector_deadline_crossing_rejects_without_negative_timeout(self):
        proc = mock.Mock(pid=12345, stdout=io.BytesIO(), stderr=io.BytesIO())
        self.no_child.side_effect = None
        self.no_child.return_value = proc
        deadline = time.monotonic() + 100
        times = iter((0, 11))
        with mock.patch.object(v.time, 'monotonic', side_effect=lambda: next(times, 11)), \
             mock.patch.object(v.selectors, 'DefaultSelector') as factory, \
             mock.patch.object(v.os, 'killpg'):
            selector = factory.return_value.__enter__.return_value
            selector.get_map.return_value = True
            with self.assertRaises(v.Refused) as caught:
                v.Client(self.repo, deadline)(v.LIST_ARGS)
            self.assertEqual(caught.exception.category, 'CLIENT_TIMEOUT')
            selector.select.assert_not_called()
        self.assertTrue(proc.stdout.closed and proc.stderr.closed)

    def test_metadata_only_new_disposable_root_and_child_no_contents_or_enumeration(self):
        root = self.repo / '.local-auth'
        root.mkdir(mode=0o700)
        child = root / LABEL_VALUE
        child.mkdir(mode=0o700)
        (child / 'DO_NOT_READ').write_bytes(CANARY.encode())
        with mock.patch.object(v.os, 'read', side_effect=AssertionError('NO_CONTENTS')), \
             mock.patch.object(v.os, 'listdir', side_effect=AssertionError('NO_LISTDIR')), \
             mock.patch.object(v.os, 'scandir', side_effect=AssertionError('NO_SCANDIR')):
            self.assertTrue(v.directory_metadata(self.repo, LABEL_VALUE, time.monotonic() + 10))
        child.chmod(0o755)
        self.refuse(lambda: v.directory_metadata(self.repo, LABEL_VALUE, time.monotonic() + 10))
        child.chmod(0o700)
        shutil.rmtree(child)
        child.symlink_to(self.repo, target_is_directory=True)
        self.refuse(lambda: v.directory_metadata(self.repo, LABEL_VALUE, time.monotonic() + 10))
        self.refuse(lambda: v.directory_metadata(self.repo, '../DO_NOT_READ', time.monotonic() + 10))

    def test_metadata_failure_and_global_timeout_closed_no_followup_or_retry(self):
        result = self.discovery(meta=mock.Mock(side_effect=OSError(CANARY))).run()
        self.assertEqual(result['privateDirectoryMetadata'], 'REFUSED')
        self.assertNotIn(CANARY.encode(), v.receipt(result))
        client = FakeClient(self.repo)
        failure = self.refuse(self.discovery(client, deadline=time.monotonic() - 1).run)
        self.assertEqual(failure.category, 'CLIENT_TIMEOUT')
        self.assertEqual(client.calls, [])
        self.refuse(lambda: v.directory_metadata(self.repo, LABEL_VALUE, 0, clock=lambda: 1))

    def test_pins_source_only_before_clients_no_controller_import(self):
        directory = self.repo / 'server/deploy/trust'
        directory.mkdir(parents=True)
        for relative in (v.SELF, v.TEST):
            shutil.copyfile(HERE.parent / Path(relative).name, self.repo / relative)
        fake_controller = self.repo / v.CONTROLLER
        fake_controller.write_bytes(b'raise AssertionError("MUST_NOT_EXECUTE_PUBLIC_SOURCE")\n')
        pins = [hashlib.sha256((self.repo / name).read_bytes()).hexdigest() for name in (v.SELF, v.TEST)]
        args = ['--discover-once', '--source-sha256', pins[0], '--test-sha256', pins[1]]
        with mock.patch.object(v, '__file__', str(self.repo / v.SELF)), \
             mock.patch.object(v, 'CONTROLLER_SHA256', hashlib.sha256(fake_controller.read_bytes()).hexdigest()):
            self.assertIsNone(v.source_gate(self.repo, args, time.monotonic() + 10))
            (directory / 'config.json').write_bytes(CANARY.encode())
            self.refuse(lambda: v.source_gate(self.repo, args, time.monotonic() + 10))
            (directory / 'config.json').unlink()
            fake_controller.write_bytes(b'PUBLIC_DRIFT')
            self.refuse(lambda: v.source_gate(self.repo, args, time.monotonic() + 10))
        self.assertEqual(self.client.calls, [])

    def test_main_invalid_arguments_closed_and_no_traceback_or_children(self):
        output = io.BytesIO()
        class Output:
            buffer = output
        with mock.patch.object(v.sys, 'stdout', Output()), \
             mock.patch.object(v, 'source_gate', side_effect=AssertionError(CANARY)):
            self.assertEqual(v.main(['--unknown', CANARY]), 1)
        result = json.loads(output.getvalue())
        self.assertEqual((result['code'], result['checkpoint']), ('REFUSED', 'ARGUMENTS'))
        self.assertNotIn(CANARY.encode(), output.getvalue())
        self.no_child.assert_not_called()


if __name__ == '__main__':
    unittest.main()
