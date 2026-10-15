#!/usr/bin/env python3
"""INERT only: fabricated metadata and disposable custody records; NEVER Docker.

No frozen tests, controller, application or helper execution. The two captured
public definition modules are hash-verified before loading; Client is always fake.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location('retirement_subject', HERE / 'retire_failed_holder.py')
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


def public_module(relative):
    raw = (d.REPO / relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != d.PINS[relative]:
        raise AssertionError('Frozen public definition pin mismatch')
    module = types.ModuleType('_inert_' + Path(relative).stem)
    module.__file__ = str(d.REPO / relative)
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


p, t = public_module(d.PROFILE), public_module(d.TRANSPORT)
CANARY = 'SYNTHETIC_PRIVATE_CANARY_NO_EXPORT'
LABEL = 'key-preservation-abcdefgh'
ARGV = ['--retire-exact-paused-holder', d.CONSENT,
        '--source-sha256', 'a' * 64, '--test-sha256', 'b' * 64]


def fixtures():
    image = {'Id': d.IMAGE, 'Config': {'Env': ['FIXTURE=' + CANARY],
        'Labels': {'com.docker.compose.project': 'public-image'}, 'WorkingDir': '/app/server/api'}}
    baseline = {name: '/synthetic/' + key.lower() for key, name in p.VOLUMES.items()}
    source = '/host_mnt' + p.HELPER_SOURCE
    declared = [{'Type': 'volume', 'Source': name, 'Target': '/source/' + key.lower()}
                for key, name in p.VOLUMES.items()]
    declared.append({'Type': 'bind', 'Source': source, 'Target': p.HELPER, 'ReadOnly': True,
                     'BindOptions': {'Propagation': 'rprivate', 'CreateMountpoint': False}})
    mounts = [{'Type': 'volume', 'Name': name, 'Source': baseline[name],
        'Destination': '/source/' + key.lower(), 'RW': True} for key, name in p.VOLUMES.items()]
    mounts.append({'Type': 'bind', 'Source': source, 'Destination': p.HELPER, 'RW': False})
    mounts += [{'Type': 'tmpfs', 'Destination': target, 'RW': True} for target in p.TMPFS]
    record = {'Id': d.TARGET, 'Name': '/dip-key-snapshot-' + 'c' * 32, 'Image': d.IMAGE,
        'Path': 'node', 'Args': ['-e', p.CODE], 'Mounts': mounts, 'NetworkNone': True,
        'Config': {'Image': d.IMAGE, 'Labels': dict(image['Config']['Labels'], **{p.LABEL: LABEL}),
            'User': '65532:65532', 'Env': copy.deepcopy(image['Config']['Env']),
            'WorkingDir': '/app/server/api', 'Entrypoint': ['node'], 'Cmd': ['-e', p.CODE],
            'Healthcheck': {'Test': ['NONE']}, 'Volumes': None, 'StopTimeout': 5},
        'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'CapDrop': ['ALL'],
            'CapAdd': None, 'Privileged': False, 'SecurityOpt': ['no-new-privileges:true'],
            'Devices': [], 'DeviceRequests': None, 'Binds': None, 'PortBindings': {},
            'CgroupnsMode': 'private', 'Memory': 2 * 1024**3, 'MemorySwap': 2 * 1024**3,
            'NanoCpus': 10**9, 'PidsLimit': 64, 'Tmpfs': copy.deepcopy(p.TMPFS),
            'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0}, 'Mounts': declared},
        'State': {'Status': 'paused', 'Running': True, 'Paused': True, 'Restarting': False,
                  'OOMKilled': False, 'Dead': False, 'ExitCode': 0}}
    volumes = [{'Name': name, 'Mountpoint': point, 'Driver': 'local', 'Scope': 'local',
        'Options': {}, 'Labels': {'com.docker.compose.project': 'dip-auth-stand'}}
        for name, point in baseline.items()]
    return record, image, baseline, volumes


def journals(record):
    common = {'version': 1, 'name': record['Name'][1:], 'image': d.IMAGE, 'backup': LABEL}
    return (dict(common, source=d.HELPER, sourceSha256=d.HELPER_SHA256, preservationMigration=True),
            dict(common, id=d.TARGET))


class InertTests(unittest.TestCase):
    def setUp(self):
        self.docker = patch.object(t.subprocess, 'Popen', side_effect=AssertionError('NO runtime'))
        self.docker.start()
        self.addCleanup(self.docker.stop)

    def assert_private(self, result):
        raw = json.dumps(result, sort_keys=True)
        self.assertLessEqual(len(raw.encode()), 4096)
        for value in (CANARY, LABEL, d.TARGET, d.IMAGE, p.HELPER_SOURCE, str(d.ROOT),
                      hashlib.sha256(CANARY.encode()).hexdigest()):
            self.assertNotIn(value, raw)
        self.assertFalse(result['preservationVerified'])
        self.assertTrue(result['manualReconciliationRequired'])


class PolicyTests(InertTests):
    def test_consent_precedes_all_reads_and_clients(self):
        for argv in ([], ARGV[:1] + ARGV[2:], ARGV + ['--target', d.TARGET],
                     ['--retire-exact-paused-holder', '--consent', *ARGV[2:]]):
            with self.subTest(argv=argv), patch.object(d, 'load_sources') as sources, \
                    patch.object(d, 'ExactClient') as client, patch.object(d, 'read_sealed') as read:
                result, status = d.run(argv)
                self.assertEqual((status, result['checkpoint']), (1, 'ARGUMENTS_CONSENT'))
                self.assertFalse(result['removalAttempted'])
                sources.assert_not_called(); client.assert_not_called(); read.assert_not_called()
                self.assert_private(result)
        d.parse_arguments(ARGV)

    def test_source_pin_refusal_before_import_or_client(self):
        with patch.object(d, 'read_sealed', return_value=(b'WRONG', None)), \
                patch.object(d.types, 'ModuleType') as module, patch.object(d, 'ExactClient') as client:
            result, status = d.run(ARGV)
            self.assertEqual((status, result['checkpoint']), (1, 'PUBLIC_SOURCES'))
            self.assertEqual(result['category'], 'PREDICATE_REFUSED')
            module.assert_not_called(); client.assert_not_called()

    def test_frozen_source_pins_are_not_recomputed_or_executed(self):
        for relative, expected in d.PINS.items():
            self.assertEqual(hashlib.sha256((d.REPO / relative).read_bytes()).hexdigest(), expected)
        self.assertNotIn('recreate_openrouter_key', p.__name__)

    def test_real_public_source_gate_loads_definitions_only(self):
        argv = ARGV.copy()
        argv[3] = hashlib.sha256((d.REPO / d.SELF).read_bytes()).hexdigest()
        argv[5] = hashlib.sha256((d.REPO / d.TEST).read_bytes()).hexdigest()
        profile, transport, pins = d.load_sources(d.REPO, argv, time.monotonic() + 10)
        self.assertEqual(set(pins), set(d.PINS) | {d.SELF, d.TEST})
        self.assertEqual(profile.GROUPS, p.GROUPS)
        self.assertEqual(transport.SOCKET, t.SOCKET)
        self.assertFalse(hasattr(profile, 'Controller'))

    def test_paused_profile_and_all_independent_predicate_drifts(self):
        record, image, baseline, _ = fixtures()
        self.assertEqual(d.qualify(p, record, image, baseline), LABEL)
        changes = [lambda r: r.update(Id='a' * 64), lambda r: r.update(NetworkNone=False),
            lambda r: r['Config'].update(User='0'), lambda r: r['Config'].update(Env=['OTHER=1']),
            lambda r: r['Config'].update(Healthcheck={'Test': ['CMD', 'true']}),
            lambda r: r['Config']['Labels'].update(extra='unexpected'),
            lambda r: r['Config'].update(Cmd=['-e', 'other']),
            lambda r: r['HostConfig'].update(ReadonlyRootfs=False),
            lambda r: r['HostConfig'].update(Memory=True),
            lambda r: r['HostConfig'].update(SecurityOpt=[]),
            lambda r: r['HostConfig'].update(CapAdd=['SYS_ADMIN']),
            lambda r: r['HostConfig'].update(NetworkMode='host'),
            lambda r: r['HostConfig'].update(Binds=['extra']),
            lambda r: r['HostConfig'].update(Tmpfs={}),
            lambda r: r['HostConfig']['Mounts'][0].update(Source='wrong'),
            lambda r: r['HostConfig']['Mounts'][2]['BindOptions'].update(CreateMountpoint=True),
            lambda r: r['Mounts'][0].update(RW=False),
            lambda r: r['Mounts'][2].update(Source=p.HELPER_SOURCE),
            lambda r: r['Mounts'].append(copy.deepcopy(r['Mounts'][0]))]
        changes += [lambda r, key=key, value=value: r['State'].update({key: value})
                    for key, value in (('Status', 'running'), ('Paused', False), ('Running', False),
                        ('Restarting', True), ('OOMKilled', True), ('Dead', True), ('ExitCode', True))]
        for change in changes:
            candidate = copy.deepcopy(record)
            change(candidate)
            with self.subTest(change=changes.index(change)), self.assertRaises(d.Refused):
                d.qualify(p, candidate, image, baseline)
        with self.assertRaises(d.Refused):
            d.qualify(p, record, image, None)

    def test_env_no_preloads_duplicates_or_ambiguity_even_if_image_agrees(self):
        cases = (['NODE_OPTIONS='], ['NODE_PATH=/synthetic'], ['A=1', 'A=1'],
                 ['bad-name=x'], ['A=x\0'], [None], 'A=x')
        for env in cases:
            record, image, baseline, _ = fixtures()
            record['Config']['Env'] = image['Config']['Env'] = env
            with self.subTest(env=env), self.assertRaises(d.Refused):
                d.qualify(p, record, image, baseline)
        record, image, baseline, _ = fixtures()
        image['Config']['Env'], record['Config']['Env'] = None, []
        with self.assertRaises(d.Refused):
            d.qualify(p, record, image, baseline)

    def test_client_exact_argv_caps_no_retry_after_ambiguous_remove(self):
        inner = Mock(return_value=b'public')
        with patch.object(t, 'Client', return_value=inner):
            client = d.ExactClient(p, t, d.REPO, time.monotonic() + 60)
            forbidden = [('rm', '--force', '-v', d.TARGET), ('rm', '--force', 'a' * 64),
                         ('container', 'ls'), ('unpause', d.TARGET), ('start', d.TARGET),
                         ('exec', d.TARGET, 'true'), ('stop', d.TARGET)]
            for args in forbidden:
                with self.assertRaises(d.Refused):
                    client(args)
            inner.assert_not_called()
            for args in (client.image, client.volumes, client.target, client.target):
                client(args)
                self.assertEqual(inner.call_args.kwargs, {'cap': 65536})
            for args in (client.image, client.volumes, client.target):
                with self.assertRaises(d.Refused):
                    client(args)
            inner.side_effect = t.Refused('CLIENT_TIMEOUT')
            with self.assertRaises(t.Refused):
                client(client.remove)
            self.assertEqual(inner.call_args.kwargs, {'cap': 4096})
            self.assertTrue(client.removal_attempted)
            for args in (client.remove, client.target):
                with self.assertRaises(d.Refused):
                    client(args)
            self.assertEqual(inner.call_count, 5)


class JournalTests(InertTests):
    def setUp(self):
        super().setUp()
        # New synthetic fixtures ONLY; never system /tmp, private state or retained files.
        self.temp = tempfile.TemporaryDirectory(prefix='retirement-inert-', dir=HERE)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'synthetic-root'
        self.root.mkdir(mode=0o755)
        self.folder = self.root / LABEL
        self.folder.mkdir(mode=0o700)
        self.record = fixtures()[0]
        self.intent, self.bound = journals(self.record)
        self.paths = [self.folder / 'holder-intent.json', self.folder / 'holder-id.json']
        self.write_records()

    def write_records(self):
        for path, value in zip(self.paths, (self.intent, self.bound)):
            path.write_bytes(t.canonical(value))
            path.chmod(0o600)

    def custody(self, label=LABEL):
        return d.custody(p, t, label, self.record, time.monotonic() + 10, root=self.root)

    def test_complete_journals_read_stably_without_change(self):
        first = self.custody()
        self.assertEqual(first, self.custody())
        self.assertNotEqual(first[0][1][:2], first[1][1][:2])
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o755)
        self.assertEqual([path.read_bytes() for path in self.paths],
                         [t.canonical(self.intent), t.canonical(self.bound)])

    def test_schema_id_hash_profile_binding_and_duplicates(self):
        mutations = [('id', 'id', 'a' * 64), ('id', 'name', 'dip-key-snapshot-' + 'a' * 32),
            ('id', 'version', True), ('intent', 'backup', 'key-preservation-ijklmnop'),
            ('intent', 'image', 'sha256:' + '0' * 64), ('intent', 'source', 'wrong'),
            ('intent', 'sourceSha256', '0' * 64), ('intent', 'preservationMigration', 1),
            ('intent', 'extra', CANARY)]
        original = copy.deepcopy((self.intent, self.bound))
        for which, key, value in mutations:
            self.intent, self.bound = copy.deepcopy(original)
            (self.intent if which == 'intent' else self.bound)[key] = value
            self.write_records()
            with self.subTest(key=key), self.assertRaises(d.Refused):
                self.custody()
        self.intent, self.bound = copy.deepcopy(original)
        del self.intent['source']
        self.write_records()
        with self.assertRaises(d.Refused):
            self.custody()
        self.paths[0].write_bytes(b'{"version":1,"version":1}')
        with self.assertRaises(t.Refused):
            self.custody()

    def test_path_modes_symlink_hardlink_and_oversize_refuse(self):
        for label in ('../elsewhere', '/absolute', LABEL + '/nested', 'key-preservation-ABCDefgh'):
            with self.assertRaises(d.Refused):
                self.custody(label)
        self.folder.chmod(0o755)
        with self.assertRaises(d.Refused):
            self.custody()
        self.folder.chmod(0o700)
        self.paths[0].chmod(0o644)
        with self.assertRaises(d.Refused):
            self.custody()
        self.paths[0].chmod(0o600)
        alias = self.folder / 'synthetic-alias'
        os.link(self.paths[0], alias)
        with self.assertRaises(d.Refused):
            self.custody()
        alias.unlink()
        self.paths[0].unlink()
        self.paths[0].symlink_to(self.paths[1].name)
        with self.assertRaises(d.Refused):
            self.custody()
        self.paths[0].unlink()
        self.paths[0].write_bytes(b'x' * 4097)
        self.paths[0].chmod(0o600)
        with self.assertRaises(d.Refused):
            self.custody()

    def test_sibling_creation_and_record_replacement_change_full_seal(self):
        before = self.custody()
        (self.root / 'synthetic-sibling').mkdir(mode=0o700)
        self.assertNotEqual(before, self.custody())
        before = self.custody()
        raw = self.paths[0].read_bytes()
        self.paths[0].unlink()
        self.paths[0].write_bytes(raw)
        self.paths[0].chmod(0o600)
        self.assertNotEqual(before, self.custody())

    def test_owner_and_live_read_mutation_refused(self):
        with patch.object(d.os, 'geteuid', return_value=os.geteuid() + 1), self.assertRaises(d.Refused):
            self.custody()
        real_read, changed = os.read, False
        def mutate(fd, cap):
            nonlocal changed
            block = real_read(fd, cap)
            if not changed:
                changed = True
                self.paths[0].write_bytes(t.canonical(dict(self.intent, version=2)))
            return block
        with patch.object(d.os, 'read', side_effect=mutate), self.assertRaises(d.Refused):
            self.custody()


class TargetMetadataTests(InertTests):
    def test_only_actual_outer_order_and_object_key_order_are_ignored(self):
        original = fixtures()[0]
        original['Mounts'][0]['SyntheticUnknown'] = {'nested': [None, False, 0, 'literal']}
        before = copy.deepcopy(original)
        permuted = copy.deepcopy(original)
        permuted['Mounts'] = [dict(reversed(tuple(item.items())))
                              for item in reversed(permuted['Mounts'])]
        self.assertEqual(d.target_metadata_signature(t, original),
                         d.target_metadata_signature(t, permuted))
        self.assertEqual(original, before)

    def test_complete_records_multiplicity_types_paths_and_nested_order_preserved(self):
        original = fixtures()[0]
        original['Mounts'][0]['SyntheticUnknown'] = {'nested': [False, 0, None]}
        changes = (
            lambda r: r['Mounts'].append(copy.deepcopy(r['Mounts'][0])),
            lambda r: r['Mounts'].pop(),
            lambda r: r['Mounts'][0].update(Extra=None),
            lambda r: r['Mounts'][0].pop('SyntheticUnknown'),
            lambda r: r['Mounts'][0]['SyntheticUnknown']['nested'].reverse(),
            lambda r: r['Mounts'][0].update(RW=1),
            lambda r: r['Mounts'][0].update(Source=r['Mounts'][0]['Source'] + '/.'),
            lambda r: r['Mounts'][0].update(SyntheticUnknown=None),
            lambda r: r['HostConfig']['Mounts'].reverse(),
            lambda r: r['HostConfig']['RestartPolicy'].update(MaximumRetryCount=False))
        for index, change in enumerate(changes):
            modified = copy.deepcopy(original)
            change(modified)
            with self.subTest(change=index):
                self.assertNotEqual(d.target_metadata_signature(t, original),
                                    d.target_metadata_signature(t, modified))
        duplicate = copy.deepcopy(original)
        duplicate['Mounts'].append(copy.deepcopy(duplicate['Mounts'][0]))
        permuted = copy.deepcopy(duplicate)
        permuted['Mounts'].reverse()
        self.assertEqual(d.target_metadata_signature(t, duplicate),
                         d.target_metadata_signature(t, permuted))

    def test_malformed_or_unbounded_actual_mount_list_refuses(self):
        for mounts in (None, {}, [None], [dict()] * 9):
            record = fixtures()[0]
            record['Mounts'] = mounts
            with self.subTest(mounts=mounts), self.assertRaises(d.Refused):
                d.target_metadata_signature(t, record)
        record.pop('Mounts')
        with self.assertRaises(d.Refused):
            d.target_metadata_signature(t, record)


class RunTests(InertTests):
    def execute(self, *, final_change=None, journal_change=False, remove_error=None, ack=None,
                source_pin_bad=False, initial_change=None):
        record, image, _, volumes = fixtures()
        if initial_change:
            initial_change(record)
        calls = []
        target_calls = 0
        def fake_client(args, cap=65536):
            nonlocal target_calls
            calls.append(args)
            if args[:2] == ('image', 'inspect'):
                return t.canonical(image)
            if args[:2] == ('volume', 'inspect'):
                return b'\n'.join(t.canonical(v) for v in volumes)
            if args[:2] == ('container', 'inspect'):
                target_calls += 1
                current = copy.deepcopy(record)
                if target_calls == 2 and final_change:
                    final_change(current)
                return t.canonical(current)
            self.assertEqual(args, ('rm', '--force', d.TARGET))
            if remove_error:
                raise remove_error
            return d.TARGET.encode() + b'\n' if ack is None else ack
        seals = [(('synthetic-seal',),), (('different-seal' if journal_change else 'synthetic-seal',),)]
        pins = {d.SELF: hashlib.sha256(b'expected-public').hexdigest()} if source_pin_bad else {}
        with patch.object(d, 'load_sources', return_value=(p, t, pins)), \
                patch.object(d, 'read_sealed', return_value=(b'changed-public', None)), \
                patch.object(t, 'Client', return_value=fake_client), \
                patch.object(d, 'custody', side_effect=seals) as custody:
            result, status = d.run(ARGV)
        self.assert_private(result)
        return result, status, calls, custody.call_count

    def test_success_five_clients_and_two_journal_seals_not_preservation_proof(self):
        result, status, calls, reads = self.execute()
        self.assertEqual((status, result['code'], reads), (0, 'REMOVAL_ACKNOWLEDGED', 2))
        self.assertEqual(len(calls), 5)
        self.assertEqual(calls[-1], ('rm', '--force', d.TARGET))
        self.assertFalse(result['uncertain'])
        self.assertTrue(result['removalAttempted'])
        self.assertFalse(result['namedVolumeRemovalRequested'])
        self.assertFalse(result['hostWritesRequested'])
        self.assertFalse(result['migrationApplied'])

    def test_second_inspect_actual_order_only_passes_full_run(self):
        result, status, calls, reads = self.execute(final_change=lambda r: r['Mounts'].reverse())
        self.assertEqual((status, result['code'], reads), (0, 'REMOVAL_ACKNOWLEDGED', 2))
        self.assertEqual(len(calls), 5)
        self.assertEqual(calls[-1], ('rm', '--force', d.TARGET))
        self.assertTrue(result['removalAttempted'])
        self.assertFalse(result['uncertain'])

    def test_second_inspect_changed_complete_record_or_duplicate_refuses(self):
        def initial(record):
            record['Mounts'][0]['SyntheticUnknown'] = {'nested': [False, 0, None]}
        changes = (
            lambda r: r['Mounts'][0]['SyntheticUnknown']['nested'].reverse(),
            lambda r: r['Mounts'][0].pop('SyntheticUnknown'),
            lambda r: r['Mounts'][0].update(Extra=None),
            lambda r: r['Mounts'].append(copy.deepcopy(r['Mounts'][0])),
            lambda r: r['Mounts'].pop())
        for index, change in enumerate(changes):
            def final(record, change=change):
                change(record)
                record['Mounts'].reverse()
            with self.subTest(change=index):
                result, status, calls, reads = self.execute(initial_change=initial, final_change=final)
                self.assertEqual((status, result['checkpoint'], reads), (1, 'TARGET_FINAL', 1))
                self.assertEqual(len(calls), 4)
                self.assertFalse(result['removalAttempted'])

    def test_second_inspect_declared_mount_order_still_refuses(self):
        def final(record):
            record['Mounts'].reverse()
            record['HostConfig']['Mounts'].reverse()
        result, status, calls, reads = self.execute(final_change=final)
        self.assertEqual((status, result['checkpoint'], reads), (1, 'TARGET_FINAL', 1))
        self.assertEqual(len(calls), 4)
        self.assertFalse(result['removalAttempted'])

    def test_final_target_and_journal_drift_refuse_without_remove(self):
        for change in (lambda r: r.update(Name='/dip-key-snapshot-' + 'd' * 32),
                       lambda r: r['State'].update(Paused=False),
                       lambda r: r['HostConfig']['RestartPolicy'].update(MaximumRetryCount=False)):
            result, status, calls, _ = self.execute(final_change=change)
            self.assertEqual((status, result['checkpoint']), (1, 'TARGET_FINAL'))
            self.assertEqual(len(calls), 4)
            self.assertFalse(result['removalAttempted'])
        result, status, calls, _ = self.execute(journal_change=True)
        self.assertEqual((status, result['checkpoint']), (1, 'JOURNALS_FINAL'))
        self.assertEqual(len(calls), 4)

    def test_source_final_pin_drift_refuses_before_final_inspect_or_remove(self):
        result, status, calls, reads = self.execute(source_pin_bad=True)
        self.assertEqual((status, result['checkpoint'], reads), (1, 'SOURCE_FINAL', 1))
        self.assertEqual(len(calls), 3)
        self.assertFalse(result['removalAttempted'])

    def test_remove_failures_are_uncertain_no_more_queries_or_retries(self):
        for error, ack, category in ((t.Refused('CLIENT_TIMEOUT'), None, 'CLIENT_TIMEOUT'),
                (t.Refused('CLIENT_NONZERO'), None, 'CLIENT_NONZERO'),
                (RuntimeError(CANARY), None, 'UNEXPECTED'),
                (None, b'wrong', 'PREDICATE_REFUSED')):
            result, status, calls, _ = self.execute(remove_error=error, ack=ack)
            self.assertEqual((status, result['checkpoint'], result['category']), (1, 'REMOVE', category))
            self.assertTrue(result['uncertain'])
            self.assertTrue(result['removalAttempted'])
            self.assertEqual(len(calls), 5)
            self.assertEqual(calls[-1], ('rm', '--force', d.TARGET))

    def test_output_guard_hides_exception_and_does_not_claim_certainty(self):
        writes = []
        sink = Mock()
        sink.fileno.return_value = 99
        context = Mock()
        context.__enter__ = Mock(return_value=sink)
        context.__exit__ = Mock(return_value=False)
        with patch.object(d.os, 'dup', return_value=90), patch.object(d.os, 'dup2'), \
                patch.object(d.os, 'close'), patch('builtins.open', return_value=context), \
                patch.object(d, 'run', side_effect=RuntimeError(CANARY)), \
                patch.object(d.os, 'write', side_effect=lambda fd, raw: writes.append(raw) or len(raw)):
            self.assertEqual(d.main(), 1)
        result = json.loads(b''.join(writes))
        self.assertEqual(result['category'], 'UNEXPECTED')
        self.assertTrue(result['uncertain'])
        self.assert_private(result)


if __name__ == '__main__':
    unittest.main()
