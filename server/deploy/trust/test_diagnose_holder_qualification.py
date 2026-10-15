#!/usr/bin/env python3
"""INERT synthetic metadata tests only. No Engine/private host/binary operation."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location('holder_qualification_test_subject', HERE / 'diagnose_holder_qualification.py')
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)
CANARY = 'SYNTHETIC_PRIVATE_ENV_CANARY_DO_NOT_EXPORT'
IDENTITY = 'a' * 64


def fixtures(identity=IDENTITY):
    image = {'Id': d.IMAGE, 'Config': {'Env': ['FIXTURE=' + CANARY],
              'Labels': {'com.docker.compose.project': 'public-inherited-image'}, 'WorkingDir': '/app/server/api'}}
    baseline = {d.VOLUMES['AUTH']: '/synthetic/auth', d.VOLUMES['DATA']: '/synthetic/data'}
    labels = dict(image['Config']['Labels'], **{d.LABEL: 'key-preservation-abcdefgh'})
    source = '/host_mnt' + d.HELPER_SOURCE
    declared = [{'Type': 'volume', 'Source': name, 'Target': '/source/' + key.lower()}
                for key, name in d.VOLUMES.items()]
    declared.append({'Type': 'bind', 'Source': source, 'Target': d.HELPER, 'ReadOnly': True,
                     'BindOptions': {'Propagation': 'rprivate', 'CreateMountpoint': False}})
    mounts = [{'Type': 'volume', 'Name': name, 'Source': baseline[name],
               'Destination': '/source/' + key.lower(), 'RW': True} for key, name in d.VOLUMES.items()]
    mounts.append({'Type': 'bind', 'Source': source, 'Destination': d.HELPER, 'RW': False})
    mounts += [{'Type': 'tmpfs', 'Destination': target, 'RW': True} for target in d.TMPFS]
    record = {'Id': identity, 'Name': '/dip-key-snapshot-' + 'b' * 32, 'Image': d.IMAGE,
        'Path': 'node', 'Args': ['-e', d.CODE], 'Mounts': mounts, 'NetworkNone': True,
        'Config': {'Image': d.IMAGE, 'Labels': labels, 'User': '65532:65532',
                   'Env': copy.deepcopy(image['Config']['Env']), 'WorkingDir': '/app/server/api',
                   'Entrypoint': ['node'], 'Cmd': ['-e', d.CODE], 'Healthcheck': {'Test': ['NONE']},
                   'Volumes': None, 'StopTimeout': 5},
        'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'CapDrop': ['ALL'], 'CapAdd': None,
            'Privileged': False, 'SecurityOpt': ['no-new-privileges:true'], 'Devices': [], 'DeviceRequests': None,
            'Binds': None, 'PortBindings': {}, 'CgroupnsMode': 'private', 'Memory': 2 * 1024**3,
            'MemorySwap': 2 * 1024**3, 'NanoCpus': 10**9, 'PidsLimit': 64, 'Tmpfs': copy.deepcopy(d.TMPFS),
            'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0}, 'Mounts': declared},
        'State': {'Status': 'created', 'Running': False, 'Paused': False, 'Restarting': False,
                  'OOMKilled': False, 'Dead': False, 'ExitCode': 0}}
    volumes = [{'Name': name, 'Mountpoint': path, 'Driver': 'local', 'Scope': 'local', 'Options': {},
                'Labels': {'com.docker.compose.project': 'dip-auth-stand'}} for name, path in baseline.items()]
    return record, image, baseline, volumes


class GroupTests(unittest.TestCase):
    def test_complete_healthy_observable_profile_and_env_private(self):
        record, image, baseline, _ = fixtures()
        result = d.compare_groups(record, image, baseline, IDENTITY)
        expected = dict.fromkeys(d.GROUPS, True)
        expected['RUN_TRUE'] = False
        self.assertEqual(result['groups'], expected)
        self.assertEqual(result['state'], 'CREATED')
        raw = json.dumps(result)
        for forbidden in (CANARY, 'FIXTURE=', hashlib.sha256(CANARY.encode()).hexdigest(), d.HELPER_SOURCE,
                          'key-preservation-abcdefgh', 'public-inherited-image'):
            self.assertNotIn(forbidden, raw)

    def test_network_projection_uses_keys_not_endpoint_truthiness(self):
        # Golden Go-template contract plus inert projection fixtures: range binds
        # the map key, never tests an endpoint value. No Go/Docker execution.
        expected_template = ('{{if eq (len .NetworkSettings.Networks) 1}}'
            '{{range $networkName, $endpoint := .NetworkSettings.Networks}}'
            '{{if eq $networkName "none"}}true{{else}}false{{end}}{{end}}'
            '{{else}}false{{end}}')
        self.assertEqual(d.NETWORK_NONE_TEMPLATE, expected_template)
        self.assertIn('"NetworkNone":' + expected_template, d.CANDIDATE_FORMAT)
        self.assertNotIn('(index .NetworkSettings.Networks "none")', d.CANDIDATE_FORMAT)
        cases = (({'none': {}}, True), ({'none': None}, True),
                 ({'none': {'EndpointID': 'synthetic'}}, True), ({}, False),
                 ({'bridge': {}}, False), ({'none': {}, 'bridge': {}}, False))
        for networks, expected in cases:
            with self.subTest(keys=tuple(networks)):
                # Exact cardinality/range/key-equality semantics of the template.
                projected = len(networks) == 1 and next(iter(networks)) == 'none'
                self.assertEqual(projected, set(networks) == {'none'})
                record, image, baseline, _ = fixtures()
                record['NetworkNone'] = projected
                self.assertIs(d.compare_groups(record, image, baseline, IDENTITY)['groups']['NET_NONE'], expected)

    def test_env_exact_order_null_and_value_mismatch_only_equality(self):
        for original, actual, expected in ((None, None, True), (None, [], False),
                (['A=1', 'B=2'], ['B=2', 'A=1'], False), (['A=1'], ['A=2'], False),
                (['A=\u03bb'], ['A=\u03bb'], True)):
            with self.subTest(expected=expected):
                record, image, baseline, _ = fixtures()
                image['Config']['Env'], record['Config']['Env'] = original, actual
                self.assertIs(d.compare_groups(record, image, baseline, IDENTITY)['groups']['ENV'], expected)
        record, image, baseline, _ = fixtures()
        record['Config']['Env'] = CANARY
        self.assertIsNone(d.compare_groups(record, image, baseline, IDENTITY)['groups']['ENV'])

    def test_independent_predicate_drift_no_early_exit(self):
        mutations = [
            ('UID', lambda r: r['Config'].update(User='0')),
            ('ENV', lambda r: r['Config'].update(Env=['DIFFERENT=' + CANARY])),
            ('CWD', lambda r: r['Config'].update(WorkingDir='/other')),
            ('ARGV', lambda r: r['Config'].update(Cmd=['wrong'])),
            ('HEALTH', lambda r: r['Config'].update(Healthcheck={'Test': ['CMD', 'true']})),
            ('VOLUMES', lambda r: r['Config'].update(Volumes={'/extra': {}})),
            ('NETMODE', lambda r: r['HostConfig'].update(NetworkMode='host')),
            ('ROOT_RO', lambda r: r['HostConfig'].update(ReadonlyRootfs=False)),
            ('CAPS', lambda r: r['HostConfig'].update(CapAdd=['SYS_ADMIN'])),
            ('PRIVILEGE', lambda r: r['HostConfig'].update(Privileged=True)),
            ('SECOPT', lambda r: r['HostConfig'].update(SecurityOpt=[])),
            ('NO_DEVICES', lambda r: r['HostConfig'].update(Devices=[{}])),
            ('NO_BINDS_PORTS', lambda r: r['HostConfig'].update(Binds=['extra'])),
            ('CGROUPNS', lambda r: r['HostConfig'].update(CgroupnsMode='host')),
            ('MEMORY', lambda r: r['HostConfig'].update(Memory=True)),
            ('SWAP', lambda r: r['HostConfig'].update(MemorySwap=0)),
            ('CPU', lambda r: r['HostConfig'].update(NanoCpus=0)),
            ('PIDS', lambda r: r['HostConfig'].update(PidsLimit=0)),
            ('TMPFS', lambda r: r['HostConfig'].update(Tmpfs={})),
            ('RESTART_STOP', lambda r: r['Config'].update(StopTimeout=6)),
            ('STATE_CLEAR', lambda r: r['State'].update(OOMKilled=True)),
            ('UNPAUSED', lambda r: r['State'].update(Paused=True)),
            ('NET_NONE', lambda r: r.update(NetworkNone=False)),
        ]
        for group, mutate in mutations:
            with self.subTest(group=group):
                record, image, baseline, _ = fixtures()
                mutate(record)
                flags = d.compare_groups(record, image, baseline, IDENTITY)['groups']
                self.assertFalse(flags[group])
                self.assertEqual(set(flags), set(d.GROUPS))

    def test_inherited_labels_exact_plus_own_not_private_binding(self):
        record, image, baseline, _ = fixtures()
        self.assertTrue(d.compare_groups(record, image, baseline, IDENTITY)['groups']['LABELS'])
        record['Config']['Labels']['extra'] = CANARY
        self.assertFalse(d.compare_groups(record, image, baseline, IDENTITY)['groups']['LABELS'])
        record['Config']['Labels'] = {d.LABEL: 'key-preservation-abcdefgh'}
        self.assertFalse(d.compare_groups(record, image, baseline, IDENTITY)['groups']['LABELS'])

    def test_declared_and_actual_mount_drift_and_bounded_alias(self):
        for change, group in ((lambda r: r['HostConfig']['Mounts'][0].update(ReadOnly=True), 'DECL_AUTH'),
                (lambda r: r['HostConfig']['Mounts'][1].update(Source='wrong'), 'DECL_DATA'),
                (lambda r: r['HostConfig']['Mounts'][2]['BindOptions'].update(CreateMountpoint=True), 'BIND_OPTIONS'),
                (lambda r: r['Mounts'][0].update(Source='/wrong'), 'ACTUAL_AUTH'),
                (lambda r: r['Mounts'][1].update(RW=False), 'ACTUAL_DATA'),
                (lambda r: r['Mounts'][2].update(Source=d.HELPER_SOURCE), 'ACTUAL_BIND'),
                (lambda r: r['Mounts'].append({'Type': 'tmpfs', 'Destination': '/extra', 'RW': True}), 'ACTUAL_TMPFS')):
            with self.subTest(group=group):
                record, image, baseline, _ = fixtures()
                change(record)
                self.assertFalse(d.compare_groups(record, image, baseline, IDENTITY)['groups'][group])
        record, image, baseline, _ = fixtures()
        record['HostConfig']['Mounts'][2]['Source'] = record['Mounts'][2]['Source'] = d.HELPER_SOURCE
        self.assertTrue(d.compare_groups(record, image, baseline, IDENTITY)['groups']['ACTUAL_BIND'])
        record['HostConfig']['Mounts'][2]['Source'] = '/host_mnt/host_mnt' + d.HELPER_SOURCE
        self.assertFalse(d.compare_groups(record, image, baseline, IDENTITY)['groups']['DECL_BIND'])

    def test_no_baseline_no_guess_and_bad_shape_does_not_hide_other_flags(self):
        record, image, _, _ = fixtures()
        result = d.compare_groups(record, image, None, IDENTITY)
        self.assertIsNone(result['groups']['ACTUAL_AUTH'])
        self.assertIsNone(result['groups']['ACTUAL_DATA'])
        self.assertTrue(result['groups']['ENV'])
        record['HostConfig'] = None
        result = d.compare_groups(record, image, None, IDENTITY)
        self.assertIsNone(result['groups']['MEMORY'])
        self.assertTrue(result['groups']['ENV'])

    def test_volume_baseline_is_exact_and_local(self):
        _, _, baseline, volumes = fixtures()
        self.assertEqual(d.volume_baseline(volumes), baseline)
        for change in (lambda v: v[0].update(Driver='remote'), lambda v: v[0].update(Name='wrong'),
                       lambda v: v[0].update(Mountpoint=v[1]['Mountpoint']), lambda v: v[0].update(Options={'x': 'y'})):
            copy_volumes = copy.deepcopy(volumes)
            change(copy_volumes)
            self.assertIsNone(d.volume_baseline(copy_volumes))


class PacketTests(unittest.TestCase):
    def module(self, ids):
        calls = []
        module = types.SimpleNamespace(decode=lambda raw: json.loads(raw), calls=calls)
        class Client:
            def __init__(self, repo, deadline):
                pass
            def __call__(self, args, cap=65536):
                calls.append((args, cap))
                if args == d.LIST_ARGS:
                    return ids
                record, image, _, volumes = fixtures()
                if args[:2] == ('image', 'inspect'):
                    return json.dumps(image).encode()
                if args[:2] == ('volume', 'inspect'):
                    return b'\n'.join(json.dumps(v).encode() for v in volumes) + b'\n'
                if args[:2] == ('container', 'inspect'):
                    record['Id'] = args[-1]
                    return json.dumps(record).encode()
                raise AssertionError('NO_OTHER_COMMAND')
        module.Client = Client
        return module

    def test_three_candidates_one_packet_exact_six_read_clients(self):
        ids = (d.INITIAL, 'b' * 64, 'c' * 64)
        module = self.module(('\n'.join(ids) + '\n').encode())
        candidates, baseline, found = d.packet(module, d.REPO, d.time.monotonic() + 60)
        self.assertEqual(found, ids)
        self.assertIsNotNone(baseline)
        self.assertEqual(len(candidates), 3)
        self.assertEqual(len(module.calls), 6)
        self.assertEqual(module.calls[0], (d.LIST_ARGS, 4096))
        for args, cap in module.calls[1:]:
            self.assertLessEqual(cap, 65536)
            self.assertNotIn('exec', args)
            self.assertNotIn('start', args)
            self.assertNotIn('logs', args)
        for args, _ in module.calls[3:]:
            self.assertEqual(args[:-1], ('container', 'inspect', '--format', d.CANDIDATE_FORMAT))
            self.assertIn(args[-1], ids)

    def test_fourth_duplicate_and_malformed_stop_before_any_other_query(self):
        for raw in (b'\n'.join(c.encode() * 64 for c in ('a', 'b', 'c', 'd')) + b'\n',
                    (IDENTITY + '\n' + IDENTITY + '\n').encode(), b'bad\n', b'\xff\n', IDENTITY.encode()):
            with self.subTest(raw_length=len(raw)):
                module = self.module(raw)
                with self.assertRaises(d.Refused):
                    d.packet(module, d.REPO, d.time.monotonic() + 60)
                self.assertEqual(len(module.calls), 1)
        module = self.module(b'')
        self.assertEqual(d.packet(module, d.REPO, d.time.monotonic() + 60)[0], [])
        self.assertEqual(len(module.calls), 1)

    def test_full_closed_receipt_privacy_and_cap_with_three_malformed_profiles(self):
        module = self.module(('\n'.join((d.INITIAL, 'b' * 64, 'c' * 64)) + '\n').encode())
        with patch.object(d, 'load_transport', return_value=(module, {})):
            receipt, status = d.run([])
        self.assertEqual(status, 0)
        self.assertEqual(receipt['privateBindings'], 'NOT_OBSERVED')
        self.assertFalse(receipt['adopted'])
        self.assertEqual(receipt['Env'], 'EQUALITY_ONLY_PRIVATE')
        raw = json.dumps(receipt, separators=(',', ':'))
        self.assertLessEqual(len(raw), 4096)
        self.assertNotIn(CANARY, raw)
        self.assertNotIn(d.HELPER_SOURCE, raw)
        self.assertNotIn('key-preservation-abcdefgh', raw)
        for candidate in receipt['candidates']:
            candidate['groups'] = dict.fromkeys(d.GROUPS, None)
        self.assertLessEqual(len(json.dumps(receipt, separators=(',', ':'))), 4096)

    def test_source_refusal_precedes_any_client_and_never_imports_controller(self):
        with patch.object(d, 'public_bytes', return_value=b'UNAPPROVED'), patch.object(d, 'packet') as packet:
            receipt, status = d.run(['--diagnose-holder-qualification-once', '--source-sha256', 'a' * 64,
                '--test-sha256', 'b' * 64, '--controller-sha256', 'c' * 64, '--controller-test-sha256', 'd' * 64])
        self.assertEqual(status, 1)
        self.assertEqual(receipt['checkpoint'], 'PUBLIC_SOURCES')
        packet.assert_not_called()

    def test_frozen_transport_public_pins_only_no_execution(self):
        for relative, pin in d.LIBRARY_PINS.items():
            self.assertEqual(hashlib.sha256((d.REPO / relative).read_bytes()).hexdigest(), pin)


if __name__ == '__main__':
    unittest.main()
