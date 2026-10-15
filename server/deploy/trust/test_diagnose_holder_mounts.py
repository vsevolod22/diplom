"""Focused inert mount diagnostics. No Docker, real metadata, old tests/app imports."""
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
import types
import unittest
from unittest import mock

HERE = Path(__file__).absolute()
spec = importlib.util.spec_from_file_location('own_mount_diagnostic', HERE.with_name('diagnose_holder_mounts.py'))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
REPO = Path('/PUBLIC_SYNTHETIC_REPO')
CANARY = 'PRIVATE_CANARY'


def records():
    common = {'image': v.IMAGE, 'running': False, 'paused': False, 'restarting': False, 'oom': False, 'dead': False}
    api = dict(common, id=v.API, status='exited', declared=None, actual=[])
    holder = dict(common, id=v.HOLDER, status='created', declared=[], actual=[])
    for name, (target, typ, volume) in v.SLOTS.items():
        source = str(REPO / v.SCRIPT) if name == 'HELPER' else '/' + CANARY + '/' + name + '/_data'
        if name != 'HELPER':
            api['actual'].append({'Type': typ, 'Name': volume, 'Source': source,
                                  'Destination': '/' + name.lower(), 'RW': True})
        holder['declared'].append({'Type': typ, 'Source': str(REPO / v.SCRIPT) if name == 'HELPER' else volume,
                                   'Target': target, 'ReadOnly': name == 'HELPER'})
        holder['actual'].append({'Type': typ, 'Name': volume, 'Source': source,
                                 'Destination': target, 'RW': name != 'HELPER'})
    return [api, holder]


class ForeignRefused(Exception):
    def __init__(self, category):
        self.category = category


class FakeClient:
    def __init__(self, records):
        self.calls = 0
        self.raw = b'\n'.join(v.canonical(r) for r in records) + b'\n'
        self.args = None
    def __call__(self, args, cap):
        self.calls += 1
        self.args = args
        assert args == v.ARGS and cap == 65536 and self.calls == 1
        return self.raw


class MountTests(unittest.TestCase):
    def setUp(self):
        self.no_child = mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('NO_REAL_CLIENT')).start()
        self.addCleanup(mock.patch.stopall)

    def refuse(self, operation):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with self.assertRaises(v.Refused) as caught:
                operation()
        self.assertEqual((out.getvalue(), err.getvalue()), ('', ''))
        self.assertEqual(str(caught.exception), 'REFUSED')
        self.no_child.assert_not_called()
        return caught.exception

    def test_exact_fields_and_closed_private_output_not_qualification(self):
        result = v.classify(records(), REPO)
        self.assertEqual(result['code'], 'MOUNTS_CLASSIFIED_NOT_QUALIFIED')
        self.assertEqual(result['Env'], 'NOT_OBSERVED')
        self.assertEqual(result['fullQualification'], 'NOT_CLAIMED')
        self.assertEqual(result['volumeBaseline'], 'COMPLETE')
        for slot in v.SLOTS:
            d = result['declared']['slots'][slot]
            a = result['materialized']['slots'][slot]
            self.assertTrue(d['typeMatch'] and a['typeMatch'] and a['nameMatch'])
            self.assertEqual((d['source'], a['source']), ('EXACT', 'EXACT'))
        self.assertEqual(result['declared']['slots']['AUTH']['readOnly'], 'FALSE')
        self.assertEqual(result['materialized']['slots']['AUTH']['rw'], 'TRUE')
        self.assertEqual(result['helperSourceAcrossViews'], 'MATCH')
        raw = v.canonical(result)
        for forbidden in (CANARY, str(REPO), v.HOLDER, v.API, v.IMAGE, v.TARGET, 'dip-auth-stand'):
            self.assertNotIn(forbidden.encode(), raw)
        self.assertLessEqual(len(raw), 4096)

    def test_shared_prefix_discrepancy_is_observation_not_normalization(self):
        r = records()
        for view in ('declared', 'actual'):
            r[1][view][-1]['Source'] = '/host_mnt' + str(REPO / v.SCRIPT)
        result = v.classify(r, REPO)
        self.assertEqual(result['declared']['slots']['HELPER']['source'], 'HOST_MNT_PREFIX')
        self.assertEqual(result['materialized']['slots']['HELPER']['source'], 'HOST_MNT_PREFIX')
        self.assertEqual(result['helperSourceAcrossViews'], 'MATCH')
        self.assertEqual(result['fullQualification'], 'NOT_CLAIMED')
        r[1]['actual'][-1]['Source'] = '/OTHER_PRIVATE_SOURCE'
        result = v.classify(r, REPO)
        self.assertEqual(result['materialized']['slots']['HELPER']['source'], 'DIFFERENT')
        self.assertEqual(result['helperSourceAcrossViews'], 'MISMATCH')
        self.assertNotIn(b'OTHER_PRIVATE_SOURCE', v.canonical(result))

    def test_options_identify_finite_extra_fields_unknown_names_never_escape(self):
        r = records()
        helper = r[1]['declared'][-1]
        helper.update(Consistency='', BindOptions={'Propagation': 'rprivate', 'CreateMountpoint': True,
                                                   CANARY: 'DO_NOT_PRINT'}, **{CANARY: 'DO_NOT_PRINT'})
        r[1]['declared'][0]['VolumeOptions'] = {'NoCopy': True, 'Labels': {CANARY: CANARY}}
        result = v.classify(r, REPO)
        opts = result['declared']['slots']['HELPER']['options']
        self.assertEqual(opts['extraKnown'], {'CONSISTENCY': 'STRING'})
        self.assertEqual(opts['unknownKeys'], 1)
        self.assertEqual(opts['bind']['propagation'], 'RPRIVATE')
        self.assertEqual(opts['bind']['flags']['CREATE_MOUNTPOINT'], 'TRUE')
        self.assertEqual(opts['bind']['unknownKeys'], 1)
        self.assertEqual(result['declared']['slots']['AUTH']['options']['volume']['noCopy'], 'TRUE')
        self.assertNotIn(CANARY.encode(), v.canonical(result))
        self.assertNotIn(b'DO_NOT_PRINT', v.canonical(result))
        self.assertEqual(result['materialized']['slots']['HELPER']['source'], 'EXACT')

    def test_null_empty_duplicate_extra_targets_and_no_runtime_inference(self):
        for value, expected in ((None, 'NULL'), ([], 'ARRAY')):
            r = records(); r[1]['actual'] = value
            result = v.classify(r, REPO)
            self.assertEqual(result['materialized']['shape']['kind'], expected)
            self.assertTrue(all(s['presence'] == 'MISSING' for s in result['materialized']['slots'].values()))
        r = records()
        r[1]['declared'].append(copy.deepcopy(r[1]['declared'][0]))
        r[1]['actual'].append({'Type': 'bind', 'Source': CANARY, 'Destination': '/UNKNOWN_PRIVATE_TARGET', 'RW': True})
        result = v.classify(r, REPO)
        self.assertEqual(result['declared']['slots']['AUTH']['presence'], 'DUPLICATE')
        self.assertTrue(result['declared']['shape']['duplicateTargets'])
        self.assertEqual(result['materialized']['shape']['unknownTargets'], 1)
        self.assertNotIn(b'UNKNOWN_PRIVATE_TARGET', v.canonical(result))

    def test_incomplete_baseline_empty_source_wrong_type_and_rw_not_coerced(self):
        r = records(); r[0]['actual'] = []
        r[1]['actual'][0]['RW'] = 1
        r[1]['actual'][1]['Source'] = ''
        r[1]['declared'][-1]['Source'] = None
        result = v.classify(r, REPO)
        self.assertEqual(result['volumeBaseline'], 'INCOMPLETE')
        self.assertEqual(result['materialized']['slots']['AUTH']['source'], 'BASELINE_NOT_OBSERVED')
        self.assertEqual(result['materialized']['slots']['AUTH']['rw'], 'WRONG_TYPE')
        self.assertEqual(result['materialized']['slots']['DATA']['source'], 'EMPTY')
        self.assertEqual(result['declared']['slots']['HELPER']['source'], 'WRONG_TYPE')

    def test_identity_image_state_changes_and_large_shapes_refuse(self):
        for change in (lambda r: r[1].update(id='0' * 64), lambda r: r[0].update(image='sha256:' + '0' * 64),
                       lambda r: r[1].update(status='running', running=True), lambda r: r[1].update(paused=True),
                       lambda r: r[1].update(oom=True), lambda r: r[1].update(actual=[{}] * 9),
                       lambda r: r[1]['declared'][0].update(VolumeOptions={str(n): None for n in range(17)})):
            r = records(); change(r)
            self.refuse(lambda: v.classify(r, REPO))

    def test_one_fixed_inspect_two_exact_ids_no_followup(self):
        client = FakeClient(records())
        module = types.SimpleNamespace(Client=mock.Mock(return_value=client), Refused=ForeignRefused, decode=json.loads)
        result = v.diagnose(module, REPO, time.monotonic() + 30)
        self.assertEqual(client.calls, 1)
        self.assertEqual(client.args[-2:], (v.API, v.HOLDER))
        self.assertEqual(result['code'], 'MOUNTS_CLASSIFIED_NOT_QUALIFIED')
        for forbidden in ('.Config.Env', '.Config.Labels', '.State.Error', '{{json .State}}', '{{json .Config}}'):
            self.assertNotIn(forbidden, v.FORMAT)
        self.assertEqual(v.ARGS[:4], ('container', 'inspect', '--format', v.FORMAT))
        self.no_child.assert_not_called()

    def test_transport_refusal_translation_and_no_extra_records(self):
        for raw in (b'{}\n', b'{}\n{}\n{}\n', b'x' * 65537):
            client = FakeClient(records()); client.raw = raw
            module = types.SimpleNamespace(Client=lambda *_: client, Refused=ForeignRefused, decode=json.loads)
            self.refuse(lambda: v.diagnose(module, REPO, time.monotonic() + 30))
            self.assertEqual(client.calls, 1)
        client = mock.Mock(calls=1, side_effect=ForeignRefused('CLIENT_EXEC_NOT_FOUND'))
        module = types.SimpleNamespace(Client=lambda *_: client, Refused=ForeignRefused, decode=json.loads)
        failure = self.refuse(lambda: v.diagnose(module, REPO, time.monotonic() + 30))
        self.assertEqual(failure.category, 'CLIENT_EXEC_NOT_FOUND')

    def test_public_loader_pins_before_only_synthetic_library_exec_no_controller_import(self):
        with tempfile.TemporaryDirectory(prefix='own-holder-mount-source-') as temp:
            repo = Path(temp).resolve()
            (repo / 'server/deploy/trust').mkdir(parents=True)
            for relative in (v.SELF, v.TEST):
                shutil.copyfile(HERE.parent / Path(relative).name, repo / relative)
            synthetic = b'MARKER="SYNTHETIC_PUBLIC_ONLY"\n'
            pins = {}
            for relative in v.PINS:
                raw = synthetic if relative == v.LIBRARY else b'raise AssertionError("NEVER_IMPORT_THIS")\n'
                (repo / relative).write_bytes(raw)
                pins[relative] = hashlib.sha256(raw).hexdigest()
            argv = ['--diagnose-once', '--source-sha256', hashlib.sha256((repo / v.SELF).read_bytes()).hexdigest(),
                    '--test-sha256', hashlib.sha256((repo / v.TEST).read_bytes()).hexdigest()]
            with mock.patch.object(v, '__file__', str(repo / v.SELF)), mock.patch.object(v, 'PINS', pins):
                module = v.load_library(repo, argv, time.monotonic() + 30)
                self.assertEqual(module.MARKER, 'SYNTHETIC_PUBLIC_ONLY')
                (repo / v.LIBRARY).write_bytes(b'raise AssertionError("MUST_REFUSE_BEFORE_EXEC")\n')
                self.refuse(lambda: v.load_library(repo, argv, time.monotonic() + 30))
            public = repo / 'public-source'
            public.symlink_to(repo / v.SELF)
            self.refuse(lambda: v.public_bytes(public, time.monotonic() + 30))
        self.no_child.assert_not_called()

    def test_bounded_worst_known_options_and_main_closed_failures(self):
        r = records()
        for m in r[1]['declared']:
            m.update({key: {} for key in v.EXTRA_KEYS})
            m['BindOptions'] = {'Propagation': CANARY, **{key: False for key in v.BOOL_KEYS}}
            m['VolumeOptions'] = {'NoCopy': False, 'Labels': {CANARY: CANARY}, 'Subpath': CANARY, 'DriverConfig': {}}
        raw = v.canonical(v.classify(r, REPO))
        self.assertLessEqual(len(raw), 4096)
        self.assertNotIn(CANARY.encode(), raw)
        output = io.BytesIO()
        with mock.patch.object(v.sys, 'stdout', types.SimpleNamespace(buffer=output)):
            self.assertEqual(v.main(['--unknown', CANARY]), 1)
        result = json.loads(output.getvalue())
        self.assertEqual((result['code'], result['checkpoint']), ('REFUSED', 'ARGUMENTS'))
        self.assertNotIn(CANARY.encode(), output.getvalue())
        self.no_child.assert_not_called()


if __name__ == '__main__':
    unittest.main()
