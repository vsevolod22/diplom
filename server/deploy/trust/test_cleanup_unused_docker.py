#!/usr/bin/env python3
"""Inert synthetic tests only: no Docker clients, runtime or private file reads."""

import ast
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import time
import types
import unittest
from unittest import mock

HERE = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location('cleanup_unused_docker', HERE / 'cleanup_unused_docker.py')
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
IMAGE = next(iter(v.SNAPSHOTS))
OTHER = 'sha256:' + 'b' * 64
ACTOR = 'c' * 64
TAG = v.SNAPSHOTS[IMAGE][0]


def stream(items):
    return b''.join(v.canonical(item) + b'\n' for item in items)


def actor(identifier=ACTOR, image=OTHER, state='exited'):
    return {'id': identifier, 'image': image, 'state': state,
            'name': 'retained-' + identifier[-12:], 'size': '0B (virtual 10MB)'}


def image(identifier=IMAGE, repository=TAG.rsplit(':', 1)[0], tag='local'):
    return {'id': identifier, 'repository': repository, 'tag': tag, 'size': '10MB'}


def plan(count=1):
    return {'version': 3,
            'images': [{'image': identifier, 'tag': tag, 'namespace': namespace}
                       for identifier, (tag, namespace) in list(v.SNAPSHOTS.items())[:count]],
            'source': {'path': v.RUNNER, 'sha256': v.RUNNER_SHA256}}


def image_rows(exact):
    return [image(entry['image'], *entry['tag'].rsplit(':', 1)) for entry in exact['images']]


def acknowledgement(entry):
    return ('Untagged: ' + entry['tag'] + '\nDeleted: ' + entry['image'] + '\n').encode()


def argv(exact=None):
    result = ['--inventory-once', '--source-sha256', '1' * 64, '--test-sha256', '2' * 64]
    if exact is not None:
        raw = v.canonical(exact)
        result[0] = '--remove-exact-batch-once'
        result += [v.AUTHORIZATION, '--plan-sha256', hashlib.sha256(raw).hexdigest(),
                   '--plan-json', raw.decode()]
    return result


class FakeRefused(Exception):
    def __init__(self, category):
        self.category = category


class FakeClient:
    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    def __call__(self, args, cap):
        self.calls.append((args, cap))
        if not self.replies:
            raise AssertionError('unexpected client')
        value = self.replies.pop(0)
        if isinstance(value, Exception):
            raise value
        if len(value) > cap:
            raise FakeRefused('OUTPUT_CAP')
        return value


class CleanupTests(unittest.TestCase):
    def setUp(self):
        # Any accidental real process launch fails even if other mocks regress.
        patcher = mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('NO CHILDREN'))
        self.no_child = patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(v, 'no_config')
        self.no_config = patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self.no_child.assert_not_called()

    def runner(self, replies):
        client = FakeClient(replies)
        instances = []
        class Bounded:
            def __init__(self, repo, deadline):
                self.calls = 0
                self.deadline = deadline
                instances.append(self)
            def __call__(self, args, cap):
                if self.calls >= 8:
                    raise AssertionError('captured transport per-instance guard')
                self.calls += 1
                return client(args, cap)
        transport = types.SimpleNamespace(Refused=FakeRefused, Client=mock.Mock(side_effect=Bounded))
        runner = v.Cleanup(transport, time.monotonic() + 60)
        runner.test_transport_instances = instances
        return runner, client

    def refuse(self, function, category='PREDICATE_REFUSED'):
        with self.assertRaises(v.Refused) as failure:
            function()
        self.assertEqual(failure.exception.category, category)
        self.assertEqual(str(failure.exception), 'REFUSED')

    def removal_replies(self, actors=None, refs=None, listing=None, exact=None, failed_ack=None):
        exact = plan() if exact is None else exact
        actors = [actor()] if actors is None else actors
        refs = [{'id': item['id'], 'image': OTHER} for item in actors] if refs is None else refs
        result = [stream(image_rows(exact) if listing is None else listing), stream(actors)]
        if actors:
            result.append(stream(refs))
        result.extend(acknowledgement(entry) for entry in exact['images'])
        if failed_ack is not None:
            result[3 if actors else 2] = failed_ack
        return result

    def test_reported_scale_two_listings_no_delete_or_eligibility(self):
        actors = [actor(format(index, '064x'), TAG if index == 0 else OTHER,
                        tuple(sorted(v.STATES))[index % len(v.STATES)]) for index in range(18)]
        listing = [image('sha256:' + format(index, '064x'), 'dip-api', 'v' + str(index))
                   for index in range(24)]
        listing[0] = image()
        listing[1] = image(OTHER, '<none>', '<none>')
        runner, client = self.runner([stream(actors), stream(listing)])
        result = runner.inventory()
        self.assertEqual((len(result['containers']), len(result['images'])), (18, 24))
        self.assertFalse(result['referencesAuthoritative'])
        self.assertFalse(result['removalAuthorized'])
        selected = next(item for item in result['images'] if item['id'] == IMAGE)
        self.assertEqual(selected['listedReferences'], [actors[0]['id']])
        untagged = next(item for item in result['images'] if item['id'] == OTHER)
        self.assertEqual(untagged['tags'], [])
        self.assertEqual(client.calls, [(v.CONTAINERS, 32768), (v.IMAGES, 32768)])
        self.assertLessEqual(len(v.canonical(result)), 65536)
        self.no_config.assert_has_calls([mock.call(), mock.call()])

    def test_tag_relations_explicitly_not_authoritative_even_when_tag_matches(self):
        runner, _ = self.runner([stream([actor(image=TAG)]), stream([image()])])
        result = runner.inventory()
        self.assertEqual(result['images'][0]['listedReferences'], [ACTOR])
        self.assertFalse(result['referencesAuthoritative'])
        runner, _ = self.runner([stream([actor(image='missing:tag')]), stream([image()])])
        self.assertEqual(runner.inventory()['images'][0]['listedReferences'], [])
        # Neither a missing tag nor an untagged image creates removal authority.

    def test_maximum_rows_and_byte_cap_and_no_followup_on_container_failure(self):
        self.assertEqual(len(v.containers(stream([actor(format(i, '064x')) for i in range(80)]))), 80)
        self.assertEqual(len(v.images(stream([image('sha256:' + format(i, '064x'), 'repo', str(i))
                                             for i in range(100)]))), 100)
        for raw in (stream([actor(format(i, '064x')) for i in range(81)]),
                    stream([actor(), actor()]), b'\n', b'{}', b'x' * 32769):
            runner, client = self.runner([raw])
            self.refuse(runner.inventory, 'OUTPUT_CAP' if len(raw) > 32768 else 'PREDICATE_REFUSED')
            self.assertEqual(len(client.calls), 1)
        self.refuse(lambda: v.images(stream([image('sha256:' + format(i, '064x'), 'repo', str(i))
                                            for i in range(101)])))

    def test_malformed_json_duplicates_extra_private_fields_and_unknown_state_closed(self):
        self.refuse(lambda: v.decode(b'{"a":1,"a":2}'), 'DECODE_REFUSED')
        for raw in (b'{', b'{"a":NaN}', b'{"a":1.5}', b'\xff'):
            self.refuse(lambda: v.decode(raw), 'DECODE_REFUSED')
        for key in ('Env', 'args', 'mounts', 'labels', 'logs'):
            item = actor()
            item[key] = 'PRIVATE_CANARY'
            self.refuse(lambda: v.containers(stream([item])))
        self.refuse(lambda: v.containers(stream([actor(state='unknown')])))
        self.refuse(lambda: v.containers(stream([actor(image='bad\nname')])))
        self.refuse(lambda: v.containers(stream([actor(identifier='short')])))
        self.refuse(lambda: v.images(stream([image(identifier='sha256:short')])))

    def test_image_grouping_no_duplicate_rows_tags_or_size_drift(self):
        second = image(tag='also-retained')
        result = v.images(stream([image(), second]))
        self.assertEqual(result[0]['tags'], sorted([TAG.rsplit(':', 1)[0] + ':also-retained', TAG]))
        for listing in ([image(), image()], [image(), image(OTHER)],
                        [image(), dict(second, size='11MB')], [image(tag='<none>')]):
            self.refuse(lambda: v.images(stream(listing)))

    def test_exact_batch_plan_pinned_canonical_exclusive_held_authorization_only(self):
        self.assertIsNone(v.arguments(argv()))
        self.assertEqual(v.arguments(argv(plan(7))), plan(7))
        for change in ({'images': []}, {'images': plan(7)['images'] + [plan()['images'][0]]},
                       {'provenance': 'name-match-only'}, {'version': True}, {'version': 1}, {'version': 2},
                       {'source': {'path': v.RUNNER, 'sha256': '0' * 64}},
                       {'afterParentDeployment': False}, {'afterParentDeployment': True}, {'extra': 'private'}):
            self.refuse(lambda: v.arguments(argv(dict(plan(), **change))))
        self.assertEqual(len(v.SNAPSHOTS), 7)
        for protected in (*v.PROTECTED, OTHER):
            altered = plan()
            altered['images'][0]['image'] = protected
            self.refuse(lambda: v.arguments(argv(altered)))
        self.assertEqual(len(v.PROTECTED), 9)
        self.assertIn('sha256:c09ce4c8e6185784fad2c263b462952092fa89058d16363ebd543e0cd4bbd50d', v.PROTECTED)
        for change in ({'tag': 'dip-cve14-snapshot-foreign:local'}, {'tag': '<none>:<none>'},
                       {'tag': '--force:x'}, {'namespace': 'diagnostic-source-build'}, {'extra': True}):
            altered = plan()
            altered['images'][0].update(change)
            self.refuse(lambda: v.arguments(argv(altered)))
        altered = plan(2)
        altered['images'][1] = copy.deepcopy(altered['images'][0])
        self.refuse(lambda: v.arguments(argv(altered)))
        for altered in ([], argv() + ['--force'], argv()[1:], ['--remove-exact-once'] + argv()[1:]):
            self.refuse(lambda: v.arguments(altered))
        altered = argv(plan())
        altered[7] = '0' * 64
        self.refuse(lambda: v.arguments(altered))
        altered = argv(plan())
        altered[9] = json.dumps(plan())
        altered[7] = hashlib.sha256(altered[9].encode()).hexdigest()
        self.refuse(lambda: v.arguments(altered))
        for rejected_flag in ('--force', '--consent-exact-obsolete-image-batch-removal',
                              '--consent-exact-obsolete-image-removal', '--after-deployment'):
            altered = argv(plan())
            altered[5] = rejected_flag
            self.refuse(lambda: v.arguments(altered))
        self.assertEqual(v.AUTHORIZATION, '--authorize-exclusive-held-stand-unused-images')
        self.assertNotIn('afterParentDeployment', plan(7))
        self.assertNotIn('provenance', plan(7))

    def test_independently_selected_two_publicly_documented_ids_supported_no_auto_fallback(self):
        exact = plan(7)
        documented = {'sha256:4ca80cff07620171413cdd48c7697547f04829089c5937430e970fc20ac64b5d',
                      'sha256:d060e223a5e927c134ffbc5c885eea6a0cd9bdbaf1bf218eefc6478b20c6eb25'}
        exact['images'] = [entry for entry in exact['images'] if entry['image'] in documented]
        self.assertEqual(v.arguments(argv(exact)), exact)
        runner, client = self.runner(self.removal_replies(exact=exact))
        result = runner.remove(exact)
        self.assertEqual(set(result['confirmedRemovedImages']), documented)
        self.assertEqual(len(client.calls), 5)
        self.assertEqual(result['notAttemptedImages'], [])
        self.assertTrue(all('afterParentDeployment' not in key for key in result))

    def test_seven_image_batch_ten_calls_exact_order_and_aggregate_budget(self):
        exact = plan(7)
        runner, client = self.runner(self.removal_replies(exact=exact))
        result = runner.remove(exact)
        self.assertTrue(result['ok'])
        self.assertFalse(result['postInventory'])
        self.assertEqual(result['confirmedRemovedImages'], list(v.SNAPSHOTS))
        self.assertEqual(result['attemptedImages'], list(v.SNAPSHOTS))
        self.assertEqual(result['notAttemptedImages'], [])
        self.assertIsNone(result['uncertainImage'])
        self.assertEqual(client.calls[:3], [(v.IMAGES, 16384), (v.CONTAINERS, 16384),
            (('container', 'inspect', '--format', v.REFERENCE_FORMAT, ACTOR), 16384)])
        self.assertEqual(client.calls[3:], [(('image', 'rm', '--no-prune', identifier), 2048)
                                          for identifier in v.SNAPSHOTS])
        self.assertEqual(sum(cap for _, cap in client.calls), 63488)
        self.assertEqual((runner.metadata_calls, runner.mutation_calls), (3, 7))
        self.assertEqual(runner.transport.Client.call_count, 2)
        self.assertEqual([instance.calls for instance in runner.test_transport_instances], [3, 7])
        self.assertTrue(all(instance.deadline == runner.deadline for instance in runner.test_transport_instances))
        self.refuse(lambda: runner.remove(exact))
        self.assertEqual(len(client.calls), 10)

    def test_entire_batch_reference_fence_before_first_mutation_any_lifecycle_tag_moved(self):
        exact = plan(7)
        for state in v.STATES:
            runner, client = self.runner(self.removal_replies(exact=exact,
                actors=[actor(image='moved:tag', state=state)],
                refs=[{'id': ACTOR, 'image': exact['images'][-1]['image']}]))
            self.refuse(lambda: runner.remove(exact))
            self.assertEqual(len(client.calls), 3)
            self.assertFalse(runner.removal_attempted)
            self.assertEqual(runner.partial_receipt()['notAttemptedImages'], list(v.SNAPSHOTS))

    def test_untagged_changed_multi_tagged_or_absent_later_member_blocks_entire_batch(self):
        exact = plan(7)
        for replacement in (None, dict(image_rows(exact)[-1], tag='changed'),
                            dict(image_rows(exact)[-1], repository='<none>', tag='<none>')):
            listing = image_rows(exact)[:-1] + ([] if replacement is None else [replacement])
            runner, client = self.runner([stream(listing)])
            self.refuse(lambda: runner.remove(exact))
            self.assertEqual(len(client.calls), 1)
            self.assertFalse(runner.removal_attempted)
        runner, client = self.runner([stream(image_rows(exact) + [image(tag='other')])])
        self.refuse(lambda: runner.remove(exact))
        self.assertEqual(len(client.calls), 1)

    def test_reference_recheck_every_listed_id_once_and_only_immutable_images(self):
        for refs in ([], [{'id': ACTOR, 'image': 'dip-api:tag'}],
                     [{'id': ACTOR, 'image': OTHER}] * 2,
                     [{'id': 'd' * 64, 'image': OTHER}],
                     [{'id': ACTOR, 'image': OTHER, 'Env': 'PRIVATE_CANARY'}]):
            runner, client = self.runner(self.removal_replies(refs=refs))
            self.refuse(lambda: runner.remove(plan()))
            self.assertEqual(len(client.calls), 3)
            self.assertFalse(runner.removal_attempted)

    def test_empty_daemon_skips_inspect_but_never_creates_actor(self):
        runner, client = self.runner(self.removal_replies(actors=[]))
        self.assertTrue(runner.remove(plan())['ok'])
        self.assertEqual(len(client.calls), 3)
        self.assertEqual(client.calls[-1], (('image', 'rm', '--no-prune', IMAGE), 2048))

    def test_first_ambiguous_ack_nonzero_or_timeout_stops_batch_and_reports_partial(self):
        exact = plan(7)
        identifiers = list(v.SNAPSHOTS)
        for failed_index in (0, 3, 6):
            for failure in (FakeRefused('CLIENT_NONZERO'), FakeRefused('CLIENT_TIMEOUT'),
                            FakeRefused('OUTPUT_CAP'), b'PRIVATE_CANARY\n', b'',
                            ('Deleted: ' + OTHER + '\n').encode(),
                            acknowledgement(exact['images'][failed_index]) + b'Untagged: unexpected:digest\n'):
                replies = self.removal_replies(exact=exact)
                replies[3 + failed_index] = failure
                runner, client = self.runner(replies)
                output = types.SimpleNamespace(buffer=io.BytesIO())
                with mock.patch.object(v, 'load_transport', return_value=runner.transport), \
                     mock.patch.object(v.sys, 'stdout', output):
                    status = v.main(argv(exact))
                self.assertEqual(status, 1)
                result = json.loads(output.buffer.getvalue())
                self.assertTrue(result['manualReconciliationRequired'])
                self.assertTrue(result['removalAttempted'])
                self.assertEqual(result['checkpoint'], 'REMOVE')
                self.assertEqual(result['confirmedRemovedImages'], identifiers[:failed_index])
                self.assertEqual(result['uncertainImage'], identifiers[failed_index])
                self.assertEqual(result['notAttemptedImages'], identifiers[failed_index + 1:])
                self.assertNotIn(b'PRIVATE_CANARY', output.buffer.getvalue())
                self.assertEqual(len(client.calls), 4 + failed_index)

    def test_deadline_between_removals_has_confirmed_subset_and_no_uncertain_next_attempt(self):
        runner, client = self.runner(self.removal_replies(exact=plan(7)))
        real_tick = v.tick
        def stop_after_first(deadline):
            if runner.confirmed_images:
                raise v.Refused('CLIENT_TIMEOUT')
            real_tick(deadline)
        with mock.patch.object(v, 'tick', side_effect=stop_after_first):
            self.refuse(lambda: runner.remove(plan(7)), 'CLIENT_TIMEOUT')
        self.assertEqual(len(client.calls), 4)
        self.assertEqual(runner.partial_receipt()['confirmedRemovedImages'], [IMAGE])
        self.assertIsNone(runner.partial_receipt()['uncertainImage'])
        self.assertEqual(runner.partial_receipt()['notAttemptedImages'], list(v.SNAPSHOTS)[1:])

    def test_preflight_failure_reports_whole_batch_not_attempted_and_no_uncertainty(self):
        exact = plan(7)
        runner, client = self.runner([stream(image_rows(exact)), FakeRefused('CLIENT_NONZERO')])
        output = types.SimpleNamespace(buffer=io.BytesIO())
        with mock.patch.object(v, 'load_transport', return_value=runner.transport), \
             mock.patch.object(v.sys, 'stdout', output):
            self.assertEqual(v.main(argv(exact)), 1)
        result = json.loads(output.buffer.getvalue())
        self.assertEqual(result['notAttemptedImages'], list(v.SNAPSHOTS))
        self.assertEqual(result['confirmedRemovedImages'], [])
        self.assertEqual(result['attemptedImages'], [])
        self.assertIsNone(result['uncertainImage'])
        self.assertFalse(result['removalAttempted'])
        self.assertFalse(result['manualReconciliationRequired'])
        self.assertEqual(len(client.calls), 2)

    def test_mutation_ack_byte_cap_stops_immediately_and_batch_plan_is_bounded(self):
        exact = plan(7)
        self.assertLessEqual(len(v.canonical(exact)), 4096)
        runner, client = self.runner(self.removal_replies(exact=exact, failed_ack=b'x' * 2049))
        self.refuse(lambda: runner.remove(exact), 'OUTPUT_CAP')
        self.assertEqual(len(client.calls), 4)
        self.assertEqual(runner.partial_receipt()['uncertainImage'], IMAGE)
        self.assertEqual(runner.partial_receipt()['confirmedRemovedImages'], [])
        self.assertEqual(runner.partial_receipt()['notAttemptedImages'], list(v.SNAPSHOTS)[1:])

    def test_client_nonzero_before_mutation_and_deadline_stop_without_followup(self):
        for category in ('CLIENT_NONZERO', 'CLIENT_TIMEOUT', 'OUTPUT_CAP', 'CLIENT_EXEC_IDENTITY'):
            runner, client = self.runner([FakeRefused(category)])
            self.refuse(runner.inventory, category)
            self.assertEqual(len(client.calls), 1)
        runner, client = self.runner([])
        runner.deadline = time.monotonic() - 1
        self.refuse(runner.inventory, 'CLIENT_TIMEOUT')
        self.assertEqual(client.calls, [])
        runner, client = self.runner([b'', b''])
        runner.inventory()
        self.refuse(runner.inventory)
        self.assertEqual(len(client.calls), 2)

    def test_source_pins_capture_before_exec_no_controller_or_config_contents(self):
        transport_raw = b'CAPTURED_VERIFIED = True\n'
        pins = {v.TRANSPORT: hashlib.sha256(transport_raw).hexdigest()}
        raw = {v.SELF: b'self', v.TEST: b'test', v.TRANSPORT: transport_raw}
        args = argv()
        args[2], args[4] = (hashlib.sha256(raw[key]).hexdigest() for key in (v.SELF, v.TEST))
        with mock.patch.object(v, 'PINS', pins), \
             mock.patch.object(v, 'public_bytes', side_effect=lambda path, deadline: raw[str(path.relative_to(v.REPO))]) as read:
            loaded = v.load_transport(args, time.monotonic() + 60)
            self.assertTrue(loaded.CAPTURED_VERIFIED)
            self.assertEqual(read.call_count, 3)
            raw[v.TRANSPORT] = b'raise AssertionError("MUST NOT EXECUTE")\n'
            self.refuse(lambda: v.load_transport(args, time.monotonic() + 60))
        self.assertEqual(set(v.PINS), {v.RUNNER, v.TRANSPORT, 'server/deploy/trust/test_discover_preservation_holder.py'})
        for relative, digest in v.PINS.items():
            self.assertEqual(hashlib.sha256((v.REPO / relative).read_bytes()).hexdigest(), digest)

    def test_no_config_is_metadata_only_and_refuses_even_symlink(self):
        # Run the saved original function with stat mocked; never touch Docker config.
        original = CleanupTests._real_no_config
        with mock.patch.object(v.os, 'stat', side_effect=FileNotFoundError) as metadata:
            original()
            metadata.assert_called_once_with(v.REPO / 'server/deploy/trust/config.json', follow_symlinks=False)
        with mock.patch.object(v.os, 'stat', return_value=object()):
            self.refuse(original)

    def test_real_public_sources_capture_verified_transport_without_a_client(self):
        args = argv()
        args[2] = hashlib.sha256((v.REPO / v.SELF).read_bytes()).hexdigest()
        args[4] = hashlib.sha256((v.REPO / v.TEST).read_bytes()).hexdigest()
        transport = v.load_transport(args, time.monotonic() + 60)
        self.assertEqual(transport.SOCKET, 'unix:///Users/vsevolod/.docker/run/docker.sock')
        self.assertEqual(str(transport.DOCKER_PATH), '/opt/homebrew/Cellar/docker/28.1.1/bin/docker')
        self.assertEqual(transport.DOCKER_SHA256,
                         '5cfddb229b6278953fdbb5016619e0f786ac8291969183fb28e3717a92f8bd52')
        client = transport.Client(v.REPO, time.monotonic() + 60)
        self.assertEqual(client.calls, 0)
        self.assertEqual(client.env, {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/var/empty',
            'DOCKER_HOST': transport.SOCKET, 'DOCKER_CONTEXT': '',
            'DOCKER_CONFIG': str(v.REPO / 'server/deploy/trust')})

    def test_no_config_failure_prevents_child_and_closed_main_failure(self):
        runner, client = self.runner([])
        self.no_config.side_effect = v.Refused()
        self.refuse(runner.inventory)
        self.assertEqual(client.calls, [])
        output = types.SimpleNamespace(buffer=io.BytesIO())
        with mock.patch.object(v, 'load_transport', side_effect=OSError('PRIVATE_CANARY')), \
             mock.patch.object(v.sys, 'stdout', output):
            self.assertEqual(v.main(argv()), 1)
        result = json.loads(output.buffer.getvalue())
        self.assertEqual(result['checkpoint'], 'PUBLIC_SOURCES')
        self.assertFalse(result['removalAttempted'])
        self.assertNotIn(b'PRIVATE_CANARY', output.buffer.getvalue())

    def test_public_runner_build_dataflow_ast_only_no_runner_execution(self):
        raw = (v.REPO / v.RUNNER).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), v.RUNNER_SHA256)
        text = raw.decode()
        tree = ast.parse(text)
        functions = {node.name: ast.get_source_segment(text, node) for node in tree.body
                     if isinstance(node, ast.FunctionDef)}
        self.assertIn('relative in INPUTS or relative in PROOFS or source_path(relative)', functions['public_read'])
        self.assertIn('files = {p: b for p, b in data.items() if p in embedded}', functions['context_files'])
        self.assertIn('files = context_files(data,hashes,source_sha,base,receipt)', functions['make_context'])
        self.assertIn('COPY proof /proof', functions['dockerfile'])
        self.assertIn("'dip-cve14-diag-snapshot-'", functions['diagnose_build'])
        self.assertIn("'dip-cve14-snapshot-'", functions['execute'])
        # Own generated credentials, release mounts, DB state and SQL proof occur
        # AFTER image construction, not in context_files or Dockerfile inputs.
        for name in ('context_files', 'make_context', 'dockerfile'):
            for private in ('own.env', 'release_dir', 'ledger.sqlite', 'recovery.json'):
                self.assertNotIn(private, functions[name])
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertFalse(any(isinstance(arg, ast.Constant) and arg.value == 'commit'
                             for node in calls for arg in node.args))

    def test_formats_only_safe_projection_no_full_inspect_and_parent_preservation(self):
        self.assertEqual(set(v.decode(v.REFERENCE_FORMAT.replace('{{json .Id}}', '"x"')
            .replace('{{json .Image}}', '"y"').encode())), {'id', 'image'})
        formats = v.CONTAINER_FORMAT + v.IMAGE_FORMAT + v.REFERENCE_FORMAT
        for forbidden in ('.Env', '.Args', '.Cmd', '.Mount', '.Labels', '.Error', '{{json .Config}}'):
            self.assertNotIn(forbidden, formats)
        for command in (v.CONTAINERS, v.IMAGES):
            self.assertNotIn('--filter', command)
            self.assertIn('--all', command)
            self.assertIn('--no-trunc', command)
        runner, client = self.runner(self.removal_replies())
        runner.remove(plan())
        for args, _ in client.calls:
            for forbidden in ('--force', '-f', '-v', 'prune', 'build', 'volume', 'create', 'logs', 'exec', 'start', 'stop'):
                self.assertNotIn(forbidden, args)


CleanupTests._real_no_config = staticmethod(v.no_config)

if __name__ == '__main__':
    unittest.main()
