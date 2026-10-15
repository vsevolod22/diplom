#!/usr/bin/env python3
"""New inert synthetic tests ONLY. No Engine, real subprocess or persistent fixtures.

The only source imported is the adjacent definition-only author extractor. All
container archives/identities, output trees, filesystem writes and Popen are fake.
No application/native/proof/legacy test imports, actual stores or private reads.
"""

import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import stat
import tarfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

SOURCE = Path(__file__).with_name("extract_old_image_sources.py")
spec = importlib.util.spec_from_file_location("old_public_source_candidate", SOURCE)
x = importlib.util.module_from_spec(spec)
spec.loader.exec_module(x)


def archive(path, data=b"export const value = 1;\n", kind=tarfile.REGTYPE, name=None, extra=False):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as writer:
        member = tarfile.TarInfo(name if name is not None else path.rsplit("/", 1)[-1])
        member.type = kind
        member.mode = 0o777  # Output must ignore the archive's permissions/ownership.
        member.uid = 123
        member.gid = 456
        member.size = len(data) if kind == tarfile.REGTYPE else 0
        if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            member.linkname = "/auth/private.sqlite"
        writer.addfile(member, io.BytesIO(data) if member.size else None)
        if extra:
            second = tarfile.TarInfo("unexpected.ts")
            second.size = 1
            writer.addfile(second, io.BytesIO(b"x"))
    return buffer.getvalue()


def image_value(image, default_main):
    return {"id": image, "os": "linux", "arch": "arm64", "user": "65532:65532",
            "workdir": "/app/server/api", "volumes": None,
            "entrypoint": ["docker-entrypoint.sh"], "cmd": ["node", "--import", "tsx", default_main]}


def container_value(owned):
    return {"id": owned["id"], "image": owned["image"], "name": "/" + owned["name"],
            "status": "created", "running": False, "paused": False, "restarting": False,
            "dead": False, "started": x.ZERO_TIME, "finished": x.ZERO_TIME,
            "mounts": 0, "binds": 0, "tmpfs": 0, "devices": 0, "privileged": False,
            "readonly": True, "network": "none", "user": "65532:65532", "workdir": "/app/server/api",
            "entrypoint": ["/bin/false"], "cmd": None, "path": "/bin/false", "args": [],
            "caps": ["ALL"], "security": ["no-new-privileges:true"], "restart": "no",
            "health": ["NONE"], "ownLabel": x.LABEL_VALUE}


class MemoryOutput:
    def __init__(self, *args):
        self.files = {}
        self.closed = False

    def write(self, parts, data):
        if parts in self.files:
            raise x.Refusal("OUTPUT_IO")
        self.files[parts] = bytes(data)

    def close(self):
        self.closed = True


class FakeDocker:
    def __init__(self):
        self.deadline = time.monotonic() + 180
        self.calls = []
        self.containers = {}
        self.collision = False
        self.image_change = {}
        self.guard_change = {}
        self.failure = None
        self.create_reply = None
        self.remove_reply = None
        self.file_changes = {}
        self.before_remove_change = None
        self.guard_after_copies = 1
        self.metadata = {
            "/app/server/api/package.json": x.encoded({"type": "module", "dependencies": {
                "@nestjs/common": "11.1.0", "reflect-metadata": "0.2.2", "better-sqlite3": "12.11.1"}}),
            "/app/server/api/tsconfig.json": x.encoded({"compilerOptions": x.TS_OPTIONS, "include": ["src/**/*.ts"]}),
            "/app/package.json": b'{"type":"module"}',
            "/app/pnpm-workspace.yaml": b"packages:\n  - server/api\n",
            "/app/pnpm-lock.yaml": b"lockfileVersion: '9.0'\n",
        }
        # Synthetic OLD-like consumer graph. NEVER substitutes for real image bytes.
        self.source = {
            "oci/nginx-local.main.ts": b"import 'reflect-metadata'; import { A } from './nginx-local.module.js'; import '../parent-ingress.js';",
            "oci/nginx-local.module.ts": b"import '../auth/auth.store.js'; import '../ledger/ledger.js'; import '../llm/quota-runtime.js';",
            "parent-ingress.ts": b"import './runtime/runtime-api.module.js';",
            "auth/auth.store.ts": b"import Database from 'better-sqlite3';",
            "ledger/ledger.ts": b"import 'node:fs'; export const terminal = 14;",
            "llm/quota-runtime.ts": b"import './quota-ledger.js';",
            "llm/quota-ledger.ts": b"import Database from 'better-sqlite3';",
            "runtime/runtime-api.module.ts": b"export const disabled = true;",
            "worker/nginx-local-worker.main.ts": b"import { runWorker } from './worker-runtime.js';",
            "worker/worker-runtime.ts": b"import '../ledger/ledger.js'; import './outbox-consumer.js';",
            "worker/outbox-consumer.ts": b"import '../ledger/ledger.js';",
        }

    def run(self, argv, seconds, cap):
        self.calls.append((list(argv), seconds, cap))
        if self.failure and self.failure(argv):
            raise x.Refusal("CLIENT_TIMEOUT", True)
        if argv[:3] == ["docker", "container", "ls"]:
            return b"f" * 64 + b"\n" if self.collision else b""
        if argv[:3] == ["docker", "image", "inspect"]:
            target = next(item for item in x.TARGETS if item[1] == argv[-1])
            return x.encoded(dict(image_value(target[1], target[4]), **self.image_change))
        if argv[:2] == ["docker", "create"]:
            name = argv[argv.index("--name") + 1]
            target = next(item for item in x.TARGETS if item[2] == name)
            identifier = ("a" if target[0] == "api" else "b") * 64
            self.containers[identifier] = {"id": identifier, "image": target[1], "name": name, "role": target[0]}
            return self.create_reply if self.create_reply is not None else (identifier + "\n").encode()
        if argv[:3] == ["docker", "container", "inspect"]:
            owned = self.containers[argv[-1]]
            change = self.guard_change
            if self.before_remove_change and sum(call[0][:2] == ["docker", "cp"] for call in self.calls) >= self.guard_after_copies:
                change = self.before_remove_change
            return x.encoded(dict(container_value(owned), **change))
        if argv[:2] == ["docker", "cp"]:
            identifier, path = argv[2].split(":", 1)
            if path in self.file_changes:
                return self.file_changes[path]
            data = self.metadata.get(path)
            if data is None:
                data = self.source[path.removeprefix(x.SOURCE_ROOT)]
            return archive(path, data)
        if argv[:2] == ["docker", "rm"]:
            return self.remove_reply if self.remove_reply is not None else (argv[-1] + "\n").encode()
        raise AssertionError("Unexpected synthetic command")


class ProjectionTests(unittest.TestCase):
    """Static template text + synthetic JSON schema ONLY; no Go evaluation."""

    def setUp(self):
        self.enterContext(patch.object(x.subprocess, 'Popen', side_effect=AssertionError('no child permitted')))
        self.enterContext(patch.object(x.os, 'open', side_effect=AssertionError('no filesystem permitted')))
        self.owned = {'id': 'a' * 64, 'image': x.API_IMAGE, 'name': x.TARGETS[0][2]}

    def test_nullable_mount_template_accepts_only_exact_nil_or_typed_empty(self):
        # Model only these explicit string-equality branches, not a Go interpreter.
        for key, lookup, empty in (('mounts', '(index . "Mounts")', '[]'),
                                   ('binds', '(index .HostConfig "Binds")', '[]'),
                                   ('tmpfs', '(index .HostConfig "Tmpfs")', '{}'),
                                   ('devices', '(index .HostConfig "Devices")', '[]')):
            fragment = ('"' + key + '":{{if or (eq (json ' + lookup + ') "null") '
                        '(eq (json ' + lookup + ') "' + empty + '")}}0{{else}}-1{{end}},')
            self.assertIn(fragment, x.CONTAINER_FORMAT)
        for forbidden in ('len .Mounts', '.HostConfig.Binds', '.HostConfig.Tmpfs', '.HostConfig.Devices'):
            self.assertNotIn(forbidden, x.CONTAINER_FORMAT)
        for key, empty in (('mounts', '[]'), ('binds', '[]'), ('tmpfs', '{}'), ('devices', '[]')):
            typed_empty = {} if empty == '{}' else []
            wrong_empty = [] if empty == '{}' else {}
            cases = ((None, 0), (typed_empty, 0), (wrong_empty, -1), ('', -1),
                     (False, -1), (0, -1), ('[]', -1), ('{}', -1),
                     (['CANARY_UNREVIEWED_MOUNT'], -1), ({'CANARY_UNREVIEWED_MOUNT': {}}, -1))
            for value, expected in cases:
                with self.subTest(key=key, value=value):
                    text = json.dumps(value, separators=(',', ':'))
                    projected = 0 if text in ('null', empty) else -1
                    self.assertEqual(projected, expected)
                    self.assertNotIn('CANARY_UNREVIEWED_MOUNT', str(projected))
                    candidate = dict(container_value(self.owned), **{key: projected})
                    if expected == 0:
                        x.check_container(candidate, self.owned)
                    else:
                        with self.assertRaises(x.Refusal) as raised:
                            x.check_container(candidate, self.owned)
                        self.assertEqual(raised.exception.code, 'OWN_CONTAINER_GUARD')
                        self.assertFalse(raised.exception.ambiguous)

    def test_projected_mount_schema_does_not_relax_zero_predicate(self):
        for key in ('mounts', 'binds', 'tmpfs', 'devices'):
            for value in (-1, 1, 2, None, [], {}, False, True, 0.0, '0'):
                with self.subTest(key=key, value=value), self.assertRaises(x.Refusal) as raised:
                    x.check_container(dict(container_value(self.owned), **{key: value}), self.owned)
                self.assertEqual(raised.exception.code, 'OWN_CONTAINER_GUARD')
        x.check_container(container_value(self.owned), self.owned)

    def test_health_template_guards_parent_without_disabled_fallback(self):
        self.assertIn('"health":{{with (index .Config "Healthcheck")}}{{json (index . "Test")}}'
                      '{{else}}null{{end}},', x.CONTAINER_FORMAT)
        self.assertNotIn('.Config.Healthcheck', x.CONTAINER_FORMAT)
        self.assertNotIn('["NONE"]', x.CONTAINER_FORMAT)
        self.assertEqual(x.create_argv(x.API_IMAGE, self.owned['name']).count('--no-healthcheck'), 1)
        for projection in (x.IMAGE_FORMAT, x.CONTAINER_FORMAT):
            self.assertNotIn('.Env', projection)
            self.assertNotIn('.History', projection)

    def test_absent_unknown_or_enabled_health_is_not_disabled(self):
        for health in (None, [], {}, False, 'NONE', ['CMD', 'probe'], ['CMD-SHELL', 'probe'],
                       ['NONE', 'extra'], ['none']):
            with self.subTest(health=health), self.assertRaises(x.Refusal) as raised:
                x.check_container(dict(container_value(self.owned), health=health), self.owned)
            self.assertEqual(raised.exception.code, 'OWN_CONTAINER_GUARD')
        missing = container_value(self.owned)
        del missing['health']
        with self.assertRaises(x.Refusal):
            x.check_container(missing, self.owned)

    def test_missing_optional_map_keys_model_as_nil_not_overall_coercion(self):
        # Representative index-on-map semantics MODEL ONLY, not executed Go.
        host = {}
        root = {}
        candidate = container_value(self.owned)
        for key, field, mapping, empty in (('mounts', 'Mounts', root, '[]'),
                                           ('binds', 'Binds', host, '[]'),
                                           ('tmpfs', 'Tmpfs', host, '{}'),
                                           ('devices', 'Devices', host, '[]')):
            self.assertNotIn(field, mapping)
            text = json.dumps(mapping.get(field), separators=(',', ':'))
            candidate[key] = 0 if text in ('null', empty) else -1
        x.check_container(candidate, self.owned)
        for key in ('mounts', 'binds', 'tmpfs', 'devices'):
            with self.subTest(key=key), self.assertRaises(x.Refusal):
                x.check_container(dict(candidate, **{key: -1}), self.owned)

    def test_missing_health_test_and_label_keys_model_fail_closed(self):
        self.assertIn('"ownLabel":{{with (index .Config "Labels")}}'
                      '{{json (index . "dip.public-source-extraction")}}{{else}}null{{end}}', x.CONTAINER_FORMAT)
        self.assertNotIn('.Config.Labels', x.CONTAINER_FORMAT)
        # Missing parent/key and explicit null are NOT disabled health or OWN label.
        for config in ({}, {'Healthcheck': None, 'Labels': None}, {'Healthcheck': {}, 'Labels': {}},
                       {'Healthcheck': {'Other': []}, 'Labels': {'other': 'value'}}):
            health = config.get('Healthcheck')
            labels = config.get('Labels')
            modeled_health = health.get('Test') if isinstance(health, dict) else None
            modeled_label = labels.get('dip.public-source-extraction') if isinstance(labels, dict) else None
            for key, value in (('health', modeled_health), ('ownLabel', modeled_label)):
                with self.subTest(config=config, key=key), self.assertRaises(x.Refusal) as raised:
                    x.check_container(dict(container_value(self.owned), **{key: value}), self.owned)
                self.assertEqual(raised.exception.code, 'OWN_CONTAINER_GUARD')

    def test_explicit_disabled_health_and_existing_empty_cmd_remain_valid(self):
        for cmd in (None, []):
            x.check_container(dict(container_value(self.owned), cmd=cmd, health=['NONE']), self.owned)


class ArchiveTests(unittest.TestCase):
    path = x.SOURCE_ROOT + "ledger/ledger.ts"

    def test_one_regular_file(self):
        self.assertEqual(x.single_file_tar(archive(self.path, b"hello"), self.path), b"hello")

    def test_empty_regular_file(self):
        self.assertEqual(x.single_file_tar(archive(self.path, b""), self.path), b"")

    def test_links_devices_directories_extensions_refuse(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.CHRTYPE,
                     tarfile.BLKTYPE, tarfile.FIFOTYPE, tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME):
            with self.subTest(kind=kind), self.assertRaises(x.Refusal):
                x.single_file_tar(archive(self.path, kind=kind), self.path)

    def test_traversal_absolute_prefix_wrong_name(self):
        for name in ("../ledger.ts", "/app/server/api/src/ledger/ledger.ts", "other.ts", "nested/ledger.ts"):
            with self.subTest(name=name), self.assertRaises(x.Refusal):
                x.single_file_tar(archive(self.path, name=name), self.path)

    def test_extra_duplicate_member_refuses(self):
        with self.assertRaises(x.Refusal):
            x.single_file_tar(archive(self.path, extra=True), self.path)

    def test_checksum_truncation_and_trailer_refuse(self):
        good = archive(self.path)
        for bad in (bytes([good[0] ^ 1]) + good[1:], good[:1024], good[:-1], good[:-512] + b"x" * 512):
            with self.subTest(size=len(bad)), self.assertRaises(x.Refusal):
                x.single_file_tar(bad, self.path)

    def test_per_file_and_stream_boundaries(self):
        self.assertEqual(len(x.single_file_tar(archive(self.path, b"a" * x.MAX_FILE_BYTES), self.path)), x.MAX_FILE_BYTES)
        for data in (archive(self.path, b"a" * (x.MAX_FILE_BYTES + 1)), b"a" * (x.MAX_FILE_BYTES + x.TAR_OVERHEAD + 1)):
            with self.assertRaises(x.Refusal):
                x.single_file_tar(data, self.path)

    def test_private_and_unknown_paths_refuse(self):
        for path in ("/auth/auth.sqlite", "/data/ledger.sqlite", "/root/.env", "/app/arbitrary.ts"):
            with self.subTest(path=path), self.assertRaises(x.Refusal):
                x.single_file_tar(archive(self.path), path)


class ImportTests(unittest.TestCase):
    def test_literal_forms_types_reexports_and_dynamic_literals(self):
        source = b"""import 'reflect-metadata';
import type { A } from './a.js'; import { A, type B } from '../b.js';
export type { C } from './c.js'; export * from './d.js';
export const x = import('./e.js'); const y = require('./f.js');"""
        self.assertEqual(x.import_specifiers(source), ['../b.js', './a.js', './c.js', './d.js', './e.js', './f.js', 'reflect-metadata'])

    def test_comments_strings_regex_and_template_text_are_not_edges(self):
        source = rb"""// import secret from './fake.js';
/* require(dynamic) */ const a = "import('./fake.js')";
const b = /import\(['"]fake['"]\)/; const c = `require(dynamic)`;
const d = new URL('./public-resource', import.meta.url); export const from = 'ignored';"""
        self.assertEqual(x.import_specifiers(source), [])

    def test_template_interpolations_and_nested_templates_scanned(self):
        source = b"const a = `text ${import('./a.js')} ${`inner ${require('./b.js')}`}`;"
        self.assertEqual(x.import_specifiers(source), ['./a.js', './b.js'])
        with self.assertRaises(x.Refusal):
            x.import_specifiers(b"const a = `text ${`inner ${import(config)}`}`;")

    def test_dynamic_nonliteral_loader_aliases_escaped_imports_refuse(self):
        for source in (b"import(config)", b"require(path)", b"import(`./a.js`)", b"const r = require;",
                       b"require.resolve('./a.js')", b"createRequire(import.meta.url)", b"eval(code)",
                       b"new Function(code)", b"import('./a.js', options)", b"import './a\\x2ejs';",
                       b"import x = resolve(name);", b"export * from variable;",
                       b"module['require'](config);", b"globalThis['eval'](code);"):
            with self.subTest(source=source), self.assertRaises(x.Refusal):
                x.import_specifiers(source)

    def test_unterminated_unicode_and_invalid_utf8_refuse(self):
        for source in (b"import 'unterminated", b"/* unterminated", b"const a = `oops", b"\xff",
                       b"import './a.js'; \\u0069mport(name)"):
            with self.subTest(source=source), self.assertRaises(x.Refusal):
                x.import_specifiers(source)

    def test_ambiguous_regex_or_division_refuses_instead_of_hiding_imports(self):
        with self.assertRaises(x.Refusal):
            x.import_specifiers(b"if (ok) /pattern/.test(value); import(config);")

    def test_sourced_call_division_nested_grouping_and_templates(self):
        snippets = (b"const minute = Math.floor(Date.now() / 60000);",
                    b"const unit = length() / 4096;",
                    b"const unit = Math.floor((length()) / (4096));",
                    b"const value = `text ${Math.floor(Date.now() / 60000)}`;",
                    b"if (ok) { const unit = length() / 4096; }")
        for source in snippets:
            with self.subTest(source=source):
                self.assertEqual(x.import_specifiers(source + b" import './known.js';"), ['./known.js'])
        for source in (b"if ((ok)) /pattern/.test(value);", b"while (ok()) /pattern/.test(value);",
                       b"for (;;) /pattern/.test(value);", b"if (ok) {} /pattern/.test(value);"):
            with self.subTest(source=source), self.assertRaises(x.Refusal):
                x.import_specifiers(source)

    def test_contextual_from_binding_is_not_the_module_delimiter(self):
        self.assertEqual(x.import_specifiers(b"import { from as fromValue } from 'rxjs';"), ['rxjs'])
        self.assertEqual(x.import_specifiers(b"export { from as value } from './known.js';"), ['./known.js'])

    def test_414_computed_loader_blind_spot_is_not_semantic_certification(self):
        # Observation preserved, not rebranded as comprehensive indirect-load refusal.
        self.assertEqual(x.import_specifiers(b'module["requ"+"ire"](unreviewed);'), [])

    def test_only_sourced_cve_policy_mjs_is_acquirable(self):
        origin = x.SOURCE_ROOT + 'ledger/ledger.ts'
        expected = x.SOURCE_ROOT + 'worker/cve-db-policy.mjs'
        self.assertEqual(x.resolve_relative(origin, '../worker/cve-db-policy.mjs'), expected)
        self.assertEqual(x.MJS_SOURCE_NAMES, {'worker/cve-db-policy.mjs'})
        for specifier in ('../worker/arbitrary.mjs', '../llm/tests/history-wire-native.client.mjs',
                          '../../../runtime/src/contract.js', '../../../runtime/src/live-port.js'):
            with self.subTest(specifier=specifier), self.assertRaises(x.Refusal):
                x.resolve_relative(origin, specifier)
        self.assertFalse(x.KNOWN_OUT_OF_SCOPE_PATHS & x.PUBLIC_PATHS)

    def test_exact_js_to_ts_resolution(self):
        origin = x.SOURCE_ROOT + "oci/nginx-local.main.ts"
        self.assertEqual(x.resolve_relative(origin, '../parent-ingress.js'), x.SOURCE_ROOT + 'parent-ingress.ts')
        self.assertEqual(x.resolve_relative(origin, './nginx-local.module.ts'), x.SOURCE_ROOT + 'oci/nginx-local.module.ts')

    def test_no_resolution_guesses_or_private_test_proof_paths(self):
        origin = x.SOURCE_ROOT + "oci/nginx-local.main.ts"
        for specifier in ('../parent-ingress', '../auth', './missing.js', './nginx-proof.main.js',
                          '../llm/history-init.js', '../llm/tests/fixtures.js', '../../../../auth/auth.sqlite',
                          './nginx-local.module.js?secret', '/data/private.ts', './x\\evil.js'):
            with self.subTest(specifier=specifier), self.assertRaises(x.Refusal):
                x.resolve_relative(origin, specifier)

    def test_externals_declared_finite_and_not_resolved(self):
        x.external_package('node:fs/promises', set())
        x.external_package('drizzle-orm/sqlite-core', {'drizzle-orm'})
        for name, declared in (('fs', set()), ('http://host/x', set()), ('#alias', set()),
                               ('unreviewed', {'unreviewed'}), ('better-sqlite3', set()),
                               ('node:unknown', set()), ('node:module', set()),
                               ('drizzle-orm/../private', {'drizzle-orm'})):
            with self.subTest(name=name), self.assertRaises(x.Refusal):
                x.external_package(name, declared)


class AcquisitionTests(unittest.TestCase):
    def setup_candidate(self):
        docker = FakeDocker()
        output = MemoryOutput()
        acquisition = x.Acquisition(docker, output)
        return docker, output, acquisition

    def test_success_two_exact_images_zero_starts_independent_graphs(self):
        docker, output, acquisition = self.setup_candidate()
        result = acquisition.run()
        self.assertEqual([graph['image'] for graph in result['graphs']], [x.API_IMAGE, x.WORKER_IMAGE])
        self.assertFalse(result['startupQualified'])
        self.assertFalse(result['provenanceIndependentlyEstablishedByExtractor'])
        self.assertEqual(len([call for call in docker.calls if call[0][1] == 'create']), 2)
        self.assertEqual([call[0] for call in docker.calls if call[0][1] == 'rm'], [['docker', 'rm', 'a' * 64], ['docker', 'rm', 'b' * 64]])
        for index, (argv, seconds, cap) in enumerate(docker.calls):
            self.assertNotIn(argv[1], ('run', 'start', 'exec', 'stop', 'kill', 'pause', 'compose', 'pull', 'build', 'save', 'export'))
            self.assertNotIn('--env', argv)
            self.assertNotIn('--mount', argv)
            self.assertNotIn('--volumes', argv)
            self.assertNotIn('--force', argv)
            if argv[1] == 'cp':
                self.assertEqual(docker.calls[index - 1][0][:3], ['docker', 'container', 'inspect'])
                self.assertEqual(seconds, 5)
                self.assertTrue(argv[2].split(':', 1)[1] in x.PUBLIC_PATHS)
                self.assertEqual(argv[-1], '-')
        self.assertTrue(('candidate.json',) in output.files)
        worker_ledger = output.files[('worker', 'server', 'api', 'src', 'ledger', 'ledger.ts')]
        api_ledger = output.files[('api', 'server', 'api', 'src', 'ledger', 'ledger.ts')]
        self.assertEqual(worker_ledger, api_ledger)  # They were separately acquired, not substituted.
        self.assertTrue(any(call[0][2].startswith('b' * 64 + ':' + x.SOURCE_ROOT + 'ledger/ledger.ts')
                            for call in docker.calls if call[0][1] == 'cp'))

    def test_cve_mjs_collected_separately_for_both_images_without_widening(self):
        docker, output, acquisition = self.setup_candidate()
        docker.source['ledger/ledger.ts'] = b"import '../worker/cve-db-policy.mjs';"
        docker.source['worker/cve-db-policy.mjs'] = b'export const minute = Math.floor(Date.now() / 60000);'
        result = acquisition.run()
        requests = [call[0][2] for call in docker.calls if call[0][1] == 'cp' and '.mjs' in call[0][2]]
        self.assertEqual(requests, ['a' * 64 + ':' + x.SOURCE_ROOT + 'worker/cve-db-policy.mjs',
                                    'b' * 64 + ':' + x.SOURCE_ROOT + 'worker/cve-db-policy.mjs'])
        self.assertFalse(result['semanticClosureQualified'])
        self.assertFalse(result['fullSourceClosureQualified'])
        self.assertFalse(result['startupQualified'])
        self.assertLessEqual(result['files'], 96)

    def test_each_completed_member_record_precedes_next_copy(self):
        docker, output, acquisition = self.setup_candidate()
        original = docker.run
        copied = [0]

        def ordered(argv, seconds, cap):
            if argv[1] == 'cp':
                if copied[0]:
                    self.assertIn((f'member-{copied[0]:04d}.json',), output.files)
                copied[0] += 1
            return original(argv, seconds, cap)

        docker.run = ordered
        result = acquisition.run()
        receipts = [json.loads(data)['member'] for key, data in output.files.items() if key[0].startswith('member-')]
        self.assertEqual(len(receipts), result['files'])
        self.assertEqual(receipts, acquisition.inventory)
        for member in receipts:
            stored = output.files[(member['role'],) + tuple(member['path'].removeprefix('/app/').split('/'))]
            self.assertEqual(member['sha256'], hashlib.sha256(stored).hexdigest())
            self.assertEqual(member['bytes'], len(stored))

    def test_names_collision_before_create_no_adoption(self):
        docker, output, acquisition = self.setup_candidate()
        docker.collision = True
        with self.assertRaises(x.Refusal):
            acquisition.run()
        self.assertFalse(any(call[0][1] in ('create', 'rm') for call in docker.calls))
        self.assertEqual(acquisition.owned, [])

    def test_image_volumes_identity_platform_defaults_refuse_before_create(self):
        changes = ({'volumes': {'/data': {}}}, {'id': 'sha256:' + 'c' * 64}, {'arch': 'amd64'},
                   {'os': 'windows'}, {'user': '0'}, {'workdir': '/root'}, {'entrypoint': ['sh']}, {'cmd': ['secret']})
        for change in changes:
            docker, output, acquisition = self.setup_candidate()
            docker.image_change = change
            with self.subTest(change=change), self.assertRaises(x.Refusal):
                acquisition.run()
            self.assertFalse(any(call[0][1] == 'create' for call in docker.calls))

    def test_foreign_running_previously_started_mounted_or_spoofed_retained(self):
        changes = ({'id': 'c' * 64}, {'image': x.WORKER_IMAGE}, {'name': '/foreign'}, {'status': 'exited'},
                   {'running': True}, {'started': '2026-10-11T00:00:00Z'}, {'finished': '2026-10-11T00:00:00Z'},
                   {'mounts': 1}, {'binds': 1}, {'tmpfs': 1}, {'ownLabel': 'foreign'}, {'entrypoint': ['node']},
                   {'privileged': True}, {'readonly': False}, {'network': 'bridge'}, {'user': '0'}, {'args': ['app']},
                   {'health': ['CMD', 'probe']}, {'running': 0}, {'readonly': 1}, {'mounts': False})
        for change in changes:
            docker, output, acquisition = self.setup_candidate()
            docker.guard_change = change
            with self.subTest(change=change), self.assertRaises(x.Refusal):
                acquisition.run()
            self.assertFalse(any(call[0][1] in ('cp', 'rm') for call in docker.calls))
            self.assertEqual(acquisition.owned[0]['id'], 'a' * 64)

    def test_create_timeout_and_bad_id_persist_only_attribution(self):
        for reply in (b'short\n', b'a' * 64 + b'\nforeign\n', b'\xff'):
            docker, output, acquisition = self.setup_candidate()
            docker.create_reply = reply
            with self.subTest(reply=reply), self.assertRaises(x.Refusal):
                acquisition.run()
            self.assertFalse(any(call[0][1] in ('cp', 'rm') for call in docker.calls))
            record = next(json.loads(data) for key, data in output.files.items()
                          if key[0].startswith('attribution-') and
                          json.loads(data)['operation']['kind'] == 'create')
            self.assertEqual(record['containers'][0]['disposition'], 'create_pending')
            self.assertIsNone(record['containers'][0]['id'])
        docker, output, acquisition = self.setup_candidate()
        docker.failure = lambda argv: argv[1] == 'create'
        with self.assertRaises(x.Refusal):
            acquisition.run()
        self.assertEqual(len([call for call in docker.calls if call[0][1] == 'create']), 1)
        self.assertFalse(any(call[0][1] == 'rm' for call in docker.calls))

    def test_copy_timeout_unsafe_tar_or_missing_relative_no_cleanup_retry(self):
        for mode in ('timeout', 'link', 'unresolved', 'dynamic'):
            docker, output, acquisition = self.setup_candidate()
            if mode == 'timeout':
                docker.failure = lambda argv: argv[1] == 'cp'
            elif mode == 'link':
                docker.file_changes[x.METADATA_PATHS[0]] = archive(x.METADATA_PATHS[0], kind=tarfile.SYMTYPE)
            elif mode == 'unresolved':
                docker.source['oci/nginx-local.main.ts'] = b"import './unknown.js';"
            else:
                docker.source['oci/nginx-local.main.ts'] = b"import(config);"
            with self.subTest(mode=mode), self.assertRaises(x.Refusal):
                acquisition.run()
            self.assertFalse(any(call[0][1] == 'rm' for call in docker.calls))
            self.assertNotIn(('candidate.json',), output.files)
            self.assertEqual(len([call for call in docker.calls if call[0][1] == 'create']), 1)

    def test_remove_ambiguity_retains_no_second_attempt(self):
        docker, output, acquisition = self.setup_candidate()
        docker.failure = lambda argv: argv[1] == 'rm'
        with self.assertRaises(x.Refusal):
            acquisition.run()
        self.assertEqual(acquisition.owned[0]['disposition'], 'removal_pending')
        self.assertEqual(len([call for call in docker.calls if call[0][1] == 'rm']), 1)
        self.assertEqual(len([call for call in docker.calls if call[0][1] == 'create']), 1)
        self.assertIn(('api-graph.json',), output.files)

    def test_guard_drift_before_next_copy_stops_removal(self):
        docker, output, acquisition = self.setup_candidate()
        docker.before_remove_change = {'running': True}
        with self.assertRaises(x.Refusal):
            acquisition.run()
        self.assertEqual(len([call for call in docker.calls if call[0][1] == 'cp']), 1)
        self.assertFalse(any(call[0][1] == 'rm' for call in docker.calls))

    def test_final_guard_before_remove_refuses_drift(self):
        docker, output, acquisition = self.setup_candidate()
        docker.guard_after_copies = 13  # Five metadata plus eight synthetic API sources.
        docker.before_remove_change = {'started': '2026-10-11T00:00:00Z'}
        with self.assertRaises(x.Refusal):
            acquisition.run()
        self.assertEqual(len([call for call in docker.calls if call[0][1] == 'cp']), 13)
        self.assertIn(('api-graph.json',), output.files)
        self.assertFalse(any(call[0][1] == 'rm' for call in docker.calls))

    def test_wrong_remove_reply_is_ambiguous_no_retry_or_worker_create(self):
        docker, output, acquisition = self.setup_candidate()
        docker.remove_reply = b'foreign\n'
        with self.assertRaises(x.Refusal):
            acquisition.run()
        self.assertEqual(acquisition.owned[0]['disposition'], 'removal_pending')
        self.assertEqual(len([call for call in docker.calls if call[0][1] == 'rm']), 1)
        self.assertEqual(len([call for call in docker.calls if call[0][1] == 'create']), 1)

    def test_global_file_count_before_next_cp(self):
        docker, output, acquisition = self.setup_candidate()
        acquisition.count = 96
        with self.assertRaises(x.Refusal):
            acquisition.run()
        self.assertFalse(any(call[0][1] in ('cp', 'rm') for call in docker.calls))

    def test_global_bytes_after_valid_archive_no_write_or_removal(self):
        docker, output, acquisition = self.setup_candidate()
        acquisition.total = x.MAX_TOTAL_BYTES
        with self.assertRaises(x.Refusal):
            acquisition.run()
        self.assertFalse(any(key[0] == 'api' for key in output.files))
        self.assertFalse(any(call[0][1] == 'rm' for call in docker.calls))

    def test_deadline_never_extends_for_cleanup(self):
        docker, output, acquisition = self.setup_candidate()
        docker.deadline = time.monotonic() - 1
        with self.assertRaises(x.Refusal):
            acquisition.run()
        self.assertFalse(any(call[0][1] in ('create', 'cp', 'rm') for call in docker.calls))

    def test_tsconfig_paths_extends_type_corruption_and_package_alias_refuse(self):
        for config in (dict(compilerOptions=dict(x.TS_OPTIONS, paths={'*': ['private/*']}), include=['src/**/*.ts']),
                       dict(compilerOptions=x.TS_OPTIONS, include=['src/**/*.ts'], extends='private'),
                       dict(compilerOptions=dict(x.TS_OPTIONS, strict=1), include=['src/**/*.ts'])):
            docker, output, acquisition = self.setup_candidate()
            docker.metadata[x.METADATA_PATHS[1]] = x.encoded(config)
            with self.subTest(config=config), self.assertRaises(x.Refusal):
                acquisition.run()
            self.assertFalse(any(call[0][1] == 'rm' for call in docker.calls))
        docker, output, acquisition = self.setup_candidate()
        docker.metadata[x.METADATA_PATHS[0]] = b'{"type":"module","imports":{"#alias":"private"}}'
        with self.assertRaises(x.Refusal):
            acquisition.run()


class OutputTests(unittest.TestCase):
    def mock_output(self):
        output = object.__new__(x.Output)
        output.fd = 10
        output.path = Path('/private/tmp/synthetic-only')
        return output

    def test_checkout_ancestor_relative_and_traversal_refuse_without_io(self):
        with patch.object(x.os, 'open', side_effect=AssertionError('must not open')):
            for path in ('relative', '/private/tmp/../checkout', '/checkout/project/output', '/checkout'):
                with self.subTest(path=path), self.assertRaises(x.Refusal):
                    x.Output(path, '/checkout/project')

    def test_output_collision_and_symlink_ancestor_refuse(self):
        with patch.object(x.os, 'open', return_value=11), patch.object(x.os, 'close'), \
                patch.object(x.os, 'mkdir', side_effect=FileExistsError):
            with self.assertRaises(x.Refusal):
                x.Output('/private/tmp/fresh', '/checkout/project')
        with patch.object(x.os, 'open', side_effect=[11, OSError('symlink')]), patch.object(x.os, 'close'):
            with self.assertRaises(x.Refusal):
                x.Output('/private/tmp/fresh', '/checkout/project')

    def test_fresh_root_0700_nofollow_and_parent_fsync(self):
        info = SimpleNamespace(st_uid=os.getuid(), st_mode=stat.S_IFDIR | 0o700)
        with patch.object(x.os, 'open', return_value=11) as opened, patch.object(x.os, 'close'), \
                patch.object(x.os, 'mkdir') as made, patch.object(x.os, 'fsync') as synced, \
                patch.object(x.os, 'fstat', return_value=info):
            output = x.Output('/private/tmp/fresh', '/checkout/project')
            made.assert_called_once_with('fresh', 0o700, dir_fd=11)
            self.assertTrue(opened.call_args.args[1] & os.O_DIRECTORY)
            self.assertTrue(opened.call_args.args[1] & os.O_NOFOLLOW)
            synced.assert_called_once_with(11)
            output.close()

    def test_fresh_0700_0600_exclusive_nofollow_fd_relative_write(self):
        output = self.mock_output()
        memory = MagicMock()
        info = SimpleNamespace(st_uid=os.getuid(), st_nlink=1, st_mode=stat.S_IFREG | 0o600)
        with patch.object(x.os, 'dup', return_value=11), patch.object(x.os, 'open', return_value=12) as opened, \
                patch.object(x.os, 'fstat', return_value=info), patch.object(x.os, 'fdopen', return_value=memory), \
                patch.object(x.os, 'close'), patch.object(x.os, 'fsync') as synced:
            output.write(('member.ts',), b'synthetic')
            flags = opened.call_args.args[1]
            self.assertTrue(flags & os.O_EXCL and flags & os.O_NOFOLLOW and flags & os.O_CREAT)
            self.assertEqual(opened.call_args.args[2], 0o600)
            self.assertEqual(opened.call_args.kwargs['dir_fd'], 11)
            memory.__enter__.return_value.write.assert_called_once_with(b'synthetic')
            self.assertEqual([call.args[0] for call in synced.call_args_list], [12, 11])

    def test_output_links_existing_files_wrong_mode_fail_no_repair(self):
        for mode, links in ((0o644, 1), (0o600, 2)):
            output = self.mock_output()
            info = SimpleNamespace(st_uid=os.getuid(), st_nlink=links, st_mode=stat.S_IFREG | mode)
            with patch.object(x.os, 'dup', return_value=11), patch.object(x.os, 'open', return_value=12), \
                    patch.object(x.os, 'fstat', return_value=info), patch.object(x.os, 'close'), \
                    patch.object(x.os, 'fdopen') as stream:
                with self.assertRaises(x.Refusal):
                    output.write(('member.ts',), b'synthetic')
                stream.assert_not_called()
        with patch.object(x.os, 'dup', return_value=11), patch.object(x.os, 'open', side_effect=FileExistsError), patch.object(x.os, 'close'):
            with self.assertRaises(x.Refusal):
                self.mock_output().write(('member.ts',), b'synthetic')


class RunnerTests(unittest.TestCase):
    def synthetic_runner(self, chunks, status=0, selector_events=True):
        process = MagicMock()
        process.pid = 987654
        process.stdout.fileno.return_value = 123
        process.wait.return_value = status
        selector = MagicMock()
        active = [True]
        selector.get_map.side_effect = lambda: {123: True} if active[0] else {}
        selector.select.return_value = [(SimpleNamespace(fd=123, fileobj=process.stdout), None)] if selector_events else []
        selector.unregister.side_effect = lambda fileobj: active.__setitem__(0, False)
        manager = MagicMock()
        manager.__enter__.return_value = selector
        return process, manager

    def test_mocked_popen_closed_channels_and_group_cleanup(self):
        process, manager = self.synthetic_runner([b'ok', b''])
        with patch.object(x.subprocess, 'Popen', return_value=process) as popen, \
                patch.object(x.selectors, 'DefaultSelector', return_value=manager), \
                patch.object(x.os, 'set_blocking'), patch.object(x.os, 'read', side_effect=[b'ok', b'']), \
                patch.object(x.os, 'killpg') as killed:
            self.assertEqual(x.Runner(time.monotonic() + 20).run(['docker', 'mock-only'], 5, 16), b'ok')
            self.assertEqual(popen.call_args.kwargs, {'stdin': x.subprocess.DEVNULL, 'stdout': x.subprocess.PIPE,
                'stderr': x.subprocess.DEVNULL, 'shell': False, 'start_new_session': True})
            killed.assert_called_once_with(process.pid, x.signal.SIGKILL)

    def test_mocked_overflow_and_nonzero_no_raw_diagnostics(self):
        for chunks, status, code in (([b'CANARY_RAW_DIAGNOSTICS'], 0, 'OUTPUT_BOUND'), ([b''], 7, 'CLIENT_FAILED')):
            process, manager = self.synthetic_runner(chunks, status)
            with patch.object(x.subprocess, 'Popen', return_value=process), \
                    patch.object(x.selectors, 'DefaultSelector', return_value=manager), \
                    patch.object(x.os, 'set_blocking'), patch.object(x.os, 'read', side_effect=chunks), \
                    patch.object(x.os, 'killpg'):
                with self.assertRaises(x.Refusal) as raised:
                    x.Runner(time.monotonic() + 20).run(['docker', 'mock-only'], 5, 8)
                self.assertEqual(str(raised.exception), code)
                self.assertTrue(raised.exception.ambiguous)

    def test_mocked_timeout_kills_client_group_no_retry(self):
        process, manager = self.synthetic_runner([])
        with patch.object(x.subprocess, 'Popen', return_value=process) as popen, \
                patch.object(x.selectors, 'DefaultSelector', return_value=manager), \
                patch.object(x.os, 'set_blocking'), patch.object(x.time, 'monotonic', side_effect=[0, 0, 6, 6]), \
                patch.object(x.os, 'killpg') as killed:
            with self.assertRaises(x.Refusal) as raised:
                x.Runner(20).run(['docker', 'mock-only'], 5, 8)
            self.assertEqual(str(raised.exception), 'CLIENT_TIMEOUT')
            self.assertEqual(popen.call_count, 1)
            killed.assert_called_once()


class CliAndInertTests(unittest.TestCase):
    def args(self):
        return ['--extract-public-sources', '--accept-historical-own-build-provenance',
                '--confirm-independent-command-source-review', '--source-sha256', hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                '--output', '/private/tmp/NOT_CREATED_SYNTHETIC-p1-r2', '--max-files', '96', '--max-file-bytes', '2097152',
                '--max-total-bytes', '25165824', '--overall-seconds', '180']

    def test_required_args_exact_bounds_unknowns_and_no_artifact_as_approval(self):
        bad = [[], self.args() + ['--unknown', 'CANARY'], self.args()[:-1] + ['181'],
               [arg for arg in self.args() if arg != '--confirm-independent-command-source-review']]
        for artifact in ('DIP-ARTF-407', 'DIP-ARTF-409', 'DIP-ARTF-410', 'DIP-ARTF-411'):
            bad.append(self.args() + ['--review-evidence', artifact])
        with patch.object(x, 'Output', side_effect=AssertionError('no output permitted')):
            for args in bad:
                out = io.StringIO()
                with self.subTest(args=args), contextlib.redirect_stderr(out), self.assertRaises(x.Refusal):
                    x.cli(args)
                self.assertEqual(out.getvalue(), '')

    def test_public_source_pin_mismatch_before_daemon_or_output(self):
        args = self.args()
        args[args.index('--source-sha256') + 1] = '0' * 64
        with patch.object(x, 'Output', side_effect=AssertionError('no output permitted')), \
                patch.object(x.subprocess, 'Popen', side_effect=AssertionError('no child permitted')):
            with self.assertRaises(x.Refusal):
                x.cli(args)

    def test_cli_success_only_mock_docker_memory_output_wall_alarm(self):
        output = MemoryOutput()
        with patch.object(x, 'Output', return_value=output), patch.object(x, 'Runner', return_value=FakeDocker()), \
                patch.object(x.signal, 'setitimer') as timer:
            receipt = x.cli(self.args())
        self.assertEqual(receipt, {'ok': True, 'code': 'CANDIDATE_COLLECTED', 'startupQualified': False})
        self.assertTrue(output.closed)
        self.assertEqual([call.args for call in timer.call_args_list], [(x.signal.ITIMER_REAL, 180), (x.signal.ITIMER_REAL, 0)])
        self.assertFalse(json.loads(output.files[('review-assertion.json',)])['evidenceContentsVerifiedByExtractor'])

    def test_cli_ambiguity_retains_attribution_and_closed_hold(self):
        output = MemoryOutput()
        docker = FakeDocker()
        docker.failure = lambda argv: argv[1] == 'cp'
        with patch.object(x, 'Output', return_value=output), patch.object(x, 'Runner', return_value=docker):
            with self.assertRaises(x.Refusal):
                x.cli(self.args())
        receipt = json.loads(output.files[('refusal.json',)])
        self.assertEqual(receipt['code'], 'HOLD')
        self.assertEqual(receipt['containers'][0]['id'], 'a' * 64)
        self.assertTrue(receipt['manualReconciliationRequired'])
        self.assertFalse(any(call[0][1] == 'rm' for call in docker.calls))

    def refusal_run(self, docker, output=None):
        output = output if output is not None else MemoryOutput()
        with patch.object(x, 'Output', return_value=output), patch.object(x, 'Runner', return_value=docker):
            with self.assertRaises(x.Refusal) as raised:
                x.cli(self.args())
        return output, raised.exception

    def test_415_timeout_vs_unsafe_archive_reason_ambiguity_and_exact_member(self):
        receipts = []
        for unsafe in (False, True):
            docker = FakeDocker()
            if unsafe:
                docker.file_changes[x.METADATA_PATHS[0]] = archive(x.METADATA_PATHS[0], kind=tarfile.SYMTYPE)
            else:
                docker.failure = lambda argv: argv[1] == 'cp'
            output, error = self.refusal_run(docker)
            receipt = json.loads(output.files[('refusal.json',)])
            receipts.append(receipt)
            self.assertEqual(receipt['reasonCode'], 'UNSAFE_ARCHIVE' if unsafe else 'CLIENT_TIMEOUT')
            self.assertEqual(receipt['ambiguous'], not unsafe)
            self.assertEqual(error.code, receipt['reasonCode'])
            self.assertEqual(receipt['operation']['path'], x.METADATA_PATHS[0])
            self.assertEqual(receipt['operation']['kind'], 'archive_validate' if unsafe else 'cp')
            self.assertEqual(receipt['operation']['containerId'], 'a' * 64)
            self.assertEqual(receipt['completedInventory'], [])
            self.assertEqual(receipt['counters']['validatedFiles'], 0)
            self.assertFalse(any(call[0][1] == 'rm' for call in docker.calls))
        self.assertNotEqual(receipts[0], receipts[1])

    def test_completed_partial_inventory_survives_fourth_copy_failure(self):
        docker = FakeDocker()
        calls = [0]

        def fourth(argv):
            if argv[1] == 'cp':
                calls[0] += 1
                return calls[0] == 4
            return False

        docker.failure = fourth
        output, _ = self.refusal_run(docker)
        receipt = json.loads(output.files[('refusal.json',)])
        self.assertEqual(receipt['operation']['path'], x.METADATA_PATHS[3])
        self.assertEqual(receipt['reasonCode'], 'CLIENT_TIMEOUT')
        self.assertEqual(receipt['counters']['completedMembers'], 3)
        self.assertEqual(receipt['counters']['validatedFiles'], 3)
        self.assertEqual([member['path'] for member in receipt['completedInventory']], list(x.METADATA_PATHS[:3]))
        self.assertEqual(receipt['counters']['completedBytes'], receipt['counters']['validatedBytes'])
        for index, member in enumerate(receipt['completedInventory'], 1):
            self.assertEqual(json.loads(output.files[(f'member-{index:04d}.json',)])['member'], member)
        pending = json.loads(output.files[(f"attribution-{receipt['lastDurableAttribution']:04d}.json",)])
        self.assertEqual(pending['operation'], receipt['operation'])
        self.assertEqual(pending['counters'], receipt['counters'])

    def test_lexical_and_import_failure_inventory_and_exact_edge_scope(self):
        for mode in ('lexical', 'known_outside', 'unknown_outside'):
            docker = FakeDocker()
            if mode == 'lexical':
                source = b'import(config);'
            elif mode == 'known_outside':
                source = b"import '../../../runtime/src/contract.js';"
            else:
                source = b"import './CANARY_UNREVIEWED_PATH.js';"
            docker.source['oci/nginx-local.main.ts'] = source
            output, _ = self.refusal_run(docker)
            receipt = json.loads(output.files[('refusal.json',)])
            expected = 'NONLITERAL_OR_INDIRECT_IMPORT' if mode == 'lexical' else 'IMPORT_OUTSIDE_ALLOWLIST'
            self.assertEqual(receipt['reasonCode'], expected)
            self.assertFalse(receipt['ambiguous'])
            self.assertEqual(receipt['operation']['path'], x.SOURCE_ROOT + 'oci/nginx-local.main.ts')
            self.assertEqual(receipt['counters']['completedMembers'], 6)
            self.assertEqual(len(receipt['completedInventory']), 6)
            self.assertNotIn('CANARY_UNREVIEWED_PATH', json.dumps(receipt))
            if mode == 'known_outside':
                self.assertEqual(receipt['operation']['targetPath'], '/app/server/runtime/src/contract.ts')
                self.assertEqual(receipt['operation']['targetScope'], 'known_out_of_scope')
                self.assertEqual(receipt['operation']['importIndex'], 0)
            elif mode == 'unknown_outside':
                self.assertIsNone(receipt['operation']['targetPath'])
                self.assertEqual(receipt['operation']['importIndex'], 0)
            self.assertFalse(any('/app/server/runtime/' in call[0][2] for call in docker.calls if call[0][1] == 'cp'))

    def test_file_count_refusal_keeps_exact_pending_member_and_counters(self):
        docker = FakeDocker()
        output = MemoryOutput()
        original = x.Acquisition.__init__

        def near_bound(acquisition, runner, staging):
            original(acquisition, runner, staging)
            acquisition.count = 96

        with patch.object(x.Acquisition, '__init__', near_bound):
            output, error = self.refusal_run(docker, output)
        receipt = json.loads(output.files[('refusal.json',)])
        self.assertEqual(error.code, 'FILE_COUNT_BOUND')
        self.assertFalse(receipt['ambiguous'])
        self.assertEqual(receipt['operation']['kind'], 'member_limit')
        self.assertEqual(receipt['operation']['path'], x.METADATA_PATHS[0])
        self.assertEqual(receipt['counters']['validatedFiles'], 96)
        self.assertFalse(any(call[0][1] in ('cp', 'rm') for call in docker.calls))

    def test_failed_member_commit_keeps_prior_receipts_not_false_completion(self):
        class FailingCommit(MemoryOutput):
            def write(self, parts, data):
                if parts == ('member-0003.json',):
                    raise OSError('CANARY_RAW_FILESYSTEM_DIAGNOSTIC')
                super().write(parts, data)

        output, error = self.refusal_run(FakeDocker(), FailingCommit())
        receipt = json.loads(output.files[('refusal.json',)])
        self.assertEqual(error.code, 'OUTPUT_IO')
        self.assertTrue(receipt['ambiguous'])
        self.assertEqual(receipt['operation']['kind'], 'member_commit')
        self.assertEqual(receipt['operation']['path'], x.METADATA_PATHS[2])
        self.assertEqual(receipt['counters']['validatedFiles'], 3)
        self.assertEqual(receipt['counters']['completedMembers'], 2)
        self.assertEqual(len(receipt['completedInventory']), 2)
        self.assertIn(('member-0002.json',), output.files)
        self.assertNotIn(('member-0003.json',), output.files)
        self.assertNotIn('CANARY_RAW_FILESYSTEM_DIAGNOSTIC', json.dumps(receipt))
        self.assertEqual(receipt['operation']['validatedMember']['path'], x.METADATA_PATHS[2])

    def test_missing_final_refusal_keeps_exact_prior_pending_and_original_reason(self):
        class NoRefusal(MemoryOutput):
            def write(self, parts, data):
                if parts == ('refusal.json',):
                    raise OSError('CANARY_FINAL_RECEIPT_FAILURE')
                super().write(parts, data)

        docker = FakeDocker()
        docker.failure = lambda argv: argv[1] == 'cp' and argv[2].endswith(x.METADATA_PATHS[3])
        output, error = self.refusal_run(docker, NoRefusal())
        self.assertEqual(error.code, 'CLIENT_TIMEOUT')
        pending = [json.loads(data) for key, data in output.files.items() if key[0].startswith('attribution-')][-1]
        self.assertEqual(pending['operation']['kind'], 'cp')
        self.assertEqual(pending['operation']['path'], x.METADATA_PATHS[3])
        self.assertEqual(pending['counters']['completedMembers'], 3)
        self.assertIn(('member-0003.json',), output.files)
        self.assertNotIn(('refusal.json',), output.files)
        self.assertFalse(any(call[0][1] == 'rm' for call in docker.calls))

    def test_failed_removal_reason_and_disposition_stay_pending_no_second_attempt(self):
        for wrong_reply in (False, True):
            docker = FakeDocker()
            if wrong_reply:
                docker.remove_reply = b'CANARY_FOREIGN_REPLY'
            else:
                docker.failure = lambda argv: argv[1] == 'rm'
            output, error = self.refusal_run(docker)
            receipt = json.loads(output.files[('refusal.json',)])
            self.assertEqual(receipt['reasonCode'], 'REMOVAL_AMBIGUOUS' if wrong_reply else 'CLIENT_TIMEOUT')
            self.assertTrue(receipt['ambiguous'])
            self.assertEqual(receipt['operation']['kind'], 'remove')
            self.assertEqual(receipt['containers'][0]['disposition'], 'removal_pending')
            self.assertEqual(receipt['operation']['containerId'], 'a' * 64)
            self.assertEqual(len([call for call in docker.calls if call[0][1] == 'rm']), 1)
            self.assertEqual(len([call for call in docker.calls if call[0][1] == 'create']), 1)
            self.assertEqual(receipt['counters']['completedMembers'], 13)
            self.assertNotIn('CANARY_FOREIGN_REPLY', json.dumps(receipt))

    def test_unknown_error_console_is_closed_vocabulary_only(self):
        console, diagnostic = io.StringIO(), io.StringIO()
        with patch.object(x, 'cli', side_effect=x.Refusal('CANARY_UNREVIEWED_REASON', True)), \
                contextlib.redirect_stdout(console), contextlib.redirect_stderr(diagnostic):
            self.assertEqual(x.main(), 1)
        receipt = json.loads(console.getvalue())
        self.assertEqual(receipt['reasonCode'], 'UNEXPECTED_FAILURE')
        self.assertTrue(receipt['ambiguous'])
        self.assertNotIn('CANARY_UNREVIEWED_REASON', console.getvalue())
        self.assertEqual(diagnostic.getvalue(), '')

    def test_definition_only_import_no_io_and_no_main(self):
        with patch.object(x.subprocess, 'Popen', side_effect=AssertionError('no child permitted')), \
                patch.object(x.os, 'open', side_effect=AssertionError('no filesystem permitted')):
            namespace = {'__name__': 'definition_only_synthetic', '__file__': str(SOURCE)}
            exec(compile(SOURCE.read_bytes(), str(SOURCE), 'exec'), namespace)
        self.assertTrue(callable(namespace['cli']))

    def test_source_ast_compile_finite_allowlist_and_no_sensitive_projections(self):
        for path in (SOURCE, Path(__file__)):
            content = path.read_text()
            ast.parse(content, filename=str(path))
            compile(content, str(path), 'exec')
            self.assertFalse(any(line.rstrip() != line for line in content.splitlines()))
        for name in x.SOURCE_NAMES:
            self.assertFalse(any(word in name for word in ('test', 'fixture', 'proof', 'smoke', '-init')))
        self.assertNotIn('main.ts', x.SOURCE_NAMES)
        self.assertNotIn('app.module.ts', x.SOURCE_NAMES)
        for projection in (x.IMAGE_FORMAT, x.CONTAINER_FORMAT):
            self.assertNotIn('.Env', projection)
            self.assertNotIn('.History', projection)
        self.assertNotIn('node_modules', '\n'.join(x.PUBLIC_PATHS))

    def test_duplicate_json_keys_and_invalid_constants_refuse(self):
        for data in (b'{"running":false,"running":true}', b'{"value":NaN}', b'{broken', b'\xff'):
            with self.subTest(data=data), self.assertRaises(x.Refusal):
                x.strict_json(data)


if __name__ == '__main__':
    # Belt-and-suspenders: even an accidental real Popen during this suite fails.
    with patch.object(x.subprocess, 'Popen', side_effect=AssertionError('REAL_SUBPROCESS_FORBIDDEN')):
        unittest.main()
