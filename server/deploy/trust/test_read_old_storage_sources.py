#!/usr/bin/env python3
"""Narrow synthetic fixed-slice tests; no Engine/Go/app/native/private fixtures."""

import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import time
import tarfile
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).with_name("read_old_storage_sources.py")
spec = importlib.util.spec_from_file_location("fixed_storage_reader", SOURCE)
x = importlib.util.module_from_spec(spec)
spec.loader.exec_module(x)
r = x.load_primitives()  # Hash-verified PUBLIC R4 definitions only, never its CLI.
Slice = x.acquisition_type(r)


def archive(path, data=b"import(dynamic); // synthetic, never lexed/executed\n", kind=tarfile.REGTYPE):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as writer:
        member = tarfile.TarInfo(path.rsplit("/", 1)[-1])
        member.type, member.mode = kind, 0o777
        member.size = len(data) if kind == tarfile.REGTYPE else 0
        writer.addfile(member, io.BytesIO(data) if member.size else None)
    return stream.getvalue()


class MemoryOutput:
    def __init__(self, *args):
        self.files = {}

    def write(self, parts, data):
        if parts in self.files:
            raise r.Refusal("OUTPUT_IO", True)
        self.files[parts] = bytes(data)

    def close(self):
        pass


def image_value(image):
    return {"id": image, "os": "linux", "arch": "arm64", "user": "65532:65532",
            "workdir": "/app/server/api", "volumes": None, "entrypoint": ["docker-entrypoint.sh"],
            "cmd": ["node", "--import", "tsx", "src/main.ts" if image == x.API_IMAGE else "src/worker/worker.main.ts"]}


def container_value(owned):
    return {"id": owned["id"], "image": owned["image"], "name": "/" + owned["name"],
            "status": "created", "running": False, "paused": False, "restarting": False, "dead": False,
            "started": r.ZERO_TIME, "finished": r.ZERO_TIME, "mounts": 0, "binds": 0, "tmpfs": 0,
            "devices": 0, "privileged": False, "readonly": True, "network": "none", "user": "65532:65532",
            "workdir": "/app/server/api", "entrypoint": ["/bin/false"], "cmd": None,
            "path": "/bin/false", "args": [], "caps": ["ALL"], "security": ["no-new-privileges:true"],
            "restart": "no", "health": ["NONE"], "ownLabel": r.LABEL_VALUE}


class FakeRunner:
    def __init__(self, deadline=None):
        self.deadline = deadline or time.monotonic() + 120
        self.calls = []
        self.worker_id = "b" * 64
        self.collision = False
        self.image_change = {}
        self.guard_change = {}
        self.failure = None
        self.cp_count = 0
        self.bad_archive = False
        self.remove_failure = False

    def run(self, argv, seconds, cap):
        self.calls.append(list(argv))
        if self.failure and self.failure(argv):
            raise r.Refusal("CLIENT_FAILED", True)
        if argv[:3] == ["docker", "container", "ls"]:
            return b"c" * 64 + b"\n" if self.collision else b""
        if argv[:3] == ["docker", "image", "inspect"]:
            return r.encoded(dict(image_value(argv[-1]), **self.image_change))
        if argv[:2] == ["docker", "create"]:
            return (self.worker_id + "\n").encode()
        if argv[:3] == ["docker", "container", "inspect"]:
            role = "api" if argv[-1] == x.API_ID else "worker"
            owned = {"id": argv[-1], "image": x.API_IMAGE if role == "api" else x.WORKER_IMAGE,
                     "name": x.API_NAME if role == "api" else x.WORKER_NAME}
            return r.encoded(dict(container_value(owned), **self.guard_change))
        if argv[:2] == ["docker", "cp"]:
            self.cp_count += 1
            path = argv[2].split(":", 1)[1]
            return archive(path, kind=tarfile.SYMTYPE if self.bad_archive else tarfile.REGTYPE)
        if argv[:2] == ["docker", "rm"]:
            if self.remove_failure:
                raise r.Refusal("CLIENT_TIMEOUT", True)
            return (argv[-1] + "\n").encode()
        raise AssertionError("Unexpected synthetic operation")


class FixedSliceTests(unittest.TestCase):
    def candidate(self):
        runner, output = FakeRunner(), MemoryOutput()
        return runner, output, Slice(runner, output, authorize_retained=True)

    def args(self):
        return ["--read-old-storage-frontier", "--authorize-exact-retained-public-read",
                "--accept-historical-own-build-provenance", "--confirm-independent-command-source-review",
                "--source-sha256", hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                "--r4-source-sha256", x.R4_SHA256, "--output", x.OUTPUT_ROOT,
                "--max-files", "28", "--max-file-bytes", "2097152", "--max-total-bytes", "25165824",
                "--overall-seconds", "120"]

    def invoke(self, runner, output):
        with patch.object(r, "Runner", return_value=runner), patch.object(r, "Output", return_value=output), \
                patch.object(x, "load_primitives", return_value=r):
            return x.reviewed_cli(self.args(), runner.deadline)

    def test_exact_frontier16_plus_candidate6_api_and6_worker_no_recopy_or_widening(self):
        expected = tuple(x.ROOT + name for name in (
            'auth/auth.module.ts', 'ledger/ledger.module.ts', 'ledger/ledger-store.ts',
            'security/security.module.ts', 'oci/oci.module.ts', 'oci/oci-resolver.ts',
            'scans/scans.controller.ts', 'scans/browser-scans.controller.ts', 'scans/scans.service.ts',
            'oci/nginx-local-profile.ts', 'llm/llm.controller.ts', 'llm/browser-identity.ts',
            'llm/report-context.ts', 'llm/llm.service.ts', 'llm/llm-exception.filter.ts', 'llm/quota-runtime.ts'))
        self.assertEqual(x.API_FRONTIER, expected)
        self.assertEqual(x.API_STORAGE_LEADS, tuple(x.ROOT + name for name in (
            'auth/auth.store.ts', 'ledger/ledger.ts', 'ledger/schema.ts',
            'llm/quota-ledger.ts', 'llm/quota-policy.ts', 'llm/policy.ts')))
        self.assertEqual(x.PATHS['worker'], tuple(x.ROOT + name for name in (
            'worker/nginx-local-worker.main.ts', 'worker/worker-runtime.ts', 'worker/outbox-consumer.ts',
            'ledger/ledger.ts', 'ledger/schema.ts')) + ('/app/server/api/package.json',))
        self.assertEqual(sum(map(len, x.PATHS.values())), 28)
        self.assertEqual(len(x.PATHS['api']), 22)
        self.assertEqual(len(x.PATHS['worker']), 6)
        prior_api = {'/app/server/api/package.json', '/app/server/api/tsconfig.json',
                     x.ROOT + 'oci/nginx-local.main.ts', x.ROOT + 'oci/nginx-local.module.ts'}
        self.assertFalse(prior_api & set(x.PATHS['api']))
        for paths in x.PATHS.values():
            self.assertEqual(len(paths), len(set(paths)))
            self.assertTrue(set(paths) <= r.PUBLIC_PATHS)
        runner, output, acquisition = self.candidate()
        with self.assertRaises(r.Refusal):
            acquisition.acquire_file({"role": "api"}, r.SOURCE_ROOT + "worker/archive-process.ts", [])
        self.assertEqual(runner.calls, [])
        for excluded in (x.ROOT + 'parent-ingress.ts', x.ROOT + 'runtime/runtime-api.module.ts',
                         x.ROOT + 'llm/history-store.ts', x.ROOT + 'main/nginx-local-worker.main.ts'):
            with self.subTest(excluded=excluded), self.assertRaises(r.Refusal):
                acquisition.acquire_file({'role': 'api'}, excluded, [])
        self.assertEqual(runner.calls, [])
        with self.assertRaises(r.Refusal):
            Slice(runner, output)

    def test_success_retained_never_created_removed_or_lexed(self):
        runner, output, acquisition = self.candidate()
        with patch.object(r, "import_specifiers", side_effect=AssertionError("NO_LEXER")), \
                patch.object(r, "tokens", side_effect=AssertionError("NO_LEXER")):
            result = acquisition.run()
        requests = [(call[2].split(":", 1)[0], call[2].split(":", 1)[1]) for call in runner.calls if call[1] == "cp"]
        self.assertEqual(requests, [(x.API_ID, path) for path in x.PATHS["api"]] +
                         [(runner.worker_id, path) for path in x.PATHS["worker"]])
        creates = [call for call in runner.calls if call[1] == "create"]
        self.assertEqual(creates, [r.create_argv(x.WORKER_IMAGE, x.WORKER_NAME)])
        self.assertEqual([call for call in runner.calls if call[1] == "rm"], [["docker", "rm", runner.worker_id]])
        for flag in x.FLAGS:
            self.assertFalse(result[flag])
        self.assertFalse(result["retainedApiRemovalAuthorized"])
        for call in runner.calls:
            self.assertNotIn(call[1], ("run", "start", "exec", "stop", "kill", "compose", "pull", "save", "export", "build"))
            self.assertFalse(set(call) & {"--env", "--mount", "--volume", "--volumes", "--force", "-f", "-v"})
        self.assertEqual(len([key for key in output.files if key[0].startswith("member-")]), 28)
        for index, call in enumerate(runner.calls):
            if call[1] == "cp":
                previous = runner.calls[index - 1]
                self.assertEqual(previous[:3], ["docker", "container", "inspect"])
                self.assertEqual(previous[-1], call[2].split(":", 1)[0])
                self.assertEqual(previous[4], Slice.container_format)
        api_ledger = output.files[("api", "server", "api", "src", "ledger", "ledger.ts")]
        self.assertEqual(api_ledger, output.files[("worker", "server", "api", "src", "ledger", "ledger.ts")])
        self.assertEqual(sum(path.endswith("ledger/ledger.ts") for _, path in requests), 2)

    def test_new_projection_is_exact_full_r4_schema_with_index_lookups(self):
        fmt = Slice.container_format
        self.assertEqual(fmt, r.CONTAINER_FORMAT)
        self.assertIn('(eq (json (index . "Mounts")) "null") '
                      '(eq (json (index . "Mounts")) "[]")}}0{{else}}-1{{end}}', fmt)
        for field in ('Binds', 'Tmpfs', 'Devices'):
            self.assertIn('(index .HostConfig "' + field + '")', fmt)
        self.assertIn('{{with (index .Config "Labels")}}{{json (index . "dip.public-source-extraction")}}', fmt)
        self.assertIn('"health":{{with (index .Config "Healthcheck")}}{{json (index . "Test")}}{{else}}null{{end}}', fmt)
        for forbidden in (".Env", ".History", '["NONE"]', 'len .Mounts', '.Config.Labels',
                          '.Config.Healthcheck', '.HostConfig.Binds', '.HostConfig.Tmpfs', '.HostConfig.Devices'):
            self.assertNotIn(forbidden, fmt)
        # Text/model assertions only. No claim of actual Go serialization.
        self.assertEqual(x.R4_SHA256, hashlib.sha256(SOURCE.with_name("extract_old_image_sources.py").read_bytes()).hexdigest())

    def test_full_api_guard_refuses_identity_started_mount_capability_health(self):
        changes = ({"id": "c" * 64}, {"name": "/foreign"}, {"image": x.WORKER_IMAGE},
                   {"ownLabel": "foreign"}, {"status": "exited"}, {"running": True},
                   {"started": "2026-10-12T00:00:00Z"}, {"finished": "2026-10-12T00:00:00Z"},
                   {"mounts": -1}, {"binds": 1}, {"tmpfs": 1}, {"devices": 1}, {"mounts": False},
                   {"caps": []}, {"security": []}, {"readonly": False}, {"network": "bridge"},
                   {"privileged": True}, {"health": None}, {"health": ["CMD", "probe"]}, {"entrypoint": ["node"]})
        for change in changes:
            runner, output, acquisition = self.candidate()
            runner.guard_change = change
            with self.subTest(change=change), self.assertRaises(r.Refusal) as raised:
                acquisition.run()
            self.assertEqual(raised.exception.code, "OWN_CONTAINER_GUARD")
            self.assertFalse(any(call[1] in ("cp", "create", "rm") for call in runner.calls))

    def test_collision_and_image_volumes_stop_before_copy_or_create(self):
        for mode in ("collision", "volumes"):
            runner, output, acquisition = self.candidate()
            if mode == "collision":
                runner.collision = True
            else:
                runner.image_change = {"volumes": {"/data": {}}}
            with self.subTest(mode=mode), self.assertRaises(r.Refusal):
                acquisition.run()
            self.assertFalse(any(call[1] in ("cp", "create", "rm") for call in runner.calls))

    def test_missing_frontier_file_keeps_exact_pending_prefix_and_no_cleanup_or_skip(self):
        runner, output = FakeRunner(), MemoryOutput()
        missing = x.ROOT + 'security/security.module.ts'
        self.assertEqual(x.API_FRONTIER[3], missing)
        runner.failure = lambda argv: argv[1] == "cp" and argv[2].endswith(missing)
        result = self.invoke(runner, output)
        receipt = json.loads(output.files[("refusal.json",)])
        self.assertEqual(result["reasonCode"], "CLIENT_FAILED")  # Never infer missing vs other client causes.
        self.assertTrue(result["ambiguous"])
        self.assertEqual(receipt["operation"]["kind"], "cp")
        self.assertEqual(receipt["operation"]["path"], missing)
        copied = [call[2].split(':', 1)[1] for call in runner.calls if call[1] == 'cp']
        self.assertEqual(copied, list(x.API_FRONTIER[:4]))
        self.assertEqual([member['path'] for member in receipt['completedInventory']], list(x.API_FRONTIER[:3]))
        self.assertEqual(receipt["operation"]["containerId"], x.API_ID)
        self.assertEqual(receipt["counters"]["completedMembers"], 3)
        self.assertEqual(len(receipt["completedInventory"]), 3)
        self.assertIn(("member-0003.json",), output.files)
        pending = json.loads(output.files[(f"attribution-{receipt['lastDurableAttribution']:04d}.json",)])
        self.assertEqual(pending["operation"], receipt["operation"])
        self.assertFalse(any(call[1] in ("create", "rm") for call in runner.calls))

    def test_member_receipt_committed_before_subsequent_copy(self):
        runner, output, acquisition = self.candidate()
        original = runner.run

        def ordered(argv, seconds, cap):
            if argv[1] == "cp" and runner.cp_count:
                self.assertIn((f"member-{runner.cp_count:04d}.json",), output.files)
            return original(argv, seconds, cap)

        runner.run = ordered
        acquisition.run()
        for index, member in enumerate(acquisition.inventory, 1):
            self.assertEqual(json.loads(output.files[(f"member-{index:04d}.json",)])["member"], member)

    def test_unsafe_tar_is_distinct_from_client_failure(self):
        runner, output = FakeRunner(), MemoryOutput()
        runner.bad_archive = True
        result = self.invoke(runner, output)
        self.assertEqual(result["reasonCode"], "UNSAFE_ARCHIVE")
        self.assertFalse(result["ambiguous"])
        receipt = json.loads(output.files[("refusal.json",)])
        self.assertEqual(receipt["operation"]["kind"], "archive_validate")
        self.assertEqual(receipt["counters"]["completedMembers"], 0)
        self.assertFalse(any(call[1] in ("create", "rm") for call in runner.calls))

    def test_tighter_count_total_and_deadline_stop(self):
        for mode, reason in (("count", "FILE_COUNT_BOUND"), ("total", "TOTAL_BYTE_BOUND"), ("deadline", "DEADLINE")):
            runner, output, acquisition = self.candidate()
            owned = {"role": "api", "id": x.API_ID, "image": x.API_IMAGE, "name": x.API_NAME}
            if mode == "count":
                acquisition.count = 28
            elif mode == "total":
                acquisition.total = x.MAX_TOTAL_BYTES
            else:
                runner.deadline = time.monotonic() - 1
            with self.subTest(mode=mode), self.assertRaises(r.Refusal) as raised:
                acquisition.acquire_file(owned, x.PATHS["api"][0], [])
            self.assertEqual(raised.exception.code, reason)
            self.assertFalse(any(call[1] in ("create", "rm") for call in runner.calls))
            if mode != "total":
                self.assertEqual(runner.calls, [])

    def test_fresh_worker_guard_failure_retains_exact_id_without_copy_or_cleanup(self):
        runner, output = FakeRunner(), MemoryOutput()
        original = runner.run

        def changed_worker(argv, seconds, cap):
            if argv[:3] == ["docker", "container", "inspect"] and argv[-1] == runner.worker_id:
                runner.guard_change = {"running": True}
            return original(argv, seconds, cap)

        runner.run = changed_worker
        result = self.invoke(runner, output)
        self.assertEqual(result["reasonCode"], "OWN_CONTAINER_GUARD")
        self.assertFalse(any(call[1] == "rm" for call in runner.calls))
        self.assertFalse(any(call[1] == "cp" and call[2].startswith(runner.worker_id + ":") for call in runner.calls))
        receipt = json.loads(output.files[("refusal.json",)])
        self.assertEqual(receipt["containers"][1]["id"], runner.worker_id)
        self.assertEqual(receipt["containers"][1]["disposition"], "created_unqualified")
        self.assertEqual(receipt["counters"]["completedMembers"], len(x.PATHS["api"]))

    def test_worker_id_ambiguity_and_removal_failure_never_touch_api(self):
        for bad_id in (True, False):
            runner, output = FakeRunner(), MemoryOutput()
            if bad_id:
                runner.worker_id = x.API_ID
            else:
                runner.remove_failure = True
            result = self.invoke(runner, output)
            self.assertEqual(result["reasonCode"], "CREATE_ID_AMBIGUOUS" if bad_id else "CLIENT_TIMEOUT")
            removals = [call for call in runner.calls if call[1] == "rm"]
            self.assertEqual(removals, [] if bad_id else [["docker", "rm", runner.worker_id]])
            self.assertFalse(any(call[-1] == x.API_ID for call in removals))
            self.assertTrue(result["ambiguous"])
            if not bad_id:
                receipt = json.loads(output.files[("refusal.json",)])
                self.assertEqual(receipt["containers"][1]["disposition"], "removal_pending")

    def test_cli_exact_authority_pins_bounds_and_output_no_docker_on_rejection(self):
        cases = ([], [arg for arg in self.args() if arg != "--authorize-exact-retained-public-read"],
                 self.args() + ["--container-id", x.API_ID], self.args()[:-1] + ["121"],
                 ["/private/tmp/foreign" if arg == x.OUTPUT_ROOT else arg for arg in self.args()],
                 ["0" * 64 if arg == x.R4_SHA256 else arg for arg in self.args()],
                 ["/private/tmp/dip-old-public-storage-slice-20261012" if arg == x.OUTPUT_ROOT else arg for arg in self.args()],
                 ["--r3-source-sha256" if arg == "--r4-source-sha256" else arg for arg in self.args()],
                 ["/private/tmp/dip-old-public-storage-slice-20261012-r2" if arg == x.OUTPUT_ROOT else arg for arg in self.args()],
                 ["--read-old-storage-sources" if arg == "--read-old-storage-frontier" else arg for arg in self.args()],
                 ["48" if arg == "28" else arg for arg in self.args()])
        with patch.object(x, "load_primitives", side_effect=AssertionError("no primitive I/O")):
            for args in cases:
                with self.subTest(args=args), self.assertRaises(x.Hold):
                    x.reviewed_cli(args, time.monotonic() + 120)
        with patch.object(x, "public_bytes", side_effect=x.Hold("SOURCE_PIN_MISMATCH")), \
                patch.object(x, "load_primitives", side_effect=AssertionError("no primitive I/O")):
            with self.assertRaises(x.Hold):
                x.reviewed_cli(self.args(), time.monotonic() + 120)

    def test_fresh_output_collision_no_reuse_and_closed_receipt(self):
        runner = FakeRunner()
        with patch.object(x, "load_primitives", return_value=r), patch.object(r, "Runner", return_value=runner), \
                patch.object(r, "Output", side_effect=r.Refusal("OUTPUT_COLLISION_OR_UNSAFE_PARENT")):
            result = x.reviewed_cli(self.args(), runner.deadline)
        self.assertEqual(result["reasonCode"], "OUTPUT_COLLISION_OR_UNSAFE_PARENT")
        self.assertEqual(runner.calls, [])

    def test_alarm_reason_and_failed_member_commit_keep_attribution(self):
        class FailedCommit(MemoryOutput):
            def write(self, parts, data):
                if parts == ("member-0002.json",):
                    raise OSError("CANARY_RAW_DIAGNOSTIC")
                super().write(parts, data)

        runner, output = FakeRunner(), FailedCommit()
        result = self.invoke(runner, output)
        receipt = json.loads(output.files[("refusal.json",)])
        self.assertEqual(result["reasonCode"], "OUTPUT_IO")
        self.assertEqual(receipt["counters"]["validatedFiles"], 2)
        self.assertEqual(receipt["counters"]["completedMembers"], 1)
        self.assertNotIn("CANARY_RAW_DIAGNOSTIC", json.dumps(receipt))
        runner, output = FakeRunner(), MemoryOutput()
        with patch.object(Slice, "run", side_effect=x.Hold("DEADLINE", True)):
            # invoke constructs a new class; patch factory instead for this probe.
            with patch.object(x, "acquisition_type", return_value=Slice):
                result = self.invoke(runner, output)
        self.assertEqual(result["reasonCode"], "DEADLINE")
        self.assertEqual(json.loads(output.files[("refusal.json",)])["reasonCode"], "DEADLINE")

    def test_definition_only_pin_tamper_and_closed_console(self):
        with patch.object(x.os, "open", side_effect=AssertionError("definition-only")), \
                patch.object(r.subprocess, "Popen", side_effect=AssertionError("no subprocess")):
            namespace = {"__name__": "synthetic_inert_reader", "__file__": str(SOURCE)}
            exec(compile(SOURCE.read_bytes(), str(SOURCE), "exec"), namespace)
        with patch.object(x, "public_bytes", side_effect=x.Hold("SOURCE_PIN_MISMATCH")):
            with self.assertRaises(x.Hold):
                x.load_primitives()
        console, diagnostics = io.StringIO(), io.StringIO()
        with patch.object(x, "cli", side_effect=RuntimeError("CANARY_RAW_DIAGNOSTIC")), \
                contextlib.redirect_stdout(console), contextlib.redirect_stderr(diagnostics):
            self.assertEqual(x.main(), 1)
        self.assertEqual(json.loads(console.getvalue())["reasonCode"], "UNEXPECTED_FAILURE")
        self.assertNotIn("CANARY_RAW_DIAGNOSTIC", console.getvalue())
        self.assertEqual(diagnostics.getvalue(), "")

    def test_source_compile_whitespace_and_no_global_primitives_mutation(self):
        for path in (SOURCE, Path(__file__)):
            text = path.read_text()
            ast.parse(text, filename=str(path))
            compile(text, str(path), "exec")
            self.assertFalse(any(line.rstrip() != line for line in text.splitlines()))
        self.assertEqual(Slice.container_format, r.CONTAINER_FORMAT)  # Reader does not mutate R4 definitions.
        self.assertTrue(x.OUTPUT_ROOT.endswith('-frontier'))
        self.assertEqual(r.MAX_FILES, 96)
        self.assertEqual(r.OVERALL_SECONDS, 180)
        self.assertEqual(x.MAX_FILES, 28)
        self.assertEqual(x.OVERALL_SECONDS, 120)


if __name__ == "__main__":
    with patch.object(r.subprocess, "Popen", side_effect=AssertionError("REAL_SUBPROCESS_FORBIDDEN")):
        unittest.main()
