#!/usr/bin/env python3
"""Fixed PUBLIC storage-frontier candidate, not a startup/compatibility certificate.

Definition-only import performs no I/O. Explicit CLI authority permits only the
retained419 API full ID and one fresh never-started worker helper. No API removal,
recursive discovery, source execution, private input or checkout substitution.
Historical OWN public-build provenance and independent literal review are external
prerequisites; 426/427's identity observation alone grants no read authority.
"""

import argparse
import hashlib
import json
import os
import signal
import stat
import time
from pathlib import Path
from types import ModuleType

R4_SHA256 = "195c200b0a6a4dd56ca31b7e88dd1100795fb9f693e413b2cf7a0fe57c222e36"
API_ID = "0feffefa7d0403c9ebf235008bef00158ef65c555e1b744cdccb663e7bdab92f"
API_IMAGE = "sha256:487c3909d3eeee08d60840a81c1adeb61c292aee0a31df17b2a8cf92f6dbb58c"
API_NAME = "dip-old-api-public-source-20261011-compat"
WORKER_IMAGE = "sha256:8748cbebba753603d79f320c2fb476c46ab676ce12e0aa08bee0021a3e14e57a"
WORKER_NAME = "dip-old-worker-storage-slice-20261012"
OUTPUT_ROOT = "/private/tmp/dip-old-public-storage-slice-20261012-frontier"
MAX_FILES = 28
MAX_FILE_BYTES = 2097152
MAX_TOTAL_BYTES = 25165824
OVERALL_SECONDS = 120
ROOT = "/app/server/api/src/"
# 447's observed OLD module literal imports, in order, mapped to reviewed TS leads.
# These are NOT a proof of leaf existence, competing-JS absence or loader behavior.
# Never recopy/read/adopt the four prior API members or their old packet roots.
API_FRONTIER = tuple(ROOT + name for name in (
    "auth/auth.module.ts", "ledger/ledger.module.ts", "ledger/ledger-store.ts",
    "security/security.module.ts", "oci/oci.module.ts", "oci/oci-resolver.ts",
    "scans/scans.controller.ts", "scans/browser-scans.controller.ts", "scans/scans.service.ts",
    "oci/nginx-local-profile.ts", "llm/llm.controller.ts", "llm/browser-identity.ts",
    "llm/report-context.ts", "llm/llm.service.ts", "llm/llm-exception.filter.ts", "llm/quota-runtime.ts",
))
# Six additional known PUBLIC storage leads, explicitly CANDIDATES. OLD presence
# and authority-changing reachability remain UNPROVEN until actual-byte review.
API_STORAGE_LEADS = tuple(ROOT + name for name in (
    "auth/auth.store.ts", "ledger/ledger.ts", "ledger/schema.ts",
    "llm/quota-ledger.ts", "llm/quota-policy.ts", "llm/policy.ts",
))
# Independent worker-image candidates, not inferred OLD graph/authority facts.
WORKER_SOURCES = tuple(ROOT + name for name in (
    "worker/nginx-local-worker.main.ts", "worker/worker-runtime.ts", "worker/outbox-consumer.ts",
    "ledger/ledger.ts", "ledger/schema.ts",
))
WORKER_METADATA = ("/app/server/api/package.json",)
PATHS = {"api": API_FRONTIER + API_STORAGE_LEADS, "worker": WORKER_SOURCES + WORKER_METADATA}
FLAGS = {"startupQualified": False, "fullSourceClosureQualified": False,
         "semanticClosureQualified": False, "installedDependenciesQualified": False,
         "storageCompatibilityQualified": False, "provenanceIndependentlyEstablishedByReader": False}


class Hold(Exception):
    """Only local constant codes; Engine failures use pinned R4's closed vocabulary."""

    def __init__(self, code, ambiguous=False):
        if code not in {"CLI_USAGE", "REVIEW_BINDING_REQUIRED", "SOURCE_PIN_MISMATCH",
                        "DEADLINE", "OUTPUT_IO", "UNEXPECTED_FAILURE"}:
            code, ambiguous = "UNEXPECTED_FAILURE", True
        self.code, self.ambiguous = code, bool(ambiguous)
        super().__init__(code)


def public_bytes(path, expected):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_FILE_BYTES:
                raise Hold("SOURCE_PIN_MISMATCH")
            with os.fdopen(fd, "rb", closefd=False) as handle:
                data = handle.read(MAX_FILE_BYTES + 1)
        finally:
            os.close(fd)
        if len(data) > MAX_FILE_BYTES or hashlib.sha256(data).hexdigest() != expected:
            raise Hold("SOURCE_PIN_MISMATCH")
        return data
    except OSError:
        raise Hold("SOURCE_PIN_MISMATCH", True) from None


def load_primitives():
    path = Path(__file__).absolute().with_name("extract_old_image_sources.py")
    data = public_bytes(path, R4_SHA256)
    module = ModuleType("pinned_r4_storage_primitives")
    module.__file__ = str(path)
    # Execute ONLY the hash-verified definition-only Python author module, not its
    # __main__, any image code, application module, lexer, or persistent bytecode.
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module


def acquisition_type(r):
    # R4 directly supplies the index-based optional-key projection. Preserve its
    # FULL schema; no wrapper rewrite, fallback guard or extra coercion.
    if (r.API_IMAGE != API_IMAGE or r.WORKER_IMAGE != WORKER_IMAGE
            or r.MAX_FILE_BYTES != MAX_FILE_BYTES or r.MAX_TOTAL_BYTES != MAX_TOTAL_BYTES
            or sum(map(len, PATHS.values())) > MAX_FILES
            or any(len(paths) != len(set(paths)) or not set(paths) <= r.PUBLIC_PATHS for paths in PATHS.values())):
        raise Hold("SOURCE_PIN_MISMATCH")
    projection = r.CONTAINER_FORMAT

    class StorageSlice(r.Acquisition):
        container_format = projection

        def __init__(self, runner, output, *, authorize_retained=False):
            if authorize_retained is not True:
                r.refuse("REVIEW_BINDING_REQUIRED")
            super().__init__(runner, output)

        def guard(self, owned, path=None):
            self.pending("container_inspect", owned, path)
            expected = {"api": (API_ID, API_IMAGE, API_NAME),
                        "worker": (owned["id"], WORKER_IMAGE, WORKER_NAME)}
            if (owned["role"] not in expected or
                    (owned["id"], owned["image"], owned["name"]) != expected[owned["role"]]
                    or not r.FULL_ID.fullmatch(owned["id"] or "")
                    or (owned["role"] == "worker" and owned["id"] == API_ID)):
                r.refuse("OWN_ID_GUARD")
            data = self.runner.run(["docker", "container", "inspect", "--format", projection, owned["id"]],
                                   r.INSPECT_SECONDS, 16384)
            r.check_container(r.strict_json(data), owned)

        def acquire_file(self, owned, path, records):
            if path not in PATHS.get(owned["role"], ()):
                r.refuse("PATH_OUTSIDE_ALLOWLIST")
            self.pending("member_limit", owned, path)
            if self.count >= MAX_FILES:
                r.refuse("FILE_COUNT_BOUND")
            # R4 implements per-file tar bounds, byte ceilings, secure writes,
            # immutable pending/member receipts and calls OUR full guard per cp.
            return super().acquire_file(owned, path, records)

        def fixed_packet(self, owned):
            records = []
            for path in PATHS[owned["role"]]:
                self.acquire_file(owned, path, records)
            self.pending("graph_write", owned)
            self.output.write((owned["role"] + "-slice.json",), r.encoded({
                "role": owned["role"], "image": owned["image"], "containerId": owned["id"],
                "files": records, "fixedIntakeCollected": True, **FLAGS}))

        def run(self):
            api = {"role": "api", "id": API_ID, "image": API_IMAGE, "name": API_NAME,
                   "disposition": "retained_read_authorized_unqualified", "removalAuthorized": False}
            self.owned.append(api)
            worker = {"role": "worker", "id": None, "image": WORKER_IMAGE, "name": WORKER_NAME,
                      "disposition": "not_created", "removalAuthorized": True}
            self.phase = "preflight"
            self.pending("name_check", worker)
            collision = self.runner.run(["docker", "container", "ls", "--all", "--quiet", "--no-trunc",
                                        "--filter", "name=^/" + WORKER_NAME + "$"], r.INSPECT_SECONDS, 4096)
            if collision.strip():
                r.refuse("NAME_COLLISION")
            for owned, default in ((api, "src/main.ts"), (worker, "src/worker/worker.main.ts")):
                self.pending("image_inspect", owned)
                data = self.runner.run(["docker", "image", "inspect", "--format", r.IMAGE_FORMAT, owned["image"]],
                                       r.INSPECT_SECONDS, 16384)
                r.check_image(r.strict_json(data), owned["image"], default)
            self.phase = "api_retained_copy"
            self.guard(api)
            api["disposition"] = "retained_qualified_read_only"
            self.record(outcome="completed")
            self.fixed_packet(api)
            # Neither name adoption nor fabricated create success for retained API.
            self.phase = "worker_create"
            worker["disposition"] = "create_pending"
            self.owned.append(worker)
            self.pending("create", worker)
            reply = self.runner.run(r.create_argv(WORKER_IMAGE, WORKER_NAME), r.CREATE_SECONDS, 128)
            try:
                identifier = reply.decode("ascii").strip()
            except UnicodeError:
                raise r.Refusal("CREATE_ID_AMBIGUOUS", True) from None
            if not r.FULL_ID.fullmatch(identifier) or identifier == API_ID:
                raise r.Refusal("CREATE_ID_AMBIGUOUS", True)
            worker["id"], worker["disposition"] = identifier, "created_unqualified"
            self.record(outcome="completed")
            self.guard(worker)
            worker["disposition"] = "qualified_never_started"
            self.phase = "worker_copy"
            self.record(outcome="completed")
            self.fixed_packet(worker)
            self.phase = "worker_remove"
            self.guard(worker)
            worker["disposition"] = "removal_pending"
            self.pending("remove", worker)
            reply = self.runner.run(["docker", "rm", identifier], r.REMOVE_SECONDS, 128)
            if reply.strip() != identifier.encode("ascii"):
                raise r.Refusal("REMOVAL_AMBIGUOUS", True)
            worker["disposition"] = "removed"
            self.record(outcome="completed")
            self.phase = "complete_candidate"
            result = {"format": "old-public-storage-frontier-v1", "ok": True, **FLAGS,
                      "files": self.count, "bytes": self.total, "completedInventory": self.inventory,
                      "containers": self.owned, "retainedApiRemovalAuthorized": False,
                      "bounds": {"filesGlobal": MAX_FILES, "fileBytes": MAX_FILE_BYTES,
                                 "totalBytesGlobal": MAX_TOTAL_BYTES, "overallSeconds": OVERALL_SECONDS},
                      "limitations": ["fixed source leads are not a proven sufficient OLD storage slice",
                          "no lexer, import closure, loader or installed dependency qualification",
                          "API frontier16 are mapped leads from447, not proven leaf presence or loader resolution",
                          "six API storage and six worker leads remain OLD-presence-unproven candidates",
                          "all28 requests are mandatory; missing files STOP without skipping or substitution",
                          "transitive history/runtime use remains unknown; no current application code removed",
                          "unknown storage-affecting edges require independent actual-byte review",
                          "no private P2, authority fingerprint, schema compatibility or preservation proof",
                          "historical OWN public-build attribution is an external prerequisite"]}
            self.pending("candidate_write")
            self.output.write(("candidate.json",), r.encoded(result))
            return result

        def failure_receipt(self, error):
            fields = {"reasonCode": error.code, "ambiguous": error.ambiguous} if isinstance(error, Hold) else r.failure_fields(error)
            return {**super().failure_receipt(error), **fields, **FLAGS, "retainedApiRemovalAuthorized": False}

    return StorageSlice


class ClosedParser(argparse.ArgumentParser):
    def error(self, message):
        raise Hold("CLI_USAGE")


def reviewed_cli(argv, deadline):
    parser = ClosedParser(description=__doc__, allow_abbrev=False)
    for switch in ("read-old-storage-frontier", "authorize-exact-retained-public-read",
                   "accept-historical-own-build-provenance", "confirm-independent-command-source-review"):
        parser.add_argument("--" + switch, action="store_true", required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--r4-source-sha256", choices=(R4_SHA256,), required=True)
    parser.add_argument("--output", choices=(OUTPUT_ROOT,), required=True)
    for name, value in (("max-files", MAX_FILES), ("max-file-bytes", MAX_FILE_BYTES),
                        ("max-total-bytes", MAX_TOTAL_BYTES), ("overall-seconds", OVERALL_SECONDS)):
        parser.add_argument("--" + name, type=int, choices=(value,), required=True)
    args = parser.parse_args(argv)
    if len(args.source_sha256) != 64 or any(c not in "0123456789abcdef" for c in args.source_sha256):
        raise Hold("REVIEW_BINDING_REQUIRED")
    source = Path(__file__).absolute()
    public_bytes(source, args.source_sha256)
    r = load_primitives()
    factory = acquisition_type(r)
    try:
        output = r.Output(args.output, source.parents[3])
    except r.Refusal as error:
        return {"ok": False, "code": "HOLD", **r.failure_fields(error), **FLAGS,
                "manualReconciliationRequired": True, "retainedApiRemovalAuthorized": False}
    acquisition = factory(r.Runner(deadline), output, authorize_retained=args.authorize_exact_retained_public_read)
    failure = None
    try:
        acquisition.pending("review_assertion")
        output.write(("review-assertion.json",), r.encoded({
            "sourceSha256": args.source_sha256, "r4SourceSha256": R4_SHA256,
            "exactRetainedPublicReadAuthorizedByParent": True,
            "independentCommandSourceReviewConfirmedByParent": True,
            "historicalOwnBuildAcceptedByParent": True, "evidenceContentsVerifiedByReader": False}))
        acquisition.run()
        return {"ok": True, "code": "CANDIDATE_COLLECTED", **FLAGS, "retainedApiRemovalAuthorized": False}
    except Exception as error:
        failure = {"reasonCode": error.code, "ambiguous": error.ambiguous} if isinstance(error, Hold) else r.failure_fields(error)
        # ONE bounded refusal attempt, no retry or failure cleanup. Durable pending
        # and member prefixes remain when disk/fsync/deadline prevent this receipt.
        try:
            acquisition.checkpoint()
            output.write(("refusal.json",), r.encoded(acquisition.failure_receipt(error)))
        except Exception:
            pass
        return {"ok": False, "code": "HOLD", **failure, **FLAGS,
                "manualReconciliationRequired": True, "retainedApiRemovalAuthorized": False}
    finally:
        try:
            output.close()
        except OSError:
            if failure is None:
                raise Hold("OUTPUT_IO", True) from None


def cli(argv=None):
    def expired(signum, frame):
        raise Hold("DEADLINE", True)

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, OVERALL_SECONDS)
    try:
        return reviewed_cli(argv, time.monotonic() + OVERALL_SECONDS)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def main():
    try:
        receipt = cli()
    except Exception as error:
        fields = {"reasonCode": error.code, "ambiguous": error.ambiguous} if isinstance(error, Hold) else {
            "reasonCode": "UNEXPECTED_FAILURE", "ambiguous": True}
        receipt = {"ok": False, "code": "HOLD", **fields, **FLAGS,
                   "manualReconciliationRequired": True, "retainedApiRemovalAuthorized": False}
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
