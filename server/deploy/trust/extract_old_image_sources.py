#!/usr/bin/env python3
"""Inert, parent-review-only P1 candidate. Importing this module performs no I/O.

Historical OWN build provenance must be independently accepted BEFORE acquisition;
file names and hashes cannot establish it. Never starts a container or loads JS/TS.
The result is a bounded literal-relative-import candidate, NOT startup evidence,
installed dependency qualification, a full-source bundle, or a preservation proof.
Q1's actual narrow PASS is DIP-ARTF-411; do not rerun it through this program.
"""

import argparse
import hashlib
import json
import os
import posixpath
import re
import selectors
import signal
import stat
import subprocess
import time
from pathlib import Path

API_IMAGE = "sha256:487c3909d3eeee08d60840a81c1adeb61c292aee0a31df17b2a8cf92f6dbb58c"
WORKER_IMAGE = "sha256:8748cbebba753603d79f320c2fb476c46ab676ce12e0aa08bee0021a3e14e57a"
TARGETS = (
    ("api", API_IMAGE, "dip-old-api-public-source-20261011-compat", "oci/nginx-local.main.ts", "src/main.ts"),
    ("worker", WORKER_IMAGE, "dip-old-worker-public-source-20261011-compat", "worker/nginx-local-worker.main.ts", "src/worker/worker.main.ts"),
)
MAX_FILES = 96  # GLOBAL across both images, including public metadata (stricter than per-image).
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 24 * 1024 * 1024
OVERALL_SECONDS = 180
INSPECT_SECONDS = 10
CREATE_SECONDS = 15
COPY_SECONDS = 5
REMOVE_SECONDS = 5
TAR_OVERHEAD = 10240
SOURCE_ROOT = "/app/server/api/src/"
LABEL = "dip.public-source-extraction"
LABEL_VALUE = "20261011-compat"
ZERO_TIME = "0001-01-01T00:00:00Z"
FULL_ID = re.compile(r"[a-f0-9]{64}\Z")
SHA256 = FULL_ID

# Finite reviewed COPY-path leads, not evidence these old image bytes are public.
# Only reachable files are requested. Tests, fixtures, proofs, initializers, smoke
# programs and default app entrypoints are deliberately not acquisition candidates.
SOURCE_NAMES = frozenset("""
parent-ingress.ts
 auth/auth.controller.ts auth/auth.module.ts auth/auth.store.ts
 image-config/bounded-json.ts image-config/contract.ts image-config/index.ts
 image-config/policy.ts image-config/report-contract.ts image-config/result.ts
 image-config/user-rule.ts image-config/verified-input.ts
 ledger/ledger-store.ts ledger/ledger.module.ts ledger/ledger.ts ledger/schema.ts
 llm/browser-identity.ts llm/history-context.ts llm/history-contract.ts
 llm/history-delivery.ts llm/history-ingress.ts llm/history-runtime.ts
 llm/history-sources.ts llm/history-store.ts llm/history.service.ts
 llm/llm-exception.filter.ts llm/llm.controller.ts llm/llm.module.ts llm/llm.service.ts
 llm/openrouter-provider.ts llm/openrouter-transport.ts llm/policy.ts
 llm/prepared-request.ts llm/quota-ledger.ts llm/quota-policy.ts llm/quota-runtime.ts
 llm/report-context.ts llm/response.ts
 oci/archive-budget.ts oci/archive-identity.ts oci/bounded-image-archive.ts
 oci/gateway-transport.ts oci/layer-tar-validator.ts oci/nginx-candidate.ts
 oci/nginx-local-policy.ts oci/nginx-local-profile.ts oci/nginx-local.main.ts
 oci/nginx-local.module.ts oci/oci-resolver.ts oci/oci.module.ts
 oci/pinned-image-config.ts oci/registry-resolver.ts
 runtime/browser-runtime-identity.ts runtime/browser-runtime.controller.ts
 runtime/runtime-api.module.ts runtime/runtime-api.service.ts runtime/runtime-caller-journal.ts
 runtime/runtime-evidence.ts runtime/runtime-http.ts runtime/runtime-image-link.adapter.ts
 runtime/runtime-intake.ts runtime/runtime-json.ts runtime/runtime-sign.ts runtime/runtime-store.ts
 scans/browser-scans.controller.ts scans/image-reference.ts scans/image-search.ts
 scans/report-page.ts scans/report-query.ts scans/scan-readiness.ts scans/scan-request.ts
 scans/scans.config.browser.ts scans/scans.controller.ts scans/scans.module.ts scans/scans.service.ts
 security/identity.ts security/scan-auth.guard.ts security/security.module.ts
 worker/archive-process.ts worker/archive-result-contract.ts worker/archive-scan-worker.ts
 worker/archive-scratch.ts worker/cve-db-evidence.ts worker/cyclonedx-components.ts
 worker/image-config-runner.ts worker/nginx-local-worker.main.ts worker/outbox-consumer.ts
 worker/sbom-worker.ts worker/scan-worker.ts worker/scanner-errors.ts worker/secret-findings.ts
 worker/verify-vuln-db-release.ts worker/vuln-advisory.ts worker/vuln-db-bundle.ts
 worker/vuln-findings.ts worker/vuln-worker.ts worker/worker-runtime.ts
""".split())
METADATA_PATHS = (
    "/app/server/api/package.json", "/app/server/api/tsconfig.json",
    "/app/package.json", "/app/pnpm-workspace.yaml", "/app/pnpm-lock.yaml",
)
# Sourced in ledger.ts:14 and outbox-consumer.ts:7; within the known src COPY.
# This is the ONLY .mjs acquisition leaf, not generic extension/path permission.
MJS_SOURCE_NAMES = frozenset(("worker/cve-db-policy.mjs",))
PUBLIC_PATHS = (frozenset(SOURCE_ROOT + name for name in SOURCE_NAMES | MJS_SOURCE_NAMES)
                | frozenset(METADATA_PATHS))
# Public checkout import leads for DIAGNOSTICS ONLY. Never eligible for cp.
KNOWN_OUT_OF_SCOPE_PATHS = frozenset("/app/server/runtime/src/" + name for name in (
    "contract.ts", "live-port.ts", "dispatch-permit.ts", "runtime-json.ts", "operator-package.ts"))
MAX_ATTRIBUTION_EVENTS = 4096
REASON_CODES = frozenset("""
INVALID_JSON DEADLINE CLIENT_TIMEOUT OUTPUT_BOUND CLIENT_FAILED CLIENT_IO
ARCHIVE_BOUND INVALID_ARCHIVE UNSAFE_ARCHIVE FILE_BOUND EXTRA_OR_TRUNCATED_ARCHIVE
UNSUPPORTED_LEXICAL_FORM AMBIGUOUS_SLASH INVALID_SOURCE_TEXT INDIRECT_LOADER
NONLITERAL_OR_INDIRECT_IMPORT UNRESOLVED_IMPORT_SYNTAX UNRESOLVED_RELATIVE_IMPORT
IMPORT_OUTSIDE_ALLOWLIST UNREVIEWED_BUILTIN UNRESOLVED_EXTERNAL_IMPORT
UNSAFE_OUTPUT OUTPUT_INSIDE_CHECKOUT OUTPUT_COLLISION_OR_UNSAFE_PARENT OUTPUT_IO
IMAGE_GUARD OWN_CONTAINER_GUARD OWN_ID_GUARD PATH_OUTSIDE_ALLOWLIST FILE_COUNT_BOUND
TOTAL_BYTE_BOUND UNREVIEWED_LOADER_CONFIG UNREVIEWED_PACKAGE_CONFIG NAME_COLLISION
CREATE_ID_AMBIGUOUS REMOVAL_AMBIGUOUS CLI_USAGE REVIEW_BINDING_REQUIRED
SOURCE_PIN_MISMATCH ATTRIBUTION_BOUND RECURSION_BOUND UNEXPECTED_FAILURE
""".split())
OPERATION_KINDS = frozenset("""
name_check image_inspect create container_inspect member_limit cp archive_validate
member_write member_commit metadata_parse loader_config lexical_collect resolve_relative
external_import graph_write remove candidate_write review_assertion
""".split())
PACKAGES = frozenset(("@nestjs/common", "@nestjs/core", "@nestjs/platform-express",
                      "better-sqlite3", "drizzle-orm", "reflect-metadata", "rxjs", "tsx"))
BUILTINS = frozenset("assert assert/strict buffer child_process crypto events fs fs/promises http https net os path stream stream/promises timers timers/promises tls url util zlib".split())
TS_OPTIONS = {
    "target": "ES2022", "module": "NodeNext", "moduleResolution": "NodeNext",
    "strict": True, "esModuleInterop": True, "experimentalDecorators": True,
    "emitDecoratorMetadata": True, "skipLibCheck": True, "noEmit": True,
}
IMAGE_FORMAT = ('{"id":{{json .Id}},"os":{{json .Os}},"arch":{{json .Architecture}},'
                '"user":{{json .Config.User}},"workdir":{{json .Config.WorkingDir}},'
                '"volumes":{{json .Config.Volumes}},"entrypoint":{{json .Config.Entrypoint}},'
                '"cmd":{{json .Config.Cmd}}}')
# OWN created-container metadata only; never Env, History, full inspect or stand inspection.
# Nullable mount fields project 0 ONLY for null or their typed empty collection.
# Every other representation projects -1 (a rejection sentinel, NOT a count),
# avoiding len(nil), truthiness coercion and disclosure of collection contents.
# R4: index optional map keys so absence does not use strict dotted-key lookup.
# Missing health/label metadata projects null, never fabricated disabled/OWN values.
CONTAINER_FORMAT = ('{"id":{{json .Id}},"image":{{json .Image}},"name":{{json .Name}},'
    '"status":{{json .State.Status}},"running":{{json .State.Running}},'
    '"paused":{{json .State.Paused}},"restarting":{{json .State.Restarting}},'
    '"dead":{{json .State.Dead}},"started":{{json .State.StartedAt}},'
    '"finished":{{json .State.FinishedAt}},'
    '"mounts":{{if or (eq (json (index . "Mounts")) "null") (eq (json (index . "Mounts")) "[]")}}0{{else}}-1{{end}},'
    '"binds":{{if or (eq (json (index .HostConfig "Binds")) "null") (eq (json (index .HostConfig "Binds")) "[]")}}0{{else}}-1{{end}},'
    '"tmpfs":{{if or (eq (json (index .HostConfig "Tmpfs")) "null") (eq (json (index .HostConfig "Tmpfs")) "{}")}}0{{else}}-1{{end}},'
    '"devices":{{if or (eq (json (index .HostConfig "Devices")) "null") (eq (json (index .HostConfig "Devices")) "[]")}}0{{else}}-1{{end}},'
    '"privileged":{{json .HostConfig.Privileged}},'
    '"readonly":{{json .HostConfig.ReadonlyRootfs}},"network":{{json .HostConfig.NetworkMode}},'
    '"user":{{json .Config.User}},"workdir":{{json .Config.WorkingDir}},'
    '"entrypoint":{{json .Config.Entrypoint}},"cmd":{{json .Config.Cmd}},'
    '"path":{{json .Path}},"args":{{json .Args}},"caps":{{json .HostConfig.CapDrop}},'
    '"security":{{json .HostConfig.SecurityOpt}},"restart":{{json .HostConfig.RestartPolicy.Name}},'
    '"health":{{with (index .Config "Healthcheck")}}{{json (index . "Test")}}{{else}}null{{end}},'
    '"ownLabel":{{with (index .Config "Labels")}}{{json (index . "dip.public-source-extraction")}}{{else}}null{{end}}}')


class Refusal(Exception):
    """Closed codes only: never propagate raw input, subprocess or parser diagnostics."""

    def __init__(self, code, ambiguous=False):
        if code not in REASON_CODES:
            code, ambiguous = "UNEXPECTED_FAILURE", True
        super().__init__(code)
        self.code = code
        self.ambiguous = bool(ambiguous)


def refuse(code):
    raise Refusal(code)


def failure_fields(error):
    if isinstance(error, Refusal):
        return {"reasonCode": error.code, "ambiguous": error.ambiguous}
    if isinstance(error, RecursionError):
        return {"reasonCode": "RECURSION_BOUND", "ambiguous": False}
    if isinstance(error, OSError):
        return {"reasonCode": "OUTPUT_IO", "ambiguous": True}
    return {"reasonCode": "UNEXPECTED_FAILURE", "ambiguous": True}


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                refuse("INVALID_JSON")
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: refuse("INVALID_JSON"))
    except (ValueError, UnicodeError, RecursionError):
        refuse("INVALID_JSON")


class Runner:
    """Bounded pipes; DEVNULL stderr/stdin, no shell, kill OWN client group only.

    Client cancellation is NOT daemon cancellation; ambiguity must retain attribution.
    The global deadline also applies to cleanup. No retries or separate rescue budget.
    """

    def __init__(self, deadline):
        self.deadline = deadline

    def run(self, argv, seconds, cap):
        remaining = min(seconds, self.deadline - time.monotonic())
        if remaining <= 0:
            raise Refusal("DEADLINE", True)
        process = None
        try:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, shell=False, start_new_session=True)
            end = min(self.deadline, time.monotonic() + remaining)
            output = bytearray()
            with selectors.DefaultSelector() as selector:
                os.set_blocking(process.stdout.fileno(), False)
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    wait = end - time.monotonic()
                    if wait <= 0:
                        raise Refusal("CLIENT_TIMEOUT", True)
                    for key, _ in selector.select(wait):
                        block = os.read(key.fd, min(65536, cap - len(output) + 1))
                        if not block:
                            selector.unregister(key.fileobj)
                        else:
                            output.extend(block)
                            if len(output) > cap:
                                raise Refusal("OUTPUT_BOUND", True)
                wait = end - time.monotonic()
                if wait <= 0:
                    raise Refusal("CLIENT_TIMEOUT", True)
                status = process.wait(timeout=wait)
            if status != 0:
                raise Refusal("CLIENT_FAILED", True)
            return bytes(output)
        except subprocess.TimeoutExpired:
            raise Refusal("CLIENT_TIMEOUT", True) from None
        except OSError:
            raise Refusal("CLIENT_IO", True) from None
        finally:
            if process is not None:
                # Kill the client group even when the leader exited but descendants
                # retained a pipe. This cannot remove/cancel any daemon resource.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if process.stdout is not None:
                    process.stdout.close()
                try:
                    process.wait(timeout=max(0, min(0.1, self.deadline - time.monotonic())))
                except subprocess.TimeoutExpired:
                    pass


def single_file_tar(raw, path):
    """One short-name ordinary USTAR member; no tar extraction APIs or extensions.

    PAX/GNU extensions, links, prefixes, extra members and nonzero trailers refuse.
    Docker-version archive representation still requires independent qualification.
    """
    if path not in PUBLIC_PATHS or len(raw) > MAX_FILE_BYTES + TAR_OVERHEAD:
        refuse("ARCHIVE_BOUND")
    if len(raw) < 1536 or len(raw) % 512:
        refuse("INVALID_ARCHIVE")
    header = raw[:512]

    def octal(field):
        value = field.strip(b" \0")
        if not value or not re.fullmatch(b"[0-7]+", value):
            refuse("INVALID_ARCHIVE")
        return int(value, 8)

    checksum = octal(header[148:156])
    if checksum != sum(header[:148]) + 8 * 32 + sum(header[156:]):
        refuse("INVALID_ARCHIVE")
    expected = posixpath.basename(path).encode("ascii")
    if (header[:100] != expected.ljust(100, b"\0") or header[156:157] not in (b"0", b"\0")
            or any(header[157:257]) or any(header[345:500])
            or header[257:263] != b"ustar\0" or header[263:265] != b"00"):
        refuse("UNSAFE_ARCHIVE")
    size = octal(header[124:136])
    if size > MAX_FILE_BYTES:
        refuse("FILE_BOUND")
    end = 512 + ((size + 511) // 512) * 512
    if len(raw) < end + 1024 or any(raw[512 + size:]):
        refuse("EXTRA_OR_TRUNCATED_ARCHIVE")
    return raw[512:512 + size]


def tokens(text):
    """Small conservative lexical collector, not a TypeScript compiler/parser.

    Comments/string text do not create edges. Template interpolations ARE scanned.
    Unsupported lexical/loader constructs refuse; no application evaluation occurs.
    Independent review must still consider indirect loaders and non-import resources.
    """
    result = []
    expression_closes = set()
    length = len(text)

    def quoted(i, quote):
        start = i + 1
        i = start
        escaped = False
        while i < length:
            if text[i] == "\\":
                escaped = True
                i += 2
            elif text[i] == quote:
                return i + 1, ("escaped" if escaped else "string", text[start:i])
            elif text[i] in "\r\n":
                refuse("UNSUPPORTED_LEXICAL_FORM")
            else:
                i += 1
        refuse("UNSUPPORTED_LEXICAL_FORM")

    def code(i, interpolation=False):
        depth = 0
        parens = []
        while i < length:
            char = text[i]
            if char.isspace():
                i += 1
            elif text.startswith("//", i):
                end = text.find("\n", i + 2)
                i = length if end < 0 else end + 1
            elif text.startswith("/*", i):
                end = text.find("*/", i + 2)
                if end < 0:
                    refuse("UNSUPPORTED_LEXICAL_FORM")
                i = end + 2
            elif char in "'\"":
                i, token = quoted(i, char)
                result.append(token)
            elif char == "`":
                result.append(("template", "`"))
                i += 1
                while i < length and text[i] != "`":
                    if text[i] == "\\":
                        i += 2
                    elif text.startswith("${", i):
                        result.append(("punct", "{"))
                        i = code(i + 2, True)
                        result.append(("punct", "}"))
                    else:
                        i += 1
                if i >= length:
                    refuse("UNSUPPORTED_LEXICAL_FORM")
                i += 1
                result.append(("template", "`"))
            elif char.isascii() and (char.isalpha() or char in "_$"):
                end = i + 1
                while end < length and (text[end].isascii() and (text[end].isalnum() or text[end] in "_$")):
                    end += 1
                result.append(("word", text[i:end]))
                i = end
            elif char == "\\" or (not char.isascii() and not char.isspace()):
                refuse("UNSUPPORTED_LEXICAL_FORM")
            elif char == "/" and (not result or result[-1][1] in ("=", "(", ":", ",", "return", "!", "&", "|", ">", "[", "{", "?", ";")):
                # A regexp literal at an expression boundary, with character classes.
                i += 1
                in_class = False
                while i < length:
                    current = text[i]
                    if current == "\\":
                        i += 2
                        continue
                    if current in "\r\n":
                        refuse("UNSUPPORTED_LEXICAL_FORM")
                    if current == "[":
                        in_class = True
                    if current == "]":
                        in_class = False
                    if current == "/" and not in_class:
                        break
                    i += 1
                if i >= length:
                    refuse("UNSUPPORTED_LEXICAL_FORM")
                i += 1
                while i < length and text[i].isascii() and text[i].isalpha():
                    i += 1
                result.append(("regexp", "/"))
            else:
                if char == "/" and result and (result[-1][1] == "}" or
                        (result[-1][1] == ")" and len(result) - 1 not in expression_closes)):
                    refuse("AMBIGUOUS_SLASH")
                if char == "(":
                    previous = result[-1] if result else None
                    if previous and previous[0] == "word" and previous[1] in ("if", "while", "for", "switch", "catch", "with"):
                        parens.append("control")
                    elif previous and ((previous[0] == "word" and previous[1] not in ("return", "throw", "typeof", "void", "delete", "yield", "await"))
                            or (previous[1] == ")" and len(result) - 1 in expression_closes)):
                        parens.append("call")
                    elif previous and previous[1] in ("=", "(", ",", ":", "[", "return", "throw", "?", "!", "+", "-", "*", "/", "&", "|", ">"):
                        parens.append("group")
                    else:
                        parens.append("unknown")
                elif char == ")":
                    context = parens.pop() if parens else "unknown"
                    if context in ("call", "group"):
                        expression_closes.add(len(result))
                if char == "{":
                    depth += 1
                if char == "}":
                    if interpolation and depth == 0:
                        return i + 1
                    depth -= 1
                result.append(("punct", char))
                i += 1
        if interpolation:
            refuse("UNSUPPORTED_LEXICAL_FORM")
        return i

    code(0)
    return result


def import_specifiers(data):
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        refuse("INVALID_SOURCE_TEXT")
    stream = tokens(text)
    found = []
    for index, (kind, word) in enumerate(stream):
        if (kind == "string" and word in ("require", "createRequire", "eval", "Function", "_compile", "_load")
                and index > 0 and stream[index - 1] == ("punct", "[")):
            refuse("INDIRECT_LOADER")
        if kind != "word":
            continue
        if word in ("eval", "Function", "createRequire", "_compile", "_load"):
            refuse("INDIRECT_LOADER")
        if word not in ("import", "export", "require"):
            continue
        after = stream[index + 1:]
        if word == "import" and after[:2] == [("punct", "."), ("word", "meta")]:
            continue
        if word == "require" or (word == "import" and after[:1] == [("punct", "(")]):
            if (len(after) < 3 or after[0] != ("punct", "(") or after[1][0] != "string"
                    or after[2] != ("punct", ")")):
                refuse("NONLITERAL_OR_INDIRECT_IMPORT")
            found.append(after[1][1])
        elif word == "import" and after and after[0][0] == "string":
            found.append(after[0][1])
        else:
            # Only binding/re-export grammar is searched; ordinary exported
            # declarations are not allowed to borrow a later statement's `from`.
            binding = after[1:] if after[:1] == [("word", "type")] else after
            if word == "export" and (not binding or binding[0][1] not in ("{", "*")):
                continue
            binding_depth = 0
            for offset, item in enumerate(after):
                if item == ("punct", "{"):
                    binding_depth += 1
                elif item == ("punct", "}"):
                    binding_depth -= 1
                if item == ("word", "from") and binding_depth == 0:
                    if offset + 1 >= len(after) or after[offset + 1][0] != "string":
                        refuse("NONLITERAL_OR_INDIRECT_IMPORT")
                    found.append(after[offset + 1][1])
                    break
                if (item[0] not in ("word", "punct") or
                        (item[0] == "punct" and item[1] not in ("{", "}", "*", ",")) or
                        item[1] in ("import", "export", "const", "class", "function", "interface")):
                    if word == "import":
                        refuse("UNRESOLVED_IMPORT_SYNTAX")
                    break
            else:
                if word == "import":
                    refuse("UNRESOLVED_IMPORT_SYNTAX")
    return sorted(set(found))


def relative_candidate(path, specifier):
    if (not specifier.startswith(("./", "../")) or not specifier.isascii()
            or not re.fullmatch(r"[a-zA-Z0-9_./-]+", specifier)):
        return None
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), specifier))
    return resolved[:-3] + ".ts" if resolved.endswith(".js") else resolved


def resolve_relative(path, specifier):
    resolved = relative_candidate(path, specifier)
    if resolved is None:
        refuse("UNRESOLVED_RELATIVE_IMPORT")
    if not resolved.endswith((".ts", ".mjs")):
        refuse("UNRESOLVED_RELATIVE_IMPORT")
    if resolved not in PUBLIC_PATHS or not resolved.startswith(SOURCE_ROOT):
        refuse("IMPORT_OUTSIDE_ALLOWLIST")
    return resolved


def external_package(specifier, declared):
    if specifier.startswith("node:"):
        if specifier[5:] not in BUILTINS:
            refuse("UNREVIEWED_BUILTIN")
        return
    base = "/".join(specifier.split("/")[:2]) if specifier.startswith("@") else specifier.split("/")[0]
    if (not re.fullmatch(r"[@a-zA-Z0-9_./-]+", specifier) or ".." in specifier.split("/")
            or base not in PACKAGES or base not in declared):
        refuse("UNRESOLVED_EXTERNAL_IMPORT")


class Output:
    """Fresh OWN directory, fd-relative nofollow/exclusive paths; no mode repair.

    Ancestors must exist without symlinks. /private/tmp is supported; /tmp's macOS
    symlink is deliberately not. Retain partial output on refusal, never adopt it.
    """

    def __init__(self, path, checkout):
        path = Path(path)
        checkout = Path(checkout)
        if not path.is_absolute() or ".." in path.parts or path == Path("/"):
            refuse("UNSAFE_OUTPUT")
        if path == checkout or checkout in path.parents or path in checkout.parents:
            refuse("OUTPUT_INSIDE_CHECKOUT")
        parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in path.parent.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                os.close(parent)
                parent = child
            os.mkdir(path.name, 0o700, dir_fd=parent)  # Existing names MUST fail.
            os.fsync(parent)
            self.fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            own = os.fstat(self.fd)
            if own.st_uid != os.getuid() or stat.S_IMODE(own.st_mode) != 0o700:
                refuse("UNSAFE_OUTPUT")
        except OSError:
            refuse("OUTPUT_COLLISION_OR_UNSAFE_PARENT")
        finally:
            os.close(parent)
        self.path = path

    def write(self, parts, data):
        if not parts or any(not re.fullmatch(r"[A-Za-z0-9_.-]+", part) or part in (".", "..") for part in parts):
            refuse("UNSAFE_OUTPUT")
        parent = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                try:
                    os.mkdir(part, 0o700, dir_fd=parent)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                own = os.fstat(child)
                if own.st_uid != os.getuid() or stat.S_IMODE(own.st_mode) != 0o700:
                    os.close(child)
                    refuse("UNSAFE_OUTPUT")
                os.fsync(parent)
                os.close(parent)
                parent = child
            fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            try:
                own = os.fstat(fd)
                if own.st_uid != os.getuid() or own.st_nlink != 1 or stat.S_IMODE(own.st_mode) & 0o177:
                    refuse("UNSAFE_OUTPUT")
                with os.fdopen(fd, "wb", closefd=False) as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(parent)
        except OSError:
            raise Refusal("OUTPUT_IO", True) from None
        finally:
            os.close(parent)

    def close(self):
        os.close(self.fd)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def create_argv(image, name):
    return ["docker", "create", "--name", name, "--label", LABEL + "=" + LABEL_VALUE,
            "--pull", "never", "--platform", "linux/arm64", "--network", "none", "--read-only",
            "--user", "65532:65532", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--restart", "no", "--no-healthcheck", "--entrypoint", "/bin/false", image]


def check_image(value, image, default_main):
    expected = {"id": image, "os": "linux", "arch": "arm64", "user": "65532:65532",
                "workdir": "/app/server/api", "volumes": None,
                "entrypoint": ["docker-entrypoint.sh"],
                "cmd": ["node", "--import", "tsx", default_main]}
    # Docker may encode the empty volume map as {} instead of null.
    if encoded(value) == encoded(dict(expected, volumes={})):
        return
    if encoded(value) != encoded(expected):
        refuse("IMAGE_GUARD")


def check_container(value, owned):
    expected = {"id": owned["id"], "image": owned["image"], "name": "/" + owned["name"],
        "status": "created", "running": False, "paused": False, "restarting": False, "dead": False,
        "started": ZERO_TIME, "finished": ZERO_TIME, "mounts": 0, "binds": 0, "tmpfs": 0,
        "devices": 0, "privileged": False, "readonly": True, "network": "none",
        "user": "65532:65532", "workdir": "/app/server/api", "entrypoint": ["/bin/false"],
        "cmd": None, "path": "/bin/false", "args": [], "caps": ["ALL"],
        "security": ["no-new-privileges:true"], "restart": "no", "health": ["NONE"],
        "ownLabel": LABEL_VALUE}
    # --entrypoint clears image CMD; engines may represent the empty CMD as [].
    if encoded(value) == encoded(dict(expected, cmd=[])):
        return
    if encoded(value) != encoded(expected):
        refuse("OWN_CONTAINER_GUARD")


class Acquisition:
    def __init__(self, runner, output):
        self.runner = runner
        self.output = output
        self.owned = []
        self.count = 0
        self.total = 0
        self.event = 0
        self.last_durable_event = 0
        self.phase = "preflight"
        self.operation = None
        self.inventory = []

    def checkpoint(self):
        if time.monotonic() >= self.runner.deadline:
            raise Refusal("DEADLINE", True)

    def counters(self):
        return {"validatedFiles": self.count, "validatedBytes": self.total,
                "completedMembers": len(self.inventory),
                "completedBytes": sum(member["bytes"] for member in self.inventory)}

    def record(self, outcome="pending"):
        self.checkpoint()
        if self.event >= MAX_ATTRIBUTION_EVENTS:
            refuse("ATTRIBUTION_BOUND")
        self.event += 1
        self.output.write((f"attribution-{self.event:04d}.json",), encoded({
            "phase": self.phase, "containers": self.owned, "operation": self.operation,
            "counters": self.counters(), "outcome": outcome,
            "reasonCode": None, "ambiguous": None,
            "noStartsIssued": True, "daemonCancellationClaimed": False,
        }))
        self.last_durable_event = self.event

    def pending(self, kind, owned=None, path=None, target=None, import_index=None, member=None):
        if (kind not in OPERATION_KINDS or (path is not None and path not in PUBLIC_PATHS)
                or (target is not None and target not in PUBLIC_PATHS | KNOWN_OUT_OF_SCOPE_PATHS)):
            refuse("UNEXPECTED_FAILURE")
        self.operation = {"kind": kind, "role": owned["role"] if owned else None,
            "image": owned["image"] if owned else None,
            "containerId": owned["id"] if owned else None,
            "name": owned["name"] if owned else None, "path": path,
            "targetPath": target, "importIndex": import_index,
            "targetScope": ("allowlisted" if target in PUBLIC_PATHS else
                            "known_out_of_scope" if target in KNOWN_OUT_OF_SCOPE_PATHS else None)}
        if member is not None:
            self.operation["validatedMember"] = member
        # Immutable fsynced pending record BEFORE the potentially failing operation.
        self.record()

    def failure_receipt(self, error):
        return {"ok": False, "code": "HOLD", **failure_fields(error),
                "phase": self.phase, "operation": self.operation,
                "containers": self.owned, "counters": self.counters(),
                "completedInventory": self.inventory,
                "lastDurableAttribution": self.last_durable_event,
                "manualReconciliationRequired": True, "startupQualified": False,
                "fullSourceClosureQualified": False, "semanticClosureQualified": False,
                "installedDependenciesQualified": False}

    def guard(self, owned, path=None):
        self.pending("container_inspect", owned, path)
        if not FULL_ID.fullmatch(owned["id"]):
            refuse("OWN_ID_GUARD")
        data = self.runner.run(["docker", "container", "inspect", "--format", CONTAINER_FORMAT, owned["id"]],
                               INSPECT_SECONDS, 16384)
        check_container(strict_json(data), owned)

    def acquire_file(self, owned, path, records):
        if path not in PUBLIC_PATHS:
            refuse("PATH_OUTSIDE_ALLOWLIST")
        self.pending("member_limit", owned, path)
        if self.count >= MAX_FILES:
            refuse("FILE_COUNT_BOUND")
        # Guard before EVERY cp; never cp running or overlay-mounted files.
        self.guard(owned, path)
        self.pending("cp", owned, path)
        raw = self.runner.run(["docker", "cp", owned["id"] + ":" + path, "-"],
                              COPY_SECONDS, MAX_FILE_BYTES + TAR_OVERHEAD)
        self.pending("archive_validate", owned, path)
        data = single_file_tar(raw, path)
        if self.total + len(data) > MAX_TOTAL_BYTES:
            refuse("TOTAL_BYTE_BOUND")
        self.count += 1
        self.total += len(data)
        summary = {"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        member = {**summary, "ordinal": self.count, "role": owned["role"],
                  "image": owned["image"], "containerId": owned["id"]}
        self.pending("member_write", owned, path, member=member)
        self.output.write((owned["role"],) + tuple(path.removeprefix("/app/").split("/")), data)
        self.pending("member_commit", owned, path, member=member)
        # Source bytes fsynced first, then an O_EXCL immutable inventory receipt
        # fsynced before ANY parser/next-member/removal work. No raw data is recorded.
        self.output.write((f"member-{self.count:04d}.json",), encoded({
            "format": "validated-public-member-v1", "member": member,
            "validatedFiles": self.count, "validatedBytes": self.total,
            "startupQualified": False, "fullSourceClosureQualified": False,
            "semanticClosureQualified": False, "installedDependenciesQualified": False}))
        self.inventory.append(member)
        records.append(summary)
        return data

    def graph(self, owned, entry):
        records = []
        metadata = {path: self.acquire_file(owned, path, records) for path in METADATA_PATHS}
        self.pending("metadata_parse", owned, METADATA_PATHS[0])
        package = strict_json(metadata[METADATA_PATHS[0]])
        self.pending("metadata_parse", owned, METADATA_PATHS[1])
        config = strict_json(metadata[METADATA_PATHS[1]])
        self.pending("loader_config", owned, METADATA_PATHS[0])
        if (not isinstance(package, dict) or package.get("type") != "module"
                or "imports" in package or "exports" in package):
            refuse("UNREVIEWED_LOADER_CONFIG")
        self.pending("loader_config", owned, METADATA_PATHS[1])
        if encoded(config) != encoded({"compilerOptions": TS_OPTIONS, "include": ["src/**/*.ts"]}):
            refuse("UNREVIEWED_LOADER_CONFIG")
        self.pending("loader_config", owned, METADATA_PATHS[0])
        declared = set()
        for key in ("dependencies", "devDependencies"):
            section = package.get(key, {})
            if not isinstance(section, dict) or any(not isinstance(value, str) for value in section.values()):
                refuse("UNREVIEWED_PACKAGE_CONFIG")
            declared.update(section)
        pending = [SOURCE_ROOT + entry]
        seen = set()
        edges = []
        external = set()
        while pending:
            self.checkpoint()
            path = pending.pop(0)
            if path in seen:
                continue
            data = self.acquire_file(owned, path, records)
            seen.add(path)
            self.pending("lexical_collect", owned, path)
            for index, specifier in enumerate(import_specifiers(data)):
                if specifier.startswith("."):
                    # Only known PUBLIC constants can enter diagnostic target fields.
                    # Unknown/raw specifiers are represented by source path+edge index.
                    candidate = relative_candidate(path, specifier)
                    diagnostic = candidate if candidate in PUBLIC_PATHS | KNOWN_OUT_OF_SCOPE_PATHS else None
                    self.pending("resolve_relative", owned, path, target=diagnostic, import_index=index)
                    target = resolve_relative(path, specifier)
                    edges.append({"from": path, "to": target})
                    if target not in seen and target not in pending:
                        pending.append(target)
                else:
                    self.pending("external_import", owned, path, import_index=index)
                    external_package(specifier, declared)
                    external.add(specifier)
        return {"role": owned["role"], "image": owned["image"], "entry": SOURCE_ROOT + entry,
                "files": records, "literalRelativeEdges": edges,
                "externalSpecifiersNotResolved": sorted(external),
                "literalRelativeCandidateCollected": True, "semanticClosureQualified": False,
                "fullSourceClosureQualified": False, "installedDependenciesQualified": False}

    def run(self):
        # Both exact names checked before ANY create. Atomic daemon create handles races.
        for role, image, name, _, _ in TARGETS:
            context = {"role": role, "image": image, "name": name, "id": None}
            self.pending("name_check", context)
            collision = self.runner.run(["docker", "container", "ls", "--all", "--quiet", "--no-trunc",
                                         "--filter", "name=^/" + name + "$"], INSPECT_SECONDS, 4096)
            if collision.strip():
                refuse("NAME_COLLISION")
        for role, image, name, _, default_main in TARGETS:
            context = {"role": role, "image": image, "name": name, "id": None}
            self.pending("image_inspect", context)
            value = strict_json(self.runner.run(["docker", "image", "inspect", "--format", IMAGE_FORMAT, image],
                                                INSPECT_SECONDS, 16384))
            check_image(value, image, default_main)
        reports = []
        for role, image, name, entry, _ in TARGETS:
            self.phase = role + "_create"
            owned = {"role": role, "image": image, "name": name, "id": None, "disposition": "create_pending"}
            self.owned.append(owned)
            self.pending("create", owned)  # Persist attribution BEFORE ambiguous create.
            raw = self.runner.run(create_argv(image, name), CREATE_SECONDS, 128)
            try:
                identifier = raw.decode("ascii").strip()
            except UnicodeError:
                raise Refusal("CREATE_ID_AMBIGUOUS", True) from None
            if not FULL_ID.fullmatch(identifier) or any(item["id"] == identifier for item in self.owned[:-1]):
                raise Refusal("CREATE_ID_AMBIGUOUS", True)
            owned["id"] = identifier
            owned["disposition"] = "created_unqualified"
            self.record(outcome="completed")
            self.guard(owned)
            owned["disposition"] = "qualified_never_started"
            self.phase = role + "_copy"
            self.record(outcome="completed")
            report = self.graph(owned, entry)
            self.pending("graph_write", owned)
            self.output.write((role + "-graph.json",), encoded(report))
            self.phase = role + "_remove"
            self.guard(owned)
            owned["disposition"] = "removal_pending"
            self.pending("remove", owned)
            # ONLY exact own full ID, freshly qualified NEVER started. No -f/-v.
            reply = self.runner.run(["docker", "rm", identifier], REMOVE_SECONDS, 128)
            if reply.strip() != identifier.encode("ascii"):
                raise Refusal("REMOVAL_AMBIGUOUS", True)
            owned["disposition"] = "removed"
            self.record(outcome="completed")
            reports.append(report)
        self.phase = "complete_candidate"
        result = {"format": "old-public-source-candidate-v2", "ok": True,
            "startupQualified": False, "fullSourceClosureQualified": False,
            "semanticClosureQualified": False, "installedDependenciesQualified": False,
            "provenanceIndependentlyEstablishedByExtractor": False,
            "q1Evidence": "DIP-ARTF-411", "graphs": reports, "containers": self.owned,
            "files": self.count, "bytes": self.total,
            "bounds": {"filesGlobal": MAX_FILES, "fileBytes": MAX_FILE_BYTES,
                       "totalBytesGlobal": MAX_TOTAL_BYTES, "overallSeconds": OVERALL_SECONDS},
            "limitations": ["historical OWN build attribution is an external prerequisite",
                "lexical relative-import candidate is not semantic TypeScript or loader certification",
                "computed loaders such as module[\"requ\"+\"ire\"] are not comprehensively detected",
                "server/runtime/src import leads remain explicitly OUTSIDE acquisition scope",
                "explicit .js-to-.ts mapping assumes historical COPY contains TS rather than competing JS files",
                "installed packages, symlink resolution and inherited entrypoint source NOT acquired",
                "no key/resource/runtime-output files acquired; non-import resources need review",
                "actual LOCAL Path/Args, overlays, mounts, config and all actors remain parent predicates",
                "no application startup, private store/config predicate, preservation or provider qualification"]}
        self.pending("candidate_write")
        self.output.write(("candidate.json",), encoded(result))
        return result


class ClosedParser(argparse.ArgumentParser):
    def error(self, message):
        refuse("CLI_USAGE")


def cli(argv=None):
    # Host-only hard wall-clock alarm; installed only during explicit invocation.
    # Signals/client kills do NOT assert daemon cancellation or safe resource removal.
    def expired(signum, frame):
        raise Refusal("DEADLINE", True)

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, OVERALL_SECONDS)
    deadline = time.monotonic() + OVERALL_SECONDS
    try:
        return reviewed_cli(argv, deadline)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def reviewed_cli(argv, deadline):
    parser = ClosedParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--extract-public-sources", action="store_true", required=True)
    parser.add_argument("--accept-historical-own-build-provenance", action="store_true", required=True)
    parser.add_argument("--confirm-independent-command-source-review", action="store_true", required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--output", required=True)
    for name, value in (("max-files", MAX_FILES), ("max-file-bytes", MAX_FILE_BYTES),
                        ("max-total-bytes", MAX_TOTAL_BYTES), ("overall-seconds", OVERALL_SECONDS)):
        parser.add_argument("--" + name, type=int, choices=(value,), required=True)
    args = parser.parse_args(argv)
    if not SHA256.fullmatch(args.source_sha256):
        refuse("REVIEW_BINDING_REQUIRED")
    # The confirmation switch is an assertion, NOT approval verification. Parent
    # must obtain/read independent acceptance of these exact bytes and literal CLI.
    # No author artifact or Q1 receipt is accepted as an automated approval token.
    # Hash only THIS public regular author source; never env/keys/stores/recovery.
    source = Path(__file__).absolute()
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
            refuse("SOURCE_PIN_MISMATCH")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            source_bytes = handle.read(MAX_FILE_BYTES + 1)
        if hashlib.sha256(source_bytes).hexdigest() != args.source_sha256:
            refuse("SOURCE_PIN_MISMATCH")
    finally:
        os.close(fd)
    output = Output(args.output, source.parents[3])
    acquisition = Acquisition(Runner(deadline), output)
    failure = None
    try:
        acquisition.pending("review_assertion")
        output.write(("review-assertion.json",), encoded({"independentCommandSourceReviewConfirmedByParent": True,
            "sourceSha256": args.source_sha256, "historicalOwnBuildAcceptedByParent": True,
            "evidenceContentsVerifiedByExtractor": False}))
        acquisition.run()
        return {"ok": True, "code": "CANDIDATE_COLLECTED", "startupQualified": False}
    except Exception as error:
        failure = failure_fields(error)
        # ONE bounded protected refusal attempt; never daemon cleanup/retry.
        # Previous fsynced pending/member records survive if time/disk precludes it.
        try:
            acquisition.checkpoint()
            output.write(("refusal.json",), encoded(acquisition.failure_receipt(error)))
        except (Refusal, OSError):
            pass
        raise Refusal(failure["reasonCode"], failure["ambiguous"]) from None
    finally:
        try:
            output.close()
        except OSError:
            if failure is None:
                raise Refusal("OUTPUT_IO", True) from None


def main():
    try:
        receipt = cli()
    except Exception as error:
        receipt = {"ok": False, "code": "HOLD", **failure_fields(error),
                   "manualReconciliationRequired": True, "startupQualified": False}
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
