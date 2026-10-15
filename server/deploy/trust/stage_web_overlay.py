#!/usr/bin/env python3
"""Closed 428 web-asset staging candidate. No Docker, build, app or network calls.

Inventory is readonly. Stage requires a separately reviewed explicit CLI flag and
creates one fresh context; failures retain partial OWN output, never clean/retry.
The immutable base's published notices/config/runtime are preserved by COPY merge.
"""

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import signal
import stat
import sys

BASE_IMAGE = "sha256:1659b39c98d5183c91feae78a8d9eb1d4c6ee527d541c1e1d74dfe842adee8c0"
WWW_ROOT = "/usr/share/nginx/html/"
CONTEXT = "/private/tmp/dip-web-overlay-context-20261012-gpt61-r1"
REPO = "/Users/vsevolod/Documents/startup/diplom"
PACKAGE = "/private/tmp/dip-frontend-qualification-2i7h1m3e"
MANIFEST_SHA256 = "14639dadd60dbe639d0955949bfa7d4ff09550a6119b3f2b2c05c2074d412e99"
STAND_DOCKERFILE_SHA256 = "4b0dd66de1374584259df9d3409dde70c7c354c55971f343c62faa6063a81b15"
SOURCE_PINS = {
    "vite.config.ts": "6f2e93ecb2805337be4767ee1d3be3966421c273e51efcbbc9a5f066ade73761",
    "src/pages/scans/ReportViewControls.tsx": "e181c0ef95b156aea11043d69471a28a64e91f36e253c110e609dd2bc6672072",
    "src/pages/scans/ScanReportSections.tsx": "368501f4b6fd478be0224195571408b3add1c6c3f844223226626906f5f0eaf8",
    "src/pages/scans/CursorReportPager.tsx": "76473e295bcbbfc1ac1b3281a88c22d3e7cf3e47abad5ba0841b63ec82dfbb0d",
    "src/pages/scans/ScanDetailPage.tsx": "b24191971dcdf785588f25e0c50a93be58b4290b48bf44765f8e43e982584523",
    "src/features/scans/ScanSummaryPanel.tsx": "8375be9c21d76bc9cb98af97cc1da5bf02e95c03773732c20162f2e136832f9d",
    "src/features/scans/ScanChatPanel.tsx": "949ccf31a9f9e4f85def9da394a6134f875e71a03ec037f7556241a1f3e26053",
    "src/shared/api/scans/llmChatClient.ts": "575fd6ffaaa68cdf9085cb054dc01991fabdfcf7ef11b9aa986e126d3067d605",
    "src/shared/api/scans/reportView.ts": "ce011b2cdfa2072c5c91f9ea7c617a4f41914c4d91c6f1a0aebe06461f58b994",
    "src/shared/api/scans/scanTransport.ts": "8d499b50b1c4ccd867915294a73cabb72b7361cd1700b8901d36d9d7c927085c",
    "src/shared/api/scans/httpScanTransport.ts": "1155764c530939d3f4a80ef22611e3b658aee0745f45d09c92b00a14f799a758",
}
MAX_FILE_BYTES = 1048576
MAX_MANIFEST_BYTES = 131072
MAX_FILES = 512
MAX_TOTAL_BYTES = 16777216
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
DIR_FLAGS = FLAGS | os.O_DIRECTORY
ASSET = re.compile(r"assets/[A-Za-z0-9_-]+\.(?:js|css|woff2?|ttf)\Z", re.ASCII)
SHA = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)


class Refused(Exception):
    """Constant public failure code; never reflect arbitrary source contents."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def stable(info):
    return identity(info) + (info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def owned_file(info, limit):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or info.st_mode & 0o022
            or not 0 <= info.st_size <= limit):
        raise Refused("FILE_METADATA")


class Tree:
    """Hold every directory descriptor and recheck its original path binding."""

    def __init__(self, path):
        self.fds = []
        self.edges = []
        parts = PurePosixPath(path).parts
        if not parts or parts[0] != "/" or any(p in (".", "..") for p in parts):
            raise Refused("ROOT_PATH")
        try:
            self.fds.append(os.open("/", DIR_FLAGS))
            for name in parts[1:]:
                parent = self.fds[-1]
                child = os.open(name, DIR_FLAGS, dir_fd=parent)
                self.fds.append(child)
                self.edges.append((parent, name, child, identity(os.fstat(child))))
            self.fd = self.fds[-1]
            self.verify()
        except BaseException:
            self.close()
            raise

    def verify(self):
        for parent, name, child, expected in self.edges:
            if (identity(os.fstat(child)) != expected
                    or identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != expected):
                raise Refused("DIRECTORY_REBOUND")

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()


@contextmanager
def tree(path):
    value = Tree(path)
    try:
        yield value
        value.verify()
    finally:
        value.close()


@contextmanager
def subdir(parent, name):
    fd = os.open(name, DIR_FLAGS, dir_fd=parent)
    initial = identity(os.fstat(fd))
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise Refused("DIRECTORY_METADATA")
        yield fd
        if (identity(os.fstat(fd)) != initial
                or identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != initial):
            raise Refused("DIRECTORY_REBOUND")
    finally:
        os.close(fd)


def read_file(parent, name, limit):
    fd = os.open(name, FLAGS, dir_fd=parent)
    try:
        before = os.fstat(fd)
        owned_file(before, limit)
        blocks = []
        remaining = before.st_size
        while remaining:
            block = os.read(fd, min(65536, remaining))
            if not block:
                raise Refused("FILE_CHANGED")
            blocks.append(block)
            remaining -= len(block)
        if (os.read(fd, 1) or stable(os.fstat(fd)) != stable(before)
                or stable(os.stat(name, dir_fd=parent, follow_symlinks=False)) != stable(before)):
            raise Refused("FILE_CHANGED")
        return b"".join(blocks)
    finally:
        os.close(fd)


def read_relative(root, path, limit):
    parts = PurePosixPath(path).parts
    if not parts or parts[0] == "/" or any(p.startswith(".") or p in ("proof", "resources") for p in parts):
        raise Refused("SOURCE_PATH")
    if len(parts) == 1:
        return read_file(root, parts[0], limit)
    with subdir(root, parts[0]) as child:
        return read_relative(child, str(PurePosixPath(*parts[1:])), limit)


@dataclass(frozen=True)
class Profile:
    package: str = PACKAGE
    repo: str = REPO
    context: str = CONTEXT
    manifest_sha256: str = MANIFEST_SHA256
    count: int = 423
    total: int = 14368463
    source_pins: tuple = tuple(sorted(SOURCE_PINS.items()))
    dockerfile_sha256: str = STAND_DOCKERFILE_SHA256


PROFILE = Profile()
# The pinned428 manifest has exactly these two dotted public library basenames.
PUBLIC_DOTTED_ASSETS = frozenset({"assets/cytoscape.esm-BnkdMOzK.js", "assets/mermaid.core-VOEfPy8Q.js"})


def public_path(path):
    if (not isinstance(path, str) or len(path) > 160
            or any(word in path.lower() for word in ("notice", "license", "shadcn", "private", ".env"))
            or not (path in ("index.html", "admin.html") or path in PUBLIC_DOTTED_ASSETS or ASSET.fullmatch(path))):
        raise Refused("MANIFEST_PATH")


def manifest(data, profile):
    if digest(data) != profile.manifest_sha256:
        raise Refused("MANIFEST_PIN")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Refused("MANIFEST_DUPLICATE_KEY")
            result[key] = value
        return result
    try:
        value = json.loads(data, object_pairs_hook=pairs)
    except (ValueError, UnicodeError):
        raise Refused("MANIFEST_JSON") from None
    if (not isinstance(value, dict) or set(value) != {"format", "files"}
            or value["format"] != "public-built-assets-v1" or not isinstance(value["files"], list)
            or not len(value["files"]) == profile.count <= MAX_FILES):
        raise Refused("MANIFEST_SHAPE")
    rows = value["files"]
    paths = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}:
            raise Refused("MANIFEST_ROW")
        public_path(row["path"])
        if (type(row["bytes"]) is not int or not 0 <= row["bytes"] <= MAX_FILE_BYTES
                or not isinstance(row["sha256"], str) or not SHA.fullmatch(row["sha256"])):
            raise Refused("MANIFEST_ROW")
        paths.append(row["path"])
    if (paths != sorted(set(paths)) or not {"index.html", "admin.html"} <= set(paths)
            or not sum(row["bytes"] for row in rows) == profile.total <= MAX_TOTAL_BYTES):
        raise Refused("MANIFEST_INVENTORY")
    return rows


def check_sources(root, profile):
    for path, expected in profile.source_pins:
        if digest(read_relative(root, path, MAX_FILE_BYTES)) != expected:
            raise Refused("SOURCE_PIN")
    if digest(read_relative(root, "server/deploy/stand.Dockerfile", MAX_FILE_BYTES)) != profile.dockerfile_sha256:
        raise Refused("WEB_ROOT_SOURCE_PIN")


def names_match(fd, expected):
    # Name comparison precedes any unknown-file payload read or stat.
    names = os.listdir(fd)
    if len(names) > MAX_FILES or set(names) != set(expected):
        raise Refused("UNEXPECTED_DIST_NAME")


def asset_bytes(dist, assets, row):
    public_path(row["path"])
    parent = assets if row["path"].startswith("assets/") else dist
    data = read_file(parent, row["path"].split("/")[-1], MAX_FILE_BYTES)
    if len(data) != row["bytes"] or digest(data) != row["sha256"]:
        raise Refused("ASSET_PIN")
    return data


def verify_dist(dist, assets, rows):
    names_match(dist, {"index.html", "admin.html", "assets"})
    names_match(assets, {r["path"].split("/")[-1] for r in rows if r["path"].startswith("assets/")})
    for row in rows:
        asset_bytes(dist, assets, row)


def generated(rows):
    dockerfile = f"FROM {BASE_IMAGE}\nCOPY dist/ {WWW_ROOT}\n".encode()
    # Re-deny children after reopening each directory; only exact files reopen.
    ignore = ("**\n!Dockerfile\n!.dockerignore\n!dist/\ndist/*\n!dist/assets/\ndist/assets/*\n"
              + "".join("!dist/" + row["path"] + "\n" for row in rows)).encode()
    return dockerfile, ignore


def write_exclusive(fd, name, data, mode):
    output = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     mode, dir_fd=fd)
    try:
        os.fchmod(output, mode)
        view = memoryview(data)
        while view:
            count = os.write(output, view)
            if count <= 0:
                raise Refused("OUTPUT_WRITE")
            view = view[count:]
        os.fsync(output)
    finally:
        os.close(output)


def make_dir(parent, name, mode):
    os.mkdir(name, mode=mode, dir_fd=parent)
    fd = os.open(name, DIR_FLAGS, dir_fd=parent)
    try:
        os.fchmod(fd, mode)  # Explicit public readability even under a restrictive umask.
        os.fsync(fd)
    finally:
        os.close(fd)


def prepare(profile=PROFILE, *, stage=False):
    with tree(profile.package) as package, tree(profile.repo) as repo:
        info = os.fstat(package.fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise Refused("PACKAGE_ROOT_METADATA")
        rows = manifest(read_file(package.fd, "public-assets-manifest.json", MAX_MANIFEST_BYTES), profile)
        check_sources(repo.fd, profile)
        with subdir(package.fd, "dist") as dist, subdir(dist, "assets") as assets:
            verify_dist(dist, assets, rows)
            dockerfile, ignore = generated(rows)
            context_rows = [{**row, "path": "dist/" + row["path"]} for row in rows]
            context_rows += [{"path": name, "bytes": len(data), "sha256": digest(data)}
                             for name, data in [("Dockerfile", dockerfile), (".dockerignore", ignore)]]
            context_rows.sort(key=lambda row: row["path"])
            receipt = {"format": "closed-web-overlay-v1", "mode": "staged" if stage else "inventory-only",
                       "baseImage": BASE_IMAGE, "wwwRoot": WWW_ROOT, "context": profile.context,
                       "sourceManifestSHA256": profile.manifest_sha256,
                       "assetFiles": len(rows), "assetBytes": profile.total,
                       "assetsAggregateSHA256": digest(encoded(rows)),
                       "sourcePins": dict(profile.source_pins),
                       "standDockerfileSHA256": profile.dockerfile_sha256,
                       "buildContextAggregateSHA256": digest(encoded(context_rows)),
                       "buildContextFiles": context_rows, "dockerExecuted": False,
                       "servingQualified": False, "stagedContextObserved": stage,
                                              "publishedNoticeContentInspected": False}
            if stage:
                parent_path, name = profile.context.rsplit("/", 1)
                with tree(parent_path) as parent:
                    make_dir(parent.fd, name, 0o700)  # Existing path always refuses.
                    with subdir(parent.fd, name) as output:
                        make_dir(output, "dist", 0o755)
                        with subdir(output, "dist") as copied:
                            make_dir(copied, "assets", 0o755)
                            with subdir(copied, "assets") as copied_assets:
                                for row in rows:
                                    target = copied_assets if row["path"].startswith("assets/") else copied
                                    write_exclusive(target, row["path"].split("/")[-1],
                                                    asset_bytes(dist, assets, row), 0o644)
                                verify_dist(copied, copied_assets, rows)
                                os.fsync(copied_assets)
                            os.fsync(copied)
                        write_exclusive(output, "Dockerfile", dockerfile, 0o644)
                        write_exclusive(output, ".dockerignore", ignore, 0o644)
                        for filename, expected in [("Dockerfile", dockerfile), (".dockerignore", ignore)]:
                            if read_file(output, filename, MAX_MANIFEST_BYTES) != expected:
                                raise Refused("GENERATED_OUTPUT_CHANGED")
                        names_match(output, {"dist", "Dockerfile", ".dockerignore"})
                        verify_dist(dist, assets, rows)
                        check_sources(repo.fd, profile)
                        if digest(read_file(package.fd, "public-assets-manifest.json", MAX_MANIFEST_BYTES)) != profile.manifest_sha256:
                            raise Refused("MANIFEST_PIN")
                        package.verify()
                        repo.verify()
                        write_exclusive(output, "staged-manifest.json", encoded(receipt), 0o600)
                        os.fsync(output)
                    os.fsync(parent.fd)
            else:
                check_sources(repo.fd, profile)
                if digest(read_file(package.fd, "public-assets-manifest.json", MAX_MANIFEST_BYTES)) != profile.manifest_sha256:
                    raise Refused("MANIFEST_PIN")
            return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--inventory-only", action="store_true")
    mode.add_argument("--stage", action="store_true")
    parser.add_argument("--authorize-reviewed-stage", action="store_true")
    parser.add_argument("--context", default=CONTEXT)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args(argv)
    if (args.context != CONTEXT or args.manifest_sha256 != MANIFEST_SHA256
            or args.stage != args.authorize_reviewed_stage):
        parser.error("fixed context/manifest and explicit reviewed-stage authority required")
    def deadline(_signum, _frame):
        raise Refused("DEADLINE")
    previous = signal.signal(signal.SIGALRM, deadline)
    signal.alarm(30)
    try:
        receipt = prepare(stage=args.stage)
        # Full exact path/size/hash inventory lives in the excluded staging receipt.
        public = {k: v for k, v in receipt.items() if k != "buildContextFiles"}
        print(encoded(public).decode(), end="")
        return 0
    except (Refused, OSError) as error:
        code = str(error) if isinstance(error, Refused) else "FILESYSTEM_REFUSAL"
        print(encoded({"ok": False, "code": code, "dockerExecuted": False,
                       "partialOwnContextMayRemain": args.stage}).decode(), end="", file=sys.stderr)
        return 1
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


if __name__ == "__main__":
    raise SystemExit(main())
