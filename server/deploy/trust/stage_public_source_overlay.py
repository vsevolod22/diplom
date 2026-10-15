#!/usr/bin/env python3
"""Inert public-source inventory/staging only; never calls Docker or executes source.

Old packages, source import closure and store/startup compatibility require separate
review. Extension selection is not a TypeScript parser or a secret-content audit.
"""
import argparse
import hashlib
import json
import os
import re
import stat
from collections import Counter
from pathlib import PurePosixPath

API_IMAGE = 'sha256:487c3909d3eeee08d60840a81c1adeb61c292aee0a31df17b2a8cf92f6dbb58c'
WORKER_IMAGE = 'sha256:8748cbebba753603d79f320c2fb476c46ab676ce12e0aa08bee0021a3e14e57a'
ROOTS = ('server/api/src', 'server/runtime/src')
ENTRYPOINTS = ('server/api/src/main.ts', 'server/api/src/oci/nginx-local.main.ts',
               'server/api/src/worker/worker.main.ts',
               'server/api/src/worker/nginx-local-worker.main.ts')
MAX_FILES, MAX_PATHS, MAX_BYTES, MAX_FILE = 2048, 8192, 64 * 1024**2, 4 * 1024**2
MAX_MANIFEST = 2 * 1024**2
# Confirmed standalone qualification/CLI tools, not production initialization modules.
EXCLUDED_FILES = frozenset(('server/api/src/oci/archive-smoke.ts',
    'server/api/src/oci/public-smoke.ts', 'server/api/src/scans/scans.config.browser.ts',
    'server/api/src/worker/verify-vuln-db-release.ts'))
SAFE_NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]*\Z')
HEX = re.compile(r'[a-f0-9]{64}\Z')
EXCLUDED_DIRS = frozenset(('tests', 'test', '__tests__', '__fixtures__', 'fixtures',
    'testfixtures', 'test-fixtures', 'testharness', 'test-harness', 'test_harness',
    'proof', 'proofs', 'proofoutputs', 'proof-outputs', 'resources', 'assets',
    'tools', 'scripts', 'init-tools', 'init_tools', 'seed', 'seeds',
    'node_modules', 'dist', 'dist-admin', 'coverage', 'test-results',
    'playwright-report', 'private', 'privatekeys', 'private-keys', 'credentials', 'keys'))
EXCLUDED_MARKER = re.compile(
    r'(?:^|[-_.])(?:tests?|spec|fixtures?|seeds?|proofs?|qualification|testharness|init-tool)(?:[-_.]|$)', re.I)
PRIVATE_MARKER = re.compile(
    r'(?:^|[-_.])(?:private[-_]?(?:signing[-_]?)?keys?|credentials|env)(?:[-_.]|$)', re.I)
FLAGS_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


class Refusal(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise Refusal(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def absolute_parts(path):
    require(isinstance(path, str) and path.startswith('/') and '\x00' not in path,
            'ABSOLUTE_PATH_REQUIRED')
    parts = path.split('/')[1:]
    require(parts and all(part not in ('', '.', '..') for part in parts), 'NONCANONICAL_PATH')
    return parts


def open_directory(path):
    """Walk from / with pinned descriptors, without following any symlink parent."""
    fd = os.open('/', FLAGS_DIR)
    try:
        for name in absolute_parts(path):
            child = os.open(name, FLAGS_DIR, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def beneath_directory(root, parts):
    fd = os.dup(root)
    try:
        for name in parts:
            child = os.open(name, FLAGS_DIR, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def stamp(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns, value.st_nlink, value.st_mode)


def read_regular(directory, name, cap, owned=False):
    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'NOT_SINGLE_REGULAR_FILE')
    require(0 < before.st_size <= cap, 'FILE_BOUND')
    if owned:
        require(before.st_uid == os.getuid(), 'MANIFEST_OWNER')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        require(stamp(os.fstat(fd)) == stamp(before), 'FILE_CHANGED')
        chunks, remaining = [], cap + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b''.join(chunks)
        require(len(raw) == before.st_size and len(raw) <= cap, 'FILE_CHANGED_OR_BOUND')
        require(stamp(os.fstat(fd)) == stamp(before), 'FILE_CHANGED')
        require(stamp(os.stat(name, dir_fd=directory, follow_symlinks=False)) == stamp(before),
                'FILE_REPLACED')
        return raw
    finally:
        os.close(fd)


def excluded_name(name):
    lower = name.lower()
    if name.startswith('.') or PRIVATE_MARKER.search(lower):
        return 'hidden_or_private_name'
    if lower in EXCLUDED_DIRS or EXCLUDED_MARKER.search(lower):
        return 'test_tool_or_payload_name'
    return None


def source_path(path):
    parts = path.split('/')
    require(path not in EXCLUDED_FILES, 'STANDALONE_TOOL')
    require(any(path.startswith(root + '/') for root in ROOTS), 'OUTSIDE_SOURCE_ROOTS')
    require(all(SAFE_NAME.fullmatch(part) and not excluded_name(part) for part in parts),
            'FORBIDDEN_SOURCE_NAME')
    require(path.endswith(('.ts', '.mjs')), 'SOURCE_EXTENSION')
    return parts


def collect(repo):
    """Enumerate only two roots. Exclusions occur BEFORE content open/hash."""
    root = open_directory(repo)
    contents, excluded = {}, Counter()
    count, total = 0, 0

    def walk(directory, relative):
        nonlocal count, total
        require(len(relative.split('/')) <= 64, 'DIRECTORY_DEPTH_BOUND')
        names = []
        with os.scandir(directory) as entries:
            for entry in entries:
                count += 1
                require(count <= MAX_PATHS, 'PATH_COUNT_BOUND')
                names.append(entry.name)
        for name in sorted(names):
            path = relative + '/' + name
            reason = 'standalone_tool' if path in EXCLUDED_FILES else excluded_name(name)
            if reason:
                excluded[reason] += 1
                continue
            require(SAFE_NAME.fullmatch(name), 'UNSAFE_SOURCE_NAME')
            value = os.stat(name, dir_fd=directory, follow_symlinks=False)
            require(not stat.S_ISLNK(value.st_mode), 'SOURCE_SYMLINK')
            if stat.S_ISDIR(value.st_mode):
                child = os.open(name, FLAGS_DIR, dir_fd=directory)
                try:
                    require(os.fstat(child).st_ino == value.st_ino and
                            os.fstat(child).st_dev == value.st_dev, 'DIRECTORY_CHANGED')
                    walk(child, path)
                    current = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    require(current.st_ino == value.st_ino and current.st_dev == value.st_dev,
                            'DIRECTORY_REPLACED')
                finally:
                    os.close(child)
            elif not name.endswith(('.ts', '.mjs')):
                # Never open/hash env, PEM, DB, assets or other unsupported extensions.
                excluded['non_source_extension'] += 1
            else:
                source_path(path)
                raw = read_regular(directory, name, MAX_FILE)
                total += len(raw)
                require(len(contents) < MAX_FILES and total <= MAX_BYTES, 'SOURCE_SET_BOUND')
                contents[path] = raw

    try:
        for relative in ROOTS:
            directory = beneath_directory(root, relative.split('/'))
            try:
                walk(directory, relative)
            finally:
                os.close(directory)
    finally:
        os.close(root)
    require(all(path in contents for path in ENTRYPOINTS), 'MISSING_ENTRYPOINT')
    require(any(path.startswith(ROOTS[1] + '/') for path in contents), 'MISSING_RUNTIME_SOURCE')
    files = [{'path': name, 'bytes': len(raw), 'sha256': sha(raw)}
             for name, raw in sorted(contents.items())]
    manifest = {'version': 1, 'repo': repo, 'roots': list(ROOTS), 'files': files,
                'source_sha256': sha(canonical(files)), 'excluded_counts': dict(sorted(excluded.items())),
                'parents': {'api': API_IMAGE, 'worker': WORKER_IMAGE},
                'qualification': {'production_import_closure': False, 'public_content_audit': False,
                                  'old_packages_compatible': False, 'store_startup_compatible': False}}
    require(len(canonical(manifest)) <= MAX_MANIFEST, 'MANIFEST_BOUND')
    return manifest, contents


def output_name(output, kind):
    parts = absolute_parts(output)
    require(parts[:-1] == ['private', 'tmp'], 'OUTPUT_PARENT')
    prefix = 'dip-public-source-overlay-' + kind + '-'
    require(parts[-1].startswith(prefix) and SAFE_NAME.fullmatch(parts[-1]) and
            len(parts[-1]) > len(prefix), 'OUTPUT_NAME')
    return parts[-1]


def new_output(output, kind):
    name = output_name(output, kind)
    parent = open_directory('/private/tmp')
    try:
        os.mkdir(name, 0o700, dir_fd=parent)  # Existing output, including symlink, refuses.
        fd = os.open(name, FLAGS_DIR, dir_fd=parent)
        try:
            value = os.fstat(fd)
            require(value.st_uid == os.getuid() and stat.S_IMODE(value.st_mode) == 0o700,
                    'OUTPUT_OWNER_MODE')
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(parent)


def write_new(directory, path, raw):
    parts = path.split('/')
    require(all(SAFE_NAME.fullmatch(p) or p == '.dockerignore' for p in parts), 'OUTPUT_PATH')
    fd = os.dup(directory)
    try:
        for name in parts[:-1]:
            try:
                os.mkdir(name, 0o755, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(name, FLAGS_DIR, dir_fd=fd)
            try:
                require(os.fstat(child).st_uid == os.getuid(), 'OUTPUT_DIRECTORY_OWNER')
                os.fchmod(child, 0o755)
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        target = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o444, dir_fd=fd)
        try:
            os.fchmod(target, 0o444)
            view = memoryview(raw)
            while view:
                written = os.write(target, view)
                require(written > 0, 'SHORT_WRITE')
                view = view[written:]
            os.fsync(target)
        finally:
            os.close(target)
    finally:
        os.close(fd)


def inventory(repo, output):
    manifest, _ = collect(repo)
    again, _ = collect(repo)
    require(manifest['files'] == again['files'], 'SOURCE_SET_CHANGED')
    raw = canonical(manifest)
    fd = new_output(output, 'plan')
    try:
        write_new(fd, 'inventory.json', raw)
        os.fsync(fd)
    finally:
        os.close(fd)
    return {'inventory': output + '/inventory.json', 'inventory_sha256': sha(raw),
            'source_sha256': manifest['source_sha256'], 'files': len(manifest['files']),
            'qualified': False, 'staged': False}


def load_inventory(path, expected):
    require(HEX.fullmatch(expected), 'INVENTORY_PIN')
    parts = absolute_parts(path)
    require(parts[-1] == 'inventory.json', 'INVENTORY_NAME')
    output_name('/' + '/'.join(parts[:-1]), 'plan')
    fd = open_directory('/' + '/'.join(parts[:-1]))
    try:
        value = os.fstat(fd)
        require(value.st_uid == os.getuid() and stat.S_IMODE(value.st_mode) == 0o700,
                'MANIFEST_DIRECTORY_OWNER_MODE')
        raw = read_regular(fd, 'inventory.json', MAX_MANIFEST, owned=True)
    finally:
        os.close(fd)
    require(sha(raw) == expected, 'INVENTORY_PIN_MISMATCH')
    manifest = json.loads(raw)
    require(canonical(manifest) == raw, 'NONCANONICAL_INVENTORY')
    return manifest


def dockerfile(image):
    return (f'FROM {image}\nWORKDIR /app/server/api\n'
            'COPY server/api/src /app/server/api/src\n'
            'COPY server/runtime/src /app/server/runtime/src\n').encode()


def ignorefile(paths):
    admitted = set(paths)
    for path in paths:
        for parent in PurePosixPath(path).parents:
            if str(parent) != '.':
                admitted.add(str(parent) + '/')
    return ('**\n' + ''.join('!' + p + '\n' for p in sorted(admitted))).encode()


def stage(repo, path, expected, output):
    approved = load_inventory(path, expected)
    current, contents = collect(repo)
    require(approved == current, 'INVENTORY_OR_SOURCE_CHANGED')
    generated = {'Dockerfile.api': dockerfile(API_IMAGE),
                 'Dockerfile.worker': dockerfile(WORKER_IMAGE)}
    generated['.dockerignore'] = ignorefile(list(contents) + list(generated))
    payloads = {**contents, **generated}
    context_files = [{'path': name, 'bytes': len(raw), 'sha256': sha(raw)}
                     for name, raw in sorted(payloads.items())]
    receipt = {'version': 1, 'inventory_sha256': expected,
               'source_sha256': current['source_sha256'],
               'context_files': context_files, 'context_sha256': sha(canonical(context_files)),
               'parents': current['parents'], 'qualification': current['qualification'],
               'leftover_parent_files_removed': False,
               'build_executed': False, 'network_or_daemon_used': False}
    # Receipt is public evidence, but default-denied from submitted build context.
    payloads['overlay-manifest.json'] = canonical(receipt)
    fd = new_output(output, 'context')
    try:
        for name, raw in sorted(payloads.items()):
            write_new(fd, name, raw)
        for name, raw in sorted(payloads.items()):
            parent = beneath_directory(fd, name.split('/')[:-1])
            try:
                require(read_regular(parent, name.split('/')[-1], max(MAX_FILE, MAX_MANIFEST)) == raw,
                        'STAGED_FILE_CHANGED')
            finally:
                os.close(parent)
        after, _ = collect(repo)
        require(after == current, 'SOURCE_SET_CHANGED_AFTER_STAGING')
        os.fsync(fd)
    finally:
        os.close(fd)
    return {'context': output, 'context_sha256': receipt['context_sha256'],
            'source_sha256': current['source_sha256'], 'inventory_sha256': expected,
            'files': len(contents), 'qualified': False, 'build_executed': False,
            'manifest_sha256': sha(payloads['overlay-manifest.json'])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    for action in ('inventory', 'stage'):
        command = sub.add_parser(action)
        command.add_argument('--repo', required=True)
        command.add_argument('--output', required=True)
        if action == 'stage':
            command.add_argument('--inventory', required=True)
            command.add_argument('--expected-inventory-sha256', required=True)
    args = parser.parse_args()
    try:
        if args.action == 'inventory':
            result = inventory(args.repo, args.output)
        else:
            result = stage(args.repo, args.inventory, args.expected_inventory_sha256, args.output)
    except (OSError, ValueError) as error:
        # On staging failure retain any own partial output; never clean/reuse/retry automatically.
        print(json.dumps({'ok': False, 'error': str(error) if isinstance(error, Refusal)
                          else type(error).__name__, 'retain_partial_output': True}))
        return 1
    print(json.dumps({'ok': True, **result}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
