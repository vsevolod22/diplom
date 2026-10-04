#!/usr/bin/env python3
"""Offline conversion of a digest-pinned GHCR DB layer; never downloads or signs.

Pass the independently reviewed OCI manifest and layer digests. Writes a NEW local
release directory, not the running read-only mount. Signing is a separate step.
"""
import gzip
import hashlib
import io
import stat
import json
import os
import re
import shutil
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

MAX_LAYER = 512 * 1024 ** 2
MAX_DB = 2 * 1024 ** 3
MAX_TAR = MAX_DB + 2 * 1024 ** 2
PATTERN = re.compile(r'sha256:[a-f0-9]{64}\Z')
MEDIA = 'application/vnd.aquasec.trivy.db.layer.v1.tar+gzip'


def require(ok):
    if not ok:
        raise ValueError('DB conversion validation failed')


def checksum(path, cap):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= cap)
    sha = hashlib.sha256()
    count = 0
    with path.open('rb') as source:
        while chunk := source.read(1024 * 1024):
            count += len(chunk)
            require(count <= cap)
            sha.update(chunk)
    return 'sha256:' + sha.hexdigest(), count


class BoundedTar(io.RawIOBase):
    """Limit inflated bytes including tar headers, and a single metadata read."""
    def __init__(self, source):
        self.source = source
        self.total = 0

    def readable(self):
        return True

    def read(self, size=-1):
        # tarfile parses PAX/longname records before yielding members. Reject a
        # giant metadata read *before* decompressing or allocating its body.
        require(0 <= size <= 2 * 1024 ** 2)
        require(self.total + size <= MAX_TAR)
        chunk = self.source.read(size)
        self.total += len(chunk)
        require(self.total <= MAX_TAR)
        return chunk


def copy_pinned_layer(source_path, snapshot, expected, expected_size):
    descriptor = os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size == expected_size and 0 < before.st_size <= MAX_LAYER)
        sha = hashlib.sha256()
        size = 0
        with os.fdopen(os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as target:
            while chunk := os.read(descriptor, 1024 * 1024):
                size += len(chunk)
                require(size <= MAX_LAYER and size <= expected_size)
                sha.update(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        after = os.fstat(descriptor)
        require(size == expected_size and (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns) and
                'sha256:' + sha.hexdigest() == expected)
    finally:
        os.close(descriptor)


def convert(candidate, destination, expected_manifest, expected_layer):
    require(PATTERN.fullmatch(expected_manifest) and PATTERN.fullmatch(expected_layer))
    require(candidate.is_dir() and not candidate.is_symlink() and destination.is_absolute())
    parent = destination.parent
    require(parent.is_dir() and not parent.is_symlink() and not destination.exists())
    manifest_path = candidate / 'manifest.json'
    descriptor = os.open(manifest_path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 65536)
        manifest_bytes = os.read(descriptor, 65537)
        require(len(manifest_bytes) == before.st_size and len(manifest_bytes) <= 65536)
        require(os.fstat(descriptor).st_mtime_ns == before.st_mtime_ns)
    finally:
        os.close(descriptor)
    require('sha256:' + hashlib.sha256(manifest_bytes).hexdigest() == expected_manifest)
    manifest = json.loads(manifest_bytes)
    require(isinstance(manifest, dict) and manifest.get('schemaVersion') == 2 and
            manifest.get('mediaType') == 'application/vnd.oci.image.manifest.v1+json')
    layers = manifest.get('layers')
    require(isinstance(layers, list) and len(layers) == 1 and isinstance(layers[0], dict) and
            layers[0].get('mediaType') == MEDIA and layers[0].get('digest') == expected_layer and
            type(layers[0].get('size')) is int and 0 < layers[0]['size'] <= MAX_LAYER)
    layer_path = candidate / 'layer.tar.gz'
    destination.mkdir(mode=0o700)
    snapshot = destination / '.layer.snapshot'
    try:
        copy_pinned_layer(layer_path, snapshot, expected_layer, layers[0]['size'])
        (destination / 'db').mkdir(mode=0o700)
        seen = set()
        with snapshot.open('rb') as compressed, gzip.GzipFile(fileobj=compressed) as expanded:
            with tarfile.open(fileobj=BoundedTar(expanded), mode='r|') as archive:
                for member in archive:
                    require(member.name in ('trivy.db', 'metadata.json') and member.name not in seen and
                            member.isfile() and not member.issym() and not member.islnk() and not member.pax_headers)
                    seen.add(member.name)
                    cap = MAX_DB if member.name == 'trivy.db' else 4096
                    require(0 < member.size <= cap)
                    source = archive.extractfile(member)
                    require(source is not None)
                    if member.name == 'metadata.json':
                        metadata = json.loads(source.read(4097).decode('utf-8'))
                        require(set(metadata) == {'Version', 'UpdatedAt', 'NextUpdate', 'DownloadedAt'} and
                                metadata['Version'] == 2 and member.size <= 4096)
                        # Upstream's DownloadedAt is a placeholder, not a claim about this download.
                        metadata['DownloadedAt'] = datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')
                        raw = json.dumps(metadata, separators=(',', ':'), ensure_ascii=True).encode('ascii')
                        (destination / 'db' / 'metadata.json').write_bytes(raw)
                    else:
                        db_hash = hashlib.sha256()
                        total = 0
                        with (destination / 'db' / 'trivy.db').open('xb') as db, (destination / 'bundle.bin').open('xb') as file:
                            with gzip.GzipFile(filename='', mode='wb', fileobj=file, mtime=0, compresslevel=1) as bundle:
                                while chunk := source.read(1024 * 1024):
                                    total += len(chunk)
                                    require(total <= cap and total <= member.size)
                                    db_hash.update(chunk)
                                    db.write(chunk)
                                    bundle.write(chunk)
                        require(total == member.size)
        snapshot.unlink()
        require(seen == {'trivy.db', 'metadata.json'})
        bundle_hash, bundle_size = checksum(destination / 'bundle.bin', MAX_LAYER)
        require(checksum(destination / 'db' / 'trivy.db', MAX_DB)[0] == 'sha256:' + db_hash.hexdigest())
        return {'manifest': expected_manifest, 'layer': expected_layer, 'bundle': bundle_hash[7:],
                'db': db_hash.hexdigest(), 'bundleBytes': bundle_size}
    except BaseException:
        shutil.rmtree(destination)
        raise


if __name__ == '__main__':
    try:
        require(len(sys.argv) == 5)
        output = convert(Path(sys.argv[1]).resolve(strict=True), Path(sys.argv[2]), sys.argv[3], sys.argv[4])
        print(json.dumps(output, sort_keys=True))  # Public hashes only; NEVER a signing key or blob URL.
        print('Unsigned release: independently review pins, then use operator-only signer.')
    except (OSError, ValueError, tarfile.TarError, UnicodeError, KeyError, TypeError):
        print('DB conversion validation failed', file=sys.stderr)
        sys.exit(1)
