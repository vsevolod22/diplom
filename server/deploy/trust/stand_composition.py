"""Fixed NONSECRET operator composition. Neither API nor worker reads this selector."""
from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
import tempfile

OVERLAY = 'server/deploy/compose.stand.nginx.local.yaml'
BASES = ('server/deploy/compose.stand.yaml', 'server/deploy/compose.stand.vuln.local.yaml')


def require(ok):
    if not ok:
        raise ValueError('Invalid operator composition')


def private_root(root):
    st = root.lstat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and not st.st_mode & 0o022)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


@dataclass(frozen=True)
class Composition:
    profile: str
    files: tuple
    command: tuple


def select(repo, root=None, env=None):
    repo = Path(repo).resolve(strict=True)
    root = Path(root) if root is not None else repo / '.local-auth'
    env = Path(env) if env is not None else root / 'stand.env'
    private_root(root)
    path = root / 'stand-composition.json'
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        # A dangling symlink is NOT a missing descriptor.
        require(not path.is_symlink())
        descriptor = {'profile': 'default'}
    else:
        try:
            st = os.fstat(fd)
            require(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and
                    not st.st_mode & 0o022 and 0 < st.st_size <= 1024)
            data = os.read(fd, 1025)
            after = os.fstat(fd)
            require(len(data) == st.st_size and (st.st_ino, st.st_size, st.st_mtime_ns) ==
                    (after.st_ino, after.st_size, after.st_mtime_ns))
            descriptor = json.loads(data, object_pairs_hook=unique_object)
        finally:
            os.close(fd)
    require(type(descriptor) is dict and set(descriptor) <= {'profile', 'overlay'} and
            descriptor.get('profile') in ('default', 'nginx-local'))
    local = descriptor['profile'] == 'nginx-local'
    require(descriptor.get('overlay', OVERLAY if local else None) == (OVERLAY if local else None))
    files = BASES + ((OVERLAY,) if local else ())
    for relative in files:
        path = repo / relative
        require(path.resolve(strict=True) == path and path.is_file())
        for ancestor in (path, *path.parents):
            require(not ancestor.is_symlink())
            if ancestor == repo:
                break
        require(not path.stat().st_mode & 0o022)
    command = ['docker', 'compose', '--env-file', str(env)]
    for relative in files:
        command.extend(('-f', str(repo / relative)))
    return Composition(descriptor['profile'], files, tuple(command))


_held_locks = {}


@contextmanager
def refresh_lock(root):
    root = Path(root).absolute()
    private_root(root)
    lock = root / '.trivy-refresh.lock'
    lock.mkdir(mode=0o700)  # No removal/reuse of a foreign lock.
    identity = lock.stat()
    capability = object()
    _held_locks[capability] = (root, identity.st_dev, identity.st_ino, os.getpid())
    try:
        yield capability
    finally:
        _held_locks.pop(capability, None)
        current = lock.lstat()
        require(current.st_ino == identity.st_ino and current.st_dev == identity.st_dev)
        lock.rmdir()


def write_descriptor_locked(repo, profile, capability, root=None):
    """Integrator calls under refresh_lock only, after reviews/config validation.

    Returns previous bytes for rollback. Does not deploy, sign or change env pins.
    """
    root = (Path(root) if root is not None else Path(repo) / '.local-auth').absolute()
    private_root(root)
    held = _held_locks.get(capability)
    require(held is not None and held[0] == root and held[3] == os.getpid())
    lock = (root / '.trivy-refresh.lock').lstat()
    require((lock.st_dev, lock.st_ino) == held[1:3])
    require(stat.S_ISDIR(lock.st_mode) and lock.st_uid == os.geteuid() and not lock.st_mode & 0o077)
    select(repo, root)  # Reject malformed existing state instead of overwriting it.
    require(profile in ('default', 'nginx-local'))
    path = root / 'stand-composition.json'
    previous = path.read_bytes() if path.exists() else None
    descriptor = {'profile': profile}
    if profile == 'nginx-local':
        descriptor['overlay'] = OVERLAY
    fd, name = tempfile.mkstemp(prefix='.composition-', dir=root)
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(json.dumps(descriptor, separators=(',', ':')) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(root, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    return previous
