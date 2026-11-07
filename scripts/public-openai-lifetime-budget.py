"""Private pipe protocol; all filesystem operations are relative to held dirfds.
flock coordinates cooperating helpers, not arbitrary same-user writers. The Node
operation directory is the persistent crash HOLD; never remove it here.
"""
import base64
from collections import namedtuple
import fcntl
import json
import os
import stat
import sys

NAME = 'openai-deployment.json'
BACKUP = NAME + '.lifetime-budget.original'
PENDING = NAME + '.lifetime-budget.pending'
FIELD = 'LLM_QUOTA_LIFETIME_USER_COST_MICROS'


def need(value):
    if not value:
        raise ValueError('hold')


StableStamp = namedtuple('StableStamp',
                         'dev ino mode uid gid nlink size mtime_ns ctime_ns')


def stable_stamp(value):
    # Reads can change atime; it is not evidence of descriptor mutation.
    return StableStamp(value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                       value.st_gid, value.st_nlink, value.st_size,
                       value.st_mtime_ns, value.st_ctime_ns)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result)
        result[key] = value
    return result


def line():
    value = sys.stdin.buffer.readline(65538)
    need(value.endswith(b'\n') and len(value) <= 65537)
    return value


def emit(value):
    print(json.dumps(value), flush=True)


def encode(value):
    return base64.b64encode(value).decode('ascii')


def main():
    request = json.loads(line(), object_pairs_hook=unique,
                         parse_constant=lambda _: need(False))
    need(set(request) == {'settings', 'apply'} and type(request['apply']) is bool)
    path = request['settings']
    need(os.path.isabs(path) and os.path.normpath(path) == path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open('/', flags)
    # Walk without following aliases, retaining the actual protected directory.
    for part in path.split('/')[1:]:
        next_fd = os.open(part, flags, dir_fd=directory)
        os.close(directory)
        directory = next_fd
    try:
        fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        parent = os.fstat(directory)
        need(parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700)

        def fence():
            current = os.open('/', flags)
            try:
                for part in path.split('/')[1:]:
                    following = os.open(part, flags, dir_fd=current)
                    os.close(current)
                    current = following
                now = os.fstat(current)
                need((now.st_dev, now.st_ino, now.st_uid, now.st_mode) ==
                     (parent.st_dev, parent.st_ino, parent.st_uid, parent.st_mode))
            finally:
                os.close(current)

        def capture(name):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                before = os.fstat(fd)
                need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                     and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                     and before.st_size <= 16384)
                saved_stamp = stable_stamp(before)
                data = os.read(fd, 16385)
                need(len(data) <= 16384 and stable_stamp(os.fstat(fd)) == saved_stamp)
                need(stable_stamp(os.stat(name, dir_fd=directory,
                                          follow_symlinks=False)) == saved_stamp)
                return data, saved_stamp
            finally:
                os.close(fd)

        def absent(name):
            try:
                os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise ValueError('collision')

        def create(name, data):
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            try:
                os.fchmod(fd, 0o600)
                view = memoryview(data)
                while view:
                    count = os.write(fd, view)
                    need(count > 0)
                    view = view[count:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(directory)
            saved = capture(name)
            need(saved[0] == data)
            return saved

        original = capture(NAME)
        value = json.loads(original[0].decode('utf-8'), object_pairs_hook=unique,
                           parse_constant=lambda _: need(False))
        need(value['monetaryLimit'] == 'uncapped' and FIELD not in value['environment'])
        value['environment'][FIELD] = '5000000'
        replacement = (json.dumps(value, ensure_ascii=True, indent=2) + '\n').encode()
        need(len(replacement) <= 16384)
        for name in (BACKUP, PENDING, NAME + '.lifetime-budget.lock'):
            absent(name)
        emit({'before': encode(original[0]), 'after': encode(replacement)})
        need(line() == b'COMMIT\n')
        need(capture(NAME) == original)
        if request['apply']:
            backup = create(BACKUP, original[0])
            pending = create(PENDING, replacement)
            need(capture(NAME) == original and capture(BACKUP) == backup
                 and capture(PENDING) == pending)
            fence()
            os.rename(PENDING, NAME, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
            published = capture(NAME)
            need(published[0] == replacement and published[1].ino == pending[1].ino
                 and published[1].dev == pending[1].dev)
            need(capture(BACKUP) == backup)
        else:
            published = capture(NAME)
            need(published == original)
        emit({'status': 'applied' if request['apply'] else 'check', 'bytes': encode(published[0])})
        need(line() == b'ACK\n')
        need(capture(NAME) == published)
        fence()
    finally:
        os.close(directory)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.stderr.write('LIFETIME_BUDGET_HOLD\n')
        sys.exit(1)
