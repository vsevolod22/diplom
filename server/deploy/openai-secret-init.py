#!/usr/bin/env python3
"""One-shot offline initializer; stdin carries the strict operator ENV payload.

Run ONLY through scripts/openai-secret-provision.py using an approved immutable
PACKAGED initializer image (openai-secret-init.Dockerfile), not a Python base
with a host script bind. Image path: /opt/openai-secret-init.py. Runtime has
network=none, no logs/core dumps and a fresh exclusive volume.
No CLI source/destination/owner override. Import is inert for synthetic tests.
Exit codes: 64 arguments, 65 payload, 73 volume, 74 IO, 75 timeout, 77 identity.
Failure is silent. A failed volume is quarantined, never retried or overwritten.
"""
import fcntl
import os
import re
import resource
import signal
import stat
import sys

DESTINATION = '/run/openai-secrets'
FILE_NAME = 'server.env'
OWNER = (65532, 65532)
MAX_BYTES = 549
PATTERN = rb'OPENAI_ENABLED=false\nOPENAI_API_KEY=[A-Za-z0-9_-]{16,512}\n'


class Refusal(Exception):
    def __init__(self, code):
        self.code = code if code in (64, 65, 73, 74, 75, 77) else 74
        super().__init__('OPENAI_SECRET_INIT_REFUSED')


def validate_payload(payload):
    if not isinstance(payload, (bytes, bytearray)) or not 53 <= len(payload) <= MAX_BYTES:
        raise Refusal(65)
    if re.fullmatch(PATTERN, payload) is None:
        raise Refusal(65)


def read_payload(source):
    payload = bytearray()
    try:
        while len(payload) <= MAX_BYTES:
            chunk = source.read(MAX_BYTES + 1 - len(payload))
            if not isinstance(chunk, bytes):
                raise Refusal(65)
            if not chunk:
                break
            payload.extend(chunk)
        validate_payload(payload)
        return payload
    except BaseException:
        payload[:] = b'\x00' * len(payload)
        raise


def initialize(directory, source, owner=OWNER):
    """Synthetic test seam; CLI always uses the fixed destination and owner."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory_fd = os.open(directory, flags)
    payload = bytearray()
    try:
        info = os.fstat(directory_fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_gid != os.getegid() or info.st_mode & 0o7022):
            raise Refusal(73)
        fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if os.listdir(directory_fd):
            raise Refusal(73)
        # Keep root-owned and inaccessible to API until the complete file is durable.
        os.fchmod(directory_fd, 0o700)
        payload = read_payload(source)
        fd = os.open(FILE_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory_fd)
        try:
            offset = 0
            while offset < len(payload):
                count = os.write(fd, memoryview(payload)[offset:])
                if count <= 0:
                    raise Refusal(74)
                offset += count
            os.fchmod(fd, 0o400)
            os.fchown(fd, *owner)
            os.fsync(fd)
            final = os.fstat(fd)
            if (not stat.S_ISREG(final.st_mode) or (final.st_uid, final.st_gid) != owner
                    or stat.S_IMODE(final.st_mode) != 0o400 or final.st_nlink != 1
                    or final.st_size != len(payload)):
                raise Refusal(73)
        finally:
            os.close(fd)
        os.fsync(directory_fd)
        os.fchown(directory_fd, *owner)
        os.fsync(directory_fd)
        final = os.fstat(directory_fd)
        if (final.st_uid, final.st_gid) != owner or stat.S_IMODE(final.st_mode) != 0o700:
            raise Refusal(73)
    finally:
        payload[:] = b'\x00' * len(payload)
        os.close(directory_fd)


def timeout(_signum, _frame):
    raise Refusal(75)


def main(argv=None):
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.umask(0o077)
        signal.signal(signal.SIGALRM, timeout)
        signal.alarm(15)
        if (sys.argv[1:] if argv is None else argv) != ['--initialize']:
            return 64
        if os.geteuid() != 0 or os.getegid() != 0:
            return 77
        initialize(DESTINATION, sys.stdin.buffer)
        return 0
    except Refusal as error:
        return error.code
    except BaseException:
        return 74
    finally:
        signal.alarm(0)


if __name__ == '__main__':
    sys.exit(main())
