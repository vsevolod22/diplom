#!/usr/bin/env python3
"""Isolated one-shot volume initializer. stdin is secret; never log it or exceptions."""

import fcntl
import os
import re
import resource
import signal
import stat
import sys

DESTINATION = "/public-llm-secret"
KEY_NAME = "public_openrouter_key"
UID = 65532
GID = 65532


def initialize(directory, source, owner=(UID, GID)):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory_fd = os.open(directory, flags)
    try:
        info = os.fstat(directory_fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError("unsafe volume")
        fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if os.listdir(directory_fd):
            raise ValueError("volume must be empty")
        payload = source.read(514)
        if not isinstance(payload, bytes) or re.fullmatch(rb"[A-Za-z0-9_-]{16,512}\n", payload) is None:
            raise ValueError("invalid input")
        fd = os.open(KEY_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory_fd)
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(fd, payload[offset:])
                if written <= 0:
                    raise OSError("incomplete write")
                offset += written
            os.fchmod(fd, 0o400)
            os.fchown(fd, *owner)
            os.fsync(fd)
            final = os.fstat(fd)
            if (final.st_uid, final.st_gid) != owner or stat.S_IMODE(final.st_mode) != 0o400 or final.st_nlink != 1:
                raise ValueError("unsafe result")
        finally:
            os.close(fd)
        # Keep an open directory FD until durability/ownership are established.
        os.fchmod(directory_fd, 0o500)
        os.fchown(directory_fd, *owner)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    signal.alarm(15)
    try:
        if sys.argv != [sys.argv[0], "--initialize"] or os.geteuid() != 0:
            return 1
        initialize(DESTINATION, sys.stdin.buffer)
        return 0
    except BaseException:
        # No traceback, payload, path, input-derived error or diagnostic output.
        return 1


if __name__ == "__main__":
    sys.exit(main())
