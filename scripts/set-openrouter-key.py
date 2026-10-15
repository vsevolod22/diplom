#!/usr/bin/env python3
"""Install a replacement key locally; no env loading, activation or provider calls."""

import fcntl
import getpass
import os
from pathlib import Path
import re
import stat
import sys
import warnings


ENV_NAME = ".env.openrouter.local"
# The parent/operator may create exactly these bytes, exclusively, with mode 0600.
EMPTY_FILE = b"# Local OpenRouter API-only replacement key; managed by scripts/set-openrouter-key.py.\n"
KEY_PATTERN = re.compile(r"[A-Za-z0-9_-]{16,512}", re.ASCII)


class Refusal(Exception):
    pass


def open_directory(path):
    """Pin every directory component without following symlinks."""
    path = Path(path).absolute()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def install_key(server_fd, key):
    """Only this fixed new filename is writable; callers own the pinned directory FD."""
    if KEY_PATTERN.fullmatch(key) is None:
        raise Refusal("Key format rejected; no file changed.")
    parent = os.fstat(server_fd)
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
            or parent.st_mode & 0o022):
        raise Refusal("Unsafe target directory; no file changed.")
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    created = False
    try:
        fd = os.open(ENV_NAME, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=server_fd)
        created = True
    except FileExistsError:
        fd = os.open(ENV_NAME, flags, dir_fd=server_fd)
    try:
        # All invocations serialize on the same inode; a competing writer fails closed.
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if created:
            os.fchmod(fd, 0o600)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise Refusal("Unsafe target file; nothing replaced.")
        expected = b"" if created else EMPTY_FILE
        # Read only the exact blank template, never parse or print existing credentials.
        if info.st_size != len(expected) or os.pread(fd, len(expected) + 1, 0) != expected:
            raise Refusal("Target is not the canonical comment-only file; nothing replaced.")
        named = os.stat(ENV_NAME, dir_fd=server_fd, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
            raise Refusal("Target changed concurrently; nothing replaced.")
        payload = EMPTY_FILE + ("OPENROUTER_API_KEY=" + key + "\n").encode("ascii")
        # No truncate, rename, alternate destination or credential overwrite path.
        offset = 0
        while offset < len(payload):
            written = os.pwrite(fd, payload[offset:], offset)
            if written <= 0:
                raise Refusal("Write incomplete; do not retry over this file.")
            offset += written
        os.fsync(fd)
        # Persist the new directory entry before reporting success, not just its bytes.
        os.fsync(server_fd)
    finally:
        os.close(fd)


def main():
    if len(sys.argv) != 1:
        print("No arguments accepted. Enter the replacement key only at the hidden prompt.", file=sys.stderr)
        return 1
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        print("An interactive terminal with hidden input is required.", file=sys.stderr)
        return 1
    try:
        # Fail closed instead of getpass's fallback to echoed input.
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            key = getpass.getpass("Replacement OpenRouter API key (hidden): ")
            confirmation = getpass.getpass("Confirm replacement key (hidden): ")
        if key != confirmation:
            raise Refusal("Confirmation differs; no file changed.")
        if KEY_PATTERN.fullmatch(key) is None:
            raise Refusal("Key format rejected; no file changed.")
        server_fd = open_directory(Path(__file__).absolute().parent.parent / "server")
        try:
            install_key(server_fd, key)
        finally:
            os.close(server_fd)
    except Refusal as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, EOFError, KeyboardInterrupt, getpass.GetPassWarning):
        # OS/terminal exception text can contain sensitive paths or input: never echo it.
        print("Installation refused or interrupted. No credential was printed; do not overwrite an existing file.", file=sys.stderr)
        return 1
    print("Replacement saved to server/.env.openrouter.local (0600). No application or Docker activation performed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
