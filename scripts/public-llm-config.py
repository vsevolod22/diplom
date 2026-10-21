#!/usr/bin/env python3
"""Prepare isolated public-8081 LLM settings/key. No Docker, network or legacy state access."""

import fcntl
import getpass
import os
from pathlib import Path
import re
import stat
import sys
import warnings

STATE_PARTS = (".local", "state", "diplom-public-images", "llm")
KEY_NAME = "openrouter.key"
CONFIG_NAME = "llm.env"
KEY_PATTERN = re.compile(r"[A-Za-z0-9_-]{16,512}", re.ASCII)
# Explicit free-only profile: official model/endpoints + ZDR catalog checked 2026-10-21.
# No live generation compatibility/availability guarantee and no automatic fallback.
# Running --prepare explicitly selects this profile; it does not activate a service.
CONFIG = """# Public image-only 8081 API settings; no credentials in this file.
LLM_ENABLED=true
LLM_FREE_ONLY=true
LLM_MODEL=xingchen-agi/xing4.0-29b-a4b:free
LLM_PROVIDER_ALLOWLIST=phala
LLM_POLICY_REVISION=public-8081-xing-phala-v1
LLM_ROUTING_APPROVED=true
LLM_REGION=global
LLM_RETENTION=no-storage
LLM_TIMEOUT_MS=30000
LLM_REQUEST_BYTES=262144
LLM_RESPONSE_BYTES=65536
LLM_MAX_FINDINGS=1000
LLM_OUTPUT_TOKENS=2048
LLM_REQUEST_BUDGET_USD=0
LLM_INPUT_PRICE_PER_MILLION_USD=0
LLM_OUTPUT_PRICE_PER_MILLION_USD=0
LLM_REQUEST_PRICE_USD=0
OPENROUTER_API_KEY_FILE=/run/secrets/public_openrouter_key
LLM_HISTORY_ENABLED=true
LLM_HISTORY_REVISION=owner-history-v1
LLM_HISTORY_AUTHORITY=single-api-quiesced-terminal-v1
LLM_QUOTA_ENABLED=true
LLM_QUOTA_REVISION=public-8081-quota-v1
LLM_QUOTA_WINDOW=utc-day
LLM_QUOTA_USER_INPUT=1048576
LLM_QUOTA_USER_OUTPUT=32768
LLM_QUOTA_USER_COST_USD=0
LLM_QUOTA_SCAN_INPUT=262144
LLM_QUOTA_SCAN_OUTPUT=16384
LLM_QUOTA_SCAN_COST_USD=0
LLM_QUOTA_WARNING_PERCENT=80
LLM_QUOTA_REQUEST_INPUT=65536
LLM_QUOTA_OBSERVATION_TOKENS=1048576
LLM_QUOTA_OBSERVATION_COST_USD=1
LLM_QUOTA_RECEIPT_MS=300000
LLM_QUOTA_REPLAY_DAYS=7
LLM_QUOTA_MAX_ROWS=100000
LLM_QUOTA_DB_BYTES=67108864
LLM_QUOTA_DISK_HEADROOM_BYTES=134217728
LLM_QUOTA_BUSY_MS=1000
LLM_QUOTA_CLEANUP_BATCH=256
"""


class Refusal(Exception):
    pass


def state_path():
    return Path.home().joinpath(*STATE_PARTS)


def open_state(path, create=False):
    """Pin every component, refusing symlinks; only the final state dir must be private."""
    path = Path(path).absolute()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise Refusal("Public LLM state directory must be owner-only (0700).")
        return fd
    except BaseException:
        os.close(fd)
        raise


def create_file(directory_fd, name, payload):
    if name not in (KEY_NAME, CONFIG_NAME):
        raise Refusal("Unsupported public state filename.")
    info = os.fstat(directory_fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Refusal("Unsafe public state directory; no file changed.")
    # Serialize directory users; never read, truncate, rename or replace an existing file.
    fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(fd, payload[offset:])
            if written <= 0:
                raise Refusal("Incomplete write; operator review is required, no overwrite allowed.")
            offset += written
        os.fsync(fd)
        os.fsync(directory_fd)
    finally:
        os.close(fd)


def install_key(directory_fd, key):
    if not isinstance(key, str) or KEY_PATTERN.fullmatch(key) is None:
        raise Refusal("Key format rejected; no file changed.")
    create_file(directory_fd, KEY_NAME, (key + "\n").encode("ascii"))


def present(directory_fd, name):
    """Metadata-only boolean. In particular, never open/read an existing key."""
    try:
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise Refusal("Unsafe public state file; refusing without reading it.")
    return True


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("--prepare", "--set-key", "--status"):
        print("Usage: public-llm-config.py --prepare | --set-key | --status. No key/path arguments accepted.", file=sys.stderr)
        return 1
    mode = sys.argv[1]
    fd = None
    try:
        if mode == "--set-key":
            if not sys.stdin.isatty() or not sys.stderr.isatty():
                raise Refusal("An interactive terminal with hidden input is required; stdin pipes are forbidden.")
            # getpass must never fall back to echoed input.
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                key = getpass.getpass("Public 8081 OpenRouter key (hidden): ")
                confirmation = getpass.getpass("Confirm public key (hidden): ")
            if key != confirmation:
                raise Refusal("Confirmation differs; no file changed.")
            fd = open_state(state_path())
            install_key(fd, key)
            print("Public key saved (0600). No activation or provider request performed.")
        elif mode == "--prepare":
            fd = open_state(state_path(), create=True)
            create_file(fd, CONFIG_NAME, CONFIG.encode("ascii"))
            print("Public non-secret LLM configuration prepared (0600). No activation or database initialization performed.")
        else:
            try:
                fd = open_state(state_path())
            except FileNotFoundError:
                print("Public LLM configuration present: false; public key present: false")
                return 0
            print("Public LLM configuration present: " + str(present(fd, CONFIG_NAME)).lower() +
                  "; public key present: " + str(present(fd, KEY_NAME)).lower())
    except Refusal as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, EOFError, KeyboardInterrupt, getpass.GetPassWarning):
        # Do not print OS error details, user input, keys, file contents or private paths.
        print("Public LLM setup refused or interrupted. Existing files are never overwritten; no credential printed.", file=sys.stderr)
        return 1
    finally:
        if fd is not None:
            os.close(fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
