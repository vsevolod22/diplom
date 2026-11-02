#!/usr/bin/env python3
"""Prepare isolated public-8081 LLM settings/key. No Docker, network or legacy state access."""

import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import warnings

STATE_PARTS = (".local", "state", "diplom-public-images", "llm")
KEY_NAME = "openrouter.key"
CONFIG_NAME = "llm.env"
OPENAI_CONFIG_NAME = "openai-deployment.json"
KEY_PATTERN = re.compile(r"[A-Za-z0-9_-]{16,512}", re.ASCII)
# Explicit operator-selected Dots replacement: no-training is NOT no-storage/ZDR.
# Reported metadata: NVIDIA training=true conflicts with API data_collection=deny;
# Dots training=false but prompts are retained. One reported synthetic HTTP 200,
# cost=0, exact-model stop is compatibility evidence only, not a quality guarantee.
# No automatic fallback or live availability guarantee.
# Running --prepare explicitly selects v5 report4096; it does not activate a service.
CONFIG = """# Public image-only 8081 API settings; no credentials in this file.
LLM_ENABLED=true
LLM_FREE_ONLY=true
LLM_MODEL=dots-studio/dots-3-note-preview:free
LLM_PROVIDER_ALLOWLIST=atlas-cloud/fp8
LLM_POLICY_REVISION=public-8081-remediation-4k-v1
LLM_ROUTING_APPROVED=true
LLM_REGION=global
LLM_RETENTION=no-training
LLM_TIMEOUT_MS=90000
LLM_REQUEST_BYTES=262144
LLM_RESPONSE_BYTES=65536
LLM_MAX_FINDINGS=1000
LLM_OUTPUT_TOKENS=4096
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


# Exact historical bytes remain the only eligible sources for their respective migrations.
DOTS_CONFIG = (CONFIG.replace('LLM_OUTPUT_TOKENS=4096\n', 'LLM_OUTPUT_TOKENS=2048\n')
               .replace('public-8081-remediation-4k-v1', 'public-8081-dots-v1'))
NVIDIA_CONFIG = (DOTS_CONFIG.replace('dots-studio/dots-3-note-preview:free', 'nvidia/nemotron-3.5-super-vl:free')
                 .replace('LLM_PROVIDER_ALLOWLIST=atlas-cloud/fp8\n', 'LLM_PROVIDER_ALLOWLIST=nvidia\n')
                 .replace('public-8081-dots-v1', 'public-8081-nvidia-v1'))
XING_CONFIG = (NVIDIA_CONFIG.replace('nvidia/nemotron-3.5-super-vl:free', 'xingchen-agi/xing4.0-29b-a4b:free')
               .replace('LLM_PROVIDER_ALLOWLIST=nvidia\n', 'LLM_PROVIDER_ALLOWLIST=phala\n')
               .replace('public-8081-nvidia-v1', 'public-8081-xing-phala-v1')
               .replace('LLM_RETENTION=no-training\n', 'LLM_RETENTION=no-storage\n'))
LEGACY_CONFIG = XING_CONFIG.replace('LLM_TIMEOUT_MS=90000\n', 'LLM_TIMEOUT_MS=30000\n')
TIMEOUT_BACKUP = 'llm.env.timeout-30-original'
TIMEOUT_PENDING = 'llm.env.timeout-90-pending'
MIGRATION_INTENT = b'{"version":1,"project":"dip-public-images","command":"public-llm-config-30-to-90","lifecycle":false}'
NVIDIA_BACKUP = 'llm.env.xing-90-original-before-nvidia-v1'
NVIDIA_PENDING = 'llm.env.nvidia-v1-pending'
NVIDIA_INTENT = b'{"version":1,"project":"dip-public-images","command":"public-llm-config-xing90-to-nvidia-v1","lifecycle":false}'
DOTS_BACKUP = 'llm.env.nvidia-90-original-before-dots-v1'
DOTS_PENDING = 'llm.env.dots-v1-pending'
DOTS_INTENT = b'{"version":1,"project":"dip-public-images","command":"public-llm-config-nvidia90-to-dots-v1","lifecycle":false}'
REPORT4K_BACKUP = 'llm.env.dots-2048-original-before-report4k-v1'
REPORT4K_PENDING = 'llm.env.report4k-v1-pending'
REPORT4K_INTENT = b'{"version":1,"project":"dip-public-images","command":"public-llm-config-dots2048-to-report4096-v1","lifecycle":false}'


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
    if name not in (KEY_NAME, CONFIG_NAME, OPENAI_CONFIG_NAME):
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


def upgrade_timeout(directory_fd, verify, *, check_only=False, expected=None):
    return migrate_config(directory_fd, verify, LEGACY_CONFIG, XING_CONFIG, TIMEOUT_BACKUP, TIMEOUT_PENDING,
                          check_only=check_only, expected=expected)


def migrate_nvidia(directory_fd, verify, *, check_only=False, expected=None):
    return migrate_config(directory_fd, verify, XING_CONFIG, NVIDIA_CONFIG, NVIDIA_BACKUP, NVIDIA_PENDING,
                          check_only=check_only, expected=expected)


def migrate_dots(directory_fd, verify, *, check_only=False, expected=None):
    return migrate_config(directory_fd, verify, NVIDIA_CONFIG, DOTS_CONFIG, DOTS_BACKUP, DOTS_PENDING,
                          check_only=check_only, expected=expected)


def migrate_report4k(directory_fd, verify, *, check_only=False, expected=None):
    return migrate_config(directory_fd, verify, DOTS_CONFIG, CONFIG, REPORT4K_BACKUP, REPORT4K_PENDING,
                          check_only=check_only, expected=expected)


def migrate_config(directory_fd, verify, prior, target, backup, pending, *, check_only=False, expected=None):
    """Only the coordinator calls this under the shared public lock. No key metadata/read."""
    fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    identity = os.fstat(directory_fd)

    def fence():
        verify()
        check = open_state(state_path())
        try:
            current = os.fstat(check)
            if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
                raise Refusal('Public config directory changed; HOLD, no retry.')
        finally:
            os.close(check)

    def read_config():
        before = os.stat(CONFIG_NAME, dir_fd=directory_fd, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > 16384):
            raise Refusal('Unsafe public config; no read permitted.')
        fd = os.open(CONFIG_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory_fd)
        try:
            stamp = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if stamp(before) != stamp(os.fstat(fd)):
                raise Refusal('Public config identity changed; HOLD.')
            payload = b''
            while len(payload) <= 16384:
                block = os.read(fd, 16385 - len(payload))
                if not block:
                    break
                payload += block
            if (len(payload) != before.st_size or stamp(before) != stamp(os.fstat(fd)) or
                    stamp(before) != stamp(os.stat(CONFIG_NAME, dir_fd=directory_fd, follow_symlinks=False))):
                raise Refusal('Public config changed during read; HOLD.')
            return payload, stamp(before)
        finally:
            os.close(fd)

    def absent(name):
        try:
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise Refusal('Public config backup/pending already exists; HOLD, no retry or overwrite.')

    def stamp_file(s):
        return (s.st_dev, s.st_ino, s.st_uid, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

    def exclusive(name, payload):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
        try:
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(payload):
                n = os.write(fd, payload[offset:])
                if n <= 0:
                    raise Refusal('Public config write incomplete; HOLD.')
                offset += n
            os.fsync(fd)
            identity = stamp_file(os.fstat(fd))
        finally:
            os.close(fd)
        os.fsync(directory_fd)

        def verify_file():
            s = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stamp_file(s) != identity:
                raise Refusal('Public config backup/pending identity changed; HOLD.')
        verify_file()
        return verify_file

    fence()
    absent(backup)
    absent(pending)
    original, stamp = read_config()
    if original != prior.encode('ascii'):
        raise Refusal('Only the exact prior public config is eligible; no file changed.')
    eligibility = {'version': 1, 'eligible': True,
                   'directory': [str(v) for v in (identity.st_dev, identity.st_ino, identity.st_uid, identity.st_mode)],
                   'config': [str(v) for v in stamp]}
    if expected is not None and eligibility != expected:
        raise Refusal('Public config eligibility changed; no file changed.')
    fence()
    if check_only:
        if read_config() != (original, stamp):
            raise Refusal('Public config eligibility changed; no file changed.')
        return eligibility
    backup_verify = exclusive(backup, original)
    fence()
    pending_verify = exclusive(pending, target.encode('ascii'))
    fence()
    backup_verify()
    pending_verify()
    if read_config() != (original, stamp):
        raise Refusal('Public config replaced before commit; HOLD.')
    fence()
    os.rename(pending, CONFIG_NAME, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
    os.fsync(directory_fd)
    fence()
    backup_verify()
    if read_config()[0] != target.encode('ascii'):
        raise Refusal('Public config postflight failed; HOLD.')


def coordinator_upgrade(lock_fd=3, intent_fd=4, *, check_only=False, migration='timeout'):
    """Inherited directory capability; no arbitrary path, timeout, profile or key arguments."""
    if migration not in ('timeout', 'nvidia', 'dots', 'report4k'):
        raise Refusal('Unsupported public config migration.')
    intent_bytes = {'timeout': MIGRATION_INTENT, 'nvidia': NVIDIA_INTENT, 'dots': DOTS_INTENT, 'report4k': REPORT4K_INTENT}[migration]
    root = Path(__file__).absolute().parent.parent
    lock_path = root / '.local-public-images' / '.operation.lock'
    lock_identity = os.fstat(lock_fd)  # inherited fd 3 in the CLI; no path/FD arguments
    if (not stat.S_ISDIR(lock_identity.st_mode) or lock_identity.st_uid != os.geteuid() or
            stat.S_IMODE(lock_identity.st_mode) != 0o700):
        raise Refusal('Public coordinator lock required.')
    if sys.stdin.isatty():
        raise Refusal('Public coordinator source fence required; no interactive migration.')
    inputs = json.loads(sys.stdin.buffer.read(4097))
    if (not isinstance(inputs, dict) or
            set(inputs) != ({'sources'} if check_only else {'sources', 'eligibility'})):
        raise Refusal('Exact public coordinator phase inputs required.')
    expected = inputs['sources']
    names = ('public-llm-stand.mjs', 'public-llm-config.py')
    if (not isinstance(expected, dict) or set(expected) != set(names) or
            any(not isinstance(v, str) or re.fullmatch(r'[a-f0-9]{64}', v) is None for v in expected.values())):
        raise Refusal('Public config source fence required.')
    eligibility = None if check_only else inputs['eligibility']
    if not check_only:
        if (not isinstance(eligibility, dict) or set(eligibility) != {'version', 'eligible', 'directory', 'config'} or
                type(eligibility['version']) is not int or eligibility['version'] != 1 or eligibility['eligible'] is not True or
                any(not isinstance(eligibility[k], list) or len(eligibility[k]) != n or
                    any(not isinstance(v, str) or re.fullmatch(r'[0-9]+', v) is None for v in eligibility[k])
                    for k, n in (('directory', 4), ('config', 8)))):
            raise Refusal('Exact read-only eligibility receipt required.')
    source_stamps = {}
    intent_stamp = None
    stamp = lambda v: (v.st_dev, v.st_ino, v.st_mode, v.st_uid, v.st_nlink, v.st_size, v.st_mtime_ns, v.st_ctime_ns)

    def verify():
        nonlocal intent_stamp
        lock = open_state(lock_path)
        try:
            s = os.fstat(lock)
            if (s.st_dev, s.st_ino) != (lock_identity.st_dev, lock_identity.st_ino):
                raise Refusal('Public coordinator lock changed; HOLD.')
            if sorted(os.listdir(lock)) != ([] if check_only else ['mutation.json']):
                raise Refusal('Unexpected public coordinator lock contents; no config access permitted.')
            if not check_only:
                info = os.fstat(intent_fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or
                        stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != len(intent_bytes) or
                        fcntl.fcntl(intent_fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY):
                    raise Refusal('Pinned read-only public migration intent required.')
                if intent_stamp is None:
                    intent_stamp = stamp(info)
                if (stamp(info) != intent_stamp or
                        stamp(os.stat('mutation.json', dir_fd=lock, follow_symlinks=False)) != intent_stamp or
                        os.pread(intent_fd, len(intent_bytes) + 1, 0) != intent_bytes or
                        stamp(os.fstat(intent_fd)) != intent_stamp):
                    raise Refusal('Public migration intent changed or unrelated HOLD; no config access permitted.')
        finally:
            os.close(lock)
        for name in names:
            path = root / 'scripts' / name
            if path.resolve() != path:
                raise Refusal('Aliased public config source; HOLD.')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                s = os.fstat(fd)
                if (not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_uid != os.geteuid() or
                        s.st_mode & 0o022 or s.st_size > 262144):
                    raise Refusal('Unsafe public config source; HOLD.')
                data = b''
                while len(data) <= 262144:
                    block = os.read(fd, 262145 - len(data))
                    if not block:
                        break
                    data += block
                initial = source_stamps.setdefault(name, stamp(s))
                if (len(data) != s.st_size or initial != stamp(os.fstat(fd)) or
                        initial != stamp(os.stat(path, follow_symlinks=False)) or path.resolve() != path or
                        hashlib.sha256(data).hexdigest() != expected[name]):
                    raise Refusal('Public config source changed; HOLD.')
            finally:
                os.close(fd)

    verify()
    fd = open_state(state_path())
    try:
        migrate = {'timeout': upgrade_timeout, 'nvidia': migrate_nvidia, 'dots': migrate_dots, 'report4k': migrate_report4k}[migration]
        return migrate(fd, verify, check_only=check_only, expected=eligibility)
    finally:
        os.close(fd)


def prepare_openai():
    """Explicit nonsecret v6 descriptor via bounded stdin; never opens server.env."""
    payload = sys.stdin.buffer.read(16385)
    if not payload or len(payload) > 16384:
        raise Refusal('OpenAI descriptor refused; no values printed.')
    root = Path(__file__).absolute().parents[1]
    destination = state_path()
    if destination == root or root in destination.parents:
        raise Refusal('OpenAI configuration must remain outside the source tree.')
    try:
        result = subprocess.run(['node', str(root / 'scripts/public-openai-config.mjs')],
                                input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                cwd=root, env={'PATH': '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin'},
                                timeout=10, check=False)
        if result.returncode != 0 or not result.stdout or len(result.stdout) > 16384:
            raise Refusal('OpenAI descriptor refused; no values printed.')
    except (OSError, subprocess.TimeoutExpired):
        raise Refusal('OpenAI descriptor validator unavailable; nothing installed.') from None
    fd = open_state(destination)
    try:
        create_file(fd, OPENAI_CONFIG_NAME, result.stdout)
    finally:
        os.close(fd)


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("--prepare", "--prepare-openai", "--set-key", "--status", "--coordinator-check-timeout", "--coordinator-commit-timeout", "--coordinator-check-nvidia", "--coordinator-commit-nvidia", "--coordinator-check-dots", "--coordinator-commit-dots", "--coordinator-check-report4k", "--coordinator-commit-report4k"):
        print("Usage: public-llm-config.py --prepare | --set-key | --status. No key/path arguments accepted.", file=sys.stderr)
        return 1
    mode = sys.argv[1]
    fd = None
    try:
        if mode == '--prepare-openai':
            prepare_openai()
            print('OpenAI nonsecret v6 descriptor prepared (0600); no key, volume, activation or database operation.')
        elif mode == '--coordinator-check-timeout':
            print(json.dumps(coordinator_upgrade(check_only=True), separators=(',', ':')))
        elif mode == '--coordinator-commit-timeout':
            coordinator_upgrade()
            print('Public nonsecret timeout config upgraded 30s to 90s; original exclusive backup retained. No activation performed.')
        elif mode == '--coordinator-check-nvidia':
            print(json.dumps(coordinator_upgrade(check_only=True, migration='nvidia'), separators=(',', ':')))
        elif mode == '--coordinator-commit-nvidia':
            coordinator_upgrade(migration='nvidia')
            print('Public nonsecret config migrated from exact Xing90 to NVIDIA non-ZDR; original backup retained. No activation performed.')
        elif mode == '--coordinator-check-dots':
            print(json.dumps(coordinator_upgrade(check_only=True, migration='dots'), separators=(',', ':')))
        elif mode == '--coordinator-commit-dots':
            coordinator_upgrade(migration='dots')
            print('Public nonsecret config migrated from exact NVIDIA90 to Dots non-ZDR/no-training; original backup retained. No activation performed.')
        elif mode == '--coordinator-check-report4k':
            print(json.dumps(coordinator_upgrade(check_only=True, migration='report4k'), separators=(',', ':')))
        elif mode == '--coordinator-commit-report4k':
            coordinator_upgrade(migration='report4k')
            print('Public nonsecret config migrated from exact Dots2048 to report4096; original backup retained. No activation performed.')
        elif mode == "--set-key":
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
    except (OSError, ValueError, EOFError, KeyboardInterrupt, getpass.GetPassWarning):
        # Do not print OS error details, user input, keys, file contents or private paths.
        print("Public LLM setup refused or interrupted; no credential printed. For config migration: HOLD, no retry or cleanup.", file=sys.stderr)
        return 1
    finally:
        if fd is not None:
            os.close(fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
