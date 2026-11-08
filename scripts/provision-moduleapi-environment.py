"""Prepare a disabled, operator-owned ModuleAPI ENV source; never activate/deploy.

Manual operator command from diplom (no key in argv/history):
  python3 -I -B scripts/provision-moduleapi-environment.py --create
No arguments / --help are inert. No destination or credential options exist.
The account database (NOT HOME/XDG) selects ~/.diplom-moduleapi/server.env:
  MODULEAPI_ENABLED=false\nMODULE_API_KEY=<new hidden local input>\n
Directory 0700, file 0600, exclusive creation, no overwrite/rotation or existing
credential reads. Requires a trusted local terminal without tracing/profiling,
working echo suppression and disabled core dumps. Accepts 16..512 ASCII letters,
digits, underscore or hyphen; this is a safe ENV grammar, NOT provider validation.
Use a newly rotated key, never one posted in chat. Python/getpass may retain
immutable strings in memory; best-effort payload clearing is not secure erasure.

This host file is preparation only, not runtime integration. Never source it in
frontend/build shells, copy it into images, give it to workers, print it or put it
in Compose environment/env_file. Any future API-only transfer/bootstrap requires
separately reviewed integration. No provider calls, billing/consent changes,
privacy guarantees, model equivalence or generation success are established.
"""
import getpass
import os
from pathlib import Path
import pwd
import re
import resource
import stat
import sys
import warnings


DIRECTORY = '.diplom-moduleapi'
FILENAME = 'server.env'
PREFIX = 'MODULEAPI_ENABLED=false\nMODULE_API_KEY='
REFUSED = 'ModuleAPI ENV provisioning refused; no secret output. Check terminal, ownership and existing destination.'


def provision():
    if (sys.gettrace() is not None or sys.getprofile() is not None
            or sys.flags.debug or sys.flags.inspect):
        raise ValueError('debugging refused')
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ValueError('interactive terminal required')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
        raise ValueError('core dumps not disabled')
    os.umask(0o077)
    # Account database, not an arbitrary HOME/XDG/CLI destination override.
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    repository = Path(__file__).resolve().parents[1]
    if not home.is_absolute() or (home / DIRECTORY).resolve().is_relative_to(repository):
        raise ValueError('unsafe destination')
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    home_fd = os.open(home, directory_flags)
    directory_fd = None
    file_fd = None
    created = False
    payload = None
    try:
        info = os.fstat(home_fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o022):
            raise ValueError('unsafe home')
        try:
            os.mkdir(DIRECTORY, mode=0o700, dir_fd=home_fd)
        except FileExistsError:
            pass
        directory_fd = os.open(DIRECTORY, directory_flags, dir_fd=home_fd)
        info = os.fstat(directory_fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError('unsafe directory')
        # Inspect metadata only; even dangling symlinks/FIFOs count as occupied.
        try:
            os.stat(FILENAME, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError('already provisioned')
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            key = getpass.getpass('New ModuleAPI API key (hidden; ModuleAPI stays disabled): ')
        if re.fullmatch(r'[A-Za-z0-9_-]{16,512}', key) is None:
            raise ValueError('invalid credential')
        payload = bytearray((PREFIX + key + '\n').encode('ascii'))
        del key
        file_fd = os.open(FILENAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                          0o600, dir_fd=directory_fd)
        created = True
        info = os.fstat(file_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ValueError('unsafe file')
        written = 0
        while written < len(payload):
            count = os.write(file_fd, memoryview(payload)[written:])
            if count <= 0:
                raise OSError('write failed')
            written += count
        os.fsync(file_fd)
        os.fsync(directory_fd)
    except BaseException:
        if created and directory_fd is not None:
            os.unlink(FILENAME, dir_fd=directory_fd)
        raise
    finally:
        if payload is not None:
            payload[:] = b'\x00' * len(payload)
        if file_fd is not None:
            os.close(file_fd)
        if directory_fd is not None:
            os.close(directory_fd)
        os.close(home_fd)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args in ([], ['--help'], ['-h']):
        print(__doc__)
        return 0
    # Do not let argparse echo unrecognized arguments (potential credentials).
    if args != ['--create']:
        print('ModuleAPI provisioning accepts only --create or --help; no secret output.', file=sys.stderr)
        return 2
    try:
        provision()
    except BaseException:
        print(REFUSED, file=sys.stderr)
        return 1
    print('Created ~/.diplom-moduleapi/server.env (0600). ModuleAPI remains disabled; no deployment performed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
