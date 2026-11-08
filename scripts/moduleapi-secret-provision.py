#!/usr/bin/env python3
"""Offline ModuleAPI secret bridge; implementation does not authorize provisioning.

--plan --image <approved-packaged-initializer-image-ID> is inert: no Docker or secret IO.
--provision --image <same-ID> requires separate operator GO. Image MUST be the
explicitly reviewed initializer artifact's local sha256 content ID, never a tag
or a generic Python image. Build separately from moduleapi-secret-init.Dockerfile
with only that Dockerfile and public moduleapi-secret-init.py in its build context;
use an approved digest-pinned PYTHON_BASE. No secret/build arguments or mounts.
The approved final image ID is the code authority, NOT current checkout bytes or
a self-asserted label. Descriptor checks enforce shape, not review/provenance.
No auto-build/pull, checkout-source hashing, mutable code binds or fallback.
The protected ~/.diplom-moduleapi/server.env FD is passed straight to Docker stdin;
this host helper never reads its contents. No key/path arguments or env-file.

Integration: external volume name moduleapi-secrets; API-only READ-ONLY mount at
/run/moduleapi-secrets; file server.env uid/gid65532 mode0400, directory0700.
Initializer source is packaged at /opt/moduleapi-secret-init.py in the approved image;
bootstrap source server/deploy/moduleapi-secret-bootstrap.mjs must be packaged as
/app/server/deploy/moduleapi-secret-bootstrap.mjs in the API image (no key build IO).
Use its exported API_COMMAND/entrypoint contract. No stand/compose changes here.

Lifecycle: reserve Docker name moduleapi-secrets-provision-lock atomically BEFORE
checking/creating a volume. All cooperating provisioning uses this lock. Never
adopt, clear, rotate or delete a volume, or touch any store/application container.
Failure retains the lock and any partial volume for explicit operator review.
The initializer has its own 15s alarm; Docker start is bounded and timeout cleanup
addresses only the newly-created initializer ID. Never reuse a failed volume.
Docker-admin access is trusted; this is not isolation against a malicious daemon.

Import-only seams: commands(image, claim), validate_image_descriptor(image, raw),
open_source(home, uid),
provision(image, run=..., source_opener=...). Use synthetic fixtures only.
Sanitized exit codes: 64 arguments/image, 73 lifecycle, 74 Docker/IO,
75 timeout, 77 source metadata, 78 image descriptor. Init failure is 74.
Only public selected image fields are inspected; never Config.Env or secret diagnostics.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import resource
import stat
import subprocess
import sys
import uuid

VOLUME = 'moduleapi-secrets'
TARGET = '/run/moduleapi-secrets'
LOCK_NAME = 'moduleapi-secrets-provision-lock'
INIT_NAME = 'moduleapi-secrets-init'
MAX_BYTES = 552
DOCKER = ['docker', '--context', 'desktop-linux']
LABEL = 'org.diplom.moduleapi-secret'
CLAIM_LABEL = LABEL + '.claim'
IMAGE_LABEL = LABEL + '.initializer'
IMAGE_ENTRYPOINT = ['/usr/local/bin/python3', '-I', '-S', '-B', '/opt/moduleapi-secret-init.py']
IMAGE_COMMAND = ['--initialize']


class Refusal(Exception):
    def __init__(self, code):
        self.code = code if code in (64, 73, 74, 75, 77, 78) else 74
        super().__init__('MODULEAPI_SECRET_PROVISION_REFUSED')


def commands(image, claim):
    """Pure argv builder: no shell, no key, no source ENV path or fingerprints."""
    if (not isinstance(image, str) or re.fullmatch(r'sha256:[a-f0-9]{64}', image) is None
            or re.fullmatch(r'[a-f0-9]{32}', claim) is None):
        raise Refusal(64)

    restricted = ['--pull=never', '--network=none', '--read-only', '--user=0:0',
                  '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=32',
                  '--memory=64m', '--cpus=0.5', '--ulimit=core=0:0', '--log-driver=none',
                  '--restart=no', '--stop-timeout=1', '--no-healthcheck']
    return {
        # Selected public fields only: never retrieve the complete image config.
        'image': DOCKER + ['image', 'inspect', '--format',
                          '[{{json .Id}},{{json .Os}},{{json .Config.Entrypoint}},'
                          '{{json .Config.Cmd}},{{json .Config.User}},{{json .Config.WorkingDir}},'
                          '{{json .Config.Volumes}},{{json .Config.OnBuild}},'
                          '{{json (index .Config.Labels "org.diplom.moduleapi-secret.initializer")}}]', image],
        # Not started, no volume/secret mount. Container name creation is atomic.
        'lock': DOCKER + ['create', '--name', LOCK_NAME, '--label', CLAIM_LABEL + '=' + claim]
                + restricted + ['--entrypoint=/usr/local/bin/python3', image, '-I', '-S', '-B', '-c', 'pass'],
        'volumes': DOCKER + ['volume', 'ls', '--filter', 'name=^' + VOLUME + '$', '--format', '{{.Name}}'],
        'users': DOCKER + ['ps', '--all', '--filter', 'volume=' + VOLUME, '--format', '{{.ID}}'],
        'volume': DOCKER + ['volume', 'create', '--driver=local', '--label', LABEL + '=v1',
                          '--label', CLAIM_LABEL + '=' + claim, VOLUME],
        'identity': DOCKER + ['volume', 'inspect', '--format',
                             '[{{json .Labels}},{{json .Driver}},{{json .Options}}]', VOLUME],
        'init': DOCKER + ['create', '--name', INIT_NAME, '--interactive'] + restricted
                + ['--cap-add=CHOWN', '--mount', 'type=volume,src=' + VOLUME + ',dst=' + TARGET + ',volume-nocopy',
                   image],
    }


def validate_image_descriptor(image, raw):
    """Require the approved ID and packaged execution shape before secret FD open."""
    try:
        if not isinstance(raw, bytes) or len(raw) > 4096:
            raise Refusal(78)
        value = json.loads(raw)
        if (not isinstance(value, list) or len(value) != 9
                or value[:6] != [image, 'linux', IMAGE_ENTRYPOINT, IMAGE_COMMAND, '0:0', '/']
                or value[6] not in (None, {}) or value[7] not in (None, []) or value[8] != 'v1'):
            raise Refusal(78)
    except (ValueError, TypeError, RecursionError):
        raise Refusal(78) from None


def source_metadata(info, uid):
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) != 0o600 or not 56 <= info.st_size <= MAX_BYTES):
        raise Refusal(77)


def open_source(home, uid):
    """Returns locked directory FD and protected source FD without reading bytes."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    home_fd = os.open(home, flags)
    directory_fd = None
    source_fd = None
    try:
        info = os.fstat(home_fd)
        if info.st_uid != uid or info.st_mode & 0o022:
            raise Refusal(77)
        directory_fd = os.open('.diplom-moduleapi', flags, dir_fd=home_fd)
        info = os.fstat(directory_fd)
        if info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
            raise Refusal(77)
        fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        source_fd = os.open('server.env', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                            dir_fd=directory_fd)
        source_metadata(os.fstat(source_fd), uid)
        return directory_fd, source_fd
    except BaseException:
        if source_fd is not None:
            os.close(source_fd)
        if directory_fd is not None:
            os.close(directory_fd)
        raise Refusal(77) from None
    finally:
        os.close(home_fd)


def verify_source_binding(home, uid, directory_fd, source_fd):
    """Metadata-only path/FD fence; replacing a protected path never changes authority."""
    home_fd = None
    try:
        home_fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        home_info = os.fstat(home_fd)
        directory = os.fstat(directory_fd)
        named_directory = os.stat('.diplom-moduleapi', dir_fd=home_fd, follow_symlinks=False)
        if (home_info.st_uid != uid or home_info.st_mode & 0o022
                or not stat.S_ISDIR(directory.st_mode) or directory.st_uid != uid
                or stat.S_IMODE(directory.st_mode) != 0o700
                or any(getattr(directory, field) != getattr(named_directory, field)
                       for field in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid'))):
            raise Refusal(77)
        source = os.fstat(source_fd)
        named_source = os.stat('server.env', dir_fd=directory_fd, follow_symlinks=False)
        source_metadata(source, uid)
        if any(getattr(source, field) != getattr(named_source, field) for field in
               ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
            raise Refusal(77)
    except (OSError, ValueError):
        raise Refusal(77) from None
    finally:
        if home_fd is not None:
            os.close(home_fd)


def container_id(result):
    value = result.stdout.strip()
    if re.fullmatch(rb'[a-f0-9]{64}', value) is None:
        raise Refusal(74)
    return value.decode('ascii')


def provision(image, run=subprocess.run, source_opener=open_source):
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    claim = uuid.uuid4().hex
    plan = commands(image, claim)
    # No ambient credentials, Docker host/context overrides, PYTHONPATH or proxies.
    child_env = {'HOME': str(home), 'PATH': '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin'}

    def invoke(argv, *, source=subprocess.DEVNULL, capture=False, seconds=25):
        try:
            result = run(argv, stdin=source, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, env=child_env, timeout=seconds, check=False,
                         close_fds=True)
        except subprocess.TimeoutExpired:
            raise Refusal(75) from None
        except BaseException:
            raise Refusal(74) from None
        if result.returncode != 0:
            raise Refusal(74)
        return result

    # The same immutable ID is used at create; checkout edits after this check
    # cannot replace executed code. Descriptor failure opens no secret source.
    validate_image_descriptor(image, invoke(plan['image'], capture=True).stdout)
    directory_fd, source_fd = source_opener(home, os.getuid())
    init_id = None
    try:
        before = os.fstat(source_fd)
        source_metadata(before, os.getuid())
        verify_source_binding(home, os.getuid(), directory_fd, source_fd)
        lock_id = container_id(invoke(plan['lock'], capture=True))
        # Refuse even an empty existing volume or a stopped container referencing it.
        if invoke(plan['volumes'], capture=True).stdout.strip() or invoke(plan['users'], capture=True).stdout.strip():
            raise Refusal(73)
        invoke(plan['volume'])
        identity = json.loads(invoke(plan['identity'], capture=True).stdout)
        if identity != [{LABEL: 'v1', CLAIM_LABEL: claim}, 'local', None]:
            raise Refusal(73)
        init_id = container_id(invoke(plan['init'], capture=True))
        # FD is directly duplicated to child stdin, never read or copied on the host.
        verify_source_binding(home, os.getuid(), directory_fd, source_fd)
        invoke(DOCKER + ['start', '--attach', '--interactive', init_id], source=source_fd)
        after = os.fstat(source_fd)
        source_metadata(after, os.getuid())
        verify_source_binding(home, os.getuid(), directory_fd, source_fd)
        if any(getattr(before, name) != getattr(after, name) for name in
               ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
            raise Refusal(77)
        invoke(DOCKER + ['rm', init_id], seconds=10)
        init_id = None
        invoke(DOCKER + ['rm', lock_id], seconds=10)
    except BaseException:
        # A timed-out Docker client does NOT imply the container stopped. Kill only
        # the ID this attempt created; never use a name to remove another attempt.
        if init_id is not None:
            try:
                invoke(DOCKER + ['rm', '--force', init_id], seconds=10)
            except BaseException:
                pass  # Its in-container alarm also bounds a live initializer.
        # Keep the name lock and volume on every failure, even if apparently empty.
        raise
    finally:
        os.close(source_fd)
        os.close(directory_fd)


class SafeParser(argparse.ArgumentParser):
    def error(self, _message):
        raise Refusal(64)


def main(argv=None):
    try:
        parser = SafeParser(description='Offline ModuleAPI FD-to-volume bridge; no key arguments.', allow_abbrev=False)
        modes = parser.add_mutually_exclusive_group(required=True)
        modes.add_argument('--plan', action='store_true')
        modes.add_argument('--provision', action='store_true')
        parser.add_argument('--image', required=True, help='Reviewed packaged initializer local sha256 image ID (not Python base)')
        args = parser.parse_args(argv)
        plan = commands(args.image, uuid.uuid4().hex)
        if args.plan:
            print(json.dumps({'executed': False, 'commands': plan, 'volume': VOLUME,
                              'target': TARGET + '/server.env', 'secretTransport': 'protected-fd-to-stdin',
                              'initializerAuthority': 'explicitly-reviewed-packaged-image-id',
                              'activation': False}, sort_keys=True))
            return 0
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.umask(0o077)
        provision(args.image)
        print('MODULEAPI_SECRET_PROVISIONED_NOT_ACTIVATED')
        return 0
    except Refusal as error:
        print('MODULEAPI_SECRET_PROVISION_E' + str(error.code), file=sys.stderr)
        return error.code
    except (Exception, KeyboardInterrupt):
        print('MODULEAPI_SECRET_PROVISION_E74', file=sys.stderr)
        return 74


if __name__ == '__main__':
    sys.exit(main())
