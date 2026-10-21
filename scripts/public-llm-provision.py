#!/usr/bin/env python3
"""Explicit operator-only Docker Desktop provisioning. --plan never invokes Docker."""

import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import uuid

spec = importlib.util.spec_from_file_location("public_llm_config", Path(__file__).with_name("public-llm-config.py"))
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)
RECEIPT = "key-volume.json"
PREFIX = "diplom-public-8081-llm-key-"


def commands(image, volume, initializer):
    if re.fullmatch(r"sha256:[a-f0-9]{64}", image) is None or re.fullmatch(PREFIX + r"[a-f0-9]{32}", volume) is None:
        raise config.Refusal("A locally approved immutable image ID and fresh public volume are required.")
    # Only the reviewed initializer source is bound; never the host secret/state dir.
    if any(c in str(initializer) for c in (",", "\n", "\r")):
        raise config.Refusal("Unsupported initializer source path.")
    docker = ["docker", "--context", "desktop-linux"]
    return [
        docker + ["volume", "ls", "--filter", "name=^" + volume + "$", "--format", "{{.Name}}"],
        docker + ["volume", "create", "--driver", "local", "--label", "diplom.public-llm=key-v1", volume],
        docker + ["run", "--rm", "--pull=never", "--name", volume + "-init", "--network=none",
                  "--read-only", "--user=0:0", "--cap-drop=ALL", "--cap-add=CHOWN",
                  "--security-opt=no-new-privileges", "--pids-limit=32", "--memory=64m", "--cpus=0.5",
                  "--ulimit=core=0:0", "--log-driver=none", "--stop-timeout=1", "--interactive",
                  "--mount", "type=volume,src=" + volume + ",dst=/public-llm-secret,volume-nocopy",
                  "--mount", "type=bind,src=" + str(initializer) + ",dst=/public-llm-key-init.py,readonly",
                  "--entrypoint=/usr/local/bin/python3", image, "-I", "-S", "-B", "/public-llm-key-init.py", "--initialize"],
    ]


def provision(image, run=subprocess.run):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    directory = config.open_state(config.state_path())
    source = None
    try:
        fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            os.stat(RECEIPT, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise config.Refusal("Public provisioning receipt already exists; no rotation or Docker action performed.")
        if not config.present(directory, config.KEY_NAME):
            raise config.Refusal("Public key is absent. Use the hidden-input public config helper first.")
        source = os.open(config.KEY_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        info = os.fstat(source)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or not 17 <= info.st_size <= 513):
            raise config.Refusal("Unsafe public key metadata; no Docker action performed.")
        volume = PREFIX + uuid.uuid4().hex
        initializer = Path(__file__).with_name("public-llm-key-init.py").absolute()
        if initializer.is_symlink() or not initializer.is_file():
            raise config.Refusal("Reviewed initializer source is required.")
        plan = commands(image, volume, initializer)
        # Do not inherit provider credentials, Docker host overrides, proxy or env files.
        env = {"HOME": str(Path.home()), "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"}
        common = {"env": env, "stderr": subprocess.DEVNULL, "timeout": 45, "check": True}
        existing = run(plan[0], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, **common)
        if existing.stdout.strip():
            raise config.Refusal("Fresh public volume name collision; no volume changed.")
        run(plan[1], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, **common)
        # FD goes straight to Docker stdin. Host helper never reads secret bytes;
        # child stdout/stderr are discarded even on failure, never captured/forwarded.
        run(plan[2], stdin=source, stdout=subprocess.DEVNULL, **common)
        receipt = json.dumps({"version": 1, "volume": volume, "target": "/run/secrets/public_openrouter_key",
                              "uid": 65532, "gid": 65532, "fileMode": "0400", "directoryMode": "0500",
                              "initializerImage": image}, sort_keys=True).encode("ascii") + b"\n"
        fd = os.open(RECEIPT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as output:
                output.write(receipt)
                output.flush()
                os.fsync(fd)
            os.fsync(directory)
        finally:
            os.close(fd)
        return volume
    finally:
        if source is not None:
            os.close(source)
        os.close(directory)


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise config.Refusal("Invalid provisioning arguments.")


def main():
    parser = SafeParser(description="Public-only stdin-to-volume provisioning; no key/path arguments.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--provision", action="store_true")
    parser.add_argument("--image", required=True, help="Approved locally available Python image ID: sha256:<64 hex>")
    # Fixed message: never echo an unrecognized argument that might be a key.
    try:
        args = parser.parse_args()
        plan = commands(args.image, PREFIX + uuid.uuid4().hex, Path(__file__).with_name("public-llm-key-init.py").absolute())
        if args.plan:
            print(json.dumps({"commands": plan, "secretTransport": "approved-public-file-fd-to-stdin", "executed": False}))
        else:
            print("Provisioned public secret volume: " + provision(args.image))
        return 0
    except (Exception, KeyboardInterrupt):
        print("Public provisioning refused or failed. No credential/child diagnostics printed. Do not reuse a partial volume; operator review required.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
