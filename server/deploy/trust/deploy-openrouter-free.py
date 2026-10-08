#!/usr/bin/env python3
"""Parent-only LOCAL activation after reviews and online backups. Never calls the model."""
from pathlib import Path
import subprocess
import sys

from stand_composition import select, refresh_lock, write_descriptor_locked, require

REPO = Path(__file__).resolve().parents[3]


def run(command, *args, timeout=180):
    # Compose env_file contains the API key. Never display config, env or raw diagnostics.
    result = subprocess.run((*command, *args), cwd=REPO, capture_output=True, timeout=timeout, check=False)
    require(result.returncode == 0)
    return result.stdout


def deploy(repo=REPO):
    root = Path(repo) / '.local-auth'
    with refresh_lock(root) as capability:
        previous = select(repo)
        require(previous.profile == 'nginx-local')  # Does not activate LOCAL itself.
        write_descriptor_locked(repo, previous.profile, capability, llm='openrouter-free')
        command = select(repo).command  # Frozen through build, recreation and checks.
        started = False
        try:
            run(command, 'config', '--quiet', timeout=30)
            run(command, 'build', 'api', 'web', 'llm-egress', timeout=900)
            started = True
            # Keep worker, JWT, auth/scan volumes, DB pins and host-only signing key untouched.
            run(command, 'up', '-d', '--no-build', '--no-deps', '--wait', '--wait-timeout', '90', 'llm-egress', 'api', 'web')
            run(command, 'exec', '-T', 'web', 'nginx', '-t', timeout=30)
            run(command, 'exec', '-T', 'api', 'node', '--import', 'tsx', '--input-type=module', '-e',
                "import {chainReady} from './src/scans/scan-readiness.ts'; "
                "import {localWorkerReady} from './src/oci/nginx-local-profile.ts'; "
                "process.exit(await chainReady() && await localWorkerReady() ? 0 : 1)", timeout=30)
        except BaseException:
            if not started:
                write_descriptor_locked(repo, previous.profile, capability, llm=previous.llm)
            # After an up attempt retain the selected descriptor for honest operator recovery.
            # Rebuilt image tags are not a verified rollback; parent needs prior image IDs/backups.
            raise
    print('LOCAL composition prepared; parent must check health/auth/report and synthetic model smoke; no live success claimed')


if __name__ == '__main__':
    if sys.argv[1:] != ['--deploy-after-review']:
        print('Not deployed. Parent only: --deploy-after-review after independent reviews, backups and approved routing/retention.')
        sys.exit(2)
    try:
        deploy()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print('LOCAL activation failed; inspect selected composition and prior images privately. No automatic rollback or model fallback.', file=sys.stderr)
        sys.exit(1)
