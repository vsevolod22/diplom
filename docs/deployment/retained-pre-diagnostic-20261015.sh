#!/bin/sh
# Frozen ONE retained-host-PRE read-only diagnostic; NOT EXECUTED by reviewer.
# Required cwd: /Users/vsevolod/Documents/startup/diplom
# Parent caller timeout_ms=110000; shared90s/client10s; <=5 metadata clients.
# Require independent security acceptance and continued exclusive maintenance.
# R4ba3d is SPENT. Preserve ALL holders/locks/journals/backups; no retry/cleanup.
# Host PRE observation only: no fsync/SQL/source DB/exec/cp/unpause/write.
# ABSENT or VALIDATED_READ_ONLY is NOT export certification or disposal authority.
DOCKER_CONTEXT= DOCKER_HOST=unix:///Users/vsevolod/.docker/run/docker.sock PYTHONDONTWRITEBYTECODE=1 \
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -I -B \
server/deploy/trust/diagnose_retained_pre.py \
--diagnose-retained-pre-once \
--source-sha256 659bf64ffdf5536a317e44eda8b3794574afaaf418b3a80c2eb8ac3262f76519 \
--test-sha256 ef02e01aebdc7781c3e5283baaa1e07334bc2e63e058f0ba1ebdcf417c503aa0
