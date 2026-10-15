#!/bin/sh
# Frozen ONE inventory-only operation; NOT EXECUTED by this reviewer.
# Correctness approval conditional on independent final security acceptance of exact sources/literal.
# Required cwd: /Users/vsevolod/Documents/startup/diplom; external caller timeout_ms=75000.
# Shared60s/client10s; ONLY container ls and image ls; <=80 containers/100 image rows.
# Each combined client stream <=32768B; aggregate transport <=65536B; public receipt <=65536B.
# No Env/args/labels/mounts/logs/private files or lifecycle/mutation/prune commands.
# Listed tag associations are NOT immutable reference/non-use proof; NO removal selected or authorized.
# No automatic deletion branch, retry or follow-up authority, including after an ambiguous retirement result.
DOCKER_CONTEXT= DOCKER_HOST=unix:///Users/vsevolod/.docker/run/docker.sock PYTHONDONTWRITEBYTECODE=1 \
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -I -B \
server/deploy/trust/cleanup_unused_docker.py \
--inventory-once \
--source-sha256 ec6ae691cc31eed7dd049cb80299e45c3ba2c5b280713b88a297db740a04dfcd \
--test-sha256 51f1890f2acb655a88ac730ae6536e7ebfed523b866a0f5e08be8bc027293bb5
