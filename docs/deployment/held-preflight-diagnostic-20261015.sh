#!/bin/sh
# Frozen ONE NEW no-write held-preflight diagnostic; NOT EXECUTED by this reviewer.
# Correctness approval is source/literal-bound; independent security acceptance required before parent invocation.
# Prior stopped-reconciliation04f35 and all prior operation authorities are SPENT; existing HOLD/locks remain untouched.
# Required cwd: /Users/vsevolod/Documents/startup/diplom
# Required external caller timeout_ms=110000; shared90s; <=12 exact read clients, each<=15s; no retries.
# Existing configuration/inspect data stays private in memory; five coordination paths are metadata-only.
# Real verifier factory LOAD ONLY; unconditional capture-prefix return. No actor/lock/store/lifecycle/cleanup writes.
# STOP after this one result, including PASS. No rollout/adoption/repair/cleanup authority is granted.
DOCKER_CONTEXT= DOCKER_HOST=unix:///Users/vsevolod/.docker/run/docker.sock PYTHONDONTWRITEBYTECODE=1 \
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -I -B \
server/deploy/trust/diagnose_held_preflight.py \
--diagnose-held-preflight \
--source-sha256 b593d0930a081608157296e5f7dc6f5619b61bb972887ca2826dcf23381e29a8 \
--test-sha256 c51b4461f191889b0dd6a2ad0fb1702ff1943e38c868e1610da846c52759192a
