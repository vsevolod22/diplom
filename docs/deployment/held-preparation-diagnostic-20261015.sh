#!/bin/sh
# Frozen ONE NEW held-preparation diagnostic; NOT READ-ONLY; NOT EXECUTED by this reviewer.
# Correctness approval is source/literal-bound; independent security acceptance required before parent invocation.
# Prior stopped-reconciliation04f35 and prior operation authorities remain SPENT; existing lock/HOLD pairs stay untouched.
# Required cwd: /Users/vsevolod/Documents/startup/diplom
# Required external caller timeout_ms=180000; shared150s; one verifier actor<=90s; ordinary clients<=15s; <=40 clients total.
# Permits fresh OWN private scratch/compiled/alignment/journals plus exact verifier lifecycle, not store/stand mutation.
# Real full preflight + FIRST release recheck then RETURN; no coordination/activate/store holder/SQL/apps/provider.
# Failed actor may be retained; exact verified successful actor alone may be removed under pinned verifier policy.
# STOP after this one result, including PASS. No rollout/adoption/repair/further cleanup authority is granted.
DOCKER_CONTEXT= DOCKER_HOST=unix:///Users/vsevolod/.docker/run/docker.sock PYTHONDONTWRITEBYTECODE=1 \
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -I -B \
server/deploy/trust/diagnose_held_preflight.py \
--prepare-held-preflight \
--source-sha256 55b0aa0ac03c1a5e7af0bbb3a4b349de90431a6d3ec927cb739be4a13c15c2fe \
--test-sha256 4a99a55c6d877a9e6ddc983e2b25dc1e21381c6b9284eb1228f9fe90ab90221b
