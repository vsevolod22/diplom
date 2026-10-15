#!/bin/sh
# NOT EXECUTED by reviewer. ONE read-only current writer-fence diagnostic only.
# Required cwd: /Users/vsevolod/Documents/startup/diplom
# Parent caller timeout_ms=75000; shared60s/client10s; <=6 metadata calls.
# Require independent security acceptance; parent separately handles approved
# cleanup first, then assesses this new invocation. No overlapping daemon work.
# No mutation, adoption, retry, historical-cause finding or rollout authority.
# CLASSIFIED/ok is packet success, not currentMatch or full qualification.
DOCKER_CONTEXT= DOCKER_HOST=unix:///Users/vsevolod/.docker/run/docker.sock PYTHONDONTWRITEBYTECODE=1 \
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -I -B \
server/deploy/trust/diagnose_writer_fence.py \
--diagnose-writer-fence-once \
--source-sha256 637211f9551dd655743f1ff7252bbfc8738b4b0dcbe22da95ad057f1505fc047 \
--test-sha256 82a085938cc40cd43c2c8e82d701a38d1b3cfc428a6bc7c544e7bc487a044446
