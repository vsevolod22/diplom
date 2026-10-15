#!/bin/sh
# Frozen ONE exact paused-holder retirement; NOT EXECUTED by this reviewer.
# Correctness approval conditional on independent final security acceptance of exact sources/literal.
# User informed consent includes loss of exact target rootfs/logs and possibly sole tmpfs recovery material.
# Target ONLY 4dc55f9708f1537fa369ea165aadd050c1f44a6570f0adccb93043d1467d1769; all other resources are non-targets.
# Required cwd: /Users/vsevolod/Documents/startup/diplom; external caller timeout_ms=75000.
# Shared60s/client10s/<=5 clients; bounded internal two-journal custody reads; ONE force rm, NEVER -v.
# No unpause/start/exec/stop, migration, prune, lock/backup removal or follow-up query; ambiguity => STOP/HOLD.
# Success acknowledges removal only, not post-inventory or preservation; manual reconciliation remains.
DOCKER_CONTEXT= DOCKER_HOST=unix:///Users/vsevolod/.docker/run/docker.sock PYTHONDONTWRITEBYTECODE=1 \
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -I -B \
server/deploy/trust/retire_failed_holder.py \
--retire-exact-paused-holder \
--consent-discard-target-rootfs-logs-and-possibly-sole-tmpfs \
--source-sha256 552c98e77a9ce6192ba05454566e32478a24b294f188ca1f0179049c3377bcc5 \
--test-sha256 5032740eb0998eb48e84a0e53caee5424d6aa515fbb1f6623ddd95266b55130c
