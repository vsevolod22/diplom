#!/bin/sh
# Frozen ONE exact retained-PRE metadata-only diagnostic; NOT EXECUTED by reviewer.
# Required cwd: /Users/vsevolod/Documents/startup/diplom
# Parent caller timeout_ms=110000; shared90s/client10s; ONE exact-ID query.
# Require independent security acceptance and continuing exclusive maintenance.
# R4ba3d and prior diagnostic8996 are SPENT; preserve ALL holders/materials.
# No Env/private-leaf reads, inventory, SQL, cp/exec/unpause, writes or cleanup.
# Metadata classification is NOT profile/custody/export/durability qualification.
DOCKER_CONTEXT= DOCKER_HOST=unix:///Users/vsevolod/.docker/run/docker.sock PYTHONDONTWRITEBYTECODE=1 \
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -I -B \
server/deploy/trust/diagnose_retained_pre.py \
--diagnose-retained-pre-metadata-once \
--source-sha256 44b2b7fc61c63df2fd7e9a7fb2331b7c905be88b6a307924b4d5d2a7b970ea91 \
--test-sha256 da42b17f35c50649d1e94e75fe2c94089d9b68f04bfbcc9d63ca9b2fccf2c446
