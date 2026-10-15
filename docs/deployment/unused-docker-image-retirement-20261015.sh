#!/bin/sh
# NOT EXECUTED by reviewer. One exact seven-image cleanup attempt only.
# Required cwd: /Users/vsevolod/Documents/startup/diplom
# Parent caller timeout_ms=75000; shared60s/client10s; <=10 calls/63488 bytes.
# Require independent security acceptance of this literal and exclusive daemon
# custody from preflight through final removal; existing deployment HOLD stays.
# No deployment-PASS prerequisite. No R4, fallback, retry or post-query authority.
# STOP on first failure/ambiguity; retain the partial receipt for reconciliation.
DOCKER_CONTEXT= DOCKER_HOST=unix:///Users/vsevolod/.docker/run/docker.sock PYTHONDONTWRITEBYTECODE=1 \
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -I -B \
server/deploy/trust/cleanup_unused_docker.py \
--remove-exact-batch-once \
--source-sha256 8ffe4d3a4566ed30d969ce7b4c49857d275fc09882322fe3d98e82d47e339526 \
--test-sha256 5a4bdf17fd4a5f6a67ea58febf12264ae3da9194f05ee03f28fd8c50d6381a6d \
--authorize-exclusive-held-stand-unused-images \
--plan-sha256 3f46f8ec5076453e7efb2ec9a44703cbadf3f04cb7ba94af7f2a2d69ae4d1775 \
--plan-json '{"images":[{"image":"sha256:15197100f752c1fe10615a85b1b33633dd35eb716dce1789320791de86693032","namespace":"combined-source-build","tag":"dip-cve14-snapshot-c68e78d102921bfc:local"},{"image":"sha256:23ffa5aa37f93186a943c5c92b47d2d6eec2df4da37729057c86ab3dd6fb790a","namespace":"combined-source-build","tag":"dip-cve14-snapshot-db0036568330ec7e:local"},{"image":"sha256:4ca2b8083033b718f490ae08ff614c3f593e35d782130e2e5c7f46acc86dcf40","namespace":"combined-source-build","tag":"dip-cve14-snapshot-d8fdd66d9bf40de5:local"},{"image":"sha256:4ca80cff07620171413cdd48c7697547f04829089c5937430e970fc20ac64b5d","namespace":"combined-source-build","tag":"dip-cve14-snapshot-50a215ff36203a77:local"},{"image":"sha256:63602c1f062b998107d827faaadfb9acc486f445d9775a587f5ccfbb65864d25","namespace":"diagnostic-source-build","tag":"dip-cve14-diag-snapshot-7c6ab13aed49881d:local"},{"image":"sha256:d060e223a5e927c134ffbc5c885eea6a0cd9bdbaf1bf218eefc6478b20c6eb25","namespace":"combined-source-build","tag":"dip-cve14-snapshot-50c9f4bae2cec49b:local"},{"image":"sha256:edc9f4875438b5caba2722a67ccf1508fa001db4199b0ef3362bf1b767ce1260","namespace":"combined-source-build","tag":"dip-cve14-snapshot-4b5a7fbb46389420:local"}],"source":{"path":"server/deploy/proof/cve14-combined-proof.py","sha256":"945404d04957c86523de0490b5a65f17787010f6733a9a7ead1f76dfcfb4adc0"},"version":3}'
