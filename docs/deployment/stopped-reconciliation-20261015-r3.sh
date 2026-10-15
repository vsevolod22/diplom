#!/bin/sh
# Frozen ONE NEW stopped-stand successor-R3 production attempt; NOT EXECUTED by this reviewer.
# Correctness approval is source/literal-bound; independent final security approval required before parent invocation.
# R2 shell59fe, retirementf46dfa and inventory8c53 are SPENT; attributed retirement ack/inventory PASS are not migration/preservation acceptance or prior-cause proof.
# Required cwd: /Users/vsevolod/Documents/startup/diplom
# Required external caller timeout_ms=660000; controller/stage600s; holder240s/pending160s; pre-pending cleanup45s/pending20s unchanged.
# Fixed fresh R3 lock only: preserve ALL THREE historical lock/HOLD pairs, backups and retained CREATED actor; no reuse/fallback; fresh retired-R2 absence required.
# ONE foreground attempt. Failure/timeout/incomplete receipt: STOP/HOLD; no retry/repair/automatic rollback. Success retains historical HOLDs/manual reconciliation; no unrelated cleanup before rollout completion.
DOCKER_CONTEXT= DOCKER_HOST=unix:///Users/vsevolod/.docker/run/docker.sock PYTHONDONTWRITEBYTECODE=1 \
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -I -B \
server/deploy/trust/recreate_openrouter_key.py \
--reconcile-stopped-stand \
--successor-r3 \
--authorize-held-lock-reconciliation \
--darwin-host-mnt-helper \
--align-api-cve-release \
--release-verifier-relative server/deploy/trust/verify_preservation_release.py \
--release-verifier-test-relative server/deploy/trust/test_verify_preservation_release.py \
--authorize-preservation-window \
--preservation-migration \
--authorize-scan-auth-additive-migration \
--authorize-migration-rw-sandbox-2g-240s \
--api-container 5cbe0936a5f09d663a77960749e687fbd41fbef52c8990b063362b9363d3e9ec \
--api-image sha256:487c3909d3eeee08d60840a81c1adeb61c292aee0a31df17b2a8cf92f6dbb58c \
--worker-container 016c41e7b3eabcbb08903bbc3c54d657ed92c22813e47fa37d444cb448602b44 \
--worker-image sha256:8748cbebba753603d79f320c2fb476c46ab676ce12e0aa08bee0021a3e14e57a \
--web-container b84245ef672d172d5513971a57ea91469800846cdf6c59bedceb006b06caa4f4 \
--web-image sha256:1659b39c98d5183c91feae78a8d9eb1d4c6ee527d541c1e1d74dfe842adee8c0 \
--egress-container 2850e2d03d0681482727f7b5d658961ef9ef2aa829b63473f36d8ed3c63f3d35 \
--egress-image sha256:2b9eff3b381979c82bf42c310fcd7941805d42adeda67c8814143d6503490655 \
--llm-egress-container f64639115f21233277ac52db2bd5ceda495203511da87896ff996e8c1ce3a68a \
--llm-egress-image sha256:3ccbd5a6c3348b7b1c99e23b29d9bdca485dfd48f690a408a119e06163a59a8d \
--candidate-api-image sha256:4b3a3d4b3c2658ec9a36209afcac69eda2b64cef6e055a5e2716e2602e5338d1 \
--candidate-worker-image sha256:891b5adccbe469345cea585e75dc71c6d3bf93405c5a18386795af1b012b314d \
--candidate-web-image sha256:3d14f3d9e7347a9609fe3ae53b46efd70293aacae64da48c001ed6e826155817 \
--candidate-source-aggregate 29c3ca5bd186d625cc102e2f7e43b4f1e8e168ba3372cabd7840cc21b6676a37 \
--sqlite-helper-relative server/deploy/trust/sqlite_state_snapshot.mjs \
--startup-review-evidence DIP-ARTF-502 \
--candidate-source-review-evidence DIP-ARTF-502 \
--migration-review-evidence DIP-ARTF-491 \
--web-source-review-evidence DIP-ARTF-463 \
--confirm-old-api-db-reads-reviewed \
--source-sha256 server/deploy/trust/recreate_openrouter_key.py=a5782ba710d63e822cdb427afcaa6d632606e56cb90b905a38b8e789eba4f70a \
--source-sha256 server/deploy/trust/test_recreate_openrouter_key.py=6cae72c16f14f658e9bc4d92c37853896d5342f32e54a8bbcb860afd15744af7 \
--source-sha256 server/deploy/trust/sqlite_state_snapshot.mjs=323ca629483f92896634ada79d2c8f098d9ff885464eb24ba9d86bb75e563dee \
--source-sha256 server/deploy/trust/sqlite_state_snapshot.test.mjs=f9668e4f288a712969bf50199f38464b3d854d28d3dc4d4e58647c9c7d59453e \
--source-sha256 server/deploy/trust/stand_composition.py=97283889749a4413d5e27f9b0ce828927f56b56ef507cb220a3c607fd3d23f5a \
--source-sha256 server/deploy/compose.stand.yaml=da5c96aaa959e10b32868a458e9cc53e7a819596a33e9ac913f8f2966f552509 \
--source-sha256 server/deploy/compose.stand.vuln.local.yaml=80ec2a655f661cfa5f51fcea0b99e216ae048b356a9c67e830e01d34bcdbe275 \
--source-sha256 server/deploy/compose.stand.nginx.local.yaml=f6587a7a355ac1c51610d65f1851223a72b9e0e64e09f548c3e8faca0ab0e3a6 \
--source-sha256 server/deploy/compose.stand.openrouter.free.yaml=6dcb3afd60363998e98d3ac1629d25c5a166ba00455d1cc735c26d2d686fb326 \
--source-sha256 server/deploy/trust/verify_preservation_release.py=c93ced26d68140f2afe3201db16b373ecc5260a9212fd2075d2e978c1d898533 \
--source-sha256 server/deploy/trust/test_verify_preservation_release.py=04c1748f6f5180225584e0f06e4e80f0e0598f2390a0bbd60296374b504fbd39
