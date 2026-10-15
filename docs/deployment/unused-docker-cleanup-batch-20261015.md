# Exact public-build snapshot cleanup batch — source-only draft, 2026-10-15

## Status / sequencing

NOT EXECUTED. No new Docker/runtime query is permitted by this document.
USER reports inventory8c53 PASS/SPENT, 18 containers/24 images; these are supplied
observations, not fresh observations here. The old inventory literal and all other
spent operations MUST NOT be rerun or silently repinned. No inventory command is
provided below.

Parent finishes deployment FIRST. Only after independent correctness/security/
source/literal review and exact obsolete-binding provenance acceptance may the
parent execute this separately scoped batch, serially and excluding concurrent
daemon writers. This document does not assert that deployment has finished or
that independent review has accepted the seven historical bindings.

Write scope: only existing `cleanup_unused_docker.py`, its test, and this NEW doc.
No other source, historical doc, paused-holder retirement, controller, HOLD, lock,
backup, actor, volume, base image or private evidence was touched. No Docker or
other runtime queries, runner execution, private Env/DB/log/evidence reads, source
actors or daemon mutations were performed in this source session.

## Frozen source and test

- `server/deploy/trust/cleanup_unused_docker.py`
  SHA256 `d07d118eba9b967f4de4994e870ffacaf6a3f552abfbe093ee3c0cc866e47fd1`.
- `server/deploy/trust/test_cleanup_unused_docker.py`
  SHA256 `a1140660da8c3b1e72192decceaab0a1ebe3f410d3d477e41b293539149d98b5`.
- Public provenance runner `server/deploy/proof/cve14-combined-proof.py`
  SHA256 `945404d04957c86523de0490b5a65f17787010f6733a9a7ead1f76dfcfb4adc0`;
  read/hash/AST inspection only, never imported or executed.

`python3 -I -B server/deploy/trust/test_cleanup_unused_docker.py`: **22 inert
synthetic tests PASS**, author-attributed. Process creation is mocked to fail.
Includes 18-container/24-image fixture, whole-batch preflight, all lifecycle
reference blocking, seven removals with separate bounded transports, exact-ID/tag/
namespace refusal, malformed metadata, partial success/nonzero/timeout/output-cap
receipts, first/middle/last failure, and no retry/fallback/post-query.

The helper captures and verifies ONLY the discovery transport before execution;
the provenance runner is hash-checked but NOT executed. Discovery source/test
pins, fixed socket/executable hash/stat, isolated Python, clean client environment,
explicit host and empty context remain unchanged. Any public CLI-config metadata
entry refuses; no ambient/private Docker config is selected. No executable search,
config read, endpoint fallback or automatic repin.

## Public-source provenance: what was actually established

The pinned public runner establishes two intentional SOURCE BUILD namespaces:

- `diagnose_build`, lines1591–1604: random suffix, exact
  `dip-cve14-diag-snapshot-<suffix>:local`, `make_context`, build, resulting image ID.
- `execute`, lines1629 and1671–1683: random project suffix, exact
  `dip-cve14-snapshot-<suffix>:local`, `make_context`, build, resulting image ID.
- `public_read`/`inventory`, lines164–185 and210–245: allowlisted public inputs,
  source trees/leaves, no-dot/private-path refusal, frozen source hashes.
- `context_files`/`make_context`, lines835–857: only selected public `data` plus
  embedded public proof PROGRAMS, public historical receipt/spec and source map;
  no runtime DB, private recovery/credential files or container rootfs capture.
- `dockerfile`, lines437–455: FROM the exact qualified worker dependency alias,
  COPY selected public source/proof programs, typecheck and in-memory SQLite ABI
  check. `Runner.build`, lines719–722: ordinary `build --network none --pull=false`.
- The worker base is qualified against its fixed immutable ID with no OnBuild or
  Volumes and sensitive configuration keys refused, before tagging/building.
- In `execute`, own generated credentials/env, release binding, fresh storage,
  accounts and runtime/SQL evidence are created/used AFTER image construction
  (lines1691 onward). They are not copied back into the source-build image.
  There is no container-commit/export-to-snapshot path in these build functions.

This distinguishes the PUBLIC RUNNER'S build dataflow from a private runtime
recovery/evidence image. It does **not** prove the origin/content of every observed
immutable image merely because its tag matches. Nor does public source build
origin make every image disposable: the retained c09ce4 image is a counterexample.
The exact seven ID/tag bindings come from USER's inventory report, NOT namespace
inference. The helper accepts ONLY those seven exact pairs, never a prefix selector.

Additional public chronology in `evidence-register-20261009.md` explicitly binds
`d060e223...` to r2 (line43) and `4ca80cff...` to r3 (line58), with historical
script/source identities. That document also records RETAINED failure resources;
it does not authorize deletion now. This session did not establish independent
historical per-ID custody for the other five images or inspect their contents.
Therefore exact obsolete/provenance review remains an explicit EXTERNAL gate,
not a machine-proven fact or a name-based permission. Do not approve the attestation
below simply to bypass this gate. No private evidence read is proposed to fill it.

## Implemented exact batch boundary

New version2 canonical literal plan, 1..7 unique entries, fixed ID/tag/namespace
allowlist, pinned public runner path/SHA, explicit exact-obsolete provenance
attestation and `afterParentDeployment:true`. The latter is a required external
precondition attestation, NOT a deployment-status query or claim. Version1 generic
single-image plans are no longer accepted. There is no default selection.

Always protected: all five original and three candidate image IDs from the HOLD
handoff PLUS full retained history/R10 base
`sha256:c09ce4c8e6185784fad2c263b462952092fa89058d16363ebd543e0cd4bbd50d`
(public binding: `rollout-evidence-update-20261010.md`, line8). Images outside the
seven exact pairs, nginx/python/trivy/busybox bases, all four reported untagged
parents and ALL containers/volumes remain outside deletion scope. Names, labels,
unknown ownership, zero listed references and age do not establish eligibility.

Before ANY removal, a new independent preflight checks the ENTIRE batch:

1. Fresh bounded complete image listing; every selected ID must exist with exactly
   its one expected tag. Missing/retagged/multiply-tagged/untagged member refuses
   the entire batch before any mutation.
2. Fresh bounded all-container listing (all lifecycles; no filters).
3. If any containers exist, one inspect of ALL exact full listed IDs projecting
   ONLY immutable `.Id` and `.Image`. Complete unique membership is mandatory.
   Any immutable reference to ANY selected member refuses the ENTIRE batch,
   even if its display tag moved or is missing. This is independent of8c53's
   non-authoritative `listedReferences` relation. Empty daemon skips inspect.
4. Only after that whole-batch fence: sequential ONE-ID invocations of
   `image rm --no-prune <immutable-ID>` in exact plan order, no force. NEVER one
   multi-ID rm command: Docker might otherwise continue past a failed member.

One shared60s deadline, client10s, external caller75s. At most three metadata
clients x16384 bytes plus seven removal clients x2048 bytes INCLUDING discarded
stderr = **10 calls /63488 transport bytes maximum**, final receipt <=65536 bytes.
Inventory mode remains two calls/65536 transport bytes, but is NOT authorized now.
At most80 container rows/100 image rows; over-cap fails closed, no pagination.
Two captured transport instances (metadata<=3 calls; mutations<=7) share the SAME
deadline and aggregate wrapper budget; the discovery transport's per-instance
8-call guard is not patched/reset. The 60s bound may stop a batch part-way.

No atomic daemon snapshot is claimed. Parent excludes concurrent writers from
preflight through the last removal, AFTER deployment; Docker's non-force conflict
checks are not bypassed. Candidate ancestry is not inferred from tags. Untagged
images are never selected and `--no-prune` prevents cascading parent deletion.

The FIRST nonzero/timeout/cap/malformed or unexpected acknowledgement STOPs the
batch: no later rm, no post-query, retry, fallback, rollback or compensation.
Success requires exactly the reviewed tag's `Untagged:` and exact ID's `Deleted:`
lines; extra digest/layer acknowledgements are conservatively ambiguous.
Receipts contain the canonical `planSha256`, `attemptedImages`,
`confirmedRemovedImages` (strict successful acknowledgements ONLY),
`uncertainImage`, and `notAttemptedImages`. An attempted/possibly attempted failure
requires manual reconciliation/HOLD. Attempts are conservatively recorded before
the guarded client call; guard failure can therefore report an uncertain attempt
even if no child was launched. Deadline between members reports the confirmed
subset, no uncertain next ID, and the untouched suffix. A preflight failure reports
the whole batch unattempted; its false manual-reconciliation flag does NOT release
existing HOLD/locks. No durable replay reservation is created: parent owns one-shot
custody; every attempted invocation is SPENT regardless of outcome.

## Exact draft plan and removal literal — NOT execution approval

The following proposed attestations become truthful only AFTER the external
provenance/obsolete review and parent-completed deployment. Merely generating or
hashing this draft did not satisfy either precondition. Canonical plan is1492 ASCII
bytes, **no final newline**, SHA256:
`3cfb9190747f769c03bfbaa7267abc80dbbbbad930838b8c85c05a5e8ba2237f`.

Required cwd `/Users/vsevolod/Documents/startup/diplom`; external
`timeout_ms=75000`. Parent ONLY, after all gates above. DO NOT RUN NOW.

```sh
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -I -B \
server/deploy/trust/cleanup_unused_docker.py \
--remove-exact-batch-once \
--source-sha256 d07d118eba9b967f4de4994e870ffacaf6a3f552abfbe093ee3c0cc866e47fd1 \
--test-sha256 a1140660da8c3b1e72192decceaab0a1ebe3f410d3d477e41b293539149d98b5 \
--consent-exact-obsolete-image-batch-removal \
--plan-sha256 3cfb9190747f769c03bfbaa7267abc80dbbbbad930838b8c85c05a5e8ba2237f \
--plan-json '{"afterParentDeployment":true,"images":[{"image":"sha256:15197100f752c1fe10615a85b1b33633dd35eb716dce1789320791de86693032","namespace":"combined-source-build","tag":"dip-cve14-snapshot-c68e78d102921bfc:local"},{"image":"sha256:23ffa5aa37f93186a943c5c92b47d2d6eec2df4da37729057c86ab3dd6fb790a","namespace":"combined-source-build","tag":"dip-cve14-snapshot-db0036568330ec7e:local"},{"image":"sha256:4ca2b8083033b718f490ae08ff614c3f593e35d782130e2e5c7f46acc86dcf40","namespace":"combined-source-build","tag":"dip-cve14-snapshot-d8fdd66d9bf40de5:local"},{"image":"sha256:4ca80cff07620171413cdd48c7697547f04829089c5937430e970fc20ac64b5d","namespace":"combined-source-build","tag":"dip-cve14-snapshot-50a215ff36203a77:local"},{"image":"sha256:63602c1f062b998107d827faaadfb9acc486f445d9775a587f5ccfbb65864d25","namespace":"diagnostic-source-build","tag":"dip-cve14-diag-snapshot-7c6ab13aed49881d:local"},{"image":"sha256:d060e223a5e927c134ffbc5c885eea6a0cd9bdbaf1bf218eefc6478b20c6eb25","namespace":"combined-source-build","tag":"dip-cve14-snapshot-50c9f4bae2cec49b:local"},{"image":"sha256:edc9f4875438b5caba2722a67ccf1508fa001db4199b0ef3362bf1b767ce1260","namespace":"combined-source-build","tag":"dip-cve14-snapshot-4b5a7fbb46389420:local"}],"provenance":"reviewed-exact-obsolete-public-build-not-private-evidence-recovery-or-candidate-parent","source":{"path":"server/deploy/proof/cve14-combined-proof.py","sha256":"945404d04957c86523de0490b5a65f17787010f6733a9a7ead1f76dfcfb4adc0"},"version":2}'
```
