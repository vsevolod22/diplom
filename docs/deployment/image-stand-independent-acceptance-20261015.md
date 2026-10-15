# Independent acceptance — isolated image-only stand, 2026-10-15

## Verdict

**PASS — the bounded default image-only secrets + SBOM smoke and its explicitly exercised HTTP/browser/isolation/cleanup checks are accepted for this single run.** No concrete blocker was found in the reviewed result/source correspondence.

This is independent acceptance of the parent-executed native run, not another execution and not the harness author's self-approval. Reviewer: Zed coding agent, GPT-6.1-Sol. Acceptance is based on the sanitized saved result and ownership journal, checked against the previously reviewed, unchanged harness source. It is not a new live Engine observation or a cryptographically attested execution trace.

**Not full 36-point acceptance, production deployment acceptance, recovery acceptance, or removal of HOLD.** Remaining gates are listed below.

## Evidence boundary and identity

- Project: `dip-image-stand-08faa29110d44d0f9a8b6ac610020fad`.
- Product baseline recorded by the run: `636b834fa7d3c4d8114ecb4cf4fcc9357ca075e7`.
- Result: **PASS**, phase `checks_finished`, elapsed **39.301s**, no recorded error.
- Execution mode: `PREBUILT_ONLY_NO_BUILD_PULL_HISTORY`; deployment marker: `NOT_PRODUCTION`.
- [Sanitized result](../../test-results/dip-image-stand-08faa29110d44d0f9a8b6ac610020fad/result.json).
- [Own resource journal](../../test-results/dip-image-stand-08faa29110d44d0f9a8b6ac610020fad/owned-resources.json).
- [Reviewed harness source](../../server/deploy/proof/final-image-stand.py).

Current source SHA-256 was recomputed and matches the result's reviewed-source pin and the independently approved revision:

```text
72af124c0a5e1d9821211f0bdd71a7f7583bb4cbb35ed6911bf754839ef9cd46  server/deploy/proof/final-image-stand.py
99d278876b7c8be5afd343e69b0159bbe119a74ca2b9e15ef58c967edfe67d6a  test-results/dip-image-stand-08faa29110d44d0f9a8b6ac610020fad/result.json
ade6ad695f35909565d2c8c93967f3bcf5929bc0948b0e741a3122000902a8aa  test-results/dip-image-stand-08faa29110d44d0f9a8b6ac610020fad/owned-resources.json
```

These are local snapshot hashes, not an external evidence seal. The result also records the approved prebuilt manifest SHA-256 `307e41943229878004438a6660ce23edc2fb255daeb6ca19b01756fe1a195889` and public context SHA-256 `ba69af8fead84d3e8ebe0b2a4316399608a900b918405330f5a014f4fc56bf8c`.

Selected immutable images recorded in the result match the approved invocation:

| Role | Image ID |
|---|---|
| API | `sha256:70d11c11167a1bd8ecbc68901b5cd4b99efb99a2a472c69a32d769df05673878` |
| Worker | `sha256:79d8cdcdf65f8d85a93390255e457f434b6cfceac6147da019fecd499d7a7844` |
| Web | `sha256:634203d96fdc419f3018db6d8d417449423f0455c0bc48778dd603f920d45d31` |
| Gateway | `sha256:e899d14b4e379b6467562b9e4fd30a9181b37a5e1257125568df16b2a857e072` |
| BusyBox init | `sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e` |

No Docker/Compose command, browser, HTTP request, scan, harness import/execution, historical proof, MCP or git command was run by this acceptance review. No credential-bearing `compose.json`, Docker config, private env/key, old DB/mount, raw container log or browser profile was read. Only the new acceptance document was written; the author's validation document was left untouched.

## Accepted observations and their source assertions

The summary does not persist every HTTP response or scanner row. Where indicated below, acceptance follows from the saved PASS and the required assertions in the exact source revision, rather than independent replay of raw responses.

| Scope | Saved observation / accepted meaning | Harness source lines |
|---|---|---|
| Real HTTP admission and ownership | Actual fixed-loopback HTTP client, three synthetic registrations, bootstrap/unenrolled 403, anonymous 401, hidden JWT ingress 404, default READY, scan POST 202 and identical idempotency replay. Enrolled foreign peer gets 404 and anonymous gets 401 on status/results/SBOM/events. These assertions precede successful completion. | 587–607, 677–686, 849–904 |
| Secrets + SBOM | `actual_scan=SECRETS_SBOM_CHECKED`; completed scan requires both outcomes `checked` and scanner version `0.69.3`. Secrets **0 findings**, SBOM **15 components**, both datasets fully traversed and counted. Zero checked secrets is not skipped coverage and is not a safety guarantee. | 699–723, 901–919 |
| Target binding and real outbox | Scan `a4629fe1-41bc-4eb8-9689-b19b09dec047`; requested `registry-1.docker.io/library/alpine:3.21.3`, resolved digest `sha256:1c4eef651f65e2f7daee7ee785882ac164b02b78fb74503052a26dc061c90474`, target platform `linux/amd64`. Saved own-ledger row: completed, checks `["secret","sbom"]`, attempts **1**, delivered **1**. SQL is read-only, inside the ownership-checked own API ID, restricted by scan and owner subject; source binds its digest to status and the SBOM target. | 834–846, 883–918 |
| SSE | **1 queued → 2 running → 3 completed**, PASS. Source additionally requires exclusive replay after event 1 to equal events 2–3, and replay after event 3 to be empty. | 628–662, 920–924 |
| Real frontend and reload | Browser PASS; reload **true**, context disabled **true**, blocked requests **0**, browser errors **0**. Source navigates the real report, performs `page.reload()`, compares real report-v1 responses and DOM inventory to HTTP first pages, and requires disabled exact owner-scan LLM context with matching target. No fulfilled/mock responses. | 726–831 |
| Dataset stability | Full HTTP datasets are fetched again after the browser step and compared to their original hashes. Secrets SHA-256 `4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945`; SBOM SHA-256 `f9f90fd96d401ab4be0eb4cf04946cce95243c05375d3416119aa828098e479c`. | 905–913, 960–964 |
| Eligibility 429 | PASS, `eligibility_only`, Retry-After **60s**. Source requires 30 unsupported-reference eligibility responses then 429 with matching bounded body/header and rate reason, without registry dispatch for those unsupported requests. | 931–943 |
| Cancellation | Second scan `8b676e87-6d2d-4407-86df-60e631bdf7a9`: PASS. Source requires a 200 cancelled receipt, terminal cancelled state, and unchanged cancelled state after a two-second wait. Saved termination qualification is explicitly `best_effort_not_proven`. | 944–959 |
| CVE default denial | `UNSUPPORTED_NOT_ENABLED_NO_DB_RELEASE`: source requires CVE create to return 503 `SCANNER_UNAVAILABLE`. This is a negative gate check, not CVE coverage. | 925–929 |

The observed datasets contain 0 and 15 rows, below the 25-row page size. Their complete traversal is accepted; this is not a new positive multi-page/cursor stress qualification.

## Ownership, isolation and cleanup acceptance

The source creates a fresh nonce project and a new private work directory, consumes selected immutable prebuilt images, and checks actual container guards, exact volume/network topology, resource limits and loopback publication before the HTTP workflow proceeds. API enrollment recreation uses only the own API ID and an API-only create spec; the other five recorded service IDs must remain unchanged. Relevant source: `prepare()` lines 1048–1074; `execute()` lines 1077–1117; ownership/create/topology checks lines 330–527.

The journal independently matches the result's exact project/nonce and contains **13 unique resource identities**:

- **4 network IDs**, with creation timestamps;
- **2 volumes**, exact project-scoped `auth_accounts` and `scan_ledger` names with creation timestamps;
- **7 container IDs**, consistent with six initial services plus the replacement API;
- `pending_storage=[]`, `create_uncertain=false`.

The journal is a historical authority inventory, **not a list of 13 surviving resources**. It retains the original API ID as well as the replacement. Docker volumes have no separate immutable ID: the source checks exact Name + CreatedAt + nonce/project labels, not a fictitious volume ID.

Saved cleanup is **PASS**, `recorded_resources=13`, `errors=[]`. In the reviewed source (`cleanup()`, lines 529–568), that result requires successful own-resource discovery, identity/ownership rechecks before removal, confirmed absence after removal (or absence when already removed), and an empty final project container/network/volume inventory. No broad `down`, prune, force-volume removal, image/cache cleanup or old-resource recovery is used. `execute()` writes the final result after cleanup and removal of its generated synthetic credential file (lines 1122–1132).

**Accepted cleanup claim:** the run's final own-namespace cleanup passed its exact-source checks. This review did not independently query the Engine afterward, inspect foreign resources, or establish global host/data preservation. The sanitized journal alone is not a per-resource deletion log.

## Remaining gates — not accepted or changed

- Full 36-point acceptance matrix, production/public deployment and operational readiness.
- Existing HOLD, old data preservation, recovery/restore, retention or incident reconciliation. No frozen historical proof is repeated or superseded.
- Positive CVE coverage, vulnerability DB freshness/release or CVE findings.
- Enabled LLM/provider calls, generation, consent/quota/chat/history acceptance. Only real **disabled** summary context was checked.
- Runtime/host capture or native-host security qualification. Native arm64 container execution of this isolated stand is not a general native-host acceptance result.
- Physical Trivy child termination following cancellation; the recorded cancelled ledger state does not prove process kill.
- Long-idle SSE, native reconnect/restart/recovery behavior, scan-admission/global-capacity 429, or load/stress qualification.
- Manual screen-reader (SR) and broader accessibility acceptance.
- Hard host-browser CPU/RAM/OS-network isolation; the explicitly agreed shared-host browser envelope remains an acknowledged limit, not a cgroup/sandbox proof.

## Review validation

A read-only standard-library JSON/hash consistency check passed for the current source, this result and this journal, including source pin, project/nonce, resource uniqueness/counts, pending state, completed outbox, checked dataset summaries, SSE/browser/rate/cancel outcomes and final cleanup. No test suite or actual workflow was rerun in this acceptance pass.

**Final decision: scoped PASS for this one isolated image-only smoke; all excluded gates remain separate and unchanged.**
