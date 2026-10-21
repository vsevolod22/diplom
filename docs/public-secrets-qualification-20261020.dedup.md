# Public Secrets — exact duplicate-row root fix and fresh proof

## Outcome

**Targeted validation and the fresh bounded qualification passed.** This is new dedup evidence, not a rewrite of the earlier packet or whole TASK2 acceptance.

Final observed execution: **2026-10-20T22:14:08.494Z–2026-10-20T22:14:14.993Z**. Final packet: `docs/public-secrets-qualification-20261020.dedup.json`.

- Normalizer tests: **9 passed, 0 failed/skipped**.
- API TypeScript: **passed**, including the reviewer-reported test errors.
- Qualification guard/fixture tests: **7 passed, 0 failed/skipped**.
- Fresh actual Trivy: **4 invocations**, each detecting the cohort's **2 freshly generated, never-issued canaries**.
- Explicit duplicate-row derivative: **4 input rows → 2 findings**, with the first original IDs/evidence references intact through adapter, consumer, SQLite, owner HTTP/report-v1 and UI.
- **61 named checks**, aggregated by assertion label, not 61 independent test cases.
- **4 UI tests passed**; actual React/authorized-decoder rendering in jsdom over this run's sanitized HTTP responses.
- **4 archive cleanups**, disposable container and private temporary directory removed; no OOM.

## Root fix and compatibility

Changes to application source remain limited to `server/api/src/worker/secret-findings.ts` and its `.test.ts`.

The public result contract still requires positional `secret-r-s` and `result-r-secret-s` identifiers. They were not replaced with a content-addressed format. The normalizer now de-duplicates **before emitting** a finding while retaining the first occurrence's **original coordinates**, including gaps for skipped duplicate rows. Existing distinct findings are not compacted/renumbered. IDs remain report-local: semantic stability across arbitrary report reorderings is **not** claimed.

Internal semantic bucket: **image digest + platform + already-safe hashed rule ID + report-local opaque location + normalized line**. Bound archives get digest/platform from the validated receipt. Legacy unbound reports use validated image-config identity/platform where present, otherwise a call-local unknown namespace; no state is shared across calls or image versions.

A location ordinal is assigned by private equality of bounded `Target`, `Class` and `Type`. The raw path is neither hashed nor serialized into that key or output. Missing, non-string, empty or oversized location evidence is handled conservatively: **no dedup**, rather than assuming two rows came from the same file.

A shared bucket is not sufficient to merge rows: original scanner finding objects must also be deeply equal. This keeps different matches, code, end-line ranges, layer/version evidence and other changed evidence distinct, even when rule/path/start-line coincide. Match/code values are compared only transiently in memory, **never hashed or emitted**. Existing rule-ID hashing is unchanged. A test spy checks every hash update performed during normalization and confirms it receives only the rule identifier.

The input-row bound is still enforced **before duplicate removal**, across result groups; repeated rows cannot evade the 1000-observation ceiling. Input reports are not mutated. No historical stored report, schema, HTTP DTO, ID grammar, ledger code or UI source was changed, migrated or rewritten.

### Reviewer TypeScript corrections

This continuation changed no production implementation. It corrected only two test typing issues:

1. The intentionally invalid digest negative fixture has a narrowly scoped explicit cast to the receipt digest type. The runtime rejection assertion remains; the production type was not widened.
2. The `Hash.update` spy supplies the encoding overload only when an encoding is defined. String/binary calls with no encoding use the one-argument overload.

The test cases cover original output compatibility, duplicate rows inside/across result groups, distinct location/line/rule, distinct matches/ranges/layer versions, unknown locations, different image versions/platform contexts, invalid bindings, raw-input bounds, non-mutation and hash-input confidentiality.

## Fresh qualification path

The existing new qualification was extended, without executing any historical TASK2/history/R10 scripts or retained holders. A fixed `--dedup` argument selects the separate `.dedup.json` path; both old and new evidence refuse overwrite. Unknown output/force arguments are refused.

Four cases run sequentially inside **one newly created disposable container**:

1. **Native positive**: actual Trivy JSON, unchanged, reaches the real public normalizer/adapter/consumer/checkpoint/finalization/ledger and owner HTTP/SSE sinks.
2. **Explicit duplicate-derived positive**: a separate actual Trivy invocation first yields two real detections. The test lifecycle then duplicates only its `Secrets` rows, without changing archive identity or metadata. The actual public adapter normalizes that labelled derivative; consumer, SQLite and HTTP/report-v1 expose exactly the two original findings. This is **not a claim that Trivy itself emitted duplicate rows**. The UI test renders that case and checks parity with the original positive.
3. **Cancel after buffered positive output, before publication**: no late positive publication; unknown count remains unknown, including in UI.
4. **Cancel after accepted Secrets checkpoint, during the controlled sibling**: audited positive Secrets remain, no invented SBOM zero, no late terminal rewrite.

Owner HTTP 200/no-store, foreign owner 404, anonymous 401, foreign cancellation rejection, idempotent admission/terminal fencing and SSE replay remain checked. Exact snapshots survive actual API/SQLite/auth close/reopen. Aging only the own original positive scan and calling `prune(30)` removes that scan and dependent report rows, survives another reopen and preserves the other younger cases. One fresh audit row intentionally remains under the separate audit `created_at` clock. This is logical retention, not secure erasure or audit-expiry qualification.

All inspected normalized/ledger-table/main-WAL-SHM/HTTP/SSE/evidence/UI material is checked for private-value absence. Raw native JSON and its derivative, raw path/marker, canaries, password and cookies stay in disposable private memory/tmpfs/auth storage and are not printed or retained as evidence. The ordinary OCI integrity hashes bind generated image/archive bytes; no direct raw-match hash was added to the normalizer.

## Isolation and honest limitations

The launcher verified the existing public worker's exact image pin, public labels, command, user and resources, and used the same image with a **read-only source snapshot**, not a rebuild or live activation:

`sha256:d8c3888125737a5059d2b42d8c8f98cf7a41677aff17838e8bc30546eccb9d0b`

The fresh resource was `public-secrets-qualification-2102ba76-83f2-4671-9f88-5d102cb23a78`. Its enforced limits were **4 GiB memory / equal MemorySwap (no additional swap), CPU1, PIDs128**. Network `none`, read-only root, user 65532, dropped caps, no-new-privileges, no devices/ports/socket, disabled Docker logs, core dumps disabled, bounded owned tmpfs and bounded commands remain enforced. No fixture entrypoint or long-running worker daemon was started. No 8080 requests, registry/proxy calls, real credential sources, private state/env/key files, public DB or retained holders were accessed by the proof.

As in the original new qualification, OCI transport and readiness are controlled internal seams. Real acquisition validation/assembly and `runArchiveProcess` run; the invocation seam does **not** execute the private `verifiedArchive` pre-invocation O_NOFOLLOW/concurrent-mutation wrapper. No claim is made about that wrapper's fence. Positive/cancel JSON stays unmodified; only the explicitly named duplicate case changes finding multiplicity.

Cancellation timing barriers are synthetic and occur after actual native output; this is not a test of killing an in-flight Trivy process. UI is **jsdom snapshot replay**, not Chromium/login or networked browser end-to-end. There is no live deployment, broker scheduling, CVE/two-source provenance, export/LLM/provider, DB rotation, backup or forensic-erasure acceptance claim. Separately preserving differing evidence is not a new multi-scanner provenance-merging schema.

## Commands actually executed

From `server/api`:

```sh
node --import tsx --test src/worker/secret-findings.test.ts
node node_modules/typescript/bin/tsc --noEmit --incremental false -p tsconfig.json
```

Normalizer test duration in this continuation: **181.996666 ms**. API tsc exited successfully with no diagnostics. No production change was used to fix those test typing errors.

From repository root:

```sh
node --test scripts/public-secrets-qualification.test.mjs
node --check scripts/public-secrets-qualification.mjs
node --check scripts/public-secrets-qualification-fixture.mjs
node scripts/public-secrets-qualification.mjs --dedup
```

Guard/fixture test duration: **34.268 ms**. The last command internally runs only the new dedicated UI test/config and requires all four tests to pass. Final safe launcher output:

```json
{"passed":true,"checks":61,"nativeInvocations":4,"uiTests":4,"containerRemoved":true,"privateTempRemoved":true}
```

Scoped `git diff --check` for the two allowed application files passed. **No full test suite, historical qualification, full frontend build, installation, shared/live mutation, MCP mutation, commit or branch creation was performed.**

## Preserved history and reconnect

At reconnect, no dedup packet had been recorded and the exact qualification ownership-label query found **zero** remaining containers. This does not reconstruct or assert success for any unrecorded work before the connection died.

There was **one observed fresh `--dedup` invocation in this continuation**, and it passed. The older `.json`, `.md`, `.validation.json`, and `.attempt1.json`–`.attempt5.json` were left unchanged. Their hashes were captured before the fresh run and checked afterward; `historicalArtifacts.preserved` and their exact hashes are in the new packet. Earlier failed attempts remain failed historical observations, not retroactively green results. The original packet's duplicate-gap observation remains historically accurate for its old source revision.

New handoff artifacts are this `.dedup.md`, `.dedup.json`, and `.dedup.validation.json`. The validation manifest records targeted checks, current touched-file hashes, old-artifact preservation and final own-resource absence. Hashes are reproducibility checks, not signed execution attestation.
