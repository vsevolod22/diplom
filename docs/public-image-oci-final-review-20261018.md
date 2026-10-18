# Independent defensive review: bounded public OCI image reader

Date: 2026-10-18

Reviewer: GPT-6.1-Sol, Zed coding agent

Disposition: **REQUEST CHANGES for the strict tar-validation contract; offline identity and byte-budget checks otherwise substantially supported. Not native or production acceptance.**

## Scope and evidence boundary

Reviewed `docs/public-image-acquisition-20261018.md` against the working-tree implementations of `server/api/src/oci/public-image*.ts`, `bounded-image-archive.ts`, `archive-identity.ts`, `layer-tar-validator.ts`, and `archive-budget.ts`. Followed their relevant dependencies into `gateway-transport.ts`, `registry-resolver.ts`, and `scans/image-reference.ts`, inspected the focused test sources, and inspected the diff of the four changed shared modules. Read the public-image entry-point/module wiring without starting it.

The checkout's HEAD was `f2853f52408a6c068503547d33e535ac7988af80`. The public acquisition document and three reader/policy production modules were untracked; the four shared modules were modified. This is a **working-tree review**, not certification of that commit or of concurrent work elsewhere. Findings below concern shared parser paths reused by the public reader; the unsafe parsing choices are inherited, not claimed to be newly introduced lines.

No registry, Docker, scanner, database, deployment, private files, or network connection was used. The three socket/TLS transport tests were deliberately not selected. No new repro harness, payload files, exploit/operational tooling, production/test edits, broad suite, branch, commit, or tracker mutation was made. This report is the only repository file written by this review.

## Findings

### R1 — Medium: mixed PAX/GNU link overrides can hide a link value from the final hardlink check

**Locations:** `server/api/src/oci/layer-tar-validator.ts:113–124,128–133`.

The validator permits both a pending PAX `linkpath` and a pending GNU `K` long-link extension for the same subsequent entry. The GNU value is initially checked with `symlink = true` at line 132, so absolute and parent-relative link targets are allowed at that stage. For the eventual hardlink entry, line 121 validates only:

`attributes.linkpath ?? this.longLink ?? header-link`

If PAX supplies a permissible hardlink target, the alternative GNU long-link target is never subjected to the hardlink restriction. Both extensions are then cleared. Thus the validator can accept conflicting link instructions even though one supplied target violates its own hardlink policy.

**Impact and qualification:** This is a source-confirmed validation gap and an ambiguity at the boundary to another tar reader. The safety decision depends on a downstream reader choosing the same precedence between GNU and PAX metadata. A reader choosing the other instruction would not be constrained by the hardlink check that passed here. This review did **not** run Trivy or demonstrate downstream acceptance, extraction, or host escape. The implementation itself writes layer bytes, not an extracted image filesystem. Hash checks still bind the exact bytes; they do not resolve competing tar interpretations.

**Required change:** Reject conflicting GNU/PAX overrides for the same semantic field, or define a supported combination whose interpretation is explicitly matched to the consumer and validate every applicable link value against the final entry type. Rejecting mixed overrides is the narrower defensive choice. Add focused offline coverage for both extension orders, final hardlink versus symlink types, and conflicting link targets. Do not treat the existing ordinary-hardlink rejection tests as covering this case.

### R2 — Medium: lossy ASCII decoding admits malformed tar magic and PAX length bytes

**Locations:** `server/api/src/oci/layer-tar-validator.ts:106–109,141–146`.

`Buffer.toString('ascii')` clears the high bit of decoded bytes. It is used before validating both the tar magic/version and PAX record-length digits. Consequently, these checks validate a normalized representation, not the original byte grammar: non-ASCII bytes can compare equal to the expected magic/version or match the decimal-digit expression. Header checksum verification does not establish that those fields used the required byte encoding.

**Impact and qualification:** The preflight gate admits malformed encodings rather than enforcing the declared strict supported tar subset. A downstream parser can reject or interpret these bytes differently. This is not evidence that the expanded-byte, entry-count, checksum, or diffID bounds are bypassed; those checks remain independent. Native acceptance or any stronger consequence was not tested.

**Required change:** Compare magic/version as exact byte sequences and validate the PAX length prefix as raw ASCII digit bytes before converting it. Add offline negative cases for non-ASCII magic/version and length-prefix bytes, alongside unchanged valid GNU/USTAR/PAX cases. Avoid repairing malformed input by decoding it lossily.

### R3 — Low: “wire bytes” and “low-level HTTP requests” overstate what the counters measure

**Locations:** `docs/public-image-acquisition-20261018.md:56–57,66`; `server/api/src/oci/public-image-inspection.ts:37–50`; `bounded-image-archive.ts:128–148`; `gateway-transport.ts:64,79,86–92`.

The byte counters measure delivered **HTTP response-body bytes**. They do include token, error, and redirect bodies, but not HTTP headers, CONNECT exchanges, or TLS overhead. The acquisition sink also does not see a chunk rejected first by `gatewayGet`'s per-response size guard. The request counters increment once per `gatewayGet` invocation; each invocation separately initiates an HTTP CONNECT and, if successful, an HTTPS GET. They are therefore GET/transport-attempt counters, not a literal count of all HTTP requests.

**Impact:** This is a resource-accounting/contract qualification, not evidence of unbounded layer storage or an auth/redirect counter bypass. An operator cannot use the declared 544 MiB or 320 requests as exact total network-traffic/HTTP-message ceilings.

**Recommended change:** Describe the ceilings and metrics as response-body bytes and transport/GET attempts, explicitly including auth and redirect attempts. If literal wire accounting is required, enforce it at an appropriate transport/egress layer. Preserve the finite application body and attempt budgets regardless.

## Resource-bound assessment

For the production wrappers and ordinary parsed metadata, source inspection supports the following distinctions:

| Resource | Enforcement and qualification |
| --- | --- |
| Policy selection | `archiveLimits()` selects only frozen legacy/public policies and rejects other profiles. Neither production preparation wrapper exposes a caller-supplied ceiling, request function, or scratch root. |
| Metadata-only inspection | The inspection wrapper allows at most three logical objects, 1024 index descriptors, 4,000,000-byte manifest/index objects and a 1,000,000-byte accepted config. Its production transport additionally caps body bytes at 16,000,000, transport attempts at 12, and gives each call the remaining 30-second allowance. Accepted objects use fatal UTF-8 decoding. |
| Preparation metadata | Reinspection uses the acquisition budget, not a new 30-second/12-attempt allowance. Its transport can buffer up to 4,000,000 bytes for ordinary metadata/error responses before the inspector rejects a config exceeding 1,000,000 bytes. The config acceptance ceiling is not a one-megabyte preparation-buffer ceiling. Token responses have their separate 32,768-byte cap. |
| Compressed layers | Manifest inventory enforces 1–64 layers, positive safe-integer descriptor sizes, 128 MiB per layer and 512 MiB aggregate. Streaming independently checks exact descriptor size, aggregate successfully streamed compressed bytes, and SHA-256 before inflation. Non-success bodies are separately bounded instead of using the large successful-layer allowance for buffering. |
| Expanded layers and files | Each inflation uses the public `LayerTarValidator` and a shared attempt `TarBudget`: 512 MiB per layer, 1024 MiB aggregate, 100,000 nonzero headers, 256 MiB ordinary-file payload, 64 KiB per extension payload, 512-byte effective fields, and 1024 aggregate PAX records. Expanded chunks are charged/validated before disk writes. These numeric limits do not remedy R1/R2's parsing gaps. |
| Gzip framing | Fixed ten-byte header with no optional flags; raw deflate consumption, CRC and ISIZE checked; exact single-member framing. Existing offline cases reject concatenation, trailing data, truncation, CRC/ISIZE errors and unsupported optional flags. Public size limits are below the ISIZE wraparound boundary. |
| Docker-save output | Writer checks the independent 1152 MiB ceiling before each write. Verified expanded bytes plus bounded config, manifest, headers and padding are already below this conservative ceiling. Existing tests inspect a small synthetic archive; they do not run the writer at the full archive ceiling. |
| Logical scratch | Reserve compressed size plus the full per-layer expansion allowance before acquisition, then retain only the validated expanded size. During assembly, remove/release each expanded layer after copying it. With at most 1024 MiB retained expanded bytes, the extra 128+512 MiB layer reservation or one copied 512 MiB layer remains below 2048 MiB, including bounded archive metadata. `statfs` additionally checks the current reservation/write against free space plus 16 MiB headroom. This is logical file-byte accounting, not a global disk reservation or exact allocated-block bound. |
| Time and cancellation | Preparation combines the caller signal with a 180-second timeout, passes it to network requests/inflation, and checks the attempt clock during streaming and assembly and before success. This supports deadline rejection, not a hard real-time guarantee that all filesystem operations and recursive cleanup finish within 180 seconds. Metadata parsing and filesystem calls are not independently preemptible. |

These are **per-attempt application bounds**, not hard RSS limits, scanner resource limits, cross-worker admission control, filesystem quotas, or complete wire accounting. Metadata parsing, chunk copies and runtime objects add overhead beyond payload sizes. No process-memory or multi-worker stress measurement was performed.

## Identity verification assessment

No missing digest stage was found in the ordinary supported acquisition chain:

1. The canonical reference is reparsed and matched to registry/repository/selector before I/O. Public targets require the fixed Docker Hub registry, bounded repository, immutable lowercase SHA-256 digest and linux/amd64. Preparation snapshots target fields before awaiting filesystem/network work.
2. Index selection requires exactly one supported linux/amd64 descriptor. The public wrapper validates descriptor size/type and the selected body length; the resolver verifies selected media type, byte hash and digest header. The returned identity is the child manifest, not the mutable tag/index.
3. Config descriptor type, exact size and SHA-256 are checked by the resolver. Public inspection also checks linux/amd64, absence of a variant, rootfs type and one valid ordered diffID per layer. Preparation re-fetches immutable metadata, compares any supplied config pin and hashes its retained config bytes again.
4. Each layer's downloaded compressed bytes must match its descriptor size and digest. Inflation validates the gzip/tar envelope and hashes all expanded bytes, including padding, against the corresponding config diffID.
5. Assembly verifies each retained layer's file type, size and diffID again while copying. Config and ordered layers are placed in Docker-save form with empty `RepoTags`. The writer hashes the archive bytes and returns a frozen receipt with the exact public versions; successful output is changed to mode `0400`.
6. Receipt validation and JSON/SBOM binding preserve distinct public versus legacy version/identity paths. JSON requires the config ID, platform and ordered diffIDs and rejects synthetic `RepoDigests`; CycloneDX compares one config ID and the diffID multiset without losing multiplicity.

`isPublicReceipt()`/`validArchiveBinding()` are structural validators, **not cryptographic proof that an arbitrary supplied receipt belongs to an arbitrary on-disk file**. `archiveSha256` is syntax-checked there, not recomputed from disk. This matches the acquisition document's separation of structural receipt checks from the engine's byte binding, and requires trusted receipt provenance and continued owned-file handling downstream. No worker/scanner handoff or post-return archive integrity claim is certified here.

## Owned cleanup assessment

`prepareBoundedImageArchive()` checks the scratch root's owner/mode and opens it with directory/no-follow flags, creates a fresh UUID directory, and uses exclusive/no-follow file creation. Once the attempt exists, failures pass through its scoped cleanup; successful callers receive the same idempotent directory cleanup function. Files/streams are closed in `finally` paths, including the corrected case where inflation's destination cannot be opened after its source has been opened. Ordinary acquisition does not call the broad recovery routine.

The offline tests support cleanup after cancellation, metadata/transport failures, compressed corruption, bad tar/diffID and retained-layer tampering. They also verify that unrelated sentinel content survives and that successful cleanup can run twice. This supports **attempt-local cleanup**, not crash recovery, cleanup under filesystem failure, protection against a malicious process with the same UID replacing ancestor paths, or proof that downstream callers always invoke cleanup. The scratch namespace and parent filesystem must remain trusted. Recursive deletion itself can fail; it is not an unconditional cleanup guarantee.

## Validation actually run

Host runtime: Node `v23.11.0`, macOS. Used installed local tools without fetching packages.

From `server/api`:

```sh
node --import tsx --test src/oci/public-image-archive.test.ts src/oci/public-image-inspection.test.ts src/oci/public-image-policy.test.ts src/oci/public-image-layer.test.ts src/oci/archive-budget.test.ts src/oci/archive-identity.test.ts src/oci/layer-tar-validator.test.ts src/oci/nginx-candidate.test.ts src/oci/registry-resolver.test.ts

node --import tsx --test --test-name-pattern='^(Hub requests build|anonymous scoped Bearer|blob redirect strips|hostile auth realms)' src/oci/gateway-transport.test.ts

./node_modules/.bin/tsc --noEmit --target ES2022 --module NodeNext --moduleResolution NodeNext --strict --esModuleInterop --skipLibCheck src/oci/public-image-archive.ts src/oci/public-image-inspection.ts src/oci/public-image-policy.ts src/oci/archive-identity.ts src/oci/public-image-archive.test.ts src/oci/public-image-inspection.test.ts src/oci/public-image-layer.test.ts src/oci/public-image-policy.test.ts
```

Results:

- **47 + 4 = 51 selected tests passed**, zero failures/cancellations/skips in the selected runs.
- The three CONNECT/TLS/socket-based gateway tests from the documented 54-test run were intentionally **not selected** to comply with the no-network constraint. The earlier 54-pass statement was not independently reproduced in full.
- Focused strict TypeScript check passed. No broad/full-project typecheck or full suite was run; the acquisition document's concurrent full-project type error was not re-evaluated.
- Scoped `git diff --check` for the four changed shared production modules passed.
- The 512 MiB validator boundary test streams a reused 64 KiB buffer; it is not a full-sized native image acquisition/scanner acceptance test.

R1/R2 are source-inspection findings, not failing existing tests. No new reproducer or regression test was added under this review's read-only code/test scope. Passing tests therefore do not close these findings.

## Final disposition

**Request changes before accepting the advertised strict tar preflight contract:** close R1's competing link-override interpretation and R2's lossy byte-grammar checks, then rerun the focused offline cases with regression coverage. R3 should be clarified so network/resource claims describe the actual counters.

The inspected code and 51 passing socket-free tests provide useful evidence for immutable metadata/layer binding, finite application payload budgets, fail-closed ordinary error paths and attempt-owned cleanup. They do **not** establish native Trivy acceptance, arbitrary Docker Hub image compatibility, scanner findings correctness, DB qualification, live registry availability, worker/API integration, deployment readiness, or production safety. No such acceptance is granted by this review.

---

## Follow-up independent review — 2026-10-18 (R1–R3 recheck)

**Current disposition: QUALIFIED APPROVE for the reviewed bounded public OCI acquisition scope. R1, R2 and R3 are closed; no remaining actionable issue was identified in this follow-up scope.** This disposition supersedes the original REQUEST CHANGES for the current reviewed working tree only. The initial review, findings and test results above are preserved as history, not rewritten as though the defects never existed.

HEAD remained `f2853f52408a6c068503547d33e535ac7988af80`; this remains a working-tree review, not approval of that commit's contents. Independently reread the original findings, the complete revised `layer-tar-validator.ts`, the new `public-image-tar-regressions.test.ts`, and the acquisition document's corrected resource policy and review-fix handoff. Rechecked the relevant inspection/transport counters, acquisition/inflation paths, fixed resource policies, attempt budget and archive identity validators. Did not rely on the author's test totals as independently established evidence.

### Findings closure

| Finding | Independent recheck | Status |
| --- | --- | --- |
| **R1: competing GNU/PAX semantics** | `layer-tar-validator.ts:119–129` rejects simultaneous PAX `path`/GNU `L` or PAX `linkpath`/GNU `K` before selecting or clearing the ordinary entry's overrides. The guard examines the accumulated state rather than extension order, and rejects equal as well as conflicting values. Global PAX path/link/size overrides remain prohibited at lines 165–166. A standalone GNU link still reaches the final entry-type-specific link check at line 126. | **Closed** |
| **R2: lossy byte grammar** | `layer-tar-validator.ts:21–22,108–110` compares the full eight-byte magic/version signature with exact USTAR/GNU buffers. Lines 146–154 require one to eight raw ASCII decimal digit bytes, with a nonzero leading digit, before checking record framing. No lossy decoding remains in these decisions; the eight-digit cap also keeps numeric accumulation within safe integer range. | **Closed** |
| **R3: accounting wording** | `public-image-acquisition-20261018.md:56–70,144–146` now identifies delivered response-body bytes and transport/GET attempts. It explicitly excludes headers, transfer framing, separately counted CONNECT exchanges and TLS/TCP overhead; distinguishes preparation's sink accounting from inspection's returned-body accounting; and explains the per-response guard's undelivered chunk. This matches the inspected transport/counter code without pretending to add literal wire enforcement. | **Closed by documentation correction** |

The regression file contains **12 test functions across both fixed profiles**, with parameterized cases inside them. Its assertions exercise the original observations directly: both link-override orders, hardlinks and symlinks, unsafe/conflicting/equal alternative values, same-field path overrides, high-bit changes at every position in both format signatures with valid recomputed checksums, and high-bit aliases in each PAX length digit. Fragmentation checks use 1-, 37- and 512-byte chunks. Positive controls retain exact USTAR/GNU signatures, standalone overrides and distinct-field combinations, and distinguish an allowed image symlink from a rejected standalone escaping hardlink. Gzip-inflation cases reject malformed input through the shared inflation path, rather than testing only a disconnected helper.

The new same-field override rejection intentionally narrows accepted inputs under **both legacy and public profiles**. The acquisition document discloses that compatibility impact. The fix does not enlarge numeric ceilings, alter receipt identity/version constants, add extraction, or depend on a native reader choosing a particular precedence. The original qualifications about structural receipt validation, trusted scratch ownership, logical versus physical resource accounting, filesystem/deadline limitations and downstream cleanup ownership remain applicable.

### Independent validation rerun

Used installed local tools on macOS with Node `v23.11.0`. From `server/api`, ran:

```sh
node --import tsx --test src/oci/public-image-tar-regressions.test.ts

node --import tsx --test src/oci/public-image-archive.test.ts src/oci/public-image-inspection.test.ts src/oci/public-image-policy.test.ts src/oci/public-image-layer.test.ts src/oci/archive-budget.test.ts src/oci/archive-identity.test.ts src/oci/layer-tar-validator.test.ts src/oci/nginx-candidate.test.ts src/oci/registry-resolver.test.ts

node --import tsx --test --test-name-pattern='^(Hub requests build|anonymous scoped Bearer|blob redirect strips|hostile auth realms)' src/oci/gateway-transport.test.ts

./node_modules/.bin/tsc --noEmit --target ES2022 --module NodeNext --moduleResolution NodeNext --strict --esModuleInterop --skipLibCheck src/oci/public-image-archive.ts src/oci/public-image-inspection.ts src/oci/public-image-policy.ts src/oci/archive-identity.ts src/oci/public-image-archive.test.ts src/oci/public-image-inspection.test.ts src/oci/public-image-layer.test.ts src/oci/public-image-policy.test.ts src/oci/public-image-tar-regressions.test.ts
```

Results observed:

- New R1/R2 regression file: **12 passed**.
- Original socket-free OCI/archive selection: **47 passed**.
- Original mock-only transport selection: **4 passed**.
- **63 selected tests passed in total**, zero failures, cancellations or skips in these selected runs. The three socket/CONNECT/TLS tests were again intentionally not selected; they were not silently counted as passing.
- Focused strict TypeScript check, now including the regression file: **passed**.
- Scoped `git diff --check` for `layer-tar-validator.ts`, `archive-budget.ts`, `archive-identity.ts` and `bounded-image-archive.ts`: **passed**.

The author's reported pre-fix 10-fail/2-pass run was not independently rerun: no production/test file was rolled back or edited to reproduce the historical state. Closure here rests on source inspection and the independently observed post-fix regression results. The author's full-API typecheck result was likewise not independently reproduced; no full suite or broad typecheck was run.

### Qualified approval boundary

**No further code change is requested for R1–R3 or for the reviewed follow-up.** The original parser blockers are resolved with direct offline regression evidence, and the accounting claims now describe the actual application counters.

This is approval of the reviewed defensive acquisition implementation within its documented finite subset and stated assumptions, **not native Trivy acceptance or production qualification**. It does not establish arbitrary-image compatibility, scanner result correctness, live registry behavior, database trust/qualification, worker/API integration, deployment readiness, hard RSS/disk/network quotas, or cross-worker admission control. No network, Docker, registry, scanner, private files or live database was accessed; no new tooling/payloads, production/test edits, branch, commit or tracker mutation was made. Only this append to the review report was written by the reviewer.

---

## Narrow independent review — embedded OCI config data (2026-10-18)

**Disposition: QUALIFIED APPROVE for this config-only inline-data extension. No actionable finding identified in the inspected extension.** Earlier review history and qualification boundaries are preserved. This was not a repeat of the full acquisition audit.

Reviewed the new `public-image-config-data.ts` and its seven synthetic regression tests, the changes to `public-image-inspection.ts`, and the acquisition document's embedded-config handoff at lines 171–190. Traced the mandatory config fetch through `registry-resolver.ts:47–63` and preparation's retained-config checks at `bounded-image-archive.ts:156–169`. HEAD remained `f2853f52408a6c068503547d33e535ac7988af80`; approval concerns the inspected working-tree extension, not a committed/live artifact.

### Source and regression assessment

- **Bounded canonical encoding:** `public-image-config-data.ts:15–34` first validates the digest, supported media type, positive safe-integer size capped at 1,000,000 bytes, and absence of foreign URLs. Inline data is admitted only for the OCI config media type. Exact encoded length is checked before decoding: at the maximum size this is 1,333,336 characters. The raw-character loop enforces the standard base64 alphabet and exact size-derived padding; decoded size and canonical re-encoding reject permissive-decoder aliases, including nonzero unused pad bits. The decoded SHA-256 must equal the original descriptor digest. The existing 4,000,000-byte manifest bound also remains in force. Additional decoding/re-encoding work is bounded; this is not a new hard RSS guarantee.
- **No alternate identity or blob bypass:** Inspection retains the manifest/config identities rather than modifying or relabelling the descriptor. At `public-image-inspection.ts:75–76,96–108`, embedded evidence additionally binds the fetched config's size/hash. The resolver still performs the repository-scoped blob GET and verifies its descriptor hash, any digest header, exact size, permitted response media type and platform; public inspection still checks UTF-8, rootfs and ordered diffIDs. Inline bytes cannot substitute for an unavailable blob. Preparation continues to retain and rehash the fetched config, not obtain it from the helper's evidence.
- **Narrow admission:** The general descriptor guard at `public-image-inspection.ts:23–27` still prohibits inline data for index children and layers, with dedicated regression assertions. Docker config descriptors without data remain accepted; Docker config descriptors with inline data are not enabled by this change. No additional transport destination, object allowance or receipt/version field is introduced by the extension.
- **Evidence and persistence:** The helper returns only frozen digest/size/media-type evidence, with a frozen optional digest/size summary. Its output contains no base64, decoded buffer, raw descriptor or Env, and it does not mutate the input. Public inspection does not return that embedded evidence; successful preparation preserves the eleven-field receipt shape. The ordinary verified config member in the Docker-save archive remains intentional existing behavior—this approval does not assert that the archive contains no config bytes.
- **Relevant coverage:** The new tests cover synthetic 453/454/455-byte and maximum-sized configs; malformed, noncanonical, oversized and descriptor-inconsistent data; required blob fetch and missing/changed/mislabelled blob failures; platform/rootfs rejection; forbidden index/layer data; and synthetic end-to-end preparation with owned cleanup and unchanged receipt shape. The existing inspector, acquisition, policy and resolver cases also passed in the targeted rerun below.

### Validation actually run for this extension

Using local installed tools on macOS, Node `v23.11.0`, from `server/api`:

```sh
node --import tsx --test src/oci/public-image-config-data.test.ts src/oci/public-image-inspection.test.ts src/oci/public-image-archive.test.ts src/oci/public-image-policy.test.ts src/oci/registry-resolver.test.ts

./node_modules/.bin/tsc --noEmit --target ES2022 --module NodeNext --moduleResolution NodeNext --strict --esModuleInterop --skipLibCheck src/oci/public-image-config-data.ts src/oci/public-image-config-data.test.ts src/oci/public-image-inspection.ts src/oci/public-image-inspection.test.ts src/oci/public-image-archive.ts src/oci/public-image-archive.test.ts src/oci/public-image-policy.ts src/oci/public-image-policy.test.ts
```

**Observed: 32 tests passed** (including all seven new tests), zero failures/cancellations/skips; focused strict TypeScript check passed. The three reviewed new/untracked source/test files were also checked with `git diff --no-index --check /dev/null <file>`: these emitted no whitespace diagnostics and returned the no-index difference status 1, not a clean exit-status-0 validation. No full suite or broad typecheck was run. The author's reported 70-test result and historical pre-fix failures were not independently reproduced in this narrow pass.

### Acceptance limit

No further code change is requested for this extension. It safely broadens the reviewed public profile to accept strictly validated embedded **OCI config** evidence while preserving the mandatory independently fetched config and existing identity/resource checks.

The coordinator's actual Debian identity/provenance and native outcome were **not verified** here. A synthetic fixture sharing the reported 453-byte size is not that real config and does not demonstrate acceptance of the reported child manifest. No actual config/base64/Env was fetched or persisted by this review. No Docker, network, live registry, native scanner, private files or database was used. Implementation and tests were read-only; only this review-note append was written. Qualified approval is limited to this inspected extension and offline evidence, not a Debian/native, live or production acceptance claim.

---

## Narrow independent review — public gzip FNAME (2026-10-18)

**Disposition: QUALIFIED APPROVE for the public-only bounded gzip FNAME extension. No actionable issue identified in this narrow source/test review.** Earlier findings, dispositions and evidence remain preserved. Prior statements describing fixed-header-only public inflation are historical: the current public subset also permits the bounded FNAME case described below; legacy's accepted gzip subset remains unchanged.

Reviewed `bounded-image-archive.ts:30–78,140–198,242–251`, the finite error-reason addition in `layer-tar-validator.ts:9–11`, all six tests in `public-image-gzip-name.test.ts`, and the acquisition handoff at `docs/public-image-acquisition-20261018.md:192–249`. HEAD remained `f2853f52408a6c068503547d33e535ac7988af80`; this verdict concerns the inspected working tree, not a committed/deployed artifact. No full acquisition audit was repeated.

### Boundary and integrity assessment

- **Exact flag admission:** At `bounded-image-archive.ts:48–51`, flags must be exactly `0` for legacy and exactly `0` or `8` for the public profile. This is equality checking, not a permissive bit mask: FTEXT, FHCRC, FEXTRA, FCOMMENT, reserved bits and combinations with FNAME remain excluded. The flag-free deflate start is still byte 10. Tests retain successful legacy flag-free gzip and explicitly reject legacy FNAME and representative unsupported public flags/combinations.
- **Finite byte-oriented name handling:** Lines 56–61 allocate/read at most `fieldBytes + 1` (513) bytes and never extend the read into the final eight-byte trailer. The NUL search uses only `bytesRead`, so zero-filled unread buffer capacity cannot supply a false terminator. Accepted name length is **0–512 non-NUL bytes**, excluding the terminator. A terminator at index 512 is accepted; a longer or unterminated name cannot trigger continued scanning. A terminator consuming all bytes before the trailer rejects because no deflate payload remains. Short/truncated headers or names fail closed; a short read cannot be treated as a complete name without a terminator. The header metadata is not decoded, used as a path or output filename, extracted, returned, or persisted separately. It remains part of the original compressed file until ordinary attempt cleanup/removal, as expected.
- **No skipped payload or integrity downgrade:** The raw stream starts immediately after the first in-bound NUL and ends before the trailer. Lines 75–77 require consumed deflate bytes to equal `size - deflateStart - 8`, verify CRC and exact ISIZE, and finish the same tar validator. Additional gzip members, trailing compressed data, truncation, corrupt trailers and malformed tar still reject. Every emitted expanded tar byte is validated, written and hashed; FNAME does not skip tar entries or change diffID computation.
- **Resource and identity binding:** Preparation still charges, size-checks and hashes the complete downloaded gzip before inflation, including fixed header, FNAME and terminator. Source-size limits remain checked before the optional-header allocation. Existing compressed/expanded aggregate limits, tar budgets, scratch reservations and deadline/cancellation paths are not relaxed. The new synthetic acquisition test verifies the full compressed digest/byte count and expanded diffID/byte count; existing tamper/size/diffID rejection tests also pass. Standalone `inflateLayer()` is still not a substitute for preparation's descriptor-hash verification.
- **Failure handling and compatibility:** Source/destination handles remain closed in `finally`, and attempt failures still clean only their owned directory. The new test covers failed FNAME acquisition cleanup as well as successful cleanup. Fixed `ArchiveRejected.reason` values survive relevant inflation/attempt catches while the error message remains generic; no name bytes are added to error text or receipts. This adds diagnostic reason metadata, not a change to legacy gzip admission, numeric ceilings or receipt versions/shape.

### Independent offline validation

Used installed local tools on macOS with Node `v23.11.0`. From `server/api`:

```sh
node --import tsx --test src/oci/public-image-gzip-name.test.ts src/oci/public-image-layer.test.ts src/oci/layer-tar-validator.test.ts src/oci/public-image-archive.test.ts src/oci/archive-budget.test.ts

./node_modules/.bin/tsc --noEmit --target ES2022 --module NodeNext --moduleResolution NodeNext --strict --esModuleInterop --skipLibCheck src/oci/bounded-image-archive.ts src/oci/layer-tar-validator.ts src/oci/public-image-gzip-name.test.ts src/oci/public-image-layer.test.ts src/oci/layer-tar-validator.test.ts src/oci/public-image-archive.test.ts src/oci/archive-budget.test.ts
```

**Observed: 25 tests passed**, including all six new FNAME tests, zero failures/cancellations/skips. Focused strict TypeScript check passed. From the project root, `git diff --check -- server/api/src/oci/bounded-image-archive.ts server/api/src/oci/layer-tar-validator.ts` passed. The bounded-memory expanded-layer ceiling test was included; no native scanner was involved. No broader 76-test selection, full suite or full-API typecheck was run, and no pre-fix rollback was performed.

### Qualified verdict and evidence boundary

No further code change is requested for this parser extension. The acceptance increase is narrowly public-only, bounded independently of name contents, and retains the compressed-hash, deflate framing, trailer, tar and expanded-identity checks.

The handoff's copied-source acquisition, reported 4,226 GNU entries and matching real-layer diffID are **author-reported acquisition evidence**, not results independently reproduced or native acceptance certified by this reviewer. This pass did not access the worker, copied source tree, registry layer, actual archive or private files, and did not run Docker, network, scanner or database commands. No implementation/test edits or new tooling/payload files were made; only this review append was written. Existing assumptions and exclusions remain: this is not a deployment, live registry, native scanner, full-chain, arbitrary-image or production qualification.
