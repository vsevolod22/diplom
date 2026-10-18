# Public Docker Hub image archive acquisition — 2026-10-18

## Scope and qualification boundary

This change adds bounded acquisition of public Docker Hub container images for **linux/amd64**, using their real repository, immutable child-manifest digest, config digest, compressed layer digests, and expanded layer diffIDs. It does not substitute either exact nginx identity.

This is an acquisition implementation with offline tests and the separately authorized, isolated Debian acquisition diagnosis below, **not full-chain/native qualification** of arbitrary images, scanner findings, a deployment, or a CVE database. The initial offline checks used no Docker commands, registry downloads, live database, old environment, or existing scratch jobs. Existing gateway transport tests exercise disposable loopback connections; synthetic acquisition tests inject transport fixtures and use fresh temporary scratch roots. The later bounded registry reads were confined to `dip-public-images-worker-1`, with copied temporary source and attempt-local cleanup; no scanner, DB, private environment, container lifecycle or live-source patch was involved.

No changes were made here to nginx-specific source/tests, proof files, worker/API integration, deployment settings, or unrelated dirty work. Concurrent agents' changes are outside this document's implementation inventory. No git commit or branch was created.

## Integration contract

`server/api/src/oci/public-image-policy.ts` exports:

- `PUBLIC_IMAGE_PROFILE = 'public-hub-amd64-v1'`
- `PUBLIC_IMAGE_RESOURCE_POLICY = 'public-hub-resources-v1'`
- `PUBLIC_IMAGE_CHECKS_VERSION = 'trivy-0.69.3-public-archive-v1'`
- Frozen `PUBLIC_IMAGE_LIMITS`
- `validPublicTarget(target)` and `isPublicReceipt(receipt)`

A target requires `registry: 'registry-1.docker.io'`, a bounded canonical lowercase repository, a lowercase SHA-256 manifest digest, and `platform: 'linux/amd64'`. `configDigest` is optional on acquisition input, but must be a valid SHA-256 digest if provided. A receipt **always** requires the verified config digest.

`server/api/src/oci/public-image-archive.ts` exports:

```ts
inspectPublicImage(reference: ImageReference)
// => { registry, repository, digest, configDigest, platform, layers }

preparePublicImageArchive(signal: AbortSignal | undefined, target: {
  registry: string;
  repository: string;
  digest: string;
  configDigest?: string;
  platform: string;
})
// => { archivePath, directory, receipt, cleanup, metrics }
```

Inspection accepts canonical explicit Docker Hub references supported by the existing image-reference parser, including namespaced repositories, tags, and SHA-256 references. It resolves a tag/index to exactly one linux/amd64 image manifest. The returned digest is the **child manifest** digest, not the mutable tag or index identity. References and targets are snapshotted before awaiting I/O.

Preparation accepts only immutable manifest digests. It re-fetches and validates metadata; prior inspection is not a cache or authorization bypass. A supplied config pin must match the freshly verified config; without a pin, the verified config becomes the receipt's mandatory config identity. Successful callers own `cleanup()` through subsequent scanner phases. Failed attempts remove only their own directory.

`ArchiveReceipt` retains its existing runtime/serialized shape: five target fields, `layerDigests`, `diffIds`, `archiveSha256`, and three version fields. Its TypeScript identity fields are generalized from exact nginx literals to strings/SHA-256 template-literal digests so generic images can use the same shape. No public boolean is added. Public receipts require exactly the existing eleven own enumerable fields, valid target/config/archive hashes, all three exact public versions, and 1–64 dense ordered layer/diffID pairs. Receipt validation checks structure and identity fields; the acquisition engine establishes the byte-to-hash binding.

`validArchiveBinding`, `validateArchiveJson`, and `validateArchiveSbom` accept a strictly validated public receipt **or** the unchanged exact legacy nginx candidates and versions. Archive paths remain restricted to the existing `/tmp/trivy/jobs/<id>/image.tar` binding. JSON still binds config ID, linux/amd64, rootfs type, and ordered diffIDs, and rejects synthetic `RepoDigests`. CycloneDX still requires one exact config ID and multiplicity-preserving diffID properties (property ordering itself is not significant).

## Frozen resource policies

Legacy `ARCHIVE_LIMITS`, default constructors, and `prepareNginxArchive` default target/profile remain unchanged. The shared validator, inflation, and attempt budget select only internally defined frozen legacy/public policies; callers cannot supply a limits object. Public acquisition uses the separate policy below. MiB means 1024² bytes.

| Resource | Public acquisition | Legacy default |
| --- | ---: | ---: |
| Layers | 64 | 32 |
| Compressed layer | 128 MiB | 32 MiB |
| Compressed layers aggregate | 512 MiB | 96 MiB |
| Delivered HTTP response-body bytes, including auth/error/redirect bodies | 544 MiB | 112 MiB |
| Transport/GET attempts, including auth and redirects (CONNECT not counted separately) | 320 | 160 |
| Acquisition deadline | 180 s | 180 s |
| Expanded layer, including tar padding | 512 MiB | 128 MiB |
| Expanded layers aggregate | 1024 MiB | 256 MiB |
| Tar entries across all layers | 100,000 | 50,000 |
| Regular-file payload | 256 MiB | 64 MiB |
| Docker-save archive | 1152 MiB | 272 MiB |
| Logical scratch reservations | 2048 MiB | 448 MiB |

Both profiles retain 64 KiB extension payloads, 512-byte effective path/link/PAX fields, and 1024 aggregate PAX records. API metadata-only inspection separately limits objects to 4,000,000 bytes, config to 1,000,000 bytes, index descriptors to 1024, logical objects to three, delivered HTTP response-body bytes to 16,000,000, transport/GET attempts to twelve, and elapsed time to thirty seconds. Preparation's reinspection participates in the single acquisition budget/deadline instead.

The existing identifiers `wireBytes`, `inspectionWireBytes`, and `requests` are retained for compatibility, not literal network accounting. Body counters include delivered token, error, redirect, metadata and layer payloads, but exclude HTTP headers, CONNECT exchanges, TLS/TCP overhead and transfer framing. Preparation charges chunks delivered to its sink; a chunk rejected first by `gatewayGet`'s per-response size guard is not delivered to that sink. Inspection counts the bodies returned by its transport. The attempt counter increments once per attempted `gatewayGet` invocation, including auth and redirect attempts; it does not separately count CONNECT and the subsequent HTTPS GET, and an unsuccessful CONNECT still consumes an attempt. These application counters are not exact total network-traffic or HTTP-message ceilings. Literal wire accounting would require independent transport/egress enforcement; no kernel/network metrics are claimed here.

Logical scratch includes retained expanded layers, the current compressed/inflating layer reservation, and the growing archive. Filesystem available space is also checked with the existing 16 MiB headroom. Layer files are removed/released as they are incorporated, avoiding simultaneous retention of two whole expanded images. These are per-attempt logical file-byte bounds, not exact allocated-block measurements, filesystem quotas, kernel/RSS measurements, or a claim of cross-worker global admission control.

## Implementation changes

### New production modules

- `server/api/src/oci/public-image-policy.ts`: public constants, finite limits, target validation, and exact-shape receipt validation.
- `server/api/src/oci/public-image-inspection.ts`: strict metadata inspection and bounded repository-scoped metadata transport. Rejects ambiguous platforms, descriptor sizes/hashes/media types, foreign/inline layer descriptors, artifact manifests, invalid UTF-8/config/rootfs, missing layers, and compressed aggregate overflow. Repository components named `blobs` are not confused with blob endpoints.
- `server/api/src/oci/public-image-archive.ts`: narrow API/worker-facing entry points selecting the public policy and shared engine.

### Shared modules changed

- `server/api/src/oci/bounded-image-archive.ts`: factors existing preparation into `prepareBoundedImageArchive`, retaining a strict legacy wrapper and using the real repository throughout. Reuses the existing gzip/tar checks, scratch reservation, download sink, archive writer, and cleanup instead of duplicating preparation. Adds source-size enforcement during inflation, closes the source if destination creation fails, bounds buffered non-success bodies independently of layer size, and rechecks retained layer size/diffID while copying into the archive. Request/root injection is an internal deterministic fixture seam; neither production wrapper exposes it.
- `server/api/src/oci/layer-tar-validator.ts`: selects frozen profile limits, including effective field limits; retains incremental framing and one bounded extension payload; rejected/finalized validators cannot resume. The review follow-up below rejects same-field mixed GNU/PAX overrides and validates tar format/PAX length syntax against raw bytes.
- `server/api/src/oci/archive-budget.ts`: selects the fixed internal profile while preserving existing clock/default constructor calls and sticky aggregate/deadline rejection.
- `server/api/src/oci/archive-identity.ts`: adds validated public receipt acceptance without weakening legacy identity/version checks; malformed bindings/arrays fail closed, including sparse metadata diffID arrays.

### Transport and byte validation

Production code uses the existing `dockerHubManifestFetch` and `gatewayGet` transport, never a new socket, direct fetch, user credential, or caller-selected registry. Auth scope is exactly `repository:<repository>:pull`. Redirects remain restricted to existing allowlisted HTTPS blob CDN destinations; tokens are not forwarded to the CDN. Manifest redirects are refused, including when the repository itself contains a `blobs` component. No CDN allowlist expansion was made.

Every accepted manifest/config is hash/descriptor/platform validated. Layers stream to disk with backpressure, exact compressed size and SHA-256 checks. Inflation accepts exactly one gzip member and verifies consumed deflate bytes, CRC, ISIZE, tar framing, and complete expanded diffID. Legacy still requires the fixed header with no optional flags. Public acquisition additionally accepts only the bounded FNAME flag described below; all other optional/reserved flags remain rejected. Concatenated members, trailing data, truncation, unknown compression, malformed tar, escaping regular paths/hardlinks, unsupported device/sparse extensions, and limit overflow reject. Same-field GNU/PAX overrides (`L` plus PAX `path`, or `K` plus PAX `linkpath`) reject in either order, even if values are equal; no downstream GNU-versus-PAX precedence is assumed. Standalone supported overrides and combinations for distinct fields remain supported. USTAR/GNU magic and version must match exact byte sequences; PAX length prefixes must contain raw ASCII decimal digits. Image symlinks are validated but never resolved/extracted on the host. Retained expanded layers are rehashed again during Docker-save assembly. The archive contains the verified config and ordered layers, an empty `RepoTags` list, a receipt-bound archive hash, and is made read-only.

The supported subset remains intentionally finite: Docker/OCI v2 image manifests/indexes, gzip layers, and the existing supported tar entry/extension types. This does not promise acceptance of zstd/uncompressed/foreign layers, Windows/ARM images, artifact manifests, private registries, local uploads, runtime filesystems, or every possible Docker Hub image.

## Initial acquisition validation (before review fixes)

New files:

- `server/api/src/oci/public-image-archive.test.ts`
- `server/api/src/oci/public-image-inspection.test.ts`
- `server/api/src/oci/public-image-layer.test.ts`
- `server/api/src/oci/public-image-policy.test.ts`
- `server/api/src/oci/public-image.test-fixtures.ts` (shared synthetic fixtures)

Coverage includes generic/namespaced references, immutable metadata/tag drift, config/platform mismatch, input mutation during awaits, descriptor count/size/aggregate N/N+1, scoped auth and redirects, bounded error-body buffering, cancellation and attempt cleanup, exact receipt versions/shape, JSON/SBOM identity binding, compressed hash/size mismatch, single gzip/CRC/ISIZE/truncation, malformed tar, diffID mismatch, and same-size retained-layer tampering. Expanded-layer N/N+1 streams through the full 512 MiB ceiling using one reused 64 KiB chunk rather than allocating a layer-sized buffer. Aggregate tar/entry/PAX and attempt response-body/compressed/transport-attempt/scratch/deadline bounds have focused boundary tests. The archive ceiling is independently checked by the writer; valid expanded data plus bounded config/framing is already below that conservative ceiling.

Commands run from `server/api`:

```sh
pnpm exec tsx --test src/oci/public-image-archive.test.ts src/oci/public-image-inspection.test.ts src/oci/public-image-policy.test.ts src/oci/public-image-layer.test.ts src/oci/archive-budget.test.ts src/oci/archive-identity.test.ts src/oci/layer-tar-validator.test.ts src/oci/nginx-candidate.test.ts src/oci/gateway-transport.test.ts src/oci/registry-resolver.test.ts
pnpm exec tsc --noEmit
pnpm exec tsc --noEmit --target ES2022 --module NodeNext --moduleResolution NodeNext --strict --esModuleInterop --skipLibCheck src/oci/public-image-archive.ts src/oci/public-image-inspection.ts src/oci/public-image-policy.ts src/oci/archive-identity.ts src/oci/public-image-archive.test.ts src/oci/public-image-inspection.test.ts src/oci/public-image-layer.test.ts src/oci/public-image-policy.test.ts
```

Results:

- **54 tests passed**, zero failures/skips, on the initial acquisition handoff's targeted run.
- Focused strict OCI TypeScript check passed, including the new modules/tests and their transitive shared dependencies.
- At the initial acquisition handoff, full API `tsc --noEmit` had passed in earlier snapshots but its last run was blocked by a concurrently added, out-of-scope error: `src/scans/public-image.service.test.ts:28`, TS2416, where subclass method `Ready.anchor()` conflicted with the base service's `anchor` property. That file was not modified here. The review-fix rerun below records the current result separately.
- Targeted `git diff --check` for the four changed shared modules passed.

Existing nginx/transport/resolver tests were run but not edited by this change. No live qualification was attempted or claimed.

## Review-fix handoff — R1, R2, R3 (2026-10-18)

Responds to `docs/public-image-oci-final-review-20261018.md`. The independent review and its REQUEST CHANGES disposition are left unchanged for the reviewer to reassess; this section records implementation/test evidence, not independent acceptance.

This follow-up changes only:

- `server/api/src/oci/layer-tar-validator.ts` (shared production parser)
- `server/api/src/oci/public-image-tar-regressions.test.ts` (new focused regressions)
- This acquisition document (accounting wording and handoff)

### R1: mixed GNU/PAX semantics

At the final non-extension entry, the validator rejects simultaneous GNU `K`/PAX `linkpath` or GNU `L`/PAX `path` values. Both extension orders reject, including equal values. No conflicting alternative survives by being hidden behind the selected PAX value. This is deliberately narrower than assuming a particular downstream parser's GNU/PAX precedence. Single supported overrides and mixed families for **different** fields remain valid. Standalone GNU hardlinks still receive the final hardlink restrictions; symlink semantics remain unchanged and no links are resolved on the host.

Compatibility impact: previously accepted same-field mixed GNU/PAX archives now reject under **both** legacy and public profiles. Numeric limits, default constructors, profile/version exports, public user bounds, and ordinary standalone USTAR/GNU/PAX support are unchanged.

### R2: exact byte grammar

Tar magic plus version is compared as an exact eight-byte USTAR or GNU sequence, without lossy ASCII decoding. PAX lengths are accumulated only from raw bytes `0x30`–`0x39`, with a nonzero first digit and the existing eight-digit cap; high-bit aliases reject before numeric conversion. Existing extension-size, record-count, framing, checksum and diffID bounds remain intact.

### R3: qualified application accounting

The resource table and metadata text now say **delivered HTTP response-body bytes** and **transport/GET attempts**. The compatibility identifiers remain unchanged. The text explicitly excludes separately counted CONNECT exchanges, HTTP headers, transfer framing and TLS/TCP overhead, and explains that a per-response-guard-rejected chunk never reaches the preparation accounting sink. Logical scratch is not presented as kernel/allocated-block/RSS measurement. No transport implementation, counter behavior, budgets or fake metrics were added or changed.

### Regression-first evidence and reviewer rerun

The new test file was written and run **before** the parser fix:

```sh
pnpm exec tsx --test src/oci/public-image-tar-regressions.test.ts
```

Pre-fix result: **10 failed, 2 passed**. Failures were missing expected `ArchiveRejected` exceptions/rejections for mixed overrides, high-bit magic/version, high-bit PAX length digits, and gzip inflation of malformed tar. The two valid-format control tests passed. After the fix, the same file passed **12/12** tests.

Regressions run both fixed profiles and cover both override orders, hardlinks versus symlinks, parent-relative/absolute/conflicting/equal link alternatives, competing path overrides, every byte position in both eight-byte format signatures with checksums recomputed, each PAX length digit's high-bit alias, fragmented input at 1/37/512-byte chunks, valid exact-format/standalone/distinct-field combinations, and rejection through actual gzip inflation. Temporary files are isolated and cleaned. No payload is extracted or supplied to Trivy.

Current post-fix commands, from `server/api`:

```sh
pnpm exec tsx --test src/oci/public-image-archive.test.ts src/oci/public-image-inspection.test.ts src/oci/public-image-policy.test.ts src/oci/public-image-layer.test.ts src/oci/public-image-tar-regressions.test.ts src/oci/archive-budget.test.ts src/oci/archive-identity.test.ts src/oci/layer-tar-validator.test.ts src/oci/nginx-candidate.test.ts src/oci/registry-resolver.test.ts
pnpm exec tsx --test --test-name-pattern='^(Hub requests build|anonymous scoped Bearer|blob redirect strips|hostile auth realms)' src/oci/gateway-transport.test.ts
pnpm exec tsc --noEmit
pnpm exec tsc --noEmit --target ES2022 --module NodeNext --moduleResolution NodeNext --strict --esModuleInterop --skipLibCheck src/oci/public-image-archive.ts src/oci/public-image-inspection.ts src/oci/public-image-policy.ts src/oci/archive-identity.ts src/oci/public-image-archive.test.ts src/oci/public-image-inspection.test.ts src/oci/public-image-layer.test.ts src/oci/public-image-policy.test.ts src/oci/public-image-tar-regressions.test.ts
```

Post-fix results: **59 + 4 = 63 tests passed**, zero failures/skips/cancellations in the selected runs. Full API and focused strict OCI TypeScript checks both passed. Scoped `git diff --check` for `layer-tar-validator.ts` passed. The three socket/CONNECT/TLS tests were not selected in this follow-up; the four selected transport tests use injected fixtures. No network, Docker, registry, scanner, live database, old environment, branch or commit was used/created. Unrelated dirty work and all nginx-specific/proof files were left untouched. Reviewer rerun/acceptance remains pending; no live or native qualification is claimed.

## Embedded OCI config compatibility handoff (2026-10-18)

Addresses the coordinator-reported Debian preflight blocker: a legitimate OCI config descriptor may include embedded `data`. This follow-up does not replay or persist actual registry config, Env, or base64, and does not independently claim a Debian/Node native result.

Changes are limited to new `server/api/src/oci/public-image-config-data.ts`, its synthetic `public-image-config-data.test.ts`, public inspection integration, and this handoff. `validatePublicConfigDescriptor()` validates descriptor digest/type/positive size (at most 1,000,000 bytes) and returns frozen bounded descriptor/hash evidence only. Embedded data is supported only with the OCI image config media type: exact encoded length derived from size, standard base64 alphabet and required padding, canonical re-encoding including unused pad bits, exact decoded size, and SHA-256 equality with the original descriptor are all required before acceptance. Decoded bytes and encoded data never leave the helper. No descriptor is mutated or relabelled, and no data/evidence field is added to the receipt.

Inspection still fetches the config blob through the existing repository-scoped gateway transport. When inline evidence exists, the fetched blob must also match its size/hash, followed by the existing resolver's hash/header/size/media/platform checks and public rootfs/diffID checks. Inline data cannot replace an unavailable blob. Embedded layer/index-child data remains rejected; Docker config descriptors without inline data remain supported, and their inline-data variant is not newly enabled. No host, budget, public version, archive schema, or legacy nginx path changed.

Regression-first run of `pnpm exec tsx --test src/oci/public-image-config-data.test.ts` before the fix: **3 failed, 2 passed**, reproducing valid-config rejection before the blob GET. The final test file has **7 passing tests**, including frozen evidence/no input mutation, synthetic 453/454/455-byte and 1,000,000-byte configs, malformed/padding/noncanonical/oversized/hash/size negatives, mandatory missing/different/mislabelled blob rejection, platform/rootfs rejection, forbidden layer/index data, and end-to-end synthetic bounded acquisition with the unchanged receipt shape.

Final rerun from `server/api`:

```sh
pnpm exec tsx --test src/oci/public-image-archive.test.ts src/oci/public-image-inspection.test.ts src/oci/public-image-config-data.test.ts src/oci/public-image-policy.test.ts src/oci/public-image-layer.test.ts src/oci/public-image-tar-regressions.test.ts src/oci/archive-budget.test.ts src/oci/archive-identity.test.ts src/oci/layer-tar-validator.test.ts src/oci/nginx-candidate.test.ts src/oci/registry-resolver.test.ts
pnpm exec tsx --test --test-name-pattern='^(Hub requests build|anonymous scoped Bearer|blob redirect strips|hostile auth realms)' src/oci/gateway-transport.test.ts
pnpm exec tsc --noEmit
pnpm exec tsc --noEmit --target ES2022 --module NodeNext --moduleResolution NodeNext --strict --esModuleInterop --skipLibCheck src/oci/public-image-archive.ts src/oci/public-image-inspection.ts src/oci/public-image-policy.ts src/oci/archive-identity.ts src/oci/public-image-archive.test.ts src/oci/public-image-inspection.test.ts src/oci/public-image-config-data.test.ts src/oci/public-image-layer.test.ts src/oci/public-image-policy.test.ts src/oci/public-image-tar-regressions.test.ts
```

Results: **66 + 4 = 70 socket-free tests passed**; full API and focused strict OCI typechecks passed. No Docker, network, live DB, actual native/scanner run, commit, or out-of-scope code changes were performed. Ready for coordinator rebuild and actual native rerun; that acceptance remains with the coordinator.

## Authorized Debian acquisition diagnosis and public FNAME fix (2026-10-18)

### Evidence collected before changing acceptance

Only `docker exec` into the explicitly permitted `dip-public-images-worker-1` was used. Diagnostic imports and source copies were placed in fresh UUID temporary trees, never over the running application. Acquisition used the existing `prepareBoundedImageArchive` budget, repository-scoped `dockerHubManifestFetch` and `gatewayGet`, with the exact immutable public target. Instrumentation preserved rejection behavior and exposed only fixed reject locations, format/type counts, gzip flags, PAX key names and hashes—not config, Env, base64, contents, filenames or tar paths.

An initial probe on the container's separate 16 MiB `/tmp` mount correctly failed the existing free-space reservation before layer download. It was cleaned and repeated under a fresh owned `/tmp/trivy` UUID tree on the scanner scratch mount (2,415,919,104 available bytes). This changed only the diagnostic root, not any limit, policy or live configuration.

The unchanged-source probe then fetched **28,249,323 compressed bytes**, with verified layer digest `sha256:7fd1ebe418b5079d4aa36f416af9b143d127bc75b0155d71cb5fd559b5e04d39`. It rejected at the original gzip fixed-header predicate (`ARCHIVE_L50` in the copied diagnostic source), before parsing any tar header. Gzip magic was `1f8b`, method `8`, flags **8 (FNAME)**. This establishes the exact root cause: a legitimate optional compression filename field, not a network, tar-entry, PAX-key or diffID mismatch. No acceptance behavior had been changed at this point.

### Narrow source change and regression-first evidence

Changes in this follow-up are confined to:

- `server/api/src/oci/bounded-image-archive.ts`: public-profile-only support for gzip FNAME; bounded NUL search using the unchanged 512-byte `fieldBytes` ceiling; exact deflate start/consumption accounting; preserve fixed safe archive reason codes through inflation and attempt cleanup.
- `server/api/src/oci/layer-tar-validator.ts`: add finite `ArchiveRejected.reason` codes (`ARCHIVE_REJECTED`, `GZIP_HEADER`, `GZIP_NAME`, `GZIP_INTEGRITY`), retaining the generic error message. Tar parsing and numeric limits are unchanged.
- New `server/api/src/oci/public-image-gzip-name.test.ts`, plus this document.

The gzip name is never decoded, interpreted as a filesystem path, used for extraction, emitted, added to a receipt, or stored separately. The compressed descriptor hash covers the whole original gzip including FNAME; every expanded tar byte is retained and still checked against the config diffID. No files/entries are skipped to obtain a successful result. Public flags must be exactly `0` or `8`; legacy still accepts only `0`. FHCRC/FEXTRA/FCOMMENT/FTEXT/reserved combinations, missing/overlong names, missing deflate payload, concatenated members, trailing bytes, CRC/ISIZE errors and malformed tar remain rejected. No limits or versions changed.

The new regression file was run before the fix: **3 failed, 3 passed**. After the fix, **6/6 passed**, covering unchanged complete tar/diffID output, empty/N-byte metadata names, N+1/truncation, default legacy rejection, unsupported flags, gzip/tar integrity, complete synthetic acquisition, stable safe reason codes and failure cleanup.

### Copied-source bounded actual acquisition after the fix

The candidate source was streamed into a new owned temporary tree in the same permitted worker. The running worker source, process and container were **not patched or rebuilt**. The exact immutable target was re-acquired through the same production transport/budget and prepared successfully; all temporary source and archive files were then removed.

| Bound identity/evidence | Observed value |
| --- | --- |
| Child manifest digest | `sha256:a4672c0cb26fbdde88e38fa2dfb6c681942306680e41e4378b28770b6e79ee91` |
| Config digest | `sha256:d4c45f66efc59f89b0597d343a9bd72808493c0eacecde5285961743252cee23` |
| Compressed layer digest | `sha256:7fd1ebe418b5079d4aa36f416af9b143d127bc75b0155d71cb5fd559b5e04d39` |
| Compressed bytes | 28,249,323 |
| Gzip method / flags / FNAME length | 8 / 8 / 10 bytes; no name value retained |
| Expanded diffID | `sha256:e58989146fcec76699871403b9897b5c014af1ccd85f5a9300a215e7975525d7` |
| Expanded bytes | 77,936,640 |
| Tar headers | 4,226, all exact GNU format |
| Entry types | 3,263 regular files; 2 hardlinks; 508 symlinks; 453 directories |
| PAX keys observed | None |
| Docker-save archive bytes | 77,940,224 |
| Archive SHA-256 | `sha256:b95ee276a3df9dd6f14ef1597ae3577db484f2fccd8af1ae936a94dedb652657` |
| Delivered response-body bytes | 28,256,443 (not literal wire accounting) |
| Transport/GET attempts | 7: four 200, two 307, one 401 responses; CONNECT not counted separately |
| Logical scratch reservation peak | 565,120,235 bytes (not kernel/block/RSS measurement) |

These are actual **archive acquisition** results with copied candidate source, not Trivy/native scanner or worker/API full-chain acceptance. The coordinator must rebuild before retrying the actual scanner chain; the running worker retains its old source until then. No DB, logs, private environment, old resources, unrelated scratch jobs or whole tar paths were accessed/emitted, and no lifecycle/pull/commit command was used.

### Final local validation

From `server/api`:

```sh
pnpm exec tsx --test src/oci/public-image-archive.test.ts src/oci/public-image-inspection.test.ts src/oci/public-image-config-data.test.ts src/oci/public-image-gzip-name.test.ts src/oci/public-image-policy.test.ts src/oci/public-image-layer.test.ts src/oci/public-image-tar-regressions.test.ts src/oci/archive-budget.test.ts src/oci/archive-identity.test.ts src/oci/layer-tar-validator.test.ts src/oci/nginx-candidate.test.ts src/oci/registry-resolver.test.ts
pnpm exec tsx --test --test-name-pattern='^(Hub requests build|anonymous scoped Bearer|blob redirect strips|hostile auth realms)' src/oci/gateway-transport.test.ts
pnpm exec tsc --noEmit
pnpm exec tsc --noEmit --target ES2022 --module NodeNext --moduleResolution NodeNext --strict --esModuleInterop --skipLibCheck src/oci/public-image-archive.ts src/oci/public-image-inspection.ts src/oci/public-image-policy.ts src/oci/archive-identity.ts src/oci/public-image-archive.test.ts src/oci/public-image-inspection.test.ts src/oci/public-image-config-data.test.ts src/oci/public-image-gzip-name.test.ts src/oci/public-image-layer.test.ts src/oci/public-image-policy.test.ts src/oci/public-image-tar-regressions.test.ts
```

Results: **72 + 4 = 76 socket-free local tests passed**; full API and focused strict OCI typechecks passed. Scoped `git diff --check` for the two modified shared production files passed. Unrelated dirty work and nginx-specific/proof files were preserved. No native/full-chain PASS is claimed; coordinator rebuild and scanner verification remain pending.
