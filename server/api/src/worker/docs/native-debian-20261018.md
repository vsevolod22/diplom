# Native Debian normalization handoff — 2026-10-18

## Result and coordinator action

Controlled native **candidate normalization passed** for the immutable public target:

`registry-1.docker.io/library/debian@sha256:a4672c0cb26fbdde88e38fa2dfb6c681942306680e41e4378b28770b6e79ee91`

- Native CycloneDX: **89 components**, including one validated OS component; normalized SBOM retains **88 Debian packages**.
- Native vulnerability JSON: **88 inventory packages**, **241 findings**; normalized output retains all **236 CVE IDs + 5 Debian TEMP advisory IDs**, all ecosystem `deb`.
- Trivy **0.69.3** version check, bounded native invocations, archive hash, full config/diffID identity validators, public result envelopes and public DB preflight/postflight identity verification passed.
- No npm inventory/coverage was invented. The observed native vulnerability result is one Debian OS result; Node coverage remains explicitly `NODE_INVENTORY_UNKNOWN`.

**Required coordinator ledger/UI change before a fresh published scan:** accept `^TEMP-[0-9]{7}-[A-F0-9]{6}$` as a bounded public Debian advisory identifier, not a CVE. Preserve its exact value in the existing compatibility field `cveId`; use a neutral advisory/identifier label and do not fabricate CVE/NVD links for it. The parser accepts this namespace only for public Debian OS evidence and ecosystem `deb`; legacy CVE-only admission remains closed. Public envelope validation limits TEMP IDs to `deb`. There is no new ecosystem enum, output field or relaxed size/count bound.

The worker-side envelope helper is `publicVulnerabilityId`. Coordinator storage/read-model/browser validators must apply the equivalent public-only rule and keep legacy grammar unchanged. Classifying every one of these 241 findings as a CVE would be inaccurate: the native evidence contains 236 CVEs and 5 temporary Debian advisories. The existing advisory normalizer emits no CVE/NVD reference URLs for TEMP IDs.

## Original stand observation versus this replay

The parent reported scan `f147b838-63b1-47a2-a2c8-4afc6774ef57` on the running `dip-public-images` stand at port 8081: config checked, Secrets checked-zero, SBOM and vulnerability checks `SCAN_FAILED`. This follow-up did **not** query, update, requeue or replace that scan or inspect actual ledger DB rows. Existing state/report records were not written by the diagnostic.

The parent separately reported a successful all-four native Node 22 Alpine run; that is parent-provided evidence, not a new claim from this Debian replay. This replay did not rescan config or Secrets and does not claim a newly published all-four Debian result. The next published scan and matching ledger/UI rollout remain coordinator work after return.

## Evidence-based diagnosis

Only the authorized new `dip-public-images-worker-1` was used. A new UUID-named source copy was created under the worker's writable temporary storage. The initial baseline used the currently shipped OCI acquisition code, including the parent's inline-config and gzip FNAME fixes; no OCI source was modified here.

Safe native acquisition counters: **4226 archive entries, one verified layer/diffID**. Both scanner stages exited successfully with bounded output: CycloneDX **191223 bytes**, vulnerability JSON **1098619 bytes**. No raw scanner stdout/stderr, report, Env, path, PURL, package identifier, advisory identifier or matched secret was printed or saved. Only fixed diagnostic labels, booleans, types and aggregate counts left memory.

### CycloneDX rejection

The existing public parser rejected the intact native report at fixed label `SBOM_PACKAGE_IDENTITY`:

- 88 library components carried the expected architecture/distro qualifiers.
- **11** additionally carried a numeric `epoch` qualifier.
- All **11** unqualified-PURL/display-version mismatches were explained exactly by `epoch + ':' + PURL version`.
- The previous parser compared the epoch-less PURL version directly to the full display version and required exactly two qualifiers, rejecting valid dpkg identity evidence.

### Vulnerability rejection

The existing public parser rejected the intact native report at `VULN_CORE`; additional independent inventory diagnostics established the next rejection it would encounter:

- Inventory contains **76** nonempty string `Release` fields and **11** integer `Epoch` fields.
- **239** findings do not match an inventory package by naive `Version === InstalledVersion`.
- Every one of those **239** matches exactly when the inventory fields are composed as `[Epoch:]Version[-Release]` and matched by the same package name. The remaining two already match without composition.
- Exactly **5** scanner IDs are not CVE-formatted. All five match the fixed Debian TEMP grammar above. They must remain findings rather than being silently omitted or converted into invented CVE IDs.

No findings were removed, OS inferred from a tag, package inventory projected into a different identity, or unsupported ecosystem silently skipped to obtain a passing result.

## Narrow worker changes

- `public-image-evidence.ts`: bounded `publicDebianVersion` for Trivy's split inventory fields and the exact public Debian TEMP ID grammar.
- `cyclonedx-components.ts`: permit one canonical numeric Debian `epoch` qualifier in addition to architecture/distro, bind the complete reconstructed version to the original full display version, and retain that full display version in normalized SBOM output.
- `vuln-findings.ts`: validate Debian epoch/revision field types and match the complete canonical inventory version against the original scanner `InstalledVersion`; preserve every supported native CVE/TEMP finding and its original identifier/version.
- `archive-result-contract.ts`: public-only identifier validation follows the bounded ecosystem-aware helper; other envelope requirements remain unchanged.
- `native-debian-normalization.test.ts`: minimal sanitized observed-shape regressions and strict negatives.
- `native-debian-diagnostic.ts`: explicit diagnostic executable with a closed immutable target, bounded invocation and fixed safe summaries. It never opens ledger rows or writes a scanner report. It was run only in the authorized container's own candidate copy.

Epoch is an optional integer between zero and 2147483647 in inventory; negative, fractional, string, nonfinite or out-of-range values fail. Revision must be a bounded valid version fragment when nonempty. The full composed version remains limited to the existing 80-character public version bound. A redundant embedded epoch plus a separate epoch is rejected. PURL epoch must be canonical positive ASCII decimal within the same bound; zero/noncanonical/duplicate/unknown qualifiers, mismatched epoch/version, bad architecture and bad distro still fail. APK/RPM/language qualifier rules and legacy Alpine/nginx parsers were not relaxed.

No archive hash/config/diffID checks, stage/JSON limits, package/result/finding counts, target admission, invocation arguments, cancellation/checkpoint behavior or DB policy was changed. In particular, the R1 accepted-checkpoint interruption/recovery fix is unchanged. Consumer/config/trust composition changes owned by the coordinator were left intact.

## Controlled candidate replay and safety boundary

The candidate copy retained the shipped source tree and dependencies; only the five worker candidate files needed for diagnosis/normalization/envelope validation were replaced inside that copy. Application source in the live container was not patched. Full raw native CycloneDX and JSON objects remained in process memory and were passed intact to `validateArchiveSbom` / `validateArchiveJson` and the normalizers. There was **no identity projection**, raw-report rewrite, dropped-result filter or substituted inventory.

The replay reused `preparePublicImageArchive`, `runArchiveProcess` and the public scratch audit. It rechecked the archive hash/read-only regular file/stable file identity before each invocation and verified cache DB file identity against the authorized read-only release. DB options were obtained only through the permitted `buildVulnConfig(undefined, localDbTrustAnchorFromEnv(), true)` composition. Signed public DB preflight before and after the stages produced the same identity. Private keys, actual SQLite ledger rows and existing reports were neither read nor printed. Raw Env fields were not inspected or emitted; the complete scanner objects remained solely in memory for full identity validation and normalization.

Both normalized per-check public envelopes passed validation in memory. Summary counters were:

| Boundary | Observed result |
| --- | --- |
| Acquisition | 4226 entries; 1 layer/diffID |
| Scanner | Trivy 0.69.3 verified; both stages exit 0 |
| Native SBOM | 89 components; 1 OS; 88 normalized `deb` packages |
| Native vulnerabilities | 1 OS result; 88 packages; 241 native and normalized findings |
| Identifier partition | 236 CVE; 5 Debian TEMP; none discarded |
| Binding/envelopes | Full original config/diffID evidence and both public envelopes verified |
| DB | Verified public release/cache binding; identity unchanged before/after |

Every acquired UUID archive scratch directory was removed by its own cleanup. The separately created UUID candidate-source directory was also removed after replay. No global scratch recovery, lifecycle/restart/rebuild, other container/resource, app-source patch, actual report write or new submitted scan was used. The diagnostic only writes its own temporary source/scratch and source-code fixtures; it never persists native report data. Native success here is a candidate SBOM/vulnerability normalization proof, **not** a ledger/UI acceptance or deployed all-four scan proof.

## Validation

From `server/api`:

```
pnpm exec tsx --test src/worker/native-debian-normalization.test.ts src/worker/public-image-worker.test.ts src/worker/public-image-consumer.test.ts src/worker/public-image-checkpoint-recovery.test.ts src/worker/archive-scan-worker.test.ts src/worker/vuln-findings.test.ts src/worker/cyclonedx-components.test.ts src/worker/archive-process.test.ts src/worker/archive-scratch.test.ts src/worker/secret-findings.test.ts src/worker/public-image-runtime.test.ts src/worker/vuln-db-trust-wiring.test.ts
pnpm exec tsc --noEmit
```

Observed: **69 tests passed, 0 failed, 0 skipped; full API typecheck passed.** The selection covers the new Debian shapes/negatives, existing legacy parsing, byte/hash/identity boundaries, cancellation, real disposable SQLite checkpoint recovery and unchanged trust wiring. No full heavy suite or production ledger/UI write was run.
