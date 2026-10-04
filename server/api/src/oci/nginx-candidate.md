# Nginx candidate inspection — not scan admission

`nginx-candidate.ts` is a preparation slice for `DIP-TASK-2`, run
`6ea945ee-a917-4936-8e64-1d34171065bc`, judgement
`5033a59a-853c-4bb5-80b2-fbaefd06f3fd`. It is not wired to a controller,
search eligibility, worker or production admission. `NGINX_PROFILE.enabled`
is permanently false in this slice; qualified targets are empty. There is no
environment flag, public test route or client override that enables it.

## Implemented inspection bounds

Only `registry-1.docker.io/library/nginx`, `linux/amd64` is inspected. The
existing OCI resolver verifies index/child/config hashes, content types and
config platform. Inspection additionally verifies the selected child size,
strict UTF-8 JSON and layer descriptors, returning the child digest and config
digest with an explicit `unqualified` classification. Linux config does not
prove Alpine/APK, scanner coverage, a CVE count, or a supported OS release.

Resource policy `nginx-candidate-resources-v1`:

| Bound | Limit | Enforcement |
| --- | --- | --- |
| Index/manifest/config wire object | 4,000,000 bytes | Gateway streaming cap and inspector check |
| Config descriptor/body | 1,000,000 bytes | Descriptor precheck and verified body |
| Inspection HTTP response bytes, including auth and redirects | 16,000,000 bytes | Shared transport budget; remaining bytes passed to streaming reader |
| Inspection HTTP requests, including auth and redirects | 12 | Shared counter; no extra retry mechanism |
| Entire inspection transport window | 30,000 ms | Monotonic budget; remaining absolute deadline passed to gateway reader |
| Layer count | 32 | Descriptor precheck |
| One compressed layer | 32 MiB | Descriptor precheck only |
| Sum of compressed layers | 96 MiB | Descriptor precheck only |

Only OCI/Docker gzip layer media types are accepted. Empty/missing layers,
foreign layer URLs, unknown compression, unsafe sizes and invalid digests fail
closed. No layer bytes are downloaded by this inspector. The gateway retains
fixed destinations, scoped anonymous auth, TLS and public-IP validation; tokens
are not forwarded to CDN redirects. Errors never include raw responses.

The transport is single-inspection scoped. A failed wire request exhausts that
instance; create a new instance only for a new bounded inspection. Injected
fetch functions in tests are fixtures, not a production network fallback.

## Release gates still pending

Before any nginx admission, establish **enforced** aggregate layer download,
retry/time, expanded per-layer/total tar bytes, entry count/field size and scratch
headroom bounds. Descriptor sizes and per-CONNECT limits do not enforce these.
No unpack/decompression claim is made by this slice. Existing worker CPU/RAM,
PID/tmpfs, timeout/stdout, Trivy `0.69.3` and registry-only guards must not be
raised to get a candidate through.

Then bind independently qualified checks to an exact child/config digest,
platform and versioned scanner/parser/resource policy, with operator proof
reference. Revalidate DB signature/hash/schema/freshness at admission and use;
keep the private signing key host-only. Obtain a real remote supported Alpine
inventory and initial positive CVE proof in a separately isolated deployment,
followed by browser and negative proofs and three independent reviews. Only
then may an operator manually opt in the stand; production is not enabled here.

The remaining Alpine-only path is intentionally unchanged: `scans.service.ts`
and `oci-resolver.ts` admission; `sbom-worker.ts`/`vuln-worker.ts` target checks;
`cyclonedx-components.ts`/`vuln-findings.ts` report identity and Alpine/APK checks;
`ledger.ts` runtime image/repository validation and audit labels;
`image-search.ts` eligibility and frontend `scanTransport.ts` wire schemas.
The secret runner's broader syntactic guard must also be narrowed to the same
admitted identity when integrating. Widening one of these alone is unsafe.
Do not migrate SQL merely for repository widening; independent outcome/DB
provenance changes require their own forward-only migration and tests.

Task 2 remains `in_progress`; future mixed-target delta
`db14160a-85f5-42f6-b112-a9b2138dc466` is not applied by this slice. Node/npm,
arbitrary Hub repos, unsupported OS, host/runtime and new upstream DB rotation
are not certified. A passing API suite does not establish that the previously
intermittent `scans.events.test.ts` issue is resolved.
