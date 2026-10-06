# Image config v1 — bounded module and scan integration

Implemented for `DIP-TASK-7`, run `ed9b6122-f013-445f-a936-f08aa1d57539`, architecture decision `28880b86-5ecf-47d5-bfbe-2d517449005b` and target delta `bb5be648-a2fa-49ee-b0f0-53d0b38a7a44`.

The pure module remains independently usable. The TASK7 integration now selects config through the existing ordered HTTP `checks` array, composes a private per-attempt worker authority, loads exact pinned OCI bytes through the existing gateway, atomically persists independent versioned results in SQLite v11 and renders strict parsed status coverage in the browser. No arbitrary repository or production nginx admission is added. Controlled Nest/worker/SQLite tests are not live external proof. The dated config-only Alpine proof below now exercises the actual stand gateway/worker and owner HTTP status; it does not establish Trivy/CVE, exhaustive TLS/DNS/egress, nginx or full production acceptance. Independent integration reviews and task-sourced strict-close documentation are separate from implementation.

Spec-history snapshot checked on **2026-10-06**: feature-source delta `bb5be648-a2fa-49ee-b0f0-53d0b38a7a44` was human-approved at **18:42:31 UTC** and applied as `DIP-DOC-5` version 2 at **18:45:21 UTC**, after the original author handoff. Earlier unapplied statements describe that author-time snapshot, not the current spec state. This later application does not prove production integration, full task acceptance or task-level strict closure. This correction does not approve, apply or undo any delta.

## Public entry

Import `createImageConfigModule` and types/constants from `./index.js`. Instantiate once in trusted server composition:

```ts
const imageConfig = createImageConfigModule(trustedCallerPort);
const result = await imageConfig.analyze({
  enabled: true,
  target: serverIssuedAuthorizedScanTarget,
  dockerfileProvided: false,
  iacProvided: false,
});
```

The names above describe trusted composition inputs. The scan adapter is `worker/image-config-runner.ts`; its ledger-derived account/scan/attempt capability is never serialized or supplied by HTTP. `TrustedCallerPort.resolveAuthorizedTarget(handle)` resolves a genuine runtime-issued opaque handle to an `AuthorizedImageInput` or returns `undefined`. It may return a promise. The module captures the resolver at construction; no request can replace it. Do not expose module construction, the port, or target minting through HTTP.

The adapter must recognize handle **object identity/origin**, bind it to the current authorized account/scan/pinned registry+repository+child manifest digest+platform, and reject cloned, serialized, cast, forged, stale or cross-context handles. For example, a server-owned per-authorized-scan handle registry can establish origin; validating `verified: true` or structural DTO fields cannot. `test-fixtures.ts` uses an in-memory registry **only as a test fixture**, not proof of real authorization. Module hashes prove byte binding, not account authorization, publisher authenticity, signature validity, or image security.

Resolved input contains:

- `identity.registry`, `identity.repository`, `identity.manifestDigest` (`sha256:` + 64 lowercase hex digits), and canonical `identity.platform`;
- raw `manifestBytes` and `configBytes` as `Uint8Array`/`Buffer`, never pre-parsed history or separately supplied descriptor evidence.

The verifier caps bytes before copying/decoding, owns copies, hashes the selected **child manifest**, bounds/decodes it, extracts that manifest's config descriptor, checks exact config hash/size/media type, bounds/decodes config and checks exact `os`/`architecture`/`variant`. An index is not a child manifest. SharedArrayBuffer inputs are rejected. All unknown JSON fields consume the same limits.

Supported manifest media types:

- `application/vnd.oci.image.manifest.v1+json`
- `application/vnd.docker.distribution.manifest.v2+json`

Supported config media types:

- `application/vnd.oci.image.config.v1+json`
- `application/vnd.docker.container.image.v1+json`

Platform strings are closed canonical tokens, not copied arbitrary strings: OS `linux`, `windows`, `freebsd`; architectures `amd64`, `386`, `arm`, `arm64`, `ppc64`, `ppc64le`, `s390x`, `riscv64`, `mips`, `mipsle`, `mips64`, `mips64le`, `loong64`. Optional variants are `v1` through `v9` for `arm`, `arm64`, or `amd64`; no aliases or empty-string variant normalization. Config platform must match exactly; schema-optional config `variant:null` equals absent, but differs from a required authoritative variant. Empty or mismatched non-null variants still fail. The authoritative caller identity is not normalized. Unsupported/noncanonical or mismatched tokens fail identity verification without echoing them.

Private instance-local WeakMap receipts have no enumerable proof fields and are not returned by `analyze`. The verifier retains only a frozen, reduced snapshot (validated User string, normalized platform and digests); owned byte copies/parsed raw documents are discarded after verification. Cloning/casting/serializing a receipt, deep-importing another verifier, or passing request `receipt`/`verified`/`descriptor` fields does not grant this instance authority. Internal helper exports exist for tests, not as alternate public analysis entry points. No mutable byte snapshot is exposed.

## Observable module contract

### Opt-in and coverage

- Only an own data-property boolean `enabled: true` activates analysis.
- Absent `enabled` or boolean `false`: `config = skipped / CHECK_DISABLED`, without reading target/bytes/receipts or calling the authority/verifier/rule.
- Present `undefined`, null, number, string, object or accessor flag: `failed / INVALID_CHECK_FLAG`. Inherited flags do not activate analysis. DTO getters are not executed to obtain source-presence, target or flag data.
- Present `policy`, `resourcePolicy`, `resourcePolicyVersion` or `checksVersion` on an enabled request: `failed / INVALID_RESOURCE_POLICY`, before target resolution. Callers cannot override/disable fixed policy, even using the current version string. On disabled/invalid flags these unrelated fields are not examined.
- Unauthorized/unrecognized handle, upstream exception, invalid identity/descriptor or byte/platform mismatch: `failed / OCI_IDENTITY_REJECTED`. Exception classification is guarded, including `instanceof` and descriptor inspection: throwing/revoked proxies fall back to this fixed reason. Exception getters are not invoked; raw exceptions are never stringified, returned or logged. Only the existing allowlisted internal validation/limit reasons are preserved.
- Malformed UTF-8/JSON, decoded duplicate keys, non-object config or wrong known metadata types: `failed / INVALID_CONFIG`. Invalid manifest identity structure instead returns `OCI_IDENTITY_REJECTED`. No parser text escapes.
- Limit exceeded: `failed / CONFIG_LIMIT_EXCEEDED`, no partial findings.

Every result has `checksVersion = image-config-user-v1`, `resourcePolicyVersion = image-config-policy-v1`, `supportedRuleIds = [IMGCFG_USER_ROOT]`, one rule outcome, actual `completedRuleIds`, and independent `config`, `history`, `dockerfile`, `iac` coverage. `completedRuleIds` is populated **only** for `checked`. A checked result with no root finding does not imply image safety or non-root runtime identity. Failed/unsupported/skipped with empty findings must never be displayed as “0 problems”. No `not_authorized` result is fabricated without an upstream authorization decision.

History is **always** `unsupported / RULE_NOT_IMPLEMENTED`. Env/Labels/history are structurally validated, not claimed as checked security rules. Dockerfile and IaC are always unsupported, independently of config/history/opt-in: `SOURCE_NOT_PROVIDED`, or `SOURCE_ANALYZER_UNSUPPORTED` when their own data-property presence boolean is exactly true. Source bytes are never read, reconstructed from history, or executed.

### Sole supported rule: `IMGCFG_USER_ROOT`

`config=checked` means bounded, identity-verified image metadata was evaluated by this **one User/default-root rule**, not that a Dockerfile or the image's security was audited. Env/Labels/history validation does not add checked rules; Dockerfile/IaC remain separately unsupported.

| Image config User | Result |
| --- | --- |
| config/User absent, schema-optional null, or exactly empty string | checked, one `DEFAULT_ROOT` metadata finding |
| decimal UID zero, including `000`, `0:1000` | checked, one `NUMERIC_ROOT` metadata finding |
| decimal UID > 0, including `1000:0` | checked, no root finding; no runtime assurance |
| names including `root`/`app`, named GID, whitespace, signs, extra colon, overflow | unsupported / `USER_NOT_RESOLVABLE`, no finding |
| non-null number, array, object, boolean User | failed / `INVALID_CONFIG`, no finding |

UID and optional GID require 1–10 ASCII decimal digits and range `0..4294967295`; leading zeros are allowed. No passwd lookup, filesystem, daemon, container execution, or runtime inspection occurs.

### Resource policy: `image-config-policy-v1`

All bounds are inclusive and fixed in frozen `POLICY`:

| Resource | Maximum |
| --- | ---: |
| Manifest bytes | 1,000,000 |
| Config bytes | 1,000,000 |
| Combined bytes | 2,000,000 |
| JSON depth (root = 1, including scalar values) | 32 |
| JSON value nodes per document (keys are not value nodes) | 16,384 |
| Members/elements in any object/array | 4,096 |
| UTF-8 bytes per decoded key | 256 |
| UTF-8 bytes per decoded string value | 8,192 |
| History records | 1,024 |
| Env entries | 1,024 |
| Labels entries | 256 |
| User UTF-8 bytes | 256 |
| Serialized result UTF-8 bytes | 16,384 |
| Findings | 1 |

Combined limit+1 necessarily also exceeds an individual limit; it cannot be isolated while respecting both individual byte caps. Tests cover combined limit−1/limit/limit+1 with this constraint. The sole v1 rule cannot naturally emit two findings; internal output-encoder tests exercise cap enforcement without inventing a second rule.

The parser bounds recursion and node/collection growth **during** parsing, uses fatal UTF-8 decoding (including rejection of a BOM), checks duplicate **decoded** keys, and uses `JSON.parse` only for an individually bounded string token. Null-prototype objects prevent prototype-key interpretation. Invalid escapes, lone surrogate escapes and nonfinite numbers fail. Unknown fields/rootfs-like arrays cannot bypass budgets. OCI image-spec v1.1.1 [Properties](https://github.com/opencontainers/image-spec/blob/v1.1.1/config.md#properties) defines optional null as absent and explicitly allows `config:null`. After exact original-byte verification, only the existing schema-view guards for config, User, Env, Labels, history, optional history record fields and config variant apply that semantics. No bytes are stripped, reserialized or rehashed. Non-null fields retain object/array/string/boolean validation and every budget; null Env elements, null label values and null history records remain invalid. Required os/architecture, the manifest config descriptor and root document are not nullable. This bounded metadata view is not a full OCI rootfs/layer validation or unpacker.

### Redaction and identity

Results are built from a closed allowlist, never spreads of config/identity/errors. Root findings contain only deterministic `findingId`, fixed rule/category/severity (`MEDIUM`)/severity source, fixed message/recommendation, `/config/User`, `DEFAULT_ROOT` or `NUMERIC_ROOT`, verified digests and canonical platform. They do not contain raw User, Env names/values, label keys/values, history, registry/repository, source bytes, parser messages or arbitrary diagnostics. The runtime module does not log.

`findingId` is SHA-256 of a JSON tuple: verified manifest digest, config digest, explicitly ordered OS/architecture/variant (null when absent), checks version, rule ID and normalized location. Same verified identity yields the same semantic result/ID regardless of scan ID/time; changed digest/platform does not reuse evidence. Every result is freshly allocated, without aliases to an earlier result or caller input.

The module imports no network, filesystem, subprocess, daemon, LLM, ledger or application services. The trusted port is the only external capability; **its implementation remains outside this module's trust/validation proof**.

## Scan integration

- Canonical HTTP selection is `secret,sbom,vuln,config`, with 1–4 distinct values. Config is default-off in UI. No raw metadata, proof, source bytes or policy override DTO is accepted. Existing fingerprints/owner admission/replay semantics stay unchanged; a changed selection with the same idempotency key is a conflict.
- `oci/pinned-image-config.ts` uses the existing Docker Hub gateway/auth/redirect transport only. Its absolute loader budget is 30s, at most 8 transport requests including token/redirect requests, at most 1MB per manifest/config (32KB token ceiling). Every gateway call receives remaining deadline, byte ceiling and abort signal. The existing manifest/config verifier independently hashes descriptor-linked bytes and checks platform. Loader budget is separate from the unchanged `image-config-policy-v1` parser/rule policy.
- `worker/image-config-runner.ts` privately registers an opaque handle for the authoritative ledger subject, scan, current attempt and complete pinned job. It rechecks authority before/after I/O, rejects forged job contexts and revokes in finally. `lease_until IS NOT NULL` is required; retry clears it without changing attempt. Cancellation/replacement/abort cannot publish late outcomes. Disabled config issues no handle and loads no config bytes.
- `ledger.ts` migrates v10→v11 forward only, without legacy backfill or table rewrites. Config + legacy sibling writes + outbox ack + terminal state/event are one transaction. Archive reports retain their exact legacy schema; config is a separate validated argument. DB expiry downgrades only vuln, retaining other outcomes. Terminal aggregation considers selected checks only; unsupported history/source and unselected config do not force partial.
- New finalized scans expose an owner-scoped bounded `status.config`, even when skipped. Old scans/no finalized row omit it rather than invent v1 evidence. Selected `perCheck.config` has config versions/rule counts, never Trivy scanner/DB attribution. `/results`, `/sbom`, `/vuln` and SSE state hints retain their existing meaning.
- Browser parsing discriminates by `check`, uses a closed config schema and rejects contradictory rule/outcome/target/selection evidence. The UI displays versions, supported/completed rules, source/history limitations and metadata-only root findings without an extra fetch. Numeric-positive User is not runtime assurance.

## Evidence boundary

Controlled real Nest cookie HTTP→actual consumer→private adapter/module→temporary SQLite→actual GET/SSE/browser parser tests exercise redaction, ownership, replay and independent outcomes. Synthetic gateway/scanner ports are explicitly not external OCI/Trivy proof. Exact nginx archive tests exercise failed/skipped config and DB expiry without pretending synthetic bytes match external pinned digests. No stand DB/auth/keys/volumes are migrated or reset by those tests. Three applicable independent integration approvals are required; historical module approvals and the feature-source applied delta do not close TASK7. Integrator must produce a narrow task-sourced delta from proven behavior, not a future whole-P0 rewrite.

**2026-10-06 optional-null fix live proof:** after runtime commit `7d2bee406ae3e5594998bdc93d9ff92c217bcd68`, only api/worker were rebuilt and recreated using both existing stand compose files and the unchanged private stand.env. Full environment (including JWT), mounts/volume/release paths and memory/swap settings compared equal; web/egress container IDs were unchanged. A new integrator-owned account created before deploy retained its original session after deploy. Password/cookie remained memory-only. Two normal owner API config-only scans completed with `checked`, one completed `IMGCFG_USER_ROOT`, one `DEFAULT_ROOT` metadata-only finding and exact fixed v1 versions:

| Target | Own scan | Pinned child manifest | Config digest |
| --- | --- | --- | --- |
| Alpine 3.16 | `868589b6-1d98-43ee-a7b1-19f411a0db55` | `sha256:0db9d004361b106932f8c7632ae54d56e92c18281e2dd203127d77405020abf6` | `sha256:d49a5025be10344cce77d178103a225cb5d7316861e5d8f106e7ff278ae51b62` |
| Alpine latest | `3788621a-fdcd-4e08-a12e-55ee4e850548` | `sha256:d56c381f961d307a21b3ca004cf1e3910f106644aefb1f43e654c8a56c4fd395` | `sha256:320994c3b997e2ec6433f717f153e108023c5bec8fefa8d76b83451d16d05ea8` |

Both use linux/amd64 and preserve the exact digests independently captured in DIP-ARTF-24; the old target's original-byte identity was not normalized away. History stayed `unsupported/RULE_NOT_IMPLEMENTED`; Dockerfile/IaC stayed `unsupported/SOURCE_NOT_PROVIDED`. No other-user scan access, live SQL, raw metadata, auth reset, nginx admission or CVE/Trivy scan. This proves these two admitted config-only paths, not exhaustive network/infrastructure logging or full task approval. Original correctness reviewer independently approved the C4 patch in **DIP-ARTF-27**: original 22/22 compatibility probes, 68 additional guards, 8 actual consumer/storage safeguards and 226 scoped tests pass; fresh reviewer-owned Alpine3.16/latest scans also checked with the same original digests. That approval is patch-correctness only; parent-controlled specification review/application and full-task acceptance remain pending.

## Validation

From `server/api`, without Docker:

```sh
pnpm test
pnpm typecheck
# Optional Chromium proof against actual disposable Nest + worker + SQLite (root dev dependencies required):
pnpm exec tsx src/scans/scans.config.browser.ts
```

Tests exercise the **public `analyze` entry**, positive/default/numeric/named-user outcomes, fixed versions, off/invalid flags without capability reads, forged/serialized/cloned/foreign target handles, independent identity/hash/size/media type/platform faults, malformed/duplicate decoded JSON keys and known field types, all reachable limit−1/limit/limit+1 boundaries (including unknown fields and UTF-8/escaped keys), deterministic IDs, independent source/history coverage, closed output fields, canaries and no logging. Exception regressions cover synchronous throws and rejected promises, throwing prototype/descriptor traps, revoked proxies, own/inherited reason getters, coercion/property traps and genuine internal failure reasons. Internal tests additionally cover private receipt forgery/cross-instance rejection, post-verification byte/identity mutation, parser edge cases and output encoder bounds. Static runtime import/call checks complement passive metadata tests; they do not validate a production port or live egress.

The original isolated delivery changed only image-config files; integration commit `4bd2fca47d6d378443a370e816d9886305d29b12` additionally connected worker/OCI/ledger/controller/UI. The runtime optional-null fix changed only image-config files. A subsequent explicitly authorized test-only follow-up updates the stale expectations in `scans/scans.config.http.test.ts` and `worker/outbox-config.test.ts`; no other shared runtime files or dependencies change. Module and controlled HTTP tests do not require Docker; live stand checks do.

Compatibility regressions cover both Docker/OCI media-type pairs with absent/null/empty/nonempty optional fields, the Docker nil-map Labels shape, required/variant mismatch and byte-tamper rejection. `optional-null.http.test.ts` exercises 40 actual cookie HTTP→consumer→private adapter→temporary SQLite→owner GET/SSE/strict-parser cases (including sibling preservation and off/no-load). The shared follow-up keeps User:null as a checked/default-root compatibility case, replaces intentional failure inputs with User:false, and adds non-null boolean/number/array/object failure regressions. Sibling/terminal/owner/redaction assertions remain intact. Earlier full-suite failures from stale expectations remain historical evidence, not a reason to restore invalid optional-null semantics. The known unchanged SSE ordering fixture at `scans/scans.events.test.ts:67` is separate; a passing rerun does not establish that flake was fixed. On 2026-10-06 after this test-only follow-up, the scoped suite passed 240/240, API typecheck passed, and a full API run passed 431/431; these are exact invocation results, not stable full-suite reliability or full task acceptance.
