# Image config v1 — standalone module / integration handoff

Implemented for `DIP-TASK-7`, run `ed9b6122-f013-445f-a936-f08aa1d57539`, architecture decision `28880b86-5ecf-47d5-bfbe-2d517449005b` and target delta `bb5be648-a2fa-49ee-b0f0-53d0b38a7a44`.

**Partial delivery, not an integrated scan feature.** These files do not register an API endpoint, add a worker option, change the report schema, persist outcomes, or render UI. No production authorization adapter, live registry egress, real HTTP/log redaction, restart/ledger integration, browser proof, or full TASK7 acceptance is claimed.

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

The names above describe **future composition inputs**, not existing adapters. `TrustedCallerPort.resolveAuthorizedTarget(handle)` resolves a genuine runtime-issued opaque handle to an `AuthorizedImageInput` or returns `undefined`. It may return a promise. The module captures the resolver at construction; no request can replace it. Do not expose module construction, the port, or target minting through HTTP.

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

Platform strings are closed canonical tokens, not copied arbitrary strings: OS `linux`, `windows`, `freebsd`; architectures `amd64`, `386`, `arm`, `arm64`, `ppc64`, `ppc64le`, `s390x`, `riscv64`, `mips`, `mipsle`, `mips64`, `mips64le`, `loong64`. Optional variants are `v1` through `v9` for `arm`, `arm64`, or `amd64`; no aliases or empty-string variant normalization. Config platform must match exactly; an absent variant differs from null or empty. Unsupported/noncanonical or mismatched tokens fail identity verification without echoing them.

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

| Image config User | Result |
| --- | --- |
| config/User absent or exactly empty string | checked, one `DEFAULT_ROOT` metadata finding |
| decimal UID zero, including `000`, `0:1000` | checked, one `NUMERIC_ROOT` metadata finding |
| decimal UID > 0, including `1000:0` | checked, no root finding; no runtime assurance |
| names including `root`/`app`, named GID, whitespace, signs, extra colon, overflow | unsupported / `USER_NOT_RESOLVABLE`, no finding |
| null, number, array, object, boolean User | failed / `INVALID_CONFIG`, no finding |

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

The parser bounds recursion and node/collection growth **during** parsing, uses fatal UTF-8 decoding (including rejection of a BOM), checks duplicate **decoded** keys, and uses `JSON.parse` only for an individually bounded string token. Null-prototype objects prevent prototype-key interpretation. Invalid escapes, lone surrogate escapes and nonfinite numbers fail. Unknown fields/rootfs-like arrays cannot bypass budgets. Optional Env/Labels/history may be absent; when present they require the documented object/array/string/boolean field types, not coercion or null-as-absence.

### Redaction and identity

Results are built from a closed allowlist, never spreads of config/identity/errors. Root findings contain only deterministic `findingId`, fixed rule/category/severity (`MEDIUM`)/severity source, fixed message/recommendation, `/config/User`, `DEFAULT_ROOT` or `NUMERIC_ROOT`, verified digests and canonical platform. They do not contain raw User, Env names/values, label keys/values, history, registry/repository, source bytes, parser messages or arbitrary diagnostics. The runtime module does not log.

`findingId` is SHA-256 of a JSON tuple: verified manifest digest, config digest, explicitly ordered OS/architecture/variant (null when absent), checks version, rule ID and normalized location. Same verified identity yields the same semantic result/ID regardless of scan ID/time; changed digest/platform does not reuse evidence. Every result is freshly allocated, without aliases to an earlier result or caller input.

The module imports no network, filesystem, subprocess, daemon, LLM, ledger or application services. The trusted port is the only external capability; **its implementation remains outside this module's trust/validation proof**.

## Integration owner checklist (not implemented here)

1. Add a real authorized API opt-in and opaque pinned-target handle adapter. Current resolver identity alone is not verified byte delivery. Acquire bounded exact manifest/config bytes through the shared owner's OCI path, not a new direct-fetch fallback in this module.
2. Preserve upstream exact host allowlist, DNS/IP gateway policy, TLS hostname checking, bounded/validated token realm/service/scope and redirect hops, and no credential forwarding across origins. No live egress proof is provided here.
3. Map this closed schema explicitly into the current exact report schema. Keep vulnerability, secrets, SBOM, container and host outcomes independent; no module failure should erase or downgrade sibling evidence.
4. Merge and persist independent versioned coverage in the existing attempt-fenced atomic result/terminal/event transaction. Retain scan ownership, idempotency/recovery and restart behavior. Verification/network work stays **outside** SQLite transactions. This delivery edits no schema/DB/config.
5. Verify redaction in actual HTTP responses, logs, events and persisted reports, plus real UI selection/status/version coverage. Pure module canaries are not end-to-end redaction proof.
6. Obtain three independent approvals for the reviewed revision, including a correctness recheck after exception-containment rework. The initial standalone spec/security reviews approved; correctness requested changes. TASK7 remains partial/in_progress pending real integration acceptance. Do not mark testing/done as if full delivery occurred. The feature-source applied delta does not satisfy the task-level strict close gate. Do not use a false no-spec-impact declaration to close behavior-changing work.

## Validation

From `server/api`, without Docker:

```sh
pnpm exec tsx --test 'src/image-config/*.test.ts'
pnpm typecheck
```

Tests exercise the **public `analyze` entry**, positive/default/numeric/named-user outcomes, fixed versions, off/invalid flags without capability reads, forged/serialized/cloned/foreign target handles, independent identity/hash/size/media type/platform faults, malformed/duplicate decoded JSON keys and known field types, all reachable limit−1/limit/limit+1 boundaries (including unknown fields and UTF-8/escaped keys), deterministic IDs, independent source/history coverage, closed output fields, canaries and no logging. Exception regressions cover synchronous throws and rejected promises, throwing prototype/descriptor traps, revoked proxies, own/inherited reason getters, coercion/property traps and genuine internal failure reasons. Internal tests additionally cover private receipt forgery/cross-instance rejection, post-verification byte/identity mutation, parser edge cases and output encoder bounds. Static runtime import/call checks complement passive metadata tests; they do not validate a production port or live egress.

No shared worker/OCI/ledger/controller/UI/broker/compose/package files are part of this delivery; no new dependencies or Docker are required.
