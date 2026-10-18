# Public image config / LOCAL trust handoff — 2026-10-18

## Scope and ownership

This slice changes only:

- `server/api/src/oci/pinned-image-config.ts`
- `server/api/src/worker/image-config-runner.ts`
- `server/api/src/worker/public-image-worker.main.ts`
- `server/api/src/worker/worker-runtime.ts`
- New own tests: `server/api/src/oci/pinned-image-config.public.test.ts`
- This handoff.

Existing worker-agent changes in the allowed files were retained. No ledger, scans, UI, deployment, live environment, Docker, private-key files, or commits were changed by this slice. Tests use temporary SQLite files, injected registry responses, and disposable public-key bytes. Tests restore any process-local environment/mocks they modify.

## Explicit composition interfaces

```ts
admittedConfigTarget(job, publicImagePolicy = false)
createPinnedConfigLoader(request = gatewayGet, publicImagePolicy = false)
runImageConfig(ledger, suppliedJob, signal, loader = undefined, publicImagePolicy = false)
buildVulnConfig(archivePolicy, anchor = PRODUCTION_DB_TRUST_ANCHOR, publicImagePolicy = false)
```

- Default config admission remains Alpine plus the existing enumerated archive candidates. No global default is widened.
- Explicit `true` config admission uses `validPublicTarget(job)` plus image scope: Docker Hub, validated repository, pinned SHA-256 digest, `linux/amd64`.
- Neither a persisted job field nor an environment flag selects public config authority.
- Public runner composition selects a public-aware pinned loader when no loader is injected. An injected loader must itself support the explicitly selected target.
- The runner retains the original claim snapshot, checks, subject/context, attempt and lease token. It checks ledger authority/context before and after loading, and checks loaded registry/repository/manifest/platform against that original claim. It does not rewrite a generic repository to an admitted legacy repository.
- Runner analysis does not write checkpoints/results; the owning consumer and ledger retain persistence authority.

### Required worker-owner update (not edited here)

In `server/api/src/worker/outbox-consumer.ts`, replace the four-argument config call with:

```ts
const config = await runImageConfig(
  ledger, job, controller.signal, options.configLoader, options.publicImagePolicy === true,
);
```

This exact update was reported early. The last inspected consumer still had the four-argument call. Until the owner updates it, generic config remains rejected at the runner even when archive consumption has public composition. Do not remove the runner gate or widen its default to compensate.

### Ledger-owner interface

The exported public-aware predicate is ready: `admittedConfigTarget(job, true)`. The ledger owner has integrated it behind its own public target guard (`publicConfigTarget`, excluding execution profiles). Default call sites remain restricted. This slice did not edit ledger implementation/tests or claim end-to-end public persistence verification.

## LOCAL broad-profile DB trust alignment

The public worker entrypoint now composes:

```ts
await runWorker(undefined, localDbTrustAnchorFromEnv(), true);
```

This uses the existing selector also used by the public API factory:

- Valid configured `LOCAL_CVE_TRUST_SHA256`: fixed `/opt/local-db-trust/public.pem`, pinned to that SPKI SHA-256.
- Absent LOCAL fingerprint: immutable production anchor.
- Invalid present LOCAL fingerprint, including empty string: selection throws rather than silently falling back.

`runWorker` forwards public composition to `buildVulnConfig(archivePolicy, anchor, publicImagePolicy)`. Only explicit LOCAL or public composition may use the supplied anchor. Default/proof composition ignores injected LOCAL anchors and LOCAL environment values. The generic runtime does not read LOCAL trust env itself.

Public-key validation remains required: regular non-symlink bounded public PEM, Ed25519, matching SPKI fingerprint. DB configuration is not signature verification/readiness: existing signed-bundle, source/schema/artifact and freshness preflight remains mandatory downstream. No private key is required by the new tests.

The code-level API/worker anchor mismatch is fixed; an operator still needs the same reviewed fingerprint, public-key mount and signed DB release available to both processes. No live configuration or deployment was changed or qualified here.

## Boundaries retained

- Config transport uses the existing HTTPS egress gateway, exact pinned manifest/blob paths and repository-scoped Docker Hub auth.
- Manifest SHA-256, manifest/config media types, descriptor shape/size, exact config length and bounded JSON remain enforced. Config SHA-256 is now also checked at transport return, before the existing verifier independently checks the manifest-to-config hash link and config platform identity.
- Existing 1,000,000-byte manifest and config caps, 2,000,000-byte verifier total, 30-second cumulative loading deadline, eight-request ceiling, abort propagation, token cap, redirect hop/host restrictions and cross-origin credential isolation remain.
- Public resource checks are unchanged: 4 GiB memory, zero swap, one CPU, 128 PIDs, physical tmpfs bounded above by 2304 MiB (and the existing scratch-budget safety floor). Default/LOCAL resource checks were not relaxed.

## Validation

From `server/api`:

```sh
pnpm exec tsx --test --test-skip-pattern='only the compiled LOCAL worker entrypoint reads LOCAL env' src/oci/pinned-image-config.public.test.ts src/oci/pinned-image-config.test.ts src/worker/image-config-runner.test.ts src/worker/public-image-runtime.test.ts src/worker/public-image-consumer.test.ts src/worker/vuln-db-trust-wiring.test.ts src/scans/public-image.service.test.ts src/worker/outbox-config.test.ts src/worker/outbox-config-archive.test.ts src/worker/outbox-combined.test.ts
pnpm typecheck
```

Results: **123 behavioral tests passed**, API `tsc --noEmit` passed. Scoped tracked-code `git diff --check` passed.

Coverage includes default rejection versus explicit public config admission/loading, malformed public targets, pinned transport hashes/types/lengths/limits/deadline/abort/auth/redirects, forged claims including lease token, loaded identity mismatches, subject/target/check/token changes during load, retry/cancel/replacement fencing, deferred uncooperative-load cancellation with late-byte discard, disabled config with no I/O, LOCAL public-key selection/fingerprint rejection, production fallback and unchanged default/proof isolation. The public API Nest factory is exercised for agreement with the worker's selector.

### One stale source assertion outside this slice's write ownership

The expanded command without the skip filter was also run and failed at `server/api/src/worker/vuln-db-trust-wiring.test.ts:191`. That source assertion requires the old literal `buildVulnConfig(archivePolicy, anchor)` runtime call. The new explicit public argument intentionally changes that call.

The test owner should update it to:

```ts
assert.match(runtime, /buildVulnConfig\(archivePolicy, anchor, publicImagePolicy\)/);
```

The new public test asserts the updated wiring, and the original LOCAL/default/proof behavioral trust tests pass. The filtered validation above excludes only that stale source assertion; it is not an unqualified green full-suite claim. No live registry, Trivy execution, signed-release readiness, container/cgroup qualification, or full end-to-end public scan was claimed.
