# Independent review: durable partial cancellation, ledger/worker

Review date: 2026-10-17. Requested filename retains 20261016.

## Verdict

**Request changes for this ledger/worker slice.** Three behavioral defects were reproduced, plus a narrower end-to-end token-fencing gap. The durable cancellation design itself is supported by the positive controls: terminal state remains `cancelled`, completed sanitized checkpoints can survive, and missing checks remain absent/unknown. This review does not propose a different product contract.

No production/test files were edited. The only repository file written by this reviewer is this report. No tracker access/mutations, staging, commits, branches, Docker, live scanners, private state, existing application databases, or full-suite run. Independent probes used fresh `:memory:` SQLite instances and synthetic values; selected existing tests used their disposable fixtures. No HTTP/UI/spec acceptance or live qualification is claimed. Coordinator owns those layers; the original author owns fixes.

Reviewed the implementation handoff, actual uncommitted production diff, the entire new `ledger.checkpoint.test.ts`, and relevant validators, persistence/read paths and worker tests. Locations below are relative to `server/api/src/` and refer to the reviewed bytes, not future concurrent edits.

## Findings

### R1 — P2: legacy vulnerability finalizer still publishes after expiry or retry revocation

**Location:** `ledger/ledger.ts:1064–1073`, especially the transaction's first UPDATE at 1070–1072. Compare the new live-lease guards in other finalizers.

`finishWithVuln(scanId, attempts, image, findings, scannerVersion)` checks running state, attempt and undelivered outbox, but not `lease_until` or a non-null token. `retry()` clears both while leaving the attempt number unchanged. A worker holding that revoked attempt can consequently publish a checked vulnerability result, acknowledge delivery and move the scan to `completed` before a replacement claim occurs. The same happens at the exact expiry boundary.

**Observed:** on a fresh legacy-policy, vuln-only scan, both expiry and retry made `checkpointActive(job)` false, yet `finishWithVuln(...)` returned true and state became `completed`. Replacement and cancellation correctly returned false. No database corruption or token forgery was needed.

Independent finalizer matrix, using valid payloads and the original claim's ID/attempt:

| Finalizer | At lease expiry | After retry, before replacement | After replacement | After cancellation |
| --- | --- | --- | --- | --- |
| `finish` | false | false | false | false |
| `finishWithResult` | false | false | false | false |
| `finishWithSbom` | false | false | false | false |
| `finishWithVuln` | **true** | **true** | false | false |
| `finishCombined` | false | false | false | false |
| `finishArchive` | false | false | false | false |

**True scope:** this is an omitted legacy path in the new fencing hardening, not a demonstrated bypass in the current consumer's `finishCombined` path. V2 policy still rejects `finishWithVuln`; an already-cancelled or replaced attempt is fenced. The handoff's statement that legacy finalizers enforce live leases is not currently true.

**Fix/test:** put the same transactional live authority check on this finalizer (and the claim-token check described in R3). Add expiry-at-equality, retry-before-reclaim and migrated-running-with-null-token cases; assert no rows, acknowledgement or terminal event on refusal. Existing new tests exercise retry/expiry through `finishCombined`, not this method.

### R2 — P2, security/contract boundary: archive checkpoint validation can persist raw extra fields or the wrong check shape

**Locations:** new call path `ledger/ledger.ts:562–570, 637–642, 680–690`; underlying shared validator `ledger/ledger.ts:152–168`; `worker/archive-result-contract.ts:29–41`.

Checked secret/SBOM objects are not checked against their own exact envelope keys. `validateStoredArchive` instead validates a derived object:

```ts
{ check: 'secret', ...report.secret, scannerVersion: report.scannerVersion }
```

An injected nested `scannerVersion` is overwritten for validation, but the original report is serialized into the checkpoint and later the cancelled archive report. An injected `check` can override the validator's intended discriminator.

**Observed in fresh in-memory ledgers:**

1. An otherwise valid secret checkpoint with `secret.scannerVersion = { Match: 'SYNTHETIC_RAW_CANARY', Code: 'SYNTHETIC_CODE_CANARY' }` returned true. The canary appeared in `scan_checkpoints.body` and survived `cancel()` and `archiveResult()` unchanged.
2. The same shadowed-field issue reproduced for checked SBOM with a nested `scannerVersion` string.
3. A secret-only scan accepted `secret = { outcome: 'checked', check: 'sbom', sbom: validArchiveSbom }` without any `secret.findings`. Cancellation and `archiveResult()` accepted and returned that malformed checked-secret shape.

This violates the claimed sanitized, exact-key checkpoint boundary; the integrity hash only authenticates consistency of those already-accepted bytes and cannot correct it.

**True scope:** the shared archive validator flaw predates this diff; the new checkpoint publication path inherits it. The supplied production archive runner constructs closed secret/SBOM envelopes, so these probes do **not** establish a scanner-output-to-HTTP exploit or cross-owner disclosure. They establish a concrete ledger validation/persistence defect for malformed adapter payloads, including raw-data persistence. Do not describe this as a new remote exploit.

**Fix/test:** exact-validate each original checked envelope before converting it to a combined outcome: secret only `outcome/findings`, SBOM only `outcome/sbom`; reject discriminator/version shadowing rather than relying on overwritten properties. Exercise checkpoints, full archive finalization and stored reads. Assert rejection before bytes reach the checkpoint table, and repeat with nested raw objects, not only a top-level `raw` key.

### R3 — P2, narrower API gap: finalizers/retry cannot enforce the caller's lease token

**Locations:** `ledger/ledger.ts:529–536, 745, 775, 797, 844, 945, 1064, 1275–1282`; production calls in `worker/outbox-consumer.ts:107, 115, 123–124, 164`.

The new checkpoint APIs receive a full `Job` and compare it with ledger-derived context. The terminal APIs still receive only `(scanId, attempts, payload...)`; `retry` receives `(scanId, attempts, nextRunAt)`. `liveAttemptTime` checks that *some* token exists, not that the caller possesses the current token. Finalizers obtain any config context themselves, which cannot prove the caller's original claim identity.

**Observed:** construct `wrong = { ...claim, leaseToken: 'wrong-token' }`. `checkpointActive(wrong)` is false, but every finalizer succeeds when invoked with its actual supported arguments derived from `wrong.scanId` and `wrong.attempts`. `retry` likewise succeeds. No token argument exists to reject. Missing-token callers have the same limitation.

**Important limitation:** this is **not** proof that an authentic old job defeats a normal replacement claim. Replacement increments attempts, and all six finalizers rejected the old attempt in the matrix above. There is no demonstrated same-attempt token rotation through the normal API. This is an incomplete implementation of exact claim-token authority, not a reason to claim that all existing attempt fencing is broken or that the token is a public authentication credential.

**Fix/test:** if exact token authority is the intended ledger boundary, finalizers and retry must accept the original claim/token and compare it inside their write transaction; consumer calls must pass that original authority. Tests need wrong/missing token with a current attempt as well as genuine stale attempts. Do not write a token test that merely changes an object field and then never passes that field to the tested API. No new HTTP/product gate is proposed here.

### R4 — P2: archive checkpoint storage errors are swallowed as scanner failures

**Locations:** new callback at `worker/outbox-consumer.ts:92–96`, broad enclosing catch at 120–125; callback exception propagation at `worker/archive-scan-worker.ts:163–165`.

The runner correctly lets callback exceptions escape its scanner catch, but `consumeOne` catches the resulting plain errors and finalizes **all requested checks as `SCAN_FAILED`**. SQLite errors are not `TypeError`/`DbPolicyContractError`, so they enter this fallback. A persistence error is therefore reported as a scanner outcome and can make already-checkpointed evidence permanently unavailable to cancellation.

**Observed:** use the real consumer, real in-memory ledger, and an injected archive runner emitting a valid secret checkpoint followed by an SBOM checkpoint. A SQLite trigger rejects only the SBOM checkpoint INSERT with `SQLITE_CONSTRAINT_TRIGGER`:

- first secret checkpoint commits;
- second checkpoint throws that SQLite error;
- consumer resolves `true`, rather than propagating the storage failure;
- scan becomes `failed`, and ordinary secret result is `failed` despite the retained checked secret checkpoint;
- `cancel()` now returns `conflict`.

The trigger is an isolated deterministic storage-failure injection, not a claim that production contains such a trigger. The existing outer catch predates checkpoints; feeding new checkpoint callback errors into it is the integration defect. The probe injected archive execution, not a live scanner, and did not rely on real disk-full/locking behavior.

**Fix/test:** distinguish and propagate checkpoint/storage failures across the archive-runner boundary, instead of translating them into scanner results. For this failure, leave the committed checkpoint and active scan available to the existing cancellation/recovery policy; do not invent results for unfinished checks. Add a consumer-level storage-error test after one committed sibling, not just ledger transaction rollback tests. Assert the storage error reaches the caller and subsequent cancellation preserves the completed sibling.

## Positive evidence and remaining limits

Independent in-memory probes also passed these controls:

- Oversized ordinary checkpoint body (>2,000,000 bytes) rejected with no checkpoint row; wrong-token checkpoint rejected; duplicate valid checkpoint could not replace the first.
- Running results remained unpublished. A different owner could not cancel. Corrupting a checkpoint body without its hash caused cancellation to fail and roll back an earlier sibling publication.
- Stripped V2 evidence was rejected. After advancing the injected clock 30 days, a previously committed valid receipt remained byte-equivalent through cancellation; the missing secret remained undefined.
- Actual ordinary consumer checkpointed secret before starting blocked SBOM, cancellation aborted the consumer, late SBOM output could not publish, and exactly one terminal cancellation event existed.

Fifteen narrowly selected existing tests were also run and passed (commands below): cancellation transaction fault points; ordinary/archive historical CVE freeze; checkpoint-fence CVE expiry; archive optional-advisory size omission; actual archive-runner cancellation with injected acquisition/scanner data; synthetic WAL/SIGKILL recovery; forward migration/reopen and migration rollback; retention.

No additional defect was established in the atomic cancel snapshot, ordinary owner binding, missing archive keys, optional-advisory merge, historical CVE read semantics, or retention/migration transaction logic beyond the findings above. This is bounded evidence, not a claim that these areas are exhaustively proven. The two-connection cases in the new test file invoke operations serially; they test both orders, not simultaneous SQLite lock contention. Old-worker deployment prohibition and backup/rollback guidance were reviewed, not operationally exercised.

## Exact selected test commands/results

Run from `server/api`, using installed dependencies, no dependency installation:

```sh
node --import tsx --test --test-name-pattern='checkpoint commits before cancel|cancel snapshot, config, siblings|CVE receipt is validated|CVE expiry at the checkpoint|checkpoint cancellation budget|v14 to v15|failed v15|retention removes|committed WAL checkpoint' src/ledger/ledger.checkpoint.test.ts src/ledger/ledger.archive.test.ts
# 14 passed, 0 failed; observed duration ~2.67 s; invocation timeout 60 s.

node --import tsx --test --test-name-pattern='archive consumer checkpoints audited positive Secrets' src/worker/archive-scan-worker.test.ts
# 1 passed, 0 failed; observed duration ~0.68 s; invocation timeout 15 s.
```

Independent probes were executed with `node --import tsx --input-type=module` via stdin, each invocation bounded to 20 seconds. Their assertions confirmed the documented buggy behavior, rather than treating acceptance of those cases as desired behavior. Additional finalizer matrix: 24 combinations, plus seven wrong-token/API-shape cases. No full suite or typecheck was repeated for this read-only review.

## Minimal reproducible probes

The following reproduces the core observations from `server/api` with installed `tsx`. It creates only fresh in-memory databases. `ledger.db` below is deliberate JS white-box access to **that newly created in-memory instance** for fault injection, not an open of private/application state. No production source change is required.

```sh
node --import tsx --input-type=module <<'EOF'
import assert from 'node:assert/strict';
import { ScanLedger } from './src/ledger/ledger.ts';
import { consumeOne } from './src/worker/outbox-consumer.ts';
import { NGINX_ARCHIVE_TARGET as nginx } from './src/oci/bounded-image-archive.ts';
const alpine = { subject: 'review', idempotencyKey: 'probe',
  registry: 'registry-1.docker.io', repository: 'library/alpine',
  digest: 'sha256:' + 'a'.repeat(64), platform: 'linux/amd64' };
const envelope = at => ({
  receipt: { ...nginx, layerDigests: ['sha256:' + 'a'.repeat(64)],
    diffIds: ['sha256:' + 'b'.repeat(64)], archiveSha256: 'sha256:' + 'c'.repeat(64),
    profileVersion: 'nginx-alpine-amd64-v1', resourcePolicyVersion: 'nginx-archive-resources-v1',
    checksVersion: 'trivy-0.69.3-archive-v1' },
  scannerVersion: '0.69.3', checkedAt: at,
  metrics: { wireBytes: 100, requests: 5, compressedBytes: 50, expandedBytes: 2048,
    entries: 1, archiveBytes: 4096, reservationPeak: 4096, scratchPeak: 4096 }
});
// R1: retry revokes the lease without changing the attempt.
{
  const now = Date.now(), l = new ScanLedger(':memory:', () => now);
  try {
    const id = l.enqueue({ ...alpine, checks: '["vuln"]' }).scanId, j = l.claim(now);
    l.retry(id, j.attempts, now + 1000);
    assert.equal(l.checkpointActive(j), false);
    assert.equal(l.finishWithVuln(id, j.attempts,
      `${j.registry}/${j.repository}@${j.digest}`, [], '0.69.3'), true); // BUG
    assert.equal(l.state(id, 'review'), 'completed');
  } finally { l.close(); }
}
// R2: raw nested data bypasses the derived-object validation.
{
  const now = Date.now(), l = new ScanLedger(':memory:', () => now);
  try {
    const id = l.enqueue({ ...alpine, ...nginx, checks: '["secret"]' }).scanId;
    const j = l.claim(now), secret = { outcome: 'checked', findings: [],
      scannerVersion: { Match: 'SYNTHETIC_RAW_CANARY' } };
    assert.equal(l.checkpointArchive(j, 'secret', { ...envelope(now), secret }), true); // BUG
    assert.ok(l.db.prepare('SELECT body FROM scan_checkpoints').get().body.includes('SYNTHETIC_RAW_CANARY'));
    l.cancel(id, 'review');
    assert.deepEqual(l.archiveResult(id, 'review').secret, secret);
  } finally { l.close(); }
}
// R3: the API never receives the incorrect token.
{
  const l = new ScanLedger(':memory:');
  try {
    const id = l.enqueue({ ...alpine, checks: '["secret"]' }).scanId;
    const wrong = { ...l.claim(), leaseToken: 'wrong-token' };
    assert.equal(l.checkpointActive(wrong), false);
    assert.equal(l.finishCombined(wrong.scanId, wrong.attempts,
      [{ check: 'secret', outcome: 'checked', findings: [], scannerVersion: '0.69.3' }]), true);
  } finally { l.close(); }
}
// R4: a real SQLite checkpoint error is converted into terminal scanner failure.
{
  const l = new ScanLedger(':memory:');
  try {
    const id = l.enqueue({ ...alpine, ...nginx, checks: '["secret","sbom"]' }).scanId;
    l.db.exec("CREATE TRIGGER reject_second BEFORE INSERT ON scan_checkpoints WHEN NEW.check_name='sbom' BEGIN SELECT RAISE(ABORT,'synthetic checkpoint storage error'); END");
    let code;
    await consumeOne(l, { timeoutMs: 1000, dbDir: '/unused', archivePolicy: 'proof' },
      undefined, Date.now(), undefined, undefined, async (_checks, options) => {
        const base = envelope(Date.now());
        assert.equal(options.onCheckpoint('secret', { ...base,
          secret: { outcome: 'checked', findings: [] } }), true);
        try { options.onCheckpoint('sbom', { ...base,
          sbom: { outcome: 'failed', reason: 'SCAN_FAILED' } }); }
        catch (error) { code = error.code; throw error; }
        throw Error('trigger did not fire');
      });
    assert.equal(code, 'SQLITE_CONSTRAINT_TRIGGER');
    assert.equal(l.state(id, 'review'), 'failed'); // BUG: storage error swallowed
    assert.equal(l.result(id, 'review').outcome, 'failed');
    assert.equal(l.cancel(id, 'review'), 'conflict');
  } finally { l.close(); }
}
console.log('Reproduced R1–R4 observations');
EOF
```

## Reviewed source fingerprints

SHA-256 captured after probes, relative to `server/api/`:

```text
41aec06f66e7d391464ba6ebbd51f4b21291997267a9cf8203d4fb673d99507f  src/ledger/ledger.ts
770e54300eb76776ca34320c886859ad8ff05743f142fa14c7ddfce356f54a3b  src/ledger/ledger.checkpoint.test.ts
116c06aa49b011303cfb1a4d3dc24398aaa1c15f5669a3c735a56723b1e4d04c  src/ledger/schema.ts
e8f2553dd134193a47da71dfc72c20516606e048178946c4759dd213a205a5b3  src/worker/outbox-consumer.ts
d33bb619c963aa9adab68f5734f9ca1a5ad7717bec0ce5b28065fa302959ef17  src/worker/archive-scan-worker.ts
3901bc691a6aa2973705559d85b191e0981efa5b41d85eeece8d9b87c28c48b6  src/worker/image-config-runner.ts
2938068d62a13f7d16aab7bbea912faceb4ceffa21ec3e099b6c5b05e6ec6e16  src/worker/archive-result-contract.ts
```

---

## Independent re-review after R1–R4 fixes — 2026-10-17

### Current verdict: APPROVE the reviewed ledger/worker R1–R4 revision

**R1, R2, R3 and R4 are resolved in the reviewed source snapshot.** No remaining actionable defect was established in this bounded re-review. This verdict supersedes the original request-changes disposition **for these revised ledger/worker paths only**; the original findings and verdict above remain intact as history.

Approval is not full TASK2/6 acceptance, HTTP/spec/UI approval, operational migration/rollback approval, or live scanner/DB qualification. The accepted product contract is unchanged: durable completed checks may survive in a `cancelled` scan; missing checks remain absent/unknown. No new acceptance gates or tracker actions are proposed.

Implementation/tests were not edited. Only this append was made to this report. No tracker, commits/staging/branches, Docker, live/old environment, existing application DB, keys or private state were accessed. Independent probes used fresh `:memory:` instances, plus one newly created and deleted synthetic migration DB in an OS temporary directory. Existing selected tests used their disposable fixtures.

**Historical preservation fingerprint:** before this append, the report was 18,405 bytes, SHA-256 `d776b1002c47ce6d76417c466df461976ba24cdfafee35edf176f0ba329cff36`. The first 18,405 bytes must retain that hash.

### Fix verification and exact locations

Paths in this section are relative to `server/api/src/`.

| Finding | Reviewed fix | Independent result |
| --- | --- | --- |
| R1 | `ledger/ledger.ts:1065–1072`: `finishWithVuln` now calls the shared live authority check inside its transaction before acknowledgement/publication. | Exact-expiry and retry-revoked original claims both return false, including with the original token explicitly supplied; no SQL table changes. Valid live legacy vulnerability finalization still succeeds. |
| R2 | `worker/archive-result-contract.ts:18–26, 43–53` validates canonical check subsets and exact original secret/SBOM envelopes. `ledger/ledger.ts:158–159` derives combined outcomes using explicit fields rather than shadowable payload spreads. | Original raw-version and discriminator-override payloads are rejected at checkpoint, full finalization, stored read and cancellation revalidation. No malformed write was accepted. |
| R3 | `ledger/ledger.ts:529–537` matches the **caller-supplied** token in SQL, checks running/current/undelivered authority and `lease_until > clock`. Guards are used at 749, 781, 818, 867, 957, 1071 and 1279. `attemptActive` is token-aware at 717–718. | All seven write APIs pass the 13-mode independent matrix below. Wrong/missing/empty/foreign/old tokens actually reach the tested method as its last argument. Refused writes leave all SQL tables unchanged. |
| R4 | `worker/outbox-consumer.ts:90–120` retains and rethrows the original checkpoint exception even when abort wins or cleanup masks it; post-commit runner failures propagate. Final persistence at 130–136 is outside the scanner fallback. | Original SQLite error propagates; scan stays running with its committed secret checkpoint, no fabricated result/event. Subsequent cancellation succeeds and preserves secret while SBOM stays absent. Finalization storage errors and cleanup/abort variants also pass. |

Consumer call sites inspected at `worker/outbox-consumer.ts:48, 54, 86, 118–119, 132, 136, 177, 185` pass `job.leaseToken` from the original claim, with explicit unused config/errorCode placeholders. They do not recover a fresh token from context for finalization. The shared guard's SELECT and following write are within the existing `BEGIN IMMEDIATE` transaction; the write does not rely on an unfenced external preflight.

### Independent reproducer / fencing matrix

The prior reproducer was repeated with fixed-behavior assertions and the new real API signatures. Running the historical reproducer unchanged would be misleading: its missing-token calls are no longer valid positive controls, and its assertions intentionally expected the old bugs. The new probes below supplied the original or deliberately invalid token explicitly, preserving the original payloads and failure injection.

Seven methods tested: `finish`, `finishWithResult`, `finishWithSbom`, `finishWithVuln`, `finishCombined`, `finishArchive`, `retry`.

Each matrix cell used a **fresh in-memory ledger**, a coherent injected clock, a live claim and a previously committed valid checkpoint. The refusal comparison snapshots **every SQL table**, including outbox, events and checkpoints, after arranging the authority condition and before invoking the tested method.

| Authority condition / actual supplied argument | Expected and observed, for all seven methods |
| --- | --- |
| Valid current original token, live lease | true |
| Wrong token string | false |
| Explicit `undefined` token | false |
| Omitted token argument (runtime JS compatibility probe) | false |
| Empty token string | false |
| Exact lease expiry equality, original token | false |
| After successful retry revocation, original token/attempt | false |
| Stored token NULL, original non-null caller token | false |
| After replacement, original attempt/token | false |
| Replacement attempt paired with **old** token | false |
| Original attempt paired with replacement **new** token | false |
| Current token belonging to a different scan | false |
| After cancellation, original attempt/token | false |

**Observed: 91/91 matrix cases matched; all 84 refusals left every SQL table unchanged.** This includes the original 24-case expiry/retry/replacement/cancel matrix and extends it to retry itself and mixed token/attempt cases. Positive controls prevent an implementation that simply rejects every finalizer from passing.

Actual final argument shapes used (the token was appended to these base arguments, except the deliberate omitted-token case):

```js
finish:           [scanId, attempts, 'failed', undefined, token]
finishWithResult: [scanId, attempts, [], '0.69.3', token]
finishWithSbom:   [scanId, attempts, validSbom, '0.69.3', token]
finishWithVuln:   [scanId, attempts, pinnedImage, [], '0.69.3', token]
finishCombined:   [scanId, attempts, [validSecretOutcome], undefined, token]
finishArchive:    [scanId, attempts, validArchiveReport, undefined, token]
retry:            [scanId, attempts, nextRunAt, token]
```

**R2 independent corpus: 16/16 cases passed.** Four original malicious/malformed payloads × four boundaries:

- checked secret with nested `scannerVersion: { Match: 'SYNTHETIC_RAW_CANARY', Code: 'SYNTHETIC_CODE_CANARY' }`;
- checked SBOM with nested `scannerVersion: 'SYNTHETIC_RAW_CANARY'`;
- checked secret with `check: 'sbom'` and SBOM data instead of findings;
- checked SBOM with `check: 'secret'` and findings instead of SBOM data.

Boundaries: checkpoint write; full archive finalization with correct live token; direct stored archive read; cancellation revalidation of an originally valid checkpoint whose body was replaced **and whose integrity hash was recomputed correctly** for the replacement body. The last boundary is deliberate white-box corruption in the disposable DB: it proves canonical validation still rejects the malformed envelope instead of passing solely because its hash matches. It does not treat SHA-256 as authentication against a hostile DB administrator. Checkpoint/finalization rejection left both archive and checkpoint tables empty; stored reads rejected for the owner while another owner got undefined; cancellation rejection left the scan running and no archive result published.

**R4 independent worker/storage probes: 7/7 cases passed.** Real `consumeOne` and real SQLite, with injected archive execution and SQLite triggers limited to the new disposable DB:

| Scenario | Observed |
| --- | --- |
| Original checkpoint trigger error rethrown by adapter | Same SQLite error object reaches caller. |
| Checkpoint error after an asynchronous turn | Same SQLite error object reaches caller. |
| Adapter swallows callback exception and never resolves | Consumer rejects with the original error without waiting for the adapter. |
| Adapter replaces checkpoint error with cleanup error | Original SQLite error object, not cleanup error, reaches caller. |
| Cleanup/runner error after a committed checkpoint | Same cleanup error reaches caller, without terminal scanner fallback. |
| Final archive INSERT trigger failure | SQLite finalization error reaches caller; checkpoint remains cancellable. |
| Actual owner cancellation after secret, before SBOM callback | Normal cancellation resolves, not a synthetic storage error. |

For each of the six error cases, state remained `running`, public ordinary/archive results remained undefined, and events remained `queued/running` before cancellation. After dropping the synthetic trigger, cancellation produced exactly `queued/running/cancelled`, preserved **one positive secret finding**, and left SBOM absent. In the normal owner-cancel control, a repeat cancel returned `already_cancelled` and the same snapshot remained. Error-triggered callbacks also observed an aborted signal.

**Additional disposable running-v14 migration control passed:** create a synthetic running scan with a current claim; close it; construct v14 by removing v15 checkpoint objects/column; reopen with the real migrator. Observed version 15 and NULL token, with old-token finalization/retry refused and no result invented. Advance the injected clock to expiry and reclaim: a new attempt/token is issued, the old token still fails with the new attempt, and correct-token vulnerability finalization succeeds. `foreign_key_check` is empty. The temporary directory was removed in `finally`; no existing volume was opened.

### Targeted existing tests rerun independently

All commands ran from `server/api` using installed dependencies. No full suite, dependency installation, HTTP/live qualification or typecheck was repeated.

```sh
node --import tsx --test src/ledger/ledger.review-regressions.test.ts
# 82 passed, 0 failed/cancelled/skipped; exit 0; ~0.46 s; deadline 25 s.

node --import tsx --test --test-name-pattern='checkpoint commits before cancel|cancel snapshot, config, siblings|CVE receipt is validated|CVE expiry at the checkpoint|checkpoint cancellation budget|v14 to v15|failed v15|retention removes|committed WAL checkpoint|archive consumer checkpoints audited positive Secrets' src/ledger/ledger.checkpoint.test.ts src/ledger/ledger.archive.test.ts src/worker/archive-scan-worker.test.ts
# 15 passed, 0 failed/cancelled/skipped; exit 0; ~2.69 s; deadline 30 s.

node --import tsx --test src/worker/outbox-config.test.ts src/worker/outbox-combined.test.ts
# 20 passed, 0 failed/cancelled/skipped; exit 0; ~0.83 s; deadline 20 s.
```

**117 targeted existing tests passed in this re-review.** This is separate from the independent probe counts (91 matrix cases, 16 malformed-envelope cases, seven worker/error scenarios and one migration scenario), not a claim of 117 new tests written. Independent stdin probes used `node --import tsx --input-type=module` under 20–25-second invocation deadlines and exited 0. Source review and these probes—not the author's green-test claim alone—support the verdict.

### Scope qualifications and integration notes

- Selected existing tests reconfirm atomic rollback, owner isolation/missing coverage, frozen historical ordinary/archive CVE evidence, checkpoint-fence DB expiry, bounded optional-advisory merge, worker cancellation/late output, WAL crash recovery, migration rollback/reopen and retention. No remaining R1–R4 defect was reproduced.
- No simultaneous lock-contention stress, disk-full qualification, hostile-DB authentication, real scanners/DB releases or operational rollback was tested. The error triggers are synthetic fault injection, not evidence of real production trigger configuration.
- The handoff explicitly reports two external `oci/nginx-local-policy.test.ts` fixture failures and two qualification-script calls needing token arguments. Those external tests/scripts were **not executed or modified in this re-review**; their current runtime behavior is not independently certified here. They remain coordinator integration work as described in the handoff, not concealed successes or additional gates invented by this review.
- The new token argument is intentionally incompatible with callers that omit it: those callers now return false (or can fail validation first for invalid payloads). Approving this bounded implementation does not certify every external caller or deployment is migrated.

### Re-reviewed source fingerprints

SHA-256 after the independent probes, relative to `server/api/`; ledger/consumer/validator hashes match their values captured before testing:

```text
e5d30ab9a40964908e53a7c8fa375993198714ad1f7393146ad9887fb68bf858  src/ledger/ledger.ts
c9f7c7810a70dd2eb861168a417236f65f4060d3634fb347036e9577b368163c  src/ledger/ledger.review-regressions.test.ts
43121fa1258b7c58d590d60bfca9e69ecbfe3628813c276d5de9d7fbb3ba5dd0  src/ledger/ledger.checkpoint.test.ts
561739bb5e752027080ef03bfcb881c37601ea702f37934034e99b4f9da56786  src/worker/outbox-consumer.ts
50b52e2cbdb6f1b14298dc8e6b8c62832ca65403e990da07e12cb587bcba3886  src/worker/archive-result-contract.ts
d33bb619c963aa9adab68f5734f9ca1a5ad7717bec0ce5b28065fa302959ef17  src/worker/archive-scan-worker.ts
3901bc691a6aa2973705559d85b191e0981efa5b41d85eeece8d9b87c28c48b6  src/worker/image-config-runner.ts
49fca4788b40d5ed98358244a41f52046b60cd8f3cc20f8035da042355b018c5  ../../docs/partial-cancel-implementation-20261016.md
```
