# Generic preserving Docker adapter — qualification handoff

Owned source: `scripts/deploy-adapter.mjs`, `scripts/deploy-adapter-stores.mjs`. CLI/core and historical operational/recovery modules were not edited. This is source implementation, **not deployment authorization or live qualification**. No real Docker, status, private configuration/credential reads, provider requests, Git operations or lifecycle commands were run in this lane.

## Implemented contract

`createAdapter(options)` implements the current `deploy-core.mjs` contract. Construction/import is inert. There is no live `migrate()` method, hidden legacy lifecycle call, incident ID exception or automatic foreign-lock adoption.

| Stage | Actual implementation |
|---|---|
| `acquireLock` | Core calls once. Existing shared lock/reconciliation guards apply. Own private lease + append-only audit are created; every later stage verifies the same opaque lease. |
| `preflight` | Protected v6 config/pins, exact current container/image/command/mount/network/volume ownership, local daemon identity, source closure, historical retention and image budgets. No build or service mutation. App reads only auth schema classification via a fixed readonly probe; exact schema/rows are qualified later on copies. |
| `build` | Compilation/COPY qualification and explicit image builds while original site remains healthy, same controls/epochs. Collision-checked immutable old/candidate references. No extra acquire/finalize. |
| `validateCandidate` | Persist and render old/new effective Compose recipes with synthetic JWT interpolation; validate both against independent normative models and immutable image metadata. |
| `waitForIdle` | Bounded readonly worker jobs/leases/outbox polling; honors drain timeout and cancellation. |
| `prepareRecovery` | Durable old/new recipes, old IDs/images/epochs, explicit upgraded and interrupted scopes, daemon and migration intent. JWT is privately byte-fenced for subsequent API startup, never serialized/hashed. |
| `fenceAdmissions` | Journal before dispatch; clean stop web, clean stop API, recheck/drain raced-in jobs, clean stop worker. Any uncertainty retains HOLD. |
| `snapshot` | **Every app**, network-none readonly keyless helper using old immutable API image. All four stores exported into new append-only `snapshots/fenced`; original live stores are never restored/reset. |
| `qualifyState` | Copy-only auth independent expected DDL + real constructor twice; real ledger/history/quota constructors twice on disposable copies, all three fingerprints unchanged. Quota policy maxRows/dbBytes applies. No live migration. |
| `switchServices` | Explicit upgraded targets only, no dependency expansion/build/pull. Resume other interrupted services unchanged. Gateways → worker → `before-api` four-store equality → API startup (the only actual auth migration point) → readiness → `after-api` exact/qualified four-store equality → **web LAST**. |
| `health` | Exact namespace/epochs plus actual API health; bounded GET `/`=200, `/api/v1/auth/me`=401 and unauthenticated LLM-readiness route=401. No generation or scan. |
| `publishReceipt` | Durable actual immutable `compose.images.json`; app also publishes standard `compose.llm-env.json` and `llm-profile.json`. Each private pending file is renamed/fsynced under the same lease. Actual small receipt follows publication. Any partial publication HOLDS. |
| `releaseLock` | Only proven published / healthy restored web / pre-mutation abort. Receipt includes retained refs and evidence index. Atomically archives its own lock, never deletes historical audit/evidence. Uncertain builds, fencing, switches and publication cannot release. |
| `restoreOld` | Web-only, before publication, known settled state only. Recreates OLD immutable web with the recorded old effective recipe and `--no-deps --no-build --pull never`; a new container ID is allowed. Backend/writers/DB untouched. No automatic app or DB rollback. |

### Scope

- `web`: upgrades/interruption exactly `web`; source-only bounded compatibility probe against running API's auth store/controller. Missing A3 capability or mismatched source refuses before build. No DB snapshot, API/worker/gateway stop, JWT-file read, or runtime-env publication.
- `app`: explicit upgrades must include `api`; `web`, `api`, `worker` are declared interrupted even if web/worker are not upgraded. Unselected services must have unchanged normative configuration. Descriptor changes currently require all six runtime targets. Topology additions/removals are not supported.
- App auth classification A2 requires core `--migrate` consent. Captured A2→A3 is qualified exactly; existing A3 follows the no-migration path. No arbitrary auth-table exemptions. New per-user auth state follows the real expected DDL; it is not falsely described as empty when users exist.
- `status`: safe metadata projection only; it does not authorize clearing a lock.
- There is **no cross-process generic `recover` CLI/receipt adoption**. In-process known-safe web restoration is implemented. Interrupted/uncertain attempts require a separately reviewed reconciliation, not guessing success from a terminal-looking file.

## Preservation and finite bounds

Four stores: auth, scan ledger, LLM history, quota. All compare full logical fingerprints; unknown/held paid liabilities are not omitted or refunded. Auth is the only allowed inequality, from an in-process branded qualification of the captured snapshot. Snapshot evidence is sealed: SQLite opens disposable copies, so WAL-header backups cannot create sidecars next to retained evidence.

The reused export protocol retains both per-chunk guards. A guard batches exact peers + helper in **one inspect**, preserving IDs/cardinality, every container validator, command and epoch checks. Full namespace/consumer/daemon/volume checks surround helper lifecycle and transfer. Helpers retain existing finite 300-second keeper and are never restarted on expiry. Partial export evidence stays on failure. Only an owned helper with proven clean exit is removed; no image/container pruning or audit cleanup.

Finite budgets: status 120s; most stages 300s; build/snapshot/switch at most 1800s each; **one apply lease at most 3600s overall**. Core readonly drain remains 1–300s. Same-epoch readiness at most 120s; only explicit `CHAIN_NOT_READY` polls. Configuration/trust/cache/resource-contract errors, unknown receipts and exec failures are fatal. Subprocesses have bounded output/time; late successful responses do not evade deadlines.

Capacity: the legacy catalog retains its independent active32/archive16/total48 bounds. The current adapter has a separate 48-directory history budget: reads include all existing directories (including the current owned attempt), while admission reserves one slot before creating a lock or attempt and repeats the check under the owned lock. Legacy records do not consume adapter slots, but every historical receipt, evidence set and original reference obligation is still validated; nothing is dropped by age, outcome or archive location. This provides finite headroom, not unlimited retention. All project-labelled image refs plus proposed old/new refs stay within128; minimum host free disk4GiB; sum of resulting running-service memory limits must fit daemon memory. No Docker Desktop setting changes. Historical active/archive authority is not rewritten. Own attempts have bounded evidence depth/count/bytes and retain incomplete attempts as HOLD. Historical enumeration, each 64KiB evidence-hash read and the final pre-lock boundary check the existing operation/lease deadlines; no timeout is extended.

Stateless gateway exit137 is **not** globally clean. It requires exact before/after control+epoch, successful stop output, readonly/no-volume/no-credential gateway, clean quiescent writers, non-OOM/restart0, and exact same-daemon TERM→timeout→KILL→die evidence. Event `--until` uses already-past daemon time with fractional seconds, not a host-clock future bound. API/worker forced stop always refuses.

## Configuration and old readers

Standard protected publication files keep their existing formats; standard v6 config/namespace validators remain in use. Recipes use `${SCAN_JWT_SECRET:?required}` rather than a credential value. OpenAI remains private volume→bootstrap→API process ENV, never image/worker/gateway/browser Docker environment. The adapter never reads the OpenAI key file or hashes a credential.

New images use receipt-backed `dip-deploy-<role>:old-<nonce>` / `candidate-<nonce>` refs; all existing retained tags remain unchanged. Canonical `:local` aliases that are outside every retained obligation are not current adapter authority. Removing one is a separate audited cleanup, not deployment: require fresh exact tag/image binding, zero container ancestors, surviving authenticated retained tags for that image, nonforce exact-tag `image rm --no-prune`, and unchanged peers/other references; never delete retained image bytes or assume an old alias is disposable. New refs count in this adapter's global project-label128 budget. Old readers can consume the published standard immutable pins/config; **frozen historical recovery does not gain authority over new adapter receipts**, and old mutating routes are not the new mechanism's recovery path. Do not mix deployment operators or assume old catalog-only retention tooling accounts for new adapter receipts.

Own evidence: `.local-public-images/deploy-adapter-v1/<random32>/` (receipt version2). Contains recipes with placeholder JWT, nonsecret submissions/results, source identities, qualified snapshots, preservation/publication receipts and its archived own lock. It contains no full Docker inspect or raw process output. `deployAdapterDiagnostic(error)` exposes finite codes and owned Docker cause/exit/signal/byte counts only.

## Test interface — Sol / reviewer

Library-only seams: `createDeployAdapter({root,home,run,now,sleep,http,Database,checkSource})`; CLI does not expose command/validator injection. `run(args,options)` models Docker transport only: **production guards are not disabled**. `http` models only fixed local GETs. `checkSource` can replace compilation for synthetic orchestration tests; real CLI always uses real source/COPY qualification. `createAdapter` exposes all core stage methods using the same seams. `createAdapterSnapshots` / `qualifyAdapterStoreCopies` are in the small store helper; no fixture-authority backdoor exists.

Suggested bounded qualification matrix (12 grouped cases, not a full suite):

1. Existing foreign/HOLD lock: no dispatch, no adoption/unlock; single owned lease across build and apply.
2. Build failure while OLD serving; no fence, no invented receipt; uncertain build retains evidence.
3. Web A3 source mismatch refuses; compatible web upgrades only web.
4. Web health failure restores immutable OLD via recorded recipe, changed ID accepted; uncertain dispatch refuses restoration.
5. Non-migrating app always snapshots; full real-validator fake route proves fenced→before-api→after-api and web LAST.
6. A2 consent + exact expected copy migration/idempotence; actual migration only inside API switch. No consent, partial schema or arbitrary auth drift refuses.
7. Real copied quota capacity/history/ledger constructors refuse incompatibility; changed held/unknown liability fails exact comparison.
8. WAL-header snapshots and byte/sidecar tampering; retained evidence never receives SQLite writes.
9. Same-daemon gateway137 proof positive; missing event/OOM/mount/credential/writer137 negatives. No global override.
10. Helper timeout/epoch/cardinality/foreign consumer and both export chunk guards; partials retained, no restart.
11. Publication failure at each rename/receipt/lock-archive boundary retains HOLD, never invokes DB/app rollback.
12. Source/config/JWT/daemon/volume drift, capacity128 overflow, replay and safe-diagnostic synthetic secret assertions.

Performed by this author: syntax/import checks; 11 small synthetic pure/filesystem checks (inert factory, scopes, full-store comparisons, forged migration rejection, single lease, HOLD, archived evidence reread), probe syntax and gateway-classifier positive/negative smoke. **No full app/web fake-engine qualification or real Docker was run here.** Independent focused tests/review are still required before live GO.

## Operator boundary

Existing historical HOLD remains the immediate operational blocker; this implementation does not clear it. These are command forms for AFTER its separately qualified reconciliation and source qualification, not commands executed here:

```sh
node scripts/deploy.mjs web --plan
node scripts/deploy.mjs app --services web,api,worker,egress,llm-egress,openai-egress --plan
# After exact plan, qualification and explicit lifecycle GO; add --migrate only for classified A2:
node scripts/deploy.mjs app --services web,api,worker,egress,llm-egress,openai-egress --apply --migrate --drain-timeout-ms 300000
```

No deployed/READY/AI-success claim follows from source implementation or smoke checks.
