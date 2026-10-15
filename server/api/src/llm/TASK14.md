# TASK14 — integrated durable history and prepared context

Author handoff for run `6ad60d60-18c5-4a6c-860f-9d8bece7232d`, TASK14 only.
Controlling decision: `76775430-b6dd-47ce-8e1d-68d27beff1a7`.
Companion `DIP-DOC-14`, task-sourced delta `13edf9b2-8929-467b-bd57-944851c9617f`: **proposed, UNAPPLIED**.
This is implementation/operations evidence, not independent acceptance or deployment evidence.
The original TASK14 slice did not implement TASK16 UI/Markdown/framing. Parent-authorized TASK16 source rework now adds opt-in completed-reply NDJSON delivery below, independently of TASK14 R3 acceptance and without applying its proposed spec delta.

## Actual composition

The existing default and LOCAL API compositions already provide `AuthStore`, `ReportReader`,
`LlmRuntime`, `LlmQuotaRuntime` and `LlmService`. `LlmService.history()` lazily composes
`HistoryService` and shares the existing **one active request per owner / eight globally**
capacity pool with summary generation. No new module graph or second capacity pool is installed.
The history ingress uses `registerHistoryIngress(app)` before Nest initializes its parsers/listener.
`main.ts` composition now belongs exclusively to the parent: it is not edited or included in
this rework's 24-file owned manifest. The initial coordination hash is recorded in the tracker;
parent changes after that observation are not pinned by this author. Preserve JWT startup/bind
defaults and existing auth 512-byte / summary 1024-byte gates.

New generation uses the actual `OpenRouterProvider.generateGuarded()` adapter, not a content-only
fake provider. It admits only the existing exact free profile:

- `apodex/apodex-1.1-mini:free`, provider only `novita/bf16`;
- no-storage, deny data collection, ZDR, prompt/completion/request price caps zero;
- `stream:false`, fixed tool-free two-message wire, no retry/fallback;
- full immutable UTF-8 wire bytes +1024 input reserve, current output ceiling <=2048;
- server-bound validated reported cost exactly zero, not invoice verification.

The new transport guard runs after verified TLS `secureConnect`, surrounding authenticated
HTTPS request creation and body initiation. It holds a synchronous auth transaction, freshly
reads the current owner-authorized terminal report/policy, holds the pending-history CAS
transaction, dispatches the existing quota reservation, and initiates the body. Neither auth
nor history transactions are held across CONNECT/TLS waits or provider response awaits.
New guards bound auth/history/report/quota lock contention to <=100ms per database operation;
this is not a total wall-clock bound for filesystem/CPU work. The quota helper restores the
ordinary connection timeout and changes neither quota schema nor the accepted policy.

Receipt accounting is bound to the original dispatch and happens before reply/citation
validation or durable completion/publication. Later revocation cannot erase a valid receipt.
After body initiation, cancellation/invalid or missing receipt is never a timer refund.
Only a still-reserved attempt can be released by the existing quota CAS.

## API contract for parent's later exact nginx ingress

Base: `/api/v1/browser/scans/<lowercase UUID>/llm`.
Use browser cookie authentication and the existing opt-in/allowlist gates; private JWT API
routes are not exposed or changed. New mutations require the configured same Origin.
No owner/session/access-generation fields are accepted from the client.

| Method | Suffix | Result |
| --- | --- | --- |
| GET | `/history` | Current report binding, durable epoch/revision, all retained turns/decisions and public pending status |
| GET | `/chat/context` | Current report binding, history epoch/revision, separate chat policy/disclosure, question/body limits, `deliveryMode:completed-response` |
| GET | `/chat/usage` | Same existing owner+scan quota counters; admission `unavailable` because no exact question/wire was supplied; no provider or reservation |
| POST | `/history/decision` | CAS mutation recording a cleaned user decision and original current-report sources; no provider |
| POST | `/chat` | One explicit consent-bound request; default completed JSON unchanged; exact `Accept: application/x-ndjson` opts into bounded validated-completed-reply frames, after persisted receipt validation and durable completion |

Decision body has exactly `{epoch,revision,mutationId,reportVersion,text,findingIds}`.
Chat body has exactly `{epoch,revision,mutationId,reportVersion,question,consent}`,
where consent is exactly `{accepted:true,policyVersion}` from **chat/context**, not summary/context.
Epoch/mutationId are lowercase UUIDs; revision is a nonnegative safe integer.
Question/decision text has a 2048 UTF-8 byte ceiling and conservative control/URL/credential
refusals. Reply text is bounded independently and citations are copied from server-owned
safe projections, never model-supplied facts or URLs.

Default responses remain JSON and `Cache-Control:no-store`. Chat alone supports the exact opt-in NDJSON representation described below; ingress/pre-admission and failures without proven admitted identity/current failed head still use the existing safe JSON exception filter. POST route aliases, query strings,
compressed/chunked bodies and non-UTF8/JSON mutations are refused before default parsing.
Both mutation routes have an **8192 actual-byte body limit**, exact declared/actual length,
and a 2-second body-ingress deadline. Rejection closes the upload connection after the
bounded safe error. Parent can configure the **exact five method/path pairs above**, an
8KiB nginx mutation-body cap and a 45-second upstream timeout; preserve existing summary
and auth limits. No broad `/llm/*` proxy allowance, nginx edit or deployment was done here.

Generation advances revision once at durable begin and again at terminal completion/failure.
An identical mutation replay returns only durable `{duplicate,id,state,epoch,revision}` status,
not a cached model answer or another provider dispatch. Original input fingerprint, accepted
chat consent-policy hash and immutable prepared-wire hash persist on every turn state. Replay
compares the original canonical tuple (kind/scan/epoch/revision/mutation/report/question/accepted
consent/policy), never a request rebuilt from today's context. Identical authorized original-revision
retries remain status-only; changed currently valid consent or revision conflicts too.
Changed payload/kind or restored epoch
under the same mutation ID conflicts. Stale/current-report mutations, pending conflicts,
mandatory context overflow and permanent history capacity refuse locally. A committed answer
may survive a disconnected/stale recipient; authorized clients reread history and do not resend.

## TASK16 opt-in completed-reply delivery — source implemented, independent review pending

No new endpoint, body field, API flag or provider streaming. `Accept` absent, `*/*` or exact
`application/json` preserves legacy JSON. Exact `application/x-ndjson` selects v1 framing;
other header forms refuse406 before generation/admission. Request fingerprints, consent,
CAS and context JSON remain unchanged. Summary controller and its existing1024-byte/35s
parent ingress requirement are untouched; nginx/main/runtime activation is not part of this rework.

`HistoryService.generate()` produces a completed delivery outcome only from the existing
attempt-bound durable quota observation plus validated committed reply. Parent-authorized
R4 (C16-SEC-R3-01, review253) returns a frozen failed outcome for opt-in NDJSON when
this invocation's successful durable observe and exact live pending identity can be bound
to a durable failed head. Parent-authorized R5 (review269 C16-SEC-R4-01) also permits the
same proven admitted/failed identity with NO valid observation: its frozen outcome has only
receipt:'unavailable', not a usage object. Earlier settled receipts and invalid/fault receipt
vectors never establish current accepted usage; quota/provider/store/schema are unchanged. The failure shape contains only report/head/mutation/turn bindings
and either the frozen current valid receipt or unavailable marker: no invalid reply, source, diagnostic or exception properties.
The existing pending guard checks reservation/request hash/session generation/incarnation/
policy, terminalizes the exact turn and verifies failed revision=pending revision+1; inability
to establish this provenance retains the safe exception path. JSON callers keep original502
behavior (generate defaults to JSON; the controller passes its negotiated representation).
Its existing
trusted-session/report/policy/head `write(action)` closure remains the publication guard,
not a returned authorization boolean. Capacity release is transferred to the controller,
idempotent, and retained through framed socket finish/abort/absolute delivery deadline.
Quota reservation cleanup remains unchanged; accepted receipt/committed history is never
retracted by delivery failure. Default JSON has exactly its prior response body/headers.

Framing precomputes and bounds all serialized lines before headers:8192 UTF8 bytes/line
including LF,196608 aggregate bytes,52 frames including reserved terminal-error capacity,
1024 UTF8 bytes per codepoint-safe delta. Existing16384-byte reply/32sources/2048-byte source
ceilings remain. Every writeHead/frame/end uses the fresh guarded closure, rechecked after
drain; no auth/history transaction survives a network await. Absolute delivery5000ms is
inside existing provider<=30000ms/client40000ms budgets; short synchronous DB/CPU scheduling
may add wall-clock overhead and is not a hard realtime guarantee.

Common exact frame keys:
`{v:1,deliveryMode:'validated-completed-reply',nativeProviderStream:false,scanId,digest,platform,reportVersion,epoch,revision,mutationId,turnId,type,seq}`.
Sequence starts0; tuple stays fixed to committed head/request identity. Payloads:

- `usage`: `usage:{input,output,costMicros:0,source:'server-validated-provider-reported-not-invoice'}`.
- `citation`: `index,source` (the original server-owned safe finding projection, never a model source object).
- `delta`: `index,text` (a contiguous slice of the already validated saved hypothesis, not a provider token).
- `done`: `outcome:'completed',kind:'hypothesis',textBytes,citationCount,deltaCount`.
- `error`: `errorCode:'LLM_UNAVAILABLE',receipt:'accepted'`, terminal, no done afterward.
- Accepted-receipt admitted failure: usage seq0→error seq1 only, bound to the exact durable failed head; no citation/delta/done or failed content.
- R5 unavailable-receipt admitted failure: ONLY error seq0, receipt:'unavailable', no usage/zero/counter inference/content, same proven failed head and v1 parser.

Normal sequence is usage→citation1..32→delta1..17→done. If usage itself cannot be written,
or authority/socket/deadline is lost, close without inventing a receipt/error or successful
terminal. After delivered usage, a recoverable write fault may emit a bounded guarded error
and finish within the same deadline. Sealed admitted failure uses the same writer, guards,
bounds and shared lease as success, while legacy JSON invalid-reply responses remain502.
Ingress/pre-admission or unsealable identity/current failed-head failures retain safe JSON.
A proven admitted failure without valid current receipt now uses error-only NDJSON; prior
settled attempts never establish this receipt. Legacy/default JSON still returns the same502. No engine/schema redesign
or fabricated receipt from counters/exceptions. No internal fingerprints/session/owner fields are framed.

Identical mutation replay is done-only with `outcome:'duplicate',state:<public turn state>`
and durable turnId/current head; no answer, counts or usage. The chat client rejects duplicate
as a generated answer, never resends, and requires manual authorized history recovery.
Client parser requires strict frame types/nonce/seq/tuple/order/byte counts, fatal UTF8,
whole reconstructed reply validation and terminal LF plus clean EOF. The panel additionally
validates authorized citation membership and exact saved turn/mutation/question/report/reply
and final revision after current-context/history reread. Partial frames never enter Markdown
or citation navigation. Cancellation/session/scan fences remain; no refund claim.

R5 focused synthetic evidence (not actual provider or deployed/main proof): R5-only backend
4PASS (3 NEW unavailable codec/writer tests + NEW synthetic-cookie HTTP test), API typecheck
PASS; actual client error-only seam1PASS/43 intentionally deselected and scoped test ESLint
PASS. Nonadmission zero-attempt JSON refusal, before-receipt admitted failure, prior receipt
nonborrowing, invalid receipt fault accounting/no usage, exact failed CAS, fresh session/
policy/report/revision writes, capacity/deadline cleanup and legacy502 are covered. Old
R3/R4/heavy/Summary/Markdown suites are NOT fresh R5 passes.
Historical R4 focused evidence: R4-only backend
subset4PASS (3 codec/writer tests+updated cookie/service/controller fixture), API typecheck PASS;
unchanged client terminal-error test1PASS/42 intentionally deselected. The HTTP fixture now
matches the CURRENT reservation row/request hash/receipt at each write, verifies script and
malformed-message failure framing, legacy JSON502, failed duplicate/no resend, post-usage
failed-head invalidation and missing current receipt refusing any borrowed usage.
Historical R3 evidence only: backend subset11PASS; frontend subset46PASS/27 intentionally
deselected, both typechecks/scoped frontend ESLint PASS. Those suites were not repeated for R4.
Exact commands, corrected fixture/import failures and raw report hashes are in
`docs/task16-chat-ui.md` and the TASK16 manifest/report. Old TASK14 heavy tests were excluded
by name filter, not rerun. Independent framing/security/correctness and real browser/operator
acceptance remain pending; no task close, spec apply, commit, nginx edit or activation.

## Ownership, trusted sessions, cache and context

History is keyed **owner+scan**, never cookie session. Same-owner independent sessions can
read the same confirmed history. New opaque server snapshots bind expiry, session ID,
generation and browser-access incarnation; they are not exposed as API authority.
Successful login/register rotates only the presented cookie session. Failed auth and an
independent device remain valid (subject to the pre-existing bounded session cap).
Configuration changes are supported by a quiesced restart; midprocess changes fail closed.

All current CRITICAL/UNKNOWN findings (including an assessment's CRITICAL severity), complete
coverage/conflicts/provenance, all cleaned user turns and every accepted decision are mandatory.
All user turns are conservatively treated as decision-bearing, including failed/interrupted
attempts. Original historical finding IDs/source tuples remain historical-unresolved when the
report changed. Only optional findings and recent assistant explanations can be reduced;
omission counts/selected IDs are explicit. If the mandatory wire cannot fit, generation refuses
**before pending/quota/provider dispatch** rather than silently deleting old constraints.

The bounded 60-second/128-entry/4MiB LRU stores prepared context only. Its key includes trusted
session/access incarnation, owner/scan, store incarnation, report binding, history epoch/revision
and content, model/provider/prompt/chat-policy versions, question and selected IDs. Every lookup
checks fresh auth/report/policy/history; the cached hash/schema is compared to an authoritative
newly selected context. The send, durable completion and actual final response write have fresh
fences. A hit neither caches output nor bypasses consent/quota/generation, and is not advertised
as a saved provider call/token/cost.

## Isolated storage and operator activation gates

The API is **default off**. It never initializes a missing file or repairs corruption on GET.
Production history path is fixed **`/auth/llm-history.sqlite`**, independent of auth, scan and quota
stores. Required history flags are:

```text
LLM_HISTORY_ENABLED=true
LLM_HISTORY_REVISION=owner-history-v1
LLM_HISTORY_AUTHORITY=single-api-quiesced-terminal-v1
```

These flags are an operator declaration, not automated topology verification. Before activation,
parent must independently verify **one API process**, immutable terminal reports and quiesced
operator changes to report/policy/auth/backup state. The implementation does not claim a second
writer/report lock protocol or a distributed capacity pool. Existing enabled/healthy finite quota
and exact provider policy are still required. No actual flags were activated in this author turn.

With the API stopped and the auth mount owned by the API UID, use a separately authorized,
network-none operator process with the history flags and installed local dependencies:

```sh
pnpm exec tsx src/llm/history-init.ts --initialize
```

Run from the API source directory in that operator environment. The initializer uses the fixed
mount path and refuses an existing file. Unsupported schema versions fail closed; no online
history migration or automatic reinitialization is supplied. It is never imported by Nest. It was **not run on /auth**
here. Disposable test databases are the only stores initialized by the tests.

For an explicitly authorized quiesced backup restore, preserve history content, then run
`src/llm/history-init.ts --rotate-restored-lineage` in the same operator environment before
reopening the API. This rotates store incarnation/all history epochs and interrupts pending
attempts; it does not erase confirmed history or migrate/reset the quota database. Old open
history handles fail closed. Ordinary restart preserves confirmed history and recovers expired
pending attempts as interrupted on the next store access; a nonexpired pending may remain for
its bounded <=40-second lifetime, then requires another access to recover. No automatic resend.

Physical limits are deliberately **stricter** than the judged main-store maximum: 8MiB main DB,
DELETE journal/FULL durability (not WAL), combined sidecars <=16MiB, 128MiB free-disk headroom,
owner0600 regular single-link/inode-checked files, 128 persistent scopes, 512KiB per head,
256 turns/128 decisions/4096 source refs. Fresh schema3 requires original input/consent/wire
identity for every terminal or pending turn; unsupported schemas1/2 fail closed, without
migration, inferred historical metadata, reset, or automatic reinitialization. Only disposable
fixtures were initialized; production store existence/schema was not inspected in this rework.
Schema3 physically preallocates a 100KiB completion BLOB in the same bounded DB before
quota admission, plus full-envelope/head-byte and citation-reference capacity checks. This padding is removed
atomically only with the pending attempt's terminal transition; it is not a history eviction.
Main DB <=8MiB makes a full rollback journal fit the sidecar limit; this is not a 64MiB-WAL
peak-space claim. Capacity is permanent until a separately authorized lifecycle exists:
**no TTL/reset/delete/eviction of history**, no volatile fallback. Stored heads/hashes and nested
citation projections are validated when opened/read/written; unsafe extras/corruption refuse.

## Focused verification and limitations

From `server/api`:

```sh
pnpm exec tsx --test src/auth/auth.store.test.ts src/auth/auth.http.test.ts src/llm/tests/history-store.test.ts src/llm/tests/history.http.test.ts src/llm/tests/openrouter-transport.test.ts
pnpm exec tsx --test src/llm/tests/llm.http.test.ts src/llm/tests/openrouter-provider.test.ts src/llm/tests/free-policy.test.ts src/llm/tests/quota-receipt.test.ts src/llm/tests/quota.http.test.ts src/llm/tests/quota-ledger.test.ts
pnpm run typecheck
```

History HTTP exercises actual Nest cookie/AuthStore/ReportReader/HistoryStore/existing quota and
**actual provider adapter with synthetic guarded transport**: owner+scan/session isolation,
CAS/dedup/changed replay, mandatory overflow, cache-to-begin policy race, presented rotation
before send, revoked publication after valid receipt, invalid citations, completion storage fault,
atomic quota shortage, UTF8/body/schema/privacy refusals and real client disconnect before/after
body initiation. Independent loopback CONNECT/TLS tests prove guard placement/refusal0send/
allow1send using only a disposable synthetic CA and fake credential, never an external host.
Unit store tests cover shared-connection CAS, reopen/restore, missing/corrupt/hardlink storage,
strict nested schema, expired pending and finite scope capacity/short quota contention.
Existing summary/provider/quota regressions are retained.

Final focused runs: **14/14** new history/auth/TLS checks and **34/34** selected existing
summary/provider/quota regression checks passed (48 total, not the full suite).
Typechecking currently reports four **peer-owned** errors: two in
`server/broker/src/audit.ts:53-54` (`findLastIndex` with the API's configured library target,
plus inferred `any`), and two in `server/api/src/runtime/runtime.integration.test.ts:148,154`
(`toReversed` with that library target). No errors in owned implementation files were reported
on the final author checks. Do not treat this as a
clean project-wide typecheck. No full suite, Docker, LIVE, remote/provider request, private-env
file read, deployed ingress/topology acceptance, commit, spec apply or task close was performed.
That is prior author evidence, not the current rework's verification result. Independent
reviews requested R1/R2/R3 corrections (artifacts170/173/176, deduplicated177).

## R1/R2/R3 rework verification

Shared `historyProjection()` produces the actual GET/decision response and the transaction's
budget projection. Every supported report binding is fixed-width ASCII: UUID36, digest71,
platform `linux/amd64` (11), reportVersion64. The budget-only binding measures the exact same
JSON header overhead; it is never used as authorization or returned report content. Actual
ReportReader bindings are tested for byte equivalence. Admission includes retention, public
pending/status, JSON escaping, original identity and revision growth, not just the stored head.
All durable writes/recovery/restore validate the complete response before commit. C+1 returns
409 `LLM_HISTORY_CAPACITY` and rolls back rather than pruning or raising512KiB.

Begin appends the complete pending turn/private metadata and advances revision before testing
`max(storedBytes, fullProjectionBytes) + 102400 <= 524288`. Same-DB physical padding is still
allocated before quota/send. Accepted reply text expands at most2x under JSON escaping (unsafe
control characters/surrogates are refused);16384x2 +32x2048 copied source bytes + commas,
reply wrapper, state/revision growth and reservation field fit100KiB. Final finish still checks
both representations inside its CAS transaction. No quota policy/schema/capacity or TLS guard
was changed. No history TTL/reset/prune or output cache was added.

Chat/context now captures nullable provider-policy state/version and fences it at the actual
final HTTP write. Omitted fences on ordinary authorized history reads are distinct from a
captured null policy; disabled providers do not make confirmed history unreadable.

Current targeted rework command:

```sh
pnpm exec tsx --test src/llm/tests/history-store.test.ts src/llm/tests/history.http.test.ts src/llm/tests/openrouter-transport.test.ts
pnpm run typecheck
```

The new actual cookie HTTP test first reproduced RED POST503 instead of409. GREEN evidence
covers source-heavy exact512KiB POST/GET, C+1 rollback with unchanged epoch/revision/content/hash
and previous GET200, plus near-limit pending+100KiB admission C/C+1 with unchanged quota and0
body sends on refusal. The actual OpenRouterProvider with synthetic guarded transport completes
16384 raw UTF8 reply bytes/32 current citations and validates/account receipts before persistence;
actual serialized completion/history responses stay bounded. Old explanations alone reduce;
all13 user questions and32 UNKNOWN findings remain mandatory. Reopen/identical original retry
is status-only/send0; changed valid consent/revision/question/kind/report/epoch conflicts without
mutation or resend; restore retains original identity. Both enabled→disabled and disabled→enabled
HTTP context final-write races refuse409; disabled history GET remains200. Store checks cover
worst-case reserve growth, identity fail/cancel/expiry/restore persistence, strict pending/terminal
hash schemas, and unsupported-schema refusal without reset.

Final rework run: **9/9 passed,0 failed,0 skipped**, not the full suite or a repeat of48.
Defensive worst-case growth bound is98698 bytes within the unchanged102400-byte reserve;
actual maximum completion POST44780/GET466115 bytes are within524288. Exact24-file source
hashes are in the updated author handoff artifact, excluding parent-owned main.ts. Current
`pnpm run typecheck` passed; earlier peer errors above are historical evidence, not current
failures. No full48 repeat/full suite, provider/network model call, LIVE, Docker, deployment,
private-env read, commit, spec apply or task close. Independent re-review and parent's default-off
activation/ingress verification remain outstanding; TASK16 is not claimed or accepted.
