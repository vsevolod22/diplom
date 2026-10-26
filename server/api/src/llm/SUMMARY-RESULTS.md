# Process-lifetime public summary retrieval

Source implementation only; no runtime, nginx/client edit, migration, credential access or provider qualification was performed for this change. This is an ephemeral result cache in the existing `LlmService`, not durable summary/history storage and not a second LLM.

## Exact client contract

Public8081 composition only, using existing cookie authentication, browser-access gates and owner-bound terminal reports.

### Successful POST (existing generation)

`POST /api/v1/browser/scans/:scanId/llm/summary`

Unchanged exact body, JSON, at most1024 bytes, same Origin and request-scoped consent:

```ts
{
  reportVersion: string;
  consent: { accepted: true; policyVersion: string }; // current summary /llm/context, not chat or translation consent
}
```

A successful public POST now retains its already validated, enriched JSON result in this service instance, only inside its final synchronous session/owner/report/policy/abort publication guard. Invalid or failed generation does not create or replace a retained result. Dispatched/observed consumption remains charged even when validation/publication fails. A prior safe result for the exact current binding may remain available after a later failed POST.

### Passive GET (read existing only)

`GET /api/v1/browser/scans/:scanId/llm/summary`

No request body or generation consent, model selection, prompt, source text, or policy selector. No provider factory/transport/key/credential-status lookup, quota construction/read/reservation/usage, history construction or generation is invoked. It authorizes the session and current owner report before cache lookup or policy disclosure. Only current, enabled-policy, exact-binding results are readable. GET never falls through to POST/generation.

Success for **both methods**: HTTP200, `Content-Type: application/json`, `Cache-Control: no-store`, `X-LLM-Summary-Retention: process-lifetime`.

The JSON body is the **same existing enriched summary DTO**, without a cache wrapper, `cached`, `available`, `policyVersion`, or invented `generatedAt` field:

```ts
type SummaryResponse = {
  scanId: string;
  digest: string;
  platform: 'linux/amd64';
  reportVersion: string;
  hypotheses: Array<{
    kind: 'hypothesis';
    text: string;
    citations: string[];
  }>;
  scannerFacts: SafeFinding[]; // existing server-only safe projections from report-context.ts
  findingCount: number;      // whole report, not just selected facts
  identifierCounts?: { cve: number; debianTemp: number };
  findingCounts?: {
    byCheck: Record<string, number | null>;
    bySeverity: Record<string, number>;
  };
  coverage: ReportContext['coverage']; // existing complete checked/failed/unknown coverage projections
  contextSelection: {
    totalFindings: number;
    selectedFindings: number;
    omittedFindings: number;
    strategy: 'all-critical-and-unknown-then-severity';
    selectedFindingIds: string[];
  };
};
```

Optional existing counts are omitted in JSON when unavailable; they are not invented or filled with zero. `SafeFinding`/coverage keep their existing bounded report projection contract; no raw advisory prose, credentials, raw scanner output or extra source data is added to the summary DTO. GET returns a detached parse of the exact retained serialized successful result, not a reconstructed or regenerated answer. The cache stores no authorization decision.

### Missing and denial

For an authorized owner with a current report but no matching retained result, including disabled policy, report/policy invalidation, eviction, failed-only generation, or a new API instance:

```http
HTTP/1.1 404
Content-Type: application/json
Cache-Control: no-store

{"errorCode":"LLM_SUMMARY_MISSING"}
```

This is explicitly **not** an authorization to generate again and does not identify the cause of absence. A frontend sessionStorage attempt marker is not evidence that the server still retains a result. On reload/fresh login, try passive GET; on missing show that no retained summary is available. Do not clear an attempt marker or replay POST automatically merely to fill the cache. Generation still requires the existing applicable explicit request consent and workflow constraints.

A foreign or nonexistent scan returns HTTP404 `{"errorCode":"SCAN_NOT_FOUND"}` **before policy/cache access**, regardless of whether another owner has a result. Legacy/nonpublic compositions return the same finite404 and do not access this cache. Anonymous/invalid cookie and existing browser-access restrictions keep their existing401/403 responses.

If session, policy, report or access changes between lookup/generation and the actual HTTP write, publication is rejected using existing finite errors (`AUTH_UNAVAILABLE`, `LLM_STALE_POLICY`, `LLM_STALE_REPORT`, `SCAN_NOT_FOUND`, etc.) and `no-store`, never stale summary content. POST also checks abort at final publication. No internal/cache/provider exception text is returned.

## Bounds, lifecycle and fences

- One cache per `LlmService` instance, no static/global cross-user cache, DB rows, file persistence, migration, new credentials, timers or second provider.
- At most64 entries, at most2MiB of accounted retained UTF-8 result/key/scope bytes, at most65536 UTF-8 result bytes per entry. Map/object overhead is additionally bounded by64 entries, not claimed to be part of an exact heap-byte measurement.
- Owner+scan scope and full digest/platform/reportVersion/policyVersion key. Reads return independent parsed objects. Report/policy changes encountered by an authorized read remove obsolete entries for that owner+scan; those entries do not reappear if settings are later restored. Disabled policy is a miss and invalidates that scope. No cache counts/keys/cross-owner errors are exposed.
- LRU eviction applies at entry/byte bounds. A successful GET refreshes only the authorized entry. Other users cannot inspect or refresh an owner's entry. Misses do not initialize generation or consume quota.
- Existing `AuthStore.guardSession` protects the exact session generation/incarnation/expiry through final synchronous publication. `ReportReader.withSummaryReport` uses the same fileMustExist + BEGIN IMMEDIATE + query_only WAL-writer fence pattern as translation, through the full current report check and synchronous final write. No application rows are written by these guards and no transaction spans a network await.
- **Survives browser reload and a new valid login for the same owner, while that service instance and entry remain. Does not survive API restart, service destruction/replacement, independent replica, or eviction. No durability/guaranteed retention interval is promised.** Module teardown clears memory.

## Coordinator-owned nginx/client integration — exact required edit

Read-only source inspection found `server/deploy/public-stand.nginx.conf`'s exact UUID `/llm/summary$` location currently has:

```nginx
limit_except POST { deny all; }
```

Within **that exact existing public location only**, the coordinator needs:

```nginx
limit_except GET POST { deny all; }
```

Preserve its exact path restriction,1k body limit, proxy settings,35s timeout, disabled access log and `Cache-Control no-store always`. GET conventionally permits HEAD in nginx/Nest; it is passive as well. Do not add a broad `/llm/*` proxy, expose private API paths, or relax other methods. The legacy `server/deploy/stand.nginx.conf` restriction is not part of this public-only change and should remain unchanged.

Until the public ingress change is deployed, the proxy will deny GET even though API-only synthetic HTTP tests pass. Coordinator/client owner must add passive retrieval to `src/shared/api/scans/llmSummaryClient.ts` and the reload/login UI flow, preserving strict success decoding, session/report/policy fences, no-store requests and missing404 handling. No client or nginx file was modified here. Any native browser runner allowlist that intentionally forbids GET summary needs its own exact, tested adjustment before qualification; no generation probe or retry is authorized by this document.

## Synthetic verification

`summary-result-cache.test.ts`: owner/full-binding isolation, stale-scope invalidation, detached objects,64-entry LRU, aggregate/per-entry byte bounds and independent instance/clear behavior.

`summary-result.http.test.ts`: actual Nest/cookie login/owned disposable report/adapter with synthetic transport; exact POST/GET success and finite missing; no provider/key metadata/quota/history on GET; foreign404 before policy/cache; current policy/report/off invalidation; unsafe failed POST charged but not cached; actual final GET/POST publication races; competing auth/report writers excluded during final write; legacy404; HTTP64-entry eviction; fresh service instance against the same auth/report fixtures returns missing without generation.

No live provider, deployed browser/reload acceptance, persistent-summary claim or nginx qualification is implied by these tests.
