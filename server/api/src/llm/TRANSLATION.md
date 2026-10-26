# Selected advisory translation — public API contract

Current candidate disclosure uses `automaticDispatch: 'account-preference'`: client automation is allowed only after saved account opt-in and still uses the existing consent-bound POST. Server GETs never dispatch. The historical `automaticDispatch: false` described the earlier manual-only UI and is not accepted by the current strict decoder. This undeployed correction retains the already-candidate v4 policy identity; no additional policy/source revision is introduced.

Source candidate only: deploying/enabling this code, importing credentials and live provider acceptance are separate coordinator/operator actions. Synthetic tests are not live provider evidence. No host scripts, keys, existing stores or lifecycle are changed by this implementation.

## Routes and frontend integration

Registered **only in PublicImageModule (public 8081 composition)**. Not registered in legacy AppModule/LlmModule, and not added to the legacy nginx configuration. All responses, including errors, use `Cache-Control: no-store`. Browser cookie authentication and same-origin POST checks are the existing browser bridge. No client credentials, prompts, URLs or source text are accepted.

### GET `/api/v1/browser/scans/:scanId/llm/translation/context?findingId=<id>&assessmentIndex=<int>`

Exactly these two query keys. `findingId` matches `^vuln-[a-f0-9]{64}$`; `assessmentIndex` is canonical decimal `0` through `15`, indexing the **saved advisory.assessments array**, not an independently sorted UI list. Duplicate/unknown keys and aliases are rejected. No provider/key access, generation, quota reservation, history store or cache access occurs.

Exact successful response shape (TypeScript notation):

```ts
type Binding = {
  scanId: string;       // report scan UUID
  digest: string;       // sha256:<64 lowercase hex>
  platform: 'linux/amd64';
  reportVersion: string; // 64 lowercase hex, same authoritative report version as existing LLM context
  findingId: string;
  assessmentIndex: number;
  sourceVersion: string; // 64 lowercase hex, selected original assessment + identifier + translation revision
};
type Source = {
  source: string;        // existing ADVISORY_SOURCES enum; do not relabel a CVSS source as the text source
  provenanceRef: string;
  language: string | null; // explicit original metadata, never inferred/replaced with ru
};
type TranslationContext = Binding & {
  targetLanguage: 'ru';
  source: Source;
  enabled: boolean;      // valid Xing/Phala free-only policy, NOT live provider readiness
  policyVersion: string | null;
  disclosure: null | {
    provider: 'OpenRouter'; model: string; providers: string[];
    region: 'global'; retention: 'no-storage';
    operatorApprovedRouting: true; providerComplianceNotProvenByDeclaration: true;
    requestBudgetUsd: 0; freeOnly: true;
    maxPrice: { prompt: 0; completion: 0; request: 0 };
    data: string; // only eligible selected normalized title/description; no other report/history data
    targetLanguage: 'ru'; machineTranslation: true;
    automaticDispatch: 'account-preference'; persistentTranslationCache: false;
  };
};
```

The translation consent version is SHA-256 of the translation revision, underlying LLM policy version, selected-text egress declaration and target language. It is **different from summary/chat consent**. Display the disclosure and require deliberate saved account opt-in before client automation; enabled metadata, a language toggle, or viewing a card alone is not authorization. After that saved opt-in, the client may schedule the existing POST with applicable per-request consent, preserving source/session/policy/readiness and revocation fences. The literal describes client behavior only: context/readiness GETs never generate, reserve quota, or construct a provider. No account preference is accepted as a new server DTO field and no POST consent gate is bypassed.

### POST `/api/v1/browser/scans/:scanId/llm/translation`

Exact JSON body, UTF-8, `Content-Type: application/json`, explicit Content-Length, at most 1024 bytes:

```ts
type TranslationRequest = {
  reportVersion: string;
  findingId: string;
  assessmentIndex: number;
  sourceVersion: string;
  targetLanguage: 'ru';
  consent: { accepted: true; policyVersion: string };
};
```

Successful response is exactly:

```ts
type TranslationResult = Binding & {
  source: Source;
  translation: { title: string | null; description: string | null };
  machineTranslated: true;
  targetLanguage: 'ru';
  model: string;             // validated exact configured free model
  provider: 'OpenRouter';    // gateway; pinned endpoint provider is disclosure.providers (currently phala)
  generatedAt: string;       // server UTC ISO-8601 timestamp
};
```

Keep the original advisory visible/available and render translated strings as plain text, not HTML/Markdown. Label this **machine translation**, not an official Russian NVD/CVE/BDU source. Preserve CVE versus Debian TEMP semantics. The response does not invent a CVE mapping, new provenance or external source URL.

### Eligibility and errors

Only saved `available`/`truncated` plaintext fields that are **not redacted**, remain unchanged by bounded normalization, and pass the existing bounded credential/URL text guard may be sent. Source title ceiling: 512 UTF-8 bytes; description: 4096 bytes. Source remains unchanged, including truncation markers. Ineligible fields are sent/returned as `null`; no reconstruction from model knowledge. If neither field is eligible, GET/POST fails locally with `409 LLM_TRANSLATION_UNAVAILABLE`.

| HTTP | errorCode / handling |
| --- | --- |
| 400 / 413 / 415 | `LLM_INVALID_REQUEST`: exact DTO/query/route, UTF-8, encoding, content type or size refusal |
| 401 / 403 / 404 | Existing auth/origin/owner protections; foreign owner scan is indistinguishable from missing scan |
| 403 | `LLM_CONSENT_REQUIRED`: explicit accepted consent missing/false |
| 409 | `LLM_STALE_REPORT`, `LLM_STALE_SOURCE`, `LLM_STALE_POLICY`: reload context and ask for current consent; no auto retry |
| 409 | `LLM_TRANSLATION_UNAVAILABLE`, `LLM_CONTEXT_LIMIT`, `LLM_REQUEST_ABORTED` |
| 429 | Existing `LLM_CAPACITY` / `LLM_QUOTA_EXCEEDED` (safe admission metadata may accompany the latter) |
| 502 / 503 | Safe existing provider/invalid-response/configuration/quota/report/auth unavailable errors; retain original, show translation unavailable |

Guard failures inside the actual adapter body-send callback are intentionally collapsed by the existing adapter to `502 LLM_PROVIDER_UNAVAILABLE`; no payload is sent. No automatic retry, paid fallback, second model/provider/chat, or fake Russian result is substituted.

## Trust, consistency and accounting

- Reuses the same `LlmService` capacity, `LlmRuntime`, `OpenRouterProvider.generateGuarded`, transport and `LlmQuotaRuntime`. No history dependency, DB schema/migration or persistent translation cache.
- Outbound user content is exactly `{title,description}`. The local binding, source metadata, package/version strings, report, other findings and history are not serialized. Identifiers already present **within the selected text** are preserved.
- Uses the exact Xing/Phala free policy/provider, ZDR/data-collection-deny, zero prompt/completion/request prices, no fallback; usage receipt liability is bound to actual prepared bytes/hash/reservation.
- Trusted session guard and current policy + owner/report/source checks run at admission, before actual body send, after reply, and around the final HTTP write. No auth decision is cached.
- The scan fence uses `fileMustExist`, `BEGIN IMMEDIATE` and then connection-local `query_only=ON`: SELECT-only data access while excluding WAL writers through the synchronous callback. SQLite readonly WAL connections do not themselves provide that writer-admission fence. No rows/schema are changed and no lock is held across a network await. `data_version`, authoritative all-page report hashing and the selected source hash are checked.
- Unknown/fault/dispatched consumption is not refunded. Late bound receipts may account after revocation/cancellation but never authorize publication.
- Reply must have exactly `{title,description}`, corresponding null fields, bounded safe plain text, unchanged per-field CVE/TEMP identifier sets and substantial Russian Cyrillic for prose. This is a fail-closed script/shape safety check, **not semantic translation-quality proof**. Technical/name-only prose can be refused rather than fabricated. No claim that regex validation proves fidelity.
- Summary/history now request Russian human-readable prose with unchanged JSON keys/citations and unchanged advisory omission. The underlying policy hash includes a new response-language revision so previously accepted policy hashes must be refreshed.

## Verification

`tests/translation-contract.test.ts` covers exact schemas, eligibility/bounds, separate consent, prepared WeakSet/wire, Russian/script/null/ID/URL validation. `tests/translation.http.test.ts` uses disposable fixtures and the **actual adapter with synthetic guarded transport only** for cookie ownership, zero-dispatch denial, selected saved fields, original/TEMP retention, quotas, actual-send session/report/policy races, cancellation, publication revocation and public-only routes.

Run from `server/api`: `pnpm exec tsx --test src/llm/tests/translation-contract.test.ts src/llm/tests/translation.http.test.ts` and `pnpm exec tsc --noEmit`. No real provider request is part of these tests.
