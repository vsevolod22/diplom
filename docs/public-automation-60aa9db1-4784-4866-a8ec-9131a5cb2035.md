# Native public automation qualification — 2026-10-26

Attempt: 60aa9db1-4784-4866-a8ec-9131a5cb2035. Actually run: true. Origin: http://127.0.0.1:8081.
Maximum one disposable account, one native Node four-check scan, four generation POSTs. No retries/fallback.
Metadata only: no answers, selected source text, conversations, credentials, screenshots, HAR or storage state.
Already-admitted summary transport may be observed during bounded cleanup; consumption remains UNKNOWN and this cannot qualify a failed/skipped case.
Already-admitted summary capture: ERROR_CAPTURED; consumption: UNKNOWN.
Russian/schema/citation checks do not establish semantic accuracy or translation fidelity. Review only in memory.
No foreign-owner isolation claim: only one account is authorized. Summary reload/fresh-login restoration requires passive GET, never another POST.
Source changes and offline tests are not deployment or live acceptance; 412 remains the stand source until coordinator deployment.

| Case | Result | Code |
| --- | --- | --- |
| tooling | PASS | VERIFIED |
| owner_registration | PASS | VERIFIED |
| preferences_original | PASS | VERIFIED |
| native_scan | PASS | VERIFIED |
| estimate | PASS | VERIFIED |
| coverage_click | PASS | VERIFIED |
| report | PASS | VERIFIED |
| always_open_chat | PASS | VERIFIED |
| summary_initial_missing | PASS | VERIFIED |
| summary | BLOCKED | LLM_HTTP_ERROR |
| chat_1 | BLOCKED | PROVIDER_STOP_NO_RETRY |
| chat_2 | BLOCKED | PROVIDER_STOP_NO_RETRY |
| history_reload | BLOCKED | PREREQUISITE_UNAVAILABLE |
| summary_reload_no_post | BLOCKED | PREREQUISITE_UNAVAILABLE |
| summary_reload_restore | BLOCKED | PREREQUISITE_UNAVAILABLE |
| preferences_ru | BLOCKED | PROVIDER_STOP_NO_RETRY |
| translation | BLOCKED | PROVIDER_STOP_NO_RETRY |
| translation_toggle | BLOCKED | PREREQUISITE_UNAVAILABLE |
| preferences_fresh_context | BLOCKED | PREREQUISITE_UNAVAILABLE |
| fresh_login | BLOCKED | PREREQUISITE_UNAVAILABLE |
| history_fresh_login | BLOCKED | PREREQUISITE_UNAVAILABLE |
| summary_fresh_login_restore | BLOCKED | PREREQUISITE_UNAVAILABLE |
| anonymous_denial | PASS | VERIFIED |
| settings_owner_isolation | BLOCKED | SECOND_OWNER_NOT_AUTHORIZED |
| preservation | PASS | VERIFIED |
| safety | PASS | VERIFIED |
