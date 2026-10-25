# Public 8081 one-scan cancel qualification

Origin: http://127.0.0.1:8081
Evidence root: docs/public-final-f086c21c-87cb-4919-b824-e457a06036ec-cancel

Run: d17ad639-9af8-4f19-b7fc-8ab1a8457add. Provisional summary only: require the matching complete JSON and a successful evidence write; this Markdown alone is not acceptance.
Native generation is NOT qualified. No key is sought or persisted. Provider dispatch is not independently observed.
One account and at most one native four-check scan are retained. All LLM POSTs are denied, including manual history; key presence is irrelevant and no key-absent/readiness probe is required. Terminal races and absent subset evidence never qualify cancellation. No relaunch.
PASS is per assertion; BLOCKED is not success; cancel races and unavailable pagination/subset observations are INCONCLUSIVE.

| Case | Result | Code |
| --- | --- | --- |
| tooling | PASS | VERIFIED |
| registration | PASS | VERIFIED |
| cancel | BLOCKED | ASSERTION_FAILED |
| cancel_report | BLOCKED | NOT_RUN |
| cancel_preservation | BLOCKED | NOT_RUN |
| cancel_reload | BLOCKED | NOT_RUN |
| cancel_history | BLOCKED | NOT_RUN |
| cancel_fresh_login | BLOCKED | NOT_RUN |
| safety | PASS | VERIFIED |
