# Additive errata: public AI historical evidence mapping — H7 / 2026-10-25

## Authority and limits

New additive record only. H7 run `7aa358d1-d67b-4ddb-b8c0-4c560c16b8f4`, exact work `540f464b-7984-41ae-96f5-c2a16529ce8d`, agent `h7-spec`. Historical JSON, Markdown, attempts, tracker history and applied spec revisions are NOT overwritten. No new browser/provider/native execution, lifecycle, key, raw env or private database access occurred. The following is a fresh static mapping/byte comparison, NOT generation proof.

## Correction to the preceding audit's mapping conclusion

The preceding audit reported a base/attempt3 Markdown run-ID mismatch in its read output. **Fresh direct filesystem extraction does NOT reproduce that claim:** all three current Markdown run IDs match their same-basename JSON run IDs. Each of the six whole files is byte-identical to the file stored in current Git HEAD `b73c28a65dc482809de5bc066ef07ed87cf57def`. Therefore retract the preceding claim that these checked-in pairs currently mismatch; do not manufacture a file fix or infer that another participant corrected them. The cause of the earlier inconsistent read observation is not established.

Canonical mapping, obtained from `JSON.runId` and the Markdown `Run:` line:

| Same-basename JSON + Markdown under docs/ | Exact run ID | Historical outcome, not a new execution |
| --- | --- | --- |
| public-ai-live-20261022 | 66874291-6aa6-427a-8ef2-e1f2595f3c73 | native scan/report/readiness PASS; chat1 BLOCKED/LLM_HTTP_ERROR; chatPosts1, translationPosts0; safety FAIL/REQUEST_GUARD, blockedRequests3 |
| public-ai-live-20261022.attempt2 | 72c55c66-ccc0-42f7-9bce-67a73f764b35 | native scan BLOCKED/REQUEST_GUARD before launch; scanLaunches0/chatPosts0/translationPosts0; safety FAIL, blockedRequests1 |
| public-ai-live-20261022.attempt3 | b32b0957-f871-4f7e-b95f-6d1acd41259f | native scan BLOCKED/REQUEST_GUARD before launch; scanLaunches0/chatPosts0/translationPosts0; safety FAIL, blockedRequests1 |

No run/receipt is interchangeable with another attempt. A Markdown summary alone is insufficient. Keep initial failure, later offline guard correction and any future separately authorized attempt as distinct evidence; no retroactive PASS/FIXED claim.

## Immutable historical file fingerprints

SHA-256 is over direct local file bytes; all six separately compared byte-for-byte against `git show HEAD:<path>` with equality=true. These are evidence-file fingerprints, not credentials, key fingerprints, provider payloads or remote MCP body hashes.

| File under docs/ | SHA-256 |
| --- | --- |
| public-ai-live-20261022.json | 6956251b0d5f488512670dd8cd98b8e3ff2e330f2ef50aef845956540e2c39f4 |
| public-ai-live-20261022.md | f5c8d123fde9872e8c14e8f0d1eb7837700df8c78887844007b56a1dc465a90f |
| public-ai-live-20261022.attempt2.json | 5e18005514bbdfcb66055d194430fbcf80ab78406e30b73110341bb4e7d0144c |
| public-ai-live-20261022.attempt2.md | 8ea9fa9d673e9eccc5a259b9968269d1654dbca3bbcce04e0bc240325920c431 |
| public-ai-live-20261022.attempt3.json | 40e30308e16c00055b67b49707517f859d81e9171a39f7515fdd6f678ccbe7b7 |
| public-ai-live-20261022.attempt3.md | 86dd2771ba544acbf0b0d4002621aaa09a97394fb3c95cc6eef2d690bdb17ebe |

## Historical STOP versus new authorization

The 2026-10-22 STOP was the effective boundary for those historical attempts and is not deleted. The owner's new H7 authorization supersedes it prospectively for the explicitly assigned new work; it does not authorize this spec participant to run provider/browser/lifecycle operations. Browser execution requires its separate coordinator READYGO. Provider generation/ru quality remain unverified in this spec result.

Attempt1's dispatched/no-observation consumption remains UNKNOWN per attributed coordinator history; no manual refund/quota reset is authorized. HTTP200 framed error is not successful chat. Auth metadata, source GO and deployment READY are not successful translation or two successful chat replies. Attempts2/3 with translationPosts0 are not translation provider failures or translation acceptance.

## Current contract reconciliation

Fresh MCP baselines: DOC16v2, DOC15v2, DOC8v3 and DOC9v2. Full new bodies: `docs/public-final-spec-doc16-full-20261025.md` and `docs/public-final-spec-doc15-full-20261025.md`, both sourced from existing DIP-TASK-42, never accepted TASK16. DOC16 includes russian-prose-v2, finite provider errors, advisory bounded Retry-After and a whole-operation45000ms translation UI deadline. DOC15 is needed because frozen source really extends NDJSON v1 errorCode/metadata, not just UI copy. Old strict clients are not falsely called compatible; success/receipt/tuple/seq/byte/write guards remain.

DOC8's historical LOCAL Apodex/Novita model scope is not rewritten into the public Xing/Phala profile. DOC9's safe-error/no-auto-retry/original-report invariants remain. No DOC8/9 delta is needed for this scoped amendment. No accepted task is reopened. New proposed bodies do not themselves prove source review, deployment, generation, semantic quality or accounting preservation.

## Apply disposition

Proposal/validation receipts are recorded in the separate H7 manifest when available. **APPLY HOLD until explicit coordinator approval after source GO**, even though fresh project policy has require_proposal_approval=false. Neither this errata nor proposal creation lifts that HOLD. Before any later apply reread the full current document, policy and delta base; do not replace a concurrently changed document with stale full text. No source/status/content/progress/closure/accepted-task mutation, commit or push is part of this lane.
