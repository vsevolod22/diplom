# DOC1 local proposal — author notes, 2026-10-18

## Baseline and ownership
- Project: `diplom`, Flownix `520a0059-d0f2-4f86-8d93-fc15035a5715` (`DIP`). Required skills and `.flownix` read before tracker reads.
- Document: `DIP-DOC-1`, id `5409b5a8-982e-4027-8c73-310d6aebc0fb`, **version 5**, updated `2026-10-15 17:24:56.526557+00`.
- Full baseline content: **30,513 UTF-8 bytes**, SHA-256 **`a04a8d75b7eef33c65da1d7beb5b0bad8e9fcd13594717b6e94a5340e8b9c1a4`** (includes final LF).
- `list_doc_deltas(source_node_slug=DIP-TASK-2, state=proposed)` returned no revisions. The document-wide proposed list contained two historical approved but unapplied feature-sourced deltas on base versions 1/2; neither was used as the baseline or changed.
- Tracker policy read: full/strict, proposal approval off, spec-first off, parallel/direct. No tracker writes performed; coordinator owns proposal/application/status decisions. Recheck document version and source-task deltas before any coordinator mutation.

## Result
- Full resulting body: `docs/public-image-doc1-proposal-20261018.md`.
- **60,195 UTF-8 bytes**; SHA-256 **`c96391884463da0bcf9597fbb2b04ca167fe4048df05f69bc0d049ecb89c170f`**.
- **37 requirements / 46 scenarios**: all 23 legacy requirement names retained, 14 separate optional public requirements added. Legacy requirement blocks remain unchanged except the explicit legacy-policy qualification of the NextUpdate scenario. Intro/non-goals/history/resource-handoff prose reconciles only conflicting profile/status scope.
- Public profile covers real pinned registry-only acquisition, finite body/attempt/resource budgets, OS/ecosystem/unknown/EOL boundaries, explicit config authority, accepted checkpoint/final consistency, cancelled-state subset recovery, DB trust/usability, owner/report/UI guards, new isolated 8081 accounts/state versus retained LOCAL8080, and remaining native/security/rollout gates.
- `wireBytes` compatibility names explicitly mean delivered response-body accounting, not physical wire traffic. Public 4 GiB/2304 MiB resource policy does not rewrite legacy 1 GiB/512 MiB handoff.
- Source and scoped controlled-test/review evidence are identified, not restated as native/live/deployed acceptance. OCI and chain follow-up approvals do not approve the launcher or waive outstanding native qualification. Launcher remediation still needs independent re-review according to the inspected handoff.

## Validation performed by this author
- MCP **`validate_spec(doc_slug=DIP-DOC-1, project_id=520a0059-d0f2-4f86-8d93-fc15035a5715, body=<FULL resulting local body>)` → `{"valid":true}`**. No issue list/new or inherited warnings returned.
- Local structural/byte checks: no duplicate requirement names, no trailing whitespace, final LF present.
- Independently reversed the six deliberate baseline edits in memory and removed the appended public section: reconstructed baseline SHA-256 exactly matched `a04a8d75…e8b9c1a4`. No baseline file was left behind.
- Read source plus acquisition/API-UI/ledger/config/isolated-stand and worker handoffs; read independent OCI/chain re-review and launcher findings. Test results cited by those documents belong to their authors, not a new run here.
- No application tests, build/typecheck, Docker, native Trivy, registry traffic, live DB readiness, existing environment/private secrets, deployment, migration, staging, branch or commit. Exclusive writes: the full local proposal and this small author note only. No `propose_doc_delta`, `apply_doc_delta`, doc/status/comment mutation or artifact upload.
