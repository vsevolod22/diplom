# Integration handoff — deliberately not enabled

This author step implements only the broker library, private raw HTTP ingress, GET-only
Unix adapter, local operator policy/audit, sanitized transient snapshot, fake Engine/unit
proof and Python orchestration. No public Nest/API/worker/UI route, shared Compose,
manifests, env/JWT/session keys, existing volumes, sockets or stand auth were changed.
Existing TASK2/TASK7 work and foreign notice files must remain intact.

## Review boundary

All three independent implementation reviews (security/correctness/spec) of original
commit `858cce46412380c58ca903699683ca8a1499ccdd` were read by the integrator. Correctness
requested changes with two medium findings (DIP-ARTF-15); security/spec approved only
the default-off library slice, not full task acceptance. The rework adds the post-audit
filesystem recheck, per-namespace configured-mode classifiers, root/UsernsMode regressions
and six individually named zero-call route tests. Typecheck, 62 TypeScript tests
(0 failed/skipped/cancelled) and Python orchestration 3/3 passed after the fix.
The patch still requires independent recheck by the **original correctness reviewer**
before integrator approval; the integrator's own tests do not replace that review.
Main/start must remain unconditionally off. A library enable boolean alone must not
become a production toggle, and the measured filesystem permit
must not be represented as verified container topology. The socket is daemon authority;
`:ro` is NOT an authorization mechanism or compromised-broker containment.

Review particularly: raw framing before parser normalization, alias/duplicate headers,
exact full-ID/path, cloned current local grants/consent, global epoch ABA protection,
actual adapter dispatch counter, synchronous slow-audit race checks, pre-commit body
serialization, bounded duplicate-aware JSON and data-minimizing projection. Post-
dispatch revocation prevents snapshot publication, not the already dispatched GET.
Boundary checks after synchronous audit reservation close the reproduced in-process
race, not hostile-OS atomicity or socket-inode/topology containment. Namespace labels
are per-field configuration hints, never effective-isolation attestations. Empty
UsernsMode is unknown because daemon UID mappings are not established by inspect;
inherited network/IPC defaults and invalid modes are not promoted to private.

## Real disposable proof still required

Docker info currently timed out within the measured 20 s bound. No resets/restarts,
prunes, downloads, production mounts, stand containers or unrelated volumes are allowed.
The new Python --real reporter is prerequisite-only and intentionally fails (no skips),
including for a responsive daemon until the disposable topology driver exists.

A later explicitly authorized proof owner must build a wholly separate uniquely owned
fixture with its own daemon/context and own A/B, trusted topology measurements and
local caller credential/grant. Container creation/cleanup belongs to trusted proof
orchestration, never broker capabilities. Pin approved available fixture images; do
not blindly pull. Verify API 1.47 actually supported, socket/key only in broker, client
mounts/networks/UIDs cannot reach daemon, no live stand exposure. Cleanup only exact
owned resources, never prune/reset. Client processes sharing broker UID do not satisfy
this isolation requirement.

Use the same authorization path for positive A/C (one canonical GET) and all negatives
(exec/create/export/B/context mismatch/expired or absent grant/:ro-only, zero dispatch).
Do not send forbidden operations directly to the daemon to demonstrate broker denials.
Record safe counters, topology booleans, status/schema/hash and prerequisites, no raw
inspect/env/labels/keys/error bodies. Fake Unix tests are not real daemon/topology proof.

Signed capability/remote transport/production deployment are not implemented. No durable
policy/audit persistence, signing service, SIEM, registry resolver or DB integration is
invented in this slice. A later reviewer/integrator should apply only a task-sourced
strict spec for the accepted proven slice, not the human-approved but unapplied full
future feature target `37ad928f-7309-4429-9e8e-b763c66659bb`. No delta or task status is
changed by this rework. DIP-TASK-5 remains in_progress until remaining runtime evidence
and independent rechecks are resolved. Exact integrator work
`b1d1b36e-66b6-4e1c-bde1-043295e2e8c3` in run
`15faf6fa-e133-4db2-bd48-1a064fb6e055` is intentionally kept leased for that handoff,
not completed with approved/changes_requested and not advanced to task close.
