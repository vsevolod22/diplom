# Integration handoff — deliberately not enabled

This author step implements only the broker library, private raw HTTP ingress, GET-only
Unix adapter, local operator policy/audit, sanitized transient snapshot, fake Engine/unit
proof and Python orchestration. No public Nest/API/worker/UI route, shared Compose,
manifests, env/JWT/session keys, existing volumes, sockets or stand auth were changed.
Existing TASK2/TASK7 work and foreign notice files must remain intact.

## Review boundary

Three independent implementation reviews (security/correctness/QA) should inspect the
actual code and counter evidence before acceptance. The author has not performed or
claimed these reviews. Main/start must remain unconditionally off. A library enable
boolean alone must not become a production toggle, and the measured filesystem permit
must not be represented as verified container topology. The socket is daemon authority;
`:ro` is NOT an authorization mechanism or compromised-broker containment.

Review particularly: raw framing before parser normalization, alias/duplicate headers,
exact full-ID/path, cloned current local grants/consent, global epoch ABA protection,
actual adapter dispatch counter, synchronous slow-audit race checks, pre-commit body
serialization, bounded duplicate-aware JSON and data-minimizing projection. Post-
dispatch revocation prevents snapshot publication, not the already dispatched GET.

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
strict spec for the accepted proven slice, not the unapplied full future feature target.
DIP-TASK-5 remains in_progress until remaining runtime evidence/reviews are resolved;
this author work can complete with outcome implemented for the coherent library slice.
