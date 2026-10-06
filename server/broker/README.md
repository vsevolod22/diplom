# Standalone inspect broker — DIP-TASK-5

Implemented library slice, **not production integration or complete task acceptance**.
Production entrypoint is unconditionally off: `node server/broker/run.mjs start` prints
`inspect_broker_disabled`, opens no listener and reads no daemon/JWT credentials. There
is no env flag, configuration file or Compose mount that enables production here.

## Verify from repository root

```sh
node server/broker/run.mjs typecheck
node server/broker/run.mjs test
python3 server/deploy/proof/test_inspect_broker.py
```

`run.mjs` resolves already-installed TypeScript/tsx relative to `server/api/package.json`
(and Node types from its dependency tree). No downloads, new dependencies, manifest or
lockfile changes, NODE_PATH, API/worker/auth imports, or Nest application startup. The
security boundary uses Node built-ins; the existing Nest toolchain remains untouched.
The suite has 62 tests (the original 50 plus 12 rework regressions). Tests create unique
owned `server/broker/.f-*` directories, actual private Unix sockets, raw HTTP clients and
fake Engine servers. They remove only their own fixture directory. These are real
HTTP/Unix tests **against a fake Engine**, not real Docker/topology proof. Six individually
named raw denial tests cover image inspect, stats, start, stop, remove and copy, each at
both the Engine-shaped route and a private inspect-route suffix, with zero adapter
dispatches and zero fake Engine requests. These supplement the existing exact-route,
operation, framing and authorization denial matrix; they do not certify every Docker API.

## Narrow private protocol

Only `GET /v1/contexts/<registered-slug>/containers/<64-lowercase-hex-ID>/inspect` using
HTTP/1.1 is admitted. No normalization, query, fragments, percent escapes, absolute-form,
body, upgrade, alternate version, HEAD/OPTIONS or arbitrary upstream method/path. Raw
wire bytes are guarded before Node's parser (including whitespace, framing and surplus
body/pipelining), then raw header multiplicity and the exact route are checked again.
One request per connection; no keepalive reuse. Parser/framing failures may close the
connection rather than returning JSON; they never dispatch Engine requests.

Allowed request headers, once each: `Host: broker`, `Authorization: Bearer <64 lowercase
hex characters>`, `X-Broker-Grant: <enrolled grant ID>`, optional `Connection: close` or
`keep-alive` (response still closes), and optional `Content-Length: 0`. Unknown headers
are forbidden. Browser/image-scan JWTs do not authenticate this protocol.

Successful response: `{status: "checked", snapshot: ...}`. Other outcomes are
`not_authorized`, `failed`, `unsupported`; no target-existence or raw daemon error body.
No public policy-update/audit endpoint, socket/key export or generic proxy exists.

## Operator-local authorization

`PolicyStore.replace` takes a validated bounded operator-owned state with callers,
contexts, grants and **separate** consent records (`src/policy.ts` exports the types).
Caller credentials are independently generated random 256-bit opaque secrets; only
SHA-256 digests are retained in enrollment. Fixed-length digest comparisons use
`timingSafeEqual`, iterating every enrolled caller. The token/grant selector is not a
self-declared subject, scope, consent, audience, target or endpoint. Maximum enrollment:
16 callers/contexts, 64 grants/consents. No maps grow per denied ID or client IP.

A grant binds caller, enrolled safe subject, consent/version, exact full ID/context and
version, policy version, audience `inspect-broker`, scope `container:inspect`, activation
and expiry (exclusive, TTL <=300 seconds), and revocation state. The input is cloned:
external aliases cannot mutate policy. Every replacement/unavailability increments a
private epoch, invalidating all operations pinned to an earlier state, including ABA
replacements. Invalid refresh makes the store unavailable rather than stale-positive.
No signed JWT capability/issuer/key-algorithm verification is implemented or claimed.

Dispatch and publication recheck state, versions, consent, time and deadlines. Operator
mutation and the critical sections are synchronous on one event loop. Audit admission,
recheck and transport start have no intervening await. Projection/body serialization is
finished before the final recheck and synchronous HTTP response commit. Slow synchronous
audit is tested. Revocation after dispatch blocks publication but cannot undo that GET.

## Boundary and adapter

`Broker` defaults disabled. A disposable library harness must explicitly enable it and
present an unforgeable in-process permit returned by `verifyPrivateBoundary`: actual
canonical private directory (0700, current UID) and owned Unix socket (0600), same root,
no symlinks. The measurements are repeated after the dispatch barrier and again after
synchronous audit reservation, immediately before dispatch alongside the deadline and
policy checks. The root-invalidation regression changes the owned root from 0700 to
0755 during audit reservation: `not_authorized`, no snapshot, zero adapter dispatches
and fake Engine requests, released audit reservation/active slot, then successful
recovery after restoring only the owned fixture. A plain object, a boolean or socket
`:ro` cannot substitute. `listenPrivate` supports Unix ingress only,
0600 in an owned 0700 parent, fresh path, never unlinking another service's socket.

**This proves a local filesystem boundary only.** Same-UID processes are not isolated
from one another; these tests do NOT demonstrate container mount/network/key isolation,
separate daemon ownership, client inability to reach a daemon, or compromised-broker
containment. Production remains off until a real disposable topology is verified and
independently reviewed. A daemon socket is daemon authority, potentially host-root-
equivalent; filesystem `:ro`, TLS and SSH do not restrict Engine verbs.

`UnixEngine.inspect` can only construct `GET /v1.47/containers/<authorized ID>/json`.
The candidate API is pinned to 1.47: no negotiation, ping, retry, redirect, list/search,
caller headers/body or fallback. Only registered canonical absolute Unix sockets are
supported; remote context transports return `unsupported` without connecting. Proxy
environment variables/DNS/TCP/TLS/SSH are not used. Real-daemon 1.47 compatibility has
not been verified. Non-200/non-JSON, duplicate content-type, compression, aborted,
truncated, oversized or invalid JSON responses never publish a snapshot.

## Finite budgets

`src/contracts.ts` fixes defaults; overrides may only tighten positive integer values.
Invalid/infinite/increasing overrides fail closed. Supplied audit capacity must fit the
configured limit. There is no waiting queue or transport retry.

| Resource                                                |                    Default |
| ------------------------------------------------------- | -------------------------: |
| Actual wire request line + headers                      |                 8192 bytes |
| Request target / headers / body                         |   256 bytes / 32 / 0 bytes |
| Ingress header deadline / accepted sockets              |               1000 ms / 16 |
| Upstream body / output snapshot                         |             1 MiB / 32 KiB |
| JSON depth / nodes (including keys) / fields per object |          32 / 50,000 / 256 |
| Individual decoded UTF-8 string                         |               65,536 bytes |
| Connect / absolute operation deadline from admission    |          1000 ms / 5000 ms |
| Concurrent operations / queued operations               |                      2 / 0 |
| Global admission token bucket                           |         burst 2, 10/minute |
| Audit retention / serialized record                     | 512 records / <=1024 bytes |

The raw header prefix retains at most B+1 bytes per socket. Upstream fragmented responses
use one bounded U-byte backing buffer, not a growing chunk-object list. Strict UTF-8,
duplicate decoded keys (including escaped aliases), non-finite numbers, trailing data,
BOM/lone surrogate strings and structural bounds are checked before `JSON.parse`. Input
is transient inside the trusted process, not logged/cached/persisted/sent to an LLM.
Managed-memory physical zeroization and a measured process RSS ceiling are not claimed.
Timers bound I/O/barriers; synchronous parsing/serialization is bounded by size/node
budgets, not preempted by timers. Stalled-I/O tests use 100 ms and assert <=350 ms local
wall-time (250 ms tolerance), then prove slot recovery; not a production SLA.

Audit buffer never overwrites silently. Before dispatch it atomically accepts admission
and reserves final capacity. Denied records cannot steal reservations; operator drain
retains reservations. Unavailable/full admission => zero dispatch. Final audit failure =>
no success. Final synchronous expiry corrects the retained publication record in place.
Fixed-schema records contain generated correlation/time, authenticated enrolled safe
subject (or anonymous), verified target/context (or invalid), operation/scope,
admission/publication decision/reason and actual dispatched boolean. No raw request,
headers, credentials, unchecked target strings, exceptions, inspect/env/labels/logs.
Retention is local in memory, not durable SIEM/audit acceptance.

## Snapshot v1 (historical configuration, not safety attestation)

Envelope: `schemaVersion=inspect-snapshot-v1`, full authorized `containerId`, safe trusted
`context={id,version}`, UTC `observedAt` after validated receipt, explicit
`coverage=runtime-config-inspect`, facts and SHA-256 `hash`. Hash input is the envelope
without hash, canonical JSON: recursively sorted object keys by UTF-16 code unit,
ordered arrays, JSON primitives without whitespace. Capability arrays are deduplicated
and code-unit sorted; mount group and port arrays are sorted by their fixed source key,
not locale-dependent order. Hash is never over raw inspect. Internal context epoch is
used for races; published context version is its enrolled version.

Required upstream object: exact matching `Id`, object `Config`/`HostConfig`, boolean
`Privileged`/`ReadonlyRootfs`. Optional malformed present values fail instead of coercing
to safe facts. Missing fields (and explicitly supported Docker null collections/resource
limits) are `unknown`. Facts are only:

- configured user class root/non-root/unknown. Empty/root/UID 0 => configured root;
  validated numeric nonzero UID => configured non-root; arbitrary names => unknown.
  Not actual process identity, namespace host-root, or runtime UID attestation.
- privileged/readonlyRootfs booleans; cap-add/drop fixed Linux enum + ALL/unknown, max64.
- security option classifications default/custom/unconfined/unknown; namespaces
  host/private/shared-container/unknown, classified **per field as configured modes**,
  not verified effective namespace isolation. No profile path, peer ID or network name.
  Explicit `host` is retained for each field. Network `bridge`/`none`, PID empty mode,
  IPC `private`/`shareable` map to configured `private`; `container:<nonempty peer>` maps
  to `shared-container` only for network/PID/IPC. Missing or unrecognized modes are
  `unknown`; empty/default network/IPC modes are also `unknown` because defaults may
  be inherited. User namespace empty/default/missing and all non-`host` strings are
  `unknown`: inspect does not establish daemon UID mappings/remapping. In particular,
  `UsernsMode=""` is NOT evidence of a private user namespace. Present non-string values
  fail schema validation. These configuration hints do not attest daemon, host or
  process isolation, even when the label is `private`.
- Mount aggregate fixed type/readOnly/count groups (max256) and socketPresent.
  Known docker.sock signal => true; no mounts => false; arbitrary/missing mounts =>
  unknown, never a claim that other daemon socket paths are ruled out. No mount paths,
  volume names or source/destination retained.
- bounded numeric port/protocol and published boolean (max256; no HostIp/HostPort), and
  safe nonnegative integer resource settings with explicit unknown. Zero is configured
  unlimited where Docker defines it, not safe; unsupported negative settings fail.

No Env/labels, command/args/entrypoint, names, credentials, LogPath, unknown nested fields,
raw profile or host paths in output, audit or diagnostics. Synthetic all-field canaries
are tested including fields considered for classification. Dangerous true/ALL/
unconfined/host/socket facts remain visible. Missing fields do not prove defaults safe.
This does not inspect writable layers, volumes, traffic, host/daemon baseline, CVE/SBOM,
secrets, process behavior or provide a public container scan. No findings != safety.

## Remaining acceptance

See `INTEGRATION.md`. All three independent reviews of original commit `858cce4` were
read: correctness requested changes (post-audit boundary and user namespace semantics);
security/spec approved only the default-off library slice, with namespace/route-coverage
qualifications. This rework addresses those findings with tests, but is NOT independent
approval of its own patch. The original correctness reviewer must independently recheck
the patch before integrator approval; prior reviews must not be silently transferred to
changed code. Real Docker Engine/API 1.47/topology proof remains pending.
The actual bounded docker info probe on 2026-10-06 timed out at 20.0 s;
no reset/restart/mutation. `python3 server/deploy/proof/test_inspect_broker.py --real`
is an optional prerequisite reporter, exits **1**, never skips/passes unavailable real
proof; even a responsive daemon is not proof without an owned disposable topology.
Do not use that reporter as real inspect acceptance. The feature target delta is
human-approved but remains proposed/unapplied; this rework neither applies it nor closes
the task. Strict close needs a task-sourced spec for only the independently accepted slice.
