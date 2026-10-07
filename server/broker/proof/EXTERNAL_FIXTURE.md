# Owned external fixture handoff (DIP-TASK-5)

**Runner implemented; real Engine/no-bypass proof is still blocked.** No fixture is
provisioned here. BusyBox on the shared Desktop daemon is not an isolated daemon.
`src/main.ts` remains unconditionally off. This runner cannot enable production.

## Run only the new targeted group

From the repository root:

```sh
python3 -m unittest discover -s server/deploy/proof -p brokerproof_runner_test.py -v
python3 server/deploy/proof/brokerproof_runner.py
```

The group uses simulated measurements and a fake **control-protocol** Unix socket.
It is NOT a real Engine, topology, namespace, mount or no-bypass test. The second
command, without enrollment, outputs `TOPOLOGY_UNQUALIFIED` and exits **1**. It does
not discover Docker, read Docker environment variables, or contact any daemon.
Existing `test_inspect_broker.py --real` is unchanged; its Docker responsiveness
probe is not topology qualification and must not be counted as this real proof.

## Operator must supply these prerequisites

1. An already-owned dedicated Linux VM/sandbox with a separate real daemon/data root,
   cached architecture-compatible target image and installed Node/tsx toolchain.
   Establish daemon ownership/isolation independently; rootless by itself is not proof.
   No Desktop/host Engine socket mount, new privileged container, SYS_ADMIN/security
   exemption, host network/PID/user/mount namespace join, implicit pull/install or
   live-stand mutation. Provisioning is a separate reviewed operator action, not a
   runner fallback. The runner allocates no such resources.
2. Four isolated non-root processes: private caller, broker, trusted observation tap,
   daemon. Distinct measured mount/net/PID/user namespace inodes, CapEff zero, no TCP
   listeners/routes. Check effective UID mappings and inherited descriptors as part of
   independent fixture review; namespace inode inequality alone cannot prove isolation.
3. Caller receives **only** ingress and its fresh 32-byte private opaque credential.
   No Engine/tap socket, daemon data/control credential, controller socket or common
   root mount/descriptor. Broker is the only application with the tap endpoint;
   observer alone has real Engine/control authority. Observer forwards actual bytes
   to real Engine (never fixture JSON or synthesized responses). All setup/version
   calls happen before the measurement baseline. Observer received/forwarded counters
   are independent of the broker's adapter counter and audit buffer.
4. Two full-ID A/B containers on that daemon, network-none, immutable owned namespace
   labels, compatible actual inspect schema. Enroll ONLY A/context v1 with caller,
   grant-a, consent-a and subject-a in the existing validated operator-local policy.
   Use actual current wall time and TTL <=300s; generate/keep the credential inside
   fixture-private memory/files, never return it to runner/logs. Inspect version must
   actually support **1.47**; no negotiation/fallback. Do not change conservative
   projection to coerce incompatible real Engine fields.
5. A separately reviewed **trusted controller implementation** that measures Linux
   `/proc` namespace/mount/network/capability state and executes the existing broker
   library/private raw ingress, real Unix adapter and trusted tap. It must independently
   inspect complete mount/FD exposure, UID mappings and effective client accessibility;
   sending a dangerous verb to Engine is forbidden. Its control socket is operator-only,
   never client-mounted. Review source and pin its SHA-256 in enrollment. The runner
   compares the declared pin, but cannot authenticate controller source/measurements
   merely from a digest it returns. Same-UID local controller trust is an explicit
   prerequisite, NOT isolation from other host processes.

**That controller/fixture is not supplied by this patch.** This is a bounded reusable
orchestrator/evidence verifier, not a hidden DinD installer. A fabricated controller
could fabricate every measurement; runner schema validation is not an independent
hardware/OS attestation. Independent source/counter review remains mandatory.

## Explicit private enrollment

Operator creates a canonical absolute 0600 JSON file in its own canonical 0700 parent.
No symlink/alias paths; owner UID must equal the runner UID. Exact keys:

| Key | Value |
| --- | --- |
| `schema` | `owned-broker-fixture-v1` |
| `fixture` | unique `[a-z][a-z0-9-]{0,31}` owned namespace |
| `ownerUid` | runner's actual integer UID |
| `controllerSocket` | explicitly consented private absolute Unix control socket, <=100 characters |
| `controllerDigest` | reviewed controller SHA-256, 64 lowercase hex |
| `resources` | 6–16 unique captured 64-lowercase-hex immutable resource identities, including A/B |
| `containerA`, `containerB` | distinct full actual container IDs |
| `context` | enrolled safe context slug, not `unregistered` |

Resource identities are exact immutable container IDs or pinned controller handles for
owned VM/process/directory resources. Non-container handles must bind to independently
captured identity (device/inode/creation identity) and owner labels, not mutable names.
The controller must resolve **only those captured identities**, revalidate ownership
before release and never follow a handle to a replaced/foreign resource. No global
reset/prune/down-v; do not delete shared prerequisites or the operator's daemon/VM.
`cleanup` releases only the enrolled disposable proof-session resources; the operator
must enroll no permanent resource. The runner's resources list is sent unchanged, not
a label-filter deletion query. Cleanup acknowledgement alone cannot certify behavior
of unreviewed controller code.

Invocation (replace illustrative paths/namespace with the actual enrollment):

```sh
python3 server/deploy/proof/brokerproof_runner.py \
  --fixture /absolute/private/enrollment.json \
  --authorize-owned-fixture operator-owned-namespace
```

The second option must exactly match `fixture`. No ambient endpoint/credential lookup.
The control path must be owned 0600 in an owned 0700 parent; symlinks, inode replacement
between calls and sockets named `docker.sock`/`podman.sock` are refused. Only explicitly
provided **non-Engine** control protocol is used, not HTTP/Engine API. Local same-UID
filesystem checks do not authenticate an otherwise unreviewed endpoint.

## Controller wire protocol v1

One connection per action. One <=128KiB strict UTF-8 JSON response, then EOF, no streams.
Requests are JSON + newline; exact common fields `schema=brokerproof-control-v1`,
`fixture`, fresh runner-generated 64-hex `challenge`, `action`. Response has exactly
those four echoed fields plus `evidence`. The challenge is correlation/replay defense,
not the caller credential. Errors use only `evidence={"error":"DOCKER_ENGINE_UNAVAILABLE"}`
(or `TOPOLOGY_UNQUALIFIED`/`PROOF_FAILED`); no raw error/inspect/exception strings.

**qualify** — read-only measurements; no allocation. Evidence exact keys:

- `backend=real-engine`, matching `controllerDigest`, exact enrolled `resources`.
- `hostSocketMounts=[]`, `hostNamespaceJoins=[]`: derived from complete actual inventory,
  not configuration flags. Inventory review must cover uncatalogued descriptors/mounts.
- `budget={cpuMillis:2000,memoryBytes:1073741824}`: independently enforce aggregate budget.
- `processes`: exact `client,broker,observer,daemon` objects; each has integer nonzero
  `uid`, `capEff="0000000000000000"`, `namespaces={mnt,net,pid,user}` positive measured
  inode numbers, `routes=[]`, `tcpListeners=[]`. Each namespace is distinct across roles.
- `mounts`: same four role keys, lists of sensitive resource measurements with exact
  `{kind,resource,device,inode,mode,uid}`. `resource` is an enrolled handle; shared same
  kind must have identical resource/device/inode/UID. Different kinds must not alias.
  `daemon-data` mode 0700, all other sensitive socket/credential kinds 0600; nonzero UID.
  Normal read-only image rootfs is outside this sensitive table but must be reviewed
  for hidden endpoints/descriptors. Exact sensitive kinds by role:
  client `ingress,caller-credential`; broker `ingress,engine-tap`; observer
  `engine-tap,engine,daemon-control`; daemon `engine,daemon-data`.
- `access`: six records `{kind,asRole,errno,result}`, all `asRole=client`. Actual bounded
  effective client connection to ingress: `kind=ingress,errno=0,result=connected`.
  For engine, engine-tap, daemon-data, daemon-control, controller: actual inaccessible
  open/connect probes with errno ENOENT(2)/EACCES(13), `result=inaccessible`. Probe only
  connection/access, NEVER a mutation verb. No-bypass review covers raw socket paths,
  alternate endpoints, inherited FDs, routes and credentials, not just these six probes.
- `engine`: exact `{apiMin,apiMax,containerA,containerB,targetLabels}` from trusted setup
  queries, supported API range containing 1.47, exact enrolled A/B,
  `targetLabels=[fixture,fixture]` measured on both targets.

**run** — one bounded seven-case sequence, only after qualification. Additional request
fields: exact `resources`, `cases` ordered as below, A/B IDs, context, `apiVersion=1.47`.
No arbitrary shell command or caller-selected upstream request. Capture complete
controller/tap source and broker source identity for independent reviewers.

Evidence exact keys `cases,caller,defaultOff,topology`:

- `caller={digest:<SHA256>,bytes:32,grant:"grant-a",consent:"consent-a",subject:"subject-a"}`.
  Digest is evidence metadata only, not proof of credential randomness/secrecy. Validate
  actual enrollment/consent independently. No credential/raw headers in responses.
- `defaultOff={stdout:"inspect_broker_disabled\n",listeners:0}` from actual ordinary start.
- `topology`: repeated full qualify measurement, exactly equal to initial evidence.
- `cases`: ordered positive, exec, create, export, wrong-id, wrong-context, ro-only.
  Each exact `{name,clientRequest,response,before,after,requests,audit}`. The runner's
  `client_request` function defines exact observed method/path/mode; all go through
  the isolated caller and private raw broker ingress, NEVER directly to Engine.
  Positive/wrong-ID/context use private inspect route; exec/create/export use respective
  Engine-shaped forbidden routes. Wrong-ID is B, wrong-context is `unregistered`.
  `clientRequest.brokerMode=disposable`, except `ro-only-no-permit`: fresh isolated
  broker variant with merely socket `:ro` and no boundary permit, must deny. Keep
  counters cumulative across variants; do not replace real Engine with fake transport.
- Counters `before/after={adapter,received,forwarded}` are measured cumulative safe
  integers. Consecutive cases' counters join exactly. Positive increments ALL by1 and
  observed `requests=[{method:"GET",path:"/v1.47/containers/<A>/json"}]`. Every negative
  independently increments ALL by0 with `requests=[]`. No post-baseline administrative
  Engine traffic. Rate limiter must not mask authorization: denial audit reason must
  be invalid_request/authorization/disabled for the corresponding case, not overload.
- Positive response `{status:"checked",snapshot:<actual sanitized snapshot v1>}`;
  negatives exactly `{status:"not_authorized"}`. Runner recomputes the documented
  canonical sanitized hash with ASCII/fixed-schema facts and safe integers, checks
  nested output allowlists/types, and accepts no Env/labels/path/error fields.
- Full fixed-schema broker `audit` records: positive correlated allowed admission +
  checked publication; each negative one not_authorized admission, expected reason,
  dispatched=false. Correlations unique between cases. Unauthorized B is never logged
  as a verified target. Parser-close/missing audit evidence fails this candidate rather
  than silently weakening the requested proof.

**cleanup** — sent only after a qualified `run` was attempted, including timeout or
invalid response (start may be ambiguous). Additional field is exact enrolled
`resources`. Idempotently release only those revalidated proof-session identities.
Return exactly `{released:<same list>,remaining:[]}`. Failure becomes `CLEANUP_FAILED`
with `operator-action-required`, never a passing result. Before a run, no cleanup is
requested: runner must not release a pre-existing fixture just because qualify failed.

## Budgets/results and independent acceptance

Hard controller call ceiling 10s **including connect/send/receive**, absolute 120s total
with 10s reserved for cleanup, bounded 128KiB response, duplicate keys/non-finite JSON
rejected, no retry, stream, shell, dependency install or Engine fallback. Fixed status
output does not copy control exceptions/raw inspect/credentials. Safe candidate output
contains challenge/source pin/topology digest/sanitized snapshot hash and joined
counter/request/audit records for review; raw daemon data is never retained by runner.

- Missing enrollment/unsafe evidence: `TOPOLOGY_UNQUALIFIED`, exit1.
- Explicit fixture endpoint/Engine unavailable: `DOCKER_ENGINE_UNAVAILABLE`, exit1.
- Deadline/evidence/cleanup failure: fixed failure status, exit1.
- Valid operator-supplied evidence: **`EVIDENCE_CANDIDATE`, exit2**, `passed=false`,
  `realProofAccepted=false`, `productionEnabled=false`. Not fake PASS, skip or full
  acceptance. Independent reviewer must inspect actual trusted controller/observer
  source, OS measurements and real Engine counters before certifying real proof.

Do not close TASK5, mark full testing/done, or apply future DOC4 delta
`37ad928f-7309-4429-9e8e-b763c66659bb` based on this runner/test group. After a genuinely
qualified run and independent reviews, a separate task-sourced full resulting spec
may describe only proven behavior. Continue independent eligible tasks meanwhile;
API/LLM TASK13 belongs to its concurrent owner.
