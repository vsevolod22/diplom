# Unused Docker cleanup — source-only draft, 2026-10-15

## Status and scope

NOT EXECUTED. Requires independent correctness/security/source/literal review.
Only the parent may run daemon operations, serially with the separately reviewed
exact paused4dc retirement and preservation controller. HOLD/locks/backups remain.
The stale 20-image/17-container summary is a test fixture scale, NOT a fresh fact.
No runtime queries, daemon mutations, private Env/DB/recovery/log reads, source
actors, Git operations or changes to existing deployment sources were made here.

New files:

- `server/deploy/trust/cleanup_unused_docker.py`
  SHA256 `ec6ae691cc31eed7dd049cb80299e45c3ba2c5b280713b88a297db740a04dfcd`
- `server/deploy/trust/test_cleanup_unused_docker.py`
  SHA256 `51f1890f2acb655a88ac730ae6536e7ebfed523b866a0f5e08be8bc027293bb5`

Validation: `python3 -I -B server/deploy/trust/test_cleanup_unused_docker.py` —
18 inert synthetic tests PASS, author-attributed, process creation mocked to fail.
The tests also hash/read only the exact public transport/source/test files and
construct the captured transport without invoking its client. No Docker binary
execution or binary/runtime probing occurred.

## Phase 1: new inventory-only literal for independent review

Required working directory `/Users/vsevolod/Documents/startup/diplom`.
Parent MUST supply external `timeout_ms=75000`; no retry/fallback/rerun is granted
by this document. This literal has NOT been run. The Python executable below is
the literal used by the existing reviewed discovery script, not newly probed here.

```sh
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -I -B \
server/deploy/trust/cleanup_unused_docker.py \
--inventory-once \
--source-sha256 ec6ae691cc31eed7dd049cb80299e45c3ba2c5b280713b88a297db740a04dfcd \
--test-sha256 51f1890f2acb655a88ac730ae6536e7ebfed523b866a0f5e08be8bc027293bb5
```

Bounded fixed argv:

1. `container ls --all --no-trunc --size --format <explicit projection>`:
   ID, displayed image, state, name and size only. At most 80 rows.
2. `image ls --all --no-trunc --format <explicit projection>`:
   immutable ID, repository/tag, size only; grouped into ID/tags/size and
   `listedReferences` (container IDs whose displayed image matches the ID/tag).
   At most 100 rows, including repeated image IDs under distinct tags.

No filters conceal other containers/images. At most two clients, each at most
10s; shared 60s deadline includes public source and binary checks. Each client
gets 32768 bytes INCLUDING discarded stderr, so total transport is at most
65536 bytes; the final receipt is separately limited to 65536 bytes. Any malformed,
truncated, over-cap, duplicate or unexpected metadata fails closed, without a
follow-up query. Empty listings are supported; overflow does not trigger paging.
No broad inspect, Env, args, labels, mounts, logs or private contents are requested.

**Important:** `container ls .Image` may be a mutable display tag. Its relation to
current image tags is not an authoritative immutable-reference graph. The receipt
therefore says `referencesAuthoritative:false` and `removalAuthorized:false`.
An empty `listedReferences` list is NOT unused/obsolete/ownership evidence and
must not be used as a deletion selector. Two CLI listing calls cannot establish
that stronger graph. No automatic candidate selection is implemented.

Transport is executed only from captured bytes verified against discovery SHA256
`4afb0bc484d34aca428fee956bd939d7b322727285eef0f721425849bb32a1f4`
and discovery-test SHA256
`cc1a168804cb9a07f9c53724730bfbbaae7596c44c88743b0dc169f26a1bf312`.
The discovery main/source gate and preservation controller are never invoked.
Its fixed socket, exact Docker binary/hash/stat pin, bounded pipe transport,
clean environment, explicit host and empty context are retained. The helper
refuses any `server/deploy/trust/config.json` metadata entry before loading and
before every client; no ambient/private Docker config is selected. Pin/config
failures stop; do not search for a different executable/endpoint or repin silently.

## Phase 2: future exact removal, NOT authorized by the inventory literal

No real deletion plan, image selection or removal literal is provided here.
After reviewing the inventory, an independent reviewer must establish exact
obsolete-image provenance. Names/tags/age/no-reference alone are insufficient.
Recovery/source/proof actors and images remain retained unless exact provenance
separately authorizes obsolete ownership; this helper never removes ANY actor.

The implemented narrow removal interface accepts ONE canonical JSON plan as a
literal argument, its SHA256, source/test hashes and the explicit
`--consent-exact-obsolete-image-removal` flag. Exact plan fields:

- `version`: integer 1;
- `image`: full `sha256:` immutable image ID;
- `tags`: exactly one reviewed nonempty repository:tag;
- `provenance`: exact attestation
  `reviewed-obsolete-not-recovery-source-proof-or-candidate-parent`.

The attestation represents external reviewed evidence, not proof inferred by
this program. It must not be supplied merely to make a guard pass. The program
always rejects all **five original plus three candidate image IDs** from the
HOLD handoff, even if another plan attests them obsolete. Untagged and multiply
tagged image removal is deliberately unsupported. All containers, including
active/paused/created/exited/unknown-ownership recovery/source/proof actors, are
outside deletion scope. There is no container-retirement branch.

Future exact removal performs at most four clients, each bounded to 10s and
16384 transport bytes including stderr (aggregate at most 65536), shared 60s:

1. Fresh complete image listing; exact selected ID and single tag must match.
2. Fresh complete all-container listing, with the same 80-container bound.
3. If nonempty, one `container inspect --format` projection of ONLY `.Id` and
   immutable `.Image` for EVERY exact full listed container ID. Every ID must be
   returned once; no omitted/added actors, mutable tags or extra fields accepted.
   A reference in ANY state refuses removal, including a moved/missing tag.
4. ONE `image rm --no-prune <exact-full-immutable-ID>`, non-force. Docker's own
   conflict checks remain mandatory. `--no-prune` prevents cascading untagged
   parent deletion; there is no image/build/volume/container prune or force flag.

The parent must exclude concurrent daemon writers throughout these checkpoints
and the final removal; these are not an atomic graph snapshot or a new lock.
Candidate ancestry is not inferred from tag listings. Untagged candidates/parents
are never selected; non-force child/reference conflict checks are not bypassed.
Any attempted-removal failure, timeout, malformed acknowledgement or extra
unexpected acknowledgement means manual reconciliation/HOLD, with no post-query,
retry, fallback, compensating mutation or automatic continuation. Strict success
acknowledgement permits only the selected tag's untagging and exact ID deletion;
registry digest/other unexpected acknowledgements also stop for manual review.
Success is not a post-inventory, integrity proof or service recovery claim.
