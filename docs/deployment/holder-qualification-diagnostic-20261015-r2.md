# Independent correctness review — holder metadata diagnostic R2

## Decision and literal

**CORRECTNESS APPROVE ONE corrected read-only diagnostic attempt, conditional on independent security acceptance of the exact final source/literal. NOT EXECUTED.** No concrete blocker remains in the reviewed NET_NONE correction. This is metadata classification only, not qualification/adoption/recovery or production approval.

- New literal: `docs/deployment/holder-qualification-diagnostic-20261015-r2.sh`.
- SHA-256: `088458ea480023c0e8a211adb7618e5ea53d53c86e6d7f0c2ad0ae0370fecdea`.
- Required cwd: `/Users/vsevolod/Documents/startup/diplom`.
- After final security acceptance only: `/bin/sh docs/deployment/holder-qualification-diagnostic-20261015-r2.sh`, ONE foreground invocation with caller `timeout_ms=75000`.
- Shared60s, each client<=10s, <=6 fixed read clients, listing<=3 IDs. Listing4096B; combined streams65536B/client; encoded receipt4096B plus newline. External wall fence remains necessary; no universal I/O/daemon cancellation guarantee.

Previous draft shell `aa6a199f0499a6afce9556cfa724d5daa2de5b4e4974630a013fb8ffd8d5fe07` was NOT executed, is rejected/superseded for endpoint-truthiness mismatch, and must NOT be invoked. Its files remain unchanged as the draft record. This report supersedes its approval. Production successor-R2 shell59fe is separately SPENT: user reports holder/MIGRATION/PREDICATE_REFUSED, uncertain=true. No root cause, absence of prior SQL, or current runtime state is inferred.

## Verified current pins

All paths under `server/deploy/trust/`:

| File | SHA-256 |
| --- | --- |
| `diagnose_holder_qualification.py` | `8e051eeb3c7a4fa913d93a50e19dc21bf32884780d3102fe3cfe36897dce3eb8` |
| `test_diagnose_holder_qualification.py` | `e25c7a9e1e7ec78c7a91d83c4f0c6e72b5e40fe42400d9f9f9f37b606a4ca8a0` |
| `recreate_openrouter_key.py` | `72f6393d97b0a946bf2bb607e7f1d0c216d91fb36cfecf20fba9b83fd2c12994` |
| `test_recreate_openrouter_key.py` | `3abf97290344e9d18add867e07a378346922407885da373c43fde2f8a6c19ea2` |
| `discover_preservation_holder.py` | `4afb0bc484d34aca428fee956bd939d7b322727285eef0f721425849bb32a1f4` |
| `test_discover_preservation_holder.py` | `cc1a168804cb9a07f9c53724730bfbbaae7596c44c88743b0dc169f26a1bf312` |

Public hashes match the new pair and unchanged controller/transport pairs. Actual shell diff confirms executable changes ONLY the diagnostic source/test pins; interpreter, socket, args and controller pins unchanged. Diff exit1 denotes these expected differences, not failed hashing.

## NET_NONE parity correction

Authoritative current controller `qualify_holder`, HOLDER_NETWORKS, requires `set(networks) == {'none'}`. The corrected Go template checks cardinality1, ranges the map and compares ONLY the key with `none`; the endpoint variable is never tested. Thus a single none key projects true whether its value is empty, null or populated. Empty map, single other key and additional keys project false. Exactly one JSON boolean is emitted. No endpoint object, name or other raw network metadata reaches the receipt. The old truthiness-based index expression is removed.

Inspected the exact template, its insertion into CANDIDATE_FORMAT, unchanged boolean NET_NONE classifier, current authoritative predicate and new inert test source. Test cases cover none:{}, none:null, populated none, empty map, bridge-only and none+bridge. These are source/model fixtures, not an executed Go/Docker proof. **No tests/imports/diagnostic execution occurred.**

## Boundary remains narrow

Reviewed current source gate, packet, classifier, failure handling and main. Same one listing -> exact OLD API image defaults -> two named-volume baselines -> at most three returned exact-ID metadata projections. Empty listing returns immediately; fourth/duplicate/malformed ID refuses before more queries. No extra client, fallback or polling added. Controller remains read/hash-only, never imported. Verified captured transport is used only for Client/decode; its historical source gate/private metadata/discovery/main routines are not invoked.

Env remains in-memory exact order/null equality with bounded shape checking; no keys/values/counts/lengths/hashes escape. Raw client stderr is bounded/drained/discarded. Closed receipt/category/state and 37 true/false/null comparisons only, with validated public IDs. No private host paths/content/journals/DB/Env/keys/recovery reads, lock/scratch/pycache writes, SQL, app/helper invocation, provider/history operation or resource lifecycle/cleanup. Exact public Docker binary is verified before each child; explicit socket/clean environment/source-config absence gate unchanged.

The prior report's observable-profile analysis still applies, but **not its superseded source pins/literal approval**. Exact private journal/intent/name/backup ownership, cached historical baselines and surrounding controller fences remain NOT_OBSERVED. Null means missing/malformed prerequisite; current baselines cannot reconstruct the failed invocation. RUN_FALSE and RUN_TRUE are alternative observations. All observable matches still do NOT mean full qualification or establish a historical first failure.

## Next boundary / validation limits

Success remains `HOLDERS_CLASSIFIED_NOT_QUALIFIED`, `fullQualification=NOT_CLAIMED`, `privateBindings=NOT_OBSERVED`, `adopted=false`, `Env=EQUALITY_ONLY_PRIVATE`. No actual result is claimed. Independent security acceptance of these exact pins/literal is required, then ONE parent invocation and STOP. No result grants follow-up inspection, retry, repinning, adoption, cleanup or migration authority. All HOLDs/resources remain untouched.

Reviewer performed only public source/test reads, public SHA-256 and shell diff. Only writes: this NEW R2 report and paired NEW R2 shell. No source/spent-file/Git/tracker mutation, Docker/native/provider operation, tests/imports or private reads. No remote artifact ID claimed.
