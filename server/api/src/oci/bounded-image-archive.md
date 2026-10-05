# Closed nginx archive pipeline

This implements actual streaming layer acquisition, validation and receipt-bound
Trivy execution for **two exact closed candidates** in `NGINX_ARCHIVE_CANDIDATES`. It does not
open public upload/local-image/daemon access or public nginx admission. Existing
Alpine remote admission/parsers continue unchanged.

## Current qualification blocker

The actual pinned Trivy 0.69.3/signed DB proof on 2026-10-04 reports the old `b17b00f7…046f114` candidate as Alpine
3.20.6 with `EOSL: true`. The raw scan reports 83 vulnerabilities, but EOL is **not**
qualified checked OS coverage. Standalone vulnerability qualification terminates
`failed` with `unsupported / OS_EOL`; combined qualification is `partial` with
Secrets/SBOM checked and vulnerability coverage unsupported. Node inventory is not
present/proven and is never called checked. The old EOL pin remains a negative fixture.

The separately discovered `nginx:1.28-alpine` child `0dcc8882…98b30e3` / config
`dc73b49f…02e2bb5` is the second exact **unqualified** candidate. Actual bounded
preparation measured 25,950,947 compressed / 63,492,096 expanded bytes, 2,271 tar
entries and 63,511,040 archive bytes. Actual Trivy identifies Alpine 3.23.3 and
72 APK packages. Its false EOSL is omitted because pinned Trivy v0.69.3 defines
`Eosl bool` as `json:"EOSL,omitempty"` in `pkg/fanal/types/artifact.go`; this is a
verified schema interpretation, not a synthetic field or EOL override. Real
standalone and combined consumer/ledger/cookie HTTP positive assertions require
nonzero normalized CVEs. No universal enable flag or production opt-in exists.
The separate unseeded combined DOM proof is implemented in
`server/deploy/proof/test_nginx_dom_path.py` (recipe: `nginx-dom.md`). The
2026-10-04 author run recorded 209 normalized OS CVEs, 72 APK and report reload;
these dated counts are not timeless expectations or independent reviewer reruns.
The standalone consumer jobs above are internally seeded real scans, not browser
POST/launch proofs. Correctness review requested rework; approval is not complete.

## Boundaries

- One shared attempt transport budget covers metadata, token challenge, auth retry,
  redirect/error bodies and streamed layers: 160 requests, 112 MiB response bytes,
  180 s absolute preparation deadline. Existing gateway CONNECT/public-IP/TLS,
  exact hosts and scoped bearer/CDN credential stripping are reused. The sink is
  backpressured and failures/abort destroy the response/tunnel. No Range/resume or
  generic retry exists.
- At most 32 gzip layers, 32 MiB each, 96 MiB compressed total. Exact descriptor
  byte count/SHA-256 is checked before inflation. Single fixed-header gzip only;
  deflate consumption, CRC and ISIZE reject concatenation/trailing payload.
- Every expanded byte, including headers/extensions/padding/trailing zeros, is
  charged: 128 MiB per layer, 256 MiB total, 50,000 entries, 64 MiB file,
  64 KiB extension, 512-byte path/link/PAX field, 1,024 PAX records. Checksums,
  octal lengths, truncation/end markers, effective names/links and bounded PAX/GNU
  extensions are validated. Sparse/device/FIFO/unknown types and escaping entry
  names fail. Symlinks retain image-root semantics; no names or links are ever
  extracted/resolved on the host.
- Ordered config `rootfs.diff_ids` are compared to hashes of full inflated layer
  tar streams. Docker-save archive uses original verified config bytes, generated
  safe names and unchanged layers/whiteouts; no merged-rootfs reconstruction.
  Archive cap 272 MiB. Rehash immutable archive before every scanner stage.
- Generated private 0700 attempt trees, O_NOFOLLOW/exclusive file creation and
  conservative 448 MiB working reservations; compressed intermediates/consumed
  layers are deleted during preparation. `reservationPeak` is a conservative
  reserved bound, **not measured disk occupancy**. `scratchPeak` measures the
  scanner attempt tree (archive + private cache/temp), not all preparation phases.
  During scanning a bounded tree/available-space monitor aborts on over-budget
  writes; the existing 512 MiB tmpfs is the independent physical hard guard.
  Only ENOENT from disappearing enumerated descendants is tolerated while Trivy
  cleans temporary files/directories; root disappearance, symlinks, special types,
  non-ENOENT errors, depth/entry/byte/free-space violations remain fail-closed.
  A quiescent final audit runs after subprocesses close. Audit violations are
  SCAN_FAILED, not a synthetic timeout; real cancellation/deadline stays SCAN_TIMEOUT.
  Cleanup removes only the own attempt tree, including fanal/cache, never RO DB.
  Single-worker boot recovery removes only generated abandoned attempt directories.
- Prepare once per attempt; sequential fixed `trivy image --input` argv, no proxy
  or inherited credentials/daemon fallback. Actual binary version 0.69.3 required.
  JSON caps: Secrets 1 MB, SBOM 2 MB, CVE 8 MB; each stage 120 s, attempt 600 s.
  The consumer reserves a 627 s lease **only for nginx**, retaining Alpine timing.
- Actual JSON identity is archive ArtifactName + config ImageID + ordered DiffIDs
  and config rootfs; RepoDigests are absent. CycloneDX DiffID properties are
  unordered in actual Trivy, so exact multiplicity is checked, not fictitious
  ordering. No raw report identity is rewritten into remote RepoDigests.
- Clean Secrets (omitted/empty/meaningless Results) require meaningful bounded
  layer DiffIDs matching inspected image DiffIDs, not archive identity alone.
  Missing/unknown/malformed OS evidence fails with SCAN_FAILED; only validated
  Alpine EOSL=true is unsupported/OS_EOL. Omitted EOSL still means false in the
  pinned binary schema when the required OS/inventory evidence is valid.
- Effective local CVE overlay RAM is **2 GiB**, overriding the base stand's 1 GiB.
  These proofs validate that existing local resource envelope, not the judge's
  1-GiB target. No cap is silently changed to obtain a pass. A separately reviewed
  1-GiB memory proof or explicit resource-contract revision remains a release gate;
  neither nginx production opt-in nor whole-task qualification follows from this
  local proof. CPU1/PIDs128/512-MiB scanner tmpfs caps stay unchanged.
- Signature/hash/schema/freshness and RO DB inode checks precede actual CVE scan
  and are repeated afterward; freshness is rechecked after hashing/final scratch audit
    and with a clock-only guard in the fenced ledger transaction. Expiry demotes CVE
    to DB_UNAVAILABLE without discarding successful independent checks. Persist actual signed release identity, not current
  environment reconstructed on GET. Local attestation is not Aqua's signature.
- v10 ledger validates bounded normalized data/receipt, fences attempts, atomically
  stores independent outcomes/state/event, isolates subjects, supports replay,
  reopen and retention. API exposes normalized paginated secret/SBOM/CVE results
  and independent OS/Node/DB/check versions; no raw archive/report/advisory/URL.

## Reproduction and evidence scope

From repository root, with the existing private env and healthy stand:

```sh
python3 -B -m unittest server.deploy.proof.test_nginx_archive_path -v
```

The disposable worker uses **both** stand Compose files plus `stand.env`, RO source
and DB mounts and private disposable auth/ledger files with a fresh test JWT;
no live service recreation, ledger migration, JWT/key/volume reset or private-key
read. Six real scenarios cover supported standalone/combined CVE, standalone EOL,
combined EOL, missing DB configuration and wrong expected DB hash. Actual Nest
HTTP cookie registration, owner/foreign/anonymous routes, no-store, bounded SBOM
pagination, rejected public replay and attempt cleanup are exercised.
Chromium proves actual authenticated public POST rejection/repeat rejection,
server-derived nginx suggestion disabled and no selected target after reload.
That wrapper is **negative DOM evidence**, not positive browser qualification.
The separate `test_nginx_dom_path.py` uses isolated auth/ledger volumes and the
exact proof-only Nest profile for real login/search/selection/combined POST/report/reload,
without seeded scans or stubs; production remains default-off/unqualified.
A fresh signed DB is a prerequisite for positive CVE proof. An expired DB must
reject it, never be bypassed or re-signed to manufacture validation. No entire
TASK-2 acceptance, remote npm positive, complete adversarial/expiry matrix,
two-source provenance completion, three final approvals or NEW upstream rotation
is claimed. The mixed future spec delta stays unapplied.
