# Public image-only 8081: existing LLM backend — 2026-10-20

> **CURRENT OPERATOR GATE: NEW `initialize` HOLD after one reviewed continuation.** Audit `deploy-8d83a8806715c2f0fa575efedee1b0af`; initializer is created/never-started. Do not retry ordinary `up` or the original checker/continuation, start/remove the helper, remove locks, prune images or reset stores. The original checker prefix no longer matches. Current source fixes do not authorize live recovery and the pre-fix API candidate is stale. See [current status and required separately reviewed next path](public-product-status-20261021.md). All deployment/checker command examples below are historical and **not instructions for the current HOLD**.

## Scope / implementation

This completes the **existing** summary + durable owner/scan chat backend for the explicitly composed public image API. No second chat service, frontend, scanner, ledger migration or tracker mutation was introduced. A later, explicitly authorized source-only public deployment layer is described below; the common/default-off 8080 composition remains unchanged.

The one public wiring file changed outside `server/api/src/llm/` is **`server/api/src/oci/public-image.module.ts`**:

- Registers the existing `LlmController`, identity, report reader, runtime, quota runtime and URL-scoped safe exception filter against the **single existing `PublicImageScansService`**.
- Does not import `LlmModule` / `ScansModule`, or expose runtime/host routes.
- Installs the existing bounded history raw intake **before** the ordinary Nest JSON parser, via `configurePublicImageIngress`. The public entrypoint already calls this function with `bodyParser: false`.
- Selects public report grammar by an internal DI token, not by environment/request data. A persisted public receipt/status selects the public report discriminator `public-hub-amd64-v1`; legacy receipts served through the public API keep their original grammar.

`BrowserIdentity`, `LlmService` and `HistoryService` now receive the existing composition-only local origin token. Public all-local-account mode uses exactly `http://127.0.0.1:8081`; default/LOCAL composition retains its existing origin. Bearer/cross-site/Origin/enrollment/session/owner gates remain in force.

## Report identity and model data

`report-context.ts` retains the owner-scoped terminal image report boundary, read-only SQLite attempt/scope metadata and `data_version` fencing across **all** Secrets/CVE/SBOM pages. `reportVersion` hashes owner, scan, digest, platform, attempt and complete authoritative projections locally. Owner IDs, raw projections and raw scanner text are not sent to OpenRouter. A tag or caller-supplied tuple never becomes report authority.

For explicit public reports:

- All 11 worker-supported package ecosystems are accepted. Only `CVE-YYYY-NNNN…`, or `TEMP-1234567-ABCDEF` **with ecosystem `deb`**, pass the identifier boundary.
- Each safe public vulnerability has `identifierKind: 'cve' | 'debian-temp'`; the legacy `cveId` field name is retained for compatibility. TEMP remains an unmapped Debian advisory, **not a CVE**. No CVE mapping/reference URL is fabricated. Existing advisory validation also refuses fabricated TEMP references.
- `identifierCounts: {cve, debianTemp}` is computed from the **whole paginated persisted finding dataset**, checked against owner-scoped public status, and present only for checked vulnerability coverage. These count finding **rows**, not unique CVE IDs or packages.
- `findingCount`, `findingCounts.byCheck` and `findingCounts.bySeverity` describe all persisted findings, never the context subset. A per-check count is `null` when not checked; unsupported/failed/not-requested coverage is not a verified zero. SBOM component counts stay in coverage.
- DB identity plus validated DB policy receipt/status/warnings, OS/node unknown/unsupported states, config rule/subcoverage and failed checks remain explicit. DB receipt timestamps are report evidence, not a claim that an old scan used today's DB.
- No package/version strings, advisory descriptions/titles/URLs, environment/config values, raw matches, credentials or scanner output are projected to the model. `fixedVersionReported` means only that a scanner reported a value, not that a particular upgrade is safe.

The complete local dataset is bounded (1000 findings, bounded pagination/canonical hashing and 4 MB public local projection). The actual serialized model request is separately bounded by policy and quota; a local projection is not itself the egress envelope.

### Bounded context without false completeness

`summary-context.ts` selects **all CRITICAL/UNKNOWN findings**, including findings with a CRITICAL advisory assessment, then at most 32 optional findings ordered by severity and stable finding ID. Optional entries are removed until the **actual prepared request plus its 1024-token framing allowance** fits the quota input ceiling and request-byte limit. Mandatory overflow returns `409 LLM_CONTEXT_LIMIT`; it never silently drops critical evidence. Legacy summaries retain their all-evidence behavior.

Existing chat selection keeps all critical/unknown evidence, all user questions/constraints/decisions and their original source bindings; it selects at most 16 optional findings by question relevance, then severity/ID. Recent model explanations are optional and removed before mandatory user memory. Historical sources remain historical, never rebound to a new report. No response/authorization/consent is cached.

Whole counts/coverage are preserved alongside selected findings and explicit omissions. The system instructions label report/history/question/decision data untrusted, forbid tools/URLs/secrets, explain TEMP versus CVE, and prohibit claiming that selected evidence is exhaustive. Summary and chat validate reply tuple/citation membership against the **sent subset**, not omitted findings. Interpretations remain hypotheses, not scanner facts or accepted decisions.

Public context GETs expose whole counts/coverage without reading the key. Public summary JSON adds `findingCount`, `findingCounts`, optional `identifierCounts`, `coverage`, and `contextSelection` (`totalFindings`, `selectedFindings`, `omittedFindings`, `strategy`, `selectedFindingIds`). Public chat JSON adds the same totals/coverage and existing chat `contextSelection` (`findings`, `explanations`, `selectedFindingIds`; these are omission counts). Existing NDJSON frames are unchanged; obtain full counts/coverage through context GETs.

## Existing HTTP / durable conversation contract

Prefix: `/api/v1/browser/scans/:scanId/llm`.

| Method / suffix | Existing contract |
| --- | --- |
| GET `context`, `usage` | Owner/report-authenticated policy disclosure or bounded quota snapshot; no provider/key read or reservation |
| POST `summary` | `{reportVersion, consent:{accepted:true, policyVersion}}`; 1024-byte JSON gate; request-scoped consent; summary remains stateless |
| GET `history` | Durable owner+scan head, sanitized public turns/decisions/pending marker |
| GET `chat/context`, `chat/usage` | Current report binding, epoch/revision, chat policy disclosure or quota state |
| POST `chat` | `{epoch, revision, mutationId, reportVersion, question, consent:{accepted:true, policyVersion}}`; existing body/question limits and CAS/idempotency |
| POST `history/decision` | `{epoch, revision, mutationId, reportVersion, text, findingIds}`; explicit user decision, never an automatically accepted model suggestion |

Chat policy version is intentionally distinct from summary policy version. Use the version returned by the matching context endpoint; never derive it client-side. There is no model/provider/prompt/context/URL override in these DTOs.

Chat uses the existing durable history SQLite store, completion space reservation, pending/complete/failed/cancelled/interrupted lifecycle, replay deduplication and existing optional `Accept: application/x-ndjson` delivery. NDJSON is a guarded delivery of a validated **completed** response, not native provider streaming. A repeated `mutationId` does not call the provider again; GET history recovers a committed response after a disconnect. Reopened public citations now validate all supported ecosystems and retain the exact TEMP/CVE discriminator.

Session/owner/report/policy are rechecked before chat dispatch, after generation and at actual publication writes. Provider failure/invalid output never becomes fake success. Validated usage is accounted even if publication fails or the session is revoked; a dispatched uncertain attempt is not timer-refunded. Missing/corrupt quota/history state refuses safely, without resetting capacity. Existing safe error codes/no-store/parser redaction remain in place. Zero findings, including incomplete/unknown coverage, refuse locally with `LLM_NO_EVIDENCE` before provider/key construction.

Questions/decisions/history remain untrusted user text. The existing bounded cleaner rejects URLs, controls, key-like strings and credential assignments; it additionally rejects bearer/basic credentials, common credential-value phrases and raw scanner JSON field shapes. This is **not a general DLP guarantee** for arbitrary natural-language private information: do not paste credentials or raw reports into chat. The server never automatically injects raw evidence or private config, and the helper's provider key never enters user history/context.

## Safe public configuration helper

New helper: `scripts/public-llm-config.py`; its fixed host directory is:

```
~/.local/state/diplom-public-images/llm/
  llm.env         # non-secret settings, mode 0600
  openrouter.key  # raw key + one LF, mode 0600
```

The directory is mode 0700 and outside this Git workspace. No legacy `.local-stand`, `.local-auth`, retained holders or old env/key file is searched/read/imported. `scripts/set-openrouter-key.py` remains the legacy replacement helper and is **not** the public setup path.

Operator commands from the repository (no secret arguments):

```sh
python3 scripts/public-llm-config.py --prepare
python3 scripts/public-llm-config.py --set-key
python3 scripts/public-llm-config.py --status
```

- `--prepare` explicitly selects the catalog-verified Xing/Phala free-only profile and finite quota/history settings in `llm.env`; it does not activate anything or initialize databases. Executed on 2026-10-21 with authorization: config created; metadata-only `--status` reports configuration present **true**, public key present **false**. No existing key was opened.
- `--set-key` requires an interactive TTY and two matching hidden inputs. Getpass's echoed-input fallback, stdin pipes, path/key/extra arguments are refused. No key is printed, passed in argv, or sent to a browser/network.
- Both files are created exclusively, never overwritten/truncated/renamed. Existing key contents are never opened by this helper. State directory components cannot be symlinks. Unsafe file aliases/modes fail closed; interrupted/partial files require operator review, not automatic repair.
- `--status` reports only metadata-derived presence booleans, never reads key bytes. Do not use `cat`, shell command substitution, `docker inspect`, or browser config to verify the key.
- Key replacement/revocation is a separate explicit operator lifecycle. The helper intentionally has no overwrite/rotation path.

## Integration contract for the deployment owner

**No live Docker/Compose lifecycle command was performed by this agent.** The original implementation used offline plans/tests. The later explicitly authorized read-only actual preflight is documented below; it used bounded public-resource metadata only, without intent/lock creation, lifecycle or stand-state writes. The deployment owner controls review, isolated initialization and activation.

### Non-secret API env

Load **only the new** `llm.env` into the new public API process, alongside its independently managed public auth/scan settings. Do not merge any retained/legacy private env or reuse a holder. No `VITE_*`, worker, gateway or browser receives LLM credentials or the LLM env file.

The generated profile explicitly selects a supported pair verified against official unauthenticated catalog metadata on **2026-10-21**, using the existing OpenRouter adapter (not a second chat system):

- Endpoint fixed in source: `https://openrouter.ai/api/v1/chat/completions`.
- Exact model `xingchen-agi/xing4.0-29b-a4b:free`, exact endpoint allowlist `phala`, revision `public-8081-xing-phala-v1`. No cross-pair combinations are admitted. Historical Apodex/Novita remains supported for legacy explicit configuration, never as an automatic fallback; its current catalog response has **zero endpoints**.
- `LLM_FREE_ONLY=true`, `LLM_ROUTING_APPROVED=true`, `LLM_REGION=global`, `LLM_RETENTION=no-storage`; request/input/output/request-price caps all exactly zero.
- `data_collection:deny`, `zdr:true`, no fallback, required parameters, JSON output, disabled/excluded reasoning. No endpoint override, router model, paid fallback, retry or automatic model switch.
- Request 262144 bytes, response 65536 bytes, deadline 30000 ms, max findings 1000, output 2048 tokens.
- `LLM_QUOTA_REQUEST_INPUT=65536`; UTC-day per-user input/output 1048576/32768, per-scan 262144/16384, zero cost allowances. Remaining receipt/storage/headroom values are in the helper and tested by the real quota parser.
- Existing history enable/revision/authority settings are included. Policy settings/revision changes invalidate matching consent.

Public browser auth still needs its separately approved `AUTH_ORIGIN=http://127.0.0.1:8081`, exact local HTTP policy and enrollment configuration. The LLM helper does not create account credentials or scan JWT secrets.

### Secret mount

`OPENROUTER_API_KEY_FILE=/run/secrets/public_openrouter_key` selects the new fixed **API-only read-only file mount** sourced from the new `openrouter.key`. Leave `OPENROUTER_API_KEY` **unset**; specifying both sources refuses instead of choosing one. Public-composed `LlmRuntime` additionally rejects env-key/unapproved file sources before provider construction and rejects any non-free policy, even if a legacy paid policy would otherwise parse. Legacy explicit paid/env-key support remains unchanged for other compositions; there is no fallback from a failed public file.

The runtime reads this file lazily only after owner/explicit-consent/freshness checks, not during startup/context/usage/readiness. It must be a regular non-symlink, single-link file, mode 0400 or 0600, owned by the API UID or root, **and readable by the actual API UID**. Contents are 16–512 ASCII key characters plus exactly one LF; no dotenv/BOM/CRLF/extra records. All failures become generic configuration-unavailable responses.

Do **not** use a Docker Desktop bind of the host-owned 0600 key for the actual UID 65532 API, or rely on Compose file-secret uid/gid/mode remapping. Use the isolated stdin-to-named-volume mechanism below. Never solve access with chmod 0644, an env substitution, a credential-printing entrypoint, or an API running as root. Do not mount the host state directory or key into worker/UI/gateway/build contexts.

### Durable public state / initialization

Provide **new public-only** auth/history/quota storage at `/auth` and the new public scan ledger at `SCAN_LEDGER_PATH`. Never attach retained auth/ledger volumes to initialize this path.

Required existing API paths:

- `/auth/llm-usage.sqlite` — existing quota initializer `src/llm/quota-init.ts --initialize`.
- `/auth/llm-history.sqlite` — existing history initializer `src/llm/history-init.ts --initialize`.

Run those operator entrypoints once, network-none, as the eventual API UID with its new `/auth` mount and approved non-secret policy env. No provider key mount is needed for either initializer. These are one-shot operator jobs, **not application startup migrations**; runtime opens only initialized files. Both use owner-only files, DELETE journal/FULL durability, bounded space and fail closed. Keep at least the configured 128 MiB free headroom plus main/journal budgets. Preserve the public history/quota files and their SQLite state through deployment. Do not reset them to clear an error/quota or blindly rotate a restored lineage.

The configured history authority requires **one public API instance**, no overlapping history writers during operator restoration/lineage operations, and separate explicit lifecycle decisions. History capacity is finite (8 MiB main, 128 heads, 256 turns/head); capacity refusal must not silently delete old decisions. Public worker does not need the `/auth` mount.

### Egress

Reuse the existing verified CONNECT transport and gateway source (`server/deploy/gateway/openrouter.py` / `openrouter.Dockerfile`) in the **new isolated public composition**:

- API resolves **`llm-egress:8080` on an internal isolated network** to the new API-only gateway. This fixed internal gateway port is not the old host UI/API port and must not point at a retained holder or be host-published.
- Gateway permits only `CONNECT openrouter.ai:443` and has the outbound DNS/TCP443 access required by the existing reviewed proxy policy. API has no direct outbound internet/fallback; worker/registry gateway cannot use this LLM gateway.
- API verifies TLS/SNI `openrouter.ai` with ordinary trusted CA verification, then POSTs only the fixed path. No MITM CA/TLS-disable env, ambient proxy or redirect relaxation. Bearer credential travels inside verified TLS; the CONNECT gateway does not receive it in HTTP proxy headers.
- Keep ordinary public registry egress separate; enabling LLM is not permission to broaden scanner egress.

Provider-reported zero cost and retention declarations are **not invoice/privacy guarantees**. Availability/model catalog may change; current code refuses unexpected model/usage/finish/content instead of relaxing the contract. No live provider call, native public-8081 activation, actual mount ownership or container-egress qualification is claimed here.

## Docker Desktop: private stdin → fresh UID65532 named volume

New operator entrypoints (not executed against Docker here):

- `scripts/public-llm-provision.py --plan --image <approved-local-sha256-image-ID>` — **offline** command plan only; no Docker command and no key open/read.
- `scripts/public-llm-provision.py --provision --image <same-approved-local-sha256-image-ID>` — explicit later operator action. The image ID must be `sha256:` plus 64 lowercase hex characters, already locally available and audited to provide `/usr/local/bin/python3` with stdlib. There is deliberately no guessed/default image, pull, build, tag, arbitrary source path, destination volume argument or existing-holder import. Angle-bracket values here are documentation placeholders, not executed commands.
- `scripts/public-llm-key-init.py --initialize` is the reviewed source mounted read-only into that init; do not run it as a host key-copy command.

The mechanism is concrete:

1. Host helper pins **only** `~/.local/state/diplom-public-images/llm/`, locks the private directory, and opens its fixed `openrouter.key` with O_NOFOLLOW/NONBLOCK. It verifies owner/0600/single-link/regular/17–513-byte metadata with fstat. It does not read any secret bytes into host Python memory.
2. Generate a fresh `diplom-public-8081-llm-key-<random32hex>` name. An exact-name volume-list check refuses a collision; create a **new** local named volume labelled `diplom.public-llm=key-v1`. No old volume/container is inspected, entered, stopped or reused. Docker context is explicitly `desktop-linux`; inherited `DOCKER_HOST`, proxy and provider env are not passed through.
3. Run the approved local image with `--pull=never --network=none --read-only --user=0:0 --cap-drop=ALL --cap-add=CHOWN --security-opt=no-new-privileges --pids-limit=32 --memory=64m --cpus=0.5 --ulimit=core=0:0 --log-driver=none --stop-timeout=1 --interactive --rm`. No TTY, shell, env file, Docker socket, auth volume, API/worker network or host key mount. The sole writable mount is the fresh volume at `/public-llm-secret` with `volume-nocopy`. The sole source bind is the reviewed initializer Python script, read-only. Entry point is overridden to isolated Python (`-I -S -B`), with site hooks and bytecode disabled.
4. Pass the already pinned host key FD **directly as Docker stdin**, not as argv/env/substitution or an output pipe. Init reads at most 514 bytes from stdin, accepts only the fixed raw-key+LF format and an empty safe destination, creates `public_openrouter_key` with O_EXCL/O_NOFOLLOW, fsyncs it, chmods to **0400**, and chowns to **65532:65532**. The volume directory becomes **0500**, **65532:65532**, and is fsynced. No overwrite, alias, repair or rotation path exists. The init has a 15-second alarm, the CLI a 45-second timeout; failed/partial volumes must be quarantined for operator review, not mounted or silently reused.
5. Child stdout/stderr are DEVNULL, Docker logging is disabled, core dumps are disabled, exceptions are fixed-text without child diagnostics. The host key remains 0600 and unchanged. Only after successful init, create exclusive mode-0600 **non-secret** `key-volume.json` in the public state directory: volume name, fixed target, uid/gid/modes, image ID; **no key/hash/prefix/last-four**. Existing receipt refuses another provision. A failure never publishes a success receipt or removes existing resources.
6. Deployment owner reads **only this non-secret receipt** to select the external volume. Mount it **API-only read-only at `/run/secrets`**, `volume.nocopy: true`, with the API running as **65532:65532**. Set only `OPENROUTER_API_KEY_FILE=/run/secrets/public_openrouter_key` (never env-key); do not mount the host source. Keep key volume separate from writable `/auth`, worker, gateways and UI. No API startup copier/chown or root permission is needed.

Trust boundary: the approved image, Docker Desktop daemon and local operator are trusted; a privileged daemon or hostile chosen image could read a mounted secret. This is ordinary local named-volume storage, **not** a claim of encrypted Docker Swarm secrets. No default image or live mount ownership validation has been invented. Offline tests exercise real synthetic file operations, the exact UID/GID contract, permission/alias/format failures and a fake child receiving only synthetic FD stdin; actual Docker UID65532 readability remains an explicit deployment qualification.

## Provider catalog evidence and remaining external blockers

Official unauthenticated sources queried with bounded requests and no Authorization headers/key/state reads:

- `https://openrouter.ai/api/v1/models`
- `https://openrouter.ai/api/v1/models/apodex/apodex-1.1-mini:free/endpoints` — HTTP200, exact model ID, **endpoints: []**. HTTP200 alone is not availability.
- `https://openrouter.ai/api/v1/models/xingchen-agi/xing4.0-29b-a4b:free/endpoints` — exact model ID, Phala endpoint **tag `phala`**, status **0**, context 262144, max completion 235929, prompt/completion prices **0/0**. Advertised `response_format`, `reasoning`, `include_reasoning`, `max_tokens`, `temperature`; observed 5-minute uptime100% is metadata, not a generation probe.
- `https://openrouter.ai/api/v1/endpoints/zdr` — contains the **same model ID + Phala tag**, with zero prompt/completion pricing and the advertised parameters above. This intersection, not a provider-name guess, supports the explicit profile. See official `https://openrouter.ai/docs/guides/features/zdr`: `provider.zdr=true` filters to ZDR endpoints and unknown policy is treated as retaining. Keep OpenRouter account prompt logging opted out; no plugin/tools are enabled here.

Google AI Studio's free Gemma endpoint was not selected merely because it is free: general endpoint metadata does not establish ZDR, and official ZDR documentation excludes AI Studio under Google ZDR. No arbitrary new profile/router/paid option or privacy relaxation was added.

These are catalog declarations only. No authenticated generation, JSON/model-response identity compatibility, account eligibility, current free rate capacity, invoice or contractual privacy guarantee has been verified. Routing still sends exact `only:[phala]`, no fallback, deny collection, ZDR, required parameters, all-zero `max_price`, and disabled/excluded reasoning. Unexpected response model aliases, nonzero/missing cost, reasoning/content/schema/citation faults remain fail-closed. An unavailable endpoint or account constraint does **not** authorize purchasing credit, paid fallback, retries or relaxed retention.

**Current exact activation blockers:** public key absent; no secret volume provisioned; approved local initializer image ID not supplied; public history/quota mounts and one-shot initialization plus isolated CONNECT egress still belong to deployment owner. No live Docker lifecycle was authorized/executed. Key entry must be performed privately by the operator with `--set-key` in a real terminal, never in agent tool arguments or browser UI.

## Credential-free UI readiness fallback

New route in the **existing** LLM controller:

`GET /api/v1/browser/scans/:scanId/llm/readiness`

Authenticated, owner-scoped, persisted public report required; foreign owner/scan404 and anonymous401. No-store. If the public reverse proxy uses a suffix allowlist, the deployment owner must include this GET suffix alongside the existing LLM routes; no new credential/header transport is needed. Returns `scanId`, `digest`, `platform`, `reportVersion` plus:

```json
{
  "status": "setup-required",
  "localReady": false,
  "blockers": ["public-key-required", "history-store-unavailable"],
  "credential": "missing",
  "quota": "available",
  "history": "unavailable",
  "provider": {
    "checkedOn": "2026-10-21",
    "liveVerified": false,
    "status": "catalog-listed-unprobed",
    "model": "xingchen-agi/xing4.0-29b-a4b:free",
    "endpoint": "phala",
    "zdrListed": true
  },
  "generationVerified": false,
  "requiresConsent": true,
  "acceptsCredentials": false,
  "setupAction": "operator-public-file-configuration"
}
```

This is an example with missing key/history; actual booleans/blockers reflect local checks. `status` is `setup-required` or `locally-configured`; the latter means only `localReady:true`, **not** successful provider authentication/generation. `credential` is `unconfigured|missing|unsafe|metadata-valid`: only lstat of the fixed approved mounted path, never a key open/read or format/authentication proof. Root-owned0400 on a non-root API is unsafe, not readable-ready. No env values, file paths, credentials or raw store errors are serialized.

Blocker vocabulary: `configuration-required`, `public-key-required`, `public-key-unsafe`, `quota-store-unavailable`, `history-store-unavailable`, `provider-profile-unavailable`. Provider snapshot status is `catalog-listed-unprobed`, `no-catalog-endpoints` (historical Apodex) or `unverified-profile`. Catalog snapshot is static/source-dated, not a live uptime monitor. It never silently switches profiles. `quota:available` means initialized/validated store, not a guarantee of admission: use the existing owner usage endpoints for remaining capacity/fit.

Readiness deliberately does not need a history **head**, consent, key or network access. It validates the existing quota snapshot and history store (normal expired-turn recovery may occur), never initializes a missing DB, reserves quota, creates a turn or calls a provider. Existing history/context503 semantics remain intact rather than fabricating an empty conversation when durable state is absent. UI can call readiness before chat context, or after a context503, display a **connection setup required by operator** indication and disable generation. There is no credential-entry/browser setup POST endpoint, no second chat state, and no reason to discard saved history or weaken consent. Once setup is complete, obtain the existing fresh context and use its exact consent/report/epoch/revision contract.

New HTTP tests prove readiness remains200 with absent/unusable history/quota and disabled configuration, owner denial, bindings, redaction and zero provider constructions/sends. New profile tests cover exact pair/no cross-pair, immutable zero-price/ZDR wire and strict single-attempt response identity; Python tests use no Docker daemon or real key.

## Source deploy integration — 2026-10-21

### Files and scope

- `scripts/public-llm-stand.mjs` — import-safe pure model/selector/validator exports plus a concrete reviewed-maintenance entrypoint.
- `scripts/test_public_llm_stand.mjs` — offline model/engine-policy tests and native disposable SQLite init/backup/export/restore tests.
- `server/deploy/compose.public-llm.yaml` — **fixed** public overlay. Existing six services remain, `llm-egress` is seventh; exactly two additional own networks: `dip-public-images_llm_internal` (internal) and `dip-public-images_llm_uplink` (gateway only).
- `server/deploy/public-stand.Dockerfile` and `public-stand.nginx.conf` — public-only web build/config. History gate1, runtime gate0, bounded anchored UUID LLM GET suffixes `context|usage|readiness`, `access_log off`, preserved incoming auth headers for backend rejection, existing bounded chat/decision/NDJSON behavior. No request-body or credential logging was introduced. The public Dockerfile has an explicit frontend build closure (source/public assets, Vite/TS/HTML manifests and the two imported runtime DTO/JSON contract files), not `COPY . .`; env/state/scripts/tests never enter its build filesystem. Its deploy typecheck excludes unrelated test/config roots, without enabling runtime ingress.

`server/deploy/stand.nginx.conf`, `stand.Dockerfile`, `compose.public-images.yaml`, the main launcher and CVE scripts were **not edited by this agent in this integration pass**. Parallel owners may have their own changes. No common 8080 gate was enabled.

### Fixed configuration and optional key mount

The module reads only the approved external **non-secret** `llm.env` and optional **non-secret** `key-volume.json`. It does not open or even stat the host `openrouter.key`. Exact name/value equality with the config helper's CONFIG is tested: duplicate/unknown variables, dotenv expansions/quoting, endpoint/paid/provider/key/env/proxy overrides refuse. The API receives the fixed validated map, not a broad `env_file`. Config is never dumped. Source state must remain outside the repository, owner-only, no symlink ancestors.

Receipt absent is a supported mode: **no key volume declaration or mount at all**. The API still gets the fixed file-source setting; readiness reports missing key; context/history remain usable after store initialization, and consented generation refuses configuration-unavailable before provider dispatch. The gateway can run without credentials. No key is mounted into helper/worker/gateway/web/build.

Receipt supplied selects only a `diplom-public-8081-llm-key-<32hex>` local volume with the provisioning label; the API alone gets external `public_llm_key` → `/run/secrets`, readonly + nocopy. No fallback to a host bind or environment key. A missing→supplied transition is allowed; arbitrary replacement of an already-recorded key volume is refused (rotation requires separate review).

Persistent integration metadata lives under the existing ignored public state:

```
.local-public-images/
  llm-profile.json       # canonical {version:1,keyVolume:null|approved-volume-name}
  compose.llm-env.json   # generated exact non-secret API map + optional readonly volume
  compose.images.json    # existing shared immutable pin format, now seven service IDs
  llm-deployments/
    deploy-<32hex>/
      fenced/{core,llm}/
      before-api/{core,llm}/
      after-api/{core,llm}/
      complete.json
```

The `llm/` group is absent in the initial fenced backup only when both stores truly do not exist. All snapshots/manifests are private 0700/0600, never public evidence or status output. Within the private export protocol only, `core/auth.sqlite` means accounts, `core/ledger.sqlite` means scans/reports; `llm/auth.sqlite` means history and `llm/ledger.sqlite` means quota. Live paths remain unchanged.

### Concrete maintenance transaction

`up` deliberately requires an **established public stand**, either uniformly healthy/running or uniformly cleanly stopped, with a valid public profile, existing JWT, fully inspectable immutable current image pins and exact runtime/mount/network authority. It is not first-ever public bootstrap, mixed/unclean-state or uncertain-HOLD recovery, or permission to adopt retained storage. If CVE is enabled, the binding must already be public v2 (no LOCAL trust/release fallback). First LLM integration requires `--build`; later missing-key activation can use existing validated images.

1. Acquire the **existing shared public lock** via import; honor all existing recovery/HOLD guards. Read the existing public profile/JWT through the existing helpers, pin the local Unix engine endpoint once, and validate **all historical image IDs before any stop/build**. Missing image metadata refuses before build; there is no container-config/tag/historical-image recovery.
2. Fence reviewed source files and source-tree membership, config/receipt, JWT/profile/CVE/pin files, private directory identities and candidate overlays. Check exact namespace and foreign consumers before mutations. Record durable uncertainty intent.
3. For running entry, stop **web first** to keep admissions closed across replacement and preservation. Gracefully stop API (60-second allowance), drain jobs/outbox/leases on the original worker, then stop worker. API/worker/initializers require exit0; readonly Python gateways/web may also have normal SIGTERM exit143. Require pid0, no OOM/restart/pause/dead/runtime error and unchanged execution/control identity. For fully stopped entry, validate every prior ID/control and clean exit plus finite started/finished epoch; do not stop again, require stale API health, exec into or restart a writer to probe it. The same mandatory readonly network-none native snapshot proves ledger quiescence. Busy/unclean/uncertain outcomes retain HOLD, not an automatic restart or data reset.
4. Before build or store initialization, use a fresh validated network-none UID65532 readonly/nocopy helper with the **original immutable API image**. Reuse imported `copyStableSqlite`, `recoverySqlite`, `sqliteTypedRow`, `backupArguments`, `validateBackupHelper`, `helperAuthorityProjection`, `backupExportOperation`, `validateExportManifest`, and `transferBackupSnapshot`. Copy stable main/WAL into private scratch, run real SQLite backup, integrity/restore-compare and bounded hashed export. Never open live host volume paths or use `docker cp`/a key-printing exec.
5. Extend that concrete bridge to BOTH existing history/quota stores, not just auth/ledger. Fingerprints preserve `application_id`, `user_version`, all sqlite_master objects, rowids, exact 64-bit INTEGER, REAL, BLOB, TEXT, NULL and duplicate rows. Mixed/missing existing LLM stores, corrupt schemas, active pending history, journals/source changes or bounded-space failures refuse; no pending turn or quota liability is silently cleared. Existing CVE `cve-backups` limit4 is untouched: LLM has a separate limit16 completed generations with ≥4 GiB initial free-space requirement and **no auto-eviction**. Partial generations remain evidence/HOLD.
6. Only after a real fenced backup, build API/worker/public-web/LLM gateway if requested. Registry egress and both volume initializers keep their original immutable IDs; registry egress is not rebuilt/recreated. Running registry egress keeps its epoch. For stopped entry, only after the fenced backup and init/check, revalidate its immutable image execution metadata and start that exact retained ID, verify unchanged controls and the new running epoch. Validate selected images and the full prospective rendered model, then consume **immutable IDs** with `--no-build --pull never --no-deps --force-recreate`.
7. A fresh one-shot helper, network-none, UID65532, no key/JWT env or key mount, initializes `/auth/llm-history.sqlite` and `/auth/llm-usage.sqlite` only if **both were absent before replacement**. It uses the same existing HistoryStore/QuotaLedger constructors and exact approved policy. Otherwise it validates existing stores, never recreates/rotates them. `/auth` is writable only for this init/check helper; `/data` remains readonly. No API startup migrations or root copier. Partial initialization is HOLD.
8. Start/replace only LLM gateway and worker, verify worker chain/CVE readiness and no bypass, snapshot again before API. Compare all account/report data to the fenced backup; compare existing LLM data exactly, or validate empty newly initialized history/quota for the initial transition.
9. Start/replace API, require same-epoch health + real chain/CVE probe and API→`llm-egress:8080` TCP reachability (local connection only, no upstream/provider request), then another four-store snapshot and full typed comparison **while web is still stopped**. Only then publish canonical LLM/env/image-pin metadata under the same lock and open the public web service. Verify anonymous auth/readiness/chat-context ingress returns401 (not a false404); this never sends credentials or calls a model. Final namespace/storage/network identity and JWT fences precede a durable completion receipt and lock release.

Failures after intent retain `.local-public-images/.operation.lock/mutation.json`, helper identities, private backups/partials and pending metadata. No auto cleanup/retry/rollback/recovery, volume deletion, key rotation or use of legacy holders. CLI errors are fixed-text with a bounded checkpoint, never raw Docker/DB/Env output. No successful generation is implied by local deployment READY.

### Coordinator import contract: main launcher and CVE refresh

Do not copy the normative model into another launcher, and do not simply append an arbitrary `-f` file:

```js
import {
  readPublicLlmBinding, expectedPublicLlmConfig, validatePublicLlmConfig,
  validatePublicLlmImage, validatePublicLlmContainer,
  inspectPublicLlmNamespace, publicLlmComposeArguments,
  publicLlmHelperArguments, validatePublicLlmHelper,
  PUBLIC_LLM_BACKUP_PROGRAM, PUBLIC_LLM_EXPORT_PROGRAM,
  createPublicLlmPreservation,
} from './public-llm-stand.mjs';

// Read/fence the persisted selection under the SAME public operation lock.
const llm = readPublicLlmBinding(root); // null means original six-service base
const model = expectedPublicLlmConfig(root, cve, llm);
validatePublicLlmConfig(rendered, root, cve, llm, images);
// Runtime inspector delegates original authority checks only after checking
// the exact extension; it returns REAL API/network/volume observations.
const inventory = await inspectPublicLlmNamespace(run, options, root, cve, llm,
  { secret: existingPublicJwt, images });
```

The corresponding single-container validator signature is `(container, role, spec, image, model, extra, llm)`. The image validator admits only existing base roles plus the exact OpenRouter gateway execution defaults. Derive role/network/volume counts from the normative model; do not retain hardcoded6/4/2 counts for an LLM-enabled binding. Ensure pin selection/recording, status/stop and recovery policies understand seven pins and optional external key volume before exposing those main operations. The old six-role paths safely refuse the extension; they must not strip it.

Compose selector order is **base → optional public CVE → fixed public LLM → exact generated env/key mount → immutable image pins**. Current and candidate CVE must use the **same** persisted LLM selection/env/pins:

```js
const current = publicLlmComposeArguments(root, args,
  { cve: true, llm: llm !== null, pinned: true });
const candidate = publicLlmComposeArguments(root, args,
  { cve: true, llm: llm !== null, pinned: true, prospectiveCve: true });
```

`prospectiveCve:true` allows only the existing fixed `.operation.lock/candidate.cve.json` slot; all other LLM/env/image files stay bound to current state. The only alternate directory is the new launcher's own fixed `.operation.lock/llm-candidate` staging slot, with fixed basenames; no user-provided overlay path or env-file option exists.

**CVE/main coordination remains separately owned and requires review before live use:** the concurrent owner has introduced seven-service imports and four-store preservation tests. This scope did not modify their launcher/bridge/refresh/fixture files. Their integration must retain same-lock peer/writer/endpoint checks, web fencing through after-API comparison, fixed current/prospective overlay order and immutable pins, and the key mount without ever mounting it in a backup helper. The factory executes native backup/export/restore and returns typed snapshots; equality/empty-bootstrap rules must guard activation. Existing CVE backup budgets are not silently widened/bypassed. The current cross-owner fixture discrepancy and diagnostic result are recorded below; they are not a blanket integration approval.

### Exact operator commands (not live-executed)

From repository root, safe source-only inspection/tests:

```sh
node scripts/public-llm-stand.mjs plan
node --test scripts/test_public_llm_stand.mjs
node --test scripts/test_public_image_stand.mjs scripts/test_public_cve_bridge.mjs scripts/test_public_refresh_cve_preservation.mjs
```

**Only after source/coordinator review and explicit live authorization**, with an established uniformly healthy/running or uniformly clean-stopped public stand, approved `llm.env` and all current images available:

```sh
# Integrate LLM, including supported key-absent mode; persistent accounts/reports/JWT retained.
node scripts/public-llm-stand.mjs up --build --ack-public-maintenance

# Metadata-only profile status, NOT engine/credential/generation verification.
node scripts/public-llm-stand.mjs status
```

For later key activation, operator first uses hidden `--set-key` and the already documented stdin provisioning helper with a supplied audited local image ID. Once its non-secret receipt exists, one maintenance command applies the readonly API key mount, without rebuilding or resetting durable state:

```sh
node scripts/public-llm-stand.mjs up --ack-public-maintenance
```

Do not substitute direct Compose, legacy recovery or hand-written overlays. The acknowledged current external provider blocker remains **no public key**; this does **not** block source completion or a reviewed key-absent deployment. No live build, nginx container syntax check, Docker Desktop ownership/egress qualification or authenticated provider generation has been performed here.

### 2026-10-21 source self-review (not an independent review or live qualification)

- **P2 fixed:** `/llm/readiness` now belongs to the existing URL-scoped global `LlmExceptionFilter`. The new real public-module HTTP regression enables an actual capturing Nest logger (not `logger:false`), sends malformed/oversized GET and POST bodies, and injects an unknown pre-controller error carrying raw-body/scanner/credential canaries. Exact safe 400/413/500 DTOs and `Cache-Control: no-store` are checked; neither response nor logs contain those canaries. Router-equivalent case/trailing-slash/query aliases remain covered; extra-child paths remain outside the matcher.
- **Native Docker IDs:** the own maintenance census explicitly uses `container ls --all --no-trunc`. The fake engine now truncates IDs without that flag, so a regression cannot pass on unrealistically full fixture IDs.
- **Immutable activation:** no-build activation selects all seven recorded immutable IDs, not mutable service tags. The full second deployment runs with service tags removed and verifies unchanged pins/no second build. Tag changes are inert; original image `Id`/`Os`/execution `Config` drift is not. The regression for original Config drift after build keeps web closed/HOLD. Historical metadata is still validated before any stop/build; actual builds remain **after** the real quiescent backup.
- **Settings/profile guards:** parse the same captured/fenced nonsecret bytes; verify approved ancestor and private directory identities, file identity/mode/owner/content, and receipt presence. The host key is never statted/opened/read by this launcher. `readPublicLlmBinding` returns null for genuinely absent state, but rejects symlink/unsafe state, orphan overlay, pending publication and incoherent exact env/profile. Export signatures remain unchanged for main/CVE integration.
- **Key-volume authority:** a supplied candidate must be local-scoped/local-driver, have empty options, the exact provisioning label and a valid mountpoint. Metadata and all consumers are checked **before the first stop**, then fenced during maintenance. No key-byte probe is performed. Existing account/scan volume metadata is also revalidated before any helper mounts it; source replacement cannot wait until the final acceptance check.
- **Helper controls:** production helper validation is exercised with created empty network observations → running `none`, Engine `DriverConfig:{}` and `OomKillDisable:null` → false. Exact program/argv/path/env, mount source/driver/nocopy, network-none/caps/HostConfig authority and execution epoch are retained. Injected env, source, argv, unknown HostConfig authority and running argv drift reject before build without opening web. No backup helper has a key mount or JWT env.
- **Admission/health:** for running entry, initial API health is required until its intentional stop; after replacement, post-readiness API health is continuously required until completion; all replacement peers must actually be running and non-paused/non-restarting/non-OOM/non-dead. A health flip immediately after the readiness probe fails before publication/web admission. Final seven-service namespace explicitly requires live peers and healthy API.
- **Strict durable stores:** four-store all-schema/all-table typed comparisons remain mandatory; no fixed-table equality bypass was introduced. Additional native regressions refuse mixed/swapped stores, wrong application IDs, pending history and orphan WAL without resetting source data. Source contents/inodes/membership, copied API manifests, external config, profile and live volume metadata drift retain HOLD with web stopped. Incomplete backup history refuses before stop/build; the existing four-generation CVE history remains untouched.

Cross-owner check: `node --test scripts/test_public_cve_llm_integration.mjs` initially passed **4/6**. Its key-mounted fixture in `scripts/public-cve-bridge-llm-fixtures.mjs` lacks native Docker volume metadata **`Scope: 'local'`**. The shared inspector now requires that value as well as local driver/empty options/exact label. With **only that fixture field supplied in memory using a test-only Node load hook**, all **6/6** passed (key-absent/key-mounted four-store CVE preservation, history/quota drift HOLD, ordinary-up dispatch, status/stop). No owner file was edited, and this diagnostic run does **not** mean the unmodified suite passed: its owner must complete that fixture alignment and rerun before coordinated live approval. Shared exported signatures did not change.

All tests use disposable synthetic state and a fake Docker engine; provider generation, Docker Desktop UID/volume behavior, real image builds and live nginx remain **unqualified until the operator's reviewed deployment**. The owner-confirmed missing public key is the exact external generation blocker. Key-absent deployment remains intentional: no credential mount; context/history/readiness are available and generation must reject. User interface connection setup can show that metadata without receiving credentials.

### Reviewer P2: clean stop → up follow-up

The running-only preflight refusal is fixed in `scripts/public-llm-stand.mjs`, without changing main/CVE/bridge/migration source, shared model/preservation exports, or the module import graph. Only the LLM `up` runtime path changes. An established all-stopped namespace now goes through the **same** immutable image/namespace/config/header-controls/source/consumer guards and native four-store preservation. No new recovery flag or bypass exists. Existing HOLD locks remain untouched and refuse before any Docker submission.

The stopped path skips repeated stops and the impossible stopped-worker `exec`; the original network-none helper checks real ledger drain before any application is started. After that backup/init/check, the readonly registry gateway starts by its original validated ID, with immutable image metadata and unchanged controls proved before/after start. It is not rebuilt/recreated. Other services follow the original replacement/readiness/comparison pipeline; web admission still opens last. Writers/initializers require exit0. Exit143 is admitted only for readonly gateways/web whose normal shutdown may be SIGTERM; exit137, OOM, restart, pause, runtime error, nonzero stopped PID, never-started epoch, mixed states and missing historical images refuse.

New concrete regressions call the **actual main `stop` and main `up` functions** against the strict fake engine, for both key-absent and key-mounted profiles, while all snapshot/init/check/export/restore work uses native SQLite helpers on disposable databases. The fake now supports multi-ID stops, normal gateway/web SIGTERM statuses, stale stopped API health and exact retained-service restarts, and rejects every `exec` into a stopped container. Both tests preserve a nonempty durable history head, quota clock, account/report rows, JWT and all seven immutable pins with mutable tags removed. All four stores are compared against each of the three real backup generations. Dirty stopped-ledger state fails during the original backup with no application start/build; existing uncertain HOLD remains unchanged. The focused stop/up/guard/order subset passed **17/17**; the full own deploy suite passed **78/78**. Script syntax checks passed. No live commands or migration actions were executed. The earlier 275/98/32 results below are prior checkpoints, not fresh reruns for this script-only follow-up.

For a reviewed clean-stopped **already LLM-bound** stand, the existing command is unchanged:

```sh
node scripts/public-llm-stand.mjs up --ack-public-maintenance
# Equivalently, the existing main dispatch (also covered by the concrete tests):
node scripts/public-image-stand.mjs up
```

A CVE-enabled stand must still have completed the separately owned public v1 → v2 migration before LLM up; this fix neither performs nor relaxes that migration.

### Actual public-v2 preflight refusal: read-only isolation and fix

The operator reported successful public CVE prepare → v1/v2 migration → fresh refresh, with the established six-service public stand running. The first real LLM `up --build --ack-public-maintenance` refused before intent and left services unaffected. This follow-up did not run a real `up` or modify that stand.

**Exact root cause, reproduced against actual source:** `sourceFence` used the private nonempty `readBounded` policy for every source file. The tracked **`src/admin-app/features/.gitkeep` is empty**. Its regular-file/single-link/current-owner checks passed; `setup-local-cve.mjs`'s `stat.size > 0` condition rejected it. The first source-only in-memory diagnostic reported just the guard's source locations and source-file metadata booleans. This was not a missing image, invalid provider profile or `.dockerignore` allowlist mismatch.

The module now has a separate bounded **byte** source fence: empty source files remain included and protected, binary asset changes cannot collapse to the same lossy UTF-8 string, and no placeholder is skipped. It retains regular-file/current-owner/single-link/nofollow checks, pre-open/opened/final identity/mode/size/mtime/ctime checks, bounded reads and stable raw-byte digests. Private config, receipt and JWT readers remain nonempty and strict. Their metadata fences compare captured values directly; the JWT is never printed or fingerprinted for diagnostics.

CLI refusals now identify finite substages such as `preflight-source`, `preflight-images-api`, `preflight-namespace`, `preflight-census` and `preflight-backup-history`. Optional internal `onDiagnostic` receives only a frozen `{phase, reason}` drawn from a fixed table, never an Error, stack, command, Env, source content or secret/hash. Callback errors cannot replace the safe refusal or prevent normal pre-intent lock release. There is no automatic retry or HOLD recovery.

**Actual read-only confirmation after the fix:** an asserted in-memory module transform replaced lock acquisition with an absence/identity-only guard and replaced the maintenance call with **only `ops.preflight()` and return**. A separate deny-by-default Docker adapter allowed bounded local context/public pinned-image/container/network/volume metadata only; namespace listings were scoped by public name/project-label unions, and all lifecycle/build/exec operations were denied. It passed **6 services / 4 networks / 2 volumes**, with **47 logical metadata operations**. Source fences, public v2 profile, all prior immutable images, namespace/peer health, public consumers, SQLite availability and backup-history guards passed. The existing public JWT was loaded internally only; no value/hash was emitted. No key was read or searched. `.operation.lock` was absent after the read-only check; no intent, audit generation, deployment metadata, image, service or store was created/modified. No old holder/8080 was inspected.

Regressions now put the actual empty `.gitkeep` shape and a non-UTF8 binary asset into every concrete deployment fixture. The production fake-engine/native-SQLite pipeline succeeds with them. A same-length `0x80` → `0x81` change (identical when decoded lossily as UTF-8) refuses before intent; empty private config/JWT still refuses. Source/JWT/engine/image failures exercise fixed substages, safe diagnostics, a throwing diagnostic callback, no raw canary leakage and released pre-intent locks. The focused subset passed **8/8**, the full deploy suite **84/84**, Python helper tests **32/32**, and both script syntax checks passed. Main/CVE/migration source was not edited. The earlier backend/275-test results are prior checkpoints, not fresh runs in this preflight-only follow-up.

That earlier pre-intent refusal required no cleanup and the read-only check confirmed preflight eligibility only. **The operator's subsequent real invocation entered a new build HOLD; the ordinary retry advice is now superseded by the current-operation procedure below.** Missing public key remains the separate generation blocker.

### Current actual build HOLD: diagnosis, review boundary and continuation

The real retry reached `phase=build`, stopped web/API/worker cleanly (exit0), completed the original fenced backup, and failed before writing candidate image pins. Registry egress is still running, initializers retain their IDs/exit0, and no replacement application container was observed. The preserved lock contains exactly `mutation.json`, `helper-fenced.json`, `llm-candidate/`; the candidate contains only the exact CVE/LLM-env overlays. The original audit contains only `fenced/core`, with its private export manifest and restored auth/ledger snapshots. These original files were not rewritten or deleted by diagnosis.

**What is actually established:** actual candidate Compose config validates. Public web TypeScript and Vite bundling both pass in the explicit Docker COPY closure, using a disposable source-only directory with the correct cwd, existing dependencies and `envFile:false`. API and worker Dockerfile TypeScript entrypoint/COPY closures also report zero diagnostics. The public worker tag now identifies a new validated image; the original worker image ID in the unchanged pins/container is unavailable. Other required original image metadata is available. A new public LLM gateway image tag also exists. This is a partial image build/publication with original stopped container identities retained.

**What is not recoverable:** the legacy launcher swallowed the build boundary/category and did not save raw stderr or original pre-build source/image/control evidence. The marker still says its original `fence-web` phase. Current metadata cannot prove the exact historical build error or reconstruct the original source fence. No Dockerfile/COPY fix, resource-error diagnosis, or build success is asserted from that absence. No rebuild, lifecycle, old-holder inspection, live DB opening or lock deletion was performed to investigate.

New source:

- `scripts/public-llm-build-continuation.mjs`: a read-only checker for this exact own pre-initialization build prefix, not historical recovery. It requires one matching partial audit, original helper absent, exact unmodified candidate pair, no candidate pins/init/late-stage records, public v2 six-service/no-key descriptor, immutable identities, clean stopped writers, running retained registry gateway, exact startup Path/Args, full normative controls, volumes/networks/foreign consumers, unchanged engine endpoint, private directory ownership, bounded audit/disk budgets and genuine original metadata for required execution images.
- The checker validates original export receipts and hashes, copies auth/ledger/main/WAL into private temporary scratch, and performs native integrity/drain/schema/typed validation **only on those copies**. Original audit DB/WAL/SHM files remain byte-fenced and unopened by SQLite. The result binds public state/config, JWT **file identity only** (the value is checked internally against the original API, never printed/hashed), pins, peers/epochs/executable controls, available immutable image Config, backup families/manifest, current source and the full audited local execution dependency closure into a stable review token. Source is qualified offline again. No provider key is opened or mounted.
- The checker explicitly reports `originalSourceBaseline: not-persisted-requires-explicit-current-source-review` and `missingPriorMetadata: [worker]`. It does **not** reconstruct original worker image metadata from a container/tag or claim historical provenance. The only proposed exception is **retirement-only**: the old stopped worker's controls are checked against the defaults/policy of a real validated replacement image, and its original ID is never used for start/exec/helper execution. This separate exception requires an additional acknowledgement. Missing API/other required metadata is not silently accepted.
- `scripts/public-llm-source-build.mjs`: no-Docker/no-dotenv/no-install TypeScript + Vite COPY-closure qualification in disposable storage. This is a source check, not container-platform/native-install/build-export qualification.
- Future builds have separate `build-source`, `build-config`, `build-submit-<role>`, `build-image-<role>` and `build-pins` boundaries. The four builds are submitted serially, with a private sanitized `build-failure.json` containing only role/phase/finite category, never raw stdout/stderr/Env. A pre-build checkpoint now persists source, validated image metadata, peer controls/epochs, original typed baseline and JWT metadata **without its value/hash**. Serial submission is not claimed to explain the old failure.

Read-only review command (safe while this exact HOLD remains untouched):

```sh
node scripts/public-llm-stand.mjs check-current-build --audit deploy-8d83a8806715c2f0fa575efedee1b0af
```

It emits only a sanitized summary and review token. Do not paste full private review/checkpoint/manifests into logs or browser. The token is not a credential and must be taken from a fresh successful checker run after source review.

**Only after parent review and explicit live agreement**, the proposed command for the currently observed missing-worker-metadata case is:

```sh
node scripts/public-llm-stand.mjs continue-current-build \
  --audit deploy-8d83a8806715c2f0fa575efedee1b0af \
  --review <fresh-64hex-review-token> \
  --ack-reviewed-current-source \
  --ack-retire-only-unavailable-worker
```

The first acknowledgement accepts the explicitly disclosed **current** source basis; it does not certify an unavailable historical source snapshot. The second authorizes only retirement of the unavailable original worker, not original-image execution or general missing-image fallback. If all original metadata is available, that second acknowledgement is rejected as inapplicable.

The continuation re-runs the checker and matches the token before any state write. A new exclusive `continue.json` claim prevents concurrent continuation, while the original lock inode/records remain. It saves the reviewed authority into private `continuation-checkpoint.json` and `<audit>/continued/review.json`; the old `fenced/` is preserved. A fresh network-none readonly helper using the still-validated original API image exports the **current live stores**, then compares them to the original native baseline **before build, initialization or any application start**. Source/state/epoch drift or mismatch retains HOLD; no reset/refund/rotation/rollback is attempted.

Only then does the existing candidate/init/readiness/four-store pipeline run. Post-build snapshot helpers use the validated candidate API image, so they do not require execution of an original API image whose metadata may have been removed by image publication. Existing old worker code is never executed. Admission remains fenced until both acceptance comparisons pass. New snapshots are under `<audit>/continued/{fenced,before-api,after-api}`. On successful completion, original operation records/candidate pair are archived under `continued/original-operation/`, review/build checkpoints remain in the audit, the existing audit earns its completion receipt and only then the known operation entries/lock are retired. This is completion of the same audited operation, not force-unlock or a new stand bootstrap.

Any failure after continuation intent creates a **new uncertain continuation boundary**. The checker intentionally refuses that later prefix; do not re-run continuation or remove its records. Source, program, JWT, pins, candidate, backup/WAL/SHM, execution/epoch or namespace changes invalidate the review. New key provisioning/secret-mount changes are outside this narrowly scoped no-key continuation.

Tests use concrete fake-engine calls plus native SQLite backup/export/restore: the current build prefix, partial published worker/missing original metadata, sanitized failure category, stable read-only proposal, both metadata-available/retirement-only branches, stale source/program/pins/JWT/backup/epoch/executable/candidate review rejection, dirty live stores rejected before build/init/start, unchanged original backup evidence, no original-worker execution, full four-store completion and refusal of a second uncertain continuation. **96/96 own tests**, **32/32 Python tests** and script syntax checks pass. The actual checker was exercised read-only; actual continuation/build/deployment has **not** been executed. Parent review remains the mutation gate.

### Reviewer P1: transitive local execution closure

The earlier three-program binding was insufficient. The current checker now captures the complete transitive literal-import graph from `public-llm-stand.mjs`, `public-llm-build-continuation.mjs` and `public-llm-source-build.mjs`: **15 audited first-party modules**, including `public-image-stand.mjs`, `local-stand.mjs`, `setup-local-cve.mjs`, `refresh-public-cve.mjs`, their profile/bridge/provision/preservation/capacity helpers, `refresh-local-cve.mjs` and `server/deploy/trust/fetch-db-layer.mjs`. The already existing whole API/runtime/web source fences still cover container/probe/application code; npm dependencies remain covered by the existing manifests/lockfile policy, not a claim of byte-attesting the installed npm tree.

A non-executing TypeScript AST walk follows literal static imports, re-exports, dynamic imports, `createRequire` aliases and `require.resolve` calls. Cycles are deduplicated. Every relative target must belong to the fixed audited module boundary before any lookup; nonliteral loaders, unreviewed local files, path escapes/URL imports and unsupported external modules refuse. Discovery is bounded to 32 modules, 1 MiB/module, 4 MiB total, 256 local edges and 512 import sites. Parsing uses text captured from the same nofollow descriptor/byte proof, not a separate unchecked file read. No discovered module is imported/evaluated by discovery. Parent directory identities, owner/mode and no-symlink properties are also bound, preventing directory aliasing from preserving only leaf proofs.

All module byte proofs, directory identities and graph entries/edges enter the review token and private checkpoint. They are verified at the end of checking, during continuation runtime before Docker boundaries and record writes, and **again immediately before the exclusive `continue.json` claim**. Changes to any transitive executed helper therefore invalidate old review tokens, not just changes to the three top-level files. Earlier review tokens are obsolete.

Regressions cover all four files named in P1 and deeper dependencies, including bridge/runtime/profile/preservation and the trust transport module. Each dependency drift invalidates both the saved runtime verifier and a subsequent continue attempt before intent/lifecycle. A separate race regression changes a dependency after the final read-only preflight result and proves that no continue record/helper/lifecycle is submitted. Pure closure tests cover cycles, non-evaluation, unauthorized targets, nonliteral import/require aliases, symlinked directories and oversized source. Targeted subset: **17/17**; full own deploy suite: **112/112**; script syntax checks passed. Actual continuation/lifecycle remains unexecuted and parent approval remains required; real HOLD metadata was not changed for this fix.

### Deploy-source verification results

**112 deploy tests passed** after the self-review, clean-stop, actual-preflight and current-build continuation follow-ups, including exact CONFIG equality, missing/provisioned selection with a denied key sentinel, fixed overlay/model rejection mutations, runtime authority projection + inherited base checks, current/prospective CVE order, public nginx gate/access-log rules, lifecycle failure order, late typed preservation failures, native existing-store/no-reset initialization, real four-store backup/export/restore, exact INTEGER/BLOB and application_id mutation detection. A concrete strict fake engine + real SQLite exercises the full production maintenance function twice: key-absent deployment then one receipt-driven activation. It also proves unavailable historical image metadata refuses before build/stop, and unsafe helper/unclean worker retain HOLD before build. Four existing CVE backup generations are retained unchanged.

**275 existing stand/CVE bridge/preservation regression tests passed.** All Docker operations in these tests are fake; native operations are confined to temporary synthetic SQLite/source fixtures. `node --check` passed for both new scripts. Public frontend deploy TypeScript checking was run against the explicit Docker closure (including the two imported runtime contract sources). The source-only `plan` was executed and does not invoke Docker or read config/key state. Common nginx/default 8080 source was not altered. No live lifecycle/exec or real public state mutation, provider request, commit/push or MCP mutation was performed by this agent. The separately authorized actual public read-only metadata preflight is documented above; the original tests remained entirely offline.

## Verification

Executed against source, ephemeral ports and disposable fixture databases/keys only:

```sh
# from server/api
pnpm exec tsx --test --test-concurrency=1 src/llm/tests/*.test.ts src/scans/public-vulnerability.http.test.ts src/scans/public-image.http.test.ts src/scans/public-image-origin.http.test.ts src/scans/public-image-legacy.http.test.ts
pnpm typecheck

# from repository root
python3 -m unittest scripts/test_public_llm_config.py scripts/test_public_llm_provision.py scripts/test_set_openrouter_key.py
```

Current rerun during the 2026-10-21 self-review: **98 TypeScript tests passed**, **32 Python tests passed**, and full API **`pnpm typecheck` passed**. This supersedes the earlier checkpoint with unrelated concurrent worker-test type errors; those files were not edited in this scope. The transport test uses only a disposable loopback TLS/CONNECT server and synthetic CA/key; legacy-origin strings in tests are headers, not calls to the old host service. Public tests cover 241 rows / 236 CVE + 5 TEMP, late critical evidence, real public module/cookie/SQLite identity, whole-count and platform conflicts, default-reader rejection, zero/unknown refusal, consent/Origin/foreign-owner denial, bounded requests, durable TEMP citation reopen/replay, failed citations with retained usage, unsafe question/parser redaction, and existing JSON/NDJSON delivery. Shared suites cover quota contention/carry/receipt/storage faults and history/session/cancellation/publication races.

No private env/key/holder contents were read. Only the newly authorized non-secret public `llm.env` was created outside Git in the earlier preparation pass; public key presence was checked by metadata only and is false. No real provider key was entered/read/provisioned; no Docker lifecycle/build/exec or old-host request/inspection was performed, and no commit/push/MCP mutation was made. The actual read-only diagnostic used only authorized public-resource metadata; the own public JWT was consumed internally without output or fingerprinting. Parallel UI/CVE/deployment-owner work is not part of this patch.
