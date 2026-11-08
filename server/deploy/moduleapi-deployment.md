# ModuleAPI v7 — preserving deployment, implementation qualified offline

## Current state — 2026-11-08

The explicit ModuleAPI v7 transition is now implemented in the existing deploy adapter. Earlier source-only/new-gateway estimates are superseded by this document. **ModuleAPI has not been activated or deployed, and no live report generation has been verified.**

The operator/user authorized the provider switch and a bounded real test. Remaining prerequisites are secure local key input, immutable Linux initializer/bootstrap qualification, explicit effective-tariff/estimate configuration, protected nonsecret descriptor installation and the actual preserving rollout. At the last metadata-only check, `~/.diplom-moduleapi/server.env` did not exist. The latest current-site status was `ready:true`, `locked:false`; no lifecycle action was taken.

## Runtime identity and limits

- Explicit selector `LLM_PROVIDER=moduleapi`; request alias `gpt-5.4-mini`, fixed endpoint `https://moduleapi.pro/v1/chat/completions`.
- Separate branded policy, prepared request, provider, usage and accounting modules. No conversion into `OpenAiPolicy` and no automatic OpenAI/OpenRouter fallback.
- ModuleAPI is a third-party recipient. Retention/training and effective account/group tariff are unverified. Disclosure says `retention: unknown`, `tariffVerified: false`, `zeroDataRetentionVerified: false` and requires a fresh ModuleAPI-specific grant. Old OpenAI/free consent is not reused.
- Integer configured-rate estimates use `moduleapi-server-estimated-configured-rates-not-invoice`. Neither catalog prices nor `x-moduleapi-cost` are silently promoted into invoice authority. Explicit input/output rates and all finite technical bounds are required; there are no rate defaults.
- The same durable ledger and owner identity enforce the existing **5,000,000 microUSD account-lifetime estimate budget**, including all retained historical provider spend and UNKNOWN holds. No reset, migration or deletion is part of this transition. This local estimate cap is not a proven cap on the provider invoice.
- One guarded send, usage before content validation, grounded Russian validation and durable commit before publication remain in place. No repair, retry or posttranslation. GET/reload never generates.

## Same topology, explicit provider change

V7 keeps the existing **eight services/eight networks**. The historical infrastructure slot `openai-egress` is replaced with the ModuleAPI gateway image/command; the internal name is not the application/provider identity.

- Existing `openai_internal`/`openai_uplink` network identities remain unchanged.
- Only the API-facing internal endpoint receives the `moduleapi-egress` alias. No host gateway ports, new worker/web access or new gateway service role.
- Fixed CONNECT `moduleapi.pro:443`, public DNS validation and numeric dial; verified TLS identity precedes Authorization. Only POST `/v1/chat/completions`; bounded bytes, deadlines and admission; no proxy/direct/redirect/retry fallback.
- API uses `moduleapi-api.Dockerfile` plus its own bootstrap and readonly/nocopy `moduleapi-secrets` mount.
- The old OpenAI secret volume stays externally declared, unmounted after replacement, with metadata/consumer fences. OpenRouter resources remain unchanged. Both old and new credential-volume metadata are checked during mixed-authority replacement.
- Existing image custody, supervisor, engine journal, fresh readonly four-store snapshots, disposable quota compatibility checks, before/after-API equality and web-last ordering are reused. No fabricated old image, candidate-only role or historical checkpoint.
- First transition requires targets `web,api,openai-egress`, without operations upgrade or migrations. A later normal v7 update uses the usual selected services. V7→v6 is not an implicit rollback.

`MODULEAPI_SLOT_DEPLOYMENT` and `validateModuleApiDeployment` in `scripts/public-llm-source-build.mjs` are the implemented authority. The older `MODULEAPI_DEPLOYMENT` / `moduleApiDeploymentSupport()` export remains explicitly historical and nonexecutable; it is not a v7 configuration or release-readiness API.

## Secure key input and transfer

Run in a trusted local terminal from `diplom`:

```sh
python3 -I -B scripts/provision-moduleapi-environment.py --create
```

Hidden TTY input creates only passwd-home `~/.diplom-moduleapi/server.env`, directory0700/file0600, exact disabled payload. It refuses overwrite. Do not put a key in argv, shell exports/history, source, chat, Docker Config.Env, Compose env_file, build/frontend/worker data or artifacts. A key already posted in chat should be revoked/replaced.

Optional bounded metadata-only preflight, after secure input:

```sh
node scripts/moduleapi-preflight.mjs --check-model-access
```

This makes one verified-TLS GET `/v1/models`; catalog visibility is **not generation, billing, privacy or schema compatibility verification**. No report data is sent.

`moduleapi-secret-provision.py` requires an independently reviewed immutable local initializer image ID. Build its minimal public-only context from `moduleapi-secret-init.Dockerfile` and `moduleapi-secret-init.py`, qualify Linux ownership/modes/execve and approve the final ID before provisioning. No approved ModuleAPI initializer image ID is recorded yet; do not substitute a generic Python image/tag or bind mutable host code.

The provisioner passes protected FD→initializer stdin without reading/printing/hash-recording the key. A fresh external volume is exclusive/no-overwrite; collisions/failures retain evidence and lock. Initializer: no network/logs/core, bounded resources/deadline, file0400/dir0700 uid/gid65532. API bootstrap validates metadata/payload and injects only `MODULE_API_KEY` into the replacement process. Missing/bad secret refuses; ambient key is not fallback. Disabled payload marker does not activate the runtime. Debug/coverage/TLS-key-log overrides refuse before credential read. Mutable buffers are cleared best-effort; immutable runtime strings cannot be guaranteed erased.

## Nonsecret descriptor and rollout

Prepare a reviewed nonsecret v7 JSON descriptor outside source control, based on the exact published v6 descriptor. It preserves the complete embedded OpenAI/OpenRouter identities, `public-images-v2` operations and all `LLM_QUOTA_*` settings, including the lifetime cap. ModuleAPI rates/revisions/technical settings are explicit, not inherited as supposedly verified prices. Do not use synthetic fixture values as production settings.

The protected installer accepts that full JSON through stdin:

```text
python3 -I -B scripts/public-llm-config.py --prepare-moduleapi < reviewed nonsecret JSON file
```

This is a command template, not an executed operation or a literal path. The installer creates the fixed outside-repository `moduleapi-deployment.json` with0600, no overwrite; it does not read a key, provision a volume, activate services or mutate a database. The loader reconciles only the approved optional operations field if the protected v6 descriptor predates its published operations-only upgrade, then compares all other fields exactly.

After all preceding prerequisites are met, use the existing interface:

```sh
node scripts/deploy.mjs app --services web,api,openai-egress
```

That is read-only planning. Only after a successful exact plan and image/secret qualification:

```sh
node scripts/deploy.mjs app --services web,api,openai-egress --apply
```

These v7 commands have **not** been run on the live site. Do not add `--migrate` or `--upgrade-operations`. Keep a sufficiently bounded outer timeout (prior app operations used2400000ms). On HOLD preserve evidence/locks; no blind retry, old launcher or automatic DB rollback.

After publication, current gateway images are validated strictly as v7. Optional old `:local` tags are admitted only through original sealed owner/custody/intent evidence and fresh immutable ID/OS/Config/retained-tag equality, with across-await fences. This permits CVE/status/stop readers to inspect the unchanged retained image without treating it as the current provider.

## Qualification evidence and remaining real acceptance

- Core/backend/UI: separate provider brands, strict actual backend→browser wire, fresh consent, shared lifetime/UNKNOWN accounting and durable summary/chat paths qualified synthetically. Independent source review: DIP-ARTF-647.
- V7 descriptor/config/source:95 Node cases,9 Python preparer cases,24 legacy Python cases; real offline source qualifier returned `{typescript:true,bundle:true,docker:false,moduleapi:true}` (DIP-ARTF-649).
- Topology:47 cases plus selected v6 regressions (DIP-ARTF-648). Adapter boundary11 cases and legacy v6 apply/CVE status-stop selections (DIP-ARTF-650).
- Final actual-adapter fake-engine tests29/29: first/repeat v7, unchanged v6, four stores/JWT/history liabilities, custody, alias/secret isolation, failures/HOLD, deterministic nonce and post-publication CVE/status/stop. DIP-ARTF-654 supersedes initial fixture/build failures.
- Independent review DIP-ARTF-652 found two P2s; both fixed and independently closed by DIP-ARTF-655 (22 selected rereview checks). No blanket retained-provider allowance or weakened published transition.
- Parent fixed stale positive OpenAI browser fixtures to use explicit fitting admission, retaining negative unknown-admission cases. Selected OpenAI/ModuleAPI browser+contract116/116, root/API typechecks and frontend build passed before final deploy-only fixes; build warns about existing >500kB chunks.

These counts overlap and must not be summed into a full-suite claim. No full test suite, actual Docker image/bootstrap qualification, ModuleAPI deployment or paid provider request is represented by them.

After live rollout, on an authorized owned report: verify ModuleAPI readiness/disclosure/remaining lifetime; obtain fresh exact consent; perform **one** summary POST; verify grounded Russian output and durable GET/reload with no extra POST. Only after success, one explicit chat POST may verify completed response/history reload. Unexpected schema/model/usage/provider failure stops the check and retains liabilities. Metadata200 or infrastructure READY is not report acceptance.
