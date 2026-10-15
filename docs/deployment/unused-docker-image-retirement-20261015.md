# Independent correctness review: exact seven-image retirement

## Decision and frozen literal

**APPROVE ONE parent attempt of the exact seven-image literal below, subject to independent security acceptance and exclusive daemon custody throughout preflight/removal. No concrete source correctness blocker found. NOT EXECUTED by this reviewer.**

- Literal: `docs/deployment/unused-docker-image-retirement-20261015.sh`
- Literal SHA256: `3bd321bbec12a60e8db528580537ad63c53dc84909925d09241abccbfe2ee3ba`
- Required cwd: `/Users/vsevolod/Documents/startup/diplom`.
- Parent may invoke the frozen file once with `/bin/sh`, caller `timeout_ms=75000`.
- Canonical version3 plan SHA256: `3f46f8ec5076453e7efb2ec9a44703cbadf3f04cb7ba94af7f2a2d69ae4d1775`, independently calculated over the exact public JSON bytes without a final newline. Full JSON and all seven immutable ID/tag bindings are frozen in the shell.
- Shared60s, each client10s; at most3 metadata calls and7 serial removal calls, aggregate63488 transport bytes including captured/discarded stderr; receipt<=65536B. External75s is a supervisor bound, not a guaranteed completion time.

This explicitly selects seven, not the optional two-ID subset. No automatic fallback, retry, extra inventory, cleanup or rollout is approved. Any changed source/plan/literal needs fresh review.

## Authority and present deployment state

The user explicitly authorized disposal of these exact unused images independently of deployment completion. Parent must exclude concurrent Docker mutation from the first listing through the last removal; the authorization flag asserts this responsibility, not a checked private lock state. No deployment-PASS prerequisite is imposed by this new approval.

User reports the R3 invocation is SPENT, failed at `HOLDER_WRITERS_PRE` before fresh-holder creation, and performed no SQL/app operations. Those are attributed observations, not independently queried facts or a root-cause finding. This cleanup does not retry R3, propose R4, resolve any deployment HOLD, or adopt/remove any lock, journal, backup or retained actor. Earlier commands and reviews remain unchanged.

The helper's `manualReconciliationRequired:false` on cleanup success concerns only this cleanup invocation. It cannot clear the pre-existing deployment HOLD or establish application readiness.

## Correctness findings

1. **Whole-batch guard precedes every removal.** Fresh complete `image ls --all --no-trunc` is parsed with a100-row bound. All seven selected immutable IDs must exist and each must have exactly its literal single expected tag. A missing/changed/multitagged/untagged selected image refuses the whole batch. Fresh complete all-lifecycle container listing is bounded to80 containers; if nonempty, one inspect projects only `.Id` and immutable `.Image` for every listed ID. Complete unique membership is required. Any selected image referenced by any lifecycle blocks the entire batch before the first mutation. Displayed tags are not authoritative references.
2. **Finite mutation boundary.** The only mutation is serial, single-ID `image rm --no-prune FULLID`, once per selected entry, without force or tag-name deletion. Docker dependency/reference conflict checks remain active. No multi-ID invocation that could continue after a conflict; no prune, container/volume/network/cache operation, actor creation or service start. `--no-prune` prevents cascading deletion of untagged parents. This is not a claim that every selected image is currently removable.
3. **Preservation by scope, not invented post-observation.** The fixed allowlist is disjoint from all five original and three candidate image pins and history-base `sha256:c09ce4c8e6185784fad2c263b462952092fa89058d16363ebd543e0cd4bbd50d`. Other images, untagged parents, every container and every volume are non-targets. No content reads or measured post-state preservation are claimed. There is no post-inventory in this literal.
4. **Stop/partial accounting is conservative.** A successful individual removal requires exactly the literal `Untagged:` and `Deleted:` acknowledgements, without duplicates/extras. First nonzero, timeout, cap or ambiguous acknowledgement stops the loop with no later member, retry, compensation or follow-up query. An unexpected additional Docker acknowledgement line can therefore produce an uncertain attempted removal; it must not prompt a blind retry. Receipts preserve `planSha256`, `attemptedImages`, `confirmedRemovedImages`, `uncertainImage`, `notAttemptedImages`, and `postInventory:false`. A deadline between removals leaves the next member not attempted; attempted/possibly attempted failure requires manual reconciliation. Receipt loss/external timeout is also not permission to repeat.
5. **Bounded transport and public-source gates.** Two transport instances share the same deadline and aggregate budgets; metadata<=3/removals<=7 do not bypass/reset the transport's per-instance8-call bound. Metadata calls allocate16384B each; removals2048B each, totaling63488B. Captured public transport bytes are verified before compilation; neither its main/controller gate nor the proof runner is invoked. Fixed binary identity/endpoint, clean child environment, and metadata-only absence check for adjacent `config.json` remain enforced before clients. No Env, arguments, labels, mounts, logs, private file or daemon-config content is requested by this helper.
6. **Honest provenance boundary.** Public runner dataflow and namespaces constrain intended source-build scope, not actual historical per-ID custody/content. Only `4ca80cff...` and `d060e223...` were individually linked in the public evidence register during this review; the other five do not gain fabricated historical provenance. Exact informed discard authorization plus the fresh zero-reference fence is the basis for selecting all seven. Namespace matches alone would not be sufficient.

## Exact public source pins

Hashes were independently measured; all match the candidate bindings.

| Public file | SHA256 |
|---|---|
| `server/deploy/trust/cleanup_unused_docker.py` | `8ffe4d3a4566ed30d969ce7b4c49857d275fc09882322fe3d98e82d47e339526` |
| `server/deploy/trust/test_cleanup_unused_docker.py` | `5a4bdf17fd4a5f6a67ea58febf12264ae3da9194f05ee03f28fd8c50d6381a6d` |
| `server/deploy/trust/discover_preservation_holder.py` | `4afb0bc484d34aca428fee956bd939d7b322727285eef0f721425849bb32a1f4` |
| `server/deploy/trust/test_discover_preservation_holder.py` | `cc1a168804cb9a07f9c53724730bfbbaae7596c44c88743b0dc169f26a1bf312` |
| `server/deploy/proof/cve14-combined-proof.py` | `945404d04957c86523de0490b5a65f17787010f6733a9a7ead1f76dfcfb4adc0` |

Reviewed the current helper/test and `unused-docker-cleanup-held-stand-20261015.md`; public runner/dataflow and evidence-register review was source-only. Author reports23 inert tests PASS; this reviewer inspected tests but did not execute/import them and does not report an independent test PASS.

## Review limits

No Docker/daemon/native/test/provider/history command, private read, source edit, Git operation, task/status mutation, or cleanup was performed. Only public reads/hash operations and these two new owned deployment documents were used. No actual eligibility, deletion, reclaimed bytes, image contents, application readiness or migration success is asserted. This is the correctness approval for the frozen one-shot cleanup only; independent security disposition is separate.
