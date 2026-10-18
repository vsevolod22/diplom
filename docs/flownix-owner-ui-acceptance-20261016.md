# Owner UI acceptance — 2026-10-16

## Authority and evidence semantics

Project: DIP / `520a0059-d0f2-4f86-8d93-fc15035a5715`.

Owner instruction: «всё что можно принять прими, а то что сейчас нельзя принять объясни почему, если там ручная проверка то принимай, я потом отдельно после тыканья сайта буду заводить задачи на фикс багов».

This explicitly accepts remaining manual UI/SR/native-select/touch/visual acceptance gates without execution. It does not waive security, provenance, or strict spec requirements.

- **VERIFIED**: supported by inspected source/history or identified existing evidence; historical execution is labelled historical.
- **ACCEPTED_BY_OWNER_NOT_TESTED**: accepted by the owner without performing the outstanding manual checks. Not an executed PASS, accessibility certification, or performance measurement.
- **FAIL / BLOCKED**: an unmet original criterion still prevents overall acceptance.

Mutation authority for this turn: TASK21/TASK27 only, including necessary task-level spec disposition. No parent closures. Local writes: only this new file. Existing reports, application files, notices and other agents' work remain untouched.

Fresh `.flownix` and server policy agree: full, strict, require_proposal_approval=false, spec_first=false, completion_flow=direct, execution_order=parallel. Existing component binding DIP-COMP-1 is correct for both tasks.

## Actual tracker result

| Task | Before | After | Result |
| --- | --- | --- | --- |
| DIP-TASK-21 | testing | **done** | Original foundation scope accepted after targeted source reconciliation, owner manual waiver, and own no-spec-impact declaration |
| DIP-TASK-27 | testing / 90 | **testing / 90, unchanged** | Exact historical upstream provenance for adapted BlurFade remains unmet |

Posted comments:

- TASK21 per-criterion review: `8b7de6e8-0913-4fdd-ab2c-427b6b845e82`.
- TASK21 done confirmation: `d360ff7b-ab3c-4498-a2c8-246440c3475e`.
- TASK27 per-criterion review/decision: `c3506fa4-3f19-4679-aa1b-14d2a308b87e`.

TASK21 own `declare_no_spec_impact` succeeded for node `87c10642-bdf3-427c-ad21-de0f3c05d50c` at **2026-10-16 15:09:38.89233 UTC**. The tool returns node ID/reason/time, not a separate declaration UUID. The subsequent status mutation returned `status=done`, `stage=done`. No separate progress mutation was made.

No new deltas proposed/applied. No DOC2 changes. No declaration or status mutation for TASK27. PLAN6, FEAT3, and all other tasks were not mutated.

## TASK21: original criteria and dispositions

### AC1 — visual language, responsive sizes, focus/contrast/reduced-motion, semantic information

**VERIFIED within the evidenced scope + ACCEPTED_BY_OWNER_NOT_TESTED for remaining manual visual checks.**

Historical review `0f991a2d-44d2-49bc-8564-fb5eec793a3b` records 320/375/1280, light/system-dark focus/contrast/reduced-motion checks. These were not rerun by this reviewer.

Fresh targeted source/history reconciliation against implementation commit `a76adcd2e8ff1685b8bb833b376752402904db22` established:

- `src/shared/ui/scan-primitives.tsx` is byte-identical to the original implementation: Card/Alert use div, Badge uses span/text, Button uses native button; native props are preserved.
- The original token/primitive CSS prefix through `.scan-alert--danger` remains unchanged.
- The root explicitly uses `color-scheme: light`; testing under system dark is not a claim that a separate dark theme was implemented. The original criterion only requires light/dark where necessary.
- Later A1 shell/decor overrides were reviewed separately; they do not make every later UI component part of TASK21's original scope.
- Filter animation is restricted to no-preference; reduced-motion rules disable transitions. Meaningful state/coverage remains textual HTML, not canvas/color-only information.

The outstanding full current visual/zoom/touch/manual contrast inspection was not executed. Its acceptance gate is waived by the owner, without claiming a successful test.

### AC2 — keyboard/SR, dialog focus, tests, dependencies, reproducibility and bundle comparison

**VERIFIED for source/dependency and recorded-test evidence; ACCEPTED_BY_OWNER_NOT_TESTED for remaining audible SR/native-select checks.**

Current ScanFilterSheet and its original-to-current diff were reviewed in full. Dialog.Root/Portal/Title/Description, native label/select, trigger/select refs, initial focus and focus restoration remain. Later changes are animation classes, category copy, and optional `cveValue`; the current detail consumer explicitly uses `demo ? "vulnerability" : "cve"`.

Original/current byte identities:

| Artifact | SHA256, equal at original commit and inspected working source |
| --- | --- |
| `src/shared/ui/scan-primitives.tsx` | `cb26328c6ee54759a8a332a87b1ee337b5814925322ffa4f2f5608b96bc1a03b` |
| `pnpm-lock.yaml` | `fabbef7d2ce7cd82d2368a3bc85584dc04363533eab34772c54a558381a2d4c3` |

Current package.json dependency/devDependency dictionaries exactly match a76adcd; later scripts differ. Existing Radix Dialog/clsx are reused, with no added runtime registry dependency or copied registry source in this task.

Historical evidence records 14 Vitest / 6 Chromium tests, typecheck/build/scoped lint. The reported bundle comparison 408K → 428K used `du -sh dist/assets`: rounded directory size, not gzip, transfer size or exact JS bytes. No new build or bundle measurement was run.

`docs/acceptance-final-20261015.md` supplies a later bounded browser AX/keyboard/trap/Escape-restore observation. It does not establish audible SR, and `selectOption` is not native keyboard-selection proof. VoiceOver/NVDA/native select/manual browser checks were not performed here. No new Safari/Firefox criterion is invented.

### AC3 — existing architecture/security boundaries and three independent reviews

**VERIFIED for the task's foundation scope and current applicability.**

The original a76adcd parent-to-commit diff is empty for package.json, pnpm-lock.yaml, app/providers, app/routes and shared/api. Current AppProviders preserves QueryClientProvider/BrowserRouter. Local primitives add no network operations or unsafe HTML.

Historical review `0f991a2d-44d2-49bc-8564-fb5eec793a3b` explicitly records three independent accessibility/correctness/architecture reviews: initial changes requested, fixes, then all approved. These reviews are not missing. This does not automatically approve every subsequent application change.

Later API/ingress and page redesign work retain their separate owners. A previously unavailable ingress need not remain disabled after separate authorized implementation. Unrelated later MagicCard/BlurFade provenance is not attributed to TASK21.

### TASK21 strict spec disposition

Full TASK20/comments and applied delta `913dec08-be0a-4c1c-9543-29216a7afe77` were read, along with current DOC2v7. TASK20 owns the TZ/contract changes in the shared a76adcd commit. Its DOC2v2→v3 delta added evidence-first composition, truthful coverage/list states, and source provenance requirements, and was applied on September 28. Those requirements remain in DOC2v7.

TASK21's local primitives/tokens/existing-Radix composition implement that already described contract without changing documented API/ingress/provenance promises. Therefore its own no-spec-impact declaration describes the **implementation's contract impact**, not the fact that this turn only performed review.

The TASK20 delta is supporting context, **not a substitute task21 closing record**. TASK21's own declaration passed the strict gate. No duplicate/no-op delta or DOC2 rewrite was needed. Owner acceptance of unperformed manual checks changes the acceptance decision, not the claimed behavior or evidence.

## TASK27: original criteria and dispositions

### AC1 — comparable concepts, expressive candidates, motion/static fallback and honest evidence

**VERIFIED for materials/historical evidence + ACCEPTED_BY_OWNER_NOT_TESTED for outstanding manual UI/SR/touch/visual checks.**

The A/B/C list/create/detail/unavailable materials cover the same data and sizes320/375/1280; source candidates, composition differences, motion and reduced-motion fallback are documented. Historical isolated-prototype review `08061b4f-c3e3-435f-bdcb-8567c760b891` records 654 assertions/0 failures and three approved reviews after gallery-focus/C-anchor fixes. The later React A1/A2/A3 slice records 18 smoke checks.

These are historical runs, not new execution. SR/touch/visual acceptance gates are now owner-accepted without execution. FPS remains unmeasured; no performance PASS or invented FPS threshold is asserted.

### AC2 — exact upstream provenance: FAIL / overall closure BLOCKED

The copied/adapted artifact is **BlurFade in the isolated React prototype**, not unrelated later production UI.

Bounded read-only investigation included git history across all local refs for BlurFade source/notices and content references. It found initial commit `e106454a8d9e975bb5e2dbe1fe54e69513a62c52` and related 9ac24c2/64a9fa6 material, but did not recover an archived exact upstream registry payload/revision.

The original `docs/ui-concepts/task-27-react/THIRD_PARTY_NOTICES.md` already says the component was retrieved September29 from mutable `https://magicui.design/r/blur-fade.json`, without an immutable upstream pin. The MIT license link also refers to mutable main.

| Artifact | SHA256, equal original/current |
| --- | --- |
| Local adapted `blur-fade.tsx` | `b057797cb4b635f8ccbb1091b02d7491a265651ce3c79de4a960ef78c5041087` |
| Local `THIRD_PARTY_NOTICES.md` | `75c03e1868cdb41cdfed5f7fd7464dad448f002f401b2942818aefa97e2364cb` |

These hashes pin **local adapted bytes**, not the historical upstream payload. The simplified adaptation does not uniquely identify its upstream revision. The later MagicCard pin `d7207e5692d14c00dceafa8488d6d01f197fa0e4` is for another component; its notice explicitly excludes copied BlurFade and cannot establish this provenance. A source search found no BlurFade/blur-fade match in production src; no unsupported claim of production import or vulnerability is made.

This is a substantive original source-record criterion, not a manual site check. To resolve it, supply the preserved historical registry JSON/source, or an independently established historical upstream revision and hash with applicable license/notice/dependency records and a mapping to the adaptation. Today's mutable live payload, a local adaptation commit, or a different component's pin is insufficient. No external recovery was attempted and no claim of universal absence is made.

### AC3 — comparison, explicit owner choice and handoff: VERIFIED

Decision `f64bd615-e20c-448f-9323-845f559152c9` at September29 13:12:20UTC selects **A1 «Сигнал»** and only its scroll indicator/moderate reveals/transitions with reduced-motion. PLAN6 confirms the TASK25/26 handoff and subsequent implementation. No reopening B/C or A2/A3, and no new API/AI promise.

### AC4 — scope and spec disposition

**VERIFIED for prototype isolation. Final task-level spec disposition remains pending before eventual closure.**

The prototype work is isolated under docs/ui-concepts and does not duplicate production/API implementation owned by25/26/23/24. Later separate production A1 implementation does not violate this prototype boundary.

No no-op delta or premature declaration was created. Once AC2 is resolved, the design-only output can receive an honest task-level no-spec-impact declaration if it still changes no documented contract; another node's applied delta does not satisfy that gate. This closing step is separate from the substantive AC2 evidence gap.

## Changed live knowledge

- TASK21's previous vague current-source reconciliation blocker is resolved by targeted source/history checks; three historical approvals are explicitly recognized.
- Its remaining manual gates are accepted by owner decision, not relabelled as performed tests. TASK21 is now done with its own strict-gate declaration.
- TASK27 no longer waits for manual UI/SR/touch/visual acceptance or a new design selection. A1 remains selected. Exact historical BlurFade provenance is the remaining substantive unmet criterion.
- Prior comments `5ba6fb71-715e-447e-a42a-aae7daf93213` and `a1ee7f74-27ab-420f-934c-676483582401` remain history; the new reviews supersede their current blockers where stated.

## Validation limits and operations not performed

Source/history review only; no tests/suites/build/manual helper were run in this acceptance turn. Existing `docs/testing-followup-20261016.md`, `docs/continuation-evidence-20261016.json`, scanner source audit and Oct15 acceptance report remain contextual evidence, not new execution.

Parent API645/UI554/report121pages19groups PASS is controlled evidence with synthetic data; it does not prove live detection, audible SR, or upstream provenance. The first concurrent UI run had550PASS/4FAIL across3files; a separate unchanged-source run had554PASS. Cause remains unresolved; no fix is claimed.

No Docker, Engine/runtime/scanner proof reruns, LLM calls, private environment/key/token access, recovery operation, application/notice edits, branch/stage/commit, or parent/other-task mutation. TASK39/40/41 remain other agents' work. No fresh runtime evidence is implied by acceptance.
