# Public8081 — actual READY25.10; scanner PASS, AI qualification BLOCKED

## Текущий итог

Public **http://127.0.0.1:8081 — HTTP200**, protected8080 — **HTTP200**. Final probes выполнены после native scan/ownership/cancel-form diagnostics. Public `.operation.lock` отсутствует. Docker Desktop перезапущен **один раз**, только после явного разрешения владельца, без factory reset/deletion/prune. Старые environments/holders/ключи/DB не inspect/exec/переносились; их lifecycle вручную не управлялся. Сам разрешённый Desktop restart затронул daemon и восстановил HTTP200 на8080.

Новые registry/LLM source changes из f39be89 развёрнуты через exact continuation, не через повторный normal up. **Accounts/reports/JWT/history/quota preserved**; original backups/evidence сохранены. Это successful deployment/preservation, не успешная LLM generation.

## Recovery receipt и границы

- Exact audit: `deploy-2c9ed08b8269264b09bf14eb6189a649`.
- Исходный normal deployment: `build-submit-worker`, category `unclassified`; root cause не установлен.
- Последующий retained init image `input/output error` после Desktop restart не воспроизвёлся. Это отдельный факт, не доказанная причина исходного worker build.
- После разрешённого restart container IDs/images/control всех7 совпали checkpoint; API/worker/web+2init epochs неизменны. Только2gateway epochs изменились точно в restart window `2026-10-25T17:57:47Z`. Узкая fixed old/new policy независимо reviewed.
- Собственный mutable worker output tag имел NotFound missing blob; scoped image-tag census отказывал с тем же blob. Exact audit/tag/digest/failure-proof deviation independently reviewed: workeroutput только rebuild-only, не image certification/executable authority. Четыре других fixed tags реально inspect/validated. **Отсутствие дополнительных inert own-prefix image tags не доказано**; full image-census PASS не заявляется. Exact container/network/volume/consumer census сохранён.
- Новый checker прошёл с fresh runtime review token; его receipt сохранён в private operation evidence. **Token consumed; не повторять.**
- Координатор выполнил **один** `continue-existing-build` с этим token и acknowledgements. Actual **READY/exit0**: mandatory fresh network-none current/original comparison всех4stores ДОbuild; worker rebuilt/actualvalidated/immutablepinned доstart; initializer не запускался; before/afterAPI comparisons и web-last выполнены sharedflow. Whole operation evidence archived; original records/backups не перезаписаны/не удалены.
- Recovery source module SHA256 `f8ea4a3d06216e578fb02557bf0dafbad26269a1247cdf40683116359d6c96dd`, stand `e4cb74fa26f7cbc6bd4629a93b0c33191d64a95ca5ce8ef88a2bd836eae01a11`. Independent review без P1/P2 в scoped delta,215offline testsPASS. Эти tests не выдаются за native proof; native READY отдельный receipt.

### Независимый postflight

Наблюдение `2026-10-25T18:34:57Z`:7services/6networks,5running/2init exited0, APIhealthy UID/GID65532, readonlyrootfs. Key-volume consumer толькоAPI `/run/secrets` RO/nocopy. Worker memory=swapTotal4GiB/CPU1/PIDs128, tmpfs16+2304MiB, DBbindRO. API/worker безuplink; registry/LLM gateways изолированы. Только web публикует127.0.0.1:8081. Все7 actualimages совпали persisted immutablepins. Нет дополнительных контейнеров/сетевых endpoints в exact public namespace.3expectedvolumes. `.operation.lock` absent, auditcompletion regularfile. Source manifest403entries/hashes/metadata/directories совпал с current reviewed source. Env/key/DB не выводились.

## Реальная браузерная проверка scanner и AI

ONE full attempt `04ee2731-a67d-4ed5-9a5b-7cd8560b80e8`, run `1355df1f-dd0d-430c-831d-c9234ec4ab59`, `18:33:27–18:35:50 UTC`. Native OCI/worker/provider не mocked.

-2disposable accounts,1actual Node scan `41450b5b-641d-4839-9fae-c2698ef75dae`.
- ManualHub target `registry-1.docker.io/library/node:22.14.0-alpine3.21`, linux/amd64, digest `sha256:01393fe5a51489b63da0ab51aa8e0a7ff9990132917cf20cfc3d46f5e36c0e48`.
- Scan **completed**, Secrets/SBOM/vuln/config **checked**; actual report **158CVE/0DebianTEMP,4pages**. Counts относятся только к этому pinned run, не future tags/DB.
- Registration/readiness/deployedUI/report/freshlogin/preservation/safety **PASS**, guarddenials0/pageerrors0.
- Chat1 **BLOCKED HTTP502 `LLM_PROVIDER_UNAVAILABLE`**, без валидной providerFailure: upstreamstatus/rootcause неизвестны. JSON502 не доказывает HTTP502 от OpenRouter; возможные transport/validation/abort/accounting ветки source не различены actual evidence.
- Chat2 не отправлялся; successful history reload/freshlogin conversations не qualified.
- Separate explicit translation context **PASS**; actual translation **BLOCKED HTTP429 `LLM_PROVIDER_RATE_LIMITED`, kind rate_limited/status429**, retryhint отсутствует, не0. Это provider-classified отказ, не `LLM_QUOTA_EXCEEDED`; точная account/upstream/capacity причина неизвестна. Original/translation toggle и semanticquality не проверены успешным ответом.
- GenerationPOST максимум3; фактически **1chat+1translation**. Нет autoretry/fallback/modelchange/paidpath. Нет manualrefund/reset unknown/dispatched liabilities.
- Overallfullrun **FAIL/exit1**: initial foreign-body assertion не принял допустимую форму404; historicalFAIL сохраняется. См. отдельную ownership qualification ниже, не переименовывать старый результат.

Artifacts `public-final-04ee2731-...-ai-translation.json/.md` exclusive0600, без credentials/conversations/providerpayload/screenshots/HAR/storageState. Provider egress/billing independently unobserved; semanticaccuracy **unverified**.

## Ownership: отдельный actual PASS

GET-only diagnostic показал exact404body `{statusCode,message}` у scan-status и404 finiteerrorCode у LLM endpoints. Исправлен только runner `assertDeniedReply`: exact2field404 NotFound branch, строгое отклонение extra/nested/non404/неверногоmessage. Native API не менялся; scopednegative tests+independentreviewPASS.

Новая independent **UI-registration** в isolated browser безcookie injection, run `4dc12aa6-fcc5-4c38-b1e4-82ea8a3ba2a5`:
- чужие status/history/chat-context/readiness/translation-context **все404**;
- чужаяreportUI показалаdenial, findings/chat отсутствуют;
-0scanPOST,0generationPOST,0guarddenials/0pageerrors; browserclosed.

`public-final-ownership-browser-20261025.json/.md` — новая acceptance, не rewrite предыдущегоFAIL. `public-final-ownership-20261025.json` — более узкий первоначальныйGET diagnostic.

## Cancel: NOT QUALIFIED, без слепого повтора

Добавлен reviewed `--cancel-only` runner: максимум1scan+1cancel, всеLLMPOST denied доpermits, suppliedkey допустим; checkedsubset→UIcancel→durablecomparisons/reload/history/freshlogin; raceINCONCLUSIVE/norelaunch. Targetedoffline67PASS, independent16tests+13guardprobes+2AIimportregressionsPASS.

ONE actual attempt `f086c21c-87cb-4919-b824-e457a06036ec`, run `d17ad639-9af8-4f19-b7fc-8ab1a8457add`, `19:03:58–19:04:25 UTC`:1account, **0scanPOST/0cancelPOST/0generationPOST**. Отказ строки561 (consent.check / ожидание enabledsubmit) доsubmission. OverallFAILexit1, cancelBLOCKED, durablecancelcasesNOTRUN; safetyPASS, browserclosed/noactivescan.

ONE отдельнаяform-onlydiagnostic registration воспроизвела шаги раздельно: eligibilityHTTP200READY, consent.checkPASS иsubmitenabledPASS,0scan/cancel/LLMPOST. Failure **NOT_REPRODUCED, rootcauseUNKNOWN**, не исправлен. `public-final-cancel-form-20261025.json` сохранён отдельно. Новый scan/cancel attempt не повторялся без установленной причины.

## Public CVE: refresh download FAILED, scheduler pending

После завершения browsertraffic, в отдельном maintenancewindow выполнен **один** `node scripts/refresh-public-cve.mjs`: exit1 **phase=download**, exactcauseUNKNOWN. Sourceflow не дошёл до namespace/fence/preservation/activation/signing. Оба порта остались200, operationlockabsent, currentmanifestunchanged. Это не successfulchangedrefresh и не новаяCVEfreshness.

Осталась пустая private `.cve-refresh-work`, без downloadreceipts. Она сохранена: следующий обычныйrefresh будет отказанpreflight. **Не удалять scratch автоматически, не retry и не устанавливать scheduler поверх непроверенного workflow.** Нужны диагностируемый transport и отдельно reviewed disposition только этой staging-directory, без любыхDB/keys/backup/locks.

Current v2manifest `sha256:5903d201b3dc68dda334b9a9397ed51bd7956d834f43ab4edae6844a18912ced`, UpdatedAt `2026-10-20T19:12:26.430296739Z`; stale-but-usable до `2026-11-03T19:12:26.430296739Z`, freshness перепроверять на use. Локальная подписьоператора **не Aqua publisher signature**. Public scheduler **не установлен**; старыйLOCAL8080 updater не перенаправлялся.

Preflight до попытки:27.798GiBfree,2releases/3.613GB,2completedCVEbackups,3completedLLMdeployments. Эти numbers не reservation и не будущая capacityguarantee.

## Provider / пользовательский путь

Настроенная request/profile policy сохранена: **OpenRouter `xingchen-agi/xing4.0-29b-a4b:free` → `phala`**, free-only, требование ZDR, без автоматического fallback. Это требования конфигурации, не независимый аудит provider privacy. Key уже provisioned; не запрашивать его в чате и не импортировать повторно. Unauthenticated official catalog GET `2026-10-25T18:51:58.988Z`: HTTP200, Phala присутствует, prompt/completion price0; request price и ZDR flags этим endpoint не установлены. Это metadata, **не generation/privacy/billing proof**. Adapter `stream=false`; NDJSON — доставка завершённого проверенного ответа, не native token streaming.

Использование: отдельныйbrowsercontext для8081 → `/register` или `/login` → `/scans/new` → publicDockerHubreference/linuxamd64 →4checks/fresheligibility/confirm → completedreport. Чат на странице своегоотчёта послеявногосогласия. Перевод у выбранногоadvisorysource: «Прочитать условия перевода»→отдельноеcheckbox→«Перевести на русский»; сейчас successfulreplyнеподтверждён, при429нетавтоповтора, оригиналсохранён.

Требуемое внешнее действие дляAI: проверить доступность/лимиты точной freeпары в OpenRouter/Phala либо отдельно согласовать другуюprofilepolicy. Не обещать, что повторныйключ или повторчерезпроизвольныйинтервал исправит429; paidfallback/сменамодели безразрешениязапрещены.

## Проверки и tracker

Последние полные suites приложения на unchangedappsource: API1346/1346/UI742/742PASS, typecheck/lint/main/adminbuildsPASS; после этого менялись narrowrecoverymodule иbrowserrunner/tests, неbackend/frontendappcode. Recovery215offlinePASS и targetedcancel/ownershipchecks независимоPASS; финальныйrootlint/diffcheck отдельно. Vitechunkwarning иSSE/UIintermittency не объявленыfixed.

Flownix fresh policy: full/strict/approval=false/spec_first=false/parallel/direct. DOC15/DOC16v3 applied, TASK42 blocked; **новых done нет**. Родители каскадом не закрывались, принятые14/16/21/39/40/41 не переоткрывались. Два harness runs H6/H7 с шестью реальными агентами завершены с ограниченными outcomes; последующие read-only, implementation и native follow-ups явно отделены от прежних work results.

ВсеисторическиеFAIL/NOTRUNсохранены. Никакихcleanup/prune/reset/deletevolumes/backups/locks/keyread/logging/fullEnv/providerpayload/privateconversationartifacts. Exactcontinuation consumed: **не повторять checker/continue для завершённогоaudit**. Текущаяordinaryработане требует launcher/rebuild.
