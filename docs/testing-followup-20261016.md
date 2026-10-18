# Оставшиеся testing-задачи: проверки и синхронизация — 2026-10-16

## Новое продолжение: расширенный public image-only профиль

По запросу владельца реализован optional `public-hub-amd64-v1`: generic bounded DockerHub/linux-amd64 archive, strict identity/hash,11 normalized ecosystems, evidence-based OS/EOL/unknown coverage, archive-only durable persistence/checkpoints/config, server eligibility/manual input и receipt-derived browser profile. Независимые OCI/chain/isolated-launcher reviews после исправлений — scoped offline APPROVE, не native qualification. Отдельный безопасный launcher `dip-public-images` на8081 с новыми данными готов в source; исходный8080/старый HOLD не изменялись.

Финальные проверки: API1176/1176+tsc PASS; последовательный UI573/573 PASS; launcher/LOCAL/CVE/refresh/scheduler218/218 PASS; lint/typechecks/main+admin builds PASS. Actual Chromium controlled public manual input→POST→public consumer→SQLite→Debian/npm report/reload/fresh owner checks PASS, без HTTP mocking и без live scanner. Один дополнительный совместный тяжёлый API/UI прогон имел UI572PASS/1FAIL (C4 replay); отдельный файл53/53 и полный последовательный573/573 прошли без правок теста. Причина нестабильности не установлена, не объявлена исправленной.

Docker daemon всё ещё недоступен, поэтому real native public acquisition/Trivy/Compose/cgroup proof НЕ выполнялся. Подготовленный `tests-e2e/public-image-live.mjs --run-native` пока имеет только syntax/self-test NOT_RUN. Нужны запуск Docker Desktop и actual isolated8081 qualification; full TASK2 не done. Полный resulting DOC1 draft находится в `public-image-doc1-proposal-20261018.md`, validate_spec valid; он не предложен/не applied и не подменяет native acceptance. Детали: [public handoff](public-image-final-20261018.md).

## Предыдущий итог завершения текущего этапа

Продолжение TASK2/6 реализовано и проверено в source, но не развёрнуто: sanitized durable checkpoints + atomic cancelled snapshot, exact lease-token fencing, report HTTP/UI/reload и runtime composition/timestamp/path isolation. См. [финальный handoff](development-wrapup-20261018.md). Полный API:867/867 PASS; полный UI suite PASS; TypeScript/ESLint/main+admin builds PASS; после последних lint/runtime правок targeted221/221 PASS. Chromium report integration PASS с четырьмя cancellation cases и storage-error сценарием; это disposable integration, не текущий deployed smoke.

TASK2 и TASK6 больше не testing: перед реализацией они переведены в `in_progress`, после завершения текущего этапа действительно переведены в `blocked` с `[review]/[blocker]` и evidence **DIP-ARTF-546**. Из исходной testing-очереди остаётся TASK27. Шесть принятых TASK14/16/21/39/40/41 остаются done; новых done в этом этапе нет. Спецификации DOC1/2/6 пока не reconciled/applied для нового cancellation-контракта; старое правило DOC2 partial-on-cancel не используется как описание v15. Task closure/no-spec-impact не подставлялись вместо полной дельты.

Последняя проверка LOCAL: `stand:local:status` завершилась ошибкой Docker command; HTTP8080 не соединяется (curl exit7/000). Причина не установлена. Docker/стенд не перезапускались; migration15/rebuild/recreate/recovery не запускались, данные не удалялись. Предыдущий HTTP200 ниже — исторический результат.

## Предыдущий итог после решения владельца о ручной приёмке

**Из исходных девяти testing-задач шесть действительно закрыты в Flownix (`done`,100%): DIP-TASK-14,16,21,39,40,41.** Финальная live-сверка 2026-10-16 подтвердила ровно три оставшиеся testing-задачи: **TASK2 (70%), TASK6 (90%), TASK27 (90%)**. Родители каскадом не закрывались.

Владелец разрешил принимать оставшиеся ручные UI/SR/native-select/touch/visual проверки без исполнения: **ACCEPTED_BY_OWNER_NOT_TESTED**, а не executed PASS. Это не отмена security/provenance/функциональных требований, не accessibility certification и не измерение FPS.

| Принятая задача | Основание и strict-spec disposition |
|---|---|
| TASK14 | Исходные context/history/cache/isolation AC проверены; существующая task14 delta `13edf9b2-8929-467b-bd57-944851c9617f` → DOC14v2. Production activation не была отдельным исходным AC. |
| TASK16 | Безопасный Markdown, изоляция delivery/timeout и сохранность report; current production payload соответствует manifest275, approvals276/277 подтверждены. Новая source16 delta `ddb27777-51fd-4ac4-bfc5-7e030b48b3ef` → DOC15v2, validate PASS. Finite completed-reply NDJSON, не native token streaming. |
| TASK21 | Исходные tokens/primitives и три historical reviews сверены; manual gates owner-accepted. Собственная no-spec-impact declaration описывает реализацию уже согласованного контракта, не заимствует task20 delta. |
| TASK39 | Подтверждена applied source39 `c8b710c1-28a4-499b-8135-cdb667476be3` → DOC10v3; report UI/pagination review. |
| TASK40 | Четыре исходных AC, historical actual R10/reviews330/332 и текущие изменённые production seams приняты. Applied source40 `2a437ff0-ab33-46a7-8a9a-acc40e4e5467` → DOC12v2. Полная дополнительная recertification всех244 paths не является новым исходным AC. |
| TASK41 | Full rebased source41 `9b1d8f2a-23e5-4486-b1f7-43143688da17` → DOC10v4, validate PASS; global queries/filter→sort→slice и owner-scoped saved reports. |

### Что действительно остаётся

- **TASK2:** не завершена полная remote npm-positive/native positive Secrets и intended sinks/retention/provenance/dedup qualification. `apk|npm` parser существует; уже принятые source-assessment/conflict-preservation не переоткрываются. Нужен отдельный разрешённый изолированный proof с закреплёнными fixtures и искусственными секретами, не повтор старого R10. Новый review `d260e381-6fc7-4833-b72c-bc8942e41e1c`.
- **TASK6:** historical inspect import не заменяет live capture; default production runtime не имеет live port. Нужен отдельный Linux Engine API1.47/controller/enrollment стенд и квалификация application caller/permit/journal/IPC topology. DOC13 feature delta уже applied; собственная task-level spec disposition остаётся будущим шагом. Новый review `2a67e20e-7dc6-499e-adcb-86392dba46d0`.
- **TASK27:** ручные gates сняты, A1 «Сигнал» выбран. Осталось восстановить точный historical upstream payload/revision/license mapping для адаптированного BlurFade в изолированном React prototype. Локальный adaptation hash и mutable registry URL не устанавливают исходную версию. Production BlurFade import не найден. Review `c3506fa4-3f19-4679-aa1b-14d2a308b87e`.
- **Общий контракт отмены:** ТЗ/DOC2 требуют partial preservation, реализация публикует atomic terminal reports. Рекомендуется согласовать sanitized durable per-check checkpoints + fenced atomic cancel snapshot; альтернативное сужение требует явного решения владельца и spec/ТЗ change. Это не скрытый новый AC TASK2 и не разрешение публиковать сырые findings.

Итог опубликован в Flownix как **DIP-ARTF-545** (`owner-acceptance-final-20261016.md`), successor к историческому DIP-ARTF-544. Финальная `git diff --check` — PASS.

Полные новые приёмки с evidence, source comparison и точными tracker IDs:
- [TASK14/16](flownix-owner-chat-acceptance-20261016.md).
- [TASK21/27 и owner manual acceptance](flownix-owner-ui-acceptance-20261016.md).
- [TASK40](flownix-owner-cve-acceptance-20261016.md).
- [TASK39/41](flownix-report-sync-20261016.md).

Последняя read-only проверка: `pnpm stand:local:status` — api/worker/web/egress running, init containers exited; HTTP GET `http://127.0.0.1:8080/` — **200**. Без rebuild/recreate/recovery. Аккаунты, отчёты, volumes и стабильный JWT сохранены. Stage/commit/branch не выполнялись.

**Ниже сохранена хронология. Старые dispositions «только39/41 done,7testing», manual blockers и дополнительный audit-only blocker40 заменены итогом выше.** Исторические evidence JSON/pins не переписываются. Закрытие implementation-задач14/16 не сертифицирует native production/provider activation, старые данные или снятие HOLD.

## Предыдущий итог после восстановления MCP — до решения владельца

**MCP восстановлен, DIP-TASK-39 и DIP-TASK-41 действительно закрыты в Flownix (`done`,100%).** В Zed обнаружен прежний endpoint `https://mcp.flow.shipoora.ru/mcp`; в пользовательских настройках изменён только URL Flownix на официальный `https://mcp.flownix.ru/mcp`. Существующий Authorization сохранён, предоставленный в чате новый PAT не использовался и не сохранялся. После reload настроек получены успешные live policy/nodes/artifacts/delta/status responses; само изменение URL не доказывает причину каждого прежнего отказа. Настройки агентов/CLI и остальных MCP не менялись.

Свежая policy совпала с `.flownix`: full/strict, approval=false, spec_first=false, parallel/direct. Прочитаны актуальные9 testing nodes с критериями, comments, parents, components и deltas; проведены независимые непересекающиеся сверки.

- **TASK39:** ранее применённая source39 `c8b710c1-28a4-499b-8135-cdb667476be3` подтверждена; narrow review и done записаны.
- **TASK41:** полное тело перебазировано на live DOC10v3, duplicate source41 отсутствовала. Delta **`9b1d8f2a-23e5-4486-b1f7-43143688da17` applied**, DOC10 **v4**, validate PASS;14 added/2 modified/0 removed. Task41 связана с web/server. Human approval не присваивался: текущая policy его не требует. Родители не закрывались.
- **Остались testing7:** TASK2,6,14,16,21,27,40. На каждой записан свежий per-criterion `[review]`; необоснованных done/spec waivers нет. TASK16 approvals276/277 и выбранный A1 сохранены. DOC1/2/6/12/13/14 applied history перепроверена — прежняя формулировка «spec не применена» больше не используется как актуальный blocker.
- **TASK40:** в Artifactory найдены packet331, reviews330/332 и исходная244-file R10 map в326. Проверены доступные текстовые implementation reviews и34-file comparison (29 same/5 changed/0 missing). Полная lossless-проверка бинарных331v1/326v1 и исходной244-map ещё не закончена; источник не объявляется отсутствующим. Нужна передача этих публичных gzip через official download UI в `test-results/scanner-sync-20261016/` либо binary-safe tool без вывода signed URL, затем offline verification/diff; исторический proof не повторять.

Подробные live результаты и IDs:
- [Report39/41 closure](flownix-report-sync-20261016.md).
- [Scanner40 evidence reconciliation](flownix-scanner-sync-20261016.md).
- [Оставшиеся2/6/14/16/21/27](flownix-remaining-sync-20261016.md).

`continuation-evidence-20261016.json` ниже — неизменённый **снимок до восстановления MCP**, а не текущий remote status. Историческую `flownix-reconciliation-20261015.json` также не переписывали. LOCAL стенд и старые HOLD не изменялись при синхронизации.

## Историческая граница офлайн-сверки

Пользователь попросил завершать оставшиеся задачи в testing. В этой сессии `get_project_policy` и `list_nodes(kind=task,status=testing)` для проекта DIP вернули **`server shut down`**. Актуальные статусы, acceptance criteria, policy и применённые deltas не получены. Никакие задачи, планы, features или epics **не переведены в done**; обхода MCP через HTTP/CLI не было.

Ниже — исторически известные testing-задачи из `flownix-reconciliation-20261015.json`, а не свежий список трекера. Старую очередь и исторические evidence hashes этот документ не заменяет и не переписывает.

## Результаты предыдущего этапа (до продолжения ниже)

- UI553/553, API639/639, launcher/setup/refresh/scheduler174/174, lint/typecheck PASS.
- Новая DB `sha256:9dd4076bb4c826ace2a305983a2285de1044fbf99d27eb619b91abc4dfc1b43c` подключена к работающему новому LOCAL стенду.
- Browser E2E29.453s, завершён11:35:06.951Z: Secrets0, SBOM14, CVE0, Image config1, report/reload/freshlogin/metadata PASS.
- macOS LaunchAgent установлен на6часов; реальный фоновый run11:36:07.117Z–11:36:12.831Z завершился `unchanged` с authenticated current usability.
- Исторический R10/history/old-data recovery не повторялись, production/runtime/host/LLM/manual-SR acceptance не заявлены.

Подробности текущего запуска и аудита: [local-cve-auto-refresh.md](local-cve-auto-refresh.md).

## Исторические задачи и оставшиеся границы

| Задача | Локально подтверждено | Что не позволяет объявить полное закрытие |
|---|---|---|
| DIP-TASK-2 | Parser/worker/lifecycle tests и реальный четырёхкатегорийный LOCAL scan | Полная negative/provenance/security/long-idle/reconnect/restart и sink/retention матрица не подтверждена;0 secrets не является positive detection; cancellation partial-results contract остаётся конфликтным |
| DIP-TASK-6 | Default-deny и runtime/import/control guards | Нужна квалификация isolated Linux Engine API1.47/controller/enrollment/IPC/store topology/restart; обычный Docker Desktop её не заменяет |
| DIP-TASK-14 | Durable history isolation/CAS/replay/quota/context/failure tests | Native ingress/init/provider/topology acceptance не установлен; исторический history workflow под STOP, повтор не разрешён |
| DIP-TASK-16 | Client/Markdown/NDJSON/mock-browser tests; исторические независимые review276/277 | Нужны привязка текущего source к scope reviews, настоящая backend/client/nginx delivery и initialized-history приёмка, ручные keyboard/SR/visual checks; completed-reply framing не native token streaming |
| DIP-TASK-21 | Roles/names/descriptions/focus/keyboard/AX subset | Ручная слышимая VoiceOver/NVDA и native-select проверка, original-scope upstream/license/transitive/review reconciliation |
| DIP-TASK-27 | Выбор A1 «Сигнал», prototype responsive/reduced-motion checks | Touch/SR/FPS и исходный design scope review; immutable upstream pinning для production reuse. Отменённые B/C не нужно заново предъявлять к выбору |
| DIP-TASK-39 | Узкий saved-report UI/pagination/counts/controls/error/reset/responsive/HTTP-browser scope проверен | Исторически source39 DOC10 v3 применён; нужна актуальная сверка DOC10/source41 и финальный review. Локального нового implementation failure по этому узкому scope не найдено |
| DIP-TASK-40 | Исторический packet331/reviews330/332, current policy tests и новые LOCAL scans | Нужна сверка исторического полного evidence scope с текущим drift; новый LOCAL scan не доказывает эквивалентность R10. Без rerun/repin старого proof |
| DIP-TASK-41 | Global filter→sort→slice, bounded dataset/cursor/snapshot/auth/owner-first и HTTP-browser tests | Полный successor DOC10 остаётся локальным draft `report-view-task-41.spec.md`; нужен live rebase/dedup/validation/delta application/final review, не фиктивный no-spec-impact |

Это локально документированные gates, не заново прочитанные исходные task AC. Источники: `release-readiness-20261015.md`, `acceptance-final-20261015.md`, `flownix-reconciliation-20261015.json`, `server/runtime/docs/operator-runbook.md`, `server/api/src/llm/TASK14.md`, `deployment/rollout-evidence-update-20261010.md`.

## Исторический план действий при восстановлении MCP

1. Прочитать свежие policy, список testing и полные nodes/parents/components/comments/deltas.
2. Для39/41 сверить DOC10 и уже подготовленную source41 спецификацию; не создавать дубли и не обходить требуемое approval.
3. Записать по каждому актуальному критерию PASS/FAIL/BLOCKED с проверяемыми evidence.
4. Закрыть только действительно принятые узкие scopes. Ручные/внешние недоказанные gates оставить явно незавершёнными; не закрывать родителя каскадом.

Локальный human-only screen-reader helper: `node tests-e2e/final-accessibility.mjs --manual`. В этой сессии он **не запускался**: AX snapshot и автоматизация не подтверждают слышимость VoiceOver и не закрывают native scanner/provider/security gates.

## Продолжение 2026-10-16: исправления и новая проверка

После запроса «продолжай здесь по промпту» заново прочитаны контекст, навыки и рабочее дерево. Ветка `feat/dip-task-30-21st-components`, HEAD `f2853f5`; все предыдущие незакоммиченные изменения сохранены. Новый вызов **только `get_project_policy`** вновь вернул `server shut down`: новый список testing не запрашивался после этого отказа, актуальные AC/policy/deltas не получены. Обходов, remote writes, stage/commit/branch не было. Историческая очередь `flownix-reconciliation-20261015.json` не изменялась.

### Реально исправлено

В отдельных непересекающихся областях работали три агента; scanner-аудитор затем независимо проверил host-исправления.

1. **HOLD-status:** scheduler больше не заменяет прошлый public status до получения обновлятором shared lock. Отказ из-за существующей блокировки сохраняет bytes/inode предыдущего статуса.
2. **Dangling symlink:** запись status отвергает существующую dangling-ссылку, а не заменяет её при проверке через `existsSync`.
3. **Идентичность scheduler lock:** перед публикацией статуса и освобождением проверяются device/inode; подменённая блокировка не снимается.
4. **Runtime qualification:** обычный refresh проверяет фактические security/resources/ports/config profiles до admission fence, при readiness пересозданных API/worker и при итоговой сверке. Ранее полная проверка использовалась в отдельном HOLD workflow, а обычная ветка была слабее.
5. **Порядок проверки mounts:** независимый reviewer обнаружил, что первоначальная корректировка пункта4 ещё позволяла дойти до `READY_PROBE` worker и запуска API до полной mount-проверки. Проверка извлечена из namespace inventory в общий `validateNamespaceMounts`; readiness использует её с **точным ожидаемым кандидатом** до exec и до API up. Семь регрессий проверяют writable/substituted release/cache и неправильный volume, sticky HOLD, отсутствие readiness exec/API up и отказ повторного запуска. Повторный независимый review: **ACCEPT для исправленного узкого scope**, не live activation acceptance.

Изменены `scripts/{local-stand,refresh-local-cve,schedule-local-cve}.mjs` и соответствующие host-тесты. Production scanner/ledger/report/React implementation в этом продолжении не менялись. Реальный refresh, install, recovery и пересоздание стенда не запускались; новый host-код будет прочитан планировщиком при следующем запуске, plist не менялся.

### Новое покрытие, а не формальное закрытие задач

- `server/api/src/worker/secrets-publication-boundary.test.ts`: **6 новых synthetic регрессий**. Положительный Secrets stdout проходит actual adapter/parser → consumer → временный SQLite → reopen; сырые canary/RuleID не сохраняются в таблицах/main/WAL/SHM. Truncated/nonzero output, buffered output при cancel, поздний успешный runner и cancel во время следующей проверки не публикуют находки/повторный terminal. Это **не native Trivy positive detection**, не все sinks/retention и не fulfillment partial-preservation AC.
- `tests-e2e/report-live-api.mjs`: реальные HTTP/SQLite/browser zero-match/reset для трёх категорий при сохранении полного итога; Secrets line0 как known, numeric asc/desc и null-last. `reportViewControls.test.tsx` добавляет UI-регрессию строки0 без evidence payload.
- [Scanner source audit](scanner-source-audit-20261016.md): независимо проверены доступные public runner/predecessor hashes; по **более ранней** Stage2-карте 85 paths —55 совпали,30 изменились,0 отсутствуют. Это не post-R10 diff. Сам packet331, полный244-path R10 map и reviews330/332 не найдены в проверенных public roots; полнота исторического scope не выдумана. Исходный R10 не запускался и не перепривязывался.

### Проверки этого продолжения

| Проверка | Фактический результат и граница |
|---|---|
| Combined launcher/setup/refresh/scheduler | **191/191 PASS** на окончательной версии, агент-исполнитель; независимый reviewer отдельно выполнил новую mount-группу **8/8** (семь вариантов + enclosing test). Координатор до второго исправления выполнил183/183; это разные версии, числа не складываются. |
| `pnpm test:api` | **645/645 PASS**,24.052s, координатор; включает6 новых synthetic worker cases. |
| `pnpm exec vitest run --reporter=default --reporter=json --outputFile=test-results/continuation-ui-20261016.json` | **554/554 PASS**,25 файлов,43.82s, координатор; исходники и timeouts перед этим запуском не менялись. |
| `pnpm test:report-integration` | **PASS**,19 групп /121 подтверждённая страница,12.987s, координатор; настоящий ephemeral Nest/auth/SQLite/current UI, synthetic dataset. Cleanup PASS,0 browser errors/внешних запросов/LLM calls. |
| `pnpm lint && pnpm typecheck` | **PASS**, координатор. После финального mount-исправления повторный scoped ESLint —PASS. API TypeScript отдельно проверен scanner-агентом —PASS. |
| `pnpm stand:local:status` | **api/worker/web/egress running**, init containers exited. Последняя проверка после host-изменений. |
| `pnpm cve:auto:status` | Schedule loaded; показан **предыдущий**, не новый launchd run11:36:07–11:36:12Z, completed/unchanged. |
| Loopback web GET `/` | **HTTP200** после изменений. Новый actual scanner/browser CVE E2E не повторялся: scanner/UI implementation и контейнеры не менялись. |
| `git diff --check` | **PASS**, без staging. |

**Промежуточные failures не скрыты:** первый full UI run одновременно с host/API tests завершился550 PASS /4 FAIL (3 файла). Отдельный повтор без изменения source/timeouts дал554/554; причина первого отказа не установлена, чувствительность к нагрузке — гипотеза, не исправленный defect. Расширенный browser probe сначала остановился на слишком точном новом locator «Строка0»; он исправлен на фактический полный текст `secret · Строка 0`, затем весь121-page run прошёл при прежнем assertion timeout7s. Scanner-агент исправил только свою новую ошибочную проверку `pending() === 0` на пустой массив; production для зелёного результата не менялся.

Публичная машинно-читаемая сводка с source hashes и подготовленными review comments на момент офлайн-проверки: [continuation-evidence-20261016.json](continuation-evidence-20261016.json). Это **новое локальное evidence**, не Flownix artifact, не замена старым seals и не автоматическая очередь команд.

### Следующие действия на момент офлайн-проверки (MCP-пункты выполнены выше)

- **Flownix:** восстановить MCP; затем перечитать policy/nodes/parents/components/deltas и сделать DOC10 source39/source41 rebase/dedup/validate/apply. Закрытых здесь задач **0**, parents не закрывались. Source41 нельзя заменять no-spec-impact.
- **TASK40:** получить через восстановленный MCP либо предоставленный владельцем публичный export packet331 + reviews330/332 + исходную R10 source map/bytes. Достаточно offline comparison; исторический proof повторять нельзя.
- **Отмена:** вопрос владельцу — **сохраняем ли требование ТЗ о частичных результатах?** Если да, следующий этап — отдельный согласованный durable per-check checkpoint + atomic cancel snapshot (дизайн и необходимые fences в scanner audit); сырые fragments публиковать нельзя. Если нет, требуется явное согласование сужения и spec/ТЗ delta, а не закрытие по текущим tests. Ни один вариант здесь не выбран.
- **Manual UI21/27:** участие человека для VoiceOver/native select/touch; FPS требует согласованного устройства и порогов. Human-only helper не запускался без оператора.
- **Runtime6 / history14 / chat16:** isolated Linux Engine1.47/controller/enrollment и отдельная native provider/history/ingress приёмка остаются внешними gates. Старые history STOP не повторялись; прежние approvals276/277 не отменены и не выдаются за current-source qualification.

Новый LOCAL стенд оставлен доступным на **http://127.0.0.1:8080**. Аккаунты, отчёты, volumes, JWT, production trust, старые holders/HOLD/locks/backups не менялись этим продолжением.
