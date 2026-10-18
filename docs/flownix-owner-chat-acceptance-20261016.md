# Приёмка TASK14 / TASK16 по исходным критериям — 2026-10-16

## Итог и полномочия

Проект `520a0059-d0f2-4f86-8d93-fc15035a5715`. Свежая MCP policy: strict, require_proposal_approval=false, spec_first=false, completion_flow=direct, execution_order=parallel, profile=full. Выполнены только разрешённые tracker mutations TASK14/TASK16 и нового task16 companion. Единственная локальная запись этого прохода — этот новый файл.

Владелец попросил принимать всё обоснованно завершённое и снял оставшиеся ручные UI/SR/keyboard/visual gates. Это **WAIVED / NOT TESTED**, не manual PASS и не снятие требований функциональности или безопасности сервера.

| Узел | До | Подтверждённое состояние после |
|---|---|---|
| DIP-TASK-14 | testing / 100 | **done / 100**, COMP3, ссылка DOC14 сохранена |
| DIP-TASK-16 | testing / 85 | **done / 100**, COMP1+COMP3 сохранены, ссылка DOC15 |
| DIP-DOC-14 | v2 | v2, без изменения |
| DIP-DOC-15 | не существовал | создан и доведён до **v2**, COMP1+COMP3, domain `scan-chat-delivery` |
| DIP-PLAN-4 / DIP-FEAT-4 | backlog | backlog, не изменены |

Все шесть задач PLAN4 теперь наблюдаются done100. Каскад родителей не выполнялся: это вне делегированной authority и не приёмка activation/rollout. TASK40 принадлежит координатору и не изменялся. TASK39/41 этого прохода не касались.

## Почему native HOLD не оставляет исходные задачи открытыми

Полные task contents/comments, PLAN4/FEAT4, актуальные DOC8v3/DOC9v2/DOC11v2/DOC14v2 и дельты прочитаны. `get_dependencies` обеих задач пуст. Исходные критерии TASK14 — context/overflow/cache/isolation; TASK16 — inert Markdown/scan-timeout isolation/report preservation. Production deployment не указан отдельным AC или dependency.

DOC14 Supported topology требует проверки topology **до activation**, а Non-goals явно исключают LIVE/provider/billing/privacy/topology proof. DOC8/9/11 отдельно исключают TASK16. Parent ранее согласовал finite completed-reply NDJSON DIP-ARTF-234 (comment `263d1a98-7ff3-483d-a17a-2f14954ac855`), а не native provider tokens.

Таким образом, прежние blanket BLOCKED dispositions были шире исходной приёмки. Новые reviews пересматривают именно этот вывод, а не исторические факты. Неудачные native preflight/initializer attempts, неизвестная причина, SPENT359/360, STOP/HOLD сохраняются. Никакого init/recovery/deploy/provider/retry разрешения закрытие задач не выдаёт.

## Per-criterion acceptance

### TASK14 — четыре PASS в implementation / controlled evidence scope

1. Большой report и длинная история: mandatory CRITICAL/UNKNOWN, coverage/reasons, source bindings, user decisions/constraints сохраняются; optional материал редуцируется детерминированно.
2. Mandatory minimum overflow: честный presend отказ; complete HTTP projection и отдельный stored cap 512KiB проверяются внутри transaction, C+1 rollback, прежний GET читаем; 100KiB completion reserve не уменьшен, память не удаляется.
3. Изменение permissions/findings: свежие trusted session/access/report/policy/history guards; immutable prepared-context cache проверяется against authoritative rebuilt context. Это не output cache и не экономия provider calls.
4. A→B: durable ownership owner+scan, operation/session fences и CAS/replay не допускают переноса истории в чужой scope. Same-owner re-login не удаляет подтверждённую память.

Исторические independent R3 reviews224/225/226→230 подтверждают исправления projection/readability, replay identity и public fingerprint allowlist. Текущий код и поздняя suite evidence сопоставлены отдельно; не заявлена неизменность всех исторических байтов.

### TASK16 — три PASS в implementation / controlled evidence scope

1. Unfinished fence/script/javascript инертны: partial NDJSON frames не публикуются в Markdown/copy/citations; lazy renderer отключает raw HTML/images/Mermaid/highlighter, unsafe URL не активен. Nested list/quote fallback/copy исправлен и проверен; corrected targeted375 evidence283/284 не смешивается с более ранним browser258/259.
2. Scan switch/timeout не смешивают беседы: session-generation/full-status scope, A→B→A invalidation, client40s/panel45s abort и guards поздних callbacks; exact tuple/nonce/seq/EOF и fresh durable full-turn equality до ответа.
3. Coverage/findings доступны при error/quota: scanner sections вне chat; controlled browser проверял byte-identical report. Accepted current receipt → usage0/error1; unavailable receipt → только error0, без invented zero, prior counters, invalid content, refund или automatic resend.

FULL independent276/277 подтверждают R5 и разрешают C16-SEC-R4-01 в его точном source scope. Реальный cookie/Nest/SQLite/QuotaLedger/adapter path тестировался с synthetic guarded transport/receipt; это больше disconnected unit, но НЕ native production/provider end-to-end.

## Сверка текущих байтов и общей wiring

### TASK16 manifest275

`docs/task16-chat-manifest.json`: 10457 bytes, SHA256 `a72207c147823b819da851a9ad58028b8bd314581d0a1d229c3fe2fdf41f3261`.

- **18/19 payload exact**, **7/7 supplements exact**.
- **Все production payload совпадают** с reviewed275.
- Единственное отличие — `server/api/src/llm/tests/history-delivery.test.ts`: 18910→18909 bytes, SHA `41f042fb162f29d9e3a36e9b5d9826c2deb385ea768bd02c830da518c33c6b26` → `127e71a83b4a2a23ad6bcb89d85102f06d07bcadc2f97f58d060613ee91148ad`. Удалён лишний escape двойной кавычки внутри single-quoted literal; строка семантически та же.
- Все пять backend texts decoded snapshot270 сопоставлены в памяти, без extraction/перезаписи: четыре exact, пятый — только указанная строка.
- Snapshot gzip SHA `d07ddcefec7e3d7bc4eea8132193b05f80a694aab4e6035488b19ea9f9b8e72f`, decoded SHA `64120448d10ffa29126480aa1c9d4521240f55c07d942477a0624365fe87783e`.

### Общая база TASK14 manifest215

**17/24 exact**. Семь отличий полностью классифицированы:

- Четыре supersessions — `TASK14.md`, `history.service.ts`, `llm.controller.ts`, `tests/history.http.test.ts` — exact current275.
- `history-contract.ts`: добавлен только локальный lint comment. Его удаление в памяти даёт точный215 SHA `fd31ff1f57887cb029b19a2119b04caddf41a030c3c4750ae2b5d6d79fb2118d`; current `bb1ffb4c566dbfc2fb5f2f450a1c0226aa1bc20a36e84490b3d24734c15c4daa`.
- `openrouter-transport.ts`: документированный TLS cleanup fix2026-10-15 — destruction через setImmediate после native secureConnect callback + lint comment. Reverse transformation в памяти даёт точный215 SHA `8f02d9d95783fc99533089a54afe80a4598f2efe7694c297a3e8032c701ac9f4`; current `a167bac07066b8ad1213dbf3cc249e83688f259059d7a7a7d73ccb260184530c`. Guards, immediate settlement, deadline/listener cleanup, verified TLS и body-send authority сохранены.
- `tests/openrouter-transport.test.ts`: текущий regression source прочитан; повторные denied children, socket cleanup, bounded child close/reap. Current SHA `2b470d77a7dcbd53b6ea6d694931c0b4f0565400f86e3a8aa0d25ad37332159a`, historical215 `750ae656aa86ec66a97e69d25d09d4d620beabfb7fe38e82edfc239333c58770`. Это поздняя regression evidence, не historical byte match. Основание: `release-readiness-20261015.md:68` и поздние API626/645 passes; новый TLS test здесь не выполнялся.

Прочитаны текущие public entry/wiring: `main.ts` с bodyParser:false → `configureParentIngress` → `registerHistoryIngress` до ordinary parsers; AppModule → LlmModule → LlmService.history → HistoryService. HistoryRuntime требует explicit enabled/revision/authority и существующий store; source presence не доказывает его активацию. На frontend прослежены ScanDetailPage sibling report + Summary→Chat, scope/session observable, источник всех нужных страниц `collectSummarySources`, usage schema, current-context/durable-history publication.

**Предел:** manifest275 никогда не содержал полного transitive graph всего приложения. Проверка owned payload + общих seams/wiring не переименована в historical whole-checkout approval или повторную native qualification. Исторические manifest/proof pins не менялись. Старые proof workspaces, retained runtime resources и private env не читались.

## Спецификации и точные записи

### TASK14

- Использована уже applied task14 delta **`13edf9b2-8929-467b-bd57-944851c9617f`**.
- DOC14 ID `31d22e2d-d9eb-457f-9973-4de823dc08c2`, base1 → **v2**.
- Human review_status=approved; applied **2026-10-15 17:26:32.040586 UTC**.
- Новый no-op delta/no-spec-impact не создавался. Stale local UNAPPLIED prose не подменяет live state.
- `[review]` **`14c2ed7e-1808-4e51-b588-14fa0d615b74`**; заменяет scope disposition `f739d347-1704-4dfe-b491-51b0fc996c21` без удаления истории.
- `[done]` **`d36bb21b-dee2-45e5-927d-1f8464181a29`**.

### TASK16

- Перед созданием: source16 deltas пусты, docs1–14 и archive проверены, RAG подтвердил adjacent scopes; отдельного task16 contract нет.
- Создан **DIP-DOC-15**, ID **`ac654c74-78b9-47d0-87d7-0669acee01ab`**, COMP1+COMP3, `scan-chat-delivery`.
- Начальная purpose-only v1 — bootstrap, не closing evidence. Автоматическая initial revision `f3bfacd3-8b96-430a-86a3-41d7e909a0e1` не task-sourced; её предупреждение no_requirements устраняется полным v2.
- Full source16 delta **`ddb27777-51fd-4ac4-bfc5-7e030b48b3ef`**, base1 → **v2**, **applied 2026-10-16 15:12:51.512987 UTC**.
- `validate_spec` полного body до предложения и applied DOC15 после применения: **valid=true**. Ops:10 added requirements, без непреднамеренных removals.
- review_status=pending сохраняется: policy approval=false разрешает apply; human approval **не заявлен**, approve tool не вызван.
- `[review]` **`50cda764-1701-4d04-bdeb-73a65bb288bd`**; заменяет blanket disposition `baa0a35b-6b6d-47c1-8052-896adc020f25`.
- `[done]` **`d627cd62-f9d9-4d29-bea8-8406b190f6c1`**.
- References: TASK16↔DOC15; DOC15→DOC8/DOC9/DOC11/DOC14. Существующие документы и parent references не переписаны. Binding проверен после closure: TASK14 COMP3, TASK16 COMP1+COMP3.

## Validation attribution и непроверенные области

В этом проходе выполнены read-only source/hash/diff inspection и server-side spec validation; **tests/build/browser/native proofs не перезапускались**. `docs/continuation-evidence-20261016.json` подтверждает результаты координатора API645 PASS, UI554 PASS; первый concurrent UI550/4FAIL остаётся с неизвестной причиной, isolated pass не объявлен исправлением. Report121 pages/19groups PASS — scanner saved-report evidence, не chat/provider proof.

Не установлены и не waived:

- native history initializer/serving, selected nginx/raw-ingress/main topology и полное реальное browser→backend→provider взаимодействие;
- production single-authority/quiesced maintenance qualification, provider availability/billing/privacy и runtime key readiness;
- сохранность прежних данных, recovery, снятие STOP/HOLD.

Ручные UI/SR/keyboard/visual проверки отдельно owner-waived; никакого услышанного SR/ручного PASS нет. Эти ограничения не объявлены скрытыми новыми AC исходных задач. Любая будущая activation/rollout проверяется отдельно координатором/оператором.

Исходники, исторические docs/evidence/pins, private данные, чужие uncommitted файлы не изменялись. Никаких branch/stage/commit, scanner/Docker/LLM/provider/host операций или parent closure.
