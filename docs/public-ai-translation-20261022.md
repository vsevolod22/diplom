# Public AI / ru advisory translation — historical22.10 DEPLOYED READY, qualification BLOCKED

> **Operational status superseded25.10:** new rollout is in build HOLD, public8081HTTP000, separate Docker blob storage-I/O refusal during read-only recovery. New provider/UI/prompt fixes are source-tested, not deployed/accepted. Historical STOP below applied to22.10 scope; owner separately authorized new bounded qualification on25.10, but no new native attempt ran because infrastructure is blocked. DOC15/DOC16 are now v3; current full-body receipts and limits: [new handoff](public-product-handoff-20261025.md). Historical evidence below remains unchanged.

## Статус и разрешённая область

- Датированный пакет: `2026-10-22`; эта сессия — только документация/Flownix, не implementation review или rollout.
- Текущий translation/key rollout public `8081` — **actual READY, exit0**, по передаче координатора; **audit830b completion**, active HOLD отсутствует. **Accounts/reports/JWT/history/quota Preserved**. Это переданное actual rollout/preservation evidence, не повторный deploy/runtime proof этой документной сессии. `fccb96e` — исторический baseline до translation, не implementation commit новой работы.
- Source **implemented/frozen**, independent security source **GO**, без P1/P2; переданы actual **14 backend + 53 UI + 18 ScanPages**, sourceVersion match. Теперь public translation GET context/POST routes и UI **deployed** по отдельному READY receipt координатора, не только по source GO. `targetLanguage=ru`, оригинал/source/provenance/исходный language сохранены отдельно; нет auto-translation при открытии, требуется отдельный consent. Это не подтверждение успешной live генерации или семантического качества.
- Approved transfer из dedicated env в private state0600 и API-only/read-only provisioning завершены; **current-key native metadata/postflight PASS**, actual gateway GET auth/key **HTTP200/authenticated=true**. Два пользовательских ключа различались; оператор выбрал dedicated public key. Значение ключа переносилось только в памяти оператора и по защищённому stdin; в этом пакете/Flownix нет значений/хешей ключа или raw env. Это auth PASS, не generation PASS.
- Финальный qualification статус **BLOCKED**: attempt1 chat dispatched без observation/receipt, generation не подтверждена; separate operator completion HTTP429 — внешний отказ с неизвестной точной причиной. Attempt2/3 **закончились до provider** на GET otherlocal REQUEST_GUARD, без scan/chat/translation. Успешная production translation и два успешных chat messages **НЕ VERIFIED**. Реализация/UI deployed READY и context-ingress auth guard verified в своём scope; не full live PASS. **Новых попыток не выполнять**, fallback нет, current exact free Xing/Phala profile неизменен.
- Единственная локальная запись этой сессии — данный новый файл. Исходники, env/keys/private state, DB, deployment/service lifecycle, accepted task statuses и git history не изменяются. Координатор отдельно ведёт существующие env keys, deploy и native/provider проверки; значения ключей не читать и не записывать в этот пакет/Flownix.
- Fresh MCP policy повторно подтверждена: `full`, `strict`, `require_proposal_approval=false`, `spec_first=false`, `parallel`, `direct`. Проверены полный current DOC16 v1, полный reviewed delta/state/base и task-sourced список. Ранее validated `valid:true` full body совпало; после actual READY применена ровно дельта **a8bb0538-7228-4b83-b750-df604aacb0de**, **DOC16 v1 → v2**, state **applied**, `applied_at=2026-10-22T22:56:03.793625Z`. Review_status pending не gate при approval=false. Apply HOLD снят выполненным READY условием; **TASK42 переведена в blocked, не done** после fresh policy check; external provider/remaining browser qualification заблокированы, production translation/chat quality unverified.

## Финальная operator-проверка координатора

- Deployment `deploy-830b7aa07d1c9a728de1a957829e43c2` завершён READY: сохранён nonempty baseline всех четырёх stores и JWT. Во время rollout исправлен helper executor: только initial fenced snapshot использует prior API; before-api/after-api используют validated candidate API. Исчезновение прежней image metadata не подменялось реконструкцией. Completion не повторял build/init/worker restart; web открыт последним.
- Native postflight: 7 services/6 networks; API healthy UID65532, key volume имеет только одного consumer — API readonly `/run/secrets`; directory0500/key0400 UID/GID65532 проверены metadata-only. Helpers не получают key mount. 402 source entries и immutable pins совпали с reviewed build. Active HOLD отсутствует.
- Final typecheck, root lint, main/admin builds — PASS. Vite chunk warning >500kB остаётся. Full UI 669/669 PASS; full API 1333 pass/1 fail/2 cancelled, isolated failed files11 PASS (не считать whole-suite green).
- Live AI runner artifacts attempts1/2/3 сохранены неизменными. Поздняя read-only/offline сверка выявила неполный guard относительно трёх auto-discovery GET RuntimeScanPanel; разрешены только точные GET без query capabilities/targets/captures, ожидается404. Coordinator фактически проверил все три anonymous GET на public8081: **404**; runtime import/capture/live POST не включались. Это не переписывает прежние FAIL и не заменяет provider acceptance. После guard fix новых live attempts не выполнялось.
- Для перевода: свой terminal report → подробности CVE/advisory → конкретный источник → «Прочитать условия перевода» → отдельный checkbox → «Перевести на русский». При verified response — «Машинный перевод», «Оригинал/Перевод». Передача не запускается от одного раскрытия карточки; unavailable/failed translation не подменяет оригинал.
- Gateway auth/key HTTP200 и completion HTTP429 — разные факты. Наличие ключа/успешная auth не доказывают доступность free generation. Точный источник429 (account limit, gateway или upstream capacity) не установлен; no-fallback/profile не ослаблены. Operator probe синтетический, не successful real-report translation.

## Flownix receipts

| Узел | ID / состояние |
| --- | --- |
| Существующая feature | `DIP-FEAT-4`, `87440f3a-1c9c-4b11-a82c-c825c07fb149` |
| Существующий plan | `DIP-PLAN-4`, `c5d866ef-3644-4404-bad6-5af4e729cd87` |
| Единственная задача | `DIP-TASK-42`, `7eaa99d4-1b20-4316-b1fe-ab4165bd3c74` — **blocked**, source GO + DEPLOYED READY; external refusal/remaining browser qualification, не done |
| Итоговый TASK42 progress | `9bb82f90-d8d8-4eb3-a680-ae7a5ff098b6` |
| Итоговый TASK42 blocker | `48d08031-c80c-426e-80cd-08e6498012b8` |
| Документ | `DIP-DOC-16`, `31e6c814-621d-4dfd-9752-a7cdb3868826`, **v2**, `public-advisory-translation`; exact reviewed full body применено без переписывания |
| Полная task-sourced дельта | `a8bb0538-7228-4b83-b750-df604aacb0de`, TASK42 → DOC16 base1/version2, **applied**, `2026-10-22T22:56:03.793625Z`; validation valid:true |
| TASK42 current READY/apply comment | `0abdf42f-c8f8-4785-8c7a-a4a4157ad0d5` |
| DOC16 current READY/историческая title оговорка | `25864198-aa39-48e2-90c6-cafe53a9db5b` |
| Initial creation snapshot | `9ff62038-2d0f-49a0-8877-439f6e522347` — сервер помечает initial DOC16 v1 applied без source TASK42; это не implementation/live acceptance |
| Компоненты задачи и документа | `DIP-COMP-1` web-app (`src`), `DIP-COMP-3` server (`server`) |

Две RAG-проверки и структурная выборка всех 39 прежних задач не нашли отдельной translation задачи. RAG вернул в том числе исторические testing snapshots принятых задач; текущие structural node records подтверждают `done` для `DIP-TASK-14/16/21/39/40/41`. Ни одна из них не переоткрыта. Новая feature/plan не создавались.

Полностью прочитаны актуальные `DIP-DOC-1 v6`, `DIP-DOC-2 v8`, `DIP-DOC-6 v3`, `DIP-DOC-8 v3`, `DIP-DOC-15 v2`. DOC1/2 описывают scan/UI и прямо исключают LLM из последней сверки; DOC6 сохраняет фактический original advisory и исключает AI enrichment/перевод. DOC8/15 описывают summary/chat, не отдельный selected-text translation egress. Поэтому создан отдельный узкий draft machine derivative, без переписывания их полных требований. Старые proposed mixed P0 дельты оставлены без изменений и не используются как baseline для перевода.

Ссылки сохранены: TASK42 → DOC16/6/8/11/14/15; DOC16 → TASK42/FEAT4/DOC6/8/9/11/14/15; FEAT4 → DOC16 **с сохранением прежних DOC14/8/11 references**. Связи с прежними документами не меняют их тела, версии, требования или статусы принятых задач.

## Read-only source observations, не verdict

- `server/api/src/llm/TRANSLATION.md`, `translation-contract.ts`, `translation.service.ts`: отдельные API, eligibility, source hash, consent hash, guarded dispatch/accounting и publication fences.
- `server/api/src/llm/policy.ts`: exact public `xingchen-agi/xing4.0-29b-a4b:free` + `phala`; старый `apodex/apodex-1.1-mini:free` + `novita/bf16` остаётся отдельным legacy профилем. Новый `responseLanguageRevision: russian-prose-v1` входит в policy hash.
- `server/api/src/llm/prepared-request.ts`: summary/history просят русский human text с неизменными ключами/bindings/citations; translation просит только перевод `{title,description}`, не расширение summary/chat advisory egress.
- `src/features/scans/AdvisoryTranslationPanel.tsx`, `src/pages/scans/VulnAdvisoryCard.tsx`: оригинал отдельным текстом, явное чтение условий и consent/button, machine marker, source/session fencing, исходный неизвестный language не подменяется английским.
- Переданные координатором actual результаты: 14 backend + 53 UI + 18 ScanPages/sourceVersion match и independent security source GO без P1/P2. Дополнительный full UI: **669 PASS**. Полный API прогон: **1333 passed / 1 failed / 2 cancelled**; последующий isolated **11 PASS**, исходный отказ **NOT_REPRODUCED, НЕ FIXED**. Полный API прогон не объявляется зелёным из-за isolated PASS. Здесь тесты не перезапускались, команды/exact frozen candidate receipts не выдумываются; source GO и controlled tests не заменяют live provider/semantic-quality/privacy/billing proof.

## Финальное live evidence текущего разрешённого scope — attempts1–3, STOP

Источники attempt1: `docs/public-ai-live-20261022.json` и `.md` прочитаны; run `66874291-6aa6-427a-8ef2-e1f2595f3c73`, actuallyRun=true, `2026-10-22T22:55:45.512Z` → `22:56:53.204Z`. Credentials/payload artifacts не сохранялись. Дополнительные wire/accounting/auth/probe факты ниже атрибутированы текущей передаче координатора, а не выведены из ограниченной case-summary JSON.

| Область | Наблюдение и точная граница |
| --- | --- |
| Current key/postflight | Coordinator-reported native metadata validation PASS; API-only/read-only. Actual GET auth/key через LLM gateway: HTTP200, authenticated=true. Это **authentication PASS**, не generation PASS |
| Native Node scan/report | JSON: completed scan `304142ee-a0e6-415f-843a-748a22c5a601`, linux/amd64; 4 страницы, 158 CVE, 0 Debian TEMP. Native scan/report/deployed UI/readiness PASS; это не AI ответ |
| Первый browser chat | JSON: chat_1 BLOCKED/LLM_HTTP_ERROR, chatPosts=1. По wire передаче координатора HTTP200 **NDJSON error LLM_UNAVAILABLE**, не успешный ответ модели: HTTP200 framed transport не означает generation PASS |
| Dispatch и receipt | По передаче координатора один POST dispatched, persisted observation/receipt отсутствуют: **consumption UNKNOWN**. Не zero-call, не доказанная отмена/нулевая стоимость и не settled receipt. **НИКОГДА не делать manual refund/сброс quota** этой попытки; точная server-egress причина не установлена |
| Browser translation | JSON: translationPosts=0; context/translation/toggle NOT_RUN. Это **не попытка browser translation и не её provider failure/acceptance**. Реализация маршрутов/UI deployed; результат ru/quality пока unverified |
| Остальные gates attempt1 | JSON: history/relogin/foreign-denial/preservation NOT_RUN, safety **FAIL/REQUEST_GUARD**, blockedRequests=3, pageErrors=0. Не переименовывать guard failure в PASS и не переносить rollout preservation PASS на NOT_RUN browser preservation case |
| Отдельный tiny operator probe | По передаче координатора ровно один synthetic `prepareTranslation` probe с тем же fixed profile: actual OpenRouter HTTP429/errorCode429. Это не browser acceptance и не результат translation UI; точная причина quota/provider busy **неизвестна** |
| Граница вывода | JSON serverEgressIndependentlyObserved=false, billingIndependentlyVerified=false. Нет fallback/retry/смены free pair. HTTP429 и LLM_UNAVAILABLE не доказывают общий root cause или неисправный ключ, особенно при отдельном authenticated=true |

### Actual attempt2 и attempt3 — guard failure до provider

Прочитаны и оставлены без изменений `docs/public-ai-live-20261022.attempt2.json/.md` и `.attempt3.json/.md`.

| Attempt | Run / время UTC | Outcome |
| --- | --- | --- |
| attempt2 | `72c55c66-ccc0-42f7-9bce-67a73f764b35`; 23:09:51.726 → 23:09:53.469 | actuallyRun=true; guard `api-get-not-allowed`, `GET`, `otherlocal`, count1; safety **FAIL/REQUEST_GUARD**, scanLaunches0/chatPosts0/translationPosts0 |
| attempt3 | `b32b0957-f871-4f7e-b95f-6d1acd41259f`; 23:13:27.646 → 23:13:29.316 | actuallyRun=true; тот же GET otherlocal guard, count1; safety **FAIL/REQUEST_GUARD**, scanLaunches0/chatPosts0/translationPosts0 |

Оба прогона остановились до нового scan/provider, после disposable owner registration; report/chat/history/translation/foreign/preservation case states — NOT_RUN. Это **не дополнительные provider refusals и не successful browser acceptance**. Credentials/payload artifacts не сохранены; прежние artifacts/FAIL остаются неизменными. Rollout preservation PASS и attempt1 Node report не превращают их NOT_RUN cases в PASS.

Узкий source/test-guard scope для возможной будущей коррекции — только fixed exact read-only runtime-capability/targets. Ограниченная guard-правка не означает исправленный historical FAIL или выполненный live PASS; в этом документном scope source не меняется, новых продуктовых требований не вводится. **Больше попыток нет и не выполнять**. Не дублировать вызовы/не менять модель/provider/квоты. Итоговый TASK42 [progress]/[blocker] записан, состояние **blocked**, не done. Это qualification verdict, не утверждение, что deployed код отсутствует или готовый продукт полностью принят.

---

# Полный контракт DIP-DOC-16 v2 — текущий operational статус READY

Ниже все 11 нормативных requirements/сценарии/Non-goals сохранены как в applied v2; только локальные Purpose/evidence/status актуализированы по READY передаче координатора. Exact reviewed applied snapshot хранится в MCP revision `a8bb0538-7228-4b83-b750-df604aacb0de` без изменений. Его authoring title «deployment READY pending» и прежние underway/HOLD фразы — история подготовки, не текущий deployment; текущий статус отражён также DOC16 comment `25864198-aa39-48e2-90c6-cafe53a9db5b`.

## Purpose
Полный контракт отдельной машинной производной выбранного advisory для DIP-TASK-42 / DIP-PLAN-4 / DIP-FEAT-4: SOURCE implemented/frozen, security source GO и фактический translation/key deployment **READY/exit0** по передаче координатора. Целевой язык ru, оригинал/source/provenance/исходный неизвестный язык сохраняются отдельно от машинного перевода. READY и applied spec не подтверждают live генерацию или качество перевода: текущие разрешённые попытки завершены без успешной production translation/двух chat replies, external refusal и remaining browser qualification **BLOCKED**. Дополняет, не заменяет DIP-DOC-6 (оригинал/provenance), DIP-DOC-8/9 (сводка), DIP-DOC-11 (квоты), DIP-DOC-14/15 (история/чат). Все 11 требований DOC16 v1/v2 сохранены; существующие требования связанных документов сохраняются; отдельный translation opt-in не расширяет egress summary/chat.

Исторический baseline public8081 fccb96e не является implementation commit новых изменений. Independent security source GO без P1/P2, actual 14 backend + 53 UI + 18 ScanPages/sourceVersion match и frozen source атрибутированы координатору. Текущий actual rollout audit830b completion завершён READY/exit0, accounts/reports/JWT/history/quota Preserved, active HOLD отсутствует; key provided через .volume3215 API-only read-only после approved env0600 transfer. Это отдельно переданные source/test/deployment/preservation сведения, не новые операции этой документной сессии. Key auth/metadata native PASS отдельно от генерации: attempt1 chat заблокирован, translation POST0; отдельный tiny operator probe дал429 без установленного root cause. Actual attempt2/3 завершены GET otherlocal guard failure до provider, без scan/chat/translation; успешная generation/ru semantic quality/privacy/billing не заявлены. TASK42 blocked, новых попыток нет.

## Requirements

### Requirement: Public-only отдельная операция перевода
Система SHALL предоставлять перевод только как отдельную операцию существующего public LLM контура, а не второй чат, историю или расширение legacy composition.

#### Scenario: Контекст и генерация
- GIVEN владелец имеет действующую browser session и доступ к сохранённому public отчёту
- WHEN он читает GET `/api/v1/browser/scans/:scanId/llm/translation/context` с findingId/assessmentIndex либо отдельно отправляет POST `/api/v1/browser/scans/:scanId/llm/translation`
- THEN GET не вызывает модель, не читает ключ и не резервирует квоту; POST проходит отдельные translation guards. Маршруты не регистрируются в legacy AppModule/LlmModule и не открывают private JWT API; ответы и ошибки имеют no-store.

### Requirement: Отдельное явное согласие на новый selected-text egress
Система SHALL разрешать один translation POST только по явному согласию пользователя на текущую раскрытую translation policy и отправку разрешённых title/description выбранной оценки внешнему провайдеру.

#### Scenario: Сводка разрешена, перевод ещё нет
- GIVEN ранее принято согласие summary/chat, но translation consent отсутствует либо относится к иной policyVersion
- WHEN открыта карточка, переключён язык, получен focus/reconnect либо предпринята отправка перевода
- THEN открытие и переключение не вызывают генерацию; прежнее согласие не разрешает перевод. UI раскрывает OpenRouter, точную модель/endpoint, global/retention declaration, free-only caps, область данных и ru, затем требует отдельные подтверждение и кнопку отправки; автоматического retry нет.

#### Scenario: Новая revision или область передачи
- GIVEN translation consent связан с hash translation revision, underlying LLM policyVersion, selected-normalized-text-only declaration и ru
- WHEN один из этих параметров изменился
- THEN прежнее согласие неприменимо, нужен свежий контекст и новое подтверждение, а не молчаливое повторение POST.

### Requirement: Серверная привязка к выбранному оригиналу
Система SHALL выбирать текст только из текущего авторизованного серверного отчёта по полному binding scanId/digest/platform/reportVersion/findingId/assessmentIndex/sourceVersion.

#### Scenario: Подмена и смена source slot
- GIVEN findingId обозначает сохранённую находку, а assessmentIndex — индекс исходного сохранённого массива assessments, не сортировки UI
- WHEN POST содержит текущие reportVersion/sourceVersion/ru/consent либо устаревший binding, чужой scan или дополнительные title/description/prompt/model/URL
- THEN только текущий разрешённый binding допускает генерацию; чужой scan неотличим от отсутствующего, недопустимый DTO отвергается. SourceVersion включает исходный assessment с состояниями полей, source identifier и translation revision; совпадения текста самого по себе недостаточно.

### Requirement: Минимальный допустимый текст без реконструкции
Система SHALL отправлять в user content провайдера только разрешённые sanitized сохранённые title/description одной выбранной оценки, не весь отчёт или историю.

#### Scenario: Частично доступный или небезопасный текст
- GIVEN поле available/truncated, не redacted, не изменяется bounded normalization и проходит credential/URL guard; либо поле missing/invalid/redacted/omitted/unsafe
- WHEN готовится translation payload
- THEN допустимый заголовок ограничен 512 UTF-8 bytes, описание 4096 bytes и отправлены ровно как сохранены; недопустимое поле становится null без восстановления. Если оба null, локальный отказ LLM_TRANSLATION_UNAVAILABLE без provider dispatch; усечённое поле не достраивается. Source metadata, package/version, binding и другие findings не сериализуются в user content; идентификаторы уже внутри выбранного текста сохраняются.

### Requirement: Неизменный оригинал и неизвестный исходный язык
Система SHALL сохранять исходные title/description, source/provenance/language, состояния redaction/truncation и report identity независимо от наличия перевода.

#### Scenario: NVD, иной источник и неизвестный язык
- GIVEN assessment имеет фактический source/provenanceRef и language либо language=null
- WHEN пользователь получает перевод ru или отказ
- THEN оригинал остаётся доступен отдельно; null обозначает неизвестный исходный язык, не en и не ru. CVSS/severity source не выдаётся за источник текста. Finding IDs/counts, CVE/TEMP partition, coverage, source assessments и исходный reportVersion переводом не изменяются.

### Requirement: Явно машинная русская производная без новой authority
Система SHALL публиковать перевод только как ограниченный plain-text результат ru с машинной маркировкой, исходным source binding и generation metadata, не как официальный NVD/БДУ текст.

#### Scenario: Валидная форма и недостоверная подмена
- GIVEN ответ модели содержит ровно title/description с соответствующими null полями
- WHEN проверяются конечные UTF-8 bounds, безопасный plaintext, русский Cyrillic/script профиль и точные per-field CVE/TEMP identifier sets
- THEN прошедший ответ имеет machineTranslated=true, targetLanguage=ru, model/provider/generatedAt и исходные binding/source; непрошедший отвергается без fake Russian fallback. Reply title ≤2048 bytes, description ≤16384 bytes дополнительно ограничены общим response budget. Script/schema guards не доказывают семантическую точность; технический/name-only текст может быть отвергнут, а не выдуман.

#### Scenario: TEMP и отсутствие официального русского источника
- GIVEN выбранный оригинал содержит CVE либо Debian TEMP
- WHEN отображаются оригинал и перевод
- THEN namespace и идентификаторы сохранены в своих полях; TEMP не получает CVE mapping, NVD/FIRST/БДУ link. Перевод не создаёт новые severity/fixes/источники/URL и не означает independently verified CVE→БДУ mapping.

### Requirement: Фиксированная public free пара в существующем LLM контуре
Система SHALL допускать translation только через существующие LlmService/runtime/guarded OpenRouter adapter/capacity/quota для exact xingchen-agi/xing4.0-29b-a4b:free и единственного endpoint phala с нулевыми prompt/completion/request caps и request budget.

#### Scenario: Пара выключена, недоступна или не соответствует
- GIVEN public free policy неполна, выключена, относится к другой паре либо provider недоступен/вернул невалидный ответ
- WHEN запрошен перевод
- THEN безопасный отказ сохраняет оригинал; нет paid/auto router, второго провайдера, fallback модели или automatic retry. Existing fixed-host bounded TLS egress, data_collection:deny и zdr:true не ослабляются; ключ остаётся API-only и не попадает в browser/report/log/docs/Flownix. Global/no-storage/routing declaration не доказывает региональное/privacy соответствие, availability или фактический billing.

### Requirement: Свежая authority отправки и публикации
Система SHALL повторно проверять session/access/owner/report/source/policy непосредственно при допуске, actual body send и публикации результата.

#### Scenario: Отзыв, гонка и поздний ответ
- GIVEN операция допущена, затем report/source/policy/session изменены, доступ отозван либо запрос отменён
- WHEN наступает следующий send/write либо возвращается поздний callback, в том числе игнорирующий abort
- THEN устаревшая authority не разрешает передачу или публикацию; нужен новый контекст/consent без autoresend. Abort не доказывает отмену уже выполненного внешнего вызова; dispatched/unknown/fault consumption не refund. Принятый late receipt может учесть текущую попытку, но не разрешает показ результата.

### Requirement: Сохранный инертный UI
Интерфейс SHALL сохранять оригинальный отчёт доступным при любом исходе перевода и показывать перевод только как инертный текст текущего source/session scope.

#### Scenario: Ошибка, смена владельца и переключение
- GIVEN original advisory уже показан и пользователь запросил перевод
- WHEN получена ошибка quota/provider/configuration/stale, timeout/cancel, сменились session/scan/source либо пользователь переключил оригинал/перевод
- THEN безопасное сообщение не содержит raw body/secret, original findings/coverage не стираются, consent/result старого scope не появляются заново; переключение не генерирует новый запрос. HTML/Markdown/URLs модели не исполняются; машинный статус и model/provider/time видимы отдельно от source provenance.

### Requirement: Русский human text сводки и чата с обновлением policy hash
Система SHALL запрашивать русский человекочитаемый текст существующих summary hypotheses и chat replies, сохраняя JSON keys, bindings, identifiers и citations.

#### Scenario: Изменён prompt policy
- GIVEN ответная языковая revision russian-prose-v1 включена в underlying LLM policy hash
- WHEN выполняется summary/chat с прежним policyVersion либо готовится новый запрос
- THEN прежнее согласие отвергается, новый запрос требует актуального согласия; система запрашивает русский human text, не переводит структурные ключи и не расширяет прежний контекст до advisory title/description. Это prompt requirement, не доказательство русскоязычности/качества любого live ответа и не новый чат/протокол истории.

### Requirement: Отсутствие новой durable translation state
Система SHALL обходиться без DB migration, persistent translation output cache и изменения исходных advisory records, повторно используя действующий quota/accounting контур.

#### Scenario: Перевод и повторное открытие отчёта
- GIVEN существуют accounts/reports/JWT/history/quota и сохранённый original advisory
- WHEN выполняется либо отменяется перевод, а затем отчёт открыт вновь
- THEN оригинал и существующая история не заменяются переводом, автоматического replay/generation нет; учёт реальной допущенной попытки не сбрасывается. Наличие исходников не доказывает preservation после deployment: это отдельная проверка координатора.

## Non-goals
- Не второй чат, token streaming, перевод всего отчёта/истории, browser-supplied text, auto-translation при открытии и не официальный русский NVD/БДУ источник.
- Не scraping/fetch внешних advisory, угадывание английского языка, CVE/TEMP mapping или восстановление отсутствующего/скрытого/усечённого текста.
- Не переписывание DIP-DOC-1 v6, DIP-DOC-2 v8, DIP-DOC-6 v3 или принятых DIP-TASK-14/16/21/39/40/41. Их требования и historical evidence не отменяются.
- Не активация public/legacy, импорт существующих env keys, смена модели через fallback, изменение service lifecycle/private state или разрешение native/provider вызова этим документом.

## Review и последующее применение
По сообщению координатора source implemented/frozen и independent security source GO, P1/P2 отсутствуют; 14 backend + 53 UI + 18 ScanPages проверок выполнены, sourceVersion match подтверждён. Числа и GO атрибутированы передаче координатора: эта документная сессия не запускала тесты и не выдавала независимый security/correctness verdict. Exact frozen candidate identity и команды/receipts остаются у координатора; baseline fccb96e не переименовывается в implementation commit. Кодовый scope: server/api/src/llm/TRANSLATION.md, translation-contract.ts, translation.service.ts, policy.ts, prepared-request.ts и UI AdvisoryTranslationPanel/VulnAdvisoryCard.

Policy bounds сохраняются без расширения: selected input title512B/description4096B, reply title2048B/description16384B под общим response cap, ru-only separate consent/source binding, fixed exact Xing/Phala free pair, zero price/budget, no automatic retry/fallback, API-only key, прежние guards/capacity/quota и отсутствие migration/cache. Deployed GET context/POST/UI scope, READY/exit0/audit830b и preservation accounts/reports/JWT/history/quota переданы координатором отдельно от исходного source review. Approved env0600 transfer и .volume3215 API-only read-only provisioning не дают generation/privacy/billing proof. Значение ключа здесь не читалось и не публиковалось. Current-key native metadata/postflight и actual GET auth/key HTTP200/authenticated=true переданы как PASS **только аутентификации**. Attempt1 JSON/MD фиксируют completed Node report/UI/readiness, но chat blocked и translation NOT_RUN; wire NDJSON LLM_UNAVAILABLE и отдельный synthetic operator probe HTTP429 не являются generation PASS или установленным quota/provider-busy root cause. Финальный статус текущего scope: qualification **BLOCKED**, implementation **DEPLOYED READY**. Attempt2/3 прочитаны: каждый GET otherlocal REQUEST_GUARD до provider, scan/chat/translation0; больше не in progress. External operator429 — refusal с точной причиной UNKNOWN, не доказанная quota/provider busy. Итоговые TASK42 [progress]/[blocker] записаны, статус blocked. Успешная production translation/два chat replies и remaining browser/semantic quality НЕ VERIFIED; **новых попыток нет**. Consumption dispatched attempt1 без observation/receipt UNKNOWN; **manual refund запрещён**.

DOC16 v1 — initial draft snapshot receipt9ff62038 без source TASK42, не task acceptance. После повторного чтения fresh policy/current full DOC16v1/full reviewed delta/source-task списка база1/stateproposed/body совпали; применена именно a8bb0538-7228-4b83-b750-df604aacb0de от TASK42, **DOC16v2**, applied_at2026-10-22T22:56:03.793625Z. Все11 requirements и Non-goals сохранены; reviewed body в MCP не редактировалось задним числом. Current READY receipt supersedes его historical READY-pending/underway/HOLD wording. Fresh policy full/strict/approval=false/spec_first=false; review_status pending не обязательный gate, нового proposal/approval cycle не создавали. **TASK42 blocked, не done:** READY/applied spec не закрывают заблокированные provider/browser/quality критерии. Нового product-contract изменения нет; applied DOC16v2/все11 requirements остаются без body rewrite/дельты, evidence/test-guard scope не подменяет behavioural spec. Старые stale mixed P0 дельты не применять.

---

## Handoff координатору

1. Сохранить source independent GO/frozen identity и scoped14 backend+53 UI+18 ScanPages/sourceVersion match, а также fullUI669PASS. API1333passed/1failed/2cancelled и isolated11PASS записывать раздельно: NOT_REPRODUCED не FIXED, полного API PASS нет. Эта сессия тесты не перезапускает.
2. `validate_spec` reviewed full body ранее вернула **valid:true**; fresh doc/delta/policy checks выполнены. Ровно **a8bb0538-7228-4b83-b750-df604aacb0de** от TASK42 **APPLIED**, DOC16 **v2**; все11 требований сохранены. Task blocked, компоненты1/3 и references сохранены. Не создавать duplicate proposal и не переписывать applied snapshot.
3. Actual translation/key rollout **READY/exit0**, **audit830b completion**, active HOLD нет; accounts/reports/JWT/history/quota **Preserved**. API-only read-only key provided через .volume3215 — координаторское evidence, значения не читать/не выводить. Никаких дополнительных lifecycle/source/key операций в этом документном scope.
4. **STOP: новых попыток не выполнять.** Attempt1 dispatched/no observation означает consumption UNKNOWN, НИКОГДА manual refund/сброс quota. Attempt2/3 завершены до provider с GET otherlocal guard FAIL; artifacts1/2/3 сохранить, ни один FAIL не переименовывать в fixed/PASS. Context-ingress auth guard/deployed UI code verified scope не равен successful production translation/двум chat messages. External completion429 имеет неизвестную точную причину; текущая exact free Xing/Phala policy/no fallback неизменна. Будущая узкая test-guard коррекция — fixed exact read-only runtime-capability/targets, не автоматическое разрешение нового прогона.
5. Финальные TASK42 комментарии: [progress] `9bb82f90-d8d8-4eb3-a680-ae7a5ff098b6`, [blocker] `48d08031-c80c-426e-80cd-08e6498012b8`; status **blocked**, не done. Fresh policy full/strict/approval=false/spec_first=false/parallel/direct допускает blocked. Для следующего qualification work нужны отдельное новое решение владельца и фактические результаты, а не retry/fallback/расширение guards. DOC16v2/applied a8bb0538, прочие tracker nodes, source/keys/lifecycle/accounting не изменялись. Два user keys различались, dedicated public выбран оператором без значений/хешей/raw env в записи.
