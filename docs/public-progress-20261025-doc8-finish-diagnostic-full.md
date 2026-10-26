# DIP-TASK-13 — Безопасная серверная ИИ-сводка OpenRouter

## Purpose
Минимальный контракт серверной доказательной ИИ-сводки для DIP-TASK-13 внутри DIP-FEAT-4, расширенный DIP-TASK-37 явной free-only политикой и сохранным API-only подключением на LOCAL стенде. Сводка дополняет, но не заменяет результаты сканеров; документ описывает требуемое поведение, а не подтверждённую live интеграцию.

Amendment от DIP-TASK-42 поверх DOC8v3 по явному поручению владельца 25.10.2026: русский grounded ответ вместо неподтверждённых гипотез, одноразовое button-only разрешение вместо отдельного checkbox. Не меняет исторический LOCAL Apodex/Novita профиль, не переоткрывает принятые задачи и не разрешает платный вызов. Public Xing/Phala остаётся отдельным профилем DOC16. TARGET, APPLY HOLD до coordinator review фактической реализации.

Source reconciliation после actual handoff: policy revision russian-prose-v3-grounded и конечные diagnostic headers подтверждены read-only source; три панели используют явные кнопки и заметки без permission-checkbox. Backend Russian CamelCase P2 rework/source GO и native semantic quality ещё не квалифицированы этой lane. APPLY HOLD до coordinator source GO/deploy verification; предыдущий completed H7 work не переписывается.

## Requirements

### Requirement: Серверный default-off OpenRouter
Серверный NestJS LlmProvider SHALL использовать реальный адаптер OpenRouter с выключенной по умолчанию интеграцией и fail-closed допуском только при серверном OPENROUTER_API_KEY, явно определённых человеком модели, бюджете и region/retention-политике, а также конечных лимитах времени, размера запроса/ответа и output tokens. Ключ читается только из серверного окружения и не раскрывается браузеру, логам, API или Flownix. Конфигурационные и провайдерские ошибки безопасны, без секретов и raw provider body; фиктивная ИИ-сводка не подменяет отказ. Отсутствующая настройка не заменяется придуманным значением; декларация региона не является доказательством соблюдения политики провайдером.

#### Scenario: Передача выключена или политика неполна
- GIVEN интеграция выключена либо отсутствует ключ, модель, бюджет или обязательная region/retention-политика
- WHEN запрошена сводка
- THEN вызовов провайдера ноль, возвращается безопасный отказ без фиктивной сводки, а результаты сканеров остаются доступны владельцу.

#### Scenario: Ограниченный вызов завершается ошибкой
- GIVEN все разрешения действуют и вызов адаптера начат
- WHEN провайдер возвращает ошибку либо превышен конечный лимит времени или ответа
- THEN обработка прекращается с безопасной ошибкой без raw provider body, секретов или искусственного результата; уже начатый вызов не обозначается как zero-call.

### Requirement: Авторизация и явный opt-in до egress
Сервер SHALL до передачи аутентифицировать пользователя, проверить владение доступным scan/отчётом и явный применимый opt-in на отправку очищенного контекста OpenRouter, связанный с пользователем, scan, текущей версией отчёта и раскрытой применяемой политикой. Одно явное нажатие Send/Translate/кнопки сводки после видимого краткого раскрытия создаёт разрешение только соответствующего запроса без отдельного checkbox; серверный consent payload и все проверки сохраняются. Клиентские subject, report и finding IDs не доказывают доступ или согласие.

#### Scenario: Отказ до передачи
- GIVEN пользователь не аутентифицирован, scan чужой, opt-in отсутствует/отозван либо версия отчёта или политика не соответствует согласию
- WHEN несоответствие установлено до egress
- THEN вызовов провайдера ноль и чужие данные не раскрываются.

#### Scenario: Запрос владельца разрешён
- GIVEN сервер подтвердил identity, владельца, актуальную версию отчёта, применимый opt-in и полную разрешённую конфигурацию
- WHEN пользователь явно нажал кнопку сводки после видимого краткого раскрытия и свежая проверка подтверждает тот же context/policy
- THEN допускается только одна ограниченная передача очищенного контекста этого серверного отчёта; checkbox не требуется, но открытие/focus/reconnect/context GET не являются разрешением и не вызывают модель.

#### Scenario: Условия изменились перед отправкой
- GIVEN пользователь нажал кнопку для показанного контекста, но report/session/policy изменились до send
- WHEN сервер или preflight обнаруживает stale binding
- THEN передачи нет, раскрытие обновляется и требуется новое явное действие; нельзя автоматически принять новые условия и продолжить прежний запрос.

### Requirement: Доверенный очищенный контекст без скрытой потери critical findings
Сервер SHALL формировать ограниченный контекст только из авторизованного текущего серверного отчёта: allowlist нормализованных findings, coverage и очищенных evidence, а не доверенного клиентского payload. Обязательные critical findings и сведения о coverage/неполноте сохраняются; если они или разрешённый контекст не помещаются в лимиты, запрос безопасно отклоняется до egress без молчаливого усечения. Credentials, токены, env, inspect secrets и raw scanner output исключаются из модельного контекста, логов и ответов API. Недоверенные metadata, evidence и текст провайдера являются данными, не инструкциями; их URLs не загружаются.

#### Scenario: Недоверенные данные и секреты
- GIVEN клиентский payload или evidence содержит секретный canary, чужие findings, инструкции обойти политику либо attacker URL
- WHEN сервер готовит контекст и проверяет ответ
- THEN контекст строится по доступному серверному отчёту, запрещённые данные не раскрываются, инструкции не меняют политику и URL не загружается.

#### Scenario: Контекст превышает лимит
- GIVEN разрешённый контекст, обязательные critical findings или coverage не помещаются в конечные лимиты
- WHEN сервер готовит запрос
- THEN вызовов провайдера ноль и возвращается явный безопасный отказ вместо сводки с молча удалёнными critical findings или coverage.

### Requirement: Проверяемые citations и актуальность публикации
Сервер SHALL перед публикацией проверять finding_id/citations по отправленному множеству findings доступного scan, digest/platform и reportVersion и повторно проверять актуальные доступ, согласие, политику и версию серверного отчёта. Неизвестные, чужие или несовместимые ссылки не публикуются как факты; недостаток доказательств обозначается прямо без генерации неподтверждённых причин, влияния или исправлений под видом гипотезы. Устаревший результат отбрасывается; результаты сканеров не изменяются.

#### Scenario: Поддельная ссылка или неподтверждённое утверждение
- GIVEN ответ содержит неизвестный/чужой finding_id, ссылку вне отправленного множества, несовместимую binding tuple либо неподтверждённое утверждение
- WHEN сервер валидирует ответ до публикации
- THEN невалидная ссылка и неподтверждённое утверждение не публикуются как результат; ответ безопасно отклоняется либо ограничивается проверяемым содержимым с явным «недостаточно данных», без выдуманного evidence.

#### Scenario: Изменение после egress
- GIVEN вызов провайдера уже начат
- WHEN до публикации отчёт изменился/удалён либо доступ, согласие или политика стали неприменимы
- THEN результат отбрасывается и не публикуется как актуальный; число уже совершённых вызовов не объявляется нулевым.

### Requirement: Явная проверенная free-only политика
Сервер SHALL допускать free-only запрос только при явном включении этого режима, точном `apodex/apodex-1.1-mini:free`, единственном endpoint провайдера `novita/bf16`, явно одобренном `no-storage` и явно нулевых prompt/completion/request price caps и бюджете. Запрос задаёт `data_collection:deny`, `zdr:true`, JSON output и `reasoning:{enabled:false, exclude:true}`; `no-training`, широкое имя `novita`, другие endpoint и прежний Liquid free профиль не допускаются. Фиксированный LOCAL overlay DIP-TASK-37 задаёт этот free-only профиль без выбора legacy режима, сохраняет default-off решения оператора и повышает revision до `openrouter-free-apodex-v2`. Общий backend сохраняет отдельно настраиваемый legacy non-free режим с положительными caps/бюджетом и default-off интеграцией; отсутствие free-only флага само по себе не означает zero-call для полной явно включённой legacy конфигурации и не разрешает платный вызов этим контрактом. Auto/free routers, неизвестные модели/модификаторы, платный fallback и автоматический retry запрещены. Политика и раскрытие включают модель, exact endpoint, retention, free-only режим и caps; изменение revision/профиля делает старое согласие неприменимым. Допустим только точный observed/request response model ID `apodex/apodex-1.1-mini:free`, без canonical alias или удаления суффиксов; reported usage.cost должен быть нулём. Имя модели, caps, снимок каталога и parent-reported успешная synthetic host compatibility проверка не являются доказательством фактического биллинга, privacy compliance или production adapter/container/LIVE acceptance.

#### Scenario: Настройка допускает неизвестную или платную маршрутизацию
- GIVEN free-only режим явно включён, но модель/endpoint/retention/caps/budget не соответствуют точной free-only политике
- WHEN сервер проверяет конфигурацию
- THEN вызовов провайдера ноль и нет fallback на платную или автоматически выбранную модель, иной endpoint или ослабленную retention-политику.

#### Scenario: Legacy backend не объявлен глобально free-only
- GIVEN используется общий backend вне обязательного free-only LOCAL overlay и free-only флаг отсутствует либо выключен
- WHEN сервер проверяет legacy конфигурацию
- THEN действует отдельная default-off проверка legacy модели, положительных caps/бюджета, routing/region/retention и остальных разрешений; отсутствие free-only флага само по себе не является отказом, но выключенная или неполная конфигурация не вызывает провайдера и TASK37 не разрешает платную активацию.

#### Scenario: Согласие предыдущего профиля устарело
- GIVEN согласие относится к прежней policyVersion до замены модели/endpoint/retention/revision
- WHEN владелец запрашивает сводку с этим согласием после перехода на новый профиль
- THEN запрос отклоняется до egress; требуется применимое согласие на текущие reportVersion и раскрытую policyVersion.

#### Scenario: Бесплатный провайдер недоступен или ответ не соответствует контракту
- GIVEN разрешён один ограниченный free-only вызов
- WHEN провайдер недоступен, возвращает ненулевую/отсутствующую стоимость, model без exact `:free` ID, reasoning, усечённый ответ либо невалидный JSON/citations
- THEN ответ безопасно отвергается без повторов, платной подмены, canonical alias или ослабления проверки; уже начатый вызов не считается zero-call.

### Requirement: API-only ограниченный TLS egress
Система SHALL передавать OpenRouter credential только из приватного окружения API через ограниченный end-to-end TLS транспорт к фиксированному `openrouter.ai:443` и chat-completions endpoint, без broad API internet, direct fallback, redirects или зависимости от ambient proxy variables. Gateway разрешает только этот host, проверяет все DNS ответы как публичные и подключается к проверенному numeric IP. Worker не получает ключ, gateway-доступ или расширение registry allowlist; браузер и образы не содержат ключ. TLS identity проверяется до отправки Bearer; таймаут, отмена и byte ceilings закрывают транспорт.

#### Scenario: Неразрешённый host, private DNS или недоверенный TLS
- GIVEN gateway получает другой host/mixed private DNS либо TLS identity недоверенна
- WHEN выполняется попытка передачи
- THEN соединение безопасно отвергается, Bearer не передаётся недоверенному HTTP endpoint и прямой обход gateway не используется.

#### Scenario: Приватный API ключ подключён на LOCAL
- GIVEN оператор разрешил LOCAL free-only интеграцию и использует owner0600 regular non-symlink секретный env source вне image/browser/worker
- WHEN Compose подключает ключ
- THEN содержимое получает только API, не shared worker environment, frontend, build, logs или Flownix; host-only закрытый DB signing key не монтируется.

### Requirement: Сохранная фиксированная LOCAL композиция
Операторский механизм SHALL выбирать optional free-only подключение только как фиксированное расширение уже выбранной LOCAL композиции под существующим общим refresh lock с live writer capability и сохранять один frozen выбор через refresh, readiness и rollback. Отсутствующий descriptor оставляет оба default bases; неизвестные/дублированные поля, произвольные overlay и небезопасные paths/permissions отвергаются. Подключение не сбрасывает JWT, accounts, scans, volumes или signed DB pins и не активирует LOCAL само. Проверка health не выдаётся за успешную live модель или verified image rollback.

#### Scenario: Refresh после явного opt-in
- GIVEN оператор выбрал exact LOCAL и fixed free-only overlay под общим lock
- WHEN DB refresh меняет pins или выполняет rollback
- THEN оба bases, LOCAL entrypoints и optional free-only overlay остаются одним frozen выбором, auth/ledger/JWT и host-only signing key сохраняются.

#### Scenario: Недопустимая композиция или чужой lock
- GIVEN отсутствует live capability своего lock либо descriptor задаёт произвольный path/profile
- WHEN оператор пытается записать или выбрать композицию
- THEN действие безопасно отвергается без обхода lock, изменения auth/ledger или молчаливого перехода на default.

### Requirement: Ограниченный browser summary ingress
Стенд SHALL допускать bounded consent-bound summary POST только на каноническом lowercase UUID-shaped пути `/api/v1/browser/scans/<UUID>/llm/summary`, с 1KiB summary body, no-store и ограниченным proxy timeout. Cookie-bound context GET доступен на каноническом context пути, а также через существующий защищённый GET-only scan-child ingress на достигающих Nest поддерживаемых case/trailing-slash aliases, например `/api/v1/browser/scans/<UUID>/llm/CONTEXT/` и `/api/v1/browser/scans/<UUID>/llm/context/`; это не обещание поддержки aliases всего URL или обхода неизменённого browser scan prefix. Все эти context GET сохраняют cookie/owner/report проверки, no-store и ограниченный proxy timeout; context GET не выдаёт согласие и не вызывает модель. Приватный JWT scan API и произвольные child mutations остаются закрыты. Ingress не заменяет серверные проверки доступа/Origin/согласия; context aliases не расширяют допуск summary POST и не обходят auth/consent fences.

#### Scenario: Запрос summary через browser ingress
- GIVEN клиент обращается к exact summary path
- WHEN запрос проходит bounded POST ingress
- THEN сервер применяет обычные cookie/Origin/owner/report/policy/consent/citation fences, ответ не кэшируется и истечение deadline не вызывает retry.

#### Scenario: Поддерживаемый context GET alias через защищённый generic GET
- GIVEN запрос использует поддерживаемый Nest context case/trailing-slash alias внутри существующего browser scan prefix, например `/api/v1/browser/scans/<UUID>/llm/CONTEXT/`
- WHEN generic GET-only ingress передаёт запрос серверному context маршруту
- THEN сервер проверяет cookie identity и доступ владельца к отчёту без вызова модели или выдачи согласия; ответ no-store, а POST к этому неканоническому пути не допускается как summary mutation.

### Requirement: Русское доказательное объяснение без неподтверждённых гипотез
Система SHALL запрашивать русский human-readable текст summary/chat, привязанный к разрешённым сохранённым фактам и citations, с явным указанием недостатка данных вместо неподтверждённых гипотез; revision russian-prose-v3-grounded входит в policy hash и делает старое согласие неприменимым.

#### Scenario: Неизвестная причина или исправленная версия
- GIVEN контекст содержит только ограниченные findings/counts/coverage и не устанавливает root cause, exploitability, fixed version либо полный inventory
- WHEN готовится и проверяется новое объяснение
- THEN неизвестное названо неизвестным по-русски, missing/null не становятся нулём или фактом, counts не превращаются в число уникальных CVE; technical/package names, versions, identifiers, JSON keys/bindings/citations не переводятся и не выдумываются. Legacy wire key hypotheses сам по себе не разрешает speculative content или навязывание UI-ярлыка «гипотеза».

#### Scenario: Граница проверки языка и качества
- GIVEN controlled tests проверили prompt/hash, форму, citations и безопасный русский script профиль
- WHEN сообщается о приёмке
- THEN эти проверки не объявляются доказательством semantic accuracy любого provider ответа; native русский grounded ответ требует отдельной фактической проверки без ослабления privacy, response bounds или credential guards.

### Requirement: Конечные diagnostic headers без изменения body wire
Система SHALL раскрывать диагностическую фазу отказа только двумя необязательными finite headers `X-LLM-Failure-Phase` и `X-LLM-Failure-Reason`, связанными с фактической текущей ошибкой, не меняя JSON/NDJSON body schema и не принимая произвольный message/body как authority.

#### Scenario: Разрешённая форма и отсутствие
- GIVEN factory-bound диагностика текущего отказа существует либо отсутствует
- WHEN формируется JSON error response или headers failed NDJSON delivery
- THEN phase допускает только request/connect/tls/dispatch_guard/headers/body/json/model/envelope/finish/content/usage/accounting/deadline/caller_abort/language/grounding; reason только invalid_request/rejected/io_error/timeout/aborted/http_error/invalid_type/limit/invalid_json/mismatch/invalid_shape/invalid_finish/invalid_content/invalid_receipt/observation_failed/not_russian/unknown_identifier/finish_length/finish_content_filter/finish_tool_calls/finish_error/finish_unknown. При отсутствии диагностики оба headers отсутствуют; произвольные вложенные поля/exception message не создают headers. Raw payload, upstream headers/URLs/credentials/private paths не раскрываются, body/receipt/accounting semantics неизменны.

#### Scenario: Значение наблюдения
- GIVEN клиент получил finite phase/reason либо headers отсутствуют
- WHEN он сообщает об ошибке
- THEN это диагностическое наблюдение текущей попытки, не доказательство исторического root cause, provider billing, zero dispatch или refund; unknown остаётся unknown. Нет нового retry/fallback или разрешения раскрыть содержание failed ответа.

#### Scenario: Конечная классификация отклонённого finish
- GIVEN provider envelope имеет нормализованный finish_reason, отличный от точного stop
- WHEN текущая ошибка классифицируется в фазе finish
- THEN length отображается в finish_length, content_filter в finish_content_filter, tool_calls и function_call в finish_tool_calls, error в finish_error, а любое иное значение, включая missing/null/нестроковое или неизвестное, в finish_unknown. Это только конечная диагностика отказа: non-stop не принимается даже при внешне валидном content; raw finish_reason/native_finish_reason не раскрываются, partial content/citation/delta/done не публикуются. Exact stop продолжает прежний success-validation path; invalid_finish сохраняется в общей allowlist для совместимости, но не подменяет новое mapping текущей ошибки. Request/policy/budget, receipt/accounting и unknown dispatched liabilities неизменны; нет retry/fallback/refund/reset или вывода о причине исторической попытки из новых headers.

## Non-goals
Чат, история, retrieval/сжатие контекста, кэш и cost UI относятся к TASK14–16, не TASK13/37. Free-only candidate выбран для отдельного LOCAL подключения, не как подтверждённая production/live модель. Контракт не разрешает платный внешний вызов, не устанавливает privacy/region соответствие провайдера декларацией и не заменяет независимые reviews, сохранный deploy и реальный bounded synthetic smoke родителем. Mocked fixtures и loopback TLS tests используются только как явно обозначенные тестовые данные; они не являются live OpenRouter acceptance.

TASK42 amendment меняет только общий opt-in способ и языковой/grounding контракт, не lifecycle/LOCAL routing и не статус ранее принятых задач. Новая кнопка разрешает ровно текущий запрос после раскрытия; не auto-egress, не paid fallback, не quota reset/refund и не waiver ownership/privacy. APPLY требует отдельного coordinator GO; historical FAIL/unknown liabilities сохраняются.
