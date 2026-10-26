# Public advisory: машинный ru-перевод отдельно от оригинала

## Purpose
Полный resulting-body amendment поверх DIP-DOC-16 v2 для DIP-TASK-42 / DIP-PLAN-4 / DIP-FEAT-4. Сохраняет все 11 исходных requirement identities и границы оригинала, согласия, fixed free profile и accounting; уточняет russian-prose-v2, проверку не-прозы, конечные ошибки провайдера/Retry-After и 45-секундный deadline панели. Дополняет DIP-DOC-6, DIP-DOC-8/9, DIP-DOC-11 и DIP-DOC-14/15 без замены их независимых контрактов. Изменение chat error wire описывается отдельным полным amendment DOC15 от той же TASK42, не переоткрытием принятой TASK16.

H7 run7aa358d1-d67b-4ddb-b8c0-4c560c16b8f4, exact work540f464b-7984-41ae-96f5-c2a16529ce8d, agent h7-spec. Source FROZEN по новому поручению владельца; baseline HEAD b73c28a65dc482809de5bc066ef07ed87cf57def не идентифицирует весь изменённый source snapshot. Это предложенный контракт, не source-review GO, deploy, generation, ru-quality, billing или privacy PASS. Исторический DOC16v2/a8bb0538-7228-4b83-b750-df604aacb0de уже applied и не переписывается задним числом. Исторический STOP новых попыток заменён новым owner authorization; эта spec lane сама не выполняет ни одной попытки. APPLY данного amendment остаётся HOLD до отдельного coordinator approval после source GO и свежей проверки базы, независимо от approval=false в policy. Provider generation и качество сейчас unverified.

Amendment H7v2 от DIP-TASK-42 поверх DOC16v3 по новому явному поручению владельца: «Странно выдаёт гипотезы и на английском, вот эти чекбоксы с разраешением не нужны». Убирается отдельный UI checkbox, но explicit Translate после краткого видимого раскрытия остаётся одноразовым разрешением только текущего selected-text egress со fresh context/policy/source. Русский grounded summary/chat и технические translation false guards уточняются без waiver ownership/privacy/accounting. Ниже прежние authoring/review сведения исторические; v3 уже applied, эта v4 TARGET ещё не applied. Source/frontend/backend находятся у других исполнителей; APPLY HOLD до coordinator review фактической реализации.

## Requirements

### Requirement: Public-only отдельная операция перевода
Система SHALL предоставлять перевод только как отдельную операцию существующего public LLM контура, а не второй чат, историю или расширение legacy composition.

#### Scenario: Контекст и генерация
- GIVEN владелец имеет действующую browser session и доступ к сохранённому public отчёту
- WHEN он читает GET `/api/v1/browser/scans/:scanId/llm/translation/context` с findingId/assessmentIndex либо отдельно отправляет POST `/api/v1/browser/scans/:scanId/llm/translation`
- THEN GET не вызывает модель, не читает ключ и не резервирует квоту; POST проходит отдельные translation guards. Маршруты не регистрируются в legacy AppModule/LlmModule и не открывают private JWT API; ответы и ошибки имеют no-store.

### Requirement: Отдельное явное согласие на новый selected-text egress
Система SHALL разрешать один translation POST только по явному нажатию Translate после видимого краткого раскрытия текущей translation policy и selected title/description egress, считая кнопку одноразовым согласием без отдельного checkbox; серверные consent/source/policy guards сохраняются.

#### Scenario: Сводка разрешена, перевод ещё нет
- GIVEN ранее принято согласие summary/chat, но translation consent отсутствует либо относится к иной policyVersion
- WHEN открыта карточка, переключён язык, получен focus/reconnect либо предпринята отправка перевода
- THEN открытие и переключение не вызывают генерацию; прежнее согласие не разрешает перевод. UI показывает краткую заметку рядом с Translate и доступные полные сведения OpenRouter/model/endpoint/global/retention/free-only caps/selected fields/ru; одно нажатие разрешает только текущий перевод без отдельного checkbox. Согласие summary/chat не переносится на перевод, автоматического retry нет.

#### Scenario: Новая revision или область передачи
- GIVEN translation consent связан с hash translation revision, underlying LLM policyVersion, selected-normalized-text-only declaration и ru
- WHEN один из этих параметров изменился
- THEN прежнее согласие неприменимо, нужны свежий контекст, обновлённое раскрытие и новое явное Translate, а не checkbox или молчаливое повторение POST.

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
- THEN прошедший ответ имеет machineTranslated=true, targetLanguage=ru, model/provider/generatedAt и исходные binding/source; непрошедший отвергается без fake Russian fallback. Reply title ≤2048 bytes, description ≤16384 bytes дополнительно ограничены общим response budget. Script/schema guards не доказывают семантическую точность; безопасный technical/name-only текст сохраняется как не-проза, а не отвергается только за отсутствие кириллицы и не дополняется выдуманным русским текстом.

#### Scenario: TEMP и отсутствие официального русского источника
- GIVEN выбранный оригинал содержит CVE либо Debian TEMP
- WHEN отображаются оригинал и перевод
- THEN namespace и идентификаторы сохранены в своих полях; TEMP не получает CVE mapping, NVD/FIRST/БДУ link. Перевод не создаёт новые severity/fixes/источники/URL и не означает independently verified CVE→БДУ mapping.

#### Scenario: Проза и неизменяемая не-проза
- GIVEN поле после исключения CVE/TEMP идентификаторов содержит буквы либо состоит только из не-прозы без букв
- WHEN проверяется ответ для этого поля
- THEN человекочитаемая проза переводится на русский, а supplied technical/package names, versions и identifiers не переводятся, не транслитерируются и не добавляются. Для безопасной не-прозы/technical-only поля требуется точное сохранение; null остаётся null. Допустимые C# и Node.js либо Latin-heavy наборы сохранённых technical names сами по себе не являются URL/credential или основанием отказа по script ratio. Это не разрешение произвольных доменов, ссылок, credentials или reconstruction: конечные byte/plaintext/identifier/unsafe-content guards остаются fail-closed; отсутствие кириллицы в technical-only поле не заменяется выдуманной прозой.

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
Система SHALL запрашивать русский grounded человекочитаемый текст summary/chat по разрешённым сохранённым фактам с явным недостатком данных вместо неподтверждённых гипотез, сохраняя JSON keys, bindings, identifiers и citations.

#### Scenario: Изменён prompt policy
- GIVEN обновлённая языковая/grounding revision включена в underlying LLM policy hash, а translationPolicy включает underlying policyVersion
- WHEN выполняется summary/chat/translation с прежним policyVersion либо готовится новый запрос
- THEN прежнее согласие неприменимо, новый запрос требует актуального одноразового authorization кнопкой после видимого раскрытия и fresh context; если preflight изменил binding, требуется новое нажатие. Summary/chat запрашивают русский human text без расширения прежнего контекста до advisory title/description; translation получает только отдельно разрешённые selected fields. Prompt сохраняет supplied technical/package names, versions и identifiers без перевода/транслитерации, запрещает выдуманные upgrades/fixed versions/mappings и трактует counts как persisted finding rows, null как unknown, выбранное подмножество как неполное. Неподтверждённые root cause/exploitability/fixed versions заменяются честным указанием недостатка данных; legacy schema key hypotheses не разрешает speculation или навязанный UI-ярлык. Это prompt policy, не доказательство русского языка/качества любого live ответа или новый chat protocol.

### Requirement: Отсутствие новой durable translation state
Система SHALL обходиться без DB migration, persistent translation output cache и изменения исходных advisory records, повторно используя действующий quota/accounting контур.

#### Scenario: Перевод и повторное открытие отчёта
- GIVEN существуют accounts/reports/JWT/history/quota и сохранённый original advisory
- WHEN выполняется либо отменяется перевод, а затем отчёт открыт вновь
- THEN оригинал и существующая история не заменяются переводом, автоматического replay/generation нет; учёт реальной допущенной попытки не сбрасывается. Наличие исходников не доказывает preservation после deployment: это отдельная проверка координатора.

### Requirement: Конечная безопасная классификация provider failure
Система SHALL раскрывать только allowlisted provider errorCode и необязательный согласованный providerFailure, без raw body/headers/messages/credentials провайдера.

#### Scenario: Наблюдаемый HTTP отказ или bounded error envelope
- GIVEN upstream HTTP status является целым 300..599 либо bounded JSON error.code является целым 400..599
- WHEN ошибка проходит через transport/provider/service/wire
- THEN 429 и 503 соответствуют LLM_PROVIDER_RATE_LIMITED и kind=rate_limited; 401 соответствует LLM_PROVIDER_AUTH_FAILED и kind=auth_failed; остальные такие статусы соответствуют LLM_PROVIDER_UNAVAILABLE и kind=unavailable. providerFailure содержит только kind, числовой upstream status и допустимый retryAfterSeconds. JSON HTTP status для rate_limited равен исходному 429/503, для auth_failed равен 503, для unavailable равен 502; upstream 401 не превращается в browser session 401. Категория rate_limited включает busy/unavailable503 и не доказывает account quota, исчерпание денег или точный root cause.

#### Scenario: Ошибка без доказанного upstream статуса
- GIVEN timeout, network/TLS failure, неподтверждённый envelope либо невалидная metadata
- WHEN формируется безопасный отказ
- THEN отсутствующие status/retry/receipt не выдумываются; остаётся generic LLM_PROVIDER_UNAVAILABLE либо существующий локальный LLM_UNAVAILABLE/локальный отказ по своему контракту. Противоречивые kind/status/code, неизвестные вложенные поля и недопустимые числа не публикуются как verified providerFailure; клиент отвергает неконсистентный wire, а не показывает raw данные.

#### Scenario: Accounting при error envelope
- GIVEN error envelope содержит usage для exact текущей matching-model попытки либо HTTP отказ оставил consumption неизвестным
- WHEN выполняются accounting и доставка ошибки
- THEN применимый receipt наблюдается до отбрасывания content; metadata ошибки не заменяет durable observation. Dispatched/unknown/fault liability не refund, не обнуляется и не выводится из HTTP status или отсутствия ответа. Нет retry/fallback/выдачи фиктивного результата.

### Requirement: Ограниченная advisory Retry-After семантика
Система SHALL трактовать retryAfterSeconds только как ограниченную подсказку ожидания провайдера, не как разрешение повторной генерации, гарантированную доступность или refund.

#### Scenario: Допустимая и недопустимая подсказка
- GIVEN retry hint относится к rate_limited429/503
- WHEN разбирается Retry-After
- THEN принимаются 1..10 десятичных цифр либо bounded IMF-style HTTP-date с GMT и конечным временем; максимум длины исходного значения 128 символов. Seconds/date delta округляются вверх до целых секунд, прошлое время даёт 0, верхний предел 86400. Отсутствующие, отрицательные, дробные, бесконечные, malformed или слишком длинные значения не создают подсказку. В wire разрешён только integer0..86400 и только для rate_limited; отсутствие отличается от0.

#### Scenario: JSON и интерфейс
- GIVEN валидный providerFailure с retryAfterSeconds либо ошибка без него
- WHEN сервер отвечает JSON HTTP429/503 и интерфейс показывает ошибку
- THEN при наличии подсказки Retry-After содержит ровно её десятичные секунды, body сохраняет ту же bounded подсказку; при отсутствии срок не выдумывается. UI показывает безопасную категорию/наблюдаемый status/подсказку как негарантированные данные, сохраняет оригинал; повтор требует fresh context и нового явного Translate после видимого раскрытия без checkbox, даже0 не инициирует автоматический POST. Локальная продуктовая quota admission остаётся отдельной от upstream hint.

### Requirement: Абсолютный deadline операции translation UI
Интерфейс SHALL ограничивать всю одну операцию read либо translate панели 45000ms от её начала, включая preflight context/readiness/source binding, POST и postflight, независимо от abort-cooperation транспорта.

#### Scenario: Зависший preflight POST или postflight
- GIVEN запущена одна явная операция и transport callback не завершился либо игнорирует abort
- WHEN наступили45000ms, отмена или смена scope
- THEN pending завершается, consent/result сбрасываются, показывается безопасный timeout/cancel, а поздний callback не передаёт и не публикует stale результат. Отдельный40s request deadline сохраняется и не перезапускает общий45s budget; timeout не вызывает повтор, refund или утверждение о zero dispatch. Повтор требует свежего контекста и нового согласия.

## Non-goals
- Не второй чат, token streaming, перевод всего отчёта/истории, browser-supplied text, auto-translation при открытии и не официальный русский NVD/БДУ источник.
- Не scraping/fetch внешних advisory, угадывание английского языка, CVE/TEMP mapping или восстановление отсутствующего/скрытого/усечённого текста.
- Не изменение DIP-DOC-1/2/6 и не переоткрытие принятых DIP-TASK-14/16/21/39/40/41. Их независимые требования и historical acceptance сохраняются; DOC15 amendment описывает только новое расширение chat error wire от TASK42.
- Не paid/auto fallback, новая модель, новый datastore, migration/cache или ослабление consent/source/authority/accounting/egress guards.
- Не lifecycle/provider/key operation и не разрешение browser live attempt этой spec lane; READYGO и выполнение принадлежат отдельно уполномоченному координатору/участнику.

## Review и последующее применение
Свежие чтения DOC16v2/DOC15v2/DOC8v3/DOC9v2 и doc/source-TASK42 proposed lists выполнены в H7; matching proposal не найден до подготовки. DOC8 сохраняет исторический LOCAL Apodex/Novita scope, DOC9 — invariant summary UI; public Xing/Phala не подменяет их legacy profile. Прямое изменение NDJSON error allowlist найдено в frozen source и требует отдельного DOC15 full-body amendment. Текст описывает observed source contract, не независимую security/correctness приёмку или выполненные тесты.

Историческое предположение о mismatched Markdown mappings отозвано additive errata docs/public-final-spec-evidence-errata-20261025.md: fresh JSON/Markdown пары совпали и originals не переписывались. Ни один FAIL не переписывается в PASS; попытки с translationPosts=0 не становятся translation acceptance. Исторические STOP и READY-pending фразы остаются датированными фактами, не текущим запретом нового owner scope и не обещанием provider availability.

Применение HOLD: coordinator отдельно подтверждает source GO и approval apply; непосредственно перед apply повторно читаются policy, current full document и delta/base. Version conflict требует новой сверки, не stale replacement. Applied spec сам по себе не закрывает TASK42; generation/semantic quality и фактическая preservation квалифицируются отдельно. Эта сессия не меняет статусы/content/progress задач и не выполняет lifecycle/provider/keys.
