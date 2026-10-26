# Public advisory: машинный ru-перевод отдельно от оригинала

## Purpose
Контракт отдельного public ru-перевода выбранного сохранённого advisory в существующем LLM контуре. Оригинал, provenance, unknown language, source/report binding и shared accounting сохраняются; это не второй чат и не официальный русский источник.

Редакция26.10.2026 от DIP-TASK-42 поверх DIP-DOC-16 v4 по новому явному поручению владельца supersedes прежние no-auto/button-only ограничения только в описанной области. PREPARED, NOT APPLIED; APPLY HOLD до отдельного coordinator source GO/deploy verification. Source inspection не является independent review, native/provider/semantic/privacy/billing acceptance. Исторические authoring/review/evidence записи остаются в предыдущих версиях и файлах без переписывания; accepted tasks не переоткрываются.

## Requirements

### Requirement: Public-only отдельная операция перевода
Система SHALL предоставлять перевод только как отдельную операцию существующего public LLM контура, а не второй чат, историю или расширение legacy composition.

#### Scenario: Контекст и генерация
- GIVEN владелец имеет действующую browser session и доступ к сохранённому public отчёту
- WHEN он читает GET `/api/v1/browser/scans/:scanId/llm/translation/context` с findingId/assessmentIndex либо отдельно отправляет POST `/api/v1/browser/scans/:scanId/llm/translation`
- THEN GET не вызывает модель, не читает ключ и не резервирует квоту; POST проходит отдельные translation guards. Маршруты не регистрируются в legacy AppModule/LlmModule и не открывают private JWT API; ответы и ошибки имеют no-store.

### Requirement: Отдельное явное согласие на новый selected-text egress
Система SHALL разрешать public ru translation открытого source slot после отдельного явно сохранённого owner-local account language=ru opt-in с раскрытием selected-text egress, сохраняя одноразовый consent текущих translationPolicy/source/report и отсутствие разрешения от summary/chat.

#### Scenario: Открытие до и после Save
- GIVEN account preference default original/не authorized либо владелец явно сохранил текущую language=ru automation revision
- WHEN открыты подробности advisory
- THEN до Save генерации нет; после Save только смонтированный открытый source slot с допустимым текстом может после свежих context/readiness автоматически планировать один translation request. Закрытые карточки не монтируют панель и не делают её context/readiness GET/POST; не переводятся весь отчёт, скрытые страницы или история. Текущий UI монтирует отдельную панель каждого assessment открытой карточки: один глобально выбранный source selector не заявляется.

#### Scenario: Условия, source и явный повтор
- GIVEN opt-in актуален, translation consent включает underlying policy/selected-normalized-text-only/ru и source binding
- WHEN preflight выявил stale report/source/policy/session либо произошла ошибка/отмена
- THEN прежняя попытка не продолжает send/publication, нет auto retry; нужен fresh context и новое применимое намерение. Отдельная «Повторить перевод» после ошибки разрешает одну новую проверку, не fallback/refund. Смена раскрываемых модели/провайдера/данных/условий требует новой automation revision и повторного Save; local grant не серверная authority.

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
- THEN прошедший ответ имеет machineTranslated=true, targetLanguage=ru, model/provider/generatedAt и исходные binding/source; непрошедший отвергается без fake Russian fallback. Reply title ≤2048 bytes, description ≤16384 bytes дополнительно ограничены общим response budget. Script/schema guards не доказывают семантическую точность; только конечные разрешённые source-bound технические tokens могут сохраняться без кириллицы и без выдуманного русского дополнения. Произвольный source CamelCase не является доказательством технического имени; неизвестный technical/name-only текст может fail-closed отклоняться.

#### Scenario: TEMP и отсутствие официального русского источника
- GIVEN выбранный оригинал содержит CVE либо Debian TEMP
- WHEN отображаются оригинал и перевод
- THEN namespace и идентификаторы сохранены в своих полях; TEMP не получает CVE mapping, NVD/FIRST/БДУ link. Перевод не создаёт новые severity/fixes/источники/URL и не означает independently verified CVE→БДУ mapping.

#### Scenario: Проза и неизменяемая не-проза
- GIVEN поле после исключения CVE/TEMP идентификаторов содержит буквы либо состоит только из не-прозы без букв
- WHEN проверяется ответ для этого поля
- THEN prompt требует русский human text и неизменные supplied technical/package names, versions и identifiers без добавления новых. Guard исключает из script-проверки только совпадающие с оригиналом tokens конечного allowlist API/CPU/CVE/HTTP/HTTPS/JSON/RCE/SQL/SSL/TEMP/TLS/UTF/XML/XSS/C#/C++/Node.js/OpenSSL/libxml2/Linux/Windows/Debian/Alpine/Phala, строгие CVE/TEMP IDs и числовые версии. После исключения требуется минимум3 русские буквы и0 иных букв; поле без оставшихся букв требует точного равенства оригиналу, null остаётся null. Произвольные CamelCase/snake_case/letter-digit tokens не получают исключение даже из source, неизвестные proper names могут fail-closed отклоняться. Exact standalone C#/Node.js не становятся credential/URL только по имени, но URL/path/domain variants и unsafe plaintext по-прежнему отвергаются; padding ради script check запрещён. Это bounded guard, не универсальный language classifier или semantic fidelity guarantee.

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
- THEN безопасное сообщение не содержит raw body/secret, original findings/coverage не стираются, consent/result старого scope не появляются заново; переключение original/готовый перевод не генерирует новый запрос; первое открытие source slot может планировать его только после отдельного сохранённого ru opt-in. HTML/Markdown/URLs модели не исполняются; машинный статус и model/provider/time видимы отдельно от source provenance.

### Requirement: Русский human text сводки и чата с обновлением policy hash
Система SHALL запрашивать русский grounded человекочитаемый текст summary/chat по разрешённым сохранённым фактам с явным недостатком данных вместо неподтверждённых гипотез, сохраняя JSON keys, bindings, identifiers и citations.

#### Scenario: Изменён prompt policy
- GIVEN responseLanguageRevision russian-prose-v4-structured включена в underlying LLM policy hash, а translationPolicy включает underlying policyVersion
- WHEN выполняется summary/chat/translation с прежним policyVersion либо готовится новый запрос
- THEN прежнее согласие неприменимо, новый запрос требует актуального одноразового server authorization после видимого раскрытия и fresh context: ручного Send либо соответствующего сохранённого account opt-in; если preflight изменил binding, требуется новое нажатие. Summary/chat запрашивают русский human text без расширения прежнего контекста до advisory title/description; translation получает только отдельно разрешённые selected fields. Prompt сохраняет supplied technical/package names, versions и identifiers без перевода/транслитерации, запрещает выдуманные upgrades/fixed versions/mappings и трактует counts как persisted finding rows, null как unknown, выбранное подмножество как неполное. Неподтверждённые root cause/exploitability/fixed versions заменяются честным указанием недостатка данных; legacy schema key hypotheses не разрешает speculation или навязанный UI-ярлык. Это prompt policy, не доказательство русского языка/качества любого live ответа или новый chat protocol.

### Requirement: Отсутствие новой durable translation state
Система SHALL обходиться без DB migration, persistent translation output cache и изменения исходных advisory records, повторно используя действующий quota/accounting контур.

#### Scenario: Перевод и повторное открытие отчёта
- GIVEN существуют accounts/reports/JWT/history/quota и сохранённый original advisory
- WHEN выполняется либо отменяется перевод, а затем отчёт открыт вновь
- THEN оригинал и существующая история не заменяются переводом, выходной перевод не persist-ится; после reload автоматический replay того же key блокирует локальный attempt marker по DOC9, а применимый новый source/report/policy key отдельно проверяется; учёт реальной допущенной попытки не сбрасывается. Наличие исходников не доказывает preservation после deployment: это отдельная проверка координатора.

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
- THEN при наличии подсказки Retry-After содержит ровно её десятичные секунды, body сохраняет ту же bounded подсказку; при отсутствии срок не выдумывается. UI показывает безопасную категорию/наблюдаемый status/подсказку как негарантированные данные, сохраняет оригинал; повтор после ошибки требует fresh context и нового явного «Повторить перевод» после видимого раскрытия без checkbox, даже0 не инициирует автоматический POST. Локальная продуктовая quota admission остаётся отдельной от upstream hint.

### Requirement: Абсолютный deadline операции translation UI
Интерфейс SHALL ограничивать всю одну операцию read либо translate панели 45000ms от её начала, включая preflight context/readiness/source binding, POST и postflight, независимо от abort-cooperation транспорта.

#### Scenario: Зависший preflight POST или postflight
- GIVEN запущена одна явная операция и transport callback не завершился либо игнорирует abort
- WHEN наступили45000ms, отмена или смена scope
- THEN pending завершается, consent/result сбрасываются, показывается безопасный timeout/cancel, а поздний callback не передаёт и не публикует stale результат. Отдельный40s request deadline сохраняется и не перезапускает общий45s budget; timeout не вызывает повтор, refund или утверждение о zero dispatch. Повтор требует свежего контекста и нового согласия.

### Requirement: Translation diagnostic headers и граница русской проверки
Система SHALL сохранять translation body wire и отклоняющие predicates, раскрывая только первый фактический локальный отказ через optional finite X-LLM-Failure-Phase/X-LLM-Failure-Reason по DOC8, без раскрытия content или обещания семантической точности.

#### Scenario: Первый отклоняющий predicate
- GIVEN top-level ответ не имеет exact title/description либо одно поле не прошло проверки
- WHEN валидатор отказывает
- THEN shape mismatch даёт content/invalid_shape, поля идут в порядке title затем description с phase translation_title/translation_description. Reasons: null_mismatch, invalid_type, limit, unsafe_text, not_normalized, invalid_link, invalid_markup, identifier_mismatch, not_russian, nonprose_changed в фактическом порядке guards. Ранний text guard может отказать URL до link guard; generic service fallback не перетирает первый диагноз. Body остаётся LLM_INVALID_RESPONSE без predicate payload, raw text/match/message/URL/credential не выходят наружу; без диагностики headers отсутствуют.

#### Scenario: Structured shape не ослабляет guards
- GIVEN exact public adapter запрашивает strict scanner_translation schema по DOC8 с title/description string/null ровно по входу
- WHEN получен schema-conforming reply
- THEN обязательны прежние UTF-8 bounds/nulls/normalization/безопасный plaintext/per-field IDs/finite source-bound script/nonprose проверки; нет unwrapping/coercion/repair. Незнакомые technical names могут fail-closed отклоняться даже в русской прозе; schema и конечный словарь не доказывают fidelity и не классифицируют исторический invalid_content задним числом.

### Requirement: Ограниченная автоматизация открытого source scope
Интерфейс SHALL использовать общий summary/translation queue и attempt-cache контур DOC9 только для открытого допустимого source scope при сохранённом ru opt-in, без persistent translation cache или скрытого обхода отчёта.

#### Scenario: Повторное открытие и cached ответ
- GIVEN ключ включает kind/owner/automation revision/scan/digest/platform/reportVersion/policyVersion/findingId/assessmentIndex/sourceVersion/ru
- WHEN открытый source slot снова монтируется
- THEN validated in-memory reply может использоваться лишь после fresh context/readiness/source проверки, failed/aborted key не автоматически повторяется. Закрытие отменяет ожидание и stale publication; sessionStorage хранит только opaque hashes, не исходник/перевод. Reload не восстанавливает output, новый tab/очистка storage не покрыты глобальным exactly-once; server quotas и unknown liability не сбрасываются.

## Non-goals
- Не второй чат, token streaming, перевод всего отчёта/истории, browser-supplied text, auto-translation без явно сохранённого применимого ru opt-in и не официальный русский NVD/БДУ источник.
- Не scraping/fetch внешних advisory, угадывание английского языка, CVE/TEMP mapping или восстановление отсутствующего/скрытого/усечённого текста.
- Не изменение DIP-DOC-1/2/6 и не переоткрытие принятых DIP-TASK-14/16/21/39/40/41. Их независимые требования и historical acceptance сохраняются; DOC15 amendment описывает только новое расширение chat error wire от TASK42.
- Не paid/auto fallback, новая модель, новый datastore, migration/cache или ослабление consent/source/authority/accounting/egress guards.
- Не lifecycle/provider/key operation и не разрешение browser live attempt этой spec lane; READYGO и выполнение принадлежат отдельно уполномоченному координатору/участнику.
