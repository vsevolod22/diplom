# DIP-TASK-16 — Безопасный чат и доставка завершённого ответа

## Purpose
Контракт реализованного чата текущего scan, дополняющий DIP-DOC-8, DIP-DOC-9, DIP-DOC-11 и DIP-DOC-14 без их замены. Основание принятой базы DOC15v2: согласованный completed-reply контракт DIP-ARTF-234 и проверенные исправления R3–R5, включая DIP-ARTF-276/277. Это конечная доставка уже проверенного ответа, а не поток токенов провайдера. Приёмка реализации не подтверждает активацию, native ingress или production работу модели.

Полный resulting-body amendment H7 от DIP-TASK-42 сохраняет все10 исходных requirement identities и сценарии, уточняя реальное расширение NDJSON v1 error payload конечными provider error codes/metadata. Основание изменения — read-only frozen source history-delivery.ts/history.service.ts и строгий browser chatFrameSchema; не переоткрытие принятой TASK16. Baseline HEADb73c28a не является hash всего изменённого source snapshot. Source GO, rollout, browser/provider generation, русский язык/качество и billing/privacy этим документом не подтверждаются. APPLY HOLD до отдельного coordinator approval после source GO; policy approval=false не снимает это указание владельца.

## Requirements

### Requirement: Ручной чат текущего владельца и отчёта
Интерфейс SHALL начинать новую генерацию только по явному действию пользователя с одноразовым согласием на действующие условия передачи вопроса и очищенного контекста истории текущего авторизованного scan.

#### Scenario: Открытие и подтверждение
- GIVEN авторизованный завершённый отчёт и раскрытые текущие условия
- WHEN пользователь открывает чат, затем отдельно подтверждает согласие и отправляет вопрос
- THEN открытие только читает контекст/историю/usage; генерация требует текущие reportVersion, policyVersion, epoch/revision и mutationId; mount, focus, reconnect и ошибка не вызывают автоматическую генерацию или retry.

#### Scenario: Недоступная генерация
- GIVEN генерация выключена либо настройки, согласие или текущий binding неприменимы
- WHEN пользователь обращается к чату
- THEN новая генерация запрещена; разрешённое чтение подтверждённой истории и отдельное сохранение пользовательского решения не подменяются вызовом модели.

### Requirement: Честная согласованная framed delivery
Сервер SHALL предоставлять opt-in NDJSON v1 на существующем POST `/api/v1/browser/scans/:scanId/llm/chat` как доставку завершённого ответа, сохраняя прежний JSON режим и отдельную сводку.

#### Scenario: Negotiation
- GIVEN запрос к существующему chat endpoint
- WHEN Accept выбирает `application/x-ndjson`, прежний JSON режим либо неподдерживаемое представление
- THEN поддержанный NDJSON выбирается явно, JSON остаётся доступным с безопасным error payload, неподдерживаемый Accept отклоняется до provider admission; новый endpoint и native token streaming не имитируются. Расширение error allowlist требует совместимого строгого клиента; старый клиент, понимающий только LLM_UNAVAILABLE, может fail-closed отвергнуть новые коды и не объявляется wire-compatible без проверки.

### Requirement: Проверенный успех до первого frame
Сервер SHALL формировать успешный поток только после проверенного receipt данной попытки, его durable учёта, полной проверки ответа/источников и durable commit подтверждённого turn.

#### Scenario: Успешная доставка
- GIVEN текущая допущенная попытка с проверенным полным ответом и сохранённым turn
- WHEN начинается NDJSON delivery
- THEN последовательность usage → citation → delta → done связана с одной версией протокола, mutation/turn, scan/digest/platform/reportVersion, epoch/revision и последовательными seq/index; provider остаётся `stream:false`, usage обозначает server-validated provider-reported данные, не invoice proof.

### Requirement: Ошибка только с доказанным состоянием попытки
Сервер SHALL различать ошибку с принятым receipt текущей попытки и ошибку без него, не выводя usage из прошлых counters, исключений или другого запроса.

#### Scenario: Accepted receipt и невалидный ответ
- GIVEN текущий receipt durably принят, но ответ невалиден и exact admitted turn безопасно перешёл в failed
- WHEN свежие проверки разрешают delivery
- THEN передаются только usage seq0 и безопасный error seq1 без citation/delta/done или невалидного содержимого; учтённые расходы не отменяются.

#### Scenario: Receipt отсутствует
- GIVEN текущая admitted попытка доказанно завершилась failed без accepted receipt
- WHEN свежие проверки разрешают delivery
- THEN передаётся только безопасный error seq0 с receipt unavailable, без fabricated zero или заимствованного usage.

#### Scenario: Admission либо доказательство failed head отсутствует
- GIVEN запрос не допущен либо exact pending/failed state и текущие полномочия не подтверждаются
- WHEN происходит ошибка
- THEN безопасный JSON отказ до заголовков либо прекращение уже начатой доставки не подменяются выдуманным framed outcome; различие JSON и framed delivery сохраняется.

### Requirement: Свежая authority каждого write
Сервер SHALL повторно проверять trusted session/access, report/policy и exact durable history head непосредственно при заголовках, каждом frame, end и после ожидания drain.

#### Scenario: Отзыв доступа во время backpressure
- GIVEN доставка ждёт drain
- WHEN сессия, политика, report или epoch/revision изменяются
- THEN последующий приватный write запрещён и соединение завершается без stale success/error disclosure; check-before-await не считается разрешением будущего write.

### Requirement: Конечные транспортные границы
Доставка SHALL ограничиваться 8192 UTF-8 bytes на строку, 196608 bytes суммарно, 52 frames с резервом terminal error, 1024 bytes на delta и абсолютным сроком 5000ms, сохраняя общую ёмкость 1 owner / 8 global до завершения или прекращения доставки.

#### Scenario: Лимит, stalled drain или finish
- GIVEN полный план слишком велик либо сокет не завершает drain/finish
- WHEN достигнут соответствующий предел
- THEN нет неограниченного буфера или ожидания; cleanup освобождает lease ровно один раз, не сбрасывая settled usage и не создавая повторный provider call.

### Requirement: Строгая клиентская сборка без partial publication
Клиент SHALL публиковать новый ответ только после bounded fatal-UTF8/LF разбора, правильных tuple/nonce/seq/index/count, done и чистого EOF, полной проверки ответа и свежего подтверждения того же полного turn в durable истории.

#### Scenario: Повреждённый или оборванный поток
- GIVEN неизвестный frame, несовместимый binding, дубликат, превышение byte/count, error, отсутствие LF/done/EOF или лишние данные после terminal
- WHEN клиент разбирает ответ
- THEN ответ не публикуется и запрос не повторяется автоматически; промежуточные delta не передаются в rich Markdown, copy или навигацию citations.

#### Scenario: Проверенная завершённость
- GIVEN полный success stream и свежие context/history/usage
- WHEN текущий сохранённый turn совпадает по question, reply, источникам и финальной revision
- THEN появляется подтверждённый ответ-гипотеза; несовпадение не превращается в optimistic success.

### Requirement: Изоляция отмены и устаревших callbacks
Интерфейс SHALL отменять ожидание и блокировать публикацию при смене scan, пользователя, поколения сессии или snapshot, явной отмене и конечном timeout, включая transport callbacks, игнорирующие abort.

#### Scenario: A → B → A и timeout
- GIVEN запрос для A ещё выполняется
- WHEN пользователь меняет scope либо истекает timeout и поздний callback возвращается
- THEN старая беседа, согласие, receipt и ответ не восстанавливаются в новом scope; клиентский запрос ограничен 40s и операция панели 45s; отмена не означает refund или доказанную отмену уже начатой передачи провайдеру.

### Requirement: Инертный Markdown и точный code fallback
Интерфейс SHALL отображать разрешённый окончательный Markdown без raw HTML, исполняемых URL, изображений, Mermaid и непроверенных plugins/highlighter, используя лениво загружаемый renderer и точный plain-text fallback для опасного либо незавершённого текста.

#### Scenario: Незакрытый fence и опасная разметка
- GIVEN незакрытый fence, включая list/quote containers, script, raw HTML или javascript URL
- WHEN текст проверяется и отображается
- THEN ничего не исполняется и небезопасная ссылка не активна; незавершённый/опасный текст остаётся инертным, copy сохраняет исходный текст, а загрузка renderer не включает подсветку или исполнение кода.

#### Scenario: Завершённый code block
- GIVEN разрешённый законченный code block
- WHEN пользователь копирует код
- THEN копируется точный текст, результат copy сообщается отдельно от подписи кнопки; syntax highlighting остаётся выключенным до отдельной проверки.

### Requirement: Авторизованные источники и сохранный отчёт
Интерфейс SHALL проверять citation по finding ID, категории и binding авторизованного отчёта независимо от текущей UI страницы, сохраняя scanner coverage/findings отдельно от состояния чата.

#### Scenario: Исторический источник и другая страница
- GIVEN citation относится к последующей странице либо к прежней версии отчёта
- WHEN отображается ответ
- THEN текущий источник проверяется по доступным проекциям всех нужных страниц, прежний tuple остаётся historical/unresolved и не привязывается к новому отчёту только по совпавшему ID.

#### Scenario: Ошибка или квота
- GIVEN scanner report уже показан
- WHEN chat/context/usage недоступны, квота исчерпана, получен error-only stream или пользователь отменяет запрос
- THEN исходные findings и coverage остаются доступны; безопасное сообщение не показывает raw диагностику, фиктивный ответ или нулевой неизвестный usage и не объявляет непроверенное безопасным.

### Requirement: Конечные provider errors в JSON и NDJSON v1
Сервер SHALL передавать новый provider failure только как валидный конечный error payload той же доказанной failed-попытки, сохраняя receipt semantics, tuple, seq, authority checks и transport ceilings.

#### Scenario: Типизированная ошибка с receipt либо без него
- GIVEN exact admitted turn durably failed и имеется validated provider failure текущей попытки
- WHEN строится error frame
- THEN errorCode входит только в LLM_PROVIDER_RATE_LIMITED, LLM_PROVIDER_AUTH_FAILED, LLM_PROVIDER_UNAVAILABLE; generic LLM_UNAVAILABLE без metadata остаётся допустимым. Необязательный providerFailure содержит только kind, upstream integer status300..599 и допустимый retryAfterSeconds. При accepted receipt перед ним usage seq0, error seq1; без accepted receipt только error seq0 с receipt unavailable. Citation/delta/done/content отсутствуют, HTTP200 NDJSON не означает generation success. Error metadata не persist-ится как ответ модели и не создаёт новый history flow.

#### Scenario: Строгая согласованность классификации
- GIVEN providerFailure присутствует
- WHEN проверяются status, kind и errorCode
- THEN upstream429/503 допускают только kind=rate_limited и LLM_PROVIDER_RATE_LIMITED; upstream401 — только auth_failed и LLM_PROVIDER_AUTH_FAILED; остальные300..599 — unavailable и LLM_PROVIDER_UNAVAILABLE. rate_limited включает busy503, не доказывает точную причину отказа/лимит аккаунта. Unknown вложенные поля, несогласованные code/kind/status, строковые/дробные/неfinite значения и raw диагностика отвергаются. Без доказанного upstream status metadata не выдумывается.

#### Scenario: Retry hint и различие JSON transport
- GIVEN валидная rate_limited metadata и необязательный retry hint
- WHEN передаётся failed JSON либо framed delivery
- THEN retryAfterSeconds только integer0..86400 и только для rate_limited; исходный Retry-After разбирается по bounded seconds/HTTP-date правилам DOC16, malformed hint отсутствует,0 не означает autoresend. Для JSON rate_limited HTTP status429/503 совпадает с upstream, auth_failed возвращает HTTP503, unavailable с metadata — HTTP502; при JSON429/503 и наличии hint заголовок Retry-After равен body seconds. Framed delivery может оставаться HTTP200 и передаёт подсказку в terminal frame без обещания HTTP Retry-After. Старый generic LLM_UNAVAILABLE остаётся без providerFailure.

#### Scenario: Неизвестное потребление и повтор
- GIVEN failed admitted attempt имеет receipt unavailable либо позднюю accounting observation
- WHEN UI показывает категорию/числовой status/негарантированную подсказку ожидания
- THEN unknown usage не становится0, HTTP отказ не authorizes refund/reset, failed content не публикуется. UI предлагает сначала обновить историю; новая генерация возможна только отдельным явным действием с новым применимым согласием. Нет automatic retry/fallback или новой передачи от reconnect/error/countdown; source scanner report сохраняется.

## Non-goals
- Native provider token streaming, output cache и экономия provider calls не реализуются этим контрактом.
- DIP-DOC-14 остаётся authority для durable owner+scan памяти, CAS, mandatory context, private fingerprints и prepared-context cache; DIP-DOC-11 — для quota/accounting. Сводка DIP-DOC-8/9 не переписывается.
- Приёмка исходных критериев TASK16 использует проверенную реализацию, controlled cookie/Nest/SQLite/adapter evidence и frontend/browser evidence с synthetic transport. Она не является подтверждением production nginx/main topology, initialized native history store, доступности/биллинга/privacy реального провайдера или сохранности старых данных. Новое error расширение от TASK42 не пересматривает эту историческую приёмку.
- Native activation требует отдельной проверки topology/init/ingress и разрешения оператора; принятие документа ничего не активирует. Исторические STOP/HOLD сохраняются как датированные факты; новое owner authorization H7 заменяет прежний STOP только в явно разрешённом scope. Spec lane не выполняет provider/browser/lifecycle операции.
- Владелец 2026-10-16 снял оставшиеся ручные UI/SR/keyboard/visual проверки как условие закрытия. Это waiver, не запись manual PASS и не снятие security/runtime требований.
- Не новый endpoint/history store/migration, не paid route, не изменение accepted task status/content/closure и не source-review/provider-quality PASS.

## Review и последующее применение
Сравнены актуальные DOC15v2/DOC16v2/DOC8v3/DOC9v2 и doc/source-TASK42 proposed deltas. Новое error wire расширение реально присутствует в frozen source: history delivery использует failure payload, browser strict enum расширен; это не только улучшение текста UI. Публикация нового error формата требует проверки paired backend/frontend candidate, не обещания совместимости старого strict клиента. Accepted success/receipt/accounting/authority/transport правила сохранены.

H7 exact work540f464b-7984-41ae-96f5-c2a16529ce8d / agent h7-spec: только read-only source/spec inspection, новые public-final-spec-* файлы, validation/proposal и разрешённые progress comments. Tests/provider/lifecycle/keys NOT_RUN. Source GO и фактическая provider/ru quality/preservation квалификация принадлежат координатору/другим участникам. APPLY HOLD до отдельного coordinator approval после source GO; перед apply перечитать policy/full current doc/delta/base, не применять stale replacement. Source данного amendment — DIP-TASK-42, не принятая DIP-TASK-16; task statuses/content/progress/closure и исторические applied revisions не меняются.
