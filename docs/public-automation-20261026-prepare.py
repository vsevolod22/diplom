"""Inert local full-body preparation; no network/MCP/runtime access. Never replay proposals."""
from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parent
PREFIX = 'public-automation-20261026-'
BASES = {
    2: (9, 'public-progress-20261025-doc2-reconciled-full.md'),
    8: (5, 'public-progress-20261025-doc8-finish-diagnostic-full.md'),
    9: (3, 'public-progress-20261025-doc9-proposed-full.md'),
    15: (4, 'public-progress-20261025-doc15-reconciled-full.md'),
    16: (4, 'public-progress-20261025-doc16-reconciled-full.md'),
}

def replace_once(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new, 1)

def requirement(text, name, replacement):
    marker = '### Requirement: ' + name + '\n'
    start = text.index(marker)
    match = re.search(r'\n(?:### Requirement: |## )', text[start + len(marker):])
    assert match, name
    end = start + len(marker) + match.start()
    return text[:start] + marker + replacement.strip() + '\n' + text[end:]

def add(text, content):
    return replace_once(text, '\n## Non-goals\n', '\n' + content.strip() + '\n\n## Non-goals\n')

def scoped_revision(text):
    before, rest = text.split('## Requirements\n', 1)
    return before + '## Requirements\n' + rest.replace('russian-prose-v3-grounded', 'russian-prose-v4-structured')

bodies = {doc: (ROOT / filename).read_text() for doc, (_, filename) in BASES.items()}
body = bodies[2]
body = requirement(body, 'Доступный индикатор фактического прогресса', '''
Интерфейс SHALL отделять неизвестный серверный percent от явно приблизительной локальной неравновесной оценки работы в списке и детали; только авторизованный completed snapshot разрешает100%, а время наблюдения, counters или SSE не подтверждают завершение.

#### Scenario: Running с native percent=null
- GIVEN scan running и серверный percent=null
- WHEN панель оценивает ход работы по локальному времени наблюдения и сохранённым outcomes выбранных checks
- THEN текст и доступное описание маркируют «Оценка прогресса: ≈N%», не серверный процент/ETA/долю успешных checks; модель даёт загрузке образа и vulnerability analysis больший вес, чем config. Веса условные, не измеренные длительности; findings/count/page не являются мерой работы, серверный DTO не изменяется. При неизвестном наборе применяется явно обозначенная общая модель без выдуманного selected set; точное оставшееся время неизвестно.

#### Scenario: Queue, остановка и подтверждённый итог
- GIVEN queued/running/cancelling либо terminal completed/partial/failed/cancelled snapshot
- WHEN показывается индикатор
- THEN queued имеет локальную оценку0 без зачёта времени очереди; только running продвигает время модели, cancelling его приостанавливает. Неподтверждённый completed не создаётся: только серверный completed показывает100%; partial/failed/cancelled сохраняют прежнюю оценку ниже100 либо отсутствие оценки при новом открытии и фактический итог. Все resolved или checked counters сами по себе не дают100, SSE close/reconnect не меняют terminal authority, missing outcomes не объявляются успешными.

#### Scenario: Локальное наблюдение и доступность
- GIVEN пользователь уходит с панели, перезагружает страницу, меняет scan/selected set/сессию либо наблюдается новый queued
- WHEN панель открыта вновь
- THEN локальная временная оценка начинается заново, не восстанавливается из updatedAt как start time; DTO не содержит attempt ID/runtime start, невидимый restart running→running этим UI надёжно не определяется. Reduced-motion сохраняет статическое представление, доступное имя и явный approximate текст; важные переходы не крадут фокус и stale scope не раскрывает чужие данные.
''')
body = requirement(body, 'Подтверждённый этап и оставшиеся выбранные проверки', '''
Интерфейс SHALL показывать текущий этап, readiness и фактические selected/resolved/checked/remaining counters только по подтверждённым авторизованным данным, отдельно от приблизительной локальной оценки работы.

#### Scenario: Projection отсутствует
- GIVEN scan state известен, percent=null, а stage/selected-check projection отсутствует
- WHEN пользователь хочет понять, сколько осталось
- THEN этап и счётчики обозначены неизвестными; общая локальная модель может дать явно approximate оценку, но не выдуманные stage/check outcomes, runtime start, серверный percent или ETA.

#### Scenario: Подтверждённый completed subset
- GIVEN авторизованные данные явно задают selected checks и фактически завершённый subset
- WHEN показываются counters
- THEN «получены итоги N из M» и отдельно checked/remaining относятся только к выбранным checks; failed/unsupported разрешают outcome, но не успешную работу и не равную долю времени. Projection следует DOC1 owner-only contract и не публикует running findings/result routes; отсутствие результата не становится0findings.
''')
body = requirement(body, 'Live counters и polling независимо от SSE', '''
Интерфейс SHALL читать owner GET status ограниченным polling пока scan активен даже при SSE и сохранять durable-outcomes-v1 counters независимо от клиентской approximate оценки, без изменения серверного progress контракта.

#### Scenario: Checkpoint без нового state event
- GIVEN scan running, checkpoint изменил progress, SSE подключён
- WHEN очередной owner GET возвращает согласованную projection
- THEN list/detail показывают resolvedChecks из requestedChecks, отдельно checkedChecks и remaining M-minus-resolved; failed/unsupported не checked. Локальные неравные веса/time smoothing не переименовывают эти counters в elapsed-time percentage; отсутствие projection означает unknown, не synthetic outcomes.

#### Scenario: Terminal и поздний callback
- GIVEN terminal snapshot либо смена scan/session/owner
- WHEN polling/SSE callback завершается поздно
- THEN прежний polling/stream прекращается, stale counters/findings не восстанавливаются; terminal берётся из GET. All-resolved не даёт100/ completed при partial/failed/cancelled, running result/perCheck/findings остаются закрытыми прежними publication guards.
''')
body = add(body, '''
### Requirement: Компактное покрытие и ссылка всей карточки списка
Интерфейс SHALL делать всю карточку списка одной семантической ссылкой на деталь соответствующего scan, сохраняя компактные статус/оценку/counters и доступное имя, без отдельного дублирующего отчёта coverage в карточке.

#### Scenario: Открытие карточки клавиатурой
- GIVEN авторизованный список либо явно помеченное демо
- WHEN пользователь фокусирует карточку и активирует ссылку
- THEN открывается правильный live/demo detail, нет вложенных интерактивных элементов; полные coverage/reasons/findings доступны в детали. Компактность не означает checked/0/безопасность и не превращает failed/unsupported в успех.
''')
bodies[2] = body

body = scoped_revision(bodies[8])
body = requirement(body, 'Авторизация и явный opt-in до egress', '''
Сервер SHALL до передачи аутентифицировать пользователя, проверить владение доступным scan/отчётом и применимый consent текущих reportVersion/policyVersion; public UI может сформировать этот одноразовый envelope после явно сохранённого owner-scoped account opt-in для auto-summary/ru-translation либо явного Send для ручного вопроса, без снятия серверных guards.

#### Scenario: Отказ до передачи
- GIVEN нет identity/ownership, consent отсутствует/отозван либо report/policy binding устарел
- WHEN сервер проверяет запрос до egress
- THEN провайдер не вызывается, чужие данные не раскрываются; локальная настройка не является серверным правом и не подменяет актуальный consent payload.

#### Scenario: Account opt-in не равен автоматическому чату
- GIVEN владелец явно сохранил текущие раскрытые условия fixed public free profile и включил autoSummary либо ru для открытого source slot
- WHEN UI допускает соответствующий единственный автоматический summary/translation запрос со свежим контекстом
- THEN существующий POST несёт accepted:true и текущую operation-specific policyVersion, сервер заново проверяет owner/report/source/policy/quotas. До сохранения автоматика выключена; GET сам не вызывает модель, чат-вопрос требует отдельного Send. Legacy/LOCAL профиль не меняется этим public разрешением.

#### Scenario: Условия изменились перед отправкой
- GIVEN accepted context уже подготовлен
- WHEN preflight обнаружил другой report/source/policy/session
- THEN прежняя попытка не продолжает передачу автоматически; stale outcome не публикуется, нужны свежие условия и новое применимое разрешение. Ошибка/отмена не разрешают retry/fallback/refund.
''')
body = replace_once(body, 'caller_abort/language/grounding; reason только', 'caller_abort/language/grounding/translation_title/translation_description; reason только')
body = replace_once(body, 'finish_error/finish_unknown. При отсутствии', 'finish_error/finish_unknown/null_mismatch/unsafe_text/invalid_markup/identifier_mismatch/nonprose_changed/not_normalized/invalid_link. При отсутствии')
body = add(body, '''
### Requirement: Строгая operation-specific JSON schema public профиля
Система SHALL для exact free Xing/Phala отправлять summary/chat/translation с response_format=json_schema, strict:true, всеми required properties и additionalProperties:false на каждом object level, сохраняя независимую локальную валидацию и stop-only envelope.

#### Scenario: Три разные provider формы
- GIVEN fixed public model xingchen-agi/xing4.0-29b-a4b:free и единственный endpoint phala
- WHEN готовятся три операции
- THEN scanner_summary требует только scanId/digest/platform/reportVersion и hypotheses:[{text,citations:string[]}]; scanner_chat — тот же binding и text/citations; scanner_translation — только title/description с индивидуальным string либо null ровно по входному полю. Server-enriched DTO, kind/source/scannerFacts/usage и translation wrapper не запрашиваются у модели. Отдельные legacy/Apodex профили сохраняют json_object, без runtime downgrade/fallback из public.

#### Scenario: Inert metadata и fail-closed validation
- GIVEN provider message имеет optional tool_calls либо неверный content/envelope
- WHEN адаптер проверяет ответ
- THEN только отсутствующий tool_calls или ровно [] допустимы; null/malformed/nonempty calls отвергаются, tools не запрашиваются и не исполняются. Unknown message keys, nonnull reasoning/refusal, nonempty annotations, неверные model/role/content/usage или non-stop finish не спасаются schema. Нет coercion/unwrap/fence stripping/repair/plugin/дополнительного запроса. Receipt/accounting предшествуют content publication, unknown dispatched consumption не refund.

#### Scenario: Каталог не доказывает успешную генерацию
- GIVEN source author сообщил о публичном каталоге26.10 с response_format/structured_outputs для exact endpoint
- WHEN оценивается готовность
- THEN это атрибутированная capability metadata, не доказательство enforcement/availability/ru quality/privacy/billing. russian-prose-v4-structured включена в policy hash: старый context/consent/cache identity неприменим, нужны свежие operation-specific bindings; bounds/routing/нулевые caps/default-off и quotas не расширяются.
''')
body = replace_once(body, 'Новая кнопка разрешает ровно текущий запрос после раскрытия; не auto-egress,', 'Историческая button-only формулировка superseded только явно сохранённым public account opt-in в новой редакции; без такого opt-in не auto-egress,')
bodies[8] = body

body = scoped_revision(bodies[9])
body = requirement(body, 'Явное раскрытие условий и согласие на один запрос', '''
Интерфейс SHALL допускать public auto-summary только после явного сохранения владельцем account opt-in с видимым fixed OpenRouter/Xing/Phala/free disclosure и отдельным выбором autoSummary, формируя для каждой допустимой попытки прежний одноразовый server consent текущих reportVersion/policyVersion.

#### Scenario: Сохранение и default-off
- GIVEN текущий владелец ещё не сохранял применимую report-automation revision
- WHEN показаны настройки original/ru и autoSummary off/on
- THEN default original/off не разрешает POST; изменение select без Save не opt-in. Save раскрывает только selected title/description для ru и sanitized findings/coverage для summary, exact xingchen-agi/xing4.0-29b-a4b:free через OpenRouter/phala, free-only/no fallback, quotas/availability и отзыв будущей автоматики. Сохранены только настройки+версия, не credentials/report/output.

#### Scenario: Один запрос и актуальная политика
- GIVEN owner-scoped сохранённый autoSummary=true и завершённый авторизованный отчёт
- WHEN открыта панель и свежий context/usage разрешают передачу
- THEN единственная автоматическая попытка использует reportVersion и consent:{accepted:true,policyVersion} текущего контекста; server guards неизменны. Stale preflight не пересылает запрос с молча обновлёнными условиями, ошибка/отмена/reconnect/focus не инициируют автоматический повтор.

#### Scenario: Бесплатный профиль и неизвестные условия
- GIVEN disclosure отсутствует либо free-only policy противоречива
- WHEN выполняются preflight и отображение условий
- THEN бесплатность не выводится из имени модели, небезопасная/неполная конфигурация не допускает передачу. Global/no-storage/routing декларации не считаются доказательством privacy/billing; смена раскрываемого профиля/области требует новой automation revision и повторного Save, не автопринятия.
''')
body = requirement(body, 'Ограниченный ручной запрос и отмена', '''
Интерфейс SHALL ограничивать размер ответов и длительность одной операции, предотвращать параллельную генерацию и допускать повтор failed/aborted попытки только отдельной явной кнопкой с новым preflight, не фоновым retry.

#### Scenario: Медленный или отменённый запрос
- GIVEN запрос ожидает либо достигнут deadline
- WHEN пользователь отменяет ожидание или срок истёк
- THEN pending заканчивается, поздний ответ не публикуется; факт передачи/расхода не обнуляется. «Повторить сводку» — отдельное намерение после ошибки с повторной проверкой context/usage/quotas, не доказательство refund и не автоматическое продолжение.
''')
body = add(body, '''
### Requirement: Owner-local настройки и ограниченная защита от автоповтора
Интерфейс SHALL изолировать account preferences и automation keys текущим владельцем, хранить настройки только в этом браузере и ограничивать автоматические summary/translation попытки без обещания глобального exactly-once.

#### Scenario: Preferences и отзыв
- GIVEN localStorage содержит только version1, текущую automationRevision, language original/ru и boolean autoSummary под owner-scoped key
- WHEN owner/поколение сессии меняются, storage недоступно/повреждено/устарело либо Save не удалось
- THEN stale draft/save/authorization не переносится новому owner; недопустимая запись даёт original/off без разрешения. Успешное сохранение original/off отзывает будущую автоматику, не уже отправленные данные; настройки не синхронизируются на другие устройства. Чтение локального grant не заменяет server policy/owner/source проверки.

#### Scenario: Общая serial queue и ключ попытки
- GIVEN разрешена summary либо translation автоматика
- WHEN панель планирует запрос
- THEN общий frontend module допускает одну активную локальную automation job и до8 ожидающих, single-flight cache до64 keys, sessionStorage ledger до256 SHA-256 attempt markers. Summary key включает kind/owner/automation revision/scan/digest/platform/reportVersion/policyVersion; translation дополнительно findingId/assessmentIndex/sourceVersion/ru. Отметка записывается до task/preflight: попытка может заблокироваться даже до provider dispatch; ошибка marker storage останавливает новую автоматическую отправку. Server capacity/quota действуют независимо; это не distributed lock или доказательство zero dispatch после abort.

#### Scenario: Reload, ошибка и явный повтор
- GIVEN попытка завершилась, отказала либо отменена и marker уже сохранён
- WHEN панель remount/reload или owner повторно вошёл в том же tab storage
- THEN автоматический повтор того же key запрещён, failed promise не rerun; cached validated reply используется только после fresh binding проверки. Outputs остаются только в памяти и очищаются при смене сессии, reload их не восстанавливает. sessionStorage не global/durable exactly-once: новый tab/очистка storage/другая policy или report создают иной scope; reauthentication generation отсутствует в key. Явная Retry после ошибки может разрешить одну новую проверяемую попытку, но не refund/reset/fallback. Отмена освобождает локальное ожидание, не доказывает прекращение игнорирующей abort внешней работы.
''')
body = replace_once(body, 'Button-only authorization не разрешает auto-egress,', 'Без явно сохранённого применимого account opt-in автоматическая передача не разрешена; новый opt-in не разрешает')
bodies[9] = body

body = scoped_revision(bodies[15])
body = add(body, '''
### Requirement: Немедленно доступный composer при read-only подключении
Интерфейс SHALL позволять вводить черновик вопроса сразу при GET-подключении context/history/readiness и независимо от autoSummary/языкового opt-in, сохраняя ручную отправку и все server admission guards.

#### Scenario: Идёт GET либо генерация ещё недоступна
- GIVEN авторизованная панель чата монтируется или читает context/history/sources/usage/readiness
- WHEN пользователь печатает вопрос до окончания чтения
- THEN textarea доступна; Send остаётся disabled до свежих согласованных context/history/CAS/readiness/usage и валидного текста. Ни GET, ни ввод, ни autoSummary/ru preference не отправляют вопрос; только явный Send создаёт одноразовый consent. Во время chat/decision mutation ввод может блокироваться, scope change отменяет stale draft/callback.

#### Scenario: Автоматика другого контура
- GIVEN владелец разрешил summary/translation в account settings
- WHEN сводка или открытый advisory автоматически обрабатываются
- THEN chat не получает автоматических вопросов/ответов и не требует включения autoSummary; ручные history/decision возможности остаются отдельными. Structured public provider JSON определяется DOC8, но success/error JSON/NDJSON, durable turn/receipt/CAS/authority и transport ceilings этого документа не меняются.
''')
bodies[15] = body

body = scoped_revision(bodies[16])
body = requirement(body, 'Отдельное явное согласие на новый selected-text egress', '''
Система SHALL разрешать public ru translation открытого source slot после отдельного явно сохранённого owner-local account language=ru opt-in с раскрытием selected-text egress, сохраняя одноразовый consent текущих translationPolicy/source/report и отсутствие разрешения от summary/chat.

#### Scenario: Открытие до и после Save
- GIVEN account preference default original/не authorized либо владелец явно сохранил текущую language=ru automation revision
- WHEN открыты подробности advisory
- THEN до Save генерации нет; после Save только смонтированный открытый source slot с допустимым текстом может после свежих context/readiness автоматически планировать один translation request. Закрытые карточки не монтируют панель и не делают её context/readiness GET/POST; не переводятся весь отчёт, скрытые страницы или история. Текущий UI монтирует отдельную панель каждого assessment открытой карточки: один глобально выбранный source selector не заявляется.

#### Scenario: Условия, source и явный повтор
- GIVEN opt-in актуален, translation consent включает underlying policy/selected-normalized-text-only/ru и source binding
- WHEN preflight выявил stale report/source/policy/session либо произошла ошибка/отмена
- THEN прежняя попытка не продолжает send/publication, нет auto retry; нужен fresh context и новое применимое намерение. Отдельная «Повторить перевод» после ошибки разрешает одну новую проверку, не fallback/refund. Смена раскрываемых модели/провайдера/данных/условий требует новой automation revision и повторного Save; local grant не серверная authority.
''')
body = replace_once(body, 'переключение не генерирует новый запрос.', 'переключение original/готовый перевод не генерирует новый запрос; первое открытие source slot может планировать его только после отдельного сохранённого ru opt-in.')
body = replace_once(body, 'автоматического replay/generation нет; учёт', 'выходной перевод не persist-ится; после reload автоматический replay того же key блокирует локальный attempt marker по DOC9, а применимый новый source/report/policy key отдельно проверяется; учёт')
body = replace_once(body, 'актуального одноразового authorization кнопкой после видимого раскрытия и fresh context;', 'актуального одноразового server authorization после видимого раскрытия и fresh context: ручного Send либо соответствующего сохранённого account opt-in;')
body = replace_once(body, 'повтор требует fresh context и нового явного Translate после видимого раскрытия без checkbox,', 'повтор после ошибки требует fresh context и нового явного «Повторить перевод» после видимого раскрытия без checkbox,')
body = requirement(body, 'Translation diagnostic headers и граница русской проверки', '''
Система SHALL сохранять translation body wire и отклоняющие predicates, раскрывая только первый фактический локальный отказ через optional finite X-LLM-Failure-Phase/X-LLM-Failure-Reason по DOC8, без раскрытия content или обещания семантической точности.

#### Scenario: Первый отклоняющий predicate
- GIVEN top-level ответ не имеет exact title/description либо одно поле не прошло проверки
- WHEN валидатор отказывает
- THEN shape mismatch даёт content/invalid_shape, поля идут в порядке title затем description с phase translation_title/translation_description. Reasons: null_mismatch, invalid_type, limit, unsafe_text, not_normalized, invalid_link, invalid_markup, identifier_mismatch, not_russian, nonprose_changed в фактическом порядке guards. Ранний text guard может отказать URL до link guard; generic service fallback не перетирает первый диагноз. Body остаётся LLM_INVALID_RESPONSE без predicate payload, raw text/match/message/URL/credential не выходят наружу; без диагностики headers отсутствуют.

#### Scenario: Structured shape не ослабляет guards
- GIVEN exact public adapter запрашивает strict scanner_translation schema по DOC8 с title/description string/null ровно по входу
- WHEN получен schema-conforming reply
- THEN обязательны прежние UTF-8 bounds/nulls/normalization/безопасный plaintext/per-field IDs/finite source-bound script/nonprose проверки; нет unwrapping/coercion/repair. Незнакомые technical names могут fail-closed отклоняться даже в русской прозе; schema и конечный словарь не доказывают fidelity и не классифицируют исторический invalid_content задним числом.
''')
body = add(body, '''
### Requirement: Ограниченная автоматизация открытого source scope
Интерфейс SHALL использовать общий summary/translation queue и attempt-cache контур DOC9 только для открытого допустимого source scope при сохранённом ru opt-in, без persistent translation cache или скрытого обхода отчёта.

#### Scenario: Повторное открытие и cached ответ
- GIVEN ключ включает kind/owner/automation revision/scan/digest/platform/reportVersion/policyVersion/findingId/assessmentIndex/sourceVersion/ru
- WHEN открытый source slot снова монтируется
- THEN validated in-memory reply может использоваться лишь после fresh context/readiness/source проверки, failed/aborted key не автоматически повторяется. Закрытие отменяет ожидание и stale publication; sessionStorage хранит только opaque hashes, не исходник/перевод. Reload не восстанавливает output, новый tab/очистка storage не покрыты глобальным exactly-once; server quotas и unknown liability не сбрасываются.
''')
body = replace_once(body, 'browser-supplied text, auto-translation при открытии и не официальный', 'browser-supplied text, auto-translation без явно сохранённого применимого ru opt-in и не официальный')
bodies[16] = body

records = []
for doc, body in bodies.items():
    version, basefile = BASES[doc]
    old = (ROOT / basefile).read_text()
    amendment = ('\nНовая редакция26.10.2026 от DIP-TASK-' + ('9' if doc == 2 else '42') +
        ': явное новое поручение владельца supersedes прежние no-estimate/no-auto/button-only ограничения только в описанной ниже области. '
        'Предыдущие authoring/HOLD/evidence записи остаются историческими; эта полная редакция — PREPARED, NOT APPLIED. '
        'Source inspection не является independent review GO/deploy/native/provider/semantic acceptance. APPLY HOLD до отдельного coordinator source GO и deploy verification.\n')
    body = replace_once(body, '\n## Requirements\n', amendment + '\n## Requirements\n')
    assert body.endswith('\n') and '\r' not in body
    names = lambda text: re.findall(r'^### Requirement: (.+)$', text, re.M)
    assert set(names(old)) <= set(names(body))
    assert len(names(body)) == len(set(names(body)))
    assert not re.search(r'[ \t]+$', body, re.M)
    path = ROOT / f'{PREFIX}doc{doc}-full.md'
    with path.open('x') as out:
        out.write(body)
    records.append({'doc': doc, 'base_version': version, 'source': f'DIP-TASK-{9 if doc == 2 else 42}',
        'base_local_mirror': 'docs/' + basefile,
        'base_local_sha256': hashlib.sha256(old.encode()).hexdigest(),
        'fullbody_path': 'docs/' + path.name, 'bytes': len(body.encode()),
        'sha256': hashlib.sha256(body.encode()).hexdigest(),
        'requirements': len(names(body)), 'scenarios': body.count('#### Scenario: '),
        'all_base_requirement_identities_retained': True,
        'full_raw_validate_spec': 'NOT_RUN', 'proposal': 'NOT_RUN', 'apply_hold': True})
with (ROOT / f'{PREFIX}preparation.json').open('x') as out:
    json.dump({'status': 'LOCAL_PREPARED_ONLY', 'records': records}, out, ensure_ascii=False, indent=2)
    out.write('\n')
print(json.dumps(records, ensure_ascii=False, indent=2))
