# DIP-TASK-38 — Панель ИИ-сводки отчёта

## Purpose
Браузерная панель сводки завершённого owner report отдельно от серверного контракта DOC8. Применимый account opt-in разрешает ограниченную app-wide автоматику для авторизованного завершённого отчёта независимо от report profile, но не автоматические chat questions. Passive GET recovery уже сохранённого результата доступен только public report и не является generation; report profile не тождествен fixed provider/model/disclosure profile.

Полная superseding редакция r3 от26.10.2026, источник DIP-TASK-42, свежая серверная база DOC9 v3. По узкому разрешению владельца superseded только r2 DOC9 delta3e230388-542f-439d-9eef-fb904db51789: исправлено ошибочное утверждение always-manual legacy generation; четыре r2 DOC2/8/15/16 не меняются. Новое явное поручение владельца supersedes прежние no-estimate/no-auto/button-only ограничения только в указанной области. Предыдущие authoring/transcription/FAIL/UNKNOWN записи, включая прежнюю замену пяти pending proposals и ошибочный полный r2 DOC9 body, остаются в неизменённых файлах и серверной истории. Это SOURCE-BOUNDED PROPOSAL, NOT APPLIED и не deployed/native/provider/semantic/privacy/billing acceptance. APPLY HOLD до фактического deploy и отдельного coordinator разрешения; сообщённые владельцем source freeze и independent AI/cache GO не являются deployment acceptance. Принятые задачи и родители не переоткрываются.

## Requirements

### Requirement: Отсутствие подразумеваемой приёмки реальной интеграции
Интерфейс SHALL отличать наблюдаемые отчёты сканера и явно запрошенные проверяемые объяснения ИИ от утверждений об успешной реальной интеграции с моделью.

#### Scenario: Только локальная проверка
- GIVEN выполнены только транспортные и компонентные тесты с имитацией ответов
- WHEN сообщается о готовности реализации
- THEN не заявляются реальные вызовы провайдера, развёртывание или приёмка в производственном окружении.

### Requirement: Только завершённый отчёт авторизованного пользователя
Интерфейс SHALL предлагать генерацию сводки только для завершённого отчёта авторизованного пользователя и SHALL не имитировать ответ модели в демонстрационном режиме.

#### Scenario: Демонстрация или выполняющееся сканирование
- GIVEN показаны демонстрационные данные либо сканирование ещё выполняется
- WHEN отображается отчёт
- THEN интерфейс объясняет недоступность генерации сводки и не отправляет POST сводки.

### Requirement: Явное раскрытие условий и согласие на один запрос
Интерфейс SHALL допускать app-wide auto-summary для авторизованного завершённого отчёта независимо от public/legacy report profile только после явного сохранения владельцем применимого account opt-in с видимым fixed OpenRouter/Xing/Phala/free disclosure и отдельным выбором autoSummary, формируя для каждой допустимой попытки прежний одноразовый server consent текущих reportVersion/policyVersion. Свежие preference snapshot identity, session, применимые flags, exact disclosure, context/usage/quotas и server guards остаются обязательны. Public-only ограничение относится к passive GET cache recovery, а не к automatic POST; legacy report не объявляется always-manual. Это не разрешает Apodex/Novita, paid/другую provider/model композицию или иное раскрытие под Xing consent.

#### Scenario: Сохранение и default-off
- GIVEN текущий владелец ещё не сохранял применимую report-automation revision
- WHEN показаны настройки original/ru и autoSummary off/on
- THEN default original/off не разрешает POST; изменение select без Save не opt-in. Save раскрывает только selected title/description для ru и sanitized findings/coverage для summary, exact xingchen-agi/xing4.0-29b-a4b:free через OpenRouter/phala, free-only/no fallback, quotas/availability и отзыв будущей автоматики. Сохранены только настройки+версия, не credentials/report/output.

#### Scenario: Один запрос и актуальная политика
- GIVEN owner-scoped сохранённый autoSummary=true и завершённый авторизованный public либо legacy отчёт с применимым fixed disclosure
- WHEN открыта панель и свежий context/usage разрешают передачу
- THEN единственная автоматическая попытка использует reportVersion и consent:{accepted:true,policyVersion} текущего контекста; server guards неизменны. Для legacy пропущен GET summary recovery, но разрешённый guarded automatic POST не блокируется одним report profile. Stale preflight не пересылает запрос с молча обновлёнными условиями, ошибка/отмена/reconnect/focus не инициируют автоматический повтор.

#### Scenario: Бесплатный профиль и неизвестные условия
- GIVEN disclosure отсутствует либо free-only policy противоречива
- WHEN выполняются preflight и отображение условий
- THEN бесплатность не выводится из имени модели, небезопасная/неполная конфигурация не допускает передачу. Global/no-storage/routing декларации не считаются доказательством privacy/billing; автоматика принимает только exact fixed disclosure: OpenRouter, xingchen-agi/xing4.0-29b-a4b:free, providers=[phala], global, no-storage, freeOnly=true, requestBudgetUsd=0, operatorApprovedRouting=true, providerComplianceNotProvenByDeclaration=true и maxPrice ровно prompt/completion/request=0, без лишних keys. Summary data ровно `Sanitized scanner findings and coverage; no raw evidence or credentials.`; другая модель/endpoint/data/retention/flags/caps/extra metadata запрещают POST и публикацию. Constant report-automation-v1 не является dynamic policy grant; fresh operation policyVersion и full context обязательны. Изменённое раскрытие требует новой поддержанной версии согласия, не молчаливого принятия новым Save старой версии.

### Requirement: Актуальная привязка перед публикацией
Интерфейс SHALL отбрасывать результаты, если пользователь или поколение сессии, сканирование, digest/platform, reportVersion либо раскрытая политика больше не соответствуют принятому контексту запроса.

#### Scenario: Устаревший отчёт или политика
- GIVEN пользователь разрешил один запрос кнопкой для показанного отчёта и политики
- WHEN свежий контекст до POST или после POST отличается
- THEN устаревший результат не показывается, согласие сбрасывается, а изменение контекста при проверке до запроса не приводит к POST.

#### Scenario: Смена маршрута или сессии
- GIVEN выполняется запрос контекста или сводки
- WHEN компонент, привязанный к маршруту и снимку статуса, размонтируется либо меняется сессия, включая новый вход того же пользователя
- THEN запрос отменяется, а запоздавшие ответы не могут восстановить прежний результат или согласие.

### Requirement: Ограниченный ручной запрос и отмена
Интерфейс SHALL ограничивать размер ответов и длительность одной операции, предотвращать параллельную генерацию и допускать повтор failed/aborted попытки только отдельной явной кнопкой с новым preflight, не фоновым retry.

#### Scenario: Медленный или отменённый запрос
- GIVEN запрос ожидает либо достигнут deadline
- WHEN пользователь отменяет ожидание или срок истёк
- THEN pending заканчивается, поздний ответ не публикуется; факт передачи/расхода не обнуляется. «Повторить сводку» — отдельное намерение после ошибки с повторной проверкой context/usage/quotas, не доказательство refund и не автоматическое продолжение.

### Requirement: Гипотезы обычным текстом и проверенные ссылки на источники
Интерфейс SHALL отображать русскоязычное объяснение сохранённых фактов экранированным обычным текстом с проверенными локальными citations, не подменяя отсутствие evidence гипотезами, неподтверждёнными причинами или обещаниями исправления. Историческое имя requirement не требует маркировать новый ответ как гипотезу; машинное происхождение и ограничения остаются видимыми.

#### Scenario: Цитата с последующей страницы или скрытой категории
- GIVEN цитата указывает на реальный finding Secrets, CVE или конфигурации вне текущего фильтра или страницы
- WHEN сводка проходит проверку
- THEN локальная ссылка на источник ведёт к видимой проекции данных сканера независимо от текущих фильтров; принадлежность источника не доказывает вывод модели, а инвентаризация SBOM не выдаётся за finding.

#### Scenario: Небезопасный текст или выдуманный источник
- GIVEN текст модели содержит HTML, Markdown или синтаксис исполняемого URL либо ссылается на отсутствующий finding
- WHEN сводка обрабатывается
- THEN текст не создаёт разметку или произвольные внешние ссылки, а непроверенная цитата или противоречивая пагинация предотвращают публикацию сводки.

#### Scenario: Недостаточно фактов и технические имена
- GIVEN report не устанавливает причину, влияние, исправленную версию либо ответ на часть вопроса
- WHEN показывается новая сводка
- THEN человекочитаемая проза русская, технические имена/версии/CVE/TEMP и keys сохранены, а недостаток данных назван прямо без выдуманного доказательства; schema/citations/script checks сами по себе не объявляются semantic-quality PASS. Текущая russian-prose-v4-structured revision меняет policy hash; permission-checkbox отсутствует, source-selection controls не являются consent.

### Requirement: Исходный отчёт сканера сохраняется при сбое ИИ
Интерфейс SHALL сохранять доступность статуса сканера, покрытия и исходных findings при ошибках контекста сводки, конфигурации, квоты или доступной ёмкости, тайм-ауте, отсутствии evidence либо сбое обработки провайдером.

#### Scenario: Отсутствие evidence или ошибка провайдера
- GIVEN отчёт доступен, но endpoint сводки возвращает безопасную ошибку
- WHEN показывается ошибка
- THEN отображается только понятное объяснение из разрешённого набора, сырая диагностика провайдера не воспроизводится, вымышленная сводка не создаётся, а отсутствие покрытия не объявляется безопасностью.

### Requirement: Owner-local настройки и ограниченная защита от автоповтора
Интерфейс SHALL изолировать account preferences и automation keys текущим владельцем, хранить настройки только в этом браузере и ограничивать автоматические summary/translation попытки без обещания глобального exactly-once.

#### Scenario: Preferences и отзыв
- GIVEN localStorage содержит только version1, текущую automationRevision, language original/ru и boolean autoSummary под owner-scoped key
- WHEN owner/поколение сессии меняются, storage недоступно/повреждено/устарело либо Save не удалось
- THEN stale draft/save/authorization не переносится новому owner; недопустимая запись даёт original/off без разрешения. Каждый Save заменяет snapshot identity; сравнение только постоянного revision недостаточно. Прямые subscriptions и свежий read проверяют ту же identity/session и применимый autoSummary либо ru флаг перед POST и publication, включая cached reply и callback ignoring abort. Успешное сохранение original/off отзывает будущую автоматику, не уже отправленные данные; настройки не синхронизируются на другие устройства. Failed persistence запрещает автоматику текущего memory scope, но не обещает durable revocation прежней записи после следующего login. Чтение локального grant не заменяет server policy/owner/source проверки.

#### Scenario: Общая serial queue и ключ попытки
- GIVEN разрешена summary либо translation автоматика
- WHEN панель планирует запрос
- THEN общий frontend module допускает одну активную локальную scheduled job и до8 ожидающих, single-flight cache до64 keys, sessionStorage ledger до256 SHA-256 attempt markers. Summary key включает kind/owner/automation revision/scan/digest/platform/reportVersion/policyVersion; translation дополнительно findingId/assessmentIndex/sourceVersion/ru. Отметка записывается до task/preflight: попытка может заблокироваться даже до provider dispatch; ошибка marker storage останавливает новую автоматическую отправку. Server capacity/quota действуют независимо; это не distributed lock или доказательство zero dispatch после abort.

#### Scenario: Reload, ошибка и явный повтор
- GIVEN попытка завершилась, отказала либо отменена и marker уже сохранён
- WHEN панель remount/reload или owner повторно вошёл в том же tab storage
- THEN автоматический повтор того же key запрещён, failed promise не rerun; cached validated reply используется только после fresh binding проверки. Browser outputs остаются только в памяти и очищаются при смене сессии; translation после reload не восстанавливается. Public summary сначала пытается passive GET recovery по следующему требованию, независимо от browser marker и autoSummary opt-in. Miss не очищает marker и не разрешает replay; без прежнего marker первая допустимая auto-попытка по отдельному сохранённому opt-in остаётся возможной. sessionStorage не global/durable exactly-once: новый tab/очистка storage/другая policy или report создают иной scope; reauthentication generation отсутствует в key. Явная Retry после ошибки может разрешить одну новую проверяемую попытку, но не refund/reset/fallback. Отмена освобождает локальное ожидание, не доказывает прекращение игнорирующей abort внешней работы.

### Requirement: Passive summary recovery до attempt marker
Интерфейс SHALL для completed public report читать fresh context и existing summary до проверки generation attempt marker, восстанавливая только текущий owner/report/policy-bound результат без требования autoSummary opt-in.

#### Scenario: Reload или новый login с выключенной автоматикой
- GIVEN тот же owner заново открыл completed public report, autoSummary может быть off, backend ещё сохраняет exact result
- WHEN выполняются context GET и `existing(context)` GET summary
- THEN reply проходит tuple/schema, authorised citations/source pages и postflight context checks; текущие preference snapshot/session/permissions ограждают publication. Read не является новым consent/POST/квотой; отключение автоматики не запрещает owner чтение прежнего результата. Иной owner/report/policy и stale callback не получают summary. Recovery GET не выполняется для legacy report; это GET-only ограничение не запрещает app-wide authorized automation. Legacy generation может выполнить automatic POST только при применимом сохранённом opt-in и всех fresh/fixed-disclosure guards выше; public cache read не расширяет provider/model consent.

#### Scenario: Missing и ограниченное удержание
- GIVEN GET вернул LLM_SUMMARY_MISSING либо endpoint недоступен/контекст stale
- WHEN UI решает, что показывать
- THEN отсутствующий retained result не выдаётся за пустую сводку или guaranteed durable history; ошибка не запускает replay и marker не сбрасывается. При уже отмеченной попытке нет автоматического POST; первоначальная разрешённая попытка без marker отдельно проходит opt-in/fresh guards. API restart/eviction/другая replica теряют summary cache по DOC8, не scanner report.

### Requirement: Bounded passive metadata scheduling
Интерфейс SHALL ограничивать passive summary/translation metadata pending singleflight тем же локальным serial scheduler, что и automation jobs, без attempt marker или сохранения stale readiness результата.

#### Scenario: Несколько открытых source panels
- GIVEN разные открытые source slots читают context/readiness либо summary recovery
- WHEN passive metadata планируются параллельно
- THEN одна scheduled job активна, до8 ждут; pending metadata keys не более9 и scoped текущим session+operation binding, одинаковый pending key разделяется подписчиками. Task допускает до2 параллельных GET, generation job не вкладывает scheduler в самого себя; отсутствие metadata capacity безопасно отказывает без provider dispatch/retry. Settled entry удаляется, не становится долгоживущим readiness cache.

#### Scenario: Отмена и граница локальной сериализации
- GIVEN pending metadata имеет нескольких подписчиков либо сессия изменилась
- WHEN один подписчик отменён либо освобождён последний/изменён session
- THEN отменённый подписчик не публикует stale result, общий read отменяется после последнего, session change отменяет jobs/clears maps. Metadata не создаёт generation marker. Освобождение локального slot после abort не доказывает остановку игнорирующего abort внешнего транспорта; это не распределённый lock/глобальный exactly-once.

## Non-goals
Потоковый чат DIP-ТASK-16, кеш DIP-TASK-14, продуктовые квоты и учёт DIP-TASK-15, конфигурация backend, развёртывание, подтверждение производственного биллинга или соблюдения требований конфиденциальности и изменение DIP-DOC-8 не входят в этот контракт. Активация модели DIP-TASK-37 и успешная реальная генерация не являются критериями приёмки узкой панели DIP-TASK-38. Родительский интегратор отвечает за независимые ревью, итоговую сборку, применение спеки, интеграцию, закрытие задачи и коммиты.

Amendment TASK42 не закрывает ни TASK42, ни ранее принятую TASK38 заново. Без явно сохранённого применимого account opt-in автоматическая передача не разрешена; новый opt-in не разрешает paid fallback, quota reset/refund, смену модели или приватное чтение; source/runtime/provider qualification остаются отдельными. Historical FAIL и unknown consumption не переписываются.
